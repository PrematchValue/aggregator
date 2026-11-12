"""Incremental Collect/Refresh checkpoint stored separately from published subscriptions.

No credentials, subscription URLs, or proxy endpoints are ever placed in this file.
All site and node keys are one-way hashes. An incomplete run is allowed to update
only this small state file, never replace the last known-good subscriptions.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

STATE_FILE = "collector-state.json"
VERSION = 2
MAX_SITES = 40000
MAX_NODES = 40000
MAX_BYTES = 8 * 1024 * 1024
HEX = re.compile(r"^[a-f0-9]{64}$")
SITE_BACKOFF = {"bad": 7 * 86400, "ready": 3 * 86400}


def site_key(url: str) -> str:
    """Lowercase normalized domain fingerprint; never write input URL to Gist."""
    try:
        parsed = urllib.parse.urlsplit(str(url).strip())
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme not in ("http", "https") or not host:
            return ""
        # Discovered directories are untrusted. Avoid probing internal hosts.
        try:
            if not ipaddress.ip_address(host).is_global:
                return ""
        except ValueError:
            if ("." not in host or host.endswith((".local", ".localhost", ".internal",
                                              ".test", ".invalid", ".example"))):
                return ""
        return hashlib.sha256(host.encode("idna")).hexdigest()
    except (ValueError, UnicodeError):
        return ""


def canonical_site(url: str) -> str:
    """Save only a public site origin, never paths, tokens or query parameters."""
    if not site_key(url):
        return ""
    try:
        parsed = urllib.parse.urlsplit(str(url).strip())
        host = (parsed.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        port = parsed.port
        authority = f"[{host}]" if ":" in host else host
        if port is not None and not (1 <= port <= 65535):
            return ""
        if port and (parsed.scheme, port) not in (("http", 80), ("https", 443)):
            authority += f":{port}"
        return f"{parsed.scheme}://{authority}"
    except (ValueError, UnicodeError):
        return ""


def _table(data: object, states: set[str], limit: int) -> dict[str, list]:
    if not isinstance(data, dict) or len(data) > limit:
        raise ValueError("invalid checkpoint table")
    result = {}
    for key, val in data.items():
        if not isinstance(key, str) or not HEX.fullmatch(key):
            raise ValueError("invalid checkpoint key")
        is_site = "new" in states
        if not isinstance(val, list) or len(val) != (4 if is_site else 3):
            raise ValueError("invalid checkpoint entry")
        timestamp, status, failures = val[:3]
        if (type(timestamp) is not int or timestamp < 0 or timestamp > 9999999999
                or not isinstance(status, str) or status not in states
                or type(failures) is not int or failures < 0 or failures > 1000):
            raise ValueError("invalid checkpoint value")
        if is_site:
            url = val[3]
            if not isinstance(url, str) or (url and (canonical_site(url) != url or site_key(url) != key)):
                raise ValueError("unsafe site checkpoint URL")
        result[key] = list(val)
    return result


@dataclass
class ScanState:
    sites: dict[str, list]
    nodes: dict[str, list]

    @classmethod
    def load(cls, content: str) -> "ScanState":
        if not content:
            return cls({}, {})
        if len(content.encode("utf-8")) > MAX_BYTES:
            raise ValueError("checkpoint exceeds size limit")
        obj = json.loads(content)
        if not isinstance(obj, dict) or obj.get("v") != VERSION:
            raise ValueError("unsupported checkpoint version")
        return cls(
            _table(obj.get("sites"), {"new", "bad", "ready"}, MAX_SITES),
            _table(obj.get("nodes"), {"good", "retry"}, MAX_NODES),
        )

    def encode(self) -> str:
        return json.dumps({"v": VERSION, "sites": self.sites, "nodes": self.nodes},
                          separators=(",", ":"), ensure_ascii=True, sort_keys=True)

    def merge(self, other: "ScanState") -> None:
        for attr in ("sites", "nodes"):
            destination = getattr(self, attr)
            for key, row in getattr(other, attr).items():
                if (key not in destination or row[0] > destination[key][0]
                        or (row[0] == destination[key][0] and len(row) == 4
                            and destination[key][1] == "new" and row[1] != "new")):
                    destination[key] = list(row)
                elif attr == "sites" and row[3] and not destination[key][3]:
                    destination[key][3] = row[3]
            if len(destination) > (MAX_SITES if attr == "sites" else MAX_NODES):
                # Never silently delete unseen work; force a deliberate capacity increase.
                raise ValueError("checkpoint capacity exceeded")

    def remember_discoveries(self, discovered: dict) -> int:
        """Persist the *whole* discovered catalogue BEFORE probing any subset."""
        added = 0
        for url in discovered:
            key, origin = site_key(url), canonical_site(url)
            if not key or not origin:
                continue
            if key not in self.sites:
                self.sites[key] = [0, "new", 0, origin]
                added += 1
            elif not self.sites[key][3]:
                self.sites[key][3] = origin
        if len(self.sites) > MAX_SITES:
            raise ValueError("too many saved airport candidates")
        return added

    def known_sites(self) -> list[str]:
        return [row[3] for row in self.sites.values() if row[3]]

    def select(self, discovered: dict, excluded_hosts=(), budget: int = 9000, now: int | None = None) -> tuple[dict, dict]:
        """Exhaustively inspect the discovered list but probe only never/overdue sites.

        Deterministic ordering is stable across runs; a processed host is never
        treated as never-tested even if it was not a valid airport.
        """
        now = int(time.time()) if now is None else int(now)
        excluded = {str(x).strip().rstrip(".").lower() for x in excluded_hosts}
        fresh, due, waiting, seen = [], [], 0, set()
        for url, record in discovered.items():
            key = site_key(url)
            if not key or key in seen:
                continue
            host = (urllib.parse.urlsplit(str(url)).hostname or "").rstrip(".").lower()
            if host in excluded:
                continue
            seen.add(key)
            row = self.sites.get(key)
            if row is None or row[1] == "new":
                fresh.append((key, url, record))
            elif now - row[0] >= SITE_BACKOFF[row[1]] * min(4, max(1, row[2])):
                due.append((row[0], key, url, record))
            else:
                waiting += 1
        fresh.sort(key=lambda x: x[0])
        due.sort(key=lambda x: (x[0], x[1]))
        picked = [(url, rec) for _, url, rec in fresh]
        picked += [(url, rec) for _, _, url, rec in due]
        if budget > 0:
            picked = picked[:budget]
        selected = dict(picked)
        stats = {"discovered": len(discovered), "new": len(fresh), "due": len(due),
                 "waiting": waiting, "selected": len(selected),
                 "remaining": len(fresh) + len(due) - len(selected)}
        return selected, stats

    def mark_sites(self, probed: dict, verified_origin_domains, now: int | None = None) -> None:
        now = int(time.time()) if now is None else int(now)
        confirmed_keys = {site_key(x) for x in verified_origin_domains}
        for url in probed:
            key = site_key(url)
            if not key:
                continue
            old = self.sites.get(key)
            good = key in confirmed_keys
            fail_count = 0 if good else min(1000, (old[2] if old else 0) + 1)
            self.sites[key] = [now, "ready" if good else "bad", fail_count,
                               old[3] if old and old[3] else canonical_site(url)]

    def mark_nodes(self, proxies: list[dict], *, identity, verified_label, now: int | None = None) -> None:
        now = int(time.time()) if now is None else int(now)
        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue
            key = identity(proxy)
            good = bool(verified_label(proxy))
            old = self.nodes.get(key)
            failures = 0 if good else min(1000, (old[2] if old else 0) + 1)
            self.nodes[key] = [now, "good" if good else "retry", failures]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("unexpected redirect while saving checkpoint")


class GistCheckpoint:
    """Only modifies STATE_FILE, checking every published file before each write.

    GitHub Actions Collect/Refresh share the same concurrency group. Should the
    publication be externally edited, abort rather than overwrite a newer copy.
    """
    def __init__(self, gist_id: str, token: str, baseline: dict[str, str], *, reader=None, writer=None):
        import collect_safety as safety
        self.gist_id = gist_id
        self.token = token
        self.base = {k: v for k, v in baseline.items() if k != STATE_FILE}
        self.read = reader or safety.read_gist
        self.write = writer or self._write
        try:
            self.state = ScanState.load(baseline.get(STATE_FILE, ""))
        except (ValueError, TypeError, KeyError) as exc:
            raise safety.PublicationError("invalid scan checkpoint; not overwriting Gist") from None
        self.revision = ""

    def _write(self, content: str) -> None:
        payload = json.dumps({"files": {STATE_FILE: {"content": content}}}, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"https://api.github.com/gists/{self.gist_id}",
            data=payload, method="PATCH",
            headers={"Authorization": f"Bearer {self.token}", "User-Agent": "aggregator-checkpoint/1",
                     "Accept": "application/vnd.github+json", "Content-Type": "application/json"})
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=45) as response:
            if response.status != 200:
                raise ValueError("checkpoint PATCH status not 200")

    def assert_unchanged_publication(self) -> str:
        import collect_safety as safety
        revision, files = self.read(self.gist_id, self.token)
        if {k: v for k, v in files.items() if k != STATE_FILE} != self.base:
            raise safety.PublicationError("Gist publication changed during run; keeping newer version")
        return revision

    def save(self) -> str:
        import collect_safety as safety
        revision, files = self.read(self.gist_id, self.token)
        if {k: v for k, v in files.items() if k != STATE_FILE} != self.base:
            raise safety.PublicationError("Gist publication changed during scan; refusing checkpoint")
        try:
            latest = ScanState.load(files.get(STATE_FILE, ""))
            self.state.merge(latest)
            content = self.state.encode()
            if len(content.encode("utf-8")) > MAX_BYTES:
                raise ValueError("checkpoint exceeds size limit")
            self.write(content)
        except safety.PublicationError:
            raise
        except Exception:
            raise safety.PublicationError("cannot save scan checkpoint; stopping before losing more progress") from None
        self.revision = self.assert_unchanged_publication()
        return self.revision
