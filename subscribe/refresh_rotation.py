"""Small Refresh execution-cycle ledger. Saved once with a successful publication.

Only SHA256 host fingerprints; no subscriptions, credentials, node endpoints or
per-batch network checkpoints. Every run discovers all configured sources.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import urllib.parse

VERSION = 1
HEX = re.compile(r"^[a-f0-9]{64}$")
LIMIT = 50000


def host_key(url: str) -> str:
    try:
        p = urllib.parse.urlsplit(str(url))
        host = (p.hostname or "").lower().rstrip(".")
        if p.scheme not in {"https", "http"} or "." not in host:
            return ""
        try:
            if not ipaddress.ip_address(host).is_global:
                return ""
        except ValueError:
            if host.endswith((".local", ".localhost", ".internal", ".test", ".invalid", ".example")):
                return ""
        return hashlib.sha256(host.encode("idna")).hexdigest()
    except (ValueError, UnicodeError):
        return ""


class RefreshRotation:
    def __init__(self, done=None, cycle=0):
        self.done = set(done or ())
        self.cycle = cycle
        self.pending = set()

    @classmethod
    def load(cls, content):
        if not content:
            return cls()
        if not isinstance(content, str) or len(content) > 4 * 1024 * 1024:
            raise ValueError("invalid Refresh rotation size")
        obj = json.loads(content)
        if (not isinstance(obj, dict) or obj.get("v") != VERSION
                or type(obj.get("cycle")) is not int or obj["cycle"] < 0
                or not isinstance(obj.get("done"), list) or len(obj["done"]) > LIMIT
                or any(not isinstance(x, str) or not HEX.fullmatch(x) for x in obj["done"])):
            raise ValueError("invalid Refresh rotation state; refusing to reset progress")
        return cls(obj["done"], obj["cycle"])

    def choose(self, discovered, budget: int, excluded_hosts=()):
        """Deduplicate the full discovered list and run a new portion each time.

        Newly discovered hosts are immediately eligible. The cycle resets only
        after all visible, non-excluded hosts have been attempted.
        """
        excluded = {str(x).strip().lower().rstrip(".") for x in excluded_hosts}
        entries, seen = [], set()
        for url, record in discovered.items():
            key = host_key(url)
            try:
                host = (urllib.parse.urlsplit(str(url)).hostname or "").lower().rstrip(".")
            except ValueError:
                continue
            if not key or key in seen or host in excluded:
                continue
            seen.add(key)
            entries.append((key, url, record))
        entries.sort(key=lambda x: x[0])
        remaining = [item for item in entries if item[0] not in self.done]
        if not remaining and entries:
            self.done.clear()
            self.cycle += 1
            remaining = entries
        chosen = remaining[:budget] if budget > 0 else remaining
        self.pending = {key for key, _, _ in chosen}
        print(f"Refresh 轮换：第 {self.cycle + 1} 轮；全量去重={len(entries)}；"
              f"剩余待执行={len(remaining)}；本次={len(chosen)}；"
              f"后续={len(remaining)-len(chosen)}", flush=True)
        return {url: record for _, url, record in chosen}

    def advance(self):
        self.done.update(self.pending)
        if len(self.done) > LIMIT:
            raise ValueError("Refresh rotation record exceeds capacity")
        self.pending.clear()

    def encode(self):
        return json.dumps({"v": VERSION, "cycle": self.cycle, "done": sorted(self.done)},
                          separators=(",", ":"))

    def persist(self, gist_id: str, token: str, previous: dict) -> str:
        """Save this round's rotation ledger once, without changing node files.

        Not a per-batch checkpoint. The ledger is saved after airport execution
        even if final publication is later blocked by node-count safeguards.
        """
        import urllib.request
        from collect_safety import PublicationError, read_gist

        def public_files(files):
            return {k: v for k, v in files.items() if k not in {"refresh-rotation.json", "collector-state.json"}}

        _, current = read_gist(gist_id, token)
        if public_files(current) != public_files(previous):
            raise PublicationError("Gist changed while Refresh was scanning; not overwriting cycle")
        content = self.encode()
        body = json.dumps({"files": {"refresh-rotation.json": {"content": content}}},
                          separators=(",", ":")).encode("utf-8")

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise RuntimeError("unexpected Gist redirect")

        request = urllib.request.Request(
            f"https://api.github.com/gists/{gist_id}", method="PATCH", data=body,
            headers={"Authorization": f"Bearer {token}",
                     "User-Agent": "aggregator-refresh-cycle/1",
                     "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json"},
        )
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
                if response.status != 200:
                    raise RuntimeError("Gist update failed")
            revision, latest = read_gist(gist_id, token)
            if (latest.get("refresh-rotation.json") != content
                    or public_files(latest) != public_files(previous)):
                raise RuntimeError("could not verify rotation update")
            return revision
        except Exception:
            raise PublicationError("could not save Refresh rotation; keeping old subscriptions") from None
