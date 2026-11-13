"""Reconcile published profiles with country-confirmed nodes.

The bundled legacy SubConverter does not understand every Mihomo protocol.  Never
silently treat an absent *supported* node as a successful conversion.  Recover
representable nodes from their validated Mihomo source; fail without publishing
when an expected node cannot be represented faithfully.
"""
from __future__ import annotations

from collections import Counter
import copy
import json
import re

import yaml


class CoverageError(ValueError):
    """Output would silently discard a node that the target can support."""


SURGE_TYPES = frozenset({
    "ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls",
    "http", "socks5", "snell", "wireguard", "masque", "ssh",
})
SINGBOX_TYPES = frozenset({
    "ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic",
    "anytls", "http", "socks5", "snell", "wireguard", "ssh",
})
PRIVATE_META = frozenset({"sub", "liveness", "cdn", "renamed", "delay", "_region", "_verified_http"})
SECTION = re.compile(r"^\[([^]]+)\]$")
SURGE_LINE = re.compile(r"^([^=\r\n]+?)\s*=\s*([\w-]+)\s*,\s*(.+)$")


def _name(node):
    return str(node.get("name", "")).strip()


def _safe_string(value):
    text = str(value)
    if not text or any(x in text for x in "\r\n\x00"):
        raise ValueError("invalid multiline or empty option")
    return text


def _opt(label, value):
    val = _safe_string(value)
    if any(ch in val for ch in ',"'):
        val = '"' + val.replace('"', '\\"') + '"'
    return f"{label}={val}"


def _tls_options(node, *, reality=False, include_tls=True):
    options = []
    if include_tls and node.get("tls") is True and not reality:
        options.append("tls=true")
    sni = node.get("servername") or node.get("sni")
    if sni:
        options.append(_opt("sni", sni))
    if node.get("skip-cert-verify") is True and not reality:
        options.append("skip-cert-verify=true")
    alpn = node.get("alpn")
    if alpn:
        if isinstance(alpn, list):
            options.append(_opt("alpn", ",".join(map(str, alpn))))
        else:
            options.append(_opt("alpn", alpn))
    return options


def _transport_options(node, *, vless=False):
    network = str(node.get("network", "tcp") or "tcp").lower()
    if network == "tcp":
        return []
    if network == "ws":
        if vless and node.get("flow"):
            raise ValueError("Surge does not support Vision with WS")
        opts = node.get("ws-opts") or {}
        if not isinstance(opts, dict):
            raise ValueError("invalid WS options")
        result = ["ws=true"]
        if opts.get("path"):
            result.append(_opt("ws-path", opts["path"]))
        headers = opts.get("headers") or {}
        if headers:
            if not isinstance(headers, dict):
                raise ValueError("invalid WS headers")
            pairs = "|".join(f"{_safe_string(k)}:{_safe_string(v)}" for k, v in headers.items())
            result.append(_opt("ws-headers", pairs))
        return result
    if network == "grpc" and vless:
        opts = node.get("grpc-opts") or {}
        if not isinstance(opts, dict):
            raise ValueError("invalid gRPC options")
        result = ["grpc=true"]
        if opts.get("grpc-service-name"):
            result.append(_opt("grpc-service-name", opts["grpc-service-name"]))
        return result
    raise ValueError("unsupported Surge transport")


def _surge_line(node):
    """Translate a common Mihomo node into a Surge policy without guessing secrets."""
    t = str(node.get("type", "")).lower()
    name, server, port = _name(node), _safe_string(node["server"]), int(node["port"])
    if not name or not 1 <= port <= 65535:
        raise ValueError("invalid proxy name or port")
    args = []
    if t == "vless":
        if str(node.get("encryption", "none") or "none") != "none":
            raise ValueError("Surge does not support VLESS Encryption")
        user = node.get("uuid")
        if not user:
            raise ValueError("VLESS missing ID")
        reality = node.get("reality-opts") or {}
        if reality and not isinstance(reality, dict):
            raise ValueError("invalid REALITY options")
        network = str(node.get("network", "tcp") or "tcp").lower()
        if reality and network == "ws":
            raise ValueError("Surge does not support WS with REALITY")
        if node.get("flow") and (not node.get("tls") and not reality):
            raise ValueError("Vision requires TLS or REALITY")
        if node.get("flow"):
            args.append(_opt("flow", node["flow"]))
        args.insert(0, _opt("username", user))
        args.extend(_tls_options(node, reality=bool(reality)))
        if reality:
            key = reality.get("public-key")
            if not key:
                raise ValueError("REALITY missing public key")
            args.append(_opt("reality-public-key", key))
            if reality.get("short-id"):
                args.append(_opt("reality-short-id", reality["short-id"]))
        args.extend(_transport_options(node, vless=True))
        if str(node.get("network", "tcp") or "tcp") == "grpc" and not (node.get("tls") or reality):
            raise ValueError("Surge gRPC needs TLS/REALITY")
    elif t == "anytls":
        if any(node.get(x) for x in ("shadow-tls-opts", "restls-opts", "jls-opts")):
            raise ValueError("special AnyTLS wrapping not safely convertible")
        args = [_opt("password", node["password"])] + _tls_options(node, include_tls=False)
    elif t == "trojan":
        args = [_opt("password", node["password"])] + _tls_options(node, include_tls=False)
        args.extend(_transport_options(node))
    elif t == "hysteria2":
        args = [_opt("password", node["password"])] + _tls_options(node, include_tls=False)
        obfs = node.get("obfs")
        if obfs:
            if obfs not in ("salamander", "gecko"):
                raise ValueError("unknown Hysteria2 obfs")
            args.append(_opt(f"{obfs}-password", node["obfs-password"]))
        if node.get("ports"):
            ports = node["ports"]
            if isinstance(ports, (list, tuple)):
                ports = ";".join(map(str, ports))
            args.append(_opt("port-hopping", ports))
        if node.get("down"):
            try:
                download_mbps = float(node["down"])
                if download_mbps > 0:
                    args.append(_opt("download-bandwidth", int(download_mbps)))
            except (ValueError, TypeError):
                pass
    elif t == "tuic":
        if node.get("token"):
            t = "tuic"
            args = [_opt("token", node["token"])]
        else:
            t = "tuic-v5"
            args = [_opt("uuid", node["uuid"]), _opt("password", node["password"])]
        args.extend(_tls_options(node, include_tls=False))
    elif t == "vmess":
        if int(node.get("alterId", 0)) != 0:
            raise ValueError("legacy non-AEAD VMess needs converter support")
        args = [_opt("username", node["uuid"]), "vmess-aead=true"]
        args.extend(_tls_options(node))
        args.extend(_transport_options(node))
    elif t == "ss":
        surge_ciphers = {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                         "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
                         "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
                         "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb",
                         "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
                         "salsa20", "chacha20", "chacha20-ietf", "none"}
        if node.get("cipher") not in surge_ciphers:
            raise ValueError("Shadowsocks cipher is not supported by Surge")
        args = [_opt("encrypt-method", node["cipher"]), _opt("password", node["password"])]
        plugin = node.get("plugin")
        if plugin:
            if plugin != "obfs":
                raise ValueError("Shadowsocks plugin needs converter support")
            opts = node.get("plugin-opts") or {}
            if opts.get("mode") not in ("http", "tls"):
                raise ValueError("unrecognized Shadowsocks obfs")
            args.append(_opt("obfs", opts["mode"]))
            if opts.get("host"):
                args.append(_opt("obfs-host", opts["host"]))
        if node.get("udp"):
            args.append("udp-relay=true")
    elif t == "snell":
        args = [_opt("psk", node["psk"])]
        if node.get("version"):
            args.append(_opt("version", node["version"]))
    elif t == "masque":
        args = [_opt(k, node[k]) for k in ("username", "password") if node.get(k)]
        args.extend(_tls_options(node, include_tls=False))
    elif t in ("http", "socks5"):
        for k in ("username", "password"):
            if node.get(k):
                args.append(_opt(k, node[k]))
        if t == "http" and node.get("tls"):
            t = "https"
        elif t == "socks5" and node.get("tls"):
            t = "socks5-tls"
        if t in ("https", "socks5-tls"):
            args.extend(_tls_options(node, include_tls=False))
    elif t in ("wireguard", "ssh"):
        raise ValueError("special proxy requires additional Surge configuration")
    else:
        raise ValueError("unsupported Surge type")
    return f"{name} = {t}, {server}, {port}" + (", " + ", ".join(args) if args else "")


def _singbox_tls(node, *, required=False):
    reality = node.get("reality-opts") or {}
    if not (node.get("tls") or required or reality):
        return None
    options = {"enabled": True}
    if node.get("servername") or node.get("sni"):
        options["server_name"] = str(node.get("servername") or node.get("sni"))
    if node.get("skip-cert-verify") is True and not reality:
        options["insecure"] = True
    if node.get("alpn"):
        options["alpn"] = node["alpn"] if isinstance(node["alpn"], list) else [str(node["alpn"])]
    if reality:
        if not reality.get("public-key"):
            raise ValueError("missing REALITY public key")
        options["reality"] = {"enabled": True, "public_key": str(reality["public-key"]),
                              "short_id": str(reality.get("short-id", ""))}
    return options


def _singbox_transport(node):
    network = str(node.get("network", "tcp") or "tcp")
    if network == "tcp":
        return None
    if network == "ws":
        opts = node.get("ws-opts") or {}
        return {"type": "ws", "path": opts.get("path", "/"), "headers": opts.get("headers", {})}
    if network == "grpc":
        opts = node.get("grpc-opts") or {}
        return {"type": "grpc", "service_name": opts.get("grpc-service-name", "")}
    if network in ("h2", "http"):
        opts = node.get("h2-opts") or node.get("http-opts") or {}
        path = opts.get("path") or "/"
        if isinstance(path, list):
            path = path[0] if path else "/"
        return {"type": "http", "host": opts.get("host", []), "path": path}
    raise ValueError("unsupported sing-box transport: " + network)


def _singbox_outbound(node):
    """Best-effort adapter for common protocols; refuse unknown transport semantics."""
    t = str(node.get("type", "")).lower()
    out = {"tag": _name(node), "server": str(node["server"]), "server_port": int(node["port"])}
    if t == "ss":
        if node.get("plugin"):
            raise ValueError("Shadowsocks plugin needs converter support")
        out.update(type="shadowsocks", method=str(node["cipher"]), password=str(node["password"]))
    elif t in ("vless", "vmess"):
        out.update(type=t, uuid=str(node["uuid"]))
        if t == "vless":
            if str(node.get("encryption", "none") or "none") != "none":
                raise ValueError("VLESS Encryption needs converter support")
            if node.get("flow"):
                out["flow"] = str(node["flow"])
        else:
            out["security"] = str(node.get("cipher", "auto"))
            out["alter_id"] = int(node.get("alterId", 0))
        if _singbox_tls(node):
            out["tls"] = _singbox_tls(node)
        transport = _singbox_transport(node)
        if transport:
            out["transport"] = transport
    elif t in ("trojan", "anytls"):
        if t == "anytls" and any(node.get(x) for x in ("shadow-tls-opts", "restls-opts", "jls-opts")):
            raise ValueError("special AnyTLS wrapping needs converter support")
        out.update(type=t, password=str(node["password"]), tls=_singbox_tls(node, required=True))
        if t == "trojan":
            transport = _singbox_transport(node)
            if transport:
                out["transport"] = transport
    elif t == "hysteria2":
        out.update(type=t, password=str(node["password"]), tls=_singbox_tls(node, required=True))
        if node.get("obfs"):
            out["obfs"] = {"type": str(node["obfs"]), "password": str(node["obfs-password"])}
        for dest, source in (("up_mbps", "up"), ("down_mbps", "down")):
            if node.get(source):
                out[dest] = int(node[source])
        if node.get("ports"):
            raise ValueError("port hopping needs converter support")
    elif t == "tuic":
        if node.get("token"):
            raise ValueError("TUIC v4 is not supported by modern sing-box")
        out.update(type=t, uuid=str(node["uuid"]), password=str(node["password"]),
                   tls=_singbox_tls(node, required=True))
        if node.get("congestion-controller"):
            out["congestion_control"] = str(node["congestion-controller"])
    elif t == "socks5":
        out["type"] = "socks"
        for k in ("username", "password"):
            if node.get(k):
                out[k] = str(node[k])
    elif t == "http":
        out["type"] = "http"
        for k in ("username", "password"):
            if node.get(k):
                out[k] = str(node[k])
        if node.get("tls"):
            out["tls"] = _singbox_tls(node)
    elif t in ("snell", "ssh", "wireguard", "hysteria"):
        raise ValueError("special proxy requires version-specific outbound configuration")
    else:
        raise ValueError("unsupported sing-box type")
    return out


def _surge_types(text):
    section = "proxy" if not any(SECTION.fullmatch(x.strip()) for x in text.splitlines()) else ""
    result = {}
    for item in text.splitlines():
        line = item.strip()
        match = SECTION.fullmatch(line)
        if match:
            section = match.group(1).strip().lower()
            continue
        if section == "proxy" and (match := SURGE_LINE.fullmatch(line)):
            result[match.group(1).strip().casefold()] = match.group(2).lower()
    return result


def _surge_names(text):
    return set(_surge_types(text))


def _insert_surge(profile, lines, new_names):
    if not lines:
        return profile
    rows = profile.splitlines()
    positions = [i for i, row in enumerate(rows) if row.strip().lower() == "[proxy]"]
    if positions:
        start = positions[0] + 1
        end = next((i for i in range(start, len(rows)) if SECTION.fullmatch(rows[i].strip())), len(rows))
        rows[end:end] = lines
    else:
        rows = ["[Proxy]"] + lines + [""] + rows
    # Make recovered nodes reachable through the existing main / auto groups.
    in_group = False
    for i, line in enumerate(rows):
        found = SECTION.fullmatch(line.strip())
        if found:
            in_group = found.group(1).strip().lower() == "proxy group"
            continue
        if not in_group or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() not in {"🔰 节点选择", "♻️ 自动选择", "🚀 节点选择"}:
            continue
        # Insert before group options, so names are never interpreted as options.
        match = re.search(r",\s*(?:url|interval|timeout|tolerance|test-url|update-interval)\s*=", value)
        suffix = ", " + ", ".join(new_names)
        value = value[:match.start()] + suffix + value[match.start():] if match else value.rstrip() + suffix
        rows[i] = name + "=" + value
    return "\n".join(rows).rstrip() + "\n"


def _update_groups(groups, names, *, clash=False):
    for group in groups:
        if not isinstance(group, dict):
            continue
        if group.get("name" if clash else "tag") not in {"🔰 节点选择", "♻️ 自动选择", "🚀 节点选择"}:
            continue
        key = "proxies" if clash else "outbounds"
        members = group.get(key)
        if not isinstance(members, list):
            continue
        for name in names:
            if name not in members:
                members.append(name)


def reconcile(target, content, nodes):
    """Return (complete artifact, counts).

    Never compare to the *previous publication*; a smaller new set is valid.
    Compare only the current, already verified source against its own output.
    Diagnostics contain only aggregate protocol counts, no sensitive endpoints.
    """
    if target not in ("clash", "surge", "singbox"):
        return content, {"restored": 0, "unsupported": {}, "expected": 0, "found": 0}
    original = {_name(n).casefold(): n for n in nodes if isinstance(n, dict) and _name(n)}
    if len(original) != len([n for n in nodes if isinstance(n, dict) and _name(n)]):
        raise CoverageError("current verified nodes have duplicate names")
    if not original:
        raise CoverageError("no verified nodes to audit")
    try:
        if target == "clash":
            data = yaml.safe_load(content)
            existing_types = {_name(n).casefold(): str(n.get("type", "")).lower()
                              for n in data["proxies"] if isinstance(n, dict)}
        elif target == "singbox":
            data = json.loads(content)
            existing_types = {str(n.get("tag", "")).strip().casefold(): str(n.get("type", "")).lower()
                              for n in data["outbounds"] if isinstance(n, dict)}
        else:
            data = None
            existing_types = _surge_types(content)
        existing = set(existing_types)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise CoverageError("cannot parse converted " + target + " artifact") from None
    recovered, recovered_names, unsupported, failures = [], [], Counter(), Counter()
    supported_types = SURGE_TYPES if target == "surge" else SINGBOX_TYPES
    for name, node in original.items():
        t = str(node.get("type", "")).lower()
        if name in existing:
            allowed_type = t
            if target == "singbox":
                allowed_type = {"ss": "shadowsocks", "socks5": "socks"}.get(t, t)
            elif target == "surge" and t == "tuic":
                allowed_type = "tuic" if node.get("token") else "tuic-v5"
            elif target == "surge" and t == "http" and node.get("tls"):
                allowed_type = "https"
            elif target == "surge" and t == "socks5" and node.get("tls"):
                allowed_type = "socks5-tls"
            if existing_types[name] != allowed_type:
                raise CoverageError(f"{target} converted node protocol mismatch ({t}); keeping previous Gist")
            continue
        if target != "clash" and t not in supported_types:
            unsupported[t] += 1
            continue
        try:
            if target == "clash":
                recovered.append({k: copy.deepcopy(v) for k, v in node.items()
                                  if k not in PRIVATE_META and not k.startswith("_")})
            elif target == "surge":
                recovered.append(_surge_line(node))
            else:
                recovered.append(_singbox_outbound(node))
            recovered_names.append(_name(node))
        except (ValueError, TypeError, KeyError, AttributeError):
            failures[t] += 1
    if failures:
        summary = ", ".join(f"{k}:{v}" for k, v in sorted(failures.items()))
        raise CoverageError(f"{target} has supported protocols without safe conversion ({summary}); keeping previous Gist")
    if recovered:
        if target == "clash":
            data["proxies"].extend(recovered)
            _update_groups(data.get("proxy-groups", []), recovered_names, clash=True)
            content = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
        elif target == "singbox":
            data["outbounds"].extend(recovered)
            _update_groups(data["outbounds"], recovered_names)
            content = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        else:
            content = _insert_surge(content, recovered, recovered_names)
    if target == "clash":
        found = {_name(n).casefold() for n in yaml.safe_load(content)["proxies"]}
    elif target == "singbox":
        found = {str(n.get("tag", "")).casefold() for n in json.loads(content)["outbounds"]}
    else:
        found = _surge_names(content)
    target_supported = sum(target == "clash" or str(n.get("type", "")).lower() in supported_types
                           for n in original.values())
    expected_names = {name for name, n in original.items()
                      if target == "clash" or str(n.get("type", "")).lower() in supported_types}
    if not expected_names.issubset(found):
        raise CoverageError("converted " + target + " still missing compatible nodes")
    by_protocol = {}
    for source in original.values():
        typ = str(source.get("type", "")).lower()
        if target != "clash" and typ not in supported_types:
            continue
        item = by_protocol.setdefault(typ, {"expected": 0, "found": 0})
        item["expected"] += 1
        if _name(source).casefold() in found:
            item["found"] += 1
    return content, {"restored": len(recovered), "unsupported": dict(unsupported),
                     "expected": target_supported, "found": len(found & expected_names),
                     "by_protocol": by_protocol}
