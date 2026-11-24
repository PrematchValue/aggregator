"""Source-scoped node DNS hints; never import arbitrary profile settings.

Hints are internal metadata, kept only for exact proxy server hostnames. The
original hostname/SNI and transport parameters are never rewritten. Public
output accepts source-supplied tokenized HTTPS DNS only with explicit opt-in.
"""
from __future__ import annotations

import ipaddress
import os
import re
from collections import defaultdict
from urllib.parse import urlsplit, parse_qsl

import yaml

KEY = '_airport_dns'
MAX_SOURCE = 4 * 1024 * 1024
MAX_VALUES = 8
_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')


def public_ip(value):
    if not isinstance(value, str):
        return ''
    try:
        ip = ipaddress.ip_address(value)
        return str(ip) if ip.is_global and not ip.is_multicast and not ip.is_reserved else ''
    except (TypeError, ValueError):
        return ''


def host_name(value):
    if not isinstance(value, str):
        return ''
    try:
        host = value.strip().rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        return ''
    if len(host) > 253 or '.' not in host or not all(_LABEL.fullmatch(x) for x in host.split('.')):
        return ''
    try:
        ipaddress.ip_address(host)
        return ''
    except ValueError:
        pass
    if host.rsplit('.', 1)[-1] in {'local', 'localhost', 'lan', 'internal', 'arpa', 'onion', 'invalid', 'test'}:
        return ''
    if host == 'metadata.google.internal' or host.rsplit('.', 1)[-1].isdigit():
        return ''
    return host


def resolver(value):
    if not isinstance(value, str):
        return ''
    value = value.strip()
    if not value or len(value) > 1024 or any(c.isspace() or ord(c) < 32 for c in value) or any(c in value for c in '#@,;\\'):
        return ''
    if ip := public_ip(value):
        return ip
    # Plain DNS with an explicit IPv4 port is portable. For encrypted DNS
    # accept only standard, non-credential-bearing endpoints, no proxy suffix.
    if re.fullmatch(r'\d+\.\d+\.\d+\.\d+:\d+', value):
        ip, port = value.rsplit(':', 1)
        return value if public_ip(ip) and 1 <= int(port) <= 65535 else ''
    try:
        u = urlsplit(value)
        if u.scheme not in {'https', 'tls', 'tcp'} or not u.hostname or u.username or u.password:
            return ''
        if not (public_ip(u.hostname) or host_name(u.hostname)):
            return ''
        if u.port is not None and not 1 <= u.port <= 65535:
            return ''
        if u.scheme == 'https':
            if not re.fullmatch(r'[A-Za-z0-9._~/%+=-]*', u.path):
                return ''
            if not re.fullmatch(r'[A-Za-z0-9._~%+=&/?-]*', u.query):
                return ''
            if (u.query or u.path not in {'', '/', '/dns-query', '/resolve'}) and os.getenv('AGGREGATOR_ALLOW_TOKENIZED_DNS', '').lower() not in {'1', 'true'}:
                return ''
        elif u.query or u.path not in {'', '/'}:
            return ''
        if u.scheme == 'tcp' and not public_ip(u.hostname):
            return ''
        return value
    except ValueError:
        return ''


def _values(value):
    return value if isinstance(value, list) else [value]


def hint(kind, value):
    vals = _values(value)
    if kind not in {'ip', 'dns'} or not vals or len(vals) > MAX_VALUES:
        return None
    normal = [public_ip(x) if kind == 'ip' else resolver(x) for x in vals]
    # Reject the whole mapping if any member is unsafe/unportable; do not
    # silently turn a private resolver into a different public resolver.
    if not all(normal):
        return None
    return {'kind': kind, 'values': sorted(set(normal))}


def metadata(node):
    raw = node.get(KEY)
    if not isinstance(raw, dict) or not host_name(node.get('server')):
        return None
    if raw.get('host') != host_name(node.get('server')):
        return None
    h = hint(raw.get('kind'), raw.get('values'))
    if h is None:
        return None
    return {'host': raw['host'], **h}


def _pattern_score(pattern, host):
    if not isinstance(pattern, str):
        return -1
    pattern = pattern.strip().lower().rstrip('.')
    if host_name(pattern) == host:
        return 1000 + len(host)
    for prefix in ('+.', '*.', '.'):
        if pattern.startswith(prefix):
            suffix = host_name(pattern[len(prefix):])
            if suffix and (host.endswith('.' + suffix) or prefix != '*.' and host == suffix):
                return len(suffix)
    return -1


def _best(mapping, host, kind):
    if not isinstance(mapping, dict):
        return False, None
    options = [(score, hint(kind, value)) for p, value in mapping.items()
               if (score := _pattern_score(p, host)) >= 0]
    if not options:
        return False, None
    best = max(score for score, _ in options)
    choices = [h for score, h in options if score == best]
    return True, choices[0] if choices[0] is not None and all(h == choices[0] for h in choices) else None


def _surge_entries(text):
    section = ''
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1].strip().lower()
            continue
        if section != 'host' or not line or line.startswith(('#', ';', '//')) or '=' not in line:
            continue
        key, val = (x.strip() for x in line.split('=', 1))
        val = re.split(r'\s+//\s+', val, maxsplit=1)[0].strip()
        kind = 'dns' if val.startswith('server:') else 'ip'
        values = [x.strip().removeprefix('server:') for x in (val[7:] if kind == 'dns' else val).split(',')]
        rows.append((key, kind, values))
    return rows


def _surge_hints(text):
    fixed, dns = {}, {}
    seen = set()
    for key, kind, values in _surge_entries(text):
        if key not in seen:
            (dns if kind == 'dns' else fixed)[key] = values
            seen.add(key)
    return fixed, dns


def _surge_match(pattern, host):
    # Surge Host uses first match, with full-host wildcards. Avoid importing
    # blanket catch-all entries or remote rule-set references.
    pattern = pattern.strip().lower().rstrip('.')
    if '.' not in pattern or not re.fullmatch(r'[a-z0-9.*?-]+', pattern):
        return False
    # A wildcard must contain a concrete DNS suffix; no global wildcard.
    tail = re.split(r'[*?]', pattern)[-1].lstrip('.')
    if not host_name(tail):
        return False
    expr = re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.')
    return re.fullmatch(expr, host) is not None


def attach_from_source(text, nodes):
    """Called before source profile data is discarded; no extra network fetch."""
    for node in nodes:
        if isinstance(node, dict):
            node.pop(KEY, None)  # no trust in a source's fabricated metadata
    if not isinstance(text, str) or len(text) > MAX_SOURCE or not nodes:
        return nodes
    text = text.lstrip('\ufeff')
    fixed, specific, general, default = {}, {}, {}, None
    surge_rows = None
    if re.search(r'(?mi)^\s*\[Host\]\s*$', text):
        surge_rows = _surge_entries(text)
    else:
        # URI lists/base64 subscriptions have no structured DNS information.
        if not re.search(r'(?m)^(?:dns|hosts|proxies)\s*:', text):
            return nodes
        try:
            doc = yaml.safe_load(text)
        except (yaml.YAMLError, RecursionError, ValueError, TypeError):
            return nodes
        if not isinstance(doc, dict):
            return nodes
        dns = doc.get('dns')
        if not isinstance(dns, dict):
            dns = {}
        if dns.get('enable') is False:
            return nodes
        fixed = doc.get('hosts', {}) if dns.get('use-hosts') is not False else {}
        specific = dns.get('proxy-server-nameserver-policy', {})
        general = dns.get('nameserver-policy', {})
        # Only an explicitly node-specific default, never the source's generic DNS.
        default = dns.get('proxy-server-nameserver')
    for node in nodes:
        if not isinstance(node, dict) or not (host := host_name(node.get('server'))):
            continue
        if surge_rows is not None:
            for pattern, kind, values in surge_rows:
                if _surge_match(pattern, host):
                    if h := hint(kind, values):
                        node[KEY] = {'host': host, **h}
                    break
            continue
        found, h = _best(fixed, host, 'ip')
        if not found:
            found, h = _best(specific, host, 'dns')
        if not found:
            found, h = _best(general, host, 'dns')
        if not found:
            h = hint('dns', default)
        if h:
            node[KEY] = {'host': host, **h}
    return nodes


def _choices(nodes):
    options = defaultdict(list)
    for n in nodes:
        if isinstance(n, dict) and (m := metadata(n)):
            options[m['host']].append(m)
    return {host: hs[0] if all(h == hs[0] for h in hs) else None for host, hs in options.items()}


def reconcile_sources(fresh, previous=()):
    """Exact hostname scope. Fresh explicit hints override older hints;
    conflicting current hints are omitted, rather than choosing arbitrarily."""
    maps = _choices(previous)
    maps.update(_choices(fresh))
    result = []
    for source in (fresh, previous):
        group = []
        for n in source:
            if not isinstance(n, dict):
                group.append(n)
                continue
            copy = dict(n)
            copy.pop(KEY, None)
            if h := maps.get(host_name(n.get('server'))):
                copy[KEY] = dict(h)
            group.append(copy)
        result.append(group)
    return tuple(result)


def clean_nodes(nodes):
    return [{k: v for k, v in n.items() if k != KEY} for n in nodes]


def mappings(nodes):
    """Only resolved hints from surviving nodes; block resolver-host cycles."""
    choices = _choices(nodes)
    node_hosts = {host_name(n.get('server')) for n in nodes if isinstance(n, dict)}
    result = {}
    for host, h in sorted(choices.items()):
        if not h:
            continue
        if h['kind'] == 'dns' and any(urlsplit(v).hostname in node_hosts for v in h['values'] if '://' in v):
            continue
        result[host] = h
    return result


def mask_credentials(nodes):
    """Register GitHub Actions masks before tests/conversion use these URLs.

    Nothing is written to the terminal in local runs. Do not put these URLs
    in exceptions or summary messages. Masking cannot protect Gist content.
    """
    if os.getenv('GITHUB_ACTIONS', '').lower() != 'true':
        return
    masks = set()
    for h in mappings(nodes).values():
        if h['kind'] != 'dns':
            continue
        for value in h['values']:
            u = urlsplit(value)
            if u.scheme != 'https' or not (u.query or u.path not in {'', '/', '/dns-query', '/resolve'}):
                continue
            masks.add(value)
            for segment in u.path.split('/'):
                if len(segment) >= 8 and segment != 'dns-query':
                    masks.add(segment)
            for _, secret in parse_qsl(u.query, keep_blank_values=False):
                if len(secret) >= 8:
                    masks.add(secret)
    for value in sorted(masks, key=len, reverse=True):
        escaped = value.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print('::add-mask::' + escaped, flush=True)


def apply_mihomo(config, nodes):
    """Extend only node-specific entries. Ordinary configurations are untouched."""
    hints = mappings(nodes)
    if not hints:
        return config
    dns = config.setdefault('dns', {})
    if not isinstance(dns, dict):
        raise ValueError('invalid Mihomo DNS section')
    dns['enable'] = True
    dns.setdefault('nameserver', ['system'])
    dns.setdefault('default-nameserver', ['223.5.5.5', '8.8.8.8'])
    # Mihomo only enables proxy-server-nameserver-policy when this is nonempty.
    dns.setdefault('proxy-server-nameserver', dns['nameserver'])
    if not dns['proxy-server-nameserver']:
        dns['proxy-server-nameserver'] = dns['nameserver']
    for host, h in hints.items():
        if h['kind'] == 'ip':
            dns.setdefault('use-hosts', True)
            if dns.get('use-hosts') is not False:
                config.setdefault('hosts', {}).setdefault(host, h['values'])
        else:
            dns.setdefault('proxy-server-nameserver-policy', {}).setdefault(host, h['values'])
    return config


def _replace_root_block(profile, key, obj):
    lines = profile.splitlines(keepends=True)
    pattern = re.compile(r'^' + re.escape(key) + r'\s*:')
    indices = [i for i, l in enumerate(lines) if pattern.match(l)]
    if len(indices) > 1:
        raise ValueError('duplicate YAML root: ' + key)
    block = yaml.safe_dump({key: obj}, allow_unicode=True, sort_keys=False, width=1000)
    if indices:
        a = indices[0]
        b = next((i for i in range(a + 1, len(lines)) if re.match(r'^[A-Za-z][\w-]*\s*:', lines[i])), len(lines))
        lines[a:b] = [block]
        return ''.join(lines)
    return profile.rstrip('\n') + '\n' + block


def apply_clash_profile(profile, nodes):
    if not mappings(nodes):
        return profile
    doc = yaml.safe_load(profile)
    actual = {(p.get('name'), host_name(p.get('server'))) for p in doc.get('proxies', doc.get('Proxy', [])) if isinstance(p, dict)}
    retained = [n for n in nodes if (n.get('name'), host_name(n.get('server'))) in actual]
    if not mappings(retained):
        return profile
    apply_mihomo(doc, retained)
    profile = _replace_root_block(profile, 'dns', doc['dns'])
    if doc.get('hosts'):
        profile = _replace_root_block(profile, 'hosts', doc['hosts'])
    return profile


def apply_surge_profile(profile, nodes):
    if not mappings(nodes):
        return profile
    section, actual = '', set()
    lines = profile.splitlines(keepends=True)
    host_sections = []
    for i, line in enumerate(lines):
        s = line.strip()
        if re.fullmatch(r'\[[^\]]+\]', s):
            section = s[1:-1].lower()
            if section == 'host':
                host_sections.append(i)
            continue
        if section == 'proxy' and '=' in s:
            name, params = s.split('=', 1)
            parts = params.split(',', 2)
            if len(parts) >= 3:
                actual.add((name.strip(), host_name(parts[1].strip().strip('"'))))
    selected = [n for n in nodes if (n.get('name'), host_name(n.get('server'))) in actual]
    hints = mappings(selected)
    if not hints:
        return profile
    if len(host_sections) > 1:
        raise ValueError('multiple Surge Host sections')
    existing = set()
    if host_sections:
        start = host_sections[0]
        end = next((i for i in range(start + 1, len(lines)) if re.fullmatch(r'\[[^\]]+\]', lines[i].strip())), len(lines))
        existing = {l.split('=', 1)[0].strip().lower() for l in lines[start + 1:end] if '=' in l and not l.lstrip().startswith(('#', ';'))}
    else:
        end = len(lines)
    additions = [host + ' = ' + ('server:' if h['kind'] == 'dns' else '') + ', '.join(h['values']) + '\n' for host, h in hints.items() if host not in existing]
    if not additions:
        return profile
    if host_sections:
        lines[end:end] = ['\n', *additions]
        return ''.join(lines)
    return profile.rstrip('\n') + '\n\n[Host]\n' + ''.join(additions)


def surge_dns_module(profile, nodes):
    """Optional companion for policy-path users. Never include proxy lines.

    Copy only accepted node mappings actually present in the full profile;
    publish an empty, named module on a run with no matching hints, clearing
    any previous stale mappings.
    """
    hints = mappings(nodes)
    fixed, dns = _surge_hints(profile)
    rows = []
    for host, h in hints.items():
        source = fixed if h['kind'] == 'ip' else dns
        if hint(h['kind'], source.get(host)) != {'kind': h['kind'], 'values': h['values']}:
            continue
        rows.append(host + ' = ' + ('server:' if h['kind'] == 'dns' else '') + ', '.join(h['values']))
    return ('#!name=Aggregator 节点专用 DNS\n'
            '#!desc=仅匹配当前已发布节点的服务器域名；纯节点订阅的可选配套模块。\n\n'
            '[Host]\n' + ('\n'.join(rows) if rows else '# 本轮没有可公开的节点专用 DNS 映射') + '\n')
