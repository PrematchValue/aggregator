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
MAX_SOURCE = 15 * 1024 * 1024
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


def attach_from_source(text, nodes, stats=None):
    """Extract explicit host-scoped settings; optionally count real parser outcomes."""
    if stats is None:
        stats = {}
    def count(key, amount=1):
        stats[key] = stats.get(key, 0) + amount
    count('sources')
    for node in nodes:
        if isinstance(node, dict):
            node.pop(KEY, None)
    count('nodes', len(nodes))
    hosts = [node for node in nodes if isinstance(node, dict) and host_name(node.get('server'))]
    count('domain_nodes', len(hosts))
    if not isinstance(text, str) or not text.strip():
        count('empty'); return nodes
    if len(text) > MAX_SOURCE:
        count('oversize'); return nodes
    text = text.lstrip('\ufeff')
    fixed, specific, general, default = {}, {}, {}, None
    surge_rows = None
    if re.search(r'(?mi)^\s*\[(?:Host|Proxy|General)\]\s*$', text):
        count('surge')
        surge_rows = _surge_entries(text)
        if re.search(r'(?mi)^\s*\[Host\]\s*$', text):
            count('host_section')
        entries = len(surge_rows)
    else:
        # Recognize quoted YAML keys and JSON-style Clash profiles as well.
        structured = re.search(r"(?m)^\s*['\"]?(?:dns|hosts|proxies|proxy-providers)['\"]?\s*:", text)
        if not structured and not text.lstrip().startswith('{'):
            count('unstructured'); return nodes
        try:
            doc = yaml.safe_load(text)
        except (yaml.YAMLError, RecursionError, ValueError, TypeError):
            count('parse_error'); return nodes
        if not isinstance(doc, dict) or not any(k in doc for k in ('dns', 'hosts', 'proxies', 'proxy-providers')):
            count('unsupported'); return nodes
        count('clash')
        dns = doc.get('dns')
        if isinstance(dns, dict):
            count('dns_section')
        if isinstance(doc.get('hosts'), dict):
            count('host_section')
        if not isinstance(dns, dict):
            dns = {}
        fixed = doc.get('hosts', {}) if dns.get('use-hosts') is not False and dns.get('enable') is not False else {}
        if dns.get('enable') is not False:
            specific = dns.get('proxy-server-nameserver-policy', {})
            general = dns.get('nameserver-policy', {})
            default = dns.get('proxy-server-nameserver')
        else:
            count('dns_disabled')
        entries = sum(len(m) for m in (fixed, specific, general) if isinstance(m, dict)) + int(default is not None)
    count('entries', entries)
    count('sources_with_entries' if entries else 'sources_without_entries')
    for node in hosts:
        host = host_name(node.get('server'))
        found, h = False, None
        if surge_rows is not None:
            for pattern, kind, values in surge_rows:
                if _surge_match(pattern, host):
                    found, h = True, hint(kind, values)
                    break
        else:
            found, h = _best(fixed, host, 'ip')
            if not found:
                found, h = _best(specific, host, 'dns')
            if not found:
                found, h = _best(general, host, 'dns')
            if not found and default is not None:
                found, h = True, hint('dns', default)
        if found:
            count('matched')
            if h:
                node[KEY] = {'host': host, **h}
                count('attached')
            else:
                count('rejected')
        else:
            count('unmatched')
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


def _endpoint(node):
    if not isinstance(node, dict):
        return None
    host = host_name(node.get('server'))
    try:
        port = int(node.get('port'))
    except (TypeError, ValueError, OverflowError):
        return None
    return (host, port) if host and 1 <= port <= 65535 else None


def _source_endpoints(text):
    """Supplementary profiles must explicitly contain the same host and port.

    Never convert or import nodes from the second response. In particular a
    Host-only module or unrelated profile cannot modify the primary nodes.
    """
    if not isinstance(text, str) or not text or len(text) > MAX_SOURCE:
        return set()
    text = text.lstrip('\ufeff')
    if re.search(r'(?mi)^\s*\[Proxy\]\s*$', text):
        section, endpoints = '', set()
        for raw in text.splitlines():
            line = raw.strip()
            if re.fullmatch(r'\[[^\]]+\]', line):
                section = line[1:-1].strip().lower()
                continue
            if section != 'proxy' or line.startswith(('#', ';', '//')) or '=' not in line:
                continue
            parts = line.split('=', 1)[1].split(',', 3)
            if len(parts) >= 3:
                item = _endpoint({'server': parts[1].strip().strip('"\''), 'port': parts[2].strip()})
                if item:
                    endpoints.add(item)
        return endpoints
    try:
        doc = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError, TypeError):
        return set()
    if not isinstance(doc, dict) or not isinstance(doc.get('proxies'), list):
        return set()
    return {ep for n in doc['proxies'] if (ep := _endpoint(n))}


def _source_format(stats):
    for k in ('empty', 'oversize', 'parse_error', 'unsupported', 'surge', 'clash', 'unstructured'):
        if stats.get(k):
            return {'empty':'空响应','oversize':'超限','parse_error':'解析失败','unsupported':'不支持','surge':'Surge','clash':'Clash','unstructured':'节点文本/其他'}[k]
    return '未知'


def enrich_subscription(text, nodes, url, fetch, log):
    """Bounded content-negotiation probes to the same subscription URL.

    The original download and conversion remain the sole node source. Missing
    hints may be filled from explicit Clash or Surge responses, but only if
    the response actually includes the corresponding endpoint. Neither source
    URLs, hosts nor resolver credentials appear in diagnostic output.
    """
    primary = {}
    attach_from_source(text, nodes, primary)
    initial = primary.get('attached', 0)
    probes = []
    try:
        parsed = urlsplit(url)
        remote = parsed.scheme in ('http', 'https') and bool(parsed.hostname)
    except (TypeError, ValueError):
        remote = False
    if remote:
        for ua in ('Clash.Meta', 'Surge'):
            missing = [n for n in nodes if _endpoint(n) and metadata(n) is None]
            if not missing:
                break
            report = {}
            try:
                extra = fetch(url=url, headers={'User-Agent': ua}, retry=1,
                              timeout=10, trace=False, max_size=MAX_SOURCE)
            except Exception:
                extra = ''
            if not isinstance(extra, str):
                extra = ''
            # Identical content has no additional evidence; avoid reparsing it.
            if extra == text:
                probes.append(f'{ua}=同原响应')
                continue
            # Never attempt to parse arbitrary base64 or other response bodies
            # as YAML when there is no structured DNS section.
            if not re.search(r'(?mi)^\s*\[Proxy\]\s*$', extra) and not re.search(r"(?m)^\s*['\"]?proxies['\"]?\s*:", extra) and not extra.lstrip().startswith('{'):
                probes.append(f'{ua}='+('空响应' if not extra.strip() else '无完整节点配置'))
                continue
            endpoints = _source_endpoints(extra)
            targets = [n for n in missing if _endpoint(n) in endpoints]
            attach_from_source(extra, targets, report)
            probes.append(f'{ua}={_source_format(report)}(条目{report.get("entries",0)}/端点匹配{len(targets)}/匹配DNS{report.get("matched",0)}/拒绝{report.get("rejected",0)}/新增{report.get("attached",0)})')
    total = sum(metadata(n) is not None for n in nodes if isinstance(n, dict))
    log('DNS采集统计：原始格式='+_source_format(primary)+
        f'；节点={len(nodes)}；域名节点={primary.get("domain_nodes",0)}；DNS段={primary.get("dns_section",0)}；Host段={primary.get("host_section",0)}；原始DNS/Host条目={primary.get("entries",0)}'
        f'；匹配={primary.get("matched",0)}；拒绝={primary.get("rejected",0)}；未匹配={primary.get("unmatched",0)}'
        f'；原始提取={initial}；补取={" | ".join(probes) if probes else "未执行"}；总附加={total}')
    return nodes


def log_stage(label, nodes, log):
    hints = [metadata(n) for n in nodes if isinstance(n, dict)]
    hosts = {h['host'] for h in hints if h}
    accepted = mappings(nodes)
    log(f'节点专用 DNS [{label}]：节点={len(nodes)}，带映射节点={sum(h is not None for h in hints)}，'
        f'关联域名={len(hosts)}，可用映射={len(accepted)}，冲突或循环跳过={len(hosts)-len(accepted)}')


def log_profile(label, profile, nodes, log):
    """Count actually rendered, matching entries without exposing any values."""
    hints = mappings(nodes)
    if not hints:
        log(f'节点专用 DNS [{label}]：实际输出=0')
        return
    if label == 'Clash':
        doc = yaml.safe_load(profile)
        fixed = doc.get('hosts', {})
        dns = doc.get('dns', {}).get('proxy-server-nameserver-policy', {})
    else:
        fixed, dns = _surge_hints(profile)
    actual = sum(hint(h['kind'], (fixed if h['kind'] == 'ip' else dns).get(host)) ==
                 {'kind': h['kind'], 'values': h['values']} for host, h in hints.items())
    log(f'节点专用 DNS [{label}]：实际输出={actual}，未输出={len(hints)-actual}')
