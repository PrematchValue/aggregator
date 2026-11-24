"""One output-only group layout for the existing SubConverter Clash / Surge profiles.

Rules and protocol conversion remain owned by SubConverter. This layer only
replaces policy groups with a deterministic, icon-bearing regional hierarchy.
It never edits proxy endpoints, DNS, subscription data, or converted rules.
"""
from __future__ import annotations

import re

import yaml

ICON_BASE = "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/"
ICONS = {
    "节点选择": "Proxy.png",
    "苹果服务": "Apple.png",
    "苹果推送": "iCloud.png",
    "谷歌服务": "Google_Search.png",
    "GitHub服务": "GitHub.png",
    "微软服务": "Windows.png",
    "国际媒体": "Streaming.png",
    "港台番剧": "bilibili_3.png",
    "人工智能": "Bot.png",
    "TikTok": "TikTok.png",
    "Telegram": "Telegram.png",
    "数字资产": "Cryptocurrency_3.png",
    "冷钱包": "Lock.png",
    "漏网之鱼": "Final.png",
    "香港节点": "Hong_Kong.png",
    "台湾节点": "Taiwan.png",
    "日本节点": "Japan.png",
    "狮城节点": "Singapore.png",
    "美国节点": "United_States.png",
    "特殊节点": "Available.png",
}
SERVICES = (
    "人工智能", "苹果推送", "苹果服务", "微软服务", "谷歌服务",
    "GitHub服务", "TikTok", "国际媒体", "港台番剧",
    "Telegram", "数字资产", "冷钱包", "漏网之鱼",
)
REGIONS = (
    ("香港节点", "🇭🇰 香港 "),
    ("台湾节点", "🇹🇼 台湾 "),
    ("日本节点", "🇯🇵 日本 "),
    ("狮城节点", "🇸🇬 新加坡 "),
    ("美国节点", "🇺🇸 美国 "),
)
SPECIAL = "特殊节点"


def region_of(name: str) -> str:
    for group, prefix in REGIONS:
        if name.startswith(prefix):
            return group
    return SPECIAL


def build_members(names: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    if not names or len(names) != len(set(names)):
        raise ValueError("empty or duplicate proxy names")
    if any(n in ICONS or n in {"DIRECT", "REJECT", "国内直连"} for n in names):
        raise ValueError("proxy name conflicts with policy group")
    by_region: dict[str, list[str]] = {group: [] for group, _ in REGIONS}
    by_region[SPECIAL] = []
    for name in names:
        by_region[region_of(name)].append(name)
    enabled = [name for name, _ in REGIONS if by_region[name]]
    if by_region[SPECIAL]:
        enabled.append(SPECIAL)
    if not enabled:
        raise ValueError("no region with supported proxies")
    return enabled, by_region


def service_choices(name: str, enabled: list[str], direct: str) -> list[str]:
    """Move only the requested first choice; retain all other relative order."""
    if name == "漏网之鱼":
        return ["节点选择", direct]
    choices = [*enabled, direct]
    first = {"苹果服务": direct, "港台番剧": direct,
             "人工智能": "日本节点", "TikTok": "日本节点",
             "GitHub服务": "香港节点", "微软服务": "美国节点"}.get(name)
    if first in choices:
        choices.remove(first)
        choices.insert(0, first)
    return choices


def groups_for_clash(names: list[str]) -> list[dict]:
    enabled, by_region = build_members(names)
    groups = [{"name": "节点选择", "type": "select", "proxies": enabled,
               "icon": ICON_BASE + ICONS["节点选择"]}]
    for name in SERVICES:
        groups.append({"name": name, "type": "select",
                       "proxies": service_choices(name, enabled, "国内直连"),
                       "icon": ICON_BASE + ICONS[name]})
    for name in enabled:
        group = {"name": name, "type": "select", "proxies": by_region[name],
                 "icon": ICON_BASE + ICONS[name]}
        if name != SPECIAL:
            group.update(type="url-test", url="https://www.gstatic.com/generate_204",
                         interval=600, tolerance=50, lazy=True)
        groups.append(group)
    return groups


def _replace_yaml_root_group(text: str, groups: list[dict]) -> str:
    # Preserve existing DNS, proxy and rule formatting instead of re-dumping
    # the entire full profile (which would drop comments and rewrite nodes).
    new_part = yaml.safe_dump({"proxy-groups": groups}, allow_unicode=True,
                              sort_keys=False, width=1000).rstrip() + "\n"
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines)
              if re.match(r"^(?:proxy-groups|Proxy Group)\s*:", line)]
    if len(starts) > 1:
        raise ValueError("multiple root proxy group sections")
    if starts:
        a = starts[0]
        b = next((i for i in range(a + 1, len(lines))
                  if re.match(r"^[A-Za-z][^\n]*:\s*", lines[i])), len(lines))
        lines[a:b] = [new_part]
        return "".join(lines)
    insert = next((i for i, line in enumerate(lines)
                   if re.match(r"^(?:rules|Rule)\s*:", line)), None)
    if insert is None:
        raise ValueError("no rule root in Clash profile")
    lines.insert(insert, new_part)
    return "".join(lines)


def _add_clash_direct_alias(text: str) -> str:
    """Append a native Mihomo direct proxy without altering real proxy entries."""
    lines = text.splitlines(keepends=True)
    headers = [i for i, line in enumerate(lines)
               if re.fullmatch(r"(?:proxies|Proxy):[ \t]*\r?\n?", line)]
    if len(headers) != 1:
        raise ValueError("Clash proxy list must use a single block-style root")
    a = headers[0]
    b = next((i for i in range(a + 1, len(lines))
              if re.match(r"^[A-Za-z][^\n]*:", lines[i])), len(lines))
    if b <= a + 1:
        raise ValueError("empty Clash proxy block")
    # Group generation is already complete. A native outbound alias is not a group.
    first = next((re.match(r"^([ 	]*)-\s", line) for line in lines[a + 1:b]
                  if re.match(r"^[ 	]*-\s", line)), None)
    if first is None:
        raise ValueError("Clash proxy entries must use a block list")
    indent = first.group(1)
    alias = f"{indent}- name: 国内直连\n{indent}  type: direct\n"
    lines.insert(b, alias)
    return "".join(lines)


def _add_surge_direct_alias(text: str) -> str:
    """Surge built-in policy alias: one [Proxy] line, no extra selector."""
    if re.search(r"(?m)^国内直连[ \t]*=", text):
        raise ValueError("duplicate 国内直连 policy")
    marker = "[Proxy]\n"
    if text.count(marker) != 1:
        raise ValueError("expected one [Proxy] section")
    return text.replace(marker, marker + "国内直连 = direct\n", 1)


def _clash_layout(text: str) -> str:
    obj = yaml.safe_load(text)
    if not isinstance(obj, dict):
        raise ValueError("Clash profile is not a mapping")
    proxies = obj.get("proxies", obj.get("Proxy"))
    if not isinstance(proxies, list) or not proxies:
        raise ValueError("Clash profile has no nodes")
    names = [p.get("name") for p in proxies if isinstance(p, dict)]
    if len(names) != len(proxies) or not all(isinstance(n, str) and n for n in names):
        raise ValueError("invalid Clash proxy name")
    result = _replace_yaml_root_group(text, groups_for_clash(names))
    result = _add_clash_direct_alias(result)
    changed = yaml.safe_load(result)
    changed_proxies = changed.get("proxies", changed.get("Proxy"))
    if changed_proxies != [*proxies, {"name": "国内直连", "type": "direct"}]:
        raise ValueError("node definitions changed while adding direct alias")
    if changed.get("rules", changed.get("Rule")) != obj.get("rules", obj.get("Rule")):
        raise ValueError("routing rules changed while generating groups")
    if changed.get("dns") != obj.get("dns"):
        raise ValueError("DNS changed while generating groups")
    return result


def _sections(text: str) -> list[tuple[str, int, int]]:
    headings = list(re.finditer(r"(?m)^\[([^\]\r\n]+)\][ \t]*$", text))
    return [(m.group(1).strip().lower(), m.start(), headings[i + 1].start()
             if i + 1 < len(headings) else len(text)) for i, m in enumerate(headings)]


def _surge_layout(text: str) -> str:
    sections = _sections(text)
    proxy = next(((a, b) for n, a, b in sections if n == "proxy"), None)
    if not proxy or not any(n == "rule" for n, _, _ in sections):
        raise ValueError("Surge profile lacks [Proxy] or [Rule]")
    entries = text[proxy[0]:proxy[1]].splitlines()[1:]
    names = []
    for line in entries:
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        matched = re.match(r"\s*([^=\r\n]+?)\s*=\s*([A-Za-z][\w-]*)\s*,", line)
        if matched:
            names.append(matched.group(1).strip())
    enabled, _ = build_members(names)
    icon = lambda name: f"icon-url={ICON_BASE}{ICONS[name]}"
    group_lines = ["[Proxy Group]",
                   "节点选择 = select, " + ", ".join([*enabled, icon("节点选择")])]
    group_lines.extend(
        f"{name} = select, {', '.join(service_choices(name, enabled, '国内直连'))}, {icon(name)}"
        for name in SERVICES
    )
    for name in enabled:
        if name == SPECIAL:
            excluded = "|".join([*(prefix for _, prefix in REGIONS), "国内直连$"])
            pattern = f"^(?!(?:{excluded}))"
        else:
            pattern = "^" + next(p for n, p in REGIONS if n == name)
        kind = "select" if name == SPECIAL else "smart"
        group_lines.append(f"{name} = {kind}, include-all-proxies=true, "
                           f"policy-regex-filter={pattern}, {icon(name)}")
    replacement = "\n".join(group_lines) + "\n\n"
    existing = next(((a, b) for n, a, b in sections if n == "proxy group"), None)
    if existing:
        updated = text[:existing[0]] + replacement + text[existing[1]:]
    else:
        rule_start = next(a for n, a, _ in sections if n == "rule")
        updated = text[:rule_start] + replacement + text[rule_start:]
    return _add_surge_direct_alias(updated)


def apply_profile_layout(profile: str, target: str) -> str:
    if not profile or not profile.strip():
        raise ValueError("empty profile")
    if target == "clash":
        return _clash_layout(profile)
    if target == "surge":
        return _surge_layout(profile)
    raise ValueError(f"unsupported layout target: {target}")
