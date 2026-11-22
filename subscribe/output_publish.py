"""Keep each converted format independent when updating a single Gist."""
from __future__ import annotations


def publication_groups(targets: list[tuple], records: dict[str, str]) -> list[tuple[str, list[str]]]:
    """Return per-platform Gist PATCH groups; Surge's two files are atomic."""
    groups = []
    for target in targets:
        filename, target_name = target[1], target[2]
        if filename not in records:
            continue
        filenames = [filename]
        if target_name == "surge":
            if "surge-proxy.conf" not in records:
                continue
            filenames.append("surge-proxy.conf")
        groups.append((target_name, filenames))
    return groups
