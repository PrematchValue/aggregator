"""Country lookup ONCE through a node that already passed upstream Clash check.

No second liveness test, multiple retries, fake country from entry IP, or
batch-isolation recursion. Unknown country is not assigned a made-up flag.
"""
from __future__ import annotations

import hashlib
import re
from location import ISO_TO_CHINESE, ProxyInfo, ProxyQueryResult, make_proxy_request

SERVICES = (
    ("https://ipwho.is", "country_code"),
    ("https://ipinfo.io", "country"),
    ("https://api.ip2location.io", "country_code"),
)


def locate_once(proxy: dict, port: int) -> ProxyQueryResult:
    name = str(proxy.get("name", ""))
    info = ProxyInfo(name=name)
    if not port:
        return ProxyQueryResult(proxy=proxy, result=info, success=False)
    seed = f"{proxy.get('type', '')}:{proxy.get('server', '')}:{proxy.get('port', '')}"
    index = int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16) % len(SERVICES)
    url, key = SERVICES[index]
    try:
        ok, data = make_proxy_request(port=port, url=url, max_retries=1, timeout=7, quiet=True)
        code = (data.get(key, "").strip().upper() if ok and isinstance(data, dict)
                and isinstance(data.get(key), str) else "")
        if re.fullmatch(r"[A-Z]{2}", code) and code in ISO_TO_CHINESE:
            proxy["_verified_http"] = True
            return ProxyQueryResult(
                proxy=proxy, result=ProxyInfo(name=name, country=ISO_TO_CHINESE[code]), success=True
            )
    except Exception:
        pass
    proxy["_verified_http"] = False
    return ProxyQueryResult(proxy=proxy, result=info, success=False)
