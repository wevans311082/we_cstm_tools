"""Detect common SSL-VPN / published-access portals (unauth HTTP)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any

from va_workspace.tools._common import emit, probe_parser

PATHS: tuple[tuple[str, str], ...] = (
    ("/remote/login", "fortigate"),
    ("/remote/logincheck", "fortigate"),
    ("/global-protect/login.esp", "globalprotect"),
    ("/global-protect/portal/portal.esp", "globalprotect"),
    ("/dana-na/auth/url_default/welcome.cgi", "pulse-ivanti"),
    ("/+CSCOE+/logon.html", "cisco-asa"),
    ("/+CSCOE+/logon.html?fcadbadd=1", "cisco-asa"),
    ("/logon/LogonPoint/index.html", "citrix"),
    ("/logon/LogonPoint/tmindex.html", "citrix"),
    ("/vpn/index.html", "generic-vpn"),
    ("/dana/home/index.cgi", "pulse-ivanti"),
    ("/RDWeb/Pages/en-US/login.aspx", "rd-gateway"),
    ("/owa/", "exchange"),
    ("/remote/fgt_lang", "fortigate"),
)


def _get(url: str, timeout: float) -> tuple[int, str, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "va-workspace"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(800).decode("utf-8", errors="replace")
            return int(resp.status), body, str(resp.headers.get("Server", ""))
    except urllib.error.HTTPError as exc:
        body = exc.read(400).decode("utf-8", errors="replace") if exc.fp else ""
        return int(exc.code), body, ""
    except (OSError, urllib.error.URLError):
        return 0, "", ""


def probe(host: str, port: int, timeout: float = 6.0) -> dict[str, Any]:
    scheme = "https" if port in {443, 4443, 8443, 10443} else "http"
    if port in {80, 8080, 8000}:
        scheme = "http"
    hits: list[str] = []
    products: list[str] = []
    for path, product in PATHS:
        url = f"{scheme}://{host}:{port}{path}"
        status, body, _server = _get(url, timeout)
        if status in {0, 404}:
            continue
        blob = body.lower()
        if status in {200, 301, 302, 401, 403} or product.split("-")[0] in blob:
            hits.append(f"{path}:{status}")
            if product not in products:
                products.append(product)
    return {
        "probe": "vpn_portals",
        "host": host,
        "port": port,
        "hits": hits,
        "products": products,
        "portal": "yes" if products else "no",
    }


def main() -> None:
    args = probe_parser("SSL VPN / published access detector").parse_args()
    emit(args.out, probe(args.host, args.port, args.timeout))


if __name__ == "__main__":
    main()
