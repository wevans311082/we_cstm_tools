"""HTTP intel: swagger, graphql, dirlisting, ds_store, actuator, open proxy."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any

from va_workspace.tools._common import emit, probe_parser

_PATHS = (
    ("/swagger.json", "swagger"),
    ("/swagger/index.html", "swagger"),
    ("/openapi.json", "openapi"),
    ("/v2/api-docs", "swagger"),
    ("/graphql", "graphql"),
    ("/graphiql", "graphql"),
    ("/.ds_store", "ds_store"),
    ("/actuator", "actuator"),
    ("/actuator/health", "actuator"),
    ("/actuator/env", "actuator"),
    ("/server-status", "apache-status"),
    ("/server-info", "apache-info"),
)


def _fetch(url: str, timeout: float, method: str = "GET") -> tuple[int, bytes, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "va-workspace"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return int(resp.status), resp.read(4000), str(resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as exc:
        body = exc.read(500) if exc.fp else b""
        return int(exc.code), body, ""
    except (OSError, urllib.error.URLError):
        return 0, b"", ""


def probe(host: str, port: int, timeout: float = 6.0) -> dict[str, Any]:
    scheme = "https" if port in {443, 8443, 4443} else "http"
    hits: list[str] = []
    listing = "no"
    graphql = "no"
    swagger = "no"
    proxy = "no"
    for path, kind in _PATHS:
        status, body, ctype = _fetch(f"{scheme}://{host}:{port}{path}", timeout)
        if status != 200 or not body:
            continue
        text = body.decode("utf-8", errors="replace")
        low = text.lower()
        hits.append(f"{path}:{status}")
        if kind in {"swagger", "openapi"} and ("swagger" in low or "openapi" in low):
            swagger = "yes"
        if kind == "graphql" and ("__schema" in low or "graphql" in low or status == 200):
            # POST introspection separately
            graphql = "maybe"
        if kind == "ds_store" and (body[:8] == b"\x00\x00\x00\x01Bud1" or b"Bud1" in body[:32]):
            hits.append("ds_store:confirmed")
        if "<title>index of" in low or "directory listing" in low:
            listing = "yes"
    status, body, _ = _fetch(f"{scheme}://{host}:{port}/", timeout)
    low = body.decode("utf-8", errors="replace").lower()
    if "<title>index of" in low or "parent directory" in low:
        listing = "yes"
        hits.append("/:dirlisting")
    # GraphQL introspection
    gstatus, gbody, _ = _fetch(f"{scheme}://{host}:{port}/graphql?query=%7B__typename%7D", timeout)
    if gstatus == 200 and (b"__typename" in gbody or b'"data"' in gbody):
        graphql = "yes"
        hits.append("/graphql:introspection")
    try:
        import http.client

        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("CONNECT", "example.com:443")
        resp = conn.getresponse()
        if resp.status == 200:
            proxy = "yes"
        conn.close()
    except OSError:
        pass
    return {
        "probe": "http_intel",
        "host": host,
        "port": port,
        "hits": hits,
        "dirlisting": listing,
        "graphql": graphql,
        "swagger": swagger,
        "open_proxy": proxy,
        "interesting": "yes" if hits or listing == "yes" or swagger == "yes" else "no",
    }


def main() -> None:
    args = probe_parser("HTTP intel pack").parse_args()
    emit(args.out, probe(args.host, args.port, args.timeout))


if __name__ == "__main__":
    main()
