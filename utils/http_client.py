"""
HTTP Client Helper - Pure Python stdlib (zero external dependencies)
Author: Sharlix | Milkyway Intelligence
Uses: asyncio + urllib + ssl + concurrent.futures
"""

import asyncio
import ssl
import urllib.parse
import urllib.request
import urllib.error
import json as json_mod
from typing import Optional, Dict, Tuple
import concurrent.futures

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=30)


def _sync_request(url: str, headers: dict, proxy: Optional[str], timeout: int,
                  method: str = "GET", body: Optional[bytes] = None
                  ) -> Tuple[Optional[int], Optional[bytes], Optional[Dict]]:
    """Blocking HTTP request using only urllib"""
    try:
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        # Ignore SSL errors
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))

        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(), {}
        except Exception:
            return e.code, b"", {}
    except Exception:
        return None, None, None


async def async_get(
    url: str,
    config,
    timeout: Optional[int] = None,
    allow_redirects: bool = True,
    extra_headers: Optional[Dict] = None
) -> Tuple[Optional[int], Optional[bytes], Optional[Dict]]:
    t = timeout or config.timeout
    headers = config.get_headers()
    if extra_headers:
        headers.update(extra_headers)
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, _sync_request, url, headers, config.proxy, t, "GET", None),
            timeout=t + 3
        )
    except Exception:
        return None, None, None


async def async_post(
    url: str,
    config,
    data: Optional[Dict] = None,
    json_data: Optional[Dict] = None,
    timeout: Optional[int] = None,
    extra_headers: Optional[Dict] = None
) -> Tuple[Optional[int], Optional[bytes], Optional[Dict]]:
    t = timeout or config.timeout
    headers = config.get_headers()
    if extra_headers:
        headers.update(extra_headers)

    post_body = None
    if json_data:
        post_body = json_mod.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif data:
        post_body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, _sync_request, url, headers, config.proxy, t, "POST", post_body),
            timeout=t + 3
        )
    except Exception:
        return None, None, None
