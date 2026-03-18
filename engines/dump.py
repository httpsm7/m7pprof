"""
Dump Engine - Smart pprof Data Dumper
Author: Sharlix | Milkyway Intelligence
"""

import asyncio
import os
from typing import List, Dict
from utils.http_client import async_get


class DumpEngine:
    # Profiles with their dump strategies
    DUMP_CONFIGS = {
        "heap":         {"path": "/debug/pprof/heap",         "params": "?debug=2", "binary": True},
        "goroutine":    {"path": "/debug/pprof/goroutine",    "params": "?debug=2", "binary": False},
        "goroutine_b":  {"path": "/debug/pprof/goroutine",    "params": "?debug=1", "binary": False},
        "threadcreate": {"path": "/debug/pprof/threadcreate", "params": "?debug=2", "binary": False},
        "block":        {"path": "/debug/pprof/block",        "params": "?debug=1", "binary": True},
        "mutex":        {"path": "/debug/pprof/mutex",        "params": "?debug=1", "binary": False},
        "allocs":       {"path": "/debug/pprof/allocs",       "params": "?debug=1", "binary": True},
        "cmdline":      {"path": "/debug/pprof/cmdline",      "params": "",         "binary": False},
        "symbol":       {"path": "/debug/pprof/symbol",       "params": "",         "binary": False},
        "trace":        {"path": "/debug/pprof/trace",        "params": "?seconds=2", "binary": True},
        "profile_1s":   {"path": "/debug/pprof/profile",     "params": "?seconds=1", "binary": True},
    }

    def __init__(self, base_url: str, endpoints: List[str], config, logger):
        self.base_url = base_url
        self.endpoints = endpoints
        self.config = config
        self.logger = logger

    async def dump_all(self) -> Dict[str, bytes]:
        """Dump all pprof profiles"""
        results = {}
        semaphore = asyncio.Semaphore(self.config.threads)

        async def fetch_dump(name, cfg):
            async with semaphore:
                url = self.base_url + cfg["path"] + cfg["params"]
                self.logger.debug(f"Dumping: {url}")
                status, body, headers = await async_get(url, self.config)
                if status == 200 and body:
                    results[name] = body
                    size = len(body)
                    self.logger.debug(f"  [{name}] {size} bytes")
                if self.config.delay:
                    await asyncio.sleep(self.config.delay)

        tasks = [fetch_dump(name, cfg) for name, cfg in self.DUMP_CONFIGS.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Also fetch any discovered endpoints
        for ep in self.endpoints:
            if ep not in [self.base_url + c["path"] for c in self.DUMP_CONFIGS.values()]:
                status, body, _ = await async_get(ep, self.config)
                if status == 200 and body:
                    key = ep.split("/")[-1] or "index"
                    results[f"discovered_{key}"] = body

        self.logger.info(f"Dump complete: {len(results)} profiles collected")
        return results

    def save_raw(self, dumps: Dict[str, bytes], output_dir: str, url: str):
        """Save raw dumps to disk"""
        import re
        safe_name = re.sub(r'[^\w\-]', '_', url.replace("http://","").replace("https://",""))
        os.makedirs(output_dir, exist_ok=True)

        for name, data in dumps.items():
            fname = os.path.join(output_dir, f"{safe_name}_{name}_raw.bin")
            with open(fname, "wb") as f:
                f.write(data)
        self.logger.success(f"Raw dumps saved to {output_dir}/")
