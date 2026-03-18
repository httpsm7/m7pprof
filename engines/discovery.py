"""
Discovery Engine - pprof Endpoint Discovery & Traffic Injection
Author: Sharlix | Milkyway Intelligence
"""

import asyncio
from typing import List
from utils.http_client import async_get


class DiscoveryEngine:
    # All known pprof endpoints
    PPROF_PATHS = [
        "/debug/pprof/",
        "/debug/pprof/heap",
        "/debug/pprof/goroutine",
        "/debug/pprof/threadcreate",
        "/debug/pprof/block",
        "/debug/pprof/mutex",
        "/debug/pprof/profile",
        "/debug/pprof/trace",
        "/debug/pprof/cmdline",
        "/debug/pprof/symbol",
        "/debug/pprof/allocs",
        "/debug/pprof/profile?seconds=1",
        # Alternate paths
        "/pprof/",
        "/pprof/heap",
        "/pprof/goroutine",
        "/metrics/pprof",
        "/internal/debug/pprof/",
        "/admin/debug/pprof/",
        "/_debug/pprof/",
        "/api/debug/pprof/",
        # Port variants handled externally
    ]

    TRAFFIC_PATHS = [
        "/", "/login", "/api", "/api/v1", "/api/v2",
        "/search?q=test", "/upload", "/admin",
        "/health", "/metrics", "/status",
        "/api/user", "/api/users", "/api/profile",
        "/register", "/signup", "/checkout",
        "/graphql", "/graphql?query={__typename}",
    ]

    def __init__(self, base_url: str, config, logger):
        self.base_url = base_url
        self.config = config
        self.logger = logger

    async def discover(self) -> List[str]:
        """Discover all accessible pprof endpoints"""
        found = []
        semaphore = asyncio.Semaphore(self.config.threads)

        async def check(path):
            async with semaphore:
                url = self.base_url + path
                status, body, headers = await async_get(url, self.config, timeout=5)
                if status and status in (200, 206):
                    self.logger.debug(f"Found endpoint: {url} [{status}]")
                    found.append(url)
                if self.config.delay:
                    await asyncio.sleep(self.config.delay)

        tasks = [check(path) for path in self.PPROF_PATHS]
        await asyncio.gather(*tasks)
        return found

    def get_default_endpoints(self, base_url: str) -> List[str]:
        """Return default pprof endpoint list without checking"""
        return [base_url + p for p in [
            "/debug/pprof/heap",
            "/debug/pprof/goroutine",
            "/debug/pprof/cmdline",
            "/debug/pprof/",
        ]]

    async def inject_traffic(self, base_url: str):
        """Inject traffic to increase memory activity for better dumps"""
        self.logger.info("Injecting traffic to boost memory activity...")
        semaphore = asyncio.Semaphore(5)

        async def hit(path):
            async with semaphore:
                url = base_url + path
                await async_get(url, self.config, timeout=3)

        tasks = [hit(p) for p in self.TRAFFIC_PATHS[:10]]  # limit to 10
        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.debug("Traffic injection complete")
