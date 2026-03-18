"""
Internal Recon Builder
Author: Sharlix | Milkyway Intelligence
Builds internal attack surface from extracted data and probes it
"""

import asyncio
import re
from typing import Dict, List
from utils.http_client import async_get


class InternalReconBuilder:
    # Common internal ports to probe
    COMMON_PORTS = [
        80, 443, 8080, 8443, 8000, 8001, 8008, 8081,
        9000, 9001, 9090, 9200, 9300,  # Elasticsearch
        3000, 3001, 3306, 3389,
        5000, 5432, 5601,  # Kibana
        6060, 6379, 6443,  # Redis, k8s
        7001, 7474,         # Cassandra, Neo4j
        4567, 4848,
        2375, 2376,         # Docker
        10250, 10255,       # Kubelet
    ]

    # Common internal paths per service
    SERVICE_PATHS = {
        "admin": ["/admin", "/admin/", "/admin/login", "/admin/dashboard"],
        "api": ["/api", "/api/v1", "/api/v2", "/api/v3", "/swagger", "/swagger-ui"],
        "debug": ["/debug", "/debug/pprof/", "/debug/vars", "/metrics", "/_status"],
        "files": ["/files", "/uploads", "/static", "/assets", "/data"],
        "internal": ["/internal", "/internal/api", "/_internal", "/__internal"],
        "k8s": ["/healthz", "/readyz", "/api/v1/namespaces", "/api/v1/pods"],
    }

    def __init__(self, extracted: Dict, config, logger):
        self.extracted = extracted
        self.config = config
        self.logger = logger

    async def build_and_probe(self) -> List[Dict]:
        """Build internal targets from extracted data and probe them"""
        targets = self._build_target_list()
        self.logger.info(f"Probing {len(targets)} internal targets...")

        found_services = []
        semaphore = asyncio.Semaphore(self.config.threads)

        async def probe(target_info):
            async with semaphore:
                url = target_info["url"]
                status, body, headers = await async_get(url, self.config, timeout=5)
                if status and status not in (404,):
                    service_info = {
                        "url": url,
                        "status": status,
                        "size": len(body) if body else 0,
                        "type": target_info.get("type", "unknown"),
                        "headers": headers or {},
                    }
                    if body:
                        service_info["snippet"] = body[:500].decode("latin-1", errors="replace")
                    found_services.append(service_info)
                    self.logger.found("INTERNAL SERVICE", f"{url} [{status}]")
                if self.config.delay:
                    await asyncio.sleep(self.config.delay)

        tasks = [probe(t) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        return found_services

    def _build_target_list(self) -> List[Dict]:
        """Build list of internal targets to probe"""
        targets = []

        # 1. From extracted internal URLs
        for url in self.extracted.get("internal_urls", []):
            targets.append({"url": url, "type": "extracted_url"})
            # Also add common paths to extracted hosts
            host_match = re.match(r'(https?://[^/]+)', url)
            if host_match:
                host = host_match.group(1)
                for category, paths in self.SERVICE_PATHS.items():
                    for path in paths[:2]:
                        targets.append({"url": host + path, "type": f"derived_{category}"})

        # 2. From IP addresses found
        for ip in self.extracted.get("ip_addresses", []):
            ip = ip.strip()
            for port in self.COMMON_PORTS[:15]:  # limit ports
                base = f"http://{ip}:{port}"
                targets.append({"url": base + "/", "type": "ip_port_scan"})
                # Add debug paths for likely dev ports
                if port in [8080, 9000, 8000, 6060]:
                    targets.append({"url": base + "/debug/pprof/", "type": "pprof_recheck"})
                    targets.append({"url": base + "/metrics", "type": "metrics"})

        # 3. Always probe localhost with common ports
        localhost_bases = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
        ]
        for base in localhost_bases:
            for port in [80, 8080, 8000, 9000, 6060, 5000, 3000]:
                targets.append({"url": f"{base}:{port}/", "type": "localhost_probe"})
                targets.append({"url": f"{base}:{port}/debug/pprof/", "type": "localhost_pprof"})

        # Deduplicate
        seen = set()
        unique = []
        for t in targets:
            if t["url"] not in seen:
                seen.add(t["url"])
                unique.append(t)

        return unique[:200]  # limit total targets
