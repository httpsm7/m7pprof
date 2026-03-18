"""
Validation Engine - Validate Findings
Author: Sharlix | Milkyway Intelligence
"""

import asyncio
import re
from typing import Dict
from utils.http_client import async_get


class ValidationEngine:
    def __init__(self, results: Dict, config, logger):
        self.results = results
        self.config = config
        self.logger = logger

    async def validate(self) -> Dict:
        """Validate tokens, endpoints, and SSRF findings"""
        self.logger.info("Validating findings...")

        # Validate JWT tokens
        if self.results.get("tokens"):
            valid_jwts = self._validate_jwts(self.results["tokens"])
            self.results["valid_jwts"] = valid_jwts
            if valid_jwts:
                self.logger.found("VALID JWT", f"{len(valid_jwts)} token(s) found")

        # Validate internal services
        if self.results.get("internal_services"):
            confirmed = [s for s in self.results["internal_services"] if s.get("status") in (200, 301, 302, 401, 403)]
            self.results["confirmed_internal"] = confirmed
            if confirmed:
                self.logger.found("CONFIRMED INTERNAL", f"{len(confirmed)} service(s)")

        # Mark confirmed SSRF
        if self.results.get("ssrf"):
            confirmed_ssrf = [s for s in self.results["ssrf"] if s.get("cloud_platform") or s.get("size", 0) > 50]
            self.results["confirmed_ssrf"] = confirmed_ssrf

        return self.results

    def _validate_jwts(self, tokens):
        """Check JWT structure validity"""
        valid = []
        for token in tokens:
            parts = token.split(".")
            if len(parts) == 3:
                try:
                    import base64
                    # Check header and payload are valid base64 JSON
                    header = base64.b64decode(parts[0] + "==").decode("utf-8", errors="replace")
                    payload = base64.b64decode(parts[1] + "==").decode("utf-8", errors="replace")
                    if '"alg"' in header or '"typ"' in header:
                        valid.append({
                            "token": token,
                            "header": header[:100],
                            "payload": payload[:200],
                        })
                except Exception:
                    pass
        return valid
