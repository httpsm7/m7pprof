"""
Config Module
Author: Sharlix | Milkyway Intelligence
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class Config:
    threads: int = 10
    timeout: int = 15
    decode_depth: int = 3
    delay: float = 0
    proxy: Optional[str] = None
    waf_bypass: bool = False
    user_agent: Optional[str] = None
    custom_headers: Dict = field(default_factory=dict)
    verbose: bool = False
    output_dir: str = "results"
    no_color: bool = False

    def get_proxies(self):
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    def get_headers(self):
        headers = {
            "User-Agent": self.user_agent or "Go-http-client/1.1",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        if self.waf_bypass:
            import random
            waf_agents = [
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "curl/7.68.0",
                "python-requests/2.28.0",
            ]
            headers["User-Agent"] = random.choice(waf_agents)
            headers["X-Forwarded-For"] = f"127.0.0.{random.randint(1,254)}"
            headers["X-Real-IP"] = "127.0.0.1"
            headers["X-Originating-IP"] = "127.0.0.1"
            headers["X-Remote-IP"] = "127.0.0.1"
            headers["X-Remote-Addr"] = "127.0.0.1"
        headers.update(self.custom_headers)
        return headers
