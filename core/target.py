"""
Target Manager
Author: Sharlix | Milkyway Intelligence
"""

from urllib.parse import urlparse, urlunparse


class TargetManager:
    def __init__(self, url: str, config, logger):
        self.url = url
        self.config = config
        self.logger = logger

    def normalize(self) -> str:
        """Normalize and validate the target URL"""
        url = self.url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        # Reconstruct clean URL
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        self.logger.debug(f"Normalized URL: {base}")
        return base

    def get_host(self) -> str:
        parsed = urlparse(self.url)
        return parsed.hostname

    def get_port(self) -> int:
        parsed = urlparse(self.url)
        return parsed.port or (443 if parsed.scheme == "https" else 80)
