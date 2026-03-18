"""
Extraction Engine - Intelligent Data Extraction
Author: Sharlix | Milkyway Intelligence
Extracts: JWT tokens, API keys, Bearer tokens, cookies, internal URLs, 
          file paths, Go stack traces, function names, high-entropy strings
"""

import re
import math
import string
from typing import Dict, List
from collections import Counter


class ExtractionEngine:
    # Regex patterns for sensitive data
    PATTERNS = {
        "jwt": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        "bearer_token": r'[Bb]earer\s+([A-Za-z0-9\-._~+/]+=*)',
        "api_key_generic": r'(?:api[_-]?key|apikey|api[_-]?token)["\s:=]+([A-Za-z0-9\-._]{20,})',
        "aws_access_key": r'(?:AKIA|AIPA|AROA|ASIA)[A-Z0-9]{16}',
        "aws_secret": r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)["\s:=]+([A-Za-z0-9/+]{40})',
        "gcp_key": r'AIza[0-9A-Za-z\-_]{35}',
        "github_token": r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
        "private_key": r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----',
        "password_field": r'(?:password|passwd|pwd)["\s:=]+([^\s"\'&;]{6,})',
        "db_url": r'(?:mysql|postgres|mongodb|redis|sqlite)://[^\s"\'<>]+',
        "internal_url": r'https?://(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|0\.0\.0\.0)[:/][^\s"\'<>]*',
        "url_generic": r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,}',
        "file_path_unix": r'(?:/(?:etc|var|home|root|usr|opt|tmp|proc|sys|dev)/[^\s"\'<>;]*)',
        "file_path_windows": r'[A-Za-z]:\\[^\s"\'<>;\\]+',
        "ipv4": r'\b(?:127|10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        "port_service": r'(?:localhost|127\.0\.0\.1)[:.](\d{3,5})',
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "cookie": r'(?:session|token|auth|csrf)[_-]?(?:id|token)?["\s:=]+([A-Za-z0-9\-._=+/]{16,})',
        "go_func": r'(?:github\.com|golang\.org)/[a-zA-Z0-9/_.-]+\.[a-zA-Z]+\(',
        "goroutine": r'goroutine\s+\d+\s+\[[^\]]+\]',
        "env_var": r'(?:export\s+)?([A-Z_]{3,})\s*=\s*([^\s\n]{4,})',
    }

    # High-entropy detection
    ENTROPY_THRESHOLD = 4.5
    MIN_ENTROPY_LEN = 20

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def extract_all(self, decoded_chunks: List[str]) -> Dict:
        """Extract all sensitive data from decoded chunks"""
        combined_text = "\n".join(decoded_chunks)

        results = {
            "tokens": [],
            "api_keys": [],
            "passwords": [],
            "internal_urls": [],
            "external_urls": [],
            "file_paths": [],
            "ip_addresses": [],
            "emails": [],
            "stack_traces": [],
            "go_functions": [],
            "env_vars": [],
            "high_entropy": [],
            "db_urls": [],
            "raw_findings": {},
        }

        # Apply all regex patterns
        for pattern_name, pattern in self.PATTERNS.items():
            try:
                matches = re.findall(pattern, combined_text)
                matches = [m if isinstance(m, str) else m[0] for m in matches]
                matches = list(set([m.strip() for m in matches if len(m.strip()) > 3]))

                if matches:
                    self.logger.debug(f"  [{pattern_name}]: {len(matches)} found")
                    results["raw_findings"][pattern_name] = matches

                    # Categorize findings
                    if pattern_name in ["jwt", "bearer_token", "cookie"]:
                        results["tokens"].extend(matches)
                    elif pattern_name in ["api_key_generic", "aws_access_key", "aws_secret", "gcp_key", "github_token"]:
                        results["api_keys"].extend(matches)
                    elif pattern_name in ["internal_url"]:
                        results["internal_urls"].extend(matches)
                    elif pattern_name in ["url_generic"]:
                        results["external_urls"].extend(matches)
                    elif pattern_name in ["file_path_unix", "file_path_windows"]:
                        results["file_paths"].extend(matches)
                    elif pattern_name in ["ipv4", "port_service"]:
                        results["ip_addresses"].extend(matches)
                    elif pattern_name in ["email"]:
                        results["emails"].extend(matches)
                    elif pattern_name in ["go_func"]:
                        results["go_functions"].extend(matches)
                    elif pattern_name in ["goroutine"]:
                        results["stack_traces"].extend(matches)
                    elif pattern_name in ["env_var"]:
                        results["env_vars"].extend([f"{m[0]}={m[1]}" if isinstance(m, tuple) else m for m in matches])
                    elif pattern_name in ["db_url"]:
                        results["db_urls"].extend(matches)
                    elif pattern_name in ["password_field"]:
                        results["passwords"].extend(matches)

            except re.error as e:
                self.logger.debug(f"Regex error for {pattern_name}: {e}")

        # High entropy string detection
        entropy_hits = self._find_high_entropy_strings(combined_text)
        results["high_entropy"] = entropy_hits

        # Deduplicate
        for key in results:
            if isinstance(results[key], list):
                results[key] = list(dict.fromkeys(results[key]))

        # Log summary
        for key, val in results.items():
            if isinstance(val, list) and val:
                self.logger.found(key.upper(), f"{len(val)} item(s)")

        return results

    def _find_high_entropy_strings(self, text: str) -> List[str]:
        """Find high-entropy strings that might be secrets"""
        candidates = []
        # Look for standalone tokens/strings
        word_pattern = r'[A-Za-z0-9+/=_\-]{%d,80}' % self.MIN_ENTROPY_LEN
        words = re.findall(word_pattern, text)

        for word in set(words):
            entropy = self._calculate_entropy(word)
            if entropy >= self.ENTROPY_THRESHOLD:
                candidates.append(word)

        return candidates[:50]  # limit output

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
