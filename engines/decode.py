"""
Auto Decode Engine - Multi-layer Decoding
Author: Sharlix | Milkyway Intelligence
Supports: gzip, base64, hex, URL encoding, binary strings, recursive decoding
"""

import gzip
import base64
import binascii
import urllib.parse
import re
import struct
from typing import Dict, List


class AutoDecodeEngine:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.max_depth = config.decode_depth

    def decode_all(self, raw_dumps: Dict[str, bytes]) -> List[str]:
        """Decode all dump data using multi-layer approach"""
        all_text = []
        for name, data in raw_dumps.items():
            self.logger.debug(f"Decoding: {name} ({len(data)} bytes)")
            decoded_chunks = self._decode_data(data, depth=0)
            all_text.extend(decoded_chunks)
        return all_text

    def _decode_data(self, data: bytes, depth: int) -> List[str]:
        """Recursively decode data using multiple strategies"""
        if depth >= self.max_depth:
            return [self._safe_decode(data)]

        results = []

        # 1. Try as plain text first
        text = self._safe_decode(data)
        if text:
            results.append(text)

        # 2. Try gzip decompression
        try:
            decompressed = gzip.decompress(data)
            self.logger.debug(f"  [gzip] decompressed {len(data)} → {len(decompressed)} bytes")
            results.extend(self._decode_data(decompressed, depth + 1))
        except Exception:
            pass

        # 3. Try as Go pprof binary format - extract strings
        binary_strings = self._extract_binary_strings(data)
        if binary_strings:
            results.append("\n".join(binary_strings))

        # 4. Extract base64 blobs from text and decode
        base64_chunks = self._extract_and_decode_base64(text)
        for chunk in base64_chunks:
            results.extend(self._decode_data(chunk, depth + 1))

        # 5. Extract hex strings and decode
        hex_decoded = self._extract_and_decode_hex(text)
        if hex_decoded:
            results.append(hex_decoded)

        # 6. URL decode
        try:
            url_decoded = urllib.parse.unquote(text)
            if url_decoded != text:
                results.append(url_decoded)
        except Exception:
            pass

        # 7. Double URL decode
        try:
            double_decoded = urllib.parse.unquote(urllib.parse.unquote(text))
            if double_decoded != text:
                results.append(double_decoded)
        except Exception:
            pass

        return results

    def _safe_decode(self, data: bytes) -> str:
        """Safely decode bytes to string"""
        for encoding in ["utf-8", "latin-1", "ascii", "utf-16"]:
            try:
                return data.decode(encoding, errors="replace")
            except Exception:
                pass
        return data.decode("latin-1", errors="replace")

    def _extract_binary_strings(self, data: bytes, min_len: int = 6) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []
        current = []

        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.append("".join(current))
                current = []

        if len(current) >= min_len:
            strings.append("".join(current))

        return strings

    def _extract_and_decode_base64(self, text: str) -> List[bytes]:
        """Find and decode base64 encoded strings"""
        decoded = []
        # Match base64 patterns (min 20 chars to avoid false positives)
        pattern = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}){5,}'
        matches = re.findall(pattern, text)
        for match in matches:
            try:
                decoded_bytes = base64.b64decode(match + "==")
                if len(decoded_bytes) > 10:
                    decoded.append(decoded_bytes)
            except Exception:
                pass
        return decoded

    def _extract_and_decode_hex(self, text: str) -> str:
        """Find and decode hex encoded strings"""
        results = []
        # Match hex strings (min 16 chars = 8 bytes)
        pattern = r'(?:0x)?([0-9a-fA-F]{16,})'
        matches = re.findall(pattern, text)
        for match in matches:
            try:
                if len(match) % 2 == 0:
                    decoded = bytes.fromhex(match)
                    text_decoded = decoded.decode("utf-8", errors="ignore")
                    if text_decoded.isprintable() and len(text_decoded) > 5:
                        results.append(text_decoded)
            except Exception:
                pass
        return "\n".join(results) if results else ""
