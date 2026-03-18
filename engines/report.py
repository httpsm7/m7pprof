"""
Report Engine - Full Output & HTML Report Generation
Author: Sharlix | Milkyway Intelligence
"""

import os
import re
import json
import datetime
from typing import Dict


class ReportEngine:
    def __init__(self, results: Dict, output_dir: str, logger):
        self.results = results
        self.output_dir = output_dir
        self.logger = logger

    def save_all(self, target_url: str):
        """Save all result files"""
        os.makedirs(self.output_dir, exist_ok=True)
        safe = re.sub(r'[^\w\-]', '_', target_url.replace("http://","").replace("https://",""))

        files_written = []

        # Raw text file
        raw_file = os.path.join(self.output_dir, f"{safe}_raw.txt")
        self._write_text(raw_file, self._format_raw())
        files_written.append(raw_file)

        # Sensitive findings
        sens_file = os.path.join(self.output_dir, f"{safe}_sensitive.txt")
        self._write_text(sens_file, self._format_sensitive())
        files_written.append(sens_file)

        # Internal URLs
        int_file = os.path.join(self.output_dir, f"{safe}_internal.txt")
        self._write_text(int_file, self._format_internal())
        files_written.append(int_file)

        # SSRF findings
        ssrf_file = os.path.join(self.output_dir, f"{safe}_ssrf.txt")
        self._write_text(ssrf_file, self._format_ssrf())
        files_written.append(ssrf_file)

        # RCE findings
        rce_file = os.path.join(self.output_dir, f"{safe}_rce.txt")
        self._write_text(rce_file, self._format_rce())
        files_written.append(rce_file)

        # JSON report
        json_file = os.path.join(self.output_dir, f"{safe}.json")
        with open(json_file, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        files_written.append(json_file)

        # HTML report
        html_file = os.path.join(self.output_dir, f"{safe}_report.html")
        self._write_text(html_file, self._generate_html(target_url))
        files_written.append(html_file)

        # Print report summary
        self._print_summary(target_url)
        self.logger.success(f"Report files written: {self.output_dir}/")
        for f in files_written:
            self.logger.debug(f"  → {f}")

    def _write_text(self, filepath: str, content: str):
        """Write text content to file"""
        with open(filepath, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)

    def _format_raw(self) -> str:
        lines = ["=" * 60, "m7pprof Raw Findings", "=" * 60, ""]
        for key, val in self.results.items():
            if isinstance(val, list) and val:
                lines.append(f"\n[{key.upper()}]")
                for item in val:
                    lines.append(f"  {item}")
        return "\n".join(lines)

    def _format_sensitive(self) -> str:
        lines = ["=" * 60, "SENSITIVE FINDINGS", "=" * 60, ""]
        for key in ["tokens", "api_keys", "passwords", "high_entropy", "db_urls", "env_vars"]:
            items = self.results.get(key, [])
            if items:
                lines.append(f"\n[{key.upper()}] ({len(items)} found)")
                for item in items:
                    lines.append(f"  {item}")
        return "\n".join(lines)

    def _format_internal(self) -> str:
        lines = ["=" * 60, "INTERNAL SURFACE", "=" * 60, ""]
        for url in self.results.get("internal_urls", []):
            lines.append(url)
        lines.append("\n[INTERNAL SERVICES]")
        for svc in self.results.get("internal_services", []):
            lines.append(f"  {svc.get('url')} [{svc.get('status')}] size={svc.get('size',0)}")
        return "\n".join(lines)

    def _format_ssrf(self) -> str:
        lines = ["=" * 60, "SSRF FINDINGS", "=" * 60, ""]
        for item in self.results.get("ssrf", []):
            lines.append(f"URL   : {item.get('url')}")
            lines.append(f"Param : {item.get('param')} = {item.get('payload')}")
            lines.append(f"Status: {item.get('status')}")
            if item.get("cloud_platform"):
                lines.append(f"Cloud : {item.get('cloud_platform')}")
            lines.append(f"Snippet:\n{item.get('snippet','')[:200]}")
            lines.append("-" * 40)
        return "\n".join(lines)

    def _format_rce(self) -> str:
        lines = ["=" * 60, "RCE INDICATORS", "=" * 60, ""]
        for item in self.results.get("rce_paths", []):
            lines.append(f"URL     : {item.get('url')}")
            lines.append(f"Method  : {item.get('method')}")
            if item.get("payload"):
                lines.append(f"Payload : {item.get('payload')}")
            if item.get("confirmed"):
                lines.append("STATUS  : *** CONFIRMED ***")
            if item.get("output_snippet"):
                lines.append(f"Output  :\n{item.get('output_snippet')}")
            lines.append("-" * 40)
        return "\n".join(lines)

    def _print_summary(self, target_url: str):
        r = self.results
        c = {
            "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
            "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"
        }
        risk = r.get("risk", "LOW")
        risk_color = c["red"] if risk in ("CRITICAL", "HIGH") else c["yellow"] if risk == "MEDIUM" else c["green"]

        print(f"""
{c['cyan']}{c['bold']}╔══════════════════════════════════════════╗
║           SCAN SUMMARY                  ║
╚══════════════════════════════════════════╝{c['reset']}

  Target     : {target_url}
  Risk Level : {risk_color}{c['bold']}{risk}{c['reset']}
  Scan Time  : {r.get('scan_time','?')}

  Tokens Found     : {len(r.get('tokens',[]))}
  API Keys         : {len(r.get('api_keys',[]))}
  Internal URLs    : {len(r.get('internal_urls',[]))}
  Internal Services: {len(r.get('internal_services',[]))}
  SSRF Findings    : {len(r.get('ssrf',[]))}
  RCE Indicators   : {len(r.get('rce_paths',[]))}
  LFI Findings     : {len(r.get('lfi',[]))}
  Cloud Metadata   : {len(r.get('metadata',[]))}
  High Entropy     : {len(r.get('high_entropy',[]))}
""")

    def _generate_html(self, target_url: str) -> str:
        r = self.results
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        risk = r.get("risk", "LOW")
        risk_color = {"CRITICAL": "#ff2244", "HIGH": "#ff6600", "MEDIUM": "#ffcc00", "LOW": "#00cc44"}.get(risk, "#00cc44")

        def section(title, items, color="#00e5ff"):
            if not items:
                return ""
            html = f'<div class="section"><h2 style="color:{color}">{title} <span class="badge">{len(items)}</span></h2><ul>'
            for item in items:
                if isinstance(item, dict):
                    html += f'<li><pre>{json.dumps(item, indent=2, default=str)}</pre></li>'
                else:
                    html += f'<li><code>{_esc(str(item))}</code></li>'
            html += '</ul></div>'
            return html

        def _esc(s):
            return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

        body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>m7pprof Report - {_esc(target_url)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0a0f; color: #c8d8e8; font-family: 'Courier New', monospace; padding: 20px; }}
  .header {{ text-align: center; padding: 30px; border-bottom: 1px solid #1a2a3a; }}
  .title {{ font-size: 2.5em; color: #00e5ff; text-shadow: 0 0 20px #00e5ff88; letter-spacing: 4px; }}
  .subtitle {{ color: #8899aa; margin-top: 8px; }}
  .meta {{ display: flex; gap: 20px; justify-content: center; flex-wrap: wrap; margin: 20px 0; }}
  .meta-item {{ background: #0f1a2a; border: 1px solid #1a3a5a; padding: 10px 20px; border-radius: 8px; }}
  .risk-badge {{ font-size: 1.5em; font-weight: bold; padding: 5px 20px; border-radius: 20px; background: {risk_color}22; border: 2px solid {risk_color}; color: {risk_color}; }}
  .section {{ background: #0d1520; border: 1px solid #1a2a3a; border-radius: 8px; padding: 20px; margin: 15px 0; }}
  .section h2 {{ font-size: 1.1em; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 2px; }}
  .badge {{ background: #1a3a5a; padding: 2px 10px; border-radius: 10px; font-size: 0.8em; }}
  ul {{ list-style: none; padding-left: 10px; }}
  li {{ padding: 6px 0; border-bottom: 1px solid #111820; }}
  code {{ color: #ffcc44; word-break: break-all; font-size: 0.85em; }}
  pre {{ color: #88ccff; font-size: 0.8em; overflow-x: auto; white-space: pre-wrap; }}
  .footer {{ text-align: center; padding: 20px; color: #445566; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <div class="title">m7pprof</div>
  <div class="subtitle">Advanced pprof Exploit Chaining Tool | Milkyway Intelligence by Sharlix</div>
  <div class="meta">
    <div class="meta-item">Target: <strong>{_esc(target_url)}</strong></div>
    <div class="meta-item">Date: <strong>{now}</strong></div>
    <div class="meta-item">Time: <strong>{r.get('scan_time','?')}</strong></div>
    <div class="meta-item risk-badge">{risk}</div>
  </div>
</div>
{section("Tokens (JWT / Bearer / Cookie)", r.get("tokens",[]), "#ff9944")}
{section("API Keys", r.get("api_keys",[]), "#ff5566")}
{section("Passwords", r.get("passwords",[]), "#ff3344")}
{section("High Entropy Strings", r.get("high_entropy",[]), "#ffaa44")}
{section("Internal URLs", r.get("internal_urls",[]), "#44ddff")}
{section("Internal Services", r.get("internal_services",[]), "#44bbff")}
{section("SSRF Findings", r.get("ssrf",[]), "#ff6644")}
{section("RCE Indicators", r.get("rce_paths",[]), "#ff2244")}
{section("LFI Findings", r.get("lfi",[]), "#ff8844")}
{section("Cloud Metadata", r.get("metadata",[]), "#ffdd44")}
{section("File Paths", r.get("file_paths",[]), "#88ff88")}
{section("Database URLs", r.get("db_urls",[]), "#cc88ff")}
{section("Environment Variables", r.get("env_vars",[]), "#88ccff")}
{section("Stack Traces", r.get("stack_traces",[]), "#6699aa")}
{section("Go Functions", r.get("go_functions",[]), "#6688bb")}
<div class="footer">
  Generated by m7pprof v1.0.0 | Milkyway Intelligence | Author: Sharlix<br>
  For authorized security testing and bug bounty only
</div>
</body>
</html>"""
        return body
