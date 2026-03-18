#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║         m7pprof - Advanced pprof Exploit Chaining Tool   ║
║         Author  : Sharlix                                ║
║         Org     : Milkyway Intelligence                   ║
║         Version : 1.0.0                                  ║
╚══════════════════════════════════════════════════════════╝
"""

import asyncio
import argparse
import sys
import os
import json
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.banner import print_banner
from core.target import TargetManager
from engines.discovery import DiscoveryEngine
from engines.dump import DumpEngine
from engines.decode import AutoDecodeEngine
from engines.extractor import ExtractionEngine
from engines.recon import InternalReconBuilder
from engines.exploit_chain import ExploitChainEngine
from engines.validation import ValidationEngine
from engines.report import ReportEngine
from utils.logger import Logger
from utils.config import Config


async def main():
    parser = argparse.ArgumentParser(
        description="m7pprof - Advanced pprof Exploit Chaining Tool by Milkyway Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 m7pprof.py -u http://target.com:6060
  python3 m7pprof.py -u http://target.com:6060 --full-chain
  python3 m7pprof.py -u http://target.com:6060 --burst --threads 20
  python3 m7pprof.py -u http://target.com:6060 --proxy http://127.0.0.1:8080
  python3 m7pprof.py -l targets.txt --full-chain
        """
    )

    # Target options
    target_group = parser.add_argument_group("Target")
    target_group.add_argument("-u", "--url", help="Single target URL")
    target_group.add_argument("-l", "--list", help="File with list of target URLs")
    target_group.add_argument("-p", "--port", type=int, default=6060, help="Default pprof port (default: 6060)")

    # Scan modes
    mode_group = parser.add_argument_group("Scan Modes")
    mode_group.add_argument("--full-chain", action="store_true", help="Run full exploit chain (SSRF → RCE)")
    mode_group.add_argument("--dump-only", action="store_true", help="Only dump pprof data")
    mode_group.add_argument("--recon-only", action="store_true", help="Only do internal recon")
    mode_group.add_argument("--burst", action="store_true", help="Enable burst attack mode")

    # Engine options
    engine_group = parser.add_argument_group("Engine Options")
    engine_group.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    engine_group.add_argument("--timeout", type=int, default=15, help="Request timeout seconds (default: 15)")
    engine_group.add_argument("--depth", type=int, default=3, help="Recursive decode depth (default: 3)")
    engine_group.add_argument("--delay", type=float, default=0, help="Delay between requests (default: 0)")

    # Bypass options
    bypass_group = parser.add_argument_group("Bypass & Evasion")
    bypass_group.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    bypass_group.add_argument("--waf-bypass", action="store_true", help="Enable WAF bypass headers")
    bypass_group.add_argument("--user-agent", help="Custom User-Agent string")
    bypass_group.add_argument("--headers", help="Custom headers as JSON string")

    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", default="results", help="Output directory (default: results)")
    output_group.add_argument("--json", action="store_true", help="Output JSON report")
    output_group.add_argument("--quiet", action="store_true", help="Suppress banner")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Print banner
    if not args.quiet:
        print_banner()

    # Validate input
    if not args.url and not args.list:
        parser.print_help()
        print("\n[!] Error: Provide -u <url> or -l <file>")
        sys.exit(1)

    # Init config
    config = Config(
        threads=args.threads,
        timeout=args.timeout,
        decode_depth=args.depth,
        delay=args.delay,
        proxy=args.proxy,
        waf_bypass=args.waf_bypass,
        user_agent=args.user_agent,
        custom_headers=json.loads(args.headers) if args.headers else {},
        verbose=args.verbose,
        output_dir=args.output,
        no_color=args.no_color
    )

    logger = Logger(verbose=args.verbose, no_color=args.no_color)

    # Build target list
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        if not os.path.exists(args.list):
            logger.error(f"Target file not found: {args.list}")
            sys.exit(1)
        with open(args.list) as f:
            targets.extend([line.strip() for line in f if line.strip()])

    logger.info(f"Loaded {len(targets)} target(s)")
    logger.info(f"Mode: {'Full Chain' if args.full_chain else 'Dump Only' if args.dump_only else 'Standard'}")

    # Process each target
    all_results = []
    for target_url in targets:
        logger.banner(f"TARGET: {target_url}")
        result = await process_target(target_url, args, config, logger)
        all_results.append(result)

    # Summary
    logger.success(f"\n[✓] All targets processed. Results in: {args.output}/")
    if args.json:
        summary_file = os.path.join(args.output, "summary.json")
        with open(summary_file, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        logger.success(f"[✓] JSON summary: {summary_file}")


async def process_target(url: str, args, config, logger):
    """Full pipeline for single target"""
    start_time = time.time()
    results = {
        "target": url,
        "tokens": [],
        "internal_urls": [],
        "ssrf": [],
        "rce_paths": [],
        "metadata": [],
        "risk": "LOW",
        "endpoints_found": []
    }

    try:
        # [1] Target validation
        target_mgr = TargetManager(url, config, logger)
        base_url = target_mgr.normalize()

        # [2] Endpoint Discovery
        logger.phase("PHASE 1: Endpoint Discovery")
        discovery = DiscoveryEngine(base_url, config, logger)
        endpoints = await discovery.discover()
        results["endpoints_found"] = endpoints
        logger.success(f"Found {len(endpoints)} pprof endpoints")

        if not endpoints:
            logger.warning("No pprof endpoints found, trying default paths...")
            endpoints = discovery.get_default_endpoints(base_url)

        # [3] Traffic injection (boost memory activity)
        logger.phase("PHASE 2: Traffic Injection (Memory Boost)")
        await discovery.inject_traffic(base_url)

        # [4] Smart Dump Engine
        logger.phase("PHASE 3: Smart Dump Engine")
        dumper = DumpEngine(base_url, endpoints, config, logger)
        raw_dumps = await dumper.dump_all()
        logger.success(f"Collected {len(raw_dumps)} profile dumps")

        if args.dump_only:
            dumper.save_raw(raw_dumps, args.output, url)
            return results

        # [5] Auto Decode Engine
        logger.phase("PHASE 4: Auto Decode Engine")
        decoder = AutoDecodeEngine(config, logger)
        decoded_data = decoder.decode_all(raw_dumps)
        logger.success(f"Decoded {len(decoded_data)} data chunks")

        # [6] Intelligent Extraction
        logger.phase("PHASE 5: Intelligent Extraction")
        extractor = ExtractionEngine(config, logger)
        extracted = extractor.extract_all(decoded_data)
        results["tokens"] = extracted.get("tokens", [])
        results["internal_urls"] = extracted.get("internal_urls", [])
        results["api_keys"] = extracted.get("api_keys", [])
        results["file_paths"] = extracted.get("file_paths", [])
        results["stack_traces"] = extracted.get("stack_traces", [])

        logger.success(f"Tokens: {len(results['tokens'])} | Internal URLs: {len(results['internal_urls'])}")

        if args.recon_only:
            _save_and_report(results, args, url, start_time, logger)
            return results

        # [7] Internal Recon Builder
        logger.phase("PHASE 6: Internal Recon Builder")
        recon = InternalReconBuilder(extracted, config, logger)
        internal_targets = await recon.build_and_probe()
        results["internal_services"] = internal_targets
        logger.success(f"Internal services found: {len(internal_targets)}")

        if args.full_chain:
            # [8] Exploit Chaining Engine
            logger.phase("PHASE 7: Exploit Chaining Engine")
            chain = ExploitChainEngine(base_url, extracted, internal_targets, config, logger)
            chain_results = await chain.run_all_phases()
            results["ssrf"] = chain_results.get("ssrf", [])
            results["rce_paths"] = chain_results.get("rce_paths", [])
            results["metadata"] = chain_results.get("metadata", [])
            results["lfi"] = chain_results.get("lfi", [])

            logger.success(f"SSRF: {len(results['ssrf'])} | RCE Paths: {len(results['rce_paths'])}")

        # [9] Validation Engine
        logger.phase("PHASE 8: Validation")
        validator = ValidationEngine(results, config, logger)
        results = await validator.validate()

        # Risk scoring
        results["risk"] = _calculate_risk(results)

    except KeyboardInterrupt:
        logger.warning("\n[!] Interrupted by user")
    except Exception as e:
        logger.error(f"Error processing {url}: {e}")
        if config.verbose:
            import traceback
            traceback.print_exc()

    # [10] Report Engine
    logger.phase("PHASE 9: Report Generation")
    elapsed = time.time() - start_time
    results["scan_time"] = f"{elapsed:.2f}s"
    _save_and_report(results, args, url, start_time, logger)

    return results


def _save_and_report(results, args, url, start_time, logger):
    """Save results and generate report"""
    reporter = ReportEngine(results, args.output, logger)
    reporter.save_all(url)


def _calculate_risk(results):
    score = 0
    if results.get("tokens"): score += 30
    if results.get("ssrf"): score += 40
    if results.get("rce_paths"): score += 60
    if results.get("metadata"): score += 50
    if results.get("api_keys"): score += 35
    if results.get("lfi"): score += 45

    if score >= 80: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"


if __name__ == "__main__":
    asyncio.run(main())
