"""
m7pprof Banner Module
Author: Sharlix | Milkyway Intelligence
"""

import sys
import os

def print_banner():
    colors = {
        "cyan": "\033[96m",
        "purple": "\033[95m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "green": "\033[92m",
        "blue": "\033[94m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
    }

    c = colors["cyan"]
    p = colors["purple"]
    y = colors["yellow"]
    r = colors["red"]
    g = colors["green"]
    b = colors["blue"]
    w = colors["white"]
    rs = colors["reset"]
    bold = colors["bold"]

    banner = f"""
{c}{bold}
 ███╗   ███╗███████╗██████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ████╗ ████║╚════██║██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔════╝
 ██╔████╔██║    ██╔╝██████╔╝██████╔╝██████╔╝██║   ██║█████╗  
 ██║╚██╔╝██║   ██╔╝ ██╔═══╝ ██╔═══╝ ██╔══██╗██║   ██║██╔══╝  
 ██║ ╚═╝ ██║   ██║  ██║     ██║     ██║  ██║╚██████╔╝██║     
 ╚═╝     ╚═╝   ╚═╝  ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     
{rs}
{p}{bold}        ╔═══════════════════════════════════════════════╗
        ║   pprof → Data Leak → SSRF → RCE Chain        ║
        ║   Author  : Sharlix                            ║
        ║   Org     : Milkyway Intelligence              ║
        ║   Version : 1.0.0                              ║
        ╚═══════════════════════════════════════════════╝{rs}

{y}  [*] Advanced pprof Exploit Chaining Tool{rs}
{r}  [!] For authorized security testing only{rs}
{g}  [+] Use responsibly | Bug Bounty | Pentest{rs}
"""
    print(banner)
