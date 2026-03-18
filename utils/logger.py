"""
Logger Module
Author: Sharlix | Milkyway Intelligence
"""

import sys
import datetime


class Logger:
    def __init__(self, verbose=False, no_color=False):
        self.verbose = verbose
        self.no_color = no_color

        if no_color:
            self.C = {k: "" for k in ["cyan","purple","yellow","red","green","blue","white","reset","bold","dim"]}
        else:
            self.C = {
                "cyan":   "\033[96m",
                "purple": "\033[95m",
                "yellow": "\033[93m",
                "red":    "\033[91m",
                "green":  "\033[92m",
                "blue":   "\033[94m",
                "white":  "\033[97m",
                "reset":  "\033[0m",
                "bold":   "\033[1m",
                "dim":    "\033[2m",
            }

    def _ts(self):
        return datetime.datetime.now().strftime("%H:%M:%S")

    def info(self, msg):
        c = self.C
        print(f"{c['blue']}[{self._ts()}]{c['reset']} {c['white']}[*]{c['reset']} {msg}")

    def success(self, msg):
        c = self.C
        print(f"{c['blue']}[{self._ts()}]{c['reset']} {c['green']}[+]{c['reset']} {msg}")

    def warning(self, msg):
        c = self.C
        print(f"{c['blue']}[{self._ts()}]{c['reset']} {c['yellow']}[!]{c['reset']} {msg}")

    def error(self, msg):
        c = self.C
        print(f"{c['blue']}[{self._ts()}]{c['reset']} {c['red']}[-]{c['reset']} {msg}", file=sys.stderr)

    def debug(self, msg):
        if self.verbose:
            c = self.C
            print(f"{c['blue']}[{self._ts()}]{c['reset']} {c['dim']}[D]{c['reset']} {msg}")

    def found(self, label, value):
        c = self.C
        print(f"{c['blue']}[{self._ts()}]{c['reset']} {c['purple']}[FOUND]{c['reset']} {c['bold']}{label}:{c['reset']} {c['yellow']}{value}{c['reset']}")

    def phase(self, msg):
        c = self.C
        width = 60
        bar = "═" * width
        print(f"\n{c['cyan']}{c['bold']}╔{bar}╗")
        print(f"║  {msg:<{width-2}}║")
        print(f"╚{bar}╝{c['reset']}")

    def banner(self, msg):
        c = self.C
        print(f"\n{c['purple']}{c['bold']}{'▓' * 3} {msg} {'▓' * 3}{c['reset']}")

    def result(self, label, items, color="yellow"):
        c = self.C
        if items:
            print(f"\n{c['bold']}{c[color]}  [{label}]{c['reset']}")
            for item in items[:20]:  # limit display
                print(f"    {c['white']}→{c['reset']} {item}")
            if len(items) > 20:
                print(f"    {c['dim']}... and {len(items)-20} more{c['reset']}")
