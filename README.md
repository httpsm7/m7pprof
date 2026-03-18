# m7pprof — Advanced pprof Exploit Chaining Tool

```
 ███╗   ███╗███████╗██████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ████╗ ████║╚════██║██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔════╝
 ██╔████╔██║    ██╔╝██████╔╝██████╔╝██████╔╝██║   ██║█████╗
 ██║╚██╔╝██║   ██╔╝ ██╔═══╝ ██╔═══╝ ██╔══██╗██║   ██║██╔══╝
 ██║ ╚═╝ ██║   ██║  ██║     ██║     ██║  ██║╚██████╔╝██║
 ╚═╝     ╚═╝   ╚═╝  ╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝
```

**Author:** Sharlix  
**Org:** Milkyway Intelligence  
**Version:** 1.0.0  
**Flow:** `pprof Exposure → Data Leak → Internal Recon → SSRF → RCE`

> For authorized security testing and bug bounty only.

---

## Features

| Engine | Description |
|--------|-------------|
| 🔍 Discovery | 20+ pprof endpoint paths auto-discovered |
| 💥 Dump | All profile types: heap, goroutine, cmdline, trace, etc. |
| 🔓 Auto Decode | gzip, base64, hex, URL, binary strings — recursive depth 3–5 |
| 🧠 Extraction | JWT, Bearer tokens, API keys, AWS/GCP/GitHub keys, DB URLs, file paths, Go stack traces, env vars, high-entropy secrets |
| 🌐 Internal Recon | Builds attack surface from extracted IPs/URLs, probes 20+ ports |
| ⛓️ Exploit Chain | SSRF → Internal Enum → RCE Detection → LFI → Cloud Metadata |
| ✅ Validation | JWT structure check, endpoint confirmation |
| 📊 Report | HTML dashboard + JSON + TXT per finding type |

---

## Installation (Single Command)

```bash
git clone https://github.com/httpsm7/m7pprof
cd m7pprof
bash install.sh
```

**Zero external dependencies** — runs on Python 3.7+ stdlib only (asyncio, urllib, ssl, gzip, base64).

---

## Usage

```bash
# Basic scan
m7pprof -u http://target.com:6060

# Full exploit chain (SSRF → RCE → Cloud Metadata)
m7pprof -u http://target.com:6060 --full-chain

# Dump only
m7pprof -u http://target.com:6060 --dump-only

# Multiple targets with Burp proxy
m7pprof -l targets.txt --proxy http://127.0.0.1:8080

# WAF bypass + fast threads
m7pprof -u http://target.com:6060 --waf-bypass --threads 20

# Full chain + JSON output + verbose
m7pprof -u http://target.com:6060 --full-chain --json -v

# Custom headers (e.g. auth)
m7pprof -u http://target.com:6060 --headers '{"Authorization":"Bearer mytoken"}'
```

---

## All Options

```
Target:
  -u URL           Single target URL
  -l FILE          File with list of target URLs
  -p PORT          Default port (default: 6060)

Scan Modes:
  --full-chain     SSRF → Internal Enum → RCE → LFI → Cloud Metadata
  --dump-only      Only collect pprof dumps
  --recon-only     Only internal recon (no exploit chain)
  --burst          High-speed burst dump mode

Engine:
  --threads N      Concurrent threads (default: 10)
  --timeout N      Request timeout in seconds (default: 15)
  --depth N        Recursive decode depth (default: 3)
  --delay N        Delay between requests (default: 0)

Bypass:
  --proxy URL      HTTP/HTTPS proxy
  --waf-bypass     Rotate User-Agent + X-Forwarded-For spoofing
  --user-agent UA  Custom User-Agent
  --headers JSON   Custom headers as JSON string

Output:
  -o DIR           Output directory (default: results/)
  --json           Write summary.json
  --quiet          No banner
  --no-color       Disable colors
  -v               Verbose mode
```

---

## Output Files

```
results/
├── target_raw.txt          All raw findings
├── target_sensitive.txt    Tokens, API keys, passwords
├── target_internal.txt     Internal URLs + services
├── target_ssrf.txt         SSRF findings
├── target_rce.txt          RCE indicators
├── target.json             Machine-readable full report
└── target_report.html      Interactive HTML dashboard
```

---

## Risk Scoring

| Score | Level |
|-------|-------|
| Tokens found | +30 |
| API keys | +35 |
| SSRF confirmed | +40 |
| Cloud metadata | +50 |
| LFI | +45 |
| RCE indicators | +60 |

`≥80 = CRITICAL` | `≥50 = HIGH` | `≥20 = MEDIUM` | `<20 = LOW`

---

## Extracted Secrets

- JWT tokens (validated)
- Bearer / session tokens
- AWS Access Keys (AKIA...)
- GCP API Keys (AIza...)
- GitHub tokens (ghp_...)
- Generic API keys
- Database URLs (mysql://, postgres://, redis://)
- Environment variables
- High-entropy strings (Shannon entropy ≥ 4.5)
- File paths (/etc/, /var/, /home/, Windows paths)
- Go stack traces & function names

---

## Legal

This tool is for **authorized security testing only**.  
Use on systems you own or have written permission to test.  
Bug bounty / pentest use only.

**Milkyway Intelligence | Author: Sharlix (httpsm7)**
