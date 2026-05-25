<p align="center">
  <br>
  <strong style="font-size: 2em;">ScanAI</strong>
  <br>
  <em>AI-Powered Penetration Testing Agent for Kali Linux</em>
  <br><br>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/version-0.4.0-green.svg" alt="Version">
  <img src="https://img.shields.io/badge/platform-Kali%20Linux-557C94.svg" alt="Platform">
  <img src="https://img.shields.io/badge/scanners-23-orange.svg" alt="Scanners">
  <img src="https://img.shields.io/badge/profiles-103-orange.svg" alt="Profiles">
</p>

---

## What is ScanAI?

ScanAI is an autonomous AI-powered penetration testing agent. Describe what you want in plain English — ScanAI picks the right scanners, selects optimal profiles, chains them together, correlates findings across modules, identifies attack paths, and generates actionable reports.

No flags. No memorizing syntax. Just tell it what you need.

```
❯ full recon example.com
❯ is this url phishing? https://suspicious-site.com
❯ web attack https://target.com
❯ stealth scan 10.0.0.1
❯ find secrets in github.com/org/repo
❯ wordpress audit blog.example.com
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Natural Language Interface** | Describe your intent — AI maps it to the right scanners and profiles |
| **23 Scanner Modules** | Network, web, OSINT, vulnerability, secrets — all covered |
| **106 YAML Workflow Profiles** | Fine-grained scan configurations, all customizable |
| **9 Attack Chains** | Pre-built multi-scanner sequences for common operations |
| **Smart Correlation Engine** | Cross-scanner intelligence finds attack paths and risk factors |
| **Auto-Chaining** | Results from one scanner automatically trigger follow-up scans |
| **Session Persistence** | Save, load, and resume scan sessions |
| **Report Export** | Markdown and HTML penetration test reports |
| **Multi-Target Scanning** | Scan a list of targets in one command |
| **Titus Integration** | Secrets detection with 459 rules + live credential validation |

---

## Quick Start

### Prerequisites

- **Kali Linux** (required — ScanAI is optimized exclusively for Kali)
- Python 3.10+
- Google Gemini API key (for AI features)
- Optional: VirusTotal, Shodan, URLScan, WPScan API keys

### Installation

```bash
git clone https://git.selfmade.ninja/0xD4rkEYe/scanai.git
cd scanai
chmod +x install.sh
sudo ./install.sh setup
```

The installer automatically:
- Installs all system dependencies (nmap, nikto, sqlmap, etc.)
- Installs Go-based tools (nuclei, dalfox, httpx)
- Downloads **Titus** from [praetorian-inc/titus](https://github.com/praetorian-inc/titus) releases
- Creates a Python virtual environment
- Installs all Python packages
- Sets up the global `scanai` command

> Every tool is checked before installation — if it's already present, it's skipped.

### Configure & Launch

```bash
scanai config --init   # set up API keys interactively
scanai config --check  # verify everything
scanai start           # launch
```

---

## Scanners (23 Modules)

### 🔍 Network & Infrastructure

| Scanner | Profiles | Description |
|---------|----------|-------------|
| **nmap** | 10 | Port scanning, service detection, OS fingerprinting, vuln scripts |
| **dns** | 6 | DNS reconnaissance — zone transfers, brute force, reverse lookups |
| **subdomain** | 4 | Subdomain enumeration via CT logs, brute force, HackerTarget |
| **whois** | 2 | Domain registration and registrar intelligence |
| **ssl** | 4 | TLS/SSL analysis — cipher audit, heartbleed, certificate inspection |
| **ip_geo** | 3 | IP geolocation + Shodan enrichment |
| **enum4linux** | 5 | SMB/NetBIOS enumeration — shares, users, password policies |

**Example prompts:**
```
❯ scan ports on 10.0.0.1
❯ stealth scan 192.168.1.0/24
❯ aggressive nmap scan target.com
❯ find subdomains for example.com
❯ dns zone transfer target.com
❯ check ssl for example.com
❯ smb enum 10.0.0.5
❯ whois example.com
❯ geolocate 8.8.8.8
```

### 🌐 Web Application

| Scanner | Profiles | Description |
|---------|----------|-------------|
| **nikto** | 5 | Web server vulnerability scanner |
| **gobuster** | 6 | Directory/file/vhost brute-forcing |
| **katana** | 8 | Next-gen web crawling — JS parsing, headless, form extraction (projectdiscovery) |
| **dalfox** | 4 | XSS vulnerability scanning with WAF evasion |
| **sqlmap** | 5 | SQL injection detection and exploitation |
| **nuclei** | 6 | Template-based vulnerability scanning (CVEs, exposures, tech detect) |
| **whatweb** | 3 | Technology fingerprinting |
| **server_headers** | 3 | HTTP security header audit and scoring |
| **waf** | 2 | WAF detection and identification (wafw00f) |
| **wpscan** | 5 | WordPress vulnerability scanning |

**Example prompts:**
```
❯ nikto scan example.com
❯ brute force directories on https://target.com
❯ find xss on https://target.com/search?q=test
❯ sqlmap https://target.com/page?id=1
❯ nuclei critical scan target.com
❯ what technologies does example.com use
❯ check security headers on example.com
❯ detect waf on target.com
❯ wordpress scan blog.example.com
❯ crawl https://target.com for forms
❯ headless crawl https://target.com
```

### 🔎 OSINT & Intelligence

| Scanner | Profiles | Description |
|---------|----------|-------------|
| **harvester** | 5 | Email, subdomain, and host harvesting from public sources |
| **virustotal** | 4 | URL/domain/IP reputation and phishing detection |
| **urlscan** | 2 | URL analysis and screenshot capture |
| **cve** | 3 | CVE database lookup with severity and exploitability filters |
| **wayback** | 4 | Wayback Machine historical URL archive |

**Example prompts:**
```
❯ find emails for company.com
❯ is this url phishing? https://suspicious-login.com
❯ virustotal report for evil.com
❯ find cve for apache 2.4.49
❯ wayback archive example.com
❯ urlscan https://target.com
```

### 🔐 Secrets & Credentials

| Scanner | Profiles | Description |
|---------|----------|-------------|
| **titus** | 7 | High-performance secrets scanner — API keys, tokens, credentials (459 rules) |

**Example prompts:**
```
❯ scan for secrets in /path/to/code
❯ find leaked credentials in github.com/org/repo
❯ scan git history for secrets in /path/to/repo
❯ deep scan for secrets with validation
```

---

## Attack Chains (9 Pre-built Sequences)

Attack chains run multiple scanners in sequence with a single prompt. Results flow between stages.

### `quick_recon` — Fast Target Overview

```
❯ quick recon example.com
```
**Flow:** whois → dns → subdomain → nmap
**Use:** First look at a target. Gets domain info, DNS records, subdomains, and open ports in one shot.

---

### `full_recon` — Comprehensive Reconnaissance

```
❯ full recon example.com
```
**Flow:** whois → dns → subdomain → harvester → ip_geo → wayback → nmap → waf → whatweb → server_headers → ssl
**Use:** Complete passive + active recon. 11 scanners cover every angle — domain intel, emails, historical URLs, ports, tech stack, WAF, headers, TLS.

---

### `web_attack` — Web Application Assessment

```
❯ web attack https://target.com
```
**Flow:** waf → nikto → katana → gobuster → dalfox → sqlmap → nuclei
**Use:** Full web app pentest chain. Detects WAF first, then runs vuln scanners, directory brute-force, XSS, SQLi, and template-based CVE checks.

---

### `vuln_assess` — Vulnerability Assessment

```
❯ vuln assess target.com
```
**Flow:** nmap → nuclei → ssl → server_headers
**Use:** Focused vulnerability scan. Finds open services, matches CVE templates, checks TLS config and security headers.

---

### `stealth_recon` — Low-Noise Reconnaissance

```
❯ stealth recon 10.0.0.1
```
**Flow:** whois → dns → subdomain → nmap (stealth profile)
**Use:** Same as quick_recon but uses SYN stealth scan with timing evasion. Minimizes IDS/IPS detection.

---

### `phishing_analysis` — Phishing URL Investigation

```
❯ is this url phishing? https://evil-login-page.com
```
**Flow:** virustotal → urlscan → whois → ssl
**Use:** Checks URL reputation, captures screenshots, inspects domain registration age, and validates certificates. Quick phishing verdict.

---

### `osint_recon` — OSINT Gathering

```
❯ osint recon company.com
```
**Flow:** whois → harvester → subdomain → wayback → dns
**Use:** Passive intelligence gathering. Finds emails, subdomains, archived URLs, DNS records — all without touching the target directly.

---

### `wordpress_audit` — WordPress Security Audit

```
❯ wordpress audit blog.example.com
```
**Flow:** wpscan → nikto → nuclei → server_headers → ssl
**Use:** Complete WordPress assessment. Enumerates plugins/themes/users, checks for known vulns, validates server security.

---

### `internal_pentest` — Internal Network Assessment

```
❯ internal pentest 10.0.0.0/24
```
**Flow:** nmap → enum4linux → nmap (vuln_scripts)
**Use:** Internal network assessment. Discovers hosts and services, enumerates SMB/NetBIOS, then runs NSE vulnerability scripts.

---

## YAML Workflow System

Every scanner is driven by YAML workflow definitions in `scanai/workflows/`. Each file defines multiple profiles with commands, methods, timeouts, and tags that the AI uses for intent matching.

**Example** (`workflows/nmap.yaml`):

```yaml
scanner: nmap
description: "Network port scanning and service detection"
binary: nmap
default_profile: aggressive_scan

profiles:
  stealth_scan:
    description: "SYN stealth scan — low noise"
    command_template: "nmap -sS -T2 -f {target}"
    timeout: 200
    tags: [stealth, syn, evasion]

  aggressive_scan:
    description: "Full aggressive scan — OS, versions, scripts, traceroute"
    command_template: "nmap -A -T4 --max-retries 2 {target}"
    timeout: 300
    tags: [aggressive, full, os, scripts]

  vuln_scripts:
    description: "NSE vulnerability scripts"
    command_template: "nmap --script vuln -sV {target}"
    timeout: 400
    tags: [vuln, scripts, cve]
```

**How it works:**
1. You say `"stealth scan 10.0.0.1"`
2. AI matches intent to `nmap` scanner with `stealth_scan` profile
3. Workflow engine resolves `{target}` and executes the command
4. Results flow to correlation engine and auto-chain triggers

**Customize profiles** by editing the YAML files — no code changes needed.

---

## Smart Correlation Engine

After every scan, the correlation engine analyzes results across all scanners and identifies:

| Analysis | Description |
|----------|-------------|
| **Attack Paths** | Combines port + CVE + WAF + vuln data into exploitation chains |
| **Risk Factors** | Exposed services, missing headers, leaked emails, weak TLS |
| **Recommendations** | Actionable hardening suggestions based on findings |
| **Intel Score** | 0–100 composite risk score across all scan data |

**Attack path types detected:**
- Service Exploitation (open ports + known CVEs)
- Unprotected Web (missing WAF + web vulns)
- WordPress CMS (outdated plugins + known exploits)
- Information Disclosure (leaked emails + exposed endpoints)
- Historical Exposure (archived sensitive URLs)

---

## CLI Commands

### Interactive Commands (inside `scanai start`)

| Command | Description |
|---------|-------------|
| `help` | Show all commands |
| `workflows` | List all scanners and profiles |
| `chains` | List all attack chains |
| `history` | Show scan history for this session |
| `save` | Save current session |
| `load` | Load a previous session |
| `export md` | Export report as Markdown |
| `export html` | Export report as HTML |
| `correlate` | Run correlation on all results |
| `multiscan targets.txt` | Scan multiple targets from file |

### Natural Language Queries

```
❯ scan example.com                          # AI picks the best approach
❯ aggressive nmap scan 10.0.0.1             # specific scanner + profile
❯ find all vulnerabilities on target.com    # triggers vuln_assess chain
❯ check if example.com is safe              # phishing_analysis chain
❯ enumerate smb shares on 10.0.0.5          # enum4linux
❯ scan github.com/org/repo for secrets      # titus github scan
❯ how to exploit log4j                      # AI knowledge query
```

---

## Configuration

Create a `.env` file in the project root or run `scanai config --init`:

```env
GEMINI_API_KEY=your_gemini_api_key_here
VIRUSTOTAL_API_KEY=your_vt_key_here
URLSCAN_API_KEY=your_urlscan_key_here
WPSCAN_API_TOKEN=your_wpscan_token_here
SHODAN_API_KEY=your_shodan_key_here
```

| Key | Required | Used By |
|-----|----------|---------|
| `GEMINI_API_KEY` | **Yes** | AI query interpretation, report generation |
| `VIRUSTOTAL_API_KEY` | **Yes** | VirusTotal scanner |
| `URLSCAN_API_KEY` | **Yes** | URLScan scanner |
| `WPSCAN_API_TOKEN` | **Yes** | WPScan scanner |
| `SHODAN_API_KEY` | **Yes** | IP geolocation enrichment |

---

## Architecture

```
User Prompt (natural language)
    │
    ▼
AI Query Interpreter
    │  ├─ intent detection
    │  ├─ scanner selection
    │  └─ profile matching (106 profiles)
    │
    ▼
Workflow Engine
    │  ├─ profile-aware execution
    │  ├─ auto-chaining (nmap→CVE, katana→dalfox, etc.)
    │  └─ attack chain orchestration (9 chains)
    │
    ▼
Scanner Modules (23 scanners)
    │
    ▼
Smart Correlation Engine
    │  ├─ attack path identification
    │  ├─ risk scoring (0–100)
    │  └─ cross-scanner analysis
    │
    ▼
AI Report Generation + Session Persistence
```

### Project Structure

```
scanai/
├── scanai/
│   ├── workflows/              # 24 YAML workflow definitions
│   │   ├── nmap.yaml           #   10 profiles
│   │   ├── nuclei.yaml         #   6 profiles
│   │   ├── titus.yaml          #   7 profiles (secrets)
│   │   ├── gobuster.yaml       #   6 profiles
│   │   ├── dns.yaml            #   6 profiles
│   │   ├── recon_chain.yaml    #   9 attack chains
│   │   └── ...                 #   + 18 more
│   ├── scanners/               # 23 scanner modules
│   │   ├── nmap_scanner.py
│   │   ├── titus_scanner.py
│   │   ├── nikto_scanner.py
│   │   └── ...
│   ├── core/
│   │   ├── cli.py              # Main TUI interface
│   │   ├── workflow.py         # Workflow engine + auto-chaining
│   │   ├── workflow_loader.py  # YAML registry + chain registry
│   │   ├── scan_manager.py     # Scanner orchestration
│   │   ├── correlator.py       # Smart correlation engine
│   │   ├── session.py          # Session persistence
│   │   └── display/            # TUI theme + renderers
│   ├── ai/
│   │   ├── agents/             # Planner, Tool Selector, Analyst
│   │   └── prompts/            # Profile-aware AI prompt templates
│   └── services/
│       └── gemini_service.py   # Gemini AI + query interpreter
├── install.sh                  # One-command Kali installer
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Powered By 🙏

ScanAI stands on the shoulders of incredible open-source projects and platforms. Huge respect to everyone behind these tools:

### Platform & AI

| Project | Description |
|---------|-------------|
| [**Kali Linux**](https://www.kali.org/) | The ultimate penetration testing distribution — ScanAI's home base. Built by [Offensive Security](https://www.offsec.com/). |
| [**Google Gemini**](https://deepmind.google/technologies/gemini/) | Powers ScanAI's natural language understanding, scan planning, and report generation via [LangChain](https://github.com/langchain-ai/langchain). |

### Security Scanners

| Tool | Author / Org | What It Does |
|------|-------------|--------------|
| [**Nmap**](https://nmap.org/) | Gordon Lyon (Fyodor) | The network scanner. Port discovery, service detection, OS fingerprinting. |
| [**Nuclei**](https://github.com/projectdiscovery/nuclei) | [ProjectDiscovery](https://projectdiscovery.io/) | Template-based vulnerability scanning with thousands of community templates. |
| [**Katana**](https://github.com/projectdiscovery/katana) | [ProjectDiscovery](https://projectdiscovery.io/) | Next-gen web crawling — headless, JS parsing, form extraction. |
| [**httpx**](https://github.com/projectdiscovery/httpx) | [ProjectDiscovery](https://projectdiscovery.io/) | Fast HTTP probing and technology detection. |
| [**Dalfox**](https://github.com/hahwul/dalfox) | [hahwul](https://github.com/hahwul) | Parameter analysis and XSS scanning with WAF evasion. |
| [**SQLMap**](https://sqlmap.org/) | Bernardo Damele & Miroslav Stampar | Automatic SQL injection detection and exploitation. |
| [**Nikto**](https://github.com/sullo/nikto) | Chris Sullo | Web server vulnerability scanner — 6,700+ checks. |
| [**WPScan**](https://wpscan.com/) | WPScan Team | WordPress vulnerability scanner — plugins, themes, users. |
| [**Titus**](https://github.com/praetorian-inc/titus) | [Praetorian](https://www.praetorian.com/) | High-performance secrets scanner — 459 rules with live credential validation. |
| [**wafw00f**](https://github.com/EnableSecurity/wafw00f) | EnableSecurity | Web Application Firewall detection and fingerprinting. |
| [**theHarvester**](https://github.com/laramies/theHarvester) | Christian Martorella | OSINT — email, subdomain, and host discovery from public sources. |
| [**enum4linux**](https://github.com/CiscoCXSecurity/enum4linux) | Mark Lowe | SMB/NetBIOS enumeration for Windows/Samba systems. |
| [**DnsRecon**](https://github.com/darkoperator/dnsrecon) | Carlos Perez | DNS enumeration — zone transfers, brute force, reverse lookups. |
| [**WhatWeb**](https://github.com/urbanadventurer/WhatWeb) | Andrew Horton | Web technology fingerprinting — 1,800+ plugins. |
| [**SSLyze**](https://github.com/nabla-c0d3/sslyze) | Alban Diquet | Fast TLS/SSL configuration analysis. |
| [**testssl.sh**](https://github.com/drwetter/testssl.sh) | Dirk Wetter | Comprehensive TLS/SSL testing from the command line. |

### Python Libraries

| Library | Purpose |
|---------|---------|
| [**Rich**](https://github.com/Textualize/rich) | Beautiful terminal UI — panels, tables, progress bars, live display. |
| [**LangChain**](https://github.com/langchain-ai/langchain) | AI agent framework — chains Gemini to scanners. |
| [**BeautifulSoup4**](https://www.crummy.com/software/BeautifulSoup/) | HTML parsing for web analysis. |
| [**dnspython**](https://github.com/rthalley/dnspython) | DNS toolkit for Python. |
| [**aiohttp**](https://github.com/aio-libs/aiohttp) | Async HTTP client for concurrent scanning. |
| [**PyYAML**](https://github.com/yaml/pyyaml) | YAML workflow parsing. |

### Wordlists

| Resource | Author |
|----------|--------|
| [**SecLists**](https://github.com/danielmiessler/SecLists) | Daniel Miessler, Jason Haddix & community | 

> ScanAI is nothing without these tools. If you find ScanAI useful, go star ⭐ the projects above — they're the real MVPs.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

**0xD4rkEYe** — [git.selfmade.ninja/0xD4rkEYe](https://git.selfmade.ninja/0xD4rkEYe)
