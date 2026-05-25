# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.4.0] - 2026-03-02

### Added
- **Katana Web Crawler**: Replaced Python-based crawl scanner with [projectdiscovery/katana](https://github.com/projectdiscovery/katana) — next-gen web crawling with headless browser support, JavaScript parsing, and form extraction.
  - 8 scan profiles: standard, deep, quick, headless, api_hunt, form_discovery, stealth, scope_strict
  - `katana_scanner.py` with live streaming via `subprocess.Popen` (line-buffered JSON output)
  - All profiles include `-crawl-duration` limits (30s–180s) to prevent infinite crawls
- **Live Crawl TUI**: Real-time Rich Live panel during katana scans showing:
  - Stats bar: URLs, endpoints, APIs, JS files, forms, elapsed time
  - Color-coded URL stream: `URL` (cyan), `API` (red), `JS` (magenta)
  - Technology detection as discovered
  - 8fps refresh, transient display
- **Titus Secrets Scanner**: Integrated [praetorian-inc/titus](https://github.com/praetorian-inc/titus) — high-performance secrets detection with 459 rules, live credential validation, git history scanning, and binary extraction (Office, PDF, archives).
  - 7 scan profiles: standard, validate, git_history, git_validate, github_repo, gitlab_project, deep
  - `titus_scanner.py` module with full YAML workflow support
- **System Wordlist Integration**: Migrated from local wordlists to standard system paths in `/usr/share/wordlists` (SecLists, Dirb, Dirbuster).
- **Automated Dependency Management**: `install.sh` now checks for and installs `seclists` on Kali Linux.
- **Powered By Section**: README now credits all open-source tools and platforms (Kali Linux, Google Gemini, ProjectDiscovery, Dalfox, Titus, and 15+ others).

### Changed
- **Installer Rewrite**: Completely rewritten `install.sh` — every tool (apt, Go, Katana, Titus) is checked before install; if present, skipped. Titus auto-downloaded from GitHub releases. Katana installed via `go install`. Go binaries symlinked to `/usr/local/bin/`.
- **README Rewrite**: Full documentation rewrite — all 23 scanners with example prompts, all 9 attack chains with flow diagrams, YAML workflow system, correlation engine, architecture diagram.
- **Scanner Count**: 22 → 23 scanners, 96 → 106 profiles (added katana/8 + titus/7, removed crawl/5).
- **Web Attack Chain**: `web_attack` chain now uses katana instead of Python crawl scanner.
- **Auto-Chaining**: katana results trigger dalfox (XSS) and gobuster (API) follow-ups.
- **Global Rebranding**: Replaced all remaining "OpenClaw" references with "ScanAI" branding.
- **Version Synchronization**: Harmonized to 0.4.0 across all metadata, User-Agent strings, and display panels.
- **Cleanup**: Removed legacy `wordlists/` directory and updated packaging configuration.

### Removed
- **crawl_scanner.py**: Removed Python-based multi-threaded web crawler (280 lines) — replaced by Katana.
- **crawl.yaml**: Removed 5 crawl profiles — replaced by 8 katana profiles.

## [0.3.1] - 2026-02-27

### Added — Kali Linux Elite Optimization
- **Exclusive Kali Linux Support**: Optimized all scanner modules and core engine strictly for Kali Linux environments.
- **Automated Installer**: Overhauled `install.sh` to provide a one-command setup (`sudo ./install.sh setup`) that handles system dependencies, Go-based tools, and venv.
- **Security Tool Consolidation**: Unified all scanner system dependencies into a managed installation flow.
- **Platform Verification**: Added strict OS detection to ensure ScanAI runs on its optimized platform.

### Changed
- **Installer Cleanup**: Removed support for non-Kali Linux distributions (Ubuntu, Arch, etc.) to ensure maximum stability and zero-configuration compatibility.
- **README Updates**: Optimized documentation for the new Kali-focused installation flow.
- **Version Bump**: Incremented to `0.3.1`.

## [0.3.0] - 2026-02-27

### Added — Complete AI Hacking Agent

#### New Scanners (6)
- **Nikto**: Web server vulnerability scanning (5 profiles: standard, quick, thorough, ssl_focus, evasion)
- **theHarvester**: OSINT email/subdomain/IP harvesting (5 profiles: standard, email_only, deep, google, linkedin)
- **WAFw00f**: WAF detection and fingerprinting (2 profiles: standard, verbose)
- **WPScan**: WordPress vulnerability scanning (5 profiles: standard, enumerate_all, plugins_only, aggressive, stealthy)
- **Wayback Machine**: URL archive discovery with sensitive file detection (4 profiles: standard, quick, deep, endpoints_only)
- **Enum4Linux**: SMB/NetBIOS enumeration (5 profiles: standard, shares, users, password_policy, aggressive)

#### YAML Workflow System
- 23 YAML workflow definition files in `scanai/workflows/`
- 96 total scan profiles across 22 scanner modules
- `WorkflowRegistry` singleton loads all YAML profiles at startup
- `WorkflowProfile.build_command()` generates scanner commands from templates
- `get_profile_summary_for_ai()` feeds all profiles to AI for smart selection
- Every scanner reads and executes from its YAML workflow profile

#### Attack Chains (9)
- `quick_recon`: whois → dns → subdomain → nmap/port_scan
- `full_recon`: whois → dns → subdomain → harvester → ip_geo → wayback → nmap → waf → whatweb → headers → ssl
- `web_attack`: waf → nikto → katana → gobuster → dalfox → sqlmap → nuclei
- `vuln_assess`: nmap → nuclei → ssl → headers
- `stealth_recon`: whois → dns → subdomain → nmap/stealth
- `phishing_analysis`: virustotal → urlscan → whois → ssl
- `osint_recon`: whois → harvester → subdomain → wayback → dns
- `wordpress_audit`: wpscan → nikto → nuclei → headers → ssl
- `internal_pentest`: nmap → enum4linux → nmap/vuln_scripts

#### Smart Correlation Engine
- Cross-scanner intelligence analysis identifies attack paths
- Correlates ports + CVEs, WAF + vulns, katana + XSS, emails + subdomains
- Risk factor identification and actionable recommendations
- Composite intelligence score (0–100)
- Auto-runs after every scan

#### AI Enhancements
- Profile-aware Planner Agent — receives full profile summary for strategic planning
- Profile-aware Tool Selector — selects optimal scanner/profile combination
- Dynamic profile injection into AI query interpreter
- Local query parser detects profile keywords (stealth, phishing, waf bypass, heartbleed, etc.)
- Attack chain detection from natural language (quick recon, web attack, etc.)

#### Session Persistence & Reporting
- Save/load scan sessions to `~/.scanai/sessions/`
- Export reports as Markdown or HTML
- Pentest report format with findings, risk level, duration

#### Interactive CLI Commands
- `help` — show all commands and example queries
- `workflows` — list all scan profiles
- `chains` — list 9 attack chains
- `history` — show saved sessions
- `save [name]` — save last scan results
- `load <id>` — load saved session
- `export [md|html]` — export report
- `correlate` — run cross-scanner correlation
- `multiscan <file>` — scan multiple targets from file

#### Auto-Chain Engine
- nmap → auto CVE lookup + security header audit
- katana → auto XSS scan + API enumeration
- nuclei/dalfox → exploitation guidance prompt
- subdomain → port scanning suggestion

#### Enhanced Existing Scanners
- **VirusTotal**: 4 methods (url_scan, domain_report, ip_report, phishing_check) with phishing verdict
- **Server Headers**: security_audit scoring + redirect chain tracking
- **Subdomain**: HackerTarget + DNS brute-force sources
- **CVE**: severity filtering + exploitable CVE flagging
- **IP Geo**: routed by method (geo-only, shodan-only, full)
- **URLScan**: submit vs search routing
- **Whois**: detailed mode with raw output
- **WhatWeb**: aggression level control (passive/standard/aggressive)

#### Display
- Display methods for all 6 new scanners (nikto, harvester, waf, wpscan, wayback, enum4linux)
- Attack path analysis panel after scans
- Auto-chain suggestion panel
- Exploitation available prompt

### Changed
- Version bumped to 0.3.0
- Author updated to 0xD4rkEYe
- `pyproject.toml` updated with new keywords, description, YAML package data
- `requirements.txt` updated with `pyyaml>=6.0`
- All 22 scanners now accept `profile` parameter and process from YAML workflows

## [0.2.6] - 2026-02-24

### Added
- **Advanced AI Web Crawler**: Introduced a new `crawl` module for deep application mapping.
  - Multi-threaded recon with robust concurrent execution engine.
  - Asset extraction: forms, scripts, styles, images, and meta tags.
  - Recursive link discovery to map full application structure.
  - Zero truncation UI: hierarchical tree visualization of attack surface.
- **Improved UI Performance**: Optimized result streaming with Rich `Live` updates for smoother terminal feedback.

### Fixed
- **Crawler Race Conditions**: Resolved worker synchronization issues ensuring consistent result discovery.
- **UI Render Errors**: Fixed `NameError` related to missing Rich imports (`Align`, `Tree`).
- **Target Normalization**: Improved URL prefixing and domain extraction for all scanners.

## [0.2.5] - 2026-02-23

### Changed
- **Documentation Overhaul**: Comprehensive update to `README.md`, `CHANGELOG.md`, and `pyproject.toml`.
- **Packaging Improvements**: Updated `MANIFEST.in` and `.gitignore` for better development workflow.
- **Version Bump**: Incremented to `0.2.5` to reflect documentation and configuration alignment.

## [0.2.4] - 2026-02-22

### Added
- **SQL Injection Integration**: Added `sqli_scanner.py` leveraging `sqlmap` for automated DB vulnerability testing.
- **Improved Reporting**: Enhanced intelligence report with better layout and deduplication.
- **XSS Scanning Fixes**: Resolved Dalfox timeout issues and Nuclei report interference.

### Fixed
- **UI Markup Errors**: Fixed Rich text markup errors in CLI display (mismatched closing tags).
- **Subdomain Scan Output**: Fixed issue where subdomain results were not showing in AI reports.

## [0.2.3] - 2026-02-19

### Added
- **Advanced SSL/TLS Scanner**: Replaced internal OpenSSL-based scanner with professional-grade tools:
  - `sslyze`: Deep cipher suite analysis, certificate chain validation, and protocol testing.
  - `testssl.sh`: Comprehensive TLS vulnerability assessment (BEAST, CRIME, DROWN, Heartbleed, etc.).
- **Live Scan Output**: SSL scans now stream real-time, color-coded output directly to the terminal via `rich`.
- **Domain Extraction**: Robust URL-to-domain parsing ensures `sslyze` and `testssl` always receive clean hostnames.

### Changed
- **AI Prompts Overhaul**: Updated all 5 AI prompt files to recognize and leverage the new SSL toolchain.
- **CLI Display**: Refactored `_display_ssl_results` with dedicated panels for sslyze findings, testssl findings, and an aggregated summary.

### Fixed
- **sslyze Installation**: Fixed `install.sh` to install `sslyze` inside the virtual environment and symlink it globally.

## [0.2.1] - 2026-02-11

### Added
- **AI-Powered Workflow Automation**: Introduced YAML-based workflow system for complex, multi-stage security assessments.
- **High-Speed Custom Scanners**:
  - `GobusterScanner`: Native high-speed directory and file enumeration with connection pooling.
  - `WhatWebScanner`: Advanced technology detection (CMS, Frameworks, Analytics).
  - `IPGeoScanner`: Precise target location and ISP intelligence.
- **Specialized AI Agents**: Refined multi-agent orchestration for `PlannerAgent`, `ToolAgent`, and `AnalystAgent`.
- **Enhanced Toolchain**:
  - `Nuclei` & `httpx`: Integrated high-performance Go-based vulnerability and HTTP analysis.
  - `crt.sh`: Replaced external tools with direct CT log analysis for high-fidelity subdomain discovery.
- **AI Personalization**: Added context-aware greetings, farewells, and professional explainers for scan results.

### Fixed
- **Subdomain Sorting**: Improved deduplication and alphabetical sorting logic.
- **Async Execution**: Resolved race conditions in concurrent scanner management.
- **Dependency Management**: Enhanced `install.sh` for reliable automated setup of Go and Python tools.

## [0.1.0] - 2026-02-04

### Added
- **Autonomous Agentic Architecture**: Major refactor to a state-aware agentic loop powered by specialized AI agents:
  - `PlannerAgent`: Strategic planning and recursive sub-task decomposition.
  - `ToolAgent`: Perfect intent recognition for picking the right scanner at the right time.
  - `AnalystAgent`: Automated generation of elite security intelligence reports.
- **Next-Gen Security Tool Integration**:
  - `Subfinder`: Replaced crt.sh with high-performance subdomain discovery.
  - `Nuclei`: Template-based vulnerability scanning for precision detection.
  - `DnsRecon`: Comprehensive DNS records enumeration and zone analysis.
  - `Dalfox`: Advanced XSS discovery and parameter analysis.
- **Aggressive Intelligence**: Updated Nmap module to use aggressive scanning defaults (`-A`) for full service fingerprinting.
- **Smart Recon**: Automatic wordlist detection for directory brute-forcing.
- **Stability Fixes**: Resolved critical "no current event loop" errors and implemented `nest-asyncio` support.

### Changed
- **Elite Reporting**: Reordered CLI output so intelligence report is the impactful final takeaway.
- **Professional Installer**: Enhanced `install.sh` for one-command, zero-config setup of all security modules and Go dependencies.

## [0.0.1 (Beta)] - 2026-02-03

### Added
- Initial release with modular scanner support.
- Basic twin-agent flow for query interpretation.
- Support for Nmap, WHOIS, VirusTotal, and URLScan.io.
