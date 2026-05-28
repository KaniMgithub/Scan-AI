"""Vulnerability & recon scan display renderers."""

import json
import re
from typing import Dict, Any, List

from rich.panel import Panel
from rich.table import Table
from rich.console import Group
from rich import box

from .theme import C, make_panel, make_table, severity_badge, severity_color


class VulnRendererMixin:
    """Mixin providing vulnerability/recon display methods for ScanAI class."""

    def _display_subdomains_results(self, subdomains_data: Dict[str, Any]) -> None:
        """Display subdomain enumeration results."""
        raw_subdomains = subdomains_data.get('subdomains', [])
        domain = subdomains_data.get('domain', 'unknown')
        message = subdomains_data.get('message', '')

        if not raw_subdomains:
            explanation = message or "No subdomains found in Certificate Transparency logs."
            helpful_tips = [
                "• Certificate Transparency logs only show SSL/TLS certified subdomains",
                "• New domains or HTTP-only sites won't appear",
                "• Try domains like 'google.com' or 'github.com'",
                "• Use additional reconnaissance techniques for full coverage"
            ]
            tips_text = "\n".join(f"[{C['primary']}]• {tip}[/]" for tip in helpful_tips)
            self.console.print(make_panel(
                f"[{C['warning']}]🔍 No subdomains found for {domain}[/]\n\n"
                f"[{C['dim']}]{explanation}[/]\n\n"
                f"[bold {C['primary']}]💡 RECONNAISSANCE NOTES:[/]\n{tips_text}",
                title="SUBDOMAIN RECON", border=C["warning"]
            ))
            return

        flattened_subs = []
        for item in raw_subdomains:
            if isinstance(item, str):
                subs = [s.strip() for s in item.split('\n') if s.strip()]
                flattened_subs.extend(subs)
            else:
                flattened_subs.append(str(item))

        unique_subdomains = sorted(list(set(flattened_subs)))

        sub_table = Table(title=f"[{C['primary']}]🔗 DISCOVERED SUBDOMAINS[/%SAME%]", show_header=True, header_style=f"bold %SAME%", border_style=C['secondary'])
        sub_table.add_column("#", style=C['text'], width=4)
        sub_table.add_column("Subdomain", style=C['success'])
        for i, subdomain in enumerate(unique_subdomains[:100], 1):
            sub_table.add_row(str(i), subdomain)

        footer = ""
        if len(unique_subdomains) > 100:
            footer = f"\n[{C['warning']}]... and {len(unique_subdomains) - 100} more subdomains[/%SAME%]\n"

        self.console.print(make_panel(
            Group(sub_table, footer) if footer else sub_table,
            title="SUBDOMAIN ENUMERATION",
            border=C["primary"]
        ))

    def _display_cve_results(self, cve_data: Dict[str, Any]) -> None:
        """Display CVE vulnerability results."""
        cves = cve_data.get('cves', [])
        if not cves:
            self.console.print(Panel("[bright_green]✓ No vulnerabilities found[/bright_green]\n\n[dim]No CVEs detected in scanned systems.[/dim]", title="VULNERABILITY SCAN", border_style="bright_green", padding=(1, 2), style="white on black"))
            return

        severity_counts = {}
        for cve in cves:
            if not cve or not isinstance(cve, dict):
                continue
            severity = cve.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        summary_table = Table(show_header=False, box=None, style="white on black")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", style="bright_white", justify="right")
        for severity, count in sorted(severity_counts.items()):
            color = {'CRITICAL': 'bright_red', 'HIGH': 'bright_red', 'MEDIUM': 'bright_yellow', 'LOW': 'bright_green', 'UNKNOWN': 'bright_white'}.get(severity, 'bright_white')
            summary_table.add_row(f"[{color}]{severity}[/{color}]", str(count))
        self.console.print(Panel(summary_table, title="⚠️ VULNERABILITY SUMMARY", border_style="bright_yellow", padding=(1, 2), style="white on black"))

        if cves:
            self.console.print("\n[bold bright_red]🚨 VULNERABILITY DETAILS[/bold bright_red]\n")
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
            sorted_cves = sorted(cves[:15], key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN'), 5) if isinstance(x, dict) else 5)

            for cve in sorted_cves:
                if not cve or not isinstance(cve, dict):
                    continue
                cve_id = cve.get('id') or cve.get('cve') or 'Unknown'
                severity = cve.get('severity', 'UNKNOWN')
                cvss_v3 = cve.get('cvss_v3')
                score = 'N/A'
                vector = ''
                if isinstance(cvss_v3, dict):
                    score = cvss_v3.get('baseScore', 'N/A')
                    vector = cvss_v3.get('vectorString', '')
                elif 'cvss' in cve:
                    score = cve.get('cvss', 'N/A')
                description = cve.get('description') or cve.get('summary') or 'No description available.'
                affected = cve.get('detected_software', {})
                affected_str = ""
                if isinstance(affected, dict):
                    sw_name = affected.get('name', '')
                    sw_ver = affected.get('version', '')
                    if sw_name:
                        affected_str = f"\n[bright_cyan]🎯 Affected:[/bright_cyan] {sw_name} {sw_ver}".strip()
                refs = cve.get('references', [])
                refs_str = ""
                if refs and isinstance(refs, list):
                    exploit_refs = [r.get('url', '') for r in refs[:3] if isinstance(r, dict) and r.get('url')]
                    if exploit_refs:
                        refs_str = "\n[bright_yellow]🔗 References:[/bright_yellow]\n  • " + "\n  • ".join(exploit_refs)
                severity_colors = {'CRITICAL': 'bright_red', 'HIGH': 'bright_red', 'MEDIUM': 'bright_yellow', 'LOW': 'bright_green', 'UNKNOWN': 'bright_white'}
                color = severity_colors.get(severity, 'bright_white')
                cve_content = (
                    f"[{color}]⚡ Severity: {severity}  |  CVSS: {score}[/{color}]\n"
                    f"{f'[{C['dim']}]{vector}[/]' if vector else ''}\n\n"
                    f"[{C['text']}]{description}[/]"
                    f"{affected_str}{refs_str}"
                )
                self.console.print(make_panel(cve_content, title=cve_id, border=color))

    def _display_nuclei_results(self, nuclei_data: Dict[str, Any]) -> None:
        """Display Nuclei vulnerability results."""
        findings = nuclei_data.get('findings', [])
        target = nuclei_data.get('target', 'N/A')
        if not findings:
            self.console.print(Panel("[bright_green]✓ No template matches found[/bright_green]\n\n[dim]Nuclei didn't detect any known vulnerabilities on this target.[/dim]", title="NUCLEI SCAN", border_style="bright_green", padding=(1, 2), style="white on black"))
            return

        nuclei_table = Table(title=f"[bright_magenta]🎯 NUCLEI FINDINGS FOR {target}[/bright_magenta]", box=box.ROUNDED, border_style="bright_magenta", title_style="bold", header_style="bold bright_white", style="white on black")
        nuclei_table.add_column("Template ID", style="bright_cyan")
        nuclei_table.add_column("Name", style="bright_white")
        nuclei_table.add_column("Severity", justify="center")
        nuclei_table.add_column("Type", style="bright_yellow")

        for finding in findings:
            info = finding.get('info', {})
            template_id = finding.get('template-id', 'N/A')
            name = info.get('name', 'N/A')
            severity = info.get('severity', 'info').upper()
            vuln_type = finding.get('type', 'N/A')
            color = {'CRITICAL': C['danger'], 'HIGH': C['danger'], 'MEDIUM': C['warning'], 'LOW': C['success'], 'INFO': C['info']}.get(severity, C['text'])
            nuclei_table.add_row(f"[bold]{template_id}[/bold]", name, f"[{color}]{severity}[/{color}]", vuln_type)

        self.console.print(make_panel(nuclei_table, title="NUCLEI VULNERABILITIES", border=C["secondary"]))
        raw_output = nuclei_data.get('raw_output')
        if raw_output:
            self.console.print(Panel(raw_output.strip(), title="RAW NUCLEI EXECUTION OUTPUT", border_style="dim", padding=(1, 2), style="dim white on black"))

    def _display_dalfox_results(self, dalfox_data: Dict[str, Any]) -> None:
        """Display Dalfox XSS scan results."""
        findings = dalfox_data.get('findings', [])
        target = dalfox_data.get('target', 'N/A')
        verified_count = dalfox_data.get('verified_count', 0)
        reflected_count = dalfox_data.get('reflected_count', 0)
        grep_count = dalfox_data.get('grep_count', 0)

        if not findings:
            self.console.print(Panel("[bright_green]✓ No XSS vulnerabilities found[/bright_green]\n\n[dim]Dalfox did not detect any cross-site scripting issues.[/dim]", title="DALFOX XSS SCAN", border_style="bright_green", padding=(1, 2), style="white on black"))
            return

        type_labels = {'V': f"[bold {C['danger']}]✗ VERIFIED[/]", 'R': f"[{C['warning']}]⚠ REFLECTED[/]", 'G': f"[{C['primary']}]● GREP[/]"}
        summary_text = (f"[bold {C['energy']}]⚡ {len(findings)} XSS FINDING(S) DETECTED[/]\n\n"
            f"  [{C['danger']}]Verified (Confirmed):[/] {verified_count}\n"
            f"  [{C['warning']}]Reflected:[/]            {reflected_count}\n"
            f"  [{C['primary']}]Grep (Pattern Match):[/]  {grep_count}\n\n"
            f"  [dim]Target: {target}[/dim]")
        self.console.print(make_panel(summary_text, title="DALFOX XSS SUMMARY", border=C["danger"]))

        dalfox_table = Table(title="⚡ DALFOX XSS FINDINGS", box=box.ROUNDED, border_style="bright_red", title_style="bold", header_style="bold bright_white", style="white on black", show_lines=True)
        dalfox_table.add_column("#", style="dim", width=3)
        dalfox_table.add_column("Type", style="bright_red", width=14)
        dalfox_table.add_column("Severity", style="bright_red", width=10)
        dalfox_table.add_column("Parameter", style="bright_cyan", width=15)
        dalfox_table.add_column("Inject Type", style="bright_magenta", width=18)
        dalfox_table.add_column("Payload", style="bright_yellow", max_width=40)
        dalfox_table.add_column("CWE", style="bright_white", width=10)

        for idx, finding in enumerate(findings, 1):
            raw_type = finding.get('type', '?')
            vuln_type = type_labels.get(raw_type, raw_type)
            severity = finding.get('severity', 'N/A')
            param = finding.get('param', 'N/A')
            inject_type = finding.get('inject_type', 'N/A')
            payload = str(finding.get('payload', 'N/A'))
            cwe = finding.get('cwe', 'N/A')
            if severity and severity.lower() in ('critical', 'high'):
                severity_display = f"[bold bright_red]{severity}[/bold bright_red]"
            elif severity and severity.lower() == 'medium':
                severity_display = f"[bright_yellow]{severity}[/bright_yellow]"
            else:
                severity_display = f"[dim]{severity}[/dim]"
            if len(payload) > 40:
                payload = payload[:37] + "..."
            dalfox_table.add_row(str(idx), vuln_type, severity_display, param, inject_type, payload, str(cwe))

        self.console.print(Panel(dalfox_table, title="🔍 DALFOX VULNERABILITIES", border_style="bright_red", padding=(1, 2), style="white on black"))

        vulnerabilities = dalfox_data.get('vulnerabilities', [])
        if vulnerabilities:
            poc_lines = []
            for vuln in vulnerabilities:
                poc_url = vuln.get('poc_url', 'N/A')
                vuln_type = vuln.get('type', 'Unknown')
                param = vuln.get('param', 'N/A')
                if poc_url and poc_url != 'N/A':
                    poc_lines.append(f"  [bright_red]●[/bright_red] [{vuln_type}] param=[bright_cyan]{param}[/bright_cyan]\n    [bright_yellow]{poc_url}[/bright_yellow]")
            if poc_lines:
                self.console.print(Panel("\n".join(poc_lines), title="[bold bright_red]💉 XSS PROOF OF CONCEPT URLs[/bold bright_red]", border_style="bright_red", padding=(1, 2), style="white on black"))

        raw_output = dalfox_data.get('raw_output')
        if raw_output:
            self.console.print(Panel(raw_output.strip(), title="RAW DALFOX EXECUTION OUTPUT", border_style="dim", padding=(1, 2), style="dim white on black"))

    def _display_sqli_results(self, sqli_data: Dict[str, Any]) -> None:
        """Display SQLMap SQL Injection scan results."""
        injectable = sqli_data.get('injectable', False)
        target = sqli_data.get('target', 'N/A')
        dbms = sqli_data.get('dbms', 'N/A')
        banner = sqli_data.get('banner', 'N/A')
        current_user = sqli_data.get('current_user', 'N/A')
        databases = sqli_data.get('databases', [])
        injection_points = sqli_data.get('injection_points', [])
        techniques = sqli_data.get('techniques', [])
        server_os = sqli_data.get('os', 'N/A')

        if not injectable:
            self.console.print(Panel("[bright_green]✓ No SQL Injection vulnerabilities found[/bright_green]\n\n[dim]sqlmap did not detect any injectable parameters on the target.[/dim]\n\n" f"[dim bright_cyan]Target: {target}[/dim bright_cyan]", title="SQLMAP SQLi SCAN", border_style="bright_green", padding=(1, 2), style="white on black"))
            return

        db_count = len(databases)
        tech_count = len(techniques)
        param_count = len(set(ip.get('parameter', '') for ip in injection_points if ip.get('parameter')))
        summary_text = (f"[bold {C['energy']}]💊 SQL INJECTION CONFIRMED![/]\n\n"
            f"  [{C['danger']}]Injectable:[/]      [bold {C['danger']}]YES[/]\n"
            f"  [{C['primary']}]DBMS:[/]            [bold {C['text']}]{dbms}[/]\n"
            f"  [{C['primary']}]Banner:[/]          [bold {C['text']}]{banner}[/]\n"
            f"  [{C['primary']}]Current User:[/]    [bold {C['warning']}]{current_user}[/]\n"
            f"  [{C['primary']}]Server OS:[/]       [bold {C['text']}]{server_os}[/]\n"
            f"  [{C['primary']}]Databases:[/]       [bold {C['success']}]{db_count}[/]\n"
            f"  [{C['primary']}]Techniques:[/]      [bold {C['text']}]{tech_count}[/]\n"
            f"  [{C['primary']}]Parameters:[/]      [bold {C['text']}]{param_count}[/]\n\n"
            f"  [dim]Target: {target}[/dim]")
        self.console.print(make_panel(summary_text, title="SQLMAP SQLi SUMMARY", border=C["danger"]))

        if techniques:
            tech_table = Table(title="💉 SQL INJECTION TECHNIQUES", box=box.ROUNDED, border_style="bright_red", title_style="bold", header_style="bold bright_white", style="white on black", show_lines=True)
            tech_table.add_column("#", style="dim", width=3)
            tech_table.add_column("Type", style="bright_red", width=30)
            tech_table.add_column("Title", style="bright_yellow", max_width=50)
            tech_table.add_column("Payload", style="bright_cyan", max_width=50)
            for idx, tech in enumerate(techniques, 1):
                payload = str(tech.get('payload', 'N/A'))
                if len(payload) > 50:
                    payload = payload[:47] + "..."
                tech_table.add_row(str(idx), tech.get('type', 'N/A'), tech.get('title', 'N/A'), payload)
            self.console.print(Panel(tech_table, title="⚡ INJECTION VECTORS", border_style="bright_red", padding=(1, 2), style="white on black"))

        if databases:
            db_table = Table(title="🗄️ AVAILABLE DATABASES", box=box.ROUNDED, border_style="bright_green", title_style="bold", header_style="bold bright_white", style="white on black")
            db_table.add_column("#", style="dim", width=4)
            db_table.add_column("Database Name", style="bold bright_green")
            for idx, db_name in enumerate(databases, 1):
                db_table.add_row(str(idx), db_name)
            self.console.print(Panel(db_table, title="🗄️ ENUMERATED DATABASES", border_style="bright_green", padding=(1, 2), style="white on black"))

        if injection_points:
            ip_lines = []
            for ip in injection_points:
                param = ip.get('parameter', '')
                itype = ip.get('type', '')
                title = ip.get('title', '')
                payload = ip.get('payload', '')
                if param or itype:
                    ip_lines.append(f"  [bright_red]●[/bright_red] {param}\n    [bright_cyan]Type:[/bright_cyan] {itype}\n    [bright_yellow]Title:[/bright_yellow] {title}\n    [dim]Payload: {payload[:80]}{'...' if len(str(payload)) > 80 else ''}[/dim]")
            if ip_lines:
                self.console.print(Panel("\n\n".join(ip_lines), title="[bold bright_red]🎯 INJECTION POINTS[/bold bright_red]", border_style="bright_red", padding=(1, 2), style="white on black"))

    def _display_whatweb_results(self, whatweb_data: Dict[str, Any]) -> None:
        """Display technology detection results."""
        technologies = whatweb_data.get('technologies', {})
        if not technologies:
            self.console.print(Panel("[bright_yellow]🔧 No technologies detected[/bright_yellow]\n\n[dim]Site may use custom or uncommon technologies.[/dim]", title="TECHNOLOGY DETECTION", border_style="bright_yellow", padding=(1, 2), style="white on black"))
            return
        tech_table = Table(title="🔧 DETECTED WEB TECHNOLOGIES", show_header=True, header_style="bold bright_cyan", border_style="bright_yellow", style="white on black")
        tech_table.add_column("Category", style="bright_white")
        tech_table.add_column("Technology", style="bright_green")
        for category, tech in technologies.items():
            tech_table.add_row(category, tech)
        self.console.print(Panel(tech_table, title="TECHNOLOGY STACK", border_style="bright_yellow", padding=(1, 2), style="white on black"))
        raw_data = whatweb_data.get('raw_data')
        if raw_data:
            self.console.print(Panel(json.dumps(raw_data, indent=2), title="RAW TECHNOLOGY DETECTION DATA", border_style="dim", padding=(1, 2), style="dim white on black"))

    def _display_gobuster_results(self, gobuster_data: Dict[str, Any]) -> None:
        """Display directory enumeration results."""
        found_paths = gobuster_data.get('found_paths', [])
        if not found_paths:
            self.console.print(Panel("[bright_green]✓ No accessible directories/files found[/bright_green]\n\n[dim]Web server has proper access controls.[/dim]", title="DIRECTORY ENUMERATION", border_style="bright_green", padding=(1, 2), style="white on black"))
            return

        dir_table = Table(title="📁 DISCOVERED PATHS", show_header=True, header_style="bold bright_cyan", border_style="bright_magenta", style="white on black")
        dir_table.add_column("Path", style="bright_green")
        dir_table.add_column("Status", style="bright_white", width=8)
        dir_table.add_column("Type", style="bright_magenta", width=10)
        dir_table.add_column("Follow Redirections", style="bright_yellow")

        for path_info in found_paths:
            path = path_info.get('path', '')
            status = path_info.get('status_code', 0)
            ptype = path_info.get('type', 'Unknown')
            redirect_url = path_info.get('redirect_url', '')
            if ptype == 'Unknown':
                if path.endswith('/'):
                    ptype = 'Directory'
                elif '.' in path.split('/')[-1]:
                    ptype = 'File'
            color = self._status_color(status)
            status_str = f"[{color}]{status}[/{color}]"
            redir_display = redirect_url if redirect_url else "—"
            dir_table.add_row(path, status_str, ptype, redir_display)

        scan_mode = gobuster_data.get('scan_mode', 'both')
        title_map = {'dir': "🔍 FOLDER ENUMERATION", 'file': "🔍 FILE DISCOVERY", 'both': "🔍 DIRECTORY & FILE SCAN"}
        title_text = title_map.get(scan_mode, "🔍 DIRECTORY & FILE SCAN")
        self.console.print(Panel(dir_table, title=f"[bright_magenta]{title_text}[/bright_magenta]", border_style="bright_cyan", padding=(1, 2), style="white on black"))

        total_found = len(found_paths)
        dirs_count = sum(1 for p in found_paths if p.get('type', '') == 'Directory')
        files_count = sum(1 for p in found_paths if p.get('type', '') == 'File')
        redirects_count = sum(1 for p in found_paths if p.get('redirect_url'))
        self.console.print(Panel(
            f"[bold]Summary:[/bold]\n• Total discovered: [bright_yellow]{total_found}[/bright_yellow]\n"
            f"• Directories: [bright_cyan]{dirs_count}[/bright_cyan]  |  Files: [bright_green]{files_count}[/bright_green]\n"
            f"• Paths with redirections: [bright_yellow]{redirects_count}[/bright_yellow]\n• Scan completed successfully",
            border_style="dim", padding=(1, 2), style="white on black"
        ))

    def _display_virustotal_results(self, vt_data: Dict[str, Any]) -> None:
        """Display VirusTotal results."""
        if not vt_data:
            return
        self.console.print(Panel(
            f"[bold]VirusTotal Analysis:[/bold]\n\n"
            f"• Malicious: [bright_red]{vt_data.get('malicious_count', 0)}[/bright_red]\n"
            f"• Suspicious: [bright_yellow]{vt_data.get('suspicious_count', 0)}[/bright_yellow]\n"
            f"• Harmless: [bright_green]{vt_data.get('harmless_count', 0)}[/bright_green]\n"
            f"• Undetected: [bright_white]{vt_data.get('undetected_count', 0)}[/bright_white]\n"
            f"• Detection Ratio: [bright_cyan]{vt_data.get('detection_ratio', 'N/A')}[/bright_cyan]",
            title="🛡️ VIRUSTOTAL",
            border_style="bright_magenta", padding=(1, 2), style="white on black"
        ))

    def _display_urlscan_results(self, us_data: Dict[str, Any]) -> None:
        """Display URLScan results."""
        if not us_data:
            return
        malicious = us_data.get('malicious', False)
        score = us_data.get('score', 0)
        self.console.print(Panel(
            f"[bold]URLScan Analysis:[/bold]\n\n"
            f"• Status: {'[bright_red]✗ MALICIOUS[/bright_red]' if malicious else '[bright_green]✓ CLEAN[/bright_green]'}\n"
            f"• Score: [bright_yellow]{score}/100[/bright_yellow]\n"
            f"• Country: [bright_white]{us_data.get('country', 'Unknown')}[/bright_white]\n"
            f"• Server: [bright_cyan]{us_data.get('server', 'Unknown')}[/bright_cyan]",
            title="🌐 URLSCAN",
            border_style="bright_cyan", padding=(1, 2), style="white on black"
        ))

    def _display_errors(self, errors: List[Dict[str, Any]]) -> None:
        """Display scanner errors."""
        if not errors:
            return
        error_table = Table(show_header=False, box=None, style="white on black")
        error_table.add_column("Scanner", style="bright_yellow")
        error_table.add_column("Error", style="bright_red")
        for error in errors:
            error_table.add_row(f"🔧 {error['scanner']}:", error['error'])
        self.console.print(Panel(error_table, title="⚠️ SCANNER ERRORS", border_style="bright_red", padding=(1, 2), style="white on black"))

    def _clean_rich_markup(self, text: str) -> str:
        """Clean rich markup from text."""
        return re.sub(r'\[/?[a-zA-Z_]+(?:\s+[a-zA-Z_]+="[^"]*")*\]', '', text)

    def _get_threat_description(self, threat_type: str) -> str:
        """Get description for threat type."""
        descriptions = {
            "Trojan/Backdoor": "Malicious code disguised as legitimate software",
            "Ransomware": "Encrypts files and demands payment",
            "Cryptominer": "Uses system resources for cryptocurrency mining",
            "Worm": "Self-replicating malware spreading across networks",
            "Virus": "Infects files and spreads when executed",
            "Spyware/Keylogger": "Monitors and steals user activity",
            "Adware/PUP": "Displays unwanted ads or bundled software",
            "Phishing": "Attempts to steal credentials",
            "Generic Malware": "General malicious software",
            "Exploit Kit": "Tools exploiting vulnerabilities",
            "Botnet": "Network of compromised devices",
            "Suspicious": "Potentially harmful activity",
            "Unknown": "Unclassified threat"
        }
        return descriptions.get(threat_type, "Unknown threat type")

    def _classify_detection_type(self, detection_result: str) -> str:
        """Classify the type of malicious detection."""
        result_lower = detection_result.lower()
        if any(k in result_lower for k in ['trojan', 'backdoor', 'rootkit']):
            return "Trojan/Backdoor"
        elif any(k in result_lower for k in ['ransomware', 'encryptor']):
            return "Ransomware"
        elif any(k in result_lower for k in ['miner', 'coinminer', 'cryptominer']):
            return "Cryptominer"
        elif 'worm' in result_lower:
            return "Worm"
        elif 'virus' in result_lower:
            return "Virus"
        elif any(k in result_lower for k in ['spyware', 'keylogger', 'infostealer']):
            return "Spyware/Keylogger"
        elif any(k in result_lower for k in ['adware', 'pup', 'unwanted']):
            return "Adware/PUP"
        elif any(k in result_lower for k in ['phishing', 'phish']):
            return "Phishing"
        elif any(k in result_lower for k in ['malware', 'malicious']):
            return "Generic Malware"
        elif any(k in result_lower for k in ['exploit', 'vulnerability']):
            return "Exploit Kit"
        elif any(k in result_lower for k in ['botnet', 'bot']):
            return "Botnet"
        elif 'suspicious' in result_lower:
            return "Suspicious"
        else:
            return "Unknown"
