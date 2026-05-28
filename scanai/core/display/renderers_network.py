"""Network scan display renderers — nmap, dns, ssl, headers, ip_geo, whois."""

import json
import re
from typing import Dict, Any, List

from rich.panel import Panel
from rich.table import Table
from rich.console import Group
from rich import box

from .theme import C, make_panel, make_table, make_header, severity_badge


class NetworkRendererMixin:
    """Mixin providing network-scan display methods for ScanAI class."""

    def _display_nmap_results(self, nmap_data: Dict[str, Any]) -> None:
        """Display Nmap scan results with detailed service information."""
        all_ports = nmap_data.get('ports', [])
        open_ports = [port for port in all_ports if isinstance(port, dict) and port.get('state') == 'open']
        os_fingerprint = nmap_data.get('os_fingerprint', '')
        target = nmap_data.get('target', 'Unknown')

        if not open_ports:
            self.console.print(make_panel(
                f"[{C['success']}]✓ No open ports found[/{C['success']}]\n\n"
                f"[{C['muted']}]Target appears secure or protected by firewall.[/{C['muted']}]",
                title="PORT SCAN RESULTS", border=C["success"]
            ))
            return

        port_table = make_table(
            f"🔌 OPEN PORTS :: {target}",
            [("Port", "center"), ("Proto", "center"), ("Service", "left"), ("Version / Banner", "left"), ("Risk", "center")],
            border=C["accent"],
        )



        for port in open_ports[:20]:
            if not port or not isinstance(port, dict):
                continue
            port_num = str(port.get('port', ''))
            protocol = port.get('protocol', 'tcp').upper()
            service = str(port.get('service', 'unknown') or 'unknown').title()
            version = port.get('full_version', '') or port.get('version', '') or port.get('extra_info', '')
            if not version and port.get('software_name'):
                version = port.get('software_name', '')
                if port.get('version'):
                    version = f"{version} {port.get('version')}"
            if len(version) > 50:
                version = version[:47] + "..."
            risk_label = self._assess_port_risk(port_num, service)
            port_table.add_row(port_num, protocol, service, version or "[dim]Unknown[/dim]", risk_label)

        self.console.print(make_panel(
            port_table,
            title="🌐 NMAP PORT ANALYSIS",
            subtitle=f"OS: {os_fingerprint or 'Unknown'}",
            border=C["primary"],
        ))

        raw_output = nmap_data.get('raw_output')
        if raw_output:
            self.console.print(make_panel(
                raw_output.strip(),
                title="RAW NMAP SCAN OUTPUT",
                border=C["muted"],
            ))

        services = nmap_data.get('services', [])
        if services:
            service_list = []
            for svc in services[:10]:
                if isinstance(svc, dict):
                    name = svc.get('name', 'unknown')
                    ver = svc.get('version', '')
                    port = svc.get('port', '')
                    if ver:
                        service_list.append(f"[bright_green]{name}[/bright_green] [bright_yellow]{ver}[/bright_yellow] [dim](:{port})[/dim]")
                    else:
                        service_list.append(f"[bright_green]{name}[/bright_green] [dim](:{port})[/dim]")
            if service_list:
                self.console.print(Panel(
                    f"[bold]🎯 Detected Software:[/bold]\n{' • '.join(service_list)}",
                    border_style="dim bright_yellow", padding=(0, 2), style="white on black"
                ))

        high_risk_ports = sum(1 for p in open_ports if isinstance(p, dict) and self._assess_port_risk(str(p.get('port', '')), str(p.get('service', ''))).startswith(f"[{C['danger']}"))
        self.console.print(make_panel(
            f"[bold]📊 SURFACE SUMMARY[/bold]\n"
            f"• Open ports: [{C['energy']}]{len(open_ports)}[/{C['energy']}]\n"
            f"• High-risk services: [{C['warning']}]{high_risk_ports}[/{C['warning']}]\n"
            f"• Host status: [{C['success']}]{nmap_data.get('host_status', 'up').upper()}[/{C['success']}]",
            border=C["dim"], padding=(0, 2)
        ))

    def _display_dns_results(self, dns_data: Dict[str, Any]) -> None:
        """Display exhaustive DNS enumeration results."""
        if not dns_data:
            return
        records = dns_data.get('records', {})
        subdomains = dns_data.get('subdomains', [])
        domain = dns_data.get('domain', 'unknown')
        method = dns_data.get('method', 'unknown')
        raw_output = dns_data.get('output', '')

        if isinstance(records, list):
            categorized = {}
            for r in records:
                if isinstance(r, dict):
                    rtype = r.get('type', 'Unknown').upper()
                    if rtype not in categorized:
                        categorized[rtype] = []
                    if 'value' not in r:
                        r['value'] = r.get('address') or r.get('exchange') or r.get('nameserver') or str(r)
                    categorized[rtype].append(r)
            records = categorized

        method_info = f" [dim](via {method})[/dim]" if method != 'unknown' else ""
        self._print_section_header(f"🔍 DNS INTELLIGENCE REPORT: [bold cyan]{domain}[/bold cyan]{method_info}")

        if records:
            infra_table = Table.grid(expand=True)
            infra_table.add_column(style="dim", width=12)
            infra_table.add_column(style="bright_white")
            has_infra = False
            for rtype in ['SOA', 'NS']:
                rlist = records.get(rtype, [])
                if rlist:
                    has_infra = True
                    vals = "\n".join([r.get('value', 'N/A') for r in rlist])
                    infra_table.add_row(f"{rtype}:", vals)
            if has_infra:
                self.console.print(Panel(infra_table, title="[bold bright_magenta]🏛️ INFRASTRUCTURE[/bold bright_magenta]", border_style="bright_magenta", padding=(1, 2)))

            mx_list = records.get('MX', [])
            if mx_list:
                mx_table = Table.grid(expand=True)
                mx_table.add_column(style="dim", width=12)
                mx_table.add_column(style="bright_cyan")
                for r in mx_list:
                    pref = r.get('preference', '10')
                    mx_table.add_row(f"MX ({pref}):", r.get('value', 'N/A'))
                self.console.print(Panel(mx_table, title="[bold bright_cyan]📧 MAIL SERVERS[/bold bright_cyan]", border_style="bright_cyan", padding=(1, 2)))

            host_table = Table(box=None, expand=True, show_header=True, border_style="dim")
            host_table.add_column("Type", style="bold yellow", width=8)
            host_table.add_column("Value", style="bright_white")
            has_hosts = False
            for rtype in ['A', 'AAAA', 'CNAME', 'TXT']:
                rlist = records.get(rtype, [])
                for r in rlist:
                    has_hosts = True
                    host_table.add_row(rtype, r.get('value', 'N/A'))
            if has_hosts:
                self.console.print(Panel(host_table, title="🖥️ HOST RECORDS", border_style="bright_yellow", padding=(1, 2)))

        if subdomains:
            sub_table = Table(box=None, expand=True, show_header=True)
            sub_table.add_column("#", style="dim", width=4)
            sub_table.add_column("Subdomain", style="bright_green")
            for i, sub in enumerate(subdomains[:20], 1):
                sub_table.add_row(str(i), sub)
            footer = ""
            if len(subdomains) > 20:
                footer = f"\n[dim]... and {len(subdomains)-20} more discovered[/dim]"
            self.console.print(Panel(Group(sub_table, footer), title=f"[bold bright_green]🔗 DISCOVERED SUBDOMAINS ({len(subdomains)})[/bold bright_green]", border_style="bright_green", padding=(1, 2)))

        if raw_output:
            clean_output = raw_output.strip()
            if len(clean_output) > 5000:
                clean_output = clean_output[:5000] + "\n\n[bold red]-- OUTPUT TRUNCATED DUE TO SIZE --[/bold red]"
            self.console.print(Panel(f"[dim]{clean_output}[/dim]", title="📜RAW DNS ENUMERATION OUTPUT", border_style="bright_white", padding=(1, 2), style="white on black"))

        total_records = sum(len(records.get(rt, [])) for rt in records)
        stats = {
            "🌐 DNS Records Found": str(total_records),
            "🔗 Subdomains Discovered": str(len(subdomains)),
            "🎯 Target Domain": domain,
            "⚡ Enumeration Tool": method
        }
        stats_text = self._format_multiline_stats(stats, "📊 DNS ENUMERATION SUMMARY")
        self.console.print()
        self.console.print(stats_text)
        self._add_section_spacing()

    def _display_whois_results(self, whois_data: Dict[str, Any]) -> None:
        """Display WHOIS lookup results."""
        self.console.print(make_panel(
            f"[bold]Domain Intel:[/bold] [{C['primary']}]{whois_data.get('domain', 'N/A')}[/{C['primary']}]\n\n"
            f"• Registrar: [{C['text']}]{whois_data.get('registrar', 'N/A')}[/{C['text']}]\n"
            f"• Created: [{C['text']}]{whois_data.get('creation_date', 'N/A')}[/{C['text']}]\n"
            f"• Expires: [{C['text']}]{whois_data.get('expiration_date', 'N/A')}[/{C['text']}]\n"
            f"• Updated: [{C['text']}]{whois_data.get('updated_date', 'N/A')}[/{C['text']}]\n\n"
            f"[{C['muted']}]Name Servers:[/{C['muted']}] {', '.join(whois_data.get('name_servers', ['N/A'])[:3])}",
            title="WHOIS INTEL",
            border=C["secondary"]
        ))
        raw_output = whois_data.get('raw_output')
        if raw_output:
            self.console.print(Panel(raw_output.strip(), title="RAW WHOIS REGISTRY DATA", border_style="dim", padding=(1, 2), style="dim white on black"))

    def _display_server_headers_results(self, headers_data: Dict[str, Any]) -> None:
        """Display HTTP headers analysis."""
        headers = headers_data.get('headers', {})
        detected_software = headers_data.get('detected_software', [])
        status_code = headers_data.get('status_code', 'N/A')

        if not headers:
            self.console.print(Panel("[bright_red]No HTTP headers could be retrieved.[/bright_red]\n[dim]Target may be unreachable or blocking requests.[/dim]", title="HTTP ANALYSIS FAILED", border_style="bright_red", padding=(1, 2)))
            return

        status_color = "bright_green"
        if str(status_code).startswith('4'):
            status_color = "bright_yellow"
        elif str(status_code).startswith('5'):
            status_color = "bright_red"

        headers_table = Table(show_header=True, header_style="bold bright_cyan", border_style="bright_blue", expand=True, title=f"[bold]📡 HTTP RESPONSE HEADERS (Status: [{status_color}]{status_code}[/{status_color}])[/bold]")
        headers_table.add_column("Header Name", style="bright_white")
        headers_table.add_column("Value", style="dim white")

        security_headers = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy']
        sorted_headers = sorted(headers.items())
        found_security_headers = []

        for name, value in sorted_headers:
            name_lower = name.lower()
            formatted_name = name
            formatted_value = value
            if len(formatted_value) > 60:
                formatted_value = formatted_value[:57] + "..."
            if name_lower in security_headers:
                formatted_name = f"[bright_green]{name}[/bright_green]"
                formatted_value = f"[bright_green]{formatted_value}[/bright_green]"
                found_security_headers.append(name)
            elif name_lower in ['server', 'x-powered-by', 'x-generator']:
                formatted_name = f"[bright_yellow]{name}[/bright_yellow]"
                formatted_value = f"[bright_yellow]{formatted_value}[/bright_yellow]"
            headers_table.add_row(formatted_name, formatted_value)

        self.console.print(Panel(headers_table, title="HTTP PROTOCOL ANALYSIS", border_style="bright_magenta", padding=(1, 2), style="white on black"))

        missing_headers = [h for h in security_headers if h not in [k.lower() for k in headers.keys()]]
        if missing_headers:
            missing_text = "\n".join([f"• [red]{h}[/red]" for h in missing_headers])
            self.console.print(Panel(f"[bold bright_red]⚠️  MISSING SECURITY HEADERS:[/bold bright_red]\n\n{missing_text}\n\n[dim]These headers recommended for defense-in-depth.[/dim]", border_style="red", padding=(1, 2), style="white on black"))

        all_headers_raw = headers_data.get('all_headers_raw', {})
        if all_headers_raw:
            self.console.print(Panel(json.dumps(all_headers_raw, indent=2), title="RAW HTTP HEADERS", border_style="dim", padding=(1, 2), style="dim white on black"))

        if detected_software:
            software_text = "\n".join([f"• [bright_cyan]{tech['name']}[/bright_cyan] {f'v{ver}' if (ver := tech.get('version')) else ''}" for tech in detected_software])
            self.console.print(Panel(f"[bold]🛠️  DETECTED TECHNOLOGIES:[/bold]\n\n{software_text}", border_style="bright_cyan", padding=(0, 2)))

    def _display_ssl_via_ai(self, target: str) -> None:
        """Display SSL certificate information."""
        self.console.print(Panel(
            f"[bold]SSL Certificate Analysis for:[/bold] [bright_cyan]{target}[/bright_cyan]\n\n"
            f"[bright_yellow]⚠️ SSL certificate analysis requires direct connection[/bright_yellow]\n\n"
            f"[dim]For comprehensive SSL analysis, use:[/dim]\n"
            f"[bright_green]• SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d={target}[/bright_green]\n"
            f"[bright_green]• Qualys SSL Test[/bright_green]\n"
            f"[bright_green]• DigiCert SSL Checker[/bright_green]",
            title="🔒 SSL CERTIFICATE",
            border_style="bright_cyan", padding=(1, 2), style="white on black"
        ))

    def _display_ssl_results(self, ssl_data: Dict[str, Any]) -> None:
        """Display exhaustive SSL/TLS analysis from sslyze and testssl."""
        if not ssl_data:
            return
        if 'success' in ssl_data and 'data' in ssl_data:
            if not ssl_data['success']:
                self.console.print(Panel(f"[bright_red]SSL Scan Error: {ssl_data.get('error', 'Unknown error')}[/bright_red]", border_style="bright_red"))
                return
            data = ssl_data['data']
        else:
            data = ssl_data
        if not isinstance(data, dict) or not data:
            return

        domain = data.get('domain', data.get('target', 'Target'))
        sslyze_out = data.get('sslyze_output', '')
        testssl_out = data.get('testssl_output', '')
        summary = data.get('summary', '')

        if summary:
            self.console.print(Panel(f"[bold bright_white]{summary}[/bold bright_white]", title=f"[bold bright_green]🔒 SSL/TLS SUMMARY: {domain}[/bold bright_green]", border_style="bright_green", padding=(1, 2)))

        def _colorize_ssl_output(output: str) -> list:
            styled = []
            for line in output.split('\n'):
                ll = line.lower()
                if any(w in ll for w in ['vulnerable', 'critical', 'high', 'severe', 'danger', 'broken']):
                    styled.append(f"[bold red]{line}[/bold red]")
                elif any(w in ll for w in ['warning', 'medium', 'weak', 'deprecated']):
                    styled.append(f"[bold yellow]{line}[/bold yellow]")
                elif any(w in ll for w in ['ok', 'success', 'good', 'passed', 'info', 'secure']):
                    styled.append(f"[bold green]{line}[/bold green]")
                else:
                    styled.append(line)
            return styled

        if sslyze_out:
            self.console.print(Panel(Group(*_colorize_ssl_output(sslyze_out)), title="[bold yellow]SSLYZE DETAILED ANALYSIS[/bold yellow]", border_style="yellow", padding=(1, 2)))
        if testssl_out:
            self.console.print(Panel(Group(*_colorize_ssl_output(testssl_out)), title="[bold yellow]TESTSSL DETAILED ANALYSIS[/bold yellow]", border_style="yellow", padding=(1, 2)))

    def _display_ip_geo_results(self, ip_data: Dict[str, Any]) -> None:
        """Display IP geolocation results."""
        if 'data' in ip_data:
            ip_data = ip_data.get('data', {})
        geo_data = ip_data.get('ip_geolocation', {})
        internetdb_data = ip_data.get('internetdb', {})
        combined = ip_data.get('combined_analysis', {})
        ip_address = ip_data.get('ip', geo_data.get('ip', 'N/A'))

        geo_content = f"[bold bright_cyan]📍 GEOLOCATION DATA[/bold bright_cyan]\n\n"
        geo_content += f"• [bold]IP Address:[/bold] [bright_white]{ip_address}[/bright_white]\n"

        if geo_data and not geo_data.get('error'):
            geo_content += f"• [bold]Country:[/bold] [bright_green]{geo_data.get('country', 'N/A')} ({geo_data.get('country_code', '')})[/bright_green]\n"
            geo_content += f"• [bold]Region:[/bold] [bright_yellow]{geo_data.get('region_name', 'N/A')}[/bright_yellow]\n"
            geo_content += f"• [bold]City:[/bold] [bright_cyan]{geo_data.get('city', 'N/A')}[/bright_cyan]\n"
            geo_content += f"• [bold]ZIP:[/bold] {geo_data.get('zip', 'N/A')}\n"
            geo_content += f"• [bold]Coordinates:[/bold] {geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}\n"
            geo_content += f"• [bold]Timezone:[/bold] {geo_data.get('timezone', 'N/A')}\n\n"
            geo_content += f"[bold bright_yellow]🏢 ISP / ORGANIZATION[/bold bright_yellow]\n\n"
            geo_content += f"• [bold]ISP:[/bold] [bright_white]{geo_data.get('isp', 'N/A')}[/bright_white]\n"
            geo_content += f"• [bold]Organization:[/bold] [bright_green]{geo_data.get('org', 'N/A')}[/bright_green]\n"
            geo_content += f"• [bold]AS Number:[/bold] {geo_data.get('as', 'N/A')}\n"
            flags = []
            if geo_data.get('proxy'):
                flags.append("[bright_red]🔒 Proxy/VPN[/bright_red]")
            if geo_data.get('hosting'):
                flags.append("[bright_yellow]☁️ Hosting Provider[/bright_yellow]")
            if geo_data.get('mobile'):
                flags.append("[bright_blue]📱 Mobile Network[/bright_blue]")
            if flags:
                geo_content += f"\n• [bold]Flags:[/bold] {' | '.join(flags)}\n"

        if internetdb_data and not internetdb_data.get('error'):
            geo_content += f"\n[bold bright_red]🔍 SHODAN INTERNETDB[/bold bright_red]\n\n"
            ports = internetdb_data.get('ports', [])
            if ports:
                port_str = ', '.join(map(str, ports[:15]))
                if len(ports) > 15:
                    port_str += f" (+{len(ports) - 15} more)"
                geo_content += f"• [bold]Open Ports ({len(ports)}):[/bold] [bright_red]{port_str}[/bright_red]\n"
            hostnames = internetdb_data.get('hostnames', [])
            if hostnames:
                host_str = ', '.join(hostnames[:5])
                if len(hostnames) > 5:
                    host_str += f" (+{len(hostnames) - 5} more)"
                geo_content += f"• [bold]Hostnames:[/bold] [bright_cyan]{host_str}[/bright_cyan]\n"
            vulns = internetdb_data.get('vulns', [])
            if vulns:
                vuln_str = ', '.join(vulns[:5])
                if len(vulns) > 5:
                    vuln_str += f" (+{len(vulns) - 5} more)"
                geo_content += f"• [bold]CVEs ({len(vulns)}):[/bold] [bright_red]{vuln_str}[/bright_red]\n"
            tags = internetdb_data.get('tags', [])
            if tags:
                geo_content += f"• [bold]Tags:[/bold] [bright_yellow]{', '.join(tags)}[/bright_yellow]\n"

        if combined and combined.get('findings'):
            geo_content += f"\n[bold bright_magenta]⚡ RISK ANALYSIS[/bold bright_magenta]\n\n"
            risk_level = combined.get('risk_level', 'low').upper()
            risk_color = 'bright_red' if risk_level in ['HIGH', 'CRITICAL'] else 'bright_yellow' if risk_level == 'MEDIUM' else 'bright_green'
            geo_content += f"• [bold]Risk Level:[/bold] [{risk_color}]{risk_level}[/{risk_color}]\n"
            for finding in combined.get('findings', []):
                geo_content += f"• {finding}\n"

        self.console.print(Panel(geo_content, title="[bold bright_magenta]🌍 IP INTELLIGENCE REPORT[/bold bright_magenta]", border_style="bright_magenta", padding=(1, 2), style="white on black"))

    @staticmethod
    def _status_color(code: int) -> str:
        """Return a Rich color tag for an HTTP status code."""
        if 200 <= code <= 299:
            return "bright_green"
        if code in (301, 302, 307, 308):
            return "bright_yellow"
        if code in (401, 403):
            return "bright_red"
        return "bright_white"

    def _assess_port_risk(self, port, service: str) -> str:
        """Assess risk level for open ports."""
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            return f"[{C['text']}]Unknown[/{C['text']}]"
        high_risk_ports = [21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        service_lower = service.lower() if service else ""
        if port_num in high_risk_ports or any(vs in service_lower for vs in ['ftp', 'telnet', 'smb', 'mssql', 'oracle', 'mysql', 'rdp', 'vnc']):
            return f"[{C['danger']}]HIGH[/{C['danger']}]"
        elif port_num in [80, 443, 587]:
            return f"[{C['warning']}]MEDIUM[/{C['warning']}]"
        else:
            return f"[{C['success']}]LOW[/{C['success']}]"
