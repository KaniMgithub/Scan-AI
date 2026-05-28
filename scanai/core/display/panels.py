"""Panel builder mixin for ScanAI CLI — dashboard, headers, cards, tables."""

from typing import Dict, Any, List, Tuple, Union

from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns

from .theme import C, make_panel, make_header, make_table, make_divider, system_stats_block, status_dot


class PanelBuilderMixin:
    """Mixin providing panel/card/header building methods for ScanAI class."""

    # ══════════════════════════════════════════════════════════════════
    #  STATS PANEL
    # ══════════════════════════════════════════════════════════════════

    def _create_scanAI_stats_panel(self, results: Dict[str, Any]) -> Panel:
        """Create statistics overview panel from scan results."""
        details = results.get("details", {})

        stats = Table(show_header=False, box=None, expand=True, padding=(0, 2))
        stats.add_column("Label", style=C["muted"])
        stats.add_column("Value", style=f"bold {C['text']}")

        stats.add_row("Target",     str(results.get("target", results.get("domain", "—"))))
        stats.add_row("IP",         str(results.get("ip", "—")))
        stats.add_row("Status",     self._format_scanAI_status(results.get("status", "unknown")))
        stats.add_row("Duration",   f"{results.get('duration', 0):.1f}s")

        # Module counts
        port_count = len([p for p in details.get("nmap", {}).get("ports", []) if p.get("state") == "open"])
        sub_count  = len(details.get("subdomains", {}).get("subdomains", []))
        cve_count  = len(details.get("cves", {}).get("cves", []))
        vuln_count = len(details.get("nuclei", {}).get("vulnerabilities", []))

        if port_count:
            stats.add_row("Open Ports",     f"[{C['warning']}]{port_count}[/{C['warning']}]")
        if sub_count:
            stats.add_row("Subdomains",     str(sub_count))
        if cve_count:
            stats.add_row("CVEs",           f"[{C['danger']}]{cve_count}[/{C['danger']}]")
        if vuln_count:
            stats.add_row("Vulnerabilities", f"[{C['danger']}]{vuln_count}[/{C['danger']}]")

        return make_panel(stats, title="▸ SCAN OVERVIEW", border=C["primary"])

    # ══════════════════════════════════════════════════════════════════
    #  STANDARD TABLE
    # ══════════════════════════════════════════════════════════════════

    def _create_standard_table(self, title: str, columns: List[Tuple[str, str, Union[int, str]]]) -> Table:
        """Create a standard themed table with column specs."""
        cols = [(name, justify) for name, justify, _ in columns]
        table = make_table(title, cols)
        # Apply width overrides
        for i, (_, _, width) in enumerate(columns):
            if isinstance(width, int) and width > 0:
                table.columns[i].width = width
                table.columns[i].min_width = width
        return table

    # ══════════════════════════════════════════════════════════════════
    #  CLEAN PANEL
    # ══════════════════════════════════════════════════════════════════

    def _create_clean_panel(self, content, title: str = "", border_style: str = C["primary"], padding: Tuple[int, int] = (1, 2)) -> Panel:
        """Create a themed panel."""
        return make_panel(content, title=title, border=border_style, padding=padding)

    # ══════════════════════════════════════════════════════════════════
    #  MULTILINE STATS & SPACING
    # ══════════════════════════════════════════════════════════════════

    def _format_multiline_stats(self, stats: Dict[str, str], title: str) -> str:
        """Format key-value stats as styled lines."""
        lines = [f"[bold {C['primary']}]▸ {title.upper()}[/bold {C['primary']}]", make_divider(40)]
        for key, val in stats.items():
            lines.append(f"  [{C['muted']}]{key}:[/{C['muted']}]  [{C['text']}]{val}[/{C['text']}]")
        return "\n".join(lines)

    def _add_section_spacing(self) -> None:
        """Add spacing between sections."""
        self.console.print()

    # ══════════════════════════════════════════════════════════════════
    #  DASHBOARD COMPONENTS — HEADER / SIDEBAR / FOOTER
    # ══════════════════════════════════════════════════════════════════

    def _create_terminal_header(self) -> Panel:
        """Top bar with branding, version, and timestamp."""
        from datetime import datetime
        now = datetime.now().strftime("%H:%M:%S")

        header_table = Table(show_header=False, box=None, expand=True)
        header_table.add_column("Left", justify="left")
        header_table.add_column("Center", justify="center")
        header_table.add_column("Right", justify="right")

        header_table.add_row(
            f"[bold {C['secondary']}]⚛ SCANAI AGENT[/bold {C['secondary']}]  [dim]|[/][{C['primary']}] Tactical Intelligence Unit[/{C['primary']}]",
            f"[{C['muted']}]v0.4.0[/{C['muted']}]",
            f"[{C['accent']}]{now}[/{C['accent']}]",
        )
        return Panel(header_table, border_style=C["dim"], padding=(0, 1))

    def _create_system_sidebar(self, scan_history: List[str] = None) -> Panel:
        """System sidebar with live CPU/MEM, date/time, and scan history."""
        from ..result_storage import result_storage

        lines = []

        # ── Live system stats ──
        lines.append(system_stats_block().replace("SYSTEM MONITOR", "NEURAL TELEMETRY"))
        lines.append("")

        # ── System status ──
        api_ok = True
        lines.append(f"[bold {C['secondary']}]⚡ ENGINE METRICS[/bold {C['secondary']}]")
        lines.append(f"[{C['muted']}]{'━' * 22}[/{C['muted']}]")
        lines.append(f"  {status_dot(api_ok)} [{C['text']}]Quantum Link[/{C['text']}] [{C['success']}]ACTIVE[/{C['success']}]")
        lines.append(f"  {status_dot(True)}  [{C['text']}]Neural Core[/{C['text']}]  [{C['success']}]IDLE[/{C['success']}]")
        lines.append("")

        # ── Scan history ──
        lines.append(f"[bold {C['secondary']}]🧠 MEMORY MODULES[/bold {C['secondary']}]")
        lines.append(f"[{C['muted']}]{'━' * 22}[/{C['muted']}]")

        if not scan_history:
            lines.append(f"  [{C['muted']}]EMPTY[/{C['muted']}]")
        else:
            for sid in scan_history[-5:]:
                short = sid[:20] + "…" if len(sid) > 20 else sid
                lines.append(f"  [{C['matrix']}]❯[/{C['matrix']}] [{C['text']}]{short}[/{C['text']}]")

        return Panel(
            "\n".join(lines),
            title=f"[bold {C['text']}]HUD[/bold {C['text']}]",
            border_style=C["primary"],
            width=30,
        )

    def _create_status_footer(self, state: str = "READY") -> Panel:
        """Informative footer with commands and status."""
        from .theme import status_dot

        footer_table = Table(show_header=False, box=None, expand=True)
        footer_table.add_column("Help", justify="left")
        footer_table.add_column("State", justify="right")

        footer_table.add_row(
            f"[{C['muted']}]scan <target>  •  analyze  •  config --init  •  exit[/{C['muted']}]",
            f"{status_dot(state == 'READY')} [{C['text']}]{state}[/{C['text']}]",
        )
        return Panel(footer_table, border_style=C["primary"], padding=(0, 1))

    # ══════════════════════════════════════════════════════════════════
    #  SECTION HEADERS
    # ══════════════════════════════════════════════════════════════════

    def _print_scanAI_header(self, text: str) -> None:
        """Print a themed section header."""
        self.console.print(make_header(text))

    def _print_section_header(self, text: str) -> None:
        """Print a sub-section header."""
        self.console.print(f"\n  [{C['primary']}]▸[/{C['primary']}] [bold {C['text']}]{text}[/bold {C['text']}]")
        self.console.print(f"  [{C['muted']}]{'─' * 48}[/{C['muted']}]")

    # ══════════════════════════════════════════════════════════════════
    #  MODULE CARDS
    # ══════════════════════════════════════════════════════════════════

    def _extract_module_summary(self, data: Dict[str, Any], card_type: str) -> str:
        """Extract a concise summary from module data for card display."""
        if not data:
            return f"[{C['muted']}]No data available[/{C['muted']}]"

        if card_type == "nmap":
            ports = data.get("ports", [])
            open_ports = [p for p in ports if p.get("state") == "open"]
            return f"[{C['text']}]{len(open_ports)} open port(s) detected[/{C['text']}]"

        elif card_type == "subdomains":
            subs = data.get("subdomains", [])
            return f"[{C['text']}]{len(subs)} subdomain(s) found[/{C['text']}]"

        elif card_type == "cves":
            cves = data.get("cves", [])
            critical = sum(1 for c in cves if c.get("severity", "").upper() == "CRITICAL")
            high = sum(1 for c in cves if c.get("severity", "").upper() == "HIGH")
            parts = [f"{len(cves)} CVE(s)"]
            if critical: parts.append(f"[{C['danger']}]{critical} critical[/{C['danger']}]")
            if high: parts.append(f"[{C['high']}]{high} high[/{C['high']}]")
            return f"[{C['text']}]{', '.join(parts)}[/{C['text']}]"

        elif card_type == "nuclei":
            vulns = data.get("vulnerabilities", [])
            return f"[{C['text']}]{len(vulns)} finding(s)[/{C['text']}]"

        elif card_type == "ssl":
            grade = data.get("grade", data.get("overall_grade", "—"))
            return f"[{C['text']}]Grade: {grade}[/{C['text']}]"

        elif card_type == "dns":
            records = data.get("records", {})
            types = [k for k, v in records.items() if v]
            return f"[{C['text']}]{len(types)} record type(s)[/{C['text']}]"

        elif card_type == "whois":
            registrar = data.get("registrar", "—")
            return f"[{C['text']}]Registrar: {registrar}[/{C['text']}]"

        elif card_type == "gobuster":
            dirs = data.get("directories", data.get("results", []))
            return f"[{C['text']}]{len(dirs)} path(s) found[/{C['text']}]"

        return f"[{C['muted']}]Data available[/{C['muted']}]"

    def _create_scanAI_module_card(self, title: str, data: Dict[str, Any], card_type: str) -> Panel:
        """Create a themed module summary card."""
        summary = self._extract_module_summary(data, card_type)

        icon_map = {
            "nmap": "🔌", "subdomains": "🌐", "cves": "🛡️",
            "nuclei": "⚡", "ssl": "🔒", "dns": "📡",
            "whois": "📋", "gobuster": "📂", "dalfox": "💉",
            "sqli": "💊", "headers": "📨", "whatweb": "🔍",
            "virustotal": "🦠", "urlscan": "🔗", "ipgeo": "🌍",
        }
        icon = icon_map.get(card_type, "◈")

        return make_panel(
            summary,
            title=f"{icon} {title}",
            border=C["primary"],
            padding=(0, 1),
            expand=False,
        )
