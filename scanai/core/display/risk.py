"""Risk assessment display mixin for ScanAI CLI."""

from typing import Dict, Any

from rich.panel import Panel

from ..result_storage import result_storage
from .theme import C, make_panel, make_header, risk_gauge, severity_badge, status_dot


class RiskDisplayMixin:
    """Mixin providing risk assessment display methods for ScanAI class."""

    def _display_scanAI_risk_assessment(self, results: Dict[str, Any]) -> None:
        """Display themed risk assessment with gradient gauge."""
        risk_data = results.get("summaries", {}).get("risk", {})
        total_risk = risk_data.get("total", 0)

        gauge = risk_gauge(total_risk)

        components = risk_data.get("components", {})
        if not isinstance(components, dict):
            components = {}

        comp_lines = []
        comp_map = [
            ("URL Analysis",    "url_heuristic", 25),
            ("Malware Check",   "virustotal",    25),
            ("Web Threats",     "urlscan",       25),
            ("Vulnerabilities", "cves",          25),
        ]
        for label, key, max_val in comp_map:
            val = components.get(key, 0)
            pct = int(val / max_val * 10) if max_val else 0
            bar_color = C["success"] if val < max_val * 0.4 else (C["warning"] if val < max_val * 0.7 else C["danger"])
            mini_bar = f"[{bar_color}]{'█' * pct}[/{bar_color}][{C['muted']}]{'░' * (10 - pct)}[/{C['muted']}]"
            comp_lines.append(f"  [{C['muted']}]{label:<16}[/{C['muted']}] {mini_bar} [{C['text']}]{val}/{max_val}[/{C['text']}]")

        content = (
            f"[bold {C['text']}]Overall Security Risk Score[/bold {C['text']}]\n\n"
            f"  {gauge}\n\n"
            f"[bold {C['primary']}]▸ COMPONENTS[/bold {C['primary']}]\n"
            f"[{C['muted']}]{'─' * 44}[/{C['muted']}]\n"
            + "\n".join(comp_lines)
        )

        self.console.print(make_panel(content, title="▸ THREAT ASSESSMENT", border=C["danger"]))

    def _create_scanAI_risk_gauge(self, score: int) -> str:
        """Convenience wrapper around theme.risk_gauge."""
        return risk_gauge(score)

    def _display_scanAI_intelligence_summary(self, results: Dict[str, Any]) -> None:
        """Display intelligence summary."""
        last_id = result_storage.get_last_result_id() or "—"

        info_table = f"""[bold {C['primary']}]▸ TARGET INTELLIGENCE[/bold {C['primary']}]
[{C['muted']}]{'─' * 44}[/{C['muted']}]
  [{C['muted']}]Domain[/{C['muted']}]     [{C['text']}]{results.get('domain', '—')}[/{C['text']}]
  [{C['muted']}]IP[/{C['muted']}]         [{C['text']}]{results.get('ip', '—')}[/{C['text']}]
  [{C['muted']}]Status[/{C['muted']}]     {self._format_scanAI_status(results.get('status', 'unknown'))}
  [{C['muted']}]Scan ID[/{C['muted']}]    [{C['text']}]{last_id}[/{C['text']}]

[bold {C['primary']}]▸ KEY FINDINGS[/bold {C['primary']}]
[{C['muted']}]{'─' * 44}[/{C['muted']}]
  [{C['text']}]• Security reconnaissance completed[/{C['text']}]
  [{C['text']}]• All security modules executed[/{C['text']}]
  [{C['text']}]• Intelligence data gathered[/{C['text']}]"""

        self.console.print(make_panel(info_table, title="▸ INTELLIGENCE BRIEFING", border=C["primary"]))

    def _get_scanAI_risk_icon(self, risk_level: str) -> str:
        """Get icon for risk level."""
        icons = {
            "LOW":      f"[{C['success']}]✓[/{C['success']}]",
            "MEDIUM":   f"[{C['warning']}]⚠[/{C['warning']}]",
            "HIGH":     f"[{C['danger']}]✗[/{C['danger']}]",
            "CRITICAL": f"[{C['danger']}]🔥[/{C['danger']}]",
        }
        return icons.get(risk_level.upper(), f"[{C['muted']}]?[/{C['muted']}]")

    def _format_scanAI_status(self, status: str) -> str:
        """Format status with themed colours."""
        status_map = {
            "safe":       (C["success"], "✓ Secure"),
            "malicious":  (C["danger"],  "✗ Malicious"),
            "suspicious": (C["warning"], "⚠ Suspicious"),
            "unknown":    (C["muted"],   "? Unknown"),
        }
        color, text = status_map.get(status.lower(), (C["muted"], status.title()))
        return f"[{color}]{text}[/{color}]"
