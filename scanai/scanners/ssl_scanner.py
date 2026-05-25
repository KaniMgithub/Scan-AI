"""SSL/TLS scanner using sslyze and testssl."""

import subprocess
import os
import sys
import time
import re
import shutil
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

from .base_scanner import BaseScanner
from ..utils.config import config


class SSLScanner(BaseScanner):
    """Scanner for SSL/TLS vulnerabilities using sslyze and testssl."""

    def __init__(self) -> None:
        """Initialize the SSL scanner."""
        super().__init__("ssl", "Advanced SSL/TLS Security Scanner")
        self.console = Console()

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform SSL/TLS scan using sslyze and testssl.

        Args:
            target: Domain name or URL to scan
            **kwargs: Additional arguments

        Returns:
            SSL scan results
        """
        start_time = time.time()
        
        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('ssl', profile_name)
            if profile:
                self.set_profile(profile)

        # Extract domain name for scanning
        domain = self._extract_domain(target)
        
        results = {
            'target': target,
            'domain': domain,
            'findings': [],
            'sslyze_output': "",
            'testssl_output': "",
            'success': False
        }

        self.console.print(f"\n[bold blue][*][/bold blue] Starting Advanced SSL/TLS Scan for: [bold cyan]{domain}[/bold cyan]")

        # Route based on workflow profile
        active_method = None
        if self._workflow_profile and self._workflow_profile.method:
            active_method = self._workflow_profile.method

        profile_cmd = self.get_profile_command(domain)

        if active_method == 'ssl_check':
            # Standard: sslyze only
            sslyze_bin = shutil.which("sslyze")
            if sslyze_bin:
                self.console.print("[bold blue][*][/bold blue] Running [bold yellow]sslyze[/bold yellow]...")
                results['sslyze_output'] = self._run_tool_live([sslyze_bin, domain])
            else:
                self.console.print("[bold red][!][/bold red] sslyze not found. Skipping...")

        elif active_method == 'ssl_detailed':
            # Detailed: both sslyze and testssl
            sslyze_bin = shutil.which("sslyze")
            if sslyze_bin:
                self.console.print("[bold blue][*][/bold blue] Running [bold yellow]sslyze[/bold yellow]...")
                results['sslyze_output'] = self._run_tool_live([sslyze_bin, domain])
            testssl_bin = shutil.which("testssl")
            if testssl_bin:
                self.console.print("\n[bold blue][*][/bold blue] Running [bold yellow]testssl[/bold yellow]...")
                results['testssl_output'] = self._run_tool_live([testssl_bin, domain])

        elif profile_cmd:
            # Profile has a command_template (cipher_audit, heartbleed use nmap scripts)
            self.console.print(f"[bold blue][*][/bold blue] Running profile command...")
            cmd_parts = profile_cmd.split()
            output = self._run_tool_live(cmd_parts)
            results['sslyze_output'] = output  # store in sslyze field for compatibility

        else:
            # Default: run both tools
            sslyze_bin = shutil.which("sslyze")
            if sslyze_bin:
                self.console.print("[bold blue][*][/bold blue] Running [bold yellow]sslyze[/bold yellow]...")
                results['sslyze_output'] = self._run_tool_live([sslyze_bin, domain])
            else:
                self.console.print("[bold red][!][/bold red] sslyze not found. Skipping...")

            testssl_bin = shutil.which("testssl")
            if testssl_bin:
                self.console.print("\n[bold blue][*][/bold blue] Running [bold yellow]testssl[/bold yellow]...")
                results['testssl_output'] = self._run_tool_live([testssl_bin, domain])
            else:
                self.console.print("[bold red][!][/bold red] testssl not found. Skipping...")

        results['success'] = bool(results['sslyze_output'] or results['testssl_output'])
        
        if results['success']:
            self.console.print(f"\n[bold green][+][/bold green] SSL/TLS scan completed for {domain}")
            # Summarize findings for the analyst
            results['summary'] = self._generate_summary(results)
        else:
            self.console.print(f"\n[bold red][-][/bold red] SSL/TLS scan failed or tools not found")

        return self._create_result(
            success=results['success'],
            data=results,
            duration=time.time() - start_time
        )

    def _extract_domain(self, target: str) -> str:
        """Extract domain from target URL."""
        target = target.strip()
        if '://' in target:
            parsed = urlparse(target)
            domain = parsed.hostname or target
        else:
            domain = target.split('/')[0]
            
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        return domain

    def _run_tool_live(self, cmd: List[str]) -> str:
        """Run a command and stream output live to the console."""
        output_lines = []
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            for line in iter(process.stdout.readline, ''):
                line_stripped = line.rstrip()
                if line_stripped:
                    # Basic colorization for live output
                    styled_line = self._colorize_line(line_stripped)
                    self.console.print(f"  {styled_line}")
                    output_lines.append(line_stripped)
                sys.stdout.flush()

            process.wait()
            return "\n".join(output_lines)
        except Exception as e:
            self.console.print(f"  [bold red]Error running tool:[/bold red] {str(e)}")
            return f"Error: {str(e)}"

    def _colorize_line(self, line: str) -> str:
        """Add basic styling to tool output lines."""
        line_lower = line.lower()
        if any(word in line_lower for word in ['vulnerable', 'critical', 'high', 'severe', 'danger', 'broken']):
            return f"[bold red]{line}[/bold red]"
        if any(word in line_lower for word in ['warning', 'medium', 'weak', 'deprecated']):
            return f"[bold yellow]{line}[/bold yellow] "
        if any(word in line_lower for word in ['ok', 'success', 'good', 'passed', 'info', 'secure']):
            return f"[bold green]{line}[/bold green]"
        return line

    def _generate_summary(self, results: Dict[str, Any]) -> str:
        """Generate a brief summary of findings for the AI analyst."""
        summary_parts = []
        
        # Look for certificate expiry in sslyze or testssl
        if "Certificate has expired" in results['sslyze_output'] or "EXPIRED" in results['testssl_output']:
            summary_parts.append("Certificate is EXPIRED.")
            
        # Look for weak protocols
        for protocol in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
            if f"{protocol} is supported" in results['sslyze_output'] or f"{protocol} offered" in results['testssl_output']:
                summary_parts.append(f"Weak protocol supported: {protocol}")

        # Vulnerabilities
        vulns = ["Heartbleed", "POODLE", "BEAST", "ROBOT", "LOGJAM", "DROWN", "SWEET32"]
        for vuln in vulns:
            if f"{vuln} is vulnerable" in results['sslyze_output'] or f"vulnerable ({vuln})" in results['testssl_output'].lower():
                summary_parts.append(f"Vulnerable to {vuln} attack.")

        if not summary_parts:
            return "No critical SSL/TLS vulnerabilities detected by quick scan summary. See full tool output for details."
        
        return " ".join(summary_parts)