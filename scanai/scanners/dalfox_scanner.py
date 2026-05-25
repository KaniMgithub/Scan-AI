"""Dalfox XSS scanner wrapper."""

import subprocess
import json
import os
import time
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner

class DalfoxScanner(BaseScanner):
    """Scanner for XSS detection using Dalfox."""

    # Map dalfox type codes to readable labels
    TYPE_LABELS = {
        'G': 'Grep (Pattern Match)',
        'R': 'Reflected',
        'V': 'Verified (Confirmed)',
    }

    def __init__(self) -> None:
        """Initialize the Dalfox scanner."""
        super().__init__(
            name="dalfox",
            description="Parameter analysis and XSS scanning using Dalfox"
        )

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform Dalfox scan on the target.

        Args:
            target: URL to scan (should include path and query params for XSS testing)
            **kwargs: Additional arguments

        Returns:
            Dalfox scan results
        """
        start_time = time.time()
        
        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('dalfox', profile_name)
            if profile:
                self.set_profile(profile)

        # Preserve the user's original URL including path, query params, and protocol
        if not target.startswith(('http://', 'https://')):
            scan_url = f"http://{target}"
        else:
            scan_url = target

        try:
            # Check if dalfox is available
            dalfox_bin = self._get_dalfox_path()
            if not dalfox_bin:
                return self._create_result(
                    success=False,
                    error="dalfox command not found on system",
                    duration=time.time() - start_time
                )

            # Build command from workflow profile or default
            profile_cmd = self.get_profile_command(scan_url)
            if profile_cmd:
                cmd = profile_cmd.split()
            else:
                cmd = [
                    dalfox_bin, "url", scan_url,
                    "--format", "json",
                    "--no-spinner",
                    "--no-color",
                    "--timeout", "30",
                    "--output-all",
                ]
            
            # Run dalfox
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            raw_output = f"{process.stderr}"

            # Parse JSON results from stdout
            # Dalfox --format json outputs a JSON array to stdout: [{...},{...},{}]
            findings = []
            stdout = process.stdout.strip()
            if stdout:
                try:
                    # Primary: parse as JSON array
                    parsed = json.loads(stdout)
                    if isinstance(parsed, list):
                        # Filter out empty {} entries that dalfox appends
                        findings = [f for f in parsed if isinstance(f, dict) and f.get('type')]
                    elif isinstance(parsed, dict) and parsed.get('type'):
                        findings = [parsed]
                except json.JSONDecodeError:
                    # Fallback: try line-delimited JSON (JSONL)
                    for line in stdout.split('\n'):
                        line = line.strip()
                        if line and line.startswith('{'):
                            try:
                                entry = json.loads(line)
                                if isinstance(entry, dict) and entry.get('type'):
                                    findings.append(entry)
                            except json.JSONDecodeError:
                                continue

            # Categorize findings by type
            verified = [f for f in findings if f.get('type') == 'V']
            reflected = [f for f in findings if f.get('type') == 'R']
            grep = [f for f in findings if f.get('type') == 'G']

            # Build structured vulnerability list from verified and reflected findings
            vulnerabilities = []
            for f in findings:
                if f.get('type') in ('V', 'R'):
                    vulnerabilities.append({
                        'type': self.TYPE_LABELS.get(f.get('type', ''), f.get('type', 'Unknown')),
                        'severity': f.get('severity', 'High'),
                        'param': f.get('param', 'N/A'),
                        'payload': f.get('payload', 'N/A'),
                        'poc_url': f.get('data', 'N/A'),
                        'inject_type': f.get('inject_type', 'N/A'),
                        'cwe': f.get('cwe', 'N/A'),
                        'method': f.get('method', 'GET'),
                        'evidence': f.get('evidence', 'N/A'),
                        'message': f.get('message_str', ''),
                    })

            result_data = {
                'target': scan_url,
                'findings': findings,
                'count': len(findings),
                'verified_count': len(verified),
                'reflected_count': len(reflected),
                'grep_count': len(grep),
                'vulnerabilities': vulnerabilities,
                'raw_output': raw_output
            }

            return self._create_result(
                success=True,
                data=result_data,
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(
                success=False,
                error="Dalfox scan timed out",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"Dalfox scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _get_dalfox_path(self) -> Optional[str]:
        """Find the dalfox binary path."""
        import shutil
        path = shutil.which("dalfox")
        if path:
            return path
        
        # Check common Go path
        go_path = os.path.expanduser("~/go/bin/dalfox")
        if os.path.exists(go_path):
            return go_path
            
        return None
