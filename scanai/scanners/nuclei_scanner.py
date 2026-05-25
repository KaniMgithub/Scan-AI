"""Nuclei vulnerability scanner wrapper."""

import subprocess
import json
import os
import time
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner

class NucleiScanner(BaseScanner):
    """Scanner for vulnerability detection using Nuclei."""

    def __init__(self) -> None:
        """Initialize the Nuclei scanner."""
        super().__init__(
            name="nuclei",
            description="Vulnerability scanning using Nuclei templates"
        )

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform Nuclei scan on the target.

        Args:
            target: URL or domain to scan
            **kwargs: Additional arguments (templates, severity, etc.)

        Returns:
            Nuclei scan results
        """
        start_time = time.time()
        
        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('nuclei', profile_name)
            if profile:
                self.set_profile(profile)

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            scan_url = f"https://{target}"
        else:
            scan_url = target

        try:
            # Check if nuclei is available
            nuclei_bin = self._get_nuclei_path()
            if not nuclei_bin:
                return self._create_result(
                    success=False,
                    error="nuclei command not found on system",
                    duration=time.time() - start_time
                )

            # Build command from workflow profile or default
            profile_cmd = self.get_profile_command(scan_url)
            if profile_cmd:
                cmd = profile_cmd.split()
                # Ensure JSON export for parsing
                if '-json-export' not in profile_cmd and '-jsonl' not in profile_cmd:
                    cmd.extend(["-json-export", "/tmp/nuclei_output.json"])
            else:
                cmd = [nuclei_bin, "-u", scan_url, "-silent", "-json-export", "/tmp/nuclei_output.json"]
            
            # severity filter if provided (override)
            severity = kwargs.get('severity')
            if severity and '-severity' not in ' '.join(cmd):
                cmd.extend(["-severity", severity])

            # Run nuclei
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            raw_output = f"STDOUT:\n{process.stdout}\n\nSTDERR:\n{process.stderr}"

            # Parse results from the temporary file
            findings = []
            if os.path.exists("/tmp/nuclei_output.json"):
                with open("/tmp/nuclei_output.json", "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                findings.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                # Clean up
                os.remove("/tmp/nuclei_output.json")

            result_data = {
                'target': scan_url,
                'findings': findings,
                'count': len(findings),
                'severities': self._summarize_severities(findings),
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
                error="Nuclei scan timed out",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"Nuclei scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _get_nuclei_path(self) -> Optional[str]:
        """Find the nuclei binary path."""
        import shutil
        path = shutil.which("nuclei")
        if path:
            return path
        
        # Check common Go path
        go_path = os.path.expanduser("~/go/bin/nuclei")
        if os.path.exists(go_path):
            return go_path
            
        return None

    def _summarize_severities(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Summarize findings by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get('info', {}).get('severity', 'info').lower()
            if sev in summary:
                summary[sev] += 1
        return summary
