"""DnsRecon scanner wrapper for comprehensive DNS enumeration."""

import subprocess
import json
import os
import time
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner

class DnsReconScanner(BaseScanner):
    """Scanner for comprehensive DNS enumeration using dnsrecon."""

    def __init__(self) -> None:
        """Initialize the DnsRecon scanner."""
        super().__init__(
            name="dnsrecon",
            description="Comprehensive DNS enumeration using dnsrecon"
        )

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform DnsRecon scan on the target.

        Args:
            target: Domain to scan
            **kwargs: Additional arguments

        Returns:
            DnsRecon scan results
        """
        start_time = time.time()
        
        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('dns', profile_name)
            if profile:
                self.set_profile(profile)

        # Extract domain from target
        domain = self._extract_domain(target)

        try:
            # Check if dnsrecon is available
            dnsrecon_bin = self._get_dnsrecon_path()
            if not dnsrecon_bin:
                return self._create_result(
                    success=False,
                    error="dnsrecon command not found on system",
                    duration=time.time() - start_time
                )

            # Build command from workflow profile or default
            profile_cmd = self.get_profile_command(domain)
            if profile_cmd:
                # Use workflow-defined command, add JSON output
                output_file = f"/tmp/dnsrecon_{int(time.time())}.json"
                cmd = profile_cmd.split() + ["-j", output_file]
            else:
                output_file = f"/tmp/dnsrecon_{int(time.time())}.json"
                cmd = [dnsrecon_bin, "-d", domain, "-j", output_file]
            
            # Run dnsrecon
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Parse results from the JSON file
            findings = []
            if os.path.exists(output_file):
                try:
                    with open(output_file, "r") as f:
                        findings = json.load(f)
                except Exception:
                    pass
                # Clean up
                os.remove(output_file)

            categorized_records = self._categorize_records(findings)
            subdomains = self._extract_subdomains_from_findings(findings, domain)

            result_data = {
                'domain': domain,
                'records': categorized_records,
                'subdomains': subdomains,
                'raw_records': findings,
                'count': len(findings),
                'summary': self._summarize_records(findings)
            }

            return self._create_result(
                success=True,
                data=result_data,
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(
                success=False,
                error="DnsRecon scan timed out",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"DnsRecon scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _get_dnsrecon_path(self) -> Optional[str]:
        """Find the dnsrecon binary path."""
        import shutil
        return shutil.which("dnsrecon")

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return as-is."""
        if target.startswith('http://') or target.startswith('https://'):
            target = target.split('://')[1].split('/')[0]
        return target

    def _categorize_records(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize findings into a dictionary of lists.
        
        Args:
            findings: List of dnsrecon findings
            
        Returns:
            Categorized records dictionary
        """
        categorized = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'SOA': [],
            'TXT': [],
            'CNAME': [],
            'SRV': []
        }
        
        for f in findings:
            rtype = f.get('type', '').upper()
            if rtype not in categorized:
                categorized[rtype] = []
            
            # Create standardized record entry
            record = {
                'type': rtype,
                'name': f.get('name', ''),
                'raw': f # Keep original finding for AI/debugging
            }
            
            # Map dnsrecon fields to standard 'value' field expected by CLI
            if rtype == 'A':
                record['value'] = f.get('address', 'N/A')
            elif rtype == 'AAAA':
                record['value'] = f.get('address', 'N/A')
            elif rtype == 'MX':
                record['value'] = f.get('exchange', 'N/A')
                record['priority'] = f.get('preference', 10)
            elif rtype == 'NS':
                record['value'] = f.get('nameserver', 'N/A')
            elif rtype == 'SOA':
                record['value'] = f.get('mname', 'N/A')
            elif rtype == 'TXT':
                record['value'] = f.get('strings', 'N/A')
            elif rtype == 'CNAME':
                record['value'] = f.get('target', 'N/A')
            elif rtype == 'SRV':
                record['value'] = f.get('target', 'N/A')
            else:
                # Fallback to whatever looks like a value
                record['value'] = f.get('address') or f.get('exchange') or f.get('nameserver') or f.get('mname') or str(f)
            
            categorized[rtype].append(record)
            
        return categorized

    def _extract_subdomains_from_findings(self, findings: List[Dict[str, Any]], domain: str) -> List[str]:
        """Extract unique subdomains from dnsrecon findings.
        
        Args:
            findings: List of dnsrecon findings
            domain: Root domain
            
        Returns:
            List of unique subdomains found
        """
        subdomains = set()
        for f in findings:
            name = f.get('name', '').lower()
            if name and name != domain.lower() and domain.lower() in name:
                subdomains.add(name)
        return sorted(list(subdomains))

    def _summarize_records(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Summarize records by type."""
        summary = {}
        for f in findings:
            rtype = f.get('type', 'Unknown')
            summary[rtype] = summary.get(rtype, 0) + 1
        return summary
