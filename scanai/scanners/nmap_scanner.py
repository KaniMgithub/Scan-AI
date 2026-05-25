"""Nmap network scanner using system nmap command."""

import subprocess
import re
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from .base_scanner import BaseScanner
from ..utils.config import config


class NmapScanner(BaseScanner):
    """Scanner for network ports and services using system nmap command."""

    def __init__(self) -> None:
        """Initialize the Nmap scanner."""
        super().__init__(
            name="nmap",
            description="Network port scanning and service detection"
        )

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform Nmap scan on the target.

        Args:
            target: IP address, domain, or URL to scan
            **kwargs: Additional arguments
                      profile: str — workflow profile name (e.g. 'service_scan', 'stealth_scan')
                      timeout: int — override timeout

        Returns:
            Nmap scan results
        """
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            registry = get_registry()
            profile = registry.get_profile('nmap', profile_name)
            if profile:
                self.set_profile(profile)

        timeout = kwargs.get('timeout', self.get_profile_timeout(config.nmap_timeout))

        try:
            # Extract IP/domain from URL if necessary
            scan_target = self._extract_target(target)
            self._validate_target(scan_target, 'target')

            # Check if nmap is available
            if not self._is_nmap_available():
                return self._create_result(
                    success=False,
                    error="nmap command not found on system",
                    duration=time.time() - start_time
                )

            # Build command from workflow profile or fall back to default
            profile_cmd = self.get_profile_command(scan_target)
            if profile_cmd:
                # Use workflow-defined command
                nmap_cmd = profile_cmd.split()
                # Inject host-timeout if not already present
                if '--host-timeout' not in profile_cmd:
                    nmap_cmd.extend(['--host-timeout', f'{timeout}s'])
            else:
                # Default: aggressive scan
                nmap_cmd = [config.nmap_path] if config.nmap_path else ['nmap']
                nmap_cmd.extend([
                    '-A',
                    '-T4',
                    '--max-retries', '2',
                    '--host-timeout', f'{timeout}s',
                    scan_target
                ])

            # Perform basic nmap scan
            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10  # Add buffer for subprocess timeout
            )

            if result.returncode == 0:
                parsed_data = self._parse_nmap_output(result.stdout)
                # Check if nmap actually scanned anything or just timed out
                stderr_lower = result.stderr.lower()
                if (parsed_data.get('scan_skipped') or
                    (not parsed_data.get('ports') and
                     ("host timeout" in stderr_lower or
                      "skipping host" in stderr_lower or
                      "due to host timeout" in stderr_lower))):
                    return self._create_result(
                        success=False,
                        error="Nmap scan blocked by host protection (timeout). Target may be protected by WAF/CDN.",
                        duration=time.time() - start_time
                    )
                return self._create_result(
                    success=True,
                    data=parsed_data,
                    duration=time.time() - start_time
                )
            else:
                error_msg = result.stderr.strip() or "Nmap scan failed"
                # Check if it's a timeout/host protection issue
                if ("host timeout" in error_msg.lower() or
                    "skipping host" in error_msg.lower() or
                    "due to host timeout" in error_msg.lower()):
                    error_msg = f"Nmap scan blocked by host protection (timeout). Target may be protected by WAF/CDN. Try scanning a different target or use --timeout to increase scan time."
                return self._create_result(
                    success=False,
                    error=error_msg,
                    duration=time.time() - start_time
                )

        except subprocess.TimeoutExpired:
            return self._create_result(
                success=False,
                error=f"Nmap scan timed out after {timeout} seconds",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"Nmap scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _extract_target(self, target: str) -> str:
        """Extract IP/domain from URL or return as-is.

        Args:
            target: URL, domain, or IP

        Returns:
            Clean target for nmap scanning
        """
        target = target.strip()

        # If it's a URL, extract the host
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.hostname or target

        return target

    def _is_nmap_available(self) -> bool:
        """Check if nmap command is available on the system.

        Returns:
            True if nmap is available, False otherwise
        """
        try:
            nmap_cmd = [config.nmap_path] if config.nmap_path else ['nmap']
            nmap_cmd.append('--version')

            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output into structured data.

        Args:
            output: Raw nmap output

        Returns:
            Parsed nmap data
        """
        result = {
            'target': None,
            'host_status': None,
            'ports': [],
            'services': [],  # Detected services with versions for CVE scanning
            'os_fingerprint': None,
            'scan_skipped': False,  # Flag to indicate if scan was skipped
            'raw_output': output
        }

        lines = output.split('\n')
        current_port_info = {}

        for line in lines:
            line = line.strip()

            # Extract target/host info
            match = re.search(r'Nmap scan report for ([^\s]+)', line)
            if match:
                result['target'] = match.group(1)

            # Extract host status
            match = re.search(r'Host is ([^\.]+)\.', line)
            if match:
                result['host_status'] = match.group(1)

            # Check if host was skipped due to timeout
            if 'skipping host' in line.lower() and 'due to host timeout' in line.lower():
                result['scan_skipped'] = True
                result['host_status'] = 'skipped (timeout)'

            # Extract port information
            match = re.match(r'^(\d+)/(\w+)\s+(\w+)\s+(.+)', line)
            if match:
                port_num, protocol, state, service_info = match.groups()

                port_data = {
                    'port': int(port_num),
                    'protocol': protocol,
                    'state': state,
                    'service': 'unknown',
                    'version': '',
                    'extra_info': service_info
                }

                # Parse service info more thoroughly
                parts = service_info.split(None, 2)  # Split on whitespace, max 3 parts
                port_data['service'] = parts[0] if parts else 'unknown'

                # Extract software name and version more intelligently
                software_name = None
                software_version = None

                if len(parts) > 1:
                    service_text = ' '.join(parts[1:])

                    # Common patterns: "Apache httpd 2.4.58", "nginx 1.20.1", "Gunicorn 19.9.0", "OpenSSH 8.2", etc.
                    # Look for software name followed by version
                    version_patterns = [
                        (r'([A-Za-z][A-Za-z0-9_-]+)\s+(\d+\.\d+(?:\.\d+)*(?:\.\d+)?)', 1, 2),  # Name Version
                        (r'([A-Za-z][A-Za-z0-9_-]+\s+[a-z]+)\s+(\d+\.\d+(?:\.\d+)*(?:\.\d+)?)', 1, 2),  # "Apache httpd" Version
                        (r'([A-Za-z][A-Za-z0-9_-]+)\s+([a-z]+)\s+(\d+\.\d+(?:\.\d+)*(?:\.\d+)?)', 1, 3),  # Name type Version
                        (r'([A-Za-z][A-Za-z0-9_-]+)\s+net/http\s+server', 1, None),  # "Golang net/http server"
                        (r'([A-Za-z][A-Za-z0-9_-]+)\s+([a-z]+/[a-z]+)\s+server', 1, None),  # "Golang net/http server"
                    ]

                    for pattern, name_group, version_group in version_patterns:
                        match = re.search(pattern, service_text, re.IGNORECASE)
                        if match:
                            software_name = match.group(name_group).strip()
                            software_version = match.group(version_group).strip() if version_group and len(match.groups()) >= version_group else ""
                            break

                    # If no pattern matched, try to extract just version
                    if not software_name:
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)*(?:\.\d+)?)', service_text)
                        if version_match:
                            software_version = version_match.group(1)
                            # Use the first non-numeric part as software name
                            name_parts = re.split(r'\d+', service_text)[0].strip()
                            if name_parts:
                                software_name = name_parts.split()[0] if name_parts.split() else service_text.split()[0]

                # Set the extracted software info
                if software_name:
                    port_data['service'] = software_name
                    port_data['software_name'] = software_name
                    port_data['full_version'] = service_text  # Always store the full banner
                if software_version:
                    port_data['version'] = software_version

                result['ports'].append(port_data)

                # Add to services list for CVE scanning if it's an open port with software info
                if state == 'open' and (port_data.get('software_name') or port_data.get('version')):
                    service_info = {
                        'name': port_data.get('software_name', port_data.get('service', 'unknown')),
                        'version': port_data.get('version', ''),
                        'port': port_num,
                        'protocol': protocol,
                        'source': 'nmap'
                    }
                    result['services'].append(service_info)

            # Extract OS fingerprint
            if line.startswith('OS details:'):
                result['os_fingerprint'] = line.replace('OS details:', '').strip()
            elif line.startswith('Aggressive OS guesses:'):
                result['os_fingerprint'] = line.replace('Aggressive OS guesses:', '').strip()

        return result