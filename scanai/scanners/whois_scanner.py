"""WHOIS domain lookup scanner using system whois command."""

import subprocess
import re
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from .base_scanner import BaseScanner
from ..utils.config import config


class WhoisScanner(BaseScanner):
    """Scanner for WHOIS domain information using system whois command."""

    def __init__(self) -> None:
        """Initialize the WHOIS scanner."""
        super().__init__(
            name="whois",
            description="Domain registration and ownership information"
        )

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform WHOIS lookup on the target domain.

        Args:
            target: Domain name or URL to lookup
            **kwargs: Additional arguments (ignored)

        Returns:
            WHOIS lookup results
        """
        import time
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('whois', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            # Extract domain from URL if necessary
            domain = self._extract_domain(target)
            self._validate_target(domain, 'domain')

            # Check if whois is available
            if not self._is_whois_available():
                return self._create_result(
                    success=False,
                    error="whois command not found on system",
                    duration=time.time() - start_time
                )

            # Find and build whois command
            whois_cmd = self._get_whois_command()
            if not whois_cmd:
                return self._create_result(
                    success=False,
                    error="Could not find whois command",
                    duration=time.time() - start_time
                )

            whois_cmd.append(domain)

            # Perform whois lookup
            result = subprocess.run(
                whois_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                parsed_data = self._parse_whois_output(result.stdout)
                
                # Detailed profile: include raw output
                active_method = None
                if self._workflow_profile and self._workflow_profile.method:
                    active_method = self._workflow_profile.method
                if active_method == 'whois_detailed':
                    parsed_data['raw_output'] = result.stdout
                    parsed_data['raw_stderr'] = result.stderr if result.stderr else ''
                
                return self._create_result(
                    success=True,
                    data=parsed_data,
                    duration=time.time() - start_time
                )
            else:
                error_msg = result.stderr.strip() or "WHOIS lookup failed"
                return self._create_result(
                    success=False,
                    error=error_msg,
                    duration=time.time() - start_time
                )

        except subprocess.TimeoutExpired:
            return self._create_result(
                success=False,
                error="WHOIS lookup timed out",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"WHOIS scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return as-is if already a domain.

        Args:
            target: URL or domain string

        Returns:
            Extracted domain name
        """
        # Remove protocol if present
        target = target.lower().strip()
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.netloc
        else:
            # Assume it's already a domain, remove www. prefix if present
            if target.startswith('www.'):
                return target[4:]
            return target

    def _is_whois_available(self) -> bool:
        """Check if whois command is available on the system.

        Returns:
            True if whois is available, False otherwise
        """
        # Check common whois command paths
        whois_paths = [
            config.whois_path,
            '/usr/bin/whois',
            '/bin/whois',
            '/usr/local/bin/whois',
            'whois'  # Use PATH
        ]

        for whois_path in whois_paths:
            if not whois_path:
                continue

            try:
                cmd = [whois_path, '--help'] if whois_path != 'whois' else ['whois', '--help']

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 or result.returncode == 1:  # Some whois commands return 1 for --help
                    return True
            except Exception:
                continue

        return False

    def _get_whois_command(self) -> Optional[List[str]]:
        """Get the whois command to use.

        Returns:
            List containing the whois command and path, or None if not found
        """
        # Check common whois command paths
        whois_paths = [
            config.whois_path,
            '/usr/bin/whois',
            '/bin/whois',
            '/usr/local/bin/whois',
            'whois'  # Use PATH
        ]

        for whois_path in whois_paths:
            if not whois_path:
                continue

            try:
                cmd = [whois_path] if whois_path != 'whois' else ['whois']

                # Test the command with a simple query
                result = subprocess.run(
                    cmd + ['--help'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 or result.returncode == 1:  # Some whois commands return 1 for --help
                    return cmd
            except Exception:
                continue

        return None

    def _parse_whois_output(self, output: str) -> Dict[str, Any]:
        """Parse WHOIS output into structured data.

        Args:
            output: Raw WHOIS output

        Returns:
            Parsed WHOIS data
        """
        parsed = {
            'raw_output': output,
            'domain': None,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'registrant': {},
            'admin_contact': {},
            'tech_contact': {},
            'status': []
        }

        lines = output.split('\n')
        current_section = None

        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue

            # Extract key-value pairs
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()

                # Domain name
                if 'domain name' in key or key == 'domain':
                    parsed['domain'] = value.lower()

                # Registrar
                elif 'registrar' in key:
                    parsed['registrar'] = value

                # Dates
                elif 'creation date' in key or 'created' in key:
                    parsed['creation_date'] = value
                elif 'expiration date' in key or 'expires' in key:
                    parsed['expiration_date'] = value
                elif 'updated date' in key or 'updated' in key:
                    parsed['updated_date'] = value

                # Name servers
                elif 'name server' in key:
                    if value:
                        parsed['name_servers'].append(value.lower())

                # Status
                elif key == 'status':
                    parsed['status'].append(value)

                # Contact information
                elif any(contact in key for contact in ['registrant', 'admin', 'tech']):
                    if 'registrant' in key:
                        current_section = 'registrant'
                        if key != 'registrant':
                            parsed['registrant'][key.replace('registrant ', '')] = value
                        else:
                            parsed['registrant']['name'] = value
                    elif 'admin' in key:
                        current_section = 'admin_contact'
                        if key != 'admin contact':
                            parsed['admin_contact'][key.replace('admin ', '')] = value
                    elif 'tech' in key:
                        current_section = 'tech_contact'
                        if key != 'tech contact':
                            parsed['tech_contact'][key.replace('tech ', '')] = value
                    else:
                        if current_section:
                            parsed[current_section][key] = value

        # Clean up data
        parsed['name_servers'] = list(set(parsed['name_servers']))  # Remove duplicates
        parsed['status'] = list(set(parsed['status']))  # Remove duplicates

        return parsed