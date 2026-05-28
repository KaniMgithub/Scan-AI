"""Shodan InternetDB service for IP intelligence."""

import requests
from typing import Dict, Any, Optional

from ..utils.config import config


class ShodanInternetDBService:
    """Shodan InternetDB service for IP address intelligence."""

    def __init__(self) -> None:
        """Initialize the InternetDB service."""
        self.base_url = "https://internetdb.shodan.io"

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Lookup IP address information from InternetDB.

        Args:
            ip_address: IP address to lookup

        Returns:
            InternetDB lookup results
        """
        try:
            url = f"{self.base_url}/{ip_address}"

            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return self._format_result(data)
            elif response.status_code == 404:
                return {
                    'error': 'IP address not found in InternetDB',
                    'ip': ip_address
                }
            else:
                return {
                    'error': f'InternetDB API error: HTTP {response.status_code}',
                    'ip': ip_address
                }

        except requests.RequestException as e:
            return {
                'error': f'InternetDB request error: {str(e)}',
                'ip': ip_address
            }
        except Exception as e:
            return {
                'error': f'InternetDB error: {str(e)}',
                'ip': ip_address
            }

    def _format_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format InternetDB API response.

        Args:
            data: Raw API response

        Returns:
            Formatted result
        """
        result = {
            'ip': data.get('ip'),
            'hostnames': data.get('hostnames', []),
            'ports': data.get('ports', []),
            'cpes': data.get('cpes', []),
            'tags': data.get('tags', []),
            'vulns': data.get('vulns', []),
            'raw_data': data
        }

        # Add derived information
        if result['vulns']:
            result['vulnerability_count'] = len(result['vulns'])
            # Extract CVE IDs
            result['cve_ids'] = [vuln.split('/')[0] if '/' in vuln else vuln for vuln in result['vulns']]
        else:
            result['vulnerability_count'] = 0
            result['cve_ids'] = []

        if result['cpes']:
            result['cpe_count'] = len(result['cpes'])
        else:
            result['cpe_count'] = 0

        return result