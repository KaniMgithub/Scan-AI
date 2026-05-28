"""Shodan CVEDB service for vulnerability intelligence."""

import requests  # pyright: ignore[reportMissingModuleSource]
import asyncio
import aiohttp  # pyright: ignore[reportMissingImports]
from typing import Dict, Any, List, Optional

from ..utils.config import config


class ShodanCVEDBService:
    """Shodan CVEDB service for vulnerability intelligence."""

    def __init__(self) -> None:
        """Initialize the CVEDB service."""
        self.base_url = "https://cvedb.shodan.io"

    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Lookup specific CVE information.

        Args:
            cve_id: CVE ID to lookup (e.g., "CVE-2021-44228")

        Returns:
            CVE details
        """
        try:
            url = f"{self.base_url}/cve/{cve_id}"

            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return self._format_cve_result(data)
            elif response.status_code == 404:
                return {
                    'error': f'CVE {cve_id} not found',
                    'cve_id': cve_id
                }
            else:
                return {
                    'error': f'CVEDB API error: HTTP {response.status_code}',
                    'cve_id': cve_id
                }

        except requests.RequestException as e:
            return {
                'error': f'CVEDB request error: {str(e)}',
                'cve_id': cve_id
            }
        except Exception as e:
            return {
                'error': f'CVEDB error: {str(e)}',
                'cve_id': cve_id
            }

    def search_cves_by_cpe(self, cpe23: str, limit: int = 50) -> Dict[str, Any]:
        """
        Search for CVEs by CPE 2.3 string.

        Args:
            cpe23: CPE 2.3 string
            limit: Maximum number of results

        Returns:
            CVE search results
        """
        try:
            url = f"{self.base_url}/cves"
            params = {'cpe23': cpe23}

            response = requests.get(url, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                return self._format_cve_search_result(data, limit)
            else:
                return {
                    'error': f'CVEDB API error: HTTP {response.status_code}',
                    'cpe23': cpe23
                }

        except requests.RequestException as e:
            return {
                'error': f'CVEDB request error: {str(e)}',
                'cpe23': cpe23
            }
        except Exception as e:
            return {
                'error': f'CVEDB error: {str(e)}',
                'cpe23': cpe23
            }

    def search_cves_by_product(self, product: str, limit: int = 50) -> Dict[str, Any]:
        """
        Search for CVEs by product name.

        Args:
            product: Product name
            limit: Maximum number of results

        Returns:
            CVE search results
        """
        try:
            url = f"{self.base_url}/cves"
            params = {'product': product}

            response = requests.get(url, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                return self._format_cve_search_result(data, limit)
            else:
                return {
                    'error': f'CVEDB API error: HTTP {response.status_code}',
                    'product': product
                }

        except requests.RequestException as e:
            return {
                'error': f'CVEDB request error: {str(e)}',
                'product': product
            }
        except Exception as e:
            return {
                'error': f'CVEDB error: {str(e)}',
                'product': product
            }

    def get_newest_vulnerabilities(self, limit: int = 20) -> Dict[str, Any]:
        """
        Get newest vulnerabilities.

        Args:
            limit: Maximum number of results

        Returns:
            Newest CVE results
        """
        try:
            url = f"{self.base_url}/cves"

            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return self._format_cve_search_result(data, limit)
            else:
                return {
                    'error': f'CVEDB API error: HTTP {response.status_code}'
                }

        except requests.RequestException as e:
            return {
                'error': f'CVEDB request error: {str(e)}'
            }
        except Exception as e:
            return {
                'error': f'CVEDB error: {str(e)}'
            }

    def _format_cve_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format single CVE result.

        Args:
            data: Raw CVE data

        Returns:
            Formatted CVE result
        """
        return {
            'cve': data.get('cve'),
            'summary': data.get('summary'),
            'cvss': data.get('cvss'),
            'cvss_version': data.get('cvss_version'),
            'cvss_v2': data.get('cvss_v2'),
            'cvss_v3': data.get('cvss_v3'),
            'epss': data.get('epss'),
            'ranking_epss': data.get('ranking_epss'),
            'kev': data.get('kev', False),
            'propose_action': data.get('propose_action'),
            'ransomware_campaign': data.get('ransomware_campaign'),
            'references': data.get('references', []),
            'published_time': data.get('published_time'),
            'cpes': data.get('cpes', []),
            'severity': self._determine_severity(data),
            'raw_data': data
        }

    def _format_cve_search_result(self, data: Dict[str, Any], limit: int) -> Dict[str, Any]:
        """Format CVE search results.

        Args:
            data: Raw search results
            limit: Maximum results to return

        Returns:
            Formatted search results
        """
        cves = data.get('cves', [])[:limit] if isinstance(data.get('cves'), list) else []

        # Format each CVE
        formatted_cves = []
        for cve in cves:
            formatted_cves.append(self._format_cve_result(cve))

        return {
            'total_results': len(formatted_cves),
            'cves': formatted_cves,
            'raw_data': data
        }

    def _determine_severity(self, cve_data: Dict[str, Any]) -> str:
        """Determine CVE severity from CVSS scores.

        Args:
            cve_data: CVE data

        Returns:
            Severity level
        """
        cvss_v3 = cve_data.get('cvss_v3')
        cvss_v2 = cve_data.get('cvss_v2')

        if cvss_v3 is not None:
            if cvss_v3 >= 9.0:
                return 'CRITICAL'
            elif cvss_v3 >= 7.0:
                return 'HIGH'
            elif cvss_v3 >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        elif cvss_v2 is not None:
            if cvss_v2 >= 7.0:
                return 'HIGH'
            elif cvss_v2 >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'

        return 'UNKNOWN'

    async def async_lookup_cve(self, cve_id: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """
        Async lookup specific CVE information.

        Args:
            cve_id: CVE ID to lookup (e.g., "CVE-2021-44228")
            session: aiohttp ClientSession

        Returns:
            CVE details
        """
        try:
            url = f"{self.base_url}/cve/{cve_id}"

            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._format_cve_result(data)
                elif response.status == 404:
                    return {
                        'error': f'CVE {cve_id} not found',
                        'cve_id': cve_id
                    }
                else:
                    return {
                        'error': f'CVEDB API error: HTTP {response.status}',
                        'cve_id': cve_id
                    }

        except asyncio.TimeoutError:
            return {
                'error': f'CVEDB request timeout for {cve_id}',
                'cve_id': cve_id
            }
        except aiohttp.ClientError as e:
            return {
                'error': f'CVEDB request error: {str(e)}',
                'cve_id': cve_id
            }
        except Exception as e:
            return {
                'error': f'Unexpected error for {cve_id}: {str(e)}',
                'cve_id': cve_id
            }

    async def async_lookup_multiple_cves(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Async lookup multiple CVEs concurrently.

        Args:
            cve_ids: List of CVE IDs to lookup

        Returns:
            Dictionary mapping CVE IDs to their results
        """
        results = {}

        # Create a connector with connection pooling
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)

        async with aiohttp.ClientSession(connector=connector) as session:
            # Create tasks for all CVE lookups
            tasks = []
            for cve_id in cve_ids:
                task = asyncio.create_task(self.async_lookup_cve(cve_id, session))
                tasks.append((cve_id, task))

            # Wait for all tasks to complete
            for cve_id, task in tasks:
                try:
                    result = await task
                    results[cve_id] = result
                except Exception as e:
                    results[cve_id] = {
                        'error': f'Task failed: {str(e)}',
                        'cve_id': cve_id
                    }

        return results