"""Async API service for concurrent HTTP requests to multiple security APIs."""

import asyncio
import aiohttp  # pyright: ignore[reportMissingImports]
import json
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from ..utils.config import config


class AsyncAPIService:
    """Async service for concurrent API calls to security services."""

    def __init__(self):
        """Initialize the async API service."""
        self.timeout = aiohttp.ClientTimeout(total=30)

    async def fetch_virustotal_reports(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Fetch VirusTotal reports for multiple URLs concurrently.

        Args:
            urls: List of URLs to scan

        Returns:
            Dictionary mapping URLs to their VirusTotal reports
        """
        if not config.virustotal_api_key:
            return {url: {'error': 'VirusTotal API key not configured'} for url in urls}

        results = {}

        connector = aiohttp.TCPConnector(limit=5, limit_per_host=2)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={'x-apikey': config.virustotal_api_key}
        ) as session:

            tasks = []
            for url in urls:
                task = asyncio.create_task(self._fetch_single_virustotal(url, session))
                tasks.append((url, task))

            for url, task in tasks:
                try:
                    result = await task
                    results[url] = result
                except Exception as e:
                    results[url] = {'error': f'Task failed: {str(e)}'}

        return results

    async def _fetch_single_virustotal(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Fetch VirusTotal report for a single URL."""
        try:
            # Submit URL for scanning
            submit_url = 'https://www.virustotal.com/api/v3/urls'
            submit_data = aiohttp.FormData()
            submit_data.add_field('url', url)

            async with session.post(submit_url, data=submit_data) as submit_response:
                if submit_response.status == 200:
                    submit_data = await submit_response.json()
                    analysis_id = submit_data.get('data', {}).get('id')

                    if analysis_id:
                        # Wait a moment for analysis
                        await asyncio.sleep(2)

                        # Get analysis results
                        result_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
                        async with session.get(result_url) as result_response:
                            if result_response.status == 200:
                                result_data = await result_response.json()
                                return self._format_virustotal_result(result_data, url)

                return {'error': f'VirusTotal submission failed: HTTP {submit_response.status}', 'url': url}

        except asyncio.TimeoutError:
            return {'error': 'VirusTotal request timeout', 'url': url}
        except aiohttp.ClientError as e:
            return {'error': f'VirusTotal request error: {str(e)}', 'url': url}
        except Exception as e:
            return {'error': f'Unexpected VirusTotal error: {str(e)}', 'url': url}

    def _format_virustotal_result(self, data: Dict[str, Any], url: str) -> Dict[str, Any]:
        """Format VirusTotal API response."""
        attributes = data.get('data', {}).get('attributes', {})

        malicious = attributes.get('stats', {}).get('malicious', 0)
        suspicious = attributes.get('stats', {}).get('suspicious', 0)
        harmless = attributes.get('stats', {}).get('harmless', 0)
        undetected = attributes.get('stats', {}).get('undetected', 0)

        total_scans = malicious + suspicious + harmless + undetected

        return {
            'url': url,
            'malicious_detections': malicious,
            'suspicious_detections': suspicious,
            'harmless_detections': harmless,
            'undetected': undetected,
            'total_scans': total_scans,
            'risk_score': (malicious + suspicious) / max(total_scans, 1) * 100,
            'status': 'completed'
        }

    async def fetch_urlscan_reports(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Fetch URLScan reports for multiple URLs concurrently.

        Args:
            urls: List of URLs to scan

        Returns:
            Dictionary mapping URLs to their URLScan reports
        """
        if not config.urlscan_api_key:
            return {url: {'error': 'URLScan API key not configured'} for url in urls}

        results = {}

        headers = {
            'API-Key': config.urlscan_api_key,
            'Content-Type': 'application/json'
        }

        connector = aiohttp.TCPConnector(limit=3, limit_per_host=1)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=headers
        ) as session:

            tasks = []
            for url in urls:
                task = asyncio.create_task(self._fetch_single_urlscan(url, session))
                tasks.append((url, task))

            for url, task in tasks:
                try:
                    result = await task
                    results[url] = result
                except Exception as e:
                    results[url] = {'error': f'Task failed: {str(e)}'}

        return results

    async def _fetch_single_urlscan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Fetch URLScan report for a single URL."""
        try:
            # Submit URL for scanning
            submit_url = 'https://urlscan.io/api/v1/scan/'
            payload = {'url': url, 'visibility': 'private'}

            async with session.post(submit_url, json=payload) as submit_response:
                if submit_response.status in [200, 201]:
                    submit_data = await submit_response.json()
                    scan_id = submit_data.get('uuid')

                    if scan_id:
                        # Wait for scan to complete (URLScan can take time)
                        await asyncio.sleep(10)

                        # Get results
                        result_url = f'https://urlscan.io/api/v1/result/{scan_id}/'
                        async with session.get(result_url) as result_response:
                            if result_response.status == 200:
                                result_data = await result_response.json()
                                return self._format_urlscan_result(result_data, url)
                            else:
                                return {'error': f'URLScan result not ready yet: HTTP {result_response.status}', 'url': url}

                return {'error': f'URLScan submission failed: HTTP {submit_response.status}', 'url': url}

        except asyncio.TimeoutError:
            return {'error': 'URLScan request timeout', 'url': url}
        except aiohttp.ClientError as e:
            return {'error': f'URLScan request error: {str(e)}', 'url': url}
        except Exception as e:
            return {'error': f'Unexpected URLScan error: {str(e)}', 'url': url}

    def _format_urlscan_result(self, data: Dict[str, Any], url: str) -> Dict[str, Any]:
        """Format URLScan API response."""
        return {
            'url': url,
            'malicious': data.get('verdicts', {}).get('malicious', False),
            'risk_score': 100 if data.get('verdicts', {}).get('malicious', False) else 0,
            'categories': data.get('categories', []),
            'server': data.get('page', {}).get('server', ''),
            'status': 'completed'
        }

    async def batch_api_requests(self, requests: List[Tuple[str, str, Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
        """
        Execute multiple API requests concurrently.

        Args:
            requests: List of (request_id, url, kwargs) tuples

        Returns:
            Dictionary mapping request_ids to their responses
        """
        results = {}

        connector = aiohttp.TCPConnector(limit=10, limit_per_host=3)

        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            tasks = []
            for request_id, url, kwargs in requests:
                task = asyncio.create_task(self._make_api_request(request_id, url, kwargs, session))
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for i, response in enumerate(responses):
                request_id = requests[i][0]
                if isinstance(response, Exception):
                    results[request_id] = {'error': f'Request failed: {str(response)}'}
                else:
                    results[request_id] = response

        return results

    async def _make_api_request(self, request_id: str, url: str, kwargs: Dict[str, Any], session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Make a single API request."""
        try:
            method = kwargs.get('method', 'GET')
            headers = kwargs.get('headers', {})
            data = kwargs.get('data')
            json_data = kwargs.get('json')

            async with session.request(method, url, headers=headers, data=data, json=json_data) as response:
                result = {
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'url': str(response.url)
                }

                if response.status == 200:
                    try:
                        if 'application/json' in response.headers.get('Content-Type', ''):
                            result['json'] = await response.json()
                        else:
                            result['text'] = await response.text()
                    except Exception:
                        result['text'] = await response.text()
                else:
                    result['error'] = f'HTTP {response.status}'

                return result

        except asyncio.TimeoutError:
            return {'error': 'Request timeout'}
        except aiohttp.ClientError as e:
            return {'error': f'Client error: {str(e)}'}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}'}


# Global async API service instance
async_api_service = AsyncAPIService()