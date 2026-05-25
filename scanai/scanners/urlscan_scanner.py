"""URLScan.io threat detection scanner."""

import requests
import time
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from .base_scanner import BaseScanner
from ..utils.config import config


class URLScanScanner(BaseScanner):
    """Scanner for URL analysis and threat detection via URLScan.io."""

    def __init__(self) -> None:
        """Initialize the URLScan scanner."""
        super().__init__(
            name="urlscan",
            description="URL analysis and threat detection"
        )
        self.base_url = "https://urlscan.io/api/v1"

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Scan target URL with URLScan.io.

        Args:
            target: URL to scan
            **kwargs: Additional arguments (ignored)

        Returns:
            URLScan analysis results
        """
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('urlscan', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            # Clean and validate target
            clean_target = self._clean_target(target)
            self._validate_target(clean_target, 'URL')

            headers = {'Accept': 'application/json'}
            if config.urlscan_api_key:
                headers['API-Key'] = config.urlscan_api_key

            # Route based on workflow profile method
            active_method = None
            if self._workflow_profile and self._workflow_profile.method:
                active_method = self._workflow_profile.method

            if active_method == 'urlscan_search':
                # Search existing results instead of submitting new scan
                from urllib.parse import urlparse
                domain = urlparse(clean_target).hostname or clean_target
                search_url = f"{self.base_url}/search/?q=domain:{domain}"
                search_resp = requests.get(search_url, headers=headers, timeout=30)
                if search_resp.status_code == 200:
                    search_data = search_resp.json()
                    results_list = search_data.get('results', [])[:5]
                    parsed = {
                        'search_results': results_list,
                        'total': search_data.get('total', 0),
                        'source': 'urlscan_search',
                    }
                    return self._create_result(success=True, data=parsed, duration=time.time() - start_time)
                else:
                    return self._create_result(success=False, error=f"URLScan search error: {search_resp.status_code}", duration=time.time() - start_time)

            # Default: submit URL for scanning
            submit_url = f"{self.base_url}/scan/"
            payload = {'url': clean_target, 'visibility': 'public'}

            response = requests.post(submit_url, headers=headers, json=payload)

            if response.status_code == 200:
                submission_data = response.json()

                # Wait for analysis to complete
                time.sleep(3)

                # Try to get results
                if 'uuid' in submission_data:
                    uuid = submission_data['uuid']
                    result_data = self._fetch_result(uuid)

                    if result_data:
                        parsed_results = self._parse_scan_results(result_data)
                        return self._create_result(
                            success=True,
                            data=parsed_results,
                            duration=time.time() - start_time
                        )

                # Fall back to submission data if result fetch fails
                parsed_results = self._parse_submission_data(submission_data)
                return self._create_result(
                    success=True,
                    data=parsed_results,
                    duration=time.time() - start_time
                )

            elif response.status_code == 429:
                return self._create_result(
                    success=False,
                    error="URLScan API rate limit exceeded",
                    duration=time.time() - start_time
                )
            else:
                return self._create_result(
                    success=False,
                    error=f"URLScan API error: {response.status_code}",
                    duration=time.time() - start_time
                )

        except requests.RequestException as e:
            return self._create_result(
                success=False,
                error=f"URLScan request error: {str(e)}",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"URLScan scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _clean_target(self, target: str) -> str:
        """Clean and normalize the target URL.

        Args:
            target: Raw target string

        Returns:
            Cleaned target URL
        """
        target = target.strip()

        # Add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        return target

    def _fetch_result(self, uuid: str) -> Optional[Dict[str, Any]]:
        """Fetch scan results by UUID.

        Args:
            uuid: Scan UUID

        Returns:
            Scan results or None if failed
        """
        try:
            headers = {'Accept': 'application/json'}
            if config.urlscan_api_key:
                headers['API-Key'] = config.urlscan_api_key

            result_url = f"{self.base_url}/result/{uuid}/"
            response = requests.get(result_url, headers=headers, timeout=10)

            if response.status_code == 200:
                return response.json()

        except Exception:
            pass

        return None

    def _parse_scan_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse complete URLScan results.

        Args:
            data: Raw URLScan result data

        Returns:
            Parsed scan results
        """
        verdicts = data.get('verdicts', {}).get('overall', {})
        task = data.get('task', {})
        page = data.get('page', {})

        return {
            'malicious': verdicts.get('malicious', False),
            'score': verdicts.get('score', 0),
            'categories': verdicts.get('categories', []),
            'brands': verdicts.get('brands', []),
            'tags': task.get('tags', []),
            'country': page.get('country'),
            'server': page.get('server'),
            'ip': page.get('ip'),
            'domain': page.get('domain'),
            'url': task.get('url'),
            'uuid': data.get('task', {}).get('uuid'),
            'raw_data': data
        }

    def _parse_submission_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse URLScan submission response.

        Args:
            data: Raw submission data

        Returns:
            Parsed submission data
        """
        return {
            'uuid': data.get('uuid'),
            'url': data.get('url'),
            'visibility': data.get('visibility'),
            'submission_time': data.get('submittedAt'),
            'message': data.get('message', 'Scan submitted, results may not be ready yet'),
            'raw_data': data
        }