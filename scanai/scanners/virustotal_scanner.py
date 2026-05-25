"""VirusTotal malware reputation scanner."""

import requests
import time
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from .base_scanner import BaseScanner
from ..utils.config import config


class VirusTotalScanner(BaseScanner):
    """Scanner for VirusTotal malware reputation analysis."""

    def __init__(self) -> None:
        """Initialize the VirusTotal scanner."""
        super().__init__(
            name="virustotal",
            description="Malware reputation analysis via VirusTotal"
        )
        self.base_url = "https://www.virustotal.com/api/v3"

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Scan target URL/domain with VirusTotal.

        Args:
            target: URL or domain to scan
            **kwargs: Additional arguments
                      profile: str — workflow profile (url_scan, domain_report, phishing_check, ip_report)

        Returns:
            VirusTotal scan results
        """
        start_time = time.time()
        profile_name = kwargs.get('profile')

        # Load workflow profile
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('virustotal', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            if not config.virustotal_api_key:
                return self._create_result(
                    success=False,
                    error="VirusTotal API key not configured",
                    duration=time.time() - start_time
                )

            # Clean and validate target
            clean_target = self._clean_target(target)
            self._validate_target(clean_target, 'target')

            headers = {
                'x-apikey': config.virustotal_api_key,
                'Accept': 'application/json'
            }

            # Route based on profile
            method = None
            if self._workflow_profile:
                method = self._workflow_profile.method

            if method == 'vt_domain_report':
                return self._domain_report(clean_target, headers, start_time)
            elif method == 'vt_ip_report':
                return self._ip_report(clean_target, headers, start_time)
            elif method == 'vt_phishing_check':
                return self._phishing_check(clean_target, headers, start_time)
            # Default: url_scan
            return self._url_scan(clean_target, headers, start_time)

        except requests.RequestException as e:
            return self._create_result(
                success=False,
                error=f"VirusTotal request error: {str(e)}",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"VirusTotal scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _url_scan(self, target: str, headers: Dict, start_time: float) -> Dict[str, Any]:
        """Submit URL for full analysis."""
        try:
            submit_url = f"{self.base_url}/urls"
            response = requests.post(submit_url, headers=headers, data={'url': target})

            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                time.sleep(2)

                result_url = f"{self.base_url}/analyses/{analysis_id}"
                result_response = requests.get(result_url, headers=headers)

                if result_response.status_code == 200:
                    result_data = result_response.json()
                    parsed_results = self._parse_analysis_results(result_data)
                    return self._create_result(success=True, data=parsed_results, duration=time.time() - start_time)
                else:
                    return self._create_result(success=False, error=f"Failed to get analysis: {result_response.status_code}", duration=time.time() - start_time)
            elif response.status_code == 429:
                return self._create_result(success=False, error="VirusTotal API rate limit exceeded", duration=time.time() - start_time)
            else:
                return self._create_result(success=False, error=f"VirusTotal API error: {response.status_code}", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)

    def _domain_report(self, target: str, headers: Dict, start_time: float) -> Dict[str, Any]:
        """Get domain reputation report."""
        try:
            domain = urlparse(target).hostname or target.replace('https://', '').replace('http://', '').split('/')[0]
            url = f"{self.base_url}/domains/{domain}"
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attrs = data.get('data', {}).get('attributes', {})
                analysis = attrs.get('last_analysis_stats', {})
                categories = attrs.get('categories', {})
                reputation = attrs.get('reputation', 0)

                parsed = {
                    'malicious_count': analysis.get('malicious', 0),
                    'suspicious_count': analysis.get('suspicious', 0),
                    'harmless_count': analysis.get('harmless', 0),
                    'undetected_count': analysis.get('undetected', 0),
                    'total_engines': sum(analysis.values()) if analysis else 0,
                    'detection_ratio': f"{analysis.get('malicious', 0) + analysis.get('suspicious', 0)}/{sum(analysis.values()) if analysis else 0}",
                    'categories': categories,
                    'reputation_score': reputation,
                    'registrar': attrs.get('registrar', 'Unknown'),
                    'creation_date': attrs.get('creation_date'),
                    'top_detections': [],
                    'scan_type': 'domain_report',
                }
                return self._create_result(success=True, data=parsed, duration=time.time() - start_time)
            else:
                return self._create_result(success=False, error=f"VT domain report error: {response.status_code}", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)

    def _ip_report(self, target: str, headers: Dict, start_time: float) -> Dict[str, Any]:
        """Get IP address reputation report."""
        try:
            import socket
            # Resolve to IP if it's a domain
            hostname = urlparse(target).hostname or target.replace('https://', '').replace('http://', '').split('/')[0]
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                ip = hostname

            url = f"{self.base_url}/ip_addresses/{ip}"
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attrs = data.get('data', {}).get('attributes', {})
                analysis = attrs.get('last_analysis_stats', {})

                parsed = {
                    'malicious_count': analysis.get('malicious', 0),
                    'suspicious_count': analysis.get('suspicious', 0),
                    'harmless_count': analysis.get('harmless', 0),
                    'undetected_count': analysis.get('undetected', 0),
                    'total_engines': sum(analysis.values()) if analysis else 0,
                    'detection_ratio': f"{analysis.get('malicious', 0) + analysis.get('suspicious', 0)}/{sum(analysis.values()) if analysis else 0}",
                    'ip': ip,
                    'as_owner': attrs.get('as_owner', 'Unknown'),
                    'asn': attrs.get('asn'),
                    'country': attrs.get('country', 'Unknown'),
                    'reputation_score': attrs.get('reputation', 0),
                    'top_detections': [],
                    'scan_type': 'ip_report',
                }
                return self._create_result(success=True, data=parsed, duration=time.time() - start_time)
            else:
                return self._create_result(success=False, error=f"VT IP report error: {response.status_code}", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)

    def _phishing_check(self, target: str, headers: Dict, start_time: float) -> Dict[str, Any]:
        """Focused phishing and social engineering detection."""
        try:
            # First do a URL scan
            url_result = self._url_scan(target, headers, start_time)
            if not url_result.get('success'):
                return url_result

            data = url_result.get('data', {})

            # Enhance with phishing-specific analysis
            phishing_engines = []
            malicious_engines = []
            raw_data = data.get('raw_data', {})
            results_map = raw_data.get('data', {}).get('attributes', {}).get('results', {})

            for engine, result in results_map.items():
                cat = result.get('category', '')
                res = result.get('result', '').lower()
                if cat == 'malicious':
                    malicious_engines.append({'engine': engine, 'result': result.get('result', '')})
                    if any(kw in res for kw in ['phish', 'phishing', 'social engineering', 'deceptive', 'fraud']):
                        phishing_engines.append({'engine': engine, 'result': result.get('result', '')})

            # Calculate phishing verdict
            total = data.get('total_engines', 1) or 1
            malicious = data.get('malicious_count', 0)
            phishing_count = len(phishing_engines)

            if phishing_count >= 3:
                verdict = "PHISHING DETECTED"
                risk = "CRITICAL"
            elif phishing_count >= 1:
                verdict = "LIKELY PHISHING"
                risk = "HIGH"
            elif malicious >= 3:
                verdict = "MALICIOUS"
                risk = "HIGH"
            elif malicious >= 1:
                verdict = "SUSPICIOUS"
                risk = "MEDIUM"
            else:
                verdict = "CLEAN"
                risk = "LOW"

            data['phishing_verdict'] = verdict
            data['phishing_risk'] = risk
            data['phishing_detections'] = phishing_count
            data['phishing_engines'] = phishing_engines[:10]
            data['malicious_engines'] = malicious_engines[:10]
            data['scan_type'] = 'phishing_check'

            # Remove raw_data to keep it clean
            data.pop('raw_data', None)

            return self._create_result(success=True, data=data, duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)

    def _clean_target(self, target: str) -> str:
        """Clean and normalize the target URL/domain.

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

    def _url_to_id(self, url: str) -> str:
        """Convert URL to VirusTotal URL ID.

        Args:
            url: URL to convert

        Returns:
            Base64-encoded URL ID
        """
        import base64
        url_bytes = url.encode('utf-8')
        return base64.urlsafe_b64encode(url_bytes).decode('utf-8').rstrip('=')

    def _parse_analysis_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal analysis results.

        Args:
            data: Raw VirusTotal API response

        Returns:
            Parsed analysis results
        """
        attributes = data.get('data', {}).get('attributes', {})

        stats = attributes.get('stats', {})
        results = attributes.get('results', {})

        # Extract top malicious detections
        top_detections = []
        for engine, result in results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                top_detections.append({
                    'engine': engine,
                    'category': result.get('category'),
                    'result': result.get('result', '')
                })
                if len(top_detections) >= 5:  # Limit to top 5
                    break

        return {
            'malicious_count': stats.get('malicious', 0),
            'suspicious_count': stats.get('suspicious', 0),
            'harmless_count': stats.get('harmless', 0),
            'undetected_count': stats.get('undetected', 0),
            'total_engines': sum(stats.values()),
            'detection_ratio': f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{sum(stats.values())}",
            'top_detections': top_detections,
            'raw_data': data
        }