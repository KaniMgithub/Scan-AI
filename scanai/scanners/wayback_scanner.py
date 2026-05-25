"""Wayback Machine URL archive discovery."""

import time
import requests
from typing import Dict, Any
from .base_scanner import BaseScanner


class WaybackScanner(BaseScanner):
    """Discover archived URLs via Wayback Machine CDX API."""

    def __init__(self) -> None:
        super().__init__("wayback", "Wayback Machine URL archive discovery")
        self.cdx_url = "http://web.archive.org/cdx/search/cdx"

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()

        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('wayback', profile_name)
            if profile:
                self.set_profile(profile)

        domain = target.replace('https://', '').replace('http://', '').split('/')[0]

        try:
            # Determine scope from profile
            active_method = None
            if self._workflow_profile and self._workflow_profile.method:
                active_method = self._workflow_profile.method

            limit = 1000
            if active_method == 'quick':
                limit = 200
            elif active_method == 'deep':
                limit = 5000
            elif active_method == 'endpoints_only':
                limit = 3000

            # Query CDX API
            params = {
                'url': f'*.{domain}/*',
                'output': 'json',
                'fl': 'original,timestamp,statuscode,mimetype',
                'collapse': 'urlkey',
                'limit': limit,
            }

            response = requests.get(
                self.cdx_url, params=params,
                headers={'User-Agent': 'ScanAI/v0.4.0'},
                timeout=self.get_profile_timeout(60)
            )

            if response.status_code != 200:
                return self._create_result(
                    success=False, error=f"Wayback CDX API error: {response.status_code}",
                    duration=time.time() - start_time
                )

            data = response.json()
            if not data or len(data) < 2:
                return self._create_result(
                    success=True,
                    data={'domain': domain, 'urls': [], 'total': 0, 'endpoints': [], 'interesting': []},
                    duration=time.time() - start_time
                )

            # First row is headers
            headers = data[0]
            rows = data[1:]

            urls = set()
            endpoints = set()
            interesting = []
            subdomains = set()

            interesting_extensions = ['.sql', '.bak', '.old', '.zip', '.tar', '.gz', '.env', '.git',
                                      '.config', '.conf', '.ini', '.log', '.json', '.xml', '.yaml',
                                      '.yml', '.key', '.pem', '.csv', '.db', '.sqlite', '.dump',
                                      '.php~', '.swp', '.DS_Store', '.htaccess', '.htpasswd']

            interesting_paths = ['/admin', '/login', '/api/', '/graphql', '/debug', '/console',
                                 '/swagger', '/phpinfo', '/wp-admin', '/backup', '/.git/',
                                 '/actuator', '/server-status', '/server-info', '/phpmyadmin']

            for row in rows:
                url = row[0] if len(row) > 0 else ''
                urls.add(url)

                # Extract endpoints (paths only)
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    path = parsed.path
                    if path and path != '/':
                        endpoints.add(path)

                    # Extract subdomains
                    host = parsed.hostname or ''
                    if host and host != domain and host.endswith(f'.{domain}'):
                        subdomains.add(host)

                    # Flag interesting files
                    if any(url.lower().endswith(ext) for ext in interesting_extensions):
                        interesting.append({'url': url, 'type': 'sensitive_file'})
                    elif any(p in url.lower() for p in interesting_paths):
                        interesting.append({'url': url, 'type': 'interesting_path'})
                except Exception:
                    pass

            # If endpoints_only profile, focus on unique paths
            if active_method == 'endpoints_only':
                sorted_urls = sorted(endpoints)
            else:
                sorted_urls = sorted(urls)

            return self._create_result(
                success=True,
                data={
                    'domain': domain,
                    'urls': list(sorted(urls))[:2000],
                    'total': len(urls),
                    'endpoints': sorted(endpoints),
                    'total_endpoints': len(endpoints),
                    'subdomains': sorted(subdomains),
                    'interesting': interesting[:50],
                    'total_interesting': len(interesting),
                },
                duration=time.time() - start_time
            )

        except requests.Timeout:
            return self._create_result(success=False, error="Wayback API timed out", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)
