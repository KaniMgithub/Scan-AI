"""WhatWeb-like Technology Scanner."""

import requests
from typing import Dict, Any, List, Set
import re

from .base_scanner import BaseScanner


class WhatWebScanner(BaseScanner):
    """Scanner that detects web technologies (similar to WhatWeb)."""

    def __init__(self) -> None:
        """Initialize the WhatWeb scanner."""
        super().__init__("whatweb", "Technology Detection Scanner")

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Scan for web technologies."""
        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('whatweb', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            # Ensure we have a proper URL
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'

            # Determine aggression level from profile
            active_method = None
            if self._workflow_profile and self._workflow_profile.method:
                active_method = self._workflow_profile.method

            # Profile controls how much data we collect
            body_snippet_len = 1000
            follow_redirects = True
            if active_method == 'passive' or (self._workflow_profile and 'passive' in (self._workflow_profile.tags or [])):
                # Passive: HEAD request only, minimal footprint
                response = requests.head(target, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }, allow_redirects=False)
                # Still need body for tech detection, do a GET but note we tried passive first
                response = requests.get(target, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }, allow_redirects=False)
                body_snippet_len = 500
                follow_redirects = False
            elif active_method == 'aggressive' or (self._workflow_profile and 'aggressive' in (self._workflow_profile.tags or [])):
                # Aggressive: follow redirects, larger body capture
                response = requests.get(target, timeout=15, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }, allow_redirects=True)
                body_snippet_len = 5000
            else:
                # Standard
                response = requests.get(target, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }, allow_redirects=True)

            # Analyze the response
            technologies = self._detect_technologies(response)

            return {
                'success': True,
                'data': {
                    'url': response.url,
                    'status_code': response.status_code,
                    'technologies': technologies,
                    'headers': dict(response.headers),
                    'scan_profile': self._workflow_profile.name if self._workflow_profile else 'standard',
                    'raw_data': {
                        'headers': dict(response.headers),
                        'body_snippet': response.text[:body_snippet_len] if response.text else ''
                    }
                }
            }

        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'HTTP request failed: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Technology detection failed: {str(e)}'
            }

    def _detect_technologies(self, response) -> Dict[str, Any]:
        """Detect technologies from HTTP response."""
        technologies = {}

        # Check headers
        headers = response.headers
        content = response.text

        # Server header
        if 'Server' in headers:
            server = headers['Server']
            if 'apache' in server.lower():
                technologies['Web Server'] = 'Apache'
            elif 'nginx' in server.lower():
                technologies['Web Server'] = 'Nginx'
            elif 'iis' in server.lower():
                technologies['Web Server'] = 'IIS'
            elif 'cloudflare' in server.lower():
                technologies['Web Server'] = 'Cloudflare'
            else:
                technologies['Web Server'] = server

        # X-Powered-By header
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            if 'php' in powered_by.lower():
                technologies['Programming Language'] = 'PHP'
            elif 'asp.net' in powered_by.lower():
                technologies['Framework'] = 'ASP.NET'
            else:
                technologies['Powered By'] = powered_by

        # Content analysis
        # JavaScript frameworks
        if 'jquery' in content.lower():
            technologies['JavaScript Library'] = 'jQuery'
        if 'react' in content.lower():
            technologies['JavaScript Framework'] = 'React'
        if 'angular' in content.lower():
            technologies['JavaScript Framework'] = 'Angular'
        if 'vue' in content.lower():
            technologies['JavaScript Framework'] = 'Vue.js'

        # CMS detection
        if 'wp-content' in content or 'wp-includes' in content:
            technologies['CMS'] = 'WordPress'
        if 'drupal' in content.lower():
            technologies['CMS'] = 'Drupal'
        if 'joomla' in content.lower():
            technologies['CMS'] = 'Joomla'
        if 'magento' in content.lower():
            technologies['CMS'] = 'Magento'

        # Analytics
        if 'google-analytics' in content or 'gtag' in content:
            technologies['Analytics'] = 'Google Analytics'
        if 'facebook' in content.lower() and 'pixel' in content.lower():
            technologies['Analytics'] = 'Facebook Pixel'

        # Check for common patterns
        if re.search(r'<\?php', content, re.IGNORECASE):
            technologies['Programming Language'] = 'PHP'
        if re.search(r'<\?xml', content, re.IGNORECASE):
            technologies['Markup'] = 'XML'

        # Check for common meta tags
        if 'generator' in content.lower():
            generator_match = re.search(r'<meta name="generator" content="([^"]+)"', content, re.IGNORECASE)
            if generator_match:
                technologies['Generator'] = generator_match.group(1)

        return technologies