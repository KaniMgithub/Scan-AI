"""Server HTTP headers scanner."""

import re
import requests
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from .base_scanner import BaseScanner


class ServerHeadersScanner(BaseScanner):
    """Scanner for server HTTP headers and software detection."""

    def __init__(self) -> None:
        """Initialize the server headers scanner."""
        super().__init__(
            name="server_headers",
            description="Server HTTP headers analysis"
        )

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Scan target for HTTP headers.

        Args:
            target: URL to scan
            **kwargs: Additional arguments (ignored)

        Returns:
            Server headers analysis results
        """
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('server_headers', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            # Clean and validate target URL
            clean_target = self._clean_target(target)
            self._validate_target(clean_target, 'URL')

            # Get headers with browser-like headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }

            response = requests.get(
                clean_target,
                headers=headers,
                timeout=15,
                allow_redirects=True,
                verify=False  # Allow self-signed certificates
            )

            response_headers = dict(response.headers)

            # Normalize header names to lowercase for consistent processing
            normalized_headers = {name.lower(): value for name, value in response_headers.items()}

            detected_software = self._extract_software_info(normalized_headers)

            # Extract key headers (case-insensitive)
            server = ''
            x_powered_by = ''
            for header_name, header_value in response_headers.items():
                header_lower = header_name.lower()
                if header_lower == 'server':
                    server = header_value
                elif header_lower == 'x-powered-by':
                    x_powered_by = header_value

            result_data = {
                'url': clean_target,
                'status_code': response.status_code,
                'headers': response_headers,
                'detected_software': detected_software,
                'server': server,
                'x_powered_by': x_powered_by,
                'final_url': response.url,
                'all_headers_raw': dict(response.raw.headers) if hasattr(response, 'raw') else {}
            }

            # Apply profile-specific processing
            active_method = None
            if self._workflow_profile and self._workflow_profile.method:
                active_method = self._workflow_profile.method

            if active_method == 'security_headers_audit':
                # Enhanced security header compliance check
                security_headers_check = {
                    'Strict-Transport-Security': normalized_headers.get('strict-transport-security'),
                    'Content-Security-Policy': normalized_headers.get('content-security-policy'),
                    'X-Frame-Options': normalized_headers.get('x-frame-options'),
                    'X-Content-Type-Options': normalized_headers.get('x-content-type-options'),
                    'X-XSS-Protection': normalized_headers.get('x-xss-protection'),
                    'Referrer-Policy': normalized_headers.get('referrer-policy'),
                    'Permissions-Policy': normalized_headers.get('permissions-policy'),
                    'Cross-Origin-Opener-Policy': normalized_headers.get('cross-origin-opener-policy'),
                    'Cross-Origin-Resource-Policy': normalized_headers.get('cross-origin-resource-policy'),
                    'Cross-Origin-Embedder-Policy': normalized_headers.get('cross-origin-embedder-policy'),
                }
                missing = [h for h, v in security_headers_check.items() if v is None]
                present = {h: v for h, v in security_headers_check.items() if v is not None}
                score = int((len(present) / len(security_headers_check)) * 100)
                result_data['security_audit'] = {
                    'present': present,
                    'missing': missing,
                    'score': score,
                    'grade': 'A' if score >= 80 else 'B' if score >= 60 else 'C' if score >= 40 else 'D' if score >= 20 else 'F',
                }
            elif active_method == 'full_headers':
                # Include redirect chain
                result_data['redirect_chain'] = [
                    {'url': r.url, 'status': r.status_code}
                    for r in response.history
                ] if response.history else []

            return self._create_result(
                success=True,
                data=result_data,
                duration=time.time() - start_time
            )

        except requests.RequestException as e:
            return self._create_result(
                success=False,
                error=f"HTTP request error: {str(e)}",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"Server headers scan error: {str(e)}",
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

    def _extract_software_info(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Extract software information from HTTP headers.

        Args:
            headers: HTTP response headers

        Returns:
            List of detected software with name and version
        """
        software = []

        # Check Server header
        server = headers.get('server', '').strip()
        if server:
            software.extend(self._parse_server_header(server))

        # Check X-Powered-By header
        powered_by = headers.get('x-powered-by', '').strip()
        if powered_by:
            software.extend(self._parse_powered_by_header(powered_by))

        # Check for additional version headers
        version_headers = {
            'x-aspnet-version': 'asp.net',
            'x-aspnetmvc-version': 'asp.net mvc',
            'x-aspnetwebpages-version': 'asp.net web pages',
            'x-php-version': 'php',
            'x-python-version': 'python',
            'x-ruby-version': 'ruby',
            'x-node-version': 'node.js',
            'x-go-version': 'go',
            'x-rust-version': 'rust',
            'x-java-version': 'java',
            'x-tomcat-version': 'apache tomcat',
            'x-nginx-version': 'nginx',
            'x-apache-version': 'apache httpd',
            'x-iis-version': 'microsoft iis',
            'x-django-version': 'django',
            'x-laravel-version': 'laravel',
            'x-wordpress-version': 'wordpress',
            'x-drupal-version': 'drupal',
            'x-joomla-version': 'joomla',
            'x-magento-version': 'magento',
        }

        for header_name, tech_name in version_headers.items():
            if header_name in headers:
                version = self._extract_version(headers[header_name])
                if version:
                    software.append({
                        'name': tech_name,
                        'version': version,
                        'source': header_name,
                        'confidence': 'high'
                    })

        # Check for technology stack indicators
        tech_headers = {
            'x-aspnet-version': 'asp.net',
            'x-aspnetmvc-version': 'asp.net mvc',
            'x-aspnetwebpages-version': 'asp.net web pages',
            'x-php-version': 'php',
            'x-python-version': 'python',
            'x-ruby-version': 'ruby',
            'x-node-version': 'node.js',
            'x-go-version': 'go',
            'x-rust-version': 'rust',
            'x-java-version': 'java',
            'x-tomcat-version': 'apache tomcat',
            'x-nginx-version': 'nginx',
            'x-apache-version': 'apache httpd',
            'x-iis-version': 'microsoft iis',
            'x-django-version': 'django',
            'x-laravel-version': 'laravel',
            'x-wordpress-version': 'wordpress',
            'x-drupal-version': 'drupal',
            'x-joomla-version': 'joomla',
            'x-magento-version': 'magento',
        }

        for header_name, tech_name in tech_headers.items():
            if header_name in headers:
                version = self._extract_version(headers[header_name])
                software.append({
                    'name': tech_name,
                    'version': version or '',
                    'source': header_name,
                    'confidence': 'high'
                })

        # Check for CDN indicators and try to detect backend software
        cdn_indicators = {
            'cf-ray': 'cloudflare',
            'x-amz-cf-id': 'amazon cloudfront',
            'x-cdn': 'generic cdn',
            'x-fastly-request-id': 'fastly',
            'x-akamai-request-id': 'akamai',
            'x-sucuri-id': 'sucuri',
            'x-varnish': 'varnish'
        }

        detected_cdn = None
        for header_name, cdn_name in cdn_indicators.items():
            if header_name in headers:
                detected_cdn = cdn_name
                break

        # If CDN detected, try additional fingerprinting techniques
        if detected_cdn:
            backend_software = self._fingerprint_backend(headers)
            software.extend(backend_software)

        # Check other common headers for software detection
        for header_name, header_value in headers.items():
            header_name = header_name.lower()
            header_value = header_value.lower()

            # ASP.NET detection
            if header_name in ['x-aspnet-version', 'x-aspnetmvc-version', 'x-aspnetwebpages-version']:
                software.append({
                    'name': 'asp.net',
                    'version': header_value.strip(),
                    'source': header_name
                })

            # PHP detection from various headers
            if 'php' in header_value and header_name in ['x-powered-by', 'server']:
                version = self._extract_version(header_value)
                if version:
                    software.append({
                        'name': 'php',
                        'version': version,
                        'source': header_name
                    })

            # WordPress detection
            if 'wordpress' in header_value:
                software.append({
                    'name': 'wordpress',
                    'version': self._extract_version(header_value),
                    'source': header_name
                })

            # Drupal detection
            if 'drupal' in header_value:
                software.append({
                    'name': 'drupal',
                    'version': self._extract_version(header_value),
                    'source': header_name
                })

            # Joomla detection
            if 'joomla' in header_value:
                software.append({
                    'name': 'joomla',
                    'version': self._extract_version(header_value),
                    'source': header_name
                })

            # Cloud providers
            cloud_indicators = {
                'x-amz': 'amazon',
                'x-goog': 'google cloud',
                'x-azure': 'microsoft azure',
                'cf-ray': 'cloudflare',
                'x-sucuri': 'sucuri',
                'x-varnish': 'varnish'
            }

            for indicator, provider in cloud_indicators.items():
                if indicator in header_name:
                    software.append({
                        'name': provider,
                        'version': '',
                        'source': header_name
                    })

        # If no software detected from headers, try to infer from common patterns
        if not software:
            software = self._infer_software_from_headers(headers)

        return software

    def _intelligent_header_analysis(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Use intelligent analysis to detect software from all HTTP headers.

        Args:
            headers: All HTTP response headers

        Returns:
            List of detected software with intelligence-based confidence
        """
        software = []

        # Convert all headers to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        # High-confidence detections based on specific headers
        high_confidence_indicators = {
            'x-powered-by': self._analyze_powered_by,
            'x-generator': self._analyze_generator,
            'x-aspnet-version': lambda v: {'name': 'asp.net', 'version': self._extract_version(v), 'confidence': 'high'},
            'x-aspnetmvc-version': lambda v: {'name': 'asp.net mvc', 'version': self._extract_version(v), 'confidence': 'high'},
            'x-drupal-cache': lambda v: {'name': 'drupal', 'version': '', 'confidence': 'high'},
            'x-wordpress-version': lambda v: {'name': 'wordpress', 'version': self._extract_version(v), 'confidence': 'high'},
            'x-joomla-version': lambda v: {'name': 'joomla', 'version': self._extract_version(v), 'confidence': 'high'},
            'x-magento-version': lambda v: {'name': 'magento', 'version': self._extract_version(v), 'confidence': 'high'},
            'x-shopify-stage': lambda v: {'name': 'shopify', 'version': '', 'confidence': 'high'},
            'x-wix-request-id': lambda v: {'name': 'wix', 'version': '', 'confidence': 'high'},
            'x-squarespace-version': lambda v: {'name': 'squarespace', 'version': '', 'confidence': 'high'},
        }

        for header_name, analyzer_func in high_confidence_indicators.items():
            if header_name in headers_lower:
                # Use the original case header value if available, or try to find it
                header_val = headers.get(header_name)
                # If using lowercase keys map, we need to find the actual value
                if header_val is None:
                    # Find the key in original headers that matches case-insensitively
                    for k, v in headers.items():
                        if k.lower() == header_name:
                            header_val = v
                            break
                            
                if header_val:
                    result = analyzer_func(header_val)
                    if result and isinstance(result, dict):
                        result['source'] = header_name
                        software.append(result)
                    elif result and isinstance(result, list):
                        for item in result:
                            item['source'] = header_name
                            software.append(item)

        # Medium-confidence detections from server header patterns
        if 'server' in headers_lower:
            server_software = self._analyze_server_header(headers_lower['server'])
            software.extend(server_software)

        # Intelligent analysis of all headers for software signatures
        software.extend(self._analyze_all_headers(headers))

        # Remove duplicates based on name, keeping highest confidence
        deduplicated = {}
        for sw in software:
            name = sw['name'].lower()
            confidence_order = {'high': 3, 'medium': 2, 'low': 1}

            if name not in deduplicated:
                deduplicated[name] = sw
            else:
                current_conf = confidence_order.get(deduplicated[name].get('confidence', 'low'), 0)
                new_conf = confidence_order.get(sw.get('confidence', 'low'), 0)
                if new_conf > current_conf:
                    deduplicated[name] = sw

        return list(deduplicated.values())

    def _analyze_powered_by(self, value: str) -> Dict[str, str]:
        """Analyze X-Powered-By header for software detection."""
        value_lower = value.lower()

        # Common patterns in X-Powered-By
        patterns = {
            'php': r'php[/-](\d+\.\d+(?:\.\d+)*)',
            'asp.net': r'asp\.net',
            'express': r'express',
            'django': r'django[/-](\d+\.\d+(?:\.\d+)*)',
            'flask': r'flask[/-](\d+\.\d+(?:\.\d+)*)',
            'laravel': r'laravel[/-](\d+\.\d+(?:\.\d+)*)',
            'wordpress': r'wordpress[/-](\d+\.\d+(?:\.\d+)*)',
            'drupal': r'drupal[/-](\d+\.\d+(?:\.\d+)*)',
            'joomla': r'joomla[/-](\d+\.\d+(?:\.\d+)*)',
            'magento': r'magento[/-](\d+\.\d+(?:\.\d+)*)',
        }

        for sw_name, pattern in patterns.items():
            match = re.search(pattern, value_lower, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else ''
                return {
                    'name': sw_name,
                    'version': version,
                    'confidence': 'high'
                }

        # Generic powered-by detection
        if value.strip():
            return {
                'name': value.strip(),
                'version': '',
                'confidence': 'medium'
            }

        return None

    def _analyze_generator(self, value: str) -> Dict[str, str]:
        """Analyze X-Generator or similar headers."""
        value_lower = value.lower()

        generators = {
            'wordpress': 'wordpress',
            'drupal': 'drupal',
            'joomla': 'joomla',
            'magento': 'magento',
            'woocommerce': 'woocommerce',
            'shopify': 'shopify',
            'wix': 'wix',
        }

        for key, sw_name in generators.items():
            if key in value_lower:
                version = self._extract_version(value)
                return {
                    'name': sw_name,
                    'version': version,
                    'confidence': 'high'
                }

        return {
            'name': value.strip(),
            'version': '',
            'confidence': 'low'
        }

    def _analyze_server_header(self, server_value: str) -> List[Dict[str, str]]:
        """Enhanced server header analysis."""
        software = []
        server_lower = server_value.lower()

        # Enhanced server patterns with better version extraction
        server_patterns = [
            (r'apache[/-](\d+\.\d+(?:\.\d+)*)', 'apache httpd'),
            (r'nginx[/-](\d+\.\d+(?:\.\d+)*)', 'nginx'),
            (r'iis[/-](\d+\.\d+(?:\.\d+)*)', 'microsoft iis'),
            (r'lighttpd[/-](\d+\.\d+(?:\.\d+)*)', 'lighttpd'),
            (r'gunicorn[/-](\d+\.\d+(?:\.\d+)*)', 'gunicorn'),
            (r'tornado[/-](\d+\.\d+(?:\.\d+)*)', 'tornado'),
            (r'caddy[/-](\d+\.\d+(?:\.\d+)*)', 'caddy'),
            (r'cloudflare', 'cloudflare'),
            (r'varnish[/-](\d+\.\d+(?:\.\d+)*)', 'varnish'),
            (r'haproxy[/-](\d+\.\d+(?:\.\d+)*)', 'haproxy'),
            (r'node\.js[/-](\d+\.\d+(?:\.\d+)*)', 'node.js'),
            (r'express[/-](\d+\.\d+(?:\.\d+)*)', 'express'),
        ]

        for pattern, sw_name in server_patterns:
            match = re.search(pattern, server_lower, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else ''
                software.append({
                    'name': sw_name,
                    'version': version,
                    'confidence': 'high',
                    'source': 'server'
                })

        return software

    def _analyze_all_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Analyze all headers for software signatures."""
        software = []

        # Common software signatures in any header
        signatures = {
            'wp-': 'wordpress',
            'drupal': 'drupal',
            'joomla': 'joomla',
            'magento': 'magento',
            'shopify': 'shopify',
            'laravel': 'laravel',
            'django': 'django',
            'flask': 'flask',
            'express': 'express',
            'rails': 'ruby on rails',
            'spring': 'spring framework',
            'tomcat': 'apache tomcat',
            'jboss': 'jboss',
            'websphere': 'websphere',
            'weblogic': 'weblogic',
        }

        headers_text = ' '.join(headers.values()).lower()

        for signature, sw_name in signatures.items():
            if signature in headers_text:
                # Try to find version in the header that contains the signature
                version = ''
                for header_value in headers.values():
                    if signature in header_value.lower():
                        version = self._extract_version(header_value)
                        break

                software.append({
                    'name': sw_name,
                    'version': version,
                    'confidence': 'medium',
                    'source': 'header_analysis'
                })

        return software

    def _fingerprint_backend(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Try to fingerprint backend software even when behind CDN.

        Args:
            headers: HTTP headers
            url: Target URL

        Returns:
            List of detected backend software
        """
        software = []

        # Intelligent software detection from all headers
        software.extend(self._intelligent_header_analysis(headers))

        return software

    def _parse_generator_header(self, generator_value: str) -> List[Dict[str, str]]:
        """Parse X-Generator or similar headers for software info.

        Args:
            generator_value: Generator header value

        Returns:
            List of software entries
        """
        software = []
        value_lower = generator_value.lower()

        # Common generator patterns
        if 'wordpress' in value_lower:
            version = self._extract_version(generator_value)
            software.append({
                'name': 'wordpress',
                'version': version,
                'source': 'x-generator',
                'confidence': 'high'
            })
        elif 'drupal' in value_lower:
            version = self._extract_version(generator_value)
            software.append({
                'name': 'drupal',
                'version': version,
                'source': 'x-generator',
                'confidence': 'high'
            })
        elif 'joomla' in value_lower:
            version = self._extract_version(generator_value)
            software.append({
                'name': 'joomla',
                'version': version,
                'source': 'x-generator',
                'confidence': 'high'
            })

        return software

    def _extract_version(self, string: str) -> Optional[str]:
        """Extract version number from a string."""
        import re
        match = re.search(r'(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', string)
        return match.group(1) if match else None

    def _infer_software_from_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Try to infer software from header patterns."""
        software = []

        # Check for common CMS/framework indicators
        header_text = ' '.join(headers.values()).lower()

        inferences = {
            'wp-json': ('wordpress', ''),
            'drupal': ('drupal', ''),
            'joomla': ('joomla', ''),
            'magento': ('magento', ''),
            'woocommerce': ('woocommerce', ''),
            'laravel': ('laravel', ''),
            'django': ('django', ''),
            'flask': ('flask', ''),
            'express': ('express', ''),
            'next.js': ('next.js', ''),
            'nuxt': ('nuxt', ''),
            'react': ('react', ''),
            'vue': ('vue', ''),
            'angular': ('angular', ''),
        }

        for indicator, (name, version) in inferences.items():
            if indicator in header_text:
                software.append({
                    'name': name,
                    'version': version,
                    'source': 'header_inference'
                })

        # Check for generator meta tag if present
        generator = headers.get('generator', '').lower()
        if generator:
            if 'wordpress' in generator:
                software.append({
                    'name': 'wordpress',
                    'version': self._extract_version(generator),
                    'source': 'generator_header'
                })

        return software

    def _parse_server_header(self, server_value: str) -> List[Dict[str, str]]:
        """Parse Server header for software information.

        Args:
            server_value: Server header value

        Returns:
            List of software entries
        """
        software = []

        # Common server software patterns with enhanced version detection
        patterns = [
            (r'Apache/([\d.]+)', 'apache httpd'),
            (r'nginx/([\d.]+)', 'nginx'),
            (r'IIS/([\d.]+)', 'microsoft iis'),
            (r'lighttpd/([\d.]+)', 'lighttpd'),
            (r'OpenBSD httpd', 'openbsd httpd'),
            (r'Cherokee/([\d.]+)', 'cherokee'),
            (r'Gunicorn/([\d.]+)', 'gunicorn'),
            (r'TornadoServer/([\d.]+)', 'tornado'),
            (r'Caddy', 'caddy'),
            (r'Cloudflare', 'cloudflare'),
            (r'LiteSpeed/([\d.]+)', 'litespeed'),
            (r'Apache-Coyote/([\d.]+)', 'apache tomcat'),
            (r'Tomcat/([\d.]+)', 'apache tomcat'),
            (r'Node\.js', 'node.js'),
            (r'PHP/([\d.]+)', 'php'),
            (r'Python/([\d.]+)', 'python'),
            (r'OpenSSL/([\d.]+)', 'openssl'),
        ]

        import re
        for pattern, name in patterns:
            match = re.search(pattern, server_value, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else ''
                # Try to extract version from the full string if regex didn't capture it
                if not version:
                    version = self._extract_version(server_value)

                software.append({
                    'name': name,
                    'version': version,
                    'source': 'server_header',
                    'confidence': 'high',
                    'full_header': server_value
                })

        # If no specific software detected, try generic extraction
        if not software:
            # Look for version patterns in the server header
            version = self._extract_version(server_value)
            if version:
                # Try to identify the software type
                server_lower = server_value.lower()
                if 'apache' in server_lower:
                    software.append({
                        'name': 'apache httpd',
                        'version': version,
                        'source': 'server_header',
                        'confidence': 'medium'
                    })
                elif 'nginx' in server_lower:
                    software.append({
                        'name': 'nginx',
                        'version': version,
                        'source': 'server_header',
                        'confidence': 'medium'
                    })

        return software

    def _parse_powered_by_header(self, powered_by_value: str) -> List[Dict[str, str]]:
        """Parse X-Powered-By header for software information.

        Args:
            powered_by_value: X-Powered-By header value

        Returns:
            List of software entries
        """
        software = []

        # Common powered-by patterns
        patterns = [
            (r'PHP/([\d.]+)', 'php'),
            (r'ASP\.NET', 'asp.net'),
            (r'Express', 'express'),
            (r'Django/([\d.]+)', 'django'),
            (r'Flask/([\d.]+)', 'flask'),
            (r'Rails/([\d.]+)', 'rails'),
        ]

        import re
        for pattern, name in patterns:
            match = re.search(pattern, powered_by_value, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else ''
                software.append({
                    'name': name,
                    'version': version,
                    'source': 'x_powered_by_header'
                })

        return software