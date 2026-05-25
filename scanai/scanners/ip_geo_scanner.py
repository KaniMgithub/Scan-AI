"""IP geolocation and ISP lookup scanner with Shodan InternetDB integration."""

import requests
import socket
import time
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from .base_scanner import BaseScanner
from ..services.shodan_internetdb_service import ShodanInternetDBService


class IPGeoScanner(BaseScanner):
    """Scanner for IP geolocation and ISP information with Shodan InternetDB."""

    def __init__(self) -> None:
        """Initialize the IP geolocation scanner."""
        super().__init__(
            name="ip_geo",
            description="IP geolocation and ISP lookup with InternetDB"
        )
        self.api_url = "http://ip-api.com/json/{}"
        self.internetdb = ShodanInternetDBService()

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Get comprehensive IP intelligence from multiple sources.

        Args:
            target: IP address, domain, or URL
            **kwargs: Additional arguments (ignored)

        Returns:
            Combined IP intelligence results
        """
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('ip_geo', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            # Extract IP from target
            ip_address = self._resolve_target(target)

            if not ip_address:
                return self._create_result(
                    success=False,
                    error="Could not resolve target to IP address",
                    duration=time.time() - start_time
                )

            # Route based on workflow profile method
            active_method = None
            if self._workflow_profile and self._workflow_profile.method:
                active_method = self._workflow_profile.method

            if active_method == 'ip_geo_only':
                # Geo only — skip Shodan
                ip_geo_data = self._get_ip_geolocation(ip_address)
                combined_data = {
                    'ip': ip_address,
                    'ip_geolocation': ip_geo_data,
                    'internetdb': {},
                    'combined_analysis': {},
                    'raw_geo': ip_geo_data.get('raw_data', {}) if isinstance(ip_geo_data, dict) else {},
                    'raw_internetdb': {}
                }
            elif active_method == 'shodan_internetdb':
                # Shodan only — skip geo
                internetdb_data = self._get_internetdb_data(ip_address)
                combined_data = {
                    'ip': ip_address,
                    'ip_geolocation': {},
                    'internetdb': internetdb_data,
                    'combined_analysis': {},
                    'raw_geo': {},
                    'raw_internetdb': internetdb_data
                }
            else:
                # Default: full — both sources
                ip_geo_data = self._get_ip_geolocation(ip_address)
                internetdb_data = self._get_internetdb_data(ip_address)
                combined_data = {
                    'ip': ip_address,
                    'ip_geolocation': ip_geo_data,
                    'internetdb': internetdb_data,
                    'combined_analysis': self._combine_intelligence(ip_geo_data, internetdb_data),
                    'raw_geo': ip_geo_data.get('raw_data', {}) if isinstance(ip_geo_data, dict) else {},
                    'raw_internetdb': internetdb_data
                }

            return self._create_result(
                success=True,
                data=combined_data,
                duration=time.time() - start_time
            )

        except Exception as e:
            return self._create_result(
                success=False,
                error=f"IP intelligence error: {str(e)}",
                duration=time.time() - start_time
            )

    def _resolve_target(self, target: str) -> Optional[str]:
        """Resolve target to IP address.

        Args:
            target: Domain, URL, or IP address

        Returns:
            IP address or None if resolution fails
        """
        target = target.strip()

        # If it's already an IP, return it
        try:
            socket.inet_aton(target)
            return target
        except socket.error:
            pass

        # Extract domain from URL if needed
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.hostname
        else:
            domain = target

        if not domain:
            return None

        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None

    def _get_ip_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Get IP geolocation data from ip-api.com.

        Args:
            ip_address: IP address to lookup

        Returns:
            Geolocation data or error
        """
        try:
            response = requests.get(self.api_url.format(ip_address), timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return self._parse_geo_data(data)
                else:
                    return {'error': data.get('message', 'IP-API request failed')}
            else:
                return {'error': f'HTTP {response.status_code}'}

        except Exception as e:
            return {'error': str(e)}

    def _get_internetdb_data(self, ip_address: str) -> Dict[str, Any]:
        """Get InternetDB data from Shodan.

        Args:
            ip_address: IP address to lookup

        Returns:
            InternetDB data or error
        """
        try:
            return self.internetdb.lookup_ip(ip_address)
        except Exception as e:
            return {'error': str(e)}

    def _combine_intelligence(self, geo_data: Dict[str, Any], db_data: Dict[str, Any]) -> Dict[str, Any]:
        """Combine intelligence from multiple sources.

        Args:
            geo_data: IP-API geolocation data
            db_data: InternetDB data

        Returns:
            Combined analysis
        """
        analysis = {
            'risk_level': 'low',
            'findings': [],
            'recommendations': []
        }

        # Check for high-risk indicators
        if db_data.get('vulns'):
            vuln_count = len(db_data['vulns'])
            analysis['findings'].append(f"Found {vuln_count} known vulnerabilities")
            analysis['risk_level'] = 'high' if vuln_count > 5 else 'medium'

        if db_data.get('tags'):
            suspicious_tags = ['honeypot', 'scanner', 'malware', 'botnet']
            found_tags = [tag for tag in db_data['tags'] if tag in suspicious_tags]
            if found_tags:
                analysis['findings'].append(f"Suspicious tags: {', '.join(found_tags)}")
                analysis['risk_level'] = 'high'

        # Port analysis
        if db_data.get('ports'):
            port_count = len(db_data['ports'])
            analysis['findings'].append(f"Open ports: {port_count}")

            # Check for high-risk ports
            high_risk_ports = [22, 23, 445, 1433, 1521, 3306, 5432]
            found_risk_ports = [port for port in db_data['ports'] if port in high_risk_ports]
            if found_risk_ports:
                analysis['findings'].append(f"High-risk ports open: {found_risk_ports}")
                analysis['recommendations'].append("Consider closing or securing high-risk ports")

        # Hostname analysis
        if db_data.get('hostnames'):
            hostname_count = len(db_data['hostnames'])
            analysis['findings'].append(f"Associated hostnames: {hostname_count}")

        return analysis

    def _parse_geo_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IP-API response data.

        Args:
            data: Raw IP-API response

        Returns:
            Parsed geolocation data
        """
        return {
            'ip': data.get('query'),
            'country': data.get('country'),
            'country_code': data.get('countryCode'),
            'region': data.get('region'),
            'region_name': data.get('regionName'),
            'city': data.get('city'),
            'zip': data.get('zip'),
            'lat': data.get('lat'),
            'lon': data.get('lon'),
            'timezone': data.get('timezone'),
            'isp': data.get('isp'),
            'org': data.get('org'),
            'as': data.get('as'),
            'reverse_dns': data.get('reverse', ''),
            'mobile': data.get('mobile', False),
            'proxy': data.get('proxy', False),
            'hosting': data.get('hosting', False),
            'raw_data': data
        }