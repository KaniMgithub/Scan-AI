import subprocess
import shutil
import time
from typing import Dict, Any, List

from .base_scanner import BaseScanner  # pyright: ignore[reportMissingImports]
from ..utils.config import config  # pyright: ignore[reportMissingImports]


class SubdomainScanner(BaseScanner):
    """Scanner for subdomain enumeration using subfinder."""

    def __init__(self) -> None:
        super().__init__(
            name="subdomains",
            description="Subdomain enumeration via subfinder"
        )

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Enumerate subdomains using crt.sh Certificate Transparency logs."""
        import requests
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('subdomain', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            domain = self._extract_domain(target)
            self._validate_target(domain, 'domain')

            # Route based on workflow profile method
            active_method = None
            if self._workflow_profile and self._workflow_profile.method:
                active_method = self._workflow_profile.method

            all_subdomains = set()
            sources = []

            # Certificate Transparency (default or ct_lookup or combined)
            if active_method in (None, 'certificate_transparency', 'all_passive'):
                ct_subs = self._enumerate_crt_sh(domain)
                all_subdomains.update(ct_subs)
                if ct_subs:
                    sources.append('crt.sh')

            # HackerTarget (hackertarget or combined)
            if active_method in ('hackertarget_api', 'all_passive'):
                ht_subs = self._enumerate_hackertarget(domain)
                all_subdomains.update(ht_subs)
                if ht_subs:
                    sources.append('hackertarget')

            # DNS brute-force
            if active_method == 'dns_bruteforce':
                bf_subs = self._enumerate_bruteforce(domain)
                all_subdomains.update(bf_subs)
                if bf_subs:
                    sources.append('dns_bruteforce')

            sorted_subs = sorted(list(all_subdomains))

            return self._create_result(
                success=True,
                data={
                    'domain': domain,
                    'subdomains': sorted_subs,
                    'count': len(sorted_subs),
                    'source': ', '.join(sources) if sources else 'crt.sh',
                },
                duration=time.time() - start_time
            )

        except requests.exceptions.Timeout:
            return self._create_result(
                success=False,
                error="crt.sh request timed out after 30 seconds",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"Subdomain enumeration error: {str(e)}",
                duration=time.time() - start_time
            )

    def _enumerate_crt_sh(self, domain: str) -> set:
        """Enumerate subdomains via crt.sh Certificate Transparency."""
        import requests
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, headers={'User-Agent': 'ScanAI/v0.4.0'}, timeout=30)
            if response.status_code == 200:
                for entry in response.json():
                    for name in entry.get('name_value', '').split('\n'):
                        name = name.strip().lower()
                        if name.endswith(f".{domain}") and "*" not in name:
                            subdomains.add(name)
        except Exception:
            pass
        return subdomains

    def _enumerate_hackertarget(self, domain: str) -> set:
        """Enumerate subdomains via HackerTarget API."""
        import requests
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, headers={'User-Agent': 'ScanAI/v0.4.0'}, timeout=30)
            if response.status_code == 200 and 'error' not in response.text.lower():
                for line in response.text.strip().split('\n'):
                    parts = line.split(',')
                    if parts and parts[0].strip().endswith(f".{domain}"):
                        subdomains.add(parts[0].strip().lower())
        except Exception:
            pass
        return subdomains

    def _enumerate_bruteforce(self, domain: str) -> set:
        """Enumerate subdomains via DNS brute-force."""
        import socket
        subdomains = set()
        wordlist_path = None
        if self._workflow_profile:
            wordlist_path = self._workflow_profile.extra.get('wordlist')
        
        # Fallback wordlist
        wordlists = [
            wordlist_path,
            '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
            '/usr/share/wordlists/amass/subdomains-top1mil-5000.txt',
        ]
        
        words = []
        for wl in wordlists:
            if wl and __import__('os').path.isfile(wl):
                with open(wl, 'r', errors='ignore') as f:
                    words = [line.strip() for line in f if line.strip()][:5000]
                break
        
        if not words:
            words = ['www', 'mail', 'ftp', 'api', 'dev', 'staging', 'test', 'admin', 'portal', 'vpn', 'cdn', 'app', 'blog', 'shop', 'store', 'ns1', 'ns2', 'mx', 'smtp']
        
        for word in words:
            sub = f"{word}.{domain}"
            try:
                socket.gethostbyname(sub)
                subdomains.add(sub)
            except socket.gaierror:
                pass
        return subdomains

    def _extract_domain(self, target: str) -> str:
        """Extract clean domain from URL or raw input."""
        from urllib.parse import urlparse

        target = target.strip().lower()

        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.netloc or parsed.path
        else:
            domain = target.split('/')[0]

        if ':' in domain:
            domain = domain.split(':')[0]

        if domain.startswith('www.'):
            domain = domain[4:]

        return domain