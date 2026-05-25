"""Katana Web Crawler Scanner for ScanAI — projectdiscovery/katana integration."""

import subprocess
import json
import time
import threading
from typing import Dict, Any, List, Optional, Callable
from urllib.parse import urlparse

from .base_scanner import BaseScanner


class KatanaScanner(BaseScanner):
    """Next-generation web crawling and spidering using Katana."""

    def __init__(self):
        super().__init__("katana", "Katana Web Crawler")
        self._live_callback: Optional[Callable] = None
        self._live_urls: List[str] = []
        self._live_endpoints: List[str] = []
        self._live_js: List[str] = []
        self._live_apis: List[str] = []
        self._live_count: int = 0

    def set_live_callback(self, callback: Callable):
        """Set callback for live URL streaming: callback(url, stats_dict)"""
        self._live_callback = callback

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run katana crawl against target with live streaming."""
        start_time = time.time()

        # Reset live state
        self._live_urls = []
        self._live_endpoints = []
        self._live_js = []
        self._live_apis = []
        self._live_count = 0

        # Load workflow profile
        profile_name = kwargs.get('profile')
        cmd = None
        timeout = 180  # 3 min default, not 5

        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('katana', profile_name)
            if profile:
                self.set_profile(profile)
                cmd = self.get_profile_command(target)
                timeout = self.get_profile_timeout()

        if not cmd:
            cmd = f"katana -u {target} -jsonl -silent -depth 3 -jc -crawl-duration 90s"

        # Ensure JSON + silent for parsing
        if '-jsonl' not in cmd and '-j' not in cmd:
            cmd += ' -jsonl'
        if '-silent' not in cmd:
            cmd += ' -silent'
        # Add crawl duration limit if not set
        if '-crawl-duration' not in cmd and '-ct' not in cmd:
            cmd += ' -crawl-duration 90s'

        try:
            # Use Popen for live streaming
            process = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )

            urls = []
            endpoints = []
            js_files = []
            forms = []
            apis = []
            technologies = []
            all_entries = []

            # Read stdout line by line for live output
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue

                self._live_count += 1
                url = None

                # Try JSON parse
                try:
                    entry = json.loads(line)
                    all_entries.append(entry)

                    # Extract URL from various JSON formats
                    url = (
                        entry.get('request', {}).get('endpoint', '') or
                        entry.get('endpoint', '') or
                        entry.get('url', '') or
                        line
                    )
                    if not url.startswith('http'):
                        url = line

                    # Technologies
                    tech = entry.get('technologies', [])
                    if tech:
                        for t in tech:
                            if t not in technologies:
                                technologies.append(t)

                    # Form extraction
                    form_data = entry.get('form', None)
                    if form_data:
                        forms.append(form_data)

                except json.JSONDecodeError:
                    # Plain URL output
                    if line.startswith('http'):
                        url = line

                if url and url.startswith('http'):
                    if url not in urls:
                        urls.append(url)
                        self._live_urls.append(url)

                        # Extract path
                        try:
                            parsed = urlparse(url)
                            path = parsed.path
                            if path and path != '/' and path not in endpoints:
                                endpoints.append(path)
                                self._live_endpoints.append(path)
                        except:
                            pass

                        # Categorize
                        if url.endswith('.js') or '.js?' in url:
                            if url not in js_files:
                                js_files.append(url)
                                self._live_js.append(url)

                        if any(p in url for p in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/']):
                            if url not in apis:
                                apis.append(url)
                                self._live_apis.append(url)

                        # Fire live callback
                        if self._live_callback:
                            self._live_callback(url, {
                                'urls': len(urls),
                                'endpoints': len(endpoints),
                                'js_files': len(js_files),
                                'apis': len(apis),
                                'forms': len(forms),
                                'technologies': technologies[:],
                            })

                # Check timeout
                if time.time() - start_time > timeout:
                    process.kill()
                    break

            process.stdout.close()
            process.wait(timeout=10)

            duration = time.time() - start_time

            return self._create_result(
                success=True,
                data={
                    'target': target,
                    'total_urls_discovered': len(urls),
                    'total_endpoints_discovered': len(endpoints),
                    'total_js_files': len(js_files),
                    'total_api_endpoints': len(apis),
                    'total_forms_discovered': len(forms),
                    'technologies_detected': technologies,
                    'all_urls': urls,
                    'all_endpoints': sorted(endpoints),
                    'all_js_files': js_files,
                    'all_apis': apis,
                    'all_forms': forms,
                    'profile_used': profile_name or 'default',
                    'command': cmd,
                },
                duration=duration
            )

        except subprocess.TimeoutExpired:
            process.kill()
            return self._create_result(
                success=False,
                error=f"Katana timed out after {timeout}s",
                duration=time.time() - start_time
            )
        except FileNotFoundError:
            return self._create_result(
                success=False,
                error="Katana not found. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=str(e),
                duration=time.time() - start_time
            )
