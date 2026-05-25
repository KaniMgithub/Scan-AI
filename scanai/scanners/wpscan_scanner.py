"""WPScan — WordPress vulnerability scanner."""

import subprocess
import time
import shutil
import json
from typing import Dict, Any
from .base_scanner import BaseScanner
from ..utils.config import config


class WPScanScanner(BaseScanner):
    """WordPress vulnerability scanner using WPScan."""

    def __init__(self) -> None:
        super().__init__("wpscan", "WordPress vulnerability scanner")

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()

        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('wpscan', profile_name)
            if profile:
                self.set_profile(profile)

        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            wpscan_bin = shutil.which('wpscan')
            if not wpscan_bin:
                return self._create_result(
                    success=False, error="wpscan not found on system",
                    duration=time.time() - start_time
                )

            profile_cmd = self.get_profile_command(target)
            if profile_cmd:
                cmd = profile_cmd.split()
            else:
                cmd = [wpscan_bin, '--url', target, '--format', 'json', '--no-banner', '--random-user-agent']

            # Add API token if available
            api_token = getattr(config, 'wpscan_api_token', None) or ''
            if api_token and '--api-token' not in ' '.join(cmd):
                cmd.extend(['--api-token', api_token])

            timeout = self.get_profile_timeout(300)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            raw_output = result.stdout

            # Parse JSON output
            data = {}
            try:
                data = json.loads(raw_output)
            except json.JSONDecodeError:
                pass

            version_info = data.get('version', {})
            main_theme = data.get('main_theme', {})
            plugins = data.get('plugins', {})
            vulnerabilities = []

            # Extract vulns from version
            if version_info and isinstance(version_info, dict):
                for vuln in version_info.get('vulnerabilities', []):
                    vulnerabilities.append({
                        'title': vuln.get('title', ''),
                        'type': 'WordPress Core',
                        'fixed_in': vuln.get('fixed_in', ''),
                        'references': vuln.get('references', {}),
                    })

            # Extract vulns from plugins
            for plugin_name, plugin_data in plugins.items():
                if isinstance(plugin_data, dict):
                    for vuln in plugin_data.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'title': vuln.get('title', ''),
                            'type': f'Plugin: {plugin_name}',
                            'fixed_in': vuln.get('fixed_in', ''),
                            'references': vuln.get('references', {}),
                        })

            # Extract vulns from theme
            if main_theme and isinstance(main_theme, dict):
                for vuln in main_theme.get('vulnerabilities', []):
                    vulnerabilities.append({
                        'title': vuln.get('title', ''),
                        'type': f'Theme: {main_theme.get("slug", "unknown")}',
                        'fixed_in': vuln.get('fixed_in', ''),
                        'references': vuln.get('references', {}),
                    })

            wp_version = version_info.get('number', 'Unknown') if isinstance(version_info, dict) else 'Unknown'
            theme_name = main_theme.get('slug', 'Unknown') if isinstance(main_theme, dict) else 'Unknown'
            interesting = data.get('interesting_findings', [])

            return self._create_result(
                success=True,
                data={
                    'target': target,
                    'wp_version': wp_version,
                    'theme': theme_name,
                    'plugins': list(plugins.keys()) if isinstance(plugins, dict) else [],
                    'vulnerabilities': vulnerabilities,
                    'total_vulns': len(vulnerabilities),
                    'interesting_findings': interesting,
                    'raw_output': raw_output[:5000],
                },
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(success=False, error="WPScan timed out", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)
