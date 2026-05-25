"""WAFw00f — Web Application Firewall detection and fingerprinting."""

import subprocess
import time
import shutil
import json
from typing import Dict, Any
from .base_scanner import BaseScanner


class WAFScanner(BaseScanner):
    """WAF detection using wafw00f."""

    def __init__(self) -> None:
        super().__init__("waf", "WAF detection and fingerprinting")

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()

        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('waf', profile_name)
            if profile:
                self.set_profile(profile)

        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            waf_bin = shutil.which('wafw00f')
            if not waf_bin:
                return self._create_result(
                    success=False, error="wafw00f not found on system",
                    duration=time.time() - start_time
                )

            profile_cmd = self.get_profile_command(target)
            if profile_cmd:
                cmd = profile_cmd.split()
            else:
                cmd = [waf_bin, target, '-o', '/tmp/waf_out.json', '-f', 'json']

            timeout = self.get_profile_timeout(60)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            raw_output = result.stdout + result.stderr

            waf_detected = False
            waf_name = 'None'
            waf_manufacturer = ''
            detections = []

            # Parse JSON
            try:
                with open('/tmp/waf_out.json', 'r') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        if entry.get('detected'):
                            waf_detected = True
                            waf_name = entry.get('firewall', 'Unknown')
                            waf_manufacturer = entry.get('manufacturer', '')
                            detections.append({
                                'firewall': waf_name,
                                'manufacturer': waf_manufacturer,
                                'url': entry.get('url', target),
                            })
            except Exception:
                # Parse from stdout
                for line in raw_output.split('\n'):
                    if 'is behind' in line.lower():
                        waf_detected = True
                        parts = line.split('is behind')
                        if len(parts) > 1:
                            waf_name = parts[1].strip().rstrip('.')
                            detections.append({'firewall': waf_name, 'manufacturer': '', 'url': target})
                    elif 'no waf' in line.lower():
                        waf_detected = False

            return self._create_result(
                success=True,
                data={
                    'target': target,
                    'waf_detected': waf_detected,
                    'waf_name': waf_name,
                    'waf_manufacturer': waf_manufacturer,
                    'detections': detections,
                    'raw_output': raw_output,
                },
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(success=False, error="wafw00f timed out", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)
