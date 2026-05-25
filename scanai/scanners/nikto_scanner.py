"""Nikto web server vulnerability scanner."""

import subprocess
import time
import json
import os
import shutil
from typing import Dict, Any
from .base_scanner import BaseScanner


class NiktoScanner(BaseScanner):
    """Web server vulnerability scanner using Nikto."""

    def __init__(self) -> None:
        super().__init__("nikto", "Web server vulnerability scanner")

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()

        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('nikto', profile_name)
            if profile:
                self.set_profile(profile)

        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        try:
            nikto_bin = shutil.which('nikto')
            if not nikto_bin:
                return self._create_result(
                    success=False, error="nikto not found on system",
                    duration=time.time() - start_time
                )

            # Use a unique temp file to avoid conflicts
            json_output_path = f'/tmp/nikto_out_{os.getpid()}.json'

            # Clean up any stale output file
            if os.path.exists(json_output_path):
                os.remove(json_output_path)

            profile_cmd = self.get_profile_command(target)
            if profile_cmd:
                # Replace the default output path in profile commands
                cmd = profile_cmd.replace('/tmp/nikto_out.json', json_output_path).split()
            else:
                cmd = [nikto_bin, '-h', target, '-Format', 'json', '-output', json_output_path, '-nointeractive']

            timeout = self.get_profile_timeout(300)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            findings = []
            raw_output = (result.stdout or '') + (result.stderr or '')

            # Try to parse JSON output first
            json_parsed = False
            try:
                if os.path.exists(json_output_path):
                    with open(json_output_path, 'r') as f:
                        content = f.read().strip()
                    if content:
                        nikto_json = json.loads(content)
                        if isinstance(nikto_json, list):
                            for entry in nikto_json:
                                vulns = entry.get('vulnerabilities', [])
                                for v in vulns:
                                    findings.append({
                                        'id': v.get('id', ''),
                                        'method': v.get('method', 'GET'),
                                        'url': v.get('url', ''),
                                        'msg': v.get('msg', ''),
                                        'references': v.get('references', {}),
                                    })
                            json_parsed = True
                        elif isinstance(nikto_json, dict):
                            # Some Nikto versions output a dict with host key
                            for host_key, host_data in nikto_json.items():
                                if isinstance(host_data, dict):
                                    vulns = host_data.get('vulnerabilities', [])
                                    for v in vulns:
                                        findings.append({
                                            'id': v.get('id', ''),
                                            'method': v.get('method', 'GET'),
                                            'url': v.get('url', ''),
                                            'msg': v.get('msg', ''),
                                            'references': v.get('references', {}),
                                        })
                            json_parsed = True
            except (json.JSONDecodeError, IOError, OSError):
                pass
            finally:
                # Clean up temp file
                if os.path.exists(json_output_path):
                    try:
                        os.remove(json_output_path)
                    except OSError:
                        pass

            # Fallback: parse findings from raw stdout/stderr
            if not json_parsed or not findings:
                for line in raw_output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    # Nikto finding lines start with '+'
                    if line.startswith('+') and len(line) > 2:
                        # Skip informational lines about host/ports/server
                        skip_prefixes = ['+ target', '+ ssl info', '+ start time', '+ end time',
                                         '+ target ip', '+ target hostname', '+ target port',
                                         '+ server:', '+ /: the site']
                        if any(line.lower().startswith(p) for p in skip_prefixes):
                            continue
                        msg = line.lstrip('+ ').strip()
                        if msg and len(msg) > 5:
                            # Try to extract URL from the finding
                            url = ''
                            if ': ' in msg and msg.startswith('/'):
                                parts = msg.split(': ', 1)
                                url = parts[0]
                                msg = parts[1] if len(parts) > 1 else msg
                            findings.append({
                                'id': '',
                                'method': 'GET',
                                'url': url,
                                'msg': msg,
                                'references': {},
                            })

            return self._create_result(
                success=True,
                data={
                    'target': target,
                    'findings': findings,
                    'total_findings': len(findings),
                    'raw_output': raw_output,
                },
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(success=False, error=f"Nikto timed out after {timeout}s", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)
