"""theHarvester OSINT scanner — emails, subdomains, IPs, URLs."""

import subprocess
import time
import json
import shutil
from typing import Dict, Any
from .base_scanner import BaseScanner


class HarvesterScanner(BaseScanner):
    """OSINT email/subdomain harvester using theHarvester."""

    def __init__(self) -> None:
        super().__init__("harvester", "OSINT email & subdomain harvester")

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()

        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('harvester', profile_name)
            if profile:
                self.set_profile(profile)

        # Extract domain
        domain = target.replace('https://', '').replace('http://', '').split('/')[0]

        try:
            harvester_bin = shutil.which('theHarvester') or shutil.which('theharvester')
            if not harvester_bin:
                return self._create_result(
                    success=False, error="theHarvester not found on system",
                    duration=time.time() - start_time
                )

            profile_cmd = self.get_profile_command(domain)
            if profile_cmd:
                cmd = profile_cmd.split()
            else:
                cmd = [harvester_bin, '-d', domain, '-b', 'all', '-l', '200', '-f', '/tmp/harvester_out.json']

            timeout = self.get_profile_timeout(180)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            raw_output = result.stdout + result.stderr

            emails = []
            hosts = []
            ips = []

            # Try JSON output
            try:
                with open('/tmp/harvester_out.json', 'r') as f:
                    data = json.load(f)
                emails = data.get('emails', [])
                hosts = data.get('hosts', [])
                ips = data.get('ips', [])
            except Exception:
                pass

            # Parse from stdout if JSON failed
            if not emails and not hosts:
                section = None
                for line in raw_output.split('\n'):
                    line = line.strip()
                    if 'emails found' in line.lower():
                        section = 'emails'
                        continue
                    elif 'hosts found' in line.lower():
                        section = 'hosts'
                        continue
                    elif 'ips found' in line.lower():
                        section = 'ips'
                        continue
                    elif line.startswith('[') or line.startswith('*') or not line:
                        continue

                    if section == 'emails' and '@' in line:
                        emails.append(line)
                    elif section == 'hosts' and '.' in line:
                        hosts.append(line)
                    elif section == 'ips':
                        ips.append(line)

            return self._create_result(
                success=True,
                data={
                    'domain': domain,
                    'emails': sorted(set(emails)),
                    'hosts': sorted(set(hosts)),
                    'ips': sorted(set(ips)),
                    'total_emails': len(set(emails)),
                    'total_hosts': len(set(hosts)),
                    'total_ips': len(set(ips)),
                    'raw_output': raw_output,
                },
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(success=False, error="theHarvester timed out", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)
