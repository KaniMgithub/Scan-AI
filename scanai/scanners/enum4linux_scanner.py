"""Enum4Linux — SMB/NetBIOS/LDAP enumeration scanner."""

import subprocess
import time
import shutil
import re
from typing import Dict, Any
from .base_scanner import BaseScanner


class Enum4LinuxScanner(BaseScanner):
    """SMB/NetBIOS enumeration using enum4linux."""

    def __init__(self) -> None:
        super().__init__("enum4linux", "SMB/NetBIOS/LDAP enumeration")

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()

        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('enum4linux', profile_name)
            if profile:
                self.set_profile(profile)

        # Extract IP/hostname
        host = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]

        try:
            enum_bin = shutil.which('enum4linux') or shutil.which('enum4linux-ng')
            if not enum_bin:
                return self._create_result(
                    success=False, error="enum4linux not found on system",
                    duration=time.time() - start_time
                )

            profile_cmd = self.get_profile_command(host)
            if profile_cmd:
                cmd = profile_cmd.split()
            else:
                cmd = [enum_bin, '-a', host]

            timeout = self.get_profile_timeout(120)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            raw_output = result.stdout + result.stderr

            # Parse results
            shares = []
            users = []
            groups = []
            os_info = ''
            domain_info = ''
            password_policy = {}

            for line in raw_output.split('\n'):
                line = line.strip()
                # Shares
                if 'Disk' in line or 'IPC' in line or 'Printer' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        shares.append({'name': parts[0], 'type': parts[1] if len(parts) > 1 else ''})
                # Users
                if re.match(r'^S-\d+-\d+-\d+', line) or 'user:' in line.lower():
                    users.append(line)
                # OS info
                if 'os=' in line.lower() or 'os information' in line.lower():
                    os_info = line
                # Domain
                if 'domain' in line.lower() and '=' in line:
                    domain_info = line

            return self._create_result(
                success=True,
                data={
                    'target': host,
                    'shares': shares,
                    'users': users[:50],
                    'groups': groups,
                    'os_info': os_info,
                    'domain_info': domain_info,
                    'raw_output': raw_output,
                },
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(success=False, error="enum4linux timed out", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)
