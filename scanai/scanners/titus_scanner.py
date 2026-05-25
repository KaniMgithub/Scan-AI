"""Titus — High-performance secrets scanner with 459 detection rules."""

import subprocess
import time
import json
import shutil
import os
import tempfile
from typing import Dict, Any, List
from .base_scanner import BaseScanner


class TitusScanner(BaseScanner):
    """Secrets scanner using Titus — finds credentials, API keys, tokens."""

    def __init__(self) -> None:
        super().__init__("titus", "High-performance secrets scanner (459 rules)")

    def _get_titus_bin(self) -> str:
        """Find titus binary."""
        # Check PATH first, then ~/.titus/
        bin_path = shutil.which('titus')
        if bin_path:
            return bin_path
        home_path = os.path.expanduser('~/.titus/titus')
        if os.path.isfile(home_path) and os.access(home_path, os.X_OK):
            return home_path
        return ''

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()

        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('titus', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            titus_bin = self._get_titus_bin()
            if not titus_bin:
                return self._create_result(
                    success=False,
                    error="titus not found. Install from https://github.com/praetorian-inc/titus/releases",
                    duration=time.time() - start_time
                )

            # Determine scan mode from profile
            active_method = None
            if self._workflow_profile and self._workflow_profile.method:
                active_method = self._workflow_profile.method

            # Build command based on profile
            profile_cmd = self.get_profile_command(target)
            if profile_cmd:
                cmd = profile_cmd.split()
            elif active_method == 'github_scan':
                cmd = [titus_bin, 'github', target]
            elif active_method == 'gitlab_scan':
                cmd = [titus_bin, 'gitlab', 'scan', '--group', target]
            else:
                # Default: scan target (file, dir, or repo URL)
                cmd = [titus_bin, 'scan', target]

            # Add validation if profile requests it
            validate = False
            if self._workflow_profile:
                validate = self._workflow_profile.extra.get('validate', False)
            if validate and '--validate' not in cmd:
                cmd.append('--validate')

            # Add git history scanning if profile requests it
            if self._workflow_profile and self._workflow_profile.extra.get('git', False):
                if '--git' not in cmd:
                    cmd.append('--git')

            timeout = self.get_profile_timeout(300)

            # Use a temp datastore
            ds_path = tempfile.mktemp(suffix='.ds', prefix='titus_scanai_')
            if '--datastore' not in ' '.join(cmd):
                cmd.extend(['--datastore', ds_path])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            raw_output = result.stdout + result.stderr

            # Get JSON report
            secrets = []
            try:
                report_cmd = [titus_bin, 'report', '--format', 'json', '--datastore', ds_path]
                report_result = subprocess.run(report_cmd, capture_output=True, text=True, timeout=30)

                if report_result.stdout.strip():
                    # Parse NDJSON (one JSON object per line)
                    for line in report_result.stdout.strip().split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            finding = json.loads(line)
                            secrets.append({
                                'rule_name': finding.get('rule_name', finding.get('ruleName', '')),
                                'rule_id': finding.get('rule_id', finding.get('ruleID', '')),
                                'secret': self._redact(finding.get('secret', finding.get('match', ''))),
                                'file': finding.get('file', finding.get('location', {}).get('file', '')),
                                'line': finding.get('line', finding.get('location', {}).get('line', 0)),
                                'validation': finding.get('validation', finding.get('validationStatus', 'unknown')),
                                'severity': self._classify_severity(finding),
                            })
                        except json.JSONDecodeError:
                            continue
            except Exception:
                # Parse from raw output as fallback
                pass

            # Cleanup datastore
            try:
                os.remove(ds_path)
            except Exception:
                pass

            # Categorize findings
            categories = {}
            active_secrets = []
            for s in secrets:
                cat = s.get('rule_name', 'unknown').split('.')[0] if '.' in s.get('rule_name', '') else s.get('rule_name', 'unknown')
                categories[cat] = categories.get(cat, 0) + 1
                if s.get('validation') in ('confirmed', 'active', 'valid'):
                    active_secrets.append(s)

            return self._create_result(
                success=True,
                data={
                    'target': target,
                    'secrets': secrets,
                    'total_secrets': len(secrets),
                    'active_secrets': len(active_secrets),
                    'categories': categories,
                    'validated': validate,
                    'top_findings': secrets[:20],
                    'active_findings': active_secrets[:10],
                    'raw_output': raw_output[:3000],
                },
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(success=False, error="Titus scan timed out", duration=time.time() - start_time)
        except Exception as e:
            return self._create_result(success=False, error=str(e), duration=time.time() - start_time)

    def _redact(self, secret: str) -> str:
        """Partially redact a secret for safe display."""
        if not secret or len(secret) < 8:
            return '***'
        return secret[:4] + '****' + secret[-4:]

    def _classify_severity(self, finding: Dict) -> str:
        """Classify finding severity based on rule and validation."""
        rule = finding.get('rule_name', finding.get('ruleName', '')).lower()
        validation = finding.get('validation', finding.get('validationStatus', '')).lower()

        # Active confirmed secrets are always critical
        if validation in ('confirmed', 'active', 'valid'):
            return 'CRITICAL'

        # High-value credentials
        if any(kw in rule for kw in ['aws', 'gcp', 'azure', 'private_key', 'database', 'password', 'jwt', 'oauth']):
            return 'HIGH'

        # Medium: API keys, tokens
        if any(kw in rule for kw in ['api_key', 'token', 'secret', 'credential']):
            return 'MEDIUM'

        return 'LOW'
