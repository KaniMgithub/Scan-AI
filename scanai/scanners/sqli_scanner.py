"""SQLMap SQL Injection scanner wrapper."""

import subprocess
import os
import re
import sys
import time
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner


class SqliScanner(BaseScanner):
    """Scanner for SQL Injection detection using sqlmap."""

    def __init__(self) -> None:
        """Initialize the SQLi scanner."""
        super().__init__(
            name="sqlmap",
            description="SQL Injection testing using sqlmap"
        )

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform sqlmap scan on the target.

        Args:
            target: URL with query parameters to test for SQLi
            **kwargs: Additional arguments

        Returns:
            SQLi scan results
        """
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('sqlmap', profile_name)
            if profile:
                self.set_profile(profile)

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            scan_url = f"http://{target}"
        else:
            scan_url = target

        try:
            # Check if sqlmap is available
            sqlmap_bin = self._get_sqlmap_path()
            if not sqlmap_bin:
                return self._create_result(
                    success=False,
                    error="sqlmap command not found on system. Install with: apt install sqlmap / pip install sqlmap",
                    duration=time.time() - start_time
                )

            # Build command from workflow profile or default
            profile_cmd = self.get_profile_command(scan_url)
            if profile_cmd:
                cmd = profile_cmd.split()
            else:
                cmd = [
                    sqlmap_bin,
                    "-u", scan_url,
                    "--banner",
                    "--current-user",
                    "--dbs",
                    "--level=3",
                "--risk=2",              # Risk of tests (1-3)
                "--batch",               # Non-interactive (auto-answer prompts)
                "--flush-session",       # Flush session for fresh results
                "--disable-coloring",    # No ANSI color codes
                "--random-agent",        # Use random User-Agent
            ]

            # Print live header
            print(f"\n{'='*80}")
            print(f"  💉 SQLMAP SQL INJECTION SCANNER")
            print(f"  🎯 Target: {scan_url}")
            print(f"  ⚙️  Level: 3 | Risk: 2 | Mode: --batch")
            print(f"{'='*80}\n")

            # Run sqlmap with LIVE output streaming
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,  # Line-buffered
            )

            # Collect full output while streaming live
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                line_stripped = line.rstrip('\n\r')
                output_lines.append(line_stripped)
                # Print live output with styling
                if line_stripped:
                    # Color-code important lines for live display
                    if any(k in line_stripped.lower() for k in ['injectable', 'injection', 'confirmed']):
                        print(f"  \033[91m⚡ {line_stripped}\033[0m")
                    elif any(k in line_stripped.lower() for k in ['banner', 'current user', 'available databases']):
                        print(f"  \033[96m📊 {line_stripped}\033[0m")
                    elif line_stripped.startswith('[') and ('INFO' in line_stripped or 'WARNING' in line_stripped):
                        print(f"  \033[90m{line_stripped}\033[0m")
                    elif line_stripped.startswith('---'):
                        print(f"  \033[95m{line_stripped}\033[0m")
                    else:
                        print(f"  {line_stripped}")
                sys.stdout.flush()

            process.wait()
            raw_output = '\n'.join(output_lines)

            print(f"\n{'='*80}")
            print(f"  ✅ SQLMAP SCAN COMPLETE (exit code: {process.returncode})")
            print(f"{'='*80}\n")

            # Parse the output
            parsed = self._parse_sqlmap_output(raw_output)

            result_data = {
                'target': scan_url,
                'injectable': parsed.get('injectable', False),
                'dbms': parsed.get('dbms', 'N/A'),
                'banner': parsed.get('banner', 'N/A'),
                'current_user': parsed.get('current_user', 'N/A'),
                'databases': parsed.get('databases', []),
                'injection_points': parsed.get('injection_points', []),
                'techniques': parsed.get('techniques', []),
                'os': parsed.get('os', 'N/A'),
                'raw_output': raw_output,
            }

            return self._create_result(
                success=True,
                data=result_data,
                duration=time.time() - start_time
            )

        except subprocess.TimeoutExpired:
            return self._create_result(
                success=False,
                error="sqlmap scan timed out (>15 minutes)",
                duration=time.time() - start_time
            )
        except Exception as e:
            return self._create_result(
                success=False,
                error=f"sqlmap scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap stdout to extract structured results.

        Args:
            output: Full sqlmap stdout text

        Returns:
            Parsed results dictionary
        """
        result: Dict[str, Any] = {
            'injectable': False,
            'dbms': 'N/A',
            'banner': 'N/A',
            'current_user': 'N/A',
            'databases': [],
            'injection_points': [],
            'techniques': [],
            'os': 'N/A',
        }

        lines = output.split('\n')

        # --- Detect if target is injectable ---
        for line in lines:
            ll = line.lower()
            if 'is vulnerable' in ll or 'injectable' in ll:
                result['injectable'] = True
                break
            if 'sqlmap identified the following injection point' in ll:
                result['injectable'] = True
                break

        # --- Extract injection points / techniques ---
        in_injection_block = False
        current_injection: Dict[str, str] = {}
        for line in lines:
            if 'sqlmap identified the following injection point' in line.lower():
                in_injection_block = True
                continue
            if in_injection_block:
                if line.strip() == '---':
                    if current_injection:
                        result['injection_points'].append(current_injection)
                        current_injection = {}
                    continue
                if line.strip().startswith('Parameter:'):
                    if current_injection:
                        result['injection_points'].append(current_injection)
                    current_injection = {'parameter': line.strip()}
                    continue
                if line.strip().startswith('Type:'):
                    current_injection['type'] = line.strip().replace('Type: ', '')
                elif line.strip().startswith('Title:'):
                    current_injection['title'] = line.strip().replace('Title: ', '')
                elif line.strip().startswith('Payload:'):
                    current_injection['payload'] = line.strip().replace('Payload: ', '')
                # End of injection block detection
                if line.strip() == '' and not any(line.strip().startswith(k) for k in ['Type:', 'Title:', 'Payload:', 'Parameter:', '---', 'Vector:']):
                    if current_injection:
                        result['injection_points'].append(current_injection)
                        current_injection = {}
                    # Check if we're truly past the block
                    # Keep in_injection_block True for multi-param results
        # Flush last injection
        if current_injection:
            result['injection_points'].append(current_injection)

        # Extract unique techniques from injection points
        seen_types = set()
        for ip in result['injection_points']:
            t = ip.get('type', '')
            if t and t not in seen_types:
                seen_types.add(t)
                result['techniques'].append({
                    'type': t,
                    'title': ip.get('title', 'N/A'),
                    'payload': ip.get('payload', 'N/A'),
                })

        # --- Extract DBMS ---
        for line in lines:
            # "back-end DBMS: MySQL >= 5.0"
            match = re.search(r'back-end DBMS:\s*(.+)', line, re.IGNORECASE)
            if match:
                result['dbms'] = match.group(1).strip()
                break
            # "web server operating system: Linux ..."
            match_os = re.search(r'web server operating system:\s*(.+)', line, re.IGNORECASE)
            if match_os:
                result['os'] = match_os.group(1).strip()

        # --- Extract banner ---
        banner_next = False
        for line in lines:
            if 'banner:' in line.lower():
                # Sometimes banner is on the same line
                after = line.split(':', 1)
                if len(after) > 1 and after[1].strip():
                    result['banner'] = after[1].strip().strip("'\"")
                else:
                    banner_next = True
                continue
            if banner_next:
                stripped = line.strip().strip("'\"")
                if stripped and stripped != '---':
                    result['banner'] = stripped
                    banner_next = False

        # --- Extract current user ---
        for line in lines:
            match = re.search(r'current user:\s*[\'"]?(.+?)[\'"]?\s*$', line, re.IGNORECASE)
            if match:
                result['current_user'] = match.group(1).strip().strip("'\"")
                break

        # --- Extract databases ---
        in_dbs = False
        for line in lines:
            if 'available databases' in line.lower():
                in_dbs = True
                continue
            if in_dbs:
                stripped = line.strip()
                if stripped.startswith('[*]'):
                    db_name = stripped.replace('[*]', '').strip()
                    if db_name:
                        result['databases'].append(db_name)
                elif stripped == '' or stripped.startswith('['):
                    # End of database list (next log line or blank)
                    if result['databases']:  # Only break if we've collected some
                        in_dbs = False

        return result

    def _get_sqlmap_path(self) -> Optional[str]:
        """Find the sqlmap binary path."""
        import shutil
        path = shutil.which("sqlmap")
        if path:
            return path

        # Check common pip install location
        local_bin = os.path.expanduser("~/.local/bin/sqlmap")
        if os.path.exists(local_bin):
            return local_bin

        return None
