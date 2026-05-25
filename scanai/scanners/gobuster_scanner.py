"""Gobuster-like Directory Scanner with high-speed performance and extension support."""

import re
import requests
from typing import Dict, Any, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import os
from pathlib import Path
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .base_scanner import BaseScanner


class GobusterScanner(BaseScanner):
    """High-speed directory and file enumeration scanner."""

    def __init__(self) -> None:
        """Initialize the high-speed Gobuster scanner."""
        super().__init__("gobuster", "High-Speed Directory Enumeration Scanner")
        
        # Get project wordlists directory - switched to system wordlists
        self.wordlists_dir = Path('/usr/share/wordlists')
        
        # Available wordlists mapping (optimized for system wordlists)
        self.available_wordlists = {
            'common': 'dirb/common.txt',
            'small': 'dirb/small.txt',
            'medium': 'dirbuster/directory-list-2.3-medium.txt',
            'big': 'dirb/big.txt',
            'admin': 'dirb/others/best1050.txt',  # Using a common admin/best list as replacement
            'api': 'seclists/Discovery/Web-Content/api/api-endpoints.txt',
            'vhost': 'seclists/Discovery/DNS/subdomains-top1million-5000.txt',
            'directories': 'dirbuster/directories.jbrofuzz',
            'dirlist-small': 'dirbuster/directory-list-2.3-small.txt',
            'dirlist-medium': 'dirbuster/directory-list-2.3-medium.txt'
        }
        
        # Default configuration
        self.default_wordlist = 'common'
        self.paths: List[str] = []
        self.extensions: List[str] = []
        
        # For false positive detection
        self.baseline_404_hash: Optional[str] = None
        self.baseline_404_length: Optional[int] = None
        
        # Session for connection pooling
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with connection pooling and retries."""
        session = requests.Session()
        
        # Connection pooling: increase pool size for high concurrency
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=Retry(total=2, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Default headers for all requests
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        return session

    def _load_wordlist(self, wordlist_name: str = 'common', max_paths: int = 0) -> List[str]:
        """Load wordlist from the system's wordlists directory."""
        wordlist_file = self.available_wordlists.get(wordlist_name)
        
        # Fallback to direct path or .txt if not in mapping
        if not wordlist_file:
            wordlist_file = f"{wordlist_name}.txt" if not wordlist_name.endswith('.txt') else wordlist_name
            
        wordlist_path = self.wordlists_dir / wordlist_file
        
        # Try absolute path if not found in system wordlists dir
        if not wordlist_path.exists():
            wordlist_path = Path(wordlist_name)
            
        if not wordlist_path.exists():
            self.logger.warning(f"Wordlist not found: {wordlist_path}")
            return []
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [
                    line.strip().lstrip('/') 
                    for line in f 
                    if line.strip() and not line.startswith('#')
                ]
                if max_paths > 0:
                    return paths[:max_paths]
                return paths
        except Exception as e:
            self.logger.error(f"Failed to load wordlist {wordlist_path}: {e}")
            return []

    def _get_baseline_404(self, base_url: str) -> None:
        """Get baseline 404 response to detect false positives."""
        try:
            # Request a random non-existent path
            random_path = f"scanai_nonexistent_{int(time.time())}"
            url = f"{base_url}/{random_path}"
            
            response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
            self.baseline_404_length = len(response.content)
            self.baseline_404_hash = hashlib.md5(response.content).hexdigest()
            
        except Exception:
            self.baseline_404_hash = None
            self.baseline_404_length = None

    # Compiled regex for soft-404 title detection
    _SOFT_404_TITLE_RE = re.compile(
        r'<title[^>]*>\s*('
        r'404|not\s+found|page\s+not\s+found|error|'
        r'does\s+not\s+exist|unavailable|missing'
        r')\s*</title>',
        re.IGNORECASE
    )

    def _is_false_positive(self, response: requests.Response) -> bool:
        """Check if response is a false positive (soft 404).
        
        Uses hash comparison, content-length similarity, and
        title-tag pattern matching to catch soft-404 pages.
        """
        # 1. Hash-based check against baseline 404
        if self.baseline_404_hash is not None:
            content_hash = hashlib.md5(response.content).hexdigest()
            if content_hash == self.baseline_404_hash:
                return True

            # Content-length similarity check
            if self.baseline_404_length:
                content_len = len(response.content)
                tolerance = max(20, self.baseline_404_length * 0.1)
                if abs(content_len - self.baseline_404_length) < tolerance:
                    return True

        # 2. Title-based soft-404 detection
        try:
            # Only check HTML responses
            ctype = response.headers.get('content-type', '')
            if 'html' in ctype.lower():
                # Check first 4KB for title tag (fast)
                head_content = response.content[:4096].decode('utf-8', errors='ignore')
                if self._SOFT_404_TITLE_RE.search(head_content):
                    return True
        except Exception:
            pass

        return False

    def scan(self, target: str, scan_mode: str = 'both', wordlist: str = 'common', extensions: Optional[List[str]] = None, max_paths: int = 0, **kwargs) -> Dict[str, Any]:
        """Perform high-speed directory and file scan.
        
        Args:
            target: Target URL or domain
            scan_mode: 'dir' (only directories), 'file' (only extensions), or 'both'
            wordlist: Wordlist name to use
            extensions: List of extensions to check
            max_paths: Maximum number of paths
            profile: str — workflow profile name
        """
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('gobuster', profile_name)
            if profile:
                self.set_profile(profile)
                # Override scan_mode based on profile
                if profile_name in ('dir_scan', 'large_wordlist', 'api_discovery'):
                    scan_mode = 'dir'
                elif profile_name == 'file_scan':
                    scan_mode = 'file'
                elif profile_name == 'combined':
                    scan_mode = 'both'
                elif profile_name == 'vhost_scan':
                    scan_mode = 'dir'
                # Extract wordlist from command_template if present
                cmd_tpl = profile.command_template or ''
                if '-w ' in cmd_tpl:
                    import shlex
                    parts = shlex.split(cmd_tpl)
                    for i, p in enumerate(parts):
                        if p == '-w' and i + 1 < len(parts):
                            ext_wordlist_path = parts[i + 1]
                            if os.path.isfile(ext_wordlist_path):
                                with open(ext_wordlist_path, 'r', errors='ignore') as wf:
                                    self.paths = [line.strip() for line in wf if line.strip()]
                                wordlist = None  # skip default loading
                            break
                # Extract extensions from command_template (-x flag)
                if '-x ' in cmd_tpl:
                    import shlex
                    parts = shlex.split(cmd_tpl)
                    for i, p in enumerate(parts):
                        if p == '-x' and i + 1 < len(parts):
                            ext_list = parts[i + 1].split(',')
                            extensions = [e.strip() for e in ext_list if e.strip()]
                            break
        
        try:
            # Load base paths
            # If wordlist is provided as an argument AND it's not the default 'common', use it.
            # Otherwise, if we already have paths from a profile, keep them.
            if wordlist != 'common' or not self.paths:
                self.paths = self._load_wordlist(wordlist or 'common', max_paths)
                
            if not self.paths:
                return {'success': False, 'error': 'No wordlist paths loaded'}
            
            # Load extensions
            if extensions is None:
                # project extensions wordlist is gone, use robust defaults
                self.extensions = ['.php', '.html', '.js', '.txt', '.bak', '.conf', '.xml', '.json']
            else:
                self.extensions = [f".{ext.lstrip('.')}" if ext else "" for ext in extensions]

            # Ensure we have a proper URL
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'

            target = target.rstrip('/')
            
            # Refresh session and baseline for new scan
            self.session = self._create_session()
            self._get_baseline_404(target)

            # Build scan queue based on mode
            unique_queue = []
            seen = set()
            
            for path in self.paths:
                # Directory mode or both
                if scan_mode in ['dir', 'both']:
                    if path not in seen:
                        unique_queue.append(path)
                        seen.add(path)
                
                # File mode or both
                if scan_mode in ['file', 'both']:
                    # If path doesn't look like a file (no dot in last part), try extensions
                    if '.' not in path.split('/')[-1]:
                        for ext in self.extensions:
                            full_path = f"{path}{ext}"
                            if full_path not in seen:
                                unique_queue.append(full_path)
                                seen.add(full_path)
                    elif scan_mode == 'file':
                        # Already a file path in wordlist, add it
                        if path not in seen:
                            unique_queue.append(path)
                            seen.add(path)
            
            # Apply limit ONLY if explicitly requested (max_paths > 0)
            if max_paths > 0 and len(unique_queue) > max_paths:
                unique_queue = unique_queue[:max_paths]

            # Perform high-speed scan (100 workers)
            found_paths = self._perform_threaded_scan(target, unique_queue)
            
            found_paths.sort(key=lambda x: (x.get('status_code', 999), x.get('path', '')))

            return {
                'success': True,
                'data': {
                    'target': target,
                    'wordlist': wordlist,
                    'scan_mode': scan_mode,
                    'total_scanned': len(unique_queue),
                    'total_found': len(found_paths),
                    'found_paths': found_paths,
                    'duration': round(time.time() - start_time, 2)
                }
            }

        except Exception as e:
            return {'success': False, 'error': f'Scan failure: {str(e)}'}

    @staticmethod
    def _classify_path_type(path: str, content_type: str) -> str:
        """Classify a discovered path as Directory, File, or Unknown."""
        basename = path.rstrip('/').rsplit('/', 1)[-1] if path else ''

        # Explicit trailing slash → directory
        if path.endswith('/'):
            return 'Directory'

        # Has a file extension → file
        if '.' in basename:
            return 'File'

        # Content-type hints
        ct = content_type.lower()
        if any(ft in ct for ft in ('html', 'xml', 'json', 'javascript', 'css',
                                    'image', 'video', 'audio', 'pdf', 'font',
                                    'octet-stream', 'zip', 'text/plain')):
            return 'File'

        return 'Directory'

    def _perform_threaded_scan(self, base_url: str, queue: List[str]) -> List[Dict[str, Any]]:
        """Scan paths using a high-concurrency thread pool and connection pooling."""
        found_paths = []

        def check_path(path: str) -> Optional[Dict[str, Any]]:
            try:
                url = f"{base_url}/{path}"

                # ---- Step 1: Initial request WITHOUT following redirects ----
                initial_resp = self.session.get(
                    url, timeout=5, allow_redirects=False, verify=False
                )
                initial_status = initial_resp.status_code

                # Skip uninteresting status codes early
                if initial_status not in (200, 201, 202, 204,
                                          301, 302, 307, 308,
                                          401, 403):
                    return None

                # ---- Step 2: If redirect, follow it to get final destination ----
                redirect_url = ''
                final_status = initial_status
                final_resp = initial_resp

                if initial_status in (301, 302, 307, 308):
                    redirect_url = initial_resp.headers.get('location', '')
                    try:
                        # Follow the redirect chain
                        final_resp = self.session.get(
                            url, timeout=8, allow_redirects=True, verify=False
                        )
                        final_status = final_resp.status_code
                        # Capture the actual final URL after all redirects
                        if final_resp.url and final_resp.url != url:
                            redirect_url = final_resp.url
                    except Exception:
                        # If following fails, keep the initial redirect info
                        pass

                # ---- Step 3: False-positive filtering ----
                if final_status == 200 and self._is_false_positive(final_resp):
                    return None

                # ---- Step 4: Build result ----
                content_type = final_resp.headers.get('content-type', '').split(';')[0].strip()
                path_type = self._classify_path_type(path, content_type)

                return {
                    'path': f"/{path}",
                    'url': url,
                    'status_code': initial_status,
                    'content_type': content_type,
                    'content_length': final_resp.headers.get(
                        'content-length', str(len(final_resp.content))
                    ),
                    'type': path_type,
                    'redirect_url': redirect_url,
                }
            except Exception:
                pass
            return None

        # High-speed scan with 100 workers + connection pooling
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_path, path): path for path in queue}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    found_paths.append(res)

        return found_paths