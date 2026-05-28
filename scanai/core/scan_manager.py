"""Scan manager for orchestrating security scans."""

import socket
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..scanners.whois_scanner import WhoisScanner
from ..scanners.nmap_scanner import NmapScanner
from ..scanners.virustotal_scanner import VirusTotalScanner
from ..scanners.urlscan_scanner import URLScanScanner
from ..scanners.ip_geo_scanner import IPGeoScanner
from ..scanners.subdomain_scanner import SubdomainScanner
from ..scanners.server_headers_scanner import ServerHeadersScanner
from ..scanners.cve_scanner import CVEScanner
from ..scanners.ssl_scanner import SSLScanner
from ..scanners.whatweb_scanner import WhatWebScanner
from ..scanners.gobuster_scanner import GobusterScanner
from ..scanners.nuclei_scanner import NucleiScanner
from ..scanners.dnsrecon_scanner import DnsReconScanner
from ..scanners.dalfox_scanner import DalfoxScanner
from ..scanners.sqli_scanner import SqliScanner
from ..scanners.katana_scanner import KatanaScanner
from ..scanners.nikto_scanner import NiktoScanner
from ..scanners.harvester_scanner import HarvesterScanner
from ..scanners.waf_scanner import WAFScanner
from ..scanners.wpscan_scanner import WPScanScanner
from ..scanners.wayback_scanner import WaybackScanner
from ..scanners.enum4linux_scanner import Enum4LinuxScanner
from ..scanners.titus_scanner import TitusScanner
from ..utils.config import config


class ScanManager:
    """Manager class for orchestrating all security scanners."""

    def __init__(self) -> None:
        """Initialize the scan manager with all scanners."""
        # Include all available scanners
        self.scanners = {
            'whois': WhoisScanner(),
            'nmap': NmapScanner(),
            'virustotal': VirusTotalScanner(),
            'urlscan': URLScanScanner(),
            'ip_geo': IPGeoScanner(),
            'subdomain': SubdomainScanner(),
            'server_headers': ServerHeadersScanner(),
            'cves': CVEScanner(),
            'ssl': SSLScanner(),
            'dns': DnsReconScanner(),
            'whatweb': WhatWebScanner(),
            'gobuster': GobusterScanner(),
            'nuclei': NucleiScanner(),
            'dalfox': DalfoxScanner(),
            'sqlmap': SqliScanner(),
            'katana': KatanaScanner(),
            'nikto': NiktoScanner(),
            'harvester': HarvesterScanner(),
            'waf': WAFScanner(),
            'wpscan': WPScanScanner(),
            'wayback': WaybackScanner(),
            'enum4linux': Enum4LinuxScanner(),
            'titus': TitusScanner(),
        }

    def perform_full_scan(self, target: str, progress_callback: Optional[callable] = None, scanners_to_run: Optional[List[str]] = None, existing_details: Optional[Dict[str, Any]] = None, scan_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform a comprehensive security scan of the target.

        Args:
            target: Target URL, domain, or IP to scan
            progress_callback: Optional callback for progress updates
            scanners_to_run: Optional list of scanner names to run. If None, runs all.
            existing_details: Optional dictionary of existing findings to include.
            scan_params: Optional dictionary of scanner-specific parameters.

        Returns:
            Complete scan results
        """
        start_time = time.time()

        # Validate and normalize target
        clean_target = self._normalize_target(target)
        domain = self._extract_domain(clean_target)
        ip_address = self._resolve_ip(domain)

        # Initialize results structure
        results = {
            'target': clean_target,
            'domain': domain,
            'ip': ip_address or 'Unable to resolve',
            'timestamp': time.time(),
            'duration': 0,
            'status': 'unknown',
            'level': '',
            'summaries': {},
            'details': existing_details.copy() if existing_details else {},
            'errors': []
        }

        # Determine which scanners to run
        if scanners_to_run:
            scanners_to_execute = {name: self.scanners[name] for name in scanners_to_run if name in self.scanners}
        else:
            scanners_to_execute = self.scanners

        total_scanners = len(scanners_to_execute)
        completed_scanners = 0

        # Initial progress update - starting at 0%
        if progress_callback:
            progress_callback('initializing', 0, total_scanners)

        # Separate scanners into independent and dependent ones
        independent_scanners = {}
        dependent_scanners = {}
        
        for name, scanner in scanners_to_execute.items():
            if name in ['cves']:  # CVE scanner depends on server_headers and nmap
                dependent_scanners[name] = scanner
            else:
                independent_scanners[name] = scanner

        # Run independent scanners concurrently
        if independent_scanners:
            with ThreadPoolExecutor(max_workers=min(8, len(independent_scanners))) as executor:
                future_to_scanner = {}

                # Submit all scanner tasks
                for scanner_name, scanner in independent_scanners.items():
                    # Extract params for this specific scanner if they exist
                    params = scan_params.get(scanner_name, {}) if scan_params else {}
                    future = executor.submit(self._run_scanner_task, scanner_name, scanner, clean_target, results, **params)
                    future_to_scanner[future] = scanner_name

                # Collect results as they complete and update progress
                for future in as_completed(future_to_scanner):
                    scanner_name = future_to_scanner[future]
                    try:
                        scan_result = future.result()
                        if scan_result['success']:
                            results['details'][scanner_name] = scan_result['data']
                        else:
                            results['errors'].append({
                                'scanner': scanner_name,
                                'error': scan_result['error']
                            })
                    except Exception as e:
                        results['errors'].append({
                            'scanner': scanner_name,
                            'error': str(e)
                        })

                    # Update progress after scanner completes
                    completed_scanners += 1
                    if progress_callback:
                        progress_callback(scanner_name, completed_scanners, total_scanners)

        # Run dependent scanners sequentially (CVE scanner needs results from others)
        for scanner_name, scanner in dependent_scanners.items():
            try:
                # Call scanner with appropriate arguments
                if scanner_name == 'cves':
                    # CVE scanner needs software list from multiple sources
                    software_list = []

                    # Get software from server headers (prioritize these as they show actual backend)
                    headers_result = results['details'].get('server_headers', {})
                    header_software = []
                    if headers_result and isinstance(headers_result, dict) and 'detected_software' in headers_result:
                        header_software = headers_result['detected_software']

                    # Get software from Nmap services
                    nmap_result = results['details'].get('nmap', {})
                    nmap_software = []
                    if nmap_result:
                        # NmapScanner returns results in 'services' or 'ports'
                        nmap_software = nmap_result.get('services', [])
                        if not nmap_software and 'ports' in nmap_result:
                            # Fallback to ports if services is empty
                            for p in nmap_result['ports']:
                                if p.get('software_name') or p.get('version'):
                                    nmap_software.append({
                                        'name': p.get('software_name', p.get('service', 'unknown')),
                                        'version': p.get('version', ''),
                                        'port': p.get('port'),
                                        'source': 'nmap'
                                    })

                    # Get software from WhatWeb (tech_detect)
                    whatweb_result = results['details'].get('whatweb', {})
                    whatweb_software = []
                    if whatweb_result and isinstance(whatweb_result, dict):
                        for plugin, data in whatweb_result.get('plugins', {}).items():
                            version = ' '.join(data.get('version', [])) if isinstance(data.get('version'), list) else data.get('version', '')
                            if version:
                                whatweb_software.append({
                                    'name': plugin,
                                    'version': str(version),
                                    'source': 'whatweb'
                                })

                    # Combine with prioritization: headers first, then whatweb, then nmap
                    software_list = header_software.copy()
                    added_names = {sw.get('name', '').lower() for sw in header_software if sw.get('name')}

                    for sw in whatweb_software:
                        if sw.get('name', '').lower() not in added_names:
                            software_list.append(sw)
                            added_names.add(sw.get('name', '').lower())

                    for nmap_sw in nmap_software:
                        nmap_name = nmap_sw.get('name', '').lower()
                        if nmap_name not in added_names and nmap_name:
                            # For web services, be more cautious - prefer headers
                            port = str(nmap_sw.get('port', ''))
                            if port in ['80', '443']:
                                # Only add nmap web software if we don't have header software
                                if not any(sw.get('source') == 'server_header' for sw in header_software if sw):
                                    software_list.append(nmap_sw)
                                    added_names.add(nmap_name)
                            else:
                                # For non-web services (like SSH), nmap is usually accurate
                                software_list.append(nmap_sw)
                                added_names.add(nmap_name)

                    # Filter out any None values or invalid software entries that might cause errors
                    software_list = [sw for sw in software_list if sw and isinstance(sw, dict) and sw.get('name')]

                    # Log the software list for debugging
                    print(f"\n[CVE Scanner] Detected {len(software_list)} software packages:")
                    for sw in software_list:
                        version_str = sw.get('version', 'unknown')
                        source_str = sw.get('source', 'unknown')
                        print(f"  - {sw.get('name')} {version_str} (from {source_str})")
                    print()

                    # Always run CVE scanner, even with empty software list
                    # It will handle displaying "No CVEs found" appropriately
                    scan_result = self._run_scanner(scanner, scanner_name, software_list)
                else:
                    # Most scanners just need the target URL/domain
                    params = scan_params.get(scanner_name, {}) if scan_params else {}
                    scan_result = self._run_scanner(scanner, scanner_name, clean_target, **params)

                if scan_result['success']:
                    results['details'][scanner_name] = scan_result['data']
                else:
                    results['errors'].append({
                        'scanner': scanner_name,
                        'error': scan_result['error']
                    })

            except Exception as e:
                results['errors'].append({
                    'scanner': scanner_name,
                    'error': str(e)
                })

            # Update progress after dependent scanner completes
            completed_scanners += 1
            if progress_callback:
                progress_callback(scanner_name, completed_scanners, total_scanners)

        # Generate summaries and risk assessment
        self._generate_summaries(results)
        self._calculate_risk_score(results)

        results['duration'] = time.time() - start_time

        if progress_callback:
            progress_callback('complete', total_scanners, total_scanners)

        return results

    def _run_scanner_task(self, scanner_name: str, scanner: Any, target: str, results: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Run a single scanner task for concurrent execution.
        
        Args:
            scanner_name: Name of the scanner
            scanner: Scanner instance
            target: Target to scan
            results: Results dictionary
            **kwargs: Scanner-specific parameters
            
        Returns:
            Scan result dictionary
        """
        try:
            return self._run_scanner(scanner, scanner_name, target, **kwargs)
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _run_scanner(self, scanner: Any, scanner_name: str, *args, **kwargs) -> Dict[str, Any]:
        """Run a single scanner with error handling.

        Args:
            scanner: Scanner instance
            scanner_name: Name of the scanner
            *args: Arguments to pass to scanner.scan()
            **kwargs: Keyword arguments to pass to scanner.scan()

        Returns:
            Scan result
        """
        try:
            result = scanner.scan(*args, **kwargs)
            # Ensure the result has the expected structure
            if not isinstance(result, dict):
                return {
                    'success': False,
                    'error': f'Scanner {scanner_name} returned invalid result type: {type(result)}',
                    'duration': 0
                }
            return result
        except Exception as e:
            return {
                'success': False,
                'error': f"Scanner {scanner_name} failed: {str(e)}",
                'duration': 0
            }

    def _normalize_target(self, target: str) -> str:
        """Normalize the target URL/domain.

        Preserves the full URL including path and query parameters.
        Only adds protocol prefix if missing.

        Args:
            target: Raw target input

        Returns:
            Normalized target with protocol
        """
        target = target.strip()

        # Add protocol if missing - preserve existing protocol choice
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        return target

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL.

        Args:
            target: URL or domain

        Returns:
            Domain name
        """
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target

        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]

        return domain

    def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address.

        Args:
            domain: Domain name

        Returns:
            IP address or None if resolution fails
        """
        try:
            # Try A record first
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None

    def _generate_summaries(self, results: Dict[str, Any]) -> None:
        """Generate summary information from scan results.

        Args:
            results: Complete scan results
        """
        summaries = {}

        # VirusTotal summary
        vt_data = results['details'].get('virustotal', {})
        if vt_data:
            summaries['virustotal'] = {
                'malicious': vt_data.get('malicious_count', 0),
                'suspicious': vt_data.get('suspicious_count', 0),
                'harmless': vt_data.get('harmless_count', 0),
                'undetected': vt_data.get('undetected_count', 0),
                'detection_ratio': vt_data.get('detection_ratio', 'N/A'),
                'top_detections': vt_data.get('top_detections', [])
            }

        # URLScan summary
        urlscan_data = results['details'].get('urlscan', {})
        if urlscan_data:
            summaries['urlscan'] = {
                'malicious': urlscan_data.get('malicious', False),
                'score': urlscan_data.get('score', 0),
                'categories': urlscan_data.get('categories', []),
                'brands': urlscan_data.get('brands', []),
                'tags': urlscan_data.get('tags', []),
                'country': urlscan_data.get('country')
            }

        # Subdomains summary with aggregation
        subdomain_results = results['details'].get('subdomain', {})
        dns_results = results['details'].get('dns', {})
        
        all_subdomains = set()
        
        # From subdomain scanner
        if subdomain_results and 'subdomains' in subdomain_results:
            all_subdomains.update(subdomain_results['subdomains'])
            
        # From DNS scanner
        if dns_results and 'subdomains' in dns_results:
            all_subdomains.update(dns_results['subdomains'])
            
        # Store aggregated list
        results['summaries']['all_subdomains'] = sorted(list(all_subdomains))
        
        if subdomain_results:
            summaries['subdomains'] = {
                'count': len(all_subdomains),
                'found': len(all_subdomains) > 0,
                'sources': ['Certificate Transparency', 'HackerTarget', 'DNS Enumeration']
            }

        # Nmap summary
        nmap_data = results['details'].get('nmap', {})
        if nmap_data:
            ports = nmap_data.get('ports', [])
            open_ports = [p for p in ports if p.get('state') == 'open']
            summaries['nmap'] = {
                'available': True,
                'open_ports': len(open_ports),
                'total_ports': len(ports)
            }

        # CVE summary
        cve_data = results['details'].get('cves', {})
        if cve_data and isinstance(cve_data, dict):
            cves = cve_data.get('cves', [])
            if not isinstance(cves, list):
                cves = []
                
            high_cves = [c for c in cves if isinstance(c, dict) and c.get('severity') in ['CRITICAL', 'HIGH']]
            medium_cves = [c for c in cves if isinstance(c, dict) and c.get('severity') == 'MEDIUM']
            low_cves = [c for c in cves if isinstance(c, dict) and c.get('severity') == 'LOW']

            summaries['cves'] = {
                'count': len(cves),
                'high': len(high_cves),
                'medium': len(medium_cves),
                'low': len(low_cves)
            }

        results['summaries'] = summaries

    def _calculate_risk_score(self, results: Dict[str, Any]) -> None:
        """Calculate overall risk score and status.

        Args:
            results: Complete scan results
        """
        risk_score = 0
        status = 'safe'

        # URL heuristic risk
        url_risk = self._calculate_url_risk(results['domain'])
        risk_score += url_risk

        # VirusTotal risk
        vt_summary = results['summaries'].get('virustotal', {})
        vt_risk = vt_summary.get('malicious', 0)
        risk_score += vt_risk

        # URLScan risk
        urlscan_summary = results['summaries'].get('urlscan', {})
        urlscan_risk = 3 if urlscan_summary.get('malicious', False) else 0
        risk_score += urlscan_risk

        # CVE risk
        cve_summary = results['summaries'].get('cves', {})
        cve_risk = cve_summary.get('high', 0) * 2 + cve_summary.get('medium', 0)
        risk_score += cve_risk

        # Determine status and level
        if risk_score == 0:
            status = 'safe'
            level = 'none'
        elif risk_score <= 3:
            status = 'low_risk'
            level = 'low'
        elif risk_score <= 7:
            status = 'medium_risk'
            level = 'medium'
        elif risk_score <= 15:
            status = 'high_risk'
            level = 'high'
        else:
            status = 'critical_risk'
            level = 'critical'

        # Update risk components in summaries
        results['summaries']['risk'] = {
            'total': risk_score,
            'components': {
                'url_heuristic': url_risk,
                'virustotal': vt_risk,
                'urlscan': urlscan_risk,
                'cves': cve_risk
            }
        }

        results['status'] = status
        results['level'] = level

    def _calculate_url_risk(self, domain: str) -> int:
        """Calculate risk score based on URL heuristics.

        Args:
            domain: Domain name

        Returns:
            Risk score from URL analysis
        """
        risk = 0

        # Contains numbers
        if any(c.isdigit() for c in domain):
            risk += 1

        # Contains hyphens
        if '-' in domain:
            risk += 1

        # Long domain
        if len(domain) > 20:
            risk += 1

        # Suspicious keywords
        suspicious_keywords = ['login', 'bank', 'secure', 'account', 'paypal', 'crypto', 'verify']
        if any(keyword in domain.lower() for keyword in suspicious_keywords):
            risk += 1

        # Many subdomains
        if domain.count('.') > 2:
            risk += 1

        return risk