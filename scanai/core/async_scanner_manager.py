"""Async scanner manager for concurrent security scanning operations."""

import asyncio
import time
from typing import Dict, Any, List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor

from .scan_manager import ScanManager
from ..scanners.dnsrecon_scanner import DnsReconScanner
from ..scanners.subdomain_scanner import SubdomainScanner
from ..scanners.cve_scanner import CVEScanner
from ..services.async_api_service import async_api_service


class AsyncScannerManager:
    """Async manager for running multiple security scans concurrently."""

    def __init__(self):
        """Initialize the async scanner manager."""
        self.scan_manager = ScanManager()
        self.dns_scanner = DnsReconScanner()
        self.subdomain_scanner = SubdomainScanner()
        self.cve_scanner = CVEScanner()

    async def async_dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """
        Perform async DNS enumeration with fallback options.

        Args:
            domain: Domain to enumerate

        Returns:
            DNS enumeration results
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()

        # Run DNS enumeration in a thread pool to avoid blocking
        # (since the current DNS scanner uses subprocess and synchronous operations)
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = await loop.run_in_executor(executor, self.dns_scanner.scan, domain)

        return result

    async def async_subdomain_enumeration(self, domain: str) -> Dict[str, Any]:
        """
        Perform async subdomain enumeration.

        Args:
            domain: Domain to enumerate subdomains for

        Returns:
            Subdomain enumeration results
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()

        # Run subdomain enumeration in a thread pool
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = await loop.run_in_executor(executor, self.subdomain_scanner.scan, domain)

        return result

    async def async_cve_lookup(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Perform async CVE lookups for multiple CVEs concurrently.

        Args:
            cve_ids: List of CVE IDs to lookup

        Returns:
            Dictionary mapping CVE IDs to their information
        """
        return await self.cve_scanner.async_lookup_cves(cve_ids)

    async def async_multiple_scans(self, target: str, scan_types: List[str]) -> Dict[str, Any]:
        """
        Run multiple scan types concurrently.

        Args:
            target: Target to scan
            scan_types: List of scan types to run ('dns', 'subdomain', 'cve')

        Returns:
            Combined scan results
        """
        start_time = time.time()
        results = {
            'target': target,
            'scan_types': scan_types,
            'results': {},
            'duration': 0,
            'errors': []
        }

        # Create tasks for each scan type
        tasks = []

        if 'dns' in scan_types:
            tasks.append(('dns', self.async_dns_enumeration(target)))

        if 'subdomain' in scan_types:
            tasks.append(('subdomain', self.async_subdomain_enumeration(target)))

        # For CVE scans, we need software information first
        # This would typically come from other scans
        if 'cve' in scan_types:
            # For now, skip CVE scans in this async version
            # They require software detection from other scans
            pass

        # Execute all tasks concurrently
        if tasks:
            task_results = await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)

            for i, (scan_type, _) in enumerate(tasks):
                try:
                    result = task_results[i]
                    if isinstance(result, Exception):
                        results['errors'].append({
                            'scan_type': scan_type,
                            'error': str(result)
                        })
                    else:
                        results['results'][scan_type] = result
                except Exception as e:
                    results['errors'].append({
                        'scan_type': scan_type,
                        'error': str(e)
                    })

        results['duration'] = time.time() - start_time
        return results

    async def async_api_batch_scan(self, urls: List[str]) -> Dict[str, Any]:
        """
        Perform batch API scanning on multiple URLs concurrently.

        Args:
            urls: List of URLs to scan

        Returns:
            Batch scan results from multiple APIs
        """
        start_time = time.time()

        # Run VirusTotal and URLScan concurrently
        vt_task = async_api_service.fetch_virustotal_reports(urls)
        urlscan_task = async_api_service.fetch_urlscan_reports(urls)

        results = await asyncio.gather(vt_task, urlscan_task, return_exceptions=True)

        scan_results = {
            'urls_scanned': urls,
            'virustotal_results': {},
            'urlscan_results': {},
            'duration': time.time() - start_time,
            'errors': []
        }

        # Process VirusTotal results
        if isinstance(results[0], Exception):
            scan_results['errors'].append({
                'service': 'virustotal',
                'error': str(results[0])
            })
        else:
            scan_results['virustotal_results'] = results[0]

        # Process URLScan results
        if isinstance(results[1], Exception):
            scan_results['errors'].append({
                'service': 'urlscan',
                'error': str(results[1])
            })
        else:
            scan_results['urlscan_results'] = results[1]

        return scan_results

    async def async_comprehensive_scan(self, target: str, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Perform a comprehensive async security scan.

        Args:
            target: Target to scan comprehensively
            progress_callback: Optional callback for progress updates

        Returns:
            Comprehensive scan results
        """
        start_time = time.time()

        if progress_callback:
            progress_callback("Starting comprehensive async scan", 0, 100)

        # Step 1: DNS and subdomain enumeration concurrently
        if progress_callback:
            progress_callback("Enumerating DNS and subdomains", 10, 100)

        dns_task = self.async_dns_enumeration(target)
        subdomain_task = self.async_subdomain_enumeration(target)

        dns_result, subdomain_result = await asyncio.gather(dns_task, subdomain_task, return_exceptions=True)

        results = {
            'target': target,
            'scan_type': 'comprehensive_async',
            'dns': dns_result if not isinstance(dns_result, Exception) else {'error': str(dns_result)},
            'subdomains': subdomain_result if not isinstance(subdomain_result, Exception) else {'error': str(subdomain_result)},
            'duration': 0,
            'errors': []
        }

        # Collect errors
        if isinstance(dns_result, Exception):
            results['errors'].append({'component': 'dns', 'error': str(dns_result)})
        if isinstance(subdomain_result, Exception):
            results['errors'].append({'component': 'subdomains', 'error': str(subdomain_result)})

        if progress_callback:
            progress_callback("Async scan completed", 100, 100)

        results['duration'] = time.time() - start_time
        return results


# Global async scanner manager instance
async_scanner_manager = AsyncScannerManager()