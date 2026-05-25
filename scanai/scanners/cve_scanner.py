"""CVE vulnerability scanner using NVD API and Shodan CVEDB (ReconEngine style)."""

import requests
import time
import asyncio
from typing import Dict, Any, List, Optional

from .base_scanner import BaseScanner
from ..services.shodan_cvedb_service import ShodanCVEDBService


class CVEScanner(BaseScanner):
    """Scanner for CVE vulnerabilities using NVD API and Shodan CVEDB."""

    def __init__(self) -> None:
        """Initialize the CVE scanner."""
        super().__init__(
            name="cves",
            description="CVE vulnerability analysis with NVD and CVEDB"
        )
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cvedb = ShodanCVEDBService()

    def scan(self, software_list: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """Scan software list for CVEs (ReconEngine style).

        Args:
            software_list: List of software with name and version
            **kwargs: Additional arguments (ignored)

        Returns:
            CVE scan results
        """
        start_time = time.time()

        # Load workflow profile if specified
        profile_name = kwargs.get('profile')
        if profile_name:
            from ..core.workflow_loader import get_registry
            profile = get_registry().get_profile('cve', profile_name)
            if profile:
                self.set_profile(profile)

        try:
            if not software_list:
                return self._create_result(
                    success=True,
                    data={
                        'cves': [],
                        'total_results': 0,
                        'software_scanned': [],
                        'message': 'No software detected for CVE scanning'
                    },
                    duration=time.time() - start_time
                )

            all_cves = []

            # Search CVEs for each software using multiple sources
            for software in software_list:
                if not software or not isinstance(software, dict):
                    continue
                    
                # Try NVD first
                software_cves = self._search_cves_by_software(software)
                if software_cves and 'cves' in software_cves:
                    # Add software info to each CVE
                    for cve in software_cves['cves']:
                        if cve and isinstance(cve, dict):
                            cve['detected_software'] = software
                            cve['source'] = 'nvd'
                            all_cves.append(cve)

                # Try CVEDB for additional data
                cvedb_cves = self._search_cves_cvedb(software)
                if cvedb_cves and 'cves' in cvedb_cves:
                    # Add CVEDB-specific data
                    for cve in cvedb_cves['cves']:
                        cve['detected_software'] = software
                        cve['source'] = 'cvedb'
                        # Avoid duplicates (use safe key access)
                        existing_ids = [
                            existing.get('id', existing.get('cve', '')) 
                            for existing in all_cves 
                            if existing and isinstance(existing, dict)
                        ]
                        if cve and isinstance(cve, dict) and cve.get('cve', '') not in existing_ids:
                            all_cves.append(cve)

            # Remove duplicates by CVE ID
            unique_cves = self._remove_duplicate_cves(all_cves)

            # Apply profile-based severity filtering
            active_method = None
            min_severity = None
            if self._workflow_profile:
                active_method = self._workflow_profile.method
                min_severity = self._workflow_profile.extra.get('min_severity')
            
            if min_severity:
                severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                min_idx = severity_order.index(min_severity) if min_severity in severity_order else 0
                unique_cves = [
                    c for c in unique_cves
                    if isinstance(c, dict) and severity_order.index(c.get('severity', 'LOW')) >= min_idx
                    if c.get('severity', 'LOW') in severity_order
                ]

            # Mark exploitable CVEs if using exploitable profile
            if active_method == 'cve_exploitable':
                for cve in unique_cves:
                    if isinstance(cve, dict):
                        # Flag CVEs that have known exploit references
                        refs = cve.get('references', [])
                        cve['has_exploit'] = any(
                            'exploit' in str(r).lower() or 'github.com' in str(r).lower() or 'packetstorm' in str(r).lower()
                            for r in (refs if isinstance(refs, list) else [])
                        )
                # Filter to only exploitable if that's what was requested
                unique_cves = [c for c in unique_cves if isinstance(c, dict) and c.get('has_exploit', False)]

            result_data = {
                'cves': unique_cves,
                'total_results': len(unique_cves),
                'software_scanned': software_list,
                'profile': self._workflow_profile.name if self._workflow_profile else 'standard',
            }

            return self._create_result(
                success=True,
                data=result_data,
                duration=time.time() - start_time
            )

        except Exception as e:
            return self._create_result(
                success=False,
                error=f"CVE scan error: {str(e)}",
                duration=time.time() - start_time
            )

    def _search_cves_by_software(self, software: Dict[str, str]) -> Dict[str, Any]:
        """Search for CVEs affecting specific software (ReconEngine style).

        Args:
            software: Software info with name and version

        Returns:
            CVE results dictionary
        """
        name = (software.get('name') or '').lower().strip()
        version = (software.get('version') or '').strip()

        if not name:
            return {'cves': [], 'total_results': 0}

        # Log what we're searching for (for debugging)
        print(f"[CVE] Searching for: {name} {version if version else '(no version)'}")

        # Use CPE-like format for better matching: vendor:product format
        # Normalize the software name to proper format
        normalized_name = self._normalize_software_name(name)
        
        # Build search keywords using multiple strategies for better accuracy
        search_keywords = []
        
        # Strategy 1: Exact product name (most specific)
        if version:
            # Try exact version match
            search_keywords.append(f"{normalized_name} {version}")
            # Try without patch version (e.g., 2.4.49 -> 2.4)
            if '.' in version:
                major_minor = '.'.join(version.split('.')[:2])
                search_keywords.append(f"{normalized_name} {major_minor}")
        
        # Strategy 2: Product name only (broader search)
        search_keywords.append(normalized_name)
        
        # Try each keyword until we get relevant results
        all_results = {'cves': [], 'total_results': 0}
        for idx, keyword in enumerate(search_keywords):
            print(f"[CVE] Attempt {idx + 1}/{len(search_keywords)}: '{keyword}'")
            results = self._search_cves(keyword, 30, 0)
            
            if results and not results.get('error'):
                cves = results.get('cves', [])
                total = results.get('total_results', 0)
                
                if cves and total > 0:
                    all_results['cves'].extend(cves)
                    all_results['total_results'] = total
                    print(f"[CVE] Found {len(cves)} results with keyword '{keyword}'")
                    break  # Found results, stop trying other keywords
        
        # If NVD API failed to find anything, try Google search as fallback
        if not all_results['cves']:
            print(f"[CVE] NVD API returned no results. Trying Google search fallback...")
            google_cves = self._search_cves_via_google(name, version)
            if google_cves:
                all_results['cves'] = google_cves
                all_results['total_results'] = len(google_cves)
                print(f"[CVE] Google search found {len(google_cves)} CVEs")
        
        # Apply strict filtering to ensure true positives
        if all_results['cves']:
            filtered = self._filter_cves_by_version(all_results['cves'], normalized_name, version or '')
            print(f"[CVE] After strict filtering: {len(filtered)} relevant CVEs")
            
            # Remove duplicates by CVE ID
            seen_ids = set()
            unique_cves = []
            for cve in filtered:
                cve_id = cve.get('id') if isinstance(cve, dict) else None
                if cve_id and cve_id not in seen_ids:
                    seen_ids.add(cve_id)
                    unique_cves.append(cve)
            
            all_results['cves'] = unique_cves[:10]  # Limit to top 10 most relevant
            all_results['total_results'] = len(unique_cves)
            
            print(f"[CVE] Final result: {len(unique_cves)} unique true positive CVEs")
        else:
            print(f"[CVE] No CVEs found for {name} {version or ''}")
        
        return all_results

    def _search_cves(self, keyword: str, results_per_page: int = 20, start_index: int = 0) -> Dict[str, Any]:
        """Search CVEs by keyword (ReconEngine style).

        Args:
            keyword: Search keyword
            results_per_page: Number of results per page
            start_index: Starting index for pagination

        Returns:
            CVE search results
        """
        try:
            # Build query URL (ReconEngine approach)
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': results_per_page,
                'startIndex': start_index
            }

            headers = {
                'Accept': 'application/json',
                'User-Agent': 'ScanAI/1.0'
            }

            response = requests.get(self.api_url, params=params, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return self._parse_cve_data(data)
            else:
                return {'error': f'API returned HTTP {response.status_code}'}

        except requests.RequestException as e:
            return {'error': f'Request error: {str(e)}'}
        except Exception as e:
            return {'error': f'Exception: {str(e)}'}
    
    def _search_cves_via_google(self, software_name: str, version: str = None) -> list:
        """Search for CVEs using Google as fallback when NVD API fails.
        
        Args:
            software_name: Name of the software
            version: Version of the software
            
        Returns:
            List of CVE vulnerability objects
        """
        import re
        
        try:
            # Build Google search query
            query = f"{software_name} {version} CVE vulnerability" if version else f"{software_name} CVE vulnerability"
            search_url = f"https://www.google.com/search?q={requests.utils.quote(query)}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            print(f"[CVE] Google search: {query}")
            response = requests.get(search_url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                return []
            
            # Extract CVE IDs from Google results (format: CVE-YYYY-NNNNN)
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cve_ids = re.findall(cve_pattern, response.text)
            
            # Remove duplicates and limit
            unique_cve_ids = list(dict.fromkeys(cve_ids))[:15]
            
            if not unique_cve_ids:
                print(f"[CVE] No CVE IDs found in Google results")
                return []
            
            print(f"[CVE] Found {len(unique_cve_ids)} CVE IDs from Google: {', '.join(unique_cve_ids[:5])}...")
            
            # Fetch full CVE details from NVD for each ID
            cves = []
            for cve_id in unique_cve_ids[:10]:  # Limit to 10 to avoid rate limiting
                try:
                    cve_url = f"{self.api_url}?cveId={cve_id}" # Changed self.base_url to self.api_url
                    cve_response = requests.get(cve_url, timeout=10)
                    
                    if cve_response.status_code == 200:
                        data = cve_response.json()
                        vulnerabilities = data.get('vulnerabilities', [])
                        if vulnerabilities:
                            cves.extend(vulnerabilities)
                    
                    # Small delay to avoid rate limiting
                    import time
                    time.sleep(0.5)
                except Exception as e:
                    print(f"[CVE] Error fetching {cve_id}: {e}")
                    continue
            
            return cves
            
        except Exception as e:
            print(f"[CVE] Google search error: {e}")
            return []
    
    def _normalize_software_name(self, name: str) -> str:
        """Normalize software name to match CVE database format with proper capitalization.
        
        Args:
            name: Raw software name
            
        Returns:
            Normalized name with proper capitalization for NVD queries
        """
        name_lower = name.lower().strip()
        
        # Map to CVE database format with PROPER CAPITALIZATION
        # Examples that work: "Apache 2.4.52", "openssh 8.2", "PHP 7.4"
        name_mapping = {
            'apache': 'Apache',
            'apache httpd': 'Apache',
            'httpd': 'Apache',
            'nginx': 'NGINX',
            'php': 'PHP',
            'php-fpm': 'PHP',
            'openssl': 'OpenSSL',
            'mysql': 'MySQL',
            'mariadb': 'MariaDB',
            'postgresql': 'PostgreSQL',
            'postgres': 'PostgreSQL',
            'tomcat': 'Apache Tomcat',
            'apache tomcat': 'Apache Tomcat',
            'iis': 'Microsoft IIS',
            'microsoft-iis': 'Microsoft IIS',
            'microsoft iis': 'Microsoft IIS',
            'asp.net': 'ASP.NET',
            'dotnet': '.NET',
            '.net': '.NET',
            'python': 'Python',
            'node': 'Node.js',
            'nodejs': 'Node.js',
            'node.js': 'Node.js',
            'express': 'Express',
            'django': 'Django',
            'flask': 'Flask',
            'laravel': 'Laravel',
            'wordpress': 'WordPress',
            'drupal': 'Drupal',
            'joomla': 'Joomla',
            'magento': 'Magento',
            'openssh': 'OpenSSH',
            'ssh': 'OpenSSH',
            'ssl': 'OpenSSL',
            'redis': 'Redis',
            'mongodb': 'MongoDB',
            'elasticsearch': 'Elasticsearch',
            'jenkins': 'Jenkins',
            'docker': 'Docker',
            'kubernetes': 'Kubernetes',
            'git': 'Git',
        }
        
        # Return capitalized name or title case the original as fallback
        return name_mapping.get(name_lower, name.title())
    
    def _filter_cves_by_version(self, cves: list, software_name: str, version: str) -> list:
        """Filter CVEs to only include those relevant to the software and version.
        
        Args:
            cves: List of CVE dictionaries
            software_name: Name of the software
            version: Version of the software
            
        Returns:
            Filtered list of relevant CVEs
        """
        if not cves:
            return []
        
        filtered = []
        software_lower = software_name.lower()
        
        for cve in cves:
            if not isinstance(cve, dict):
                continue
            
            description = (cve.get('description', '') or '').lower()
            
            # STRICT: CVE must mention the software name
            if software_lower not in description:
                continue
            
            # If version is provided, check if CVE is relevant to this version
            if version:
                # Check if version is mentioned in description
                if version in description:
                    filtered.append(cve)
                    continue
                
                # Check major.minor version (e.g., 2.4 from 2.4.49)
                if '.' in version:
                    parts = version.split('.')
                    if len(parts) >= 2:
                        major_minor = f"{parts[0]}.{parts[1]}"
                        if major_minor in description:
                            filtered.append(cve)
                            continue
                    
                    # Check major version only
                    if parts[0] in description:
                        # Be careful - only add if it looks like a version context
                        if f"version {parts[0]}" in description or f"v{parts[0]}" in description:
                            filtered.append(cve)
                            continue
                
                # If CVE has "all versions" or "versions prior to" it might be relevant
                if any(phrase in description for phrase in [
                    'all versions',
                    'versions prior',
                    'versions before',
                    'versions up to',
                    'through version',
                    'before version'
                ]):
                    filtered.append(cve)
            else:
                # No version specified, just ensure software name matches
                filtered.append(cve)
        
        return filtered

    def _generate_search_terms(self, name: str, version: str) -> List[str]:
        """Generate search terms for CVE lookup.

        Args:
            name: Software name
            version: Software version

        Returns:
            List of search terms to try
        """
        terms = []

        # Normalize software names to match NVD database with enhanced mappings
        name_mapping = {
            'apache': 'apache http server',
            'apache httpd': 'apache http server',
            'httpd': 'apache http server',
            'nginx': 'nginx',
            'php': 'php',
            'openssl': 'openssl',
            'mysql': 'mysql',
            'mariadb': 'mariadb',
            'postgresql': 'postgresql',
            'postgres': 'postgresql',
            'tomcat': 'apache tomcat',
            'apache tomcat': 'apache tomcat',
            'iis': 'microsoft iis',
            'microsoft iis': 'microsoft iis',
            'asp.net': 'asp.net',
            'dotnet': '.net framework',
            '.net': '.net framework',
            'python': 'python',
            'node': 'node.js',
            'nodejs': 'node.js',
            'node.js': 'node.js',
            'express': 'express',
            'django': 'django',
            'flask': 'flask',
            'laravel': 'laravel',
            'wordpress': 'wordpress',
            'drupal': 'drupal',
            'joomla': 'joomla',
            'magento': 'magento',
            'gunicorn': 'gunicorn',
            'tornado': 'tornado',
            'caddy': 'caddy',
            'cloudflare': 'cloudflare',
            'litespeed': 'litespeed',
            'openbsd httpd': 'openbsd httpd',
            'cherokee': 'cherokee',
        }

        normalized_name = name_mapping.get(name.lower(), name)

        # Generate search terms
        terms.append(normalized_name)
        if version:
            terms.append(f"{normalized_name} {version}")

        return terms

    def _query_nvd_api(self, keyword: str) -> List[Dict[str, Any]]:
        """Query NVD API for CVEs matching keyword.

        Args:
            keyword: Search keyword

        Returns:
            List of CVE data
        """
        try:
            # Try multiple search strategies
            search_strategies = [
                # Exact software match
                {'keywordSearch': keyword, 'resultsPerPage': 10},
                # Software with version
                {'keywordSearch': f'"{keyword}"', 'resultsPerPage': 10},
                # Broader search without severity filter first
                {'keywordSearch': keyword, 'resultsPerPage': 5, 'cvssV3Severity': 'HIGH,CRITICAL'},
            ]

            for params in search_strategies:
                response = requests.get(self.api_url, params=params, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    cves = self._parse_nvd_response(data)
                    if cves:  # Return first successful result
                        return cves

        except Exception as e:
            print(f"CVE API error for '{keyword}': {e}")

        return []

    def _parse_cve_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CVE data from NVD API (ReconEngine style).

        Args:
            data: Raw NVD API response

        Returns:
            Parsed CVE data dictionary
        """
        result = {
            'total_results': data.get('totalResults', 0),
            'cves': []
        }

        vulnerabilities = data.get('vulnerabilities', [])
        if not isinstance(vulnerabilities, list):
            return result

        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            if not cve_data:
                continue

            cve_id = cve_data.get('id', 'Unknown')

            # Get description (ReconEngine approach)
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc and isinstance(desc, dict) and desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')

            # Get CVSS scores and severity (ReconEngine approach)
            metrics = cve_data.get('metrics', {})
            cvss_v3 = None
            cvss_v2 = None
            severity = 'UNKNOWN'

            if metrics.get('cvssMetricV31') and isinstance(metrics['cvssMetricV31'], list) and len(metrics['cvssMetricV31']) > 0:
                cvss = metrics['cvssMetricV31'][0]
                cvss_data = cvss.get('cvssData', {}) if isinstance(cvss, dict) else {}
                cvss_v3 = {
                    'version': '3.1',
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': cvss_data.get('baseSeverity'),
                    'vectorString': cvss_data.get('vectorString')
                }
                severity = (cvss_v3.get('baseSeverity') or 'UNKNOWN')
            elif metrics.get('cvssMetricV30') and isinstance(metrics['cvssMetricV30'], list) and len(metrics['cvssMetricV30']) > 0:
                cvss = metrics['cvssMetricV30'][0]
                cvss_data = cvss.get('cvssData', {}) if isinstance(cvss, dict) else {}
                cvss_v3 = {
                    'version': '3.0',
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': cvss_data.get('baseSeverity'),
                    'vectorString': cvss_data.get('vectorString')
                }
                severity = (cvss_v3.get('baseSeverity') or 'UNKNOWN')
            elif metrics.get('cvssMetricV2') and isinstance(metrics['cvssMetricV2'], list) and len(metrics['cvssMetricV2']) > 0:
                cvss = metrics['cvssMetricV2'][0]
                cvss_data = cvss.get('cvssData', {}) if isinstance(cvss, dict) else {}
                cvss_v2 = {
                    'version': '2.0',
                    'baseScore': cvss_data.get('baseScore'),
                    'vectorString': cvss_data.get('vectorString')
                }
                # Map CVSS v2 to severity
                score = cvss_v2['baseScore'] or 0
                if score >= 7.0:
                    severity = 'HIGH'
                elif score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'

            # Get references
            references = []
            refs = cve_data.get('references', [])
            if isinstance(refs, list):
                for ref in refs:
                    if ref and isinstance(ref, dict):
                        references.append({
                            'url': ref.get('url', ''),
                            'source': ref.get('source', '')
                        })

            # Get dates
            published = cve_data.get('published')
            last_modified = cve_data.get('lastModified')
            vuln_status = cve_data.get('vulnStatus', 'UNKNOWN')

            result['cves'].append({
                'id': cve_id,
                'description': description,
                'severity': severity,
                'cvss_v3': cvss_v3,
                'cvss_v2': cvss_v2,
                'references': references,
                'published': published,
                'last_modified': last_modified,
                'vuln_status': vuln_status
            })

        return result

    def _search_cves_cvedb(self, software: Dict[str, str]) -> Dict[str, Any]:
        """Search CVEs using Shodan CVEDB.

        Args:
            software: Software info with name and version

        Returns:
            CVEDB search results
        """
        name = (software.get('name') or '').lower().strip()
        version = (software.get('version') or '').strip()

        if not name:
            return {'cves': [], 'total_results': 0}

        try:
            # Try searching by product name
            results = self.cvedb.search_cves_by_product(name, limit=5)

            if results and 'cves' in results and results['cves']:
                # Filter by version if available
                filtered_cves = []
                for cve in results['cves']:
                    if not cve or not isinstance(cve, dict):
                        continue
                    if version and version in str(cve.get('summary', '')):
                        filtered_cves.append(cve)
                    elif not version:  # If no version specified, include all
                        filtered_cves.append(cve)

                return {
                    'cves': filtered_cves[:3],  # Limit to top 3
                    'total_results': len(filtered_cves)
                }

        except Exception as e:
            # CVEDB failures shouldn't break the scan
            pass

        return {'cves': [], 'total_results': 0}

    def _remove_duplicate_cves(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate CVEs by ID, keeping the highest severity version.

        Args:
            cves: List of CVE data

        Returns:
            Deduplicated list of CVEs
        """
        seen_ids = {}
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}

        for cve in cves:
            if not cve or not isinstance(cve, dict):
                continue
                
            cve_id = cve.get('id', cve.get('cve', 'Unknown'))
            severity = cve.get('severity', 'UNKNOWN')

            if cve_id not in seen_ids:
                seen_ids[cve_id] = cve
            else:
                # Keep the higher severity version
                existing_cve = seen_ids[cve_id]
                current_severity_str = existing_cve.get('severity', 'UNKNOWN') if isinstance(existing_cve, dict) else 'UNKNOWN'
                current_severity = severity_order.get(current_severity_str, 0)
                new_severity = severity_order.get(severity, 0)

                if new_severity > current_severity:
                    seen_ids[cve_id] = cve

        return list(seen_ids.values())

    async def async_lookup_cves(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Async lookup multiple CVEs concurrently using CVEDB service.

        Args:
            cve_ids: List of CVE IDs to lookup

        Returns:
            Dictionary mapping CVE IDs to their detailed information
        """
        if not cve_ids:
            return {}

        # Use the async CVEDB service for bulk lookups
        return await self.cvedb.async_lookup_multiple_cves(cve_ids)