"""Smart Correlation Engine — cross-scanner intelligence analysis."""

from typing import Dict, Any, List


class IntelCorrelator:
    """Correlates findings across multiple scanners to identify attack paths."""

    def correlate(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze all scan results and correlate findings.

        Returns:
            Dictionary with attack_paths, risk_factors, recommendations, and intel_score.
        """
        details = results.get('details', {})
        if not details:
            return {'attack_paths': [], 'risk_factors': [], 'recommendations': [], 'intel_score': 0}

        attack_paths = []
        risk_factors = []
        recommendations = []
        intel_score = 0

        # ── Extract key intelligence ──────────────────────
        open_ports = self._extract_open_ports(details)
        cves = self._extract_cves(details)
        web_vulns = self._extract_web_vulns(details)
        tech_stack = self._extract_tech_stack(details)
        subdomains = self._extract_subdomains(details)
        exposed_paths = self._extract_paths(details)
        emails = self._extract_emails(details)
        waf_info = self._extract_waf(details)
        wp_info = self._extract_wordpress(details)
        wayback_interesting = self._extract_wayback_interesting(details)
        secrets = self._extract_secrets(details)

        # ── Correlate: Port + CVE → Attack Path ──────────
        if open_ports and cves:
            critical_cves = [c for c in cves if c.get('severity') in ('CRITICAL', 'HIGH')]
            if critical_cves:
                attack_paths.append({
                    'name': 'Service Exploitation',
                    'severity': 'CRITICAL',
                    'description': f'{len(critical_cves)} critical CVEs on {len(open_ports)} open services',
                    'steps': [
                        f'Open ports: {", ".join(str(p["port"]) for p in open_ports[:5])}',
                        f'Critical CVEs: {", ".join(c.get("id", "?") for c in critical_cves[:3])}',
                        'Search for public exploits → Exploit service → Gain access'
                    ]
                })
                intel_score += 30

        # ── Correlate: WAF absent + Web vulns → Easy exploitation ──
        if web_vulns and not waf_info.get('waf_detected'):
            attack_paths.append({
                'name': 'Unprotected Web Exploitation',
                'severity': 'HIGH',
                'description': f'{len(web_vulns)} web vulnerabilities with NO WAF protection',
                'steps': [
                    'No WAF detected — direct exploitation possible',
                    f'Vulnerabilities: {", ".join(v.get("type", "?") for v in web_vulns[:3])}',
                    'Craft payloads → Exploit directly → Exfiltrate data'
                ]
            })
            intel_score += 25
        elif web_vulns and waf_info.get('waf_detected'):
            risk_factors.append(f'WAF detected ({waf_info.get("waf_name", "Unknown")}) — may need evasion techniques')
            recommendations.append(f'Test WAF bypass: try encoding, case variation, and tamper scripts for {waf_info.get("waf_name", "the WAF")}')

        # ── Correlate: WordPress + Plugins → CMS attack path ──
        if wp_info.get('vulnerabilities'):
            attack_paths.append({
                'name': 'WordPress CMS Exploitation',
                'severity': 'HIGH',
                'description': f'WordPress {wp_info.get("version", "?")} with {len(wp_info["vulnerabilities"])} known vulnerabilities',
                'steps': [
                    f'WordPress version: {wp_info.get("version", "Unknown")}',
                    f'Vulnerable plugins/themes: {len(wp_info["vulnerabilities"])}',
                    'Use public exploits → Gain admin access → Upload web shell'
                ]
            })
            intel_score += 25

        # ── Correlate: Exposed paths + Tech stack → Info disclosure ──
        if exposed_paths:
            sensitive_paths = [p for p in exposed_paths if any(kw in p.lower() for kw in
                ['admin', 'backup', 'config', '.env', '.git', 'debug', 'phpmyadmin', 'api'])]
            if sensitive_paths:
                attack_paths.append({
                    'name': 'Information Disclosure',
                    'severity': 'MEDIUM',
                    'description': f'{len(sensitive_paths)} sensitive paths discovered',
                    'steps': [
                        f'Sensitive paths: {", ".join(sensitive_paths[:5])}',
                        'Access sensitive paths → Extract config/credentials → Pivot'
                    ]
                })
                intel_score += 15

        # ── Correlate: Wayback + Current → Historical exposure ──
        if wayback_interesting:
            attack_paths.append({
                'name': 'Historical Exposure (Wayback Machine)',
                'severity': 'MEDIUM',
                'description': f'{len(wayback_interesting)} historically interesting URLs found',
                'steps': [
                    'Archived sensitive files found in Wayback Machine',
                    'Check if files still accessible → Extract leaked data'
                ]
            })
            intel_score += 10

        # ── Correlate: Secrets/Credentials found ──
        if secrets:
            active_secrets = [s for s in secrets if s.get('validation') in ('confirmed', 'active', 'valid')]
            if active_secrets:
                attack_paths.append({
                    'name': 'Active Credential Exposure',
                    'severity': 'CRITICAL',
                    'description': f'{len(active_secrets)} ACTIVE credentials validated — immediate access possible',
                    'steps': [
                        f'Active secrets found: {", ".join(s.get("rule_name", "?") for s in active_secrets[:3])}',
                        'Use credentials to authenticate → Access services → Pivot internally'
                    ]
                })
                intel_score += 40
            elif secrets:
                risk_factors.append(f'{len(secrets)} secrets/credentials detected in target — review for active exposure')
                recommendations.append('Rotate all detected credentials immediately and audit secret storage')
                intel_score += 15

        # ── Correlate: Emails + Subdomains → Social engineering surface ──
        if emails:
            risk_factors.append(f'{len(emails)} email addresses discovered — phishing/social engineering risk')
            recommendations.append('Implement email spoofing protections (DMARC, DKIM, SPF)')
            intel_score += 5

        if subdomains and len(subdomains) > 10:
            risk_factors.append(f'Large attack surface: {len(subdomains)} subdomains — some may be unmonitored')
            recommendations.append('Audit all subdomains for security posture — check for takeover vulnerabilities')
            intel_score += 5

        # ── Correlate: Open ports → Network hardening ──
        high_risk_ports = [p for p in open_ports if p.get('port') in [21, 23, 445, 3306, 3389, 5432, 6379, 5900]]
        if high_risk_ports:
            risk_factors.append(f'High-risk services exposed: {", ".join(str(p["port"]) for p in high_risk_ports)}')
            recommendations.append('Restrict high-risk services to VPN/internal network only')
            intel_score += 10

        # ── Security header analysis ──
        headers_data = details.get('server_headers', {})
        audit = headers_data.get('security_audit', {})
        if audit and audit.get('score', 100) < 50:
            risk_factors.append(f'Poor security header score: {audit.get("score", "?")}% — missing {len(audit.get("missing", []))} headers')
            recommendations.append('Implement missing security headers: ' + ', '.join(audit.get('missing', [])[:3]))
            intel_score += 10

        # Cap score
        intel_score = min(100, intel_score)

        return {
            'attack_paths': attack_paths,
            'risk_factors': risk_factors,
            'recommendations': recommendations,
            'intel_score': intel_score,
            'summary': self._generate_summary(attack_paths, risk_factors, intel_score),
        }

    def _generate_summary(self, paths: List, factors: List, score: int) -> str:
        if score >= 70:
            return f"CRITICAL — {len(paths)} attack paths identified with high exploitation probability"
        elif score >= 40:
            return f"HIGH RISK — {len(paths)} potential attack vectors, {len(factors)} risk factors"
        elif score >= 20:
            return f"MODERATE — some risk factors identified, limited attack surface"
        else:
            return "LOW RISK — minimal attack surface detected"

    # ── Data Extractors ───────────────────────────────────

    def _extract_open_ports(self, details: Dict) -> List[Dict]:
        nmap = details.get('nmap', {})
        ports = nmap.get('ports', [])
        return [p for p in ports if isinstance(p, dict) and p.get('state') == 'open']

    def _extract_cves(self, details: Dict) -> List[Dict]:
        cves = details.get('cves', {})
        return cves.get('cves', []) if isinstance(cves, dict) else []

    def _extract_web_vulns(self, details: Dict) -> List[Dict]:
        vulns = []
        # Nuclei
        nuclei = details.get('nuclei', {})
        vulns.extend(nuclei.get('findings', []))
        # Dalfox
        dalfox = details.get('dalfox', {})
        vulns.extend(dalfox.get('findings', []))
        # SQLMap
        sqli = details.get('sqlmap', {})
        if sqli.get('injectable'):
            vulns.append({'type': 'SQL Injection', 'target': sqli.get('target', '')})
        # Nikto
        nikto = details.get('nikto', {})
        vulns.extend(nikto.get('findings', []))
        return vulns

    def _extract_tech_stack(self, details: Dict) -> Dict:
        return details.get('whatweb', {}).get('technologies', {})

    def _extract_subdomains(self, details: Dict) -> List[str]:
        sub = details.get('subdomain', {})
        return sub.get('subdomains', [])

    def _extract_paths(self, details: Dict) -> List[str]:
        paths = []
        gobuster = details.get('gobuster', {})
        for p in gobuster.get('found_paths', []):
            paths.append(p.get('path', ''))
        katana = details.get('katana', {})
        paths.extend(katana.get('all_endpoints', []))
        return paths

    def _extract_emails(self, details: Dict) -> List[str]:
        harvester = details.get('harvester', {})
        return harvester.get('emails', [])

    def _extract_waf(self, details: Dict) -> Dict:
        return details.get('waf', {})

    def _extract_wordpress(self, details: Dict) -> Dict:
        return details.get('wpscan', {})

    def _extract_wayback_interesting(self, details: Dict) -> List[Dict]:
        wb = details.get('wayback', {})
        return wb.get('interesting', [])

    def _extract_secrets(self, details: Dict) -> List[Dict]:
        titus = details.get('titus', {})
        return titus.get('secrets', [])
