"""Analyst agent implementation — handles scan analysis, pro reports, and Q&A."""

import json
import logging
from typing import Dict, Any, Optional, Union

from .base_agent import BaseAgent
from ..prompts.analyst import ANALYST_SYSTEM_PROMPT, ANALYST_REPORT_PROMPT

logger = logging.getLogger(__name__)


class AnalystAgent(BaseAgent):
    """Agent responsible for analyzing findings and generating hacking guidance."""

    def generate_pro_report(self, target: str, findings: dict, query: str = "") -> str:
        """
        Generate a "Pro Hacker" report based on scan findings and user query.

        Args:
            target: The primary target.
            findings: Dictionary of scan findings.
            query: The original user query for context.

        Returns:
            A Markdown formatted report.
        """
        # Extract scanners used from findings keys ONLY IF they have data
        scanners_used = [k for k, v in findings.items() if v] if findings else ['unknown']
        scanners_used_str = ', '.join(scanners_used) if scanners_used else 'none'

        # Determine scan type based on number of scanners
        if len(scanners_used) > 2:
            scan_type = "comprehensive"
        elif len(scanners_used) == 1:
            scan_type = "targeted"
        else:
            scan_type = "multi-targeted"

        user_prompt = ANALYST_REPORT_PROMPT.format(
            target=target,
            query=query,
            scan_type=scan_type,
            scanners_used=scanners_used_str,
            findings_json=json.dumps(findings, indent=2)
        )

        # Use _generate_text for raw markdown output (not JSON)
        return self._generate_text(
            system_prompt=ANALYST_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.7
        )

    # ── Scan Result Analysis (migrated from ScanAIService) ────────────

    def explain_scan_results(
        self,
        scan_results: Dict[str, Any],
        user_query: str,
        skip_validation: bool = False
    ) -> Dict[str, Union[str, bool]]:
        """
        Explain vulnerability scan results based on user query.

        Args:
            scan_results: Complete scan results dictionary.
            user_query: User's question about the scan results.
            skip_validation: Whether to skip relevance validation.

        Returns:
            Dictionary with 'success', 'response', or 'error'.
        """
        try:
            # Validate that the query is about our scan results
            if not skip_validation and not self._is_scan_related_query(user_query, scan_results):
                return {
                    'error': 'I can only answer questions about the findings from this specific security scan. Please ask about the results shown above.'
                }

            context = self._build_scan_context(scan_results)
            scan_analysis = self._analyze_scan_findings(scan_results)

            prompt = f"""You are ScanAI, an advanced AI security assistant that thinks and operates like an experienced ethical hacker. You analyze security scan results and provide detailed, actionable guidance for security testing, vulnerability assessment, and bug hunting purposes.

CRITICAL: Your responses must be based SOLELY on what was ACTUALLY FOUND in this specific scan. Do NOT provide generic security advice or suggest testing for vulnerabilities that were not detected in the scan results.

=== ACTUAL SCAN FINDINGS ANALYSIS ===
{scan_analysis}

=== SCANAI SCAN RESULTS ===
{context}

=== USER QUESTION ===
{user_query}

RESPONSE GUIDELINES:
- Base ALL advice on the ACTUAL findings shown above
- If the user asks about a vulnerability type that was NOT found, explain why it's not applicable based on scan results
- If asking about testing a specific vulnerability, check if that vulnerability or related services were detected
- For database-related testing (SQLi, etc.), only provide guidance if database services or web applications were found
- For web application testing, only provide guidance if web services (HTTP/HTTPS) were detected
- For network service testing, only provide guidance for services that were actually found open
- Always reference specific findings from the scan results
- If something wasn't found, say so clearly and explain why testing might not be relevant

ETHICAL HACKER APPROACH:
- Provide targeted testing guidance based on confirmed findings
- Suggest appropriate tools for the specific services detected
- Include proof-of-concept examples using the actual target information
- Explain why certain tests are or aren't applicable based on scan results
- Focus on responsible testing methodologies

FORMATTING GUIDELINES:
- Use **Markdown** formatting for all responses
- Use **Emojis** for section headers and key points to make it visually engaging
- Use **Bold** for emphasis on critical findings
- Use `Code Blocks` for commands or technical details
- Structure the response with clear, bulleted lists
- Example Section Header: ### 🛡️ Executive Summary

Provide responses that are directly tied to the evidence found in this scan."""

            try:
                response_text = self._generate_text(
                    system_prompt="You are ScanAI, an elite cybersecurity analysis AI.",
                    user_prompt=prompt,
                    temperature=0.2
                )

                if response_text:
                    return {
                        'success': True,
                        'response': response_text.strip()
                    }
                else:
                    return {'error': 'No response generated from AI'}

            except Exception as e:
                return {'error': f'AI error: {str(e)}'}

        except Exception as e:
            return {'error': f'Service initialization error: {str(e)}'}

    def analyze_previous_scan(
        self,
        scan_results: Dict[str, Any],
        user_query: str
    ) -> Dict[str, Any]:
        """
        Analyze previous scan results and answer user questions about them.

        Args:
            scan_results: Complete scan result data.
            user_query: User's question about the scan results.

        Returns:
            Dictionary with success status and AI response.
        """
        try:
            target = scan_results.get('target', scan_results.get('url', 'Unknown'))
            risk_level = scan_results.get('level', 'unknown')
            duration = scan_results.get('duration', 0)
            details = scan_results.get('details', {})

            # Build rich context from scan data
            context_parts = []
            context_parts.append(f"Target: {target}")
            context_parts.append(f"Risk Level: {risk_level}")
            context_parts.append(f"Scan Duration: {duration:.1f} seconds")

            # DNS information
            if 'dns' in details:
                dns_data = details['dns']
                records = dns_data.get('records', {})
                record_types = [k for k, v in records.items() if v]
                if record_types:
                    context_parts.append(f"DNS Record Types: {', '.join(record_types)}")
                if 'SOA' in records and records['SOA']:
                    context_parts.append("SOA Record: Present")
                if 'NS' in records and records['NS']:
                    context_parts.append(f"Name Servers: {len(records['NS'])} found")
                if 'MX' in records and records['MX']:
                    context_parts.append(f"Mail Servers: {len(records['MX'])} found")

            # Port scan information
            if 'nmap' in details:
                nmap_data = details['nmap']
                ports = nmap_data.get('ports', [])
                open_ports = [p for p in ports if p.get('state') == 'open']
                context_parts.append(f"Open Ports: {len(open_ports)}")
                if open_ports:
                    port_nums = [str(p.get('port', 'unknown')) for p in open_ports[:5]]
                    context_parts.append(f"Open Port Numbers: {', '.join(port_nums)}")

            # Subdomain information
            if 'subdomain' in details:
                subdomain_data = details['subdomain']
                subdomains = subdomain_data.get('subdomains', [])
                context_parts.append(f"Subdomains Found: {len(subdomains)}")

            # Vulnerability information
            if 'cves' in details:
                cve_data = details['cves']
                cves = cve_data.get('cves', [])
                context_parts.append(f"Vulnerabilities Found: {len(cves)}")
                if cves:
                    critical_count = sum(1 for cve in cves if cve.get('severity', '').upper() == 'CRITICAL')
                    high_count = sum(1 for cve in cves if cve.get('severity', '').upper() == 'HIGH')
                    context_parts.append(f"Critical Vulnerabilities: {critical_count}, High: {high_count}")

            # SSL information
            if 'ssl' in details:
                context_parts.append("SSL Certificate: Checked")

            # Risk assessment
            risk_data = scan_results.get('summaries', {}).get('risk', {})
            total_risk = risk_data.get('total', 0)
            context_parts.append(f"Overall Risk Score: {total_risk}/100")

            scan_context = "\n".join(f"- {part}" for part in context_parts)

            prompt = f"""You are ScanAI, an elite cybersecurity analysis AI with extensive knowledge of network security, penetration testing, and threat assessment. You have just completed a comprehensive security scan of {target} and the user is asking follow-up questions about the results.

SCAN SUMMARY:
Target: {target}
Risk Level: {risk_level}
Scan Duration: {duration:.1f} seconds
Risk Score: {total_risk}/100

SCAN RESULTS OVERVIEW:
{scan_context}

USER QUESTION: "{user_query}"

INSTRUCTIONS FOR ANALYSIS:
1. **Be Extremely Technical**: Use precise cybersecurity terminology and concepts
2. **Provide Actionable Intelligence**: Give specific recommendations, not generic advice
3. **Security-First Mindset**: Always prioritize security implications and attack vectors
4. **Evidence-Based Analysis**: Reference specific findings from the scan data
5. **Risk Assessment**: Evaluate actual security risks, not just compliance
6. **Hacker Perspective**: Think like both a defender and an attacker
7. **Practical Solutions**: Provide implementable security measures
8. **Context Awareness**: Understand what information is available vs. what would need additional scanning

RESPONSE GUIDELINES:
- Start with direct answer to the question
- Explain technical details with authority
- Identify specific security implications
- Provide prioritized remediation steps
- Mention any additional investigation needed
- Use professional cybersecurity language
- Be concise but comprehensive
- Format with clear sections when appropriate

SECURITY ANALYSIS FRAMEWORK:
- **Immediate Threats**: Critical vulnerabilities, exposed services, misconfigurations
- **Attack Vectors**: How an attacker could exploit findings
- **Defense Strategy**: Specific countermeasures and hardening steps
- **Risk Quantification**: High/Medium/Low risk with justification
- **Investigation Path**: Next steps for deeper analysis

Answer the user's question with elite-level cybersecurity intelligence and actionable insights."""

            try:
                response_text = self._generate_text(
                    system_prompt="You are ScanAI, an elite cybersecurity analysis AI.",
                    user_prompt=prompt,
                    temperature=0.3
                )

                if response_text:
                    return {
                        'success': True,
                        'response': response_text.strip()
                    }
                else:
                    return {'success': False, 'error': 'No response from AI'}

            except Exception as e:
                return {'success': False, 'error': f'AI analysis error: {str(e)}'}

        except Exception as e:
            return {'success': False, 'error': f'Analysis failed: {str(e)}'}

    # ── Private helpers (migrated from ScanAIService) ─────────────────

    def _is_scan_related_query(self, query: str, scan_results: Dict[str, Any]) -> bool:
        """Check if the query is related to security testing and our scan results."""
        query_lower = query.lower()

        security_terms = [
            'cve', 'vulnerability', 'exploit', 'hack', 'security', 'penetration', 'pentest',
            'bug', 'bounty', 'testing', 'assessment', 'scan', 'attack', 'payload',
            'metasploit', 'burp', 'nmap', 'sql', 'xss', 'csrf', 'rce', 'lfi', 'rfi',
            'buffer', 'overflow', 'injection', 'deserialization', 'ssrf', 'xxe'
        ]

        has_security_context = any(term in query_lower for term in security_terms)

        scan_indicators = []

        if 'target' in scan_results:
            target = scan_results['target'].lower()
            scan_indicators.extend(target.split('.'))

        if 'details' in scan_results and 'cves' in scan_results['details']:
            cve_data = scan_results['details']['cves']
            if 'software_scanned' in cve_data:
                for software in cve_data['software_scanned']:
                    if 'name' in software:
                        scan_indicators.append(software['name'].lower())

        if 'details' in scan_results and 'cves' in scan_results['details']:
            cve_data = scan_results['details']['cves']
            if 'cves' in cve_data:
                for cve in cve_data['cves']:
                    cve_id = cve.get('id', cve.get('cve', '')).lower()
                    if cve_id:
                        scan_indicators.append(cve_id)

        scan_specific_terms = ['scan', 'result', 'finding', 'detected', 'found', 'this scan', 'these results']
        has_scan_reference = any(term in query_lower for term in scan_specific_terms)
        has_specific_finding = any(indicator in query_lower for indicator in scan_indicators if indicator)

        return has_security_context or has_scan_reference or has_specific_finding

    def _build_scan_context(self, scan_results: Dict[str, Any]) -> str:
        """Build a detailed technical context from scan results."""
        lines = []

        lines.append(f"🎯 Target: {scan_results.get('url', 'N/A')}")
        lines.append(f"🌐 IP Address: {scan_results.get('ip', 'N/A')}")
        lines.append(f"📊 Scan Status: {scan_results.get('status', 'N/A')}")
        lines.append(f"⏱️  Scan Duration: {scan_results.get('duration', 'N/A'):.2f} seconds")

        if 'level' in scan_results:
            risk_level = scan_results['level'].upper()
            risk_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(risk_level, '⚪')
            lines.append(f"🚨 Risk Level: {risk_emoji} {risk_level}")

        if 'summaries' in scan_results and 'virustotal' in scan_results['summaries']:
            vt = scan_results['summaries']['virustotal']
            malicious = vt.get('malicious', 0)
            suspicious = vt.get('suspicious', 0)
            harmless = vt.get('harmless', 0)
            lines.append(f"🛡️  VirusTotal: {malicious} malicious, {suspicious} suspicious, {harmless} harmless detections")

        if 'details' in scan_results and 'cves' in scan_results['details']:
            cve_data = scan_results['details']['cves']
            if 'cves' in cve_data and cve_data['cves']:
                lines.append(f"\n🔍 CVEs Found ({len(cve_data['cves'])} total):")
                for i, cve in enumerate(cve_data['cves'][:10], 1):
                    cve_id = cve.get('id', cve.get('cve', 'Unknown'))
                    severity = cve.get('severity', 'Unknown')
                    cvss_score = cve.get('cvss_score', 'N/A')
                    description = cve.get('description', '')[:300]
                    published = cve.get('published_date', 'Unknown')
                    severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity.upper(), '⚪')
                    lines.append(f"{i}. {severity_emoji} {cve_id} (CVSS: {cvss_score})")
                    lines.append(f"   📅 Published: {published}")
                    lines.append(f"   📝 {description}...")
                    if 'references' in cve and cve['references']:
                        lines.append(f"   🔗 References: {len(cve['references'])} available")
                    lines.append("")

        if 'details' in scan_results and 'nmap' in scan_results['details']:
            nmap_data = scan_results['details']['nmap']
            if 'ports' in nmap_data:
                open_ports = [p for p in nmap_data['ports'] if p.get('state') == 'open']
                if open_ports:
                    lines.append(f"\n🔌 Open Ports ({len(open_ports)} found):")
                    for port in open_ports[:15]:
                        port_num = port.get('port', 'Unknown')
                        service = port.get('service', 'Unknown')
                        version = port.get('version', '')
                        product = port.get('product', '')
                        service_info = f"{service}"
                        if product:
                            service_info += f" ({product}"
                        if version:
                            service_info += f" {version}"
                        if product or version:
                            service_info += ")"
                        lines.append(f"   {port_num}/tcp - {service_info}")

        if 'details' in scan_results and 'subdomains' in scan_results['details']:
            subdomains = scan_results['details']['subdomains'].get('subdomains', [])
            if subdomains:
                lines.append(f"\n🌐 Subdomains ({len(subdomains)} found):")
                subdomain_list = ', '.join(subdomains[:20])
                lines.append(f"   {subdomain_list}")
                if len(subdomains) > 20:
                    lines.append(f"   ... and {len(subdomains) - 20} more")

        if 'details' in scan_results and 'ssl' in scan_results['details']:
            ssl_data = scan_results['details']['ssl']
            if ssl_data:
                lines.append(f"\n🔒 SSL/TLS Information:")
                if 'certificate' in ssl_data:
                    cert = ssl_data['certificate']
                    issuer = cert.get('issuer', 'Unknown')
                    subject = cert.get('subject', 'Unknown')
                    valid_until = cert.get('valid_until', 'Unknown')
                    lines.append(f"   📜 Certificate Issuer: {issuer}")
                    lines.append(f"   📜 Certificate Subject: {subject}")
                    lines.append(f"   📅 Valid Until: {valid_until}")

        return '\n'.join(lines)

    def _analyze_scan_findings(self, scan_results: Dict[str, Any]) -> str:
        """Analyze scan results to determine what was actually found."""
        findings = []

        target = scan_results.get('target', 'Unknown')
        ip = scan_results.get('ip', 'Unknown')
        findings.append(f"🎯 TARGET: {target} (IP: {ip})")

        has_web_services = False
        web_ports = []
        if 'details' in scan_results and 'nmap' in scan_results['details']:
            nmap_data = scan_results['details']['nmap']
            if 'ports' in nmap_data:
                for port in nmap_data['ports']:
                    if port.get('state') == 'open':
                        service = port.get('service', '').lower()
                        port_num = port.get('port', 0)
                        if service in ['http', 'https'] or port_num in [80, 443, 8080, 8443]:
                            has_web_services = True
                            web_ports.append(f"{port_num}/{service}")
                        findings.append(f"🔌 OPEN PORT: {port_num}/tcp - {service}")

        if has_web_services:
            findings.append(f"🌐 WEB SERVICES DETECTED: {', '.join(web_ports)} - Web application testing may be applicable")
        else:
            findings.append("❌ NO WEB SERVICES: No HTTP/HTTPS ports detected - web application testing not applicable")

        has_db_services = False
        db_ports = []
        if 'details' in scan_results and 'nmap' in scan_results['details']:
            nmap_data = scan_results['details']['nmap']
            if 'ports' in nmap_data:
                for port in nmap_data['ports']:
                    if port.get('state') == 'open':
                        port_num = port.get('port', 0)
                        service = port.get('service', '').lower()
                        if port_num in [3306, 5432, 1433, 1521, 27017] or any(
                            db in service for db in ['mysql', 'postgres', 'mssql', 'oracle', 'mongodb']
                        ):
                            has_db_services = True
                            db_ports.append(f"{port_num}/{service}")

        if has_db_services:
            findings.append(f"🗄️ DATABASE SERVICES DETECTED: {', '.join(db_ports)} - Direct database testing may be possible")
        else:
            findings.append("❌ NO DATABASE SERVICES: No database ports detected - direct database testing not applicable")

        cve_count = 0
        critical_cves = []
        if 'details' in scan_results and 'cves' in scan_results['details']:
            cve_data = scan_results['details']['cves']
            if 'cves' in cve_data and cve_data['cves']:
                cve_count = len(cve_data['cves'])
                for cve in cve_data['cves']:
                    severity = cve.get('severity', '').upper()
                    if severity == 'CRITICAL':
                        cve_id = cve.get('id', cve.get('cve', 'Unknown'))
                        critical_cves.append(cve_id)

        if cve_count > 0:
            findings.append(f"🔍 CVEs FOUND: {cve_count} total vulnerabilities detected")
            if critical_cves:
                findings.append(f"🚨 CRITICAL CVEs: {', '.join(critical_cves[:3])}")
        else:
            findings.append("✅ NO CVEs: No vulnerabilities detected in software scanning")

        has_ssl = False
        if 'details' in scan_results and 'ssl' in scan_results['details']:
            has_ssl = True
            findings.append("🔒 SSL/TLS DETECTED: Certificate analysis available")

        risk_level = scan_results.get('level', 'unknown')
        status = scan_results.get('status', 'unknown')
        findings.append(f"📊 RISK ASSESSMENT: {risk_level.upper()} risk, Status: {status}")

        applicable_tests = []
        if has_web_services:
            applicable_tests.extend(["Web application testing (XSS, CSRF, etc.)", "HTTP header analysis", "Directory enumeration"])
        if has_db_services:
            applicable_tests.append("Direct database testing")
        if has_web_services and not has_db_services:
            applicable_tests.append("SQL injection testing (if web app uses database)")
        if has_ssl:
            applicable_tests.append("SSL/TLS testing")
        if cve_count > 0:
            applicable_tests.append("CVE-specific exploitation testing")

        if applicable_tests:
            findings.append(f"🧪 APPLICABLE TESTING: {', '.join(applicable_tests)}")
        else:
            findings.append("🧪 LIMITED TESTING: Only basic network reconnaissance applicable")

        return '\n'.join(findings)
