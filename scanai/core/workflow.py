"""Autonomous workflow engine for ScanAI — profile-aware with auto-chaining."""

import asyncio
import logging
import time
from typing import Dict, Any, List, Optional, Callable
from .state import ScanState
from .workflow_loader import get_registry
from ..ai.agents.planner_agent import PlannerAgent
from ..ai.agents.tool_agent import ToolAgent
from ..ai.agents.analyst_agent import AnalystAgent


class WorkflowEngine:
    """Orchestrates the autonomous agentic loop for security scans."""

    def __init__(
        self,
        ai_service: Any,
        scan_manager: Any,
        progress_callback: Optional[Callable] = None
    ):
        self.planner = PlannerAgent(ai_service)
        self.tool_agent = ToolAgent(ai_service)
        self.analyst = AnalystAgent(ai_service)
        self.scan_manager = scan_manager
        self.progress_callback = progress_callback
        self.logger = logging.getLogger(self.__class__.__name__)

        # Action → scanner mapping
        self.action_to_scanner = {
            'subdomain_enum': 'subdomain',
            'port_scan': 'nmap',
            'vuln_scan': 'nuclei',
            'cve_scan': 'cves',
            'web_scan': 'web_scan',
            'ssl_scan': 'ssl',
            'dns_enum': 'dns',
            'whois_lookup': 'whois',
            'tech_detect': 'whatweb',
            'dir_enum': 'gobuster',
            'file_enum': 'gobuster',
            'xss_scan': 'dalfox',
            'sqli_scan': 'sqlmap',
            'http_headers': 'server_headers',
            'ip_geo': 'ip_geo',
            'crawl_scan': 'katana',
            'virustotal_scan': 'virustotal',
            'nikto_scan': 'nikto',
            'osint_scan': 'harvester',
            'waf_detect': 'waf',
            'wordpress_scan': 'wpscan',
            'wayback_scan': 'wayback',
            'smb_enum': 'enum4linux',
            'secrets_scan': 'titus',
        }

    # ── Auto-Chain Rules ──────────────────────────────────────────

    def _get_auto_chains(self, scanner_name: str, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Determine auto-chain follow-up scans based on results.

        Returns list of {"scanner": name, "profile": profile_or_None, "reason": str}
        """
        chains = []

        if scanner_name == 'nmap':
            # After nmap: auto-chain CVE lookup on detected services
            ports = results.get('ports', [])
            open_ports = [p for p in ports if isinstance(p, dict) and p.get('state') == 'open']
            if open_ports:
                chains.append({
                    'scanner': 'cves',
                    'profile': 'standard',
                    'reason': f'CVE lookup for {len(open_ports)} open services detected by nmap'
                })
                # If web ports found, chain whatweb
                web_ports = [p for p in open_ports if p.get('port') in [80, 443, 8080, 8443]]
                if web_ports:
                    chains.append({
                        'scanner': 'server_headers',
                        'profile': 'security_audit',
                        'reason': 'Web ports detected — running security header audit'
                    })

        elif scanner_name == 'subdomain':
            # After subdomain: report count, could chain nmap on top subdomains
            subs = results.get('subdomains', [])
            if len(subs) > 0:
                chains.append({
                    'scanner': 'nmap',
                    'profile': 'port_scan',
                    'reason': f'{len(subs)} subdomains found — quick port scan recommended'
                })

        elif scanner_name in ('nuclei', 'dalfox'):
            # After vuln scan: chain exploitation guidance
            findings = results.get('findings', results.get('vulnerabilities', []))
            if findings:
                chains.append({
                    'scanner': '_exploitation_guidance',
                    'profile': None,
                    'reason': f'{len(findings)} vulnerabilities found — exploitation guidance available'
                })

        elif scanner_name == 'katana':
            # After katana crawl: chain XSS/SQLi on discovered forms/endpoints
            forms = results.get('all_forms', [])
            apis = results.get('all_apis', [])
            if forms:
                chains.append({
                    'scanner': 'dalfox',
                    'profile': 'standard',
                    'reason': f'{len(forms)} forms discovered — XSS scan recommended'
                })
            if apis:
                chains.append({
                    'scanner': 'gobuster',
                    'profile': 'api_discovery',
                    'reason': f'{len(apis)} API endpoints found — deeper enumeration recommended'
                })

        return chains

    # ── Targeted Scan ─────────────────────────────────────────────

    async def run_targeted_scan(self, action: str, target: str, query: str, profile: Optional[str] = None, auto_chain: bool = True) -> Dict[str, Any]:
        """Run a targeted single-scanner scan with optional auto-chaining."""
        start_time = time.time()

        scanner_name = self.action_to_scanner.get(action)
        if not scanner_name:
            self.logger.warning(f"Unknown action '{action}', falling back to full scan")
            return await self.run_autonomous(query, target)

        self._notify_progress(f"🎯 Running targeted scan: {scanner_name}" + (f"/{profile}" if profile else ""), 1, 3)

        results_container = self._init_results(target)

        # CVE scanner needs dependencies
        scanners_to_run = [scanner_name]
        if scanner_name == 'cves':
            scanners_to_run = ['nmap', 'server_headers', 'cves']
            self._notify_progress("🔍 Running prerequisites (nmap + headers) for CVE detection...", 1, 3)

        # Execute
        try:
            normalized_target = self.scan_manager._normalize_target(target)
            scan_params = {}
            if profile:
                scan_params[scanner_name] = {'profile': profile}
            if action == 'dir_enum':
                scan_params.setdefault('gobuster', {})['scan_mode'] = 'dir'
            elif action == 'file_enum':
                scan_params.setdefault('gobuster', {})['scan_mode'] = 'file'

            scan_results = self.scan_manager.perform_full_scan(
                target=normalized_target,
                scanners_to_run=scanners_to_run,
                scan_params=scan_params
            )

            results_container['details'] = scan_results.get('details', {})
            results_container['ip'] = scan_results.get('ip', 'Unknown')

        except Exception as e:
            self.logger.error(f"Scanner {scanner_name} error: {e}")
            results_container['errors'].append(str(e))

        # Auto-chain: analyze results and suggest/run follow-ups
        chain_info = []
        if auto_chain and scanner_name in results_container['details']:
            chains = self._get_auto_chains(scanner_name, results_container['details'][scanner_name])
            for chain in chains:
                chain_info.append(chain['reason'])
            results_container['auto_chain_suggestions'] = chains

        self._notify_progress("📊 Calculating risk metrics...", 2, 2)

        self.scan_manager._generate_summaries(results_container)
        self.scan_manager._calculate_risk_score(results_container)

        results_container['duration'] = time.time() - start_time
        results_container['status'] = 'complete'

        return {
            "results": results_container,
            "state": {
                "query": query,
                "target": target,
                "scanner_used": scanner_name,
                "profile_used": profile,
                "is_targeted_scan": True,
                "auto_chains": chain_info,
            }
        }

    # ── Multi-Targeted Scan ───────────────────────────────────────

    async def run_multi_targeted_scan(self, actions: list, target: str, query: str) -> Dict[str, Any]:
        """Run multiple targeted scans sequentially."""
        start_time = time.time()
        results_container = self._init_results(target)
        results_container['scanners_executed'] = []

        total = len(actions)
        normalized_target = self.scan_manager._normalize_target(target)

        self._notify_progress(f"🎯 Running {total} targeted scans", 0, total + 1)

        for idx, action in enumerate(actions, 1):
            scanner_name = self.action_to_scanner.get(action)
            if not scanner_name:
                results_container['errors'].append(f"Unknown action: {action}")
                continue

            self._notify_progress(f"🔍 [{idx}/{total}] Running: {scanner_name}", idx, total + 1)

            try:
                scan_results = self.scan_manager.perform_full_scan(
                    target=normalized_target,
                    scanners_to_run=[scanner_name]
                )
                results_container['details'][scanner_name] = scan_results.get('details', {}).get(scanner_name, {})
                results_container['scanners_executed'].append(scanner_name)

                if results_container['ip'] == 'Initializing...' and scan_results.get('ip'):
                    results_container['ip'] = scan_results['ip']

            except Exception as e:
                results_container['errors'].append(f"{scanner_name}: {str(e)}")

        self._notify_progress("📊 Calculating risk metrics...", total + 1, total + 1)

        self.scan_manager._generate_summaries(results_container)
        self.scan_manager._calculate_risk_score(results_container)
        results_container['duration'] = time.time() - start_time
        results_container['status'] = 'complete'

        return {
            "results": results_container,
            "state": {
                "query": query,
                "target": target,
                "scanners_used": results_container['scanners_executed'],
                "is_multi_scan": True
            }
        }

    # ── Autonomous Agentic Loop ───────────────────────────────────

    async def run_autonomous(self, query: str, target: str) -> Dict[str, Any]:
        """Run the autonomous AI-driven scan loop with profile selection."""
        state = ScanState(query, target)
        max_iterations = 10
        iteration = 0
        results_container = self._init_results(target)

        while not state.is_complete and iteration < max_iterations:
            iteration += 1

            # 1. PLAN — AI selects next phase + scanner + profile
            plan = self.planner.plan(
                query=state.query,
                target=state.target,
                completed_actions=state.completed_actions,
                findings_summary=state.get_findings_summary()
            )

            if plan.get("is_complete") or plan.get("next_subtask") in ["report", "REPORTING", None]:
                state.is_complete = True
                break

            subtask = plan.get("next_subtask", "")
            scan_target = plan.get("target") or state.target
            plan_profile = plan.get("profile")

            # Extract reasoning
            reasoning = plan.get("reasoning", "")
            if isinstance(reasoning, dict):
                reasoning = reasoning.get("scanner_selection", str(reasoning))

            state.current_subtask = subtask
            objective = plan.get("objective", subtask)
            phase = plan.get("phase", "?")
            risk = plan.get("risk_level", "LOW")

            self._notify_progress(
                f"🧠 [{phase}] {objective} [dim]| RISK: {risk}[/dim]",
                iteration, max_iterations
            )

            # 2. SELECT TOOL — AI picks scanner + profile
            tool_selection = self.tool_agent.select_tool(
                subtask=subtask,
                target=scan_target,
                planner_reasoning=str(reasoning)
            )

            scanner_name = tool_selection.get("scanner")
            tool_profile = tool_selection.get("profile") or plan_profile
            params = tool_selection.get("parameters", {})

            if not scanner_name:
                state.completed_actions.append(f"{subtask}_failed")
                continue

            # Inject profile into params
            if tool_profile:
                params['profile'] = tool_profile

            self._notify_progress(
                f"🚀 Running: {scanner_name}" + (f"/{tool_profile}" if tool_profile else ""),
                iteration, max_iterations
            )

            # 3. EXECUTE
            try:
                scanner_details = await self._execute_scanner(
                    scanner_name, scan_target, params, state.findings
                )
                state.add_finding(scanner_name, scanner_details)
                results_container['details'][scanner_name] = scanner_details

                # 4. AUTO-CHAIN — check if results trigger follow-up scans
                if scanner_details and isinstance(scanner_details, dict):
                    chains = self._get_auto_chains(scanner_name, scanner_details)
                    for chain in chains:
                        if chain['scanner'] != '_exploitation_guidance':
                            # Only auto-chain if not already completed
                            if chain['scanner'] not in state.completed_actions:
                                self._notify_progress(
                                    f"⛓️ Auto-chain: {chain['reason']}",
                                    iteration, max_iterations
                                )

            except Exception as e:
                self.logger.error(f"Scanner {scanner_name} error: {e}")
                state.add_finding(scanner_name, {"error": str(e)})

        # Final
        self._notify_progress("📊 Calculating risk metrics...", iteration, max_iterations)
        self.scan_manager._generate_summaries(results_container)
        self.scan_manager._calculate_risk_score(results_container)
        results_container['duration'] = time.time() - getattr(state, '_start_time', time.time())
        results_container['status'] = 'complete'

        return {
            "results": results_container,
            "state": state.to_dict()
        }

    # ── Attack Chain Execution ────────────────────────────────────

    async def run_attack_chain(self, chain_name: str, target: str, query: str) -> Dict[str, Any]:
        """Execute a pre-built attack chain."""
        from .workflow_loader import get_chain_registry

        chain_reg = get_chain_registry()
        chain = chain_reg.get_chain(chain_name)
        if not chain:
            self.logger.error(f"Attack chain '{chain_name}' not found")
            return await self.run_autonomous(query, target)

        start_time = time.time()
        results_container = self._init_results(target)
        results_container['chain_name'] = chain_name
        results_container['scanners_executed'] = []

        total_steps = len(chain.steps)
        self._notify_progress(f"⛓️ Attack chain: {chain.description}", 0, total_steps + 1)

        normalized_target = self.scan_manager._normalize_target(target)

        for idx, step in enumerate(chain.steps, 1):
            scanner_name = step['scanner']
            profile_name = step.get('profile')

            self._notify_progress(
                f"⛓️ [{idx}/{total_steps}] {scanner_name}" + (f"/{profile_name}" if profile_name else ""),
                idx, total_steps + 1
            )

            try:
                scan_params = {}
                if profile_name:
                    scan_params[scanner_name] = {'profile': profile_name}

                scan_results = self.scan_manager.perform_full_scan(
                    target=normalized_target,
                    scanners_to_run=[scanner_name],
                    existing_details=results_container['details'],
                    scan_params=scan_params
                )

                scanner_data = scan_results.get('details', {}).get(scanner_name, {})
                results_container['details'][scanner_name] = scanner_data
                results_container['scanners_executed'].append(f"{scanner_name}/{profile_name or 'default'}")

                if results_container['ip'] == 'Initializing...' and scan_results.get('ip'):
                    results_container['ip'] = scan_results['ip']

            except Exception as e:
                self.logger.error(f"Chain step {scanner_name} failed: {e}")
                results_container['errors'].append(f"{scanner_name}: {str(e)}")

        self._notify_progress("📊 Calculating risk metrics...", total_steps + 1, total_steps + 1)

        self.scan_manager._generate_summaries(results_container)
        self.scan_manager._calculate_risk_score(results_container)
        results_container['duration'] = time.time() - start_time
        results_container['status'] = 'complete'

        return {
            "results": results_container,
            "state": {
                "query": query,
                "target": target,
                "chain": chain_name,
                "scanners_used": results_container['scanners_executed'],
                "is_chain": True
            }
        }

    # ── Helpers ────────────────────────────────────────────────────

    def _init_results(self, target: str) -> Dict[str, Any]:
        """Initialize a results container."""
        return {
            'target': target,
            'domain': self.scan_manager._extract_domain(target),
            'ip': 'Initializing...',
            'timestamp': time.time(),
            'duration': 0,
            'status': 'scanning',
            'level': 'none',
            'summaries': {},
            'details': {},
            'errors': []
        }

    async def _execute_scanner(self, scanner_name: str, target: str, params: Dict[str, Any], existing_findings: Dict[str, Any]) -> Any:
        """Execute a specific scanner with profile support."""
        normalized_target = self.scan_manager._normalize_target(target)

        # Build scan_params with profile
        scan_params = {}
        if params:
            scan_params[scanner_name] = params

        results = self.scan_manager.perform_full_scan(
            target=normalized_target,
            scanners_to_run=[scanner_name],
            existing_details=existing_findings,
            scan_params=scan_params
        )
        return results.get('details', {}).get(scanner_name, {})

    def _notify_progress(self, message: str, completed: int, total: int):
        if self.progress_callback:
            self.progress_callback(message, completed, total)
