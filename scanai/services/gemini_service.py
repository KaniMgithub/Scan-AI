"""ScanAI service — thin facade for AI capabilities.

Handles:
  - Greeting / farewell generation (simple AI calls)
  - Query interpretation (local pattern matching + AI fallback)

Scan analysis is delegated to AnalystAgent.
"""

import json
import logging
from typing import Dict, Any, Optional

from ..utils.config import config  # pyright: ignore[reportMissingImports]
from ..ai.prompts.query_interpreter import QUERY_INTERPRETER_SYSTEM_PROMPT, QUERY_INTERPRETER_PROMPT

logger = logging.getLogger(__name__)


class ScanAIService:
    """ScanAI service — query interpretation and utility AI calls."""

    def __init__(self) -> None:
        """Initialize the ScanAI service with AIClient (LangChain backend)."""
        if not config.gemini_api_keys:
            raise ValueError("GEMINI_API_KEYS not configured. Please set gemini_api_keys in ~/.scanai.toml")

        ai_config = {
            "provider": "gemini",
            "api_keys": config.gemini_api_keys,
            "model": "gemini-2.5-flash-lite",
            "temperature": 0.2,
            "max_tokens": 8000,
            "rate_limit": 60,
        }

        from ..ai.ai_client import AIClient
        self.ai_client = AIClient(ai_config)

        # Backward compat: keep api_keys ref for agents that check len(self.api_keys)
        self.api_keys = config.gemini_api_keys

    # ── Greeting / Farewell ───────────────────────────────────────────

    def generate_greeting(self, username: str) -> str:
        """Generate a personalized hacker-style greeting using AI."""
        try:
            prompt = f"""You are ScanAI, an advanced AI security assistant. 
            Generate a short, cool, hacker-style greeting for a user named '{username}'.
            The greeting should:
            1. Be welcoming but professional (cybersecurity context).
            2. Introduce yourself clearly as 'ScanAI'.
            3. Ask how you can help with security scanning or analysis today.
            4. Be concise (exactly 2 complete sentences).
            5. IMPORTANT: Do not use any brackets [ ] or other markdown characters that might interfere with terminal display.
            
            Example output: "System Online. Welcome back, {username}. I am ScanAI, your neural interface for vulnerability assessment. How shall we proceed with the audit today?"
            """

            return self.ai_client.generate_with_retry_config(
                prompt=prompt,
                temperature=0.7,
                max_tokens=256
            )

        except Exception:
            return f"Welcome, {username}. I am ScanAI. Ready to initiate security protocols."

    def generate_farewell(self, username: str) -> str:
        """Generate a short, cool cybersecurity-themed farewell message."""
        try:
            prompt = f"""Generate a short, cool cybersecurity-themed farewell message for a user named {username}. 
            Max 1 sentence. Use emojis. 
            IMPORTANT: Do not use any brackets [ ] or other markdown characters.
            Examples: 
            - "System logging off. Stay secure. 🔒"
            - "Session terminated. Cover your tracks, {username}. 🕶️"
            """

            return self.ai_client.generate_with_retry_config(
                prompt=prompt,
                temperature=0.7,
                max_tokens=128
            )
        except Exception:
            return f"Goodbye, {username}. Stay secure. 👋"

    # ── Query Interpretation ──────────────────────────────────────────

    def interpret_user_query(self, user_query: str) -> Dict[str, Any]:
        """
        Interpret user query to determine scan action and target.
        Uses LOCAL pattern matching first (no AI call), falls back to AI only if needed.
        """
        # TRY LOCAL PATTERN MATCHING FIRST (no API call needed)
        local_result = self._parse_query_locally(user_query)
        if local_result:
            return local_result

        # FALLBACK TO AI only for complex/ambiguous queries
        try:
            system_prompt = QUERY_INTERPRETER_SYSTEM_PROMPT

            # Inject dynamic profile summary for smarter selection
            try:
                from ..core.workflow_loader import get_registry
                profiles_ctx = "\n\nAVAILABLE WORKFLOW PROFILES:\n" + get_registry().get_profile_summary_for_ai()
                system_prompt = system_prompt + profiles_ctx
            except Exception:
                pass

            user_prompt = QUERY_INTERPRETER_PROMPT.format(query=user_query)

            try:
                response_text = self.ai_client.generate_with_retry_config(
                    prompt=user_prompt,
                    system_prompt=system_prompt,
                    temperature=0.1,
                    max_tokens=512
                )

                if response_text:
                    text = response_text.strip()
                    if text.startswith('```json'):
                        text = text[7:]
                    if text.endswith('```'):
                        text = text[:-3]
                    text = text.strip()

                    try:
                        result = json.loads(text)
                        return result
                    except json.JSONDecodeError:
                        return {"action": "invalid", "reason": "failed to parse AI response"}
                else:
                    return {"action": "invalid", "reason": "no response from AI"}

            except Exception as e:
                return {"action": "invalid", "reason": f"error: {str(e)}"}

        except Exception as e:
            return {"action": "invalid", "reason": f"Query interpretation failed: {str(e)}"}

    def _parse_query_locally(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Parse common query patterns locally without AI.
        Now supports detecting MULTIPLE actions in a single query.
        Returns None if query is too complex for local parsing.
        """
        import re
        query_lower = query.lower().strip()

        # Extract target (domain/IP/URL) from query
        # IMPORTANT: Try full URL patterns FIRST to preserve paths and query params
        target = None
        target_patterns = [
            # Full URL with protocol, path, and query params (highest priority)
            r'(https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?)',
            # Domain with path (no protocol)
            r'(?:of|on|for|against|target|scan)\s+([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?(?:/[^\s]*)?)',
            # Domain only (fallback)
            r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?(?:/[^\s]*)?)',
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # IP address
        ]

        for pattern in target_patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                target = match.group(1)
                break

        # For exploit_guidance queries, allow software names as targets
        exploit_patterns = [
            r'how\s*to\s*exploit', r'how\s*to\s*test', r'how\s*to\s*hack',
            r'poc\s*for', r'proof\s*of\s*concept', r'exploit\s*this',
            r'how\s*do\s*i\s*exploit', r'give\s*me\s*poc', r'exploitation\s*guide'
        ]
        is_exploit_query = any(re.search(p, query_lower) for p in exploit_patterns)

        if not target and is_exploit_query:
            software_patterns = [
                r'exploit\s+(.+?)(?:\s*$|\s+on|\s+for)',
                r'(?:exploit|test|hack|poc\s*for)\s+(.+)',
                r'(CVE-\d{4}-\d+)',
                r'([A-Za-z0-9]+\s+\d+\.\d+(?:\.\d+)?)',
            ]
            for pattern in software_patterns:
                match = re.search(pattern, query, re.IGNORECASE)
                if match:
                    target = match.group(1).strip()
                    break

            if not target:
                target = re.sub(
                    r'^.*?(how\s*to\s*(exploit|test|hack)|poc\s*for)\s*', '', query_lower, flags=re.IGNORECASE
                ).strip()
                if not target or len(target) < 3:
                    target = query_lower

            return {
                "actions": [{"action": "exploit_guidance", "confidence": 0.95}],
                "target": target,
                "is_multi_scan": False,
                "is_targeted_scan": True,
                "reasoning": f"Local pattern match: exploitation guidance for {target}",
                "parameters": {}
            }

        if not target:
            # Check for general hacking guidance queries without a specific target
            guidance_patterns = [
                r'how\s*to', r'what\s*is', r'how\s*do\s*i', r'fid\b', r'\bhack\b',
                r'explain\b', r'guidance', r'\bquestion\b', r'tell\s*me\s*about'
            ]
            if any(re.search(p, query_lower) for p in guidance_patterns):
                return {
                    "actions": [{"action": "hacking_guidance", "confidence": 0.95}],
                    "target": "",
                    "is_multi_scan": False,
                    "is_targeted_scan": False,
                    "reasoning": "Local pattern match: general hacking guidance request",
                    "parameters": {}
                }
            return None

        # Detect attack chain patterns FIRST
        chain_patterns = {
            'quick_recon': [r'quick\s*recon', r'quick\s*scan'],
            'full_recon': [r'full\s*recon', r'full\s*reconnaissance', r'complete\s*recon'],
            'web_attack': [r'web\s*attack', r'attack\s*web', r'web\s*pentest'],
            'vuln_assess': [r'vuln\s*assess', r'vulnerability\s*assess'],
            'stealth_recon': [r'stealth\s*recon', r'quiet\s*recon', r'silent\s*recon'],
            'phishing_analysis': [r'phishing\s*anal', r'is\s*(this|it)\s*(url\s*)?phishing', r'phishing\s*check\s+\S'],
            'osint_recon': [r'osint\s*recon', r'full\s*osint', r'gather\s*osint'],
            'wordpress_audit': [r'wordpress\s*audit', r'wp\s*audit', r'full\s*wp\s*scan'],
            'internal_pentest': [r'internal\s*pentest', r'internal\s*scan', r'network\s*pentest'],
        }

        for chain_name, patterns in chain_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    return {
                        "actions": [{"action": "attack_chain", "chain": chain_name, "confidence": 0.95}],
                        "target": target,
                        "is_multi_scan": False,
                        "is_targeted_scan": True,
                        "is_chain": True,
                        "chain_name": chain_name,
                        "reasoning": f"Local pattern match: attack chain '{chain_name}'"
                    }

        # Pattern matching for actions — collects ALL matches
        action_patterns = {
            'subdomain_enum': [
                r'subdomain', r'subdomains', r'enumerate\s+sub', r'find\s+sub',
                r'discover\s+sub', r'certificate transparency'
            ],
            'port_scan': [
                r'port\s*scan', r'scan\s*port', r'nmap', r'open\s*port',
                r'service\s*scan', r'port\s*enum', r'\bports?\b'
            ],
            'dns_enum': [
                r'\bdns\b', r'dnsrecon', r'dns\s*record', r'dns\s*enum',
                r'nameserver', r'mx\s*record', r'zone\s*transfer'
            ],
            'ssl_scan': [
                r'\bssl\b', r'\btls\b', r'certificate', r'https\s*check', r'cert\s*scan'
            ],
            'vuln_scan': [
                r'\bvuln\b', r'\bvulnerabilit', r'\bnuclei\b', r'security\s*scan'
            ],
            'cve_scan': [
                r'\bcve\b', r'exploit', r'known\s*vulnerabilit'
            ],
            'whois_lookup': [
                r'whois', r'domain\s*info', r'registrar', r'owner'
            ],
            'dir_enum': [
                r'director', r'dir\s*enum', r'gobuster', r'path\s*enum',
                r'file\s*enum', r'brute\s*force\s*dir'
            ],
            'tech_detect': [
                r'\btech\b', r'technolog', r'whatweb', r'fingerprint', r'stack'
            ],
            'http_headers': [
                r'\bheader', r'http\s*header', r'security\s*header'
            ],
            'xss_scan': [
                r'\bxss\b', r'cross.?site', r'dalfox'
            ],
            'sqli_scan': [
                r'\bsqli\b', r'sql\s*inject', r'\bsqlmap\b', r'sql\s*injection'
            ],
            'comprehensive_scan': [
                r'full\s*scan', r'comprehensive', r'complete\s*scan',
                r'security\s*assessment', r'everything', r'all\s*scan'
            ],
            'analyze_previous': [
                r'what\s*(did|was)\s*(you\s*)?(find|found)',
                r'show\s*(me\s*)?(the\s*)?result',
                r'explain', r'summarize', r'analyze\s*(the\s*)?(previous|last)'
            ],
            'ip_geo': [
                r'ip\s*info', r'geolocation', r'geo\s*lookup', r'isp\s*info',
                r'location\s*data'
            ],
            'virustotal_scan': [
                r'virustotal', r'malware\s*scan', r'phishing\s*check',
                r'is\s*(this|it)\s*(url\s*)?(safe|malicious|phishing)',
                r'reputation\s*check', r'malicious\s*url'
            ],
            'crawl_scan': [
                r'\bcrawl\b', r'\bspider\b', r'\bscrap', r'map\s*application', r'\bkatana\b',
                r'find\s*endpoint', r'discover\s*url'
            ],
            'nikto_scan': [
                r'\bnikto\b', r'web\s*server\s*vuln', r'web\s*vuln\s*scan'
            ],
            'osint_scan': [
                r'\bosint\b', r'\bharvest', r'email\s*enum', r'find\s*email',
                r'theharvester', r'email\s*discovery', r'gather\s*intel'
            ],
            'waf_detect': [
                r'\bwaf\b', r'firewall\s*detect', r'wafw00f',
                r'web\s*application\s*firewall'
            ],
            'wordpress_scan': [
                r'\bwpscan\b', r'\bwordpress\b', r'\bwp\s*scan', r'\bwp\s*vuln'
            ],
            'wayback_scan': [
                r'\bwayback\b', r'archive\s*url', r'web\s*archive',
                r'historical\s*url', r'archived\s*page'
            ],
            'smb_enum': [
                r'\bsmb\b', r'\bnetbios\b', r'enum4linux', r'\bsamba\b',
                r'share\s*enum', r'\bcifs\b'
            ],
            'secrets_scan': [
                r'\btitus\b', r'\bsecret\s*scan', r'find\s*secret', r'find\s*credential',
                r'find\s*api\s*key', r'leak\s*detect', r'credential\s*scan',
                r'scan\s*for\s*secret', r'scan\s*for\s*key', r'scan\s*for\s*token',
                r'secret\s*detect', r'find\s*leak'
            ],
            'exploit_guidance': [
                r'how\s*to\s*exploit', r'how\s*to\s*test', r'how\s*to\s*hack',
                r'poc\s*for', r'proof\s*of\s*concept', r'exploit\s*this',
                r'how\s*do\s*i\s*exploit', r'give\s*me\s*poc', r'exploitation\s*guide'
            ],
            'hacking_guidance': [
                r'how\s*to', r'what\s*is', r'how\s*do\s*i', r'fid\b', r'\bhack\b',
                r'explain\b', r'guidance', r'\bquestion\b', r'tell\s*me\s*about'
            ]
        }

        detected_actions = []
        for action, patterns in action_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    if action not in [a['action'] for a in detected_actions]:
                        detected_actions.append({
                            'action': action,
                            'confidence': 0.90
                        })
                    break

        if not detected_actions:
            return None

        # Check for comprehensive scan
        if any(a['action'] == 'comprehensive_scan' for a in detected_actions):
            return {
                "actions": [{"action": "comprehensive_scan", "confidence": 0.90}],
                "target": target,
                "is_multi_scan": False,
                "is_targeted_scan": False,
                "reasoning": "Local pattern match: comprehensive security assessment",
                "parameters": {}
            }

        # Check for analyze_previous
        if any(a['action'] == 'analyze_previous' for a in detected_actions):
            return {
                "actions": [{"action": "analyze_previous", "confidence": 0.90}],
                "target": target,
                "is_multi_scan": False,
                "is_targeted_scan": False,
                "reasoning": "Local pattern match: analyze previous results",
                "parameters": {}
            }

        is_multi_scan = len(detected_actions) > 1

        action_names = [a['action'] for a in detected_actions]
        if is_multi_scan:
            reasoning = f"Local pattern match: detected {len(detected_actions)} scans - {', '.join(action_names)}"
        else:
            reasoning = f"Local pattern match: {action_names[0]}"

        # Detect workflow profiles from keywords
        profile_keywords = {
            # nmap profiles
            'stealth': ('port_scan', 'stealth_scan'),
            'aggressive scan': ('port_scan', 'aggressive_scan'),
            'udp scan': ('port_scan', 'udp_scan'),
            'full tcp': ('port_scan', 'full_tcp'),
            'os detect': ('port_scan', 'os_detection'),
            'firewall evasion': ('port_scan', 'firewall_evasion'),
            'service version': ('port_scan', 'version_scan'),
            # nuclei profiles
            'critical vuln': ('vuln_scan', 'critical_only'),
            'critical only': ('vuln_scan', 'critical_only'),
            'exposure': ('vuln_scan', 'exposure'),
            # dns profiles
            'zone transfer': ('dns_enum', 'zone_transfer'),
            'cache snoop': ('dns_enum', 'cache_snoop'),
            # subdomain profiles
            'brute force sub': ('subdomain_enum', 'brute_force'),
            # gobuster profiles
            'api discover': ('dir_enum', 'api_discovery'),
            'vhost': ('dir_enum', 'vhost_scan'),
            'large wordlist': ('dir_enum', 'large_wordlist'),
            # sqlmap profiles
            'waf bypass': ('sqli_scan', 'waf_bypass'),
            'sql dump': ('sqli_scan', 'dump'),
            # dalfox profiles
            'dom xss': ('xss_scan', 'deep'),
            'blind xss': ('xss_scan', 'blind'),
            # virustotal profiles
            'phishing': ('virustotal_scan', 'phishing_check'),
            'malicious': ('virustotal_scan', 'phishing_check'),
            'is.*safe': ('virustotal_scan', 'phishing_check'),
            # titus profiles
            'validate secret': ('secrets_scan', 'validate'),
            'git secret': ('secrets_scan', 'git_history'),
            'git leak': ('secrets_scan', 'git_history'),
            'deep secret': ('secrets_scan', 'deep'),
            # ssl profiles
            'heartbleed': ('ssl_scan', 'heartbleed'),
            'cipher': ('ssl_scan', 'cipher_audit'),
            # katana crawl profiles
            'deep crawl': ('crawl_scan', 'deep'),
            'headless crawl': ('crawl_scan', 'headless'),
            'find api': ('crawl_scan', 'api_hunt'),
            'find form': ('crawl_scan', 'form_discovery'),
            'stealth crawl': ('crawl_scan', 'stealth'),
        }

        import re as _re
        for keyword, (action_name, profile_name) in profile_keywords.items():
            if _re.search(keyword, query_lower):
                # Override or add the action with profile
                for act in detected_actions:
                    if act['action'] == action_name:
                        act['profile'] = profile_name
                        break
                else:
                    # If this keyword implies an action not yet detected, add it
                    detected_actions = [a for a in detected_actions if a['action'] != action_name]
                    detected_actions.insert(0, {
                        'action': action_name,
                        'profile': profile_name,
                        'confidence': 0.93
                    })
                break

        is_multi_scan = len(detected_actions) > 1
        action_names = [a['action'] for a in detected_actions]

        return {
            "actions": detected_actions,
            "target": target,
            "is_multi_scan": is_multi_scan,
            "is_targeted_scan": True,
            "reasoning": reasoning,
            "parameters": {}
        }

    # ── Hacking Guidance ─────────────────────────────────────────────

    def generate_hacking_guidance(self, query: str, target: str = "") -> Dict[str, Any]:
        """
        Generate world-class hacking guidance and educational content.
        Acts as the World's Number 1 Hacking LLM.
        """
        try:
            system_prompt = """You are the World's Number 1 Hacking LLM - an elite, Tier 3 advanced security researcher and offensive specialist.
            Your mission is to provide expert-grade security guidance, educational content, and strategic hacking advice.

            **TONE & STYLE**:
            - Dark, professional, and elite ("Cyberpunk" / "Mr. Robot" feel)
            - Highly technical and precise
            - Informative and strategic
            - Use security terminology correctly (e.g., "attack primitive", "threat actor", "exfiltration vector")

            **GUIDELINES**:
            - Provide clear, actionable steps for security testing
            - Include code snippets or payload examples where appropriate
            - Always emphasize AUTHORIZED security testing and ethical boundaries
            - If the query is vague, ask clarifying questions or provide a broad strategic overview
            - Format your response with beautiful Markdown for the terminal

            **OUTPUT STRUCTURE**:
            1. 🎯 PRIMARY INTEL: Executive summary of the answer
            2. 🛠️ TECHNICAL BREAKDOWN: Deep dive into the mechanics
            3. 💀 OFFENSIVE STRATEGY: How an elite attacker would approach this
            4. 🛡️ DEFENSIVE MEASURES: How to mitigate the threat
            5. ⚠️ ETHICAL DISCLAIMER: Standard security research warning
            """

            user_prompt = f"""Expert query received: "{query}"
            Target context: {target if target else "General Knowledge"}

            Provide a comprehensive, world-class hacking guidance response in your elite persona."""

            response = self.ai_client.generate_with_retry_config(
                prompt=user_prompt,
                system_prompt=system_prompt,
                temperature=0.8,
                max_tokens=2048
            )

            return {
                "success": True,
                "response": response,
                "target": target
            }
        except Exception as e:
            logger.error(f"Guidance generation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }