"""Command-line interface for ScanAI with comprehensive argument parsing."""

import asyncio
import sys
import json
import time
import argparse
import warnings
from typing import Dict, Any, Optional, List, Tuple, Union
from pathlib import Path

from rich.console import Console, Group  # pyright: ignore[reportMissingImports]
from rich.table import Table  # pyright: ignore[reportMissingImports]
from .display.theme import C, ThemePanel
from rich.panel import Panel
from rich.text import Text  # pyright: ignore[reportMissingImports]
from rich.align import Align # pyright: ignore[reportMissingImports]
from rich.tree import Tree # pyright: ignore[reportMissingImports]
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn  # pyright: ignore[reportMissingImports]
from rich.prompt import Prompt # pyright: ignore[reportMissingImports]
from rich.markdown import Markdown # pyright: ignore[reportMissingImports]
from rich.layout import Layout # pyright: ignore[reportMissingImports]
from rich.live import Live # pyright: ignore[reportMissingImports]
from rich.columns import Columns # pyright: ignore[reportMissingImports]
from rich import box # pyright: ignore[reportMissingImports]
# pyfiglet removed — clean ScanAI-style boot

from .scan_manager import ScanManager
from .result_storage import result_storage
from .async_scanner_manager import async_scanner_manager
from .workflow import WorkflowEngine
from ..services.gemini_service import ScanAIService
from ..utils.config import config

# Suppress Google Gemini deprecation warnings globally
warnings.filterwarnings("ignore", message=".*google.generativeai.*deprecated.*", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*google.genai.*", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*All support for the.*", category=FutureWarning)


def create_argument_parser() -> argparse.ArgumentParser:
    """Create the argument parser for ScanAI."""
    parser = argparse.ArgumentParser(
        prog="scanai",
        description="👾 ScanAI - AI-Powered Security Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  scanai                          # Show usage information
  scanai start                    # Start interactive mode
  scanai --help                   # Show detailed help
  scanai config --init            # Create configuration template
  scanai config --check           # Check configuration status
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Config subcommand
    config_parser = subparsers.add_parser(
        'config',
        help='Configuration management commands'
    )
    config_parser.add_argument(
        '--init',
        action='store_true',
        help='Create configuration template with API keys'
    )
    config_parser.add_argument(
        '--check',
        action='store_true',
        help='Check configuration status and API keys'
    )

    # Start subcommand (default behavior)
    start_parser = subparsers.add_parser(
        'start',
        help='Start the interactive ScanAI security scanner'
    )

    return parser


def handle_config_init() -> int:
    """Handle config --init command.

    This will interactively collect API keys and create/update the .env file.
    """
    from pathlib import Path

    try:
        project_root = Path.cwd()
        env_path = project_root / ".env"

        print("👾 Initializing ScanAI configuration...")
        print("This will help you set up your API keys interactively.\n")

        # Collect API keys interactively
        api_keys = {}

        # Gemini API Keys (Required)
        print("👾 Google Gemini API Keys (Required for AI analysis)")
        print("   Get your keys from: https://aistudio.google.com/")
        print("   Multiple keys help with rate limiting and redundancy.\n")

        while True:
            try:
                num_keys = int(Prompt.ask("   How many Gemini API keys do you want to configure?", default="1"))
                if num_keys > 0:
                    break
                print("   ❌ Please enter at least 1 key.")
            except ValueError:
                print("   ❌ Please enter a valid number.")

        if num_keys == 1:
            gemini_keys = [Prompt.ask("   Enter your Gemini API key")]
        else:
            print(f"   Enter {num_keys} Gemini API keys (comma-separated):")
            keys_input = Prompt.ask("   Keys")
            gemini_keys = [key.strip() for key in keys_input.split(',') if key.strip()]

            while len(gemini_keys) != num_keys:
                print(f"   ❌ Expected {num_keys} keys, but got {len(gemini_keys)}. Please try again.")
                keys_input = Prompt.ask("   Keys")
                gemini_keys = [key.strip() for key in keys_input.split(',') if key.strip()]

        api_keys['GEMINI_API_KEYS'] = ','.join(gemini_keys)
        print(f"   ✅ Configured {len(gemini_keys)} Gemini API key(s)\n")

        # VirusTotal API Key (Optional)
        print(" VirusTotal API Key (Optional - for malware scanning)")
        print("   Get your key from: https://www.virustotal.com/")
        print("   Leave empty to skip.\n")

        vt_key = Prompt.ask("   Enter your VirusTotal API key (or press Enter to skip)", default="")
        if vt_key.strip():
            api_keys['VIRUSTOTAL_API_KEY'] = vt_key.strip()
            print("   ✅ VirusTotal API key configured\n")
        else:
            api_keys['VIRUSTOTAL_API_KEY'] = ""
            print("   ⏭️  VirusTotal API key skipped\n")

        # URLScan API Key (Optional)
        print("URLScan.io API Key (Optional - for URL analysis)")
        print("   Get your key from: https://urlscan.io/")
        print("   Leave empty to skip.\n")

        urlscan_key = Prompt.ask("   Enter your URLScan.io API key (or press Enter to skip)", default="")
        if urlscan_key.strip():
            api_keys['URLSCAN_API_KEY'] = urlscan_key.strip()
            print("   ✅ URLScan.io API key configured\n")
        else:
            api_keys['URLSCAN_API_KEY'] = ""
            print("   ⏭️  URLScan.io API key skipped\n")

        # Create or update .env file
        env_content = f"""# ScanAI .env configuration
# Auto-generated by scanai config --init

# Required: Google Gemini API Keys for AI analysis (supports multiple keys, comma-separated)
# Get your keys from: https://aistudio.google.com/
GEMINI_API_KEYS="{api_keys['GEMINI_API_KEYS']}"

# Optional: VirusTotal API Key for malware scanning
# Get your key from: https://www.virustotal.com/
VIRUSTOTAL_API_KEY="{api_keys['VIRUSTOTAL_API_KEY']}"

# Optional: URLScan.io API Key for URL analysis
# Get your key from: https://urlscan.io/
URLSCAN_API_KEY="{api_keys['URLSCAN_API_KEY']}"
"""

        env_path.write_text(env_content)
        print(f"✅ Configuration saved to: {env_path}")

        # Also create a TOML template for non-secret settings (optional)
        config.save_toml_template()

        print("\n👾 Configuration complete!")
        print("\n👾 Summary:")
        print(f"   • Gemini API Keys: {len(gemini_keys)} configured")
        print(f"   • VirusTotal API Key: {'✅ Configured' if api_keys['VIRUSTOTAL_API_KEY'] else '⏭️  Skipped'}")
        print(f"   • URLScan.io API Key: {'✅ Configured' if api_keys['URLSCAN_API_KEY'] else '⏭️  Skipped'}")

        print("\nRun 'scanai config --check' to verify your configuration.")
        print("You can now start scanning!")

        return 0

    except KeyboardInterrupt:
        print("\n\n❌ Configuration cancelled by user.")
        return 1
    except Exception as e:
        print(f"\n❌ Failed to create configuration: {str(e)}")
        return 1


def handle_config_check() -> int:
    """Handle config --check command."""
    try:
        print("👾 Checking ScanAI configuration...")
        print()

        # Show config file locations
        config.show_config_locations()
        print()

        # Check API key status
        validation = config.validate_api_keys()

        print("API Keys Status:")
        key_requirements = {
            'gemini': 'Required',
            'virustotal': 'Optional',
            'urlscan': 'Optional'
        }

        for key, valid in validation.items():
            status_icon = "✅" if valid else "❌"
            status_text = "[green]Configured[/green]" if valid else "[red]Missing[/red]"
            required = key_requirements.get(key, 'Unknown')
            print(f"  {status_icon} {key.upper()}: {status_text} ({required})")

        # Show Gemini key count if configured
        if validation.get('gemini', False):
            gemini_keys = config.gemini_api_keys
            print(f"  GEMINI_KEYS: ✅ {len(gemini_keys)} configured")

        print()
        print("Scan Settings:")
        print(f"  ⏱️  Nmap Timeout: {config.nmap_timeout}s")
        print(f"  Scan Timeout: {config.scan_timeout}s")
        print(f"  Max Subdomains: {config.max_subdomains}")
        print(f"  Verbose Output: {'Enabled' if config.verbose else 'Disabled'}")
        print(f"  JSON Output: {'Enabled' if config.json_output else 'Disabled'}")

        # Overall status
        gemini_ok = validation.get('gemini', False)
        if gemini_ok:
            print("\n[✓] Configuration Status: [green]READY[/green] - ScanAI is properly configured!")
            return 0
        else:
            print("\n[✕] Configuration Status: [red]INCOMPLETE[/red] - Run 'scanai config --init' to configure API keys")
            return 1

    except Exception as e:
        print(f"❌ Failed to check configuration: {str(e)}")
        return 1


def main() -> int:
    """Main entry point for the ScanAI CLI with argument parsing."""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Handle config commands
    if args.command == 'config':
        if args.init:
            return handle_config_init()
        elif args.check:
            return handle_config_check()
        else:
            print("❌ Error: config command requires --init or --check")
            print("Run 'scanai config --help' for more information.")
            return 1

    # Handle different commands
    if args.command == 'start':
        # Explicit start command - launch interactive mode
        try:
            app = ScanAI()
            app.run()
            return 0
        except KeyboardInterrupt:
            print("\n❌ Operation cancelled by user")
            return 1
        except Exception as e:
            print(f"❌ Fatal error: {str(e)}")
            return 1

    elif args.command is None:
        # No command provided - show usage message
        print("👾 ScanAI - AI-Powered Security Agent")
        print()
        print("Please use --help or -h for usage information.")
        print()
        print("Quick start:")
        print("  scanai start                    # Start interactive mode")
        print("  scanai config --init           # Initialize configuration")
        print("  scanai config --check          # Check configuration status")
        print("  scanai --help                  # Show detailed help")
        return 0

    # This shouldn't happen, but just in case
    parser.print_help()
    return 1


class ScanAI:
    """Main ScanAI CLI application with scanAI OS themed UI."""

    def __init__(self) -> None:
        """Initialize the CLI application."""
        # Dark theme for scanAI OS style
        self.console = Console(style="white on black")
        self.scan_manager = ScanManager()
        self.scanai_service = ScanAIService() if config.gemini_api_keys else None
        self.username = None
        self._session_logs = ["[bright_green]✔ System initialized. Ready for commands.[/bright_green]"]

    def run(self) -> None:
        """Run the CLI application in interactive mode."""
        self.console.clear()

        # Ask for username
        self.username = Prompt.ask(
            "[bold]Username[/bold]",
            default="operator",
            show_default=False
        ).strip()

        self._greet_user()

        while True:
            try:
                # Modern, advanced prompt redesign
                # Uses a more "OS" feel with cleaner symbols
                try:
                    query = self.console.input("[bold green]❯[/bold green] ").strip()
                except EOFError:
                    break
                
                if query.lower() in ['exit', 'quit', 'q']:
                    self._farewell_user()
                    break
                
                if not query:
                    continue

                # Handle CLI commands (non-AI)
                handled = self._handle_command(query)
                if handled:
                    continue
                
                # Interpret the query using AI
                with self.console.status("[bold bright_magenta]👾 Neural Agent interpreting request...[/bold bright_magenta]", spinner="bouncingBar"):
                    interpretation = self._interpret_query(query)
                
                # Handle new 'actions' array format and legacy 'action' field for invalid check
                actions_list = interpretation.get('actions', [])
                if actions_list:
                    first_action = actions_list[0].get('action') if isinstance(actions_list[0], dict) else actions_list[0]
                else:
                    first_action = interpretation.get('action', 'invalid')
                
                if first_action == 'invalid':
                    reason = interpretation.get('reason', interpretation.get('reasoning', 'Invalid query'))
                    error_panel = ThemePanel(
                        f"[bright_red][✕] {reason}[/bright_red]",
                        title="ERROR",
                        border_style="bright_red",
                        padding=(1, 2),
                        style="white on black"
                    )
                    self.console.print(error_panel)
                    continue
                
                # Perform the action
                self._perform_action(interpretation, query)
                
            except EOFError:
                # Handle Ctrl+D or EOF
                self.console.print("\n[bright_yellow]👾 Connection terminated![/bright_yellow]")
                break
            except KeyboardInterrupt:
                self.console.print("\n[bright_yellow][✓] Operation cancelled by user.[/bright_yellow]")
            except Exception as e:
                error_panel = ThemePanel(
                    f"[bright_red][✕] System Error: {str(e)}[/bright_red]",
                    title="SYSTEM ERROR",
                    border_style="bright_red",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(error_panel)

    def _handle_command(self, query: str) -> bool:
        """Handle built-in CLI commands. Returns True if handled."""
        cmd = query.strip().lower()
        parts = query.strip().split(maxsplit=1)
        cmd_name = parts[0].lower() if parts else ''

        if cmd in ('help', '?', '/help'):
            self._show_help()
            return True

        if cmd in ('workflows', '/workflows', 'profiles'):
            self._show_workflows()
            return True

        if cmd in ('chains', '/chains'):
            self._show_chains()
            return True

        if cmd in ('history', '/history', 'sessions'):
            self._show_history()
            return True

        if cmd_name in ('save', '/save'):
            name = parts[1] if len(parts) > 1 else None
            self._save_session(name)
            return True

        if cmd_name in ('load', '/load'):
            if len(parts) > 1:
                self._load_session(parts[1])
            else:
                self.console.print("[bright_red]Usage: load <session_id>[/bright_red]")
            return True

        if cmd_name in ('export', '/export'):
            fmt = parts[1].strip() if len(parts) > 1 else 'md'
            self._export_session(fmt)
            return True

        if cmd_name in ('correlate', '/correlate'):
            self._run_correlation()
            return True

        if cmd_name in ('multiscan', '/multiscan', 'multi'):
            if len(parts) > 1:
                self._run_multitarget(parts[1])
            else:
                self.console.print("[bright_red]Usage: multiscan <targets_file.txt>[/bright_red]")
            return True

        return False

    def _show_help(self) -> None:
        """Display help with all available commands."""
        help_text = (
            "[bold bright_cyan]COMMANDS[/bold bright_cyan]\n\n"
            "  [bright_green]help[/bright_green]              Show this help\n"
            "  [bright_green]workflows[/bright_green]         List all scanner profiles\n"
            "  [bright_green]chains[/bright_green]            List attack chains\n"
            "  [bright_green]history[/bright_green]           Show saved scan sessions\n"
            "  [bright_green]save [name][/bright_green]       Save last scan results\n"
            "  [bright_green]load <id>[/bright_green]         Load a saved session\n"
            "  [bright_green]export [md|html][/bright_green]  Export last scan as report\n"
            "  [bright_green]correlate[/bright_green]         Run cross-scanner correlation on last scan\n"
            "  [bright_green]multiscan <file>[/bright_green]  Scan multiple targets from file\n"
            "  [bright_green]exit[/bright_green]              Quit ScanAI\n\n"
            "[bold bright_cyan]NATURAL LANGUAGE[/bold bright_cyan]\n\n"
            "  Just type what you want to do:\n"
            "  [dim]• stealth scan example.com[/dim]\n"
            "  [dim]• quick recon target.com[/dim]\n"
            "  [dim]• web attack https://target.com[/dim]\n"
            "  [dim]• is this url phishing? https://evil.com[/dim]\n"
            "  [dim]• find emails for company.com[/dim]\n"
            "  [dim]• detect waf on target.com[/dim]\n"
            "  [dim]• wordpress scan blog.example.com[/dim]\n"
            "  [dim]• smb enum 10.0.0.5[/dim]\n"
            "  [dim]• wayback archive example.com[/dim]\n"
            "  [dim]• nikto web vuln scan example.com[/dim]\n"
            "  [dim]• full recon target.com[/dim]\n"
            "  [dim]• how to exploit log4j[/dim]\n"
        )
        self._stream_panel_content("SCANAI AGENT v0.4.0", help_text, "bright_cyan")

    def _show_workflows(self) -> None:
        """List all scanner workflows and profiles."""
        from .workflow_loader import get_registry
        reg = get_registry()

        lines = []
        for scanner_name, wf in sorted(reg.workflows.items()):
            lines.append(f"[bold bright_cyan]{scanner_name}[/bold bright_cyan] — {wf.description}")
            for prof_name, prof in wf.profiles.items():
                default = " [dim](default)[/dim]" if prof_name == wf.default_profile else ""
                lines.append(f"  [bright_green]{prof_name}[/bright_green]: {prof.description}{default}")
            lines.append("")

        total_profiles = sum(len(w.profiles) for w in reg.workflows.values())
        header = f"[bold]{len(reg.workflows)} scanners × {total_profiles} profiles[/bold]\n\n"
        self._stream_panel_content("WORKFLOW PROFILES", header + "\n".join(lines), "bright_magenta")

    def _show_chains(self) -> None:
        """List all attack chains."""
        from .workflow_loader import get_chain_registry
        cr = get_chain_registry()

        lines = []
        for name, chain in sorted(cr.chains.items()):
            steps = " → ".join(f"{s['scanner']}/{s.get('profile', 'default')}" for s in chain.steps)
            lines.append(f"[bold bright_red]👾 {name}[/bold bright_red]")
            lines.append(f"  {chain.description}")
            lines.append(f"  [dim]{steps}[/dim]\n")

        self._stream_panel_content("ATTACK CHAINS", "\n".join(lines), "bright_red")

    def _show_history(self) -> None:
        """Show saved scan sessions."""
        from .session import ScanSession
        sess = ScanSession()
        sessions = sess.list_sessions()

        if not sessions:
            self.console.print("[dim]No saved sessions. Use 'save' after a scan.[/dim]")
            return

        table = Table(title="👾 SAVED SESSIONS", border_style="bright_cyan", style="white on black")
        table.add_column("ID", style="bright_green")
        table.add_column("Target", style="bright_white")
        table.add_column("Scanners", style="dim")
        table.add_column("Risk", style="bright_red")
        table.add_column("Date", style="dim")

        for s in sessions:
            table.add_row(
                s['id'], s['target'],
                ', '.join(s['scanners'][:4]) + ('...' if len(s['scanners']) > 4 else ''),
                s['risk_level'], s['timestamp'][:19]
            )

        self.console.print(table)

    def _save_session(self, name=None) -> None:
        """Save last scan results."""
        from .session import ScanSession
        if not hasattr(self, '_last_results') or not self._last_results:
            self.console.print("[bright_red]No scan results to save. Run a scan first.[/bright_red]")
            return
        sess = ScanSession()
        sid = sess.save(self._last_results, self._last_query or '', name)
        self.console.print(f"[bright_green][✓] Saved as: {sid}[/bright_green]")

    def _load_session(self, session_id: str) -> None:
        """Load and display a saved session."""
        from .session import ScanSession
        sess = ScanSession()
        data = sess.load(session_id)
        if not data:
            self.console.print(f"[bright_red]Session '{session_id}' not found.[/bright_red]")
            return
        results = data.get('results', {})
        self._last_results = results
        self._last_query = data.get('query', '')
        self._display_scanAI_results(results, show_detailed=True)

    def _export_session(self, fmt: str = 'md') -> None:
        """Export last scan as report."""
        from .session import ScanSession
        if not hasattr(self, '_last_results') or not self._last_results:
            self.console.print("[bright_red]No scan results to export. Run a scan first.[/bright_red]")
            return

        sess = ScanSession()
        sid = sess.save(self._last_results, self._last_query or '', f"export_{int(time.time())}")

        if 'html' in fmt.lower():
            content = sess.export_html(sid)
            ext = 'html'
        else:
            content = sess.export_markdown(sid)
            ext = 'md'

        if content:
            filename = f"scanai_report_{int(time.time())}.{ext}"
            with open(filename, 'w') as f:
                f.write(content)
            self.console.print(f"[bright_green][✓] Report exported: {filename}[/bright_green]")
        else:
            self.console.print("[bright_red]Export failed.[/bright_red]")

    def _run_correlation(self) -> None:
        """Run cross-scanner correlation on last results."""
        from .correlator import IntelCorrelator
        if not hasattr(self, '_last_results') or not self._last_results:
            self.console.print("[bright_red]No scan results to correlate. Run a scan first.[/bright_red]")
            return

        correlator = IntelCorrelator()
        intel = correlator.correlate(self._last_results)

        lines = []
        score = intel.get('intel_score', 0)
        score_color = 'bright_red' if score >= 70 else 'bright_yellow' if score >= 40 else 'bright_green'
        lines.append(f"[bold {score_color}]Intelligence Score: {score}/100[/bold {score_color}]")
        lines.append(f"[dim]{intel.get('summary', '')}[/dim]\n")

        # Attack paths
        paths = intel.get('attack_paths', [])
        if paths:
            lines.append("[bold bright_red]ATTACK PATHS:[/bold bright_red]\n")
            for i, path in enumerate(paths, 1):
                sev_color = 'bright_red' if path['severity'] in ('CRITICAL', 'HIGH') else 'bright_yellow'
                lines.append(f"  [{sev_color}]{i}. {path['name']} [{path['severity']}][/{sev_color}]")
                lines.append(f"     {path['description']}")
                for step in path.get('steps', []):
                    lines.append(f"     → {step}")
                lines.append("")

        # Risk factors
        factors = intel.get('risk_factors', [])
        if factors:
            lines.append("[bold bright_yellow]RISK FACTORS:[/bold bright_yellow]\n")
            for f in factors:
                lines.append(f"  [!] {f}")
            lines.append("")

        # Recommendations
        recs = intel.get('recommendations', [])
        if recs:
            lines.append("[bold bright_green]RECOMMENDATIONS:[/bold bright_green]\n")
            for r in recs:
                lines.append(f"  [TIP] {r}")

        self._stream_panel_content("INTELLIGENCE CORRELATION", "\n".join(lines), score_color)

    def _run_multitarget(self, filepath: str) -> None:
        """Scan multiple targets from a file."""
        import os
        if not os.path.isfile(filepath):
            self.console.print(f"[bright_red]File not found: {filepath}[/bright_red]")
            return

        with open(filepath, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        if not targets:
            self.console.print("[bright_red]No targets found in file.[/bright_red]")
            return

        self.console.print(f"[bright_cyan]👾 Multi-target scan: {len(targets)} targets[/bright_cyan]")

        for idx, target in enumerate(targets, 1):
            self.console.print(f"\n[bold bright_magenta]┌── [{idx}/{len(targets)}] {target}[/bold bright_magenta]")
            # Run quick recon chain for each target
            from .workflow import WorkflowEngine
            engine = WorkflowEngine(
                ai_service=self.scanai_service,
                scan_manager=self.scan_manager,
                progress_callback=lambda m, c, t: None
            )
            try:
                import asyncio
                results_with_state = asyncio.run(engine.run_attack_chain('quick_recon', target, f'quick recon {target}'))
                results = results_with_state.get("results")
                if results:
                    self._last_results = results
                    self._display_scanAI_results(results, show_detailed=False)
                    # Auto-save each
                    from .session import ScanSession
                    ScanSession().save(results, f'multiscan: {target}')
            except Exception as e:
                self.console.print(f"[bright_red]Error scanning {target}: {e}[/bright_red]")

        self.console.print(f"\n[bright_green][✓] Multi-target scan complete: {len(targets)} targets[/bright_green]")

    def _greet_user(self) -> None:
        """Greet the user — ScanAI-style clean boot."""
        from .workflow_loader import get_registry, get_chain_registry
        from .scan_manager import ScanManager

        try:
            reg = get_registry()
            cr = get_chain_registry()
            n_scanners = len(ScanManager().scanners)
            n_profiles = sum(len(w.profiles) for w in reg.workflows.values())
            n_chains = len(cr.chains)
        except Exception:
            n_scanners = n_profiles = n_chains = 0

        self.console.print()
        self.console.print("[bold white]  ░█▀▀░█▀▀░█▀█░█▀█░█▀█░▀█▀[/bold white]")
        self.console.print("[bold white]  ░▀▀█░█░░░█▀█░█░█░█▀█░░█░[/bold white]")
        self.console.print("[bold white]  ░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀[/bold white]")
        self.console.print(f"  [bold bright_red]👾  SCANAI 👾[/bold bright_red]\n")

        # ScanAI-style status table
        status_table = Table(box=box.ROUNDED, border_style="dim", expand=True, show_header=False, padding=(0, 1))
        status_table.add_column("Item", style="bold", width=18)
        status_table.add_column("Value")

        status_table.add_row("Agent", f"ScanAI v0.4.0 · AI-Powered Security Agent")
        status_table.add_row("User", f"{self.username}")
        status_table.add_row("Scanners", f"{n_scanners} modules · {n_profiles} profiles")
        status_table.add_row("Chains", f"{n_chains} attack chains")
        status_table.add_row("AI", f"{'connected' if self.scanai_service else 'offline'}")
        status_table.add_row("Help", f"type [bold]help[/bold] for commands")

        self.console.print(status_table)
        self.console.print()

    def _farewell_user(self) -> None:
        """Bid farewell to the user with AI-generated message."""
        if self.scanai_service and self.username:
            with self.console.status("[bold bright_magenta]Terminating core Agent processes...[/bold bright_magenta]", spinner="bouncingBar"):
                farewell = self.scanai_service.generate_farewell(self.username)
                
            from rich.markup import escape
            farewell_panel = ThemePanel(
                f"[{C['success']}]{escape(farewell)}[/]",
                title="👾 SESSION TERMINATED 👾",
                border_style=C['primary'],
                padding=(1, 2)
            )
            self.console.print(farewell_panel)
        else:
            self.console.print("\n[bold orange1]👾 Goodbye! Stay anonymous! 👾[/bold orange1]")

    def _display_previous_analysis_results(self, results: Dict[str, Any], original_query: str) -> None:
        """Display analysis of previous scan results."""
        # Get the actual scan results from the result data
        scan_data = results.get('result', {})

        if self.scanai_service:
            with self.console.status("[bold bright_magenta]Agent synthesizing previous Context...[/bold bright_magenta]", spinner="bouncingBar"):
                # Use generate_hacking_guidance or interpret_user_query instead
                ai_response = self.scanai_service.generate_hacking_guidance(original_query, results.get('target', ''))

            if ai_response.get('success'):
                analysis_panel = ThemePanel(
                    f"[bold bright_cyan]ScanAI Analysis[/bold bright_cyan]\n\n"
                    f"{ai_response['response']}",
                    title="SCAN RESULT ANALYSIS",
                    border_style="bright_magenta",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(analysis_panel)
            else:
                error_panel = ThemePanel(
                    f"[bright_red]Analysis failed: {ai_response.get('error', 'Unknown error')}[/bright_red]",
                    title="ANALYSIS ERROR",
                    border_style="bright_red",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(error_panel)
        else:
            error_panel = ThemePanel(
                "[bright_red]AI service not configured. Cannot analyze previous results.[/bright_red]",
                title="CONFIGURATION ERROR",
                border_style="bright_red",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(error_panel)

    def _display_exploitation_guidance(self, results: Dict[str, Any], query: str) -> None:
        """Display Tier 3 hacker exploitation guidance and POC."""
        from ..ai.agents.exploitation_agent import ExploitationAgent
        
        # Gather target info and vulnerabilities from previous scan results
        target_info = {
            'target': results.get('target', results.get('domain', 'unknown')),
            'details': results.get('details', {})
        }
        
        # Extract vulnerabilities/CVEs if available
        vulnerabilities = []
        details = results.get('details', {})
        if 'cves' in details and details['cves']:
            cves_data = details['cves'].get('data', {}).get('cves', [])
            if isinstance(cves_data, list):
                vulnerabilities.extend(cves_data)
        
        # Extract services from nmap
        if 'nmap' in details and details['nmap']:
            nmap_data = details['nmap'].get('data', {})
            services = nmap_data.get('services', [])
            if services:
                target_info['services'] = services
        
        if self.scanai_service:
            with self.console.status("[bold bright_red]Neural Agent synthesizing Exploitation Vectors...[/bold bright_red]", spinner="bouncingBar"):
                agent = ExploitationAgent(ai_service=self.scanai_service)
                guidance = agent.generate_exploitation_guidance(
                    query=query,
                    target_info=target_info,
                    vulnerabilities=vulnerabilities
                )
            
            if guidance:
                exploit_panel = ThemePanel(
                    Markdown(guidance),
                    title="[bold bright_red]SCANAI'S EXPLOITATION GUIDANCE[/bold bright_red]",
                    border_style="bright_red",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(exploit_panel)
            else:
                error_panel = ThemePanel(
                    "[bright_red]Failed to generate exploitation guidance.[/bright_red]",
                    title="ERROR",
                    border_style="bright_red",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(error_panel)
        else:
            error_panel = ThemePanel(
                "[bright_red]AI service not configured. Cannot generate exploitation guidance.[/bright_red]",
                title="CONFIGURATION ERROR",
                border_style="bright_red",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(error_panel)

    def _display_hacking_guidance(self, query: str, target: str = "") -> None:
        """Display World's Number 1 Hacking LLM guidance."""
        if self.scanai_service:
            with self.console.status("[bold bright_magenta]Neural Agent synthesizing Elite Guidance...[/bold bright_magenta]", spinner="bouncingBar"):
                ai_response = self.scanai_service.generate_hacking_guidance(query, target)

            if ai_response.get('success'):
                # Wrap response in a more "encyclopedia/decrypted" look
                from rich.rule import Rule
                
                guidance_content = Group(
                    Rule(f"[bold {C['secondary']}]DECRYPTED INTELLIGENCE[/]", style=C['secondary']),
                    Text(""),
                    Markdown(ai_response['response']),
                    Text(""),
                    Rule(style=C['dim'])
                )
                
                guidance_panel = ThemePanel(
                    guidance_content,
                    title="ELITE HACKING INTELLIGENCE",
                    border_style=C['secondary'],
                    padding=(1, 2)
                )
                self.console.print(guidance_panel)
            else:
                error_panel = ThemePanel(
                    f"[bright_red]Guidance generation failed: {ai_response.get('error', 'Unknown error')}[/bright_red]",
                    title="ERROR",
                    border_style="bright_red",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(error_panel)
        else:
            error_panel = ThemePanel(
                "[bright_red]AI service not configured. Cannot generate hacking guidance.[/bright_red]",
                title="CONFIGURATION ERROR",
                border_style="bright_red",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(error_panel)

    def _interpret_query(self, query: str) -> Dict[str, Any]:
        """Interpret user query using AI."""
        if not self.scanai_service:
            return {"action": "invalid", "reason": "AI service not configured"}

        # Determine if this is a follow-up about previous results via AI service
        # (The specialized prompt in gemini_service handles this now)
        return self.scanai_service.interpret_user_query(query)

    def _perform_action(self, interpretation: Dict[str, Any], original_query: str = "") -> None:
        """Perform the interpreted action with scanAI OS themed UI."""
        # Handle new 'actions' array format and legacy 'action' field
        actions_list = interpretation.get('actions', [])
        if actions_list:
            # Extract action names and profiles from actions array
            action_names = [a.get('action') if isinstance(a, dict) else a for a in actions_list]
            action_profiles = {
                (a.get('action') if isinstance(a, dict) else a): (a.get('profile') if isinstance(a, dict) else None)
                for a in actions_list
            }
            action = action_names[0] if action_names else 'invalid'
        else:
            # Legacy format with single 'action' field
            action = interpretation.get('action', 'invalid')
            action_names = [action] if action else []
            action_profiles = {}
        
        target = interpretation.get('target', '')
        params = interpretation.get('parameters', {})
        # Extract profile for the primary action
        primary_profile = action_profiles.get(action)
        is_multi_scan = interpretation.get('is_multi_scan', False)

        # Handle analysis of previous scan results
        if action == 'analyze_previous':
            result_id = params.get('result_id')
            if result_id:
                # Retrieve the previous scan result
                stored_result = result_storage.get_result(result_id)
                if stored_result:
                    # Show analysis header
                    self._print_scanAI_header(f"ANALYZING PREVIOUS SCAN: [bold bright_cyan]{target}[/bold bright_cyan]")

                    # Display the analysis
                    self._display_previous_analysis_results(stored_result, original_query)
                    return
                else:
                    error_panel = ThemePanel(
                        f"[bright_red]Could not retrieve scan result with ID: {result_id}[/bright_red]",
                        title="RETRIEVAL ERROR",
                        border_style="bright_red",
                        padding=(1, 2),
                        style="white on black"
                    )
                    self.console.print(error_panel)
                    return
            else:
                error_panel = ThemePanel(
                    "[bright_red]No previous scan results found. Please run a scan first.[/bright_red]",
                    title="NO PREVIOUS RESULTS",
                    border_style="bright_red",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(error_panel)
                return

        # Handle async scanning actions
        if action == 'async_scan':
            asyncio.run(self._perform_async_action(target, params))
            return

        # Handle attack chains
        if action == 'attack_chain' or interpretation.get('is_chain'):
            chain_name = interpretation.get('chain_name')
            if not chain_name:
                # Try to get from first action
                first_action = actions_list[0] if actions_list else {}
                chain_name = first_action.get('chain') if isinstance(first_action, dict) else None
            if chain_name and target:
                engine = WorkflowEngine(
                    ai_service=self.scanai_service,
                    scan_manager=self.scan_manager,
                    progress_callback=lambda m, c, t: self._session_logs.append(f"[bright_green]✔[/bright_green] {m}") or (self._session_logs.pop(0) if len(self._session_logs) > 7 else None)
                )
                try:
                    results_with_state = asyncio.run(engine.run_attack_chain(chain_name, target, original_query))
                except RuntimeError:
                    import nest_asyncio
                    nest_asyncio.apply()
                    loop = asyncio.get_event_loop()
                    results_with_state = loop.run_until_complete(engine.run_attack_chain(chain_name, target, original_query))

                results = results_with_state.get("results")
                if results:
                    self._display_scanAI_results(results, show_detailed=True)
                    self._display_pro_report(results, original_query)
                return

        # Check if this is a targeted scan (single scanner) or comprehensive scan
        is_targeted_scan = interpretation.get('is_targeted_scan', False)
        
        # List of targeted scan actions that should bypass the planning loop
        targeted_actions = [
            'subdomain_enum', 'port_scan', 'vuln_scan', 'cve_scan', 'web_scan',
            'ssl_scan', 'dns_enum', 'whois_lookup', 'tech_detect', 'dir_enum',
            'file_enum', 'xss_scan', 'sqli_scan', 'http_headers', 'ip_geo',
            'crawl_scan', 'virustotal_scan', 'nikto_scan', 'osint_scan', 'waf_detect',
            'wordpress_scan', 'wayback_scan', 'smb_enum', 'secrets_scan'
        ]

        # Progress callback for workflow engine
        def workflow_progress_callback(message: str, completed: int, total: int):
            prefix = "[bright_magenta]❯[/bright_magenta]" if completed == 0 else "[bright_green]✔[/bright_green]"
            if completed == 0 and len(self._session_logs) >= 7:
                 # Clear most logs when a new workflow starts to keep it fresh
                 self._session_logs = self._session_logs[-1:]
            
            self._session_logs.append(f"{prefix} {message}")
            if len(self._session_logs) > 7:
                self._session_logs.pop(0)

        engine = WorkflowEngine(
            ai_service=self.scanai_service,
            scan_manager=self.scan_manager,
            progress_callback=workflow_progress_callback
        )

        # Handle MULTI-SCAN requests (multiple targeted scans in one query)
        if is_multi_scan and len(action_names) > 1:
            valid_actions = [a for a in action_names if a in targeted_actions]
            if valid_actions:
                self._print_scanAI_header(
                    f"INITIATING MULTI-SCAN ({len(valid_actions)} scans) ON [bold bright_cyan]{target}[/bold bright_cyan]"
                )
                
                try:
                    results_with_state = asyncio.run(
                        engine.run_multi_targeted_scan(valid_actions, target, original_query)
                    )
                except RuntimeError as e:
                    if "already running" in str(e) or "current event loop" in str(e):
                        import nest_asyncio
                        nest_asyncio.apply()
                        loop = asyncio.get_event_loop()
                        results_with_state = loop.run_until_complete(
                            engine.run_multi_targeted_scan(valid_actions, target, original_query)
                        )
                    else:
                        raise e
                
                results = results_with_state.get("results")
                if results:
                    self._display_scanAI_results(results, show_detailed=True)
                    self._display_pro_report(results, original_query)
                return
        
        # Determine if we should use targeted or autonomous scan
        use_targeted_scan = is_targeted_scan or action in targeted_actions
        
        # For comprehensive/full scans, use autonomous loop
        if action == 'scan' or action == 'comprehensive_scan':
            use_targeted_scan = False
        
        if use_targeted_scan and action in targeted_actions:
            # TARGETED SCAN: Run single scanner directly (no AI planning loop)
            self._print_scanAI_header(f"TARGETED SCAN: [bold bright_cyan]{target}[/bold bright_cyan]")

            # For katana (crawl_scan): run with live TUI display
            if action == 'crawl_scan':
                results_with_state = self._run_katana_live(engine, action, target, original_query, primary_profile)
            else:
                # Run targeted scan (single scanner, no planning loop)
                try:
                    results_with_state = asyncio.run(engine.run_targeted_scan(action, target, original_query, profile=primary_profile))
                except RuntimeError as e:
                    if "already running" in str(e) or "current event loop" in str(e):
                        import nest_asyncio
                        nest_asyncio.apply()
                        loop = asyncio.get_event_loop()
                        results_with_state = loop.run_until_complete(engine.run_targeted_scan(action, target, original_query, profile=primary_profile))
                    else:
                        raise e
            
            results = results_with_state.get("results")
            state = results_with_state.get("state", {})

            if results:
                # Store for save/export/correlate
                self._last_results = results
                self._last_query = original_query

                # Display final results
                self._display_scanAI_results(results, show_detailed=True)
                self._display_pro_report(results, original_query)

                # Auto-run correlation
                from .correlator import IntelCorrelator
                intel = IntelCorrelator().correlate(results)
                if intel.get('attack_paths'):
                    score = intel.get('intel_score', 0)
                    sc = 'bright_red' if score >= 70 else 'bright_yellow' if score >= 40 else 'bright_green'
                    paths_text = f"[bold {sc}]Intel Score: {score}/100[/bold {sc}]\n"
                    for p in intel['attack_paths'][:3]:
                        paths_text += f"\n  [bold]{p['name']}[/bold] [{p['severity']}]: {p['description']}"
                    if intel.get('recommendations'):
                        paths_text += f"\n\n  {intel['recommendations'][0]}"
                    self._stream_panel_content("ATTACK PATH ANALYSIS", paths_text, sc)

                # Display auto-chain suggestions
                auto_chains = results.get('auto_chain_suggestions', [])
                if auto_chains:
                    chain_lines = "\n".join(f"  ⛓️  {c['reason']}" for c in auto_chains if c.get('scanner') != '_exploitation_guidance')
                    exploit_chains = [c for c in auto_chains if c.get('scanner') == '_exploitation_guidance']
                    if chain_lines.strip():
                        chain_content = f"[bold bright_cyan]Recommended follow-up scans:[/bold bright_cyan]\n{chain_lines}"
                        self._stream_panel_content("AUTO-CHAIN SUGGESTIONS", chain_content, "bright_cyan")
                    if exploit_chains:
                        self._stream_panel_content(
                            "EXPLOITATION AVAILABLE",
                            f"[bright_red]{exploit_chains[0]['reason']}[/bright_red]\n"
                            f"Type: [bold]how to exploit <target>[/bold] for POC guidance",
                            "bright_red"
                        )
            return
        
        elif action == 'scan' or action == 'comprehensive_scan':
            # COMPREHENSIVE SCAN: Use full autonomous agentic loop
            self._print_scanAI_header(f"COMPREHENSIVE ANALYSIS: [bold bright_cyan]{target}[/bold bright_cyan]")

            # Run the autonomous loop
            try:
                # Use asyncio.run for a clean execution if no loop is running
                results_with_state = asyncio.run(engine.run_autonomous(original_query, target))
            except RuntimeError as e:
                if "already running" in str(e) or "current event loop" in str(e):
                    # Fallback for nested loops (though shouldn't happen in CLI usually)
                    import nest_asyncio
                    nest_asyncio.apply()
                    loop = asyncio.get_event_loop()
                    results_with_state = loop.run_until_complete(engine.run_autonomous(original_query, target))
                else:
                    raise e
            
            results = results_with_state.get("results")

            if results:
                # Display final comprehensive results
                self._display_scanAI_results(results, show_detailed=True)
                self._display_pro_report(results, original_query)
            return
        elif action == 'exploit_guidance':
            # EXPLOITATION GUIDANCE: Generate Tier 3 hacker POC
            self._print_scanAI_header(f"EXPLOITATION GUIDANCE: [bold bright_red]{target}[/bold bright_red]")
            
            # Get any previous scan results to provide context
            # Use get_latest_result if it exists (it was added in recent refactors)
            previous_results = {}
            if hasattr(result_storage, 'get_latest_result'):
                 previous_results = result_storage.get_latest_result(target)
            
            self._display_exploitation_guidance(
                results=previous_results if previous_results else {'target': target, 'details': {}},
                query=original_query
            )
            return

        elif action == 'hacking_guidance':
            # HACKING GUIDANCE: World's Number 1 Hacking LLM Mode
            self._print_scanAI_header(f"KNOWLEDGE RETRIEVAL: [bold bright_magenta]{target if target else 'General Guidance'}[/bold bright_magenta]")
            self._display_hacking_guidance(original_query, target)
            return

        # scanAI OS scanning header - fallback for unknown actions
        self._print_scanAI_header(f"FALLBACK SCAN: [bold bright_cyan]{target}[/bold bright_cyan]")

    async def _perform_async_action(self, target: str, params: Dict[str, Any]) -> None:
        """Perform async scanning actions."""
        try:
            # Show async scan header
            self._print_scanAI_header(f"ASYNC SCAN: [bold bright_cyan]{target}[/bold bright_cyan]")

            # Perform async comprehensive scan
            with self.console.status("[bold bright_magenta]Running async security scans...[/bold bright_magenta]", spinner="bouncingBar") as status:
                results = await async_scanner_manager.async_comprehensive_scan(target)

            if results:
                # Save async scan results
                result_id = result_storage.save_result(target, results)
                self.console.print(f"[dim bright_cyan]💾 Async scan saved with ID: [bold]{result_id}[/bold][/dim bright_cyan]")

                # Display results
                self._display_scanAI_results(results, show_detailed=True)

        except Exception as e:
            error_panel = ThemePanel(
                f"[bright_red]Async scan failed: {str(e)}[/bright_red]",
                title="ASYNC SCAN ERROR",
                border_style="bright_red",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(error_panel)

    def _handle_scan(self, args: Any, show_detailed: bool = True, display_results: bool = True) -> Dict[str, Any]:
        """Handle scan command with scanAI OS themed UI."""
        target = args.target

        # Validate configuration
        if not self._check_config():
            return {}

        # scanAI OS progress tracking - dark theme with purple/cyan
        with Progress(
            SpinnerColumn(spinner_name="arc", style=f"bold {C['secondary']}"),
            TextColumn(f"[bold {C['primary']}]{{task.description}}[/]"),
            BarColumn(bar_width=None, complete_style=C['matrix'], finished_style=C['secondary']),
            TextColumn(f"[bold {C['matrix']}] {{task.percentage:>3.0f}}%[/]"),
            console=self.console,
            refresh_per_second=20,
            transient=True
        ) as progress:
            task = progress.add_task("Neural Processing...", total=100, completed=0)

            def progress_callback(scanner_name: str, completed: int, total: int):
                messages = [
                    "Quantum synchronization in progress...",
                    "Mapping attack surface topography...",
                    "Decrypting remote security layers...",
                    "Probing network vulnerabilities...",
                    "Synthesizing threat intelligence...",
                    "Generating mission report..."
                ]
                
                message_index = int((completed / total) * len(messages)) % len(messages) if total > 0 else 0
                description = f"[bright_cyan]{messages[message_index]}[/bright_cyan]"
                progress.update(task, description=description, completed=(completed/total)*100 if total > 0 else 100)

            # Perform scan
            try:
                scanners_to_run = getattr(args, 'scanners', None)
                results = self.scan_manager.perform_full_scan(target, progress_callback, scanners_to_run)
                progress.update(task, description="[bright_green]✅ Security analysis complete![/bright_green]", completed=100)

                # Save scan results
                result_id = result_storage.save_result(target, results)
                self.console.print(f"[dim bright_cyan]💾 Scan saved with ID: [bold]{result_id}[/bold][/dim bright_cyan]")

                if args.json:
                    self._output_json(results)
                elif display_results:
                    self._display_scanAI_results(results, show_detailed)

                return results

            except KeyboardInterrupt:
                self.console.print("[bright_red]✗ Scan interrupted by user[/bright_red]")
                return {}
            except Exception as e:
                self.console.print(f"[bright_red]✗ Scan failed: {str(e)}[/bright_red]")
                return {}

    def _display_scanAI_results(self, results: Dict[str, Any], show_detailed: bool = True) -> None:
        """Display scan results with ScanAI themed UI."""
        self._print_scanAI_header(f"SECURITY REPORT: {results['target']}")
        
        # *** SHOW DETAILED RESULTS FIRST (what user wants to see) ***
        if show_detailed:
            # Detailed scanner results
            self._display_detailed_scanAI_modules(results)
            
            # Show errors if any occurred during scanning
            errors = results.get('errors', [])
            if errors:
                self._display_errors(errors)
        
        # *** THEN SHOW SUMMARY PANELS ***
        # Quick stats in columns - scanAI OS style
        stats_panel = self._create_scanAI_stats_panel(results)
        self.console.print(stats_panel)
        
        # Risk assessment
        self._display_scanAI_risk_assessment(results)
        
        # Intelligence summary
        self._display_scanAI_intelligence_summary(results)

    def _display_pro_report(self, results: Dict[str, Any], query: str = "") -> None:
        """Display the Pro Hacker Report (ELITE HACKING INTELLIGENCE) at the end.
        
        If the report hasn't been pre-generated, this will generate it now
        (after scan results have already been displayed).
        """
        # --- FOOLPROOF DUPLICATION PREVENTION ---
        # 1. Use a instance-level set to track which IDs have been displayed
        if not hasattr(self, '_displayed_report_ids'):
            self._displayed_report_ids = set()
            
        res_id = id(results)
        if res_id in self._displayed_report_ids:
            return
            
        # 2. Also check the unique session key as a backup
        session_key = f"_pro_report_displayed_{res_id}"
        if getattr(self, session_key, False):
            return

        # Generate report if not already present
        if 'pro_report' not in results or not results['pro_report']:
            self.console.print("\n")
            with self.console.status("[bold bright_magenta]Generating ELITE Intelligence Report...[/bold bright_magenta]", spinner="bouncingBar"):
                from ..ai.agents.analyst_agent import AnalystAgent
                analyst = AnalystAgent(ai_service=self.scanai_service)
                target = results.get('target', results.get('domain', 'unknown'))
                findings = results.get('details', {})
                results['pro_report'] = analyst.generate_pro_report(
                    target=target,
                    findings=findings,
                    query=query
                )
        
        if results.get('pro_report'):
            # Mark as displayed immediately to prevent race conditions or rapid re-calls
            self._displayed_report_ids.add(res_id)
            setattr(self, session_key, True)
            
            report_text = results['pro_report']
            
            # ROBUST FILTERING: Trim residual AI titles and duplicate headers
            lines = report_text.split('\n')
            clean_lines = []
            skip_header = True
            for line in lines:
                lstrip = line.strip()
                # Skip the first few lines if they look like a repeated H1 title
                if skip_header:
                    if lstrip.startswith('#') or lstrip.startswith('╭──'):
                        if any(term in lstrip.upper() for term in ["ELITE", "HACKING", "INTELLIGENCE"]):
                            continue
                    if not lstrip:
                        continue
                    skip_header = False
                clean_lines.append(line)
            
            report_text = '\n'.join(clean_lines).strip()
            
            from rich.live import Live
            from rich.markdown import Markdown
            import time
            
            self.console.print("\n")
            
            # ScanAI OS themed header (same style as all other sections)
            self._print_scanAI_header("ELITE HACKING INTELLIGENCE")
            
            # Stream the report line-by-line inside a dim-bordered panel
            report_lines = report_text.split('\n')
            current_markdown = ""
            
            with Live(console=self.console, refresh_per_second=10) as live:
                for line in report_lines:
                    current_markdown += line + "\n"
                    report_panel = Panel(
                        Markdown(current_markdown),
                        border_style="dim",
                        padding=(1, 2),
                        box=box.ROUNDED
                    )
                    live.update(report_panel)
                    # Smooth delay
                    time.sleep(0.04 if len(report_lines) < 30 else 0.02)
            
            self.console.print()

    def _create_scanAI_stats_panel(self, results: Dict[str, Any]) -> Panel:
        """Create scanAI OS themed statistics panel."""
        details = results.get('details', {})
        
        # Calculate stats with safe defaults for partial scans
        
        # Vulnerabilities
        if 'cves' in details and isinstance(details['cves'], dict):
            cve_list = details['cves'].get('cves', [])
            if not isinstance(cve_list, list):
                cve_list = []
            vuln_count = len(cve_list)
            vuln_display = str(vuln_count)
            vuln_icon = "✓" if vuln_count == 0 else "✗"
        else:
            vuln_display = "[dim]N/A[/dim]"
            vuln_icon = "[dim]⚪[/dim]"

        # Open Ports
        if 'nmap' in details and isinstance(details['nmap'], dict):
            ports_list = details['nmap'].get('ports', [])
            if not isinstance(ports_list, list):
                ports_list = []
            open_ports = len([p for p in ports_list if isinstance(p, dict) and p.get('state') == 'open'])
            ports_display = str(open_ports)
            ports_icon = "✓" if open_ports < 5 else "⚠"
        else:
            ports_display = "[dim]N/A[/dim]"
            ports_icon = "[dim]⚪[/dim]"

        # Subdomains
        if 'subdomain' in details and isinstance(details['subdomain'], dict):
            # subdomain scanner returns: {subdomains: [...], count: X}
            sub_list = details['subdomain'].get('subdomains', [])
            if not isinstance(sub_list, list):
                sub_list = []
            subdomains = len(sub_list)
            subs_display = str(subdomains)
            subs_icon = "📊"
        else:
            subs_display = "[dim]N/A[/dim]"
            subs_icon = "[dim]⚪[/dim]"

        # Katana Crawl Results
        if 'katana' in details and isinstance(details['katana'], dict):
            katana_urls = details['katana'].get('total_urls_discovered', 0)
            katana_endpoints = details['katana'].get('total_endpoints_discovered', 0)
            crawl_display = f"{katana_urls} urls / {katana_endpoints} eps"
            crawl_icon = "🕷️"
        else:
            crawl_display = "[dim]N/A[/dim]"
            crawl_icon = "[dim]⚪[/dim]"

        risk_level = results.get('level', 'unknown').upper()
        if not risk_level or risk_level == 'NONE':
             # If risk wasn't fully calculated, show unknown or low depending on context
             # But for unified display, 'unknown' might be better if we really don't know
             if not results.get('summaries', {}).get('risk'):
                 risk_level = "UNKNOWN"
        
        # ScanAI pipe-separated stat bar
        parts = []
        parts.append(f"[bold bright_cyan]{risk_level}[/bold bright_cyan]")
        parts.append(f"[bold]{vuln_display}[/bold] vulns")
        parts.append(f"[bold]{ports_display}[/bold] ports")
        parts.append(f"[bold]{subs_display}[/bold] subs")
        parts.append(f"[bold]{crawl_display}[/bold]")
        parts.append(f"[dim]{results.get('duration', 0):.1f}s[/dim]")
        
        stat_bar = " [dim]│[/dim] ".join(parts)
        
        return Panel(
            stat_bar,
            border_style="dim",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _create_standard_table(self, title: str, columns: List[Tuple[str, str, Union[int, str]]]) -> Table:
        """Create an ScanAI-style table with dim borders."""
        table = Table(
            show_header=True,
            header_style="bold bright_cyan",
            border_style="dim",
            box=box.ROUNDED,
        )

        for col_name, col_style, col_width in columns:
            if col_width == "auto":
                table.add_column(col_name, style=col_style)
            elif isinstance(col_width, int):
                table.add_column(col_name, style=col_style, width=col_width)
            else:
                table.add_column(col_name, style=col_style, ratio=int(col_width) if col_width.isdigit() else 1)

        return table

    def _create_clean_panel(self, content, title: str = "", border_style: str = "dim", padding: Tuple[int, int] = (1, 2)) -> Panel:
        """Create an ScanAI-style panel with dim borders."""
        return Panel(
            content,
            title=f"[bright_cyan]{title}[/bright_cyan]" if title else "",
            border_style="dim",
            box=box.ROUNDED,
            padding=padding,
        )

    def _format_multiline_stats(self, stats: Dict[str, str], title: str) -> str:
        """Format stats as multiline text with scanAI OS styling."""
        lines = [f"[bold bright_cyan]{title}[/bold bright_cyan]"]
        lines.append("[bright_cyan]" + "─" * len(title) + "[/bright_cyan]")

        for key, value in stats.items():
            lines.append(f"[bright_white]{key}:[/bright_white] [bold bright_green]{value}[/bold bright_green]")

        return "\n".join(lines)

    def _add_section_spacing(self) -> None:
        """Add spacing between sections."""
        self.console.print()

    def _display_scanAI_risk_assessment(self, results: Dict[str, Any]) -> None:
        """Display ScanAI-style risk assessment."""
        risk_data = results['summaries'].get('risk', {})
        total_risk = risk_data.get('total', 0)
        
        risk_bar = self._create_scanAI_risk_gauge(total_risk)
        
        components = risk_data.get('components', {})
        if not isinstance(components, dict):
            components = {}
        
        content = (
            f"[bold]Risk Score:[/bold] [bright_yellow]{total_risk}/100[/bright_yellow]\n"
            f"{risk_bar}\n\n"
            f"[dim]└─ url:[/dim]  {components.get('url_heuristic', 0)}/25\n"
            f"[dim]└─ malware:[/dim]  {components.get('virustotal', 0)}/25\n"
            f"[dim]└─ web:[/dim]  {components.get('urlscan', 0)}/25\n"
            f"[dim]└─ vulns:[/dim]  {components.get('cves', 0)}/25"
        )
        
        self._print_scanAI_header("THREAT ASSESSMENT")
        panel = Panel(content, border_style="dim", box=box.ROUNDED, padding=(1, 2))
        self.console.print(panel)

    def _create_scanAI_risk_gauge(self, score: int) -> str:
        """Create an ScanAI-style risk gauge."""
        bar_length = 30
        filled = int(score / 100 * bar_length)
        
        if score < 30:
            color, label, dot = "bright_green", "LOW", "●"
        elif score < 60:
            color, label, dot = "bright_yellow", "MEDIUM", "●"
        elif score < 80:
            color, label, dot = "bright_red", "HIGH", "●"
        else:
            color, label, dot = "bright_red", "CRITICAL", "●"
        
        bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * (bar_length - filled)}[/dim]"
        return f"{bar} [{color}]{dot} {label}[/{color}]"

    def _display_scanAI_intelligence_summary(self, results: Dict[str, Any]) -> None:
        """Display ScanAI-style intelligence summary."""
        details = results.get('details', {})
        
        content = (
            f"[dim]└─[/dim] [bold]target:[/bold]  {results['domain']}\n"
            f"[dim]└─[/dim] [bold]ip:[/bold]      {results['ip']}\n"
            f"[dim]└─[/dim] [bold]status:[/bold]  {self._format_scanAI_status(results['status'])}\n"
            f"[dim]└─[/dim] [bold]id:[/bold]      {result_storage.get_last_result_id()}"
        )
        
        self._print_scanAI_header("INTELLIGENCE BRIEFING")
        panel = Panel(content, border_style="dim", box=box.ROUNDED, padding=(1, 2))
        self.console.print(panel)

    def _display_detailed_scanAI_modules(self, results: Dict[str, Any]) -> None:
        """Display detailed module results in scanAI OS style."""
        details = results.get('details', {})
        
        # Create module cards for other components (scanAI OS colors)
        modules = []
        
        if 'virustotal' in details and details['virustotal']:
            modules.append(self._create_scanAI_module_card("VIRUSTOTAL", details["virustotal"], "threat_analysis"))
        
        if 'urlscan' in details and details['urlscan']:
            modules.append(self._create_scanAI_module_card("URLSCAN ANALYSIS", details['urlscan'], "web_analysis"))
        
        if 'katana' in details and details['katana']:
            modules.append(self._create_scanAI_module_card("KATANA", details['katana'], "katana"))
            
        # Use 'subdomain' key (scanner name) not 'subdomains'
        if 'subdomain' in details and details['subdomain']:
            subdomain_data = details['subdomain']  # Already the data dict
            if isinstance(subdomain_data, dict):
                subdomains_list = subdomain_data.get('subdomains', [])
                modules.append(self._create_scanAI_module_card("SUBDOMAINS", {"subdomains": subdomains_list}, "enumeration"))
        
        if 'whois' in details and details['whois']:
            modules.append(self._create_scanAI_module_card("WHOIS", details['whois'], "domain_info"))
        
        if 'dns' in details and details['dns']:
            modules.append(self._create_scanAI_module_card("DNS", details['dns'], "dns_info"))

        # Only print header if we have something to show
        all_scanner_keys = [
            'nmap', 'cves', 'nuclei', 'dalfox', 'ip_geo', 'gobuster', 'ssl',
            'subdomain', 'dns', 'katana', 'sqlmap', 'nikto', 'harvester',
            'waf', 'wpscan', 'wayback', 'enum4linux', 'whois', 'whatweb',
            'server_headers', 'virustotal', 'urlscan',
        ]
        has_any_results = any(k in details and details[k] for k in all_scanner_keys) or modules
        
        if has_any_results:
            self._print_scanAI_header("SECURITY MODULE ANALYSIS")
            
            # Display Nmap Table if available (User Requested)
            if 'nmap' in details and details['nmap']:
                 self._display_nmap_results(details['nmap'])

            # Display CVE Table if available (User Requested)
            if 'cves' in details and details['cves']:
                 self._display_cve_results(details['cves'])

            # Display Subdomain detailed results if available
            if 'subdomain' in details and details['subdomain']:
                # subdomain scanner returns the data directly
                self._display_subdomains_results(details['subdomain'])

            # Display Nuclei results if available
            if 'nuclei' in details and details['nuclei']:
                self._display_nuclei_results(details['nuclei'])

            # Display Dalfox results if available
            if 'dalfox' in details and details['dalfox']:
                self._display_dalfox_results(details['dalfox'])
            
            # Display DNS results if available
            if 'dns' in details and details['dns']:
                self._display_dns_results(details['dns'])
            
            # Display SQLMap results if available
            if 'sqlmap' in details and details['sqlmap']:
                self._display_sqlmap_results(details['sqlmap'])

            # Display WHOIS results if available
            if 'whois' in details and details['whois']:
                self._display_whois_results(details['whois'])

            # Display WhatWeb results if available
            if 'whatweb' in details and details['whatweb']:
                self._display_whatweb_results(details['whatweb'])

            # Display Server Headers results if available
            if 'server_headers' in details and details['server_headers']:
                self._display_server_headers_results(details['server_headers'])

            # Display VirusTotal results if available
            if 'virustotal' in details and details['virustotal']:
                self._display_virustotal_results(details['virustotal'])

            # Display URLScan results if available
            if 'urlscan' in details and details['urlscan']:
                self._display_urlscan_results(details['urlscan'])
            
            # Display IP Geo results if available
            if 'ip_geo' in details and details['ip_geo']:
                self._display_ip_geo_results(details['ip_geo'])
            
            # Display Gobuster/Directory enumeration results if available
            if 'gobuster' in details and details['gobuster']:
                self._display_gobuster_results(details['gobuster'])
            
            # Display SSL results if available
            if 'ssl' in details and details['ssl']:
                self._display_ssl_results(details['ssl'])
            
            # Display Crawl results if available
            if 'katana' in details and details['katana']:
                self._display_katana_results(details['katana'])

            # Display new scanner results
            if 'nikto' in details and details['nikto']:
                self._display_nikto_results(details['nikto'])

            if 'harvester' in details and details['harvester']:
                self._display_harvester_results(details['harvester'])

            if 'waf' in details and details['waf']:
                self._display_waf_results(details['waf'])

            if 'wpscan' in details and details['wpscan']:
                self._display_wpscan_results(details['wpscan'])

            if 'wayback' in details and details['wayback']:
                self._display_wayback_results(details['wayback'])

            if 'enum4linux' in details and details['enum4linux']:
                self._display_enum4linux_results(details['enum4linux'])

            if 'titus' in details and details['titus']:
                self._display_titus_results(details['titus'])
            
            # Display modules in columns
            if modules:
                columns = Columns(modules, equal=True, expand=True)
                self.console.print(columns)

    def _extract_module_summary(self, data: Dict[str, Any], card_type: str) -> str:
        """Extract a concise summary from module data for card display."""
        if card_type == "enumeration":  # Subdomains
            subdomains = data.get('subdomains', []) if isinstance(data, dict) else []
            count = len(subdomains) if isinstance(subdomains, list) else 0
            return f"[bright_cyan]{count}[/bright_cyan] subdomains\n[bright_white]Active discovery[/bright_white]"

        elif card_type == "katana":  # Katana Web Crawler
            urls = data.get('total_urls_discovered', 0)
            endpoints = data.get('total_endpoints_discovered', 0)
            return f"[bright_cyan]{urls}[/bright_cyan] URLs discovered\n[bright_white]{endpoints} endpoints found[/bright_white]"

        elif card_type == "vulnerabilities":  # CVEs
            cves = data.get('cves', []) if isinstance(data, dict) else []
            if not isinstance(cves, list):
                cves = []
            count = len(cves)
            critical_count = sum(1 for cve in cves if isinstance(cve, dict) and str(cve.get('severity', '')).upper() == 'CRITICAL')
            return f"[bright_red]{count}[/bright_red] vulnerabilities\n[bright_yellow]{critical_count}[/bright_yellow] critical"

        elif card_type == "domain_info":  # WHOIS
            domain = data.get('domain', 'N/A') if isinstance(data, dict) else 'N/A'
            registrar = data.get('registrar', 'N/A') if isinstance(data, dict) else 'N/A'
            return f"[bright_cyan]Domain: {domain}[/bright_cyan]\n[bright_white]Registrar: {registrar}[/bright_white]"

        elif card_type == "dns_info":  # DNS
            records = data.get('records', {}) if isinstance(data, dict) else {}
            if not isinstance(records, dict):
                records = {}
            total_records = sum(len(records.get(record_type, [])) for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'] if isinstance(records.get(record_type), list))
            return f"[bright_blue]{total_records}[/bright_blue] DNS records\n[bright_white]Complete enumeration[/bright_white]"

        elif card_type == "ssl_info":  # SSL
            cert_data = data.get('data', {}) if isinstance(data, dict) else {}
            if not isinstance(cert_data, dict):
                cert_data = {}
            subject_data = cert_data.get('subject', {})
            subject = subject_data.get('common_name', 'N/A') if isinstance(subject_data, dict) else 'N/A'
            valid = not cert_data.get('has_expired', False)
            status = "[bright_green]✓ Valid[/bright_green]" if valid else "[bright_red]✗ Expired[/bright_red]"
            return f"[bright_white]{subject}[/bright_white]\n{status}"

        else:
            # Generic fallback
            keys = list(data.keys())
            return f"[bright_white]{len(keys)}[/bright_white] data points\n[bright_cyan]Module active[/bright_cyan]"

    def _create_scanAI_module_card(self, title: str, data: Dict[str, Any], card_type: str) -> Panel:
        """Create a scanAI OS themed module card."""
        card_styles = {
            "threat_analysis": ("bright_red", "🛡️"),
            "web_analysis": ("bright_cyan", "🌐"),
            "port_scan": ("bright_green", "🔌"),
            "enumeration": ("bright_magenta", "🔍"),
            "vulnerabilities": ("bright_yellow", "⚠️"),
            "domain_info": ("bright_cyan", "📋"),
            "dns_info": ("bright_blue", "🌐"),
            "ssl_info": ("bright_green", "🔒"),
            "katana": ("bright_cyan", "🕷️")
        }

        color, icon = card_styles.get(card_type, ("bright_white", "⚙️"))

        # Extract summary from data
        summary = self._extract_module_summary(data, card_type)

        return ThemePanel(
            summary,
            title=f"[bold {color}]{icon} {title}[/bold {color}]",
            border_style=color,
            padding=(1, 2),
            width=35,
            style="white on black"
        )

    def _print_scanAI_header(self, text: str) -> None:
        """Print an ScanAI-style left-corner section header."""
        # Strip any Rich markup for length calculation
        import re
        clean_text = re.sub(r'\[.*?\]', '', text)
        line_len = max(60, len(clean_text) + 8)
        self.console.print(f"\n[dim]◇{'─' * 4}[/dim] [bold bright_cyan]{text}[/bold bright_cyan] [dim]{'─' * (line_len - len(clean_text) - 6)}[/dim]")

    def _stream_panel_content(self, title: str, content: str, border_style: str = "dim") -> None:
        """Display content in an ScanAI-style panel with dim borders."""
        self._print_scanAI_header(title)
        panel = Panel(
            content,
            border_style=border_style,
            box=box.ROUNDED,
            padding=(1, 2),
        )
        self.console.print(panel)

    def _stream_table_display(self, table: Table, title: str, border_style: str = "dim") -> None:
        """Display a table with an ScanAI-style header."""
        self._print_scanAI_header(title)
        self.console.print(table)
        self.console.print()

    def _print_section_header(self, text: str) -> None:
        """Print an ScanAI-style section header (alias)."""
        self._print_scanAI_header(text)

    def _get_scanAI_risk_icon(self, risk_level: str) -> str:
        """Get icon for risk level in scanAI OS style."""
        icons = {
            'LOW': '[bright_green]✓[/bright_green]',
            'MEDIUM': '[bright_yellow]⚠[/bright_yellow]',
            'HIGH': '[bright_red]✗[/bright_red]',
            'CRITICAL': '[bright_red]🔥[/bright_red]'
        }
        return icons.get(risk_level.upper(), '[bright_white]?[/bright_white]')

    def _display_specific_action_results(self, action: str, results: Dict[str, Any], target: str, original_query: str = "") -> None:
        """Display results for specific actions with scanAI OS intelligence overview."""
        # First show Target Intelligence and Threat Assessment
        
        # Main header
        self._print_scanAI_header(f"SECURITY REPORT: [bold bright_green]{results['target']}[/bold bright_green]")
        
        # Quick stats in columns - scanAI OS style
        stats_panel = self._create_scanAI_stats_panel(results)
        self.console.print(stats_panel)

        self._display_scanAI_risk_assessment(results)
        self._display_scanAI_intelligence_summary(results)

        # Then show the specific requested results
        self._print_scanAI_header(f"REQUESTED ANALYSIS: {action.upper().replace('_', ' ')}")

        details = results.get('details', {})

        # Route to appropriate display method
        if action == 'subdomain_enum' and 'subdomains' in details:
            self._display_subdomains_results(details['subdomains'])
        elif action == 'port_scan' and 'nmap' in details:
            self._display_nmap_results(details['nmap'])
        elif action == 'vuln_scan' or action == 'cve_scan':
            if 'cves' in details:
                self._display_cve_results(details['cves'])
        elif action == 'ssl_scan':
            self._display_ssl_via_ai(target)
        elif action == 'ssl' and 'ssl' in details:
            self._display_ssl_results(details['ssl'])
        elif action == 'crawl_scan' and 'katana' in details:
            self._display_katana_results(details['katana'])
        elif action == 'dns_enum' and 'dns' in details:
            self._display_dns_results(details['dns'])
        elif action == 'whois_lookup' and 'whois' in details:
            self._display_whois_results(details['whois'])
        elif action == 'tech_detect' and 'whatweb' in details:
            self._display_whatweb_results(details['whatweb'])
        elif action == 'dir_enum' and 'gobuster' in details:
            self._display_gobuster_results(details['gobuster'])
        elif action == 'http_headers' and 'server_headers' in details:
            self._display_server_headers_results(details['server_headers'])
        elif action == 'analyze_previous':
            self._display_previous_analysis_results(results, original_query)
        elif action == 'exploit_guidance':
            # Handle exploitation guidance request
            self._display_exploitation_guidance(results, original_query)
        else:
            info_panel = ThemePanel(
                f"[bright_yellow]No specific results available for this action.[/bright_yellow]\n\n"
                f"Try comprehensive reconnaissance: [bright_green]scan {target}[/bright_green]",
                title="INFORMATION",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(info_panel)

        # Always provide AI analysis for specific scans too
        if self.scanai_service:
            with self.console.status("[bold bright_magenta]Agent analyzing findings and generating insights...[/bold bright_magenta]"):
                # Use a specific prompt context for the action
                query_context = f"Analyze these specific {action} findings for {target}. Provide security insights and recommendations."
                ai_response = self.scanai_service.generate_hacking_guidance(query_context, target)
            
            if ai_response.get('success'):
                ai_panel = ThemePanel(
                    Markdown(ai_response['response']),
                    title="NEURAL SYNTHESIS",
                    border_style="bright_magenta",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(ai_panel)

        # ALWAYS print ELITE HACKING INTELLIGENCE last if it exists
        self._display_pro_report(results)
    def _display_comprehensive_results(self, results: Dict[str, Any]) -> None:
        """Display comprehensive scan results."""
        self._display_scanAI_results(results, show_detailed=True)
        
        # Show AI insights if available
        if self.scanai_service:
            with self.console.status("[bold bright_magenta]�� Agent deriving security insights...[/bold bright_magenta]"):
                ai_response = self.scanai_service.explain_scan_results(results, "Provide security insights and recommendations in hacker style")
            
            if ai_response.get('success'):
                ai_panel = ThemePanel(
                    Markdown(ai_response['response']),
                    title="NEURAL SYNTHESIS",
                    border_style="bright_magenta",
                    padding=(1, 2),
                    style="white on black"
                )
                self.console.print(ai_panel)

        # ALWAYS print ELITE HACKING INTELLIGENCE last if it exists
        self._display_pro_report(results)

    def _check_config(self) -> bool:
        """Check if configuration is valid."""
        missing_keys = config.get_missing_keys()

        if missing_keys:
            warning_panel = ThemePanel(
                "[bright_yellow] Warning: Some API keys are not configured:[/bright_yellow]\n\n"
                f"{chr(10).join(f'   - [bright_cyan]{key.upper()}[/bright_cyan]' for key in missing_keys)}\n\n"
                "Run 'scanai config --init' to create a configuration template",
                title="CONFIGURATION",
                border_style="bright_yellow",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(warning_panel)

        return True

    def _display_subdomains_results(self, subdomains_data: Dict[str, Any]) -> None:
        """Display subdomain enumeration results with scanAI OS UI."""
        raw_subdomains = subdomains_data.get('subdomains', [])
        domain = subdomains_data.get('domain', 'unknown')
        message = subdomains_data.get('message', '')

        if not raw_subdomains:
            # Hacker-style explanation
            if message:
                explanation = message
            else:
                explanation = "No subdomains found in Certificate Transparency logs."

            helpful_tips = [
                "• Certificate Transparency logs only show SSL/TLS certified subdomains",
                "• New domains or HTTP-only sites won't appear",
                "• Try domains like 'google.com' or 'github.com'",
                "• Use additional reconnaissance techniques for full coverage"
            ]

            tips_text = "\n".join(f"[bright_cyan]• {tip}[/bright_cyan]" for tip in helpful_tips)

            self._print_scanAI_header("SUBDOMAIN RECONNAISSANCE")
            self.console.print(Panel(
                f"[bright_yellow]No subdomains found for {domain}[/bright_yellow]\n\n"
                f"[dim]{explanation}[/dim]\n\n"
                f"[bold bright_cyan]Reconnaissance Notes:[/bold bright_cyan]\n{tips_text}",
                border_style="dim",
                box=box.ROUNDED,
                padding=(1, 2),
            ))
            return

        # Flatten and deduplicate
        flattened_subs = []
        for item in raw_subdomains:
            if isinstance(item, str):
                subs = [s.strip() for s in item.split('\n') if s.strip()]
                flattened_subs.extend(subs)
            else:
                flattened_subs.append(str(item))

        unique_subdomains = sorted(list(set(flattened_subs)))
        
        from rich.tree import Tree
        from rich.live import Live
        import time
        
        # Create Tree with sub-node points
        tree = Tree(f"[bold bright_cyan]{domain}[/bold bright_cyan]")
        
        # Limit to 50 subdomains for readable tree display
        display_limit = 50
        
        # Stream the discovery
        self._print_scanAI_header(f"SUBDOMAIN DISCOVERY ({len(unique_subdomains)})")
        with Live(console=self.console, refresh_per_second=20) as live:
            for sub in unique_subdomains[:display_limit]:
                tree.add(f"[bright_green]{sub}[/bright_green]")
                live.update(Panel(
                    tree,
                    border_style="dim",
                    box=box.ROUNDED,
                    padding=(1, 2),
                ))
                time.sleep(0.06)
                
            if len(unique_subdomains) > display_limit:
                tree.add(f"[dim]... and {len(unique_subdomains) - display_limit} more discovered[/dim]")
                live.update(Panel(
                    tree,
                    border_style="dim",
                    box=box.ROUNDED,
                    padding=(1, 2),
                ))
                time.sleep(0.12)

        # # Pro Raw Output (The "Full Raw Result" request)
        # raw_data = subdomains_data.get('raw_data')
        # if raw_data:
        #     import json
        #     pretty_json = json.dumps(raw_data, indent=2)
        #     # Truncate if too long for CLI
        #     if len(pretty_json) > 5000:
        #         pretty_json = pretty_json[:5000] + "\n\n[... output truncated for readability ...]"
            
        #     raw_panel = ThemePanel(
        #         pretty_json,
        #         title="PRO SUBDOMAIN RECON OUTPUT",
        #         border_style="dim",
        #         padding=(1, 2),
        #         style="dim white on black"
        #     )
        #     self.console.print(raw_panel)

    def _display_nmap_results(self, nmap_data: Dict[str, Any]) -> None:
        """Display Nmap scan results with detailed service information."""
        all_ports = nmap_data.get('ports', [])
        open_ports = [port for port in all_ports if isinstance(port, dict) and port.get('state') == 'open']
        os_fingerprint = nmap_data.get('os_fingerprint', '')
        target = nmap_data.get('target', 'Unknown')

        if not open_ports:
            self._print_scanAI_header("PORT SCAN RESULTS")
            self.console.print(Panel(
                "[bright_green]\u2713 No open ports found[/bright_green]\n\n"
                "[dim]Target appears secure or protected by firewall.[/dim]",
                border_style="dim",
                box=box.ROUNDED,
                padding=(1, 2),
            ))
            return

        # Create detailed port table with full service info
        port_table = Table(
            title=f"[bright_cyan]OPEN PORTS :: {target}[/bright_cyan]",
            show_header=True,
            header_style="bold bright_cyan",
            border_style="dim",
            box=box.ROUNDED,
            expand=True
        )
        port_table.add_column("Port", style="bold bright_white", width=8, justify="center")
        port_table.add_column("Proto", style="bright_blue", width=6, justify="center")
        port_table.add_column("Service", style="bold bright_green", width=12)
        port_table.add_column("Version / Banner", style="bright_yellow", ratio=2)
        port_table.add_column("Risk", style="bright_red", width=10, justify="center")
        
        for port in open_ports[:20]:  # Show up to 20 ports
            if not port or not isinstance(port, dict):
                continue
            
            port_num = port.get('port', '')
            protocol = port.get('protocol', 'tcp').upper()
            service = str(port.get('service', 'unknown') or 'unknown').title()
            
            # Get full version info - prefer full_version if available
            version = port.get('full_version', '') or port.get('version', '') or port.get('extra_info', '')
            if not version and port.get('software_name'):
                version = port.get('software_name', '')
                if port.get('version'):
                    version = f"{version} {port.get('version')}"
            
            # Truncate very long versions but keep meaningful info
            if len(version) > 50:
                version = version[:47] + "..."
            
            # Convert port_num to int, handling potential non-integer values
            try:
                port_num_int = int(port_num)
            except (ValueError, TypeError):
                port_num_int = 0
            
            risk_label = self._assess_port_risk(port_num_int, service)
            
            port_table.add_row(
                str(port_num), 
                protocol, 
                service, 
                version or "[dim]Unknown[/dim]",
                risk_label
            )
        
        self._print_scanAI_header(f"NMAP PORT ANALYSIS  [dim]OS: {os_fingerprint or 'Unknown'}[/dim]")
        self.console.print(port_table)

        # Pro Raw Output (Full Nmap Output)
        raw_output = nmap_data.get('raw_output')
        if raw_output:
            self._stream_panel_content("RAW NMAP OUTPUT", raw_output.strip(), "dim")
        
        # Services summary for potential CVE scanning
        services = nmap_data.get('services', [])
        if services:
            service_list = []
            for svc in services[:10]:
                if isinstance(svc, dict):
                    name = svc.get('name', 'unknown')
                    ver = svc.get('version', '')
                    port = svc.get('port', '')
                    if ver:
                        service_list.append(f"[bright_green]{name}[/bright_green] [bright_yellow]{ver}[/bright_yellow] [dim](:{port})[/dim]")
                    else:
                        service_list.append(f"[bright_green]{name}[/bright_green] [dim](:{port})[/dim]")
            
            if service_list:
                services_text = " • ".join(service_list)
                self._stream_panel_content("DETECTED SOFTWARE", services_text, "dim bright_yellow")
        
        # Summary stats
        high_risk_ports = sum(1 for p in open_ports if isinstance(p, dict) and self._assess_port_risk(int(p.get('port', 0)) if p.get('port') else 0, str(p.get('service', ''))).startswith('[bright_red]'))
        
        summary_text = (
            f"• Open ports: [bright_red]{len(open_ports)}[/bright_red]\n"
            f"• High-risk services: [bright_yellow]{high_risk_ports}[/bright_yellow]\n"
            f"• Host status: [bright_green]{nmap_data.get('host_status', 'up')}[/bright_green]"
        )
        self._stream_panel_content("SCAN SUMMARY", summary_text, "dim")

    def _display_cve_results(self, cve_data: Dict[str, Any]) -> None:
        """Display CVE vulnerability results with scanAI OS UI."""
        cves = cve_data.get('cves', [])

        if not cves:
            self._print_scanAI_header("VULNERABILITY SCAN")
            self.console.print(Panel(
                "[bright_green]\u2713 No vulnerabilities found[/bright_green]\n\n"
                "[dim]No CVEs detected in scanned systems.[/dim]",
                border_style="dim",
                box=box.ROUNDED,
                padding=(1, 2),
            ))
            return

        # Count by severity
        severity_counts = {}
        for cve in cves:
            if not cve or not isinstance(cve, dict):
                continue
            severity = cve.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary_text = ""
        for severity, count in sorted(severity_counts.items()):
            color = {
                'CRITICAL': 'bright_red',
                'HIGH': 'bright_red',
                'MEDIUM': 'bright_yellow',
                'LOW': 'bright_green',
                'UNKNOWN': 'bright_white'
            }.get(severity, 'bright_white')
            summary_text += f"• [{color}]{severity}[/{color}]: {count}\n"
        
        self._stream_panel_content("VULNERABILITY SUMMARY", summary_text, "bright_yellow")
        
        # Show top CVEs with full details
        if cves:
            self.console.print("\n[bold bright_red]VULNERABILITY DETAILS[/bold bright_red]\n")
            
            # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
            sorted_cves = sorted(cves[:15], key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN'), 5) if isinstance(x, dict) else 5)
            
            for cve in sorted_cves:
                if not cve or not isinstance(cve, dict):
                    continue
                    
                cve_id = cve.get('id') or cve.get('cve') or 'Unknown'
                severity = cve.get('severity', 'UNKNOWN')
                
                # ... existing logic to gather data ...
                cvss_v3 = cve.get('cvss_v3')
                score = x = cve.get('cvss', 'N/A')
                vector = ''
                if isinstance(cvss_v3, dict):
                    score = cvss_v3.get('baseScore', 'N/A')
                    vector = cvss_v3.get('vectorString', '')
                
                description = cve.get('description') or cve.get('summary') or 'No description available.'
                affected = cve.get('detected_software', {})
                affected_str = ""
                if isinstance(affected, dict):
                    sw_name = affected.get('name', '')
                    sw_ver = affected.get('version', '')
                    if sw_name:
                        affected_str = f"\n[bright_cyan]Affected:[/bright_cyan] {sw_name} {sw_ver}".strip()
                
                refs = cve.get('references', [])
                refs_str = ""
                if refs and isinstance(refs, list):
                    exploit_refs = [r.get('url', '') for r in refs[:3] if isinstance(r, dict) and r.get('url')]
                    if exploit_refs:
                        refs_str = "\n[bright_yellow]References:[/bright_yellow]\n  • " + "\n  • ".join(exploit_refs)
                
                severity_colors = {'CRITICAL': 'bright_red', 'HIGH': 'bright_red', 'MEDIUM': 'bright_yellow', 'LOW': 'bright_green', 'UNKNOWN': 'bright_white'}
                color = severity_colors.get(severity, 'bright_white')
                
                cve_content = (
                    f"[{color}]Severity: {severity}  |  CVSS: {score}[/{color}]\n"
                    f"{f'[dim]{vector}[/dim]' if vector else ''}\n\n"
                    f"[bright_white]{description}[/bright_white]"
                    f"{affected_str}"
                    f"{refs_str}"
                )
                
                self._stream_panel_content(f"{cve_id}", cve_content, color)

    def _display_nuclei_results(self, nuclei_data: Dict[str, Any]) -> None:
        """Display Nuclei vulnerability results with scanAI OS UI."""
        findings = nuclei_data.get('findings', [])
        target = nuclei_data.get('target', 'N/A')

        if not findings:
            self._print_scanAI_header("NUCLEI SCAN")
            self.console.print(Panel(
                "[bright_green]\u2713 No template matches found[/bright_green]\n\n"
                "[dim]Nuclei didn't detect any known vulnerabilities on this target.[/dim]",
                border_style="dim",
                box=box.ROUNDED,
                padding=(1, 2),
            ))
            return

        # Create Nuclei findings table
        nuclei_table = Table(
            title=f"NUCLEI FINDINGS FOR {target}",
            box=box.ROUNDED,
            border_style="dim",
            title_style="bold",
            header_style="bold bright_white",
            expand=True
        )
        nuclei_table.add_column("Template ID", style="bright_cyan")
        nuclei_table.add_column("Name", style="bright_white")
        nuclei_table.add_column("Severity", justify="center")
        nuclei_table.add_column("Type", style="bright_yellow")

        for finding in findings:
            info = finding.get('info', {})
            template_id = finding.get('template-id', 'N/A')
            name = info.get('name', 'N/A')
            severity = info.get('severity', 'info').upper()
            vuln_type = finding.get('type', 'N/A')

            color = {
                'CRITICAL': 'bright_red',
                'HIGH': 'bright_red',
                'MEDIUM': 'bright_yellow',
                'LOW': 'bright_green',
                'INFO': 'bright_blue'
            }.get(severity, 'bright_white')

            nuclei_table.add_row(
                f"[bold]{template_id}[/bold]",
                name,
                f"[{color}]{severity}[/{color}]",
                vuln_type
            )

        self._print_scanAI_header("NUCLEI VULNERABILITIES")
        self.console.print(nuclei_table)

        # Pro Raw Output (Full Nuclei Output)
        raw_output = nuclei_data.get('raw_output')
        if raw_output:
            self._stream_panel_content("RAW NUCLEI OUTPUT", raw_output.strip(), "dim")

    def _display_dalfox_results(self, dalfox_data: Dict[str, Any]) -> None:
        """Display Dalfox XSS scan results with scanAI OS UI."""
        findings = dalfox_data.get('findings', [])
        target = dalfox_data.get('target', 'N/A')

        if not findings:
            self._print_scanAI_header("DALFOX XSS SCAN")
            self.console.print(Panel(
                "[bright_green]\u2713 No XSS vulnerabilities found[/bright_green]\n\n"
                "[dim]Dalfox did not detect any cross-site scripting issues.[/dim]",
                border_style="dim",
                box=box.ROUNDED,
                padding=(1, 2),
            ))
            return

        # Create Dalfox findings table
        dalfox_table = Table(
            title=f"[bright_red]DALFOX XSS FINDINGS FOR {target}[/bright_red]",
            box=box.ROUNDED,
            border_style="dim",
            title_style="bold",
            header_style="bold bright_white",
            expand=True
        )
        dalfox_table.add_column("Type", style="bright_red")
        dalfox_table.add_column("Payload", style="bright_yellow")
        dalfox_table.add_column("Parameter", style="bright_cyan")
        dalfox_table.add_column("Evidence", style="bright_white")

        for finding in findings:
            vuln_type = finding.get('type', 'XSS')
            payload = finding.get('payload', 'N/A')
            param = finding.get('param', 'N/A')
            evidence = finding.get('evidence', 'N/A')

            dalfox_table.add_row(
                vuln_type,
                payload,
                param,
                evidence[:40] + "..." if len(str(evidence)) > 40 else str(evidence)
            )

        self._print_scanAI_header("DALFOX VULNERABILITIES")
        self.console.print(dalfox_table)

        # Pro Raw Output (Full Dalfox Output)
        raw_output = dalfox_data.get('raw_output')
        if raw_output:
            self._stream_panel_content("RAW DALFOX OUTPUT", raw_output.strip(), "dim")


    def _display_ssl_via_ai(self, target: str) -> None:
        """Display SSL certificate information."""
        self._stream_panel_content(
            "SSL CERTIFICATE",
            f"[bold]SSL Certificate Analysis for:[/bold] [bright_cyan]{target}[/bright_cyan]\n\n"
            f"[bright_yellow]SSL certificate analysis requires direct connection[/bright_yellow]\n\n"
            f"[dim]For comprehensive SSL analysis, use:[/dim]\n"
            f"[bright_green]  SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d={target}[/bright_green]\n"
            f"[bright_green]  Qualys SSL Test[/bright_green]\n"
            f"[bright_green]  DigiCert SSL Checker[/bright_green]",
            "dim"
        )

    def _display_sqlmap_results(self, sqli_data: Dict[str, Any]) -> None:
        """Display SQLMap injection scan results with styled panels."""
        if not sqli_data:
            return

        injectable = sqli_data.get('injectable', False)
        # Handle both list (scanner output) and dict formats if necessary, 
        # but usually it's the data dict from _create_result
        data = sqli_data.get('data', sqli_data) if isinstance(sqli_data, dict) else {}
        
        target = data.get('target', 'Unknown')
        dbms = data.get('dbms', 'N/A')
        current_user = data.get('current_user', 'N/A')
        databases = data.get('databases', [])
        techniques = data.get('techniques', [])
        
        if injectable:
            status_text = f"[bold bright_red]Target is INJECTABLE![/bold bright_red]\n"
            status_text += f"[bright_white]DBMS:[/bright_white] [bold green]{dbms}[/bold green]\n"
            status_text += f"[bright_white]User:[/bright_white] {current_user}\n"
            
            if techniques:
                status_text += "\n[bold bright_yellow]Detected Techniques:[/bold bright_yellow]\n"
                for i, tech in enumerate(techniques, 1):
                    type_str = tech.get('type', 'Unknown')
                    title = tech.get('title', 'N/A')
                    status_text += f" {i}. [bold cyan]{type_str}[/bold cyan] - {title}\n"
            
            if databases:
                dbs_str = ", ".join(databases)
                status_text += f"\n[bold bright_cyan]Available Databases ({len(databases)}):[/bold bright_cyan]\n {dbs_str}"

            self._stream_panel_content(f"SQLMap Vulnerability: {target}", status_text, "dim")
        else:
            self._stream_panel_content(
                "SQLMap Scan Result",
                f"[bright_green]No SQL injection vulnerabilities were identified on {target}.[/bright_green]\n"
                f"[dim]Note: sqlmap tested with level=3 and risk=2.[/dim]",
                "dim"
            )


    def _display_dns_results(self, dns_data: Dict[str, Any]) -> None:
        """Display exhaustive DNS enumeration results."""
        if not dns_data:
            return

        records = dns_data.get('records', {})
        subdomains = dns_data.get('subdomains', [])
        domain = dns_data.get('domain', 'unknown')
        method = dns_data.get('method', 'unknown')
        raw_output = dns_data.get('output', '')

        # Defensive check: if records is a list (legacy/incorrect format), convert it
        if isinstance(records, list):
            categorized = {}
            for r in records:
                if isinstance(r, dict):
                    rtype = r.get('type', 'Unknown').upper()
                    if rtype not in categorized:
                        categorized[rtype] = []
                    # Ensure it has a value key for display
                    if 'value' not in r:
                        r['value'] = r.get('address') or r.get('exchange') or r.get('nameserver') or str(r)
                    categorized[rtype].append(r)
            records = categorized

        method_info = f" [dim](via {method})[/dim]" if method != 'unknown' else ""
        self._print_section_header(f"DNS INTELLIGENCE REPORT: [bold cyan]{domain}[/bold cyan]{method_info}")

        if records:
            # 1. Infrastructure Records (SOA, NS)
            infra_table = Table.grid(expand=True)
            infra_table.add_column(style="dim", width=12)
            infra_table.add_column(style="bright_white")
            
            has_infra = False
            for rtype in ['SOA', 'NS']:
                rlist = records.get(rtype, [])
                if rlist:
                    has_infra = True
                    vals = "\n".join([r.get('value', 'N/A') for r in rlist])
                    infra_table.add_row(f"{rtype}:", vals)
            
            if has_infra:
                from rich.live import Live
                import time
                with self.console.status("[bold bright_magenta]Decoding DNS Infrastructure...[/bold bright_magenta]", spinner="dots8"):
                    time.sleep(0.3)
                    self.console.print(Panel(infra_table, title="[bold bright_magenta]INFRASTRUCTURE[/bold bright_magenta]", border_style="dim", box=box.ROUNDED, padding=(1, 2)))

            # 2. Mail Servers (MX)
            mx_list = records.get('MX', [])
            if mx_list:
                mx_table = Table.grid(expand=True)
                mx_table.add_column(style="dim", width=12)
                mx_table.add_column(style="bright_cyan")
                for r in mx_list:
                    pref = r.get('preference', '10')
                    mx_table.add_row(f"MX ({pref}):", r.get('value', 'N/A'))
                with self.console.status("[bold bright_cyan]Decoding DNS Mail Servers...[/bold bright_cyan]", spinner="dots8"):
                    time.sleep(0.3)
                    self.console.print(Panel(mx_table, title="[bold bright_cyan]MAIL SERVERS[/bold bright_cyan]", border_style="dim", box=box.ROUNDED, padding=(1, 2)))

            # 3. Host Records (A, AAAA, CNAME, TXT)
            host_table = Table(box=None, expand=True, show_header=True, border_style="dim")
            host_table.add_column("Type", style="bold yellow", width=8)
            host_table.add_column("Value", style="bright_white")
            
            has_hosts = False
            for rtype in ['A', 'AAAA', 'CNAME', 'TXT']:
                rlist = records.get(rtype, [])
                for r in rlist:
                    has_hosts = True
                    val = r.get('value', 'N/A')
                    # Don't truncate TXT records as they often contain sensitive info (SPF, etc.)
                    host_table.add_row(rtype, val)
            
            if has_hosts:
                with self.console.status("[bold bright_yellow]Decoding Host Records...[/bold bright_yellow]", spinner="dots8"):
                    time.sleep(0.3)
                    self.console.print(Panel(host_table, title="HOST RECORDS", border_style="dim", box=box.ROUNDED, padding=(1, 2)))

        # 4. Subdomains Discovery
        if subdomains:
            sub_table = Table(box=None, expand=True, show_header=True)
            sub_table.add_column("#", style="dim", width=4)
            sub_table.add_column("Subdomain", style="bright_green")
            
            # Show up to 20 subdomains
            for i, sub in enumerate(subdomains[:20], 1):
                sub_table.add_row(str(i), sub)
            
            footer = ""
            if len(subdomains) > 20:
                footer = f"\n[dim]... and {len(subdomains)-20} more discovered[/dim]"

            with self.console.status("[bold bright_green]Decoding Discovered Subdomains...[/bold bright_green]", spinner="dots8"):
                time.sleep(0.3)
                self.console.print(Panel(Group(sub_table, footer), title=f"[bold bright_green]DISCOVERED SUBDOMAINS ({len(subdomains)})[/bold bright_green]", border_style="dim", box=box.ROUNDED, padding=(1, 2)))

        # 5. Raw Output (The "Full Raw" request)
        if raw_output:
            # Clean up output (remove banners if possible or just show it)
            clean_output = raw_output.strip()
            # Truncate if extreme, but usually output is manageable
            if len(clean_output) > 5000:
                clean_output = clean_output[:5000] + "\n\n[bold red]-- OUTPUT TRUNCATED DUE TO SIZE --[/bold red]"
                
            self._stream_panel_content("DNS ENUMERATION OUTPUT", f"[dim]{clean_output}[/dim]", "bright_white")

        # Summary statistics
        total_records = sum(len(records.get(rt, [])) for rt in records)
        stats = {
            "DNS Records Found": str(total_records),
            "Subdomains Discovered": str(len(subdomains)),
            "Target Domain": domain,
            "Enumeration Tool": method
        }

        stats_text = self._format_multiline_stats(stats, "DNS ENUMERATION SUMMARY")
        self.console.print()
        self.console.print(stats_text)
        self._add_section_spacing()

    def _display_whois_results(self, whois_data: Dict[str, Any]) -> None:
        """Display WHOIS lookup results with scanAI OS UI."""
        content = (
            f"[bold]Domain Intelligence:[/bold] [bright_cyan]{whois_data.get('domain', 'N/A')}[/bright_cyan]\n\n"
            f"• Registrar: [bright_white]{whois_data.get('registrar', 'N/A')}[/bright_white]\n"
            f"• Created: [bright_white]{whois_data.get('creation_date', 'N/A')}[/bright_white]\n"
            f"• Expires: [bright_white]{whois_data.get('expiration_date', 'N/A')}[/bright_white]\n"
            f"• Updated: [bright_white]{whois_data.get('updated_date', 'N/A')}[/bright_white]\n\n"
            f"[dim bright_cyan]Name Servers:[/dim bright_cyan] {', '.join(whois_data.get('name_servers', ['N/A'])[:3])}"
        )
        self._stream_panel_content("WHOIS LOOKUP", content, "bright_magenta")

        # Pro Raw Output (WHOIS Raw)
        raw_output = whois_data.get('raw_output')
        if raw_output:
            raw_panel = ThemePanel(
                raw_output.strip(),
                title="PRO WHOIS REGISTRY DATA",
                border_style="dim",
                padding=(1, 2),
                style="dim white on black"
            )
            self.console.print(raw_panel)

    def _display_whatweb_results(self, whatweb_data: Dict[str, Any]) -> None:
        """Display technology detection results with scanAI OS UI."""
        technologies = whatweb_data.get('technologies', {})

        if not technologies:
            self._stream_panel_content(
                "TECHNOLOGY DETECTION",
                "[bright_yellow]No technologies detected[/bright_yellow]\n\n"
                "[dim]Site may use custom or uncommon technologies.[/dim]",
                "dim"
            )

        # Create Technologies Table
        tech_table = Table(
            title=f"[bright_cyan]DETECTED WEB TECHNOLOGIES[/bright_cyan]",
            show_header=True,
            header_style="bold bright_cyan",
            border_style="dim",
            box=box.ROUNDED,
            expand=True
        )
        tech_table.add_column("Category", style="bright_white")
        tech_table.add_column("Technology", style="bright_green")
        
        for category, tech in technologies.items():
            tech_table.add_row(category, tech)
            
        self._print_scanAI_header("TECHNOLOGY STACK")
        self.console.print(tech_table)

        # Pro Raw Output (WhatWeb Raw)
        raw_data = whatweb_data.get('raw_data')
        if raw_data:
            import json
            raw_panel = ThemePanel(
                json.dumps(raw_data, indent=2),
                title="RAW TECHNOLOGY DETECTION DATA",
                border_style="dim",
                padding=(1, 2),
                style="dim white on black"
            )
            self.console.print(raw_panel)

    def _display_server_headers_results(self, headers_data: Dict[str, Any]) -> None:
        """Display HTTP headers analysis with scanAI OS UI."""
        headers = headers_data.get('headers', {})
        detected_software = headers_data.get('detected_software', [])
        status_code = headers_data.get('status_code', 'N/A')
        
        if not headers:
            self._stream_panel_content(
                "HTTP ANALYSIS FAILED",
                "[bright_red]No HTTP headers could be retrieved.[/bright_red]\n"
                "[dim]Target may be unreachable or blocking requests.[/dim]",
                "dim"
            )
            return

        # Determine status color
        status_color = "bright_green"
        if str(status_code).startswith('4'):
            status_color = "bright_yellow"
        elif str(status_code).startswith('5'):
            status_color = "bright_red"

        # Create Headers Table
        headers_table = Table(
            show_header=True, 
            header_style="bold bright_cyan", 
            border_style="dim",
            box=box.ROUNDED,
            expand=True,
            title=f"[bold]HTTP RESPONSE HEADERS (Status: [{status_color}]{status_code}[/{status_color}])[/bold]"
        )
        headers_table.add_column("Header Name", style="bright_white")
        headers_table.add_column("Value", style="dim white")

        # Key security headers to highlight
        security_headers = [
            'strict-transport-security', 
            'content-security-policy', 
            'x-frame-options', 
            'x-content-type-options', 
            'referrer-policy',
            'permissions-policy'
        ]

        # Sort headers for better readability
        sorted_headers = sorted(headers.items())

        found_security_headers = []

        for name, value in sorted_headers:
            name_lower = name.lower()
            
            # Formatting logic
            formatted_name = name
            formatted_value = value
            
            if len(formatted_value) > 60:
                formatted_value = formatted_value[:57] + "..."

            if name_lower in security_headers:
                formatted_name = f"[bright_green]{name}[/bright_green]"
                formatted_value = f"[bright_green]{formatted_value}[/bright_green]"
                found_security_headers.append(name)
            elif name_lower in ['server', 'x-powered-by', 'x-generator']:
                formatted_name = f"[bright_yellow]{name}[/bright_yellow]"
                formatted_value = f"[bright_yellow]{formatted_value}[/bright_yellow]"
            
            headers_table.add_row(formatted_name, formatted_value)

        # Print the table panel
        self._print_scanAI_header("HTTP PROTOCOL ANALYSIS")
        self.console.print(headers_table)
        
        # Display missing security headers if any
        missing_headers = [h for h in security_headers if h not in [k.lower() for k in headers.keys()]]
        
        if missing_headers:
            missing_text = "\n".join([f"[dim]\u2514\u2500[/dim] [red]{h}[/red]" for h in missing_headers])
            self._stream_panel_content(
                "MISSING SECURITY HEADERS",
                f"[bold bright_red]Missing Headers:[/bold bright_red]\n\n{missing_text}\n\n"
                "[dim]These headers recommended for defense-in-depth.[/dim]",
                "dim"
            )

        # Pro Raw Output (Full HTTP Headers)
        all_headers_raw = headers_data.get('all_headers_raw', {})
        if all_headers_raw:
            self._stream_panel_content("RAW HTTP HEADERS", json.dumps(all_headers_raw, indent=2), "dim")

        # Software Detection Summary
        if detected_software:
            software_text = "\n".join([
                f"[dim]└─[/dim] [bright_cyan]{tech['name']}[/bright_cyan] {f'v{ver}' if (ver := tech.get('version')) else ''}" 
                for tech in detected_software
            ])
            sw_panel = ThemePanel(
                f"[bold]🛠️  DETECTED TECHNOLOGIES:[/bold]\n\n{software_text}",
                border_style="bright_cyan",
                padding=(0, 2)
            )
            self.console.print(sw_panel)

    def _display_gobuster_results(self, gobuster_data: Dict[str, Any]) -> None:
        """Display directory enumeration results with scanAI OS UI."""
        found_paths = gobuster_data.get('found_paths', [])

        if not found_paths:
            self._stream_panel_content(
                "DIRECTORY ENUMERATION",
                "[bright_green]\u2713 No accessible directories/files found[/bright_green]\n\n"
                "[dim]Web server has proper access controls.[/dim]",
                "dim"
            )
            return

        # Create directory table
        dir_table = Table(
            title="DISCOVERED PATHS",
            show_header=True,
            header_style="bold bright_cyan",
            border_style="dim",
            box=box.ROUNDED,
            expand=True
        )
        dir_table.add_column("Path", style="bright_green")
        dir_table.add_column("Status", style="bright_white", width=6)
        
        for path_info in found_paths[:15]:
            path = path_info.get('path', '')
            status = path_info.get('status_code', '')
            content_type = path_info.get('content_type', '')
            
            # Determine type
            if path.endswith('/'):
                ptype = "Directory"
            elif '.' in path.split('/')[-1]:
                ptype = "File"
            else:
                ptype = "Unknown"
            
            dir_table.add_row(path, str(status), ptype)
        
        # Determine title based on scan mode if available
        scan_mode = gobuster_data.get('scan_mode', 'both')
        title_map = {
            'dir': "FOLDER ENUMERATION",
            'file': "FILE DISCOVERY",
            'both': "DIRECTORY SCAN"
        }
        title_text = title_map.get(scan_mode, "DIRECTORY SCAN")

        self._print_scanAI_header(title_text)
        self.console.print(dir_table)
        
        # Summary
        total_found = len(found_paths)
        self._stream_panel_content(
            "SCAN SUMMARY",
            f"[bold]Summary:[/bold]\n"
            f"[dim]\u2514\u2500[/dim] Accessible paths: [bright_yellow]{total_found}[/bright_yellow]\n"
            f"[dim]\u2514\u2500[/dim] Scan completed successfully",
            "dim"
        )

    def _run_katana_live(self, engine, action: str, target: str, query: str, profile: Optional[str] = None) -> Dict[str, Any]:
        """Run katana crawl with live TUI display showing URLs as they're discovered."""
        import threading

        # Get katana scanner instance and set up live callback
        katana_scanner = self.scan_manager.scanners.get('katana')
        if not katana_scanner:
            self.console.print("[bright_red]✕ Katana scanner not available[/bright_red]")
            return {}

        # Shared state for live display
        live_state = {
            'urls': [],
            'stats': {'urls': 0, 'endpoints': 0, 'js_files': 0, 'apis': 0, 'forms': 0, 'technologies': []},
            'done': False,
            'latest': [],  # Last N URLs for display
        }
        lock = threading.Lock()
        MAX_DISPLAY = 20  # Show last N URLs

        def on_url_found(url: str, stats: dict):
            with lock:
                live_state['stats'] = stats
                live_state['urls'].append(url)
                live_state['latest'].append(url)
                if len(live_state['latest']) > MAX_DISPLAY:
                    live_state['latest'] = live_state['latest'][-MAX_DISPLAY:]

        katana_scanner.set_live_callback(on_url_found)

        # Run the scan in a background thread
        result_holder = [None]

        def run_scan():
            try:
                r = asyncio.run(engine.run_targeted_scan(action, target, query, profile=profile))
                result_holder[0] = r
            except RuntimeError as e:
                if "already running" in str(e) or "current event loop" in str(e):
                    import nest_asyncio
                    nest_asyncio.apply()
                    loop = asyncio.get_event_loop()
                    result_holder[0] = loop.run_until_complete(engine.run_targeted_scan(action, target, query, profile=profile))
                else:
                    result_holder[0] = {}
            finally:
                with lock:
                    live_state['done'] = True

        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()

        # Live display loop
        start_time = time.time()

        def build_live_panel() -> Panel:
            with lock:
                s = live_state['stats']
                elapsed = time.time() - start_time
                latest = live_state['latest'][:]

            # Stats bar
            stats_parts = [
                f"[bold bright_cyan]{s['urls']}[/bold bright_cyan] URLs",
                f"[bold bright_yellow]{s['endpoints']}[/bold bright_yellow] endpoints",
                f"[bold bright_red]{s['apis']}[/bold bright_red] APIs",
                f"[bold bright_magenta]{s['js_files']}[/bold bright_magenta] JS",
                f"[bold bright_green]{s['forms']}[/bold bright_green] forms",
                f"[dim]{elapsed:.0f}s[/dim]",
            ]
            stats_line = " [dim]│[/dim] ".join(stats_parts)

            # Tech detected
            tech_line = ""
            if s.get('technologies'):
                techs = " · ".join(s['technologies'][:8])
                tech_line = f"\n  [dim]Tech:[/dim] [bright_cyan]{techs}[/bright_cyan]"

            # URL stream
            url_lines = []
            for url in latest:
                # Color code by type
                if url.endswith('.js') or '.js?' in url:
                    url_lines.append(f"  [bright_magenta]JS[/bright_magenta]  [dim]{url}[/dim]")
                elif any(p in url for p in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql']):
                    url_lines.append(f"  [bright_red]API[/bright_red] [dim]{url}[/dim]")
                else:
                    url_lines.append(f"  [bright_cyan]URL[/bright_cyan] [dim]{url}[/dim]")

            url_block = "\n".join(url_lines) if url_lines else "  [dim]Waiting for results...[/dim]"

            content = f"  {stats_line}{tech_line}\n\n{url_block}"

            return Panel(
                content,
                title=f"[bold bright_cyan]🕷️ KATANA CRAWLING[/bold bright_cyan] [dim]{target}[/dim]",
                border_style="bright_cyan",
                box=box.ROUNDED,
                padding=(1, 1),
            )

        try:
            with Live(build_live_panel(), console=self.console, refresh_per_second=8, transient=True) as live:
                while not live_state['done']:
                    live.update(build_live_panel())
                    time.sleep(0.125)
                # Final update
                live.update(build_live_panel())
        except KeyboardInterrupt:
            self.console.print("[bright_yellow]⚠ Crawl interrupted[/bright_yellow]")

        scan_thread.join(timeout=5)

        # Clear callback
        katana_scanner.set_live_callback(None)
        katana_scanner._live_callback = None

        return result_holder[0] or {}

    def _display_katana_results(self, katana_data: Dict[str, Any]) -> None:
        """Display Katana web crawl results."""
        if not katana_data:
            return

        total_urls = katana_data.get('total_urls_discovered', 0)
        total_endpoints = katana_data.get('total_endpoints_discovered', 0)
        total_js = katana_data.get('total_js_files', 0)
        total_apis = katana_data.get('total_api_endpoints', 0)
        total_forms = katana_data.get('total_forms_discovered', 0)
        technologies = katana_data.get('technologies_detected', [])
        all_urls = katana_data.get('all_urls', [])
        all_endpoints = katana_data.get('all_endpoints', [])
        all_js = katana_data.get('all_js_files', [])
        all_apis = katana_data.get('all_apis', [])

        # 1. Header
        self._print_scanAI_header(f"KATANA CRAWL INTELLIGENCE  [dim]{katana_data.get('target', 'Target')}[/dim]")

        # 2. Discovery Metrics
        metrics_grid = Table.grid(expand=True)
        metrics_grid.add_column(ratio=1)
        metrics_grid.add_column(ratio=1)
        metrics_grid.add_column(ratio=1)
        metrics_grid.add_row(
            f" [bold bright_green]URLs:[/bold bright_green] [white]{total_urls}[/white]",
            f" [bold bright_yellow]ENDPOINTS:[/bold bright_yellow] [white]{total_endpoints}[/white]",
            f" [bold bright_red]APIs:[/bold bright_red] [white]{total_apis}[/white]"
        )
        metrics_grid.add_row(
            f" [bold bright_magenta]JS FILES:[/bold bright_magenta] [white]{total_js}[/white]",
            f" [bold bright_blue]FORMS:[/bold bright_blue] [white]{total_forms}[/white]",
            f" [bold bright_cyan]PROFILE:[/bold bright_cyan] [white]{katana_data.get('profile_used', 'default')}[/white]"
        )
        self.console.print(Panel(metrics_grid, border_style="dim", box=box.ROUNDED, padding=(1, 1)))

        # 3. Technologies
        if technologies:
            self._print_scanAI_header(f"TECHNOLOGIES DETECTED ({len(technologies)})")
            tech_text = " · ".join(f"[bright_cyan]{t}[/bright_cyan]" for t in technologies)
            self.console.print(Panel(tech_text, border_style="dim", box=box.ROUNDED))

        # 4. API Endpoints
        if all_apis:
            self._print_scanAI_header(f"API ENDPOINTS ({len(all_apis)})")
            api_tree = Tree("[bold bright_red]DISCOVERED APIs[/bold bright_red]")
            for i, api in enumerate(all_apis, 1):
                api_tree.add(f"[bright_red]{i:4d}.[/bright_red] [white]{api}[/white]")
            self.console.print(api_tree)
            self.console.print()

        # 5. JS Files
        if all_js:
            self._print_scanAI_header(f"JAVASCRIPT FILES ({len(all_js)})")
            js_tree = Tree("[bold bright_yellow]JS FILES[/bold bright_yellow]")
            for i, js in enumerate(all_js, 1):
                js_tree.add(f"[yellow]{i:4d}.[/yellow] [white]{js}[/white]")
            self.console.print(js_tree)
            self.console.print()

        # 6. All URLs
        if all_urls:
            self._print_scanAI_header(f"DISCOVERED URLs ({total_urls})")
            url_tree = Tree("[bold bright_cyan]FULL URL LIST[/bold bright_cyan]")
            for i, url in enumerate(all_urls, 1):
                url_tree.add(f"[cyan]{i:4d}.[/cyan] {url}")
            self.console.print(url_tree)
            self.console.print()

        # 7. Endpoints
        if all_endpoints:
            self._print_scanAI_header(f"ENDPOINTS ({total_endpoints})")
            ep_tree = Tree("[bold bright_white]PATH LIST[/bold bright_white]")
            for i, ep in enumerate(all_endpoints, 1):
                ep_tree.add(f"[white]{i:4d}.[/white] [dim]{ep}[/dim]")
            self.console.print(ep_tree)
            self.console.print()

        self._add_section_spacing()

    def _format_scanAI_status(self, status: str) -> str:
        """Format status with scanAI OS colors."""
        status_map = {
            'safe': ('bright_green', '✓ Secure'),
            'malicious': ('bright_red', '✗ Malicious'),
            'suspicious': ('bright_yellow', '⚠ Suspicious'),
            'unknown': ('bright_white', '? Unknown')
        }
        
        color, text = status_map.get(status.lower(), ('bright_white', status.title()))
        return f"[{color}]{text}[/{color}]"

    # Keep other methods that don't need scanAI OS theming
    def _ask_ai_question(self, results: Dict[str, Any], question: str) -> None:
        """Ask AI a question about scan results."""
        if not self.scanai_service:
            error_panel = ThemePanel(
                "[bright_red]✗ AI service not available[/bright_red]",
                title="ERROR",
                border_style="bright_red",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(error_panel)
            return

        with self.console.status("[bold bright_magenta]Neural Agent processing query...[/bold bright_magenta]"):
            response = self.scanai_service.explain_scan_results(results, question)

        if response.get('success'):
            ai_panel = ThemePanel(
                f"[bold bright_cyan]AGENT INSIGHTS[/bold bright_cyan]\n\n{response['response']}",
                title="NEURAL SYNTHESIS",
                border_style="bright_magenta",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(ai_panel)
        else:
            error_panel = ThemePanel(
                f"[bright_red]✗ AI analysis failed: {response.get('error', 'Unknown error')}[/bright_red]",
                title="ERROR",
                border_style="bright_red",
                padding=(1, 2),
                style="white on black"
            )
            self.console.print(error_panel)

    def _output_json(self, results: Dict[str, Any]) -> None:
        """Output results in JSON format."""
        print(json.dumps(results, indent=2, default=str))

    def _assess_port_risk(self, port: int, service: str) -> str:
        """Assess risk level for open ports."""
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            return "[bright_white]Unknown[/bright_white]"

        # High-risk ports
        high_risk_ports = [21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 
                          143, 445, 993, 995, 1433, 1521, 3306, 3389, 
                          5432, 5900, 6379, 8080, 8443]

        service_lower = service.lower() if service else ""

        if port_num in high_risk_ports or any(vuln_service in service_lower for vuln_service in ['ftp', 'telnet', 'smb', 'mssql', 'oracle', 'mysql', 'rdp', 'vnc']):
            return "[bright_red]HIGH[/bright_red]"
        elif port_num in [80, 443, 587]:
            return "[bright_yellow]MEDIUM[/bright_yellow]"
        else:
            return "[bright_green]LOW[/bright_green]"

    def _display_virustotal_results(self, vt_data: Dict[str, Any]) -> None:
        """Display VirusTotal results with scanAI OS UI — enhanced for phishing detection."""
        if not vt_data:
            return

        scan_type = vt_data.get('scan_type', 'url_scan')
        malicious = vt_data.get('malicious_count', 0)
        suspicious = vt_data.get('suspicious_count', 0)

        vt_content = f"[bold]VirusTotal Analysis:[/bold]\n\n"

        # Phishing verdict banner
        if scan_type == 'phishing_check':
            verdict = vt_data.get('phishing_verdict', 'UNKNOWN')
            risk = vt_data.get('phishing_risk', 'UNKNOWN')
            phishing_count = vt_data.get('phishing_detections', 0)

            if risk == 'CRITICAL':
                color = 'bright_red'
                icon = '🚨'
            elif risk == 'HIGH':
                color = 'bright_red'
                icon = '⚠️'
            elif risk == 'MEDIUM':
                color = 'bright_yellow'
                icon = '⚠️'
            else:
                color = 'bright_green'
                icon = '✅'

            vt_content += (
                f"{icon} [bold {color}]VERDICT: {verdict}[/bold {color}]  |  "
                f"RISK: [bold {color}]{risk}[/bold {color}]\n"
                f"• Phishing Detections: [{color}]{phishing_count}[/{color}]\n"
            )

            # Show phishing engines
            phishing_engines = vt_data.get('phishing_engines', [])
            if phishing_engines:
                vt_content += f"\n[bold]Phishing Engines:[/bold]\n"
                for eng in phishing_engines[:5]:
                    vt_content += f"  🔴 {eng.get('engine', '?')}: {eng.get('result', '')}\n"

            # Show malicious engines
            malicious_engines = vt_data.get('malicious_engines', [])
            if malicious_engines:
                vt_content += f"\n[bold]Malicious Detections:[/bold]\n"
                for eng in malicious_engines[:5]:
                    vt_content += f"  🟠 {eng.get('engine', '?')}: {eng.get('result', '')}\n"

            vt_content += "\n"

        # Domain report extras
        if scan_type == 'domain_report':
            categories = vt_data.get('categories', {})
            reputation = vt_data.get('reputation_score', 0)
            registrar = vt_data.get('registrar', 'Unknown')
            vt_content += (
                f"• Reputation Score: [bright_cyan]{reputation}[/bright_cyan]\n"
                f"• Registrar: [bright_white]{registrar}[/bright_white]\n"
            )
            if categories:
                cats = ", ".join(f"{k}: {v}" for k, v in list(categories.items())[:3])
                vt_content += f"• Categories: [bright_white]{cats}[/bright_white]\n"
            vt_content += "\n"

        # IP report extras
        if scan_type == 'ip_report':
            vt_content += (
                f"• IP: [bright_cyan]{vt_data.get('ip', 'N/A')}[/bright_cyan]\n"
                f"• ASN Owner: [bright_white]{vt_data.get('as_owner', 'N/A')}[/bright_white]\n"
                f"• Country: [bright_white]{vt_data.get('country', 'N/A')}[/bright_white]\n"
                f"• Reputation: [bright_cyan]{vt_data.get('reputation_score', 0)}[/bright_cyan]\n\n"
            )

        # Standard stats
        vt_content += (
            f"• Malicious: [bright_red]{malicious}[/bright_red]\n"
            f"• Suspicious: [bright_yellow]{suspicious}[/bright_yellow]\n"
            f"• Harmless: [bright_green]{vt_data.get('harmless_count', 0)}[/bright_green]\n"
            f"• Undetected: [bright_white]{vt_data.get('undetected_count', 0)}[/bright_white]\n"
            f"• Detection Ratio: [bright_cyan]{vt_data.get('detection_ratio', 'N/A')}[/bright_cyan]"
        )

        # Top detections
        top = vt_data.get('top_detections', [])
        if top:
            vt_content += "\n\n[bold]Top Detections:[/bold]\n"
            for det in top[:5]:
                cat_color = 'bright_red' if det.get('category') == 'malicious' else 'bright_yellow'
                vt_content += f"  [{cat_color}]• {det.get('engine', '?')}: {det.get('result', '')}[/{cat_color}]\n"

        self._stream_panel_content("VIRUSTOTAL INTELLIGENCE", vt_content, "bright_magenta")

    def _display_urlscan_results(self, us_data: Dict[str, Any]) -> None:
        """Display URLScan results with scanAI OS UI."""
        if not us_data:
            return

        malicious = us_data.get('malicious', False)
        score = us_data.get('score', 0)

        urlscan_content = (
            f"[bold]URLScan Analysis:[/bold]\n\n"
            f"• Status: {'[bright_red]✗ MALICIOUS[/bright_red]' if malicious else '[bright_green]✓ CLEAN[/bright_green]'}\n"
            f"• Score: [bright_yellow]{score}/100[/bright_yellow]\n"
            f"• Country: [bright_white]{us_data.get('country', 'Unknown')}[/bright_white]\n"
            f"• Server: [bright_cyan]{us_data.get('server', 'Unknown')}[/bright_cyan]"
        )
        self._stream_panel_content("URLSCAN ANALYSIS", urlscan_content, "bright_cyan")

    def _display_ip_geo_results(self, ip_data: Dict[str, Any]) -> None:
        """Display IP geolocation results with scanAI OS UI."""
        # Handle nested data structure from scanner
        if 'data' in ip_data:
            ip_data = ip_data.get('data', {})
        
        geo_data = ip_data.get('ip_geolocation', {})
        internetdb_data = ip_data.get('internetdb', {})
        combined = ip_data.get('combined_analysis', {})
        ip_address = ip_data.get('ip', geo_data.get('ip', 'N/A'))
        
        # Build geolocation section
        geo_content = f"[bold bright_cyan]GEOLOCATION DATA[/bold bright_cyan]\n\n"
        geo_content += f"• [bold]IP Address:[/bold] [bright_white]{ip_address}[/bright_white]\n"
        
        if geo_data and not geo_data.get('error'):
            geo_content += f"• [bold]Country:[/bold] [bright_green]{geo_data.get('country', 'N/A')} ({geo_data.get('country_code', '')})[/bright_green]\n"
            geo_content += f"• [bold]Region:[/bold] [bright_yellow]{geo_data.get('region_name', 'N/A')}[/bright_yellow]\n"
            geo_content += f"• [bold]City:[/bold] [bright_cyan]{geo_data.get('city', 'N/A')}[/bright_cyan]\n"
            geo_content += f"• [bold]ZIP:[/bold] {geo_data.get('zip', 'N/A')}\n"
            geo_content += f"• [bold]Coordinates:[/bold] {geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}\n"
            geo_content += f"• [bold]Timezone:[/bold] {geo_data.get('timezone', 'N/A')}\n\n"
            
            geo_content += f"[bold bright_yellow]🏢 ISP / ORGANIZATION[/bold bright_yellow]\n\n"
            geo_content += f"• [bold]ISP:[/bold] [bright_white]{geo_data.get('isp', 'N/A')}[/bright_white]\n"
            geo_content += f"• [bold]Organization:[/bold] [bright_green]{geo_data.get('org', 'N/A')}[/bright_green]\n"
            geo_content += f"• [bold]AS Number:[/bold] {geo_data.get('as', 'N/A')}\n"
            
            # Flags
            flags = []
            if geo_data.get('proxy'):
                flags.append("[bright_red]Proxy/VPN[/bright_red]")
            if geo_data.get('hosting'):
                flags.append("[bright_yellow]☁️ Hosting Provider[/bright_yellow]")
            if geo_data.get('mobile'):
                flags.append("[bright_blue]📱 Mobile Network[/bright_blue]")
            if flags:
                geo_content += f"\n• [bold]Flags:[/bold] {' | '.join(flags)}\n"
        
        # InternetDB section (Shodan data)
        if internetdb_data and not internetdb_data.get('error'):
            geo_content += f"\n[bold bright_red]SHODAN INTERNETDB[/bold bright_red]\n\n"
            
            # Open ports
            ports = internetdb_data.get('ports', [])
            if ports:
                port_str = ', '.join(map(str, ports[:15]))
                if len(ports) > 15:
                    port_str += f" (+{len(ports) - 15} more)"
                geo_content += f"• [bold]Open Ports ({len(ports)}):[/bold] [bright_red]{port_str}[/bright_red]\n"
            
            # Hostnames
            hostnames = internetdb_data.get('hostnames', [])
            if hostnames:
                host_str = ', '.join(hostnames[:5])
                if len(hostnames) > 5:
                    host_str += f" (+{len(hostnames) - 5} more)"
                geo_content += f"• [bold]Hostnames:[/bold] [bright_cyan]{host_str}[/bright_cyan]\n"
            
            # Vulnerabilities
            vulns = internetdb_data.get('vulns', [])
            if vulns:
                vuln_str = ', '.join(vulns[:5])
                if len(vulns) > 5:
                    vuln_str += f" (+{len(vulns) - 5} more)"
                geo_content += f"• [bold]CVEs ({len(vulns)}):[/bold] [bright_red]{vuln_str}[/bright_red]\n"
            
            # Tags
            tags = internetdb_data.get('tags', [])
            if tags:
                geo_content += f"• [bold]Tags:[/bold] [bright_yellow]{', '.join(tags)}[/bright_yellow]\n"
        
        # Risk analysis
        if combined and combined.get('findings'):
            geo_content += f"\n[bold bright_magenta]RISK ANALYSIS[/bold bright_magenta]\n\n"
            risk_level = combined.get('risk_level', 'low').upper()
            risk_color = 'bright_red' if risk_level in ['HIGH', 'CRITICAL'] else 'bright_yellow' if risk_level == 'MEDIUM' else 'bright_green'
            geo_content += f"• [bold]Risk Level:[/bold] [{risk_color}]{risk_level}[/{risk_color}]\n"
            
            for finding in combined.get('findings', []):
                geo_content += f"• {finding}\n"
        
        self._stream_panel_content("IP INTELLIGENCE", geo_content, "bright_magenta")

        # Pro Raw Output (IP Geo Raw)
        raw_geo = ip_data.get('raw_geo')
        if raw_geo:
            import json
            raw_panel = ThemePanel(
                json.dumps(raw_geo, indent=2),
                title="PRO IP GEOLOCATION RAW DATA",
                border_style="dim",
                padding=(1, 2),
                style="dim white on black"
            )
            self.console.print(raw_panel)

        # Pro Raw Output (InternetDB Raw)
        raw_internetdb = ip_data.get('raw_internetdb')
        if raw_internetdb:
            import json
            raw_panel = ThemePanel(
                json.dumps(raw_internetdb, indent=2),
                title="PRO SHODAN INTERNETDB RAW DATA",
                border_style="dim",
                padding=(1, 2),
                style="dim white on black"
            )
            self.console.print(raw_panel)

    def _display_nikto_results(self, data: Dict[str, Any]) -> None:
        """Display Nikto web vulnerability scan results."""
        findings = data.get('findings', [])
        target = data.get('target', 'N/A')
        
        if not findings:
            self._stream_panel_content(
                "NIKTO WEB VULNERABILITY SCAN", 
                f"[bright_green]✓ No web server vulnerabilities found for [bold]{target}[/bold][/bright_green]\n\n[dim]Nikto scanned the target and found no immediate security issues.[/dim]", 
                "bright_green"
            )
            return

        # Create finding table
        table = Table(
            title=f"[bright_red]NIKTO FINDINGS :: {target}[/bright_red]",
            show_header=True,
            header_style="bold bright_red",
            border_style="dim",
            box=box.ROUNDED,
            expand=True
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Path / URL", style="bright_cyan", width=20)
        table.add_column("Vulnerability / Message", style="bright_white", ratio=1)
        
        for i, f in enumerate(findings[:30], 1):
            url = f.get('url', 'N/A') or '—'
            msg = f.get('msg', 'N/A')
            table.add_row(str(i), url, msg)
            
        self._print_scanAI_header("NIKTO WEB VULNERABILITIES")
        self.console.print(table)
        
        if len(findings) > 30:
            self.console.print(f"  [dim]... and {len(findings) - 30} more findings[/dim]")
        
        self.console.print()

    def _display_harvester_results(self, data: Dict[str, Any]) -> None:
        """Display theHarvester OSINT results."""
        emails = data.get('emails', [])
        hosts = data.get('hosts', [])
        ips = data.get('ips', [])
        content = f"[dim]└─[/dim] [bold]domain:[/bold]  {data.get('domain', 'N/A')}\n\n"
        if emails:
            content += f"[bold bright_cyan]emails ({len(emails)}):[/bold bright_cyan]\n"
            for e in emails[:15]:
                content += f"  [dim]└─[/dim] [bright_green]{e}[/bright_green]\n"
            if len(emails) > 15:
                content += f"  [dim]   +{len(emails)-15} more[/dim]\n"
            content += "\n"
        if hosts:
            content += f"[bold bright_yellow]hosts ({len(hosts)}):[/bold bright_yellow]\n"
            for h in hosts[:10]:
                content += f"  [dim]└─[/dim] {h}\n"
            if len(hosts) > 10:
                content += f"  [dim]   +{len(hosts)-10} more[/dim]\n"
            content += "\n"
        if ips:
            content += f"[bold bright_magenta]ips ({len(ips)}):[/bold bright_magenta]\n"
            for ip in ips[:10]:
                content += f"  [dim]└─[/dim] {ip}\n"
        if not emails and not hosts and not ips:
            content += "[dim]no OSINT data found[/dim]"
        self._stream_panel_content("OSINT HARVESTER", content)

    def _display_waf_results(self, data: Dict[str, Any]) -> None:
        """Display WAF detection results."""
        detected = data.get('waf_detected', False)
        if detected:
            content = (
                f"[bright_red]● waf detected[/bright_red]\n\n"
                f"[dim]└─[/dim] [bold]firewall:[/bold]  [bright_yellow]{data.get('waf_name', 'Unknown')}[/bright_yellow]\n"
                f"[dim]└─[/dim] [bold]vendor:[/bold]    {data.get('waf_manufacturer', 'Unknown')}\n\n"
                f"[dim]evasion techniques may be required[/dim]"
            )
            self._stream_panel_content("WAF DETECTION", content)
        else:
            self._stream_panel_content("WAF DETECTION",
                "[bright_green]● no WAF detected[/bright_green]\n[dim]direct exploitation may be possible[/dim]")

    def _display_wpscan_results(self, data: Dict[str, Any]) -> None:
        """Display WordPress scan results."""
        vulns = data.get('vulnerabilities', [])
        content = (
            f"[dim]└─[/dim] [bold]version:[/bold]  [bright_cyan]{data.get('wp_version', 'Unknown')}[/bright_cyan]\n"
            f"[dim]└─[/dim] [bold]theme:[/bold]    {data.get('theme', 'Unknown')}\n"
            f"[dim]└─[/dim] [bold]plugins:[/bold]  {', '.join(data.get('plugins', [])[:5]) or 'none'}\n"
            f"[dim]└─[/dim] [bold]vulns:[/bold]    [bright_red]{len(vulns)}[/bright_red]\n"
        )
        if vulns:
            content += "\n"
            for v in vulns[:10]:
                content += f"  [bright_red]●[/bright_red] {v.get('title', 'Unknown')} [{v.get('type', '')}]\n"
                if v.get('fixed_in'):
                    content += f"     [dim]fixed in: {v['fixed_in']}[/dim]\n"
        self._stream_panel_content("WORDPRESS SCAN", content)

    def _display_wayback_results(self, data: Dict[str, Any]) -> None:
        """Display Wayback Machine archive results."""
        total = data.get('total', 0)
        interesting = data.get('interesting', [])
        endpoints = data.get('endpoints', [])
        subs = data.get('subdomains', [])
        content = (
            f"[dim]└─[/dim] [bold]domain:[/bold]     {data.get('domain', 'N/A')}\n"
            f"[dim]└─[/dim] [bold]archived:[/bold]   [bright_cyan]{total}[/bright_cyan]\n"
            f"[dim]└─[/dim] [bold]endpoints:[/bold]  [bright_yellow]{data.get('total_endpoints', 0)}[/bright_yellow]\n"
            f"[dim]└─[/dim] [bold]subdomains:[/bold] [bright_green]{len(subs)}[/bright_green]\n"
        )
        if interesting:
            content += f"\n[bold bright_red]interesting ({len(interesting)}):[/bold bright_red]\n"
            for item in interesting[:10]:
                content += f"  [bright_red]●[/bright_red] {item.get('url', '?')} [{item.get('type', '?')}]\n"
        if endpoints:
            content += f"\n[bold bright_yellow]endpoints:[/bold bright_yellow]\n"
            for ep in endpoints[:15]:
                content += f"  {ep}\n"
            if len(endpoints) > 15:
                content += f"  [dim]... +{len(endpoints)-15} more[/dim]\n"
        self._stream_panel_content("WAYBACK ARCHIVE", content, "bright_yellow")

    def _display_titus_results(self, data: Dict[str, Any]) -> None:
        """Display Titus secrets scan results."""
        total = data.get('total_secrets', 0)
        active = data.get('active_secrets', 0)
        validated = data.get('validated', False)
        categories = data.get('categories', {})

        if total == 0:
            self._stream_panel_content("🔑 SECRETS SCAN (TITUS)",
                "[green]✓ No secrets or credentials detected[/green]", "green")
            return

        # Header
        sev_color = 'red' if active > 0 else 'yellow' if total > 5 else 'cyan'
        content = (
            f"[bold]Target:[/bold] {data.get('target', 'N/A')}\n"
            f"[bold]Total Secrets:[/bold] [{sev_color}]{total}[/{sev_color}]\n"
        )
        if validated:
            content += f"[bold]Active (Validated):[/bold] [bold red]{active}[/bold red]\n"
        content += "\n"

        # Categories
        if categories:
            content += "[bold]Categories:[/bold]\n"
            for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
                content += f"  {cat}: [cyan]{count}[/cyan]\n"
            content += "\n"

        # Active secrets (critical!)
        active_findings = data.get('active_findings', [])
        if active_findings:
            content += "[bold red]🚨 ACTIVE CREDENTIALS:[/bold red]\n"
            for s in active_findings[:5]:
                content += (
                    f"  [red]●[/red] {s.get('rule_name', '?')}\n"
                    f"    Secret: [dim]{s.get('secret', '***')}[/dim]\n"
                    f"    File: {s.get('file', '?')}:{s.get('line', '?')}\n"
                )
            content += "\n"

        # Top findings
        top = data.get('top_findings', [])
        if top:
            content += "[bold]Findings:[/bold]\n"
            for i, s in enumerate(top[:15], 1):
                sev = s.get('severity', 'LOW')
                sc = 'red' if sev in ('CRITICAL', 'HIGH') else 'yellow' if sev == 'MEDIUM' else 'dim'
                val = f" [bold green]✓ ACTIVE[/bold green]" if s.get('validation') in ('confirmed', 'active', 'valid') else ""
                content += (
                    f"  [{sc}]{i:2d}. {s.get('rule_name', '?')}[/{sc}]{val}\n"
                    f"      {s.get('file', '?')}:{s.get('line', '?')} → [dim]{s.get('secret', '***')}[/dim]\n"
                )
            if len(top) > 15:
                content += f"  [dim]... +{total - 15} more[/dim]\n"

        self._stream_panel_content("🔑 SECRETS SCAN (TITUS)", content, sev_color)

    def _display_enum4linux_results(self, data: Dict[str, Any]) -> None:
        """Display SMB/NetBIOS enumeration results."""
        shares = data.get('shares', [])
        users = data.get('users', [])
        content = (
            f"[dim]└─[/dim] [bold]target:[/bold]  {data.get('target', 'N/A')}\n"
            f"[dim]└─[/dim] [bold]os:[/bold]      {data.get('os_info', 'N/A')}\n"
            f"[dim]└─[/dim] [bold]domain:[/bold]  {data.get('domain_info', 'N/A')}\n\n"
        )
        if shares:
            content += f"[bold bright_cyan]shares ({len(shares)}):[/bold bright_cyan]\n"
            for s in shares[:10]:
                content += f"  [dim]└─[/dim] [bright_green]{s.get('name', '?')}[/bright_green] [{s.get('type', '')}]\n"
            content += "\n"
        if users:
            content += f"[bold bright_yellow]users ({len(users)}):[/bold bright_yellow]\n"
            for u in users[:10]:
                content += f"  [dim]└─[/dim] {u}\n"
        if not shares and not users:
            content += "[dim]no SMB data enumerated[/dim]"
        self._stream_panel_content("SMB ENUMERATION", content)

    def _display_errors(self, errors: List[Dict[str, Any]]) -> None:
        """Display scanner errors in ScanAI style."""
        if not errors:
            return

        error_table = Table(
            show_header=True,
            header_style="bold bright_red",
            border_style="dim",
            box=box.ROUNDED,
            expand=True
        )
        error_table.add_column("Scanner", style="bold bright_yellow", width=15)
        error_table.add_column("Error Message", style="bright_red", ratio=1)
        
        for error in errors:
            error_table.add_row(f"✗ {error['scanner']}", error['error'])
        
        self._print_scanAI_header("SCANNER ADVISORIES & ERRORS")
        self.console.print(error_table)
        self.console.print()

    def _display_ssl_results(self, ssl_data: Dict[str, Any]) -> None:
        """Display exhaustive SSL certificate analysis."""
        if not ssl_data:
            return

        # Handle both wrapped and unwrapped data from ScanManager
        if 'success' in ssl_data and 'data' in ssl_data:
            if not ssl_data['success']:
                self.console.print(ThemePanel(f"[bright_red]SSL Scan Error: {ssl_data.get('error', 'Unknown error')}[/bright_red]", border_style="bright_red"))
                return
            cert_info = ssl_data['data']
        else:
            # Assume ssl_data is the cert_info dict directly
            cert_info = ssl_data

        if not isinstance(cert_info, dict) or not cert_info:
            return
            
        subject = cert_info.get('subject') or {}
        issuer = cert_info.get('issuer') or {}
        validity = cert_info.get('validity') or {}
        pubkey = cert_info.get('public_key') or {}
        san = cert_info.get('subject_alt_names', [])
        extensions = cert_info.get('extensions', {})
        
        # Identification Table
        id_table = Table.grid(expand=True)
        id_table.add_column(style="dim", width=18)
        id_table.add_column(style="bright_white")
        if isinstance(subject, dict):
            id_table.add_row("Common Name:", f"[bold]{subject.get('common_name', 'N/A')}[/bold]")
            id_table.add_row("Organization:", subject.get('organization', 'N/A'))
            id_table.add_row("Organizational Unit:", subject.get('organizational_unit', 'N/A'))
            id_table.add_row("Location:", f"{subject.get('locality', 'N/A')}, {subject.get('state', 'N/A')}, {subject.get('country', 'N/A')}")

        # Issuance Table
        iss_table = Table.grid(expand=True)
        iss_table.add_column(style="dim", width=18)
        iss_table.add_column(style="bright_cyan")
        if isinstance(issuer, dict):
            iss_table.add_row("Authority CN:", issuer.get('common_name', 'N/A'))
            iss_table.add_row("Authority Org:", issuer.get('organization', 'N/A'))
            iss_table.add_row("Authority Country:", issuer.get('country', 'N/A'))

        # Technical Specifications Table
        tech_table = Table.grid(expand=True)
        tech_table.add_column(style="dim", width=18)
        tech_table.add_column(style="bright_yellow")
        tech_table.add_row("Public Key:", f"{pubkey.get('type', 'N/A')} {pubkey.get('bits', 'N/A')} bits")
        tech_table.add_row("Signature Algo:", str(cert_info.get('signature_algorithm', 'N/A')))
        tech_table.add_row("Serial Number:", str(cert_info.get('serial_number', 'N/A')))
        tech_table.add_row("Version:", f"v{cert_info.get('version', 'N/A')}")

        # Expiry status
        days = cert_info.get('days_until_expiry', 'Unknown')
        if cert_info.get('has_expired'):
            status = "[bold bright_red]✗ EXPIRED[/bold bright_red]"
        elif isinstance(days, int) and days < 30:
            status = f"[bold bright_yellow]! EXPIRING IN {days} DAYS[/bold bright_yellow]"
        else:
            status = f"[bold bright_green]✓ VALID ({days} days remaining)[/bold bright_green]"

        # Build content
        content = []
        content.append("[bold bright_white]IDENTIFICATION[/bold bright_white]")
        content.append(id_table)
        content.append("\n[bold bright_cyan]ISSUANCE & TRUST[/bold bright_cyan]")
        content.append(iss_table)
        content.append("\n[bold bright_yellow]TECHNICAL SPECIFICATIONS[/bold bright_yellow]")
        content.append(tech_table)
        
        content.append(f"\n[bold bright_white]VALIDITY[/bold bright_white]\n{status}")
        
        if san:
            san_text = ", ".join(san[:8]) + ("..." if len(san) > 8 else "")
            content.append(f"\n[bold bright_magenta]ALT NAMES (SAN)[/bold bright_magenta]\n[dim]{san_text}[/dim]")

        # Extensions
        if extensions:
            ext_grid = Table.grid(expand=True)
            ext_grid.add_column(style="dim", width=22)
            ext_grid.add_column(style="bright_white")
            
            # Show top 5 extensions
            shown = 0
            for name, val in extensions.items():
                if shown >= 6: break
                # Shorten value if too long
                val_str = str(val)
                display_val = (val_str[:50] + '...') if len(val_str) > 50 else val_str
                ext_grid.add_row(f"{name}:", f"[dim]{display_val}[/dim]")
                shown += 1
            
            content.append("\n[bold bright_white]EXTENSIONS[/bold bright_white]")
            content.append(ext_grid)

        # PEM Content
        if cert_info.get('pem'):
            pem_snippet = str(cert_info['pem']).strip().split('\n')
            if len(pem_snippet) > 8:
                pem_display = "\n".join(pem_snippet[:4] + ["      ... TRUNCATED ..."] + pem_snippet[-4:])
            else:
                pem_display = "\n".join(pem_snippet)
            
            content.append(f"\n[bold bright_white]CERTIFICATE DATA (PEM)[/bold bright_white]\n[dim]{pem_display}[/dim]")

        # Fingerprints
        content.append(f"\n[dim][bold]SHA256:[/bold] {cert_info.get('fingerprint_sha256', 'N/A')}[/dim]")
        if cert_info.get('fingerprint_sha1'):
             content.append(f"[dim][bold]SHA1:  [/bold] {cert_info.get('fingerprint_sha1', 'N/A')}[/dim]")

        ssl_panel = ThemePanel(
            Group(*content),
            title="ENHANCED SSL INTELLIGENCE",
            border_style="bright_green",
            padding=(1, 2),
            style="white on black"
        )
        self.console.print(ssl_panel)

    def _clean_rich_markup(self, text: str) -> str:
        """Clean rich markup from text."""
        import re
        return re.sub(r'\[/?[a-zA-Z_]+(?:\s+[a-zA-Z_]+="[^"]*")*\]', '', text)

    def _get_threat_description(self, threat_type: str) -> str:
        """Get description for threat type."""
        descriptions = {
            "Trojan/Backdoor": "Malicious code disguised as legitimate software",
            "Ransomware": "Encrypts files and demands payment",
            "Cryptominer": "Uses system resources for cryptocurrency mining",
            "Worm": "Self-replicating malware spreading across networks",
            "Virus": "Infects files and spreads when executed",
            "Spyware/Keylogger": "Monitors and steals user activity",
            "Adware/PUP": "Displays unwanted ads or bundled software",
            "Phishing": "Attempts to steal credentials",
            "Generic Malware": "General malicious software",
            "Exploit Kit": "Tools exploiting vulnerabilities",
            "Botnet": "Network of compromised devices",
            "Suspicious": "Potentially harmful activity",
            "Unknown": "Unclassified threat"
        }
        return descriptions.get(threat_type, "Unknown threat type")

    def _classify_detection_type(self, detection_result: str) -> str:
        """Classify the type of malicious detection."""
        result_lower = detection_result.lower()

        if any(keyword in result_lower for keyword in ['trojan', 'backdoor', 'rootkit']):
            return "Trojan/Backdoor"
        elif any(keyword in result_lower for keyword in ['ransomware', 'encryptor']):
            return "Ransomware"
        elif any(keyword in result_lower for keyword in ['miner', 'coinminer', 'cryptominer']):
            return "Cryptominer"
        elif 'worm' in result_lower:
            return "Worm"
        elif 'virus' in result_lower:
            return "Virus"
        elif any(keyword in result_lower for keyword in ['spyware', 'keylogger', 'infostealer']):
            return "Spyware/Keylogger"
        elif any(keyword in result_lower for keyword in ['adware', 'pup', 'unwanted']):
            return "Adware/PUP"
        elif any(keyword in result_lower for keyword in ['phishing', 'phish']):
            return "Phishing"
        elif any(keyword in result_lower for keyword in ['malware', 'malicious']):
            return "Generic Malware"
        elif any(keyword in result_lower for keyword in ['exploit', 'vulnerability']):
            return "Exploit Kit"
        elif any(keyword in result_lower for keyword in ['botnet', 'bot']):
            return "Botnet"
        elif 'suspicious' in result_lower:
            return "Suspicious"
        else:
            return "Unknown"