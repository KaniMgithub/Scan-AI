"""Configuration management for ScanAI."""

import os
import sys
from pathlib import Path
from typing import Dict, Optional, Any, List

# Handle TOML parsing for different Python versions
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

try:
    # Optional: load .env support if python-dotenv is installed
    from dotenv import load_dotenv  # type: ignore[import]
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None  # type: ignore[assignment]


class Config:
    """Configuration manager for API keys and settings.

    Priority order:
    1. Environment variables / .env (recommended for secrets)
    2. TOML config files (for non-secret settings and legacy support)
    """

    def __init__(self) -> None:
        """Initialize configuration from .env and TOML files."""
        # First, load .env from project root or current working directory
        self._load_env()

        # Then load TOML configuration (non-secret settings)
        self._config = self._load_config()

        # -----------------------
        # API Keys (from .env first, then TOML)
        # -----------------------
        api_keys = self._config.get('api_keys', {})

        # Gemini API keys (supports multiple keys for rotation)
        self._gemini_api_keys: List[str] = []

        # 1) From environment variables / .env
        #    GEMINI_API_KEYS can be a comma-separated list
        env_gemini_keys = os.getenv("GEMINI_API_KEYS") or os.getenv("GEMINI_API_KEY")
        if env_gemini_keys:
            # Support comma-separated or single key
            keys = [k.strip() for k in env_gemini_keys.split(",") if k.strip()]
            self._gemini_api_keys.extend(keys)

        # 2) Fallback to TOML config if nothing in env
        if not self._gemini_api_keys:
            gemini_keys = api_keys.get("gemini_api_keys", [])
            if isinstance(gemini_keys, list):
                self._gemini_api_keys = [key.strip() for key in gemini_keys if key.strip()]
            else:
                # Fallback for single key
                single_key = api_keys.get("gemini_api_key", "").strip()
                if single_key:
                    self._gemini_api_keys = [single_key]

        # For backward compatibility - primary key
        self._gemini_api_key: Optional[str] = (
            self._gemini_api_keys[0] if self._gemini_api_keys else None
        )

        # VirusTotal API key
        self._virustotal_api_key: Optional[str] = (
            os.getenv("VIRUSTOTAL_API_KEY")
            or api_keys.get("virustotal_api_key", "").strip()
            or None
        )

        # URLScan API key
        self._urlscan_api_key: Optional[str] = (
            os.getenv("URLSCAN_API_KEY")
            or api_keys.get("urlscan_api_key", "").strip()
            or None
        )

        # -----------------------
        # Scan settings (from TOML only)
        # -----------------------
        scan_settings = self._config.get("scan_settings", {})
        # Increased from 45 to 120 seconds for more reliable scans
        self._nmap_timeout: int = scan_settings.get("nmap_timeout", 120)
        self._scan_timeout: int = scan_settings.get("scan_timeout", 300)
        self._max_subdomains: int = scan_settings.get("max_subdomains", 50)

        # -----------------------
        # Output settings
        # -----------------------
        output = self._config.get("output", {})
        self._verbose: bool = output.get("verbose", False)
        self._json_output: bool = output.get("json_output", False)

        # -----------------------
        # System settings
        # -----------------------
        system = self._config.get("system", {})
        self._nmap_path: Optional[str] = system.get("nmap_path", "").strip() or None
        self._whois_path: Optional[str] = system.get("whois_path", "").strip() or None
        self._storage_dir: str = system.get("storage_dir", "/tmp/scanai")

    def _load_env(self) -> None:
        """Load environment variables from a .env file if available."""
        # Prefer project root .env if running from an installed package
        if load_dotenv is None:
            return

        # Look for .env in multiple locations
        env_paths = []

        # Current working directory (highest priority)
        cwd_env = Path.cwd() / ".env"
        env_paths.append(cwd_env)

        # Try to find project root by looking for common project files
        # This works better than using __file__ which points to installed location in dev mode
        current_path = Path.cwd()
        for parent in [current_path] + list(current_path.parents):
            # Look for project indicators
            if any((parent / indicator).exists() for indicator in ['pyproject.toml', 'setup.py', 'scanai', 'requirements.txt']):
                project_env = parent / ".env"
                if project_env not in env_paths:  # Avoid duplicates
                    env_paths.append(project_env)
                break

        # Fallback: try the old method for edge cases
        legacy_env = Path(__file__).resolve().parents[2] / ".env"
        if legacy_env not in env_paths:
            env_paths.append(legacy_env)

        # Load from all found .env files
        for env_path in env_paths:
            if env_path.exists():
                load_dotenv(dotenv_path=env_path, override=False)

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from TOML files (non-secret settings)."""
        config: Dict[str, Any] = {}

        # Default config locations in order of priority
        config_paths = [
            Path.cwd() / "config.toml",      # Local project config
            Path.cwd() / "scanai.toml",      # Alternative local config
            Path.home() / ".scanai.toml",    # Legacy user config (still supported)
        ]

        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, "rb") as f:
                        file_config = tomllib.load(f)
                        # Merge configs (later files override earlier ones)
                        self._deep_merge(config, file_config)
                except Exception:
                    # Continue with other config files if this one fails
                    continue

        return config

    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Deep merge update dict into base dict."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    @property
    def gemini_api_key(self) -> Optional[str]:
        """Get primary Gemini API key."""
        return self._gemini_api_key

    @property
    def gemini_api_keys(self) -> List[str]:
        """Get all Gemini API keys."""
        return self._gemini_api_keys

    @property
    def virustotal_api_key(self) -> Optional[str]:
        """Get VirusTotal API key."""
        return self._virustotal_api_key

    @property
    def urlscan_api_key(self) -> Optional[str]:
        """Get URLScan API key."""
        return self._urlscan_api_key

    @property
    def nmap_timeout(self) -> int:
        """Get Nmap scan timeout in seconds."""
        return self._nmap_timeout

    @property
    def scan_timeout(self) -> int:
        """Get overall scan timeout in seconds."""
        return self._scan_timeout

    @property
    def max_subdomains(self) -> int:
        """Get maximum number of subdomains to retrieve."""
        return self._max_subdomains

    @property
    def verbose(self) -> bool:
        """Get verbose output setting."""
        return self._verbose

    @property
    def json_output(self) -> bool:
        """Get JSON output setting."""
        return self._json_output

    @property
    def nmap_path(self) -> Optional[str]:
        """Get custom nmap path."""
        return self._nmap_path

    @property
    def whois_path(self) -> Optional[str]:
        """Get custom whois path."""
        return self._whois_path

    @property
    def storage_dir(self) -> str:
        """Get storage directory path."""
        return self._storage_dir

    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate that required API keys are configured."""
        return {
            'gemini': len(self._gemini_api_keys) > 0,
            'virustotal': self._virustotal_api_key is not None,
            'urlscan': self._urlscan_api_key is not None,
        }

    def get_missing_keys(self) -> list[str]:
        """Get list of missing API keys."""
        validation = self.validate_api_keys()
        return [key for key, valid in validation.items() if not valid]

    # ---------- Legacy TOML helpers (kept for backward compatibility) ----------

    def create_toml_template(self) -> str:
        """Generate a template TOML file content (legacy, non-secret settings)."""
        template = """# ScanAI Configuration (legacy TOML)
# This file is optional. API keys should be stored in a .env file.
# Save this as config.toml in your project directory if you want to override defaults.

[scan_settings]
# Nmap scan timeout in seconds
nmap_timeout = 120

# Overall scan timeout in seconds
scan_timeout = 300

# Maximum number of subdomains to retrieve
max_subdomains = 50

[output]
# Enable verbose output
verbose = false

# Output results in JSON format
json_output = false

[system]
# Custom paths to system tools (leave empty to use PATH)
nmap_path = ""
whois_path = ""

# Storage directory for scan results (default: /tmp/scanai)
storage_dir = "/tmp/scanai"
"""
        return template

    def save_toml_template(self, path: Optional[Path] = None) -> None:
        """Save the TOML template to a file (legacy helper)."""
        if path is None:
            path = Path.cwd() / "config.toml"

        if path.exists():
            print(f"Configuration file already exists at: {path}")
            return

        with open(path, "w") as f:
            f.write(self.create_toml_template())

        print(f"✅ Configuration template created at: {path}")

    def get_config_paths(self) -> list[Path]:
        """Get list of possible configuration file paths."""
        return [
            Path.cwd() / "config.toml",
            Path.cwd() / "scanai.toml",
            Path.home() / ".scanai.toml",
        ]

    def show_config_locations(self) -> None:
        """Show current configuration file locations and status."""
        print("Configuration sources:")

        # .env files - use same logic as _load_env
        env_paths = []

        # Current working directory (highest priority)
        cwd_env = Path.cwd() / ".env"
        env_paths.append(cwd_env)

        # Try to find project root by looking for common project files
        current_path = Path.cwd()
        for parent in [current_path] + list(current_path.parents):
            # Look for project indicators
            if any((parent / indicator).exists() for indicator in ['pyproject.toml', 'setup.py', 'scanai', 'requirements.txt']):
                project_env = parent / ".env"
                if project_env not in env_paths:  # Avoid duplicates
                    env_paths.append(project_env)
                break

        # Fallback: try the old method for edge cases
        legacy_env = Path(__file__).resolve().parents[2] / ".env"
        if legacy_env not in env_paths:
            env_paths.append(legacy_env)

        for env_path in env_paths:
            status = "✅ Found" if env_path.exists() else "❌ Not found"
            print(f"  {status}: {env_path}")

        # Only show TOML if it actually exists
        if self._config:
            print("\nConfiguration sections loaded:")
            for section in self._config.keys():
                print(f"  • {section}")
        else:
            print("\nUsing default configuration.")


# Global configuration instance
config = Config()