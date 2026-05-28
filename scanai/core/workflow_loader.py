"""YAML workflow loader and registry for ScanAI.

Loads scanner workflow definitions from YAML files and provides
a registry for profile-based scan execution.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


class WorkflowProfile:
    """Represents a single scan profile from a workflow YAML."""

    def __init__(self, scanner: str, name: str, data: Dict[str, Any]) -> None:
        self.scanner = scanner
        self.name = name
        self.description = data.get("description", "")
        self.command_template = data.get("command_template")
        self.method = data.get("method")
        self.timeout = data.get("timeout", 120)
        self.tags = data.get("tags", [])
        self.extra = {k: v for k, v in data.items()
                      if k not in ("description", "command_template", "method", "timeout", "tags")}

    def build_command(self, target: str, **kwargs: Any) -> Optional[str]:
        """Build the shell command from template, if applicable."""
        if not self.command_template:
            return None
        cmd = self.command_template.replace("{target}", target)
        for key, val in kwargs.items():
            cmd = cmd.replace(f"{{{key}}}", str(val))
        return cmd

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "profile": self.name,
            "description": self.description,
            "tags": self.tags,
            "timeout": self.timeout,
            "has_command": self.command_template is not None,
            "method": self.method,
        }

    def __repr__(self) -> str:
        return f"<WorkflowProfile {self.scanner}/{self.name}>"


class WorkflowDefinition:
    """Represents a full scanner workflow loaded from YAML."""

    def __init__(self, data: Dict[str, Any]) -> None:
        self.scanner = data.get("scanner", "unknown")
        self.description = data.get("description", "")
        self.binary = data.get("binary")
        self.default_profile = data.get("default_profile", "standard")
        self.dependencies = data.get("dependencies", [])

        self.profiles: Dict[str, WorkflowProfile] = {}
        for name, profile_data in data.get("profiles", {}).items():
            self.profiles[name] = WorkflowProfile(self.scanner, name, profile_data)

    def get_profile(self, name: Optional[str] = None) -> Optional[WorkflowProfile]:
        """Get a profile by name, falling back to default."""
        if name and name in self.profiles:
            return self.profiles[name]
        if self.default_profile in self.profiles:
            return self.profiles[self.default_profile]
        # Return first profile if nothing matches
        if self.profiles:
            return next(iter(self.profiles.values()))
        return None

    def list_profiles(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self.profiles.values()]

    def __repr__(self) -> str:
        return f"<WorkflowDefinition {self.scanner} ({len(self.profiles)} profiles)>"


class WorkflowRegistry:
    """Central registry for all scanner workflows.

    Loads YAML files from the workflows directory and provides
    lookup by scanner name, profile name, or tag matching.
    """

    _instance: Optional["WorkflowRegistry"] = None

    def __init__(self) -> None:
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self._loaded = False

    @classmethod
    def instance(cls) -> "WorkflowRegistry":
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.load()
        return cls._instance

    def load(self, workflows_dir: Optional[str] = None) -> None:
        """Load all YAML workflow definitions."""
        if workflows_dir is None:
            workflows_dir = str(Path(__file__).parent.parent / "workflows")

        wf_path = Path(workflows_dir)
        if not wf_path.is_dir():
            logger.warning(f"Workflows directory not found: {wf_path}")
            return

        for yaml_file in sorted(wf_path.glob("*.yaml")):
            try:
                with open(yaml_file, "r") as f:
                    data = yaml.safe_load(f)
                if data and isinstance(data, dict) and "scanner" in data:
                    wf = WorkflowDefinition(data)
                    self.workflows[wf.scanner] = wf
                    logger.debug(f"Loaded workflow: {wf.scanner} ({len(wf.profiles)} profiles)")
            except Exception as e:
                logger.error(f"Failed to load workflow {yaml_file}: {e}")

        self._loaded = True
        logger.info(f"Loaded {len(self.workflows)} scanner workflows")

    def get_workflow(self, scanner: str) -> Optional[WorkflowDefinition]:
        """Get workflow definition for a scanner."""
        return self.workflows.get(scanner)

    def get_profile(self, scanner: str, profile: Optional[str] = None) -> Optional[WorkflowProfile]:
        """Get a specific profile from a scanner workflow."""
        wf = self.workflows.get(scanner)
        if wf:
            return wf.get_profile(profile)
        return None

    def find_by_tags(self, tags: List[str]) -> List[Tuple[str, WorkflowProfile]]:
        """Find profiles matching any of the given tags."""
        results = []
        tag_set = set(t.lower() for t in tags)
        for wf in self.workflows.values():
            for profile in wf.profiles.values():
                profile_tags = set(t.lower() for t in profile.tags)
                if tag_set & profile_tags:
                    results.append((wf.scanner, profile))
        return results

    def list_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """List all scanners and their profiles."""
        return {
            scanner: wf.list_profiles()
            for scanner, wf in self.workflows.items()
        }

    def get_profile_summary_for_ai(self) -> str:
        """Generate a text summary of all profiles for AI query interpretation."""
        lines = []
        for scanner, wf in sorted(self.workflows.items()):
            lines.append(f"\nScanner: {scanner} — {wf.description}")
            for name, profile in wf.profiles.items():
                tags_str = ", ".join(profile.tags)
                lines.append(f"  - {scanner}/{name}: {profile.description} [tags: {tags_str}]")
        return "\n".join(lines)


class AttackChain:
    """Represents a pre-built attack chain from YAML."""

    def __init__(self, name: str, data: Dict[str, Any]) -> None:
        self.name = name
        self.description = data.get("description", "")
        self.steps = data.get("steps", [])
        self.timeout = data.get("timeout", 600)
        self.tags = data.get("tags", [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "steps": self.steps,
            "timeout": self.timeout,
            "tags": self.tags,
        }

    def __repr__(self) -> str:
        return f"<AttackChain {self.name} ({len(self.steps)} steps)>"


class ChainRegistry:
    """Registry for pre-built attack chains."""

    _instance: Optional["ChainRegistry"] = None

    def __init__(self) -> None:
        self.chains: Dict[str, AttackChain] = {}

    @classmethod
    def instance(cls) -> "ChainRegistry":
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.load()
        return cls._instance

    def load(self, workflows_dir: Optional[str] = None) -> None:
        if workflows_dir is None:
            workflows_dir = str(Path(__file__).parent.parent / "workflows")

        chain_file = Path(workflows_dir) / "recon_chain.yaml"
        if not chain_file.is_file():
            return

        try:
            with open(chain_file, "r") as f:
                data = yaml.safe_load(f)
            if data and "chains" in data:
                for name, chain_data in data["chains"].items():
                    self.chains[name] = AttackChain(name, chain_data)
                logger.info(f"Loaded {len(self.chains)} attack chains")
        except Exception as e:
            logger.error(f"Failed to load chains: {e}")

    def get_chain(self, name: str) -> Optional[AttackChain]:
        return self.chains.get(name)

    def find_by_tags(self, tags: List[str]) -> List[AttackChain]:
        tag_set = set(t.lower() for t in tags)
        return [c for c in self.chains.values() if tag_set & set(t.lower() for t in c.tags)]

    def list_all(self) -> Dict[str, Dict[str, Any]]:
        return {name: chain.to_dict() for name, chain in self.chains.items()}

    def get_summary_for_ai(self) -> str:
        lines = ["\nAttack Chains (pre-built multi-scanner sequences):"]
        for name, chain in sorted(self.chains.items()):
            steps_str = " → ".join(f"{s['scanner']}/{s.get('profile', 'default')}" for s in chain.steps)
            lines.append(f"  - {name}: {chain.description}")
            lines.append(f"    Steps: {steps_str}")
        return "\n".join(lines)


def get_chain_registry() -> ChainRegistry:
    """Get the global chain registry (loads on first access)."""
    return ChainRegistry.instance()


# Module-level convenience
def get_registry() -> WorkflowRegistry:
    """Get the global workflow registry (loads on first access)."""
    return WorkflowRegistry.instance()
