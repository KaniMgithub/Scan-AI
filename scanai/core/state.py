"""Module for managing the state of an autonomous scan."""

from typing import Dict, Any, List, Optional
import json

class ScanState:
    """Tracks the state, context, and findings of a scan session."""

    def __init__(self, query: str, target: str):
        """
        Initialize the scan state.

        Args:
            query: The original natural language query.
            target: The primary target.
        """
        self.query = query
        self.target = target
        self.completed_actions: List[str] = []
        self.findings: Dict[str, Any] = {}
        self.current_subtask: Optional[str] = None
        self.is_complete = False
        self.plan_history: List[Dict[str, Any]] = []

    def add_finding(self, scanner_name: str, data: Any):
        """
        Add findings from a scanner execution.

        Args:
            scanner_name: Name of the scanner.
            data: Data produced by the scanner.
        """
        self.findings[scanner_name] = data
        self.completed_actions.append(scanner_name)

    def get_findings_summary(self) -> str:
        """
        Generate a concise summary of findings for the AI context.

        Returns:
            A string summarizing current knowledge.
        """
        if not self.findings:
            return "No findings yet."
        
        summary = []
        for scanner, data in self.findings.items():
            # Basic summarization logic - can be expanded
            if isinstance(data, dict):
                # If we have a 'summary' or 'count' field, use it
                keys = list(data.keys())
                summary.append(f"- {scanner}: Found {len(data)} items ({', '.join(keys[:5])})")
            else:
                summary.append(f"- {scanner}: Data captured")
        
        return "\n".join(summary)

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary for logging or UI."""
        return {
            "query": self.query,
            "target": self.target,
            "completed_actions": self.completed_actions,
            "is_complete": self.is_complete,
            "current_subtask": self.current_subtask
        }
