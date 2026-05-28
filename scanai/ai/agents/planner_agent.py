"""Planner agent implementation — profile-aware strategic planning."""

from typing import Dict, Any, List
from .base_agent import BaseAgent
from ..prompts.planner import PLANNER_SYSTEM_PROMPT, PLANNER_DECISION_PROMPT


class PlannerAgent(BaseAgent):
    """Agent responsible for high-level scan planning with workflow profiles."""

    def plan(self, query: str, target: str, completed_actions: List[str], findings_summary: str) -> Dict[str, Any]:
        """
        Determine the next tactical step for the scan.

        Args:
            query: Original user query.
            target: Main target.
            completed_actions: List of actions already completed.
            findings_summary: Summary of current findings.

        Returns:
            A dictionary containing the next subtask, profile, and reasoning.
        """
        # Inject live profile + chain summaries from workflow registry
        try:
            from ...core.workflow_loader import get_registry, get_chain_registry
            profiles_summary = get_registry().get_profile_summary_for_ai()
            profiles_summary += "\n" + get_chain_registry().get_summary_for_ai()
        except Exception:
            profiles_summary = "(Profile registry unavailable)"

        system_prompt = PLANNER_SYSTEM_PROMPT.format(
            profiles_summary=profiles_summary
        )

        user_prompt = PLANNER_DECISION_PROMPT.format(
            query=query,
            target=target,
            completed_actions="\n".join([f"- {action}" for action in completed_actions]) if completed_actions else "None yet",
            findings_summary=findings_summary if findings_summary else "No findings yet — starting fresh"
        )

        return self._generate_response(system_prompt, user_prompt)
