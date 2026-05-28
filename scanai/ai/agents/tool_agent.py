"""Tool agent implementation — profile-aware scanner selection."""

from typing import Dict, Any
from .base_agent import BaseAgent
from ..prompts.tool_selector import TOOL_SELECTOR_SYSTEM_PROMPT, TOOL_SELECTOR_DECISION_PROMPT


class ToolAgent(BaseAgent):
    """Agent responsible for selecting scanning tools and workflow profiles."""

    def select_tool(self, subtask: str, target: str, planner_reasoning: str) -> Dict[str, Any]:
        """
        Select the best tool and profile for the given subtask.

        Args:
            subtask: The subtask to perform.
            target: The target for the subtask.
            planner_reasoning: Reasoning provided by the Planner.

        Returns:
            A dictionary containing the selected scanner, profile, and parameters.
        """
        # Inject live profile summary from workflow registry
        try:
            from ...core.workflow_loader import get_registry
            profiles_summary = get_registry().get_profile_summary_for_ai()
        except Exception:
            profiles_summary = "(Profile registry unavailable — use scanner defaults)"

        system_prompt = TOOL_SELECTOR_SYSTEM_PROMPT.format(
            profiles_summary=profiles_summary
        )

        user_prompt = TOOL_SELECTOR_DECISION_PROMPT.format(
            subtask=subtask,
            target=target,
            planner_reasoning=planner_reasoning
        )

        return self._generate_response(system_prompt, user_prompt)
