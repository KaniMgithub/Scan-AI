"""Base class for all ScanAI agents — uses AIClient (LangChain backend)."""

import json
import logging
from typing import Dict, Any, Optional


class BaseAgent:
    """Base class for AI agents in ScanAI."""

    def __init__(self, ai_service: Any):
        """
        Initialize the agent.

        Args:
            ai_service: The ScanAIService instance (which now wraps AIClient).
        """
        self.ai_service = ai_service
        self.logger = logging.getLogger(self.__class__.__name__)

    def _generate_response(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """
        Generate a response from the AI service.

        Uses the AIClient (LangChain) backend with proper system/user message separation.

        Args:
            system_prompt: The system prompt.
            user_prompt: The user prompt.

        Returns:
            Parsed JSON response from the AI.
        """
        try:
            # Use the ai_client if available (new LangChain path)
            if hasattr(self.ai_service, 'ai_client') and self.ai_service.ai_client is not None:
                content = self.ai_service.ai_client.generate_sync(
                    prompt=user_prompt,
                    system_prompt=system_prompt
                )
            else:
                # Legacy fallback: combine prompts and use model directly
                full_prompt = f"{system_prompt}\n\n{user_prompt}"
                response = self.ai_service.model.generate_content(
                    full_prompt,
                    generation_config={'temperature': 0.1}
                )
                content = response.text.strip()

            # Clean possible markdown code blocks
            content = content.strip()
            if content.startswith("```json"):
                content = content[7:-3].strip()
            elif content.startswith("```"):
                content = content[3:-3].strip()

            return json.loads(content)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse AI response as JSON: {e}")
            return {"error": f"JSON parse error: {str(e)}"}
        except Exception as e:
            self.logger.error(f"Error generating AI response: {e}")
            return {"error": str(e)}

    def _generate_text(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.7
    ) -> str:
        """
        Generate a raw text (non-JSON) response from the AI service.

        Used by agents that need markdown output (analyst reports, exploitation guides).

        Args:
            system_prompt: The system prompt.
            user_prompt: The user prompt.
            temperature: Generation temperature.

        Returns:
            Raw text response.
        """
        try:
            if hasattr(self.ai_service, 'ai_client') and self.ai_service.ai_client is not None:
                return self.ai_service.ai_client.generate_sync_with_config(
                    prompt=user_prompt,
                    system_prompt=system_prompt,
                    temperature=temperature
                )
            else:
                # Legacy fallback
                full_prompt = f"{system_prompt}\n\n{user_prompt}"
                response = self.ai_service.model.generate_content(
                    full_prompt,
                    generation_config={'temperature': temperature}
                )
                return response.text.strip()
        except Exception as e:
            self.logger.error(f"Error generating text response: {e}")
            return f"Error generating response: {str(e)}"
