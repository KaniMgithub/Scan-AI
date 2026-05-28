"""
AI Client for ScanAI.
Unified client that delegates to specific providers (Gemini, future: OpenAI, Claude).
Modeled after guardian-cli's AIClient pattern.
"""

from typing import Optional, Dict, Any, List
import logging

from scanai.ai.providers import get_provider


class AIClient:
    """
    Unified AI client that works with multiple providers.
    Delegates all operations to the configured provider.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize AI client with specified provider.

        Args:
            config: Configuration dictionary with provider settings.
                Expected keys:
                    - provider: str (default: "gemini")
                    - api_keys: List[str]
                    - model: str
                    - temperature: float
                    - max_tokens: int
                    - rate_limit: int
        """
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

        # Load the appropriate provider based on config
        self.provider = get_provider(config)

        # Expose provider's model name
        self.model_name = self.provider.get_model_name()
        self.logger.info(
            f"AIClient initialized with {self.provider.__class__.__name__}: {self.model_name}"
        )

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """
        Generate AI response asynchronously.

        Args:
            prompt: User prompt.
            system_prompt: Optional system instruction.
            context: Optional conversation history.

        Returns:
            Generated response text.
        """
        return await self.provider.generate(prompt, system_prompt, context)

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """
        Generate AI response synchronously.

        Args:
            prompt: User prompt.
            system_prompt: Optional system instruction.
            context: Optional conversation history.

        Returns:
            Generated response text.
        """
        return self.provider.generate_sync(prompt, system_prompt, context)

    def generate_sync_with_config(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        context: Optional[list] = None
    ) -> str:
        """
        Generate AI response synchronously with custom generation config.

        Args:
            prompt: User prompt.
            system_prompt: Optional system instruction.
            temperature: Custom temperature.
            max_tokens: Custom max tokens.
            context: Optional conversation history.

        Returns:
            Generated response text.
        """
        if hasattr(self.provider, 'generate_sync_with_config'):
            return self.provider.generate_sync_with_config(
                prompt, system_prompt, temperature, max_tokens, context
            )
        # Fallback to standard generate_sync
        return self.provider.generate_sync(prompt, system_prompt, context)

    async def generate_with_reasoning(
        self,
        prompt: str,
        system_prompt: str,
        task_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate response with reasoning steps.

        Args:
            prompt: User prompt.
            system_prompt: System instruction.
            task_context: Optional task context.

        Returns:
            Dictionary with response and reasoning.
        """
        return await self.provider.generate_with_reasoning(
            prompt, system_prompt, task_context
        )

    def generate_with_retry(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        generation_config: Optional[dict] = None
    ) -> str:
        """
        Generate content with automatic API key rotation on rate limits.

        Args:
            prompt: The prompt to send.
            system_prompt: Optional system prompt.
            generation_config: Optional config (temperature, max_tokens).

        Returns:
            Response text.
        """
        return self.provider.generate_with_retry(prompt, system_prompt, generation_config)

    def generate_with_retry_config(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        Generate with custom config + automatic API key rotation on rate limits.

        Args:
            prompt: The prompt to send.
            system_prompt: Optional system prompt.
            temperature: Custom temperature.
            max_tokens: Custom max tokens.

        Returns:
            Response text.
        """
        return self.provider.generate_with_retry_config(
            prompt, system_prompt, temperature, max_tokens
        )

    def rotate_api_key(self) -> str:
        """Rotate to next API key."""
        return self.provider.rotate_api_key()

    def get_model_name(self) -> str:
        """Get the current model name."""
        return self.model_name

    def is_available(self) -> bool:
        """Check if the provider is properly configured."""
        return self.provider.is_available()


# Backward compatibility alias
GeminiClient = AIClient
