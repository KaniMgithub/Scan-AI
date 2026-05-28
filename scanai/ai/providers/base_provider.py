"""
Base Provider Interface for AI Models.
Defines the common interface that all AI providers must implement.
Enhanced with ScanAI's multi-key rotation support.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
import time
import asyncio
import logging


class BaseProvider(ABC):
    """Abstract base class for AI providers with rate limiting and key rotation."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

        # Rate limiting
        self.rate_limit = config.get("rate_limit", 60)
        self._min_request_interval = 60.0 / self.rate_limit if self.rate_limit > 0 else 0
        self._last_request_time = 0.0

        # API key rotation (ScanAI feature)
        self.api_keys: List[str] = config.get("api_keys", [])
        self.current_key_index = 0

    @abstractmethod
    def _initialize(self):
        """Initialize the provider backend."""
        pass

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """Generate response asynchronously."""
        pass

    @abstractmethod
    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """Generate response synchronously."""
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Get current model name."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available."""
        pass

    async def generate_with_reasoning(
        self,
        prompt: str,
        system_prompt: str,
        task_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate response with reasoning steps.
        Default implementation — can be overridden by providers.
        """
        full_prompt = f"{prompt}\n\nPlease think through this step-by-step and provide your reasoning."

        if task_context:
            full_prompt = f"Context: {task_context}\n\n{full_prompt}"

        response = await self.generate(full_prompt, system_prompt)

        return {
            "response": response,
            "reasoning": "Provider does not support explicit reasoning extraction"
        }

    def rotate_api_key(self) -> str:
        """
        Rotate to the next API key.

        Returns:
            Message about the key rotation.
        """
        if len(self.api_keys) <= 1:
            return "No additional API keys available for rotation"

        old_key = self.current_key_index + 1
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        self._initialize()
        new_key = self.current_key_index + 1
        return f"🔄 Rotated from API key #{old_key} to #{new_key} due to rate limit"

    def generate_with_retry(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        generation_config: Optional[dict] = None
    ) -> str:
        """
        Generate content synchronously with automatic API key rotation on rate limits.

        Args:
            prompt: The prompt to send to the model.
            system_prompt: Optional system prompt.
            generation_config: Optional generation config (temperature, max_tokens, etc.).

        Returns:
            Response text from the model.

        Raises:
            Exception if all API keys have been exhausted.
        """
        keys_tried = 0
        max_keys = max(len(self.api_keys), 1)
        last_error = None

        while keys_tried < max_keys:
            try:
                return self.generate_sync(prompt, system_prompt)
            except Exception as e:
                error_str = str(e).lower()
                if '429' in error_str or 'quota' in error_str or 'rate' in error_str:
                    keys_tried += 1
                    last_error = e
                    if keys_tried < max_keys:
                        rotation_msg = self.rotate_api_key()
                        self.logger.info(rotation_msg)
                        time.sleep(1)
                        continue
                    else:
                        raise Exception(
                            f"All {max_keys} API keys exhausted due to rate limits. "
                            f"Original error: {str(e)}"
                        )
                else:
                    raise e

        raise last_error if last_error else Exception("Failed to generate content")

    def generate_with_retry_config(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        Generate with custom config + automatic API key rotation on rate limits.

        Like generate_with_retry but uses generate_sync_with_config so
        custom temperature/max_tokens survive across key rotations.
        """
        keys_tried = 0
        max_keys = max(len(self.api_keys), 1)
        last_error = None

        while keys_tried < max_keys:
            try:
                if hasattr(self, 'generate_sync_with_config'):
                    return self.generate_sync_with_config(
                        prompt, system_prompt, temperature, max_tokens
                    )
                return self.generate_sync(prompt, system_prompt)
            except Exception as e:
                error_str = str(e).lower()
                if '429' in error_str or 'quota' in error_str or 'rate' in error_str:
                    keys_tried += 1
                    last_error = e
                    if keys_tried < max_keys:
                        rotation_msg = self.rotate_api_key()
                        self.logger.info(rotation_msg)
                        time.sleep(1)
                        continue
                    else:
                        raise Exception(
                            f"All {max_keys} API keys exhausted due to rate limits. "
                            f"Original error: {str(e)}"
                        )
                else:
                    raise e

        raise last_error if last_error else Exception("Failed to generate content")

    async def _apply_rate_limit(self):
        """Apply rate limiting between async API calls."""
        if self._min_request_interval > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self._min_request_interval:
                wait_time = self._min_request_interval - elapsed
                await asyncio.sleep(wait_time)
        self._last_request_time = time.time()

    def _apply_rate_limit_sync(self):
        """Apply rate limiting between sync API calls."""
        if self._min_request_interval > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self._min_request_interval:
                wait_time = self._min_request_interval - elapsed
                time.sleep(wait_time)
        self._last_request_time = time.time()
