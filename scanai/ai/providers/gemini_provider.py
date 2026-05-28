from __future__ import annotations
"""
Gemini Provider Implementation.
Google Gemini models via langchain-google-genai.
"""

import os
from typing import Optional, Dict, Any, List, Union

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from scanai.ai.providers.base_provider import BaseProvider


class GeminiProvider(BaseProvider):
    """Google Gemini API provider using LangChain."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        # Get Gemini-specific configuration
        self.model_name = config.get("model", "gemini-2.5-flash-lite")
        self.temperature = config.get("temperature", 0.2)
        self.max_tokens = config.get("max_tokens", 10000)

        # API keys — from config or environment
        if not self.api_keys:
            env_keys = os.environ.get("GEMINI_API_KEYS") or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if env_keys:
                self.api_keys = [k.strip() for k in env_keys.split(",") if k.strip()]

        self.backend = None
        self._initialize()

    def _initialize(self):
        """Initialize Gemini backend with current API key."""
        if not LANGCHAIN_AVAILABLE:
            raise RuntimeError(
                "LangChain Google GenAI library not found. "
                "Install with: pip install langchain-google-genai langchain-core"
            )

        if not self.api_keys:
            raise RuntimeError(
                "GEMINI_API_KEYS not found. "
                "Set environment variable or add to .env file. "
                "Get your API key from: https://aistudio.google.com/apikey"
            )

        current_key = self.api_keys[self.current_key_index]

        try:
            self.backend = ChatGoogleGenerativeAI(
                model=self.model_name,
                google_api_key=current_key,
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
                convert_system_message_to_human=True
            )
            self.logger.info(
                f"Initialized Gemini provider: {self.model_name} "
                f"(key #{self.current_key_index + 1}/{len(self.api_keys)})"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Gemini backend: {e}")

    def _format_context(self, context: Optional[List[Any]]) -> List[Union[HumanMessage, AIMessage]]:
        """Format conversation context for LangChain."""
        if not context:
            return []

        messages = []
        for msg in context:
            if hasattr(msg, "content"):
                messages.append(msg)
            elif isinstance(msg, dict):
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "user":
                    messages.append(HumanMessage(content=content))
                else:
                    messages.append(AIMessage(content=content))

        return messages

    def _is_rate_limit_error(self, error: Exception) -> bool:
        """Check if an exception is a rate-limit / quota error from Gemini."""
        err = str(error).lower()
        return any(k in err for k in [
            '429', 'quota', 'rate', 'resource_exhausted',
            'resourceexhausted', 'too many requests',
        ])

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """Generate response using Gemini asynchronously with auto key rotation."""
        await self._apply_rate_limit()

        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.extend(self._format_context(context))
        messages.append(HumanMessage(content=prompt))

        keys_tried = 0
        max_keys = max(len(self.api_keys), 1)

        while keys_tried < max_keys:
            try:
                response = await self.backend.ainvoke(messages)
                return response.content
            except Exception as e:
                if self._is_rate_limit_error(e) and keys_tried + 1 < max_keys:
                    keys_tried += 1
                    rotation_msg = self.rotate_api_key()
                    self.logger.warning(rotation_msg)
                    import asyncio
                    await asyncio.sleep(1)
                    continue
                self.logger.error(f"Gemini async generation failed: {e}")
                raise

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """Generate response using Gemini synchronously with auto key rotation."""
        self._apply_rate_limit_sync()

        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.extend(self._format_context(context))
        messages.append(HumanMessage(content=prompt))

        keys_tried = 0
        max_keys = max(len(self.api_keys), 1)

        while keys_tried < max_keys:
            try:
                response = self.backend.invoke(messages)
                return response.content
            except Exception as e:
                if self._is_rate_limit_error(e) and keys_tried + 1 < max_keys:
                    keys_tried += 1
                    rotation_msg = self.rotate_api_key()
                    self.logger.warning(rotation_msg)
                    import time
                    time.sleep(1)
                    continue
                self.logger.error(f"Gemini sync generation failed: {e}")
                raise

    def generate_sync_with_config(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        context: Optional[list] = None
    ) -> str:
        """
        Generate response synchronously with custom config and auto key rotation.
        """
        self._apply_rate_limit_sync()

        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens if max_tokens is not None else self.max_tokens

        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.extend(self._format_context(context))
        messages.append(HumanMessage(content=prompt))

        keys_tried = 0
        max_keys = max(len(self.api_keys), 1)

        while keys_tried < max_keys:
            try:
                current_key = self.api_keys[self.current_key_index]
                temp_backend = ChatGoogleGenerativeAI(
                    model=self.model_name,
                    google_api_key=current_key,
                    temperature=temp,
                    max_output_tokens=tokens,
                    convert_system_message_to_human=True
                )
                response = temp_backend.invoke(messages)
                return response.content
            except Exception as e:
                if self._is_rate_limit_error(e) and keys_tried + 1 < max_keys:
                    keys_tried += 1
                    rotation_msg = self.rotate_api_key()
                    self.logger.warning(rotation_msg)
                    import time
                    time.sleep(1)
                    continue
                self.logger.error(f"Gemini sync generation (custom config) failed: {e}")
                raise

    def get_model_name(self) -> str:
        """Get current model name."""
        return self.model_name

    def is_available(self) -> bool:
        """Check if provider is available."""
        return LANGCHAIN_AVAILABLE and bool(self.api_keys) and self.backend is not None
