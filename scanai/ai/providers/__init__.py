"""
AI Providers Module
Provider factory and registry for different AI providers.
"""

from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

# Provider registry — extensible for future providers
PROVIDERS = {
    "gemini": "scanai.ai.providers.gemini_provider.GeminiProvider",
}


def get_provider(config: Dict[str, Any]):
    """
    Factory function to create appropriate AI provider.

    Args:
        config: Configuration dictionary with 'provider', 'api_keys', etc.

    Returns:
        Initialized provider instance.

    Raises:
        ValueError: If provider is unknown.
        RuntimeError: If provider initialization fails.
    """
    provider_name = config.get("provider", "gemini").lower()

    if provider_name not in PROVIDERS:
        available = ", ".join(PROVIDERS.keys())
        raise ValueError(
            f"Unknown provider: {provider_name}. "
            f"Available providers: {available}"
        )

    # Import and instantiate provider
    provider_path = PROVIDERS[provider_name]
    module_path, class_name = provider_path.rsplit(".", 1)

    try:
        import importlib
        module = importlib.import_module(module_path)
        provider_class = getattr(module, class_name)

        provider = provider_class(config)
        logger.info(f"Loaded AI provider: {provider_name}")
        return provider

    except ImportError as e:
        raise RuntimeError(
            f"Failed to import provider {provider_name}: {e}. "
            f"Make sure required dependencies are installed."
        )
    except Exception as e:
        raise RuntimeError(f"Failed to initialize provider {provider_name}: {e}")


def list_available_providers() -> list:
    """Get list of available provider names."""
    return list(PROVIDERS.keys())


__all__ = ["get_provider", "list_available_providers", "PROVIDERS"]
