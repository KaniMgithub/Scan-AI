"""Base scanner class for all security scanners."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import time
import logging

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    def __init__(self, name: str, description: str) -> None:
        """Initialize the scanner.

        Args:
            name: Scanner name
            description: Scanner description
        """
        self.name = name
        self.description = description
        self._workflow_profile = None

    def set_profile(self, profile: Any) -> None:
        """Set the active workflow profile for this scan.

        Args:
            profile: WorkflowProfile instance from workflow_loader
        """
        self._workflow_profile = profile

    def get_profile_timeout(self, default: int = 120) -> int:
        """Get timeout from active profile or fall back to default."""
        if self._workflow_profile:
            return self._workflow_profile.timeout
        return default

    def get_profile_command(self, target: str, **kwargs: Any) -> Optional[str]:
        """Build command from active profile template."""
        if self._workflow_profile:
            return self._workflow_profile.build_command(target, **kwargs)
        return None

    @abstractmethod
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform the scan on the target.

        Args:
            target: Target to scan (URL, domain, IP, etc.)
            **kwargs: Additional scanner-specific arguments
                      profile: str — workflow profile name to use

        Returns:
            Scan results dictionary
        """
        pass

    def _create_result(self,
                      success: bool = True,
                      data: Optional[Any] = None,
                      error: Optional[str] = None,
                      duration: Optional[float] = None) -> Dict[str, Any]:
        """Create a standardized result dictionary.

        Args:
            success: Whether the scan was successful
            data: Scan data/results
            error: Error message if scan failed
            duration: Scan duration in seconds

        Returns:
            Standardized result dictionary
        """
        result = {
            'scanner': self.name,
            'timestamp': time.time(),
            'success': success
        }

        if duration is not None:
            result['duration'] = duration

        if success and data is not None:
            result['data'] = data
        elif not success and error:
            result['error'] = error

        return result

    def _validate_target(self, target: str, target_type: str = 'target') -> None:
        """Validate the target format.

        Args:
            target: Target to validate
            target_type: Type of target for error messages

        Raises:
            ValueError: If target is invalid
        """
        if not target or not isinstance(target, str):
            raise ValueError(f"Invalid {target_type}: must be a non-empty string")

        target = target.strip()
        if not target:
            raise ValueError(f"Invalid {target_type}: cannot be empty or whitespace")

    def __str__(self) -> str:
        """String representation of the scanner."""
        return f"{self.name}: {self.description}"