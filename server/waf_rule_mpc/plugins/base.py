"""Base plugin interface for CVE sources."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class CVEResult:
    """Result from a CVE source lookup."""
    cve_id: str
    source: str
    content: str
    metadata: Optional[dict] = None

    def to_dict(self) -> dict:
        result = {
            "cve_id": self.cve_id,
            "source": self.source,
            "content": self.content,
        }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


class CVESourcePlugin(ABC):
    """
    Abstract base class for CVE source plugins.

    Each plugin implements a strategy for fetching CVE vulnerability data
    from a specific source (e.g., local files, APIs, databases).
    """

    def __init__(self, name: str, priority: int = 100, enabled: bool = True):
        """
        Initialize the plugin.

        Args:
            name: Human-readable name for the plugin
            priority: Lower numbers = higher priority (checked first)
            enabled: Whether this plugin is active
        """
        self.name = name
        self.priority = priority
        self.enabled = enabled

    @abstractmethod
    def fetch_cve(self, cve_id: str) -> Optional[CVEResult]:
        """
        Fetch CVE vulnerability data.

        Args:
            cve_id: The CVE identifier (e.g., "CVE-2025-55182")

        Returns:
            CVEResult if found, None otherwise
        """
        pass

    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the plugin (download resources, authenticate, etc.).

        Returns:
            True if initialization was successful
        """
        pass

    @abstractmethod
    def update(self) -> bool:
        """
        Update plugin resources (refresh data, re-authenticate, etc.).

        Returns:
            True if update was successful
        """
        pass

    def is_available(self) -> bool:
        """Check if the plugin is ready to serve requests."""
        return self.enabled

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, priority={self.priority}, enabled={self.enabled})"

