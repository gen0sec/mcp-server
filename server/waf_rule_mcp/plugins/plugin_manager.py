"""
CVE Plugin Manager.

Orchestrates multiple CVE source plugins, providing a unified interface
for fetching vulnerability data from various sources.
"""

from typing import Optional
import logging

from .base import CVESourcePlugin, CVEResult

logger = logging.getLogger(__name__)


class CVEPluginManager:
    """
    Manages multiple CVE source plugins.

    Plugins are queried in priority order (lower priority number = checked first).
    The first plugin to return data wins.
    """

    def __init__(self):
        """Initialize the plugin manager."""
        self._plugins: list[CVESourcePlugin] = []

    def register(self, plugin: CVESourcePlugin) -> None:
        """
        Register a plugin.

        Args:
            plugin: The plugin to register
        """
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda p: p.priority)
        logger.info(f"[PluginManager] Registered: {plugin.name} (priority={plugin.priority})")

    def unregister(self, plugin_name: str) -> bool:
        """
        Unregister a plugin by name.

        Args:
            plugin_name: Name of the plugin to remove

        Returns:
            True if plugin was found and removed
        """
        for plugin in self._plugins:
            if plugin.name == plugin_name:
                self._plugins.remove(plugin)
                logger.info(f"[PluginManager] Unregistered: {plugin_name}")
                return True
        return False

    def get_plugin(self, plugin_name: str) -> Optional[CVESourcePlugin]:
        """Get a plugin by name."""
        for plugin in self._plugins:
            if plugin.name == plugin_name:
                return plugin
        return None

    def list_plugins(self) -> list[dict]:
        """
        List all registered plugins.

        Returns:
            List of plugin info dicts
        """
        return [
            {
                "name": p.name,
                "priority": p.priority,
                "enabled": p.enabled,
                "available": p.is_available(),
            }
            for p in self._plugins
        ]

    def initialize_all(self) -> dict[str, bool]:
        """
        Initialize all registered plugins.

        Returns:
            Dict mapping plugin names to initialization success
        """
        results = {}
        for plugin in self._plugins:
            try:
                results[plugin.name] = plugin.initialize()
            except Exception as e:
                logger.error(f"[PluginManager] Failed to initialize {plugin.name}: {e}")
                results[plugin.name] = False
        return results

    def update_all(self) -> dict[str, bool]:
        """
        Update all registered plugins.

        Returns:
            Dict mapping plugin names to update success
        """
        results = {}
        for plugin in self._plugins:
            if plugin.enabled:
                try:
                    results[plugin.name] = plugin.update()
                except Exception as e:
                    logger.error(f"[PluginManager] Failed to update {plugin.name}: {e}")
                    results[plugin.name] = False
        return results

    def fetch_cve(self, cve_id: str, source: str = None) -> dict:
        """
        Fetch CVE data from registered plugins.

        Queries plugins in priority order. Returns the first successful result.

        Args:
            cve_id: The CVE identifier (e.g., "CVE-2025-55182")
            source: Optional specific source to query (plugin name)

        Returns:
            Dict with CVE data and metadata, or error info
        """
        if not self._plugins:
            return {
                "success": False,
                "error": "No CVE source plugins registered",
                "cve_id": cve_id,
            }

        # Filter to specific source if requested
        plugins_to_query = self._plugins
        if source:
            plugins_to_query = [p for p in self._plugins if p.name == source]
            if not plugins_to_query:
                return {
                    "success": False,
                    "error": f"Source '{source}' not found",
                    "cve_id": cve_id,
                    "available_sources": [p.name for p in self._plugins],
                }

        # Query plugins in priority order
        errors = []
        for plugin in plugins_to_query:
            if not plugin.enabled:
                continue

            if not plugin.is_available():
                errors.append(f"{plugin.name}: not available")
                continue

            try:
                result = plugin.fetch_cve(cve_id)
                if result:
                    return {
                        "success": True,
                        "cve_id": result.cve_id,
                        "source": result.source,
                        "content": result.content,
                        "metadata": result.metadata,
                    }
                errors.append(f"{plugin.name}: not found")
            except Exception as e:
                logger.error(f"[PluginManager] Error from {plugin.name}: {e}")
                errors.append(f"{plugin.name}: {str(e)}")

        return {
            "success": False,
            "error": f"CVE {cve_id} not found in any source",
            "cve_id": cve_id,
            "sources_checked": [p.name for p in plugins_to_query if p.enabled],
            "details": errors,
        }

    def fetch_cve_from_all(self, cve_id: str) -> dict:
        """
        Fetch CVE data from ALL enabled plugins.

        Useful for comparing data across sources.

        Args:
            cve_id: The CVE identifier

        Returns:
            Dict with results from all sources
        """
        results = {}
        for plugin in self._plugins:
            if not plugin.enabled or not plugin.is_available():
                continue

            try:
                result = plugin.fetch_cve(cve_id)
                if result:
                    results[plugin.name] = {
                        "success": True,
                        "content": result.content,
                        "metadata": result.metadata,
                    }
                else:
                    results[plugin.name] = {
                        "success": False,
                        "error": "Not found",
                    }
            except Exception as e:
                results[plugin.name] = {
                    "success": False,
                    "error": str(e),
                }

        return {
            "cve_id": cve_id,
            "sources": results,
            "found_in": [name for name, r in results.items() if r.get("success")],
        }

