from waf_rule_mpc.waf_context_manager import WirefilterWAFContextManager
from waf_rule_mpc.plugins import CVEPluginManager
import logging
import time
import threading

logger = logging.getLogger(__name__)


class ResourceUpdater:
    def __init__(
        self,
        waf_context_manager: WirefilterWAFContextManager,
        plugin_manager: CVEPluginManager,
        interval_hours: float
    ):
        self.waf_context_manager = waf_context_manager
        self.plugin_manager = plugin_manager
        self.interval = interval_hours * 3600
        self._thread = None
        self._running = False

    def _run(self):
        """
        Internal loop that runs the update functions every interval until stopped.
        """
        while self._running:
            try:
                # Update all CVE source plugins
                results = self.plugin_manager.update_all()
                for plugin_name, success in results.items():
                    if success:
                        logger.info(f"Successfully updated plugin: {plugin_name}")
                    else:
                        logger.warning(f"Failed to update plugin: {plugin_name}")
            except Exception as e:
                logger.error(f"Error updating resources: {e}")

            time.sleep(self.interval)

    def start(self):
        """Starts the periodic fetching of resources."""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            logger.info(f"Periodic resource update started. Updating every {self.interval/3600} hours.")

    def stop(self):
        """Stops the periodic fetching of resources."""
        if not self._running:
            return
        self._running = False
        if self._thread and self._thread.is_alive():
            # Don't block indefinitely - daemon thread will exit with main process
            self._thread.join(timeout=0.5)
            if self._thread.is_alive():
                logger.debug("Resource updater thread still running (daemon, will exit with process)")
            self._thread = None
        logger.info("Periodic resource update stopped.")
