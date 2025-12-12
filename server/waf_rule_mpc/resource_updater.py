from waf_rule_mpc.waf_context_manager import WirefilterWAFContextManager
from waf_rule_mpc.cve_source_manager import CVESourceManager
import logging
import time
import threading

logger = logging.getLogger(__name__)

class ResourceUpdater:
    def __init__(self, waf_context_manager: WirefilterWAFContextManager, cve_source_manager: CVESourceManager, interval_hours: float):
        self.waf_context_manager = waf_context_manager
        self.cve_source_manager = cve_source_manager
        self.interval = interval_hours * 3600
        self._thread = None
        self._running = False

    def _run(self):
        """
        Internal loop that runs the update functions every interval until stopped.
        """
        while self._running:
            try:
                # Only update CVE repositories (nuclei templates)
                # Context files are now local and don't need to be downloaded
                self.cve_source_manager.clone_cve_repositories()
            except Exception as e:
                logger.error(f"Error fetching resources: {e}")

            time.sleep(self.interval)

    def start(self):
        """Starts the periodic fetching of resources."""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            logger.info(f"Periodic resource update started. Updating resource every {self.interval/3600} hours.")

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
