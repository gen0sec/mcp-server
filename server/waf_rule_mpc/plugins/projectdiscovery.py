"""
ProjectDiscovery Plugin.

Fetches CVE vulnerability data from the ProjectDiscovery API.
Requires an API key for access to premium vulnerability data.
"""

from typing import Optional
import logging
import requests
import json

from .base import CVESourcePlugin, CVEResult

logger = logging.getLogger(__name__)


class ProjectDiscoveryPlugin(CVESourcePlugin):
    """
    Plugin for fetching CVE data from the ProjectDiscovery API.

    Provides access to premium vulnerability intelligence including
    detailed exploit information, severity scores, and remediation guidance.
    """

    API_BASE_URL = "https://api.projectdiscovery.io/v2/vulnerability"

    def __init__(
        self,
        api_key: str,
        priority: int = 50,
        enabled: bool = True
    ):
        """
        Initialize the ProjectDiscovery plugin.

        Args:
            api_key: ProjectDiscovery API key
            priority: Plugin priority (lower = checked first). Default 50 (higher priority than open source)
            enabled: Whether the plugin is active
        """
        super().__init__(
            name="ProjectDiscovery API",
            priority=priority,
            enabled=enabled
        )
        self.api_key = api_key
        self._api_verified = False

    def _get_headers(self) -> dict:
        """Get HTTP headers for API requests."""
        return {
            "X-API-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "gen0sec-mcp-server/1.0",
        }

    def _verify_api_key(self) -> bool:
        """Verify the API key is valid."""
        if not self.api_key:
            logger.warning("[ProjectDiscovery] No API key configured")
            return False

        # Test with a known CVE
        try:
            response = requests.get(
                f"{self.API_BASE_URL}/CVE-2021-44228",
                headers=self._get_headers(),
                timeout=10
            )
            if response.status_code == 200:
                logger.info("[ProjectDiscovery] API key verified successfully")
                return True
            elif response.status_code == 401:
                logger.error("[ProjectDiscovery] Invalid API key")
                return False
            elif response.status_code == 403:
                logger.error("[ProjectDiscovery] API key lacks required permissions")
                return False
            else:
                # API might return 404 for unknown CVE, but that's fine
                logger.info(f"[ProjectDiscovery] API responded with status {response.status_code}")
                return response.status_code != 401

        except requests.exceptions.Timeout:
            logger.error("[ProjectDiscovery] API request timed out")
            return False
        except Exception as e:
            logger.error(f"[ProjectDiscovery] Failed to verify API key: {e}")
            return False

    def initialize(self) -> bool:
        """Initialize the plugin by verifying API credentials."""
        if not self.api_key:
            logger.warning("[ProjectDiscovery] No API key provided, plugin disabled")
            self.enabled = False
            return False

        self._api_verified = self._verify_api_key()
        if not self._api_verified:
            logger.warning("[ProjectDiscovery] API key verification failed")
            # Don't disable the plugin, might be a temporary issue
        return self._api_verified

    def update(self) -> bool:
        """Re-verify API credentials."""
        self._api_verified = self._verify_api_key()
        return self._api_verified

    def is_available(self) -> bool:
        """Check if the API is accessible."""
        return self.enabled and bool(self.api_key)

    def fetch_cve(self, cve_id: str) -> Optional[CVEResult]:
        """
        Fetch CVE vulnerability data from ProjectDiscovery API.

        Args:
            cve_id: The CVE identifier (e.g., "CVE-2025-55182")

        Returns:
            CVEResult if found, None otherwise
        """
        if not self.is_available():
            logger.debug("[ProjectDiscovery] Plugin not available")
            return None

        # Normalize CVE ID format
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        try:
            url = f"{self.API_BASE_URL}/{cve_id}"
            logger.info(f"[ProjectDiscovery] Fetching {cve_id} from API...")

            response = requests.get(
                url,
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                # Format the response as a readable template
                content = self._format_vulnerability_data(cve_id, data)

                logger.info(f"[ProjectDiscovery] Found data for {cve_id}")
                return CVEResult(
                    cve_id=cve_id,
                    source=self.name,
                    content=content,
                    metadata={
                        "api_response": data,
                        "api_url": url,
                    }
                )

            elif response.status_code == 404:
                logger.info(f"[ProjectDiscovery] No data found for {cve_id}")
                return None

            elif response.status_code == 401:
                logger.error("[ProjectDiscovery] Invalid API key")
                return None

            elif response.status_code == 429:
                logger.warning("[ProjectDiscovery] Rate limit exceeded")
                return None

            else:
                logger.warning(f"[ProjectDiscovery] API returned status {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            logger.error(f"[ProjectDiscovery] Request timeout for {cve_id}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"[ProjectDiscovery] Request failed for {cve_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"[ProjectDiscovery] Unexpected error for {cve_id}: {e}")
            return None

    def _format_vulnerability_data(self, cve_id: str, data: dict) -> str:
        """
        Format API response into a structured template.

        Args:
            cve_id: The CVE identifier
            data: API response data

        Returns:
            Formatted vulnerability template string
        """
        lines = [
            f"id: {cve_id}",
            "",
            "info:",
        ]

        # Extract and format info section
        info = data.get("info", {}) or data

        name = info.get("name") or data.get("name") or cve_id
        lines.append(f"  name: {name}")

        author = info.get("author") or data.get("author")
        if author:
            if isinstance(author, list):
                lines.append(f"  author: {', '.join(author)}")
            else:
                lines.append(f"  author: {author}")

        severity = info.get("severity") or data.get("severity")
        if severity:
            lines.append(f"  severity: {severity}")

        description = info.get("description") or data.get("description")
        if description:
            lines.append(f"  description: |")
            for desc_line in description.split('\n'):
                lines.append(f"    {desc_line}")

        # References
        references = info.get("references") or data.get("references") or []
        if references:
            lines.append("  reference:")
            for ref in references:
                lines.append(f"    - {ref}")

        # Classification
        classification = info.get("classification") or data.get("classification") or {}
        if classification:
            lines.append("  classification:")
            if classification.get("cvss-metrics"):
                lines.append(f"    cvss-metrics: {classification['cvss-metrics']}")
            if classification.get("cvss-score"):
                lines.append(f"    cvss-score: {classification['cvss-score']}")
            if classification.get("cve-id"):
                lines.append(f"    cve-id: {classification['cve-id']}")
            if classification.get("cwe-id"):
                cwe = classification["cwe-id"]
                if isinstance(cwe, list):
                    lines.append(f"    cwe-id: {', '.join(cwe)}")
                else:
                    lines.append(f"    cwe-id: {cwe}")
            if classification.get("epss-score"):
                lines.append(f"    epss-score: {classification['epss-score']}")

        # Tags
        tags = info.get("tags") or data.get("tags") or []
        if tags:
            if isinstance(tags, list):
                lines.append(f"  tags: {', '.join(tags)}")
            else:
                lines.append(f"  tags: {tags}")

        # Remediation
        remediation = info.get("remediation") or data.get("remediation")
        if remediation:
            lines.append(f"  remediation: |")
            for rem_line in str(remediation).split('\n'):
                lines.append(f"    {rem_line}")

        # HTTP requests (if available)
        http_requests = data.get("http") or data.get("requests") or []
        if http_requests:
            lines.append("")
            lines.append("http:")
            for i, req in enumerate(http_requests):
                if isinstance(req, dict):
                    method = req.get("method", "GET")
                    path = req.get("path", ["/"])
                    if isinstance(path, list):
                        path = path[0] if path else "/"

                    lines.append(f"  - method: {method}")
                    lines.append(f"    path:")
                    lines.append(f"      - {path}")

                    # Headers
                    headers = req.get("headers")
                    if headers:
                        lines.append(f"    headers:")
                        for k, v in headers.items():
                            lines.append(f"      {k}: {v}")

                    # Body
                    body = req.get("body")
                    if body:
                        lines.append(f"    body: |")
                        for body_line in str(body).split('\n'):
                            lines.append(f"      {body_line}")

                    # Matchers
                    matchers = req.get("matchers") or req.get("matchers-condition")
                    if matchers:
                        lines.append(f"    matchers:")
                        if isinstance(matchers, list):
                            for matcher in matchers:
                                if isinstance(matcher, dict):
                                    lines.append(f"      - type: {matcher.get('type', 'word')}")
                                    if matcher.get("words"):
                                        lines.append(f"        words:")
                                        for word in matcher["words"]:
                                            lines.append(f"          - \"{word}\"")
                                    if matcher.get("regex"):
                                        lines.append(f"        regex:")
                                        for regex in matcher["regex"]:
                                            lines.append(f"          - \"{regex}\"")

        # Raw payload data (if available and not structured)
        payload = data.get("payload") or data.get("payloads")
        if payload:
            lines.append("")
            lines.append("# Payload Information:")
            if isinstance(payload, dict):
                lines.append(f"# {json.dumps(payload, indent=2)}")
            elif isinstance(payload, list):
                for p in payload:
                    lines.append(f"#   - {p}")
            else:
                lines.append(f"# {payload}")

        return "\n".join(lines)

