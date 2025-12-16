"""
Nuclei Open Source Plugin.

Fetches CVE templates from the projectdiscovery/nuclei-templates GitHub repository.
This is the free, open-source version.
"""

from pathlib import Path
from typing import Optional
import logging
import requests
import zipfile
import shutil
import os

from .base import CVESourcePlugin, CVEResult

logger = logging.getLogger(__name__)


class NucleiOpenSourcePlugin(CVESourcePlugin):
    """
    Plugin for fetching CVE data from the nuclei-templates open source repository.

    Downloads and extracts the nuclei-templates ZIP archive from GitHub,
    then searches locally for CVE template files.
    """

    GITHUB_API_URL = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"
    GITHUB_ZIP_URL_TEMPLATE = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{version}.zip"

    def __init__(
        self,
        repo_folder: str,
        version: str = "v10.3.5",
        auto_update: bool = False,
        priority: int = 100,
        enabled: bool = True
    ):
        """
        Initialize the Nuclei Open Source plugin.

        Args:
            repo_folder: Path to store downloaded templates
            version: Version tag to download (e.g., "v10.3.5")
            auto_update: If True, always fetch latest version
            priority: Plugin priority (lower = checked first)
            enabled: Whether the plugin is active
        """
        super().__init__(
            name="Nuclei Open Source (GitHub)",
            priority=priority,
            enabled=enabled
        )
        self.repo_folder = Path(repo_folder)
        self.version = self._normalize_version(version)
        self.auto_update = auto_update
        self._templates_path = self.repo_folder / "nuclei-templates"

    def _normalize_version(self, version: str) -> str:
        """Normalize version string to include 'v' prefix."""
        if not version:
            return "v10.3.5"
        version = version.strip()
        if not version.startswith('v'):
            return f"v{version}"
        return version

    def _get_latest_version(self) -> str:
        """Fetch the latest release version from GitHub API."""
        try:
            response = requests.get(self.GITHUB_API_URL, timeout=10)
            response.raise_for_status()
            data = response.json()
            tag_name = data.get("tag_name", "")
            if tag_name:
                logger.info(f"[NucleiOpenSource] Latest release: {tag_name}")
                return self._normalize_version(tag_name)
        except Exception as e:
            logger.error(f"[NucleiOpenSource] Failed to fetch latest version: {e}")
        return self.version

    def _get_target_version(self) -> str:
        """Get the version to download."""
        if self.auto_update:
            return self._get_latest_version()
        return self.version

    def _get_current_version(self) -> Optional[str]:
        """Get the currently installed version."""
        version_file = self._templates_path / ".nuclei_version"
        if version_file.exists():
            try:
                return version_file.read_text().strip()
            except Exception:
                pass
        return None

    def _save_version(self, version: str) -> None:
        """Save the installed version."""
        try:
            version_file = self._templates_path / ".nuclei_version"
            version_file.write_text(version)
        except Exception as e:
            logger.warning(f"[NucleiOpenSource] Failed to save version file: {e}")

    def _download_and_extract(self, version: str) -> bool:
        """Download and extract the templates ZIP."""
        zip_url = self.GITHUB_ZIP_URL_TEMPLATE.format(version=version)
        zip_path = self.repo_folder / "nuclei-templates.zip"
        temp_path = self.repo_folder / "nuclei-templates_temp"

        try:
            logger.info(f"[NucleiOpenSource] Downloading {zip_url}...")

            response = requests.get(zip_url, stream=True, timeout=300)
            response.raise_for_status()

            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            logger.info(f"[NucleiOpenSource] Extracting...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_path)

            zip_path.unlink()

            # Handle nested folder structure
            extracted = list(temp_path.iterdir())
            if len(extracted) == 1 and extracted[0].is_dir():
                nested = extracted[0]
                if self._templates_path.exists():
                    shutil.rmtree(self._templates_path)
                nested.rename(self._templates_path)
                temp_path.rmdir()
            else:
                if self._templates_path.exists():
                    shutil.rmtree(self._templates_path)
                temp_path.rename(self._templates_path)

            self._save_version(version)
            logger.info(f"[NucleiOpenSource] Successfully installed version {version}")
            return True

        except Exception as e:
            logger.error(f"[NucleiOpenSource] Download failed: {e}")
            # Cleanup on failure
            if zip_path.exists():
                zip_path.unlink()
            if temp_path.exists():
                shutil.rmtree(temp_path)
            return False

    def initialize(self) -> bool:
        """Initialize the plugin by downloading templates if needed."""
        self.repo_folder.mkdir(parents=True, exist_ok=True)

        target_version = self._get_target_version()
        current_version = self._get_current_version()

        if current_version == target_version:
            logger.info(f"[NucleiOpenSource] Already at version {target_version}")
            return True

        if self._templates_path.exists():
            logger.info(f"[NucleiOpenSource] Updating from {current_version} to {target_version}")
            shutil.rmtree(self._templates_path)

        return self._download_and_extract(target_version)

    def update(self) -> bool:
        """Update templates to latest version."""
        if not self.auto_update:
            logger.info("[NucleiOpenSource] Auto-update disabled, skipping")
            return True

        target_version = self._get_latest_version()
        current_version = self._get_current_version()

        if current_version == target_version:
            logger.info(f"[NucleiOpenSource] Already at latest version {target_version}")
            return True

        logger.info(f"[NucleiOpenSource] Updating to {target_version}")
        if self._templates_path.exists():
            shutil.rmtree(self._templates_path)
        return self._download_and_extract(target_version)

    def is_available(self) -> bool:
        """Check if templates are available."""
        return self.enabled and self._templates_path.exists()

    def fetch_cve(self, cve_id: str) -> Optional[CVEResult]:
        """
        Search for a CVE template file in the downloaded templates.

        Args:
            cve_id: The CVE identifier (e.g., "CVE-2025-55182")

        Returns:
            CVEResult if found, None otherwise
        """
        if not self.is_available():
            logger.warning("[NucleiOpenSource] Templates not available")
            return None

        cve_id_upper = cve_id.upper()
        cve_id_lower = cve_id.lower()

        # Search for files containing the CVE ID
        for file_path in self._templates_path.rglob('*'):
            if file_path.is_file():
                filename = file_path.name
                if cve_id_upper in filename.upper() or cve_id_lower in filename.lower():
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        logger.info(f"[NucleiOpenSource] Found {cve_id} in {file_path}")
                        return CVEResult(
                            cve_id=cve_id,
                            source=self.name,
                            content=content,
                            metadata={
                                "file_path": str(file_path),
                                "version": self._get_current_version(),
                            }
                        )
                    except Exception as e:
                        logger.error(f"[NucleiOpenSource] Failed to read {file_path}: {e}")

        logger.info(f"[NucleiOpenSource] No template found for {cve_id}")
        return None

