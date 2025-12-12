import subprocess
from pathlib import Path
import logging
import urllib.request
import zipfile
import shutil
import os
import requests

logger = logging.getLogger(__name__)


class CVESourceManager:

    def __init__(self, cve_repositories: list[str], repo_folder: str, nuclei_templates_version: str = None, nuclei_templates_auto_update: bool = False):
        self.cve_repositories = cve_repositories
        self.repo_folder = repo_folder
        self.auto_update = nuclei_templates_auto_update
        version = nuclei_templates_version or os.getenv("NUCLEI_TEMPLATES_VERSION", "v10.3.5")
        self.nuclei_templates_version = self._normalize_version(version)

    def _run_command(self, command: list[str], cwd: str = None) -> tuple[int, str]:
        """
        Run a shell command and return its exit code and output.

        Args:
            command (list[str]): The command to run as a list of arguments.
            cwd (str, optional): The working directory to run the command in.

        Returns:
            tuple[int, str]: A tuple containing the exit code and combined stdout/stderr output.
        """
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                text=True,
                capture_output=True,
                check=False
            )
            output = result.stdout + result.stderr
            return result.returncode, output
        except Exception as e:
            logger.error(f"Error running command {' '.join(command)}: {e}")
            return -1, str(e)

    def _is_zip_url(self, url: str) -> bool:
        """Check if URL is a ZIP artifact."""
        return url.endswith('.zip') or 'archive/refs/tags' in url

    def _is_nuclei_templates_repo(self, url: str) -> bool:
        """Check if URL is the nuclei-templates repository."""
        return 'nuclei-templates' in url.lower()

    def _normalize_version(self, version: str) -> str:
        """
        Normalize version string to always include 'v' prefix.

        Args:
            version (str): Version string with or without 'v' prefix (e.g., 'v10.3.5' or '10.3.5')

        Returns:
            str: Normalized version with 'v' prefix (e.g., 'v10.3.5')
        """
        if not version:
            return "v10.3.5"
        version = version.strip()
        if not version.startswith('v'):
            return f"v{version}"
        return version

    def _get_latest_nuclei_templates_version(self) -> str:
        """
        Fetch the latest release version from GitHub API.

        Returns:
            str: Latest version tag (e.g., "v10.3.5")
        """
        try:
            api_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            data = response.json()
            tag_name = data.get("tag_name", "")
            if tag_name:
                logger.info(f"Latest nuclei-templates release: {tag_name}")
                return self._normalize_version(tag_name)
            else:
                logger.warning("Could not find tag_name in GitHub API response, using default version")
                return self.nuclei_templates_version
        except Exception as e:
            logger.error(f"Failed to fetch latest nuclei-templates version from GitHub: {e}")
            logger.info(f"Falling back to configured version: {self.nuclei_templates_version}")
            return self.nuclei_templates_version

    def _get_nuclei_templates_zip_url(self, version: str = None) -> str:
        """
        Get the ZIP URL for nuclei-templates based on version.

        Args:
            version (str, optional): Version to use. If None, uses self.nuclei_templates_version or latest if auto_update is enabled.

        Returns:
            str: ZIP download URL
        """
        if version is None:
            if self.auto_update:
                version = self._get_latest_nuclei_templates_version()
            else:
                version = self.nuclei_templates_version
        return f"https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{version}.zip"

    def _download_and_extract_zip(self, zip_url: str, extract_path: Path) -> bool:
        """
        Download a ZIP file and extract it to the specified path.

        Args:
            zip_url (str): URL of the ZIP file to download.
            extract_path (Path): Path where the ZIP should be extracted.

        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            logger.info(f"Downloading ZIP from {zip_url}...")

            # Create a temporary file for the ZIP
            zip_file_path = extract_path.parent / f"{extract_path.name}.zip"

            # Download the ZIP file using requests (better SSL handling)
            response = requests.get(zip_url, stream=True, timeout=300)
            response.raise_for_status()

            with open(zip_file_path, 'wb') as out_file:
                for chunk in response.iter_content(chunk_size=8192):
                    out_file.write(chunk)

            # Extract the ZIP file to a temporary location first
            temp_extract_path = extract_path.parent / f"{extract_path.name}_temp"
            logger.info(f"Extracting ZIP to {temp_extract_path}...")
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_extract_path)

            # Remove the ZIP file after extraction
            zip_file_path.unlink()

            # Handle nested extraction (ZIP files often contain a folder with the version name)
            extracted_items = list(temp_extract_path.iterdir())
            if len(extracted_items) == 1 and extracted_items[0].is_dir():
                # Move contents from nested folder to extract_path
                nested_folder = extracted_items[0]
                if extract_path.exists():
                    shutil.rmtree(extract_path)
                nested_folder.rename(extract_path)
                temp_extract_path.rmdir()
            else:
                # No nested folder, move temp to final location
                if extract_path.exists():
                    shutil.rmtree(extract_path)
                temp_extract_path.rename(extract_path)

            logger.info(f"Successfully downloaded and extracted {zip_url}")
            return True
        except Exception as e:
            logger.error(f"Failed to download/extract ZIP from {zip_url}: {e}")
            return False

    def clone_cve_repositories(self) -> None:
        """
        Clone CVE repositories or download ZIP artifacts into the repository folder.
        Automatically downloads nuclei-templates if a version is configured.
        """
        repo_root = Path(self.repo_folder)
        repo_root.mkdir(parents=True, exist_ok=True)

        # Automatically download nuclei-templates if version is configured or auto-update is enabled
        # (even if not in exploit_repositories list)
        if self.nuclei_templates_version or self.auto_update:
            repo_name = "nuclei-templates"
            repo_path = repo_root / repo_name

            # Get the version to use (latest if auto-update, otherwise configured version)
            if self.auto_update:
                target_version = self._get_latest_nuclei_templates_version()
                logger.info(f"Auto-update enabled: using latest version {target_version}")
            else:
                target_version = self.nuclei_templates_version

            zip_url = self._get_nuclei_templates_zip_url(target_version)

            # Check if we need to update (version changed or doesn't exist)
            should_download = True
            if repo_path.exists() and not self.auto_update:
                # Only skip if not auto-updating and version matches
                version_file = repo_path / ".nuclei_version"
                if version_file.exists():
                    try:
                        with open(version_file, 'r') as f:
                            existing_version = f.read().strip()
                        if existing_version == target_version:
                            logger.info(f"nuclei-templates version {target_version} already exists, skipping download")
                            should_download = False
                    except Exception:
                        pass
            elif self.auto_update:
                # Always check for updates when auto-update is enabled
                version_file = repo_path / ".nuclei_version"
                if version_file.exists():
                    try:
                        with open(version_file, 'r') as f:
                            existing_version = f.read().strip()
                        if existing_version == target_version:
                            logger.info(f"nuclei-templates is already at latest version {target_version}, skipping download")
                            should_download = False
                    except Exception:
                        pass

            if should_download:
                if repo_path.exists():
                    logger.info(f"Removing existing {repo_name} to update to version {target_version}...")
                    shutil.rmtree(repo_path)

                logger.info(f"Downloading nuclei-templates version {target_version} from {zip_url}...")
                if self._download_and_extract_zip(zip_url, repo_path):
                    # Save version file for future checks
                    try:
                        version_file = repo_path / ".nuclei_version"
                        with open(version_file, 'w') as f:
                            f.write(target_version)
                    except Exception as e:
                        logger.warning(f"Failed to save version file: {e}")
                    logger.info(f"Successfully downloaded nuclei-templates version {target_version}")
                else:
                    logger.error(f"Failed to download nuclei-templates version {target_version}")

        for repo_url in self.cve_repositories:
            # Handle nuclei-templates specially - use ZIP artifact if configured
            if self._is_nuclei_templates_repo(repo_url) and not repo_url.endswith('.zip'):
                # Already handled above, skip
                continue

            # Handle ZIP URLs directly
            if self._is_zip_url(repo_url):
                repo_name = Path(repo_url).stem.replace('.zip', '')
                # Remove version suffix if present (e.g., nuclei-templates-10.3.5 -> nuclei-templates)
                if '-' in repo_name and repo_name.split('-')[-1].replace('.', '').isdigit():
                    repo_name = '-'.join(repo_name.split('-')[:-1])
                repo_path = repo_root / repo_name

                # Always re-download ZIP artifacts
                if repo_path.exists():
                    logger.info(f"Removing existing {repo_name} to update...")
                    shutil.rmtree(repo_path)

                if self._download_and_extract_zip(repo_url, repo_path):
                    logger.info(f"Successfully downloaded {repo_url}")
                else:
                    logger.error(f"Failed to download {repo_url}")
                continue

            # Handle git repositories
            repo_name = Path(repo_url).stem
            repo_path = repo_root / repo_name

            if repo_path.exists():
                logger.info(f"Pulling latest changes for {repo_url}...")

                returncode, output = self._run_command(["git", "pull"], cwd=repo_path)

                if returncode != 0:
                    logger.error(f"Pulling repository failed: {output}")
                else:
                    logger.info(f"Successfully updated {repo_url}")
            else:
                logger.info(f"Cloning {repo_url} into {repo_path}...")

                returncode, output = self._run_command(["git", "clone", repo_url, repo_path])

                if returncode != 0:
                    logger.error(f"Cloning repository failed: {output}")
                else:
                    logger.info(f"Successfully cloned {repo_url}")

    def fetch_cve_file(self, cve_id: str) -> str:
        """
        Search for files relating to the specific CVE Identifier in the cloned repositories and return the first one found

        Args:
            cve_id (str): The CVE Identifier to search for.

        Returns:
            str: The contents of the exploit file if found, else an empty string.
        """
        # Always check nuclei-templates if version is configured (even if not in exploit_repositories)
        repos_to_check = list(self.cve_repositories)
        if self.nuclei_templates_version:
            # Add nuclei-templates to check list if not already there
            has_nuclei = any(self._is_nuclei_templates_repo(repo_url) for repo_url in self.cve_repositories)
            if not has_nuclei:
                repos_to_check.append("nuclei-templates")

        for repo_url in repos_to_check:
            # Determine repo name based on type
            if self._is_nuclei_templates_repo(repo_url) or repo_url == "nuclei-templates":
                repo_name = "nuclei-templates"
            elif self._is_zip_url(repo_url):
                repo_name = Path(repo_url).stem.replace('.zip', '')
                if '-' in repo_name and repo_name.split('-')[-1].replace('.', '').isdigit():
                    repo_name = '-'.join(repo_name.split('-')[:-1])
            else:
                repo_name = Path(repo_url).stem

            repo_path = Path(self.repo_folder) / repo_name

            if not repo_path.exists():
                continue

            # Use rglob to recursively search for files containing CVE ID
            for file_path in repo_path.rglob('*'):
                if file_path.is_file() and cve_id in file_path.name:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        logger.info(f"Found exploit for {cve_id} in {file_path}")
                        return content
                    except Exception as e:
                        logger.error(f"Failed to read exploit file {file_path}: {e}")

        logger.info(f"No exploit found for {cve_id}")
        return ""
