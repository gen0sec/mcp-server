import subprocess
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CVESourceManager:

    def __init__(self, cve_repositories: list[str], repo_folder: str):
        self.cve_repositories = cve_repositories
        self.repo_folder = repo_folder

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
        
    def clone_cve_repositories(self) -> None:
        """
        Clone CVE repositories into the repository folder.
        """
        repo_root = Path(self.repo_folder)
        repo_root.mkdir(parents=True, exist_ok=True)

        for repo_url in self.cve_repositories:
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
        for repo_url in self.cve_repositories:
            repo_name = Path(repo_url).stem
            repo_path = Path(self.repo_folder) / repo_name

            for root, dirs, files in repo_path.walk():
                for file in files:
                    if cve_id in file:
                        file_path = root / file
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                            logger.info(f"Found exploit for {cve_id} in {file_path}")
                            return content
                        except Exception as e:
                            logger.error(f"Failed to read exploit file {file_path}: {e}")

        logger.info(f"No exploit found for {cve_id}")
        return ""