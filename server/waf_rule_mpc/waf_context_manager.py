import requests
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class WirefilterWAFContextManager:
    def __init__(self, waf_context_urls: list[str], context_folder: str):
        self.waf_context_urls = waf_context_urls
        self.context_folder = context_folder

    def download_waf_contexts(self) -> None:
        """
        Download the Wirefilter WAF context files from the stored URLs and save them in the context folder.
        """
        context_root = Path(self.context_folder)
        context_root.mkdir(parents=True, exist_ok=True)

        for item in self.waf_context_urls:
            try:
                url = item.get("url")
                name = item.get("name")

                if not url or not name:
                    logger.warning(f"Invalid WAF context entry: {item}")
                    continue

                response = requests.get(url)
                response.raise_for_status()
                filename = context_root / f"{name}.md"

                with open(filename, 'wb') as f:
                    f.write(response.content)

                logger.info(f"Fetched WAF context from {url} to {filename}")
            except Exception as e:
                logger.error(f"Failed to fetch WAF context from {url}: {e}")

    def read_context_file(self, file_path: str) -> str:
        """
        Read in and return the contents of a specific file.

        Args:
            file_path (str): The path to the resource file.

        Returns:
            str: The content of the file.
        """
        try:
            path = Path(self.context_folder) / f"{file_path}.md"

            if not path.exists():
                raise FileNotFoundError("The requested file is not found.")

            with open(path, 'r') as f:
                content = f.read()
            logger.info(f"Read resource file {file_path}")
            return content
        except Exception as e:
            logger.error(f"Failed to read resource file {file_path}: {e}")
            return ""
