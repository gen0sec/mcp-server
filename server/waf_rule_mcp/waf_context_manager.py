import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class WirefilterWAFContextManager:
    def __init__(self, waf_context_urls: list[str], context_folder: str):
        self.waf_context_urls = waf_context_urls
        self.context_folder = context_folder

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
