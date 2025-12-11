from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class PromptManager:
    def __init__(self, prompt_folder: str):
        self.prompt_folder = prompt_folder

    def read_prompt_file(self, file_path: str) -> str:
        """
        Read in and return the contents of a specific prompt file.

        Args:
            file_path (str): The path to the prompt file.

        Returns:
            str: The content of the file.
        """
        try:
            path = Path(self.prompt_folder) / f"{file_path}.txt"

            if not path.exists():
                raise FileNotFoundError("The requested file is not found.")

            with open(path, 'r') as f:
                content = f.read()

            logger.info(f"Read prompt file {file_path}")
            return content
        except Exception as e:
            logger.error(f"Failed to read prompt file {file_path}: {e}")
            return ""