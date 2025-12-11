from dataclasses import dataclass
import yaml
from pathlib import Path
import os

@dataclass
class Config:
    WAF_CONTEXT_URLS: tuple[dict] = ()
    EXPLOIT_REPOSITORIES: tuple[str] = ()
    WAF_VALIDATION_API_URL: str = "https://public.gen0sec.com/v1/waf/validate"
    CONTEXT_FOLDER: str = "context"
    REPO_FOLDER: str = "repo"
    PROMPTS_FOLDER: str = "prompts"
    RESOURCE_UPDATE_INTERVAL: float = 24

    @classmethod
    def from_yaml(cls, filepath: str) -> "Config":

        path = Path(filepath).absolute()
        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        with open(path, 'r') as f:
            data: dict = yaml.safe_load(f)

        context_folder = path.parent / data.get("context_folder", cls.CONTEXT_FOLDER)
        repo_folder = path.parent / data.get("repo_folder", cls.REPO_FOLDER)
        prompts_folder = path.parent / data.get("prompts_folder", cls.PROMPTS_FOLDER)

        resource_update_interval = data.get("resource_update_interval", cls.RESOURCE_UPDATE_INTERVAL)
        if not isinstance(resource_update_interval, (int, float)):
            raise TypeError("Resource update interval must be a number.")

        validation_api_url = os.getenv("WAF_VALIDATION_API_URL") or data.get("waf_validation_api_url", cls.WAF_VALIDATION_API_URL)

        return cls(
            WAF_CONTEXT_URLS=data.get("waf_context_urls", cls.WAF_CONTEXT_URLS),
            EXPLOIT_REPOSITORIES=data.get("exploit_repositories", cls.EXPLOIT_REPOSITORIES),
            WAF_VALIDATION_API_URL=validation_api_url,
            CONTEXT_FOLDER=context_folder,
            PROMPTS_FOLDER=prompts_folder,
            REPO_FOLDER=repo_folder,
            RESOURCE_UPDATE_INTERVAL=resource_update_interval
        )
