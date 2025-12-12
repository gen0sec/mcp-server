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
    NUCLEI_TEMPLATES_VERSION: str = "v10.3.5"
    NUCLEI_TEMPLATES_AUTO_UPDATE: bool = False

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

        # Configuration precedence (highest to lowest):
        # 1. Environment variables (set by MCP extension from user_config in manifest.json)
        # 2. config.yaml file (for standalone usage)
        # 3. Default values (hardcoded in class)
        #
        # When running as MCP extension: user_config values are passed as env vars via manifest.json
        # When running standalone: values are read from config.yaml
        #
        # Note: Empty strings in env vars are treated as unset and fall back to config.yaml/defaults

        # Helper to get env var or fallback (treats empty strings as unset)
        def get_env_or_config(env_key: str, config_key: str, default):
            env_val = os.getenv(env_key)
            if env_val and env_val.strip():  # Not None and not empty/whitespace
                return env_val
            return data.get(config_key, default)

        validation_api_url = get_env_or_config("WAF_VALIDATION_API_URL", "waf_validation_api_url", cls.WAF_VALIDATION_API_URL)
        nuclei_templates_version_raw = get_env_or_config("NUCLEI_TEMPLATES_VERSION", "nuclei_templates_version", cls.NUCLEI_TEMPLATES_VERSION)
        nuclei_templates_version = nuclei_templates_version_raw if nuclei_templates_version_raw.startswith('v') else f"v{nuclei_templates_version_raw}"

        # Read auto-update from environment variable or config file
        nuclei_templates_auto_update_raw = get_env_or_config("NUCLEI_TEMPLATES_AUTO_UPDATE", "nuclei_templates_auto_update", cls.NUCLEI_TEMPLATES_AUTO_UPDATE)
        if isinstance(nuclei_templates_auto_update_raw, str):
            nuclei_templates_auto_update = nuclei_templates_auto_update_raw.lower() in ("true", "1", "yes", "on")
        elif isinstance(nuclei_templates_auto_update_raw, bool):
            nuclei_templates_auto_update = nuclei_templates_auto_update_raw
        else:
            nuclei_templates_auto_update = cls.NUCLEI_TEMPLATES_AUTO_UPDATE
        if not isinstance(nuclei_templates_auto_update, bool):
            raise TypeError("nuclei_templates_auto_update must be a boolean.")

        return cls(
            WAF_CONTEXT_URLS=data.get("waf_context_urls", cls.WAF_CONTEXT_URLS),
            EXPLOIT_REPOSITORIES=data.get("exploit_repositories", cls.EXPLOIT_REPOSITORIES),
            WAF_VALIDATION_API_URL=validation_api_url,
            CONTEXT_FOLDER=context_folder,
            PROMPTS_FOLDER=prompts_folder,
            REPO_FOLDER=repo_folder,
            RESOURCE_UPDATE_INTERVAL=resource_update_interval,
            NUCLEI_TEMPLATES_VERSION=nuclei_templates_version,
            NUCLEI_TEMPLATES_AUTO_UPDATE=nuclei_templates_auto_update
        )
