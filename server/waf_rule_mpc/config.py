from dataclasses import dataclass, field
import yaml
from pathlib import Path
import os
from typing import Optional

@dataclass
class Config:
    WAF_CONTEXT_URLS: tuple[dict] = ()
    WAF_VALIDATION_API_URL: str = "https://public.gen0sec.com/v1/waf/validate"
    CONTEXT_FOLDER: str = "context"
    REPO_FOLDER: str = "repo"
    PROMPTS_FOLDER: str = "prompts"
    RESOURCE_UPDATE_INTERVAL: float = 24
    NUCLEI_TEMPLATES_VERSION: str = "v10.3.5"
    NUCLEI_TEMPLATES_AUTO_UPDATE: bool = False

    # Plugin configuration
    NUCLEI_OPENSOURCE_ENABLED: bool = True
    NUCLEI_OPENSOURCE_PRIORITY: int = 100
    PROJECTDISCOVERY_ENABLED: bool = False
    PROJECTDISCOVERY_API_KEY: Optional[str] = None
    PROJECTDISCOVERY_PRIORITY: int = 50  # Higher priority (lower number) than open source

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

        # Plugin configuration
        nuclei_opensource_enabled_raw = get_env_or_config("NUCLEI_OPENSOURCE_ENABLED", "nuclei_opensource_enabled", cls.NUCLEI_OPENSOURCE_ENABLED)
        if isinstance(nuclei_opensource_enabled_raw, str):
            nuclei_opensource_enabled = nuclei_opensource_enabled_raw.lower() in ("true", "1", "yes", "on")
        else:
            nuclei_opensource_enabled = bool(nuclei_opensource_enabled_raw)

        nuclei_opensource_priority_raw = get_env_or_config("NUCLEI_OPENSOURCE_PRIORITY", "nuclei_opensource_priority", cls.NUCLEI_OPENSOURCE_PRIORITY)
        nuclei_opensource_priority = int(nuclei_opensource_priority_raw)

        projectdiscovery_enabled_raw = get_env_or_config("PROJECTDISCOVERY_ENABLED", "projectdiscovery_enabled", cls.PROJECTDISCOVERY_ENABLED)
        if isinstance(projectdiscovery_enabled_raw, str):
            projectdiscovery_enabled = projectdiscovery_enabled_raw.lower() in ("true", "1", "yes", "on")
        else:
            projectdiscovery_enabled = bool(projectdiscovery_enabled_raw)

        projectdiscovery_api_key = get_env_or_config("PROJECTDISCOVERY_API_KEY", "projectdiscovery_api_key", cls.PROJECTDISCOVERY_API_KEY)
        if projectdiscovery_api_key:
            projectdiscovery_api_key = str(projectdiscovery_api_key).strip()
            if not projectdiscovery_api_key:
                projectdiscovery_api_key = None

        projectdiscovery_priority_raw = get_env_or_config("PROJECTDISCOVERY_PRIORITY", "projectdiscovery_priority", cls.PROJECTDISCOVERY_PRIORITY)
        projectdiscovery_priority = int(projectdiscovery_priority_raw)

        return cls(
            WAF_CONTEXT_URLS=data.get("waf_context_urls", cls.WAF_CONTEXT_URLS),
            WAF_VALIDATION_API_URL=validation_api_url,
            CONTEXT_FOLDER=context_folder,
            PROMPTS_FOLDER=prompts_folder,
            REPO_FOLDER=repo_folder,
            RESOURCE_UPDATE_INTERVAL=resource_update_interval,
            NUCLEI_TEMPLATES_VERSION=nuclei_templates_version,
            NUCLEI_TEMPLATES_AUTO_UPDATE=nuclei_templates_auto_update,
            NUCLEI_OPENSOURCE_ENABLED=nuclei_opensource_enabled,
            NUCLEI_OPENSOURCE_PRIORITY=nuclei_opensource_priority,
            PROJECTDISCOVERY_ENABLED=projectdiscovery_enabled,
            PROJECTDISCOVERY_API_KEY=projectdiscovery_api_key,
            PROJECTDISCOVERY_PRIORITY=projectdiscovery_priority,
        )
