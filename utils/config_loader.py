# utils/config_loader.py
import os
from pathlib import Path
from typing import Any

import yaml

_config_cache: dict | None = None
_CONFIG_FILE = Path(__file__).parent.parent / "config.yaml"


def get_config(config_path: str | None = None) -> dict:
    """
    Load and return the configuration dictionary.

    Reads from config.yaml by default. Environment variables override specific
    keys using the following mapping:
        THIRDEYE_VT_API_KEY       -> virustotal.api_key
        THIRDEYE_LOG_LEVEL        -> logging.level
        THIRDEYE_LOG_FILE         -> logging.log_file
        THIRDEYE_YARA_RULES       -> yara.rules_path
        THIRDEYE_REPORT_DIR       -> reporting.output_dir

    Results are cached after the first load.
    """
    global _config_cache

    if _config_cache is not None:
        return _config_cache

    path = Path(config_path) if config_path else _CONFIG_FILE

    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r") as f:
        config = yaml.safe_load(f)

    # Apply environment variable overrides
    _apply_env_overrides(config)

    _config_cache = config
    return config


def _apply_env_overrides(config: dict) -> None:
    """Apply environment variable overrides to the config dict in-place."""
    env_map = {
        "THIRDEYE_VT_API_KEY": ("virustotal", "api_key"),
        "THIRDEYE_LOG_LEVEL":  ("logging",    "level"),
        "THIRDEYE_LOG_FILE":   ("logging",    "log_file"),
        "THIRDEYE_YARA_RULES": ("yara",       "rules_path"),
        "THIRDEYE_REPORT_DIR": ("reporting",  "output_dir"),
    }

    for env_var, (section, key) in env_map.items():
        value = os.environ.get(env_var)
        if value is not None:
            if section not in config:
                config[section] = {}
            config[section][key] = value


def reload_config(config_path: str | None = None) -> dict:
    """Force a reload of the config, bypassing the cache."""
    global _config_cache
    _config_cache = None
    return get_config(config_path)
