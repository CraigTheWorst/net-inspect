"""
net-inspect configuration and path management.
"""
import os
from pathlib import Path

# Get the package root directory (parent of netinspect/)
PACKAGE_ROOT = Path(__file__).parent.parent.parent

# Data directories
DATA_DIR = PACKAGE_ROOT / "data"
BASELINES_DIR = DATA_DIR / "baselines"
CAPTURES_DIR = DATA_DIR / "captures"
LOGS_DIR = DATA_DIR / "logs"
RESULTS_DIR = DATA_DIR / "results"

# CVE cache directory (in user's home)
HOME = Path.home()
CVE_CACHE_DIR = HOME / ".cache" / "net-inspect" / "cve"

# Create directories
for dir_path in [DATA_DIR, BASELINES_DIR, CAPTURES_DIR, LOGS_DIR, RESULTS_DIR, CVE_CACHE_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Convert to strings for compatibility
DATA_DIR_STR = str(DATA_DIR)
BASELINES_DIR_STR = str(BASELINES_DIR)
CAPTURES_DIR_STR = str(CAPTURES_DIR)
LOGS_DIR_STR = str(LOGS_DIR)
RESULTS_DIR_STR = str(RESULTS_DIR)
CVE_CACHE_DIR_STR = str(CVE_CACHE_DIR)

# Configuration Management
import json
from typing import Dict, Optional, Any


class ConfigManager:
    """
    Hybrid configuration management.

    Priority order:
    1. Command-line arguments (highest)
    2. Environment variables
    3. Config file (~/.config/net-inspect/config.json)
    4. Defaults (lowest)
    """

    def __init__(self, config_file: Optional[str] = None):
        """Initialize Config Manager."""
        if config_file:
            self.config_file = Path(config_file)
        else:
            self.config_file = HOME / ".config" / "net-inspect" / "config.json"

        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_config(self, config: Dict[str, Any]):
        """Save configuration to file."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

    def get(self, key: str, cli_value: Optional[Any] = None, default: Optional[Any] = None) -> Optional[Any]:
        """Get configuration value with priority resolution."""
        if cli_value is not None:
            return cli_value

        env_key = key.upper().replace('.', '_')
        env_value = os.environ.get(env_key)
        if env_value:
            return env_value

        config_value = self._get_nested(self.config, key)
        if config_value is not None:
            return config_value

        return default

    def _get_nested(self, data: Dict, key: str) -> Optional[Any]:
        """Get nested dictionary value using dot notation."""
        keys = key.split('.')
        value = data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return None
        return value

    def get_api_keys(self) -> Dict[str, str]:
        """Get all API keys from config."""
        return self.config.get('api_keys', {})


# Global config instance
_config_manager = None


def get_config_manager() -> ConfigManager:
    """Get global ConfigManager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def load_api_key(key_name: str, cli_value: Optional[str] = None) -> Optional[str]:
    """Load API key with priority resolution."""
    if cli_value:
        return cli_value

    env_key = f"{key_name.upper()}_API_KEY"
    if env_key in os.environ:
        return os.environ[env_key]

    config = get_config_manager()
    api_keys = config.get_api_keys()
    if key_name in api_keys:
        return api_keys[key_name]

    return None
