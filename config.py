#!/usr/bin/env python3
import logging
import sys
from pathlib import Path
import toml # type: ignore
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class ConfigManager:
    """Handles configuration and session setup for the Email Analyzer."""

    def __init__(self, api_key=None, config_path="~/.vt.toml", max_retries=3):
        self.api_key = api_key
        self.max_retries = max_retries
        if not self.api_key:
            self._load_config(config_path)
        self.session = self._create_session()

    def _load_config(self, config_path):
        """Load configuration from TOML file."""
        try:
            path = Path(config_path).expanduser()
            if not path.exists():
                logger.error(f"Config file not found: {path}")
                sys.exit(1)
            config = toml.load(path)
            self.api_key = config.get("apikey")
            if not self.api_key:
                logger.error("VirusTotal API key not found in config file")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")
            sys.exit(1)

    def _create_session(self):
        """Create requests session with retry mechanism."""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.headers.update({"x-apikey": self.api_key})
        return session