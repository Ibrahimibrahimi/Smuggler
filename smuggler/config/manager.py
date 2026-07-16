"""
Config Manager
Handles loading, saving, and merging of scan configs and auth configs
"""

import os
import json
import yaml
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List
from datetime import datetime


CONFIG_DIR = Path.home() / ".http-smuggler"
AUTH_CONFIG_PATH = CONFIG_DIR / "auth_config.yaml"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.yaml"


@dataclass
class AuthConfig:
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    token: str = ""
    token_type: str = "Bearer"        # Bearer | Basic | Custom | None
    proxy_enabled: bool = False
    proxy_url: str = ""
    proxy_username: str = ""
    proxy_password: str = ""
    ssl_verify: bool = True
    saved_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def get_auth_headers(self) -> Dict[str, str]:
        """Build final headers dict including Authorization if token set"""
        headers = dict(self.headers)
        if self.token:
            if self.token_type == "Bearer":
                headers["Authorization"] = f"Bearer {self.token}"
            elif self.token_type == "Basic":
                headers["Authorization"] = f"Basic {self.token}"
            elif self.token_type == "Custom":
                headers["Authorization"] = self.token
        return headers

    def get_cookies_dict(self) -> Dict[str, str]:
        return dict(self.cookies)

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        if not self.proxy_enabled or not self.proxy_url:
            return None
        url = self.proxy_url
        if self.proxy_username and self.proxy_password:
            proto, rest = url.split("://", 1)
            url = f"{proto}://{self.proxy_username}:{self.proxy_password}@{rest}"
        return {"http": url, "https": url}


@dataclass
class ScanConfig:
    # Target
    target: str = ""
    targets_file: str = ""
    path: str = "/"
    method: str = "POST"

    # Techniques
    techniques: List[str] = field(default_factory=lambda: ["CL.TE", "TE.CL", "TE.TE", "H2.CL", "H2.TE", "CRLF"])
    timeout: float = 10.0
    timing_threshold: float = 5.0   # seconds extra to confirm timing-based vuln
    retries: int = 2
    threads: int = 5
    delay: float = 0.5              # delay between requests (rate limiting)

    # Output
    output_dir: str = "./results"
    output_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    verbose: int = 0                # 0=normal, 1=verbose, 2=debug

    # Auth (populated from AuthConfig when --auth is used)
    use_auth: bool = False
    auth: Optional[AuthConfig] = None

    # Scan behavior
    follow_redirects: bool = False
    detect_waf: bool = True
    fingerprint_backend: bool = True
    confirm_vulns: bool = True      # Run confirmation pass on detected vulns

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_auth_config(auth: AuthConfig) -> Path:
    ensure_config_dir()
    auth.saved_at = datetime.now().isoformat()
    data = auth.to_dict()
    with open(AUTH_CONFIG_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
    return AUTH_CONFIG_PATH


def load_auth_config(path: Optional[str] = None) -> Optional[AuthConfig]:
    config_path = Path(path) if path else AUTH_CONFIG_PATH
    if not config_path.exists():
        return None
    with open(config_path) as f:
        data = yaml.safe_load(f)
    if not data:
        return None
    return AuthConfig(
        headers=data.get("headers", {}),
        cookies=data.get("cookies", {}),
        token=data.get("token", ""),
        token_type=data.get("token_type", "Bearer"),
        proxy_enabled=data.get("proxy_enabled", False),
        proxy_url=data.get("proxy_url", ""),
        proxy_username=data.get("proxy_username", ""),
        proxy_password=data.get("proxy_password", ""),
        ssl_verify=data.get("ssl_verify", True),
        saved_at=data.get("saved_at", ""),
    )


def save_default_config(scan_cfg: ScanConfig) -> Path:
    ensure_config_dir()
    data = scan_cfg.to_dict()
    data.pop("auth", None)  # Don't embed full auth in main config
    with open(DEFAULT_CONFIG_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
    return DEFAULT_CONFIG_PATH


def load_default_config(path: Optional[str] = None) -> ScanConfig:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return ScanConfig()
    with open(config_path) as f:
        data = yaml.safe_load(f) or {}
    cfg = ScanConfig()
    for k, v in data.items():
        if hasattr(cfg, k) and k != "auth":
            setattr(cfg, k, v)
    return cfg


def build_scan_config(
    target: Optional[str] = None,
    targets_file: Optional[str] = None,
    techniques: Optional[List[str]] = None,
    timeout: float = 10.0,
    threads: int = 5,
    output_dir: str = "./results",
    output_formats: Optional[List[str]] = None,
    verbose: int = 0,
    auth: Optional[AuthConfig] = None,
    config_file: Optional[str] = None,
    **kwargs,
) -> ScanConfig:
    """Build a ScanConfig, merging file config with CLI overrides"""
    cfg = load_default_config(config_file)

    if target:
        cfg.target = target
    if targets_file:
        cfg.targets_file = targets_file
    if techniques:
        cfg.techniques = techniques
    cfg.timeout = timeout
    cfg.threads = threads
    cfg.output_dir = output_dir
    if output_formats:
        cfg.output_formats = output_formats
    cfg.verbose = verbose

    if auth:
        cfg.use_auth = True
        cfg.auth = auth

    for k, v in kwargs.items():
        if hasattr(cfg, k):
            setattr(cfg, k, v)

    return cfg


def auth_config_exists() -> bool:
    return AUTH_CONFIG_PATH.exists()


def get_auth_config_path() -> Path:
    return AUTH_CONFIG_PATH
