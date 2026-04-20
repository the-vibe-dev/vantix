from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass
from pathlib import Path


DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    repo_root: Path
    runtime_root: Path
    database_url: str
    api_token: str
    secret_key: str
    codex_bin: str
    default_model: str
    default_reasoning_effort: str
    cve_search_url: str
    nvd_nist_api_key: str
    github_token: str
    vulncheck_api_token: str
    hackerone_username: str
    hackerone_api_token: str
    packetstorm_api_key: str
    reports_root: Path
    shared_root: Path
    frontend_root: Path
    skills_root: Path
    validation_benchmarks_root: Path
    enable_cve_mcp: bool
    cve_mcp_path: str
    cve_mcp_json_response: bool
    cve_mcp_stateless: bool
    cve_mcp_require_token: bool
    cve_mcp_allowed_origins: list[str]
    enable_vantix_mcp: bool
    vantix_mcp_path: str
    source_allowed_roots: list[Path]
    source_upload_max_mb: int
    source_upload_ttl_hours: int
    enable_write_execution: bool
    enable_codex_execution: bool
    enable_script_execution: bool
    default_stream_poll_interval: float
    dev_mode: bool
    cors_allow_origins: list[str]


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


def _default_runtime_root(root: Path) -> Path:
    state_home = Path(os.getenv("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    repo_id = hashlib.sha1(str(root).encode("utf-8")).hexdigest()[:8]
    return state_home / "ctf-security-ops" / f"{root.name}-{repo_id}"


repo_root = Path(os.getenv("SECOPS_REPO_ROOT", str(DEFAULT_REPO_ROOT))).resolve()
runtime_root = Path(os.getenv("SECOPS_RUNTIME_ROOT", str(_default_runtime_root(repo_root)))).resolve()
default_database_url = f"sqlite+pysqlite:///{runtime_root / 'secops.db'}"


settings = Settings(
    repo_root=repo_root,
    runtime_root=runtime_root,
    database_url=os.getenv("SECOPS_DATABASE_URL") or default_database_url,
    api_token=os.getenv("SECOPS_API_TOKEN", ""),
    secret_key=os.getenv("VANTIX_SECRET_KEY", os.getenv("SECOPS_SECRET_KEY", "")),
    codex_bin=os.getenv("SECOPS_CODEX_BIN", "codex"),
    default_model=os.getenv("SECOPS_DEFAULT_MODEL", "gpt-5.4"),
    default_reasoning_effort=os.getenv("SECOPS_DEFAULT_REASONING_EFFORT", "medium"),
    cve_search_url=os.getenv("SECOPS_CVE_SEARCH_URL", "http://127.0.0.1:5000"),
    nvd_nist_api_key=os.getenv("NVD_NIST_API_KEY", ""),
    github_token=os.getenv("GITHUB_TOKEN", ""),
    vulncheck_api_token=os.getenv("VULNCHECK_API_TOKEN", ""),
    hackerone_username=os.getenv("HACKERONE_USERNAME", ""),
    hackerone_api_token=os.getenv("HACKERONE_API_TOKEN", ""),
    packetstorm_api_key=os.getenv("PACKETSTORM_API_KEY", ""),
    reports_root=Path(os.getenv("SECOPS_REPORTS_ROOT", os.getenv("SECOPS_ARTIFACTS_ROOT", str(runtime_root / "reports")))),
    shared_root=Path(os.getenv("SECOPS_SHARED_ROOT", str(runtime_root))),
    frontend_root=Path(os.getenv("SECOPS_FRONTEND_ROOT", str(repo_root / "frontend"))),
    skills_root=Path(
        os.getenv("VANTIX_SKILLS_ROOT") or os.getenv("SECOPS_SKILLS_ROOT") or str(repo_root / "agent_skills")
    ),
    validation_benchmarks_root=Path(
        os.getenv("SECOPS_VALIDATION_BENCHMARKS_ROOT", str(repo_root / "tools" / "validation-benchmarks"))
    ),
    enable_cve_mcp=_env_bool("SECOPS_ENABLE_CVE_MCP", default=False),
    cve_mcp_path=os.getenv("SECOPS_CVE_MCP_PATH", "/mcp/cve"),
    cve_mcp_json_response=_env_bool("SECOPS_CVE_MCP_JSON_RESPONSE", default=True),
    cve_mcp_stateless=_env_bool("SECOPS_CVE_MCP_STATELESS", default=True),
    cve_mcp_require_token=_env_bool("SECOPS_CVE_MCP_REQUIRE_TOKEN", default=True),
    cve_mcp_allowed_origins=_env_list(
        "SECOPS_CVE_MCP_ALLOWED_ORIGINS",
        ["http://localhost", "http://127.0.0.1"],
    ),
    enable_vantix_mcp=_env_bool("SECOPS_ENABLE_VANTIX_MCP", default=False),
    vantix_mcp_path=os.getenv("SECOPS_VANTIX_MCP_PATH", "/mcp/vantix"),
    source_allowed_roots=[Path(value).expanduser().resolve() for value in _env_list("SECOPS_SOURCE_ALLOWED_ROOTS", [str(repo_root)])],
    source_upload_max_mb=int(os.getenv("SECOPS_SOURCE_UPLOAD_MAX_MB", "500")),
    source_upload_ttl_hours=int(os.getenv("SECOPS_SOURCE_UPLOAD_TTL_HOURS", "24")),
    enable_write_execution=_env_bool("SECOPS_ENABLE_WRITE_EXECUTION", default=False),
    enable_codex_execution=_env_bool("SECOPS_ENABLE_CODEX_EXECUTION", default=False),
    enable_script_execution=_env_bool("SECOPS_ENABLE_SCRIPT_EXECUTION", default=False),
    default_stream_poll_interval=float(os.getenv("SECOPS_STREAM_POLL_INTERVAL", "0.5")),
    dev_mode=_env_bool("SECOPS_DEV_MODE", default=False),
    cors_allow_origins=_env_list("SECOPS_CORS_ALLOW_ORIGINS", ["http://127.0.0.1:4173", "http://localhost:4173"]),
)
