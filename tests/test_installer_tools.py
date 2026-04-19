from pathlib import Path

from secops.installer import banner_text, default_runtime_root, render_progress_bar, render_user_systemd_unit, write_env_file
from secops.services.installer_state import InstallerStateService
from secops.services.tools import ToolService


def test_default_runtime_root_is_stable(tmp_path: Path) -> None:
    root_a = default_runtime_root(tmp_path / "repo")
    root_b = default_runtime_root(tmp_path / "repo")
    assert root_a == root_b
    assert "ctf-security-ops" in str(root_a)


def test_write_env_file_updates_existing_values(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("A=1\nB=2\n", encoding="utf-8")
    write_env_file(env_path, {"B": "3", "C": "4"})
    text = env_path.read_text(encoding="utf-8")
    assert "A=1" in text
    assert "B=3" in text
    assert "C=4" in text


def test_banner_text_uses_drop_art_when_present(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    drop = tmp_path / "drop"
    repo_root.mkdir()
    drop.mkdir()
    (drop / "vantix.txt").write_text("ASCII VANTIX\n", encoding="utf-8")

    assert banner_text(repo_root) == "ASCII VANTIX"


def test_banner_text_has_embedded_fallback(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    assert "888     888" in banner_text(repo_root)


def test_progress_bar_renders_known_total() -> None:
    assert render_progress_bar(2, 4, width=8) == "[####----] 2/4"
    assert render_progress_bar(9, 4, width=8) == "[########] 4/4"


def test_render_user_systemd_unit_contains_repo_paths(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    script_path = repo_root / "scripts" / "secops-api.sh"
    unit = render_user_systemd_unit(description="Vantix API", repo_root=repo_root, script_path=script_path)

    assert "Description=Vantix API" in unit
    assert f"WorkingDirectory={repo_root}" in unit
    assert f"EnvironmentFile=-{repo_root / '.env'}" in unit
    assert f"ExecStart=/usr/bin/env bash {script_path}" in unit
    assert "Restart=on-failure" in unit


def test_installer_state_round_trip(tmp_path: Path) -> None:
    service = InstallerStateService(tmp_path)
    service.write({"ready": True, "tools": {"suite": "common"}})
    service.append_tool_history({"tool_id": "ffuf", "ok": True})
    assert service.read()["ready"] is True
    history = service.tool_history()
    assert history[-1]["tool_id"] == "ffuf"


def test_tool_service_registry_and_dry_run_install(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / "agent_ops" / "config").mkdir(parents=True)
    (repo_root / "agent_ops" / "config" / "tool_registry.yaml").write_text(
        """
tools:
  - id: fake-tool
    name: Fake Tool
    binaries: [missing-fake-tool]
    suites: [minimal]
    allow_auto_install: true
    install:
      method: apt
      packages: [curl]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (repo_root / "agent_ops" / "config" / "tool_suites.yaml").write_text(
        """
suites:
  minimal:
    tools: [fake-tool]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    service = ToolService(repo_root=repo_root, runtime_root=tmp_path / "runtime")
    service.os_info = lambda: {"debian_family": True, "kali": False}  # type: ignore[method-assign]
    tools = service.list_tools()
    assert tools[0]["id"] == "fake-tool"
    assert tools[0]["installed"] is False
    results = service.install_tools(["fake-tool"], apply=False)
    assert results[0]["ok"] is True
    assert results[0]["status"] == "planned"
    assert results[0]["commands"]


def test_tool_service_reports_missing_apt_sources(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / "agent_ops" / "config").mkdir(parents=True)
    (repo_root / "agent_ops" / "config" / "tool_registry.yaml").write_text(
        """
tools:
  - id: apt-tool
    name: Apt Tool
    binaries: [missing-apt-tool]
    suites: [minimal]
    allow_auto_install: true
    install:
      method: apt
      packages: [curl]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (repo_root / "agent_ops" / "config" / "tool_suites.yaml").write_text(
        """
suites:
  minimal:
    tools: [apt-tool]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    service = ToolService(repo_root=repo_root, runtime_root=tmp_path / "runtime")
    service.os_info = lambda: {"debian_family": True, "kali": True}  # type: ignore[method-assign]
    service._apt_sources_configured = lambda: False  # type: ignore[method-assign]
    results = service.install_tools(["apt-tool"], apply=True)
    assert results[0]["ok"] is False
    assert results[0]["reason"] == "apt-sources-missing"
