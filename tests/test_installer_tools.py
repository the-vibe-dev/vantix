from pathlib import Path

from secops.installer import default_runtime_root, write_env_file
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
