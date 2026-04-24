"""V2-18 — YAML tool manifest loader."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from secops.tools.manifest import (
    ManifestError,
    ShellTool,
    ToolManifest,
    load_manifest_dir,
)
from secops.tools.registry import ToolRegistry


def test_from_mapping_happy_path():
    m = ToolManifest.from_mapping({
        "name": "echo_tool",
        "description": "prints a target",
        "command": "echo",
        "args": ["{target}"],
        "inputs": {"target": {"required": True, "type": "string"}},
    })
    assert m.name == "echo_tool"
    assert m.args == ["{target}"]
    assert m.inputs["target"]["required"] is True


@pytest.mark.parametrize(
    "data, match",
    [
        ({}, "missing required field"),
        ({"name": "", "command": "x"}, "name must not be empty"),
        ({"name": "x", "command": "y", "kind": "http"}, "unsupported kind"),
        ({"name": "x", "command": ""}, "command must not be empty"),
        ({"name": "x", "command": "y", "args": "nope"}, "args must be a list"),
        ({"name": "x", "command": "y", "inputs": "nope"}, "inputs must be a mapping"),
    ],
)
def test_from_mapping_rejects_bad_manifest(data, match):
    with pytest.raises(ManifestError, match=match):
        ToolManifest.from_mapping(data)


def test_from_yaml_loads_file(tmp_path: Path):
    path = tmp_path / "nmap_quick.yaml"
    path.write_text(
        """
        name: nmap_quick
        description: Quick TCP SYN scan.
        command: nmap
        args: ["-sS", "-T4", "{target}"]
        inputs:
          target: {required: true, type: string}
        timeout_seconds: 120
        """
    )
    m = ToolManifest.from_yaml(path)
    assert m.name == "nmap_quick"
    assert m.timeout_seconds == 120.0


def test_shell_tool_resolves_args_and_succeeds():
    @dataclass
    class _Proc:
        returncode: int
        stdout: str = ""
        stderr: str = ""

    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        assert kwargs["shell"] is False
        return _Proc(returncode=0, stdout="pong\n")

    m = ToolManifest.from_mapping({
        "name": "echo", "command": "echo",
        "args": ["hello", "{who}"],
        "inputs": {"who": {"required": True}},
    })
    tool = ShellTool(m, executor=fake_run)
    result = tool.run({"who": "world"})
    assert result.status == "completed"
    assert result.summary == "pong"
    # argv ends with the substituted placeholder, not the template
    assert calls[0][-1] == "world"


def test_shell_tool_missing_required_input_fails_fast():
    def fake_run(argv, **kwargs):  # pragma: no cover - should not be invoked
        raise AssertionError("executor must not run on bad inputs")

    m = ToolManifest.from_mapping({
        "name": "echo", "command": "echo",
        "args": ["{who}"],
        "inputs": {"who": {"required": True}},
    })
    tool = ShellTool(m, executor=fake_run)
    result = tool.run({})
    assert result.status == "failed"
    assert result.error["reason"] == "bad_inputs"


def test_shell_tool_nonzero_exit_reports_failed():
    def fake_run(argv, **kwargs):
        class P:
            returncode = 2
            stdout = ""
            stderr = "boom\n"
        return P()

    m = ToolManifest.from_mapping({"name": "x", "command": "false", "args": []})
    result = ShellTool(m, executor=fake_run).run({})
    assert result.status == "failed"
    assert result.error["reason"] == "nonzero_exit"
    assert "boom" in result.error["stderr"]


def test_load_manifest_dir_registers_all(tmp_path: Path):
    (tmp_path / "a.yaml").write_text("name: a\ncommand: echo\nargs: []\n")
    (tmp_path / "b.yml").write_text("name: b\ncommand: echo\nargs: []\n")
    (tmp_path / "README.md").write_text("ignored")
    registry = ToolRegistry()
    loaded = load_manifest_dir(tmp_path, registry)
    assert {m.name for m in loaded} == {"a", "b"}
    assert set(registry.names()) == {"a", "b"}
