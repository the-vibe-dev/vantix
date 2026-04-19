import subprocess
from pathlib import Path

import pytest

from secops.updater import UpdateError, Updater


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return (proc.stdout or "").strip()


def make_repo_with_origin(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    source.mkdir()
    git(source, "init", "-b", "main")
    git(source, "config", "user.name", "Test User")
    git(source, "config", "user.email", "test@example.invalid")
    (source / "README.md").write_text("initial\n", encoding="utf-8")
    git(source, "add", "README.md")
    git(source, "commit", "-m", "initial")
    origin = tmp_path / "origin.git"
    git(source, "clone", "--bare", str(source), str(origin))
    repo = tmp_path / "repo"
    subprocess.run(["git", "clone", str(origin), str(repo)], capture_output=True, text=True, check=True)
    git(repo, "checkout", "main")
    return source, repo


def test_updater_check_reports_remote_ahead(tmp_path: Path) -> None:
    source, repo = make_repo_with_origin(tmp_path)
    (source / "README.md").write_text("updated\n", encoding="utf-8")
    git(source, "add", "README.md")
    git(source, "commit", "-m", "update")
    git(source, "push", str(tmp_path / "origin.git"), "main")

    result = Updater(repo, runtime_root=tmp_path / "runtime").check()

    assert result.ok is True
    assert result.changed is True
    assert result.details
    assert result.details["updates_available"] is True
    assert result.details["ahead_count"] == 1


def test_updater_blocks_dirty_working_tree(tmp_path: Path) -> None:
    _, repo = make_repo_with_origin(tmp_path)
    (repo / "local.txt").write_text("local\n", encoding="utf-8")
    updater = Updater(repo, runtime_root=tmp_path / "runtime")

    with pytest.raises(UpdateError) as exc:
        updater.ensure_clean_tree()

    assert exc.value.step == "preflight"
    assert "local.txt" in str(exc.value.details["dirty"])


def test_update_history_round_trip(tmp_path: Path) -> None:
    _, repo = make_repo_with_origin(tmp_path)
    updater = Updater(repo, runtime_root=tmp_path / "runtime")
    updater.record({"ok": True, "status": "noop", "current_commit": "abc"})

    state = updater.state.read()
    history = updater.state.update_history()
    assert state["last_update"]["status"] == "noop"
    assert history[-1]["current_commit"] == "abc"
