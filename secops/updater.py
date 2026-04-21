from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secops.installer import Wizard, default_runtime_root, read_env_file
from secops.services.installer_state import InstallerStateService, utc_ts


@dataclass
class UpdateResult:
    ok: bool
    status: str
    current_commit: str = ""
    target_commit: str = ""
    changed: bool = False
    message: str = ""
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "ok": self.ok,
            "status": self.status,
            "current_commit": self.current_commit,
            "target_commit": self.target_commit,
            "changed": self.changed,
            "message": self.message,
            "details": self.details or {},
        }
        return payload


class UpdateError(RuntimeError):
    def __init__(self, step: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.step = step
        self.details = details or {}


class Updater:
    def __init__(self, repo_root: Path, runtime_root: Path | None = None) -> None:
        self.repo_root = repo_root.resolve()
        self.env = read_env_file(self.repo_root / ".env")
        self.runtime_root = (runtime_root or Path(self.env.get("SECOPS_RUNTIME_ROOT") or default_runtime_root(self.repo_root))).expanduser().resolve()
        self.state = InstallerStateService(self.runtime_root)
        self.install_root = self.runtime_root / "install"
        self.install_root.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.install_root / "update.lock"

    def run(self, command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        merged.update(self.env)
        if env:
            merged.update(env)
        return subprocess.run(command, cwd=cwd or self.repo_root, env=merged, capture_output=True, text=True, check=False)

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.run(["git", *args])

    def git_value(self, *args: str) -> str:
        proc = self.git(*args)
        if proc.returncode != 0:
            return ""
        return (proc.stdout or "").strip()

    def ensure_git_repo(self) -> None:
        if self.git("rev-parse", "--is-inside-work-tree").returncode != 0:
            raise UpdateError("preflight", "Repository is not a git checkout")
        if not self.git_value("remote", "get-url", "origin"):
            raise UpdateError("preflight", "Repository does not have an origin remote")

    def fetch(self) -> None:
        proc = self.git("fetch", "origin", "main")
        if proc.returncode != 0:
            raise UpdateError("fetch", "Failed to fetch origin/main", {"stderr": proc.stderr, "stdout": proc.stdout})

    def metadata(self) -> dict[str, Any]:
        head = self.git_value("rev-parse", "HEAD")
        target = self.git_value("rev-parse", "origin/main")
        branch = self.git_value("branch", "--show-current")
        ahead_count = self.git_value("rev-list", "--count", "HEAD..origin/main") if target else "0"
        behind_count = self.git_value("rev-list", "--count", "origin/main..HEAD") if target else "0"
        dirty = self.dirty_files()
        return {
            "branch": branch,
            "current_commit": head,
            "target_commit": target,
            "remote": self.git_value("remote", "get-url", "origin"),
            "updates_available": bool(target and head != target and ahead_count not in {"", "0"}),
            "ahead_count": int(ahead_count or 0),
            "behind_count": int(behind_count or 0),
            "dirty": dirty,
            "clean": not dirty,
        }

    def dirty_files(self) -> list[str]:
        proc = self.git("status", "--porcelain", "--untracked-files=all")
        if proc.returncode != 0:
            raise UpdateError("preflight", "Failed to inspect working tree", {"stderr": proc.stderr})
        return [line for line in (proc.stdout or "").splitlines() if line.strip()]

    def ensure_clean_tree(self) -> None:
        dirty = self.dirty_files()
        if dirty:
            raise UpdateError("preflight", "Working tree has local changes; commit, stash, or remove them before updating", {"dirty": dirty})

    def stash_worktree(self) -> dict[str, Any]:
        dirty = self.dirty_files()
        if not dirty:
            return {"created": False, "dirty": []}
        marker = f"vantix-updater-auto-{utc_ts()}"
        proc = self.git("stash", "push", "--include-untracked", "-m", marker)
        if proc.returncode != 0:
            raise UpdateError("preflight", "Failed to auto-stash dirty worktree", {"stderr": proc.stderr, "stdout": proc.stdout, "dirty": dirty})
        top = self.git_value("stash", "list", "--format=%gd:%s", "-n", "1")
        stash_ref = ""
        if top:
            left, _, right = top.partition(":")
            if marker in right:
                stash_ref = left.strip()
        if not stash_ref:
            raise UpdateError("preflight", "Auto-stash did not create a resolvable stash entry", {"dirty": dirty})
        return {"created": True, "dirty": dirty, "ref": stash_ref, "marker": marker}

    def restore_stash(self, stash_ref: str) -> None:
        ref = str(stash_ref or "").strip()
        if not ref:
            return
        proc = self.git("stash", "pop", ref)
        if proc.returncode != 0:
            raise UpdateError(
                "post-update",
                "Update completed, but restoring stashed changes failed; resolve stash manually",
                {"stash_ref": ref, "stderr": proc.stderr, "stdout": proc.stdout},
            )

    def acquire_lock(self) -> None:
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise UpdateError("lock", f"Update lock already exists: {self.lock_path}") from exc
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"pid": os.getpid(), "ts": utc_ts()}) + "\n")

    def release_lock(self) -> None:
        self.lock_path.unlink(missing_ok=True)

    def snapshot(self) -> str:
        stamp = utc_ts().replace(":", "").replace("-", "")
        snapshot_dir = self.install_root / "snapshots" / stamp
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        env_path = self.repo_root / ".env"
        if env_path.exists():
            shutil.copy2(env_path, snapshot_dir / ".env")
        if self.state.state_path.exists():
            shutil.copy2(self.state.state_path, snapshot_dir / "installer_state.json")
        return str(snapshot_dir)

    def managed_status(self) -> dict[str, Any]:
        script = self.repo_root / "scripts" / "vantixctl.sh"
        if not script.exists():
            return {"managed": False, "services": {}}
        proc = self.run(["bash", str(script), "status", "all", "--json"])
        if proc.returncode != 0:
            return {"managed": False, "services": {}, "error": (proc.stderr or proc.stdout).strip()}
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"managed": False, "services": {}, "raw": proc.stdout}

    def restart_services(self, before_status: dict[str, Any], *, no_restart: bool = False) -> dict[str, Any]:
        services = before_status.get("services") or {}
        running = [name for name, row in services.items() if row.get("running")]
        if not running:
            return {"restarted": [], "skipped": "no managed services were running"}
        if no_restart:
            return {"restarted": [], "skipped": "restart disabled", "previously_running": running}
        script = self.repo_root / "scripts" / "vantixctl.sh"
        restarted: list[str] = []
        failed: list[dict[str, str]] = []
        for service in running:
            proc = self.run(["bash", str(script), "restart", service])
            if proc.returncode == 0:
                restarted.append(service)
            else:
                failed.append({"service": service, "output": (proc.stderr or proc.stdout).strip()})
        return {"restarted": restarted, "failed": failed}

    def stop_managed_services(self, before_status: dict[str, Any], *, no_restart: bool = False) -> dict[str, Any]:
        if no_restart:
            return {"stopped": [], "skipped": "restart disabled"}
        services = before_status.get("services") or {}
        running = [name for name, row in services.items() if row.get("running")]
        if not running:
            return {"stopped": [], "skipped": "no managed services were running"}
        script = self.repo_root / "scripts" / "vantixctl.sh"
        stopped: list[str] = []
        failed: list[dict[str, str]] = []
        for service in running:
            proc = self.run(["bash", str(script), "stop", service])
            if proc.returncode == 0:
                stopped.append(service)
            else:
                failed.append({"service": service, "output": (proc.stderr or proc.stdout).strip()})
        if failed:
            raise UpdateError("services", "Failed to stop managed services", {"failed": failed})
        return {"stopped": stopped}

    def fast_forward(self) -> None:
        proc = self.git("merge", "--ff-only", "origin/main")
        if proc.returncode != 0:
            raise UpdateError("merge", "Fast-forward update failed; resolve branch divergence manually", {"stderr": proc.stderr, "stdout": proc.stdout})

    def ensure_backend(self) -> None:
        venv_python = self.repo_root / ".venv" / "bin" / "python"
        if not venv_python.exists():
            proc = self.run(["python3", "-m", "venv", str(self.repo_root / ".venv")])
            if proc.returncode != 0:
                raise UpdateError("backend", "Failed to create Python virtual environment", {"stderr": proc.stderr})
        pip = [str(venv_python), "-m", "pip"]
        commands = [
            [*pip, "install", "--upgrade", "pip"],
            [*pip, "install", "-e", ".[dev]"],
            [*pip, "install", "passlib[argon2]", "argon2-cffi", "playwright"],
        ]
        for command in commands:
            proc = self.run(command)
            if proc.returncode != 0:
                raise UpdateError("backend", f"Dependency refresh failed: {' '.join(command)}", {"stderr": proc.stderr, "stdout": proc.stdout})
        browser_install = self.run([str(venv_python), "-m", "playwright", "install", "--with-deps", "chromium"])
        if browser_install.returncode != 0:
            browser_install = self.run([str(venv_python), "-m", "playwright", "install", "chromium"])
        if browser_install.returncode != 0:
            raise UpdateError(
                "backend",
                "Playwright Chromium runtime install failed",
                {"stderr": browser_install.stderr, "stdout": browser_install.stdout},
            )

    def ensure_frontend(self) -> None:
        frontend = self.repo_root / "frontend"
        commands = [["corepack", "pnpm", "install"], ["corepack", "pnpm", "build"]]
        for command in commands:
            proc = self.run(command, cwd=frontend)
            if proc.returncode != 0:
                raise UpdateError("frontend", f"Frontend refresh failed: {' '.join(command)}", {"stderr": proc.stderr, "stdout": proc.stdout})

    def verify(self) -> dict[str, Any]:
        wizard = Wizard(self.repo_root)
        result = wizard.verify()
        if not result.get("ready"):
            raise UpdateError("verify", "Post-update verification failed", {"verify": result})
        return result

    def record(self, payload: dict[str, Any]) -> None:
        self.state.append_update_history(payload)
        current = self.state.read()
        current["last_update"] = payload
        current["updated_at"] = utc_ts()
        self.state.write(current)

    def check(self) -> UpdateResult:
        self.ensure_git_repo()
        self.fetch()
        meta = self.metadata()
        message = "updates available" if meta["updates_available"] else "already current"
        return UpdateResult(True, "check", meta["current_commit"], meta["target_commit"], meta["updates_available"], message, meta)

    def apply(self, *, no_restart: bool = False, allow_dirty: bool = False) -> UpdateResult:
        self.acquire_lock()
        before_status: dict[str, Any] = {}
        event: dict[str, Any] = {"ts": utc_ts(), "action": "apply", "ok": False}
        stashed: dict[str, Any] = {"created": False}
        try:
            self.ensure_git_repo()
            self.fetch()
            before = self.metadata()
            event.update({"before": before})
            if allow_dirty:
                stashed = self.stash_worktree()
                if stashed.get("created"):
                    event["auto_stash"] = stashed
            else:
                self.ensure_clean_tree()
            if not before["updates_available"]:
                result = UpdateResult(True, "noop", before["current_commit"], before["target_commit"], False, "already current", before)
                event.update(result.as_dict())
                if stashed.get("created"):
                    self.restore_stash(str(stashed.get("ref") or ""))
                self.record(event)
                return result
            before_status = self.managed_status()
            event["managed_services_before"] = before_status
            event["snapshot"] = self.snapshot()
            event["stopped_services"] = self.stop_managed_services(before_status, no_restart=no_restart)
            self.fast_forward()
            self.ensure_backend()
            self.ensure_frontend()
            verify = self.verify()
            restart = self.restart_services(before_status, no_restart=no_restart)
            if stashed.get("created"):
                self.restore_stash(str(stashed.get("ref") or ""))
            after = self.metadata()
            details = {"before": before, "after": after, "verify": verify, "restart": restart, "snapshot": event.get("snapshot")}
            if stashed.get("created"):
                details["auto_stash"] = stashed
            result = UpdateResult(True, "updated", before["current_commit"], after["current_commit"], True, "updated successfully", details)
            event.update(result.as_dict())
            self.record(event)
            return result
        except UpdateError as exc:
            event.update({"ok": False, "status": "failed", "failed_step": exc.step, "message": str(exc), "details": exc.details})
            self.record(event)
            raise
        finally:
            self.release_lock()

    def verify_only(self) -> UpdateResult:
        verify = self.verify()
        meta = self.metadata() if self.git("rev-parse", "--is-inside-work-tree").returncode == 0 else {}
        return UpdateResult(True, "verify", meta.get("current_commit", ""), meta.get("target_commit", ""), False, "verification passed", {"verify": verify, "git": meta})


def print_result(result: UpdateResult) -> None:
    print(json.dumps(result.as_dict(), indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Update Vantix from origin/main")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--check", action="store_true", help="fetch and report update availability")
    parser.add_argument("--apply", action="store_true", help="apply update; default when no mode is selected")
    parser.add_argument("--verify", action="store_true", help="run post-install verification only")
    parser.add_argument("--no-restart", action="store_true", help="do not restart managed services")
    parser.add_argument("--allow-dirty", action="store_true", help="auto-stash local changes while applying updates")
    args = parser.parse_args(argv)
    updater = Updater(Path(args.repo_root))
    try:
        if args.verify:
            print_result(updater.verify_only())
        elif args.check:
            print_result(updater.check())
        else:
            print_result(updater.apply(no_restart=args.no_restart, allow_dirty=args.allow_dirty))
    except UpdateError as exc:
        print(json.dumps({"ok": False, "status": "failed", "failed_step": exc.step, "message": str(exc), "details": exc.details}, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
