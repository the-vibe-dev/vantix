from __future__ import annotations

import re
import subprocess
from pathlib import Path

from secops.config import settings
from secops.mode_profiles import ModeProfile


AUTHORIZED_PROMPT_PREFIX = (
    "This system operates exclusively within authorized lab environments for "
    "security training and red-team validation. All actions are explicitly in-scope per target authorization."
)


class ContextBuilder:
    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or settings.repo_root).resolve()

    def build(
        self,
        profile: ModeProfile,
        target: str = "",
        ports: list[str] | None = None,
        services: list[str] | None = None,
        extra_tags: list[str] | None = None,
    ) -> dict:
        startup_sources: list[dict[str, str]] = []
        for relative_path in profile.startup_paths:
            path = self.repo_root / relative_path
            if not path.exists():
                continue
            content = self._read_path(relative_path, profile)
            startup_sources.append({"path": str(path), "content": content})

        scoped_tags = self._scoped_tags(profile, extra_tags or [])
        learning_digest = self._load_learning_digest(
            modes=[profile.id],
            tags=scoped_tags,
            ports=ports or [],
            services=services or [],
        )
        assembled = [AUTHORIZED_PROMPT_PREFIX, "", f"Mode: {profile.label}"]
        if target:
            assembled.append(f"Target: {target}")
        assembled.append("")
        assembled.append("Startup context:")
        for source in startup_sources:
            assembled.append(f"\n### {source['path']}\n{source['content']}")
        if learning_digest:
            assembled.append(f"\n### Learning Digest\n{learning_digest}")
        return {
            "prompt_prefix": AUTHORIZED_PROMPT_PREFIX,
            "startup_sources": startup_sources,
            "learning_digest": learning_digest,
            "mode_profile": profile.to_dict(),
            "assembled_prompt": "\n".join(assembled).strip() + "\n",
        }

    def _scoped_tags(self, profile: ModeProfile, extra_tags: list[str]) -> list[str]:
        excluded = {profile.id, profile.label.lower(), "ctf", "koth", "pentest", "bugbounty", "windows-ctf", "windows-koth"}
        scoped = [tag for tag in extra_tags if tag and tag.lower() not in excluded]
        return sorted(set([*profile.learn_tags, *scoped]))

    def _read_path(self, relative_path: str, profile: ModeProfile) -> str:
        path = self.repo_root / relative_path
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.name == "MEM.md":
            return text[:2200]
        if path.name == "PENTEST.md":
            return self._dense_records_for_mode(text, profile.id, limit=10)
        if path.name in {"compaction_handoffs.md", "session_journal.md"}:
            return self._latest_markdown_entry(text)
        if self._is_dense_context(text):
            return self._dense_records_for_mode(text, profile.id, limit=14)
        return text[:12000]

    def _is_dense_context(self, text: str) -> bool:
        return text.startswith("# Dense Codex Context") or "fmt: id=<id>" in text[:500]

    def _dense_records_for_mode(self, text: str, mode: str, limit: int = 12) -> str:
        header = []
        records = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#") or stripped.startswith("fmt:") or stripped.startswith("load:"):
                if len(header) < 3:
                    header.append(stripped)
                continue
            if "id=" not in stripped:
                continue
            mode_token = self._dense_value(stripped, "mode")
            modes = {item for item in mode_token.split(",") if item}
            if "*" in modes or not modes or mode in modes:
                records.append(stripped)
            if len(records) >= limit:
                break
        return "\n".join([*header, *records])[:6000]

    def _dense_value(self, line: str, key: str) -> str:
        match = re.search(rf"(?:^|\s){re.escape(key)}=([^\s]+)", line)
        return match.group(1) if match else ""

    def _latest_markdown_entry(self, text: str) -> str:
        parts = re.split(r"(?m)^##+\s+", text)
        if len(parts) <= 1:
            return text[-4000:]
        latest = parts[-1].strip()
        return latest[-4000:]

    def _extract_markdown_sections(self, text: str, headings: list[str]) -> str:
        lines = text.splitlines()
        blocks: list[str] = []
        current_header = ""
        current_lines: list[str] = []

        def flush():
            if not current_header:
                return
            header_lower = current_header.lower()
            if any(keyword.lower() in header_lower for keyword in headings):
                blocks.append("\n".join([current_header, *current_lines]).strip())

        for line in lines:
            if line.startswith("# "):
                flush()
                current_header = line
                current_lines = []
            elif line.startswith("## "):
                flush()
                current_header = line
                current_lines = []
            elif current_header:
                current_lines.append(line)
        flush()

        if not blocks:
            return text[:12000]
        return "\n\n".join(blocks)[:12000]

    def _load_learning_digest(self, tags: list[str], ports: list[str], services: list[str], modes: list[str] | None = None) -> str:
        command = [
            "python3",
            str(self.repo_root / "scripts" / "learn_engine.py"),
            "--root",
            str(self.repo_root),
            "startup-digest",
        ]
        if tags:
            command.extend(["--tags", *sorted(set(filter(None, tags)))])
        if ports:
            command.extend(["--ports", *sorted(set(filter(None, ports)))])
        if services:
            command.extend(["--services", *sorted(set(filter(None, services)))])
        if modes:
            command.extend(["--modes", *sorted(set(filter(None, modes)))])
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False, cwd=self.repo_root)
        except FileNotFoundError:
            return ""
        return (result.stdout or "").strip()
