from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from secops.config import settings


class LearningService:
    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or settings.repo_root).resolve()
        self.learning_root = self.repo_root / "memory" / "learning"

    def review_queue(self) -> list[dict[str, Any]]:
        return self._load_jsonl(self.learning_root / "review_queue.jsonl")

    def search_memory(self, query: str, limit: int = 25) -> list[dict[str, Any]]:
        records = []
        for name in ("vectors.jsonl", "guardrails.jsonl", "bugs.jsonl"):
            for row in self._load_jsonl(self.learning_root / name):
                haystack = " ".join(
                    [
                        row.get("title", ""),
                        row.get("summary", ""),
                        row.get("summary_short", ""),
                        " ".join(row.get("tags", [])),
                    ]
                ).lower()
                if query.lower() in haystack:
                    row["_source_file"] = name
                    records.append(row)
        records.sort(key=lambda row: row.get("confidence", 0.0), reverse=True)
        return records[:limit]

    def retrieve_for_run(
        self,
        *,
        mode: str,
        query: str,
        services: list[str],
        ports: list[str],
        tags: list[str],
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        records = []
        for name in ("vectors.jsonl", "guardrails.jsonl", "bugs.jsonl"):
            for row in self._load_jsonl(self.learning_root / name):
                score = self._score_row(row, mode=mode, query=query, services=services, ports=ports, tags=tags)
                if score <= 0:
                    continue
                row = dict(row)
                row["rank"] = round(score, 4)
                row["_source_file"] = name
                records.append(row)
        records.sort(key=lambda row: row["rank"], reverse=True)
        return records[:limit]

    def ingest_path(self, path: Path) -> str:
        command = [
            "python3",
            str(self.repo_root / "scripts" / "learn_engine.py"),
            "--root",
            str(self.repo_root),
            "ingest",
            "--source-path",
            str(path),
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False, cwd=self.repo_root)
        return (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")

    def _score_row(
        self,
        row: dict[str, Any],
        *,
        mode: str,
        query: str,
        services: list[str],
        ports: list[str],
        tags: list[str],
    ) -> float:
        text = " ".join(
            [
                row.get("title", ""),
                row.get("summary", ""),
                row.get("summary_short", ""),
                " ".join(row.get("tags", [])),
            ]
        ).lower()
        score = 0.0
        evidence_hits = 0
        row_tags = {tag.lower() for tag in row.get("tags", [])}
        query_terms = self._query_terms(query)
        query_matches = sum(1 for term in query_terms if term in text)
        if query_matches:
            evidence_hits += query_matches
            score += min(query_matches, 3) * 0.75
        if mode.lower() in row_tags:
            score += 4.0
        elif mode.startswith("windows") and "windows" in row_tags:
            score += 3.0
        elif mode == "koth" and "koth" in row_tags:
            score += 4.0
        elif mode == "pentest" and "web" in row_tags:
            score += 1.0
        for service in services:
            if service.lower() in text:
                evidence_hits += 1
                score += 2.5
        for port in ports:
            if port in text:
                evidence_hits += 1
                score += 1.5
        for tag in tags:
            if tag.lower() in row_tags:
                evidence_hits += 1
                score += 1.0
        scope = row.get("metadata", {}).get("scope", "") if isinstance(row.get("metadata"), dict) else ""
        if scope == "mode-only" and mode.lower() not in row_tags:
            score -= 10.0
        if evidence_hits == 0:
            return 0.0
        score += float(row.get("confidence", 0.0) or 0.0)
        return score

    def _query_terms(self, query: str) -> list[str]:
        generic = {
            "active",
            "against",
            "app",
            "baseline",
            "benchmark",
            "challenge",
            "ctf",
            "enumerate",
            "exploit",
            "initial",
            "launch",
            "local",
            "objective",
            "path",
            "proof",
            "run",
            "service",
            "solve",
            "target",
            "test",
            "validate",
            "validation",
            "web",
        }
        terms: list[str] = []
        for raw in query.lower().replace(":", " ").replace("/", " ").split():
            token = raw.strip(" ,.;()[]{}<>\"'")
            if len(token) < 4 or token in generic:
                continue
            terms.append(token)
        return sorted(set(terms))

    def _load_jsonl(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        rows = []
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return rows
