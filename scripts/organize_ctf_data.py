#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(".")
MEMORY_DIR = ROOT / "memory"
SESSION_ROOT = MEMORY_DIR / "sessions"
INDEX_FILE = MEMORY_DIR / "session_index.jsonl"
ALIASES_FILE = MEMORY_DIR / "session_aliases.json"
JOURNAL_FILE = MEMORY_DIR / "session_journal.md"
HANDOFF_FILE = MEMORY_DIR / "compaction_handoffs.md"
LEARNING_DIR = MEMORY_DIR / "learning"
REPORTS_DIR = MEMORY_DIR / "reports"
CHALLENGES_DIR = ROOT / "challenges"


def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"`+", "", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "ip", text)
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    text = re.sub(r"-{2,}", "-", text)
    return text[:48] or "entry"


def parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M %Z", "%Y-%m-%d - %Z", "%Y-%m-%d %H:%M:%S %Z"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def utc_from_local(ts: str) -> str:
    parsed = parse_ts(ts)
    if not parsed:
        return ""
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_blocks(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    blocks: list[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("### ") and "YYYY-MM-DD" not in line:
            ts = line[4:].strip()
            body: list[str] = []
            i += 1
            while i < len(lines) and lines[i].strip() != "---":
                body.append(lines[i])
                i += 1
            blocks.append({"ts": ts, "body": "\n".join(body).strip()})
        i += 1
    return blocks


def parse_kv_block(block: dict) -> dict:
    data = {"ts": block["ts"], "raw": block["body"]}
    for line in block["body"].splitlines():
        if not line.startswith("- "):
            continue
        key, _, value = line[2:].partition(":")
        if not _:
            continue
        data[key.strip().lower().replace(" ", "_")] = value.strip()
    return data


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=False, separators=(",", ":")) + "\n")


def write_session_files(session_id: str, journal_entries: list[dict], handoff_entries: list[dict]) -> None:
    session_dir = SESSION_ROOT / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    journal_path = session_dir / "journal.md"
    handoff_path = session_dir / "handoffs.md"

    journal_lines = [f"# Session Journal ({session_id})", ""]
    for entry in journal_entries:
        journal_lines.extend(
            [
                f"### {entry['ts']}",
                f"- Mode: {entry['mode']}",
                f"- Session ID: {session_id}",
                "- Agent ID: legacy-migration",
                f"- Goal: {entry['objective']}",
                f"- Actions taken: {entry['done']}",
                f"- Files changed: {entry['files']}",
                f"- Blockers: {entry['issues']}",
                f"- Next step: {entry['next']}",
                f"- Event TS (UTC): {entry['ts_utc']}",
                "",
                "---",
            ]
        )
    journal_path.write_text("\n".join(journal_lines).rstrip() + "\n", encoding="utf-8")

    handoff_lines = [f"# Session Handoffs ({session_id})", ""]
    for entry in handoff_entries:
        handoff_lines.extend(
            [
                f"### {entry['ts']}",
                f"- Mode: {entry['mode']}",
                f"- Session ID: {session_id}",
                "- Agent ID: legacy-migration",
                f"- Current objective: {entry['objective']}",
                f"- Completed items: {entry['done']}",
                f"- Files touched: {entry['files']}",
                f"- Unresolved issues: {entry['issues']}",
                f"- Next exact action: {entry['next']}",
                f"- Event TS (UTC): {entry['ts_utc']}",
                "",
                "---",
            ]
        )
    handoff_path.write_text("\n".join(handoff_lines).rstrip() + "\n", encoding="utf-8")


def index_key(row: dict) -> tuple[str, str, str]:
    return (row.get("session_id", ""), row.get("ts", ""), row.get("mode", ""))


def rows_from_session_dir(session_dir: Path) -> list[dict]:
    session_id = session_dir.name
    rows: list[dict] = []
    sources = [
        ("journal.md", "goal", "actions_taken", "files_changed", "blockers", "next_step"),
        ("handoffs.md", "current_objective", "completed_items", "files_touched", "unresolved_issues", "next_exact_action"),
    ]
    for filename, objective_key, summary_key, files_key, blockers_key, next_key in sources:
        path = session_dir / filename
        if not path.exists():
            continue
        for block in load_blocks(path):
            entry = parse_kv_block(block)
            ts_local = entry.get("ts", "")
            ts_utc = entry.get("event_ts_(utc)", "") or utc_from_local(ts_local)
            if not ts_utc:
                continue
            row = {
                "ts": ts_utc,
                "session_id": entry.get("session_id", session_id) or session_id,
                "agent_id": entry.get("agent_id", "legacy-migration") or "legacy-migration",
                "mode": entry.get("mode", "checkpoint") or "checkpoint",
                "objective": entry.get(objective_key, "(not recorded)"),
                "blockers": entry.get(blockers_key, "(not recorded)"),
                "next_action": entry.get(next_key, "(not recorded)"),
                "summary": entry.get(summary_key, "(not recorded)"),
                "files_touched": entry.get(files_key, "(not recorded)"),
                "alias": entry.get("alias", ""),
                "phase": "legacy-import" if session_id.startswith("legacy-") else "session-backfill",
                "tags": "legacy,preserved" if session_id.startswith("legacy-") else "session,preserved",
                "classification": "legacy-preserved" if session_id.startswith("legacy-") else "session-preserved",
            }
            rows.append(row)
    return rows


def preserved_rows_from_session_dirs(existing_rows: list[dict], migrated_rows: list[dict]) -> list[dict]:
    migrated_keys = {index_key(row) for row in migrated_rows}
    migrated_session_ids = {row.get("session_id", "") for row in migrated_rows if row.get("session_id")}
    existing_keys = {index_key(row) for row in existing_rows}
    preserved: list[dict] = []
    preserved_keys: set[tuple[str, str, str]] = set()
    for session_dir in sorted(path for path in SESSION_ROOT.iterdir() if path.is_dir()):
        if session_dir.name in migrated_session_ids:
            continue
        for row in rows_from_session_dir(session_dir):
            key = index_key(row)
            if key in migrated_keys or key in existing_keys or key in preserved_keys:
                continue
            preserved.append(row)
            preserved_keys.add(key)
    return preserved


def session_inventory(index_rows: list[dict]) -> dict:
    SESSION_ROOT.mkdir(parents=True, exist_ok=True)
    indexed_ids = {row.get("session_id", "") for row in index_rows if row.get("session_id")}
    session_dirs = sorted(path for path in SESSION_ROOT.iterdir() if path.is_dir())

    legacy_dirs = [path.name for path in session_dirs if path.name.startswith("legacy-")]
    native_dirs = [path.name for path in session_dirs if not path.name.startswith("legacy-")]
    orphan_dirs = [path.name for path in session_dirs if path.name not in indexed_ids]
    missing_dirs = sorted(sid for sid in indexed_ids if not (SESSION_ROOT / sid).is_dir())

    empty_dirs = []
    for path in session_dirs:
        files = list(path.glob("*.md"))
        if not files:
            empty_dirs.append(path.name)
            continue
        if all(file.stat().st_size == 0 for file in files):
            empty_dirs.append(path.name)

    return {
        "total_dirs": len(session_dirs),
        "legacy_dirs": legacy_dirs,
        "native_dirs": native_dirs,
        "orphan_dirs": orphan_dirs,
        "missing_dirs": missing_dirs,
        "empty_dirs": empty_dirs,
    }


def migrate_legacy_memory() -> dict:
    SESSION_ROOT.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    journal_entries = [parse_kv_block(block) for block in load_blocks(JOURNAL_FILE)]
    handoff_entries = [parse_kv_block(block) for block in load_blocks(HANDOFF_FILE)]

    handoff_by_ts = defaultdict(list)
    for entry in handoff_entries:
        handoff_by_ts[entry["ts"]].append(entry)

    all_existing_index = load_jsonl(INDEX_FILE)
    existing_index = [row for row in all_existing_index if row.get("agent_id") != "legacy-migration"]
    migrated_rows: list[dict] = []
    created_sessions = 0

    for index, entry in enumerate(journal_entries, start=1):
        objective = entry.get("goal", "(not recorded)")
        done = entry.get("actions_taken", "(not recorded)")
        files = entry.get("files_changed", "(not recorded)")
        issues = entry.get("blockers", "(not recorded)")
        next_step = entry.get("next_step", "(not recorded)")
        ts = entry["ts"]
        ts_utc = utc_from_local(ts)
        parsed = parse_ts(ts)
        if parsed:
            stamp = parsed.strftime("%Y%m%d-%H%M")
        else:
            stamp = f"legacy-{index:04d}"
        session_id = f"legacy-{stamp}-{slugify(objective)}"
        matching_handoffs = handoff_by_ts.get(ts, [])
        journal_payload = [
            {
                "ts": ts,
                "ts_utc": ts_utc,
                "mode": "close" if matching_handoffs else "checkpoint",
                "objective": objective,
                "done": done,
                "files": files,
                "issues": issues,
                "next": next_step,
            }
        ]
        handoff_payload = []
        if matching_handoffs:
            for handoff in matching_handoffs:
                handoff_payload.append(
                    {
                        "ts": ts,
                        "ts_utc": ts_utc,
                        "mode": "handoff",
                        "objective": handoff.get("current_objective", objective),
                        "done": handoff.get("completed_items", done),
                        "files": handoff.get("files_touched", files),
                        "issues": handoff.get("unresolved_issues", issues),
                        "next": handoff.get("next_exact_action", next_step),
                    }
                )
        write_session_files(session_id, journal_payload, handoff_payload)
        created_sessions += 1

        migrated_rows.append(
            {
                "ts": ts_utc or "",
                "session_id": session_id,
                "agent_id": "legacy-migration",
                "mode": journal_payload[0]["mode"],
                "objective": objective,
                "blockers": issues,
                "next_action": next_step,
                "summary": done,
                "files_touched": files,
                "alias": "",
                "phase": "legacy-import",
                "tags": "legacy,migration",
                "classification": "legacy-import",
            }
        )
        for handoff in handoff_payload:
            migrated_rows.append(
                {
                    "ts": handoff["ts_utc"] or "",
                    "session_id": session_id,
                    "agent_id": "legacy-migration",
                    "mode": "handoff",
                    "objective": handoff["objective"],
                    "blockers": handoff["issues"],
                    "next_action": handoff["next"],
                    "summary": handoff["done"],
                    "files_touched": handoff["files"],
                    "alias": "",
                    "phase": "legacy-import",
                    "tags": "legacy,migration",
                    "classification": "legacy-import",
                }
            )

    preserved_rows = preserved_rows_from_session_dirs(existing_index, migrated_rows)
    merged = existing_index + migrated_rows + preserved_rows
    merged.sort(key=lambda row: (row.get("ts", ""), row.get("session_id", ""), row.get("mode", "")))
    write_jsonl(INDEX_FILE, merged)
    if not ALIASES_FILE.exists():
        ALIASES_FILE.write_text("{\n}\n", encoding="utf-8")

    return {
        "journal_entries": len(journal_entries),
        "handoff_entries": len(handoff_entries),
        "created_sessions": created_sessions,
        "index_rows_written": len(migrated_rows),
        "existing_rows_preserved": len(existing_index),
        "preserved_rows": len(preserved_rows),
        "index_rows": merged,
    }


def challenge_kind_for(path: Path) -> str:
    rel = path.relative_to(CHALLENGES_DIR)
    return rel.parts[0] if rel.parts else "unknown"


def challenge_inventory() -> tuple[list[dict], dict]:
    records = []
    stats = {"tryhackme_dirs": 0, "unclassified_files": 0}

    tryhackme = CHALLENGES_DIR / "tryhackme"
    if tryhackme.exists():
        for entry in sorted(p for p in tryhackme.iterdir() if p.is_dir()):
            files = sorted([f.name for f in entry.iterdir() if f.is_file()])
            status = "HAS_NOTES" if any(name.lower().startswith("notes") or "writeup" in name.lower() for name in files) else "ARTIFACTS_ONLY"
            records.append(
                {
                    "name": entry.name,
                    "path": entry.relative_to(ROOT).as_posix(),
                    "kind": "tryhackme",
                    "status": status,
                    "file_count": len(files),
                    "files": files[:8],
                }
            )
            stats["tryhackme_dirs"] += 1

    unclassified = CHALLENGES_DIR / "_unclassified"
    if unclassified.exists():
        files = sorted(p.relative_to(ROOT).as_posix() for p in unclassified.rglob("*") if p.is_file())
        stats["unclassified_files"] = len(files)
        records.append(
            {
                "name": "_unclassified",
                "path": unclassified.relative_to(ROOT).as_posix(),
                "kind": "unclassified",
                "status": "NEEDS_TRIAGE",
                "file_count": len(files),
                "files": files[:20],
            }
        )
    return records, stats


def write_challenge_index(records: list[dict]) -> None:
    lines = ["# Challenge Index", ""]
    thm = [row for row in records if row["kind"] == "tryhackme"]
    lines.append("## TryHackMe")
    for row in thm:
        lines.append(f"- `{row['name']}`")
        lines.append(f"  - path: `/{ROOT.relative_to('/').as_posix()}/{row['path']}`")
        lines.append(f"  - status: {row['status']}")
        lines.append(f"  - files: {row['file_count']}")
    lines.append("")
    unclassified = [row for row in records if row["kind"] == "unclassified"]
    lines.append("## Unclassified")
    for row in unclassified:
        lines.append(f"- path: `/{ROOT.relative_to('/').as_posix()}/{row['path']}`")
        lines.append(f"  - status: {row['status']}")
        lines.append(f"  - files: {row['file_count']}")
        if row["files"]:
            lines.append(f"  - sample: `{row['files'][0]}`")
    (CHALLENGES_DIR / "CHALLENGE_INDEX.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_unclassified_manifest() -> None:
    unclassified = CHALLENGES_DIR / "_unclassified"
    if not unclassified.exists():
        return
    lines = ["# Unclassified Manifest", "", f"Generated: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}", ""]
    for path in sorted(unclassified.rglob("*")):
        if path == unclassified:
            continue
        lines.append(path.relative_to(ROOT).as_posix())
    (unclassified / "MANIFEST.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_session_inventory_report(stats: dict) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = REPORTS_DIR / "session_inventory.md"
    lines = [
        "# Session Inventory",
        "",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Counts",
        f"- Total session directories: {stats['total_dirs']}",
        f"- Legacy session directories: {len(stats['legacy_dirs'])}",
        f"- Native session directories: {len(stats['native_dirs'])}",
        f"- Orphan session directories: {len(stats['orphan_dirs'])}",
        f"- Missing session directories for indexed sessions: {len(stats['missing_dirs'])}",
        f"- Empty session directories: {len(stats['empty_dirs'])}",
        "",
        "## Orphan Session Directories",
    ]
    if stats["orphan_dirs"]:
        lines.extend(f"- `{name}`" for name in stats["orphan_dirs"])
    else:
        lines.append("- (none)")
    lines.extend(["", "## Empty Session Directories"])
    if stats["empty_dirs"]:
        lines.extend(f"- `{name}`" for name in stats["empty_dirs"])
    else:
        lines.append("- (none)")
    lines.extend(["", "## Missing Indexed Session Directories"])
    if stats["missing_dirs"]:
        lines.extend(f"- `{name}`" for name in stats["missing_dirs"])
    else:
        lines.append("- (none)")
    report.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_cutover_status(migration: dict, session_stats: dict) -> None:
    status = MEMORY_DIR / "CUTOVER_STATUS.md"
    orphan_count = len(session_stats["orphan_dirs"])
    empty_count = len(session_stats["empty_dirs"])
    state = "READY"
    if orphan_count or empty_count:
        state = "READY_WITH_CLEANUP"
    lines = [
        "# Cutover Status",
        "",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        f"- State: {state}",
        "- Primary continuity source: `memory/session_index.jsonl` plus `memory/sessions/<session_id>/`",
        "- Legacy compatibility mirrors: `memory/session_journal.md` and `memory/compaction_handoffs.md`",
        f"- Legacy rows imported: {migration['index_rows_written']}",
        f"- Existing non-legacy rows preserved: {migration['existing_rows_preserved']}",
        f"- Preserved session rows recovered from existing session folders: {migration['preserved_rows']}",
        f"- Session directories present: {session_stats['total_dirs']}",
        f"- Orphan session directories: {orphan_count}",
        f"- Empty session directories: {empty_count}",
        "",
        "## Operator Notes",
        "- New writes should go through `scripts/codex-close.sh` only.",
        "- Startup should treat the session index as authoritative for machine-readable continuity.",
        "- Legacy mirror auto-sync should only repair manual/legacy gaps, not checkpoint-only index state.",
    ]
    status.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_cutover_report(migration: dict, inventory_stats: dict, session_stats: dict) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = REPORTS_DIR / "migration_cutover_report.md"
    orphan_count = len(session_stats["orphan_dirs"])
    empty_count = len(session_stats["empty_dirs"])
    lines = [
        "# Migration Cutover Report",
        "",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Legacy Memory Backfill",
        f"- Journal entries migrated: {migration['journal_entries']}",
        f"- Handoff entries migrated: {migration['handoff_entries']}",
        f"- Session folders created/refreshed: {migration['created_sessions']}",
        f"- Legacy index rows written: {migration['index_rows_written']}",
        f"- Existing non-legacy index rows preserved: {migration['existing_rows_preserved']}",
        f"- Preserved rows recovered from existing session folders: {migration['preserved_rows']}",
        "",
        "## Challenge Inventory",
        f"- TryHackMe challenge directories indexed: {inventory_stats['tryhackme_dirs']}",
        f"- Unclassified files inventoried: {inventory_stats['unclassified_files']}",
        "",
        "## Session Inventory",
        f"- Total session directories present: {session_stats['total_dirs']}",
        f"- Legacy session directories: {len(session_stats['legacy_dirs'])}",
        f"- Native session directories: {len(session_stats['native_dirs'])}",
        f"- Orphan session directories: {orphan_count}",
        f"- Empty session directories: {empty_count}",
        "",
        "## Cutover Status",
        "- Session-aware memory is now backfilled from legacy journal/handoff history.",
        "- `memory/session_index.jsonl` is ready to serve as the primary machine-readable continuity source.",
        "- `memory/CUTOVER_STATUS.md` records current cutover state and operator expectations.",
        "- `challenges/CHALLENGE_INDEX.md` and `_unclassified/MANIFEST.md` were refreshed from the actual workspace tree.",
        "- Remaining manual work: review `_unclassified` artifacts and re-home them into challenge folders where confidence is high.",
        f"- Remaining cleanup signals: orphan session dirs={orphan_count}, empty session dirs={empty_count}.",
    ]
    report.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    global ROOT, MEMORY_DIR, SESSION_ROOT, INDEX_FILE, ALIASES_FILE, JOURNAL_FILE, HANDOFF_FILE, LEARNING_DIR, REPORTS_DIR, CHALLENGES_DIR
    parser = argparse.ArgumentParser(description="Organize existing CTF data and prepare migration.")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    ROOT = Path(args.root).resolve()
    MEMORY_DIR = ROOT / "memory"
    SESSION_ROOT = MEMORY_DIR / "sessions"
    INDEX_FILE = MEMORY_DIR / "session_index.jsonl"
    ALIASES_FILE = MEMORY_DIR / "session_aliases.json"
    JOURNAL_FILE = MEMORY_DIR / "session_journal.md"
    HANDOFF_FILE = MEMORY_DIR / "compaction_handoffs.md"
    LEARNING_DIR = MEMORY_DIR / "learning"
    REPORTS_DIR = MEMORY_DIR / "reports"
    CHALLENGES_DIR = ROOT / "challenges"

    migration = migrate_legacy_memory()
    session_stats = session_inventory(migration["index_rows"])
    records, inventory_stats = challenge_inventory()
    write_challenge_index(records)
    write_unclassified_manifest()
    write_session_inventory_report(session_stats)
    write_cutover_status(migration, session_stats)
    write_cutover_report(migration, inventory_stats, session_stats)

    print(
        f"[+] Organized existing data: sessions={migration['created_sessions']} "
        f"legacy_rows={migration['index_rows_written']} challenge_dirs={inventory_stats['tryhackme_dirs']} "
        f"unclassified_files={inventory_stats['unclassified_files']} orphan_sessions={len(session_stats['orphan_dirs'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
