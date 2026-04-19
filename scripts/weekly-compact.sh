#!/usr/bin/env bash
# Weekly memory compaction — LLM-summarize old entries, archive stale sessions, rotate indexes,
# consolidate learning JSONL.
#
# Run manually or via systemd timer (ctf-weekly-compact.timer).
#
# Usage: bash scripts/weekly-compact.sh [--keep-days N] [--dry-run] [--no-llm] [--model MODEL]
#
# Default: keep last 7 days verbatim, LLM-summarize older entries, archive old session dirs,
# consolidate learning events. Uses codex exec with gpt-5.2-codex for summaries (mid-tier).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MEM_DIR="$ROOT_DIR/memory"
LEARN_DIR="$MEM_DIR/learning"
SESSION_ROOT="$MEM_DIR/sessions"
ARCHIVE_DIR="$MEM_DIR/archive"

KEEP_DAYS=7
DRY_RUN=0
USE_LLM=1
LLM_MODEL="gpt-5.2-codex"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-days) KEEP_DAYS="${2:-7}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-llm) USE_LLM=0; shift ;;
    --model) LLM_MODEL="${2:-gpt-5.2-codex}"; shift 2 ;;
    --help|-h)
      sed -n '2,/^$/{ s/^# //; p }' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

CUTOFF_EPOCH="$(date -u -d "-${KEEP_DAYS} days" +%s 2>/dev/null || date -u -v-${KEEP_DAYS}d +%s)"
CUTOFF_DATE="$(date -u -d "@$CUTOFF_EPOCH" '+%Y-%m-%d')"
TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"

mkdir -p "$ARCHIVE_DIR"

log() { echo "[compact] $*"; }

# Check if codex CLI is available for LLM summaries
if [[ "$USE_LLM" -eq 1 ]] && ! command -v codex >/dev/null 2>&1; then
  log "WARNING: codex CLI not found, falling back to mechanical summarization."
  USE_LLM=0
fi

# ─── LLM summarization helper ──────��────────────────────────────────────────

llm_summarize() {
  # Takes old entries on stdin, writes summary to stdout.
  # Falls back to mechanical summary if LLM fails.
  local label="$1"
  local input_file="$2"
  local output_file="$3"

  local input_lines
  input_lines="$(wc -l < "$input_file")"

  if [[ "$USE_LLM" -eq 1 && "$input_lines" -gt 5 ]]; then
    local prompt
    prompt="You are compacting a CTF operator's session journal. Summarize the entries provided on stdin into a dense operational digest. Rules:
1. Group by date. Use format: ### YYYY-MM-DD (compacted)
2. For each date, write 2-5 bullet points capturing: key objectives, important discoveries (credentials, access, vulns), unresolved blockers, critical decisions/pivots.
3. Drop routine boilerplate (agent IDs, session IDs, 'not recorded' fields, repeated health checks).
4. Preserve: credential pairs, IP addresses, specific CVEs, file paths that matter, tool names.
5. Keep total output under 40% of input line count.
6. End each date section with ---
7. Output ONLY the summary markdown, no preamble or explanation."

    local llm_output_file
    llm_output_file="$(mktemp)"

    # codex exec: read stdin, write last message to file, ephemeral (no session save)
    if codex exec -m "$LLM_MODEL" --ephemeral --skip-git-repo-check \
         -s read-only -o "$llm_output_file" \
         "$prompt" < "$input_file" >/dev/null 2>&1; then
      if [[ -s "$llm_output_file" && "$(wc -l < "$llm_output_file")" -gt 2 ]]; then
        cp "$llm_output_file" "$output_file"
        log "$label: LLM summary generated ($(wc -l < "$output_file") lines from $input_lines input lines)."
        rm -f "$llm_output_file"
        return 0
      fi
    fi
    rm -f "$llm_output_file"
    log "$label: LLM failed, falling back to mechanical summary."
  fi

  # Mechanical fallback
  python3 - "$input_file" "$output_file" <<'PYEOF'
import sys, re
from collections import OrderedDict
old_path, out_path = sys.argv[1], sys.argv[2]

entries = []
current = {"date": "", "goal": "", "done": "", "next": "", "blockers": "", "files": ""}
date_re = re.compile(r"### (\d{4}-\d{2}-\d{2})")

with open(old_path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.rstrip()
        m = date_re.match(line)
        if m:
            if current["date"] and current["goal"]:
                entries.append(dict(current))
            current = {"date": m.group(1), "goal": "", "done": "", "next": "", "blockers": "", "files": ""}
        for prefix, key in [("- Goal: ", "goal"), ("- Current objective: ", "goal"),
                            ("- Actions taken: ", "done"), ("- Completed items: ", "done"),
                            ("- Next step: ", "next"), ("- Next exact action: ", "next"),
                            ("- Blockers: ", "blockers"), ("- Unresolved issues: ", "blockers"),
                            ("- Files changed: ", "files"), ("- Files touched: ", "files")]:
            if line.startswith(prefix):
                val = line[len(prefix):]
                if val and val != "(not recorded)" and val != "(checkpoint)":
                    current[key] = val
    if current["date"] and current["goal"]:
        entries.append(dict(current))

by_date = OrderedDict()
for e in entries:
    by_date.setdefault(e["date"], []).append(e)

with open(out_path, "w") as f:
    for date, items in by_date.items():
        f.write(f"### {date} (compacted)\n")
        for e in items:
            if e["goal"] and e["goal"] != "(not recorded)":
                f.write(f"- {e['goal']}\n")
            if e["done"] and e["done"] not in ("(not recorded)", "(checkpoint)"):
                f.write(f"  - Done: {e['done'][:120]}\n")
            if e["blockers"] and e["blockers"] != "(not recorded)":
                f.write(f"  - Blockers: {e['blockers'][:100]}\n")
        last = items[-1]
        if last["next"] and last["next"] != "(not recorded)":
            f.write(f"- Last next action: {last['next']}\n")
        f.write("\n---\n")
PYEOF
  log "$label: mechanical fallback summary generated."
}

# ─── 1. Compact legacy journal / handoffs ────────────────────────────────────

compact_legacy_md() {
  local src="$1"
  local label="$2"
  [[ -f "$src" ]] || return 0

  local line_count
  line_count="$(wc -l < "$src")"
  if (( line_count < 50 )); then
    log "$label: only $line_count lines, skipping."
    return 0
  fi

  local recent_file old_file summary_file
  recent_file="$(mktemp)"
  old_file="$(mktemp)"
  summary_file="$(mktemp)"

  # Split into old (before cutoff) and recent (cutoff and after)
  python3 - "$src" "$CUTOFF_DATE" "$recent_file" "$old_file" <<'PYEOF'
import sys, re
src, cutoff, recent_path, old_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

blocks = []
current = []
with open(src, "r", encoding="utf-8", errors="replace") as f:
    header_line = ""
    for line in f:
        if line.startswith("### "):
            if current:
                blocks.append((header_line, current[:]))
                current = []
            header_line = line.rstrip()
            current.append(line)
        elif line.strip() == "---":
            current.append(line)
            blocks.append((header_line, current[:]))
            current = []
            header_line = ""
        else:
            current.append(line)
    if current:
        blocks.append((header_line, current[:]))

date_re = re.compile(r"### (\d{4}-\d{2}-\d{2})")
old_blocks = []
recent_blocks = []
for header, lines in blocks:
    m = date_re.match(header)
    if m and m.group(1) < cutoff:
        old_blocks.append((header, lines))
    else:
        recent_blocks.append((header, lines))

with open(old_path, "w") as f:
    for _, lines in old_blocks:
        f.writelines(lines)
with open(recent_path, "w") as f:
    for _, lines in recent_blocks:
        f.writelines(lines)

print(f"old={len(old_blocks)} recent={len(recent_blocks)}")
PYEOF

  local old_count
  old_count="$(wc -l < "$old_file")"
  if (( old_count < 10 )); then
    log "$label: only $old_count old lines, nothing to compact."
    rm -f "$recent_file" "$old_file" "$summary_file"
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    local recent_lines
    recent_lines="$(wc -l < "$recent_file")"
    log "$label: DRY RUN — would compact $old_count old lines, keep $recent_lines recent lines (LLM=$USE_LLM)."
    rm -f "$recent_file" "$old_file" "$summary_file"
    return 0
  fi

  # Summarize old entries (LLM or mechanical fallback)
  llm_summarize "$label" "$old_file" "$summary_file"

  local summary_lines recent_lines
  summary_lines="$(wc -l < "$summary_file")"
  recent_lines="$(wc -l < "$recent_file")"

  # Archive original
  cp "$src" "$ARCHIVE_DIR/$(basename "$src" .md)_${TIMESTAMP}.md"

  # Rebuild: file header + summary + recent
  {
    head -1 "$src"
    echo
    echo "<!-- Compacted on $TIMESTAMP — entries before $CUTOFF_DATE summarized (LLM=$USE_LLM) -->"
    echo
    cat "$summary_file"
    cat "$recent_file"
  } > "$src.tmp"
  mv "$src.tmp" "$src"

  log "$label: $old_count old lines → $summary_lines summary + $recent_lines recent. Archive: $ARCHIVE_DIR/"
  rm -f "$recent_file" "$old_file" "$summary_file"
}

compact_legacy_md "$MEM_DIR/session_journal.md" "session_journal"
compact_legacy_md "$MEM_DIR/compaction_handoffs.md" "compaction_handoffs"

# ─── 2. Rotate session_index.jsonl ───────────────────────────────────────────

rotate_index() {
  local idx="$MEM_DIR/session_index.jsonl"
  [[ -f "$idx" ]] || return 0

  local total
  total="$(wc -l < "$idx")"
  if (( total < 30 )); then
    log "session_index: only $total entries, skipping rotation."
    return 0
  fi

  local recent_file old_file
  recent_file="$(mktemp)"
  old_file="$(mktemp)"

  python3 - "$idx" "$CUTOFF_DATE" "$recent_file" "$old_file" <<'PYEOF'
import json, sys
idx_path, cutoff, recent_path, old_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

old_lines = []
recent_lines = []
with open(idx_path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.rstrip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            recent_lines.append(line)
            continue
        ts = row.get("ts", "")
        if ts[:10] < cutoff:
            old_lines.append(line)
        else:
            recent_lines.append(line)

with open(old_path, "w") as f:
    for l in old_lines:
        f.write(l + "\n")
with open(recent_path, "w") as f:
    for l in recent_lines:
        f.write(l + "\n")

print(f"old={len(old_lines)} recent={len(recent_lines)}")
PYEOF

  local old_count
  old_count="$(wc -l < "$old_file")"
  if (( old_count < 5 )); then
    log "session_index: only $old_count old entries, skipping."
    rm -f "$recent_file" "$old_file"
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    local recent_count
    recent_count="$(wc -l < "$recent_file")"
    log "session_index: DRY RUN — would archive $old_count old, keep $recent_count recent."
    rm -f "$recent_file" "$old_file"
    return 0
  fi

  cat "$old_file" >> "$MEM_DIR/session_index.archive.jsonl"
  mv "$recent_file" "$idx"
  log "session_index: archived $old_count old entries → session_index.archive.jsonl"
  rm -f "$old_file"
}

rotate_index

# ─── 3. Archive old session dirs ─────────────────────────────────────────────

archive_session_dirs() {
  [[ -d "$SESSION_ROOT" ]] || return 0

  local count=0
  for dir in "$SESSION_ROOT"/*/; do
    [[ -d "$dir" ]] || continue
    local dirname
    dirname="$(basename "$dir")"
    local dir_date=""
    if [[ "$dirname" =~ ^s-([0-9]{8})- ]]; then
      dir_date="${BASH_REMATCH[1]}"
      dir_date="${dir_date:0:4}-${dir_date:4:2}-${dir_date:6:2}"
    elif [[ "$dirname" =~ ^legacy-([0-9]{8})- ]]; then
      dir_date="${BASH_REMATCH[1]}"
      dir_date="${dir_date:0:4}-${dir_date:4:2}-${dir_date:6:2}"
    fi
    [[ -z "$dir_date" ]] && continue
    [[ "$dir_date" < "$CUTOFF_DATE" ]] || continue

    if [[ "$DRY_RUN" -eq 1 ]]; then
      log "session dir: DRY RUN — would archive $dirname"
      count=$(( count + 1 ))
      continue
    fi

    tar -czf "$ARCHIVE_DIR/${dirname}.tar.gz" -C "$SESSION_ROOT" "$dirname" 2>/dev/null
    rm -rf "$dir"
    count=$(( count + 1 ))
  done

  [[ $count -gt 0 ]] && log "session dirs: archived $count old session(s)."
}

archive_session_dirs

# ─��─ 4. Compact learning JSONL (events archive + field strip) ────────────────

compact_learning() {
  if [[ ! -f "$ROOT_DIR/scripts/learn_engine.py" ]]; then
    log "learn_engine.py not found, skipping learning compact."
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "learning: DRY RUN — would run learn_engine.py compact --archive-days $KEEP_DAYS"
    return 0
  fi

  python3 "$ROOT_DIR/scripts/learn_engine.py" --root "$ROOT_DIR" compact --archive-days "$KEEP_DAYS" 2>&1 | \
    sed 's/^/[compact] learning: /'
}

compact_learning

# ─── 5. LLM learning consolidation ───���──────────────────────────────────────
#
# Ask LLM to review the canonical JSONL files and identify:
# - Duplicate/near-duplicate entries to merge
# - Low-value entries to demote
# - Patterns that should be promoted to PENTEST.md
# Writes recommendations to memory/reports/compact_review.md for human review.

consolidate_learning() {
  if [[ "$USE_LLM" -eq 0 ]]; then
    log "learning consolidation: skipped (--no-llm)."
    return 0
  fi

  local vectors_file="$LEARN_DIR/vectors.jsonl"
  local guardrails_file="$LEARN_DIR/guardrails.jsonl"
  local bugs_file="$LEARN_DIR/bugs.jsonl"

  # Only run if files exist and have meaningful content
  local total_lines=0
  for f in "$vectors_file" "$guardrails_file" "$bugs_file"; do
    [[ -f "$f" ]] && total_lines=$(( total_lines + $(wc -l < "$f") ))
  done
  if (( total_lines < 20 )); then
    log "learning consolidation: only $total_lines total entries, skipping."
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "learning consolidation: DRY RUN — would analyze $total_lines learning entries."
    return 0
  fi

  # Build a compact view of all entries for the LLM
  local learning_snapshot
  learning_snapshot="$(mktemp)"

  python3 - "$vectors_file" "$guardrails_file" "$bugs_file" "$learning_snapshot" <<'PYEOF'
import json, sys

files = [("vectors", sys.argv[1]), ("guardrails", sys.argv[2]), ("bugs", sys.argv[3])]
out_path = sys.argv[4]

with open(out_path, "w") as out:
    for label, path in files:
        out.write(f"\n## {label.upper()}\n")
        try:
            with open(path, "r") as f:
                for i, line in enumerate(f):
                    if i >= 50:  # cap per file to control token cost
                        out.write(f"... ({i} more entries truncated)\n")
                        break
                    try:
                        row = json.loads(line)
                        cid = row.get("canonical_id", "?")
                        title = row.get("title", "?")[:80]
                        conf = row.get("confidence", 0)
                        occ = row.get("occurrences", 1)
                        promote = row.get("promote_target", "")
                        out.write(f"- [{cid}] conf={conf:.2f} occ={occ} promote={promote or 'none'} | {title}\n")
                    except json.JSONDecodeError:
                        pass
        except FileNotFoundError:
            out.write("- (file not found)\n")
PYEOF

  local prompt
  prompt="You are reviewing a CTF learning system's canonical entries provided on stdin. For each section (VECTORS, GUARDRAILS, BUGS), produce a compact report:

## Duplicates / Near-Duplicates
List pairs of canonical_ids that cover the same concept and should be merged. Format:
- MERGE [id1] + [id2]: reason

## Low-Value Entries
Entries with low confidence, single occurrence, and generic content that add noise. Format:
- DEMOTE [id]: reason

## Promotion Candidates
High-confidence, multi-occurrence entries not yet targeting PENTEST.md that should be. Format:
- PROMOTE [id] to PENTEST.md: one-line summary of what to add

## Gaps
Important patterns missing from the learning entries. Format:
- GAP: description

Keep the report concise. Only flag clear wins, not marginal cases."

  local review_output_file
  review_output_file="$(mktemp)"

  if codex exec -m "$LLM_MODEL" --ephemeral --skip-git-repo-check \
       -s read-only -o "$review_output_file" \
       "$prompt" < "$learning_snapshot" >/dev/null 2>&1; then
    if [[ -s "$review_output_file" && "$(wc -l < "$review_output_file")" -gt 3 ]]; then
      {
        echo "# Learning Consolidation Review"
        echo ""
        echo "Generated: $TIMESTAMP (model: $LLM_MODEL)"
        echo "Entries analyzed: $total_lines"
        echo ""
        cat "$review_output_file"
      } > "$MEM_DIR/reports/compact_review.md"
      log "learning consolidation: review written to memory/reports/compact_review.md ($(wc -l < "$review_output_file") lines)."
      rm -f "$review_output_file"
    else
      log "learning consolidation: LLM returned empty result, skipped."
      rm -f "$review_output_file"
    fi
  else
    log "learning consolidation: codex exec failed, skipped."
    rm -f "$review_output_file"
  fi

  rm -f "$learning_snapshot"
}

consolidate_learning

# ─── Done ────────────────────────────────────────────────────────────────────

log "Weekly compaction complete (cutoff: $CUTOFF_DATE, keep-days: $KEEP_DAYS, LLM: $USE_LLM)."
