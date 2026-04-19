#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT_DIR"
default_runtime_root() {
  local state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
  local repo_id
  repo_id="$(printf '%s' "$ROOT_DIR" | sha1sum | awk '{print substr($1,1,8)}')"
  printf '%s/ctf-security-ops/%s-%s\n' "$state_home" "$(basename "$ROOT_DIR")" "$repo_id"
}
TMP_ROOT="${SECOPS_RUNTIME_ROOT:-$(default_runtime_root)}/tmp"

PRINT_ONLY=0
REQUIRE_RESUME=0
SYNC_STALE_HANDOFF=1
AUTO_CLOSE_ON_INTERRUPT=1
NO_MEMORY_WATCH=0
for arg in "$@"; do
  case "$arg" in
    --fresh) ;; # Default behavior, kept for backwards compat
    --print-only) PRINT_ONLY=1 ;;
    --resume) REQUIRE_RESUME=1 ;;
    --require-resume) REQUIRE_RESUME=1 ;;
    --no-handoff-sync) SYNC_STALE_HANDOFF=0 ;;
    --no-auto-close) AUTO_CLOSE_ON_INTERRUPT=0 ;;
    --no-memory-watch) NO_MEMORY_WATCH=1 ;;
    --target-tags) TARGET_TAGS_OVERRIDE="${2:-}"; shift ;;
    --target-tags=*) TARGET_TAGS_OVERRIDE="${arg#*=}" ;;
    --help|-h)
      cat <<'USAGE'
Usage: bash scripts/codex-start.sh [--print-only] [--resume] [--no-handoff-sync] [--no-auto-close] [--no-memory-watch] [--target-tags <csv>]

--print-only    Print startup memory brief and exit.
--resume        Resume last codex session instead of starting fresh.
--no-handoff-sync    Do not auto-append a handoff when journal is newer.
--no-auto-close    Disable automatic close write when Codex exits due to interrupt.
--no-memory-watch  Disable background dense-memory heartbeat watcher.
--target-tags <csv>  Override target context (e.g., "web,port:80,service:apache").
USAGE
      exit 0
      ;;
  esac
done

mkdir -p memory runbooks scripts notes
mkdir -p memory/sessions
mkdir -p memory/learning memory/reports
mkdir -p "$TMP_ROOT"

ensure_file() {
  local path="$1"
  local title="$2"
  if [[ ! -f "$path" ]]; then
    printf '# %s\n' "$title" > "$path"
  fi
}

ensure_file AGENTS.md "Codex Repo Instructions"
ensure_file MEM.md "CTF Codex Memory Map"
ensure_file memory/session_journal.md "Session Journal"
ensure_file memory/compaction_handoffs.md "Compaction-Safe Handoffs"
ensure_file memory/lessons_learned.md "Lessons Learned"
ensure_file memory/training_notes.md "Training Notes"
ensure_file runbooks/workflow.md "Codex Workflow Runbook"

if [[ ! -f memory/session_index.jsonl ]]; then
  : > memory/session_index.jsonl
fi
if [[ ! -f memory/session_aliases.json ]]; then
  printf '{\n}\n' > memory/session_aliases.json
fi

START_PROMPT=$'Read startup context in this order:\n1) MEM.md dense map\n2) LOOKUP.md intelligence map\n3) latest memory/session_index.jsonl record\n4) latest dense handoff mirror\n5) targeted context only: python3 scripts/learn_engine.py --root . context mode:<mode> tag:<tag> service:<svc>\nRecon emits focus={mode,tags,ports,svc,versions,cves,phase}; all agents lookup from focus before loading context. Do not load full playbooks by default. Summarize current objective, blockers, and next exact action.'

# Detect target context from latest handoff for targeted learning digest
detect_target_context() {
  local latest
  latest=$(tail -50 memory/compaction_handoffs.md 2>/dev/null || true)
  [[ -z "$latest" ]] && return

  local ports="" services="" tags=""

  # Extract ports from :PORT and nmap-style output
  ports=$(echo "$latest" | grep -oP '(?:(?<=:)\d{2,5}(?=\b)|(?<=\s)\d{2,5}(?=/(?:open|tcp|udp)))' 2>/dev/null | sort -un | tr '\n' ' ')

  # Detect services
  for svc in apache nginx wordpress openssh smb mysql ftp redis tomcat; do
    echo "$latest" | grep -qi "$svc" && services="$services $svc"
  done

  # Detect platform tags
  for tag in koth web windows ad linux container; do
    echo "$latest" | grep -qi "$tag" && tags="$tags $tag"
  done

  local args=""
  [[ -n "${ports// /}" ]] && args="$args --ports $ports"
  [[ -n "${services// /}" ]] && args="$args --services $services"
  [[ -n "${tags// /}" ]] && args="$args --tags $tags"
  echo "$args"
}

# Build target context filters (manual override or auto-detect)
TARGET_CTX=""
if [[ -n "${TARGET_TAGS_OVERRIDE:-}" ]]; then
  # Parse comma-separated tags: "web,port:80,apache" -> --tags web --ports 80 --services apache
  IFS=',' read -ra ITEMS <<< "$TARGET_TAGS_OVERRIDE"
  _tags="" _ports="" _services=""
  for item in "${ITEMS[@]}"; do
    item="${item## }"; item="${item%% }"
    case "$item" in
      port:*) _ports="$_ports ${item#port:}" ;;
      service:*) _services="$_services ${item#service:}" ;;
      tag:*) _tags="$_tags ${item#tag:}" ;;
      *) _tags="$_tags $item" ;;
    esac
  done
  [[ -n "${_tags// /}" ]] && TARGET_CTX="$TARGET_CTX --tags $_tags"
  [[ -n "${_ports// /}" ]] && TARGET_CTX="$TARGET_CTX --ports $_ports"
  [[ -n "${_services// /}" ]] && TARGET_CTX="$TARGET_CTX --services $_services"
else
  TARGET_CTX=$(detect_target_context)
fi

# Inject learning digest into startup prompt (targeted if context available)
# shellcheck disable=SC2086
DIGEST_OUTPUT=$(python3 "$ROOT_DIR/scripts/learn_engine.py" --root "$ROOT_DIR" startup-digest $TARGET_CTX 2>/dev/null || true)
if [[ -n "$DIGEST_OUTPUT" ]]; then
  START_PROMPT="${START_PROMPT}"$'\n\n'"${DIGEST_OUTPUT}"
fi
BRIEF_FILE=""
AGENT_ID="${CODEX_AGENT_ID:-$(hostname):$$}"
SESSION_ID="${SESSION_ID:-s-$(date -u '+%Y%m%d')-$(cat /proc/sys/kernel/random/uuid 2>/dev/null | cut -d- -f1 || date +%s)}"
SESSION_TMPDIR=""
CODEX_STARTED=0
INTERRUPT_SEEN=0
AUTO_CLOSE_REASON=""
LAST_OBJECTIVE=""

trap 'INTERRUPT_SEEN=1; AUTO_CLOSE_REASON="signal"' INT TERM

init_tmp_workspace() {
  local stamp agent_safe
  stamp="$(date '+%Y%m%d_%H%M%S')"
  agent_safe="$(printf '%s' "$AGENT_ID" | tr -c 'A-Za-z0-9._-' '_')"
  SESSION_TMPDIR="$TMP_ROOT/${stamp}_${agent_safe}_$$"
  mkdir -p "$SESSION_TMPDIR"
  export TMPDIR="$SESSION_TMPDIR"
  printf '%s\n' "$SESSION_TMPDIR" > "$ROOT_DIR/.ctf_tmpdir"
  BRIEF_FILE="$SESSION_TMPDIR/codex_start_brief.txt"
}

init_tmp_workspace

if [[ -x "$ROOT_DIR/scripts/memory-write.py" ]]; then
  "$ROOT_DIR/scripts/memory-write.py" \
    --root "$ROOT_DIR" \
    --mode startup \
    --session-id "$SESSION_ID" \
    --agent "$AGENT_ID" \
    --phase startup \
    --objective "session startup" \
    --done "startup context requested" \
    --next "review latest memory and proceed" \
    --context "startup" >/dev/null 2>&1 || true
fi

supports_flag() {
  local cmd="$1"
  local flag="$2"
  $cmd --help 2>/dev/null | grep -q -- "$flag"
}

json_field() {
  local line="$1"
  local field="$2"
  printf '%s\n' "$line" | sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p"
}

last_index_line() {
  local file="$ROOT_DIR/memory/session_index.jsonl"
  [[ -s "$file" ]] || return 0
  tail -n 1 "$file"
}

latest_index_for_agent() {
  local agent="$1"
  local file="$ROOT_DIR/memory/session_index.jsonl"
  [[ -s "$file" ]] || return 0
  awk -v a="$agent" '
    {
      aid=""
      if (match($0, /"agent"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
        seg=substr($0, RSTART, RLENGTH)
        sub(/^"agent"[[:space:]]*:[[:space:]]*"/, "", seg)
        sub(/"$/, "", seg)
        aid=seg
      } else if (match($0, /"agent_id"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
        seg=substr($0, RSTART, RLENGTH)
        sub(/^"agent_id"[[:space:]]*:[[:space:]]*"/, "", seg)
        sub(/"$/, "", seg)
        aid=seg
      }
      if (aid == a) last=$0
    }
    END { if (last != "") print last }
  ' "$file"
}

index_modes_for_ts() {
  local ts_utc="$1"
  local file="$ROOT_DIR/memory/session_index.jsonl"
  [[ -s "$file" ]] || return 0
  python3 - "$file" "$ts_utc" <<'PY'
import json
import sys

path, target = sys.argv[1], sys.argv[2]
modes = []
seen = set()
with open(path, "r", encoding="utf-8", errors="ignore") as handle:
    for raw in handle:
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if row.get("ts") != target:
            continue
        mode = row.get("mode", "")
        if mode and mode not in seen:
            seen.add(mode)
            modes.append(mode)
print(",".join(modes))
PY
}

append_legacy_from_index_line_if_missing() {
  local line="$1"
  local ts_utc
  ts_utc="$(json_field "$line" "ts")"
  [[ -z "$ts_utc" ]] && return 0
  if grep -Fq -- "ts=$ts_utc " "$ROOT_DIR/memory/session_journal.md"; then
    return 0
  fi
  python3 - "$line" "$ROOT_DIR/memory/session_journal.md" "$ROOT_DIR/memory/compaction_handoffs.md" <<'PYINNER'
import json
import sys

raw, journal, handoff = sys.argv[1:4]
try:
    row = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(0)

def arr(value):
    if not value:
        return "[]"
    if isinstance(value, str):
        value = [value]
    return "[" + ";".join(str(v).replace("\n", " ")[:180] for v in value if str(v).strip()) + "]"

line = (
    f"ts={row.get('ts','')} sid={row.get('sid') or row.get('session_id','')} run={row.get('run_id','')} "
    f"agent={row.get('agent') or row.get('agent_id','')} mode={row.get('mode') or row.get('classification','checkpoint')} "
    f"phase={row.get('phase','')} ctx={arr(row.get('ctx') or row.get('tags'))} obj={arr(row.get('obj') or row.get('objective'))} "
    f"done={arr(row.get('done') or row.get('summary'))} issues={arr(row.get('issues') or row.get('blockers'))} "
    f"next={arr(row.get('next') or row.get('next_action'))} files={arr(row.get('files') or row.get('files_touched'))} seq={row.get('seq','')}"
)
with open(journal, "a", encoding="utf-8") as handle:
    handle.write(line + "\n")
if (row.get('mode') or row.get('classification')) in {'handoff', 'close', 'failure'}:
    with open(handoff, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
PYINNER
}

show_recent_sessions() {
  local file="$ROOT_DIR/memory/session_index.jsonl"
  [[ -s "$file" ]] || { echo "(none)"; return 0; }
  python3 - "$file" <<'PY'
import json, sys
from collections import OrderedDict

path = sys.argv[1]
rows = []
with open(path, "r", encoding="utf-8", errors="ignore") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue

seen = OrderedDict()
for row in rows:
    sid = row.get("sid") or row.get("session_id")
    if not sid:
        continue
    seen[sid] = (row.get("ts", ""), row.get("obj") or row.get("objective", ""))

items = list(seen.items())[-3:][::-1]
if not items:
    print("(none)")
else:
    for sid, (ts, objective) in items:
        print(f"- {sid} | {ts} | {objective}")
PY
}

show_learning_digest() {
  if [[ ! -x "$ROOT_DIR/scripts/learn-ingest.sh" ]] || [[ ! -f "$ROOT_DIR/scripts/learn_engine.py" ]]; then
    echo "(learning pipeline unavailable)"
    return 0
  fi
  python3 "$ROOT_DIR/scripts/learn_engine.py" --root "$ROOT_DIR" startup-digest 2>/dev/null || echo "(learning digest unavailable)"
}

latest_real_header() {
  local file="$1"
  awk '
    /^### / && $0 !~ /^### YYYY-MM-DD HH:MM TZ/ {last=$0}
    END {
      sub(/^### /, "", last)
      print last
    }
  ' "$file"
}

latest_real_journal_block() {
  local file="$1"
  awk '
    /^### / {
      if ($0 ~ /^### YYYY-MM-DD HH:MM TZ/) {
        cap=0
        next
      }
      cap=1
      buf=$0 ORS
      next
    }
    cap {
      if ($0 == "---") {
        buf=buf $0 ORS
        last=buf
        cap=0
        next
      }
      buf=buf $0 ORS
    }
    END {
      if (cap) last=buf
      printf "%s", last
    }
  ' "$file"
}

to_epoch_or_empty() {
  local ts="$1"
  if [[ -z "$ts" ]]; then
    echo ""
    return 0
  fi
  date -d "$ts" +%s 2>/dev/null || true
}

append_handoff_from_latest_journal_if_stale() {
  local journal_file="$ROOT_DIR/memory/session_journal.md"
  local handoff_file="$ROOT_DIR/memory/compaction_handoffs.md"
  local journal_ts handoff_ts journal_epoch handoff_epoch
  journal_ts="$(latest_real_header "$journal_file")"
  handoff_ts="$(latest_real_header "$handoff_file")"
  journal_epoch="$(to_epoch_or_empty "$journal_ts")"
  handoff_epoch="$(to_epoch_or_empty "$handoff_ts")"

  local stale=0
  if [[ -n "$journal_epoch" && -z "$handoff_epoch" ]]; then
    stale=1
  elif [[ -n "$journal_epoch" && -n "$handoff_epoch" && "$journal_epoch" -gt "$handoff_epoch" ]]; then
    stale=1
  fi

  if [[ "$stale" -eq 0 ]]; then
    return 0
  fi

  local block ts objective done files issues next mode event_ts_utc legacy_event_ts index_modes
  block="$(latest_real_journal_block "$journal_file")"
  ts="$(printf '%s\n' "$block" | sed -n 's/^### //p' | head -n1)"
  objective="$(printf '%s\n' "$block" | sed -n 's/^- Goal: //p' | head -n1)"
  done="$(printf '%s\n' "$block" | sed -n 's/^- Actions taken: //p' | head -n1)"
  files="$(printf '%s\n' "$block" | sed -n 's/^- Files changed: //p' | head -n1)"
  issues="$(printf '%s\n' "$block" | sed -n 's/^- Blockers: //p' | head -n1)"
  next="$(printf '%s\n' "$block" | sed -n 's/^- Next step: //p' | head -n1)"
  mode="$(printf '%s\n' "$block" | sed -n 's/^- Mode: //p' | head -n1)"
  event_ts_utc="$(printf '%s\n' "$block" | sed -n 's/^- Event TS (UTC): //p' | head -n1)"

  if [[ -z "$ts" || -z "$objective" ]]; then
    echo "[!] Could not parse latest journal block for auto-sync; leaving files unchanged."
    return 0
  fi

  if [[ -z "$event_ts_utc" ]]; then
    event_ts_utc="$(date -u -d "$ts" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"
  fi
  legacy_event_ts="$(printf '%s\n' "$ts" | sed 's/ [A-Z][A-Z][A-Z]$//' | xargs -I{} date -d "{}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"

  if [[ "$mode" == "checkpoint" ]]; then
    echo "[i] Latest journal block is checkpoint-only; leaving handoff mirror unchanged."
    return 0
  fi

  if [[ -n "$event_ts_utc" ]]; then
    index_modes="$(index_modes_for_ts "$event_ts_utc")"
    if [[ -z "$index_modes" && -n "$legacy_event_ts" ]]; then
      index_modes="$(index_modes_for_ts "$legacy_event_ts")"
    fi
    if [[ -n "$index_modes" ]] && [[ ",$index_modes," != *",handoff,"* ]] && [[ ",$index_modes," != *",close,"* ]]; then
      echo "[i] Latest journal block maps to checkpoint-only index entry; leaving handoff mirror unchanged."
      return 0
    fi
  fi

  echo "[!] Process gap: latest compaction handoff appears stale relative to newest journal activity."
  if [[ "$SYNC_STALE_HANDOFF" -eq 0 ]]; then
    echo "[i] Handoff auto-sync disabled by --no-handoff-sync."
    return 0
  fi

  [[ -z "$done" ]] && done="(not recorded)"
  [[ -z "$files" ]] && files="(not recorded)"
  [[ -z "$issues" ]] && issues="(not recorded)"
  [[ -z "$next" ]] && next="(not recorded)"

  cat >> "$handoff_file" <<HANDOFF
ts=$ts sid=legacy-auto run= agent=$AGENT_ID mode=handoff phase=auto-sync ctx=[] obj=[$objective] done=[$done] issues=[$issues] next=[$next] files=[$files] seq=
HANDOFF
  echo "[+] Auto-synced compaction handoff from latest session journal entry ($ts)."
}

build_resume_prompt() {
  local parts=""
  # Latest handoff context
  local handoff_tail
  handoff_tail="$(tail -n 15 "$ROOT_DIR/memory/compaction_handoffs.md" 2>/dev/null || true)"
  if [[ -n "$handoff_tail" ]]; then
    parts+="## Latest Handoff"$'\n'"$handoff_tail"$'\n\n'
  fi
  # Latest journal context
  local journal_tail
  journal_tail="$(tail -n 15 "$ROOT_DIR/memory/session_journal.md" 2>/dev/null || true)"
  if [[ -n "$journal_tail" ]]; then
    parts+="## Latest Journal"$'\n'"$journal_tail"$'\n\n'
  fi
  # Learning digest
  if [[ -n "${DIGEST_OUTPUT:-}" ]]; then
    parts+="## Learning Digest"$'\n'"$DIGEST_OUTPUT"$'\n\n'
  fi
  if [[ -z "$parts" ]]; then
    echo "Session resumed. Check memory/session_journal.md and memory/compaction_handoffs.md for latest state, then continue."
    return
  fi
  printf 'Session resumed. Here is the latest context from disk:\n\n%s\nReview this context, confirm current objective and next action, then continue.' "$parts"
}

run_resume_last() {
  set +e
  echo "[+] Resume method: --last"
  codex resume --last
  local rc=$?
  set -e
  return $rc
}

run_fresh_with_prompt() {
  echo "[+] Starting fresh Codex session with startup prompt"
  codex -C "$ROOT_DIR" "$START_PROMPT"
}

{
  append_handoff_from_latest_journal_if_stale
  LAST_INDEX="$(last_index_line)"
  if [[ -n "${LAST_INDEX:-}" ]]; then
    append_legacy_from_index_line_if_missing "$LAST_INDEX"
  fi
  AGENT_LAST_INDEX="$(latest_index_for_agent "$AGENT_ID")"
  if [[ -n "${AGENT_LAST_INDEX:-}" ]]; then
    LAST_OBJECTIVE="$(json_field "$AGENT_LAST_INDEX" "obj")"
  elif [[ -n "${LAST_INDEX:-}" ]]; then
    LAST_OBJECTIVE="$(json_field "$LAST_INDEX" "obj")"
  fi

  echo "=== CODEX STARTUP BRIEF ==="
  echo "Timestamp: $(date '+%Y-%m-%d %H:%M %Z')"
  echo "Repo: $ROOT_DIR"
  echo "Agent ID: $AGENT_ID"
  echo
  echo "[Read Order]"
  echo "1) $ROOT_DIR/MEM.md"
  echo "2) latest $ROOT_DIR/memory/compaction_handoffs.md"
  echo "3) latest $ROOT_DIR/memory/session_journal.md"
  echo "4) relevant $ROOT_DIR/PENTEST.md"
  echo
  echo "[Latest Dense Handoff]"
  grep -v '^#' "$ROOT_DIR/memory/compaction_handoffs.md" 2>/dev/null | tail -n 8 || true
  echo
  echo "[Latest Dense Journal]"
  grep -v '^#' "$ROOT_DIR/memory/session_journal.md" 2>/dev/null | tail -n 8 || true
  echo
  echo "[Latest Index Entry]"
  if [[ -n "${LAST_INDEX:-}" ]]; then
    printf '%s\n' "$LAST_INDEX"
  else
    echo "(none)"
  fi
  echo
  echo "[Latest Same-Agent Entry]"
  if [[ -n "${AGENT_LAST_INDEX:-}" ]]; then
    printf '%s\n' "$AGENT_LAST_INDEX"
  else
    echo "(none)"
  fi
  echo
  echo "[Recent Sessions (Top 3)]"
  show_recent_sessions
  echo
  show_learning_digest
  echo
  echo "[First Message To Send In Codex]"
  echo "$START_PROMPT"
  echo "=== END STARTUP BRIEF ==="
} > "$BRIEF_FILE"

echo "[+] Repo continuity check complete."
echo "[+] Startup reading order: MEM.md -> handoff -> journal -> PENTEST docs"
echo "[+] Session TMPDIR: $SESSION_TMPDIR"
echo "[+] Startup brief written: $BRIEF_FILE"
echo
cat "$BRIEF_FILE"
echo

if [[ "$PRINT_ONLY" -eq 1 ]]; then
  exit 0
fi

MEMORY_WATCH_PID=""
if ! command -v codex >/dev/null 2>&1; then
  echo "[!] codex binary not found in PATH."
  echo "    Install/restore Codex CLI, then rerun this helper."
  exit 127
fi

if [[ "$NO_MEMORY_WATCH" -ne 1 && -x "$ROOT_DIR/scripts/codex-memory-watch.sh" ]]; then
  SESSION_ID="$SESSION_ID" AGENT_ID="$AGENT_ID" OBJECTIVE="${LAST_OBJECTIVE:-session active}" \
    "$ROOT_DIR/scripts/codex-memory-watch.sh" >/dev/null 2>&1 &
  MEMORY_WATCH_PID="$!"
  echo "[+] Memory watcher started: pid=$MEMORY_WATCH_PID session=$SESSION_ID"
fi

auto_close_if_needed() {
  local rc="$1"
  local reason=""
  if [[ -n "${MEMORY_WATCH_PID:-}" ]]; then
    kill "$MEMORY_WATCH_PID" >/dev/null 2>&1 || true
    wait "$MEMORY_WATCH_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$AUTO_CLOSE_ON_INTERRUPT" -ne 1 || "$CODEX_STARTED" -ne 1 ]]; then
    return 0
  fi
  if [[ "$INTERRUPT_SEEN" -eq 1 ]]; then
    reason="${AUTO_CLOSE_REASON:-signal}"
  elif [[ "$rc" -eq 130 || "$rc" -eq 143 ]]; then
    reason="interrupt-exit"
  else
    return 0
  fi

  local objective done next
  objective="${LAST_OBJECTIVE:-Auto-close from codex-start wrapper}"
  done="codex-start wrapper observed Codex exit due to ${reason} (rc=${rc}) and persisted a close entry."
  next="Run bash scripts/codex-start.sh and resume from the latest session memory."

  echo
  echo "[+] Auto-close: writing close entry + running learning ingest."
  bash "$ROOT_DIR/scripts/codex-close.sh" \
    --mode close \
    --learn \
    --agent-id "$AGENT_ID" \
    --objective "$objective" \
    --done "$done" \
    --files "(not recorded by wrapper)" \
    --issues "(session interrupted; summarize specifics manually if needed)" \
    --next "$next" \
    --context-tags "auto-close,codex-start"
}

trap 'rc=$?; auto_close_if_needed "$rc"' EXIT

if [[ "$REQUIRE_RESUME" -eq 1 ]]; then
  echo "[+] Attempting: codex resume --last (--require-resume)"
  CODEX_STARTED=1
  run_resume_last
  exit $?
fi

echo "[+] Starting fresh Codex session with startup context."
CODEX_STARTED=1
run_fresh_with_prompt
