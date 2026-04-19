#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MEM_DIR="$ROOT_DIR/memory"
SESSION_ROOT="$MEM_DIR/sessions"
INDEX_FILE="$MEM_DIR/session_index.jsonl"
ALIASES_FILE="$MEM_DIR/session_aliases.json"
LOCK_FILE="$MEM_DIR/.memory.lock"
LEGACY_HANDOFF="$MEM_DIR/compaction_handoffs.md"
LEGACY_JOURNAL="$MEM_DIR/session_journal.md"

cd "$ROOT_DIR"
mkdir -p "$MEM_DIR" "$SESSION_ROOT"

MODE="close"
SESSION_ID="${SESSION_ID:-}"
ALIAS="${ALIAS:-}"
AGENT_ID="${AGENT_ID:-${CODEX_AGENT_ID:-$(hostname):$$}}"
PHASE="${PHASE:-}"
CONTEXT_TAGS="${CONTEXT_TAGS:-}"
HEARTBEAT=0
HEARTBEAT_MINUTES=20
AUTO_LEARN=0
AUTO_LEARN_SET=0

OBJECTIVE="${OBJECTIVE:-}"
DONE="${DONE:-}"
FILES="${FILES:-}"
ISSUES="${ISSUES:-}"
NEXT="${NEXT:-}"
SESSION_NOTE="${SESSION_NOTE:-}"

usage() {
  cat <<'USAGE'
Usage: bash scripts/codex-close.sh [options]

Core fields:
  --objective <text>
  --done <text>
  --files <text>
  --issues <text>
  --next <text>

Session/mode options:
  --mode checkpoint|handoff|close   (default: close)
  --session-id <id>
  --alias <name>
  --agent-id <id>
  --phase <label>
  --context-tags <csv>
  --heartbeat
  --heartbeat-minutes <N>           (default: 20)
  --learn
  --no-learn

Compatibility:
  If mode is handoff/close and required fields are missing, script prompts interactively.
  --session-note <text> is accepted as a shorthand compatibility flag for
  checkpoint-style writes and maps to the action summary when the structured
  fields are otherwise omitted.
USAGE
}

json_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

latest_session_for_agent() {
  local file="$1"
  local agent="$2"
  [[ -f "$file" ]] || return 0
  awk -v a="$agent" '
    {
      sid=""; aid=""
      if (match($0, /"session_id"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
        seg=substr($0, RSTART, RLENGTH)
        sub(/^"session_id"[[:space:]]*:[[:space:]]*"/, "", seg)
        sub(/"$/, "", seg)
        sid=seg
      }
      if (match($0, /"agent_id"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
        seg=substr($0, RSTART, RLENGTH)
        sub(/^"agent_id"[[:space:]]*:[[:space:]]*"/, "", seg)
        sub(/"$/, "", seg)
        aid=seg
      }
      if (aid == a && sid != "") last=sid
    }
    END { if (last != "") print last }
  ' "$file"
}

alias_lookup() {
  local file="$1"
  local alias="$2"
  [[ -f "$file" ]] || return 0
  awk -v key="$alias" '
    match($0, /^[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*"[^"]+"[[:space:]]*,?[[:space:]]*$/) {
      line=$0
      sub(/^[[:space:]]*"/, "", line)
      split(line, p, /"[[:space:]]*:[[:space:]]*"/)
      k=p[1]
      v=p[2]
      sub(/"[[:space:]]*,?[[:space:]]*$/, "", v)
      if (k == key) {
        print v
        exit
      }
    }
  ' "$file"
}

alias_update() {
  local file="$1"
  local alias="$2"
  local sid="$3"
  local tmp
  tmp="$(mktemp)"
  if [[ ! -f "$file" ]]; then
    printf '{\n}\n' > "$file"
  fi

  awk -v a="$alias" -v s="$sid" '
    BEGIN { }
    match($0, /^[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*"[^"]+"[[:space:]]*,?[[:space:]]*$/) {
      line=$0
      sub(/^[[:space:]]*"/, "", line)
      split(line, p, /"[[:space:]]*:[[:space:]]*"/)
      k=p[1]
      v=p[2]
      sub(/"[[:space:]]*,?[[:space:]]*$/, "", v)
      m[k]=v
    }
    END {
      m[a]=s
      print "{"
      n=0
      for (k in m) {
        keys[++n]=k
      }
      for (i=1; i<=n; i++) {
        k=keys[i]
        printf "  \"%s\": \"%s\"", k, m[k]
        if (i < n) printf ","
        printf "\n"
      }
      print "}"
    }
  ' "$file" > "$tmp"
  mv "$tmp" "$file"
}

ensure_legacy_file() {
  local path="$1"
  local title="$2"
  if [[ ! -f "$path" ]]; then
    printf '# %s\n\n' "$title" > "$path"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --session-id) SESSION_ID="${2:-}"; shift 2 ;;
    --alias) ALIAS="${2:-}"; shift 2 ;;
    --agent-id) AGENT_ID="${2:-}"; shift 2 ;;
    --phase) PHASE="${2:-}"; shift 2 ;;
    --context-tags) CONTEXT_TAGS="${2:-}"; shift 2 ;;
    --heartbeat) HEARTBEAT=1; shift ;;
    --heartbeat-minutes) HEARTBEAT_MINUTES="${2:-}"; shift 2 ;;
    --learn) AUTO_LEARN=1; AUTO_LEARN_SET=1; shift ;;
    --no-learn) AUTO_LEARN=0; AUTO_LEARN_SET=1; shift ;;
    --heartbeat-learn) HEARTBEAT_LEARN=1; shift ;;
    --objective) OBJECTIVE="${2:-}"; shift 2 ;;
    --done) DONE="${2:-}"; shift 2 ;;
    --files) FILES="${2:-}"; shift 2 ;;
    --issues) ISSUES="${2:-}"; shift 2 ;;
    --next) NEXT="${2:-}"; shift 2 ;;
    --session-note) SESSION_NOTE="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  checkpoint|handoff|close) ;;
  *) echo "Invalid --mode: $MODE" >&2; exit 2 ;;
esac

if [[ "$MODE" == "handoff" || "$MODE" == "close" ]] && [[ "$AUTO_LEARN_SET" -eq 0 ]]; then
  AUTO_LEARN=1
fi

if [[ "$MODE" == "handoff" || "$MODE" == "close" ]]; then
  if [[ -z "$OBJECTIVE" ]]; then read -r -p "Current objective: " OBJECTIVE; fi
  if [[ -z "$DONE" ]]; then read -r -p "Completed items: " DONE; fi
  if [[ -z "$FILES" ]]; then read -r -p "Files touched: " FILES; fi
  if [[ -z "$ISSUES" ]]; then read -r -p "Unresolved issues: " ISSUES; fi
  if [[ -z "$NEXT" ]]; then read -r -p "Next exact action: " NEXT; fi
else
  if [[ -n "$SESSION_NOTE" ]]; then
    [[ -z "$DONE" ]] && DONE="$SESSION_NOTE"
    [[ -z "$OBJECTIVE" ]] && OBJECTIVE="(checkpoint via --session-note)"
    [[ -z "$ISSUES" ]] && ISSUES="(not recorded)"
    [[ -z "$NEXT" ]] && NEXT="(not recorded)"
  fi
  [[ -z "$OBJECTIVE" ]] && OBJECTIVE="(not recorded)"
  [[ -z "$DONE" ]] && DONE="(checkpoint)"
  [[ -z "$FILES" ]] && FILES="(not recorded)"
  [[ -z "$ISSUES" ]] && ISSUES="(not recorded)"
  [[ -z "$NEXT" ]] && NEXT="(not recorded)"
fi

if [[ -n "$ALIAS" && ! "$ALIAS" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Alias must match [A-Za-z0-9._-]+" >&2
  exit 2
fi

ensure_legacy_file "$LEGACY_HANDOFF" "Compaction-Safe Handoffs"
ensure_legacy_file "$LEGACY_JOURNAL" "Session Journal"

exec 9>"$LOCK_FILE"
flock 9

if [[ -z "$SESSION_ID" && -n "$ALIAS" ]]; then
  SESSION_ID="$(alias_lookup "$ALIASES_FILE" "$ALIAS")"
fi
if [[ -z "$SESSION_ID" ]]; then
  SESSION_ID="$(latest_session_for_agent "$INDEX_FILE" "$AGENT_ID")"
fi
if [[ -z "$SESSION_ID" ]]; then
  short_uuid="$(cat /proc/sys/kernel/random/uuid 2>/dev/null | cut -d- -f1 || true)"
  [[ -z "$short_uuid" ]] && short_uuid="$(date +%s)"
  SESSION_ID="s-$(date -u '+%Y%m%d')-$short_uuid"
fi

SESSION_DIR="$SESSION_ROOT/$SESSION_ID"
SESSION_JOURNAL="$SESSION_DIR/journal.md"
SESSION_HANDOFF="$SESSION_DIR/handoffs.md"
mkdir -p "$SESSION_DIR"
if [[ ! -f "$SESSION_JOURNAL" ]]; then
  printf '# Session Journal (%s)\n\n' "$SESSION_ID" > "$SESSION_JOURNAL"
fi
if [[ ! -f "$SESSION_HANDOFF" ]]; then
  printf '# Session Handoffs (%s)\n\n' "$SESSION_ID" > "$SESSION_HANDOFF"
fi

TMP_SWEEP_RESULT=""
if [[ -x "$ROOT_DIR/scripts/tmp-artifact-sweep.sh" ]]; then
  TMP_SWEEP_RESULT="$("$ROOT_DIR/scripts/tmp-artifact-sweep.sh" --session-id "$SESSION_ID" --window-hours 24 2>/dev/null || true)"
fi

CTF_TMPDIR="${TMPDIR:-}"
if [[ -z "$CTF_TMPDIR" && -f "$ROOT_DIR/.ctf_tmpdir" ]]; then
  CTF_TMPDIR="$(cat "$ROOT_DIR/.ctf_tmpdir" 2>/dev/null || true)"
fi

if [[ "$HEARTBEAT" -eq 1 ]]; then
  NOW_EPOCH="$(date -u +%s)"
  LAST_EPOCH="$(awk '
    {
      if (match($0, /"session_id"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
        seg=substr($0, RSTART, RLENGTH)
        sub(/^"session_id"[[:space:]]*:[[:space:]]*"/, "", seg)
        sub(/"$/, "", seg)
        sid=seg
      } else sid=""
      if (sid == want && match($0, /"ts"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
        t=substr($0, RSTART, RLENGTH)
        sub(/^"ts"[[:space:]]*:[[:space:]]*"/, "", t)
        sub(/"$/, "", t)
        gsub(/T/, " ", t)
        gsub(/Z$/, " UTC", t)
        cmd="date -u -d \"" t "\" +%s"
        cmd | getline epoch
        close(cmd)
        if (epoch ~ /^[0-9]+$/) last=epoch
      }
    }
    END { if (last != "") print last }
  ' want="$SESSION_ID" "$INDEX_FILE" 2>/dev/null || true)"

  if [[ -n "${LAST_EPOCH:-}" && "$LAST_EPOCH" =~ ^[0-9]+$ ]]; then
    MIN_DELTA=$(( HEARTBEAT_MINUTES * 60 ))
    DELTA=$(( NOW_EPOCH - LAST_EPOCH ))
    if (( DELTA < MIN_DELTA )); then
      echo "[i] Heartbeat skipped: last write ${DELTA}s ago (< ${MIN_DELTA}s)."
      exit 0
    fi
  fi
fi

TS_LOCAL="$(date '+%Y-%m-%d %H:%M %Z')"
TS_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
CLASSIFICATION="event"
if [[ "$HEARTBEAT" -eq 1 ]]; then
  CLASSIFICATION="heartbeat"
fi

if [[ -n "$ALIAS" ]]; then
  alias_update "$ALIASES_FILE" "$ALIAS" "$SESSION_ID"
fi

{
  echo "### $TS_LOCAL"
  echo "- Mode: $MODE"
  echo "- Session ID: $SESSION_ID"
  [[ -n "$ALIAS" ]] && echo "- Alias: $ALIAS"
  echo "- Agent ID: $AGENT_ID"
  [[ -n "$PHASE" ]] && echo "- Phase: $PHASE"
  [[ -n "$CONTEXT_TAGS" ]] && echo "- Context tags: $CONTEXT_TAGS"
  echo "- Goal: $OBJECTIVE"
  echo "- Actions taken: $DONE"
  echo "- Files changed: $FILES"
  echo "- Blockers: $ISSUES"
  echo "- Next step: $NEXT"
  echo "- Classification: $CLASSIFICATION"
  echo "- Event TS (UTC): $TS_UTC"
  echo
  echo "---"
} >> "$SESSION_JOURNAL"

if [[ "$MODE" == "handoff" || "$MODE" == "close" ]]; then
  {
    echo "### $TS_LOCAL"
    echo "- Mode: $MODE"
    echo "- Session ID: $SESSION_ID"
    [[ -n "$ALIAS" ]] && echo "- Alias: $ALIAS"
    echo "- Agent ID: $AGENT_ID"
    [[ -n "$PHASE" ]] && echo "- Phase: $PHASE"
    [[ -n "$CONTEXT_TAGS" ]] && echo "- Context tags: $CONTEXT_TAGS"
    echo "- Current objective: $OBJECTIVE"
    echo "- Completed items: $DONE"
    echo "- Files touched: $FILES"
    echo "- Unresolved issues: $ISSUES"
    echo "- Next exact action: $NEXT"
    echo "- Event TS (UTC): $TS_UTC"
    echo
    echo "---"
  } >> "$SESSION_HANDOFF"
fi

OBJ_JSON="$(json_escape "$OBJECTIVE")"
DONE_JSON="$(json_escape "$DONE")"
FILES_JSON="$(json_escape "$FILES")"
ISSUES_JSON="$(json_escape "$ISSUES")"
NEXT_JSON="$(json_escape "$NEXT")"
ALIAS_JSON="$(json_escape "$ALIAS")"
AGENT_JSON="$(json_escape "$AGENT_ID")"
PHASE_JSON="$(json_escape "$PHASE")"
TAGS_JSON="$(json_escape "$CONTEXT_TAGS")"
CLASS_JSON="$(json_escape "$CLASSIFICATION")"

printf '{"ts":"%s","session_id":"%s","agent_id":"%s","mode":"%s","objective":"%s","blockers":"%s","next_action":"%s","summary":"%s","files_touched":"%s","alias":"%s","phase":"%s","tags":"%s","classification":"%s"}\n' \
  "$TS_UTC" "$SESSION_ID" "$AGENT_JSON" "$MODE" "$OBJ_JSON" "$ISSUES_JSON" "$NEXT_JSON" "$DONE_JSON" "$FILES_JSON" "$ALIAS_JSON" "$PHASE_JSON" "$TAGS_JSON" "$CLASS_JSON" >> "$INDEX_FILE"

# Dense canonical memory record. Legacy markdown and the older flat JSONL line
# above are kept for compatibility with existing agents.
if [[ -x "$ROOT_DIR/scripts/memory-write.py" ]]; then
  "$ROOT_DIR/scripts/memory-write.py" \
    --root "$ROOT_DIR" \
    --mode "$MODE" \
    --session-id "$SESSION_ID" \
    --agent "$AGENT_ID" \
    --phase "$PHASE" \
    --objective "$OBJECTIVE" \
    --done "$DONE" \
    --issue "$ISSUES" \
    --next "$NEXT" \
    --file "$FILES" \
    --context "$CONTEXT_TAGS" >/dev/null 2>&1 || true
fi

# Compatibility mirrors remain populated for startup read order and existing tools.
{
  echo "### $TS_LOCAL"
  echo "- Goal: $OBJECTIVE"
  echo "- Actions taken: $DONE"
  echo "- Files changed: $FILES"
  echo "- Blockers: $ISSUES"
  echo "- Next step: $NEXT"
  echo "- Session ID: $SESSION_ID"
  [[ -n "$ALIAS" ]] && echo "- Alias: $ALIAS"
  echo "- Agent ID: $AGENT_ID"
  echo "- Mode: $MODE"
  echo "- Event TS (UTC): $TS_UTC"
  echo
  echo "---"
} >> "$LEGACY_JOURNAL"

if [[ "$MODE" == "handoff" || "$MODE" == "close" ]]; then
  {
    echo "### $TS_LOCAL"
    echo "- Current objective: $OBJECTIVE"
    echo "- Completed items: $DONE"
    echo "- Files touched: $FILES"
    echo "- Unresolved issues: $ISSUES"
    echo "- Next exact action: $NEXT"
    echo "- Session ID: $SESSION_ID"
    [[ -n "$ALIAS" ]] && echo "- Alias: $ALIAS"
    echo "- Agent ID: $AGENT_ID"
    echo "- Mode: $MODE"
    echo "- Event TS (UTC): $TS_UTC"
    echo
    echo "---"
  } >> "$LEGACY_HANDOFF"
fi

echo "[+] Wrote $MODE entry for session $SESSION_ID (agent: $AGENT_ID)."
echo "[+] Session files: $SESSION_JOURNAL$( [[ "$MODE" == "handoff" || "$MODE" == "close" ]] && printf ', %s' "$SESSION_HANDOFF" )"
echo "[+] Index updated: $INDEX_FILE"
if [[ -n "$TMP_SWEEP_RESULT" ]]; then
  echo "[+] tmp artifact sweep: $TMP_SWEEP_RESULT"
fi
if [[ -n "$CTF_TMPDIR" && "$CTF_TMPDIR" == /tmp/CTF/* && -d "$CTF_TMPDIR" ]]; then
  rm -rf "$CTF_TMPDIR"
  if [[ -f "$ROOT_DIR/.ctf_tmpdir" ]] && [[ "$(cat "$ROOT_DIR/.ctf_tmpdir" 2>/dev/null || true)" == "$CTF_TMPDIR" ]]; then
    : > "$ROOT_DIR/.ctf_tmpdir"
  fi
  echo "[+] cleaned temp workspace: $CTF_TMPDIR"
fi

flock -u 9
exec 9>&-

# Opponent intel: summarize and auto-ingest if opponent-watch log exists
OPP_WATCH_LOGS=$(find "$ROOT_DIR/challenges/tryhackme/koth/" -name "opponent_watch_*.log" -newer "$SESSION_JOURNAL" 2>/dev/null || true)
if [[ -n "$OPP_WATCH_LOGS" ]]; then
  echo "[+] Opponent watch logs detected — summarizing..."
  for opp_log in $OPP_WATCH_LOGS; do
    opp_files=$(grep -c 'type=new_file' "$opp_log" 2>/dev/null || echo 0)
    opp_procs=$(grep -c 'type=new_proc' "$opp_log" 2>/dev/null || echo 0)
    opp_conns=$(grep -c 'type=new_conn' "$opp_log" 2>/dev/null || echo 0)
    opp_kings=$(grep -c 'type=king_change' "$opp_log" 2>/dev/null || echo 0)
    opp_logins=$(grep -c 'type=ssh_login' "$opp_log" 2>/dev/null || echo 0)
    opp_captured=$(grep -c 'type=captured' "$opp_log" 2>/dev/null || echo 0)
    echo "    $(basename "$opp_log"): files=$opp_files procs=$opp_procs conns=$opp_conns kings=$opp_kings logins=$opp_logins captured=$opp_captured"
  done
fi

# Auto-ingest new opponent tool reports
OPP_REPORTS=$(find "$ROOT_DIR/memory/opponent_tools/" -name "opponent_tool_report_*.md" -newer "$SESSION_JOURNAL" 2>/dev/null || true)
if [[ -n "$OPP_REPORTS" ]]; then
  echo "[+] Auto-ingesting opponent tool reports..."
  for rpt in $OPP_REPORTS; do
    python3 "$ROOT_DIR/scripts/learn_engine.py" --root "$ROOT_DIR" opponent-ingest "$rpt" --session-id "$SESSION_ID" 2>&1 || true
  done
fi

if [[ "$AUTO_LEARN" -eq 1 && -x "$ROOT_DIR/scripts/learn-ingest.sh" ]]; then
  if ! "$ROOT_DIR/scripts/learn-ingest.sh" --session-id "$SESSION_ID"; then
    echo "[!] Learning ingest failed; memory write already completed." >&2
  fi
fi

# Heartbeat learning: run ingest during checkpoint mode without full handoff
if [[ "${HEARTBEAT_LEARN:-0}" -eq 1 && -x "$ROOT_DIR/scripts/learn-ingest.sh" ]]; then
  echo "[+] Heartbeat learning: running ingest..."
  "$ROOT_DIR/scripts/learn-ingest.sh" --session-id "$SESSION_ID" || \
    echo "[!] Heartbeat learning ingest failed." >&2
fi
