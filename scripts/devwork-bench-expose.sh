#!/usr/bin/env bash
set -euo pipefail

DEVWORK_HOST="${DEVWORK_HOST:-<BENCH_HOST>}"
DEVWORK_USER="${DEVWORK_USER:-<CRACK_NODE_USER>}"
SSH_KEY="${SSH_KEY:-~/.ssh/<LAB_KEY>}"
REMOTE_ROOT="${REMOTE_ROOT:-${REMOTE_HOME:-$HOME}/validation-benchmarks}"
LAN_HOST="${LAN_HOST:-<BENCH_HOST>}"
LIMIT="${LIMIT:-0}"
NO_SYNC="${NO_SYNC:-0}"

SSH_OPTS=(
  -i "$SSH_KEY"
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o ConnectTimeout=10
)

REMOTE="${DEVWORK_USER}@${DEVWORK_HOST}"

if [[ "$NO_SYNC" != "1" ]]; then
  echo "[*] Syncing benchmark repo to ${REMOTE}:${REMOTE_ROOT}"
  rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
    ${CTF_ROOT:-.}/tools/validation-benchmarks/ \
    "${REMOTE}:${REMOTE_ROOT}/"
fi

echo "[*] Launching benchmarks on ${REMOTE} (detached, LAN exposed)"
ssh "${SSH_OPTS[@]}" "$REMOTE" \
  "REMOTE_ROOT='${REMOTE_ROOT}' LAN_HOST='${LAN_HOST}' LIMIT='${LIMIT}' bash -s" <<'REMOTE_SCRIPT'
set -euo pipefail

REMOTE_ROOT="${REMOTE_ROOT:-${REMOTE_HOME:-$HOME}/validation-benchmarks}"
LAN_HOST="${LAN_HOST:-<BENCH_HOST>}"
LIMIT="${LIMIT:-0}"
MAP_DIR="$REMOTE_ROOT/_lan_map"
JSONL="$MAP_DIR/endpoints.jsonl"
CSV="$MAP_DIR/endpoints.csv"
BUNDLES_JSON="$MAP_DIR/benchmarks.json"

mkdir -p "$MAP_DIR"
: > "$JSONL"
echo "benchmark_id,service,container_port,proto,host_port,url,status" > "$CSV"
echo "[" > "$BUNDLES_JSON"

cd "$REMOTE_ROOT"

count=0
first_bundle=1
for bench in benchmarks/XBEN-*; do
  if [[ ! -d "$bench" ]]; then
    continue
  fi
  bench_id="$(basename "$bench")"
  if [[ "$LIMIT" -gt 0 && "$count" -ge "$LIMIT" ]]; then
    break
  fi
  count=$((count + 1))

  status="ok"
  endpoint_count=0
  endpoint_json=""

  if ! sudo make -C "$bench" build >/tmp/"$bench_id"_build.log 2>&1; then
    status="build_failed"
  else
    if ! sudo docker compose -f "$bench/docker-compose.yml" up -d >/tmp/"$bench_id"_up.log 2>&1; then
      status="up_failed"
    else
      services="$(sudo docker compose -f "$bench/docker-compose.yml" config --services 2>/dev/null || true)"
      for svc in $services; do
        cid="$(sudo docker compose -f "$bench/docker-compose.yml" ps -q "$svc" 2>/dev/null | head -n1 || true)"
        if [[ -z "$cid" ]]; then
          continue
        fi
        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          left="${line%% -> *}"
          right="${line##* -> }"
          cport="${left%%/*}"
          proto="${left##*/}"
          hport="${right##*:}"
          case "$cport" in
            80|443|3000|5000|8000|8080|8443) scheme="http" ;;
            *) scheme="tcp" ;;
          esac
          if [[ "$scheme" == "http" ]]; then
            url="${scheme}://${LAN_HOST}:${hport}"
          else
            url="${LAN_HOST}:${hport}"
          fi
          printf '{"benchmark_id":"%s","service":"%s","container_port":"%s","proto":"%s","host_port":"%s","url":"%s","status":"%s"}\n' \
            "$bench_id" "$svc" "$cport" "$proto" "$hport" "$url" "$status" >> "$JSONL"
          printf '%s,%s,%s,%s,%s,%s,%s\n' \
            "$bench_id" "$svc" "$cport" "$proto" "$hport" "$url" "$status" >> "$CSV"

          ep="{\"service\":\"$svc\",\"container_port\":\"$cport\",\"proto\":\"$proto\",\"host_port\":\"$hport\",\"url\":\"$url\"}"
          if [[ "$endpoint_count" -eq 0 ]]; then
            endpoint_json="$ep"
          else
            endpoint_json="$endpoint_json,$ep"
          fi
          endpoint_count=$((endpoint_count + 1))
        done < <(sudo docker port "$cid" 2>/dev/null || true)
      done
      if [[ "$endpoint_count" -eq 0 ]]; then
        status="no_http_port"
      fi
    fi
  fi

  if [[ "$endpoint_count" -eq 0 ]]; then
    endpoint_json=""
  fi
  bundle="{\"benchmark_id\":\"$bench_id\",\"status\":\"$status\",\"endpoint_count\":$endpoint_count,\"endpoints\":[${endpoint_json}]}"
  if [[ "$first_bundle" -eq 1 ]]; then
    echo "  $bundle" >> "$BUNDLES_JSON"
    first_bundle=0
  else
    echo "  ,$bundle" >> "$BUNDLES_JSON"
  fi
done

echo "]" >> "$BUNDLES_JSON"
echo "[done] wrote $JSONL, $CSV and $BUNDLES_JSON"
REMOTE_SCRIPT

echo "[*] Pulling endpoint map locally"
mkdir -p ${CTF_ROOT:-.}/artifacts/benchmarks
rsync -az -e "ssh ${SSH_OPTS[*]}" \
  "${REMOTE}:${REMOTE_ROOT}/_lan_map/" \
  ${CTF_ROOT:-.}/artifacts/benchmarks/devwork_lan_map/

echo "[ok] LAN map saved to ${CTF_ROOT:-.}/artifacts/benchmarks/devwork_lan_map/"
