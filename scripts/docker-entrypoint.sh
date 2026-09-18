#!/usr/bin/env bash
# scripts/docker-entrypoint.sh
# Universal entrypoint for all ckcSOC services.
# Waits for required dependencies before starting the main process.
set -e

# ── Colours ───────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; RST='\033[0m'

log()  { echo -e "${GRN}[entrypoint]${RST} $*"; }
warn() { echo -e "${YLW}[entrypoint]${RST} $*"; }
die()  { echo -e "${RED}[entrypoint] FATAL:${RST} $*"; exit 1; }

# ── Wait for TCP port ────────────────────────────────────────────
wait_for() {
  local host="$1" port="$2" label="$3" timeout="${4:-120}"
  log "Waiting for ${label} (${host}:${port}) … timeout ${timeout}s"
  local elapsed=0
  while ! timeout 2 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "$elapsed" -ge "$timeout" ]; then
      die "${label} not reachable after ${timeout}s"
    fi
  done
  log "${label} is up ✓  (took ~${elapsed}s)"
}

# ── Wait for Kafka to be truly ready (broker metadata available) ─
wait_for_kafka() {
  local host="$1" port="$2" timeout="${3:-120}"
  wait_for "$host" "$port" "Kafka" "$timeout"

  # Extra: verify Kafka responds to topic list (broker fully initialised)
  log "Verifying Kafka broker is accepting requests …"
  local elapsed=0
  while ! python -c "
import socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('${host}', ${port}))
    # Send ApiVersions request (API key 18, v0) — lightest possible check
    header = struct.pack('>hhih', 18, 0, 1, 0)
    s.sendall(struct.pack('>i', len(header)) + header)
    resp_len = struct.unpack('>i', s.recv(4))[0]
    s.recv(resp_len)
    exit(0)
except Exception:
    exit(1)
finally:
    s.close()
" 2>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "$elapsed" -ge 60 ]; then
      warn "Kafka broker metadata check timed out — proceeding anyway"
      break
    fi
  done
  log "Kafka broker ready ✓"
}

# ── Wait for Elasticsearch cluster health ────────────────────────
wait_for_es() {
  local url="$1" timeout="${2:-120}"
  log "Waiting for Elasticsearch (${url}) …"
  local elapsed=0
  while true; do
    local status
    status=$(curl -sf "${url}/_cluster/health?timeout=2s" 2>/dev/null | python -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('status','red'))
except: print('red')
" 2>/dev/null || echo "red")
    if [ "$status" = "green" ] || [ "$status" = "yellow" ]; then
      log "Elasticsearch is ${status} ✓  (took ~${elapsed}s)"
      return 0
    fi
    sleep 3
    elapsed=$((elapsed + 3))
    if [ "$elapsed" -ge "$timeout" ]; then
      warn "Elasticsearch not healthy after ${timeout}s — proceeding anyway"
      return 0
    fi
  done
}

# ── Wait for Ollama (optional — pipeline degrades gracefully) ────
wait_for_ollama() {
  local url="$1" timeout="${2:-15}"
  log "Checking Ollama at ${url} …"
  local elapsed=0
  while ! curl -sf "${url}/api/tags" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "$elapsed" -ge "$timeout" ]; then
      warn "Ollama not reachable — playbooks will use template fallback"
      return 0
    fi
  done
  log "Ollama is up ✓"
}

# ── Auto-generate dataset if missing ─────────────────────────────
ensure_dataset() {
  if [ ! -f "datasets/hetero_events.mixed" ] && [ ! -f "datasets/all_events.json" ]; then
    log "No dataset found — generating synthetic data …"
    python datasets/hetero_dataset_builder.py 2>/dev/null || warn "Dataset generation skipped"
  fi
}

# ── Parse KAFKA_BOOTSTRAP into host:port ─────────────────────────
parse_kafka() {
  local bs="${KAFKA_BOOTSTRAP:-localhost:9092}"
  KAFKA_HOST="${bs%%:*}"
  KAFKA_PORT="${bs##*:}"
}

parse_es() {
  local url="${ES_URL:-http://localhost:9200}"
  # strip protocol
  url="${url#http://}"
  url="${url#https://}"
  ES_HOST="${url%%:*}"
  ES_PORT="${url##*:}"
  ES_PORT="${ES_PORT%%/*}"
}

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

SERVICE_ROLE="${SERVICE_ROLE:-pipeline}"
log "Starting ckcSOC service: ${SERVICE_ROLE}"

parse_kafka
parse_es

case "$SERVICE_ROLE" in
  pipeline)
    wait_for_kafka "$KAFKA_HOST" "$KAFKA_PORT" 120
    wait_for_es "$ES_URL" 90
    wait_for_ollama "${OLLAMA_URL:-http://host.docker.internal:11434}" 15
    ensure_dataset
    ;;
  gateway)
    # Gateway only needs state/ files — optional ES
    wait_for_es "$ES_URL" 30 || true
    ;;
  drift-monitor)
    # Drift monitor just needs state/ files
    log "Drift monitor — no hard dependencies"
    ;;
  kafka-pusher)
    wait_for_kafka "$KAFKA_HOST" "$KAFKA_PORT" 120
    ensure_dataset
    ;;
  *)
    warn "Unknown SERVICE_ROLE=${SERVICE_ROLE} — starting without dependency checks"
    ;;
esac

log "Handing off to: $*"
exec "$@"
