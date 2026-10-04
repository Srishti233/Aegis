#!/usr/bin/env bash
# Run Aegis WITHOUT Docker (needs a reachable PostgreSQL with the pgvector extension and a Redis).
# Usage: scripts/run_local.sh start|stop
set -euo pipefail
cd "$(dirname "$0")/.."
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://aegis:aegis@localhost:5432/aegis}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"
export UPSTREAM_URL="${UPSTREAM_URL:-http://localhost:9000}"
LOGDIR="${LOGDIR:-/tmp}"
case "${1:-start}" in
  start)
    setsid nohup python3 -m uvicorn mock_llm.main:app --host 0.0.0.0 --port 9000 >"$LOGDIR/aegis-mock.log" 2>&1 < /dev/null &
    setsid nohup python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 >"$LOGDIR/aegis-gateway.log" 2>&1 < /dev/null &
    for _ in $(seq 1 60); do
      curl -fs localhost:8000/ready >/dev/null 2>&1 && { echo "Aegis is ready on http://localhost:8000"; exit 0; }
      sleep 1
    done
    echo "gateway did not become ready; see $LOGDIR/aegis-gateway.log" >&2; exit 1 ;;
  stop)
    pkill -f "[u]vicorn app.main:app" || true; pkill -f "[u]vicorn mock_llm.main:app" || true ;;
esac
