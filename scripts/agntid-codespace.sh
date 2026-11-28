#!/usr/bin/env bash
# Run INSIDE the AgentProof Codespace (via `gh codespace ssh`). No secrets are read or printed.
#   bash scripts/agntid-codespace.sh up       # start/resume the AgntID runtime, wait for health
#   bash scripts/agntid-codespace.sh status   # health, readiness, MCP tool list
#   bash scripts/agntid-codespace.sh matrix   # live scenario matrix -> docs/agntid-live/<UTC time>/
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
AGNTID_DIR="${AGNTID_DIR:-}"
find_agntid() {
  [ -n "$AGNTID_DIR" ] && return
  local proj
  proj="$(docker compose ls -a --format json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const p=JSON.parse(s).find(x=>/agntid/i.test(x.Name+x.ConfigFiles));if(p)console.log(p.ConfigFiles.split(",")[0])}catch{}})')"
  if [ -n "$proj" ]; then AGNTID_DIR="$(dirname "$proj")"; return; fi
  for d in /workspaces/agntid-python "$HOME/agntid-python" /workspaces/*/agntid-python; do
    [ -f "$d/docker-compose.yml" ] && { AGNTID_DIR="$d"; return; }
  done
  AGNTID_DIR="$HOME/agntid-python"
  git clone --depth 1 https://github.com/AGNTID-AI/agntid-python "$AGNTID_DIR"
}
wait_health() {
  for _ in $(seq 1 40); do
    curl -fsS -o /dev/null http://localhost:8080/health && { echo "health: 200"; return 0; }
    sleep 5
  done
  echo "health: not ready after 200s"; return 1
}
case "${1:-status}" in
  up)
    find_agntid; echo "AgntID compose dir: $AGNTID_DIR"
    (cd "$AGNTID_DIR" && docker compose up -d achr-runtime)   # legacy-ml model profile NOT started
    wait_health
    docker ps --filter name=achr --format '{{.Names}}: {{.Status}}'
    echo "Next (on your laptop): gh codespace ports visibility 8080:private 8082:private -c <name>"
    echo "                       gh codespace ports forward 8080:8080 -c <name>   then open http://localhost:8080";;
  status)
    curl -s -o /dev/null -w 'health: %{http_code}\n' http://localhost:8080/health || true
    curl -s -w '\n' http://localhost:8080/ready | head -c 600 || true
    docker ps --filter name=achr --format '{{.Names}}: {{.Status}}' || true;;
  matrix)
    : "${AGNTID_AGENT_ID:?export AGNTID_AGENT_ID (portal agent id for AgentProof Security Demo)}"
    : "${AGNTID_USER_ID:?export AGNTID_USER_ID (e.g. your portal user / test user id)}"
    cd "$REPO"; [ -d node_modules ] || npm ci --no-audit --no-fund
    OUT="docs/agntid-live/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$OUT"
    AGNTID_MCP_URL="${AGNTID_MCP_URL:-http://localhost:8082/mcp}" node demo/agntid-matrix.ts --out "$OUT" | tee "$OUT.log" | sed -n '/^SUMMARY/,$p'
    mv "$OUT.log" "$OUT/console.log"
    AGNTID_MCP_URL="${AGNTID_MCP_URL:-http://localhost:8082/mcp}" node demo/agntid-live.ts --out "$OUT/starter" > "$OUT/starter.log" 2>&1 \
      && echo "starter smoke: PASS" || echo "starter smoke: see $OUT/starter.log"
    if grep -rEl 'eyJ[A-Za-z0-9_-]{10,}\.|Bearer [A-Za-z0-9]' "$OUT" >/dev/null; then echo "WARNING: token-like text found in $OUT; do not commit"; else echo "secret scan: clean"; fi
    echo "Evidence: $REPO/$OUT";;
  *) echo "usage: $0 up|status|matrix"; exit 2;;
esac
