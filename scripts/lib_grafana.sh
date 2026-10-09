# Sourced by scripts/setup_restricted_org.sh and scripts/add_restricted_user.sh.
# Talks to Grafana's HTTP API as the admin user from .env.
#
#   body="$(api METHOD PATH [JSON] [ORG_ID])"; [[ "$(code)" == 200 ]]
#   field NAME <<<"$body"      # top-level JSON field (python3, since jq is optional)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
RESTRICTED_ORG_NAME="Restricted"
# grafana/provisioning/dashboards/provider.yml provisions the restricted
# dashboards into this org id. Provider files cannot name an org, only an id.
RESTRICTED_ORG_ID=2

env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true; }
PW="$(env_get GF_ADMIN_PASSWORD)"
PORT="$(env_get GRAFANA_PORT)"
GF="${GF_URL:-http://127.0.0.1:${PORT:-3000}}"
[[ -n "$PW" ]] || { echo "error: GF_ADMIN_PASSWORD not found in $ENV_FILE" >&2; exit 1; }

# The HTTP status of the last api() call goes to a file, not a variable:
# api() runs in a $(...) subshell, which cannot set the caller's variables.
CODE_FILE="$(mktemp)"; trap 'rm -f "$CODE_FILE"' EXIT
api() {
  local args=(-s -w '%{http_code}' -u "admin:$PW" -H 'Content-Type: application/json' -X "$1")
  [[ -n "${4:-}" ]] && args+=(-H "X-Grafana-Org-Id: $4")
  [[ -n "${3:-}" ]] && args+=(--data "$3")
  local out; out="$(curl "${args[@]}" "$GF$2")"
  printf '%s' "${out:0:${#out}-3}"
  printf '%s' "${out: -3}" > "$CODE_FILE"
}
code() { cat "$CODE_FILE"; }
field() { python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }

curl -sf -o /dev/null "$GF/api/health" \
  || { echo "error: Grafana is not answering at $GF -- docker compose up -d" >&2; exit 1; }
