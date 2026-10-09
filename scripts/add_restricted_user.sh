#!/usr/bin/env bash
#
# Put a Grafana account in the "Restricted" org ONLY, as a Viewer, so it sees
# the dashboards with hashed client IPs and nothing else.
#
# Creates the account if the login does not exist (a password is generated and
# printed once), or converts an existing one. Either way it then enforces the
# three conditions the restriction depends on, each of which Grafana's own
# defaults get wrong:
#
#   - member of org 2 and NO other org. Grafana adds every new user to org 1
#     (GF_USERS_AUTO_ASSIGN_ORG_ID), and org 1 has the full-IP datasource.
#   - Viewer there, not Editor/Admin. An org Admin can edit the datasource and
#     point it at the full tenant.
#   - not a Grafana server admin, which can switch into any org.
#
# Usage:  ./scripts/add_restricted_user.sh <login> [email] [name]
#
# Run scripts/setup_restricted_org.sh first.

set -euo pipefail

[[ $# -ge 1 ]] || { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
LOGIN="$1"
EMAIL="${2:-}"
NAME="${3:-$LOGIN}"
[[ "$LOGIN" != "admin" ]] || { echo "error: refusing to restrict the admin account" >&2; exit 1; }

source "$(dirname "${BASH_SOURCE[0]}")/lib_grafana.sh"
ORG="$RESTRICTED_ORG_ID"

api GET "/api/orgs/$ORG" >/dev/null
[[ "$(code)" == 200 ]] || { echo "error: org $ORG does not exist -- run scripts/setup_restricted_org.sh" >&2; exit 1; }

# --- create or find -------------------------------------------------------
body="$(api GET "/api/users/lookup?loginOrEmail=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$LOGIN")")"
if [[ "$(code)" == 200 ]]; then
  USER_ID="$(field id <<<"$body")"
  echo "user         '$LOGIN' exists (id $USER_ID) -- converting to restricted"
else
  PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(15))')"
  user_json="$(python3 -c '
import json, sys
print(json.dumps({"login": sys.argv[1], "email": sys.argv[2], "name": sys.argv[3],
                  "password": sys.argv[4], "OrgId": int(sys.argv[5])}))' \
    "$LOGIN" "$EMAIL" "$NAME" "$PASSWORD" "$ORG")"
  body="$(api POST /api/admin/users "$user_json")"
  [[ "$(code)" == 200 ]] || { echo "error: creating user: $body" >&2; exit 1; }
  USER_ID="$(field id <<<"$body")"
  echo "user         '$LOGIN' created (id $USER_ID)"
  # Printed now, not at the end: a later step failing must not lose it.
  echo "password     $PASSWORD   (shown once -- the user should change it)"
fi

# --- server admin ---------------------------------------------------------
body="$(api GET "/api/users/$USER_ID")"
if [[ "$(field isGrafanaAdmin <<<"$body")" == "True" ]]; then
  api PUT "/api/admin/users/$USER_ID/permissions" '{"isGrafanaAdmin": false}' >/dev/null
  [[ "$(code)" == 200 ]] || { echo "error: could not revoke server admin" >&2; exit 1; }
  echo "server admin revoked"
fi

# --- org membership -------------------------------------------------------
orgs="$(api GET "/api/users/$USER_ID/orgs" | python3 -c '
import json, sys
print(" ".join(str(o["orgId"]) for o in json.load(sys.stdin)))')"
if [[ " $orgs " != *" $ORG "* ]]; then
  api POST "/api/orgs/$ORG/users" "{\"loginOrEmail\": \"$LOGIN\", \"role\": \"Viewer\"}" >/dev/null
  [[ "$(code)" == 200 ]] || { echo "error: adding to org $ORG" >&2; exit 1; }
fi
api PATCH "/api/orgs/$ORG/users/$USER_ID" '{"role": "Viewer"}' >/dev/null
[[ "$(code)" == 200 ]] || { echo "error: setting Viewer role in org $ORG" >&2; exit 1; }
# Switch the active org BEFORE leaving the others: Grafana refuses to remove a
# user from the org they are currently using.
api POST "/api/users/$USER_ID/using/$ORG" >/dev/null
for o in $orgs; do
  [[ "$o" == "$ORG" ]] && continue
  body="$(api DELETE "/api/orgs/$o/users/$USER_ID")"
  [[ "$(code)" == 200 ]] || { echo "error: removing from org $o: $body" >&2; exit 1; }
  echo "removed from org $o"
done

# --- verify ---------------------------------------------------------------
final="$(api GET "/api/users/$USER_ID/orgs" | python3 -c '
import json, sys
print(" ".join("%s:%s" % (o["orgId"], o["role"]) for o in json.load(sys.stdin)))')"
if [[ "$final" != "$ORG:Viewer" ]]; then
  echo "error: memberships are '$final', expected '$ORG:Viewer' only" >&2
  exit 1
fi
echo "membership   org $ORG (Restricted) as Viewer, no other org"
