#!/usr/bin/env bash
#
# Create the "Restricted" Grafana org: accounts in it see the Apache dashboards
# with every client IP replaced by a salted hash, and cannot reach the real ones
# by any route.
#
# Why an org and not a folder: Grafana OSS has no per-panel permissions, and
# no per-datasource query permissions either (Enterprise only). Anyone who can
# open a dashboard can send arbitrary LogQL to its datasource through
# /api/ds/query, and the raw log lines carry the IP regardless of which panels
# are shown. Datasources belong to exactly one org, so the boundary that holds
# is: org 2 only has a datasource reading the `redacted` Loki tenant.
#
# Idempotent -- safe to re-run, and re-running is how a dashboard edit in
# grafana/dashboards/ reaches the restricted org. Needs the stack running.
#
# Usage:  ./scripts/setup_restricted_org.sh
#
# Then add accounts with scripts/add_restricted_user.sh.

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib_grafana.sh"
DS_UID="apache-loki-redacted"
HOME_UID="apache-traffic-approx-restricted"

# --- org ------------------------------------------------------------------
body="$(api GET "/api/orgs/name/$RESTRICTED_ORG_NAME")"
if [[ "$(code)" == 200 ]]; then
  ORG_ID="$(field id <<<"$body")"
  echo "org          '$RESTRICTED_ORG_NAME' exists (id $ORG_ID)"
else
  body="$(api POST /api/orgs "{\"name\": \"$RESTRICTED_ORG_NAME\"}")"
  [[ "$(code)" == 200 ]] || { echo "error: creating org: $body" >&2; exit 1; }
  ORG_ID="$(field orgId <<<"$body")"
  echo "org          '$RESTRICTED_ORG_NAME' created (id $ORG_ID)"
fi
if [[ "$ORG_ID" != "$RESTRICTED_ORG_ID" ]]; then
  echo "error: '$RESTRICTED_ORG_NAME' is org $ORG_ID, but provider.yml provisions its" \
       "dashboards into org $RESTRICTED_ORG_ID. Change orgId there (and" \
       "RESTRICTED_ORG_ID in scripts/lib_grafana.sh) to $ORG_ID." >&2
  exit 1
fi

# --- datasource -----------------------------------------------------------
# Created through the API, not a provisioning file: a datasource file naming an
# org that does not exist yet would have to be added only AFTER this script ran,
# which a fresh deployment would get wrong. The consequence is that an org
# Admin could edit it -- so restricted accounts are Viewers, never Admins
# (add_restricted_user.sh enforces that). Pointing this at tenant `fake` would
# expose every IP; that is the one edit that must never happen.
DS_JSON="$(cat <<EOF
{
  "name": "Loki (hashed IPs)",
  "type": "loki",
  "uid": "$DS_UID",
  "access": "proxy",
  "url": "http://loki:3100",
  "isDefault": true,
  "jsonData": {"maxLines": 5000, "timeout": 60, "httpHeaderName1": "X-Scope-OrgID"},
  "secureJsonData": {"httpHeaderValue1": "redacted"}
}
EOF
)"
body="$(api GET "/api/datasources/uid/$DS_UID" "" "$ORG_ID")"
if [[ "$(code)" == 200 ]]; then
  body="$(api PUT "/api/datasources/uid/$DS_UID" "$DS_JSON" "$ORG_ID")"
  verb="updated"
else
  body="$(api POST /api/datasources "$DS_JSON" "$ORG_ID")"
  verb="created"
fi
[[ "$(code)" == 200 ]] || { echo "error: datasource: $body" >&2; exit 1; }
echo "datasource   $DS_UID $verb (Loki tenant 'redacted')"

# Belt and braces: nothing else may live in this org's datasource list.
others="$(api GET /api/datasources "" "$ORG_ID" | python3 -c '
import json, sys
print(" ".join(d["uid"] for d in json.load(sys.stdin) if d["uid"] != sys.argv[1]))' "$DS_UID")"
if [[ -n "$others" ]]; then
  echo "WARNING: org $ORG_ID has other datasources ($others). Remove any that" \
       "read tenant 'fake' -- they expose the real IPs." >&2
fi

# --- dashboards -----------------------------------------------------------
# Copies of grafana/dashboards/*.json, pointed at the redacted datasource and
# pushed through the API. NOT a dashboard provider with orgId 2: Grafana 12
# treats a provider whose org does not exist as fatal ("failed to get org by
# ID: 2") and restart-loops -- on every fresh deployment, and again after any
# `docker compose down -v`, since the org lives in the Grafana volume.
#
# So these do not follow edits to the originals by themselves: RE-RUN THIS
# SCRIPT AFTER EDITING A DASHBOARD. It fails if a client-IP title or a
# reference to the full datasource survives the rewrite.
for src in "$ROOT"/grafana/dashboards/*.json; do
  payload="$(python3 - "$src" "$DS_UID" <<'EOF'
import json, sys
src, ds_uid = sys.argv[1], sys.argv[2]
d = json.load(open(src))
RENAME = {
    'Unique client IPs': 'Unique clients (hashed)',
    'Top 10 client IPs': 'Top 10 clients (hashed)',
    'Client IP (regex)': 'Client hash (regex)',
}

def walk(o):
    if isinstance(o, dict):
        if o.get('type') == 'loki' and o.get('uid') == 'apache-loki':
            o['uid'] = ds_uid
        for k in ('title', 'label'):
            if isinstance(o.get(k), str):
                o[k] = RENAME.get(o[k], o[k])
        for v in o.values():
            walk(v)
    elif isinstance(o, list):
        for v in o:
            walk(v)

walk(d)
d['uid'] += '-restricted'
d['title'] = (d['title'][:-1] + ', restricted)' if d['title'].endswith(')')
              else d['title'] + ' (restricted)')
d.pop('id', None)
text = json.dumps(d)
if '"apache-loki"' in text:
    sys.exit(f'{src}: a reference to datasource apache-loki survived the rewrite')
for o in [d] + d.get('panels', []) + d.get('templating', {}).get('list', []):
    for k in ('title', 'label'):
        if 'client IP' in str(o.get(k, '')):
            sys.exit(f'{src}: {k} {o[k]!r} still says "client IP" -- add it to RENAME')
print(json.dumps({'dashboard': d, 'overwrite': True,
                  'message': 'scripts/setup_restricted_org.sh'}))
EOF
)"
  body="$(api POST /api/dashboards/db "$payload" "$ORG_ID")"
  [[ "$(code)" == 200 ]] || { echo "error: dashboard $(basename "$src"): $body" >&2; exit 1; }
  echo "dashboard    $(field uid <<<"$body")"
done

# GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH is server-wide and points at the
# org-1 dashboard, whose datasource does not exist here. An org preference wins
# over it.
body="$(api PATCH /api/org/preferences "{\"homeDashboardUID\": \"$HOME_UID\"}" "$ORG_ID")"
[[ "$(code)" == 200 ]] || { echo "error: home dashboard: $body" >&2; exit 1; }
echo "home         $HOME_UID"

echo
echo "Done. Add accounts with: ./scripts/add_restricted_user.sh <login> [email]"
