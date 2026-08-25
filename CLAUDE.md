# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Docker Compose stack (Grafana + Loki + Grafana Alloy) that turns Apache access/error logs
into a filterable traffic dashboard. There is **no build, no lint, and no test suite** — the
repo is configuration plus one standard-library Python script. "Running the tests" means
importing a small log family and querying Loki back; see Verification below.

## Commands

```bash
./scripts/setup.sh              # generate .env from the machine (safe to re-run; --force to regenerate)
docker compose up -d
docker compose down             # stop, keep data
docker compose down -v          # stop and delete ALL ingested logs
docker compose restart alloy    # after editing alloy/config.alloy
docker compose restart grafana  # after editing grafana/provisioning/alerting/*.yaml
```

A change to `loki/config.yml` or `alloy/config.alloy` needs a container restart; a change to
`docker-compose.yml` (volumes, mem_limit) needs `docker compose up -d` to *recreate*, not
restart. `grafana/dashboards/*.json` is re-read every 30s with no restart.

Validate an Alloy config before restarting — it fails silently into a crash loop otherwise:

```bash
docker run --rm -v "$PWD/alloy/config.alloy:/c.alloy:ro" --entrypoint alloy \
  grafana/alloy:v1.12.0 validate /c.alloy
```

Importing rotated archives (`scripts/import_logs.py`, stdlib only, Python 3.9+):

```bash
./scripts/import_logs.py --log-dir ./backfill --discover --list      # what it found, no writes
./scripts/import_logs.py --log-dir ./backfill --discover --dry-run   # parse + report, push nothing
./scripts/import_logs.py --log-dir ./backfill --discover --exclude error.log -v
./scripts/import_logs.py --log-dir ./backfill --access-log jjj_access.log   # one family, seconds
```

`--dry-run` on a large archive set takes ~20 min and is the fastest way to prove a parser
change against real data at full scale. Naming `--access-log` explicitly is what keeps a
smoke test fast: `--discover --since` still reads every archive to find lines in range.

## Architecture

### Two ingestion paths, deliberately disjoint

```
live:     /var/log/apache2/*.log ──→ Alloy ──┐
                                    (parse)  ├─→ Loki ──→ Grafana
history:  ./backfill/*.log[.N][.gz] ─────────┘  (store)  (dashboard)
             scripts/import_logs.py (parse + push)
```

Alloy tails **live files only**, with exact paths and never globs — `logrotate` renames on
rotation, so `access.log*` would make Alloy re-read a file it already tailed. History goes
through `import_logs.py`, which POSTs straight to Loki's push API and needs nothing from the
stack. `./backfill` is **not** mounted into Alloy; staging decompressed archives there meant
~20 GB of plaintext beside the `.gz` it came from and two paths that could each ingest the
same history.

### Parser parity is the main invariant

`alloy/config.alloy` and `scripts/import_logs.py` implement **the same four regexes and emit
the same labels and structured metadata**, so live and imported data land in one stream and
one dashboard query covers both. Change a regex or a label in one and you must change the
other. The formats, tried in order and decided per line:

| Format | Signature |
|---|---|
| `combined` | `%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"`, plus any number of trailing `"..."` fields |
| `vhost_combined` | a `%v:%p` prefix (`other_vhosts_access.log`) |
| proxied | no `%l %u`, XFF chain in `%h`, User-Agent *before* Referer |
| Apache / Phusion Passenger | interleaved in one error log, split per line |

The trailing-quoted-fields tail on `combined` is load-bearing: sites extend the format freely
(a session cookie, an `Accept` header), and a regex ending at the User-Agent rejects every
such line outright rather than degrading — which is how one 57M-line vhost silently
contributed nothing.

Passenger/Apache classification is **per line, not per file**: a server-wide `error.log`
interleaves them in wildly varying ratios, so the file name proves nothing. Passenger lines
get `log_type="passenger"` to keep the dashboard's error panel readable.

Alloy's `stage.regex` has no fall-through, so the format is carried as a `log_format` target
label, selected on with `stage.match`, and dropped via `stage.label_drop` before shipping.
Per-line branching that labels cannot express (the Passenger split) uses a **line filter** in
the `stage.match` selector.

### Label strategy

Stream labels are low-cardinality only: `job`, `host`, `vhost`, `log_type`, `method`,
`status`, `level`, `module`. Everything high-cardinality (`remote_addr`, `path`, `user_agent`,
`referer`, `bytes`) is **structured metadata**, filterable in LogQL (`| remote_addr =~ "..."`)
without multiplying streams.

Two cardinality rules that exist because the internet is hostile:

- Only real HTTP verbs become the `method` label. Scanners put arbitrary text in the request
  line (`Chrome`, `yacybot`, `EmailWolf`); anything else is labelled `OTHER` with the raw
  token kept as `method_raw` metadata.
- `%v` (which Apache resolved) outranks a filename-derived vhost. `%{Host}i` does **not** — it
  is client input, so trusting it would let a request claim any site. It is stored as
  `vhost_hdr` metadata only.

### Alerting

Alert rules are **Grafana-managed**, provisioned as files from
`grafana/provisioning/alerting/` (already covered by the existing
`./grafana/provisioning` bind mount, so adding rules needs no compose change --
only `docker compose restart grafana`). Loki's `ruler:` block in `loki/config.yml`
is deliberately unused: it has no `alertmanager_url`, so rules evaluated there
would fire into nothing. Do not add rule files under it as well, or the same
condition is evaluated twice.

`apache-rules.yaml` holds the rules, `contact-points.yaml` the email contact
point and the notification policy. Both are read-only in the UI; edit the file
and restart.

**There is exactly one rule, `apache-scanner-surge`, and it is deliberately
seasonal.** It compares the 403/404 share of traffic against the same clock time
**one week earlier** (`offset 7d`) and alerts when it exceeds that baseline by
more than 15 percentage points.

It is **scoped to `vhost="fairdomhub"`** -- every selector in the expression
carries that matcher. Widening it means deleting those five matchers *and*
re-calibrating: +15pp was measured against fairdomhub's traffic profile alone,
and a vhost with a different baseline shape needs its own threshold. Before the
matchers existed the `> 1000 requests / 30m` volume guard did this filtering as a
side effect, which meant any quiet vhost growing past that line would silently
start paging under a rule not calibrated for it.

A fixed-percentage threshold was measured and rejected: total traffic swings 3x
across the day (34k-103k requests/hour) and the 40x share independently swings
3.5%-31% by hour, so the single largest 40x spike in a sample day -- 73% -- fell
at 02:40, caused only by legitimate traffic draining away at night. `offset 7d`
lands on the same weekday at the same clock time, cancelling both the diurnal and
the weekday/weekend shape, and needs no timezone handling -- which matters,
because `APACHE_TZ` describes the host that WROTE the logs, not the reader.

Measured separation over 30m windows, in percentage points:

| period | median | p95 | max |
|---|---|---|---|
| quiet weeks | -0.2pp | 0.4pp | 6.6pp |
| active campaign | 4.2pp | 34.4pp | 55.9pp |

Three findings that constrain any future edit to this rule:

- **`method="OTHER"` is not a scanner signal on this data**, despite being the
  label built for exactly that purpose -- it matched 1 request in 1,358,176.
- **User agent is not a discriminator either.** The top UA strings on 403
  responses are byte-identical to those on 200s (spoofed `Chrome/142-145`), so
  UA-pattern matching catches none of this traffic.
- **Subtract the baseline, do not divide by it.** The week-ago share is often
  near zero (0.24% against 28.8% live in one measured hour), and a ratio of
  ratios goes to infinity there. Percentage points stay bounded and legible.

Two caveats that are properties of the seasonal design, not bugs:

- **The baseline poisons itself after 7 days.** A campaign lasting longer than a
  week becomes its own baseline and the alert resolves while the scanning
  continues. Resolved means "no longer unusual for this hour", not "stopped". If
  that bites, average a 7d and a 14d baseline rather than lengthening the offset.
- **The first week of a deployment cannot alert.** With no data 7 days back the
  offset term returns no series, so the rule sits at NoData -> `OK`. Same after
  `docker compose down -v`.

**Removing a rule needs more than deleting it from the file.** Grafana keeps
provisioned rules until told to drop them, via a `deleteRules:` stanza (orgId +
uid) that must survive one restart:

```yaml
deleteRules:
  - orgId: 1
    uid: apache-5xx
```

Confirm with the API, then the stanza can be removed. The same applies to
`deleteContactPoints:`.

**Alert expressions are not dashboard expressions, and cannot be copied across.**
Two independent reasons:

- Every panel expression contains Grafana macros (`$__range`, `$__auto`) and
  template variables (`$host`, `${vhost:regex}`, `$ip`, ...). Those are
  interpolated by the browser at render time. A rule is evaluated server-side
  with no dashboard around it, so windows must be literal and match the rule's
  `relativeTimeRange`.
- A rule re-runs every `interval`, forever. `topk`/`approx_topk` and any
  `sum by (remote_addr|path|user_agent)` are therefore banned in rules -- see the
  `max_query_series` and `LOKI_MEM` notes below. The shipped rule groups only by
  `vhost`, and matches on `status`; both are stream labels, so it is answered
  from the index and measures 0.11s against its 1m interval.

The rule omits the `host` label entirely rather than hardcoding `APACHE_HOST`,
which would recreate the `.env` coupling described below for no gain on a
single-host deployment.

**A malformed alerting provisioning file kills Grafana.** Unlike dashboard
provisioning, which logs and carries on, a rejected contact point or rule file
stops the provisioning service and the container restart-loops:

```
Failed to provision alerting ... failure to map file contact-points.yaml
Error: *provisioning.ProvisioningServiceImpl run error
```

The sharpest edge is an **empty** value, not a malformed one: `addresses:` with
nothing in it fails validation with `could not find addresses in settings`. That
is why `ALERT_EMAIL_TO` has a non-routable fallback in `docker-compose.yml` --
an unconfigured mailbox must not be able to take the stack down. Check after any
edit:

```bash
docker compose up -d && docker logs apachemon-grafana 2>&1 | grep -i "provision"
```

Email delivery is configured entirely through `.env` (`SMTP_*`, `ALERT_EMAIL_TO`)
and is optional: with `SMTP_HOST` empty the rules still evaluate and fire, they
just reach no one. The alert is visible under Alerting -> Active notifications
either way, so the UI looks identical whether or not mail works -- the delivery
failure shows up only in the Grafana log, where an unconfigured relay falls back
to `localhost:25`:

```bash
docker logs apachemon-grafana --since 10m 2>&1 | grep "Notify for alerts failed"
# ... err="apache-email/email[0]: ... failed to send email: dial tcp [::1]:25: connect: connection refused"
```

That line is the check that delivery actually works; a firing alert on the
dashboard proves only that the rule evaluated. Note that `scripts/setup.sh`
carries these keys over from an existing `.env` rather than regenerating them, so
`--force` does not silently disable alert delivery.

### Configuration coupling

`APACHE_HOST` in `.env` reaches both sides: Compose passes it as the Alloy container's
`hostname:`, which is what `constants.hostname` resolves to in `config.alloy`, and
`import_logs.py` reads the same key for its `--host` default. Keeping them equal is what gives
the dashboard a single `Host` value — the variable is single-select, so a mismatch splits live
and historical data into two views you must toggle between.

Adding a vhost means adding a `path_targets` entry per live log file in `alloy/config.alloy`.
The importer needs nothing: `--discover` finds archives by name and derives the vhost from it.

The dashboard (`grafana/dashboards/apache-traffic.json`, datasource uid `apache-loki`) carries
an identical matcher set in all 15 panel expressions. Adding a variable means threading it
into every one; edit the JSON as text rather than round-tripping it through a JSON dumper,
which reflows the hand-formatting into a several-hundred-line diff.

## Three silent failure modes

Each costs data or hours, and none announces itself.

**`schema_config.from` must predate the oldest log line.** Loki answers a push with HTTP 204
whether or not an index period covers the timestamp; if none does, the entry is stored and
permanently unqueryable. Compare the `Time span` the importer prints against `from` in
`loki/config.yml`. Lower it and re-import; never raise it.

**Loki's memory ceiling is a cliff that reports itself as clean restarts.** The ingester holds
an open chunk per active stream, so its footprint tracks `active streams x chunk_target_size`,
and streams multiply with vhosts x methods x statuses. When the cgroup limit is hit the kernel
kills the ingester while Docker reports `exit 0` and `OOMKilled=false`. Diagnose with:

```bash
docker inspect apachemon-loki --format '{{.RestartCount}}'
journalctl -k | grep oom-kill
```

`LOKI_MEM` in `.env` sets the ceiling; `chunk_target_size` in `loki/config.yml` sets the
appetite. Raising `max_chunk_age` for out-of-order tolerance directly raises memory too.

**A query that exceeds `max_query_series` reports itself as a Grafana client timeout, not as
an error.** The three "Top 10" panels shard into per-shard `sum by (<high-cardinality field>)`
results that travel querier -> query frontend over gRPC, and that payload scales with distinct
values rather than with the 10 rows shown. Past the 4MB gRPC default the frontend rejects every
shard with `ResourceExhausted` -- logged querier-side as `error notifying frontend about
finished query` -- so neither the results nor the `maximum of series (100000) reached for a
single query` 400 can be delivered. The frontend retries, no response header is ever written,
and Grafana surfaces it at 60s (its datasource `timeout`) as:

```
net/http: request canceled (Client.Timeout exceeded while awaiting headers)
```

Nothing in that message names the series limit or gRPC. `server.grpc_server_max_*_msg_size`
plus `frontend_worker.grpc_client_config.max_send_msg_size` in `loki/config.yml` are raised to
100MB so the refusal arrives as a 400 in ~2s instead. Both ends must be raised; lifting one
leaves the other rejecting. This only restores the error message -- it does not make an exact
`topk` over unbounded cardinality affordable. Confirm which of the two you are looking at:

```bash
docker logs apachemon-loki --since 5m 2>&1 | grep -E "reached for a single query|larger than max"
```

On this dataset the exact-`topk` dashboard cannot serve those panels beyond a few hours -- one
day of one vhost is already >100k distinct client IPs. `approx_topk` answers the same 24h range
in ~5s at ~680MB, so **"Apache Traffic (approx)" is the dashboard to use for any range wider
than a few hours**; `apache-traffic.json` is the exact-count reference for narrow ones, and it
is also `GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH`, so the default landing page is the variant
that refuses first. `approx_topk` is bounded but not free: at 7d it peaked past a 2g `LOKI_MEM`
and was OOM-killed per the cliff above.

## Verification

The importer's own read-back verification issues one instant query spanning the whole import,
which **fails on large imports** (`could not verify`, connection closed) — that is a query-size
limit, not data loss. Verify large imports with the index stats API instead, which reads the
index rather than scanning chunks:

```bash
curl -sG http://127.0.0.1:3100/loki/api/v1/index/stats \
  --data-urlencode 'query={job="apache", log_type="access"}' \
  --data-urlencode "start=$(date -d 2023-01-01 +%s)000000000" \
  --data-urlencode "end=$(date +%s)000000000"
```

Per-day counts from that endpoint are the real correctness check: a continuous series means
timestamps parsed, **a single tall spike means they did not** and lines inherited the previous
entry's time. Also confirm `method` label values stay a short list, and that the stream count
is far below `max_streams_per_user`.

Grafana's default range is 24h; historical data looks like an empty dashboard until the range
is widened to the imported span.

Alert rules are verified through Grafana's API rather than the UI -- a rule that provisions
successfully can still fail every evaluation, and `health` is the field that says so:

```bash
PW=$(grep -E '^GF_ADMIN_PASSWORD=' .env | cut -d= -f2-)
curl -s -u "admin:$PW" http://127.0.0.1:3000/api/v1/provisioning/alert-rules | jq -r '.[].title'
curl -s -u "admin:$PW" http://127.0.0.1:3000/api/prometheus/grafana/api/v1/rules \
  | jq -r '.data.groups[].rules[] | "\(.name)\t\(.state)\t\(.health)\t\(.lastError // "")"'
```

`health=ok` means the LogQL ran. Check the contact point's `addresses` in
`/api/v1/provisioning/contact-points` resolved to a real mailbox and not to the placeholder,
which is what an unset `ALERT_EMAIL_TO` leaves behind.

On a deployment fed only from `./backfill` the rule cannot fire and should sit `Normal`: the
archives carry old timestamps, so the live 30m window is empty and `noDataState: OK` keeps it
quiet. To prove the expression still discriminates, evaluate it directly at a timestamp where
data exists rather than waiting for it to trigger:

```bash
# a known scanner campaign -> ~ +27.9pp ; a quiet week -> ~ -0.6pp
curl -sG http://127.0.0.1:3100/loki/api/v1/query \
  --data-urlencode 'time=1786010380000000000' \
  --data-urlencode 'query=<the expr from apache-rules.yaml>' | jq '.data.result'
```

## Data handling

`./backfill/` holds copies of a production log directory — client IPs, session cookies,
requested URLs, gigabytes of it. The whole directory is gitignored, as is `import.log`, which
echoes log lines. `.env` holds the Grafana admin password and is gitignored; `.env.example`
documents every setting.
