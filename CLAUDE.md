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

## Two silent failure modes

Both cost data or hours, and neither announces itself.

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

## Data handling

`./backfill/` holds copies of a production log directory — client IPs, session cookies,
requested URLs, gigabytes of it. The whole directory is gitignored, as is `import.log`, which
echoes log lines. `.env` holds the Grafana admin password and is gitignored; `.env.example`
documents every setting.
