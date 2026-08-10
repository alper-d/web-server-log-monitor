#!/usr/bin/env python3
"""
Import older (rotated) Apache log files straight into Loki, so they show up in
the Grafana dashboard alongside live traffic.

Handles the shapes logrotate leaves behind:

    access.log.1        trailing integer, uncompressed (logrotate delaycompress)
    access.log.2.gz     trailing integer, gzip compressed
    access_log-20250101.gz    dateext naming is picked up too, ordered by mtime

and, with --discover, every access/error log in the directory rather than just
one pair -- a multi-vhost server keeps one per site (fairdomhub-access.log,
jjj_access.log, other_vhosts_access.log, ...), each labelled with its vhost.

Four log formats are recognised, tried in order and detected per line, because
one directory routinely mixes them:

    combined [+ %D %{Host}i] [+ any number of trailing "..." fields]
    vhost_combined              a %v:%p prefix (other_vhosts_access.log)
    proxied                     %h holds an X-Forwarded-For chain, UA comes first
    Apache / Phusion Passenger  interleaved in one error log, split per line
                                onto log_type="error" and log_type="passenger"

This talks to Loki's HTTP push API directly. It does not need Alloy, a Docker
volume, or write access to anything -- it only reads the log files and POSTs to
Loki. Lines are parsed into the same labels and structured metadata that
alloy/config.alloy produces, so imported history is queryable with the same
dashboard filters as live data.

Re-running is safe: Loki drops entries that are byte-identical in timestamp,
line and labels within a stream, so a second import of the same archive adds
nothing rather than doubling counts.

Examples
--------
    ./scripts/import_logs.py --list             # what would be imported, in order
    ./scripts/import_logs.py --dry-run          # parse everything, report, push nothing
    ./scripts/import_logs.py                    # do it
    ./scripts/import_logs.py --since 2025-01-01 --only access
    sudo -E ./scripts/import_logs.py            # if the logs aren't readable by you

    # every vhost in ./backfill, minus the server-wide (mostly Passenger) log
    ./scripts/import_logs.py --log-dir ./backfill --discover --exclude error.log

Requires only the Python 3 standard library (3.9+).
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9
    ZoneInfo = None  # type: ignore

ROOT = Path(__file__).resolve().parent.parent


class _TooLarge(Exception):
    """A push payload exceeded Loki's message size limit; split and retry."""

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
# These mirror alloy/config.alloy so that imported lines land in the same
# streams, with the same structured metadata, as live-tailed ones.

# One quoted-field body. (?:[^"\\]|\\.)* rather than [^"]* so that a
# backslash-escaped quote inside a URL or User-Agent doesn't end the field
# early -- Apache escapes `"` as `\"` in these positions.
_QF = r'(?:[^"\\]|\\.)*'

# Any number of trailing `"..."` fields after the User-Agent. Sites extend
# `combined` freely: FAIRDOMHub appends a session cookie
# (`... "Mozilla/5.0 ..." "_seek_session=abc123"`), others append Accept or
# X-Forwarded-For. Tolerating an arbitrary tail is what lets one regex serve
# every vhost -- without it a single extra field makes the whole line fail to
# match, and 57M requests land with an inherited timestamp instead of their own.
_EXTRA = rf'(?P<extra>(?: "{_QF}")*)'

ACCESS_RE = re.compile(
    rf'^(?P<remote_addr>\S+) (?P<ident>\S+) (?P<remote_user>\S+) '
    rf'\[(?P<ts>[^\]]+)\] "(?P<request>{_QF})" '
    rf'(?P<status>\d{{3}}) (?P<bytes>\S+)'
    rf'(?: "(?P<referer>{_QF})" "(?P<user_agent>{_QF})")?'
    rf'(?: (?P<duration_us>\d+) (?P<vhost_hdr>\S+))?'
    rf'{_EXTRA}\s*$'
)

# Apache's `vhost_combined`, which is what other_vhosts_access.log uses:
#   %v:%p %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"
#   seek.example.org:443 1.2.3.4 - - [05/Aug/2026:00:00:20 +0000] "GET / ..." 301 5407 "-" "..."
# Tried only after ACCESS_RE, and the two cannot be confused: a plain combined
# line fails here (its 4th field is a "[timestamp", not a request), and a
# vhost_combined line fails ACCESS_RE for the same structural reason.
VHOST_ACCESS_RE = re.compile(
    rf'^(?P<vhost>[^\s:"]+)(?::(?P<port>\d+))? '
    rf'(?P<remote_addr>\S+) (?P<ident>\S+) (?P<remote_user>\S+) '
    rf'\[(?P<ts>[^\]]+)\] "(?P<request>{_QF})" '
    rf'(?P<status>\d{{3}}) (?P<bytes>\S+)'
    rf'(?: "(?P<referer>{_QF})" "(?P<user_agent>{_QF})")?'
    rf'(?: (?P<duration_us>\d+) (?P<vhost_hdr>\S+))?'
    rf'{_EXTRA}\s*$'
)

# A vhost fronted by a reverse proxy (fairdomhub-55555-access.log). Its
# LogFormat drops %l %u entirely, puts a client chain in %h, and -- unlike
# combined -- leads with the User-Agent rather than the Referer:
#   %h %t "%r" %>s %O "%{User-Agent}i" "%{Accept}i" "%{Host}i" "%{Referer}i" "%{Accept-Encoding}i"
#   66.249.76.228, 172.18.0.1 [12/Aug/2025:13:44:05 +0000] "GET /s/26227 HTTP/1.1" 500 4393 "Mozilla/5.0 ..." "text/html..." "fairdomhub.org" "-" "gzip"
# Tried last, and safely so: both regexes above require the literal `%l %u`
# fields between the address and the "[timestamp", which this format has not
# got, and this one requires the timestamp immediately after the address chain.
# The chain repeat is `*` not `+` -- some lines carry a single address.
PROXIED_ACCESS_RE = re.compile(
    rf'^(?P<remote_addr>[0-9a-fA-F.:]+)(?P<forwarded_for>(?:, *[0-9a-fA-F.:]+)*) '
    rf'\[(?P<ts>[^\]]+)\] "(?P<request>{_QF})" '
    rf'(?P<status>\d{{3}}) (?P<bytes>\S+)'
    rf' "(?P<user_agent>{_QF})"'
    rf'(?: "(?P<accept>{_QF})")?'
    rf'(?: "(?P<vhost_hdr>{_QF})")?'
    rf'(?: "(?P<referer>{_QF})")?'
    rf'(?: "(?P<accept_encoding>{_QF})")?\s*$'
)

ACCESS_FORMATS = (ACCESS_RE, VHOST_ACCESS_RE, PROXIED_ACCESS_RE)

# Split separately so a malformed %r from a scanner only costs method/path
# rather than dropping the whole line.
REQUEST_RE = re.compile(r'^(?P<method>[A-Za-z_-]+) (?P<path>\S*)(?: (?P<protocol>\S+))?$')

# Only these become the `method` stream label. Everything else Apache logs in
# that position is a malformed request line from a scanner, and each distinct
# value would multiply the stream count by the number of statuses and vhosts it
# co-occurs with. A 2M-line sample of real traffic yielded `Chrome`,
# `ZoominfoBot`, `WPMU`, `Link`, `yacybot`, `RecordedFuture`, `Passenger`,
# `Hello` and `EmailWolf` -- a long tail with no ceiling. The raw token is kept
# as `method_raw` structured metadata, which costs no cardinality.
HTTP_METHODS = frozenset((
    'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT',
))

ERROR_RE = re.compile(
    r'^\[(?P<ts>[^\]]+)\] \[(?P<module>[^:\]]+):(?P<level>[^\]]+)\] '
    r'\[pid (?P<pid>[^\]]+)\](?: \[client (?P<client>[^\]]+)\])? ?(?P<message>.*)$'
)

# Phusion Passenger writes into the same error log as Apache, in its own format:
#   [ N 2026-08-06 00:00:18.5302 2180209/T1 age/Wat/WatchdogMain.cpp:1365 ]: Starting Passenger watchdog...
# The severity is a single letter (N notice, W warning, E error, D debug) and the
# timestamp is ISO-ish with no UTC offset, so it needs the same --tz treatment as
# Apache's. These are separated onto log_type="passenger" so the dashboard's
# Apache error panel stays readable; the mix is per-LINE, not per-file (one
# archive here holds 48870 Passenger lines against 1130 Apache ones, another
# 1478 against 2088), so the file name cannot be used to tell them apart.
PASSENGER_RE = re.compile(
    r'^\[ (?P<level>[A-Za-z]) '
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) '
    r'(?P<pid>\d+)/(?P<tid>\S+) (?P<src>.*?) \]: ?(?P<message>.*)$'
)

# Output the Rails app itself wrote to stdout/stderr, which Passenger forwards
# with a prefix but no timestamp of its own:  `App 2181012 output: ...`
APP_RE = re.compile(r'^App (?P<pid>\d+) (?P<channel>output|stderr): ?(?P<message>.*)$')

PASSENGER_LEVELS = {
    'D': 'debug', 'I': 'info', 'N': 'notice',
    'W': 'warn', 'E': 'error', 'C': 'crit', 'F': 'fatal',
}

# Apache always writes English month/day abbreviations regardless of the
# server's locale. Python's strptime("%b") consults LC_TIME, so on a host with
# e.g. LC_TIME=de_DE it would expect "Okt" and fail on Apache's "Oct". An
# explicit table keeps parsing correct on every locale.
MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}

# 10/Oct/2024:14:03:55 +0200
ACCESS_TS_RE = re.compile(
    r'^(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-])(\d{2})(\d{2}))?$'
)
# Wed Aug 05 08:41:47.196518 2026
ERROR_TS_RE = re.compile(
    r'^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+(\d{4})$'
)
# 2026-08-06 00:00:18.5302   (Passenger; numeric month, so no MONTHS lookup)
PASSENGER_TS_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$'
)


def parse_access_ts(raw: str):
    """Parse an access-log timestamp, honouring its embedded UTC offset."""
    m = ACCESS_TS_RE.match(raw.strip())
    if not m:
        return None
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    month = MONTHS.get(mon)
    if month is None:
        return None
    if sign:
        offset = timedelta(hours=int(oh), minutes=int(om))
        tz = timezone(-offset if sign == '-' else offset)
    else:
        tz = timezone.utc
    try:
        return datetime(int(year), month, int(day), int(hh), int(mm), int(ss), tzinfo=tz)
    except ValueError:
        return None


def parse_error_ts(raw: str, tz):
    """Parse an error-log timestamp. It carries no offset, hence the tz argument."""
    m = ERROR_TS_RE.match(raw.strip())
    if not m:
        return None
    mon, day, hh, mm, ss, frac, year = m.groups()
    month = MONTHS.get(mon)
    if month is None:
        return None
    micro = int((frac or '0')[:6].ljust(6, '0'))
    try:
        return datetime(int(year), month, int(day), int(hh), int(mm), int(ss), micro, tzinfo=tz)
    except ValueError:
        return None


def parse_passenger_ts(raw: str, tz):
    """Parse a Passenger timestamp. Like the Apache error log, it carries no offset."""
    m = PASSENGER_TS_RE.match(raw.strip())
    if not m:
        return None
    year, month, day, hh, mm, ss, frac = m.groups()
    micro = int((frac or '0')[:6].ljust(6, '0'))
    try:
        return datetime(int(year), int(month), int(day),
                        int(hh), int(mm), int(ss), micro, tzinfo=tz)
    except ValueError:
        return None


def to_ns(dt: datetime) -> int:
    return int(dt.timestamp() * 1_000_000_000)


def parse_access_line(line: str):
    """-> (datetime|None, labels, structured_metadata). None datetime = unparsed."""
    for regex in ACCESS_FORMATS:
        m = regex.match(line)
        if m:
            break
    else:
        return None, {}, {}
    g = m.groupdict()

    labels = {}
    meta = {}

    # Only %v -- the vhost Apache itself resolved the request to -- outranks the
    # one derived from the file name. A `%{Host}i` header does NOT: it is client
    # input, and trusting it would merge fairdomhub-55555 into fairdomhub.
    if g.get('vhost'):
        labels['vhost'] = g['vhost']
    if g.get('port'):
        meta['port'] = g['port']

    rq = REQUEST_RE.match(g.get('request') or '')
    if rq:
        method = rq.group('method')
        path = rq.group('path') or ''
        # Only real HTTP verbs become a label; see HTTP_METHODS. Anything else
        # is a malformed request line, and its raw form is preserved as metadata
        # so nothing is lost from the log-details pane.
        if method:
            if method.upper() in HTTP_METHODS:
                labels['method'] = method.upper()
            else:
                labels['method'] = 'OTHER'
                meta['method_raw'] = method
        if path:
            meta['path'] = path
            meta['path_base'] = path.split('?', 1)[0]
        if rq.group('protocol'):
            meta['protocol'] = rq.group('protocol')

    if g.get('status'):
        labels['status'] = g['status']

    for key in ('remote_addr', 'remote_user', 'referer', 'user_agent', 'bytes'):
        if g.get(key):
            meta[key] = g[key]

    # Format-dependent extras: `duration_us`/`vhost_hdr` come from the extended
    # LogFormat (%D %{Host}i), the rest only from the proxied one. Absent groups
    # are skipped rather than stored empty, which keeps Grafana's log-details
    # pane free of blank rows on the formats that don't carry them.
    for key in ('duration_us', 'vhost_hdr', 'forwarded_for',
                'accept', 'accept_encoding'):
        if g.get(key):
            meta[key] = g[key].strip(', ') if key == 'forwarded_for' else g[key]

    return parse_access_ts(g['ts']), labels, meta


def parse_error_line(line: str, tz):
    """Parse an error-log line, whichever of the three shapes it is.

    A server-wide error log interleaves Apache's own entries with Phusion
    Passenger's and with whatever the application printed, so the shape is
    decided per line. Passenger and app lines come back carrying
    log_type="passenger", which overrides the file-derived value in
    process_file() and keeps them out of the dashboard's Apache error panel.
    """
    m = ERROR_RE.match(line)
    if m:
        g = m.groupdict()
        labels = {}
        meta = {}
        if g.get('level'):
            labels['level'] = g['level']
        if g.get('module'):
            labels['module'] = g['module']
        for key in ('client', 'pid'):
            if g.get(key):
                meta[key] = g[key]
        return parse_error_ts(g['ts'], tz), labels, meta

    m = PASSENGER_RE.match(line)
    if m:
        g = m.groupdict()
        labels = {'log_type': 'passenger'}
        # Map N/W/E/... onto the same words Apache uses, so `level` means one
        # thing across both sources and a single dashboard filter covers them.
        level = PASSENGER_LEVELS.get((g.get('level') or '').upper())
        if level:
            labels['level'] = level
        meta = {}
        for key in ('pid', 'tid', 'src'):
            if g.get(key):
                meta[key] = g[key]
        return parse_passenger_ts(g['ts'], tz), labels, meta

    m = APP_RE.match(line)
    if m:
        g = m.groupdict()
        # No timestamp of its own -- process_file() inherits the previous
        # entry's, which is the closest truth available and keeps the line
        # adjacent to the Passenger entry that produced it.
        return None, {'log_type': 'passenger'}, {
            'pid': g['pid'], 'channel': g['channel'],
        }

    return None, {}, {}


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def rotation_index(path: Path, base: str):
    """N from access.log.N or access.log.N.gz, else None."""
    m = re.match(rf'^{re.escape(base)}\.(\d+)(\.gz)?$', path.name)
    return int(m.group(1)) if m else None


def is_dateext_archive(path: Path, base: str) -> bool:
    """logrotate `dateext` naming: access_log-20250101 / access_log-20250101.gz."""
    return bool(re.match(rf'^{re.escape(base)}[-.]\d{{6,8}}(\.gz)?$', path.name))


def discover(log_dir: Path, base: str, include_live: bool):
    """(archives oldest-first, skipped names) for `base`.

    Recognised, matching how logrotate names things:
        base.N        base.N.gz       numeric rotation (N counts UP with age)
        base.gz                       compressed with no index
        base-YYYYMMDD base-YYYYMMDD.gz   dateext rotation

    Anything else starting with `base` is deliberately IGNORED and reported, so
    strays like `access.log.test` or a stray `logs-md5.txt` never get imported
    as if they were log archives.

    Numeric archives come first, oldest (highest index) to newest; dateext ones
    follow, ordered by mtime. Ordering is cosmetic: every line carries its own
    timestamp and entries are sorted per stream before pushing.
    """
    if not log_dir.is_dir():
        return [], []

    numbered: list[tuple[int, Path]] = []
    dated: list[tuple[float, Path]] = []
    live: list[Path] = []
    skipped: list[str] = []

    for p in sorted(log_dir.iterdir()):
        if not p.is_file() or not p.name.startswith(base):
            continue
        if p.name == base:
            if include_live:      # normally Alloy's job
                live.append(p)
            continue
        idx = rotation_index(p, base)
        if idx is not None:
            numbered.append((idx, p))
        elif p.name == base + '.gz' or is_dateext_archive(p, base):
            try:
                dated.append((p.stat().st_mtime, p))
            except OSError:
                skipped.append(p.name)
        else:
            skipped.append(p.name)

    numbered.sort(key=lambda t: -t[0])   # highest index = oldest = first
    dated.sort(key=lambda t: t[0])
    return [p for _, p in numbered] + [p for _, p in dated] + live, skipped


ACCESS_HINT = re.compile(r'access[_.-]?log$|access\.log$|^access\.log$')
ERROR_HINT = re.compile(r'error[_.-]?log$|error\.log$|^error\.log$')


def discover_bases(log_dir: Path):
    """Find every Apache access/error log base name in a directory.

    Multi-vhost servers keep one pair of logs per site (fairdomhub-access.log,
    jjj_access.log, other_vhosts_access.log, ...). Returns
    [(kind, base), ...] so all of them can be imported in one run.
    """
    bases: set[tuple[str, str]] = set()
    for p in sorted(log_dir.iterdir()):
        if not p.is_file():
            continue
        # Strip a rotation suffix to recover the logical base name.
        name = re.sub(r'\.gz$', '', p.name)
        name = re.sub(r'[-.]\d+$', '', name)
        if not name.endswith('.log') and not name.endswith('_log'):
            continue
        stem = name[:-4] if name.endswith('.log') else name[:-4]
        if ACCESS_HINT.search(name) or 'access' in stem:
            bases.add(('access', name))
        elif ERROR_HINT.search(name) or 'error' in stem:
            bases.add(('error', name))
    # access logs first, then error logs; alphabetical within each
    return sorted(bases, key=lambda t: (t[0] != 'access', t[1]))


def vhost_from_base(base: str) -> str:
    """fairdomhub-access.log -> fairdomhub, jjj_access.log -> jjj, access.log -> default."""
    stem = re.sub(r'\.(log)$', '', base)
    stem = re.sub(r'[-_]?(access|error)$', '', stem)
    stem = stem.strip('-_.')
    return stem or 'default'


def open_log(path: Path):
    """Text handle for a plain or gzipped log. Bad bytes are replaced, not fatal."""
    if path.suffix == '.gz':
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'rt', encoding='utf-8', errors='replace')


# --------------------------------------------------------------------------
# Pushing
# --------------------------------------------------------------------------

class LokiPusher:
    # Loki's internal gRPC receive limit is 4 MiB by default, and a push larger
    # than that fails with HTTP 500 "ResourceExhausted: received message larger
    # than max". Batches are therefore capped by BYTES as well as entry count --
    # entry count alone is not a safe proxy, because log line lengths vary
    # hugely (a 5000-entry batch of long URLs reached 4.7 MB).
    DEFAULT_MAX_BYTES = 3_000_000

    def __init__(self, url: str, batch_size: int, dry_run: bool, verbose: bool,
                 max_bytes: int = DEFAULT_MAX_BYTES):
        self.url = url.rstrip('/') + '/loki/api/v1/push'
        self.batch_size = batch_size
        self.max_bytes = max_bytes
        self.dry_run = dry_run
        self.verbose = verbose
        self.streams: dict[tuple, list] = defaultdict(list)
        self.pending = 0
        self.pending_bytes = 0
        self.pushed = 0
        self.batches = 0
        self.throttled = 0
        self.split = 0
        self.rejected_ooo = 0

    def add(self, labels: dict, ts_ns: int, line: str, meta: dict):
        key = tuple(sorted(labels.items()))
        self.streams[key].append((ts_ns, line, meta))
        self.pending += 1
        # Rough JSON cost: the line, the metadata values, plus framing overhead.
        self.pending_bytes += (len(line) + 40
                               + sum(len(k) + len(v) + 6 for k, v in meta.items()))
        if self.pending >= self.batch_size or self.pending_bytes >= self.max_bytes:
            self.flush()

    def flush(self):
        if not self.pending:
            return
        payload = {'streams': []}
        for key, entries in self.streams.items():
            # Ascending timestamps within a stream: Loki's preferred shape.
            entries.sort(key=lambda e: e[0])
            values = []
            for ts_ns, line, meta in entries:
                if meta:
                    values.append([str(ts_ns), line, meta])
                else:
                    values.append([str(ts_ns), line])
            payload['streams'].append({'stream': dict(key), 'values': values})

        count = self.pending
        self.streams.clear()
        self.pending = 0
        self.pending_bytes = 0

        if self.dry_run:
            self.pushed += count
            self.batches += 1
            return

        self._send(payload, count)
        self.pushed += count
        self.batches += 1
        if self.verbose:
            print(f'    pushed batch of {count} entries')

    @staticmethod
    def _halve(payload: dict):
        """Split a push payload into two, by entries, preserving stream labels."""
        a, b = [], []
        for s in payload['streams']:
            vals = s['values']
            if len(vals) == 1:
                a.append(s)
                continue
            mid = len(vals) // 2
            a.append({'stream': s['stream'], 'values': vals[:mid]})
            b.append({'stream': s['stream'], 'values': vals[mid:]})
        return {'streams': a}, {'streams': b}

    def _send(self, payload: dict, count: int, depth: int = 0):
        """Push, halving the payload if Loki says the message is too large.

        Belt-and-braces behind the byte cap in add(): metadata-heavy lines can
        still push a batch over the gRPC limit, and silently losing them would
        be worse than an extra round trip.
        """
        try:
            self._post(payload, count)
        except _TooLarge:
            if depth >= 6 or count <= 1:
                die(f'a single entry exceeds Loki\'s message size limit; '
                    f'raise server.grpc_server_max_recv_msg_size in loki/config.yml')
            first, second = self._halve(payload)
            self.split += 1
            if self.verbose:
                print(f'    batch too large, splitting ({count} entries)')
            n1 = sum(len(s['values']) for s in first['streams'])
            self._send(first, n1, depth + 1)
            n2 = sum(len(s['values']) for s in second['streams'])
            if n2:
                self._send(second, n2, depth + 1)

    MAX_ATTEMPTS = 8

    def _post(self, payload: dict, count: int):
        body = gzip.compress(json.dumps(payload).encode('utf-8'))
        last_err = None
        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            req = urllib.request.Request(
                self.url,
                data=body,
                headers={
                    'Content-Type': 'application/json',
                    'Content-Encoding': 'gzip',
                    'User-Agent': 'apache-log-importer/1.0',
                },
                method='POST',
            )
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    if 200 <= resp.status < 300:
                        return
                    last_err = f'HTTP {resp.status}'
            except urllib.error.HTTPError as e:
                detail = e.read().decode('utf-8', 'replace').strip()
                if e.code == 429:
                    # Rate limited, NOT a rejection: bulk imports routinely trip
                    # Loki's ingestion_rate_mb / per_stream_rate_limit. Back off
                    # and retry, honouring Retry-After when Loki sends it.
                    self.throttled += 1
                    wait = float(e.headers.get('Retry-After') or 0) or min(2 ** attempt, 30)
                    if self.verbose:
                        print(f'    rate limited, retrying in {wait:.0f}s')
                    time.sleep(wait)
                    last_err = f'HTTP 429: {detail}'
                    continue
                if 'larger than max' in detail or 'ResourceExhausted' in detail:
                    # Oversized payload: permanent for THIS batch, but fixable by
                    # splitting it. Raised so _send can halve and retry -- eight
                    # blind retries of the same too-big body just waste minutes.
                    raise _TooLarge from None
                if e.code == 400 and ('too far behind' in detail
                                      or 'ignored, reason' in detail):
                    # PARTIAL rejection: Loki accepted the rest of the batch and
                    # dropped only the entries outside its out-of-order window.
                    # Counting and continuing beats aborting a multi-million-line
                    # import over a handful of stale lines. Widen the window with
                    # ingester.max_chunk_age if this number is large.
                    m = re.search(r'total ignored: (\d+)', detail)
                    self.rejected_ooo += int(m.group(1)) if m else 1
                    if self.verbose:
                        print(f'    some entries outside the out-of-order window: '
                              f'{detail[:160]}')
                    return
                if 400 <= e.code < 500:
                    # A genuine rejection (bad labels, malformed entry, ...).
                    # Retrying the same payload cannot help; the body says why.
                    die(f'Loki rejected the push (HTTP {e.code}): {detail}\n'
                        f'       {count} entries in this batch were not imported.')
                last_err = f'HTTP {e.code}: {detail}'
            except (urllib.error.URLError, OSError) as e:
                last_err = str(e)
            if attempt < self.MAX_ATTEMPTS:
                time.sleep(min(2 ** attempt, 30))
        die(f'giving up after {self.MAX_ATTEMPTS} attempts pushing to {self.url}: {last_err}')


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def die(msg: str):
    print(f'error: {msg}', file=sys.stderr)
    sys.exit(1)


def load_env(path: Path) -> dict:
    """Read simple KEY=value pairs from .env without executing it."""
    out = {}
    if not path.is_file():
        return out
    for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
        raw = raw.strip()
        if not raw or raw.startswith('#') or '=' not in raw:
            continue
        k, v = raw.split('=', 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def resolve_tz(name: str):
    if not name or name.upper() == 'UTC':
        return timezone.utc
    if ZoneInfo is None:
        print(f'warning: zoneinfo unavailable, treating error-log times as UTC '
              f'instead of {name}', file=sys.stderr)
        return timezone.utc
    try:
        return ZoneInfo(name)
    except Exception:
        print(f'warning: unknown timezone {name!r}, treating error-log times as UTC. '
              f'Error entries may be offset by an hour or two.', file=sys.stderr)
        return timezone.utc


def human(n: int) -> str:
    return f'{n:,}'.replace(',', ' ')


def flush_ingester(loki_url: str) -> bool:
    """Ask Loki to write its in-memory chunks out to the store.

    Essential after importing history. Loki's querier only consults ingesters
    for timestamps within `query_ingesters_within` (3h by default) and expects
    anything older to come from the store. Freshly pushed 2023 entries are still
    in an in-memory chunk, so they are in neither place and queries return
    nothing -- until a flush happens, either on the chunk_idle_period timer or
    because we ask for it here.
    """
    req = urllib.request.Request(
        loki_url.rstrip('/') + '/flush', data=b'', method='POST')
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return 200 <= resp.status < 300
    except Exception:  # noqa: BLE001 - best effort; verification still polls
        return False


def verify_range(loki_url: str, log_type: str, host: str, first: datetime, last: datetime):
    """Query back what Loki actually stored for the imported span.

    Worth doing on every run: Loki answers a push with HTTP 204 even when the
    timestamp falls before schema_config's first `from` date, and the data is
    then unqueryable. Without reading it back, that looks like a clean import.
    Returns the entry count Loki reports, or None if the query failed.
    """
    span = max(int((last - first).total_seconds()) + 120, 120)
    query = (f'sum(count_over_time({{job="apache", log_type="{log_type}", '
             f'host="{host}"}}[{span}s]))')
    params = urllib.parse.urlencode({
        'query': query,
        'time': str(to_ns(last + timedelta(seconds=60))),
    })
    url = f"{loki_url.rstrip('/')}/loki/api/v1/query?{params}"
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace').strip()
        print(f'  warning: verification query failed (HTTP {e.code}): {detail}',
              file=sys.stderr)
        return None
    except Exception as e:  # noqa: BLE001 - verification must never mask the import
        print(f'  warning: verification query failed: {e}', file=sys.stderr)
        return None
    result = data.get('data', {}).get('result', [])
    if not result:
        return 0
    try:
        return int(float(result[0]['value'][1]))
    except (KeyError, IndexError, ValueError):
        return None


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def process_file(path: Path, kind: str, base_labels: dict, tz, pusher: LokiPusher,
                 since, until, verbose: bool) -> dict:
    """Parse one archive and hand its entries to the pusher."""
    stats = {'lines': 0, 'imported': 0, 'unparsed': 0, 'skipped_range': 0,
             'first': None, 'last': None}

    # Fallback for lines whose timestamp can't be read (e.g. Apache's AH00558
    # startup warning, which it writes before logging is configured and so has
    # no "[...]" prefix). Alloy assigns the previous entry's timestamp; do the
    # same, seeding from the file's mtime so the first such line isn't stranded.
    try:
        last_dt = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        last_dt = datetime.now(timezone.utc)

    # `filename` is the LOGICAL log name, not the archive name, so all 28 error
    # archives share streams instead of multiplying them by 28. Per-line
    # provenance lives in the `archive` structured metadata field below, which
    # costs no cardinality and is still queryable (`| archive = "error.log.3.gz"`).
    labels = dict(base_labels)

    try:
        handle = open_log(path)
    except PermissionError:
        print(f'  {path.name}: NOT READABLE by {os.getenv("USER", "this user")} '
              f'-- re-run with sudo -E to include it', file=sys.stderr)
        stats['unreadable'] = True
        return stats
    except OSError as e:
        print(f'  {path.name}: cannot open ({e})', file=sys.stderr)
        stats['unreadable'] = True
        return stats

    with handle:
        for raw in handle:
            line = raw.rstrip('\n').rstrip('\r')
            if not line.strip():
                continue
            stats['lines'] += 1

            if kind == 'access':
                dt, extra, meta = parse_access_line(line)
            else:
                dt, extra, meta = parse_error_line(line, tz)

            if dt is None:
                stats['unparsed'] += 1
                dt = last_dt
            else:
                last_dt = dt

            if since and dt < since:
                stats['skipped_range'] += 1
                continue
            if until and dt >= until:
                stats['skipped_range'] += 1
                continue

            if stats['first'] is None or dt < stats['first']:
                stats['first'] = dt
            if stats['last'] is None or dt > stats['last']:
                stats['last'] = dt

            meta['archive'] = path.name
            pusher.add({**labels, **extra}, to_ns(dt), line, meta)
            stats['imported'] += 1

            # Multi-million-line archives exist; don't go silent for minutes.
            if verbose and stats['imported'] % 100_000 == 0:
                print(f"    {path.name}: {human(stats['imported'])} entries so far")

    return stats


def main():
    env = load_env(ROOT / '.env')

    default_url = f"http://{env.get('BIND_ADDR', '127.0.0.1')}:{env.get('LOKI_PORT', '3100')}"
    if env.get('BIND_ADDR') == '0.0.0.0':
        default_url = f"http://127.0.0.1:{env.get('LOKI_PORT', '3100')}"

    p = argparse.ArgumentParser(
        description='Import rotated Apache logs into Loki so Grafana can show them.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Defaults are read from .env in the project root.',
    )
    p.add_argument('--log-dir', default=env.get('APACHE_LOG_DIR', '/var/log/apache2'),
                   help='directory holding the Apache logs (default: %(default)s)')
    p.add_argument('--access-log', action='append', metavar='NAME',
                   help='access log base name; repeatable. '
                        f"(default: {env.get('APACHE_ACCESS_LOG', 'access.log')})")
    p.add_argument('--error-log', action='append', metavar='NAME',
                   help='error log base name; repeatable. '
                        f"(default: {env.get('APACHE_ERROR_LOG', 'error.log')})")
    p.add_argument('--discover', action='store_true',
                   help='import EVERY access/error log found in the directory, one '
                        'per vhost (fairdomhub-access.log, jjj_access.log, ...), '
                        'labelling each with its vhost')
    p.add_argument('--exclude', action='append', default=[], metavar='BASE',
                   help='skip this log base name; repeatable. Exact match, so '
                        '`--exclude error.log` drops the server-wide log without '
                        'touching fairdomhub-error.log. Useful with --discover to '
                        'leave out a family that dwarfs the rest')
    p.add_argument('--loki-url', default=os.getenv('LOKI_URL', default_url),
                   help='Loki base URL (default: %(default)s)')
    p.add_argument('--host', default=env.get('APACHE_HOST') or os.uname().nodename,
                   help='value for the `host` label (default: %(default)s)')
    p.add_argument('--tz', default=env.get('APACHE_TZ', 'UTC'),
                   help='timezone of error-log timestamps (default: %(default)s)')
    p.add_argument('--only', choices=('access', 'error', 'both'), default='both',
                   help='which logs to import (default: %(default)s)')
    p.add_argument('--include-live', action='store_true',
                   help='also import the current, un-rotated log (normally Alloy tails it)')
    p.add_argument('--since', metavar='YYYY-MM-DD', help='skip entries before this date')
    p.add_argument('--until', metavar='YYYY-MM-DD', help='skip entries from this date on')
    p.add_argument('--batch-size', type=int, default=5000, metavar='N',
                   help='entries per push request. Larger means fewer round trips '
                        'on big imports (default: %(default)s)')
    p.add_argument('--list', action='store_true',
                   help='list the files that would be imported, in order, then exit')
    p.add_argument('--dry-run', action='store_true',
                   help='parse and report, push nothing')
    p.add_argument('--max-batch-bytes', type=int, metavar='N',
                   default=LokiPusher.DEFAULT_MAX_BYTES,
                   help='flush a batch once it reaches this many bytes, to stay '
                        "under Loki's 4 MiB gRPC limit (default: %(default)s)")
    p.add_argument('--no-verify', action='store_true',
                   help='skip reading the data back from Loki after importing')
    p.add_argument('-v', '--verbose', action='store_true', help='per-batch detail')
    args = p.parse_args()

    log_dir = Path(args.log_dir).expanduser()
    if not log_dir.is_dir():
        die(f'log directory {log_dir} does not exist (set APACHE_LOG_DIR in .env '
            f'or pass --log-dir)')

    if args.discover:
        kinds = discover_bases(log_dir)
        if not kinds:
            die(f'no Apache access/error logs found in {log_dir}')
    else:
        kinds = []
        for base in (args.access_log or [env.get('APACHE_ACCESS_LOG', 'access.log')]):
            kinds.append(('access', base))
        for base in (args.error_log or [env.get('APACHE_ERROR_LOG', 'error.log')]):
            kinds.append(('error', base))

    kinds = [(k, b) for k, b in kinds
             if args.only == 'both' or k == args.only]

    if args.exclude:
        # Report names that matched nothing: a typo'd --exclude would otherwise
        # silently import the very family it was meant to leave out.
        unmatched = set(args.exclude) - {b for _, b in kinds}
        if unmatched:
            print(f'warning: --exclude matched no log base: '
                  f'{", ".join(sorted(unmatched))}', file=sys.stderr)
        dropped = sorted(b for _, b in kinds if b in set(args.exclude))
        kinds = [(k, b) for k, b in kinds if b not in set(args.exclude)]
        if dropped:
            print(f'Excluding: {", ".join(dropped)}\n')
        if not kinds:
            die('every log base was excluded; nothing left to import')

    targets = []
    all_skipped: list[str] = []
    for kind, base in kinds:
        files, skipped = discover(log_dir, base, args.include_live)
        all_skipped.extend(skipped)
        targets.append((kind, base, vhost_from_base(base), files))

    if args.list:
        for kind, base, vhost, files in targets:
            print(f'{kind} ({base}, vhost={vhost}) -- {len(files)} file(s), oldest first:')
            total = 0
            for f in files:
                try:
                    size = f.stat().st_size
                except OSError:
                    size = 0
                total += size
                print(f'  {f.name:<40} {human(size):>14} bytes')
            if not files:
                print('  (none found)')
            else:
                print(f'  {"":<40} {human(total):>14} bytes total')
        if all_skipped:
            print(f'\nIgnored (not a recognised rotation name): '
                  f'{", ".join(sorted(set(all_skipped)))}')
        return

    if not any(files for _, _, _, files in targets):
        print(f'Nothing to import: no rotated archives found in {log_dir}')
        bases = ', '.join(b for _, b in kinds)
        print(f'Looked for {bases} with a .N, .N.gz or -YYYYMMDD suffix.')
        print('Tip: --discover finds every access/error log in the directory, '
              'and --list shows what matched.')
        return

    if all_skipped:
        print(f'Ignoring (not a recognised rotation name): '
              f'{", ".join(sorted(set(all_skipped)))}\n')

    # `backfill/` is where the server's archives are kept for this importer to
    # read; Alloy does not mount it and no longer tails anything from it, so
    # finding logs there is the normal case, not a double-import risk. The guard
    # that used to live here refused to run whenever backfill/*.log was
    # non-empty, which -- once the directory became the source rather than a
    # staging area -- meant refusing to run at all.

    tz = resolve_tz(args.tz)

    since = until = None
    try:
        if args.since:
            since = datetime.strptime(args.since, '%Y-%m-%d').replace(tzinfo=tz)
        if args.until:
            until = datetime.strptime(args.until, '%Y-%m-%d').replace(tzinfo=tz)
    except ValueError as e:
        die(f'bad date: {e}')

    pusher = LokiPusher(args.loki_url, args.batch_size, args.dry_run, args.verbose,
                        max_bytes=args.max_batch_bytes)

    print(f'Importing from {log_dir}')
    print(f'  target      {args.loki_url}' + ('  (DRY RUN, nothing sent)' if args.dry_run else ''))
    print(f'  host label  {args.host}')
    print(f'  error tz    {args.tz}')
    print()

    totals = {'lines': 0, 'imported': 0, 'unparsed': 0, 'skipped_range': 0,
              'files': 0, 'unreadable': 0}
    span_first = span_last = None
    per_kind: dict[str, list] = {}

    for kind, base, vhost, files in targets:
        if not files:
            continue
        kind_first = kind_last = None
        kind_count = 0
        print(f'{kind} ({base}, vhost={vhost}): {len(files)} archive(s)')
        # vhost from the file name; a %v on the line itself overrides it.
        base_labels = {'job': 'apache', 'host': args.host, 'log_type': kind,
                       'vhost': vhost}
        for f in files:
            st = process_file(f, kind, base_labels, tz, pusher, since, until, args.verbose)
            if st.get('unreadable'):
                totals['unreadable'] += 1
                continue
            totals['files'] += 1
            for k in ('lines', 'imported', 'unparsed', 'skipped_range'):
                totals[k] += st[k]
            if st['first'] and (span_first is None or st['first'] < span_first):
                span_first = st['first']
            if st['last'] and (span_last is None or st['last'] > span_last):
                span_last = st['last']
            if st['first'] and (kind_first is None or st['first'] < kind_first):
                kind_first = st['first']
            if st['last'] and (kind_last is None or st['last'] > kind_last):
                kind_last = st['last']
            kind_count += st['imported']

            note = ''
            if st['unparsed']:
                note += f", {st['unparsed']} unparsed"
            if st['skipped_range']:
                note += f", {st['skipped_range']} outside date range"
            print(f"  {f.name:<40} {human(st['imported']):>8} entries{note}")

        if kind_first and kind_last:
            prev = per_kind.get(kind)
            if prev:
                prev[0] = min(prev[0], kind_first)
                prev[1] = max(prev[1], kind_last)
                prev[2] += kind_count
            else:
                per_kind[kind] = [kind_first, kind_last, kind_count]

    pusher.flush()

    print()
    print(f"Files read        {totals['files']}"
          + (f" ({totals['unreadable']} unreadable)" if totals['unreadable'] else ''))
    print(f"Lines read        {human(totals['lines'])}")
    print(f"Entries imported  {human(pusher.pushed)} in {pusher.batches} batch(es)")
    if totals['unparsed']:
        print(f"Unparsed lines    {human(totals['unparsed'])} "
              f"(stored verbatim, timestamp inherited from the previous line)")
    if totals['skipped_range']:
        print(f"Skipped by date   {human(totals['skipped_range'])}")
    if span_first and span_last:
        print(f"Time span         {span_first.isoformat()}  ->  {span_last.isoformat()}")

    if pusher.throttled:
        print(f"Rate limited      {pusher.throttled} time(s), retried with backoff")
    if pusher.split:
        print(f"Batches split     {pusher.split} (exceeded Loki's message size limit)")
    if pusher.rejected_ooo:
        print(f"Dropped by Loki   {human(pusher.rejected_ooo)} entries outside its "
              f"out-of-order window\n"
              f"                  (raise ingester.max_chunk_age in loki/config.yml "
              f"to widen it)")

    if args.dry_run:
        print('\nDry run: nothing was sent to Loki.')
        return

    if not pusher.pushed:
        return

    ok = True
    if not args.no_verify:
        print('\nVerifying (reading back from Loki)')
        if flush_ingester(args.loki_url):
            print('  flushed ingester chunks to the store')
        else:
            print('  warning: could not force a flush; imported history may take '
                  'a few minutes to become queryable')
        for kind, (first, last, count) in per_kind.items():
            # Poll: the flush is asynchronous, so give it time to land.
            found = None
            for _ in range(12):
                found = verify_range(args.loki_url, kind, args.host, first, last)
                if found:
                    break
                time.sleep(5)
            if found is None:
                print(f'  {kind:<8} could not verify')
                continue
            if found == 0 and count > 0:
                ok = False
                print(f'  {kind:<8} 0 of {human(count)} entries found -- NOT STORED')
            elif found < count * 0.5:
                ok = False
                print(f'  {kind:<8} only {human(found)} of {human(count)} entries found')
            else:
                # Exact equality isn't expected: Loki drops byte-identical lines
                # that share a one-second Apache timestamp.
                print(f'  {kind:<8} {human(found)} entries queryable '
                      f'(pushed {human(count)}; identical same-second lines dedup)')

    if not ok:
        print('\nSome entries are not queryable. Two causes, both silent because '
              'Loki answers')
        print('the push with HTTP 204 either way:')
        print('  1. schema_config.from in loki/config.yml is LATER than the oldest')
        print('     imported timestamp, so no index period covers it. Set an '
              'earlier date,')
        print('     restart Loki, re-run this import.')
        print('  2. The chunks have not reached the store yet. Retry the '
              'verification with')
        print(f'     curl -XPOST {args.loki_url.rstrip("/")}/flush and query again.')
        sys.exit(1)

    print('\nDone. In Grafana, widen the dashboard time range to cover the span above.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\ninterrupted', file=sys.stderr)
        sys.exit(130)
