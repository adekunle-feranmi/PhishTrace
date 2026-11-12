# Performance

PhishTrace targets a single-team deployment: a few concurrent analysts, one
process, SQLite in WAL mode. This note records the measured cost of the local
pipeline so capacity assumptions are explicit. It is not a benchmark against
provider APIs or a browser rendering a very large graph.

## How the numbers were produced

`scripts/loadtest.py` creates a disposable investigation directly through the
repository (no providers, no network), then times graph reads, report data
assembly and every renderer:

```bash
python scripts/loadtest.py --nodes 600
python scripts/loadtest.py --nodes 600 --json
```

Environment: 4 vCPU, 4 GiB RAM, Debian 12 container, Python 3.14.6,
SQLAlchemy 2.x with SQLite WAL, local disk. Each render is measured once after
data assembly; timings are wall-clock and include template compilation on first
use. Peak memory is `tracemalloc` around data assembly plus all renders.

## Results

| Metric | 60 nodes / 68 edges | 600 nodes / 878 edges |
| --- | ---: | ---: |
| Ingest (per-row commits) | 104.6 ms | 1,114.4 ms |
| Graph read | 3.5 ms | 21.6 ms |
| Report data assembly | 44.3 ms | 116.6 ms |
| CSV render | 1.5 ms / 15.6 KB | 16.4 ms / 181.4 KiB |
| HTML render | 98.8 ms / 18.5 KB | 112.2 ms / 82.2 KB |
| JSON render | 3.4 ms / 75.0 KB | 32.9 ms / 731.8 KB |
| Markdown render | 81.3 ms / 7.9 KB | 97.6 ms / 39.4 KB |
| MISP render | 3.1 ms / 21.5 KB | 25.8 ms / 199.2 KB |
| PDF render | 668.4 ms / 23.4 KB | 656.7 ms / 23.4 KB |
| STIX render | 10.7 ms / 133.8 KB | 108.3 ms / 1,473.2 KB |
| TXT render | 0.3 ms / 3.6 KB | 0.3 ms / 3.4 KB |
| Peak traced memory | 9.1 MiB | 13.1 MiB |

All eight formats for 600 nodes total 2,799,648 bytes and about 1.05 seconds of
render time. PDF is the slowest renderer and is effectively flat between 60 and
600 nodes (~0.66 s), which is consistent with a fixed ReportLab setup cost.

Observed scaling is close to linear for graph reads and serialization. A
complete report bundle for 600 nodes renders in roughly one second of CPU after
data assembly, with a peak of about 13 MiB. Ingest is slower per row because
every indicator and edge commits in its own transaction; a 600-node synthetic
graph costs about 1.1 s, so the default 500-node cap keeps a live run well inside
the 900-second investigation timeout.

## Interpretation and limits

* The test writes through the same repository methods as the orchestrator, but
  it does not exercise provider HTTP calls, retries, DNS or the fetcher's
  isolated subprocess. Network latency usually dominates a real investigation.
* SQLite allows one writer. The web process and a CLI `run` share the database;
  WAL and a 30-second busy timeout avoid most contention, but do not point
  several web workers at the same file.
* The UI graph is rendered client-side. A 600-node graph is a practical upper
  bound for comfortable interaction; the default `limits.max_nodes` is 500.
* Evidence bodies, archived HTML and kit assets dominate disk usage, not the
  database. Size the data volume for the archive caps
  (`max_archive_snapshots`, `fetcher.max_total_bytes`) and the retention period.
* The harness is deliberately capped at 5,000 nodes and uses a temporary
  directory that is removed on exit; it is safe to run on a workstation.

## If you need more capacity

1. Keep one process and move the database to a host with faster fsync (or a
   dedicated SSD); most ingest time is commit latency.
2. Raise `limits.max_nodes` only after checking that the browser can render the
   resulting graph; reports and exports handle the larger set more gracefully
   than the interactive canvas.
3. Archive or purge old investigations before large imports; evidence files are
   the main consumer of disk and backup time.
4. For multi-user or multi-worker deployments, plan a migration to PostgreSQL
   and a shared throttle/session store; neither is implemented today.
