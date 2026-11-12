#!/usr/bin/env python3
"""Bounded load test for the storage, graph and report pipeline.

The test builds a synthetic investigation directly through the repository (no
network, no providers), then measures graph reads, report data assembly and
every renderer. It is deliberately capped and disposable: everything lives in a
temporary directory that is removed on exit.

Usage:
    python scripts/loadtest.py --nodes 600
    python scripts/loadtest.py --nodes 600 --json
"""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from phishtrace.config import Config
from phishtrace.reports import SUPPORTED_FORMATS, build_report_data, render_report
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository


def timed(label: str, fn):
    started = time.perf_counter()
    value = fn()
    return label, (time.perf_counter() - started) * 1000.0, value


def build_graph(repo: Repository, investigation_id: str, nodes: int, fanout: int) -> list[dict]:
    """Create ``nodes`` indicators shaped like a pivoted phishing investigation."""
    created: list[dict] = []
    seed, _ = repo.ensure_indicator(
        investigation_id,
        type="domain",
        value="login.evil-example.test",
        normalized_value="login.evil-example.test",
        depth=0,
        path_confidence=1.0,
        tags=["seed"],
    )
    seed_id = seed["id"]
    created.append(seed)
    providers = ("crt_sh", "urlscan", "dns_intel", "virustotal", "urlhaus", "whoisxml")
    for index in range(1, nodes):
        depth = 1 + (index % 3)
        child, _ = repo.ensure_indicator(
            investigation_id,
            type="domain" if index % 3 else "ip",
            value=f"node{index:04d}.evil-example.test" if index % 3 else f"10.{index // 250}.{index % 250}.7",
            normalized_value=f"node{index:04d}.evil-example.test" if index % 3 else f"10.{index // 250}.{index % 250}.7",
            depth=depth,
            path_confidence=round(0.35 + (index % 60) / 100.0, 2),
            parent_id=seed_id if index <= fanout or len(created) < 2 else created[1 + (index % (len(created) - 1))]["id"],
            tags=["passive"] if index % 2 else ["pivot"],
        )
        created.append(child)
        repo.add_edge(
            investigation_id,
            src_id=seed_id,
            dst_id=child["id"],
            relation="resolves_to" if child["type"] == "ip" else "related_domain",
            provider=providers[index % len(providers)],
            confidence=0.4 + (index % 5) / 10.0,
            selector_strength="medium",
        )
        if index > fanout and index % 2 == 0:
            parent = created[(index // 2) % len(created)]
            repo.add_edge(
                investigation_id,
                src_id=parent["id"],
                dst_id=child["id"],
                relation="shares_certificate",
                provider=providers[(index + 2) % len(providers)],
                confidence=0.55,
                selector_strength="weak",
            )
    return created


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=int, default=600, help="indicators to create (default 600, hard cap 5000)")
    parser.add_argument("--fanout", type=int, default=40, help="direct children of the seed")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args()
    nodes = max(10, min(5000, args.nodes))

    with tempfile.TemporaryDirectory(prefix="phishtrace-loadtest-") as tmp:
        config = Config(host="127.0.0.1", data_dir=Path(tmp) / "data", providers={})
        config.data_dir.mkdir(parents=True)
        _, factory = init_db(config.sqlalchemy_url, config.data_dir)
        repo = Repository(factory, EvidenceStore(config.evidence_dir))
        investigation = repo.create_investigation(
            seed="login.evil-example.test",
            seed_type="domain",
            seed_normalized="login.evil-example.test",
            config_snapshot=config.redacted(),
            owner="loadtest",
        )
        investigation_id = investigation["id"]

        _, ingest_ms, _ = timed("ingest", lambda: build_graph(repo, investigation_id, nodes, args.fanout))
        repo.finalize(
            investigation_id,
            status="completed",
            coverage={"providers_run": 6, "skipped": {}},
            stats={"nodes": nodes},
            summary={"verdict": "synthetic load test"},
        )

        _, graph_ms, graph = timed("graph_read", lambda: repo.graph(investigation_id))
        tracemalloc.start()
        _, data_ms, data = timed(
            "report_data",
            lambda: build_report_data(repo, investigation_id, settings=config.reports, default_region="US"),
        )
        renders: dict[str, dict] = {}
        for fmt in SUPPORTED_FORMATS:
            _, render_ms, content = timed(f"render_{fmt}", lambda fmt=fmt: render_report(data, fmt))
            renders[fmt] = {"ms": round(render_ms, 2), "bytes": len(content)}
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    result = {
        "nodes_requested": nodes,
        "nodes_loaded": len(graph.get("nodes") or []),
        "edges_loaded": len(graph.get("edges") or []),
        "ingest_ms": round(ingest_ms, 1),
        "graph_read_ms": round(graph_ms, 1),
        "report_data_ms": round(data_ms, 1),
        "renders": {k: v for k, v in sorted(renders.items())},
        "slowest_render_ms": round(max(v["ms"] for v in renders.values()), 1),
        "median_render_ms": round(statistics.median(v["ms"] for v in renders.values()), 1),
        "peak_traced_mb": round(peak / (1024 * 1024), 2),
        "total_serialized_bytes": sum(v["bytes"] for v in renders.values()),
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"PhishTrace load test: {result['nodes_loaded']} nodes / {result['edges_loaded']} edges")
        print(f"  ingest (per-row writes) : {result['ingest_ms']:.1f} ms")
        print(f"  graph read              : {result['graph_read_ms']:.1f} ms")
        print(f"  report data assembly    : {result['report_data_ms']:.1f} ms")
        for fmt, timing in result["renders"].items():
            print(f"  render {fmt:<5}            : {timing['ms']:8.1f} ms  {timing['bytes'] / 1024:9.1f} KiB")
        print(f"  peak traced memory      : {result['peak_traced_mb']:.2f} MiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
