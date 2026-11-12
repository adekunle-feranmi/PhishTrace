"""PhishTrace command line interface."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys
from pathlib import Path

from phishtrace import __version__
from phishtrace.config import ConfigError, ensure_dirs, is_loopback_host, load_config
from phishtrace.core.registry import Registry
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository


def _bootstrap(config):
    ensure_dirs(config)
    engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))
    return repo


def cmd_create_admin(args) -> int:
    config = load_config(args.config, validate=False)
    repo = _bootstrap(config)
    username = args.username or input("Admin username: ").strip()
    password = os.environ.get("PHISHTRACE_ADMIN_PASSWORD") or getpass.getpass("Password (min 12 chars): ")
    if not os.environ.get("PHISHTRACE_ADMIN_PASSWORD"):
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("error: passwords do not match", file=sys.stderr)
            return 2
    from phishtrace.api.app import create_admin
    try:
        result = create_admin(config, repo, username, password)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{'Created' if result['created'] else 'Updated'} administrator {result['username']!r}.")
    if config.auth.enabled and not config.auth.session_secret:
        print("Set PHISHTRACE_SESSION_SECRET in .env before binding a non-loopback address.", file=sys.stderr)
    return 0


def cmd_serve(args) -> int:
    config = load_config(args.config)
    if args.host:
        config.host = args.host
    if args.port:
        config.port = int(args.port)
    if args.data_dir:
        config.data_dir = Path(args.data_dir)
    config.validate_bind()
    repo = _bootstrap(config)
    if config.auth.enabled and repo.count_users() == 0:
        print("WARNING: no users exist. Run 'phishtrace create-admin' or login will be impossible.", file=sys.stderr)
    import uvicorn
    from phishtrace.api.app import create_app
    app = create_app(config, repo=repo)
    print(f"PhishTrace {__version__} listening on http://{config.host}:{config.port} "
          f"(auth={'on' if config.auth.enabled else 'off'}, active_fetch={config.fetcher.active_fetch})")
    # Forwarded headers are honored only when the immediate peer is a trusted
    # proxy, so login throttling and audit logs see the real client behind
    # nginx. A direct client cannot spoof X-Forwarded-For. Override the list for
    # a proxy that connects from a container gateway address.
    trusted_proxies = os.environ.get("PHISHTRACE_TRUSTED_PROXIES", "127.0.0.1,::1")
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level=config.log_level.lower(),
        access_log=True,
        proxy_headers=True,
        forwarded_allow_ips=trusted_proxies,
        server_header=False,
    )
    return 0


def cmd_run(args) -> int:
    config = load_config(args.config, validate=False)
    if args.data_dir:
        config.data_dir = Path(args.data_dir)
    repo = _bootstrap(config)
    from phishtrace.core.orchestrator import InvestigationRunner

    progress = None
    if args.verbose:
        def progress(event: dict) -> None:
            if event.get("event") == "node.start":
                print(f"  [depth {event['depth']}] {event['type']}: {event['value']}", file=sys.stderr)
            elif event.get("event") == "provider.done" and event.get("error"):
                print(f"    ! {event['provider']}: {event['error']}", file=sys.stderr)

    runner = InvestigationRunner(config, repo, progress=progress)
    try:
        result = asyncio.run(runner.run_seed(
            args.seed,
            kind=args.type,
            reuse=not args.no_reuse,
            owner=args.owner,
            run_sightings=not args.no_sightings,
        ))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"investigation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    inv = result["investigation"]
    counts = result["counts"]
    print(f"Investigation : {inv['id']}" + (" (reused)" if result["reused"] else ""))
    print(f"Seed          : {inv['seed_type']} {inv['seed_normalized']}")
    print(f"Status        : {result['status']}")
    print(f"Indicators    : {counts['indicators']}")
    print(f"Edges         : {counts['edges']}")
    print(f"Events        : {counts['events']}")
    print(f"Sightings     : {counts['sightings']}")
    print(f"Evidence      : {counts['evidence']}")
    stats = result.get("stats") or {}
    if stats.get("truncated"):
        print(f"Truncated     : {stats['truncated']}")
    if stats.get("stoplist_hits"):
        print(f"Stop-list     : {stats['stoplist_hits']} context-only node(s)")
    timeline = (result.get("investigation") or {}).get("summary", {}).get("timeline") or {}
    if timeline.get("earliest_observed"):
        print(
            f"Earliest obs. : {timeline['earliest_observed']} "
            f"({timeline.get('earliest_stage') or 'unknown stage'}) - {timeline.get('earliest_label') or ''}".rstrip()
        )
    sightings_stage = (result.get("investigation") or {}).get("summary", {}).get("sightings") or {}
    if sightings_stage.get("collected"):
        kept = sightings_stage.get("stored", 0)
        capped = " (capped)" if sightings_stage.get("capped") else ""
        print(f"Social        : {kept}/{sightings_stage['collected']} collected kept{capped}")
    coverage = result.get("coverage") or {}
    print(f"Providers ran : {', '.join(coverage.get('ran') or []) or 'none'}")
    if result.get("failed"):
        print("Failed providers:")
        for item in result["failed"]:
            print(f"  - {item['provider']}: {item['reason']}")
    if result.get("skipped"):
        print("Skipped providers:")
        for item in result["skipped"]:
            print(f"  - {item['provider']}: {item['reason']}")
    if result.get("warnings"):
        print("Warnings:")
        for warning in result["warnings"][:15]:
            print(f"  - {warning}")
    print("Note          : all timestamps are 'earliest observed', not proof of first activity.")
    return 0


def cmd_doctor(args) -> int:
    config = load_config(args.config, validate=False)
    print(f"PhishTrace {__version__} doctor")
    print(f"  config        : {Path(args.config or 'config.yaml').resolve()}")
    print(f"  data dir      : {config.data_dir.resolve()}")
    print(f"  database      : {config.sqlalchemy_url}")
    print(f"  bind          : {config.host}:{config.port} ({'loopback' if is_loopback_host(config.host) else 'NETWORK'})")
    print(f"  auth          : {'enabled' if config.auth.enabled else 'DISABLED'}")
    print(f"  active fetch  : {config.fetcher.active_fetch}")
    try:
        config.validate_bind()
        print("  bind check    : OK")
    except ConfigError as exc:
        print(f"  bind check    : FAIL - {exc}")
    try:
        repo = _bootstrap(config)
        print(f"  db check      : OK ({repo.count_users()} user(s))")
        if config.auth.enabled and repo.count_users() == 0:
            print("  users         : none - run 'phishtrace create-admin'")
    except Exception as exc:  # noqa: BLE001
        print(f"  db check      : FAIL - {exc}")
        return 1
    registry = Registry(config)
    summary = registry.summary()
    print(f"  providers     : {summary['enabled']} enabled, {summary['skipped']} skipped, "
          f"{summary['failed']} failed, {summary['total']} total")
    for status in registry.statuses():
        marker = "OK " if status.status == "enabled" else "SKIP"
        reason = f" - {status.reason}" if status.reason else ""
        print(f"    [{marker}] {status.name:<22} {status.category:<14} {status.phase}{reason}")
    if registry.load_errors:
        print("  plugin errors :")
        for err in registry.load_errors:
            print(f"    ! {err.module}: {err.error}")
    missing = sorted({key for status in registry.statuses() for key in status.missing_keys})
    print(f"  API keys      : {len(missing)} missing/optional key name(s)")
    for key in missing:
        print(f"    - {key}")
    if args.validate:
        import asyncio
        from phishtrace.core.orchestrator import validate_provider_keys
        results = asyncio.run(validate_provider_keys(config, registry))
        for name, (ok, message) in results.items():
            print(f"    {'PASS' if ok else 'FAIL'} {name}: {message}")
    return 0


def cmd_providers(args) -> int:
    config = load_config(args.config, validate=False)
    registry = Registry(config)
    if args.json:
        print(json.dumps([s.model_dump() for s in registry.statuses()], indent=2))
        return 0
    print(f"{'NAME':<24}{'STATUS':<10}{'PHASE':<7}{'CATEGORY':<16}REASON")
    for status in registry.statuses():
        print(f"{status.name:<24}{status.status:<10}{status.phase:<7}{status.category:<16}{status.reason or ''}")
    return 0


def _investigation_id(repo, args) -> str:
    value = getattr(args, "investigation_id", None)
    if value:
        return value
    if getattr(args, "latest", False):
        rows = repo.list_investigations(limit=1)
        if rows:
            return rows[0]["id"]
    raise ValueError("no investigation id supplied (pass an id or --latest)")


def _format_list(values) -> list[str] | None:
    if not values:
        return None
    selected: list[str] = []
    for value in values:
        for item in str(value).split(","):
            item = item.strip()
            if item:
                selected.append(item)
    return selected or None


def cmd_report(args) -> int:
    config = load_config(args.config, validate=False)
    if args.data_dir:
        config.data_dir = Path(args.data_dir)
    repo = _bootstrap(config)
    from phishtrace.reports import ReportNotFound, write_report_bundle

    try:
        investigation_id = _investigation_id(repo, args)
        manifest = write_report_bundle(
            repo,
            investigation_id,
            settings=config.reports,
            output_dir=args.output_dir or config.report_dir,
            formats=_format_list(args.format),
            default_region=config.default_region,
        )
    except (ReportNotFound, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
        return 0
    print(f"Reports for {manifest['investigation_id']} -> {manifest['output_dir']}")
    for item in manifest.get("files") or []:
        print(f"  {item['format']:<6} {item['filename']}  {item['size']:>9} bytes  sha256 {item['sha256'][:16]}...")
    for item in manifest.get("errors") or []:
        print(f"  ! {item['format']}: {item['error']}", file=sys.stderr)
    print("Note: all report dates are 'earliest observed', and coverage/skipped reasons are included.")
    return 0 if not manifest.get("errors") else 1


def cmd_abuse(args) -> int:
    config = load_config(args.config, validate=False)
    if args.data_dir:
        config.data_dir = Path(args.data_dir)
    repo = _bootstrap(config)
    from phishtrace.reports import ReportNotFound, build_report_data, render_report, write_abuse_package

    try:
        investigation_id = _investigation_id(repo, args)
        data = build_report_data(
            repo,
            investigation_id,
            settings=config.reports,
            default_region=config.default_region,
        )
    except (ReportNotFound, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    output = Path(args.out) if args.out else config.report_dir / investigation_id / "abuse"
    attachment = render_report(data, "json") if config.reports.abuse_include_attachment else None
    manifest = write_abuse_package(output, data, config.reports, json_attachment=attachment)
    archive = None
    if args.zip:
        import zipfile
        archive = output.with_suffix(".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(output.iterdir()):
                if path.is_file():
                    zf.write(path, arcname=path.name)
        manifest["archive"] = str(archive)
    if args.json:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
        return 0
    print(f"Abuse drafts for {investigation_id} -> {output}")
    print(f"  targets (with configured address): {len(manifest.get('emails') or [])}")
    print(f"  targets needing manual review   : {len(manifest.get('manual_review') or [])}")
    if archive:
        print(f"  archive                         : {archive}")
    print("No message was sent. Review every draft and confirm the recipient before use.")
    return 0


def cmd_export(args) -> int:
    config = load_config(args.config, validate=False)
    if args.data_dir:
        config.data_dir = Path(args.data_dir)
    repo = _bootstrap(config)
    from phishtrace.reports import (
        IntegrationError,
        ReportNotFound,
        build_misp_event,
        build_report_data,
        build_stix_bundle,
        push_misp,
        push_stix_bundle,
    )

    try:
        investigation_id = _investigation_id(repo, args)
        data = build_report_data(
            repo,
            investigation_id,
            settings=config.reports,
            default_region=config.default_region,
        )
    except (ReportNotFound, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    output = Path(args.output_dir) if args.output_dir else config.report_dir / investigation_id
    output.mkdir(parents=True, exist_ok=True)
    result: dict = {"investigation_id": investigation_id, "target": args.target}
    try:
        if args.target == "stix":
            bundle = build_stix_bundle(data)
            path = output / f"phishtrace-{investigation_id}.stix.json"
            path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
            result["file"] = str(path)
            result["objects"] = len(bundle.get("objects") or [])
            if args.push:
                settings = dict(config.reports.opencti or {})
                if not settings.get("enabled"):
                    raise IntegrationError("OpenCTI push is disabled in reports.opencti.enabled")
                token = config.api_key(str(settings.get("token_env") or "OPENCTI_TOKEN"))
                result["push"] = asyncio.run(push_stix_bundle(bundle, settings, token=token))
        else:
            event = build_misp_event(data)
            path = output / f"phishtrace-{investigation_id}.misp.json"
            path.write_text(json.dumps(event, indent=2, ensure_ascii=False), encoding="utf-8")
            result["file"] = str(path)
            result["attributes"] = len((event.get("Event") or {}).get("Attribute") or [])
            if args.push:
                settings = dict(config.reports.misp or {})
                if not settings.get("enabled"):
                    raise IntegrationError("MISP push is disabled in reports.misp.enabled")
                api_key = config.api_key(str(settings.get("key_env") or "MISP_API_KEY"))
                result["push"] = asyncio.run(push_misp(event, settings, api_key=api_key))
    except IntegrationError as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"Wrote {result['target']} export for {investigation_id} -> {result['file']}")
        if "push" in result:
            print(f"  pushed: HTTP {result['push'].get('status_code')}")
        else:
            print("  not pushed (pass --push to send it to the configured platform).")
    return 0


def cmd_purge(args) -> int:
    config = load_config(args.config, validate=False)
    repo = _bootstrap(config)
    days = args.days if args.days is not None else config.retention_days
    result = repo.purge_older_than(days)
    print(f"Purged {result['count']} investigation(s) older than {result['cutoff']}.")
    return 0


def cmd_version(args) -> int:
    print(f"PhishTrace {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishtrace", description="Phishing infrastructure & persona investigations")
    parser.add_argument("--config", default=None, help="path to config.yaml")
    parser.add_argument("--version", action="version", version=f"PhishTrace {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the web console")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--data-dir")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("create-admin", help="create or reset the administrator account")
    p.add_argument("--username")
    p.set_defaults(func=cmd_create_admin)

    p = sub.add_parser("run", help="investigate a seed indicator")
    p.add_argument("seed", help="URL, domain, IP, email, phone, hash, Telegram handle, analytics ID, ...")
    p.add_argument("--type", default=None, help="force the seed selector type")
    p.add_argument("--json", action="store_true", help="print the full result as JSON")
    p.add_argument("--no-sightings", action="store_true", help="skip the social sightings stage")
    p.add_argument("--no-reuse", action="store_true", help="force a new investigation even if this seed was run before")
    p.add_argument("--data-dir")
    p.add_argument("--owner", default="cli")
    p.add_argument("--verbose", action="store_true", help="stream node progress to stderr")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("doctor", help="validate configuration, providers and keys")
    p.add_argument("--validate", action="store_true", help="make harmless live key-validation calls")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("providers", help="list provider availability")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_providers)

    p = sub.add_parser("report", help="render HTML/PDF/JSON/STIX/MISP/MD/TXT/CSV reports")
    p.add_argument("investigation_id", nargs="?", help="investigation id (omit with --latest)")
    p.add_argument("--latest", action="store_true", help="use the most recent investigation")
    p.add_argument("--format", action="append", help="format (repeatable or comma-separated); default: reports.formats")
    p.add_argument("--output-dir", help="directory for the report bundle (default: <data>/reports/<id>)")
    p.add_argument("--data-dir")
    p.add_argument("--json", action="store_true", help="print the manifest as JSON")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("abuse", help="build abuse-report email drafts and a manifest")
    p.add_argument("investigation_id", nargs="?", help="investigation id (omit with --latest)")
    p.add_argument("--latest", action="store_true", help="use the most recent investigation")
    p.add_argument("--out", help="output directory (default: <data>/reports/<id>/abuse)")
    p.add_argument("--zip", action="store_true", help="also write a .zip of the drafts")
    p.add_argument("--data-dir")
    p.add_argument("--json", action="store_true", help="print the manifest as JSON")
    p.set_defaults(func=cmd_abuse)

    p = sub.add_parser("export", help="write and optionally push a STIX bundle or MISP event")
    p.add_argument("investigation_id", nargs="?", help="investigation id (omit with --latest)")
    p.add_argument("--latest", action="store_true", help="use the most recent investigation")
    p.add_argument("--target", choices=("stix", "misp"), default="stix")
    p.add_argument("--push", action="store_true", help="push to the configured OpenCTI (stix) or MISP platform")
    p.add_argument("--output-dir", help="directory for the export file")
    p.add_argument("--data-dir")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("purge", help="delete investigations older than the retention period")
    p.add_argument("--days", type=int)
    p.set_defaults(func=cmd_purge)

    p = sub.add_parser("version", help="print version")
    p.set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
