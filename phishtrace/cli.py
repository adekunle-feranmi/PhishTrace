"""PhishTrace command line interface."""

from __future__ import annotations

import argparse
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
    uvicorn.run(app, host=config.host, port=config.port, log_level=config.log_level.lower(), access_log=True)
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

    p = sub.add_parser("doctor", help="validate configuration, providers and keys")
    p.add_argument("--validate", action="store_true", help="make harmless live key-validation calls")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("providers", help="list provider availability")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_providers)

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
