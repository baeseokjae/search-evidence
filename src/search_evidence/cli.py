from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_profile
from .core import EvidenceError, Result, atomic_file, canonical, secret_free_error
from .importers import import_csv, import_json
from .live import register_manifest
from .providers import SCOPE, Providers
from .service import Service


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="search-evidence", description="Private search analytics and URL evidence."
    )
    p.add_argument("--profile", help="Local TOML profile (or SEARCH_EVIDENCE_PROFILE).")
    commands = p.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status")
    status.add_argument("--remote", action="store_true")
    collect = commands.add_parser("collect")
    collect.add_argument("--start", required=True)
    collect.add_argument("--end", required=True)
    collect.add_argument("--sources", nargs="+", choices=["gsc", "bing"], default=["gsc", "bing"])
    collect.add_argument("--tables", nargs="+", default=["totals", "pages", "queries"])
    collect.add_argument(
        "--aggregate", action="store_true", help="Use a whole-window request instead of daily shards."
    )
    collect.add_argument("--resume")
    collect.add_argument("--page-url")
    finality = commands.add_parser("finality")
    finality.add_argument("--start", required=True)
    finality.add_argument("--end", required=True)
    for name in ("traffic", "compare", "protect"):
        sub = commands.add_parser(name)
        sub.add_argument("--limit", type=int, default=50)
        sub.add_argument("--cursor")
        if name == "traffic":
            sub.add_argument("--source", default="gsc", choices=["gsc", "bing", "ga4", "csv"])
            sub.add_argument("--table", default="pages")
            sub.add_argument("--snapshot-id")
            sub.add_argument("--url")
        elif name == "compare":
            sub.add_argument("--before", required=True)
            sub.add_argument("--after", required=True)
        else:
            sub.add_argument("--urls", nargs="+")
    imp = commands.add_parser("import-json")
    imp.add_argument("path", type=Path)
    imp = commands.add_parser("import-csv")
    imp.add_argument("path", type=Path)
    imp.add_argument("--start", required=True)
    imp.add_argument("--end", required=True)
    imp.add_argument("--observed-at")
    manual = commands.add_parser("protect-add")
    manual.add_argument("--url", required=True)
    manual.add_argument("--reason", required=True)
    audit = commands.add_parser("audit")
    audit.add_argument("--audit-id")
    audit.add_argument("--limit", type=int, default=50)
    audit.add_argument("--cursor")
    prior = commands.add_parser("prioritize")
    prior.add_argument("--audit-id", required=True)
    prior.add_argument("--limit", type=int, default=50)
    prior.add_argument("--cursor")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--urls", nargs="+", required=True)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--urls", nargs="+")
    manifest.add_argument("--urls-file", type=Path, help="JSON array of raw URLs.")
    manifest.add_argument("--revision")
    verify = commands.add_parser("verify")
    verify.add_argument("--manifest-id")
    verify.add_argument("--verification-id")
    verify.add_argument("--limit", type=int, default=50)
    verify.add_argument("--cursor")
    verify.add_argument("--cache-check", action="store_true")
    report = commands.add_parser("report")
    report.add_argument("--audit-id")
    report.add_argument("--verification-id")
    commands.add_parser("backup")
    commands.add_parser("mcp")
    auth = commands.add_parser("auth-login", help="Optional desktop OAuth login; uses a loopback callback.")
    auth.add_argument("--client-secrets", type=Path, required=True)
    auth.add_argument("--token-output", type=Path, required=True)
    return p


def execute(args) -> Result:
    profile = load_profile(args.pop("profile"))
    command = args.pop("command")
    if command == "mcp":
        from .mcp_server import run

        run(profile)
        return Result()
    service = Service(profile)
    try:
        if command == "import-json":
            return Result(data=import_json(service.store, profile.site, **args))
        if command == "import-csv":
            return Result(data=import_csv(service.store, profile.site, **args))
        if command == "protect-add":
            service.store.protect(profile.site, **args)
            return Result(data={"protected": True, "url": args["url"]})
        if command == "manifest":
            urls = args.pop("urls") or []
            file = args.pop("urls_file")
            if file:
                urls.extend(json.loads(file.read_text()))
            return Result(data=register_manifest(service.store, profile, urls=urls, **args))
        if command == "finality":
            return Result(data=Providers(profile, service.store).finality(**args))
        if command == "backup":
            return Result(data=service.store.backup())
        if command == "auth-login":
            from google_auth_oauthlib.flow import InstalledAppFlow

            output = args["token_output"].expanduser().resolve()
            if output.exists():
                raise EvidenceError("token_output_exists")
            flow = InstalledAppFlow.from_client_secrets_file(str(args["client_secrets"]), scopes=[SCOPE])
            # Auth instructions go to stderr so JSON stdout remains parseable.
            with __import__("contextlib").redirect_stdout(sys.stderr):
                credentials = flow.run_local_server(host="127.0.0.1", port=0, timeout_seconds=180)
            atomic_file(output, credentials.to_json().encode())
            return Result(data={"token_saved": True})
        method = {
            "status": "search_status",
            "collect": "search_collect",
            "traffic": "search_traffic",
            "compare": "search_compare",
            "protect": "search_protect_urls",
            "audit": "search_audit_content",
            "prioritize": "search_prioritize",
            "inspect": "search_inspect_urls",
            "verify": "search_verify_live",
            "report": "search_render_report",
        }[command]
        if command == "collect":
            args["daily"] = not args.pop("aggregate")
        return service.invoke(method, args)
    finally:
        service.close()


def main():
    args = vars(parser().parse_args())
    is_mcp = args["command"] == "mcp"
    try:
        result = execute(args)
    except KeyboardInterrupt:
        result = Result(ok=False, error={"code": "interrupted", "retryable": True})
    except Exception as exc:
        result = secret_free_error(exc)
    if not is_mcp:
        print(canonical(result.model_dump()).decode())
    elif not result.ok:
        print(canonical(result.model_dump()).decode(), file=sys.stderr)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
