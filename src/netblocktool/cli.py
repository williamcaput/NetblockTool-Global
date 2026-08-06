from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .dedupe import deduplicate, filter_ip_version
from .http import HttpClient
from .output import write_csv, write_json, write_table
from .providers import AfrinicProvider, ApnicProvider, ArinProvider, LacnicProvider, RipeProvider
from .scoring import score_netblocks
from .whois import WhoisClient

LOG = logging.getLogger("netblocktool")
REGISTRIES = ("arin", "ripe", "apnic", "lacnic", "afrinic")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netblocktool",
        description="Discover and rank netblocks associated with an organization.",
    )
    parser.add_argument("company", help="Organization name, e.g. 'MUFG Bank'")
    parser.add_argument("-o", "--output", type=Path, help="Write output to this path")
    parser.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table")
    parser.add_argument(
        "-t", "--threshold", type=int, default=0, choices=range(0, 100), metavar="0-99"
    )
    parser.add_argument(
        "--registry", action="append", choices=REGISTRIES, dest="registries",
        help="Registry to query; repeat to select several. Default: all.",
    )
    family = parser.add_mutually_exclusive_group()
    family.add_argument("-4", "--ipv4", action="store_true", help="Return IPv4 only")
    family.add_argument("-6", "--ipv6", action="store_true", help="Return IPv6 only")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--user-agent",
        default=os.getenv(
            "NETBLOCKTOOL_USER_AGENT",
            "NetblockTool/4.0 contact=security@example.invalid",
        ),
        help="Identify your organization/contact to HTTP registry services",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=(
            logging.DEBUG
            if args.verbose > 1
            else logging.INFO
            if args.verbose
            else logging.WARNING
        ),
        format="%(levelname)s: %(message)s",
    )
    selected = args.registries or list(REGISTRIES)
    items = []
    failures = 0
    with HttpClient(user_agent=args.user_agent, timeout=args.timeout, retries=args.retries) as http:
        providers = {
            "arin": ArinProvider(http),
            "ripe": RipeProvider(http),
            "apnic": ApnicProvider(WhoisClient(timeout=args.timeout), http),
            "lacnic": LacnicProvider(WhoisClient(timeout=args.timeout)),
            "afrinic": AfrinicProvider(WhoisClient(timeout=args.timeout), http),
        }
        for registry in selected:
            try:
                items.extend(providers[registry].search(args.company))
            except (RuntimeError, OSError) as exc:
                failures += 1
                LOG.error("%s provider failed: %s", registry.upper(), exc)

    if failures == len(selected):
        return 2
    items = deduplicate(items)
    items = score_netblocks(items, args.company)
    version = 4 if args.ipv4 else 6 if args.ipv6 else None
    items = filter_ip_version(items, version)
    items = [item for item in items if item.confidence >= args.threshold]

    if args.format == "json":
        write_json(items, args.output)
    elif args.format == "csv":
        write_csv(items, args.output)
    else:
        write_table(items, args.output)

    if args.output:
        LOG.info("Wrote %d results to %s", len(items), args.output)
    elif not items:
        LOG.warning(
            "No matching netblocks were returned. "
            "Try a legal name, subsidiary, or registry filter."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
