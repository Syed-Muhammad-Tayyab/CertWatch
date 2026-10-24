"""Command-line entrypoint for CertWatch."""

import argparse
import sys

from .analyzer import analyze_host, DEFAULT_PORT
from .report import print_console_report, write_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certwatch",
        description="Audit a host's TLS/SSL certificate for expiry, weak protocols, and misconfigurations.",
    )
    parser.add_argument("host", help="Target hostname (e.g. example.com)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Target port (default: {DEFAULT_PORT})")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--json", metavar="PATH", help="Write a JSON report to PATH")
    parser.add_argument(
        "--warn-days",
        type=int,
        default=None,
        metavar="DAYS",
        help="Exit with code 1 if certificate expires within this many days (useful in CI/monitoring)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    report = analyze_host(args.host, port=args.port, timeout=args.timeout)
    print_console_report(report)

    if not report.reachable:
        sys.exit(2)

    if args.json:
        write_json_report(report, args.json)
        print(f"JSON report written to {args.json}")

    if args.warn_days is not None and report.days_remaining is not None:
        if report.days_remaining <= args.warn_days:
            print(f"\nCertificate expires within {args.warn_days} day(s) threshold — failing.")
            sys.exit(1)

    if report.overall == "critical":
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
