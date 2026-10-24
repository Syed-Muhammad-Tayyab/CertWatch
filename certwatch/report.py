"""
Report rendering: console (colored) and JSON export.
"""

import json
from datetime import datetime, timezone

from .analyzer import CertReport

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
GRAY = "\033[90m"

STATUS_TAG = {
    "pass": f"{GREEN}[PASS]{RESET}",
    "warn": f"{YELLOW}[WARN]{RESET}",
    "fail": f"{RED}[FAIL]{RESET}",
}

OVERALL_COLOR = {
    "healthy": GREEN,
    "warning": YELLOW,
    "critical": RED,
}


def print_console_report(report: CertReport) -> None:
    if not report.reachable:
        print(f"{RED}{BOLD}[ERROR]{RESET} Could not connect to {report.host}:{report.port} — {report.error}")
        return

    color = OVERALL_COLOR.get(report.overall, RESET)

    print(f"\n{BOLD}CertWatch Report{RESET}")
    print(f"{GRAY}{'-' * 52}{RESET}")
    print(f"Host:            {report.host}:{report.port}")
    print(f"Subject:         {report.subject}")
    print(f"Issuer:          {report.issuer}")
    print(f"Valid From:      {report.not_before}")
    print(f"Valid Until:     {report.not_after}")
    print(f"Days Remaining:  {report.days_remaining}")
    print(f"Protocol:        {report.protocol}")
    print(f"Cipher Suite:    {report.cipher}")
    print(f"SAN Entries:     {', '.join(report.san) if report.san else '(none)'}")
    print(f"Overall Status:  {color}{BOLD}{report.overall.upper()}{RESET}")
    print(f"{GRAY}{'-' * 52}{RESET}\n")

    print(f"{BOLD}Checks{RESET}")
    for finding in report.findings:
        tag = STATUS_TAG.get(finding.status, finding.status)
        print(f"  {tag} {finding.check}: {finding.detail}")
    print()


def to_dict(report: CertReport) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": report.host,
        "port": report.port,
        "reachable": report.reachable,
        "error": report.error,
        "subject": report.subject,
        "issuer": report.issuer,
        "not_before": report.not_before.isoformat() if report.not_before else None,
        "not_after": report.not_after.isoformat() if report.not_after else None,
        "days_remaining": report.days_remaining,
        "protocol": report.protocol,
        "cipher": report.cipher,
        "san": report.san,
        "signature_algorithm": report.signature_algorithm,
        "overall": report.overall,
        "findings": [
            {"check": f.check, "status": f.status, "detail": f.detail}
            for f in report.findings
        ],
    }


def write_json_report(report: CertReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(to_dict(report), handle, indent=2)
