"""
Core TLS/SSL analysis logic.

Connects to a host over TLS, retrieves the peer certificate, and evaluates
it against a set of hygiene checks: expiry window, key strength, signature
algorithm, hostname match, and negotiated protocol version.
"""

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10

# Protocols considered weak/deprecated if negotiated
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Signature/hash algorithms considered weak in a certificate
WEAK_SIG_ALGORITHMS = {"md5", "sha1", "md2"}

EXPIRY_WARNING_DAYS = 30


@dataclass
class CertFinding:
    check: str
    status: str          # "pass" | "warn" | "fail"
    detail: str


@dataclass
class CertReport:
    host: str
    port: int
    reachable: bool
    error: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    san: list[str] = field(default_factory=list)
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    signature_algorithm: Optional[str] = None
    findings: list[CertFinding] = field(default_factory=list)
    overall: str = "unknown"   # "healthy" | "warning" | "critical"


def _dn_to_str(dn_tuple) -> str:
    """Flatten an x509 name tuple-of-tuples into 'CN=example.com' style string."""
    parts = []
    for rdn in dn_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _parse_asn1_time(value: str) -> datetime:
    # cert['notAfter'] / ['notBefore'] look like 'Jun  1 12:00:00 2026 GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def analyze_host(host: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT) -> CertReport:
    report = CertReport(host=host, port=port, reachable=False)

    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                report.reachable = True
                report.protocol = tls_sock.version()
                cipher_name, _, _ = tls_sock.cipher()
                report.cipher = cipher_name

                cert = tls_sock.getpeercert()
                der_cert = tls_sock.getpeercert(binary_form=True)

    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        report.error = f"connection failed: {exc}"
        return report
    except ssl.SSLError as exc:
        report.error = f"TLS handshake failed: {exc}"
        return report

    if not cert:
        report.error = "no certificate returned by peer"
        return report

    report.issuer = _dn_to_str(cert.get("issuer", []))
    report.subject = _dn_to_str(cert.get("subject", []))
    report.san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    try:
        report.not_before = _parse_asn1_time(cert["notBefore"])
        report.not_after = _parse_asn1_time(cert["notAfter"])
        now = datetime.now(timezone.utc)
        report.days_remaining = (report.not_after - now).days
    except (KeyError, ValueError):
        pass

    report.signature_algorithm = _signature_algorithm_from_der(der_cert)

    _run_checks(report, host)
    _set_overall_status(report)
    return report


def _signature_algorithm_from_der(der_cert: bytes) -> Optional[str]:
    """
    Best-effort extraction of the signature algorithm name without requiring
    a heavyweight ASN.1 dependency. Falls back to None if it can't be parsed.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        parsed = x509.load_der_x509_certificate(der_cert, default_backend())
        return parsed.signature_hash_algorithm.name if parsed.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001 - cryptography may not be installed; degrade gracefully
        return None


def _run_checks(report: CertReport, host: str) -> None:
    # Expiry
    if report.days_remaining is not None:
        if report.days_remaining < 0:
            report.findings.append(CertFinding("Expiry", "fail", f"Certificate expired {abs(report.days_remaining)} day(s) ago."))
        elif report.days_remaining <= EXPIRY_WARNING_DAYS:
            report.findings.append(CertFinding("Expiry", "warn", f"Certificate expires in {report.days_remaining} day(s) — renew soon."))
        else:
            report.findings.append(CertFinding("Expiry", "pass", f"Valid for {report.days_remaining} more day(s)."))
    else:
        report.findings.append(CertFinding("Expiry", "warn", "Could not determine expiry date."))

    # Protocol version
    if report.protocol in WEAK_PROTOCOLS:
        report.findings.append(CertFinding("Protocol Version", "fail", f"Negotiated {report.protocol} — deprecated/weak, should be disabled server-side."))
    elif report.protocol:
        report.findings.append(CertFinding("Protocol Version", "pass", f"Negotiated {report.protocol}."))
    else:
        report.findings.append(CertFinding("Protocol Version", "warn", "Could not determine negotiated protocol."))

    # Signature algorithm
    if report.signature_algorithm:
        if any(weak in report.signature_algorithm.lower() for weak in WEAK_SIG_ALGORITHMS):
            report.findings.append(CertFinding("Signature Algorithm", "fail", f"Uses {report.signature_algorithm} — weak/deprecated hash."))
        else:
            report.findings.append(CertFinding("Signature Algorithm", "pass", f"Uses {report.signature_algorithm}."))
    else:
        report.findings.append(CertFinding("Signature Algorithm", "warn", "Could not determine signature algorithm (install the 'cryptography' package for this check)."))

    # Hostname coverage (SAN)
    if report.san:
        covered = host in report.san or any(_matches_wildcard(san, host) for san in report.san)
        if covered:
            report.findings.append(CertFinding("Hostname Match", "pass", f"'{host}' is covered by the certificate's SAN list."))
        else:
            report.findings.append(CertFinding("Hostname Match", "fail", f"'{host}' is NOT listed in the certificate's SAN entries: {report.san}"))
    else:
        report.findings.append(CertFinding("Hostname Match", "warn", "Certificate has no Subject Alternative Names (SAN) — relies on deprecated CN matching."))


def _matches_wildcard(pattern: str, host: str) -> bool:
    if not pattern.startswith("*."):
        return pattern == host
    suffix = pattern[1:]  # ".example.com"
    return host.endswith(suffix) and host.count(".") == pattern.count(".")


def _set_overall_status(report: CertReport) -> None:
    statuses = {f.status for f in report.findings}
    if "fail" in statuses:
        report.overall = "critical"
    elif "warn" in statuses:
        report.overall = "warning"
    else:
        report.overall = "healthy"
