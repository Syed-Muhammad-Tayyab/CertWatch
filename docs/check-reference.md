# Check Reference — Why Each Check Exists

## Expiry Window

An expired TLS certificate causes browsers to block the connection outright with a hard security warning — no graceful degradation. CertWatch warns at **30 days remaining by default** (configurable via `--warn-days` on the CLI) so renewal has a real buffer instead of being caught the day it lapses.

## Protocol Version

TLS 1.0 and 1.1 are deprecated by all major browsers and formally deprecated by the IETF (RFC 8996). SSLv2/SSLv3 have known practical attacks (e.g. POODLE). If a handshake negotiates any of these, it usually means the server still offers them for compatibility — which is itself a downgrade-attack risk. CertWatch flags any negotiated protocol older than TLS 1.2.

## Signature Algorithm

Certificates signed with **MD5** or **SHA-1** are considered cryptographically weak — both have practical collision attacks. Modern CAs no longer issue these, but older or self-signed certificates in internal environments sometimes still carry them forward on renewal without anyone checking.

## Hostname Match (SAN)

Modern TLS clients validate the **Subject Alternative Name (SAN)** list, not the legacy Common Name (CN) field. A certificate that doesn't list the hostname you're connecting to — common after a domain migration, a misconfigured load balancer, or a wildcard that doesn't actually cover the subdomain in use — will fail validation in real clients even if your manual TLS handshake "succeeds" at the socket level.

---

## Extending CertWatch

To add a new check, extend `_run_checks()` in `certwatch/analyzer.py` and append a `CertFinding(check, status, detail)` to `report.findings`. Status must be one of `"pass"`, `"warn"`, or `"fail"` — `_set_overall_status()` rolls these up automatically into the report's overall health.

Ideas for future checks are tracked in the Roadmap section of the main README.
