# Responsible security use

CaseVault is a CYC386 training project. All deliberately vulnerable examples are under `lab/` and are intended for **offline or localhost-only** proof. They must not be exposed publicly, connected to real user datasets or run on a trusted production server.

Report new findings privately to the project maintainers through an agreed internal channel; avoid public exploit details before remediation. The default deployment is localhost-only for this reason.

## Security controls
Parameterized SQL; per-object authorization; per-session CSRF tokens; SameSite/HttpOnly session cookie; native bounded filename validation; non-shell subprocess invocation; CSP/XFO/NoSniff; Docker non-root; automated tests; Semgrep severity gate; ZAP passive DAST.

## Operational deployment gaps
No internet exposure without HTTPS, `SESSION_SECURE=true`, restricted network ingress, approved secret storage, audited backups, rate limiting, malware scanning, and signed-off operational risk acceptance.
