# CaseVault — Secure Incident Evidence Exchange

**CYC386 Secure Software Design and Development · Midterm DevSecOps Security Engineering Sprint**

**Team:** Muhammad Taha Ejaz (FA23-BCT-028), Muhammad Ahmad Shabaan (FA23-BCT-021), Sheheryar Khan (FA23-BCT-037).  
**GitHub:** https://github.com/m-taha-ejaz/SecureApp-Sprint-CaseVaultTeam

This repository contains the **secure implementation** of the CaseVault design, and a separate controlled local lab for demonstrating five mandatory vulnerability classes before and after remediation. The documents already merged into `main` under `docs/` provide the PNE/CIA and threat-model baseline.

## What the secure application actually does

- Registration, sign-in, sign-out and signed SameSite sessions with salted password hashes.
- Upload evidence files (1 byte to 2 MiB), validated via a compiled **C helper in the real upload route**.
- Unique opaque storage filename, SHA-256 digest per item, integrity validation on download.
- List owned and shared evidence, owner-only sharing, revocation, and deletion.
- Per-object authorization, CSRF verification for sensitive POST requests, restrictive framing policies.
- Timestamped application-level audit entries for uploads, downloads, shares, revocations, and deletions.
- Docker Compose launch and health endpoint.

**Scope:** localhost course deployment; not a production internet-facing forensic chain-of-custody service. The database owner can modify audit records; audit integrity is a documented residual risk. Production would need TLS, backup/restore validation, malware scanning, account lockout/rate limits, centralized immutable logging and operations hardening.

## Fast launch — Windows PowerShell

Install Docker Desktop with Linux containers enabled, unzip the package, and open PowerShell in its project folder.

```powershell
docker --version
docker compose version
Copy-Item .env.example .env
$secret = python -c "import secrets; print(secrets.token_urlsafe(48))"
(Get-Content .env) -replace 'REPLACE_WITH_RANDOM_SECRET', $secret | Set-Content .env
docker compose up --build -d
docker compose ps
```

Open **http://127.0.0.1:8000**. Create two dummy accounts (`investigator1`, `analyst2`), upload `incident_log.txt`, confirm that user 2 cannot download before user 1 shares access, share and revoke, then view SHA-256 and activity on dashboard. Never use real incident evidence or passwords in demos.

## Real security tests and evidence (run on your computer)

```powershell
docker compose --profile lab run --rm lab pytest -q tests
docker compose --profile lab run --rm lab python scripts/demo_security.py
Get-Content .\evidence\DEMO_RESULTS.txt
Get-Content .\evidence\BUFFER_ASAN_EXCERPT.txt | Select-Object -First 30
```

Controlled examples under `lab/` are not served by the deployable `web` container. The tests and demonstration outputs must be generated on the actual team's machines; don't fabricate logs or screenshots. Review false positives/negatives before claiming fixes are fully verified.

## GitHub integration and CI/CD

**Do not push directly to `main`** (it's protected). Create a branch `feature/casevault-app`, upload/add this application's contents **without deleting the existing `docs/`**, commit, open PR, obtain a real teammate's approval, and merge only after CI passes. GitHub Actions workflow contains unit/security tests, Semgrep SAST, policy gate and baseline OWASP ZAP DAST. Check actual workflow runs in **Actions** and download generated artifacts. Security enforcement should be expanded based on those real results.

## Evidence / final submission

Use the included `VIDEO_RUN_OF_SHOW.md` and `EVIDENCE_CAPTURE_NEXT.md`. Retain original import/scan/ASAN/pytest logs as well as screenshots. The instructor-required report is 18–30 pages; add real implementation and testing proof to the documentation already on `main`. Six-to-ten-minute video must show architecture, at least three before/after vulnerability classes, CI pipeline, and design decisions.

## Safety

This is an educational local demonstration. Do not deploy the `lab/` examples to an internet-exposed server. Do not upload `.env`, `instance/`, `evidence` containing confidential material, or actual user files to public GitHub.
