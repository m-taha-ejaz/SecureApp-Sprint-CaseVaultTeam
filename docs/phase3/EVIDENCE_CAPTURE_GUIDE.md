# Phase 3 — Real Evidence Collection Guide (Windows / PowerShell)

**Purpose:** create independently verifiable evidence from your actual PC and authenticated GitHub/Jira accounts. Files in this package are design documents; there are no claimed exploit logs or scanner results.

## Step 1 — Run two deterministic model checks (mandatory, approx. 2 minutes once Python is available)

1. Download/extract the Phase 3 ZIP. Open the folder containing `THREAT_MODEL.pdf` in File Explorer.
2. Click the File Explorer address bar, type `powershell` and press Enter. In that PowerShell window, execute:

```powershell
python --version
Get-Date -Format o
python .\scripts\check_model_integrity.py | Tee-Object -FilePath .\model_integrity_log.txt
python .\scripts\cvss31_verify.py | Tee-Object -FilePath .\cvss_verification_log.txt
Get-FileHash .\THREAT_MODEL.pdf -Algorithm SHA256 | Format-List | Out-File .\model_pdf_sha256.txt
```

Expected *design QA* results: `RESULT: PASS`, **30 PNEs mapped**, **26 STRIDE scenarios**, **36 DFD element coverage entries**, and **16 checked CVSS vectors / 0 mismatches**. A result is genuine evidence only when you have rerun it yourself; do not submit these expected strings as if they were a log. If any command fails, capture the original error and show it for troubleshooting; don't edit the log to make it pass.

**Capture screenshot EV-3-03** showing your PowerShell prompt/path, `Get-Date` result, and `PASS` results. Keep the **unmodified** `.txt` logs above in `evidence/phase3/`. Note that these tests do **not** show the software's security fixes have passed.

## Step 2 — Show independently reproducible CVSS vector values

1. Visit the FIRST official v3.1 calculator: https://www.first.org/cvss/calculator/3.1
2. Select the metric values for `R-01`, from the Risk Register: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. Expected Base score: **8.8 (High)**.
3. Repeat for `R-02`: `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`. Expected Base score: **7.5 (High)**.
4. Repeat for `R-03`: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`. Expected Base score: **8.1 (High)**.

**Capture screenshot EV-3-04** for each vector and its score with browser address visible, using filenames `CVSS_R01.png`, `CVSS_R02.png`, `CVSS_R03.png` (do not add fabricated screenshots).

## Step 3 — Save original design and traceability in GitHub

1. Use your real `SecureApp-Sprint-<TeamName>` repository. If not yet created, make it in GitHub first and protect `main` with peer-review rules supported by your plan.
2. Add this Phase 3 folder as `docs/phase03/` on a real feature branch (e.g. `docs/threat-model`); do not add fake commit history or change your system clock.
3. Make a PR that describes `PNE-001..030`, `TH-001..026`, the two attack trees and all 16 scores. Ask an actual teammate to review the PR; save the real review URL and screenshot (EV-3-07).
4. Never upload actual passwords, cookies, private `.env`, or real incident evidence.

## Step 4 — Create/link real Jira issues (no invented issue keys)

- The 30 original PNE Stories from Phase 2 should be the source of truth. You may link multiple THs to an existing Story or create appropriate child tasks; **the instructor requires traceability, not 26 manually created tasks specifically**. The `Jira_Threat_Tasks_Planned.csv` is a reusable seed, not a completed board.
- At minimum, prioritize the five mandatory weaknesses: `TH-013/ R-02/ PNE-013` (Buffer Overflow), `TH-014/ R-01/ PNE-014` (Command Injection), `TH-006/ R-03/ PNE-001..003` (IDOR), `TH-008/ R-05/ PNE-008` (CSRF), `TH-009/ R-06/ PNE-009` (Clickjacking). Other TH IDs should remain linked through grouped Jira work or follow-on risk tasks.
- Each issue should reference the **real** target `PNE`/`SR`, `TH`, `R` identifiers and planned `T-xxx` test; later add the actual PR and test evidence.
- **Capture screenshot EV-3-06** showing an issue's actual key/description plus project board status, and export board when done.

## Step 5 — Real team review (not invented)

Ask your team to inspect the two DFDs, verify the assumed attacker privileges (especially `AV`, `PR`, `UI`) and confirm the risk priorities. Record their **actual** review date, attendees, objections, decisions and signatures/PR approvals in `TEAM_THREAT_REVIEW.md`. Preserve a real PR comment, issue discussion, or dated screenshot as EV-3-08.

## What is NOT evidence for Phase 3

- Downloading our PDF or viewing a diagram alone is not proof of tool execution.
- A modeled CVSS score is not proof that a running app has that vulnerability.
- No simulated GitHub Actions, Jira task, SAST/DAST or exploit log belongs in the final verified-evidence section.
- Actual vulnerability tests, ASAN output, scanner SARIF/JSON and CI logs are to be captured during the implementation and testing phases.

## Evidence hygiene

Use the included `Evidence_Manifest.csv` to fill actual capture date, collector, filename/path and status. Retain raw logs as well as screenshots; cross-link them in Jira, the final IEEE report and the 6–10 min demo.
