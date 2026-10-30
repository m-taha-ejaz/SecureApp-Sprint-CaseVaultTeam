# CYC386 CaseVault Demo Video — 8-minute run of show

**Record real screens and narrate what you actually did; do not use simulated terminal logs.** Recommended capture with Windows Snipping Tool / OBS. Each team member should present their actual contribution.

| Time | Screen and narration | Evidence to keep |
|---|---|---|
| 0:00–0:40 | Introduce CaseVault, all three members, mission and CIA outcomes | Repo and app browser |
| 0:40–1:20 | Show context and Level-1 DFD + two STRIDE risks | `docs/phase3` diagrams, THREAT_MODEL.pdf |
| 1:20–2:30 | Live secured app: register, upload dummy `incident_log.txt`, observe SHA-256 and audit history | Browser screenshot, Docker status |
| 2:30–3:40 | IDOR before/after: isolated lab behavior vs second-user real 404, then authorized sharing | Lab terminal and browser |
| 3:40–4:50 | Command injection before/after: benign marker in lab; secure no-shell validation rejects it | `DEMO_RESULTS.txt` plus test source |
| 4:50–5:50 | Buffer overflow before/after: ASAN crash of isolated C legacy parser, safe C helper rejects overlong string | `BUFFER_ASAN_EXCERPT.txt`, source code |
| 5:50–6:40 | Briefly show CSRF invalid-token rejection, clickjacking response headers | Lab script output + browser/devtools |
| 6:40–7:20 | Show pytest, Semgrep and ZAP outputs and high-severity gating on actual GitHub Actions | Actions run + artifact logs |
| 7:20–8:00 | Show GitHub reviewed PR and Jira traceability, discuss residual risks and conclusion | Real Jira board, merged PR |

**Do not claim unverified checks passed.** If tests or GitHub pipeline are failing, fix them or disclose limitations; do not record a fictitious success. Use dummy files only. Avoid revealing secret values.
