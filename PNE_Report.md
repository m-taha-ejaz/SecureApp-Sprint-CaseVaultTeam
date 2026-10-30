# CaseVault — Protection Needs Elicitation (PNE) & CIA Mapping
**Course:** CYC386 — Secure Software Design and Development  |  **Exam:** Fall 2026 Midterm Lab, 7-day DevSecOps sprint
**Document:** `PNE_Report.md`  |  **Version:** 1.0  |  **Status:** Design baseline — pending team/stakeholder validation and instructor approval confirmation
**Team:** [Insert approved team name and up to three members]  |  **Date:** [Insert actual date]

> **Evidence integrity statement:** This document specifies *planned* controls and verification criteria. It does not assert that interviews occurred, code has been implemented, tests passed, an issue was created, or the instructor approved the theme. Record genuine results in the linked project artifacts.

## 1. Purpose, source, and scope
This is the required protection-needs deliverable under Sections 4 (Day 0–1), 5, and **6.2** of the CYC386 Midterm Lab Exam brief. It directly supports the **12-mark PNE/CIA assessment**. The report enumerates data/process/component/external-entity assets, perspectives of users/admins/operators/adversaries, explicit CIA mappings, and testable security requirements. The proposed values are design assumptions pending team validation.

**Product:** CaseVault, a browser-based incident-evidence exchange service under the recommended **File Sharing / Collaboration** theme. Baseline flow: user registers/signs in → uploads bounded evidence with native metadata validation → server stores file privately and SHA-256 digest → owner grants/revokes a named collaborator → server rechecks access for every download → events recorded in audit log. Stack: FastAPI/Jinja2, SQLite, private object store, C metadata helper, Docker, GitHub Actions and Jira.

**In scope for 7-day MVP:** registration/login/logout, per-evidence ownership and sharing, upload/list/download/delete, integrity hashes, minimum audit events, native helper boundary, five security-remediation classes, tests/CI, health endpoint, reproducible Docker run. **Out of scope:** public share links, live malware detonation, legal chain-of-custody certification, enterprise SSO, distributed storage, production HSM, regulatory compliance claims.

**Environment assumption:** Local Docker lab with dummy incident files, no real confidential evidence. Production internet hosting would additionally need TLS, managed secrets, backups, malware scanning, stronger audit immutability and operational controls; these are not presumed implemented.

## 2. Elicitation method and provenance
Because no signed stakeholder interviews have been supplied, the initial PNEs are **scenario-based elicitation proposals**, derived from the locked Phase 1 architecture, the exam rubric, and anticipated abuse cases. The team should review the nine scenarios below, agree priorities/limits, and record actual review date in `TEAM_VALIDATION.md`. Do not misrepresent role-play/scenario analysis as external stakeholder interviews.

| Scenario | Need elicited from | Stakeholder view | Linked PNEs |
|---|---|---|---|
| SC-01 | Owner uploads an incident log and expects it to remain unreadable to other users. | ST-01 | PNE-001, PNE-010, PNE-011, PNE-012, PNE-015 |
| SC-02 | Owner grants a colleague access and later revokes it. | ST-01, ST-02 | PNE-002, PNE-003, PNE-007, PNE-008 |
| SC-03 | Another authenticated user guesses an evidence identifier and tries to download/delete it. | ST-05 | PNE-001, PNE-004, PNE-011 |
| SC-04 | Malicious file metadata reaches a native parser or shell-like command path. | ST-04, ST-05 | PNE-012, PNE-013, PNE-014, PNE-020 |
| SC-05 | User accesses sensitive actions from an external webpage or embedded frame. | ST-05 | PNE-008, PNE-009 |
| SC-06 | Investigator asks whether the downloaded evidence bytes still match the upload. | ST-01, ST-02 | PNE-016, PNE-017 |
| SC-07 | Operator must reproduce tests and reject a high/critical finding before merge. | ST-04, ST-06 | PNE-021, PNE-022, PNE-023 |
| SC-08 | Host disk is low or the service stops unexpectedly. | ST-04 | PNE-012, PNE-024, PNE-027 |
| SC-09 | System is considered for external production hosting after the lab. | ST-03, ST-04 | PNE-025, PNE-026, PNE-027, PNE-028, PNE-029, PNE-030 |

## 3. Stakeholder perspectives
| ID | Stakeholder | Objective / actions | Security interest / limitation |
|---|---|---|---|
| ST-01 | Evidence owner / investigator | Uploads an incident artifact, shares with named coworkers, revokes access, deletes own artifact. | Confidentiality, authorized changes, availability; must not disclose by manipulating IDs. |
| ST-02 | Authorized collaborator / analyst | Views and downloads evidence explicitly shared with their account. | Read only within a current grant; must not inherit owner privileges. |
| ST-03 | System administrator / security manager | Configures users and policies and reviews security posture; no admin evidence-browser capability in the MVP. | Least privilege and controls over security events; no assumed unrestricted evidence access. |
| ST-04 | Operator / DevSecOps engineer | Deploys app, maintains secrets, observes health, handles failures and CI/CD. | Availability, bounded resource use, protected secrets, repeatable security gates. |
| ST-05 | Adversary (abuse-case perspective) | Attempts unauthorized object access, forged state changes, unsafe metadata, or resource exhaustion. NOT an authorized product role. | Negative test scenarios and design constraints; no approval or genuine interviews implied. |
| ST-06 | Reviewer / instructor | Checks CIA rationale, code changes, tests, Git/Jira traceability and residual risks. | Reproducible evidence and clear distinction between design and verified implementation. |

**Authorization boundary:** The operator/admin manages deployment and security review but is *not* automatically a superuser for confidential evidence in the MVP. Access to stored files is determined by object ownership or explicit sharing; the attacker is a modeled adversary, not an authorized role.

## 4. Asset inventory
| ID | Asset | Class | Location / system | CIA | Main loss scenario |
|---|---|---|---|---|---|
| A-01 | User identities and password hashes | Data | FastAPI + SQLite | C/I | Account takeover or credential disclosure |
| A-02 | Authenticated session and anti-CSRF tokens | Data | Browser / server session store | C/I | Session theft, forged sensitive action |
| A-03 | Incident evidence file contents | Data | Private filesystem | C/I/A | Confidential case data exposed, changed, or lost |
| A-04 | Evidence metadata (owner, opaque ID, name, timestamp) | Data | SQLite | C/I | Enumeration or incorrect object ownership |
| A-05 | Sharing grants and revocation state | Data | SQLite | C/I | Unauthorized disclosure or persistent access |
| A-06 | SHA-256 digest per evidence file | Data | SQLite | I | Undetected file tampering |
| A-07 | Audit event records | Data | SQLite / protected logs | C/I | Investigation accountability lost or logs leak metadata |
| A-08 | Relational database | Component / data store | SQLite file | C/I/A | Unauthorized reads, corruption, database unavailable |
| A-09 | Private object storage directory | Component / data store | Docker volume or private local directory | C/I/A | Path traversal or public file serving |
| A-10 | Web UI, API and authentication processes | Process / component | FastAPI + Jinja2 | C/I/A | Improper auth, CSRF, UI framing, service disruption |
| A-11 | Native metadata helper and invocation boundary | Component / process | C executable called by server | I/A/C | Memory corruption or shell injection |
| A-12 | Secrets and runtime configuration | Data / component | Environment/config, never committed | C/I | Forged sessions, compromise of app credentials |
| A-13 | Runtime compute and container | Component | Docker/local host | A/I | Resource exhaustion, high privilege process |
| A-14 | Source code, dependencies and build workflow | Process / component | GitHub repository / Actions | I/A | Vulnerable supply chain, unreviewed insecure changes |
| A-15 | Web browser and signed-in user | External entity | Investigator / collaborator endpoint | C/I | Compromised session, untrusted page origin |
| A-16 | GitHub, Jira and MS Teams | External systems | Collaboration and submission | I/A | Lost traceability or unavailable review evidence |

CIA key: **C** = Confidentiality (restrict disclosure); **I** = Integrity (prevent/detect unauthorized changes); **A** = Availability (keep authorized use possible). Asset CIA entries indicate primary sensitivities; the PNE register is the authoritative need-by-need mapping.

## 5. Protection-needs register: explicit CIA mapping
**Priority definition:** P0 = mandatory for the secured lab MVP or the exam process; P1 = deployment hardening / proposed residual-risk follow-up. Priority here is a **planning decision**, not a formal CVSS score; Phase 3 threat modeling will quantify applicable threats.

| PNE ID | Protection need | Stakeholders | Assets | CIA | Priority |
|---|---|---|---|:---:|:---:|
| PNE-001 | Only the owner and currently authorized collaborators may retrieve each evidence object. | ST-01/ST-02/ST-05 | A-03/A-04/A-05 | **C,I** | P0 |
| PNE-002 | Only the evidence owner may grant access to a named existing user. | ST-01/ST-02 | A-05/A-04 | **C,I** | P0 |
| PNE-003 | Revoked collaborators must lose access at the next request. | ST-01/ST-02 | A-05/A-03 | **C,I** | P0 |
| PNE-004 | Non-owners must not delete or alter evidence objects. | ST-01/ST-05 | A-03/A-04/A-05 | **I,A** | P0 |
| PNE-005 | Sensitive operations must require an authenticated user. | ST-01/ST-02 | A-01/A-02/A-10 | **C,I** | P0 |
| PNE-006 | Passwords must not be exposed in source, logs or stored as plaintext. | ST-01/ST-03 | A-01/A-12 | **C** | P0 |
| PNE-007 | User sessions must resist predictable or cross-site misuse. | ST-01/ST-02 | A-02/A-15 | **C,I** | P0 |
| PNE-008 | Cross-site pages must not silently perform sensitive state changes. | ST-01/ST-05 | A-02/A-05/A-10 | **I** | P0 |
| PNE-009 | Sensitive pages must not be operable when embedded by an untrusted site. | ST-01/ST-05 | A-10/A-15 | **I** | P0 |
| PNE-010 | Evidence files must not be publicly available through static web paths. | ST-01/ST-05 | A-03/A-09/A-10 | **C** | P0 |
| PNE-011 | External identifiers must not reveal paths or grant access by themselves. | ST-01/ST-05 | A-04/A-09 | **C** | P0 |
| PNE-012 | Large uploads must not exhaust service capacity. | ST-04/ST-05 | A-03/A-09/A-13 | **A** | P0 |
| PNE-013 | Untrusted metadata must not corrupt native memory. | ST-04/ST-05 | A-11/A-13 | **I,A** | P0 |
| PNE-014 | User-supplied values must not become shell commands. | ST-01/ST-04/ST-05 | A-11/A-13 | **C,I,A** | P0 |
| PNE-015 | Untrusted filenames and paths must not escape private storage. | ST-01/ST-05 | A-03/A-04/A-09 | **C,I** | P0 |
| PNE-016 | Evidence bytes must have a verifiable integrity reference. | ST-01/ST-02 | A-03/A-06 | **I** | P0 |
| PNE-017 | Security-relevant evidence actions must be accountable. | ST-01/ST-03/ST-06 | A-07/A-04 | **I** | P0 |
| PNE-018 | Audit and error messages must not disclose secrets or evidence contents. | ST-01/ST-04 | A-07/A-12/A-10 | **C** | P0 |
| PNE-019 | Database requests must not permit SQL manipulation by user inputs. | ST-03/ST-05 | A-08/A-10 | **C,I** | P0 |
| PNE-020 | Invalid file metadata must fail closed without crashing normal workflows. | ST-01/ST-04/ST-05 | A-04/A-11/A-13 | **I,A** | P0 |
| PNE-021 | Deployment and build secrets must remain private and separately configurable. | ST-03/ST-04 | A-12/A-14 | **C,I** | P0 |
| PNE-022 | High/critical findings must block the secure delivery workflow. | ST-04/ST-06 | A-14/A-10 | **I** | P0 |
| PNE-023 | Security changes must be reviewed and traceable to the need they address. | ST-04/ST-06 | A-14/A-16 | **I** | P0 |
| PNE-024 | Service failures must be detectable and startup reproducible. | ST-04 | A-08/A-09/A-13 | **A** | P0 |
| PNE-025 | Application runtime should minimize privileges. | ST-04 | A-09/A-13 | **C,I,A** | P1 |
| PNE-026 | Remote deployment should protect session and evidence traffic in transit. | ST-03/ST-04 | A-02/A-03/A-15 | **C,I** | P1 |
| PNE-027 | Evidence and configuration should be recoverable after storage failures. | ST-03/ST-04 | A-03/A-08/A-09 | **A,I** | P1 |
| PNE-028 | Authentication attempts should be resistant to automated guessing. | ST-01/ST-04 | A-01/A-10 | **C,A** | P1 |
| PNE-029 | Evidence retention and deletion must follow an explicit policy. | ST-01/ST-03 | A-03/A-07/A-09 | **C,I** | P1 |
| PNE-030 | Audit records should become tamper-evident for real investigations. | ST-03/ST-06 | A-07 | **I** | P1 |

**Coverage check:** 30 distinct needs; 24 P0 and 6 P1. Need-level CIA associations: C=17, I=23, A=9 (a need can belong to multiple pillars). No needs have an empty CIA mapping.

## 6. Derived measurable security requirements and acceptance criteria
Each security requirement is uniquely numbered and testable. **T-xxx is a planned test reference**, not a passed test or captured evidence.

### SR-001 | PNE-001 | P0 | CIA: C,I
- **Shall requirement:** For every list/download route, server-side authorization shall evaluate the signed-in principal against that specific evidence ID and current share grants.
- **Measurable acceptance:** Two users: owner and grantee succeed; a third authenticated user and anonymous request receive 403 or non-disclosing 404; enumeration exposes no file content.
- **Planned verification (T-001):** Authorization integration test with 3 accounts + negative HTTP evidence.

### SR-002 | PNE-002 | P0 | CIA: C,I
- **Shall requirement:** Share endpoint shall require owner permission and a validated target account; reject self/invalid grants without exposing evidence.
- **Measurable acceptance:** Authorized grant succeeds; non-owner and unknown target cannot create grants; database remains unchanged on rejected attempts.
- **Planned verification (T-002):** Owner/non-owner grant tests + DB check.

### SR-003 | PNE-003 | P0 | CIA: C,I
- **Shall requirement:** Revocation shall update server-side grant state and every later download shall recheck current permissions.
- **Measurable acceptance:** After revocation, previously authorized collaborator receives 403/404; owner still succeeds.
- **Planned verification (T-003):** Grant → download → revoke → denied regression test.

### SR-004 | PNE-004 | P0 | CIA: I,A
- **Shall requirement:** Delete operation shall be owner-only; denied attempts shall not remove metadata, grants, or bytes.
- **Measurable acceptance:** Unauthorized delete rejected and original owner can still download the same file and digest.
- **Planned verification (T-004):** Two-account delete integration test.

### SR-005 | PNE-005 | P0 | CIA: C,I
- **Shall requirement:** Upload, list, download, share, revoke, delete and audit views shall enforce authenticated session checks.
- **Measurable acceptance:** Each protected endpoint rejects unauthenticated requests; authenticated owner workflows succeed.
- **Planned verification (T-005):** Authentication route matrix test.

### SR-006 | PNE-006 | P0 | CIA: C
- **Shall requirement:** Use vetted salted password hashing; never persist plaintext; prevent secrets from being printed.
- **Measurable acceptance:** Database password hash differs from entered password, login verifies it, no source code contains seeded plaintext credentials.
- **Planned verification (T-006):** Credential storage test + source inspection.

### SR-007 | PNE-007 | P0 | CIA: C,I
- **Shall requirement:** Use signed/unpredictable session state, HttpOnly and SameSite cookies, logout invalidation and appropriate expiry; Secure flag under HTTPS.
- **Measurable acceptance:** Logout prevents reuse; cookie attributes are visible; altered tokens are rejected.
- **Planned verification (T-007):** Cookie/header inspection and session lifecycle tests.

### SR-008 | PNE-008 | P0 | CIA: I
- **Shall requirement:** All authenticated browser state-changing forms shall require session-bound anti-CSRF token verification plus SameSite cookies.
- **Measurable acceptance:** Missing/wrong token rejected (403); correct token accepted; GET has no state-changing side effect.
- **Planned verification (T-008):** CSRF negative/positive test and controlled forged-form demo.

### SR-009 | PNE-009 | P0 | CIA: I
- **Shall requirement:** Authenticated pages shall emit CSP frame-ancestors 'none' and X-Frame-Options DENY.
- **Measurable acceptance:** Browser refuses to render secure page within cross-origin iframe; secure response headers contain the policy.
- **Planned verification (T-009):** Browser iframe demo + response header test.

### SR-010 | PNE-010 | P0 | CIA: C
- **Shall requirement:** Store evidence outside static root; access only via authorized server download route.
- **Measurable acceptance:** A guessed direct path cannot retrieve bytes; authorized API download succeeds.
- **Planned verification (T-010):** HTTP direct-path negative test + storage inspection.

### SR-011 | PNE-011 | P0 | CIA: C
- **Shall requirement:** Generate opaque evidence IDs and server-controlled storage names; never use client filenames as filesystem path components.
- **Measurable acceptance:** Uploads receive non-sequential random-looking IDs; path-like filenames do not traverse storage.
- **Planned verification (T-011):** Upload metadata and path traversal tests.

### SR-012 | PNE-012 | P0 | CIA: A
- **Shall requirement:** Reject oversized uploads with a configured maximum and bounded streaming/storage; clean up failed writes.
- **Measurable acceptance:** Configured over-limit upload rejected, not written to disk; subsequent normal request still succeeds.
- **Planned verification (T-012):** Boundary-size integration test and disk inspection.

### SR-013 | PNE-013 | P0 | CIA: I,A
- **Shall requirement:** Bound and validate native helper input lengths; use bounded memory operations; compile and test helper with AddressSanitizer.
- **Measurable acceptance:** Overlong input terminates safely with non-zero validation error; ASAN reports no overflow for fixed parser.
- **Planned verification (T-013):** Controlled legacy/fixed C harness + ASAN output.

### SR-014 | PNE-014 | P0 | CIA: C,I,A
- **Shall requirement:** Invoke the fixed native helper through argument arrays with shell disabled; validate input and set timeout.
- **Measurable acceptance:** Shell metacharacter input is treated as data or rejected; marker file/extra command never executes in secure version.
- **Planned verification (T-014):** Controlled legacy/fixed command invocation test.

### SR-015 | PNE-015 | P0 | CIA: C,I
- **Shall requirement:** Normalize and validate display metadata; use server-generated object storage paths, never client-supplied path segments.
- **Measurable acceptance:** Traversal patterns do not create or read files outside the configured private store.
- **Planned verification (T-015):** Traversal negative tests + filesystem assertions.

### SR-016 | PNE-016 | P0 | CIA: I
- **Shall requirement:** Compute SHA-256 on upload, store digest, and recompute/compare before authorized download or verification.
- **Measurable acceptance:** Original bytes match the stored digest; a deliberately modified test file is flagged as mismatched.
- **Planned verification (T-016):** Hash correctness and tamper-detection tests.

### SR-017 | PNE-017 | P0 | CIA: I
- **Shall requirement:** Record actor, event, evidence ID, outcome and UTC timestamp for upload/share/revoke/download/delete/failed authorization without recording file contents.
- **Measurable acceptance:** Each required event generates a timestamped record tied to actor and object; failures are recorded without file bytes.
- **Planned verification (T-017):** Audit event integration test and record screenshot.

### SR-018 | PNE-018 | P0 | CIA: C
- **Shall requirement:** Do not log passwords, session tokens, full file bodies, or secret configuration; use generic client errors.
- **Measurable acceptance:** Known secret/test content strings are absent from generated audit/error logs; 500 response does not show stack trace.
- **Planned verification (T-018):** Log redaction and safe-error tests.

### SR-019 | PNE-019 | P0 | CIA: C,I
- **Shall requirement:** Use parameterized DB operations and validated input; avoid dynamic SQL composition from request values.
- **Measurable acceptance:** SQL metacharacter username/filename does not change query scope, corrupt data, or authenticate falsely.
- **Planned verification (T-019):** DB query tests / static code review.

### SR-020 | PNE-020 | P0 | CIA: I,A
- **Shall requirement:** Validate length, encoding and allowed metadata at the web/native boundary; apply subprocess timeout and nonzero error handling.
- **Measurable acceptance:** Empty/overlong/invalid input rejected with controlled HTTP error; health endpoint stays reachable.
- **Planned verification (T-020):** Boundary, malformed-input and timeout tests.

### SR-021 | PNE-021 | P0 | CIA: C,I
- **Shall requirement:** Read secrets from environment/secret store; ignore .env and avoid real tokens in repo, images, CI logs and screenshots.
- **Measurable acceptance:** Repository secret scan has no real secret; app refuses unsafe missing production secret; local .env is ignored.
- **Planned verification (T-021):** Git ignore inspection + secret scanning.

### SR-022 | PNE-022 | P0 | CIA: I
- **Shall requirement:** Run tests, SAST and DAST evidence workflow; enforce a nonzero security stage result for verified high/critical findings.
- **Measurable acceptance:** Passing clean run is green; synthetic/known high finding in a controlled test makes required CI check fail.
- **Planned verification (T-022):** GitHub Actions/SAST/DAST artifacts, passing and failing screenshots.

### SR-023 | PNE-023 | P0 | CIA: I
- **Shall requirement:** Protect main; merge via PR with one peer approval; name PNE-ID in issue/PR and link later threat, fix, test records.
- **Measurable acceptance:** Main denies direct push; sample PR has reviewer approval and linked issue/test; actual issue keys saved after creation.
- **Planned verification (T-023):** GitHub settings screenshot + real PR screenshot.

### SR-024 | PNE-024 | P0 | CIA: A
- **Shall requirement:** Provide health endpoint, repeatable Docker Compose configuration, and clear restart/run instructions.
- **Measurable acceptance:** Container starts from documented commands and /health responds; restart returns service to healthy state.
- **Planned verification (T-024):** Docker Compose logs + health verification.

### SR-025 | PNE-025 | P1 | CIA: C,I,A
- **Shall requirement:** Run container process as non-root with least required filesystem permissions and avoid privileged mounting.
- **Measurable acceptance:** Inspection shows non-root UID and private writable directory only where required.
- **Planned verification (T-025):** Container inspection test.

### SR-026 | PNE-026 | P1 | CIA: C,I
- **Shall requirement:** For any internet-facing environment, terminate TLS and set Secure cookies; local HTTP is lab-only and must not be called production-ready.
- **Measurable acceptance:** HTTPS request succeeds; HTTP redirects/rejected and browser cookie carries Secure in deployed environment.
- **Planned verification (T-026):** Deployment configuration and TLS inspection.

### SR-027 | PNE-027 | P1 | CIA: A,I
- **Shall requirement:** Define encrypted backup, restore and integrity-check procedure for DB and file store; test before production use.
- **Measurable acceptance:** Restored dummy evidence metadata and bytes match recorded digest after a rehearsal.
- **Planned verification (T-027):** Documented restore drill (future).

### SR-028 | PNE-028 | P1 | CIA: C,A
- **Shall requirement:** Introduce per-account/IP login throttling and monitored failure events before broader exposure.
- **Measurable acceptance:** Repeated failed attempts trigger bounded rejection without blocking unrelated accounts.
- **Planned verification (T-028):** Rate-limit test (future).

### SR-029 | PNE-029 | P1 | CIA: C,I
- **Shall requirement:** Agree retention limits and deletion semantics; prevent unauthorized purge and document backups not necessarily erased by live deletion.
- **Measurable acceptance:** Policy defines retention and delete effect on primary/backup copy; sample deletion verified.
- **Planned verification (T-029):** Policy review + cleanup test (future).

### SR-030 | PNE-030 | P1 | CIA: I
- **Shall requirement:** For production, forward audit logs to protected append-only/tamper-evident store; a mutable local SQLite audit table is not tamper-proof.
- **Measurable acceptance:** Attempted modification detectable via protected archive/integrity chain; evidence of independent storage.
- **Planned verification (T-030):** Integrity chain test (future).

## 7. Mandatory five-vulnerability coverage
| Mandatory class | PNEs | Primary security property | Evidence required later (not yet collected) |
|---|---|---|---|
| CWE-120 Buffer Overflow | PNE-013, PNE-020 | I, A | Legacy and fixed C helper + ASAN and input-boundary test |
| CWE-78 Command Injection | PNE-014, PNE-020 | C, I, A | Legacy shell invocation vs fixed argv invocation + negative regression |
| CWE-639 IDOR | PNE-001–004 | C, I | 3-account unauthorized object read/share/revoke/delete checks |
| CWE-352 CSRF | PNE-008 | I | Missing/invalid/valid token test + controlled demo |
| CWE-1021 Clickjacking | PNE-009 | I | Legacy framed page, fixed browser block + CSP/XFO headers |

## 8. Traceability method for Jira, Phase 3, fixes and tests
**Expected link path:** `PNE-xxx` → `SR-xxx` → `TH-xxx` (created from STRIDE in next phase) → Jira issue key (actual) → fix branch/PR/commit (actual) → `T-xxx` result + screenshot/log (actual). The exported `PNE_Traceability_Register.csv` contains the same identifiers. Threat, Jira, commit and result cells are intentionally blank until those artifacts exist.

**Jira setup:** Create the real course board and a sprint, use Epics → Stories → Tasks. The provided `Jira_Backlog_Seed.csv` seeds one Story for each PNE; its suggested epic names are categories to organize the work, not imaginary Jira issue keys. Create actual epics and link them through your Jira configuration. Link every P0 item to implementation/test work; P1 items to backlog/residual risk. Capture real board screenshots.

**GitHub setup:** Create `SecureApp-Sprint-<TeamName>` (replace placeholder), protect `main`, and require a peer-approved PR where supported. Save actual settings/PR evidence; no PR or reviewed branch is claimed here.

## 9. Open risks, feasibility and review questions
- **Approval gate:** Theme has been selected by team, but teacher uniqueness/approval confirmation is not in this document. Record exact response before claiming it as approved.
- **Native helper integration:** Must be called by the actual upload flow; isolated toy overflow would be insufficient.
- **Local demo vs production:** Local SQLite/file store, SHA-256 digest, and mutable application audit table do not alone provide regulated chain of custody, tamper-proof audit or robust recovery.
- **File integrity nuance:** SHA-256 detects byte changes only when separately verified against a protected reference; it does not prove who created a file or prevent authorized tampering.
- **P1 residual risk:** TLS, backups, login throttling, retention and tamper-evident logs are follow-on hardening. If not implemented, list explicitly as residual risk in the final report.
- **Peer validation prompts:** Confirm max file size, intended file types, who may grant/revoke, audit retention expectations and the production deployment assumption; document team decision rather than inventing client sign-off.

## 10. Phase 2 acceptance checklist
- [ ] Asset inventory covers data, processes, components, and external entities.
- [ ] Stakeholder views include investigator/user, administrator, operator and attacker perspectives.
- [ ] Each of the 30 PNE IDs has an explicit CIA mapping and priority.
- [ ] Every PNE is linked to a testable SR, a planned verification, and a CSV register row.
- [ ] All five required vulnerability classes are mapped to actual CaseVault attack surfaces.
- [ ] Team validates scenarios, signs/records decisions, and saves genuine review evidence.
- [ ] GitHub and Jira setup performed during real sprint work (where appropriate), not fabricated.
- [ ] Phase 3 will fill STRIDE threat IDs, CVSS priorities and risk register links.

## 11. Basis and next-phase dependencies
1. Instructor-issued **CYC386 Midterm Lab Exam | Fall 2026**, especially Sections 2, 4–7 and Section 6.2.
2. **CaseVault Phase 1 Architecture Blueprint**, locked design scope; theme approval still requires real instructor confirmation.
3. Future **Phase 3 THREAT_MODEL.pdf**, not yet produced for this proposed CaseVault design; will supply formal Context/Level-1 DFDs, STRIDE, at least two Attack Trees, CVSS v3.1 high/critical scoring, risk register and residual-risk decisions.

