# Evidence checklist — only the next essential steps

1. **Jira:** save CSV import detailed log from actual successful import; capture the 61 items under the CVLT project, verify 5 epics with children. Check issue types/parents before claiming full traceability.
2. **App:** run `docker compose up --build -d` and capture `docker compose ps` plus the real browser dashboard.
3. **Tests:** run local pytest and demo scripts. Capture entire console output; preserve generated text under `evidence/`.
4. **GitHub:** create `feature/casevault-app`, commit, obtain actual reviewer approval, merge; retain PR URL and snapshot.
5. **CI:** run Actions on PR; inspect **both** jobs. Download actual SAST and DAST artifacts; fix failures rather than hiding them. Enable the required passing status checks on main when jobs exist.
6. **Final:** attach logs, screenshots and actual Jira keys to SECURITY_IMPLEMENTATION.md, SECURITY_TEST_REPORT.md, and 18–30-page final PDF; record 6–10 minute technical video.

Never store passwords, tokens, `.env`, real case evidence, personal data, or test cookies in a public repository.
