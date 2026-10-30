# Team contribution process

1. Protect `main` in GitHub; no direct commits or force-pushes.
2. Create branch `feature/short-description` or `fix/short-description` from current main.
3. Link every PR to Jira issue/PNE ID, e.g., `PNE-02 / R-02 object-level authorization`.
4. Run `pytest -q tests` locally and obtain one different member's approval; merge only after CI passes.
5. Each team member must create meaningful work and review work written by other members. Never fake review or split attribution after the fact.
6. Never commit `.env`, credentials, personal information or real production files.
