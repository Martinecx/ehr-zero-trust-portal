# MedVault Zero-Trust EHR Portal — Prototype Package

## Contents
- `prototype/index.html` — zero-install interactive prototype (demo MFA code: **314159**)
- `backend/app.py` — FastAPI security core: RBAC + zero-trust PDP/PEP (10 passing policy tests)
- `docs/PROJECT_PROPOSAL.md` — full project proposal (scope, architecture, plan, budget)

## Quick start
1. **Prototype:** open `prototype/index.html` in any browser. Try disabling device-posture
   checkboxes (trust drops, PHI blocks), opening Jonah Reyes' chart (step-up MFA),
   break-glass, and the auditor's hash-chained log.
2. **Backend:**
   ```bash
   pip install fastapi uvicorn "python-jose[cryptography]"
   python backend/app.py            # PDP self-tests
   uvicorn backend.app:app --reload # API on :8000
   ```
