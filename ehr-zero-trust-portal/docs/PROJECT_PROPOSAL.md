# MedVault — Zero-Trust, Role-Based Electronic Health Records Portal
## Project Proposal & Prototype Documentation

| | |
|---|---|
| **Project** | MedVault Zero-Trust EHR Portal |
| **Version** | 0.1 (prototype) |
| **Date** | October 2026 |
| **Prepared for** | Healthcare provider pilot program |
| **Status** | Proposal — seeking approval for Phase 1 |

---

## 1. Executive Summary

MedVault is a web-based Electronic Health Records (EHR) portal that applies **zero-trust architecture (ZTA)** and **role-based access control (RBAC)** to protected health information (PHI). The core premise: *no user, device, or network is trusted by default* — every request is authenticated, authorized, and continuously evaluated against device posture, role permissions, data sensitivity tier, and consent state.

The prototype delivered with this proposal demonstrates the full zero-trust control loop in a working browser application, plus a FastAPI security core whose policy engine passes 10 automated authorization tests (default-deny, least privilege, device-posture gating, step-up authentication, consent enforcement).

**Ask:** approve a 6-month, 5-phase implementation (§9) with a team of 6 (§10) and an estimated budget of **$486k** (§11).

---

## 2. Background & Problem Statement

Healthcare is the most-breached sector: the majority of breaches involve insiders or compromised credentials, and the average healthcare breach costs $9–10M — the highest of any industry. Legacy EHR portals rely on perimeter security: one login grants broad, standing access for hours or days.

Specific gaps in typical deployments:

1. **Standing privileges** — clinicians retain access to all patients, not just their panel (violates HIPAA "minimum necessary").
2. **Weak session hygiene** — long-lived tokens, no continuous verification.
3. **Flat data model** — sensitive records (behavioral health, HIV, SUD under 42 CFR Part 2) are not segmented.
4. **Weak audit integrity** — logs that privileged insiders can alter.
5. **No device trust** — unmanaged, unpatched devices read PHI.

---

## 3. Objectives

| # | Objective | Success metric |
|---|---|---|
| O1 | Enforce default-deny, per-request authorization | 100% API calls pass PDP; 0 privilege-escalation findings in pen-test |
| O2 | Implement least-privilege RBAC for 5 roles | Access-review violations = 0 per quarter |
| O3 | Segment Tier-2 sensitive data (42 CFR Part 2) | Step-up MFA on 100% of Tier-2 reads; dual-control on break-glass |
| O4 | Continuous device/session verification | Trust score evaluated per request; token TTL ≤ 8 min |
| O5 | Tamper-evident audit trail | Hash-chained, WORM-stored logs; auditor sign-off |
| O6 | Patient consent enforcement in the policy layer | 100% of shared-data access filtered by active consents |

---

## 4. Scope

**In scope:** clinician/patient/auditor portals; RBAC policy engine; device posture service; step-up MFA; break-glass workflow; consent management; immutable audit log; FHIR R4 read APIs; SMART on FHIR app launch.

**Out of scope (Phase 1):** billing/RCM, e-prescribing of controlled substances beyond stub integration, inpatient CPOE, imaging (PACS) viewers, mobile native apps.

---

## 5. Architecture

```
                          ┌────────────────────────────────────────────┐
        Clinician/Nurse/  │                 EDGE                        │
        Patient/Auditor   │   WAF · mTLS termination · rate limiting   │
               │          └─────────────────┬──────────────────────────┘
               ▼                            ▼
      ┌─────────────────┐      ┌──────────────────────┐
      │  React SPA      │      │  FastAPI API GW (PEP)│──► policy_guard on EVERY call
      │  (prototype:    │─────►│  JWT 8-min TTL       │
      │  single HTML)   │      └─────────┬────────────┘
      └─────────────────┘                ▼
                              ┌──────────────────────┐
                              │  PDP (OPA/Rego-style)│  role + posture + tier + consent
                              │  PolicyEngine        │
                              └─────────┬────────────┘
              ┌───────────────┬─────────┼─────────┬──────────────┐
              ▼               ▼         ▼         ▼              ▼
        ┌───────────┐ ┌────────────┐ ┌───────┐ ┌────────┐ ┌────────────┐
        │ IdP (OIDC)│ │ Device     │ │ TOTP/ │ │ Consent│ │ Audit WORM │
        │ + MFA     │ │ Posture    │ │ WebA- │ │ svc    │ │ + SIEM     │
        │ (Keycloak)│ │ (MDM integ)│ │ uthn  │ │        │ │ stream     │
        └───────────┘ └────────────┘ └───────┘ └────────┘ └────────────┘
              │
        ┌─────┴──────┐
        │ FHIR Svc   │──► FHIR R4 server (PostgreSQL, encrypted at rest, column-level enc for Tier-2)
        └────────────┘
```

**Zero-trust mapping (NIST SP 800-207):**

| NIST principle | Implementation |
|---|---|
| Resource-based access | Every API route is a protected resource in the RBAC matrix |
| Strict authentication | OIDC SSO + TOTP/WebAuthn; step-up for sensitive data |
| Secure enterprise / micro-segmentation | API gateway per-service policies; PHI DB reachable only from FHIR service |
| Device posture | MDM-reported posture → trust score; floor 85/100 for any PHI read |
| Session recording & behavioral analytics | Hash-chained audit events streamed to SIEM; UEBA later phase |

---

## 6. Security Design

### 6.1 Roles & permissions (least privilege)

| Resource | Doctor | Nurse | Patient | Admin | Auditor |
|---|---|---|---|---|---|
| `patient.chart.full` (incl. Tier-2) | ✅ + step-up | — | own only | — | metadata |
| `patient.chart.vitals` | ✅ | ✅ | own only | — | metadata |
| `rx.write` | ✅ + step-up | — | — | — | — |
| `admin.users` | — | — | — | ✅ JIT | — |
| `audit.read` | — | — | — | — | ✅ |
| *(anything not listed)* | deny | deny | deny | deny | deny |

### 6.2 Policy engine decision flow (per request)

1. **Device posture** — trust score < 85 ⇒ `DENY` (policy `device-posture`)
2. **RBAC** — role ∉ resource's role set ⇒ `DENY` (default-deny; policy `rbac-core`)
3. **Consent** — patient-scoped resource without valid consent ⇒ `DENY`
4. **Sensitivity tier** — Tier-2 resource without fresh MFA (< 2 min) ⇒ `STEP_UP` (policy `pii-tier2`)
5. Otherwise `ALLOW` — full event written to audit chain.

All 10 rule combinations are covered by automated tests (see `backend/app.py` header; test matrix reproduced in §13).

### 6.3 Break-glass emergency access

- Triggered from the chart view; requires second-clinician co-sign within 15 minutes (dual control).
- Auto-creates a compliance incident; access review within 72 h.
- Every break-glass event is flagged in the auditor dashboard.

### 6.4 Audit integrity

Each log entry embeds the hash of its predecessor (SHA-256 chain). Storage is WORM (S3 Object Lock / Azure Immutable Storage), mirrored in real time to the SIEM. Auditors receive read-only, metadata-level access — they can verify integrity but never read clinical content.

---

## 7. Compliance Mapping

| Requirement | Control implemented |
|---|---|
| HIPAA §164.312(a) Access Control | Unique IDs, RBAC, emergency access procedure |
| HIPAA §164.312(b) Audit Controls | Hash-chained WORM audit, SIEM streaming |
| HIPAA §164.312(c) Integrity | Hash chain + signed FHIR resources |
| HIPAA §164.312(d) Person/Entity Auth | OIDC + MFA + step-up |
| 42 CFR Part 2 | Tier-2 segmentation, consent-gated sharing, excluded from HIE exchange by default |
| GDPR Art. 32 | Encryption at rest/in transit, least privilege, tokenization of identifiers |

---

## 8. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Frontend | React + TypeScript (prototype: vanilla JS single-file) | Fast iteration; component reuse |
| API | FastAPI (Python) + Pydantic | Async, typed, rapid security iteration |
| PDP | OPA (Rego) in prod; engine mirrored in code here | Signed, versioned policy bundles |
| IdP / MFA | Keycloak (OIDC) + TOTP/WebAuthn | Open source, self-hostable |
| AuthZ tokens | JWT, 8-min access TTL | Short-lived = assume breach |
| Database | PostgreSQL + pgcrypto; column-level encryption for Tier-2 | Auditable, encrypted at rest |
| FHIR | HAPI FHIR server; SMART on FHIR | Interop standard |
| Audit | S3 Object Lock + syslog/SIEM | WORM + real-time analytics |
| Device posture | MDM (Intune/Jamf) webhook feed | Real trust signals |
| Infra | Kubernetes, mTLS via service mesh (Istio/Linkerd) | Micro-segmentation |

---

## 9. Implementation Plan (6 months)

| Phase | Weeks | Deliverables |
|---|---|---|
| **P0 — Foundations** | 1–3 | Threat model (STRIDE), policy schema, IdP + MFA stand-up, CI/CD with security gates |
| **P1 — Core security services** | 4–8 | PDP/PEP on all routes, RBAC matrix, JWT lifecycle, audit hash chain, device-posture ingestion |
| **P2 — Clinical portal MVP** | 9–14 | Doctor/nurse/patient dashboards, FHIR read APIs, consent management |
| **P3 — Sensitive data & break-glass** | 15–18 | Tier-2 segmentation, step-up MFA, break-glass dual-control, Part-2 compliance tests |
| **P4 — Hardening & interop** | 19–23 | Pen-test + remediation, SMART on FHIR, HIE/TEFCA gateway, UEBA v1 |
| **P5 — Pilot & rollout** | 24–26 | 2-department pilot (60 users), training, go/no-go, phased rollout plan |

**Milestones:** M1 (wk 8) PDP enforced on 100% routes · M2 (wk 14) portal MVP sign-off · M3 (wk 23) security pen-test passed · M4 (wk 26) pilot live.

---

## 10. Team (6 FTE)

| Role | FTE | Responsibility |
|---|---|---|
| Tech Lead / Security Architect | 1 | ZTA design, PDP, threat model |
| Backend Engineers | 2 | FastAPI services, FHIR, audit pipeline |
| Frontend Engineer | 1 | React portal, SMART apps |
| DevSecOps | 1 | K8s, mTLS, CI/CD security gates, MDM integration |
| Compliance & QA Lead | 1 | HIPAA/Part-2 test matrix, pen-test mgmt, UAT |

---

## 11. Budget Estimate (Phase 1, 6 months)

| Item | Estimate |
|---|---|
| Personnel (6 FTE × 6 mo, blended $13k/mo) | $468,000 |
| Cloud infra (dev/staging/prod, HA) | $9,500 |
| Security tooling (SIEM, SAST/DAST, pentest) | $6,500 |
| Training & contingency (~5%) | $2,000 |
| **Total** | **≈ $486,000** |

---

## 12. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Clinician friction (MFA fatigue) | High | Medium | Number matching, WebAuthn passkeys, risk-based step-up only |
| Legacy HL7/v2 integration delays | Medium | Medium | Interface engine (Mirth) in P2; FHIR facade pattern |
| False positives in device posture | Medium | Low | Grace period + self-remediation portal (shown in prototype) |
| Insider misuse of break-glass | Low | High | Dual control + 72-h mandatory review + UEBA anomaly scoring |
| Vendor lock-in on IdP | Low | Low | Open standards (OIDC/SAML, SCIM) throughout |

---

## 13. Prototype Validation

The delivered prototype (`prototype/index.html`) demonstrates: SSO+MFA login with lockout policy, role-specific navigation for 5 roles, device-posture trust scoring (disable checks → live trust drop → PHI blocked), step-up MFA modal for Tier-2 charts, break-glass flow, patient consent grant/revoke, and the hash-chained audit viewer.

The backend skeleton (`backend/app.py`) implements the PDP/PEP split; the policy engine passes these 10 automated tests:

```
PASS doctor + fresh stepup            -> ALLOW
PASS doctor + stale stepup            -> STEP_UP
PASS nurse / full chart               -> DENY   (least privilege)
PASS nurse / vitals                   -> ALLOW
PASS patient / own chart              -> ALLOW
PASS 1 posture failure (score 85)     -> ALLOW
PASS 2 posture failures (score 70)    -> DENY   (device floor 85)
PASS patient consent revoked          -> DENY
PASS unknown resource (default deny)  -> DENY
PASS auditor / audit.read             -> ALLOW
```

**Run it yourself:**
```bash
# Frontend prototype — no build needed
open prototype/index.html            # demo MFA code: 314159

# Backend (requires: pip install fastapi uvicorn python-jose[cryptography])
python backend/app.py                # runs PDP self-tests
uvicorn backend.app:app --reload     # serves the API
```

---

## 14. Future Work (post-Phase 1)

- **ABAC extension** — attributes (department, care relationship, location) layered onto RBAC.
- **Patient-mediated exchange** — 21st Century Cures Act information-blocking compliant APIs.
- **UEBA v2** — behavioral anomaly scoring feeding dynamic trust.
- **Zero-trust network overlay** — micro-segmentation down to database connection level.
- **Native mobile** — device-bound keys, biometric step-up.

---

*Appendices available on request: A) Threat model (STRIDE), B) Rego policy bundle schema, C) FHIR resource/permission matrix, D) DPIA template.*
