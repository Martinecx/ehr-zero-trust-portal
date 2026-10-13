"""
MedVault EHR — Zero-Trust Security Core (prototype backend skeleton)
====================================================================
Run:  pip install fastapi uvicorn pydantic python-jose[cryptography]
      uvicorn app:app --reload --port 8443   (terminate TLS with mTLS in prod)

Design notes
------------
* PEP/PDP split: every API call passes through `policy_guard` (PEP) which
  asks `PolicyEngine.evaluate` (PDP) for an allow/deny/step_up decision.
* ZT principles: verify explicitly (OIDC + TOTP step-up), least privilege
  (RBAC permission sets), assume breach (8-min access tokens, audit hash
  chain, break-glass dual control).
* Production hardening TODOs are marked with # PROD:
"""
from enum import Enum
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel

# ----------------------------------------------------------------- config
JWT_SECRET = "CHANGE-ME-USE-KMS"          # PROD: fetch from Vault/KMS
ALGO = "HS256"
ACCESS_TTL_MIN = 8                        # ZT: short-lived access token
STEPUP_TTL_MIN = 2                        # ZT: fresh MFA for SENSITIVE data

# ------------------------------------------------------------- RBAC model
class Role(str, Enum):
    DOCTOR = "doctor"
    NURSE = "nurse"
    PATIENT = "patient"
    ADMIN = "admin"
    AUDITOR = "auditor"

# resource -> set of roles allowed to perform "read" (least privilege)
RBAC_MATRIX: dict[str, set[Role]] = {
    "patient.chart.full":     {Role.DOCTOR},
    "patient.chart.vitals":   {Role.DOCTOR, Role.NURSE},
    "patient.chart.self":     {Role.PATIENT},
    "rx.write":               {Role.DOCTOR},
    "admin.users":            {Role.ADMIN},      # PROD: wrap in JIT elevation
    "audit.read":             {Role.AUDITOR},
    "audit.metadata":         {Role.AUDITOR, Role.ADMIN},
}

SENSITIVE_RESOURCES = {"patient.chart.full"}     # 42 CFR Part 2 / psych notes

# ------------------------------------------------------- zero-trust PDP
class DevicePosture(BaseModel):
    os_patched: bool = True
    disk_encrypted: bool = True
    edr_healthy: bool = True
    geo_allowed: bool = True

    @property
    def trust_score(self) -> int:
        score = 100
        for ok in (self.os_patched, self.disk_encrypted, self.edr_healthy, self.geo_allowed):
            if not ok:
                score -= 15
        return score

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"

class PolicyEngine:
    """Evaluates: role (RBAC) + device trust + step-up freshness + resource tier."""

    TRUST_FLOOR = 85

    @staticmethod
    def evaluate(role: Role, resource: str, posture: DevicePosture,
                 stepup_at: Optional[datetime], consent_valid: bool = True) -> Decision:
        if posture.trust_score < PolicyEngine.TRUST_FLOOR:
            return Decision.DENY                                   # device-posture
        if role not in RBAC_MATRIX.get(resource, set()):
            return Decision.DENY                                   # rbac-core (deny by default)
        if resource == "patient.chart.self" and not consent_valid:
            return Decision.DENY                                   # patient consent gate
        if resource in SENSITIVE_RESOURCES:
            fresh = stepup_at and (datetime.now(timezone.utc) - stepup_at
                                   < timedelta(minutes=STEPUP_TTL_MIN))
            if not fresh:
                return Decision.STEP_UP                            # pii-tier2
        return Decision.ALLOW

# ----------------------------------------------------------- auth (stub)
oauth2 = OAuth2PasswordBearer(tokenUrl="token")

def fake_user_token(role: Role) -> str:  # PROD: OIDC code flow via Keycloak/Entra ID
    return jwt.encode(
        {"sub": "demo-user", "role": role.value,
         "stepup_at": None, "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TTL_MIN)},
        JWT_SECRET, algorithm=ALGO)

def step_up(role: Role) -> str:          # PROD: verify TOTP/WebAuthn assertion
    return jwt.encode(
        {"sub": "demo-user", "role": role.value,
         "stepup_at": datetime.now(timezone.utc).isoformat(),
         "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TTL_MIN)},
        JWT_SECRET, algorithm=ALGO)

def current_principal(token: str = Depends(oauth2)):
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
        if datetime.fromtimestamp(claims["exp"], timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(401, "token expired (8-min TTL)")  # session-ttl
        return claims
    except JWTError:
        raise HTTPException(401, "invalid token")

# ------------------------------------------------------- audit hash chain
_audit_chain = "genesis"
def audit(actor: str, action: str, resource: str, decision: str) -> str:
    global _audit_chain
    import hashlib
    rec = f"{datetime.now(timezone.utc).isoformat()}|{actor}|{action}|{resource}|{decision}|{_audit_chain}"
    _audit_chain = hashlib.sha256(rec.encode()).hexdigest()[:16]
    # PROD: write to WORM store (S3 Object Lock) + stream to SIEM (CEF/syslog)
    return _audit_chain

# ------------------------------------------------------------- API (PEP)
app = FastAPI(title="MedVault Zero-Trust EHR API", version="0.1.0")

def policy_guard(request: Request, resource: str, posture: DevicePosture,
                 claims=Depends(current_principal)) -> str:
    stepup_at = (datetime.fromisoformat(claims["stepup_at"])
                 if claims.get("stepup_at") else None)
    d = PolicyEngine.evaluate(Role(claims["role"]), resource, posture, stepup_at)
    audit(claims["sub"], request.method, resource, d.value)
    if d == Decision.DENY:
        raise HTTPException(403, f"PDP DENY on {resource} (role/trust/consent)")
    if d == Decision.STEP_UP:
        raise HTTPException(401, "STEP_UP required: fresh MFA (<2 min) — policy pii-tier2")
    return claims["sub"]

@app.get("/fhir/Patient/{pid}/$summary")
def patient_summary(pid: str, actor: str = Depends(
        lambda r, p="patient.chart.full": policy_guard(r, p, DevicePosture()))):
    return {"resourceType": "Bundle", "actor": actor, "patient": pid,
            "note": "Returned only after PDP ALLOW"}

@app.get("/fhir/Observation")
def vitals(actor: str = Depends(
        lambda r: policy_guard(r, "patient.chart.vitals", DevicePosture()))):
    return {"resourceType": "Bundle", "type": "vitals", "actor": actor}

@app.get("/audit/events")
def audit_events(actor: str = Depends(
        lambda r: policy_guard(r, "audit.read", DevicePosture()))):
    return {"chain_tip": _audit_chain, "events": "WORM-backed store"}

@app.post("/auth/token")
def token(role: Role):
    return {"access_token": fake_user_token(role), "token_type": "bearer",
            "expires_in": ACCESS_TTL_MIN * 60}

@app.post("/auth/step-up")
def do_step_up(role: Role):
    return {"access_token": step_up(role), "token_type": "bearer",
            "step_up_valid_minutes": STEPUP_TTL_MIN}

if __name__ == "__main__":
    # quick PDP self-test
    p = DevicePosture()
    assert PolicyEngine.evaluate(Role.DOCTOR, "patient.chart.full", p, None) == Decision.STEP_UP
    assert PolicyEngine.evaluate(Role.NURSE, "patient.chart.full", p, None) == Decision.DENY
    assert PolicyEngine.evaluate(Role.DOCTOR, "patient.chart.full",
                                 DevicePosture(os_patched=False, disk_encrypted=False), None) == Decision.DENY
    print("PDP self-tests passed.")
