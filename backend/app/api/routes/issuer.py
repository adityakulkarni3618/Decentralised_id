import hashlib
import secrets
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_current_principal
from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.rbac import Role, require_roles
from app.core.issuer_crypto import ensure_issuer_public_key, sign_commitment
from app.core.security import encrypt_field
from app.db.session import get_db
from app.models.credential import Credential, CredentialClaim, CredentialStatus
from app.models.user import IssuerProfile, User
from app.schemas.issuer import (
    IssueCredentialRequest,
    IssueCredentialResponse,
    IssuerCredentialOut,
    IssuerDashboardOut,
    RevokeCredentialRequest,
)
from app.services.audit.logger import log_event

router = APIRouter(prefix="/issuer", tags=["issuer"])


def _get_active_issuer_profile(db: Session, user_id: str) -> IssuerProfile:
    profile = db.query(IssuerProfile).filter(IssuerProfile.user_id == user_id).first()
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issuer profile not found.")
    if profile.is_blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This issuer account has been blocked.")
    if not profile.is_approved:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Issuer is pending admin approval.")
    return profile


@router.post("/credentials", response_model=IssueCredentialResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_DEFAULT)
def issue_credential(
    request: Request,
    payload: IssueCredentialRequest,
    principal: Principal = Depends(require_roles(Role.ISSUER)),
    db: Session = Depends(get_db),
):
    issuer_profile = _get_active_issuer_profile(db, principal.user_id)
    ensure_issuer_public_key(db, principal.user_id)

    holder = db.query(User).filter(User.email == payload.holder_email).first()
    if holder is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Holder account not found.")

    expires_at = (
        datetime.utcnow() + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None
    )

    # Build one canonical, order-stable commitment over all claims for the
    # top-level credential signature, and per-claim commitments for ZK use.
    claim_commitments = []
    claim_rows = []
    for key in sorted(payload.claims.keys()):
        value = payload.claims[key]
        salt = secrets.token_hex(16)
        commitment = hashlib.sha256(f"{salt}{value}".encode()).hexdigest()
        claim_commitments.append(f"{key}:{commitment}")
        claim_rows.append((key, value, salt, commitment))

    overall_commitment = hashlib.sha256("|".join(claim_commitments).encode()).hexdigest()
    signing_key_id = f"issuer:{issuer_profile.id}"
    signature = sign_commitment(overall_commitment, principal.user_id, db)

    # Encrypt the full raw claims payload as an audit-recoverable backup
    # (e.g. for issuer-initiated disputes); individual per-claim values
    # are also separately encrypted below for granular ZK proof access.
    claims_encrypted = encrypt_field(str(sorted(payload.claims.items())))

    credential = Credential(
        id=uuid.uuid4(),
        holder_id=holder.id,
        issuer_id=principal.user_id,
        credential_type=payload.credential_type,
        status=CredentialStatus.ACTIVE,
        claims_encrypted=claims_encrypted,
        claims_commitment=overall_commitment,
        issuer_signature=signature,
        signing_key_id=signing_key_id,
        issued_at=datetime.utcnow(),
        expires_at=expires_at,
    )
    db.add(credential)
    db.flush()

    for key, value, salt, commitment in claim_rows:
        db.add(
            CredentialClaim(
                id=uuid.uuid4(),
                credential_id=credential.id,
                claim_key=key,
                value_encrypted=encrypt_field(value),
                commitment=commitment,
                salt=salt,
            )
        )

    log_event(
        db, actor_id=principal.user_id, action="credential.issue", resource_type="credential",
        resource_id=str(credential.id), details={"holder_id": str(holder.id), "type": payload.credential_type},
    )
    db.commit()
    db.refresh(credential)

    return IssueCredentialResponse(
        credential_id=credential.id,
        holder_id=credential.holder_id,
        credential_type=credential.credential_type,
        claims_commitment=credential.claims_commitment,
        issuer_signature=credential.issuer_signature,
        issued_at=credential.issued_at,
        expires_at=credential.expires_at,
        blockchain_tx_hash=credential.blockchain_tx_hash,
    )


@router.get("/credentials", response_model=list[IssuerCredentialOut])
def list_issued_credentials(
    principal: Principal = Depends(require_roles(Role.ISSUER)),
    db: Session = Depends(get_db),
):
    # Scoped strictly to credentials issued by the authenticated issuer.
    return db.query(Credential).filter(Credential.issuer_id == principal.user_id).all()


@router.post("/revoke", status_code=status.HTTP_200_OK)
def revoke_credential(
    payload: RevokeCredentialRequest,
    principal: Principal = Depends(require_roles(Role.ISSUER)),
    db: Session = Depends(get_db),
):
    credential = (
        db.query(Credential)
        .filter(Credential.id == payload.credential_id, Credential.issuer_id == principal.user_id)
        .first()
    )
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found.")

    if credential.status == CredentialStatus.REVOKED:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Credential is already revoked.")

    credential.status = CredentialStatus.REVOKED
    credential.revoked_at = datetime.utcnow()
    credential.revocation_reason = payload.reason

    log_event(
        db, actor_id=principal.user_id, action="credential.revoke", resource_type="credential",
        resource_id=str(credential.id), details={"reason": payload.reason},
    )
    db.commit()
    return {"credential_id": str(credential.id), "status": credential.status}


@router.get("/dashboard", response_model=IssuerDashboardOut)
def issuer_dashboard(
    principal: Principal = Depends(require_roles(Role.ISSUER)),
    db: Session = Depends(get_db),
):
    profile = db.query(IssuerProfile).filter(IssuerProfile.user_id == principal.user_id).first()
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issuer profile not found.")

    base_q = db.query(Credential).filter(Credential.issuer_id == principal.user_id)
    total_issued = base_q.count()
    total_active = base_q.filter(Credential.status == CredentialStatus.ACTIVE).count()
    total_revoked = base_q.filter(Credential.status == CredentialStatus.REVOKED).count()
    since = datetime.utcnow() - timedelta(days=30)
    issued_30d = base_q.filter(Credential.issued_at >= since).count()

    return IssuerDashboardOut(
        organization_name=profile.organization_name,
        is_approved=profile.is_approved,
        total_issued=total_issued,
        total_active=total_active,
        total_revoked=total_revoked,
        issued_last_30_days=issued_30d,
    )
