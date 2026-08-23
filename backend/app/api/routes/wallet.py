import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_current_principal
from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import decrypt_field
from app.db.session import get_db
from app.models.credential import Credential, CredentialClaim, CredentialStatus
from app.models.did import DIDProfile
from app.models.zk import ZKProofRecord
from app.schemas.wallet import (
    CredentialOut,
    GenerateProofRequest,
    GenerateProofResponse,
    WalletMeOut,
)
from app.services.audit.logger import log_event
from app.services.zk.proof_engine import generate_proof

router = APIRouter(prefix="/wallet", tags=["wallet"])


@router.get("/me", response_model=WalletMeOut)
def get_wallet_overview(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    did_profile = db.query(DIDProfile).filter(DIDProfile.user_id == principal.user_id).first()
    total = db.query(Credential).filter(Credential.holder_id == principal.user_id).count()
    active = (
        db.query(Credential)
        .filter(Credential.holder_id == principal.user_id, Credential.status == CredentialStatus.ACTIVE)
        .count()
    )
    return WalletMeOut(
        user_id=uuid.UUID(principal.user_id),
        email=principal.email or "",
        did=did_profile.did if did_profile else None,
        credential_count=total,
        active_credential_count=active,
    )


@router.get("/credentials", response_model=list[CredentialOut])
def list_my_credentials(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    # Object-level scoping: only the authenticated holder's own credentials
    # are ever queried — never filterable by an arbitrary holder_id param,
    # which prevents IDOR against other users' wallets.
    return db.query(Credential).filter(Credential.holder_id == principal.user_id).all()


@router.post("/generate-proof", response_model=GenerateProofResponse)
@limiter.limit(settings.RATE_LIMIT_VERIFY)
def generate_wallet_proof(
    request: Request,
    payload: GenerateProofRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    credential = (
        db.query(Credential)
        .filter(Credential.id == payload.credential_id, Credential.holder_id == principal.user_id)
        .first()
    )
    if credential is None:
        # 404, not 403 — avoids confirming the credential exists but
        # belongs to someone else.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found.")

    if credential.status != CredentialStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Credential is {credential.status}.")

    claim_key = payload.claim_predicate.split("_gte_")[0].split("_eq_")[0]
    claim = (
        db.query(CredentialClaim)
        .filter(CredentialClaim.credential_id == credential.id, CredentialClaim.claim_key == claim_key)
        .first()
    )
    if claim is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Credential has no claim '{claim_key}'.")

    raw_value = decrypt_field(claim.value_encrypted)

    # Verify the issuer's signature on the credential
    from app.core.issuer_crypto import verify_credential_signature

    if not verify_credential_signature(credential, db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential has an invalid or tampered issuer signature.",
        )

    try:
        proof = generate_proof(
            claim_value=raw_value,
            salt=claim.salt,
            credential_commitment=claim.commitment,
            predicate=payload.claim_predicate,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    expires_at = datetime.utcnow() + timedelta(hours=1)
    record = ZKProofRecord(
        id=uuid.uuid4(),
        subject_id=principal.user_id,
        credential_id=credential.id,
        claim_predicate=payload.claim_predicate,
        circuit_id="pedersen_or_proof_v1",
        public_inputs=proof.public_inputs,
        proof_blob=proof.proof_blob,
        expires_at=expires_at,
    )
    db.add(record)

    log_event(
        db, actor_id=principal.user_id, action="zk.proof_generated", resource_type="credential",
        resource_id=str(credential.id), details={"predicate": payload.claim_predicate},
    )
    db.commit()

    return GenerateProofResponse(
        zk_proof_id=record.id,
        claim_predicate=record.claim_predicate,
        public_inputs=record.public_inputs,
        proof_blob=record.proof_blob,
        expires_at=expires_at,
    )
