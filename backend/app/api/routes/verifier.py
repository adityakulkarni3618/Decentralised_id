import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_current_principal
from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.rbac import Role, require_roles
from app.db.session import get_db
from app.models.consent import ConsentRecord, ConsentStatus
from app.models.credential import Credential, CredentialStatus
from app.models.user import User
from app.models.zk import ZKProofRecord
from app.schemas.verifier import (
    ProofRequestCreate,
    ProofRequestOut,
    VerificationHistoryItem,
    VerifyProofRequest,
    VerifyProofResponse,
)
from app.services.audit.logger import log_event
from app.services.zk.proof_engine import verify_proof
from app.models.audit import VerificationLog

router = APIRouter(prefix="/verifier", tags=["verifier"])


@router.post("/proof-request", response_model=ProofRequestOut, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_VERIFY)
def create_proof_request(
    request: Request,
    payload: ProofRequestCreate,
    principal: Principal = Depends(require_roles(Role.VERIFIER)),
    db: Session = Depends(get_db),
):
    subject = db.query(User).filter(User.email == payload.subject_email).first()
    if subject is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subject account not found.")

    expires_at = datetime.utcnow() + timedelta(hours=payload.expires_in_hours)

    consent = ConsentRecord(
        id=uuid.uuid4(),
        subject_id=subject.id,
        verifier_id=principal.user_id,
        requested_scopes=payload.requested_scopes,
        purpose=payload.purpose,
        status=ConsentStatus.PENDING,
        expires_at=expires_at,
    )
    db.add(consent)

    log_event(
        db, actor_id=principal.user_id, action="consent.request_created", resource_type="consent_record",
        resource_id=str(consent.id), details={"subject_id": str(subject.id), "scopes": payload.requested_scopes},
    )
    db.commit()
    db.refresh(consent)

    return ProofRequestOut(
        consent_id=consent.id,
        subject_id=consent.subject_id,
        requested_scopes=consent.requested_scopes,
        status=consent.status,
        requested_at=consent.requested_at,
        expires_at=consent.expires_at,
    )


@router.post("/verify-proof", response_model=VerifyProofResponse)
@limiter.limit(settings.RATE_LIMIT_VERIFY)
def verify_submitted_proof(
    request: Request,
    payload: VerifyProofRequest,
    principal: Principal = Depends(require_roles(Role.VERIFIER)),
    db: Session = Depends(get_db),
):
    consent = (
        db.query(ConsentRecord)
        .filter(ConsentRecord.id == payload.consent_id, ConsentRecord.verifier_id == principal.user_id)
        .first()
    )
    if consent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Consent record not found.")

    proof_record: ZKProofRecord | None = None
    credential: Credential | None = None

    if consent.status != ConsentStatus.APPROVED:
        result = "consent_denied"
    elif consent.expires_at and consent.expires_at < datetime.utcnow():
        result = "expired"
    else:
        proof_record = (
            db.query(ZKProofRecord)
            .filter(ZKProofRecord.id == payload.zk_proof_id, ZKProofRecord.subject_id == consent.subject_id)
            .first()
        )
        if proof_record is None:
            result = "invalid"
        elif proof_record.expires_at and proof_record.expires_at < datetime.utcnow():
            result = "expired"
        elif proof_record.claim_predicate.split("_gte_")[0].split("_eq_")[0] not in "|".join(consent.requested_scopes):
            # The proof's claim must fall within what the subject actually
            # consented to disclose — prevents scope creep beyond consent.
            result = "invalid"
        else:
            credential = db.query(Credential).filter(Credential.id == proof_record.credential_id).first()
            if credential is None or credential.status != CredentialStatus.ACTIVE:
                result = "revoked" if credential and credential.status == CredentialStatus.REVOKED else "invalid"
            else:
                from app.core.issuer_crypto import verify_credential_signature
                from app.core.keystore import is_issuer_key_active

                if not is_issuer_key_active(credential.issuer_id, db):
                    sig_valid = False
                else:
                    sig_valid = verify_credential_signature(credential, db)
                
                if not sig_valid:
                    result = "invalid"
                else:
                    is_valid = verify_proof(
                        public_inputs=proof_record.public_inputs, proof_blob=proof_record.proof_blob
                    )
                    proof_record.is_valid = is_valid
                    proof_record.verified_at = datetime.utcnow()
                    result = "valid" if is_valid and proof_record.public_inputs.get("witness_satisfied") else "invalid"

    verification_log = VerificationLog(
        id=uuid.uuid4(),
        verifier_id=principal.user_id,
        subject_id=consent.subject_id,
        credential_id=proof_record.credential_id if proof_record else None,
        consent_id=consent.id,
        claim_scope=",".join(consent.requested_scopes),
        result=result,
        zk_proof_id=payload.zk_proof_id if result != "consent_denied" else None,
    )
    db.add(verification_log)

    log_event(
        db, actor_id=principal.user_id, action="proof.verify", resource_type="zk_proof_record",
        resource_id=str(payload.zk_proof_id), details={"result": result},
    )
    db.commit()

    return VerifyProofResponse(
        result=result,
        claim_predicate=proof_record.claim_predicate if proof_record else "",
        verified_at=datetime.utcnow(),
        credential_status=credential.status if credential else None,
    )


@router.get("/history", response_model=list[VerificationHistoryItem])
def verification_history(
    principal: Principal = Depends(require_roles(Role.VERIFIER)),
    db: Session = Depends(get_db),
):
    return (
        db.query(VerificationLog)
        .filter(VerificationLog.verifier_id == principal.user_id)
        .order_by(VerificationLog.created_at.desc())
        .limit(200)
        .all()
    )
