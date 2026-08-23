import hashlib
import os
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_current_principal
from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import encrypt_field
from app.db.session import get_db
from app.models.ai import DocumentStatus, DocumentUpload, FaceMatchResult, FraudScore
from app.schemas.ai import (
    DocumentVerifyResponse,
    FaceVerifyResponse,
    FraudScoreRequest,
    FraudScoreResponse,
    LivenessCheckResponse,
)
from app.services.ai.document_verification import analyze_document
from app.services.ai.face_verification import assess_liveness, verify_face
from app.services.ai.fraud_scoring import assess_fraud, compute_behavioral_signals
from app.services.audit.logger import log_event

router = APIRouter(prefix="/ai", tags=["ai"])

MAX_UPLOAD_BYTES = settings.MAX_UPLOAD_MB * 1024 * 1024
ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp"}


async def _read_validated_upload(file: UploadFile) -> bytes:
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported file type.")
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds size limit.")
    if len(data) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file upload.")
    return data


def _persist_encrypted(data: bytes, subdir: str) -> tuple[str, str]:
    """
    Encrypts raw bytes with AES-256-GCM and writes them to the (private,
    non-web-served) upload directory. Returns (storage_path, iv_hex).
    Never writes plaintext document/selfie bytes to disk or logs.
    """
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = hashlib.sha256(settings.FIELD_ENCRYPTION_KEY.encode()).digest()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    directory = os.path.join(settings.UPLOAD_DIR, subdir)
    os.makedirs(directory, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.enc"
    path = os.path.join(directory, filename)
    with open(path, "wb") as f:
        f.write(ciphertext)

    return path, base64.b64encode(nonce).decode()


@router.post("/verify-document", response_model=DocumentVerifyResponse)
@limiter.limit(settings.RATE_LIMIT_AI)
async def verify_document(
    request: Request,
    document_type: str,
    file: UploadFile = File(...),
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    data = await _read_validated_upload(file)
    fingerprint = hashlib.sha256(data).hexdigest()

    storage_path, iv = _persist_encrypted(data, "documents")

    analysis = analyze_document(data)
    del data  # raw bytes are never retained beyond this scope

    upload = DocumentUpload(
        id=uuid.uuid4(),
        user_id=principal.user_id,
        document_type=document_type,
        encrypted_storage_path=storage_path,
        encrypted_storage_iv=iv,
        sha256_fingerprint=fingerprint,
        status=DocumentStatus.PROCESSED,
        ocr_extracted_fields=analysis.ocr_extracted_fields,
        tamper_indicators=analysis.tamper_indicators,
    )
    db.add(upload)

    log_event(
        db, actor_id=principal.user_id, action="ai.document_verified", resource_type="document_upload",
        resource_id=str(upload.id), ip_address=request.client.host if request.client else None,
        details={"tamper_risk_score": analysis.tamper_risk_score},
    )
    db.commit()
    db.refresh(upload)

    return DocumentVerifyResponse(
        document_upload_id=upload.id,
        document_type=document_type,
        ocr_extracted_fields=upload.ocr_extracted_fields,
        tamper_indicators=upload.tamper_indicators,
        tamper_risk_score=analysis.tamper_risk_score,
        status=upload.status,
    )


@router.post("/verify-face", response_model=FaceVerifyResponse)
@limiter.limit(settings.RATE_LIMIT_AI)
async def verify_face_endpoint(
    request: Request,
    document_upload_id: uuid.UUID,
    selfie: UploadFile = File(...),
    document_photo: UploadFile = File(...),
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    upload = (
        db.query(DocumentUpload)
        .filter(DocumentUpload.id == document_upload_id, DocumentUpload.user_id == principal.user_id)
        .first()
    )
    if upload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document upload not found.")

    selfie_bytes = await _read_validated_upload(selfie)
    doc_photo_bytes = await _read_validated_upload(document_photo)

    result = verify_face(selfie_bytes, doc_photo_bytes, threshold=settings.FACE_MATCH_THRESHOLD)
    del selfie_bytes, doc_photo_bytes

    commitment_source = f"{principal.user_id}:{result.similarity_score}:{uuid.uuid4().hex}"
    embedding_commitment = encrypt_field(hashlib.sha256(commitment_source.encode()).hexdigest())

    match = FaceMatchResult(
        id=uuid.uuid4(),
        user_id=principal.user_id,
        document_upload_id=upload.id,
        similarity_score=result.similarity_score,
        match_passed=result.match_passed,
        embedding_commitment_encrypted=embedding_commitment,
    )
    db.add(match)

    log_event(
        db, actor_id=principal.user_id, action="ai.face_verified", resource_type="face_match_result",
        resource_id=str(match.id), ip_address=request.client.host if request.client else None,
        details={"match_passed": result.match_passed},
    )
    db.commit()
    db.refresh(match)

    return FaceVerifyResponse(
        face_match_id=match.id,
        similarity_score=result.similarity_score,
        match_passed=result.match_passed,
        threshold=settings.FACE_MATCH_THRESHOLD,
    )


@router.post("/liveness-check", response_model=LivenessCheckResponse)
@limiter.limit(settings.RATE_LIMIT_AI)
async def liveness_check(
    request: Request,
    frames: list[UploadFile] = File(...),
    face_match_id: uuid.UUID | None = None,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    if len(frames) < 2 or len(frames) > 10:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Submit between 2 and 10 frames.")

    frame_bytes = [await _read_validated_upload(f) for f in frames]
    result = assess_liveness(frame_bytes)
    del frame_bytes

    if face_match_id is not None:
        match = (
            db.query(FaceMatchResult)
            .filter(FaceMatchResult.id == face_match_id, FaceMatchResult.user_id == principal.user_id)
            .first()
        )
        if match is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Face match record not found.")
        match.liveness_passed = result.liveness_passed
        match.liveness_score = result.liveness_score
        db.commit()

    return LivenessCheckResponse(
        liveness_score=result.liveness_score,
        liveness_passed=result.liveness_passed,
        signals=result.signals,
    )


@router.post("/fraud-score", response_model=FraudScoreResponse)
@limiter.limit(settings.RATE_LIMIT_AI)
def fraud_score(
    request: Request,
    payload: FraudScoreRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    document = (
        db.query(DocumentUpload)
        .filter(DocumentUpload.id == payload.document_upload_id, DocumentUpload.user_id == principal.user_id)
        .first()
    )
    face_match = (
        db.query(FaceMatchResult)
        .filter(FaceMatchResult.id == payload.face_match_id, FaceMatchResult.user_id == principal.user_id)
        .first()
    )
    if document is None or face_match is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Referenced AI results not found.")

    document_tamper_risk = document.tamper_indicators.get("copy_move_similarity", 0.0)
    # Combine all three document tamper sub-signals into one risk figure.
    doc_risk = min(
        1.0,
        document.tamper_indicators.get("noise_variance_inconsistency", 0.0) * 0.4
        + document.tamper_indicators.get("edge_density_inconsistency", 0.0) * 0.35
        + document.tamper_indicators.get("copy_move_similarity", 0.0) * 0.25,
    )

    behavioral = compute_behavioral_signals(db, principal.user_id)
    assessment = assess_fraud(
        document_tamper_risk=doc_risk,
        face_similarity_score=face_match.similarity_score,
        face_match_passed=face_match.match_passed,
        liveness_passed=face_match.liveness_passed,
        behavioral_signals=behavioral,
    )

    record = FraudScore(
        id=uuid.uuid4(),
        user_id=principal.user_id,
        document_upload_id=document.id,
        face_match_id=face_match.id,
        document_score=assessment.document_score,
        face_score=assessment.face_score,
        behavioral_score=assessment.behavioral_score,
        overall_score=assessment.overall_score,
        status=assessment.status,
        signals=assessment.signals,
        ip_address=request.client.host if request.client else None,
    )
    db.add(record)

    log_event(
        db, actor_id=principal.user_id, action="ai.fraud_scored", resource_type="fraud_score",
        resource_id=str(record.id), details={"status": assessment.status, "overall_score": assessment.overall_score},
    )
    db.commit()
    db.refresh(record)

    return FraudScoreResponse(
        fraud_score_id=record.id,
        document_score=record.document_score,
        face_score=record.face_score,
        behavioral_score=record.behavioral_score,
        overall_score=record.overall_score,
        status=record.status,
        signals=record.signals,
    )
