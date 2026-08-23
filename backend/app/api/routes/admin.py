from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_current_principal
from app.core.rbac import Role, require_roles
from app.db.session import get_db
from app.models.audit import AuditEvent
from app.models.user import IssuerProfile, User
from app.schemas.admin import (
    AdminAuditLogOut,
    AdminIssuerOut,
    AdminUserOut,
    ApproveIssuerRequest,
    BlockIssuerRequest,
)
from app.core.issuer_crypto import ensure_issuer_public_key
from app.services.audit.logger import log_event, verify_chain

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_roles(Role.ADMIN))])


@router.get("/users", response_model=list[AdminUserOut])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).order_by(User.created_at.desc()).limit(500).all()


@router.get("/logs", response_model=list[AdminAuditLogOut])
def list_audit_logs(db: Session = Depends(get_db)):
    return db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(500).all()


@router.get("/logs/integrity")
def check_log_integrity(db: Session = Depends(get_db)):
    intact, broken_id = verify_chain(db)
    return {"intact": intact, "first_broken_record_id": broken_id}


@router.get("/issuers", response_model=list[AdminIssuerOut])
def list_issuers(db: Session = Depends(get_db)):
    return db.query(IssuerProfile).order_by(IssuerProfile.created_at.desc()).all()


@router.post("/approve-issuer")
def approve_issuer(
    payload: ApproveIssuerRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    profile = db.query(IssuerProfile).filter(IssuerProfile.id == payload.issuer_profile_id).first()
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issuer profile not found.")

    profile.is_approved = True
    profile.is_blocked = False
    ensure_issuer_public_key(db, str(profile.user_id))

    log_event(
        db, actor_id=principal.user_id, action="admin.issuer_approved", resource_type="issuer_profile",
        resource_id=str(profile.id),
    )
    db.commit()
    return {"issuer_profile_id": str(profile.id), "is_approved": True}


@router.post("/block-issuer")
def block_issuer(
    payload: BlockIssuerRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    profile = db.query(IssuerProfile).filter(IssuerProfile.id == payload.issuer_profile_id).first()
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issuer profile not found.")

    profile.is_blocked = True

    log_event(
        db, actor_id=principal.user_id, action="admin.issuer_blocked", resource_type="issuer_profile",
        resource_id=str(profile.id), details={"reason": payload.reason},
    )
    db.commit()
    return {"issuer_profile_id": str(profile.id), "is_blocked": True}
