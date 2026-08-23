import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.credential import CredentialStatus, CredentialType


class IssueCredentialRequest(BaseModel):
    holder_email: str = Field(..., description="Email of the credential recipient; they must already hold a DID.")
    credential_type: CredentialType
    claims: dict[str, str] = Field(
        ..., description="Raw claim key/value pairs, e.g. {'date_of_birth': '2001-05-04', 'enrollment_status': 'active'}"
    )
    expires_in_days: int | None = Field(default=365, ge=1, le=3650)


class IssueCredentialResponse(BaseModel):
    credential_id: uuid.UUID
    holder_id: uuid.UUID
    credential_type: CredentialType
    claims_commitment: str
    issuer_signature: str
    issued_at: datetime
    expires_at: datetime | None
    blockchain_tx_hash: str | None


class IssuerCredentialOut(BaseModel):
    id: uuid.UUID
    holder_id: uuid.UUID
    credential_type: CredentialType
    status: CredentialStatus
    issued_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    blockchain_tx_hash: str | None = None

    class Config:
        from_attributes = True


class RevokeCredentialRequest(BaseModel):
    credential_id: uuid.UUID
    reason: str = Field(..., min_length=3, max_length=255)


class IssuerDashboardOut(BaseModel):
    organization_name: str
    is_approved: bool
    total_issued: int
    total_active: int
    total_revoked: int
    issued_last_30_days: int
