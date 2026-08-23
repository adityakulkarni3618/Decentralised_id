import uuid
from datetime import datetime

from app.db.base import Base, String, Boolean, DateTime, ForeignKey, SAEnum, UUID, JSONB, Mapped, mapped_column, relationship
from app.core.rbac import Role


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name_encrypted: Mapped[str] = mapped_column(String(512), nullable=True)  # AES-256-GCM ciphertext
    role: Mapped[str] = mapped_column(SAEnum(Role, name="user_role"), default=Role.USER, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    mfa_secret_encrypted: Mapped[str] = mapped_column(String(512), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    failed_login_attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    did_profile: Mapped["DIDProfile"] = relationship(back_populates="user", uselist=False, cascade="all, delete-orphan")
    credentials: Mapped[list["Credential"]] = relationship(back_populates="holder", foreign_keys="Credential.holder_id")
    consent_records: Mapped[list["ConsentRecord"]] = relationship(back_populates="subject")


class IssuerProfile(Base):
    """Extended profile for organizations approved to issue credentials."""
    __tablename__ = "issuer_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_domain: Mapped[str] = mapped_column(String(255), nullable=True)
    is_approved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    onchain_issuer_id: Mapped[str] = mapped_column(String(66), nullable=True)  # bytes32 hex id in IssuerRegistry
    signing_public_key_pem: Mapped[str] = mapped_column(String(1024), nullable=True)  # Ed25519 verify key
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    user: Mapped["User"] = relationship()
