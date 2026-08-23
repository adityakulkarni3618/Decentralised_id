"""
Issuer credential signing and verification.

Public keys are persisted on IssuerProfile so signatures remain verifiable
across restarts and deployments even when local PEM files are regenerated.
Private keys stay in the keystore (KMS/HSM in production).
"""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.keystore import get_issuer_signing_key
from app.models.credential import Credential
from app.models.user import IssuerProfile


def _issuer_id_str(issuer_id) -> str:
    return str(issuer_id)


def public_key_pem_from_private(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Expected Ed25519 public key.")
    return key


def ensure_issuer_public_key(db, issuer_user_id: str) -> str:
    """Ensure issuer has a keypair; persist the public key on IssuerProfile."""
    issuer_user_id = _issuer_id_str(issuer_user_id)
    private_key = get_issuer_signing_key(issuer_user_id)
    public_pem = public_key_pem_from_private(private_key)

    profile = db.query(IssuerProfile).filter(IssuerProfile.user_id == issuer_user_id).first()
    if profile is not None and profile.signing_public_key_pem != public_pem:
        profile.signing_public_key_pem = public_pem
        db.flush()
    return public_pem


def sign_commitment(commitment_hex: str, issuer_user_id: str, db=None) -> str:
    issuer_user_id = _issuer_id_str(issuer_user_id)
    if db is not None:
        ensure_issuer_public_key(db, issuer_user_id)
    private_key = get_issuer_signing_key(issuer_user_id)
    return private_key.sign(bytes.fromhex(commitment_hex)).hex()


def verify_credential_signature(credential: Credential, db) -> bool:
    issuer_id = _issuer_id_str(credential.issuer_id)
    profile = db.query(IssuerProfile).filter(IssuerProfile.user_id == issuer_id).first()

    public_pem = profile.signing_public_key_pem if profile else None
    if not public_pem:
        # Backward compatibility: derive from local keystore if profile has no stored key.
        try:
            from app.core.keystore import get_issuer_verification_key

            pub_key = get_issuer_verification_key(issuer_id)
            pub_key.verify(
                bytes.fromhex(credential.issuer_signature),
                bytes.fromhex(credential.claims_commitment),
            )
            if profile is not None:
                profile.signing_public_key_pem = public_key_pem_from_private(get_issuer_signing_key(issuer_id))
                db.flush()
            return True
        except Exception:
            return False

    try:
        pub_key = load_public_key(public_pem)
        pub_key.verify(
            bytes.fromhex(credential.issuer_signature),
            bytes.fromhex(credential.claims_commitment),
        )
        return True
    except Exception:
        return False


def resync_issuer_credentials(db, issuer_user_id: str) -> int:
    """Re-sign all credentials for an issuer with the current signing key."""
    from app.models.credential import Credential

    issuer_user_id = _issuer_id_str(issuer_user_id)
    ensure_issuer_public_key(db, issuer_user_id)
    private_key = get_issuer_signing_key(issuer_user_id)

    credentials = db.query(Credential).filter(Credential.issuer_id == issuer_user_id).all()
    updated = 0
    for cred in credentials:
        signature = private_key.sign(bytes.fromhex(cred.claims_commitment)).hex()
        if cred.issuer_signature != signature:
            cred.issuer_signature = signature
            updated += 1
    return updated
