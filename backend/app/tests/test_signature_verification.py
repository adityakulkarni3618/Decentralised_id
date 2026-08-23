import os
import sys
import pytest
from cryptography.exceptions import InvalidSignature

# Ensure backend directory is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.core.issuer_crypto import sign_commitment
from app.core.keystore import get_issuer_signing_key, get_issuer_verification_key, is_issuer_key_active

def test_ed25519_signature_and_tampering():
    issuer_id = "test_issuer_123"
    unknown_issuer_id = "unknown_issuer_456"
    
    # Original commitment (32 bytes hex)
    original_commitment = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    
    # Generate signature
    signature_hex = sign_commitment(original_commitment, issuer_id)
    print(f"\n[Signature Test] Real Ed25519 signature: {signature_hex}")
    print(f"[Signature Test] Length of Ed25519 signature hex (should be 128): {len(signature_hex)}")
    
    # Verification key
    pub_key = get_issuer_verification_key(issuer_id)
    
    # 1. Verify valid signature
    try:
        pub_key.verify(bytes.fromhex(signature_hex), bytes.fromhex(original_commitment))
        verification_success = True
    except InvalidSignature:
        verification_success = False
    
    assert verification_success is True, "Valid signature failed verification!"
    
    # 2. Tamper with commitment payload (change one byte)
    tampered_commitment = "9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    with pytest.raises(InvalidSignature):
        pub_key.verify(bytes.fromhex(signature_hex), bytes.fromhex(tampered_commitment))
    print("[Signature Test] Confirmed: Tampering with commitment payload fails verification.")
        
    # 3. Tamper with signature (change last byte)
    tampered_sig_hex = signature_hex[:-2] + "00"
    with pytest.raises(InvalidSignature):
        pub_key.verify(bytes.fromhex(tampered_sig_hex), bytes.fromhex(original_commitment))
    print("[Signature Test] Confirmed: Tampering with signature value fails verification.")

    # 4. Unknown/different issuer key verification
    unknown_pub_key = get_issuer_verification_key(unknown_issuer_id)
    with pytest.raises(InvalidSignature):
        unknown_pub_key.verify(bytes.fromhex(signature_hex), bytes.fromhex(original_commitment))
    print("[Signature Test] Confirmed: Verification using unknown/revoked issuer key fails.")


def test_revoked_issuer_key_at_verification():
    from app.core.keystore import is_issuer_key_active
    from app.db.session import SessionLocal
    from app.models.user import IssuerProfile
    import uuid

    db = SessionLocal()
    issuer_user_id = str(uuid.uuid4())
    
    # Create an active and approved issuer
    profile = IssuerProfile(
        id=uuid.uuid4(),
        user_id=issuer_user_id,
        organization_name="Temp Test Issuer",
        is_approved=True,
        is_blocked=False
    )
    db.add(profile)
    db.commit()
    
    try:
        # Confirm they are active
        assert is_issuer_key_active(issuer_user_id, db) is True
        print("\n[Issuer Status Test] Confirmed: Active issuer is marked as active.")
        
        # Query the profile via session to register it in tracked list
        db_profile = db.query(IssuerProfile).filter(IssuerProfile.user_id == issuer_user_id).first()
        assert db_profile is not None
        
        # Block the issuer (revoking their authorization)
        db_profile.is_blocked = True
        db.commit()
        
        # Verify the key is no longer active at verification time
        assert is_issuer_key_active(issuer_user_id, db) is False
        print("[Issuer Status Test] Confirmed: Revoked/Blocked issuer key is marked as inactive.")
        
    finally:
        # Clean up
        db_profile_cleanup = db.query(IssuerProfile).filter(IssuerProfile.user_id == issuer_user_id).first()
        if db_profile_cleanup:
            db.delete(db_profile_cleanup)
            db.commit()
        db.close()
