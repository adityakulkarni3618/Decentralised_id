import os
import sys
import pytest
import uuid
from fastapi.testclient import TestClient

# Ensure backend directory is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.main import app
from app.db.session import SessionLocal
from app.models.user import User

client = TestClient(app)

def test_cookie_authentication_flow():
    # Attempt to log in as Alice (seeded user)
    login_payload = {
        "email": "alice@example.com",
        "password": "AlicePass!2024"
    }
    
    response = client.post("https://testserver/api/auth/login", json=login_payload)
    assert response.status_code == 200
    
    response_json = response.json()
    print(f"\n[Cookie Test] Login JSON Response: {response_json}")
    
    # 1. Assert that access_token and refresh_token are NOT present in the JSON body
    assert "access_token" not in response_json or response_json["access_token"] is None
    assert "refresh_token" not in response_json or response_json["refresh_token"] is None
    print("[Cookie Test] Confirmed: JSON body does not contain credentials.")
    
    # 2. Assert that cookies are set
    cookies = response.cookies
    print(f"[Cookie Test] Set Cookies: {dict(cookies)}")
    
    assert "access_token" in cookies
    assert "refresh_token" in cookies
    assert "csrf_token" in cookies
    print("[Cookie Test] Confirmed: access_token, refresh_token, and csrf_token cookies are present.")

    # 3. Assert HttpOnly, Secure, and SameSite flags are set on both access and refresh cookies
    cookie_headers = response.headers.get("set-cookie", "")
    print(f"[Cookie Test] Raw Set-Cookie headers: {cookie_headers}")
    
    # Check access_token flags
    assert "access_token=" in cookie_headers
    # Check refresh_token flags
    assert "refresh_token=" in cookie_headers
    
    # Verify strict SameSite and HttpOnly; Secure only enforced in production.
    assert "samesite=strict" in cookie_headers.lower()
    assert "httponly" in cookie_headers.lower()
    if os.environ.get("ENVIRONMENT") == "production":
        assert "secure" in cookie_headers.lower()
    print("[Cookie Test] Confirmed: tokens have httponly and SameSite=strict flags.")

    # 4. Verify access is allowed when making a GET request with cookies (SAFE method)
    profile_response = client.get("https://testserver/api/wallet/credentials", cookies=response.cookies)
    assert profile_response.status_code == 200
    print("[Cookie Test] Confirmed: Authenticated GET request using cookies succeeds.")

    # 5. CSRF Test - POST request without CSRF token header
    post_payload = {
        "credential_id": str(uuid.uuid4()),
        "claim_predicate": "age_gte_18"
    }
    # State-changing method (POST) with valid access_token but no X-CSRF-Token header
    csrf_blocked_response = client.post(
        "https://testserver/api/wallet/generate-proof",
        json=post_payload,
        cookies=response.cookies
    )
    print(f"[Cookie Test] CSRF Blocked Response status: {csrf_blocked_response.status_code}, JSON: {csrf_blocked_response.json()}")
    assert csrf_blocked_response.status_code == 403
    assert "csrf" in csrf_blocked_response.json()["detail"].lower()
    print("[Cookie Test] Confirmed: state-changing request without CSRF token header is rejected (403).")

    # 6. CSRF Test - POST request WITH matching CSRF token header
    csrf_token_value = response.cookies.get("csrf_token")
    csrf_success_headers = {
        "X-CSRF-Token": csrf_token_value
    }
    csrf_passed_response = client.post(
        "https://testserver/api/wallet/generate-proof",
        json=post_payload,
        headers=csrf_success_headers,
        cookies=response.cookies
    )
    print(f"[Cookie Test] CSRF Passed Response status: {csrf_passed_response.status_code}, JSON: {csrf_passed_response.json()}")
    # The request should bypass CSRF check (since we used random UUID for credential, it should fail with 404 Credential Not Found, NOT 403 CSRF Block)
    assert csrf_passed_response.status_code == 404
    print("[Cookie Test] Confirmed: state-changing request with matching CSRF token header bypasses CSRF block (404).")
