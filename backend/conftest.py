"""Pytest configuration — set required env vars before app imports."""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-for-ci-only-must-be-long-enough-value-123456")
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "test-field-encryption-key-for-ci-32b")
os.environ.setdefault("ENVIRONMENT", "development")

import pytest


@pytest.fixture(scope="session", autouse=True)
def prepare_demo_database():
    """Ensure demo credentials match the active encryption key and issuer signatures."""
    from scripts.seed_db import run

    run(force=True)
