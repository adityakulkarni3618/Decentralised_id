"""
OTP login challenge store — Redis-backed with in-memory fallback for local dev.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import redis

from app.core.config import settings

_redis_client: redis.Redis | None | bool = None
_memory: dict[str, dict] = {}


def _get_redis() -> redis.Redis | None:
    global _redis_client
    if _redis_client is False:
        return None
    if _redis_client is None:
        try:
            client = redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
            client.ping()
            _redis_client = client
        except Exception:
            _redis_client = False
            return None
    return _redis_client  # type: ignore[return-value]


def store_otp_challenge(token: str, user_id: str, ttl_seconds: int) -> None:
    payload = {
        "user_id": user_id,
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat(),
    }
    client = _get_redis()
    if client:
        client.setex(f"otp_challenge:{token}", ttl_seconds, json.dumps(payload))
    else:
        _memory[token] = payload


def get_otp_challenge(token: str) -> dict | None:
    client = _get_redis()
    if client:
        raw = client.get(f"otp_challenge:{token}")
        if not raw:
            return None
        payload = json.loads(raw)
    else:
        payload = _memory.get(token)
        if not payload:
            return None

    expires_at = datetime.fromisoformat(payload["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        delete_otp_challenge(token)
        return None
    return payload


def delete_otp_challenge(token: str) -> None:
    client = _get_redis()
    if client:
        client.delete(f"otp_challenge:{token}")
    _memory.pop(token, None)
