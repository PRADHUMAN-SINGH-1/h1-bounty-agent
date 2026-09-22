from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials


def require_basic(credentials: HTTPBasicCredentials | None, user: str, password: str) -> None:
    if not user or not password:
        raise HTTPException(status_code=503, detail="Dashboard authentication is not configured.")
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Basic"},
        )
    if not (
        hmac.compare_digest(credentials.username, user)
        and hmac.compare_digest(credentials.password, password)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Basic"},
        )


def action_token(secret: str, bucket_seconds: int = 300) -> str:
    if not secret:
        raise HTTPException(status_code=503, detail="Dashboard action secret is not configured.")
    bucket = int(time.time() // bucket_seconds)
    return hmac.new(secret.encode(), str(bucket).encode(), hashlib.sha256).hexdigest()


def verify_action_token(token: str | None, secret: str, bucket_seconds: int = 300) -> None:
    expected = action_token(secret, bucket_seconds)
    if token is None or not hmac.compare_digest(token, expected):
        # Accept the immediately previous bucket so a user can click during rollover.
        previous_bucket = int(time.time() // bucket_seconds) - 1
        previous = hmac.new(secret.encode(), str(previous_bucket).encode(), hashlib.sha256).hexdigest()
        if token is None or not hmac.compare_digest(token, previous):
            raise HTTPException(status_code=403, detail="Invalid or expired action token.")
