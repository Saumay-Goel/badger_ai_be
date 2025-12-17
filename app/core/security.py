from __future__ import annotations

from datetime import datetime, timedelta, timezone
from jose import jwt
from pwdlib import PasswordHash
from .config import settings

password_hash = PasswordHash.recommended()


def verify_password(plain_password, password):
    return password_hash.verify(plain_password, password)


def get_password_hash(password):
    return password_hash.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt