from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from typing import Final


PASSWORD_HASH_ALGORITHM: Final = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS: Final = 310_000
PASSWORD_SALT_BYTES: Final = 16
PASSWORD_HASH_BYTES: Final = 32


def hash_password(password: str) -> tuple[str, str]:
    if not password:
        raise ValueError("Password must not be empty.")

    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    password_salt = _encode_bytes(salt)
    digest = _derive_password_hash(password, salt, PASSWORD_HASH_ITERATIONS)
    password_hash = f"{PASSWORD_HASH_ALGORITHM}${PASSWORD_HASH_ITERATIONS}${_encode_bytes(digest)}"
    return password_hash, password_salt


def verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    try:
        algorithm, iterations_text, expected_digest_text = password_hash.split("$", 2)
        if algorithm != PASSWORD_HASH_ALGORITHM:
            return False
        iterations = int(iterations_text)
        if iterations <= 0:
            return False
        salt = _decode_bytes(password_salt)
        expected_digest = _decode_bytes(expected_digest_text)
    except (ValueError, binascii.Error):
        return False

    actual_digest = _derive_password_hash(password, salt, iterations)
    return hmac.compare_digest(actual_digest, expected_digest)


def _derive_password_hash(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=PASSWORD_HASH_BYTES,
    )


def _encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_bytes(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


__all__ = [
    "PASSWORD_HASH_ALGORITHM",
    "PASSWORD_HASH_ITERATIONS",
    "PASSWORD_SALT_BYTES",
    "hash_password",
    "verify_password",
]
