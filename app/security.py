import base64
import hashlib
import hmac
import json
from typing import Any

import jwt
from jwt.algorithms import RSAAlgorithm

from app.key_material import KEY_DIR, read_task2_public_key


class AuthError(Exception):
    pass


TASK1_HS256_SECRET = "task1-teaching-secret"
ISSUER = "jwt-lab"
AUDIENCE = "jwt-lab-students"


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _split_token(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("JWT must contain header, payload, and signature")
    return parts[0], parts[1], parts[2]


def _decode_json_segment(segment: str) -> dict[str, Any]:
    try:
        return json.loads(_b64url_decode(segment))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthError("JWT contains invalid JSON") from exc


def _get_unverified_header(token: str) -> dict[str, Any]:
    try:
        return jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AuthError(str(exc)) from exc


def vulnerable_task1_decode(token: str) -> dict[str, Any]:
    header = _get_unverified_header(token)

    if header.get("alg") == "none":
        return jwt.decode(token, options={"verify_signature": False, "verify_exp": False})

    try:
        return jwt.decode(token, TASK1_HS256_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise AuthError(str(exc)) from exc


def _verify_hs256_manually(token: str, secret: bytes) -> dict[str, Any]:
    header_b64, payload_b64, signature_b64 = _split_token(token)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    supplied = _b64url_decode(signature_b64)

    if not hmac.compare_digest(expected, supplied):
        raise AuthError("invalid HS256 signature")

    return _decode_json_segment(payload_b64)


def vulnerable_task2_decode(token: str) -> dict[str, Any]:
    header = _get_unverified_header(token)
    public_key = read_task2_public_key()

    try:
        if header.get("alg") == "RS256":
            return jwt.decode(token, public_key, algorithms=["RS256"])

        if header.get("alg") == "HS256":
            return _verify_hs256_manually(token, public_key.encode("utf-8"))
    except jwt.PyJWTError as exc:
        raise AuthError(str(exc)) from exc

    raise AuthError("unsupported algorithm")


def vulnerable_task3_decode(token: str) -> dict[str, Any]:
    header = _get_unverified_header(token)
    kid = header.get("kid", "task3-default.key")

    if header.get("alg") != "HS256":
        raise AuthError("task 3 expects HS256")

    key_path = KEY_DIR / kid
    try:
        secret = key_path.read_bytes()
        return jwt.decode(token, secret, algorithms=["HS256"])
    except OSError as exc:
        raise AuthError(f"could not read key: {key_path}") from exc
    except jwt.PyJWTError as exc:
        raise AuthError(str(exc)) from exc


def vulnerable_task4_decode(token: str) -> dict[str, Any]:
    header = _get_unverified_header(token)

    if header.get("alg") != "RS256":
        raise AuthError("task 4 expects RS256")

    jwk_data = header.get("jwk")
    if not jwk_data:
        raise AuthError("missing jwk header parameter")

    try:
        public_key = RSAAlgorithm.from_jwk(
            json.dumps(jwk_data) if isinstance(jwk_data, dict) else jwk_data
        )
        return jwt.decode(token, public_key, algorithms=["RS256"])
    except jwt.PyJWTError as exc:
        raise AuthError(str(exc)) from exc
    except Exception as exc:
        raise AuthError(f"invalid jwk: {exc}") from exc


def student_secure_decode_rs256(token: str) -> dict[str, Any]:
    """Task 5: students must replace this TODO with secure JWT validation."""
    header = _get_unverified_header(token)

    # TODO 1: reject every token whose algorithm is not exactly RS256.
    # TODO 2: reject unknown key IDs. For this lab, the only valid kid is "task2".
    # TODO 3: verify the token with the RSA public key, not an HMAC secret.
    # TODO 4: require issuer=ISSUER and audience=AUDIENCE.
    # TODO 5: raise AuthError with a useful message when validation fails.
    #
    # Hint: use jwt.decode(..., algorithms=["RS256"], issuer=ISSUER, audience=AUDIENCE).
    raise AuthError("Task 5 TODO: implement secure JWT validation")
