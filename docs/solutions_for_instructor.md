# Solutions for Instructor

This file is intended for instructors, teaching assistants, or project evaluators. It should not be distributed to students if the lab is used as an assessment.

## Task 1 Solution

In `exploits/task1_alg_none.py`:

```python
payload["role"] = "admin"
```

The helper `encode_none()` changes the header algorithm to `none` and returns a token with an empty signature segment:

```text
header.payload.
```

The attack works because `vulnerable_task1_decode()` disables signature verification when it sees `alg:none`.

## Task 2 Solution

In `exploits/task2_alg_confusion.py`:

```python
header["alg"] = "HS256"
payload["role"] = "admin"
```

The script downloads the RSA public key from `/task2/public.pem` and uses the public key bytes as the HS256 HMAC secret.

The attack works because `vulnerable_task2_decode()` accepts both `RS256` and `HS256`, then manually verifies HS256 using the RSA public key as a symmetric secret.

## Task 3 Solution

In `exploits/task3_kid_traversal.py`:

```python
ATTACKER_SECRET = b"student-controlled-secret"
TRAVERSAL_KID = "../../../tmp/jwt-lab/attacker.key"
payload["role"] = "admin"
```

The attack works because `vulnerable_task3_decode()` builds a filesystem path directly from the untrusted JWT `kid` header:

```python
key_path = KEY_DIR / kid
```

This allows traversal from `/lab/app/keys` to `/tmp/jwt-lab/attacker.key`.

## Task 4 Reference Solution

A correct implementation for `student_secure_decode_rs256()` is:

```python
def student_secure_decode_rs256(token: str) -> dict[str, Any]:
    header = _get_unverified_header(token)

    if header.get("alg") != "RS256":
        raise AuthError("only RS256 is accepted")

    if header.get("kid") != "task2":
        raise AuthError("unknown key id")

    try:
        return jwt.decode(
            token,
            read_task2_public_key(),
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )
    except jwt.PyJWTError as exc:
        raise AuthError(str(exc)) from exc
```

This blocks:

- `alg:none`, because only `RS256` is accepted;
- RS256 to HS256 confusion, because `HS256` is rejected before verification;
- `kid` path traversal, because the key ID must equal `task2` and is never used as a filesystem path;
- replay of malformed tokens missing issuer or audience, because `jwt.decode()` validates both.

## Expected Verification

A real admin token from `/fixed/login` should succeed against `/fixed/admin`.

Forged tokens from Tasks 1, 2, and 3 should fail against `/fixed/admin` with HTTP `401`.
