# Theoretical Background: JWT Vulnerabilities

## JSON Web Tokens

A JSON Web Token (JWT) is a compact, URL-safe string used to transmit claims(information or assertions about a user or session) between parties.
A signed JWT has three base64url-encoded parts separated by dots:

```
header.payload.signature
```

**Header** — identifies the algorithm and optional metadata:

```json
{"alg": "HS256", "typ": "JWT"}
```

**Payload** — contains the claims (assertions about the user or session):

```json
{"sub": "alice", "role": "user", "iat": 1700000000, "exp": 1700001800}
```

**Signature** — computed over `base64url(header).base64url(payload)` using the chosen algorithm and a secret or private key.

A full token looks like:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDE4MDB9
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

> **Important:** base64url is an encoding, not encryption. Anyone who holds a JWT can decode the header and payload without any key. Only the signature provides integrity.

JWT security depends entirely on the server enforcing which algorithms and keys it will trust. The token must never be allowed to make those decisions itself.

---

## Signing Algorithms

**HS256 (HMAC-SHA256)** is symmetric: the same secret is used to both sign and verify a token. Both sides must know the secret, making it suitable for a single server or a closed system.

**RS256 (RSA-SHA256)** is asymmetric: a private key signs the token and the corresponding public key verifies it. The private key stays on the signing server; the public key can be shared freely. An entity that only holds the public key can verify tokens but cannot forge new ones.

---

## Vulnerability 1: `alg:none`

The JWT specification defines an unsecured mode where `"alg": "none"` means no signature is present. This was intended for situations where integrity is guaranteed by other means, such as a TLS-only channel between two trusted services.

A vulnerable server may read the algorithm directly from the JWT header without restricting which values it accepts. If it sees `"alg": "none"`, it skips signature verification entirely. An attacker can:

1. Take a legitimately issued token.
2. Decode the header and payload (no key needed — it is just base64url).
3. Change a claim such as `"role": "user"` to `"role": "admin"`.
4. Re-encode the header with `"alg": "none"` and the modified payload, leaving the signature part empty.
5. Send the unsigned token to the server, which accepts it.

The resulting forged token ends with a trailing dot where the signature would be:

```
eyJhbGciOibm9uZSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.
```

**Defense:** servers must enforce an explicit algorithm allowlist and never accept `none` for authenticated routes.

---

## Vulnerability 2: Algorithm Confusion (RS256 → HS256)

When a server accepts both RS256 and HS256 for the same route and selects the verification path based on the `alg` header, an attacker can switch the algorithm:

- In RS256, the server verifies the token by computing `RSA-verify(public_key, signature)`.
- In HS256, the server verifies the token by computing `HMAC-SHA256(secret, signing_input)` and comparing it to the signature.

If the server uses the RSA public key as the HMAC secret when it sees `"alg": "HS256"`, and the public key is available (e.g., exposed at a `/public.pem` endpoint), the attacker can:

1. Download the public key.
2. Modify the token payload (e.g., elevate `role` to `admin`).
3. Change the header to `"alg": "HS256"`.
4. Sign the forged token with `HMAC-SHA256(public_key_bytes, header.payload)`.
5. The server fetches the same public key, performs the same HMAC computation, and the signature matches.

The public key is, by design, not secret — yet here it becomes the attacker's signing credential.

**Defense:** algorithm selection must never be delegated to the token. The server must pin the expected algorithm independently and keep RS256 and HS256 verification paths entirely separate.

---

## Vulnerability 3: `kid` Header Path Traversal

The `kid` (key ID) header is an optional hint that helps the server select the right verification key when multiple keys are in rotation. Its intended use is as an opaque identifier looked up in a predefined map.

If a server constructs a filesystem path directly from `kid`, for example:

```python
key_path = keys_directory / header["kid"]
secret = key_path.read_bytes()
```

then an attacker can supply a traversal sequence:

```
../../../tmp/attacker.key
```

which resolves to a file outside the keys directory. If the attacker has previously written a known value to that path (through any writable endpoint or side channel), they can forge a token signed with that value and the server will verify it successfully.

**Defense:** treat `kid` as an opaque identifier and look it up in a fixed allowlist. Never concatenate it into a path or use it as a filename.

---

## Vulnerability 4: `jwk` Header Injection

The JWT spec allows an optional `jwk` header parameter containing the public key the recipient should use to verify the token. The intended use is to accompany a token with its verification key in scenarios where keys are distributed dynamically.

A vulnerable server that reads `jwk` from the token header and uses it directly as the verification key can be exploited:

1. The attacker generates their own RSA key pair — entirely under their control.
2. They embed the public key in the JWT `jwk` header as a JWK object.
3. They sign the token (with any payload they choose) using their private key.
4. The server reads the embedded public key and verifies the signature — which matches, because the attacker signed with the corresponding private key.

The attack is subtle because the token is a legitimately signed RS256 token. The flaw is that the server has outsourced its trust decision to the token itself.

```json
{
  "alg": "RS256",
  "kid": "attacker",
  "jwk": { "kty": "RSA", "n": "...", "e": "AQAB" }
}
```

**Defense:** never read verification keys from the token. The server must use a pre-configured key or key store. The `jwk` header should be ignored for verification purposes.

---

## Hardening Checklist

- Enforce a strict algorithm allowlist; never accept `alg:none`.
- Do not use the JWT header to select the verification algorithm.
- Keep HS256 and RS256 verification paths separate.
- Treat `kid` as an identifier from a known allowlist, never as a path.
- Never use keys embedded in the token (`jwk`, `jku`, `x5c`) for verification.
- Validate `exp` (expiration), `iss` (issuer), and `aud` (audience) on every token.
- Store signing keys outside the web root; never expose private keys.

---

## References

- RFC 7519 — JSON Web Token, Jones et al., IETF, 2015.
- RFC 7518 — JSON Web Algorithms, Jones, IETF, 2015.
- "Critical vulnerabilities in JSON Web Token libraries", Tim McLean, Auth0, 2015 — documents the real-world `alg:none` and algorithm confusion disclosures.
- "Attacking JWT authentication", Sjoerd Langkemper, 2016 — practical overview of common JWT attacks.
- PortSwigger Web Security Academy — JWT attacks, portswigger.net/web-security/jwt.
