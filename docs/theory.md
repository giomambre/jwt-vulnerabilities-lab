# Theoretical Background: JWT Vulnerabilities

## JSON Web Tokens

A JSON Web Token is a compact string used to transmit claims between parties. A signed JWT has three base64url-encoded parts:

```text
header.payload.signature
```

The header identifies the signing algorithm and optional metadata such as `kid`. The payload contains claims such as the subject, role, issuer, audience, and expiration time. The signature protects the header and payload from modification.

JWT security depends on strict validation. The server must decide which algorithms and keys are trusted. It must not let the token itself make security-critical decisions.

## Vulnerability 1: `alg:none`

JWT supports an unsecured mode named `none`, where the token has no signature. This is only safe in very limited situations and should not be accepted for authentication.

A vulnerable server may read the JWT header, see `"alg":"none"`, skip signature verification, and still trust the payload. An attacker can then change a claim such as `"role":"user"` to `"role":"admin"` and remove the signature.

Secure implementations reject `none` for authenticated routes and enforce a strict algorithm allowlist.

## Vulnerability 2: Algorithm Confusion

RS256 is asymmetric: the server signs with a private key and verifies with a public key. HS256 is symmetric: the same secret signs and verifies the token.

Algorithm confusion happens when the server trusts the token's `alg` header and uses the wrong verification method. A common example is accepting HS256 for a system intended to use RS256, then using the RSA public key as an HMAC secret. Since the public key is public, an attacker can forge an HS256 token that the server accepts.

Secure implementations do not mix symmetric and asymmetric verification paths for the same token type. They enforce the expected algorithm independently of the JWT header.

## Vulnerability 3: `kid` Header Injection

The `kid` header is a key identifier. It helps the server select the correct verification key when several keys are available.

If the server directly appends `kid` to a filesystem path, the attacker may use path traversal sequences such as `../` to force the server to load an attacker-controlled key. The attacker then signs a token with that key and gains unauthorized access.

Secure implementations treat `kid` as an identifier, not a path. They use a fixed map of allowed key IDs and reject unknown values.

## Hardening Checklist

- Reject `alg:none`.
- Enforce a strict algorithm allowlist.
- Keep HS256 and RS256 verification logic separate.
- Treat `kid` as an opaque identifier from an allowlist.
- Validate expiration, issuer, and audience.
- Keep signing keys outside the web root and never accept attacker-selected key paths.
