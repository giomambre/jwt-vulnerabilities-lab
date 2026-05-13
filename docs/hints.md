# Hints

Use these hints only if you are stuck. Try each task first without reading all hints.

## Task 1: `alg:none`

Hint 1:
Look at the JWT payload. Which claim controls whether the user is treated as an administrator?

Hint 2:
The admin endpoints check for this value:

```text
role = admin
```

Hint 3:
An unsigned JWT still has three parts:

```text
header.payload.
```

The final dot is important because the signature part is empty.

## Task 2: RS256 to HS256 Algorithm Confusion

Hint 1:
The normal token is signed with `RS256`, but the vulnerable server also accepts another algorithm.

Hint 2:
The attack requires changing the JWT header algorithm to:

```text
HS256
```

Hint 3:
In a correct RS256 system, the public key only verifies signatures. In this vulnerable system, the public key is incorrectly reused as an HMAC secret.

## Task 3: `kid` Path Traversal

Hint 1:
The vulnerable server builds a path like this:

```text
/lab/app/keys/<kid>
```

Hint 2:
You want the server to read this file instead:

```text
/tmp/jwt-lab/attacker.key
```

Hint 3:
A relative path from `/lab/app/keys` to `/tmp/jwt-lab/attacker.key` is:

```text
../../../tmp/jwt-lab/attacker.key
```

Hint 4:
The attacker key file contains:

```text
student-controlled-secret
```

## Task 4: `jwk` Header Injection

Hint 1:
The vulnerable server reads the `jwk` field from the JWT header and uses that key to verify the token.

Hint 2:
You need to generate an RSA key pair. Use the `cryptography` library:

```python
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
```

Hint 3:
Convert the public key to JWK format using PyJWT:

```python
import json
from jwt.algorithms import RSAAlgorithm
jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
```

Hint 4:
Embed the JWK in the JWT header and sign with your private key:

```python
import jwt
forged = jwt.encode(payload, private_key, algorithm="RS256", headers={"jwk": jwk, "kid": "task4"})
```

## Task 5: Hardening

Hint 1:
Do not trust the JWT header to choose the security policy. Your code should decide the only accepted algorithm.

Hint 2:
The only valid algorithm for the fixed endpoint is:

```text
RS256
```

Hint 3:
The only valid key ID for the fixed endpoint is:

```text
task2
```

Hint 4:
Use `jwt.decode()` with:

```python
algorithms=["RS256"]
issuer=ISSUER
audience=AUDIENCE
```

Hint 5:
Wrap PyJWT errors and raise `AuthError`, so the Flask app returns a controlled `401` response instead of crashing.

Hint 6:
A correctly implemented `student_secure_decode_rs256` also blocks the `jwk` injection attack from Task 4 — because it uses a pre-configured key from disk and never reads from the token header. Which of the TODOs achieves this?
