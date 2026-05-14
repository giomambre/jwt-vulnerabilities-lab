# Student Guide: JWT Vulnerabilities Lab

## Lab Goal

In this lab you are given a vulnerable web application that uses JSON Web Tokens for authentication.

Your goal is to understand how JWT validation mistakes lead to authentication bypasses. You will exploit four vulnerabilities, then modify the server code to prevent them.

This is not only a command-running exercise. You must complete small pieces of exploit code and then implement a secure validation function.

## What You Must Do

You must complete four tasks:

| Task | Topic | What you do |
| --- | --- | --- |
| 1 | `alg:none` | Complete a script that creates an unsigned admin token |
| 2 | RS256 to HS256 confusion | Complete a script that signs an admin token with HS256 using the RSA public key as the HMAC secret |
| 3 | `kid` path traversal | Complete a script that points `kid` to an attacker-controlled key file |
| 4 | `jwk` header injection | Complete a script that embeds an attacker-controlled public key in the JWT header |
| 5 | Hardening | Edit the server code so all four forged tokens are rejected |

## What You Must Submit

Submit a short report containing:

- The completed code snippets for the TODOs in Tasks 1, 2, 3, and 4.
- Terminal output showing successful admin access for Tasks 1, 2, 3, and 4.
- Your completed `student_secure_decode_rs256()` function from `app/security.py`.
- Terminal output showing that all four attacks fail after your fix.
- Short answers to the questions at the end of each task.

## 1. Setup

### Install Docker

**Debian / Ubuntu:**

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER   # log out and back in afterwards
```

**Arch Linux:**

```bash
sudo pacman -S docker docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # log out and back in afterwards
```

**macOS / Windows:** install [Docker Desktop](https://www.docker.com/products/docker-desktop). On Windows PowerShell, if `docker` is not found after installation:

```powershell
$env:PATH='C:\Program Files\Docker\Docker\resources\bin;' + $env:PATH
```

### Install Python packages for Task 4

The Task 4 exploit script requires two packages on the host. Tasks 1–3 use only the standard library. Create a virtual environment in the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate         # Windows PowerShell
pip install pyjwt cryptography
```

Activate the virtual environment each time before running the Task 4 exploit script.

### Start the lab

```bash
docker compose up --build
```

Check that it is running:

```bash
curl http://localhost:5000/health
```

Expected output:

```json
{"ok":true}
```


The low-privilege account is:

```text
alice / password123
```

The admin account, used only for Task 5 verification, is:

```text
admin / admin123
```

## 2. Task 1: `alg:none` and Claim Tampering

### Objective

Exploit a server that accepts unsigned JWTs.

You will log in as `alice`, receive a normal signed token, modify the token payload so `alice` becomes an admin, and remove the signature by using `alg:none`.

### Code You Must Complete

Open:

```text
exploits/task1_alg_none.py
```

Complete the TODOs. You must decide:

- which claim must be changed;
- what value gives admin privileges;
- why an unsigned JWT has an empty signature segment.

### Commands

Get a normal user token:

```bash
TOKEN=$(curl -s -X POST http://localhost:5000/task1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

Confirm that the normal token is not an admin token:

```bash
curl -i http://localhost:5000/task1/admin -H "Authorization: Bearer $TOKEN"
```

After completing the TODOs, generate the forged token:

```bash
FORGED=$(python3 exploits/task1_alg_none.py "$TOKEN")
curl -i http://localhost:5000/task1/admin -H "Authorization: Bearer $FORGED"
```

### Success Condition

The final request should contain:

```json
"message": "Task 1 admin access granted"
```

### Questions

- Which JWT claim did you change?
- What happened to the JWT signature?
- What validation rule would prevent this attack?

## 3. Task 2: RS256 to HS256 Algorithm Confusion

### Objective

Exploit a server that confuses asymmetric and symmetric JWT algorithms.

The server is supposed to use RS256. In RS256, the private key signs tokens and the public key verifies them. The vulnerable server also accepts HS256 and incorrectly uses the RSA public key as an HMAC secret.

### Code You Must Complete

Open:

```text
exploits/task2_alg_confusion.py
```

Complete the TODOs. You must decide:

- which algorithm to place in the JWT header;
- which claim must be changed;
- why the public key can be abused as an HS256 secret in this vulnerable implementation.

### Commands

Get a normal RS256 token:

```bash
TOKEN=$(curl -s -X POST http://localhost:5000/task2/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

Inspect the public key:

```bash
curl http://localhost:5000/task2/public.pem
```

After completing the TODOs, forge an HS256 token:

```bash
FORGED=$(python3 exploits/task2_alg_confusion.py "$TOKEN")
curl -i http://localhost:5000/task2/admin -H "Authorization: Bearer $FORGED"
```

### Success Condition

The final request should contain:

```json
"message": "Task 2 admin access granted"
```

### Questions

- What is the difference between RS256 and HS256?
- Why is the public key safe to publish in a correct RS256 system?
- Which server-side mistake made the public key useful to the attacker?

## 4. Task 3: `kid` Header Path Traversal

### Objective

Exploit a server that uses the JWT `kid` header as part of a filesystem path.

The server reads a key from its `app/keys` directory based on the token's `kid` header. Because the server does not sanitize `kid`, you can use path traversal to make it read `/tmp/jwt-lab/attacker.key` instead.

### Code You Must Complete

Open:

```text
exploits/task3_kid_traversal.py
```

Complete the TODOs. You must decide:

- the secret value written into the attacker key file;
- the traversal path from `/lab/app/keys` to `/tmp/jwt-lab/attacker.key`;
- which claim must be changed.

### Commands

Get a normal user token:

```bash
TOKEN=$(curl -s -X POST http://localhost:5000/task3/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

Create the attacker-controlled key inside the container:

```bash
curl -s -X POST http://localhost:5000/task3/write-attacker-key
```

After completing the TODOs, forge a token whose `kid` traverses to the attacker-controlled key:

```bash
FORGED=$(python3 exploits/task3_kid_traversal.py "$TOKEN")
curl -i http://localhost:5000/task3/admin -H "Authorization: Bearer $FORGED"
```

### Success Condition

The final request should contain:

```json
"message": "Task 3 admin access granted"
```

### Questions

- Why is `kid` security-sensitive?
- Why is direct filesystem path construction dangerous here?
- How should the server map a `kid` value to a key?

## 5. Task 4: `jwk` Header Injection

### Objective

Exploit a server that trusts the public key embedded in the JWT header.

The server validates RS256 tokens by reading the `jwk` field from the token header and using whatever public key it finds there. An attacker can generate their own RSA key pair, embed the public key in the JWT header, sign the token with the corresponding private key, and the server will verify it successfully — because it is using the attacker's own key.

### Code You Must Complete

Open:

```text
exploits/task4_jwk_injection.py
```

Complete the TODOs. You must:

- generate an RSA key pair you control;
- convert the public key to JWK format and embed it in the header;
- sign the forged token with your private key.

This exploit requires PyJWT and the cryptography library on your host machine:

```bash
pip install pyjwt cryptography
```

### Commands

Get a normal RS256 token:

```bash
TOKEN=$(curl -s -X POST http://localhost:5000/task4/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

After completing the TODOs, forge an injected token:

```bash
FORGED=$(python3 exploits/task4_jwk_injection.py "$TOKEN")
curl -i http://localhost:5000/task4/admin -H "Authorization: Bearer $FORGED"
```

### Success Condition

The final request should contain:

```json
"message": "Task 4 admin access granted"
```

### Questions

- What does the `jwk` JWT header parameter contain?
- Why is trusting a key embedded in the token fundamentally broken, even if the signature is valid?
- What is the correct way for a server to obtain the verification key?

---

## 6. Task 5: Hardening the Server

### Objective

Modify the server so the previous attacks fail.

This task requires server-side code changes.

### Code You Must Complete

Open:

```text
app/security.py
```

Find:

```python
def student_secure_decode_rs256(token: str) -> dict[str, Any]:
```

Replace the TODO with secure JWT validation.

Your implementation must:

- reject `alg:none`;
- accept only `RS256`;
- reject unknown `kid` values;
- verify with the RSA public key;
- validate expiration;
- validate issuer `jwt-lab`;
- validate audience `jwt-lab-students`;
- raise `AuthError` when validation fails.

After editing the server code, rebuild and restart the lab:

```bash
docker compose up --build
```

### Verification

First, prove a legitimate admin token works:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:5000/fixed/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -i http://localhost:5000/fixed/admin -H "Authorization: Bearer $ADMIN_TOKEN"
```

Expected result:

```json
"message": "Secure admin access granted"
```

Then send the forged tokens from Tasks 1, 2, 3, and 4 to:

```text
GET /fixed/admin
```

They must all be rejected.

### Questions

- Which check blocks the `alg:none` attack?
- Which check blocks the RS256 to HS256 confusion attack?
- Which check blocks the `kid` path traversal attack?
- Which check also blocks the `jwk` header injection attack?
- Why is issuer and audience validation useful?

## 7. Final Checklist

Before submitting, make sure your report includes:

- completed exploit TODOs;
- successful Task 1 attack output;
- successful Task 2 attack output;
- successful Task 3 attack output;
- successful Task 4 attack output;
- completed secure validation function;
- output showing legitimate `/fixed/admin` access works;
- output showing all four forged tokens fail against `/fixed/admin`;
- answers to all task questions.
