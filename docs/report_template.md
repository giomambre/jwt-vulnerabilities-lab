# Report Template

## Group Members

- Name 1
- Name 2
- Name 3
- Name 4

## Task 1: `alg:none`

### Completed Code

Paste the relevant completed lines from `exploits/task1_alg_none.py`.

### Evidence

Paste terminal output showing admin access.

### Explanation

Answer:

- Which JWT claim did you change?
- What happened to the JWT signature?
- What validation rule would prevent this attack?

## Task 2: RS256 to HS256 Algorithm Confusion

### Completed Code

Paste the relevant completed lines from `exploits/task2_alg_confusion.py`.

### Evidence

Paste terminal output showing admin access.

### Explanation

Answer:

- What is the difference between RS256 and HS256?
- Why is the public key safe to publish in a correct RS256 system?
- Which server-side mistake made the public key useful to the attacker?

## Task 3: `kid` Path Traversal

### Completed Code

Paste the relevant completed lines from `exploits/task3_kid_traversal.py`.

### Evidence

Paste terminal output showing admin access.

### Explanation

Answer:

- Why is `kid` security-sensitive?
- Why is direct filesystem path construction dangerous here?
- How should the server map a `kid` value to a key?

## Task 4: `jwk` Header Injection

### Completed Code

Paste the relevant completed lines from `exploits/task4_jwk_injection.py`.

### Evidence

Paste terminal output showing admin access.

### Explanation

Answer:

- What does the `jwk` JWT header parameter contain?
- Why is trusting a key embedded in the token fundamentally broken, even if the signature is valid?
- What is the correct way for a server to obtain the verification key?

## Task 5: Hardening

### Completed Server Code

Paste your completed `student_secure_decode_rs256()` function.

### Evidence

Paste terminal output showing:

- legitimate admin token accepted by `/fixed/admin`;
- forged Task 1 token rejected by `/fixed/admin`;
- forged Task 2 token rejected by `/fixed/admin`;
- forged Task 3 token rejected by `/fixed/admin`;
- forged Task 4 token rejected by `/fixed/admin`.

### Explanation

Answer:

- Which check blocks the `alg:none` attack?
- Which check blocks the RS256 to HS256 confusion attack?
- Which check blocks the `kid` path traversal attack?
- Which check also blocks the `jwk` header injection attack?
- Why is issuer and audience validation useful?
