# Lab Design Notes

## Educational Model

This lab follows a SEED-style progression:

1. Students observe normal application behavior.
2. Students exploit a deliberately vulnerable implementation.
3. Students complete small code fragments to demonstrate understanding.
4. Students modify server-side security logic.
5. Students verify that the original attacks no longer work.

The lab is intentionally transparent: students can read both the vulnerable Flask routes and the JWT validation code.

## Learning Objectives

After completing the lab, students should be able to:

- describe the structure of a signed JWT;
- explain why unsigned authentication tokens are dangerous;
- distinguish symmetric JWT algorithms from asymmetric JWT algorithms;
- explain how algorithm confusion breaks the RS256 security model;
- explain why `kid` must be treated as an identifier, not a path;
- explain why trusting keys embedded in the JWT header (`jwk`) is insecure;
- implement strict JWT validation using algorithm, key ID, issuer, audience, and expiration checks.

## Student Workload

Students are expected to:

- complete four exploit scripts;
- collect evidence of successful exploitation for each attack;
- implement one secure validation function;
- collect evidence that all forged tokens are rejected after hardening;
- answer conceptual questions in a short report.

## Relationship to Existing Labs

PortSwigger Web Security Academy covers the same three JWT attacks. This lab is a significant alternative on the following grounds:

- **White-box** — students read the vulnerable server code directly (`app/security.py`), so they understand *why* each validation is broken, not just *that* it is.
- **Hardening task** — Task 4 requires students to implement the fix. PortSwigger stops at exploitation.
- **Code-completion model** — exploit scripts contain TODOs that students must complete, rather than running pre-built tools.
- **Self-contained and open** — runs entirely offline via Docker with no external account or dependency; the full source is available for inspection and modification.
- **Complete educational package** — ships as a SEED-style bundle: theory, guided lab, hints, report template, grading rubric, and instructor solutions.

## Files

| Path | Purpose |
| --- | --- |
| `app/main.py` | Flask routes and login endpoints |
| `app/security.py` | Vulnerable validation functions and Task 5 TODO |
| `exploits/task1_alg_none.py` | Starter exploit for Task 1 |
| `exploits/task2_alg_confusion.py` | Starter exploit for Task 2 |
| `exploits/task3_kid_traversal.py` | Starter exploit for Task 3 |
| `exploits/task4_jwk_injection.py` | Starter exploit for Task 4 |
| `exploits/jwt_helpers.py` | Shared base64url and signing helpers |
| `docs/theory.md` | Theoretical background |
| `docs/student_guide.md` | Lab instructions |
| `docs/report_template.md` | Suggested student report format |
| `docs/grading_rubric.md` | Suggested evaluation criteria |
