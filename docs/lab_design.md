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
- implement strict JWT validation using algorithm, key ID, issuer, audience, and expiration checks.

## Student Workload

Students are expected to:

- complete three exploit scripts;
- collect evidence of successful exploitation;
- implement one secure validation function;
- collect evidence that forged tokens are rejected after hardening;
- answer conceptual questions in a short report.

## Files

| Path | Purpose |
| --- | --- |
| `app/main.py` | Flask routes and login endpoints |
| `app/security.py` | Vulnerable validation functions and Task 4 TODO |
| `exploits/` | Starter exploit scripts with TODOs |
| `docs/theory.md` | Theoretical background |
| `docs/student_guide.md` | Lab instructions |
| `docs/report_template.md` | Suggested student report format |
| `docs/grading_rubric.md` | Suggested evaluation criteria |
