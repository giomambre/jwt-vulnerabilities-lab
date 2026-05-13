# JWT Vulnerabilities Laboratory

This mini-project is a Dockerized Flask lab for learning common JWT implementation vulnerabilities.

Students complete starter exploit scripts, collect evidence of successful attacks, then edit the server-side validation code to harden the application.

1. `alg:none` and claim tampering
2. RS256 to HS256 algorithm confusion
3. `kid` header path traversal
4. `jwk` header injection
5. Secure JWT validation and hardening

## Prerequisites
*[Installation instructions all in [docs/student_guide.md](docs/student_guide.md)]*

- **Docker** — to run the lab server
- **Python 3.9+** — to run the exploit scripts on the host
- **PyJWT and cryptography** — for the Task 4 exploit script only




## Deliverables

- [docs/theory.md](docs/theory.md): theoretical background
- [docs/student_guide.md](docs/student_guide.md): practical lab guide
- [docs/report_template.md](docs/report_template.md): suggested student report structure
- [docs/hints.md](docs/hints.md): progressive hints for students who get stuck
- [docs/grading_rubric.md](docs/grading_rubric.md): suggested evaluation rubric
- [docs/lab_design.md](docs/lab_design.md): learning objectives and lab design notes
- [docs/solutions_for_instructor.md](docs/solutions_for_instructor.md): reference solutions, not intended for students during assessment
- `app/`: vulnerable Flask application
- `exploits/`: helper scripts for the attacks

Before final submission, zip this folder as required by the course instructions.

## Group Members

- <!-- Name 1 -->
- João Belchior
- <!-- Name 3 -->
