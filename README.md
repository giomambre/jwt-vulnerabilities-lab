# JWT Vulnerabilities Laboratory

This mini-project is a Dockerized Flask lab for learning common JWT implementation vulnerabilities.

Students complete starter exploit scripts, collect evidence of successful attacks, then edit the server-side validation code to harden the application.

1. `alg:none` and claim tampering
2. RS256 to HS256 algorithm confusion
3. `kid` header path traversal
4. Secure JWT validation and hardening

## Run

```bash
docker compose up --build
```

The lab listens on `http://localhost:5000`.

On Windows PowerShell, if `docker` is not found immediately after installing Docker Desktop, restart the terminal or add Docker's bin directory for the current session:

```powershell
$env:PATH='C:\Program Files\Docker\Docker\resources\bin;' + $env:PATH
```

## Student Credentials

| Username | Password | Role |
| --- | --- | --- |
| `alice` | `password123` | `user` |
| `admin` | `admin123` | `admin` |

## Deliverables

- `docs/theory.md`: theoretical background
- `docs/student_guide.md`: practical lab guide
- `docs/report_template.md`: suggested student report structure
- `docs/hints.md`: progressive hints for students who get stuck
- `docs/grading_rubric.md`: suggested evaluation rubric
- `docs/lab_design.md`: learning objectives and lab design notes
- `docs/solutions_for_instructor.md`: reference solutions, not intended for students during assessment
- `app/`: vulnerable Flask application
- `exploits/`: helper scripts for the attacks
- `developers.txt`: group members

Before final submission, add all group member names to `developers.txt` and zip this folder as required by the course instructions.
