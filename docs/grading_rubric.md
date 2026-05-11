# Suggested Grading Rubric

This rubric can be used by instructors or teaching assistants when evaluating the lab submission.

| Component | Expected evidence |
| --- | --- |
| Task 1 exploit | Student completes the `alg:none` TODOs, obtains admin access, and explains missing signature verification |
| Task 2 exploit | Student completes the algorithm confusion TODOs, obtains admin access, and explains RS256 vs HS256 |
| Task 3 exploit | Student completes the `kid` traversal TODOs, obtains admin access, and explains unsafe key lookup |
| Hardening | Student implements secure validation in `student_secure_decode_rs256()` |
| Verification | Legitimate admin token works and forged tokens are rejected by `/fixed/admin` |
| Explanation quality | Answers connect each exploit to the corresponding validation failure |

Strong submissions should include terminal outputs, completed code snippets, and concise explanations of root causes and defenses.
