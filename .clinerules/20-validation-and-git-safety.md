# Validation and Git safety

- Before implementation: inspect both repository status and the relevant
  branch history when the task spans backend and frontend.
- During implementation: use focused tests and lightweight checks for the
  affected apps. Add or update tests for authorization, projection allowlists,
  query scope, lifecycle eligibility, and contract changes when applicable.
- After backend contract changes: run the appropriate backend checks, export
  `openapi/compass-api.json` into the frontend repository, then let Orval
  regenerate the frontend client. Never edit generated client files manually.
- Run full-suite verification only when explicitly requested, for a release or
  defense-readiness check, or when the change risk genuinely justifies it.
- Finish with `git diff --check` and a status review. Clearly state what was
  not run.
- Do not commit, push, deploy, reset, clean, or discard changes without direct
  user authorization.
