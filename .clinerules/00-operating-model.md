# COMPASS Cline operating model

These are permanent working rules for Cline in the COMPASS backend repository.

## Work sequence

Use this gate for every non-trivial task:

**Investigate first -> ask only necessary questions -> establish a resolved plan -> act.**

- Inspect the affected code, dependencies, tests, contracts, and relevant
  documentation before proposing implementation.
- Distinguish repository facts, user decisions, assumptions, and unresolved
  questions. Do not silently turn an assumption into a product decision.
- Plan Mode is investigation and planning only. Do not edit files, run
  mutations, or begin implementation from an unresolved plan.
- Ask a targeted question only when the answer cannot be established by
  inspecting the repository and would materially affect scope, architecture,
  security, privacy, compatibility, data integrity, workflow behavior, or UX.
- If code conflicts with an explicit specification, API contract, test,
  permanent instruction, or user decision, treat it as a conflict to
  investigate. Do not assume the current implementation is automatically
  correct or automatically wrong.

## Implementation discipline

- Follow the resolved plan and preserve existing architecture unless a change
  is justified in the plan.
- Keep the patch scoped. Avoid opportunistic refactors, renames, migrations,
  or generated-file edits outside the task.
- If implementation reveals a material contradiction or unexpected boundary,
  stop and return to planning.
- Never conceal failed checks, skipped verification, incomplete work, or
  unresolved risks.

## Change safety

- Inspect `git status` before editing and preserve unrelated user changes.
- Never use reset, clean, broad revert, or destructive commands to solve an
  unrelated problem.
- Report the modified files, important assumptions, validation performed, and
  remaining work. Do not commit, push, or deploy unless explicitly requested.
