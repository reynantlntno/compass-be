# COMPASS backend boundaries

Use the existing backend architecture as the implementation context; do not
copy the whole project blueprint into these rules.

## Authority and contracts

- Django policies, selectors, services, and domain commands own
  authorization, row scope, lifecycle eligibility, privacy, and business
  rules. API adapters must not replace them with frontend or role guesses.
- The API operation registry and exported OpenAPI document define the public
  API boundary. When a contract changes, update the operation registration and
  regenerate the frontend client through the approved workflow.
- Safe projections are deliberate allowlists. Do not expose database IDs,
  actor relations, emails, encrypted fields, notes, narratives, traces, or
  backend diagnostics unless an explicit approved contract permits them.
- Preserve CSRF, idempotency, audit events, rate limits, session/trusted-device
  behavior, conflict handling, and safe error envelopes.
- Do not weaken an existing student-facing contract to create a staff queue;
  add a separate projection or operation when the boundary requires it.

## Runtime and verification

- Follow the repository README and deployment documentation for Podman,
  local-staging secrets, and release operations. Do not invent alternate
  runtime topology or commit local credentials.
- Prefer targeted Django tests, `manage.py check`, relevant migration/check
  commands, OpenAPI export, and contract tests for the changed area. Do not
  run the entire suite by default.
- Treat source-form specifications under `docs/source-forms/specs/` as the
  reference for form meaning and fields. If they conflict with code or an API
  contract, stop and resolve the conflict instead of silently choosing one.
