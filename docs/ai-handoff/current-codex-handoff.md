# Current COMPASS Codex handoff

**Status:** Temporary cross-repository project context for a future Cline
agent. This is not a permanent policy document and is lower authority than
repository instructions, source specifications, tests, API contracts, and
implemented authorization rules.

**Updated:** September 12, 2026

## How to use this document

Use the gate:

**Investigate first -> ask only necessary questions -> establish a resolved plan -> Act.**

This document helps locate recent work and decisions. It must not be used to
justify assumptions when the repositories, contracts, tests, or specifications
say something different. When sources disagree, record and investigate the
conflict before implementation.

## Repositories and current state

The project is split across two sibling repositories:

- Backend: `/Users/reynantlntno/Projects/compass-be`
  - branch: `staging`
  - current commit: `8b62a40 feat(forms): add staff inventory and exit interview queue workspaces`
  - worktree was clean and synchronized with `origin/staging` at handoff time.
- Frontend: `/Users/reynantlntno/Projects/compass-fe`
  - branch: `staging`
  - current commit: `6c20af6 feat(portal): add forms and submissions workspace`
  - worktree was clean and synchronized with `origin/staging` at handoff time.

There is no shared repository root. This backend document is the single
canonical handoff location; do not create a duplicate in the frontend.

## Authority hierarchy

The following is a working hierarchy, not permission to ignore conflicts:

1. Current user-approved scope and decisions for the task.
2. Permanent repository instructions (`compass-fe/AGENTS.md` and the local
   `.clinerules/` files).
3. Explicit API contracts, exported OpenAPI, operation registration, tests,
   policies, selectors, services, and domain commands for their respective
   boundaries.
4. Backend source-form specifications under
   `compass-be/docs/source-forms/specs/` for form meaning and field intent.
5. READMEs and deployment/infrastructure documentation for local runtime and
   release procedures.
6. This temporary handoff for orientation and recent project context.

If code and an explicit contract/specification/test disagree, do not silently
rank the current implementation above the other source. Investigate and ask
when the conflict cannot be resolved from repository evidence.

## Completed product slices

The following slices are present in the current branches. Verify the exact
implementation before extending them:

- Portal shell, capability-aware dock overflow, portal search, and responsive
  desktop/mobile layouts.
- Shared password policy and validation across activation, recovery reset, and
  account password change.
- Plane-aware Audit Trail with Technical, Business, and Privacy presentation.
- Counselor portal home and Appointments queue with backend-authorized filters.
- Counseling workspace sections:
  - Sessions;
  - Routine Interviews;
  - Cases;
  - Urgent Support.
- Counselor session detail and e-counseling workspace with separate context
  panels, private-note boundaries, pre-intake separation, recording state, and
  a separate future student-room boundary.
- Forms & Submissions workspace with two staff-facing sections:
  - Individual Inventory;
  - Exit Interviews.

The latest Forms slice adds additive backend queue/detail operations and
capabilities, exports OpenAPI, regenerates Orval output, and adds the shared
frontend `/portal/forms` shell. It does not add student-facing form UI or
merge sensitive answers into queue rows.

## Established product and architecture decisions

- Backend authorization remains final. Frontend capability snapshots control
  visibility only; the UI must not infer roles or broaden row scope.
- Safe queue projections are allowlists. Do not render raw IDs, emails,
  control numbers, actor relations, encrypted fields, notes, narratives,
  traces, request IDs, or backend diagnostics unless an explicit contract
  allows the field.
- API contract changes follow the sequence: backend operation/schema/policy
  work -> OpenAPI export -> `pnpm api:generate` -> frontend adapter/UI.
- Frontend adapters may keep generated request identifiers only in in-memory,
  request-local state when the generated operation requires them. Do not put
  them in URLs, storage, analytics, logs, or frontend domain types.
- Separate staff workflows from student-facing workflows. Do not duplicate
  Referral, Call Slip, or student form creation inside Counseling.
- Counseling Session Detail is counselor-side. The student session room is a
  separate future route and permission boundary.
- Private counselor notes, evaluation data, intake answers, shared summaries,
  and recording controls must remain distinct and policy-gated. Recording is
  never automatic.
- Do not invent metrics, aggregates, reports, actions, capabilities, picker
  data, or sensitive access that the backend does not provide.
- Reuse existing workspace composition and state patterns: page header,
  workspace navigation, filter panel, collection frame, semantic responsive
  tables, left-aligned empty/error states, safe detail expansion, focus states,
  reduced motion, forced colors, safe areas, and dock offsets.

## Important locations

Backend:

- `apps/access_control/` — capability catalog, authority resolution, grants,
  coverage, and scope primitives.
- `apps/common/api/` — operation registry, shared API preparation, pagination,
  errors, idempotency, and contract tests.
- `apps/counseling/` — sessions, routine interviews, cases, urgent support,
  e-counseling, recording, and counseling policies.
- `apps/inventory/` — Individual Inventory models, selectors, policies,
  queries, queue projections, and API.
- `apps/exit_interviews/` — Exit Interview models, selectors, policies,
  queue projections, sensitive detail, lifecycle services, and API.
- `docs/source-forms/specs/` — source-form field and meaning references.
- `README.md`, `compose.local-staging.yaml`, and `deploy/` — local staging
  and deployment procedures.

Frontend:

- `src/app/(portal)/portal/` — portal routes, loading, and error boundaries.
- `src/components/portal/` — portal shell, navigation, workspace layouts,
  filters, tables, and state patterns.
- `src/lib/api/` — non-generated adapters and API transport helpers.
- `src/lib/api/generated/` — Orval output; never edit manually.
- `openapi/compass-api.json` — generated API snapshot.
- `AGENTS.md` — detailed Next.js and COMPASS frontend rules.

## Validation already performed

For the Forms & Submissions slice, the following was verified before this
handoff:

- Backend `manage.py check` passed in the local Podman web container.
- Targeted backend coverage for inventory, exit interviews, access control,
  common API contracts, and the new queue projections passed under the testing
  settings (`119` tests in the final run).
- OpenAPI was exported from the backend container and Orval regeneration
  completed successfully.
- Frontend TypeScript check, lint, and production build passed.
- `git diff --check` passed before the commits were created.

The host Python environment does not provide the project Django installation;
use the repository's documented Podman/testing workflow rather than silently
substituting a different runtime.

## Future work and boundaries

No next feature is approved by this handoff. Likely future areas discussed so
far include:

- Referrals and Call Slips as separate operational workspaces;
- Reports, starting with profiling and read-only aggregate views;
- Head Guidance administration/configuration, including academic terms,
  form families/revisions, branding, and capability administration;
- Graduate Tracer, CSM/service feedback, and Good Moral workflows.

Do not choose among these silently. Inspect the current backend contracts and
ask the user when the next priority or ownership boundary is not explicit.

## Known unresolved questions

- Which of the future work areas should be implemented next?
- For each future form/report workflow, which role owns creation, review,
  aggregation, release, and sensitive-detail access?
- Are any new backend projections or capabilities needed, or can an existing
  selector/contract support the requested slice?

Resolve these through repository inspection and a targeted user question when
they materially affect the design. Do not treat this list as a requirement to
add features.

## Handoff checklist for the next agent

1. Read the applicable repository `AGENTS.md` and `.clinerules/` files.
2. Read this handoff only for orientation; verify current branches and status.
3. Inspect the affected policies, selectors, API operations, generated client,
   tests, and source-form specifications.
4. Propose a bounded plan with assumptions, risks, security/privacy impact,
   files, and targeted verification.
5. Wait for a resolved plan before editing.
6. Preserve unrelated work and report exact validation and remaining gaps.
