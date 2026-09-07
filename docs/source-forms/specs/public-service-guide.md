# COMPASS human-centered content guide

This guide defines the writing rules for the COMPASS interface, notifications,
and email templates. It is a governance reference, not a CMS or a second
runtime content system. The rendered Django view, form, selector, and policy
remain authoritative.

## Voice and audience

- Use plain, respectful language. Say what happened, what the person can do
  next, and who owns the next step when that is already known.
- Write for the current role. Students need a clear service name and a safe
  next step; counselors and Head Guidance need operational context; GCO Staff
  and IT Admin need a precise scope or access explanation without confidential
  values.
- Keep privacy boundaries visible in the wording. Use approved reference codes
  where needed; never render database primary keys, raw tokens, private notes,
  or confidential narratives as a fallback label.
- Do not invent a diagnosis, risk score, fee, deadline, provider guarantee,
  emergency instruction, legal meaning, translation, or automatic escalation.
  Put unresolved policy wording in approval review instead.

## Approved terminology

| Use | Avoid on user-facing surfaces | Notes |
| --- | --- | --- |
| **Counseling Folder** / **counseling folders** | Case Record, Case Records, case record(s) | Internal route names, model classes, fields, audit codes, and migration history stay unchanged. |
| **Urgent Student Support** | Escalation Access, Emergency Escalations | Temporary access remains a record-level security action, not the service name. |
| **urgent support temporary access grant** | emergency escalation access grant | Django admin presentation label only; no database identifier is renamed. |

Official source-form titles and controlled clauses remain exact: **Good Moral
Character**, **Individual Inventory**, **Guidance Interview Permit / Call
Slip**, **Customer Feedback Form**, **Exit Interview Form**, **Students’
Profile**, **Referral Slip**, and **Routine Interview Form**. Any change to a
controlled clause requires the owning office and document-governance approval.

## Component rules and examples

### Headings and page context

Name the service first, then add the reference code or a short, non-sensitive
context. Use “Counseling Folder CAS-…” and “Urgent Student Support ESC-…”
rather than an internal model name. Keep headings sentence case except for
approved service and official form titles.

### Buttons and links

Use a verb plus the object: “Create Counseling Folder”, “Review Urgent Student
Support”, “Save draft”, or “Try again”. Avoid “Submit” without context,
“Execute”, “Workflow action”, and labels that expose an authorization mechanism.
Destructive or consequential actions use a confirmation page or dialog that
states the object and the resulting state.

### Helper text and forms

Explain why a field is needed only when that reason is already authoritative.
Use “Choose a student from the assigned scope” instead of describing a query,
primary key, or policy implementation. Validation identifies the field and the
next correction: “Choose a counselor.” Do not echo raw submitted confidential
text in a generic error summary.

### Empty, loading, and no-results states

Keep these states distinct:

- Empty: “No counseling folders are available yet. Assigned counseling folders
  will appear here.”
- No results: “No students matched that search. Try a different approved
  search term.”
- Loading: “Loading available times…”
- Unavailable: “Available times could not be loaded. You can still submit your
  request for server review.”

Do not imply that an empty result proves that no record exists outside the
actor’s authorized scope.

### Success, warnings, and failures

Name the actual outcome: “Your draft was saved”, “The request was queued for
another attempt”, or “The email was sent”. Use “could not be saved” when the
server did not persist the change. Provider unavailability is not delivery or
acceptance: say “The online session is not available right now” and preserve
the server-authoritative retry path.

### Closed, expired, and unauthorized states

Say which state applies and what can happen next: “This form is closed”, “This
link has expired”, or “You do not have access to this service.” Do not combine
closed, expired, denied, and unavailable into one ambiguous message. Do not
reveal whether a private record exists when authorization fails.

### Confirmations

Confirm the object and the transition: “Please confirm before closing this
counseling folder.” For no-op or unchanged submissions, say that nothing
changed. Keep reason fields and server-side transition rules authoritative.

### Notifications and email

Start with the service or request name, not “Dear User” or “automated
notification”. Include only the context allowlisted by the notification
contract: a safe service label, status, and approved reference code. Use
“Sign in to COMPASS to review the current status.” Do not include narratives,
raw answers, recovery tokens, secrets, or unapproved actor identity. Multipart
templates must keep their text and HTML meaning aligned.

## Approval and translation boundary

Local copy changes can use this guide when the existing state and next action
are already authoritative. GCO final terminology and bilingual review remain
open gates for FND-010. DPO/legal review is required for controlled clauses,
official forms, emergency guidance, and any wording that could change legal or
policy meaning. Do not add a translation as an implementation shortcut.
