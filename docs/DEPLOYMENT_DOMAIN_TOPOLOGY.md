# COMPASS deployment domain topology

This document records the staging hostname contract. It does not contain
credentials, certificate material, provider tokens, or private runtime
configuration.

| Host | Responsibility | Current state |
| --- | --- | --- |
| `compass-gco.com` | Future searchable Next.js production frontend | Reserved; no DNS record is created by the backend release |
| `www.compass-gco.com` | Future frontend redirect/alias | Reserved; no DNS record is created by the backend release |
| `staging.compass-gco.com` | Future searchable Next.js staging frontend | Reserved; the legacy API DNS record has been removed |
| `staging-api.compass-gco.com` | Django staging API | Verified proxied record and active staging deployment |
| `api.compass-gco.com` | Future production API | Intentionally unassigned until a separate production OCI origin exists |

## Application contract

The staging runtime uses:

```text
COMPASS_API_BASE_URL=https://staging-api.compass-gco.com
COMPASS_CLIENT_BASE_URL=https://staging.compass-gco.com
ALLOWED_HOSTS=staging-api.compass-gco.com
CORS_ALLOWED_ORIGINS=https://staging.compass-gco.com
CSRF_TRUSTED_ORIGINS=https://staging.compass-gco.com,https://staging-api.compass-gco.com
```

The Turnstile hostname remains `staging.compass-gco.com` because the widget is
served by the future frontend. The e-counseling webhook URL in repository
deployment templates points to the API host. The external Daily configuration
is updated separately through its provider control plane.

Backend API, health, documentation, protected files, and generated documents
remain non-indexable and private where applicable. The future frontend owns
its public search/indexing policy independently.

## OCI and Cloudflare cutover

Reuse the existing `COMPASS` Resource Manager stack, `compass-staging-lb`,
and its current reserved floating load-balancer address. The staging cutover
was completed using the following controlled sequence:

1. Securely provision an OCI origin certificate whose SANs cover both
   `staging-api.compass-gco.com` and `staging.compass-gco.com`.
2. Attach the certificate to the existing HTTPS listener and set the same
   certificate OCID in the Resource Manager stack.
3. Review a zero-destroy Resource Manager plan; do not apply a plan that
   replaces the load balancer, network, storage, Vault, or Bastion resources.
4. Create the proxied `staging-api` A record to the existing load-balancer IP.
5. Verify TLS, `/health/`, API headers, Cloudflare proxying, and origin access.
6. Remove the old `staging` API DNS record after the new host passes TLS and
   health verification.

The verified state is now:

- `staging-api.compass-gco.com` resolves through Cloudflare to the existing
  staging load balancer and returns a healthy API response.
- `staging.compass-gco.com` has no Cloudflare DNS record and is reserved for
  the future frontend.
- The apex, `www`, production API, and mail records were not changed.
- The origin certificate retains the old staging hostname for rollback safety,
  but the old hostname no longer routes to the Django service through DNS.

Only a scoped Cloudflare DNS token may be used locally for the DNS change.
Certificate private keys and API tokens stay in their secure provider/import
boundaries and must never be committed, logged, or pasted into chat.

Cloudflare cache rules must bypass private API, admin, documentation,
OpenAPI, protected-file, and generated-document paths. The only intentional
media cache exception is a short-lived signed branding URL. No broad bot
challenge is added to ordinary public reads; existing application abuse
controls and Turnstile policies remain authoritative.

The Vercel project may later add the exact project-provided records for the
root, `www`, and staging frontend hosts. This cutover does not create a second
OCI stack, a production API record, or a frontend placeholder record.
