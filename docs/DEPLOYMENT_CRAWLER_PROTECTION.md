# COMPASS crawler protection

The Django service host is not an indexable public website. In staging, that
host is `staging-api.compass-gco.com`; the future Next.js frontend will use
`staging.compass-gco.com` and is a separate indexing contract. The backend
must publish its noindex policy for API, health, documentation, error,
document, asset, and backend HTML responses without imposing that policy on
the future public frontend.

## Application contract

- `GET https://staging-api.compass-gco.com/robots.txt` returns a static
  directive with `Disallow: /` and explicit rules for `/api/`, `/admin/`,
  `/docs/`, and `/openapi.json`. The same service contract applies to a future
  production API host only after a production origin exists.
- Django responses carry `X-Robots-Tag: noindex, nofollow, noarchive`.
- Private API and protected-file responses remain `Cache-Control: no-store`.
- Signed branding content is the only intentional public CDN-cache exception;
  its cache lifetime must not exceed the signed URL lifetime. This is the
  signed branding-content path, not a public storage URL.
- No directory listing or public protected-media location may be enabled.

## Cloudflare deployment contract

The application repository does not manage the Cloudflare dashboard. Before a
staging deployment, verify these rules on the proxied
`staging-api.compass-gco.com` hostname:

1. Bypass caching for `/api/*`, `/admin/*`, `/docs/*`, `/openapi.json`, and
   protected media. Do not cache authenticated or sensitive responses.
2. Keep the signed branding-content path cacheable only by its complete,
   short-lived signed URL. Do not transform it into a public storage URL.
3. Use WAF/bot controls and rate limits for abuse-prone flows such as
   authentication, recovery, activation, contact submission, invitation/token
   verification, e-counseling join, and escalated student search.
4. Do not challenge ordinary public reads solely because they are automated;
   the existing central Turnstile and abuse-action registry remains the source
   of truth for application challenges.
5. Confirm the origin remains reachable only through the approved Cloudflare
   proxy path and that no alternate origin hostname is publicly exposed.

`robots.txt` and `X-Robots-Tag` discourage compliant crawlers; they do not
provide authorization or stop malicious clients. Authentication, authorization,
protected storage, rate limiting, and edge controls remain the security boundary.

The future Next.js hosts are intentionally different:

- `compass-gco.com` and `www.compass-gco.com` remain reserved for the
  searchable public frontend;
- `staging.compass-gco.com` remains the future searchable staging frontend;
- no frontend DNS record is created until its Vercel project exists;
- the frontend must independently define its own `robots.txt`, HTML metadata,
  and response-header policy. It must not inherit the Django API's blanket
  noindex policy merely because both hosts share the parent domain.
