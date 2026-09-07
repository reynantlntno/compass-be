# COMPASS OCI staging stack

This directory is the Terraform source for the existing OCI Resource Manager
stack. It is not intended to be run with a local state file. Upload the
directory as a zip to the existing Resource Manager stack and keep state in
OCI.

The stack is pinned to `ap-singapore-1` and creates only the approved staging
resource families:

- VCN, Internet Gateway, Service Gateway, route table, subnets, security list,
  NSGs, and NSG rules;
- one paid `VM.Standard.E5.Flex` instance at 2 OCPUs/12 GB with a 50 GB boot
  volume;
- one 100 GB Block Volume and one paravirtualized attachment;
- one public Flexible Load Balancer at 10 Mbps, with an HTTPS listener on 443,
  a backend on port 8080, and a `/health/` check;
- two private, versioned Object Storage buckets using the Singapore S3
  compatibility endpoint;
- one standard Bastion and one default software Vault with one storage key.

The origin certificate is created/imported through OCI Certificates Service
outside Terraform. For the staging API cutover, the certificate must cover
`staging-api.compass-gco.com` and retain `staging.compass-gco.com` as a
rollback SAN. Terraform receives only its certificate OCID and never receives
PEM or private-key values. There is intentionally no managed
PostgreSQL, OCI Cache/Redis, NAT Gateway, OCIR, alternative Compute shape,
listener on port 80, or other application platform resource in this stack.
Secret values are not Terraform variables.

## Resource Manager workflow

1. Run `scripts/verify_oci_staging_policy.sh` from the repository root.
2. Create a zip containing only the files in this directory. Do not include
   Terraform state or any `.tfvars` file.
3. Upload the zip to the existing Resource Manager stack. Do not create a
   second VCN, Load Balancer, Vault, or bucket set.
4. Set or verify `tenancy_ocid`, `compartment_ocid`, `ssh_public_key`,
   `origin_certificate_id`, the selected availability domain, and the pinned
   x86 image OCID. Keep `region` at `ap-singapore-1`.
5. Review the plan. Stop if it contains a destroy/recreate of existing
   network, storage, Vault, Bastion, or Load Balancer resources, an unapproved
   resource family, a non-E5 shape, an HTTP listener, or a listener without
   the certificate OCID.
6. Apply only after the capacity report and zero-destroy plan are approved.

The existing `compass-staging-lb` and its reserved floating address are
reused. Create the proxied `staging-api.compass-gco.com` DNS record only after
the replacement certificate is attached and the API release is ready. Remove
the old `staging.compass-gco.com` API record immediately after the new host
passes TLS and health verification. The root, `www`, and future frontend
records remain outside this stack.

The app VNIC has an ephemeral public IP for outbound updates/provider calls.
The app NSG and host firewall do not allow public ports 8080, 5432, or 6379.
The LB listener accepts port 443 only from Cloudflare CIDRs, and SSH is
reachable through Bastion only.

## Post-apply order

1. Read Resource Manager outputs for the instance private/public IPs, LB IP,
   Bastion OCID, Vault OCID, and bucket names.
2. From a clean, reviewed commit, run
   `scripts/verify_staging_release_policy.sh` and
   `scripts/oci/package_staging_release.sh /tmp/compass-staging-release`.
   Transfer only the generated image archive, release bundle, and manifest
   through a Bastion-managed SSH session. Never transfer the repository or
   local runtime data.
3. Create root-owned Podman secrets from the OCI Vault secret map.
4. Start the self-contained `compose.staging.yaml` with
   `/etc/compass/staging.env`.
5. Run migrations, static collection, and read-only readiness checks against
   the blank database. Do not run demo seed commands.
6. Verify the HTTPS health endpoint and the health-only 503 boundary. Provider
   credentials may be staged for readiness, but SMTP, Turnstile verification,
   notification, and real user-flow activation remain deferred.
