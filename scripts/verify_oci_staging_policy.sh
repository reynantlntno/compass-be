#!/usr/bin/env bash
# Static guardrail for the Resource Manager Terraform source. This is a
# read-only check; the authoritative decision remains the reviewed Resource
# Manager plan before apply.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stack_dir="$repo_root/infra/oci/staging"

if [ ! -d "$stack_dir" ]; then
  echo "OCI staging stack directory is missing." >&2
  exit 1
fi

declare -A allowed=(
  [oci_core_vcn]=1
  [oci_core_internet_gateway]=1
  [oci_core_service_gateway]=1
  [oci_core_route_table]=1
  [oci_core_security_list]=1
  [oci_core_subnet]=1
  [oci_core_network_security_group]=1
  [oci_core_network_security_group_security_rule]=1
  [oci_core_instance]=1
  [oci_core_volume]=1
  [oci_core_volume_attachment]=1
  [oci_load_balancer_load_balancer]=1
  [oci_load_balancer_backend_set]=1
  [oci_load_balancer_backend]=1
  [oci_load_balancer_listener]=1
  [oci_objectstorage_bucket]=1
  [oci_kms_vault]=1
  [oci_kms_key]=1
  [oci_bastion_bastion]=1
)

unexpected=0
while read -r resource_type; do
  if [ -z "${allowed[$resource_type]+present}" ]; then
    echo "Unexpected OCI resource family in source: $resource_type" >&2
    unexpected=1
  fi
done < <(rg -o 'resource "oci_[a-z0-9_]+' "$stack_dir" --glob '*.tf' | sed 's/.*resource "//' | sort -u)

if rg -n 'oci_(psql|redis|database|core_nat_gateway|artifacts_|containerengine_|functions_|network_load_balancer|load_balancer_certificate)' "$stack_dir" --glob '*.tf'; then
  echo "A disallowed managed, NAT, registry, or load-balancer certificate resource is present." >&2
  unexpected=1
fi

instance_count=$(rg -o 'resource "oci_core_instance"' "$stack_dir" --glob '*.tf' | wc -l | tr -d ' ')
if [ "$instance_count" -ne 1 ]; then
  echo "Expected exactly one Compute instance resource; found $instance_count." >&2
  unexpected=1
fi

rg -q 'default\s*=\s*"VM\.Standard\.E5\.Flex"' "$stack_dir/variables.tf" || {
  echo "The stack is not pinned to VM.Standard.E5.Flex." >&2
  unexpected=1
}
if ! rg -q 'protocol\s*=\s*"HTTP"' "$stack_dir/main.tf" || \
   ! rg -q 'ssl_configuration\s*\{' "$stack_dir/main.tf" || \
   ! rg -q 'certificate_ids\s*=\s*\[var\.origin_certificate_id\]' "$stack_dir/main.tf"; then
  echo "The stack is missing the OCI HTTPS listener (HTTP protocol with SSL configuration)." >&2
  unexpected=1
fi
rg -q 'port\s*=\s*443' "$stack_dir/main.tf" || {
  echo "The stack is missing the HTTPS listener on port 443." >&2
  unexpected=1
}
if rg -n 'port\s*=\s*80\s*$' "$stack_dir" --glob '*.tf'; then
  echo "The stack must not expose an HTTP listener." >&2
  unexpected=1
fi
rg -q 'minimum_bandwidth_in_mbps\s*=\s*10' "$stack_dir/main.tf" || {
  echo "The LB minimum bandwidth is not 10 Mbps." >&2
  unexpected=1
}

if [ "$unexpected" -ne 0 ]; then
  exit 1
fi
echo "OCI staging resource-policy check passed. Review the Resource Manager plan before apply."
