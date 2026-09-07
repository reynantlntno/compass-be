output "region" {
  value = var.region
}

output "vcn_id" {
  value = oci_core_vcn.compass.id
}

output "app_instance_id" {
  value = oci_core_instance.app.id
}

output "app_private_ip" {
  value = data.oci_core_private_ips.app.private_ips[0].ip_address
}

output "app_ephemeral_public_ip" {
  value = data.oci_core_public_ip.app.ip_address
}

output "load_balancer_id" {
  value = oci_load_balancer_load_balancer.compass.id
}

output "load_balancer_public_ip" {
  value = try(oci_load_balancer_load_balancer.compass.ip_address_details[0].ip_address, "")
}

output "bastion_id" {
  value = oci_bastion_bastion.compass.id
}

output "protected_bucket_name" {
  value = oci_objectstorage_bucket.protected.name
}

output "backup_bucket_name" {
  value = oci_objectstorage_bucket.backups.name
}

output "object_storage_namespace" {
  value = var.namespace
}

output "vault_id" {
  value = oci_kms_vault.compass.id
}

output "storage_kms_key_id" {
  value = oci_kms_key.storage.id
}

output "approved_resource_allowlist" {
  value = [
    "oci_core_vcn",
    "oci_core_internet_gateway",
    "oci_core_service_gateway",
    "oci_core_route_table",
    "oci_core_security_list",
    "oci_core_subnet",
    "oci_core_network_security_group",
    "oci_core_network_security_group_security_rule",
    "oci_core_instance",
    "oci_core_volume",
    "oci_core_volume_attachment",
    "oci_load_balancer_load_balancer",
    "oci_load_balancer_backend_set",
    "oci_load_balancer_backend",
    "oci_load_balancer_listener",
    "oci_objectstorage_bucket",
    "oci_kms_vault",
    "oci_kms_key",
    "oci_bastion_bastion",
  ]
}
