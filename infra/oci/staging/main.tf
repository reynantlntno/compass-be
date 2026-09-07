locals {
  compartment_id = var.compartment_ocid == "" ? var.tenancy_ocid : var.compartment_ocid

  common_tags = {
    "compass:environment"   = "staging"
    "compass:billing-class" = "trial-credit"
    "compass:region"        = var.region
  }
}

data "oci_core_services" "all" {
  filter {
    name   = "name"
    values = ["All .* Services In Oracle Services Network"]
    regex  = true
  }
}

resource "oci_core_vcn" "compass" {
  compartment_id = local.compartment_id
  cidr_block     = var.vcn_cidr
  display_name   = "${var.name_prefix}-vcn"
  dns_label      = "compass"
  is_ipv6enabled = false
  freeform_tags  = local.common_tags
}

resource "oci_core_internet_gateway" "compass" {
  compartment_id = local.compartment_id
  display_name   = "${var.name_prefix}-igw"
  enabled        = true
  vcn_id         = oci_core_vcn.compass.id
  freeform_tags  = local.common_tags
}

resource "oci_core_service_gateway" "compass" {
  compartment_id = local.compartment_id
  display_name   = "${var.name_prefix}-service-gateway"
  vcn_id         = oci_core_vcn.compass.id
  freeform_tags  = local.common_tags

  services {
    service_id = data.oci_core_services.all.services[0].id
  }
}

resource "oci_core_route_table" "public" {
  compartment_id = local.compartment_id
  vcn_id         = oci_core_vcn.compass.id
  display_name   = "${var.name_prefix}-public-routes"
  freeform_tags  = local.common_tags

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.compass.id
  }
}

resource "oci_core_route_table" "private_services" {
  compartment_id = local.compartment_id
  vcn_id         = oci_core_vcn.compass.id
  display_name   = "${var.name_prefix}-private-service-routes"
  freeform_tags  = local.common_tags

  route_rules {
    destination       = data.oci_core_services.all.services[0].cidr_block
    destination_type  = "SERVICE_CIDR_BLOCK"
    network_entity_id = oci_core_service_gateway.compass.id
  }
}

# Subnets attach this deliberately empty-ingress security list. NSGs then add
# only the LB->app and Bastion->SSH flows required by this baseline.
resource "oci_core_security_list" "empty_ingress" {
  compartment_id = local.compartment_id
  vcn_id         = oci_core_vcn.compass.id
  display_name   = "${var.name_prefix}-empty-ingress"
  freeform_tags  = local.common_tags

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    stateless   = false
  }
}

resource "oci_core_subnet" "lb" {
  compartment_id             = local.compartment_id
  vcn_id                     = oci_core_vcn.compass.id
  cidr_block                 = var.lb_subnet_cidr
  display_name               = "${var.name_prefix}-lb-subnet"
  dns_label                  = "lb"
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.empty_ingress.id]
  freeform_tags              = local.common_tags
}

resource "oci_core_subnet" "app" {
  compartment_id             = local.compartment_id
  vcn_id                     = oci_core_vcn.compass.id
  cidr_block                 = var.app_subnet_cidr
  display_name               = "${var.name_prefix}-app-subnet"
  dns_label                  = "app"
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.empty_ingress.id]
  freeform_tags              = local.common_tags
}

resource "oci_core_subnet" "bastion" {
  compartment_id             = local.compartment_id
  vcn_id                     = oci_core_vcn.compass.id
  cidr_block                 = var.bastion_subnet_cidr
  display_name               = "${var.name_prefix}-bastion-subnet"
  dns_label                  = "bastion"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.private_services.id
  security_list_ids          = [oci_core_security_list.empty_ingress.id]
  freeform_tags              = local.common_tags
}

resource "oci_core_network_security_group" "lb" {
  compartment_id = local.compartment_id
  display_name   = "${var.name_prefix}-lb-nsg"
  vcn_id         = oci_core_vcn.compass.id
  freeform_tags  = local.common_tags
}

resource "oci_core_network_security_group" "app" {
  compartment_id = local.compartment_id
  display_name   = "${var.name_prefix}-app-nsg"
  vcn_id         = oci_core_vcn.compass.id
  freeform_tags  = local.common_tags
}

resource "oci_core_network_security_group_security_rule" "lb_to_app_8080" {
  network_security_group_id = oci_core_network_security_group.app.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = oci_core_network_security_group.lb.id
  source_type               = "NETWORK_SECURITY_GROUP"
  stateless                 = false
  description               = "Only the OCI LB NSG may reach the app proxy."

  tcp_options {
    destination_port_range {
      min = 8080
      max = 8080
    }
  }
}

resource "oci_core_network_security_group_security_rule" "bastion_to_app_ssh" {
  network_security_group_id = oci_core_network_security_group.app.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = oci_core_subnet.bastion.cidr_block
  source_type               = "CIDR_BLOCK"
  stateless                 = false
  description               = "SSH is reachable only from the Bastion target subnet."

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "app_egress" {
  network_security_group_id = oci_core_network_security_group.app.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false
  description               = "Outbound updates and approved provider calls only."
}

resource "oci_core_network_security_group_security_rule" "lb_to_app_egress" {
  network_security_group_id = oci_core_network_security_group.lb.id
  direction                 = "EGRESS"
  protocol                  = "6"
  destination               = oci_core_subnet.app.cidr_block
  destination_type          = "CIDR_BLOCK"
  stateless                 = false
  description               = "The LB may forward only to the app proxy port."

  tcp_options {
    destination_port_range {
      min = 8080
      max = 8080
    }
  }
}

resource "oci_core_network_security_group_security_rule" "cloudflare_to_lb_https" {
  # The existing VCN is intentionally IPv4-only and Cloudflare has an A
  # record for the origin. OCI rejects IPv6 NSG rules on this VCN; keep the
  # IPv6 ranges parameterized for a future IPv6 VCN migration instead of
  # attempting to create invalid rules here.
  for_each = toset(var.cloudflare_ipv4_cidrs)

  network_security_group_id = oci_core_network_security_group.lb.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = each.value
  source_type               = "CIDR_BLOCK"
  stateless                 = false
  description               = "Only Cloudflare proxied traffic may reach the HTTPS listener."

  tcp_options {
    destination_port_range {
      min = 443
      max = 443
    }
  }
}

resource "oci_kms_vault" "compass" {
  compartment_id = local.compartment_id
  display_name   = "${var.name_prefix}-vault"
  vault_type     = "DEFAULT"
  freeform_tags  = local.common_tags
}

resource "oci_kms_key" "storage" {
  compartment_id      = local.compartment_id
  display_name        = "${var.name_prefix}-storage-key"
  management_endpoint = oci_kms_vault.compass.management_endpoint
  protection_mode     = "SOFTWARE"
  freeform_tags       = local.common_tags

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

resource "oci_objectstorage_bucket" "protected" {
  compartment_id        = local.compartment_id
  namespace             = var.namespace
  name                  = var.protected_bucket_name
  access_type           = "NoPublicAccess"
  storage_tier          = "Standard"
  versioning            = "Enabled"
  object_events_enabled = false
  freeform_tags         = local.common_tags
}

resource "oci_objectstorage_bucket" "backups" {
  compartment_id        = local.compartment_id
  namespace             = var.namespace
  name                  = var.backup_bucket_name
  access_type           = "NoPublicAccess"
  storage_tier          = "Standard"
  versioning            = "Enabled"
  object_events_enabled = false
  freeform_tags         = local.common_tags
}

resource "oci_bastion_bastion" "compass" {
  compartment_id               = local.compartment_id
  name                         = "${var.name_prefix}-bastion"
  bastion_type                 = "STANDARD"
  target_subnet_id             = oci_core_subnet.bastion.id
  client_cidr_block_allow_list = var.bastion_client_cidr_block_allow_list
  max_session_ttl_in_seconds   = var.bastion_session_ttl_seconds
  freeform_tags                = local.common_tags

  # OCI treats the Bastion name as immutable. The existing stack predates the
  # staging naming normalization, so changing it would destroy and recreate
  # the access path. Keep the legacy name in place until an explicit Bastion
  # migration is approved.
  lifecycle {
    ignore_changes = [name]
  }
}

resource "oci_core_instance" "app" {
  availability_domain = var.availability_domain
  compartment_id      = local.compartment_id
  display_name        = "${var.name_prefix}-app"
  shape               = var.instance_shape
  freeform_tags       = local.common_tags

  agent_config {
    are_all_plugins_disabled = false
    is_management_disabled   = false
    is_monitoring_disabled   = false

    plugins_config {
      desired_state = "ENABLED"
      name          = "Bastion"
    }
  }

  shape_config {
    ocpus         = var.instance_ocpus
    memory_in_gbs = var.instance_memory_in_gbs
  }

  source_details {
    source_id               = var.image_ocid
    source_type             = "image"
    boot_volume_size_in_gbs = 50
  }

  create_vnic_details {
    assign_public_ip = true
    hostname_label   = "compassapp"
    nsg_ids          = [oci_core_network_security_group.app.id]
    subnet_id        = oci_core_subnet.app.id
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = base64encode(file("${path.module}/cloud-init.yaml"))
  }

  # Cloud-init is first-boot configuration. The existing staging VM was
  # bootstrapped and is managed through the release runbook; changing the
  # rendered user-data must not replace the VM or detach its data volume.
  lifecycle {
    ignore_changes = [metadata["user_data"]]
  }
}

resource "oci_core_volume" "data" {
  availability_domain = var.availability_domain
  compartment_id      = local.compartment_id
  display_name        = "${var.name_prefix}-data"
  size_in_gbs         = 100
  freeform_tags       = local.common_tags
}

resource "oci_core_volume_attachment" "data" {
  attachment_type = "paravirtualized"
  device          = "/dev/oracleoci/oraclevdb"
  display_name    = "${var.name_prefix}-data-attachment"
  instance_id     = oci_core_instance.app.id
  volume_id       = oci_core_volume.data.id
}

data "oci_core_vnic_attachments" "app" {
  compartment_id = local.compartment_id
  instance_id    = oci_core_instance.app.id
}

data "oci_core_private_ips" "app" {
  vnic_id = data.oci_core_vnic_attachments.app.vnic_attachments[0].vnic_id
}

data "oci_core_public_ip" "app" {
  private_ip_id = data.oci_core_private_ips.app.private_ips[0].id
}

resource "oci_load_balancer_load_balancer" "compass" {
  compartment_id             = local.compartment_id
  display_name               = "${var.name_prefix}-lb"
  shape                      = "flexible"
  subnet_ids                 = [oci_core_subnet.lb.id]
  is_private                 = false
  network_security_group_ids = [oci_core_network_security_group.lb.id]
  freeform_tags              = local.common_tags

  shape_details {
    minimum_bandwidth_in_mbps = 10
    maximum_bandwidth_in_mbps = 10
  }
}

resource "oci_load_balancer_backend_set" "compass" {
  load_balancer_id = oci_load_balancer_load_balancer.compass.id
  name             = "compass-backend"
  policy           = "ROUND_ROBIN"

  health_checker {
    protocol            = "HTTP"
    port                = 8080
    url_path            = "/health/"
    return_code         = 200
    interval_ms         = 10000
    timeout_in_millis   = 3000
    retries             = 3
    is_force_plain_text = true
  }
}

resource "oci_load_balancer_listener" "https" {
  load_balancer_id         = oci_load_balancer_load_balancer.compass.id
  name                     = "compass-https"
  default_backend_set_name = oci_load_balancer_backend_set.compass.name
  # OCI models an HTTPS listener as HTTP plus an SSL configuration. The API
  # rejects HTTPS as a listener protocol enum.
  protocol = "HTTP"
  port     = 443

  ssl_configuration {
    certificate_ids         = [var.origin_certificate_id]
    protocols               = ["TLSv1.2", "TLSv1.3"]
    verify_peer_certificate = false
  }
}

resource "oci_load_balancer_backend" "compass" {
  load_balancer_id = oci_load_balancer_load_balancer.compass.id
  backendset_name  = oci_load_balancer_backend_set.compass.name
  ip_address       = data.oci_core_private_ips.app.private_ips[0].ip_address
  port             = 8080
  weight           = 1
  drain            = false
  offline          = false
  backup           = false
}
