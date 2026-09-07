variable "tenancy_ocid" {
  description = "OCID of the tenancy that owns the staging resources."
  type        = string
  nullable    = false
}

variable "compartment_ocid" {
  description = "Target compartment OCID; empty uses the tenancy root compartment."
  type        = string
  default     = ""
  nullable    = false
}

variable "region" {
  description = "OCI home region for this stack."
  type        = string
  default     = "ap-singapore-1"
  nullable    = false

  validation {
    condition     = var.region == "ap-singapore-1"
    error_message = "This approved staging stack is pinned to ap-singapore-1."
  }
}

variable "availability_domain" {
  description = "Availability domain for the single x86 instance and data volume."
  type        = string
  default     = "cNRC:AP-SINGAPORE-1-AD-1"
  nullable    = false
}

variable "image_ocid" {
  description = "Pinned x86 Oracle Linux image OCID for the Compute instance."
  type        = string
  default     = "ocid1.image.oc1.ap-singapore-1.aaaaaaaaisvsyetgr6ss66ix3ru7dbpmqsoe6jupfuwqoij6ar42f3c2354a"
  nullable    = false
}

variable "instance_shape" {
  description = "Paid trial Compute shape selected for staging capacity."
  type        = string
  default     = "VM.Standard.E5.Flex"
  nullable    = false

  validation {
    condition     = var.instance_shape == "VM.Standard.E5.Flex"
    error_message = "This staging stack is approved only for VM.Standard.E5.Flex."
  }
}

variable "instance_ocpus" {
  description = "Number of OCPUs assigned to the staging instance."
  type        = number
  default     = 2
  nullable    = false

  validation {
    condition     = var.instance_ocpus == 2
    error_message = "The staging instance must use exactly 2 OCPUs."
  }
}

variable "instance_memory_in_gbs" {
  description = "Memory assigned to the staging instance in GB."
  type        = number
  default     = 12
  nullable    = false

  validation {
    condition     = var.instance_memory_in_gbs == 12
    error_message = "The staging instance must use exactly 12 GB of memory."
  }
}

variable "origin_certificate_id" {
  description = "OCID of the certificate stored in OCI Certificates Service for the HTTPS listener."
  type        = string
  nullable    = false

  validation {
    condition     = startswith(trimspace(var.origin_certificate_id), "ocid1.certificate.oc1.")
    error_message = "Provide an OCI Certificates Service certificate OCID; PEM and private-key values are not accepted."
  }
}

variable "cloudflare_ipv4_cidrs" {
  description = "Cloudflare IPv4 ranges allowed to reach the public HTTPS listener."
  type        = list(string)
  default = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
  ]
}

variable "cloudflare_ipv6_cidrs" {
  description = "Cloudflare IPv6 ranges allowed to reach the public HTTPS listener."
  type        = list(string)
  default = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
  ]
}

variable "ssh_public_key" {
  description = "Public SSH key installed for Bastion-managed access to opc."
  type        = string
  nullable    = false

  validation {
    condition     = length(trimspace(var.ssh_public_key)) > 20 && !strcontains(var.ssh_public_key, "PRIVATE KEY")
    error_message = "Provide an actual SSH public key, never private key material."
  }
}

variable "namespace" {
  description = "Object Storage namespace returned by oci os ns get."
  type        = string
  default     = "axhpojfzy4cq"
  nullable    = false
}

variable "name_prefix" {
  description = "Prefix applied to all staging resource display names."
  type        = string
  default     = "compass-staging"
  nullable    = false
}

variable "vcn_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "lb_subnet_cidr" {
  type    = string
  default = "10.0.10.0/24"
}

variable "app_subnet_cidr" {
  type    = string
  default = "10.0.20.0/24"
}

variable "bastion_subnet_cidr" {
  type    = string
  default = "10.0.30.0/24"
}

variable "protected_bucket_name" {
  description = "Private bucket for protected media."
  type        = string
  default     = "compass-private-staging"
}

variable "backup_bucket_name" {
  description = "Private, versioned, Vault-encrypted bucket for backups."
  type        = string
  default     = "compass-backups-staging"
}

variable "bastion_client_cidr_block_allow_list" {
  description = "CIDR allowlist for creating Bastion sessions; provide the current operator IP as a /32."
  type        = list(string)

  validation {
    condition     = length(var.bastion_client_cidr_block_allow_list) > 0 && alltrue([for cidr in var.bastion_client_cidr_block_allow_list : cidr != "0.0.0.0/0"])
    error_message = "Bastion access must use a non-empty narrow CIDR allowlist; 0.0.0.0/0 is not permitted."
  }
}

variable "bastion_session_ttl_seconds" {
  type    = number
  default = 3600
}
