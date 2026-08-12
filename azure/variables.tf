variable "email" {
  type        = string
  description = "Corporate email address of the DSPM administrator"
}

variable "datasunrise_password" {
  type        = string
  sensitive   = true
  description = <<EOF
  Create a new password for the reference DataSunrise server.
  The reference DataSunrise server is needed to centrally configure target DataSunrise instances.
  Must be at least 8 characters, contain upper and lowercase Latin letters, numbers, symbols:
  !#$%&\()*+,-./:;<=>?@[]^_`"'{|}~"
  EOF
}

variable "resource_group_location" {
  type        = string
  description = <<EOT
The Azure region (location) where the new resource group and associated resources will be created.

Requirements:
- The value must be in lowercase with no spaces (i.e., in lower_snake_case format), e.g., "eastus", "westeurope", "northeurope".
- The region must support **Azure Database for PostgreSQL - Flexible Server**.
- The region must support the required SKU: **B_Standard_B2s**.
- The region must support **Availability Zone 1** for the selected SKU.
- The region must also have access to **DSPM community images** (from the 'datasunrise' public shared image gallery).

To check if DSPM images are available in a region, use the following command:

  az sig image-definition list-community --public-gallery-name datasunrise-c6a43e8c-c5f9-4e77-aeb7-29f27c10a8d4 --location <your-region>

For example:

  az sig image-definition list-community --public-gallery-name datasunrise-c6a43e8c-c5f9-4e77-aeb7-29f27c10a8d4 --location eastus

Make sure the command returns a list of images. If the list is empty, the region is not supported.
EOT
}


variable "resource_group_name" {
  type        = string
  description = "The name of the new Azure resource group to be created."
}

variable "image_id" {
  type    = string
  default = ""
}


variable "pathPublicKey" {
  type    = string
  default = "~/.ssh/id_rsa.pub"
}

variable "username" {
  type        = string
  description = "The username for the local account that will be created on the new VM."
  default     = "azureuser"
}

variable "postgres_password" {
  type        = string
  sensitive   = true
  description = "Create a new password for the database where DSPM configuration settings and data will be stored"
}

variable "postgres_zone" {
  type    = string
  default = "1"
}

variable "allow_cidr_to_backend_8080" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR IP range from which the DSPM web interface will be accessible"
}

variable "allow_cidr_to_ssh_22" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR IP range from which SSH access to the DSPM VM instance will be allowed"
}

variable "datasunrise_custom_url" {
  type    = string
  default = ""
}
