variable "email" {
  type        = string
  default     = ""
  description = "Corporate email address of the DSPM administrator"
}

variable "resource_group_location" {
  type        = string
  description = <<EOT
The Azure region where the DSPM resource group and its resources will be created.

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
  description = "The name of the Azure resource group that Terraform will create."
}

variable "image_channel" {
  type        = string
  default     = "release"
  description = "DSPM image channel. Supported values: release, dev."

  validation {
    condition     = contains(["release", "dev"], var.image_channel)
    error_message = "image_channel must be either \"release\" or \"dev\"."
  }
}

variable "image_id" {
  type        = string
  default     = ""
  description = "Optional DSPM image version ID. When set, overrides image_channel."
}

variable "is_public" {
  type        = bool
  default     = false
  description = "Whether public IP addresses are assigned to the DSPM and Reference DataSunrise VMs."
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

variable "postgres_zone" {
  type    = string
  default = "1"
}

variable "datasunrise_custom_url" {
  type    = string
  default = ""
}
