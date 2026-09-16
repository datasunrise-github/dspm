variable "email" {
  type        = string
  description = "Corporate email address of the DSPM administrator"
}

variable "region" {
  type        = string
  description = "AWS region where the infrastructure will be deployed"
}

variable "access_key" {
  type      = string
  sensitive = true
}

variable "secret_key" {
  type      = string
  sensitive = true
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

variable "image_type" {
  type    = string
  default = "release"
  validation {
    condition     = contains(["dev", "rc", "release"], var.image_type)
    error_message = "Valid values for 'image_type': dev, rc, release"
  }
}

variable "s3_bucket_name" {
  type        = string
  default     = ""
  description = "Name of the S3 bucket where Terraform cache of created resources via DSPM will be stored. If not specified, a bucket will be created automatically using the prefix_name."
}

variable "s3_bucket_region" {
  type        = string
  default     = ""
  description = "Region of the S3 bucket where Terraform cache will be stored. If not specified, the current region will be used."
}

variable "iam_role_profile_name" {
  type        = string
  description = "Name of the Instance Profile attached to the DSPM EC2 instance"
}

variable "prefix_name" {
  type        = string
  description = "Prefix name for DSPM resources"
}

variable "postgres_password" {
  type        = string
  sensitive   = true
  description = "Create a new password for the database where DSPM configuration settings and data will be stored"
}

variable "allow_cidr_to_backend_8080" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR IP range from which the DSPM web interface will be accessible"
}

variable "allow_cidr_to_ssh_22" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR IP range from which SSH access to the DSPM EC2 instance will be allowed"
}

variable "key_name" {
  type        = string
  description = "Name of the key pair used to access the DSPM EC2 instance via SSH"
}

variable "allow_access_for_aws_account_ids" {
  type        = list(string)
  default     = []
  description = "List of allowed AWS accounts to access DSPM. The list should contain string IDs of AWS accounts."
}

variable "allow_access_for_azure_account_ids" {
  type        = list(string)
  default     = []
  description = "List of allowed Azure accounts to access DSPM. The list should contain TenantID strings."
}

variable "rds_certificate_s3_arn" {
  type        = string
  default     = ""
  description = "Optional S3 object ARN with custom database CA certificate bundle. DSPM appends it to the bundled RDS CA bundle when configuring database TLS."
}

variable "enable_driver_archives_installation" {
  type        = bool
  description = "When true, DSPM installs uploaded custom driver archives on newly created DS instances"
  default     = false
}

variable "encryption_private_key" {
  description = "Deprecated legacy override. DSPM encryption key material is generated and stored by DSPM at startup. If set, this private key is embedded into EC2 UserData; leave empty for new deployments and prefer URL/secret-based key delivery when an override is required. Set together with encryption_public_key only."
  type        = string
  default     = ""
  sensitive   = true
}

variable "encryption_public_key" {
  description = "Deprecated legacy override. DSPM encryption key material is generated and stored by DSPM at startup. Use only with encryption_private_key for existing deployments that still require this legacy UserData-based override."
  type        = string
  default     = ""
  sensitive   = true
}

variable "http_server_crt" {
  description = "Deprecated. WEB-UI certificate is now generated and stored by DSPM at startup."
  type        = string
  default     = ""
  sensitive   = true
}

variable "http_server_key" {
  description = "Deprecated. WEB-UI private key is now generated and stored by DSPM at startup."
  type        = string
  default     = ""
  sensitive   = true
}



variable "path_to_private_key_for_update_build" {
  type    = string
  default = ""
}

variable "vpc_cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}

variable "ami_id" {
  type    = string
  default = ""
}
