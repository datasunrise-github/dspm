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
  type        = string
  default     = ""
}


variable "pathPublicKey" {
  type        = string
  default     = "~/.ssh/id_rsa.pub"
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
  type        = string
  default     = "1"
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

variable "encryption_private_key" {
  type        = string
  default     = <<EOT
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
EOT
  sensitive   = true
}

variable "encryption_public_key" {
  type        = string
  default     = <<EOT
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEA6dRPdtyh10ybNgNEb9T3uvm8An61fNogGkjtijTjg6h/veaNUaFI
g6OSBsVXa15bkhPfZ1tN/HzV/VgU0OEtnAydiK+mi+V2kaorGok4Kt575z+xUuYS
KP1/6k7JF0XqAnfXgY8bCt3snYZdg+PvHfi+LqM+ViAbDia/1G65Ed20a91sVHdq
46KXgasQmw4ZpxCz1ehRleKH4EA3MM62SmyuyjWxY0VjHgkWZLm0P5XjYTfSljlb
xgytxT/FdkrwIOb/U5XbkeqMPUL0apEmsVyXaO0+1LbLuG88fPf7Hj6QPm/UTaAb
ptT3gQta7UDV05d9xSGJolNkfTAOunHqN7/c3ZDW6ygP5KIgNn4Lm5CDK8CDzvs1
/c8f41qjjS0LpfBhWY93rdHgDGkMN5KRDWNRWBiz2leUEYecKqcx1FQEeqY2xJiq
YZD5MAuVU62Vlsj1r3Sb9dpfX0HXJ1MpDK8gKYX7X3V2pN6kkNN9+fqH3TabvNOp
fbT41mjUh19JV2eKfTxoynhwXK972uUFaT/nLptJ23qiZXzQuel/4TvqY+qET1j+
1mtQAGTHN8Pta0xr2C8sz9wncATW8dumBL/a64XsjYljOilGNAcmPNLEYttXWOaA
OfltX6K0aP+3LI6hnSD5MzahWThk6jfAX6PyHeKTM0Y3W0DwhwxJX88CAwEAAQ==
-----END RSA PUBLIC KEY-----
EOT
  sensitive   = true
}

variable "http_server_crt" {
  type        = string
  default     = <<EOT
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUESQjdzTUvBu46ZHMzGUKeRTRqZcwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzExMDkxNDA3MjRaFw0yMzEy
MDkxNDA3MjRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDD1HP3MU6WI2rkBOn7BviGvXx8/vNXt9Z+ZeM+1/ge
6AJFMvi2E90VFD1vmhfSYWt9UMeqR/jsEwM/eTC5W7dT4wKbAIs273GugN+VOJ+4
dqUTJ5KkErebuBw5zr+IQwqD0YxRRHkgNSRD2g/y2uSDRDiTaXltDZ5aRfcOj4Uo
LUp9iz22yZHOqpoXW49A7udMp3avVyhFf93gH370soYvSNoVmODMP5DOGbWRu36U
laOzNtLku/2wlDsFkIfePuJlbtFYHQB7EiWcLJx+/Fh+Tpc13f5AzZX9c62hPquI
6VX3smzJ46JGcQ+IHb0NNfufyLzjVKopUvij8VUwQANvAgMBAAGjUzBRMB0GA1Ud
DgQWBBTlTdgERoKEIXFKAlPird05yDIQ4TAfBgNVHSMEGDAWgBTlTdgERoKEIXFK
AlPird05yDIQ4TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAP
ODjAsgIupN2KTvf/AHLeJQIPxH/tn/V0ejV9EVqPwQi5vt08gHg2skQ39ynXEqY2
gonU/WustsBlAMWx6sN+V2D7DVZNuSy3h5xyP1F6DoUnLRk447XYRRik43I9Xary
NNiOelMao41xfPzFyk0BPXRVYwWXj6n5UnIDpJ1hFMBW2ML2hPfeTIAK1zP6knC3
twq2HJqaRZUw5S8DpmvYwoG+0KiKYDHJoySdSPUP7whKwXiXR9IsvhBBdGS7M5DN
uXIbuhfosKkJn7If/0GZyOAKVBp9nXGcmsmBLS/NujjquPRQqsFGslMw6816MKJx
MDmr4Dmx+5hJ9CzyA8aT
-----END CERTIFICATE-----
EOT
  sensitive   = true
}

variable "http_server_key" {
  type        = string
  default     = <<EOT
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDD1HP3MU6WI2rk
BOn7BviGvXx8/vNXt9Z+ZeM+1/ge6AJFMvi2E90VFD1vmhfSYWt9UMeqR/jsEwM/
eTC5W7dT4wKbAIs273GugN+VOJ+4dqUTJ5KkErebuBw5zr+IQwqD0YxRRHkgNSRD
2g/y2uSDRDiTaXltDZ5aRfcOj4UoLUp9iz22yZHOqpoXW49A7udMp3avVyhFf93g
H370soYvSNoVmODMP5DOGbWRu36UlaOzNtLku/2wlDsFkIfePuJlbtFYHQB7EiWc
LJx+/Fh+Tpc13f5AzZX9c62hPquI6VX3smzJ46JGcQ+IHb0NNfufyLzjVKopUvij
8VUwQANvAgMBAAECggEAOmN7qi4Q7PIlelQ+wYKsElyoJArOWo6tTSWq8n9pcymh
F6nhf0R/7DuLL93lkWxLpOMzjUGFZjorAz9quDGxATmT+sxYNeqB3lJ9l5v4/4Kc
qI/piLMt/KeR/uh2sjWvCmut50M/zEscA4EetT3v2XW7WrSdqFbhqq/mwHgpbzc/
sIzEIO4fOrgfDCx3ZKyMdfb8tDMLVB1cAaX2fpRMgHpotR2FBumBUVym7RxdO2wR
CKONNklTT0F2KpbacdWSU00GoRz8I7lpjZAIUQEBPZUuSk7vl1r7ztaFUxr2WZ+T
cSgRJAbPumLsu3DtjKhdLL/hO4gbpn2/7KE774URrQKBgQDLC89kmYdAfJxaf9jG
qJWAGWRx0mqYQL2+FzqLhM4efqTAWdVo/yzkzrrRF4OBv100JU93kvYFivrhdQ+v
BIrNJ7RIudwa2TARXYEZnrmTg9gOuZzXofn+T81k4HBujMAqpXdTm2z3RDKYwhn4
9xzK5rG2+yo9TZb0ApujPEkvWwKBgQD25tt1XgbvcEMPw0ZJ8inzFgBb4kd0+DEl
nwLHr416l1MTMhvA84zV7CbjdWnTbGbrLd2jQlVTYZJjQIIkxKm81lgWT2dWq+r1
OoCy4lb0cty4+pWdQlvViyZ7WqWXzMuOIeaypuHI8tDJlIEC+FB95/Hm0cPeRbkJ
6VegbVTsfQKBgGsoOXSzHdEnsnCEhkgZkoS/YeY8ESt3B2w54BjfptQrLBGjl2BJ
Q00h2TAeQ7YG405w3maRtaspNMwltng8YnBxItE63XGB679OZKK7xN6YNz9WL/MR
NdlEDnbNiCifuY8IMlh6b2Bzqmw6C/D7oUNnyqRyG1GtEByI/9B/MXR/AoGBAKl4
nHpbJ/eB3wYay0xGZHTuTSDEmLe5BEMGeioGXd4fsG4kntg6VBkiFy9ZkGIGrj4P
JWrCRT8OYiSuSqZiNv/fQGdP6WacapIYre4bXgQ8MzTlC3z953sUID3bYn5nm/Db
ZDaMRb5grN8wh706JEXHx0rgAMm4oeIjwHnlkb0hAoGATv2yqqdJh5JIu/morFGi
Bqrf0JioSXuQVc/Nn8VLIu/LdeCEBFD5+EtYLbo0+6qoU5DiEXTLTlR8Bo7HGrb3
n4usjs0P29bHf2WQa77WhXSYNp6S5qTCnkkylpImIHxNaNRsI8I/hKpEI7sYSIHE
Y5zxE/gAPLcb9vqbELl4GDk=
-----END PRIVATE KEY-----
EOT
  sensitive   = true
}

variable "datasunrise_custom_url" {
  type = string
  default = ""
}