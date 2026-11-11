resource "random_pet" "database" {
  separator = "-"
}

resource "random_id" "global_name" {
  byte_length = 6
}

resource "random_password" "postgres" {
  length           = 32
  special          = true
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%&()*+,-.:;<=>?[]^_{|}~"
}

resource "random_password" "datasunrise" {
  length      = 16
  special     = true
  min_lower   = 1
  min_upper   = 1
  min_numeric = 1
  min_special = 1
}

data "external" "validate_region" {
  program = ["bash", "./validate_region.sh", var.resource_group_location, var.postgres_zone]
}

locals {
  image_channels = {
    release = {
      type       = "marketplace"
      publisher  = "datasunrise"
      offer      = "datasunrise-dspm"
      sku        = "datasunrise-dspm"
      gallery    = ""
      definition = ""
    }
    dev = {
      type       = "community"
      publisher  = ""
      offer      = ""
      sku        = ""
      gallery    = "datasunrise-c6a43e8c-c5f9-4e77-aeb7-29f27c10a8d4"
      definition = "DSPM-MR"
    }
  }

  selected_image_channel = local.image_channels[var.image_channel]
  use_marketplace_image  = var.image_id == "" && local.selected_image_channel.type == "marketplace"
}

data "external" "latest_image" {
  count = var.image_id == "" && local.selected_image_channel.type == "community" ? 1 : 0

  program = [
    "bash",
    "./get_community_images.sh",
    var.resource_group_location,
    local.selected_image_channel.gallery,
    local.selected_image_channel.definition
  ]
}

locals {
  image_id = var.image_id != "" ? var.image_id : (
    local.selected_image_channel.type == "community" ? lookup(
      data.external.latest_image[0].result,
      "imageId",
      ""
    ) : ""
  )
  image_lookup_error = var.image_id == "" && local.selected_image_channel.type == "community" ? lookup(
    data.external.latest_image[0].result,
    "error",
    "DSPM image lookup returned an invalid response."
  ) : null
  image_is_community = startswith(
    lower(local.image_id),
    "/communitygalleries/"
  )
}

locals {
  region_validation_error = lookup(data.external.validate_region.result, "error", null)
}


data "azurerm_client_config" "current" {}

locals {
  name                = "${var.resource_group_name}-${random_pet.database.id}"
  resource_group_name = azurerm_resource_group.resource_group.name
  location            = var.resource_group_location
  global_resource_name = "dspm${substr(
    replace(lower(var.resource_group_name), "/[^a-z0-9]/", ""),
    0,
    8
  )}${random_id.global_name.hex}"
}

resource "azurerm_resource_group" "resource_group" {
  name     = var.resource_group_name
  location = var.resource_group_location

  lifecycle {
    precondition {
      condition     = local.image_lookup_error == null || local.image_lookup_error == ""
      error_message = local.image_lookup_error == null ? "" : local.image_lookup_error
    }

    precondition {
      condition     = local.region_validation_error == null
      error_message = local.region_validation_error == null ? "" : local.region_validation_error
    }
  }
}


resource "azurerm_storage_account" "storage" {
  name                     = local.global_resource_name
  resource_group_name      = azurerm_resource_group.resource_group.name
  location                 = local.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_storage_container" "container" {
  name                  = "dspm"
  storage_account_id    = azurerm_storage_account.storage.id
  container_access_type = "private"

  depends_on = [
    azurerm_storage_account.storage
  ]
}

resource "azurerm_user_assigned_identity" "identity" {
  name                = "${local.name}-identity"
  location            = local.location
  resource_group_name = local.resource_group_name

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_key_vault" "vault" {
  name                        = local.global_resource_name
  resource_group_name         = local.resource_group_name
  location                    = local.location
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  sku_name = "standard"

  rbac_authorization_enabled = true
}

resource "azurerm_role_assignment" "identity_key_vault_secrets_user" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.identity.principal_id
}

resource "azurerm_role_assignment" "identity_storage_blob_data_contributor" {
  scope                = azurerm_storage_account.storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.identity.principal_id
}

resource "azurerm_key_vault_secret" "ds_reference" {
  key_vault_id = azurerm_key_vault.vault.id
  name         = "${local.name}-ds"
  value = jsonencode({
    username = "admin"
    password = random_password.datasunrise.result
  })

  depends_on = [
    azurerm_key_vault.vault
  ]
}

resource "azurerm_key_vault_secret" "postgres" {
  key_vault_id = azurerm_key_vault.vault.id
  name         = "${local.name}-postgres"
  value = jsonencode({
    username = "postgres"
    password = random_password.postgres.result
  })

  depends_on = [
    azurerm_key_vault.vault
  ]
}

resource "azurerm_ssh_public_key" "ssh_key" {
  name                = local.name
  resource_group_name = local.resource_group_name
  location            = var.resource_group_location
  public_key          = file(var.pathPublicKey)

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

# Create Network Security Group and rule
resource "azurerm_network_security_group" "network_security_group" {
  name                = local.name
  resource_group_name = local.resource_group_name
  location            = var.resource_group_location

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_virtual_network" "virtual_network" {
  name                = local.name
  address_space       = ["10.0.0.0/16"]
  resource_group_name = local.resource_group_name
  location            = var.resource_group_location

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_subnet" "default_subnet" {
  name                 = "${local.name}-default"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.virtual_network.name
  address_prefixes     = ["10.0.0.0/24"]

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_public_ip" "public_ip" {
  count               = var.is_public ? 1 : 0
  name                = local.name
  resource_group_name = local.resource_group_name
  location            = var.resource_group_location
  allocation_method   = "Static"
  sku                 = "Standard"

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_network_interface" "interface_dspm" {
  name                = local.name
  resource_group_name = local.resource_group_name
  location            = var.resource_group_location

  ip_configuration {
    name                          = "interface_dspm_configuration"
    subnet_id                     = azurerm_subnet.default_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.is_public ? azurerm_public_ip.public_ip[0].id : null
  }

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_network_interface_security_group_association" "association_sg_to_interface" {
  network_interface_id      = azurerm_network_interface.interface_dspm.id
  network_security_group_id = azurerm_network_security_group.network_security_group.id
  depends_on = [
    azurerm_resource_group.resource_group,
    azurerm_network_interface.interface_dspm,
    azurerm_network_security_group.network_security_group
  ]
}


### Database
resource "azurerm_subnet" "default_pg" {
  name                 = "${local.name}-pg"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.virtual_network.name
  address_prefixes     = ["10.0.1.0/24"]
  service_endpoint {
    service = "Microsoft.Storage"
  }
  delegation {
    name = local.name
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }

  depends_on = [azurerm_virtual_network.virtual_network]
}

resource "azurerm_private_dns_zone" "private_dns_zone" {
  name                = "${local.name}.${local.location}.private.postgres.database.azure.com"
  resource_group_name = local.resource_group_name
  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_private_dns_zone_virtual_network_link" "private_dns_zone_virtual_network_link" {
  name                = local.name
  private_dns_zone_id = azurerm_private_dns_zone.private_dns_zone.id
  virtual_network_id  = azurerm_virtual_network.virtual_network.id
  depends_on = [
    azurerm_subnet.default_pg,
    azurerm_private_dns_zone.private_dns_zone
  ]
}

resource "tls_private_key" "encryption_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "azurerm_key_vault_secret" "enc_private" {
  name         = "${local.name}-enc-private"
  value        = tls_private_key.encryption_key.private_key_pem
  key_vault_id = azurerm_key_vault.vault.id

}

resource "azurerm_key_vault_secret" "enc_public" {
  name         = "${local.name}-enc-public"
  value        = tls_private_key.encryption_key.public_key_pem
  key_vault_id = azurerm_key_vault.vault.id

}

resource "azurerm_postgresql_flexible_server" "postgres" {
  name                   = local.name
  resource_group_name    = local.resource_group_name
  location               = var.resource_group_location
  version                = "16"
  administrator_login    = "postgres"
  administrator_password = random_password.postgres.result
  # zone                          = var.postgres_zone
  sku_name                      = "B_Standard_B2s"
  delegated_subnet_id           = azurerm_subnet.default_pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.private_dns_zone.id
  public_network_access_enabled = false

  lifecycle {
    ignore_changes = [
      zone
    ]
  }

  depends_on = [
    azurerm_private_dns_zone.private_dns_zone,
    azurerm_subnet.default_pg
  ]
}

resource "azurerm_postgresql_flexible_server_database" "dictionary" {
  for_each  = toset(["dictionary", "audit"])
  name      = each.key
  charset   = "utf8"
  collation = "en_US.utf8"
  server_id = azurerm_postgresql_flexible_server.postgres.id

  depends_on = [
    azurerm_postgresql_flexible_server.postgres
  ]
}

locals {
  dspm_public_ip   = var.is_public ? azurerm_public_ip.public_ip[0].ip_address : ""
  dspm_access_ip   = var.is_public ? local.dspm_public_ip : azurerm_network_interface.interface_dspm.private_ip_address
  dspm_access_type = var.is_public ? "public" : "private"

  userData = <<EOT
#!/bin/bash

public_ip="${local.dspm_public_ip}"

# wait dictionary
DICT_HOST="${azurerm_postgresql_flexible_server.postgres.fqdn}"
DICT_PORT="5432"
while true; do
  timeout 1 bash -c "echo > /dev/tcp/$DICT_HOST/$DICT_PORT" 2>/dev/null && break
  echo "Waiting for $DICT_HOST:$DICT_PORT"
  sleep 1
done
echo "$DICT_HOST:$DICT_PORT is now available"

echo "{
   \"UrlToBuild\": \"\",
   \"Email\": \"${var.email}\",
   \"PublicIP\": \"$public_ip\",
   \"Reference\": {
      \"DsSecret\": \"${azurerm_key_vault.vault.id}/secrets/${local.name}-ds\",
      \"Dictionary\": {
        \"SSL\": true,
        \"Host\": \"${azurerm_postgresql_flexible_server.postgres.fqdn}\",
        \"Database\": \"dictionary\",
        \"Schema\": \"public\",
        \"Username\": \"postgres\",
        \"Secret\": \"${azurerm_key_vault.vault.id}/secrets/${azurerm_key_vault_secret.postgres.name}\"
      },
      \"Audit\": {
        \"SSL\": true,
        \"Host\": \"${azurerm_postgresql_flexible_server.postgres.fqdn}\",
        \"Database\": \"audit\",
        \"Schema\": \"public\",
        \"Username\": \"postgres\",
        \"Secret\": \"${azurerm_key_vault.vault.id}/secrets/${azurerm_key_vault_secret.postgres.name}\"
      }
   },
   \"AccountIDs\": [],
   \"TenantIDs\": [\"${data.azurerm_client_config.current.tenant_id}\"],
   \"TerraformCache\": {
     \"AccountStorage\": \"${azurerm_storage_account.storage.name}\",
     \"AccountStorageKey\": \"\"
   },
   \"AliasKeyNames\": {},
   \"Subnets\": [
     \"${azurerm_subnet.default_subnet.id}\"
   ],
   \"SecurityGroups\": [
     \"${azurerm_network_security_group.network_security_group.id}\"
   ],
   \"FullEncryptionProtocol\": false,
   \"OnlyOneRegion\": true,
   \"MaxThreadUpdateMetadata\": 25,
   \"SessionTimeout\": 100,
   \"IgnoreMaskTypeCheck\": true,
   \"Region\": \"$REGION\",
   \"Logs\": {
     \"RPC\": true,
     \"UPDATE_METADATA\": true,
     \"OTHER\": false,
     \"ERROR\": true,
     \"API_REQUEST\": false,
     \"API_RESPONSE\": false,
     \"ACCOUNTS\": true,
     \"TRACE_NET_ACCESS_AWS\": false,
     \"COMMANDS\": false
   }
}" > /opt/dspm/config/app.json

VAULT_NAME="${azurerm_key_vault.vault.name}"

mkdir -p /opt/dspm/src/helpers/encryption/
mkdir -p /opt/dspm/certs/

SECRETS_READY=false
for attempt in $(seq 1 30); do
  unset PRIVATE_KEY PUBLIC_KEY POSTGRES_SECRET POSTGRES_PASSWORD

  az login --identity \
    --client-id "${azurerm_user_assigned_identity.identity.client_id}" \
    --allow-no-subscriptions >/dev/null 2>&1 &&
  PRIVATE_KEY=$(az keyvault secret show \
    --vault-name "$VAULT_NAME" \
    --name "${azurerm_key_vault_secret.enc_private.name}" \
    --query value -o tsv 2>/dev/null) &&
  PUBLIC_KEY=$(az keyvault secret show \
    --vault-name "$VAULT_NAME" \
    --name "${azurerm_key_vault_secret.enc_public.name}" \
    --query value -o tsv 2>/dev/null) &&
  POSTGRES_SECRET=$(az keyvault secret show \
    --vault-name "$VAULT_NAME" \
    --name "${azurerm_key_vault_secret.postgres.name}" \
    --query value -o tsv 2>/dev/null) &&
  POSTGRES_PASSWORD=$(printf '%s' "$POSTGRES_SECRET" | jq -er \
    '.password | select(type == "string" and length > 0)' 2>/dev/null) &&
  printf '%s\n' "$PRIVATE_KEY" | openssl pkey -check -noout >/dev/null 2>&1 &&
  printf '%s\n' "$PUBLIC_KEY" | openssl pkey -pubin -noout >/dev/null 2>&1 &&
  { SECRETS_READY=true; break; }

  echo "Waiting for DSPM secrets, attempt $attempt/30"
  sleep 10
done

if [ "$SECRETS_READY" != true ]; then
  echo "Failed to load DSPM secrets from Key Vault" >&2
  exit 1
fi

echo "{
  \"development\": {
    \"username\": \"postgres\",
    \"password\": \"$POSTGRES_PASSWORD\",
    \"database\": \"postgres\",
    \"host\": \"${azurerm_postgresql_flexible_server.postgres.fqdn}\",
    \"dialect\": \"postgres\",
    \"dialectOptions\": {
      \"ssl\": {
        \"require\": true,
        \"rejectUnauthorized\": false
      }
    }
  }
}" > /opt/dspm/config/config.json

printf '%s\n' "$PRIVATE_KEY" > /opt/dspm/src/helpers/encryption/private.pem.tmp
printf '%s\n' "$PUBLIC_KEY" > /opt/dspm/src/helpers/encryption/public.pem.tmp

chmod 600 /opt/dspm/config/config.json
chown dspm:dspm /opt/dspm/src/helpers/encryption/*.tmp
chmod 600 /opt/dspm/src/helpers/encryption/private.pem.tmp
chmod 640 /opt/dspm/src/helpers/encryption/public.pem.tmp
mv -f /opt/dspm/src/helpers/encryption/private.pem.tmp /opt/dspm/src/helpers/encryption/private.pem
mv -f /opt/dspm/src/helpers/encryption/public.pem.tmp /opt/dspm/src/helpers/encryption/public.pem
chown -R dspm:dspm /opt/dspm/config/
chown -R dspm:dspm /opt/dspm/src/helpers/encryption/
chown -R dspm:dspm /opt/dspm/certs/

unset PRIVATE_KEY PUBLIC_KEY POSTGRES_SECRET POSTGRES_PASSWORD

cd /opt/dspm
runuser -u dspm -- env HOME=/opt/dspm UV_USE_IO_URING=0 npm run start-database-migration

echo '[Unit]
Description=DSPM (Data Security Posture Management) Service
After=network.target

[Service]
Type=simple
User=dspm
Group=dspm
WorkingDirectory=/opt/dspm
Environment="HOME=/opt/dspm"
Environment="UV_USE_IO_URING=0"
Environment="AZURE_CLIENT_ID=${azurerm_user_assigned_identity.identity.client_id}"
ExecStart=/usr/bin/npm run start-http-server
ExecStop=/usr/bin/pkill -f "node.*start-http-server"
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
ProtectHome=no
ProtectSystem=off

[Install]
WantedBy=multi-user.target
' > /etc/systemd/system/dspm.service

sudo systemctl daemon-reload

sudo systemctl enable dspm.service

sudo systemctl start dspm.service

sudo systemctl status dspm.service

sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent && sudo firewall-cmd --reload

EOT
}

resource "azapi_resource" "vm" {
  count     = 1
  type      = "Microsoft.Compute/virtualMachines@2022-08-01"
  name      = local.name
  parent_id = azurerm_resource_group.resource_group.id
  location  = local.location

  body = {
    identity = {
      type = "UserAssigned"
      userAssignedIdentities = {
        "${azurerm_user_assigned_identity.identity.id}" = {}
      }
    }

    plan = local.use_marketplace_image ? {
      name      = local.selected_image_channel.sku
      product   = local.selected_image_channel.offer
      publisher = local.selected_image_channel.publisher
    } : null

    properties = {
      hardwareProfile = {
        vmSize = "Standard_B2s"
      }
      storageProfile = {
        osDisk = {
          createOption = "fromImage"
          managedDisk = {
            storageAccountType = "Standard_LRS"
          }
          deleteOption = "Delete"
        }
        imageReference = local.use_marketplace_image ? {
          publisher = local.selected_image_channel.publisher
          offer     = local.selected_image_channel.offer
          sku       = local.selected_image_channel.sku
          version   = "latest"
          } : (
          local.image_is_community ? {
            communityGalleryImageId = local.image_id
            } : {
            id = local.image_id
          }
        )
      }
      networkProfile = {
        networkInterfaces = [{
          id = azurerm_network_interface.interface_dspm.id
        }]
      }

      osProfile = {
        computerName  = "hostname"
        adminUsername = var.username
        customData    = base64encode(local.userData)
        linuxConfiguration = {
          disablePasswordAuthentication = true
          ssh = {
            publicKeys = [{
              path    = "/home/${var.username}/.ssh/authorized_keys"
              keyData = file(var.pathPublicKey)
            }]
          }
        }
      }
    }
  }

  depends_on = [
    azurerm_resource_group.resource_group,
    azurerm_ssh_public_key.ssh_key,
    azurerm_network_security_group.network_security_group,
    azurerm_virtual_network.virtual_network,
    azurerm_subnet.default_subnet,
    azurerm_subnet.default_pg,
    azurerm_public_ip.public_ip,
    azurerm_network_interface.interface_dspm,
    azurerm_network_interface_security_group_association.association_sg_to_interface,
    azurerm_private_dns_zone.private_dns_zone,
    azurerm_private_dns_zone_virtual_network_link.private_dns_zone_virtual_network_link,
    azurerm_role_assignment.identity_key_vault_secrets_user,
    azurerm_role_assignment.identity_storage_blob_data_contributor,
    azurerm_postgresql_flexible_server.postgres
  ]
}

locals {
  referenceUserData = <<EOT
#!/bin/bash
echo '[Unit]
 Description=/etc/rc.local Compatibility
 ConditionPathExists=/etc/rc.local
 Before=shutdown.target reboot.target halt.target
 After=network.target

[Service]
 Type=oneshot
 ExecStart=/etc/rc.local start
 ExecStop=/etc/rc.local stop
 TimeoutStopSec=90
 StandardOutput=tty
 RemainAfterExit=yes

[Install]
 WantedBy=multi-user.target
' > /etc/systemd/system/rc-local.service


echo '#!/bin/bash
echo "Installation..."
yum install jq wget -y

CUSTOM_DS_URL="${var.datasunrise_custom_url}"
if [[ $CUSTOM_DS_URL != "" ]]
then
  echo "Using custom DataSunrise URL: $CUSTOM_DS_URL"
  # Download and install from custom URL
  cd /tmp
  wget -O datasunrise-installer.rpm "$CUSTOM_DS_URL"
  sudo yum install datasunrise-installer.rpm -y
  rm -f datasunrise-installer.rpm
else
  echo "Using default DataSunrise from image"
  sudo yum install /var/cooked/installer.rpm -y
fi

sudo systemctl stop datasunrise.service

if [[ $1 == "start" ]]
then
  export AF_HOME=/opt/datasunrise/
  sudo chmod +x /opt/datasunrise/scripts/configure-datasunrise.sh
  instanceId=`curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | jq --raw-output ".vmId"`
  ipaddr=`curl -H Metadata:true "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-04-02&format=text"`
  while [[ $ipaddr == "" ]]; do
    echo "." && sleep 5 && ipaddr=`curl -H Metadata:true "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-04-02&format=text"`
  done
  echo "server_name: dspm-$${instanceId}-${local.name}"
  echo "ipaddr: $ipaddr"
  echo "Configuration..."
  LOG=/opt/datasunrise/logs/start.log
  attempt=0
  while true; do
    attempt=$((attempt + 1))
    az login --identity --client-id "${azurerm_user_assigned_identity.identity.client_id}" >/dev/null 2>>"$LOG"
    DS_SECRET=`az keyvault secret show --name ${azurerm_key_vault_secret.ds_reference.name} --vault-name ${azurerm_key_vault.vault.name} --query value -o tsv 2>>"$LOG"`
    POSTGRES_SECRET=`az keyvault secret show --name ${azurerm_key_vault_secret.postgres.name} --vault-name ${azurerm_key_vault.vault.name} --query value -o tsv 2>>"$LOG"`
    PASS=`echo "$DS_SECRET" | jq --raw-output ".password" 2>>"$LOG"`
    POSTGRES_PASSWORD=`echo "$POSTGRES_SECRET" | jq --raw-output ".password" 2>>"$LOG"`
    [[ $PASS != "" && $POSTGRES_PASSWORD != "" ]] && break
    echo "Waiting for Key Vault secrets, attempt $attempt" >> "$LOG"
    sleep 10
  done

  echo "Reference DS secrets loaded from Key Vault" >> "$LOG"
  PASS="$${PASS//\'\''/\'\''\\\'\''\'\''}"
  sudo runuser -u datasunrise -- /opt/datasunrise/scripts/configure-datasunrise.sh setup-remote-configuration --dictionary-type postgresql --dictionary-host ${azurerm_postgresql_flexible_server.postgres.fqdn} --dictionary-port 5432 --dictionary-database dictionary --dictionary-schema public --dictionary-login postgres --dictionary-password "$POSTGRES_PASSWORD" --dictionary-use-ssl 1 --server-name dspm-$${instanceId}-${local.name} --server-host $${ipaddr} --server-port 11000  --server-use-https 1  --copy-proxies 1  -f >> /opt/datasunrise/logs/start.log
  sudo runuser -u datasunrise -- /opt/datasunrise/scripts/configure-datasunrise.sh setup-remote-audit --audit-type postgresql --audit-host ${azurerm_postgresql_flexible_server.postgres.fqdn} --audit-port 5432 --audit-database audit --audit-schema public --audit-login postgres --audit-password "$POSTGRES_PASSWORD" --audit-use-ssl 1 -f >> /opt/datasunrise/logs/start.log
  sudo runuser -u datasunrise -- /opt/datasunrise/scripts/configure-datasunrise.sh setup-password --password "$PASS" -f >> /opt/datasunrise/logs/start.log
  sudo systemctl start datasunrise.service
fi

if [[ $1 == "stop" ]]
then
  sudo /opt/datasunrise/AppBackendService AF_HOME=/opt/datasunrise AF_CONFIG=/opt/datasunrise/ UNREGISTER_FIREWALL_SERVER
fi

exit 0
' > /etc/rc.local

sudo chmod +x /etc/rc.local

sudo systemctl enable rc-local

sudo systemctl start rc-local.service

sudo systemctl status rc-local.service

sudo -i
echo -e "
      DEVICE=eth0:0
      BOOTPROTO=static
      ONBOOT=yes
      IPADDR=$${public_ip}
      NETMASK=255.255.255.0" > /etc/sysconfig/network-scripts/ifcfg-eth0:0
systemctl restart NetworkManager.service
echo -e "
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>datasunrise</short>
  <description>DataSunrise Web Console and Proxy.</description>
  <port protocol="tcp" port="11000"/>
</service>
" > /usr/lib/firewalld/services/datasunrise.xml

systemctl restart firewalld.service
EOT
}

resource "azurerm_network_security_group" "network_security_group_reference" {
  name                = "${local.name}-reference"
  resource_group_name = azurerm_virtual_network.virtual_network.resource_group_name
  location            = azurerm_virtual_network.virtual_network.location

  security_rule {
    name                       = "DSPM-Backend-11000"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    source_address_prefix      = azurerm_subnet.default_subnet.address_prefixes[0]
    destination_port_range     = 11000
    destination_address_prefix = "*"
  }
}

# Connect the security group to the network interface
resource "azurerm_network_interface_security_group_association" "association_sg_to_interface_reference" {
  count                     = 1
  network_interface_id      = azurerm_network_interface.ds_network_interface[count.index].id
  network_security_group_id = azurerm_network_security_group.network_security_group_reference.id
  depends_on = [
    azurerm_network_security_group.network_security_group_reference
  ]
}

resource "azurerm_public_ip" "public_ip_reference" {
  count               = var.is_public ? 1 : 0
  name                = "${local.name}-reference-ds"
  resource_group_name = azurerm_virtual_network.virtual_network.resource_group_name
  location            = azurerm_virtual_network.virtual_network.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "ds_network_interface" {
  count               = 1
  name                = "${local.name}-${count.index}-reference-ds"
  resource_group_name = azurerm_virtual_network.virtual_network.resource_group_name
  location            = azurerm_virtual_network.virtual_network.location

  ip_configuration {
    name                          = "${local.name}-${count.index}-reference-ds"
    subnet_id                     = azurerm_subnet.default_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.is_public ? azurerm_public_ip.public_ip_reference[0].id : null
  }
}

resource "azurerm_linux_virtual_machine" "datasunrise_instance" {
  count               = 1
  name                = "${local.name}-reference-ds"
  resource_group_name = azurerm_virtual_network.virtual_network.resource_group_name
  location            = azurerm_virtual_network.virtual_network.location
  network_interface_ids = [
    azurerm_network_interface.ds_network_interface[count.index].id
  ]
  size = "Standard_B2s"

  os_disk {
    name                 = "${local.name}-reference-ds"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = 64
  }

  source_image_reference {
    publisher = "datasunrise"
    offer     = "datasunrise-database-security-suite"
    sku       = "datasunrise"
    version   = "latest"
  }

  plan {
    name      = "datasunrise"
    product   = "datasunrise-database-security-suite"
    publisher = "datasunrise"
  }

  user_data = base64encode(local.referenceUserData)

  computer_name  = "hostname"
  admin_username = var.username

  admin_ssh_key {
    username   = var.username
    public_key = azurerm_ssh_public_key.ssh_key.public_key
  }

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.identity.id
    ]
  }

  depends_on = [
    azurerm_key_vault_secret.ds_reference,
    azurerm_role_assignment.identity_key_vault_secrets_user,
    azurerm_role_assignment.identity_storage_blob_data_contributor,
    azurerm_postgresql_flexible_server.postgres,
    azurerm_network_interface_security_group_association.association_sg_to_interface_reference,
    azurerm_network_interface.ds_network_interface,
    azurerm_public_ip.public_ip_reference,
    azurerm_subnet.default_subnet,
    azurerm_network_security_group.network_security_group_reference,
    azurerm_ssh_public_key.ssh_key
  ]
}

locals {
  link = <<EOT

DSPM web console endpoint (${local.dspm_access_type} IP):
===============================================================================
https://${local.dspm_access_ip}:8080
===============================================================================
An inbound NSG rule for TCP/8080 is required before this endpoint is reachable.

EOT
}

output "result" {
  value = <<EOT
Thank you for deploying and using DataSunrise DSPM!
${local.link}
Azure App Registration is not created by this Terraform configuration.
Use existing Azure credentials when connecting the Azure tenant in the DSPM UI.
EOT
}

output "dspm_url" {
  value = "https://${local.dspm_access_ip}:8080"
}

output "image_id" {
  value = local.image_id
}

output "managed_identity_id" {
  value = azurerm_user_assigned_identity.identity.id
}

output "managed_identity_client_id" {
  value = azurerm_user_assigned_identity.identity.client_id
}

output "key_vault_id" {
  value = azurerm_key_vault.vault.id
}

output "storage_account_name" {
  value = azurerm_storage_account.storage.name
}
