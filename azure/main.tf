resource "random_pet" "database" {
  separator = "-"
}

data "external" "validate_region" {
  program = ["bash", "./validate_region.sh", var.resource_group_location, var.postgres_zone]
}

data "external" "latest_community_image" {
  program = ["bash", "./get_community_images.sh", var.resource_group_location]
}

locals {
  image_type = var.image_id == "" ? "release" : "dev"
}

locals {
  image_id = local.image_type == "dev" ? var.image_id : data.external.latest_community_image.result.communityGalleryImageId
}

locals {
  region_validation_error = lookup(data.external.validate_region.result, "error", null)
}


data "azurerm_client_config" "current" {}

locals {
  name = "${var.resource_group_name}-${random_pet.database.id}"
}

resource "azurerm_resource_group" "resource_group" {
  name     = local.name
  location = var.resource_group_location

  lifecycle {
    precondition {
      condition     = local.region_validation_error == null
      error_message = local.region_validation_error == null ? "" : local.region_validation_error
    }
  }
}


resource "azurerm_storage_account" "storage" {
  name                     = var.resource_group_name
  resource_group_name      = azurerm_resource_group.resource_group.name
  location                 = azurerm_resource_group.resource_group.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_storage_container" "container" {
  name                  = "dspm"
  storage_account_name    = azurerm_storage_account.storage.name
  container_access_type = "private"

  depends_on = [
    azurerm_storage_account.storage
  ]
}

resource "azurerm_user_assigned_identity" "dspm" {
  name                        = "${local.name}-dspm"
  location                    = var.resource_group_location
  resource_group_name         = local.name

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_user_assigned_identity" "identity" {
  name                        = local.name
  location                    = var.resource_group_location
  resource_group_name         = local.name

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_key_vault" "vault" {
  name                        = var.resource_group_name
  resource_group_name         = local.name
  location                    = azurerm_resource_group.resource_group.location
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  sku_name = "standard"

  enable_rbac_authorization    = true
}

resource "azurerm_role_assignment" "admin" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "reader" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Reader"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "user" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "admin_identity" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = azurerm_user_assigned_identity.identity.principal_id
}

resource "azurerm_role_assignment" "reade_identityr" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Reader"
  principal_id         = azurerm_user_assigned_identity.identity.principal_id
}

resource "azurerm_role_assignment" "user_identity" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.identity.principal_id
}

resource "azurerm_role_assignment" "blob_contributor" {
  scope                = azurerm_storage_account.storage.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.dspm.principal_id
}


resource "azurerm_key_vault_secret" "ds_reference" {
  key_vault_id = azurerm_key_vault.vault.id
  name         = "${local.name}-ds"
  value        = jsonencode({
    username   = "admin"
    password   = var.datasunrise_password
  })

  depends_on = [
    azurerm_key_vault.vault
  ]
}

data "azurerm_key_vault_secret" "ds" {
  name         = "${local.name}-ds"
  key_vault_id = azurerm_key_vault.vault.id
  depends_on = [
    azurerm_key_vault_secret.ds_reference
  ]
}

resource "azurerm_ssh_public_key" "ssh_key" {
  name                = local.name
  resource_group_name = local.name
  location            = var.resource_group_location
  public_key          = file(var.pathPublicKey)

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

# Create Network Security Group and rule
resource "azurerm_network_security_group" "network_security_group" {
  name                = local.name
  resource_group_name = local.name
  location            = var.resource_group_location

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allow_cidr_to_ssh_22
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "Web"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = 8080
    source_address_prefix      = var.allow_cidr_to_backend_8080
    destination_address_prefix = "*"
  }

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_virtual_network" "virtual_network" {
  name                  = local.name
  address_space         = ["10.0.0.0/16"]
  resource_group_name   = local.name
  location              = var.resource_group_location

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_subnet" "default_subnet" {
  name                  = "${local.name}-default"
  resource_group_name   = local.name
  virtual_network_name  = azurerm_virtual_network.virtual_network.name
  address_prefixes      = ["10.0.0.0/24"]

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_public_ip" "public_ip" {
  name                = local.name
  resource_group_name = local.name
  location            = var.resource_group_location
  allocation_method   = "Static"

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_network_interface" "interface_dsssm" {
  name                = local.name
  resource_group_name = local.name
  location            = var.resource_group_location

  ip_configuration {
    name                          = "interface_dsssm_configuration"
    subnet_id                     = azurerm_subnet.default_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.public_ip.id
  }

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_network_interface_security_group_association" "association_sg_to_interface" {
  network_interface_id      = azurerm_network_interface.interface_dsssm.id
  network_security_group_id = azurerm_network_security_group.network_security_group.id
  depends_on                = [
    azurerm_resource_group.resource_group,
    azurerm_network_interface.interface_dsssm,
    azurerm_network_security_group.network_security_group
  ]
}


### Database
resource "azurerm_subnet" "default_pg" {
  name                  = "${local.name}-pg"
  resource_group_name   = local.name
  virtual_network_name  = azurerm_virtual_network.virtual_network.name
  address_prefixes      = ["10.0.1.0/24"]
  service_endpoints     = [
    "Microsoft.Storage"
  ]
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
  name                = "${local.name}.${azurerm_resource_group.resource_group.location}.private.postgres.database.azure.com"
  resource_group_name = local.name
  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

resource "azurerm_private_dns_zone_virtual_network_link" "private_dns_zone_virtual_network_link" {
  name                  = local.name
  private_dns_zone_name = azurerm_private_dns_zone.private_dns_zone.name
  virtual_network_id    = azurerm_virtual_network.virtual_network.id
  resource_group_name   = azurerm_resource_group.resource_group.name
  depends_on            = [
    azurerm_subnet.default_pg,
    azurerm_private_dns_zone.private_dns_zone
  ]
}

resource "azurerm_postgresql_flexible_server" "postgres" {
  name                          = local.name
  resource_group_name           = local.name
  location                      = var.resource_group_location
  version                       = "16"
  administrator_login           = "postgres"
  administrator_password        = var.postgres_password
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
  for_each            = toset(["dictionary", "audit"])
  name                = "${each.key}"
  charset             = "utf8"
  collation           = "en_US.utf8"
  server_id           = azurerm_postgresql_flexible_server.postgres.id

  depends_on = [
    azurerm_postgresql_flexible_server.postgres
  ]
}

locals {
  userData = <<EOT
#!/bin/bash

sudo yum install nodejs npm -y

# wait public address
public_ip=""
while [[ $public_ip == "" ]]; do
  echo "." && sleep 5 && public_ip=`curl -H Metadata:true "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text"`
  [[ $public_ip == "" ]] && echo "." && sleep 5 && public_ip=`curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/loadbalancer?api-version=2020-10-01&format=json" | jq --raw-output ".loadbalancer.publicIpAddresses[0].frontendIpAddress"`
done

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
        \"Password\": \"${var.postgres_password}\"
      },
      \"Audit\": {
        \"SSL\": true,
        \"Host\": \"${azurerm_postgresql_flexible_server.postgres.fqdn}\",
        \"Database\": \"audit\",
        \"Schema\": \"public\",
        \"Username\": \"postgres\",
        \"Password\": \"${var.postgres_password}\"
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
   \"OnlyOneRegion\": false,
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
}" > /home/${var.username}/dsssm/config/app.json

echo '{
  "development": {
    "username": "postgres",
    "password": "${var.postgres_password}",
    "database": "postgres",
    "host": "${azurerm_postgresql_flexible_server.postgres.fqdn}",
    "dialect": "postgres",
    "dialectOptions": {
      "ssl": {
        "require": true,
        "rejectUnauthorized": false
      }
    }
  }
}' > /home/${var.username}/dsssm/config/config.json

echo '${var.http_server_key}' > /home/${var.username}/dsssm/certs/server.key

echo '${var.http_server_crt}' > /home/${var.username}/dsssm/certs/server.crt

echo '${var.encryption_private_key}' > /home/${var.username}/dsssm/src/helpers/encryption/private.pem

echo '${var.encryption_public_key}' > /home/${var.username}/dsssm/src/helpers/encryption/public.pem

cd /home/${var.username}/dsssm && npm install && npm run start-database-migration

echo '[Unit]
Description=DSPM (Data Security Posture Management) Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/${var.username}/dsssm
Environment="UV_USE_IO_URING=0"
ExecStart=npm run start-http-server
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
  count = 1
  type      = "Microsoft.Compute/virtualMachines@2022-08-01"
  name      = local.name
  parent_id = azurerm_resource_group.resource_group.id
  location  = azurerm_resource_group.resource_group.location

  body = jsonencode({
    identity = {
      type = "UserAssigned"
      userAssignedIdentities = {
        "${azurerm_user_assigned_identity.dspm.id}" = {}
      }
    }

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
        imageReference = {
          communityGalleryImageId = local.image_type != "dev" ? local.image_id : null
          id = local.image_type == "dev" ? local.image_id : null
        }
      }
      networkProfile = {
        networkInterfaces = [{
          id = azurerm_network_interface.interface_dsssm.id
        }]
      }

      osProfile = {
        computerName = "hostname"
        adminUsername = var.username
        customData = base64encode(local.userData)
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
  })

  depends_on = [
    azurerm_resource_group.resource_group,
    azurerm_ssh_public_key.ssh_key,
    azurerm_network_security_group.network_security_group,
    azurerm_virtual_network.virtual_network,
    azurerm_subnet.default_subnet,
    azurerm_subnet.default_pg,
    azurerm_public_ip.public_ip,
    azurerm_network_interface.interface_dsssm,
    azurerm_network_interface_security_group_association.association_sg_to_interface,
    azurerm_private_dns_zone.private_dns_zone,
    azurerm_private_dns_zone_virtual_network_link.private_dns_zone_virtual_network_link,
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
az login --identity

if [[ $1 == "start" ]]
then
  export AF_HOME=/opt/datasunrise/
  sudo chmod +x /opt/datasunrise/scripts/configure-datasunrise.sh
  instanceId=`curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | jq --raw-output ".vmId"`
  ipaddr=`curl -H Metadata:true "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-04-02&format=text"`
  while [[ $ipaddr == "" ]]; do
    echo "." && sleep 5 && ipaddr=`curl -H Metadata:true "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-04-02&format=text"`
  done
  echo "server_name: dsssm-$${instanceId}-${local.name}"
  echo "ipaddr: $ipaddr"
  echo "Configuration..."
  PASS=`az keyvault secret show --name ${data.azurerm_key_vault_secret.ds.name} --vault-name ${azurerm_key_vault.vault.name} | jq --raw-output ".value" | jq --raw-output ".password"`
  PASS="$${PASS//\'\''/\'\''\\\'\''\'\''}"
  sudo runuser -u datasunrise -- /opt/datasunrise/scripts/configure-datasunrise.sh setup-remote-configuration --dictionary-type postgresql --dictionary-host ${azurerm_postgresql_flexible_server.postgres.fqdn} --dictionary-port 5432 --dictionary-database dictionary --dictionary-schema public --dictionary-login postgres ${join("", ["--dictionary-password ", "'\\''", var.postgres_password, "'\\''"])} --dictionary-use-ssl 1 --server-name dsssm-$${instanceId}-${local.name} --server-host $${ipaddr} --server-port 11000  --server-use-https 1  --copy-proxies 1  -f -v >> /opt/datasunrise/logs/start.log
  sudo runuser -u datasunrise -- /opt/datasunrise/scripts/configure-datasunrise.sh setup-remote-audit --audit-type postgresql --audit-host ${azurerm_postgresql_flexible_server.postgres.fqdn} --audit-port 5432 --audit-database audit --audit-schema public --audit-login postgres ${join("", ["--audit-password ", "'\\''", var.postgres_password, "'\\''"])} --audit-use-ssl 1 -f >> /opt/datasunrise/logs/start.log
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
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    source_address_prefix      = var.allow_cidr_to_ssh_22
    destination_port_range     = 22
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "Backend-11000"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    source_address_prefix      = var.allow_cidr_to_backend_8080
    destination_port_range     = 11000
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "Backend-11001"
    priority                   = 1004
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    source_address_prefix      = var.allow_cidr_to_backend_8080
    destination_port_range     = 11001
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "Backend-11002"
    priority                   = 1005
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    source_address_prefix      = var.allow_cidr_to_backend_8080
    destination_port_range     = 11002
    destination_address_prefix = "*"
  }
}

# Connect the security group to the network interface
resource "azurerm_network_interface_security_group_association" "association_sg_to_interface_reference" {
  count                     = 1
  network_interface_id      = azurerm_network_interface.ds_network_interface[count.index].id
  network_security_group_id = azurerm_network_security_group.network_security_group_reference.id
  depends_on                = [
    azurerm_network_security_group.network_security_group_reference
  ]
}

resource "azurerm_public_ip" "public_ip_reference" {
  # IS PUBLIC
  count               = 1
  name                = "${local.name}-reference-ds"
  resource_group_name = azurerm_virtual_network.virtual_network.resource_group_name
  location            = azurerm_virtual_network.virtual_network.location
  allocation_method   = "Dynamic"
  sku                 = "Basic"
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
    public_ip_address_id          = azurerm_public_ip.public_ip_reference[0].id
  }
}

resource "azurerm_linux_virtual_machine" "datasunrise_instance" {
  count                 = 1
  name                  = "${local.name}-reference-ds"
  resource_group_name   = azurerm_virtual_network.virtual_network.resource_group_name
  location              = azurerm_virtual_network.virtual_network.location
  network_interface_ids = [
    azurerm_network_interface.ds_network_interface[count.index].id
  ]
  size                  = "Standard_B2s"

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
    type         = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.identity.id
    ]
  }

  depends_on = [
    azurerm_key_vault_secret.ds_reference,
    azurerm_postgresql_flexible_server.postgres,
    azurerm_network_interface_security_group_association.association_sg_to_interface_reference,
    azurerm_network_interface.ds_network_interface,
    azurerm_public_ip.public_ip_reference,
    azurerm_subnet.default_subnet,
    azurerm_network_security_group.network_security_group_reference,
    azurerm_ssh_public_key.ssh_key
  ]
}

// APP
data "azurerm_subscription" "current" {
}

resource "azuread_application_registration" "app_registration" {
  display_name = "app-${local.name}"
}

resource "azuread_service_principal" "dspm_sp" {
  client_id = azuread_application_registration.app_registration.client_id
}

resource "azurerm_role_assignment" "admin_app" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = azuread_service_principal.dspm_sp.object_id
}

resource "azurerm_role_assignment" "reade_app" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Reader"
  principal_id         = azuread_service_principal.dspm_sp.object_id
}

resource "azurerm_role_assignment" "user_app" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azuread_service_principal.dspm_sp.object_id
}

resource "azurerm_role_assignment" "subscription_app" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.dspm_sp.object_id
}

resource "azurerm_role_assignment" "contributor_app" {
  scope                = azurerm_resource_group.resource_group.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.dspm_sp.object_id
}

resource "azurerm_role_assignment" "owner_app" {
  scope                = azurerm_resource_group.resource_group.id
  role_definition_name = "Owner"
  principal_id         = azuread_service_principal.dspm_sp.object_id
}


resource "azuread_application_password" "secret" {
  display_name    = local.name
  application_id  = azuread_application_registration.app_registration.id
  depends_on = [
    azuread_application_registration.app_registration
  ]
}

locals {
  link = azurerm_public_ip.public_ip.ip_address == "" ? "" : <<EOT

You can now access the DSPM web console at:
===============================================================================
👉 https://${azurerm_public_ip.public_ip.ip_address}:8080
===============================================================================

EOT
}

output "result" {
  value = <<EOT
🎉 Thank you for deploying and using DataSunrise DSPM! 🎉
${local.link}
Use the following parameters to log in to the DSPM UI:

  🔹 Tenant ID:     ${nonsensitive(data.azurerm_client_config.current.tenant_id)}
  🔹 Client ID:     ${nonsensitive(azuread_application_registration.app_registration.client_id)}
  🔹 Client Secret: ${nonsensitive(azuread_application_password.secret.value)}

⚠️ Please store this information securely.
EOT
}

output "image_id" {
  value = local.image_id
}