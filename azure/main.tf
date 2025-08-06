resource "random_pet" "database" {
  prefix    = "database"
  separator = "-"
}

resource "azurerm_resource_group" "resource_group" {
  name     = var.resource_group_name
  location = var.resource_group_location
}

resource "azurerm_ssh_public_key" "ssh_key" {
  name                = "ssh_key"
  resource_group_name = var.resource_group_name
  location            = var.resource_group_location
  public_key          = file(var.pathPublicKey)

  depends_on = [
    azurerm_resource_group.resource_group
  ]
}

# Create Network Security Group and rule
resource "azurerm_network_security_group" "network_security_group" {
  name                = "network_security_group"
  resource_group_name = var.resource_group_name
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
  name                  = "virtual_network"
  address_space         = ["10.0.0.0/16"]
  resource_group_name   = var.resource_group_name
  location            = var.resource_group_location

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_subnet" "default_subnet" {
  name                  = "default_subnet"
  resource_group_name   = var.resource_group_name
  virtual_network_name  = azurerm_virtual_network.virtual_network.name
  address_prefixes      = ["10.0.0.0/24"]

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_subnet" "default_pg" {
  name                  = "default_pg"
  resource_group_name   = var.resource_group_name
  virtual_network_name  = azurerm_virtual_network.virtual_network.name
  address_prefixes      = ["10.0.1.0/24"]

  service_endpoints    = ["Microsoft.Storage"]
  delegation {
    name = "fs"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }

  depends_on = [azurerm_virtual_network.virtual_network]
}



resource "azurerm_public_ip" "public_ip" {
  name                = "public_ip"
  resource_group_name = var.resource_group_name
  location            = var.resource_group_location
  allocation_method   = "Dynamic"

  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_network_interface" "interface_dsssm" {
  name                = "interface_dsssm"
  resource_group_name = var.resource_group_name
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

locals {
  userData = <<EOT
#!/bin/bash

echo '{
  "UrlToBuild": "",
  "AliasKeyNames": {},
  "Subnets": [
    "${azurerm_subnet.default_subnet.id}"
  ],
  "SecurityGroups": [
    "${azurerm_network_security_group.network_security_group.id}"
  ],
  "FullEncryptionProtocol": false,
  "OnlyOneRegion": false,
  "MaxThreadUpdateMetadata": 25,
  "SessionTimeout": 100,
  "IgnoreMaskTypeCheck": true,
  "Logs": {
    "UPDATE_METADATA": true,
    "RPC": true,
    "OTHER": false,
    "ERROR": true,
    "API_REQUEST": false,
    "API_RESPONSE": false,
    "ACCOUNTS": true,
    "TRACE_NET_ACCESS_AWS": false,
    "COMMANDS": false
  }
} > /etc/dsssm/dsssm/config/app.json'

echo '{
  "development": {
    "username": "${var.postgres_username}",
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
}' > /etc/dsssm/dsssm/config/config.json

echo '${var.http_server_key}' > /etc/dsssm/dsssm/certs/server.key

echo '${var.http_server_crt}' > /etc/dsssm/dsssm/certs/server.crt

echo '${var.encryption_private_key}' > /etc/dsssm/dsssm/src/helpers/encryption/private.pem

echo '${var.encryption_public_key}' > /etc/dsssm/dsssm/src/helpers/encryption/public.pem

cd /etc/dsssm/dsssm && npm install && npm run start-database-migration

echo '[Unit]
Description=DSPM (Data Security Posture Management) Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/dsssm/dsssm
Environment="UV_USE_IO_URING=0"
ExecStart=/usr/bin/npm run start-http-server
ExecStop=/usr/bin/pkill -f "node.*start-http-server"
Restart=on-failure
RestartSec=10
StandardOutput=append:/etc/dsssm/dsssm/logs/dsssm.txt
StandardError=append:/etc/dsssm/dsssm/logs/dsssm.txt

[Install]
WantedBy=multi-user.target
' > /etc/systemd/system/dspm.service

sudo systemctl daemon-reload

sudo systemctl enable dspm.service

sudo systemctl start dspm.service

sudo systemctl status dspm.service

EOT
}


### Database

resource "azurerm_private_dns_zone" "private_dns_zone" {
  name                = var.postgres_domain
  resource_group_name = var.resource_group_name
  depends_on = [azurerm_resource_group.resource_group]
}

resource "azurerm_private_dns_zone_virtual_network_link" "private_dns_zone_virtual_network_link" {
  name                  = "link_database_dsssm"
  private_dns_zone_name = azurerm_private_dns_zone.private_dns_zone.name
  virtual_network_id    = azurerm_virtual_network.virtual_network.id
  resource_group_name   = azurerm_resource_group.resource_group.name
  depends_on            = [azurerm_subnet.default_pg, azurerm_private_dns_zone.private_dns_zone]
}

resource "azurerm_postgresql_flexible_server" "postgres" {
  name                          = random_pet.database.id
  resource_group_name           = var.resource_group_name
  location                      = var.resource_group_location
  version                       = "13"
  delegated_subnet_id           = azurerm_subnet.default_pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.private_dns_zone.id
  administrator_login           = var.postgres_username
  administrator_password        = var.postgres_password
  zone                          = "1"

  storage_mb   = 32768

  sku_name   = "B_Standard_B2s"
  depends_on = [azurerm_private_dns_zone.private_dns_zone]
}

// Instance
resource "azurerm_linux_virtual_machine" "virtual_machine" {
  name                  = "virtual_machine"
  location              = var.resource_group_location
  resource_group_name   = var.resource_group_name
  network_interface_ids = [
    azurerm_network_interface.interface_dsssm.id
  ]
  size                  = "Standard_B2s"

  os_disk {
    name                 = "dsssm_disk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_id = var.image_id

  user_data = base64encode(local.userData)

  computer_name  = "hostname"
  admin_username = var.username

  admin_ssh_key {
    username   = var.username
    public_key = azurerm_ssh_public_key.ssh_key.public_key
  }

  provisioner "local-exec" {
    when        = destroy
    on_failure  = fail
    command     = "az vm run-command create --async-execution false --resource-group \"${self.resource_group_name}\" --location \"${self.location}\" --run-command-name \"DELETION_RESOURCES_CREATED_BY_DSSSM\" --vm-name \"${self.name}\" --script \"cd /etc/dsssm/dsssm && npm run uninstall\""
    interpreter = [
      "bash",
      "-c"
    ]
  }

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

resource "null_resource" "update" {
  count = var.path_to_private_key_for_update_build != "" ? 1 : 0
  triggers = {
    always_run  = "${timestamp()}"
    host        = azurerm_public_ip.public_ip.ip_address
    private_key = file(var.path_to_private_key_for_update_build)
  }

  provisioner "local-exec" {
    command = "cd ../../ && npm run deploy"
  }

  provisioner "file" {
    source      = "../../../dsssm"
    destination = "/etc/dsssm"
  }

  connection {
    host        = self.triggers.host
    type        = "ssh"
    user        = azurerm_linux_virtual_machine.virtual_machine.admin_username
    private_key = self.triggers.private_key
  }

  depends_on = [
    azurerm_linux_virtual_machine.virtual_machine
  ]
}

output "WebConsole" {
  value = "https://${azurerm_public_ip.public_ip.ip_address}:8080"
  depends_on = [
    azurerm_linux_virtual_machine.virtual_machine
  ]
}
