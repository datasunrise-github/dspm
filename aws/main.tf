locals {
  is_linux = length(regexall("/home/", lower(abspath(path.root)))) > 0
}

locals {
  search_ami = {
    "dev" = "MR-*-DataSunrise-Data-Security-Posture-Management-*",
    "rc" = "RC-*-DataSunrise-Data-Security-Posture-Management-*",
    "release" = "DataSunrise-Data-Security-Posture-Management*"
  }
}
data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "dspm" {
  most_recent = true
  owners      = ["042001279082"]

  filter {
    name   = "name"
    values = [
      local.search_ami[var.image_type]
    ]
  }
}

data "aws_ami" "ds" {
  owners = ["042001279082"]
  most_recent = true
  filter {
    name   = "is-public"
    values = [true]
  }
  filter {
    name   = "name"
    values = ["Datasunrise-AMZN-LINUX2023*"]
  }
}

locals {
  # Generate bucket name if not provided
  auto_bucket_name = var.s3_bucket_name != "" ? var.s3_bucket_name : "${lower(var.prefix_name)}-dspm-terraform-cache"
  # Use specified region or current region
  bucket_region = var.s3_bucket_region != "" ? var.s3_bucket_region : var.region
}

# Create S3 bucket if not provided
resource "aws_s3_bucket" "terraform_cache_auto" {
  count  = var.s3_bucket_name == "" ? 1 : 0
  bucket = local.auto_bucket_name

  tags = {
    Name        = "${var.prefix_name}-DSPM-Terraform-Cache"
    Environment = "DSPM"
    ManagedBy   = "Terraform"
    Purpose     = "Terraform state cache for DSPM resources"
  }

  depends_on = [
    aws_db_instance.postgres
  ]
}

resource "null_resource" "s3" {
  count  = var.s3_bucket_name == "" ? 1 : 0
  triggers = {
    name            = local.auto_bucket_name
  }
  provisioner "local-exec" {
    when        = destroy
    on_failure  = fail
    command     = "aws s3 rm s3://${self.triggers.name}/dsssm/"
  }

  depends_on = [
    aws_s3_bucket.terraform_cache_auto
  ]
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "terraform_cache_auto_pab" {
  count  = var.s3_bucket_name == "" ? 1 : 0
  bucket = aws_s3_bucket.terraform_cache_auto[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [
    aws_s3_bucket.terraform_cache_auto
  ]
}

# Use existing bucket if provided, otherwise use the auto-created one
data "aws_s3_bucket" "terraform_cache" {
  bucket = var.s3_bucket_name != "" ? var.s3_bucket_name : aws_s3_bucket.terraform_cache_auto[0].id
  depends_on = [aws_s3_bucket.terraform_cache_auto]
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "${var.prefix_name}-Ds3mVpc"
  }
}

resource "aws_subnet" "subnet_ec2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.0.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.prefix_name}-Ds3mSubnetEc2"
  }

  depends_on = [
    aws_vpc.main
  ]
}

resource "aws_subnet" "subnet_db" {
  count = length(data.aws_availability_zones.available.names)
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.prefix_name}-Ds3mSubnet-${data.aws_availability_zones.available.names[count.index]}"
  }
  depends_on = [
    aws_vpc.main
  ]
}

resource "aws_internet_gateway" "ig" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.prefix_name}-Ds3mNetGw"
  }
  depends_on = [
    aws_vpc.main
  ]
}

resource "aws_eip" "nat_eip" {
  domain     = "vpc"
  depends_on = [
    aws_vpc.main,
    aws_internet_gateway.ig
  ]
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.subnet_ec2.id

  tags = {
    Name = "${var.prefix_name}-Ds3mNat"
  }

  depends_on    = [
    aws_eip.nat_eip,
    aws_subnet.subnet_ec2,
    aws_internet_gateway.ig
  ]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.prefix_name}-Ds3mRt"
  }
  depends_on = [
    aws_vpc.main
  ]
}

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.ig.id

  depends_on = [
    aws_vpc.main,
    aws_internet_gateway.ig,
    aws_route_table.public
  ]
}

resource "aws_route_table_association" "ec2" {
  subnet_id      = aws_subnet.subnet_ec2.id
  route_table_id = aws_route_table.public.id

  depends_on = [
    aws_route_table.public,
    aws_subnet.subnet_ec2,
    aws_vpc.main
  ]
}

resource "aws_security_group" "ec2" {
  name        = "${var.prefix_name}-Ds3mEc2Sg"
  description = "Allow8080and22"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.prefix_name}-Ds3mEc2Sg"
  }

  depends_on = [
    aws_vpc.main
  ]
}

resource "aws_security_group" "db" {
  name        = "${var.prefix_name}-Ds3mDbSg"
  description = "Allow5432"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.prefix_name}-Ds3mDbSg"
  }
  depends_on = [
    aws_vpc.main
  ]
}

resource "aws_security_group" "ds" {
  name        = "${var.prefix_name}-Ds3mDsSg"
  description = "Allow11000"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.prefix_name}-Ds3mDsSg"
  }
  depends_on = [
    aws_vpc.main
  ]
}

########################
### DSPM
########################

## DSPM users
resource "aws_vpc_security_group_ingress_rule" "request_from_user_to_dspm" {
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = var.allow_cidr_to_backend_8080
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2
  ]
}

resource "aws_vpc_security_group_egress_rule" "response_from_dspm_to_user" {
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = var.allow_cidr_to_backend_8080
  from_port         = 32768
  to_port           = 65535
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2
  ]
}

## DSPM admin

resource "aws_vpc_security_group_ingress_rule" "request_by_ssh_22" {
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = var.allow_cidr_to_ssh_22
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2
  ]
}

resource "aws_vpc_security_group_egress_rule" "response_by_ssh" {
  count             = var.allow_cidr_to_ssh_22 == var.allow_cidr_to_backend_8080 ? 0 : 1
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = var.allow_cidr_to_ssh_22
  from_port         = 32768
  to_port           = 65535
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2
  ]
}

## DSPM downloading tools, certs and metadata
resource "aws_vpc_security_group_ingress_rule" "request_net" {
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 32768
  to_port           = 65535
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2
  ]
}

resource "aws_vpc_security_group_egress_rule" "response_net" {
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 1
  to_port           = 32768
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2
  ]
}

## DSPM Reference DS

resource "aws_vpc_security_group_egress_rule" "request_from_dspm_to_ds_11000" {
  security_group_id             = aws_security_group.ec2.id
  referenced_security_group_id  = aws_security_group.ds.id
  from_port                     = 11000
  to_port                       = 11000
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2,
    aws_security_group.ds
  ]
}

resource "aws_vpc_security_group_ingress_rule" "response_from_dspm_to_ds" {
  security_group_id =             aws_security_group.ec2.id
  referenced_security_group_id  = aws_security_group.ds.id
  from_port                       = 32768
  to_port                         = 65535
  ip_protocol                     = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2,
    aws_security_group.ds
  ]
}

## DSPM database

resource "aws_vpc_security_group_egress_rule" "request_from_dspm_to_database" {
  security_group_id             = aws_security_group.ec2.id
  referenced_security_group_id  = aws_security_group.db.id
  from_port                     = 5432
  to_port                       = 5432
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2,
    aws_security_group.db
  ]
}

resource "aws_vpc_security_group_ingress_rule" "response_from_database_to_dspm" {
  security_group_id             = aws_security_group.ec2.id
  referenced_security_group_id  = aws_security_group.db.id
  from_port                     = 32768
  to_port                       = 65535
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ec2,
    aws_security_group.db
  ]
}

## DSPM downloading tools, certs and metadata
resource "aws_vpc_security_group_ingress_rule" "ds_request_net" {
  security_group_id = aws_security_group.ds.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 32768
  to_port           = 65535
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds
  ]
}

resource "aws_vpc_security_group_egress_rule" "ds_response_net" {
  security_group_id = aws_security_group.ds.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 1
  to_port           = 32768
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds
  ]
}

########################
# Database
########################

## Database DSPM
resource "aws_vpc_security_group_ingress_rule" "request_from_dspm_to_database" {
  security_group_id             = aws_security_group.db.id
  referenced_security_group_id  = aws_security_group.ec2.id
  from_port                     = 5432
  to_port                       = 5432
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.db,
    aws_security_group.ec2
  ]
}

resource "aws_vpc_security_group_egress_rule" "response_from_database_to_dspm" {
  security_group_id             = aws_security_group.db.id
  referenced_security_group_id  = aws_security_group.ec2.id
  from_port                     = 32768
  to_port                       = 65535
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.db,
    aws_security_group.ec2
  ]
}

## Database reference DS
resource "aws_vpc_security_group_ingress_rule" "request_from_ds_to_database" {
  security_group_id             = aws_security_group.db.id
  referenced_security_group_id  = aws_security_group.ds.id
  from_port                     = 5432
  to_port                       = 5432
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.db,
    aws_security_group.ds
  ]
}

resource "aws_vpc_security_group_egress_rule" "response_from_database_to_ds" {
  security_group_id             = aws_security_group.db.id
  referenced_security_group_id  = aws_security_group.ds.id
  from_port                     = 32768
  to_port                       = 65535
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.db,
    aws_security_group.ds
  ]
}

## Database admin
resource "aws_vpc_security_group_ingress_rule" "request_from_admin_to_database" {
  security_group_id             = aws_security_group.db.id
  cidr_ipv4                     = var.allow_cidr_to_ssh_22
  from_port                     = 5432
  to_port                       = 5432
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.db
  ]
}

resource "aws_vpc_security_group_egress_rule" "response_from_database_to_admin" {
  security_group_id             = aws_security_group.db.id
  cidr_ipv4                     = var.allow_cidr_to_ssh_22
  from_port                     = 32768
  to_port                       = 65535
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.db
  ]
}


########################
# Reference DataSunrise
########################

## DSPM
resource "aws_vpc_security_group_ingress_rule" "request_from_dspm_to_ds" {
  security_group_id             = aws_security_group.ds.id
  referenced_security_group_id  = aws_security_group.ec2.id
  from_port                     = 11000
  to_port                       = 11000
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds,
    aws_security_group.ec2
  ]
}

resource "aws_vpc_security_group_egress_rule" "response_from_ds_to_dspm" {
  security_group_id             = aws_security_group.ds.id
  referenced_security_group_id  = aws_security_group.ec2.id
  from_port                     = 32768
  to_port                       = 65535
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds,
    aws_security_group.ec2
  ]
}

## Database
resource "aws_vpc_security_group_egress_rule" "request_from_ds_to_database" {
  security_group_id             = aws_security_group.ds.id
  referenced_security_group_id  = aws_security_group.db.id
  from_port                     = 5432
  to_port                       = 5432
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds,
    aws_security_group.db
  ]
}

resource "aws_vpc_security_group_ingress_rule" "response_from_database_to_ds" {
  security_group_id             = aws_security_group.ds.id
  referenced_security_group_id  = aws_security_group.db.id
  from_port                     = 32768
  to_port                       = 65535
  ip_protocol                   = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds,
    aws_security_group.db
  ]
}

## DS admin

resource "aws_vpc_security_group_ingress_rule" "request_to_ds_by_ssh_22" {
  security_group_id = aws_security_group.ds.id
  cidr_ipv4         = var.allow_cidr_to_ssh_22
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds
  ]
}

resource "aws_vpc_security_group_ingress_rule" "request_to_ds_by_admin_11000" {
  security_group_id = aws_security_group.ds.id
  cidr_ipv4         = var.allow_cidr_to_ssh_22
  from_port         = 11000
  to_port           = 11000
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds
  ]
}

resource "aws_vpc_security_group_egress_rule" "response_from_ds_by_ssh" {
  security_group_id = aws_security_group.ds.id
  cidr_ipv4         = var.allow_cidr_to_ssh_22
  from_port         = 32768
  to_port           = 65535
  ip_protocol       = "tcp"
  depends_on = [
    aws_vpc.main,
    aws_security_group.ds
  ]
}

############################################################


resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "${var.prefix_name}-ds3m-subnet-group"
  subnet_ids = aws_subnet.subnet_db[*].id

  tags = {
    Name = "${var.prefix_name}-ds3m-subnet-group"
  }

  depends_on = [
    aws_vpc.main,
    aws_subnet.subnet_db
  ]
}

resource "aws_db_instance" "postgres" {
  identifier             = "${var.prefix_name}-ds3m-db"
  instance_class         = "db.t3.micro"
  allocated_storage      = 32
  engine                 = "postgres"
  engine_version         = "16"
  username               = "postgres"
  password               = var.postgres_password
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  skip_final_snapshot    = true

  depends_on = [
    aws_vpc.main,
    aws_db_subnet_group.db_subnet_group,
    aws_security_group.db
  ]
}

resource "aws_secretsmanager_secret" "ds_secret" {
  name = "${var.prefix_name}-ds3m-ds-secret"

  depends_on = [
    aws_db_instance.postgres
  ]
}

resource "aws_secretsmanager_secret_version" "ds_secret_version" {
  secret_id     = aws_secretsmanager_secret.ds_secret.id
  secret_string = "{\"username\": \"admin\", \"password\": \"${var.datasunrise_password}\"}"
  depends_on = [
    aws_secretsmanager_secret.ds_secret
  ]
}

# IAM role for DSPM EC2 instance
resource "aws_iam_role" "dspm_instance_role" {
  name               = "${var.prefix_name}-DSPM-Instance-Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.prefix_name}-DSPM-Instance-Role"
  }
}

# IAM policy for accessing the DataSunrise secret
resource "aws_iam_role_policy" "dspm_secret_access" {
  name = "${var.prefix_name}-DSPM-Secret-Access"
  role = aws_iam_role.dspm_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.ds_secret.arn
      }
    ]
  })

  depends_on = [
    aws_iam_role.dspm_instance_role
  ]
}

# Instance profile for DSPM EC2 instance
resource "aws_iam_instance_profile" "dspm_instance_profile" {
  name = "${var.prefix_name}-DSPM-Instance-Profile"
  role = aws_iam_role.dspm_instance_role.name

  tags = {
    Name = "${var.prefix_name}-DSPM-Instance-Profile"
  }

  depends_on = [
    aws_iam_role.dspm_instance_role
  ]
}

locals {
  userData = <<EOT
#!/bin/bash
TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
INSTID=`curl -s http://169.254.169.254/latest/meta-data/instance-id -H "X-aws-ec2-metadata-token: $TOKEN"`
REGION=`curl -s http://169.254.169.254/latest/meta-data/placement/region -H "X-aws-ec2-metadata-token: $TOKEN"`
PUB_IP=`curl -s http://169.254.169.254/latest/meta-data/public-ipv4 -H "X-aws-ec2-metadata-token: $TOKEN"`

wget -O /home/ec2-user/dsssm/certs/rds.crt "${var.url_rds_certificate}"

echo "{
   \"UrlToBuild\": \"\",
   \"Email\": \"${var.email}\",
   \"PublicIP\": \"$PUB_IP\",
   \"Reference\": {
      \"DsSecret\": \"${aws_secretsmanager_secret.ds_secret.arn}\",
      \"Dictionary\": {
        \"SSL\": true,
        \"Host\": \"${element(split(":", aws_db_instance.postgres.endpoint), 0)}\",
        \"Database\": \"postgres\",
        \"Schema\": \"public\",
        \"Username\": \"postgres\",
        \"Password\": \"${var.postgres_password}\"
      },
      \"Audit\": {
        \"SSL\": true,
        \"Host\": \"${element(split(":", aws_db_instance.postgres.endpoint), 0)}\",
        \"Database\": \"postgres\",
        \"Schema\": \"public\",
        \"Username\": \"postgres\",
        \"Password\": \"${var.postgres_password}\"
      }
   },
   \"AccountIDs\": [${length(var.allow_access_for_aws_account_ids) == 0 ? format("\\\"%s\\\"", data.aws_caller_identity.current.account_id) : join(",", formatlist("\\\"%s\\\"", var.allow_access_for_aws_account_ids))}],
   \"TenantIDs\": [${join(",", formatlist("\\\"%s\\\"", var.allow_access_for_azure_account_ids))}],
   \"TerraformCache\": {
     \"BucketName\": \"${local.auto_bucket_name}\",
     \"Region\": \"${data.aws_s3_bucket.terraform_cache.region}\"
   },
   \"AliasKeyNames\": {},
   \"Subnets\": [
     \"${aws_subnet.subnet_ec2.id}\"
   ],
   \"SecurityGroups\": [
     \"${aws_security_group.ec2.id}\"
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
}" > /home/ec2-user/dsssm/config/app.json

echo '{
  "development": {
    "username": "postgres",
    "password": "${var.postgres_password}",
    "database": "postgres",
    "host": "${element(split(":", aws_db_instance.postgres.endpoint), 0)}",
    "dialect": "postgres",
    "dialectOptions": {
      "ssl": {
        "require": true,
        "rejectUnauthorized": true,
        "ca": [
          "/home/ec2-user/dsssm/certs/rds.crt"
        ]
      }
    }
  }
}' > /home/ec2-user/dsssm/config/config.json

echo '${var.http_server_key}' > /home/ec2-user/dsssm/certs/server.key

echo '${var.http_server_crt}' > /home/ec2-user/dsssm/certs/server.crt

echo '${var.encryption_private_key}' > /home/ec2-user/dsssm/src/helpers/encryption/private.pem

echo '${var.encryption_public_key}' > /home/ec2-user/dsssm/src/helpers/encryption/public.pem

yum install nodejs -y

UV_USE_IO_URING=0
export UV_USE_IO_URING=0

cd /home/ec2-user/dsssm && npm install && npm run start-database-migration

sudo chown -R root:root /home/ec2-user/dsssm

echo '[Unit]
Description=DSPM (Data Security Posture Management) Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/ec2-user/dsssm
Environment="UV_USE_IO_URING=0"
ExecStart=/usr/bin/npm run start-http-server
ExecStop=/usr/bin/pkill -f "node.*start-http-server"
Restart=on-failure
RestartSec=10
StandardOutput=append:/home/ec2-user/dsssm/logs/dsssm.txt
StandardError=append:/home/ec2-user/dsssm/logs/dsssm.txt

[Install]
WantedBy=multi-user.target
' > /etc/systemd/system/dspm.service

sudo systemctl daemon-reload

sudo systemctl enable dspm.service

sudo systemctl start dspm.service

sudo systemctl status dspm.service

EOT
}

resource "aws_instance" "ds3m" {
  ami                               = data.aws_ami.dspm.id
  instance_type                     = "t3.medium"
  iam_instance_profile              = var.iam_role_profile_name
  subnet_id                         = aws_subnet.subnet_ec2.id
  key_name                          = var.key_name
  vpc_security_group_ids            = [aws_security_group.ec2.id]
  user_data_base64 = base64encode(local.userData)

  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 32
  }

  tags = {
    Name = "${var.prefix_name}-Ds3mInstance"
  }

  depends_on = [
    aws_db_instance.postgres,
    aws_s3_bucket.terraform_cache_auto,
    aws_vpc.main,
    aws_subnet.subnet_db,
    aws_subnet.subnet_ec2,
    aws_internet_gateway.ig,
    aws_eip.nat_eip,
    aws_nat_gateway.nat,
    aws_route_table.public,
    aws_route.public_internet_gateway,
    aws_route_table_association.ec2,
    aws_security_group.ec2,
    aws_security_group.db,
    aws_security_group.ds,
    aws_db_subnet_group.db_subnet_group,
    aws_db_instance.postgres,
    aws_instance.ds3m,
    aws_iam_role.iam_role,
    aws_iam_instance_profile.iam_role_profile
  ]
}

locals {
  dsUserData = <<EOT
#!/bin/bash

echo "Installation..."
yum install jq -y
yum install /opt/cooked/installer.rpm -y
CUSTOM_CONFIG_DS=""
if [[ $CUSTOM_CONFIG_DS != "" ]]
then
  echo "Usage custom file: $CUSTOM_CONFIG_DS"
  rm /opt/datasunrise/scripts/configure-datasunrise.sh
  aws s3 cp $CUSTOM_CONFIG_DS /opt/datasunrise/scripts/configure-datasunrise.sh
  chmod +x /opt/datasunrise/scripts/configure-datasunrise.sh
  chown datasunrise:datasunrise /opt/datasunrise/scripts/configure-datasunrise.sh
fi

echo '[Unit]
 Description=/etc/rc.local Compatibility
 ConditionPathExists=/etc/rc.local

[Service]
 Type=forking
 ExecStart=/etc/rc.local start
 ExecStop=/etc/rc.local stop
 TimeoutSec=0
 StandardOutput=tty
 RemainAfterExit=yes
 SysVStartPriority=99

[Install]
 WantedBy=multi-user.target
' > /etc/systemd/system/rc-local.service

echo '#!/bin/bash
systemctl stop datasunrise.service

if [[ $1 == "start" ]]
then
  export AF_HOME=/opt/datasunrise/
  TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
  INSTID=`curl -s http://169.254.169.254/latest/meta-data/instance-id -H "X-aws-ec2-metadata-token: $TOKEN"`
  DS_HOST_PRIVIP=`curl -s http://169.254.169.254/latest/meta-data/local-ipv4 -H "X-aws-ec2-metadata-token: $TOKEN"`

  echo "Configuration..."
  sudo runuser -u datasunrise -- /opt/datasunrise/scripts/configure-datasunrise.sh setup-remote-configuration --dictionary-type "postgresql" --dictionary-host ${element(split(":", aws_db_instance.postgres.endpoint), 0)} --dictionary-port 5432 --dictionary-database "postgres" --dictionary-schema "public" --dictionary-login "postgres" ${join("", ["--dictionary-password ", "'\\''", var.postgres_password, "'\\''"])} --dictionary-use-ssl 1 --server-name dsssm-$INSTID-${var.prefix_name} --server-host "$DS_HOST_PRIVIP" --server-port 11000  --server-use-https 1 --copy-proxies 1  -f -v >> /opt/datasunrise/logs/start.log
  PASS=`aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.ds_secret.id} | jq --raw-output ".SecretString" | jq --raw-output ".password"` >> /opt/datasunrise/logs/start.log
  PASS="$${PASS//\'\''/\'\''\\\'\''\'\''}"
  /opt/datasunrise/scripts/configure-datasunrise.sh setup-password --password "$PASS" -f >> /opt/datasunrise/logs/start.log
  systemctl start datasunrise.service
fi

if [[ $1 == "stop" ]]
then
  /opt/datasunrise/AppBackendService AF_HOME=/opt/datasunrise AF_CONFIG=/opt/datasunrise/ UNREGISTER_FIREWALL_SERVER
fi

exit 0
' > /etc/rc.local

chmod +x /etc/rc.local

systemctl stop datasunrise.service

systemctl enable rc-local

systemctl start rc-local.service

systemctl status rc-local.service

EOT
}

resource "aws_instance" "ds_reference_instance" {
  count = 1
  ami                               = data.aws_ami.ds.id
  instance_type                     = "t3.medium"
  iam_instance_profile              = aws_iam_instance_profile.dspm_instance_profile.name
  subnet_id                         = aws_subnet.subnet_ec2.id
  key_name                          = var.key_name
  vpc_security_group_ids            = [aws_security_group.ds.id]
  user_data_base64                  = base64encode(local.dsUserData)
  tags = {
    Name                            = "${var.prefix_name}-reference-ds"
  }
  root_block_device {
    volume_size           = 64
    volume_type           = "gp3"
    delete_on_termination = true
  }

  depends_on = [
    aws_vpc.main,
    aws_subnet.subnet_ec2,
    aws_security_group.ds,
    aws_iam_instance_profile.dspm_instance_profile
  ]
}

resource "aws_iam_role" "iam_role" {
  name               = "${var.prefix_name}-Ds3mIamRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": [
            "rds.amazonaws.com",
            "s3.amazonaws.com",
            "ec2.amazonaws.com"
          ]
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })
  inline_policy {
    name = "${var.prefix_name}-access-to-put-logs-by-aws-service"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          "Effect": "Allow",
          "Action": [
            "s3:ListMultipartUploadParts",
            "s3:PutObject",
            "s3:AbortMultipartUpload"
          ],
          "Resource": "arn:aws:s3:::*"
        }
      ]
    })
  }
  inline_policy {
    name = "${var.prefix_name}-access-to-read-logs-by-aws-service"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          "Effect": "Allow",
          "Action": [
            "s3:GetBucketLocation",
            "s3:GetBucketACL",
            "s3:ListBucket"
          ],
          "Resource": "arn:aws:s3:::*"
        }
      ]
    })
  }
  inline_policy {
    name = "${var.prefix_name}-access-to-read-files-by-aws-DS"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          "Effect": "Allow",
          "Action": [
            "s3:ListAllMyBuckets",
            "s3:GetObject",
            "s3:HeadObject",
            "s3:ListObjectsV2",
            "s3:ListObjects"
          ],
          "Resource": "arn:aws:s3:::*"
        }
      ]
    })
  }
  inline_policy {
    name = "${var.prefix_name}-datasunrise-instance-policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          "Effect": "Allow",
          "Action": [
            "rds:DownloadCompleteDBLogFile",
            "rds:DownloadDBLogFilePortion",
            "rds:DescribeDBClusters",
            "rds:DescribeDBInstances",
            "rds:DescribeDBLogFiles"
          ],
          "Resource": "arn:aws:rds:*"
        },
        {
          "Effect": "Allow",
          "Action": [
            "secretsmanager:DescribeSecret",
            "secretsmanager:GetSecretValue"
          ],
          "Resource": "arn:aws:secretsmanager:*"
        }
      ]
    })
  }
}

resource "aws_iam_instance_profile" "iam_role_profile" {
  name = "${var.prefix_name}-Ds3mIamRoleProfile"
  role = aws_iam_role.iam_role.name
}

resource "null_resource" "update" {
  count = var.path_to_private_key_for_update_build != "" ? 1 : 0
  triggers = {
    always_run  = "${timestamp()}"
    host        = aws_instance.ds3m.public_ip
    private_key = file(var.path_to_private_key_for_update_build)
  }

  provisioner "remote-exec" {
    inline = [
      "sudo systemctl stop rc-local",
      "sudo rm dsssm/ -R"
    ]
  }

  provisioner "local-exec" {
    command = "cd ../../ && npm run deploy"
  }

  provisioner "file" {
    source      = "../../../dsssm"
    destination = "/home/ec2-user"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo chown root:root dsssm/ -R"
    ]
  }

  connection {
    host        = self.triggers.host
    type        = "ssh"
    user        = "ec2-user"
    private_key = self.triggers.private_key
  }

  depends_on = [
    aws_instance.ds3m
  ]
}

output "web_console" {
  value = "https://${aws_instance.ds3m.public_ip}:8080"
}

output "dspm_ami" {
  value = "${data.aws_ami.dspm.name} (${data.aws_ami.dspm.id})"
}

output "ds_ami" {
  value = "${data.aws_ami.ds.name} (${data.aws_ami.ds.id})"
}
