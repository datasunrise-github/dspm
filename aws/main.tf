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

data "aws_ami" "latest" {
  most_recent = true
  owners      = ["042001279082"]

  filter {
    name   = "name"
    values = [
      local.search_ami[var.image_type]
    ]
  }
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
}

resource "aws_internet_gateway" "ig" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.prefix_name}-Ds3mNetGw"
  }
}

resource "aws_eip" "nat_eip" {
  vpc        = true
  depends_on = [aws_internet_gateway.ig]
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.subnet_ec2.id
  depends_on    = [aws_internet_gateway.ig]
  tags = {
    Name = "${var.prefix_name}-Ds3mNat"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.prefix_name}-Ds3mRt"
  }
}

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.ig.id
}

resource "aws_route_table_association" "ec2" {
  subnet_id      = aws_subnet.subnet_ec2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "ec2" {
  name        = "${var.prefix_name}-Ds3mEc2Sg"
  description = "Allow8080and22"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.prefix_name}-Ds3mEc2Sg"
  }
}

resource "aws_security_group" "db" {
  name        = "${var.prefix_name}-Ds3mDbSg"
  description = "Allow5432"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.prefix_name}-Ds3mDbSg"
  }
}

resource "aws_security_group" "ds" {
  name        = "${var.prefix_name}-Ds3mDsSg"
  description = "Allow11000"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${var.prefix_name}-Ds3mDsSg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "allow_8000" {
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = var.allow_cidr_to_backend_8080
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "ec2_all" {
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "all"
}

resource "aws_vpc_security_group_ingress_rule" "allow_22" {
  security_group_id = aws_security_group.ec2.id
  cidr_ipv4         = var.allow_cidr_to_ssh_22
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "allow_5432" {
  security_group_id             = aws_security_group.db.id
  referenced_security_group_id  = aws_security_group.ec2.id
  from_port                     = 5432
  to_port                       = 5432
  ip_protocol                   = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "db_all" {
  security_group_id             = aws_security_group.db.id
  referenced_security_group_id  = aws_security_group.ec2.id
  ip_protocol                   = "all"
}

resource "aws_vpc_security_group_ingress_rule" "allow_11000" {
  security_group_id = aws_security_group.ds.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 11000
  to_port           = 11000
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "ds_allow_22" {
  security_group_id = aws_security_group.ds.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "ds_all" {
  security_group_id = aws_security_group.ds.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "all"
}

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "${var.prefix_name}-ds3m-subnet-group"
  subnet_ids = aws_subnet.subnet_db[*].id

  tags = {
    Name = "${var.prefix_name}-ds3m-subnet-group"
  }
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
}

locals {
  userData = <<EOT
#!/bin/bash
TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
INSTID=`curl -s http://169.254.169.254/latest/meta-data/instance-id -H "X-aws-ec2-metadata-token: $TOKEN"`
REGION=`curl -s http://169.254.169.254/latest/meta-data/placement/region -H "X-aws-ec2-metadata-token: $TOKEN"`

wget -O /home/ec2-user/dsssm/certs/rds.crt "${var.url_rds_certificate}"

echo "{
   \"UrlToBuild\": \"\",
   \"AccountIDs\": [${length(var.allow_access_for_aws_account_ids) == 0 ? format("\\\"%s\\\"", data.aws_caller_identity.current.account_id) : join(",", formatlist("\\\"%s\\\"", var.allow_access_for_aws_account_ids))}],
   \"TenantIDs\": [${join(",", formatlist("\\\"%s\\\"", var.allow_access_for_azure_account_ids))}],
   \"TerraformCache\": {
     \"BucketName\": \"${var.s3_bucket_name}\",
     \"Region\": \"${var.s3_bucket_region}\"
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
 Description=/etc/rc.local Compatibility
 ConditionPathExists=/etc/rc.local

[Service]
 Type=forking
 ExecStart=/etc/rc.local start
 TimeoutSec=0
 StandardOutput=tty
 RemainAfterExit=yes
 SysVStartPriority=99

[Install]
 WantedBy=multi-user.target
' > /etc/systemd/system/rc-local.service

echo '#!/bin/bash
cd /home/ec2-user/dsssm && npm run start-http-server >> /home/ec2-user/dsssm/logs/dsssm.txt
exit 0
' > /etc/rc.local

sudo chmod +x /etc/rc.local

sudo systemctl enable rc-local

sudo systemctl start rc-local.service

sudo systemctl status rc-local.service

EOT
}

resource "aws_instance" "ds3m" {
  ami                               = data.aws_ami.latest.id
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

  depends_on = [aws_db_instance.postgres]
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

resource "null_resource" "deletion" {
  triggers = {
    name          = "${var.prefix_name}-Ds3mInstance"
    region        = var.region
    prefix        = local.is_linux ? "./" : ""
  }
  provisioner "local-exec" {
    when        = destroy
    on_failure  = fail
    command     = "${self.triggers.prefix}exec_aws_command_to_ec2.sh ${self.triggers.name} ${self.triggers.region}"
  }
  depends_on = [
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
    aws_vpc_security_group_ingress_rule.allow_22,
    aws_vpc_security_group_ingress_rule.allow_5432,
    aws_vpc_security_group_ingress_rule.allow_8000,
    aws_vpc_security_group_ingress_rule.allow_11000,
    aws_vpc_security_group_ingress_rule.ds_allow_22,
    aws_vpc_security_group_egress_rule.db_all,
    aws_vpc_security_group_egress_rule.ds_all,
    aws_vpc_security_group_egress_rule.ec2_all,
    aws_db_subnet_group.db_subnet_group,
    aws_db_instance.postgres,
    aws_instance.ds3m,
    aws_iam_role.iam_role,
    aws_iam_instance_profile.iam_role_profile
  ]
}

output "web_console" {
  value = "https://${aws_instance.ds3m.public_ip}:8080"
}

output "ami" {
  value = "${data.aws_ami.latest.name} (${data.aws_ami.latest.id})"
}
