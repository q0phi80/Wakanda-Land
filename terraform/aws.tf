# Basic AWS configuration which will grab our keys from the AWS CLI
# If you are not using the keys in the default profile of aws cli, then change below to the profile name 
provider "aws" {
  profile = "default"
  region  = "us-east-1"
}

# AWS keypair
resource "aws_key_pair" "terraformkey" {
  key_name   = "${terraform.workspace}-wakanda-land"
  public_key = file(var.PATH_TO_PUBLIC_KEY)
}

# VPC definition, using a default IP range of 10.0.0.0/16
resource "aws_vpc" "land-vpc" {
  cidr_block           = var.VPC_CIDR
  enable_dns_support   = true
  enable_dns_hostnames = true
}

# Default route required for the VPC to push traffic via gateway
resource "aws_route" "bast-internet-route" {
  route_table_id         = aws_vpc.land-vpc.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.land-vpc-gateway.id
}

# Gateway which allows outbound and inbound internet access to the VPC
resource "aws_internet_gateway" "land-vpc-gateway" {
  vpc_id = aws_vpc.land-vpc.id
}

# Create our first subnet (Defaults to 10.0.1.0/24)
resource "aws_subnet" "bast-vpc-subnet" {
  vpc_id = aws_vpc.land-vpc.id

  cidr_block        = var.BAST_SUBNET_CIDR
  availability_zone = "us-east-1a"

  tags = {
    Name = "Bast Subnet"
  }
}

# Create our second subnet (Defaults to 10.0.2.0/24)
resource "aws_subnet" "wakanda-vpc-subnet" {
  vpc_id = aws_vpc.land-vpc.id

  cidr_block        = var.WAKANDA_SUBNET_CIDR
  availability_zone = "us-east-1a"

  tags = {
    Name = "Wakanda Subnet"
  }
}

# Set DHCP options for delivering things such as DNS servers
resource "aws_vpc_dhcp_options" "bast-dhcp" {
  domain_name          = "bast.land"
  domain_name_servers  = [var.BAKU_DC_IP, var.PUBLIC_DNS]
  ntp_servers          = [var.BAKU_DC_IP]
  netbios_name_servers = [var.BAKU_DC_IP]
  netbios_node_type    = 2

  tags = {
    Name = "Bast DHCP"
  }
}

# Associate our DHCP configuration with our VPC
resource "aws_vpc_dhcp_options_association" "bast-dhcp-assoc" {
  vpc_id          = aws_vpc.land-vpc.id
  dhcp_options_id = aws_vpc_dhcp_options.bast-dhcp.id
}

# Domain Controller of the "bast.land" domain
resource "aws_instance" "baku-dc" {
  ami                         = data.aws_ami.latest-windows-server.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.bast-vpc-subnet.id
  private_ip                  = var.BAKU_DC_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-baku-dc"
  }

  vpc_security_group_ids = [
    aws_security_group.bast-sg.id,
  ]
}

# Windows Server in the bast domain
resource "aws_instance" "nakia" {
  ami                         = data.aws_ami.latest-windows-server.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.bast-vpc-subnet.id
  private_ip                  = var.NAKIA_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-nakia"
  }

  vpc_security_group_ids = [
    aws_security_group.bast-sg.id,
  ]
}

# A Windows 10 Pro development host providing RDP access for crafting and testing payloads
resource "aws_instance" "ramonda" {
  ami                         = data.aws_ami.windows-client.image_id
  instance_type               = "t2.medium"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.bast-vpc-subnet.id
  private_ip                  = var.RAMONDA_IP
  depends_on                  = [aws_instance.baku-dc]
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-ramonda"
  }

  vpc_security_group_ids = [
    aws_security_group.bast-sg.id,
  ]

  # Connect to the Win 10 with the Local Admin account and then activate the default Administrator account
  provisioner "remote-exec" {
    inline = [
      "net user Administrator /active:yes",
      "net user Administrator ${var.WinRM_PASSWORD}"
    ]

    connection {
      type     = "winrm"
      user     = "admin"
      password = var.WinRM_PASSWORD
      host     = aws_instance.ramonda.public_ip
      port     = 5985
      insecure = true
      https    = false
      timeout  = "10m"
    }
  }

  # Push some PowerShell scripts from our local box unto the remote Win 10 box
  provisioner "file" {
    source      = "./scripts/rt-toolz.ps1"
    destination = "C:/Windows/Temp/rt-toolz.ps1"

    connection {
      type     = "winrm"
      user     = "Administrator"
      password = var.WinRM_PASSWORD
      host     = aws_instance.ramonda.public_ip
      port     = 5985
      insecure = true
      https    = false
      timeout  = "7m"
    }
  }

  provisioner "file" {
    source      = "./scripts/join-domain.ps1"
    destination = "C:/Windows/Temp/join-domain.ps1"

    connection {
      type     = "winrm"
      user     = "Administrator"
      password = var.WinRM_PASSWORD
      host     = aws_instance.ramonda.public_ip
      port     = 5985
      insecure = true
      https    = false
      timeout  = "7m"
    }
  }

  # Run the PowerShell scripts on the Remote Win 10 box to install tools
  provisioner "remote-exec" {
    inline = [
      "powershell -ExecutionPolicy Bypass -File C:/Windows/Temp/rt-toolz.ps1"
    ]

    connection {
      type     = "winrm"
      user     = "Administrator"
      password = var.WinRM_PASSWORD
      host     = aws_instance.ramonda.public_ip
      port     = 5985
      insecure = true
      https    = false
      timeout  = "7m"
    }
  }

# Join the Windows 10 box to the domain bast
  provisioner "remote-exec" {
    inline = [
      "powershell -ExecutionPolicy Bypass -File C:/Windows/Temp/join-domain.ps1"
    ]

    connection {
      type     = "winrm"
      user     = "Administrator"
      password = var.WinRM_PASSWORD
      host     = aws_instance.ramonda.public_ip
      port     = 5985
      insecure = true
      https    = false
      timeout  = "7m"
    }
  }

  # Once the Win 10 box is joined to the domain, it will need to be restarted. Using this as a backup to make sure the box actually do reboot
  provisioner "remote-exec" {
    inline = [
      "powershell -ExecutionPolicy Bypass Restart-Computer -Force"
    ]
    on_failure = continue

    connection {
      type     = "winrm"
      user     = "Administrator"
      password = var.WinRM_PASSWORD
      host     = aws_instance.ramonda.public_ip
      port     = 5985
      insecure = true
      https    = false
      timeout  = "7m"
    }
  }
}

# 1st Web Server in the bast domain
resource "aws_instance" "okoye" {
  ami                         = data.aws_ami.latest-debian.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.bast-vpc-subnet.id
  private_ip                  = var.OKOYE_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-okoye"
  }

  vpc_security_group_ids = [
    aws_security_group.bast-sg.id,
  ]
}

resource "null_resource" "okoye-setup" {
  connection {
    type        = "ssh"
    host        = aws_instance.okoye.public_ip
    user        = var.SSH_USER
    port        = "22"
    private_key = file(var.PATH_TO_PRIVATE_KEY)
    agent       = false
  }
  provisioner "file" {
    source      = "./scripts/juice-shop-setup.sh"
    destination = "/tmp/juice-shop-setup.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "sleep 10",
      "sudo chmod +x /tmp/juice-shop-setup.sh",
      "sudo /tmp/juice-shop-setup.sh",
    ]
  }
}

# A 2nd Web Server in the bast domain
resource "aws_instance" "soninke" {
  ami                         = data.aws_ami.latest-debian.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.bast-vpc-subnet.id
  private_ip                  = var.SONINKE_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-soninke"
  }

  vpc_security_group_ids = [
    aws_security_group.bast-sg.id,
  ]
  root_block_device {
    delete_on_termination = true
    volume_size           = 100
  }
}

resource "null_resource" "soninke-setup" {
  connection {
    type        = "ssh"
    host        = aws_instance.soninke.public_ip
    user        = var.SSH_USER
    port        = "22"
    private_key = file(var.PATH_TO_PRIVATE_KEY)
    agent       = false
  }

  provisioner "file" {
    source      = "./scripts/vuln-install.sh"
    destination = "/tmp/vuln-install.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "sleep 10",
      "sudo chmod +x /tmp/vuln-install.sh",
      "sudo /tmp/vuln-install.sh start",
    ]
  }
}

# Domain Controller of the "wakanda.land" domain
resource "aws_instance" "challa-dc" {
  ami                         = data.aws_ami.latest-windows-server.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.wakanda-vpc-subnet.id
  private_ip                  = var.CHALLA_DC_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-challa-dc"
  }

  vpc_security_group_ids = [
    aws_security_group.wakanda-sg.id,
  ]
}

# Guacamole Server providing a dashboard access to Kali and Windows boxes for attacks and developments
resource "aws_instance" "guac-server" {
  ami                         = data.aws_ami.latest-debian.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.bast-vpc-subnet.id
  private_ip                  = var.GUAC_SERVER_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-Guac-Server"
  }

  vpc_security_group_ids = [
    aws_security_group.bast-sg.id,
  ]
}

resource "null_resource" "guac-server-setup" {
  connection {
    type        = "ssh"
    host        = aws_instance.guac-server.public_ip
    user        = var.SSH_USER
    port        = "22"
    private_key = file(var.PATH_TO_PRIVATE_KEY)
    agent       = false
  }

  provisioner "file" {
    source      = "./scripts/guac-setup.sh"
    destination = "/tmp/guac-setup.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "sleep 10",
      "sudo chmod +x /tmp/guac-setup.sh",
      "sudo /tmp/guac-setup.sh",
    ]
  }
}

resource "null_resource" "guacozy-server-setup" {
  depends_on = [
    null_resource.guac-server-setup
  ]
  connection {
    type        = "ssh"
    host        = aws_instance.guac-server.public_ip
    user        = var.SSH_USER
    port        = "22"
    private_key = file(var.PATH_TO_PRIVATE_KEY)
    agent       = false
  }
  
  provisioner "file" {
    source      = "./files/playbook.yml"
    destination = "/tmp/playbook.yml"
  }

  provisioner "file" {
    source      = "./files/docker-compose.yml"
    destination = "/tmp/docker-compose.yml"
  }

  provisioner "remote-exec" {
    inline = [
      "sleep 10",
      "cd /tmp/",
      "ansible-playbook playbook.yml",
/*       "sudo chmod +x /tmp/guacozy.sh",
      "sudo /tmp/guacozy.sh" */
    ]
    on_failure = continue
  }
}

# Kali Linux Installation and setup
resource "aws_instance" "ulysses" {
  #count						  = "1" ? 1 : 0
  ami                         = data.aws_ami.latest-kali-linux.image_id
  instance_type               = "t3.medium"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.bast-vpc-subnet.id
  private_ip                  = var.ULYSSES_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-ulysses"
  }

  vpc_security_group_ids = [
    aws_security_group.bast-sg.id,
  ]
  root_block_device {
    delete_on_termination = true
    volume_size           = 100
  }
}

resource "null_resource" "ulysses-setup" {
  connection {
    type        = "ssh"
    host        = aws_instance.ulysses.public_ip
    user        = "kali"
    port        = "22"
    private_key = file(var.PATH_TO_PRIVATE_KEY)
    agent       = false
  }

  provisioner "file" {
    source      = "./scripts/kali-setup.sh"
    destination = "/tmp/kali-setup.sh"
  }
  provisioner "remote-exec" {
    inline = [
      "sleep 10",
      "sudo chmod +x /tmp/kali-setup.sh",
      "sudo /tmp/kali-setup.sh",
    ]
  }
}

# IAM Role required to access SSM from EC2
resource "aws_iam_role" "ssm_role" {
  name               = "${terraform.workspace}_ssm_role_default"
  count              = 1
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ssm_role_policy" {
  role       = aws_iam_role.ssm_role.0.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "${terraform.workspace}_ssm_instance_profile"
  role = aws_iam_role.ssm_role.0.name
}

# Security group for bast.land
resource "aws_security_group" "bast-sg" {
  vpc_id = aws_vpc.land-vpc.id

  # WinRM access from anywhere
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow wakanda zone to bast
  ingress {
    protocol    = "-1"
    cidr_blocks = [var.WAKANDA_SUBNET_CIDR]
    from_port   = 0
    to_port     = 0
  }

  ingress {
    protocol    = "-1"
    cidr_blocks = [var.BAST_SUBNET_CIDR]
    from_port   = 0
    to_port     = 0
  }

  # Allow management from our IP
  ingress {
    protocol    = "-1"
    cidr_blocks = var.MANAGEMENT_IPS
    from_port   = 0
    to_port     = 0
  }

  # Allow global outbound
  egress {
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
  }
}

# Security group for wakanda.land
resource "aws_security_group" "wakanda-sg" {
  vpc_id = aws_vpc.land-vpc.id

  # Allow bast zone to wakanda
  ingress {
    protocol    = "-1"
    cidr_blocks = [var.BAST_SUBNET_CIDR]
    from_port   = 0
    to_port     = 0
  }

  ingress {
    protocol    = "-1"
    cidr_blocks = [var.WAKANDA_SUBNET_CIDR]
    from_port   = 0
    to_port     = 0
  }

  # Allow management from Our IP
  ingress {
    protocol    = "-1"
    cidr_blocks = var.MANAGEMENT_IPS
    from_port   = 0
    to_port     = 0
  }

  # Allow global outbound
  egress {
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
  }
}

# Add bast.land MOF's to S3
resource "aws_s3_object" "baku-dc-mof" {
  bucket = var.SSM_S3_BUCKET
  key    = "Jungle/Bast.mof"
  source = "../dsc/Jungle/Bast.mof"
  etag   = filemd5("../dsc/Jungle/Bast.mof")
}

# Add wakanda.land MOF's to S3
resource "aws_s3_object" "challa-dc-mof" {
  bucket = var.SSM_S3_BUCKET
  key    = "Jungle/Wakanda.mof"
  source = "../dsc/Jungle/Wakanda.mof"
  etag   = filemd5("../dsc/Jungle/Wakanda.mof")
}

# Add nakia MOF's to S3
resource "aws_s3_object" "nakia-mof" {
  bucket = var.SSM_S3_BUCKET
  key    = "Jungle/Nakia.mof"
  source = "../dsc/Jungle/Nakia.mof"
  etag   = filemd5("../dsc/Jungle/Nakia.mof")
}

# Add ramonda MOF's to S3
resource "aws_s3_object" "ramonda-mof" {
  bucket = var.SSM_S3_BUCKET
  key    = "Jungle/Ramonda.mof"
  source = "../dsc/Jungle/Ramonda.mof"
  etag   = filemd5("../dsc/Jungle/Ramonda.mof")
}
# SSM parameters used by DSC
resource "aws_ssm_parameter" "tsankara-ssm-parameter" {
  name  = "tsankara"
  type  = "SecureString"
  value = "{\"Username\":\"tsankara\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "land-user-ssm-parameter" {
  name  = "land-user"
  type  = "SecureString"
  value = "{\"Username\":\"land-user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "bast-tsankara-ssm-parameter" {
  name  = "bast-tsankara"
  type  = "SecureString"
  value = "{\"Username\":\"bast.land\\\\tsankara\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "wakandan-ssm-parameter" {
  name  = "Wakandan"
  type  = "SecureString"
  value = "{\"Username\":\"Wakandan\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "thoth-ssm-parameter" {
  name  = "Thoth"
  type  = "SecureString"
  value = "{\"Username\":\"Thoth\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "kokou-ssm-parameter" {
  name  = "Kokou"
  type  = "SecureString"
  value = "{\"Username\":\"Kokou\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "mujaji-ssm-parameter" {
  name  = "Mujaji"
  type  = "SecureString"
  value = "{\"Username\":\"Mujaji\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "sobek-ssm-parameter" {
  name  = "Sobek"
  type  = "SecureString"
  value = "{\"Username\":\"Sobek\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "ghekre-ssm-parameter" {
  name  = "Ghekre"
  type  = "SecureString"
  value = "{\"Username\":\"Ghekre\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "ngi-ssm-parameter" {
  name  = "Ngi"
  type  = "SecureString"
  value = "{\"Username\":\"Ngi\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "hadari-yao-ssm-parameter" {
  name  = "Hadari-Yao"
  type  = "SecureString"
  value = "{\"Username\":\"Hadari-Yao\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "yaounde-ssm-parameter" {
  name  = "Yaounde"
  type  = "SecureString"
  value = "{\"Username\":\"Yaounde\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "baoule-ssm-parameter" {
  name  = "Baoule"
  type  = "SecureString"
  value = "{\"Username\":\"Baoule\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "hanuman-ssm-parameter" {
  name  = "Hanuman"
  type  = "SecureString"
  value = "{\"Username\":\"Hanuman\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "akamba-ssm-parameter" {
  name  = "Akamba"
  type  = "SecureString"
  value = "{\"Username\":\"Akamba\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "mmusa-ssm-parameter" {
  name  = "Mmusa"
  type  = "SecureString"
  value = "{\"Username\":\"Mmusa\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "jabari-ssm-parameter" {
  name  = "Jabari"
  type  = "SecureString"
  value = "{\"Username\":\"Jabari\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "plumumba-ssm-parameter" {
  name  = "Plumumba"
  type  = "SecureString"
  value = "{\"Username\":\"Plumumba\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "knkrumah-ssm-parameter" {
  name  = "Knkrumah"
  type  = "SecureString"
  value = "{\"Username\":\"Knkrumah\", \"Password\":\"Password@1\"}"
}

# Apply DSC via SSM to bast.land
resource "aws_ssm_association" "baku-dc" {
  name             = "AWS-ApplyDSCMofs"
  association_name = "${terraform.workspace}-baku-dc"

  targets {
    key    = "InstanceIds"
    values = [aws_instance.baku-dc.id]
  }

  parameters = {
    MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Jungle/Bast.mof"
    RebootBehavior = "Immediately"
  }

}

# Apply DSC via SSM to wakanda.land
resource "aws_ssm_association" "challa-dc" {
  name             = "AWS-ApplyDSCMofs"
  association_name = "${terraform.workspace}-challa-dc"

  targets {
    key    = "InstanceIds"
    values = [aws_instance.challa-dc.id]
  }

  parameters = {
    MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Jungle/Wakanda.mof"
    RebootBehavior = "Immediately"
  }

}

# Apply DSC via SSM to nakia
resource "aws_ssm_association" "nakia" {
  name             = "AWS-ApplyDSCMofs"
  association_name = "${terraform.workspace}-nakia"

  targets {
    key    = "InstanceIds"
    values = [aws_instance.nakia.id]
  }

  parameters = {
    MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Jungle/Nakia.mof"
    RebootBehavior = "Immediately"
  }

}

# Apply DSC via SSM to ramonda
resource "aws_ssm_association" "ramonda" {
  name             = "AWS-ApplyDSCMofs"
  association_name = "${terraform.workspace}-ramonda"

  targets {
    key    = "InstanceIds"
    values = [aws_instance.ramonda.id]
  }

  parameters = {
    MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Jungle/Ramonda.mof"
    RebootBehavior = "Immediately"
  }

}
