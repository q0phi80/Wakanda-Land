# Basic AWS configuration which will grab our keys from the AWS CLI
# If you are not using the keys in the default profile of aws cli, then change below to the profile name 
provider "aws" {
  profile = "default"
  region  = "us-east-1"
}

# Our AWS keypair
resource "aws_key_pair" "terraformkey" {
  key_name   = "${terraform.workspace}-terraform-lab"
  public_key = file(var.PATH_TO_PUBLIC_KEY)
}

# Our VPC definition, using a default IP range of 10.0.0.0/16
resource "aws_vpc" "lab-vpc" {
  cidr_block           = var.VPC_CIDR
  enable_dns_support   = true
  enable_dns_hostnames = true
}

# Default route required for the VPC to push traffic via gateway
resource "aws_route" "first-internet-route" {
  route_table_id         = aws_vpc.lab-vpc.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.lab-vpc-gateway.id
}

# Gateway which allows outbound and inbound internet access to the VPC
resource "aws_internet_gateway" "lab-vpc-gateway" {
  vpc_id = aws_vpc.lab-vpc.id
}

# Create our first subnet (Defaults to 10.0.1.0/24)
resource "aws_subnet" "first-vpc-subnet" {
  vpc_id = aws_vpc.lab-vpc.id

  cidr_block        = var.FIRST_SUBNET_CIDR
  availability_zone = "us-east-1a"

  tags = {
    Name = "First Subnet"
  }
}

# Create our second subnet (Defaults to 10.0.2.0/24)
resource "aws_subnet" "second-vpc-subnet" {
  vpc_id = aws_vpc.lab-vpc.id

  cidr_block        = var.SECOND_SUBNET_CIDR
  availability_zone = "us-east-1a"

  tags = {
    Name = "Second Subnet"
  }
}

# Set DHCP options for delivering things like DNS servers
resource "aws_vpc_dhcp_options" "first-dhcp" {
  domain_name          = "first.local"
  domain_name_servers  = [var.FIRST_DC_IP, var.PUBLIC_DNS]
  ntp_servers          = [var.FIRST_DC_IP]
  netbios_name_servers = [var.FIRST_DC_IP]
  netbios_node_type    = 2

  tags = {
    Name = "First DHCP"
  }
}

# Associate our DHCP configuration with our VPC
resource "aws_vpc_dhcp_options_association" "first-dhcp-assoc" {
  vpc_id          = aws_vpc.lab-vpc.id
  dhcp_options_id = aws_vpc_dhcp_options.first-dhcp.id
}

# Our first domain controller of the "first.local" domain
resource "aws_instance" "first-dc" {
  ami                         = data.aws_ami.latest-windows-server.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.first-vpc-subnet.id
  private_ip                  = var.FIRST_DC_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-First-DC"
  }

  vpc_security_group_ids = [
    aws_security_group.first-sg.id,
  ]
}

# The User server which will be main foothold
resource "aws_instance" "user-server" {
  ami                         = data.aws_ami.latest-windows-server.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.first-vpc-subnet.id
  private_ip                  = var.USER_SERVER_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-User-Server"
  }

  vpc_security_group_ids = [
    aws_security_group.first-sg.id,
  ]
}
/* resource "time_sleep" "wait_30_mins" {
  depends_on      = [aws_instance.user-server]
  create_duration = "30m"
}
resource "null_resource" "user-server-setup" {
  depends_on = [time_sleep.wait_30_mins]

  connection {
    type     = "winrm"
    user     = var.WinRM_USER
    password = var.WinRM_PASSWORD
    host     = aws_instance.user-server.public_ip
    port     = 5985
    insecure = true
    https = true
    timeout  = "10m"
    use_ntlm = true
  }
  provisioner "remote-exec" {
    inline = [
      "mkdir toolz",
    ]
  }
  provisioner "local-exec" {
    command = "Get-Date > completed.txt"
    interpreter = ["PowerShell", "-Command"]
  }
} */

# The User Windows 10 workstation which will be main foothold
resource "aws_instance" "user-workstation" {
  ami                         = data.aws_ami.windows-10.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.first-vpc-subnet.id
  private_ip                  = var.USER_WORKSTATION_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-User-Workstation"
  }

  vpc_security_group_ids = [
    aws_security_group.first-sg.id,
  ]
}
/* resource "time_sleep" "wait_30_mins" {
  depends_on      = [aws_instance.user-server]
  create_duration = "30m"
}
resource "null_resource" "user-server-setup" {
  depends_on = [time_sleep.wait_30_mins]

  connection {
    type     = "winrm"
    user     = var.WinRM_USER
    password = var.WinRM_PASSWORD
    host     = aws_instance.user-server.public_ip
    port     = 5985
    insecure = true
    https = true
    timeout  = "10m"
    use_ntlm = true
  }
  provisioner "remote-exec" {
    inline = [
      "mkdir toolz",
    ]
  }
  provisioner "local-exec" {
    command = "Get-Date > completed.txt"
    interpreter = ["PowerShell", "-Command"]
  }
} */

# First Web Server
resource "aws_instance" "web-server-1" {
  ami                         = data.aws_ami.latest-debian.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.first-vpc-subnet.id
  private_ip                  = var.WEB_SERVER_1_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-Web-Server-1"
  }

  vpc_security_group_ids = [
    aws_security_group.first-sg.id,
  ]
}

resource "null_resource" "web-server-1-setup" {
  connection {
    type        = "ssh"
    host        = aws_instance.web-server-1.public_ip
    user        = var.SSH_USER
    port        = "22"
    private_key = file(var.PATH_TO_PRIVATE_KEY)
    agent       = false
  }
  /* provisioner "file" {
    source      = "vuln-install.sh"
    destination = "/tmp/vuln-install.sh"
  } */

  provisioner "remote-exec" {
    inline = [
      "export DEBIAN_FRONTEND=noninteractive",
      "sudo apt-get -qy -o \"Dpkg::Options::=--force-confdef\" -o \"Dpkg::Options::=--force-confold\" upgrade",
      "sudo apt-get remove docker docker-engine docker.io containerd runc",
      "curl -fsSL https://get.docker.com -o get-docker.sh",
      "sudo sh get-docker.sh",
      "sudo apt install git -y",
      "sudo curl -L https://github.com/docker/compose/releases/download/1.25.3/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose",
      "sudo chmod +x /usr/local/bin/docker-compose",
      "git clone https://github.com/vulhub/vulhub.git",
      "sudo docker pull bkimminich/juice-shop",
      "sudo docker run -d -p 3000:3000 bkimminich/juice-shop",
    ]
  }
}

# Second Web Server
resource "aws_instance" "web-server-2" {
  ami                         = data.aws_ami.latest-debian.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.first-vpc-subnet.id
  private_ip                  = var.WEB_SERVER_2_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-Web-Server-2"
  }

  vpc_security_group_ids = [
    aws_security_group.first-sg.id,
  ]
}

resource "null_resource" "web-server-2-setup" {
  connection {
    type        = "ssh"
    host        = aws_instance.web-server-2.public_ip
    user        = var.SSH_USER
    port        = "22"
    private_key = file(var.PATH_TO_PRIVATE_KEY)
    agent       = false
  }

  provisioner "remote-exec" {
    inline = [
      "export DEBIAN_FRONTEND=noninteractive",
      "sudo apt-get -qy -o \"Dpkg::Options::=--force-confdef\" -o \"Dpkg::Options::=--force-confold\" upgrade",
      "sudo apt-get remove docker docker-engine docker.io containerd runc",
      "curl -fsSL https://get.docker.com -o get-docker.sh",
      "sudo sh get-docker.sh",
      "sudo apt install git -y",
      "sudo curl -L https://github.com/docker/compose/releases/download/1.25.3/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose",
      "sudo chmod +x /usr/local/bin/docker-compose",
      "git clone https://github.com/vulhub/vulhub.git",
      "cd vulhub/tomcat/tomcat8/",
      "sudo docker-compose up -d",
    ]
  }
}

# Our second domain controller of the "second.local" domain
resource "aws_instance" "second-dc" {
  ami                         = data.aws_ami.latest-windows-server.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.second-vpc-subnet.id
  private_ip                  = var.SECOND_DC_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-Second-DC"
  }

  vpc_security_group_ids = [
    aws_security_group.second-sg.id,
  ]
}

# Guacamole Server
resource "aws_instance" "guac-server" {
  ami                         = data.aws_ami.latest-debian.image_id
  instance_type               = "t2.small"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.first-vpc-subnet.id
  private_ip                  = var.GUAC_SERVER_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-Guac-Server"
  }

  vpc_security_group_ids = [
    aws_security_group.first-sg.id,
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

  provisioner "remote-exec" {
    inline = [
      "export DEBIAN_FRONTEND=noninteractive",
      "sudo apt-get -qy -o \"Dpkg::Options::=--force-confdef\" -o \"Dpkg::Options::=--force-confold\" upgrade",
      "sudo apt-get remove docker docker-engine docker.io containerd runc",
      "curl -fsSL https://get.docker.com -o get-docker.sh",
      "sudo sh get-docker.sh",
      "sudo apt install git -y",
      "sudo curl -L https://github.com/docker/compose/releases/download/1.25.3/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose",
      "sudo chmod +x /usr/local/bin/docker-compose",
      "git clone https://github.com/q0phi80/guacamole.git",
      "cd guacamole",
      "sudo ./bin/prepare_initdb.sh",
      "sudo docker-compose up -d guacamole mysql guacd",
      "sudo docker-compose up -d",
    ]
  }
}

# Kali Linux Install
resource "aws_instance" "attacker-kali" {
  #count						  = "1" ? 1 : 0
  ami                         = data.aws_ami.latest-kali-linux.image_id
  instance_type               = "t3.medium"
  key_name                    = aws_key_pair.terraformkey.key_name
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.first-vpc-subnet.id
  private_ip                  = var.ATTACKER_KALI_IP
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Workspace = "${terraform.workspace}"
    Name      = "${terraform.workspace}-Attacker-Kali"
  }

  vpc_security_group_ids = [
    aws_security_group.first-sg.id,
  ]
  root_block_device {
    delete_on_termination = true
    volume_size           = 100
  }
}

resource "null_resource" "attacker-kali-setup" {
  connection {
    type        = "ssh"
    host        = aws_instance.attacker-kali.public_ip
    user        = "kali"
    port        = "22"
    private_key = file(var.PATH_TO_PRIVATE_KEY)
    agent       = false
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt update",
      "DEBIAN_FRONTEND=noninteractive sudo apt-get --yes --force-yes install kali-desktop-xfce xorg xrdp",
      "sudo sed -i 's/port=3389/port=3390/g' /etc/xrdp/xrdp.ini",
      "sudo systemctl enable xrdp --now",
      # Install dotnet
      "wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb",
      "sudo dpkg -i packages-microsoft-prod.deb",
      "sudo apt-get update",
      "sudo apt-get install -y apt-transport-https",
      "sudo apt-get update",
      "sudo apt-get install -y dotnet-sdk-3.1",
      "sudo apt-get install -y git",
      "sudo apt install -y python3-pip",
      # Change the password to the default ‘kali’ account
      "echo kali:kali | sudo chpasswd",
      "mkdir -p toolz",
      "cd toolz/",
      # Install Impacket
      "git clone https://github.com/SecureAuthCorp/impacket.git",
      "cd impacket",
      "sudo python3 -m pip install --upgrade pip",
      "sudo python3 -m pip install .",
      "cd ../",
      # Get Covenant C2 framework
      "git clone --recurse-submodules https://github.com/cobbr/Covenant",
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

# Security group for first.local
resource "aws_security_group" "first-sg" {
  vpc_id = aws_vpc.lab-vpc.id

  # WinRM access from anywhere
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow second zone to first
  ingress {
    protocol    = "-1"
    cidr_blocks = [var.SECOND_SUBNET_CIDR]
    from_port   = 0
    to_port     = 0
  }

  ingress {
    protocol    = "-1"
    cidr_blocks = [var.FIRST_SUBNET_CIDR]
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

# Security group for second.local
resource "aws_security_group" "second-sg" {
  vpc_id = aws_vpc.lab-vpc.id

  # Allow secure zone to first
  ingress {
    protocol    = "-1"
    cidr_blocks = [var.FIRST_SUBNET_CIDR]
    from_port   = 0
    to_port     = 0
  }

  ingress {
    protocol    = "-1"
    cidr_blocks = [var.SECOND_SUBNET_CIDR]
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

# Add first.local MOF's to S3
resource "aws_s3_object" "first-dc-mof" {
  bucket = var.SSM_S3_BUCKET
  key    = "Lab/First.mof"
  source = "../dsc/Lab/First.mof"
  etag   = filemd5("../dsc/Lab/First.mof")
}

# Add second.local MOF's to S3
resource "aws_s3_object" "second-dc-mof" {
  bucket = var.SSM_S3_BUCKET
  key    = "Lab/Second.mof"
  source = "../dsc/Lab/Second.mof"
  etag   = filemd5("../dsc/Lab/Second.mof")
}

# Add userserver MOF's to S3
resource "aws_s3_object" "user-server-mof" {
  bucket = var.SSM_S3_BUCKET
  key    = "Lab/UserServer.mof"
  source = "../dsc/Lab/UserServer.mof"
  etag   = filemd5("../dsc/Lab/UserServer.mof")
}

# Add userworkstation MOF's to S3
resource "aws_s3_object" "user-workstation-mof" {
  bucket = var.SSM_S3_BUCKET
  key    = "Lab/UserWorkstation.mof"
  source = "../dsc/Lab/UserWorkstation.mof"
  etag   = filemd5("../dsc/Lab/UserWorkstation.mof")
}
# SSM parameters used by DSC
resource "aws_ssm_parameter" "admin-ssm-parameter" {
  name  = "admin"
  type  = "SecureString"
  value = "{\"Username\":\"admin\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "local-user-ssm-parameter" {
  name  = "local-user"
  type  = "SecureString"
  value = "{\"Username\":\"local-user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "first-admin-ssm-parameter" {
  name  = "first-admin"
  type  = "SecureString"
  value = "{\"Username\":\"first.local\\\\admin\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "regular-user-ssm-parameter" {
  name  = "regular.user"
  type  = "SecureString"
  value = "{\"Username\":\"regular.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "dnsadmin-user-ssm-parameter" {
  name  = "dnsadmin.user"
  type  = "SecureString"
  value = "{\"Username\":\"dnsadmin.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "unconstrainer-user-ssm-parameter" {
  name  = "unconstrained.user"
  type  = "SecureString"
  value = "{\"Username\":\"unconstrained.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "constrained-user-ssm-parameter" {
  name  = "constrained.user"
  type  = "SecureString"
  value = "{\"Username\":\"constrained.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "userwrite-user-ssm-parameter" {
  name  = "userwrite.user"
  type  = "SecureString"
  value = "{\"Username\":\"userwrite.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "userall-user-ssm-parameter" {
  name  = "userall.user"
  type  = "SecureString"
  value = "{\"Username\":\"userall.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "compwrite-user-ssm-parameter" {
  name  = "compwrite.user"
  type  = "SecureString"
  value = "{\"Username\":\"compwrite.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "gpowrite-user-ssm-parameter" {
  name  = "gpowrite.user"
  type  = "SecureString"
  value = "{\"Username\":\"gpowrite.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "lapsread-user-ssm-parameter" {
  name  = "lapsread.user"
  type  = "SecureString"
  value = "{\"Username\":\"lapsread.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "groupwrite-user-ssm-parameter" {
  name  = "groupwrite.user"
  type  = "SecureString"
  value = "{\"Username\":\"groupwrite.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "writedacldc-user-ssm-parameter" {
  name  = "writedacldc.user"
  type  = "SecureString"
  value = "{\"Username\":\"writedacldc.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "readgmsa-user-ssm-parameter" {
  name  = "readgmsa.user"
  type  = "SecureString"
  value = "{\"Username\":\"readgmsa.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "clearpass-user-ssm-parameter" {
  name  = "clearpass.user"
  type  = "SecureString"
  value = "{\"Username\":\"clearpass.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "dcsync-user-ssm-parameter" {
  name  = "dcsync.user"
  type  = "SecureString"
  value = "{\"Username\":\"dcsync.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "roast-user-ssm-parameter" {
  name  = "roast.user"
  type  = "SecureString"
  value = "{\"Username\":\"roast.user\", \"Password\":\"Password@1\"}"
}

resource "aws_ssm_parameter" "asrep-user-ssm-parameter" {
  name  = "asrep.user"
  type  = "SecureString"
  value = "{\"Username\":\"asrep.user\", \"Password\":\"Password@1\"}"
}

/* output "first-dc_ip" {
  value       = aws_instance.first-dc.public_ip
  description = "Public IP of First-DC"
} */

/* output "user-server_ip" {
  value       = aws_instance.user-server.public_ip
  description = "Public IP of User Server"
} */

/* output "user-workstation_ip" {
  value       = aws_instance.user-workstation.public_ip
  description = "Public IP of User Workstation"
} */

/* output "web-server-1_ip" {
  value       = aws_instance.web-server-1.public_ip
  description = "Public IP of Web Server 1"
} */

/* output "web-server-2_ip" {
  value       = aws_instance.web-server-2.public_ip
  description = "Public IP of Web Server 2"
}
 */
output "guac-server_ip" {
  value       = aws_instance.guac-server.public_ip
  description = "Public IP of Guacamole Server. Access this at <ip-address:8080/guacamole>"
}

/* output "attacker-kali_ip" {
  value       = aws_instance.attacker-kali.public_ip
  description = "Public IP of Kali Linux"
} */

/* output "second-dc_ip" {
  value       = aws_instance.second-dc.public_ip
  description = "Public IP of Second-DC"
} */

output "timestamp" {
  value = formatdate("hh:mm", timestamp())
}

# Apply our DSC via SSM to first.local
resource "aws_ssm_association" "first-dc" {
  name             = "AWS-ApplyDSCMofs"
  association_name = "${terraform.workspace}-First-DC"

  targets {
    key    = "InstanceIds"
    values = [aws_instance.first-dc.id]
  }

  parameters = {
    MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Lab/First.mof"
    RebootBehavior = "Immediately"
  }

}

# Apply our DSC via SSM to second.local
resource "aws_ssm_association" "second-dc" {
  name             = "AWS-ApplyDSCMofs"
  association_name = "${terraform.workspace}-Second-DC"

  targets {
    key    = "InstanceIds"
    values = [aws_instance.second-dc.id]
  }

  parameters = {
    MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Lab/Second.mof"
    RebootBehavior = "Immediately"
  }

}

# Apply our DSC via SSM to User-Server
resource "aws_ssm_association" "user-server" {
  name             = "AWS-ApplyDSCMofs"
  association_name = "${terraform.workspace}-User-Server"

  targets {
    key    = "InstanceIds"
    values = [aws_instance.user-server.id]
  }

  parameters = {
    MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Lab/UserServer.mof"
    RebootBehavior = "Immediately"
  }

}

# Apply our DSC via SSM to User-Workstation
resource "aws_ssm_association" "user-workstation" {
  name             = "AWS-ApplyDSCMofs"
  association_name = "${terraform.workspace}-User-Workstation"

  targets {
    key    = "InstanceIds"
    values = [aws_instance.user-workstation.id]
  }

  parameters = {
    MofsToApply    = "s3:${var.SSM_S3_BUCKET}:Lab/UserWorkstation.mof"
    RebootBehavior = "Immediately"
  }

}
