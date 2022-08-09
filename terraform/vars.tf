variable "PATH_TO_PUBLIC_KEY" {
  # Add the path to the public key you made in AWS like below
  #default = "YOUR_PUBLIC_KEY"
  default = "./keys/terraformkey.pub"
}

variable "PATH_TO_PRIVATE_KEY" {
  # Add the path to the private key you made in AWS like below
  #default = "YOUR_PRIVATE_KEY"
  default = "./keys/terraformkey.pem"
}

variable "SSH_USER" {
  default = "admin"
}

variable "WinRM_USER" {
  default = "admin@bast.land"
}

variable "Domain_Admin" {
  default = "tsankara@bast.land"
}

variable "WinRM_PASSWORD" {
  default = "Password@1"
}

variable "VPC_CIDR" {
  default = "10.0.0.0/16"
}

variable "BAST_SUBNET_CIDR" {
  default = "10.0.1.0/24"
}

variable "WAKANDA_SUBNET_CIDR" {
  default = "10.0.2.0/24"
}

variable "BAKU_DC_IP" {
  default = "10.0.1.100"
}

variable "NAKIA_IP" {
  default = "10.0.1.50"
}

variable "OKOYE_IP" {
  default = "10.0.1.51"
}

variable "SONINKE_IP" {
  default = "10.0.1.52"
}

variable "RAMONDA_IP" {
  default = "10.0.1.53"
}

variable "GUAC_SERVER_IP" {
  default = "10.0.1.10"
}

variable "ULYSSES_IP" {
  default = "10.0.1.11"
}

variable "CHALLA_DC_IP" {
  default = "10.0.2.100"
}

variable "PUBLIC_DNS" {
  default = "1.1.1.1"
}

variable "MANAGEMENT_IPS" {
  # Add in the public IP Address you will be hitting the cloud from, for example the public IP of your home address or VPN
  #default = ["1.2.3.4/32"]
  default = ["0.0.0.0/0"]
}

variable "SSM_S3_BUCKET" {
  # Add in the name of your S3 bucket like the example below
  #default = "this-is-just-a-fake-bucket"
  default = "fluffy-wabbit-bucket"
}

# Find latest Windows Server
data "aws_ami" "latest-windows-server" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base-*"]
  }
}

# Find latest Windows 10
data "aws_ami" "windows-10" {
  most_recent = true
  owners      = ["679593333241"]

  filter {
    name   = "name"
    values = ["TechnologyLeadershipWinPro10-Intel-4205fe6b-14fe-4864-ae41-61a0049385c0"]
  }
}

# Find Latest Debian
data "aws_ami" "latest-debian" {
  most_recent = true
  owners      = ["136693071363"]

  filter {
    name   = "name"
    values = ["debian-10-amd64-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Find latest Ubuntu
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

# Find Latest Kali
data "aws_ami" "latest-kali-linux" {
  most_recent = true
  owners      = ["679593333241"] # owned by AWS marketplace

  filter {
    name   = "name"
    values = ["kali-linux-2022*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# My Customized Windows 10 Pro for Workstation AMI Image
# Borrowed from https://github.com/splunk/attack_range/wiki/Upload-Windows-10-AMI-to-AWS and
# https://www.rickgouin.com/run-a-windows-10-instance-in-aws-ec2/
data "aws_ami" "windows-client" {
  owners = ["104743148836"]
  #owners = ["self"]

  filter {
    name   = "name"
    values = ["import-ami-07b944fe8b0a37493"]
  }

  most_recent = true
}
