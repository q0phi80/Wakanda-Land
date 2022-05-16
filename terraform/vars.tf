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
  default = "admin@first.local"
}
variable "WinRM_PASSWORD" {
  default = "Password@1"
}
variable "VPC_CIDR" {
  default = "10.0.0.0/16"
}

variable "FIRST_SUBNET_CIDR" {
  default = "10.0.1.0/24"
}

variable "SECOND_SUBNET_CIDR" {
  default = "10.0.2.0/24"
}

variable "FIRST_DC_IP" {
  default = "10.0.1.100"
}

variable "USER_SERVER_IP" {
  default = "10.0.1.50"
}

variable "WEB_SERVER_1_IP" {
  default = "10.0.1.51"
}

variable "WEB_SERVER_2_IP" {
  default = "10.0.1.52"
}

variable "USER_WORKSTATION_IP" {
  default = "10.0.1.53"
}

variable "GUAC_SERVER_IP" {
  default = "10.0.1.10"
}

variable "ATTACKER_KALI_IP" {
  default = "10.0.1.11"
}

variable "SECOND_DC_IP" {
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