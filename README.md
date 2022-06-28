# Wakanda-Land
## Purpose
Wakanda Land is a Cyber Range deployment tool that uses ```terraform``` for automating the process of deploying an Adversarial Simulation lab infrastructure for practicing various offensive attacks. This project inherits from other people's work in the Cybersecurity Community and due credit has been provided in the Credit Section. I just added some additional sprinkles to their work from my other researches.

## Attack Techniques Covered
- Kerberoasting
- ASRepRoasting
- Constrained Delegation (computer and user)
- Unconstrained Delegation
- Resource Based Constrained Delegation
- Write ACL of user
- Write ACL of computer
- WriteDACL over domain
- Write ACL of group
- DnsAdmin members
- Write ACL of GPO
- Password in AD Attributes
- Cross Domain Trusts (for Trust Abuse)
- SMBSigning disabled on all machines for relay attacks
- Windows Defender uninstalled
- Others such as Pass-the-Hash, Pass-the-Ticket, Golden Tickets, Silver Tickets, etc.
- Web application exploitation techniques (covering OWASP Top 10)

## Architecture
The deployment of Wakanda Land environment consist of:
- Two Subnets
- Guacamole Server
  - *This provides dashboard access to Kali GUI and Windows RDP instances*
  - *The Kali GUI, Windows RDP and the user accounts used to log into these instances are already backed into the deployment process*
  - *To log into the Guacamole dashboard with the ```guacadmin``` account, you need to SSH into the Guacamole server using the public IP address (which is displayed after the deployment is complete) and then change into the ```guacamole``` directory and then type ```cat .env``` for the password (the ```guacadmin``` password is randomnly generated and saved as an environment variable)*
- Windows Domain Controller for the Child Domain
- Windows Domain Controller for the Parent Domain
- Windows Server in the Child Domain
- Windows 10 Pro in the Child Domain - had to create an AMI image for this one
- Kali Machine - a directory called ```toolz``` is created on this box and Covenant C2 is downloaded into that folder, so its just a matter of running Covenant once you are authenticated into Kali
- Debian Server serving as Web Server 1 - OWASP's Juice Shop running on this one
- Debian Server serving as Web Server 2 - Several vulnerable applications running on this one

## Installation and Setup
```
Terraform
Visit https://www.terraform.io/downloads and follow the installation process for your OS

AWS
Log into your AWS dashboard and create an EC2 Key Pair
Download a copy of the Private Key unto your development system
Create a Public Key from your Private (e.g. from a commandline, you can use a command like this: ```ssh-keygen -y -f /terraform-key.pem```)
Installation: Visit https://aws.amazon.com/cli/ and follow the installation process for your OS
Configuration: Visit https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html and follow the instruction on setting up your AWS CLI environment
e.g  aws configure
     AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
     AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
     Default region name [None]: us-west-2
     Default output format [None]: json

DSC
1. First, install the following from the PowerShell terminal (Assuming doing this on Windows box)
  - Install-module -name GroupPolicyDsc
  - Install-module -name activedirectorydsc
  - Install-module -name networkingdsc
  - Install-module -name ComputerManagementDsc
2. Update the PowerShell script (adlab.ps1) with the following:
  - Import-DscResource -ModuleName ActiveDirectoryDsc
  - Import-DscResource -ModuleName NetworkingDsc
  - Import-DscResource -ModuleName ComputerManagementDSC
  - Import-DscResource -ModuleName PSDesiredStateConfiguration
3. Run the script (```. .\adlab.ps1```) from within the ```dsc``` directory to create the MOF files, which will be dumped into the ```Lab``` folder 

S3
Create an S3 bucket for your account and modify the variable in terraform/vars.tf with your bucket name

Management IP 
Change the management IP variable in vars.tf to be your public IP address

SSH Keys
Store the SSH Public Key file within ./terraform/keys/terraform-key.pub 
Update the file in the vars.tf to point to that public key (which will assign it to the created EC2 instances)
Can use this key pair to get the administrator default password from AWS

Once you run the terraform, it will take some time to provision everything, so give it about 30 mins to an hour and you should be good to go.
```
## Running the lab
You can take the following steps in running the lab (must be ran from the terraform subfolder):

### Initialize terraform
```
terraform init
```
### Validate your script is properly setup
```
terraform validate
```
### Plan for final sanity checks
```
terraform plan
```
### Deploy the environment
```
terraform apply --auto-approve
```
### Destroy the environment
```
terraform destroy --auto-approve
```
## Credits
```
- XPN: https://github.com/xpn/DemoLab
- MDSec: https://www.mdsec.co.uk/2020/04/designing-the-adversary-simulation-lab/
- Phil Keeble: https://github.com/PhilKeeble/AWS-RedTeam-ADLab
- Splunk: https://github.com/splunk/attack_range
- oehrlis: https://github.com/oehrlis/guacamole
- https://github.com/splunk/attack_range/wiki/Upload-Windows-10-AMI-to-AWS
- https://www.rickgouin.com/run-a-windows-10-instance-in-aws-ec2/
```
