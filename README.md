# Wakanda-Land
## Purpose
Wakanda Land is a Cyber Range deployment tool that uses ```terraform``` for automating the process of deploying an Adversarial Simulation lab infrastructure for practicing various offensive attacks. This project inherits from other people's work in the Cybersecurity Community and due credit has been provided in the Credit Section. I just added some additional sprinkles to their work from my other researches.

## Attacks Covered
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
- Cross domain trusts
- SMBSigning disabled on all machines for relay attacks
- Defender uninstalled so no need to worry about AV
- Multiple machines so you can practise tunneling, double hop problem, etc
- All the default things like lateral movement, persistence, pass the hash, pass the ticket, golden tickets, silver tickets etc
- Web applications exploitations (covering OWASP Top 10)

## Architecture
The deployment of Wakanda Land environment consist of:
- Two Subnets
- Guacamole Server
  - *This provides dashboard access to Kali GUI and Windows RDP instances*
  - *The Kali GUI, Windows RDP and the user accounts used to log into these instances are already backed into the deployment process*
  - *To log into the Guacamole dashboard with the ```guacadmin``` account, you need to SSH into the Guacamole server using the public IP address (which is displayed after the deployment is complete) and then change into the ```guacamole``` directory and then type ```cat .env``` for the password (the ```guacadmin``` password is randomnly generated and saved as an environment variable)*
- Windows Domain Controller for the Child Domain (first.local)
- Windows Domain Controller for the Parent Domain (second.local)
- Windows Server in the Child Domain - this serves as a victim machine for the initial access
- Kali Machine - a directory called ```toolz``` is created on this box and Covenant C2 is downloaded into that folder, so its just a matter of running Covenant once you are authenticated into Kali
- Debian Server serving as Web Server 1 - OWASP's Juice Shop deployed via Docker
- Debian Server serving as Web Server 2 - Vulnerable Tomcat deployed via Docker

## Installation
```
Terraform
Install terraform
Install aws cli
set up creds in aws cli 

DSC
1. First, install the following from the PowerShell terminal
  - Install-module -name GroupPolicyDsc
  - Install-module -name activedirectorydsc
  - Install-module -name networkingdsc
  - Install-module -name ComputerManagementDsc
2. Update the PowerShell script (adlab.ps1) with the following:
  - Import-DscResource -ModuleName ActiveDirectoryDsc
  - Import-DscResource -ModuleName NetworkingDsc
  - Import-DscResource -ModuleName ComputerManagementDSC
  - Import-DscResource -ModuleName PSDesiredStateConfiguration
3. Run the script (```. .\adlab.ps1```) from within the ```dsc``` directory to create teh MOF files, which will be dumped into the ```Lab``` folder 

S3
Create an S3 bucket for your account and modify the variable in terraform/vars.tf with your bucket name

Management IP 
Change the management IP variable in vars.tf to be your public IP address

Keys
Create an EC2 key pair, get public key from the pem with ssh-keygen -y -f /key.pem
Store the file ./terraform/keys/terraform-key.pub 
Update the file in the vars.tf to point to that public key (which will assign it to the created EC2 instances)
Can use this key pair to get the administrator default password from AWS

Once you run the terraform, it will take some time to provision everything, so give it about 30 mins to an hour and you should be good to go.
```
## Running the lab
You can take the following steps in running the lab:

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
```
