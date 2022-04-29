# Wakanda-Bazeng-Lab
## Purpose🛡
The Wakanda Bazeng (a slang in Swahili meaning Big Boss) Lab is an Adversarial Simulation Lab platform that uses ```terraform``` to automate the process of whipping up a lab infrastructure to practice various offensive attacks. This project inherits from other people's work in the Cybersecurity Community and due credit has been provided in the Credit Section. 

I just added some additional sprinkles to their work from my other researches.

## Demo 📺
[A short demo (< 3 min)](https://www.youtube.com/watch?v=yE7ytM3VNDQ) which shows the basic functions of the lab infrastructure and how it builds a testing environment using terraform.

[![Attack Range Demo](https://img.youtube.com/vi/yE7ytM3VNDQ/1.jpg)](https://www.youtube.com/watch?v=yE7ytM3VNDQ)
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
- Vulnerable web applications for exploitation

## Architecture 🏯
The deployment of Wakanda Bazeng environment consist of:
- Two Subnets
- Windows Domain Controller for the Child Domain (first.local)
- Windows Domain Controller for the Parent Domain (second.local)
- Windows Server in the Child Domain - this serves as a victim machine for the initial access
- Kali Machine - Covenant C2 is bootstrapped in
- Debian Server running an Apache Guacamole service - Kali GUI and Windows Server RDP are bootstrapped during deploymnet
- Debian Server serving as Web Server 1 - OWASP's Juice Shop deployed via Docker
- Debian Server serving as Web Server 2 - Vulnerable Tomcat deployed via Docker

## Installation 🏗
```
Terraform
Install terraform
Install aws cli
set up creds in aws cli 

DSC
Install-module -name activedirectorydsc
install-module -name networkingdsc 
install-module -name ComputerManagementDsc
install-module -name GroupPolicyDsc
With these you can use ". .\adlab.ps1" to make the MOF files 

S3
Create an S3 bucket for your account and modify the variable in terraform/vars.tf with your bucket name

Management IP 
Change the management IP variable in vars.tf to be your public IP address

Keys
Create an EC2 key pair, get public key from the pem with ssh-keygen -y -f /key.pem
Store the file ./terraform/keys/terraform-key.pub 
Update the file in the vars.tf to point to that public key (which will assign it to the created EC2 instances)
Can use this key pair to get the administrator default password from AWS

Once you run the terraform, it will take some time to provivision everything so give it about 30 mins to an hour and you should be good to go.
```
## Running the lab 🏃‍♀️
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
