#!/usr/bin/env bash

# Update the /etc/hosts file (just a quick patch)
cat << EOF >> /etc/hosts
13.80.99.124	packages.microsoft.com
20.81.111.85	microsoft.com
140.82.121.3	github.com
50.116.58.136	kali.org
104.18.102.100	kali.download
EOF

apt update -y
DEBIAN_FRONTEND=noninteractive sudo apt install kali-desktop-xfce xorg xrdp --yes --force-yes
sudo sed -i 's/port=3389/port=3390/g' /etc/xrdp/xrdp.ini
sudo systemctl enable xrdp --now

# Install dotnet
wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
apt update -y
apt install -y apt-transport-https
apt update -y
apt install dotnet-sdk-3.1 -y
apt install git -y
apt install python3-pip -y

# Change the password of the default kali account
echo kali:kali | sudo chpasswd
mkdir -p toolz
cd toolz/

# Install Impacket
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install .
cd ../

# Get Covenant C2 framework
git clone --recurse-submodules https://github.com/cobbr/Covenant
# cd toolz/Covenant/Covenant && sudo dotnet run
# Navigate to https://127.0.0.1:7443 in a browser