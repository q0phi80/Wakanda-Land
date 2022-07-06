#!/usr/bin/env bash
apt update
DEBIAN_FRONTEND=noninteractive sudo apt-get --yes --force-yes install kali-desktop-xfce xorg xrdp
sudo sed -i 's/port=3389/port=3390/g' /etc/xrdp/xrdp.ini
sudo systemctl enable xrdp --now

# Install dotnet
wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
apt-get update
apt-get install -y apt-transport-https
apt-get update -y
apt-get install -y dotnet-sdk-3.1
apt-get install -y git
apt install -y python3-pip

# Change the password of the default ‘kali’ account
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