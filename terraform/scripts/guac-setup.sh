#!/usr/bin/env bash
# Install Docker and related stuff
export DEBIAN_FRONTEND=noninteractive
apt-get -qy -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold" upgrade
apt-get remove docker docker-engine docker.io containerd runc
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
apt install git -y
apt-get update -y
apt install -y python3-pip ansible
sudo curl -L https://github.com/docker/compose/releases/download/1.25.3/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Setup Guacamole and run it
git clone https://github.com/q0phi80/guacamole.git
cd guacamole
sudo ./bin/prepare_initdb.sh
sudo docker-compose up -d guacamole mysql guacd
sudo docker-compose up -d