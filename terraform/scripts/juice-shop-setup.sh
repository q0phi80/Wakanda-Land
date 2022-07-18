#!/usr/bin/env bash

# Install Docker and related stuff
export DEBIAN_FRONTEND=noninteractive
apt-get -qy -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold" upgrade
apt-get remove docker docker-engine docker.io containerd runc
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
apt install git -y
apt-get update -y
apt install -y python3-pip

# Setup and run the vulnerable web application
sudo docker pull bkimminich/juice-shop
sudo docker run -d -p 3000:3000 bkimminich/juice-shop