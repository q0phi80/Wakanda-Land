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
sudo curl -L https://github.com/docker/compose/releases/download/1.25.3/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Pull the vulnerable Docker images
DIRECTORY="vulhub"
CONTAINERS[0]="$DIRECTORY/coldfusion/CVE-2017-3066/docker-compose.yml" # port 8500
CONTAINERS[1]="$DIRECTORY/jboss/JMXInvokerServlet-deserialization/docker-compose.yml" # port 8080
CONTAINERS[2]="$DIRECTORY/activemq/CVE-2016-3088/docker-compose.yml" # port 8161
CONTAINERS[3]="$DIRECTORY/samba/CVE-2017-7494/docker-compose.yml" # port 445
CONTAINERS[4]="$DIRECTORY/couchdb/CVE-2017-12636/docker-compose.yml" # port 5984
CONTAINERS[5]="$DIRECTORY/supervisor/CVE-2017-11610/docker-compose.yml" # port 9001
CONTAINERS[6]="$DIRECTORY/weblogic/ssrf/docker-compose.yml" # port 7001
git clone https://github.com/vulhub/vulhub.git

# Run each of the vulneble Docker images
for i in ${CONTAINERS[@]}; do sudo docker-compose -f $i up -d; done