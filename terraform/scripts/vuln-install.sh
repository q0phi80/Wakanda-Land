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

# Install the vulnerable packages via Docaker
DIRECTORY="vulhub"
CONTAINERS[0]="$DIRECTORY/coldfusion/CVE-2017-3066/docker-compose.yml" # port 8500
CONTAINERS[1]="$DIRECTORY/jboss/JMXInvokerServlet-deserialization/docker-compose.yml" # port 8080
CONTAINERS[2]="$DIRECTORY/activemq/CVE-2016-3088/docker-compose.yml" # port 8161
CONTAINERS[3]="$DIRECTORY/samba/CVE-2017-7494/docker-compose.yml" # port 445
CONTAINERS[4]="$DIRECTORY/couchdb/CVE-2017-12636/docker-compose.yml" # port 5984
CONTAINERS[5]="$DIRECTORY/supervisor/CVE-2017-11610/docker-compose.yml" # port 9001
CONTAINERS[6]="$DIRECTORY/weblogic/ssrf/docker-compose.yml" # port 7001
git clone https://github.com/vulhub/vulhub.git

for i in ${CONTAINERS[@]}; do sudo docker-compose -f $i up -d; done

init_check () { # Check if vulhub folder exists
    if [[ ! -d vulhub ]]
    then
        echo "The vulhub folder was not found. Download from https://github.com/vulhub/vulhub"
        exit 1
    fi

    # Check if docker is installed
    docker --version > /dev/null 2>&1
    if [[ $? -ne 0 ]]
    then
        echo "Docker is not installed. Read: https://docs.docker.com/get-docker/ "
        exit 3
    fi

    # Check if docker-compose is installed
    docker-compose version > /dev/null 2>&1
    if [[ $? -ne 0 ]]
    then
        echo "Docker-compose is not installed. Read: https://docs.docker.com/compose/install/"
        exit 3
    fi
}

# Start each container with docker-compose
start () {
    for i in "${CONTAINERS[@]}"
    do
        docker-compose -f "${i}" up -d
        if [[ $? -ne 0 ]]
        then
            exit 1 # Exit docker engine is not running
        fi
    done
}

stop () {
    for i in "${CONTAINERS[@]}"
    do
        docker-compose -f "${i}" down -v
        if [[ $? -ne 0 ]]
        then
            echo "You may need to manually disable container(s) using docker."
            echo "To show running containers type: docker ps"
            #exit 1 # Exit docker engine is not running
        fi
    done
}

if [[ $1 == "start" ]]
then
    init_check
    echo "Starting all docker containers..."
    start
elif [[ $1 == "stop" ]]
then
    init_check
    echo "Stopping all docker containers ..."
    stop
elif [[ $1 == "list" ]]
then
    echo -e "Listing all available Docker containers from vulhub."
    
else
    echo -e "\n\e[31m\e[1mVulnerables\e[0m: a quick and simple way of starting multiple Docker containers from vulhub.\n"
    echo -e "Usage: $0 [start or stop]\n"
fi