#!/usr/bin/env bash
cd /tmp
mkdir guacozy
cd guacozy
touch docker-compose.yml

cat << EOF >> docker-compose.yml
version: '3'  
services:
  server:
    image: guacozy/guacozy-server
    restart: always
    depends_on:
      - db
    environment:
      - DJANGO_SECRET_KEY=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz
      - FIELD_ENCRYPTION_KEY=qjq4ObsXMqiqQyfKgD-jjEGm4ep8RaHKGRg4ohGCi1A=
      - DJANGO_DB_URL=postgres://postgres@db:5432/postgres
      - DJANGO_ALLOWED_HOSTS=*
      - DJANGO_TIME_ZONE=US/Eastern
      - SUPERUSER_NAME=fluffy
      - SUPERUSER_EMAIL=fluffy@email.com
      - SUPERUSER_PASSWORD=Fluffy123!
    ports:
      - 443:443
  guacd:
    image: linuxserver/guacd
    restart: always
  db:
    image: postgres:10.4-alpine
    restart: always
    volumes:
    - postgres-data:/var/lib/postgresql/data
volumes:
  postgres-data:
EOF

# Check if docker-compose.yml exists
init_check () { # Check whether vulhub folder exists
    if [[ ! -f docker-compose.yml ]]
    then
        echo "The docker-compose.yml file doesn't exit"
        exit 1
    fi
}

start () {
	docker-compose -f docker-compose.yml up -d
}

stop () {
	docker-compose -f docker-dompose.yml down -v
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
else
    echo -e "Usage: $0 [start or stop]\n"
fi

#sudo docker-compose up -d