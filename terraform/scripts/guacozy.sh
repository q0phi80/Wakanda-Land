#!/usr/bin/env bash
cd /tmp
touch dc.yml
var=/tmp/dc.yml
cat << EOF >> $var
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

sudo docker-compose -f dc.yml up -d

#sudo docker-compose up -d