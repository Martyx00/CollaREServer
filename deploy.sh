#!/bin/bash

echo "[*] Deploying the CollaRE server ..."

# Ask for the CollaRE server name
echo "[?] What hostname will be used for the CollaRE (in format: google.com)?"
read domain

if grep -Fxq "HOSTNAME_PLACEHOLDER" ./conf.d/flaskapp.conf
then
    cp ./conf.d/flaskapp.conf ./conf.d/flaskapp.conf.bak
    sed -i.bak "s/HOSTNAME_PLACEHOLDER/$domain/g" ./conf.d/flaskapp.conf
else
    cp ./conf.d/flaskapp.conf.bak ./conf.d/flaskapp.conf
    sed -i.bak "s/HOSTNAME_PLACEHOLDER/$domain/g" ./conf.d/flaskapp.conf
fi


# Check if docker is running
docker info | grep 'Container' &> /dev/null
if [ $? != 0 ]; then
   echo "[!] Docker is not running. Start Docker first"
   exit 1
fi

echo -en "[*] Starting the services ... "
docker-compose up -d --build
echo "[*] Done :)"