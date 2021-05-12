# CollaREServer v1.0

![CollaRE](https://raw.githubusercontent.com/Martyx00/CollaRE/master/collare/icons/collare-full-white.png)


This repository holds the source code and deployment tools for the server used by the `CollaRE` application which aims to provide a platform and application independent solution for collaboration during reverse engineering.

## Deployment

Generate certificates which are going to be used by the server (can be self-signed) and put them to the `certs` folder with names `nginx-cert.crt` and `nginx-cert.key`. Then run the `deploy.sh` script which will ask you for the hostname of the server and handle the rest of the deployment.

You can use this command from the root of this repository to generate the certificates (self-signed valid for 10 years): `openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout ./certs/nginx-cert.key -out ./certs/nginx-cert.crt`

Make sure to keep the certificate file as all clients connecting to the server will need it to validate the server identity.

## How it works

The whole server is very simple Flask application with an Nginx in front of it. The only operations it performs is creating and deleting appropriate files. No database is connect.

