# CollaREServer

This repository holds the source code and deployment tools for the server used by the `CollaRE` application which aims to provide a platform and application independent solution for collaboration during reverse engineering.

## Deployment

Generate certificates which are going to be used by the server (can be self-signed) and put them to the `certs` folder with names `nginx-cert.crt` and `nginx-cert.key`. Then run the `deploy.sh` script which will ask you for the hostname of the server.