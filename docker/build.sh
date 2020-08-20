#!bin/bash

cp build/distributions/signer-service.tar docker
docker build -t signer-service:$1 docker
