#!bin/bash

cp build/distributions/signer-service.tar docker
docker build -t signer-service:$GIT_LOCAL_BRANCH docker
