#!/bin/bash

ACCT=${ACCT:-zexi}

docker build -t $ACCT/yke-cert-deployer:v0.1.1 .
docker push $ACCT/yke-cert-deployer:v0.1.1
