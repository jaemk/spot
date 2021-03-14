#!/bin/bash

set -e

name=spistorfy-server
if [ -z "$1" ]; then
    echo "please specify tag"
    exit 1
fi


echo "building images... latest, $1 "

docker build -t jaemk/$name:$1 .
docker build -t jaemk/$name:latest .

if [ "$2" = "push" ]; then
    echo "pushing images..."
    set -x
    docker push jaemk/$name:$1
    docker push jaemk/$name:latest
fi
