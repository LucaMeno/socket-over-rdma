#!/bin/bash

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <number>"
  exit 1
fi

if ! rdma link show | grep -q .; then
  echo "Adding RDMA device"
  sudo rdma link add rxe0 type rxe netdev ens33
fi


DOCKER_COMPOSE_FILE=$1
# --force-recreate 
docker compose -f docker-compose.yaml up -d sk-boost-$DOCKER_COMPOSE_FILE

echo "⏳ Waiting for the container to be up..."
sleep 3
docker exec -it sk-boost-c-"$DOCKER_COMPOSE_FILE" /bin/bash

docker exec -it sk-boost-c-2 /bin/bash