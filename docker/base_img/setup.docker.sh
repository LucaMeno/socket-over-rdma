#!/bin/bash

# Check if rxe0 interface already exists using rdma link
if ! rdma link show > /dev/null 2>&1; then
  echo "rxe0 interface already exists, skipping..."
  exit 0
else
  echo "rxe0 interface does not exist, creating..."
  rdma link add rxe0 type rxe netdev $NETDEV
fi
