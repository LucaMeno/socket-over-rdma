#!/bin/bash

# Check if rxe0 interface already exists using rdma link
if ! rdma link show | grep -q .; then
  echo "No RDMA interfaces found, creating rxe0..."
  #rdma link add rxe0 type rxe netdev $NETDEV
else
  echo "RDMA interfaces exist, skipping creation of rxe0..."
fi
