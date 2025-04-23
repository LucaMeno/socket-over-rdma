
LOCAL_NETDEV="ens33"

if ! rdma link show | grep -q .; then
  echo "Adding RDMA device"
  sudo rdma link add rxe0 type rxe netdev $LOCAL_NETDEV
fi