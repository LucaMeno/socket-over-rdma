
# RDMA setup

1. **Install the required packages**  
```bash
sudo apt update
sudo apt install rdma-core ibverbs-utils # infiniband-diags

# for devs
sudo apt install ibverbs-utils libibverbs-dev 
```

2. **Load the Soft-RoCE kernel module**  
```bash
sudo modprobe rdma_rxe
```

3. **Check if the module is loaded**  
```bash
lsmod | grep rxe
```

4. **Attach Soft-RoCE to your Ethernet interface**  
Identify your network interface with `ip a`, then run:  
```bash
sudo rdma link add rxe0 type rxe netdev ens33
```
_(Replace `ens33` with your actual network interface.)_

5. **Verify Soft-RoCE is active**  
```bash
rdma link
# Expected output: rxe0: rxe enp0s3 state ACTIVE
```

6. **Check if RDMA devices are available**  
```bash
ibv_devinfo
```
If Soft-RoCE is working, you should see an RDMA device listed.

---

### **Testing RDMA Between Two VMs**


```bash
# install perftest on both VM1 and VM2
sudo apt install perftest

# VM 1 (RX)
ib_write_bw -d rxe0

# VM 2 (TX)
ib_write_bw <first_VM_IP> -d rxe0
```



