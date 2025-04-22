
VM1
192.168.88.134:7777             192.168.88.131:35576 

VM2
192.168.88.131:35576              192.168.88.134:7777



### RDMA
```sh
ibv_rc_pingpong -g 0 -d rxe0
ibv_rc_pingpong -g 0 -d rxe0 192.168.100.11
```

### Sync VMs
```sh
ssh-keygen -t rsa -b 2048
ssh-copy-id lucam@192.168.88.131
mkdir -p /home/lucam/poli/socket-over-rdma

#add custom alia
nano ~/.bashrc
alias push='rsync -avz --delete /home/lucam/poli/socket-over-rdma/socket_boost lucam@192.168.88.131:/home/lucam/poli/socket-over-rdma'

ssh lucam@192.168.88.131

source ~/.bashrc

```


### clear docker
```sh
docker compose down --volumes --rmi all --remove-orphans

docker stop $(docker ps -aq)

docker rm $(docker ps -aq)

docker rmi $(docker images -q)
```

### add bpftool and libbpf as submodules

```sh

cd / && \
apt-get install git llvm -y && \
git clone https://github.com/libbpf/bpftool.git && \
cd bpftool && \
git submodule update --init --recursive && \
cd src && \
make && \
make install
```

### Build and install libbpf:
```sh
cd ./libbpf/src
make
sudo make install

# Make sure the loader knows where to find libbpf
sudo ldconfig /usr/lib64
```


```sh
# git submodule add https://github.com/libbpf/bpftool.git bpftool
# git submodule add https://github.com/libbpf/libbpf.git libbpf
```



### BPF

Install pre-requirements:
```sh
sudo apt update
sudo apt install -y clang libelf-dev zlib1g-dev gcc-multilib
```

Init libbpf and bpftool submodules:
```sh
git submodule update --init --recursive
```


Build and install bpftool:
```sh
cd ./bpftool/src
make
sudo make install
```

```sh
# see eBPF output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

see bpf

```sh
sudo bpftool prog show
sudo bpftool map show
```


# RDMA setup

1. **Install the required packages**  
```bash
sudo apt update
sudo apt install rdma-core ibverbs-utils # infiniband-diags

sudo apt install ibverbs-utils libibverbs-dev librdmacm-dev
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

