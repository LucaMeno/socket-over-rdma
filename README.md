
# Socket bust

## Overview

The idea of this project is to intercept socket calls and redirect them to RDMA calls. This is done using eBPF (extended Berkeley Packet Filter) technology, which allows for efficient packet filtering and manipulation at the kernel level.
It allows for high-performance communication between processes using RDMA technology, which is particularly useful in high-throughput and low-latency scenarios.
...

## Building

Install pre-requirements:
```sh
sudo apt update
sudo apt install -y make clang gcc libbpf-dev librdmacm-dev rdma-core libibverbs-dev
```

Enable RDMA (SoftRoce)

```sh
sudo rdma link add rxe0 type rxe netdev ens33
```
_(Replace `ens33` with your actual network interface.)_

Use it
```sh
make

# run scap
sudo ./build/bin/scap

# see eBPF output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Test
Open 2 Terminal and:
```sh
make test

# Socket:
./build/bin/server # 1
./build/bin/client # 1

# RDMA
./build/bin/rdma_server # 1
./build/bin/rdma_client # 1

```


### Bpftool (optional)

Build and install:
```sh
cd ./bpftool/src
make
sudo make install
```

Use it
```sh
sudo bpftool prog show
sudo bpftool map show
```

### Testing RDMA Between Two VMs

```bash
# install perftest on both VM1 and VM2
sudo apt install perftest

# VM 1 (RX)
ib_write_bw -d rxe0

# VM 2 (TX)
ib_write_bw <first_VM_IP> -d rxe0
```


## Install docker

```sh
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl -y
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Add your user to the docker group
sudo usermod -aG docker $USER
newgrp docker

```



