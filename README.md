
# Socket bust

## Overview

The idea of this project is to intercept socket calls and redirect them to RDMA calls. This is done using eBPF (extended Berkeley Packet Filter) technology, which allows for efficient packet filtering and manipulation at the kernel level.
It allows for high-performance communication between processes using RDMA technology, which is particularly useful in high-throughput and low-latency scenarios.
...

## Building

Install pre-requirements:
```sh
sudo apt update
sudo apt install -y make clang gcc libbpf-dev librdmacm-dev rdma-core libibverbs-dev git llvm -y
```

Install bpftool:
```sh
cd bpftool
git clone https://github.com/libbpf/bpftool.git
cd bpftool
git submodule update --init --recursive
cd src
make
make install
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



