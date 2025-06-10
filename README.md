
# Socket bust

## Overview

The idea of this project is to intercept socket calls and redirect them to RDMA calls. This is done using eBPF technology, which allows for efficient packet filtering and manipulation at the kernel level.
It allows for high-performance communication between processes using RDMA technology.
...

## Building

Install pre-requirements:
```sh
sudo apt update
sudo apt install make clang gcc libbpf-dev librdmacm-dev rdma-core libibverbs-dev git llvm -y
```

Compile

```sh
mkdir build
cd build
cmake ..
make
```

## Running

Machine 1:
```sh
sudo ./bin/scap
```

Machine 2:
```sh
sudo ./bin/scap
```



