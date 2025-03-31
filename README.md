
## Building

Install pre-requirements:
```sh
sudo apt update
sudo apt install -y clang libelf-dev zlib1g-dev gcc-multilib
```

Init libbpf and bpftool submodules:
```sh
git submodule update --init --recursive
# git submodule add https://github.com/libbpf/bpftool.git bpftool
# git submodule add https://github.com/libbpf/libbpf.git libbpf
```

Build and install libbpf:
```sh
cd ./libbpf/src
make
sudo make install
# Make sure the loader knows where to find libbpf
sudo ldconfig /usr/lib64
```

Build and install bpftool:
```sh
cd ./bpftool/src
make
sudo make install
```

Build and run the network monitor:
```sh
make
sudo ./scap
```

Test
```sh
# see output
sudo cat /sys/kernel/debug/tracing/trace_pipe

#test
curl http://example.com
netcat localhost 7777

```

see bpf
```sh
sudo bpftool prog show
sudo bpftool map show
```