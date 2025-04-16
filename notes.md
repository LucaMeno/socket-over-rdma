



Build and install libbpf:
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