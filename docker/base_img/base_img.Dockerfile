FROM ubuntu:24.04

# Install required packages
RUN apt-get update && \
    apt-get install -y \
    make \
    clang \
    gcc \
    libbpf-dev \
    librdmacm-dev \
    rdma-core \
    libibverbs-dev \
    iproute2 \
    git \
    llvm \
    iputils-ping \
    perftest \
    ibverbs-utils \
    ca-certificates && \
    apt-get clean
    
# Clone, build, and install bpftool
RUN git clone https://github.com/libbpf/bpftool.git && \
    cd bpftool && \
    git submodule update --init --recursive && \
    cd src && \
    make && \
    make install && \
    cd / && rm -rf bpftool

# Add a startup script for the RDMA link setup
COPY setup.docker.sh /setup.docker.sh
RUN chmod +x /setup.docker.sh

# run the startup script in the OTHER container
