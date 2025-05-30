
```sh
cd socket-over-rdma/socket_boost

ssh lucam@$REMOTE_IP

cd poli/socket-over-rdma/

make clean && make && make test

sudo ./build/bin/scap

./buil/bin/server
./buil/bin/client

nc -l 5544

nc $REMOTE_IP 5544


iperf3 -s
iperf3 -c $REMOTE_IP

```




### RDMA
```sh
ibv_rc_pingpong -g 0 -d rxe0
ibv_rc_pingpong -g 0 -d rxe0 192.168.100.11
```

### VMs setup

fiel sync

```sh
ssh-keygen -t rsa -b 2048
ssh-copy-id lucam@192.168.88.131
mkdir -p /home/lucam/poli/socket-over-rdma

#add custom alia
nano ~/.bashrc
alias push='rsync -avz --delete /home/lucam/poli/socket-over-rdma/socket_boost/build lucam@192.168.100.6:/home/lucam/poli/socket-over-rdma'

ssh lucam@$REMOTE_IP

source ~/.bashrc

```

change prompt color
```sh
PS1='${debian_chroot:+($debian_chroot)}\[\033[01;33m\]\u@\h\[\033[00m\]:\[\033[01;35m\]\w\[\033[00m\]\[\033[01;31m\]\$\[\033[00m\] '
```


script at boot time
```sh
nano /home/lucam/.bashrc

# VM1
export REMOTE_IP="192.168.100.6"
export LOCAL_IP="192.168.100.5"

# VM2
export REMOTE_IP="192.168.100.5"
export LOCAL_IP="192.168.100.6"

# COMMON
LOCAL_NETDEV="ens33"
if ! rdma link show | grep -q .; then
  echo "Adding RDMA device"
  sudo rdma link add rxe0 type rxe netdev $LOCAL_NETDEV
fi

```


ip conf
```sh
lucam@lucamsrv:~$ sudo cat /etc/netplan/50-cloud-init.yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      addresses:
        - 192.168.100.5/24
      nameservers:
        addresses:
          - 192.168.100.2
      routes:
        - to: 0.0.0.0/0
          via: 192.168.100.2

sudo netplan apply
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


```c

// Writer thread
while(1)
{
  Select(fds_to_monitor);

  If(ISSET(fd))
  {
    while (1)
    {
      // consume the buffer
      char dummy;
      int size = recv(fd, dummy, 1, MSG_PEEK);
      If(size > 0) rdma_write_msg(fd);
    }
  }
}

// write msg
if(ringbuffer.size > 0)
{
  int contiguos_space = ....
  msg.size = recv(fd, msg.data, contiguos_space, 0);
  msg.socket_id = get_socket_id(fd);
  mag.number_of_msg = msg.size / sizeof(msg);
}

...
if(number_of_msg_written > THRESHOLD)
{
  // flush
  write(buffer.data[start], number_of_msg_written);
  // update the write index
  write(new_write_index);
  if(peerBuffer.flags.is_polling == FALSE) {
    // send notification
    send(data_ready);
  }
}

// Reader thread
while(1)
{
  if(read_index != write_index)
  {
    // add a read job
    int n_msg = write_index - read_index;
    int n_thread = n_msg / MAX_MSG_PER_THREAD;
    for(int i = 0; i < n_thread; i++)
    {
      threadpool.add_job(read_job, 
                      read_index + i * MAX_MSG_PER_THREAD,
                      MAX_MSG_PER_THREAD);
    }
  }
}

// read job
int i=0;
for(start; i<start+number_of_msg;)
{
  *msg = read_buffer[i];
  int dest_fd = lookup(swap(msg->socket_id));
  send(dest_fd, msg->data, msg->size, 0);
  i += msg.number_of_msg;
}
// update the other side
write(peerBuffer, new_read_index);



struct rdma_msg
{
    uint32_t msg_flags;            // flags
    struct sock_id original_sk_id; // id of the socket
    uint32_t msg_size;             // size of the message
    uint32_t number_of_slots;      // number of slots
    char msg[MAX_PAYLOAD_SIZE];    // message
};

struct rdma_ringbuffer
{
    rdma_flag_t flags;
    atomic_uint remote_write_index;
    atomic_uint remote_read_index;
    atomic_uint local_write_index;
    atomic_uint local_read_index;
    rdma_msg_t data[MAX_MSG_BUFFER];
};




```