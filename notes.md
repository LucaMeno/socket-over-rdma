

### Some commands

```sh
sudo cpupower frequency-set -g performance

sudo numactl --cpunodebind=0 --membind=0 ./bin/scap x y


```

```sh
nc -l 7777
nc $REMOTE_IP 7777

iperf3 -s -p 7777
iperf3 -c $REMOTE_IP -p 7777
```
testing RDAM

```sh
sudo apt install perftest

ib_write_bw

ib_write_bw <first_VM_IP>
```
See BPF output:

```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```


bpftools commands
```sh
sudo bpftool prog show
sudo bpftool map show
```


### Ex MakeFile

```makefile
# Variabili
CC = gcc
CLANG_FLAGS = -g -O2 -target bpf
BPFTOOL = bpftool
LDLIBS = -lbpf -lrdmacm -libverbs
PUSH = rsync -avz --delete /home/${USER}/poli/socket-over-rdma/socket_boost/build poli-server:/home/${USER}/poli/socket-over-rdma

SRC = src
INC = include
TEST_RDMA = tests/rdma
TEST_SOCKET = tests/socket

BUILD = build
BIN = $(BUILD)/bin
OBJ = $(BUILD)/obj
OUT = $(BIN)/scap

all: $(BUILD) $(BIN) $(OBJ) $(OUT)

$(BUILD) $(BIN) $(OBJ):
	mkdir -p $@

$(BIN)/scap: $(SRC)/main.c $(INC)/common.h $(OBJ)/scap.skel.h $(OBJ)/scap.o $(OBJ)/sk_utils.o $(OBJ)/rdma_utils.o $(OBJ)/rdma_manager.o
	$(CC) $(CFLAGS) -I$(INC) -o $@ $< $(OBJ)/scap.o $(OBJ)/sk_utils.o $(OBJ)/rdma_utils.o $(OBJ)/rdma_manager.o $(LDLIBS)
	$(PUSH)

$(OBJ)/scap.o: $(SRC)/scap.c $(INC)/scap.h
	$(CC) $(CFLAGS) -I$(INC) -c -o $@ $< $(LDLIBS)

$(OBJ)/sk_utils.o: $(SRC)/sk_utils.c $(INC)/sk_utils.h
	$(CC) $(CFLAGS) -I$(INC) -c -o $@ $<

$(OBJ)/rdma_utils.o: $(SRC)/rdma_utils.c $(INC)/rdma_utils.h $(INC)/scap.h
	$(CC) $(CFLAGS) -I$(INC) -c -o $@ $<

$(OBJ)/rdma_manager.o: $(SRC)/rdma_manager.c $(INC)/rdma_manager.h $(INC)/rdma_utils.h $(INC)/scap.h
	$(CC) $(CFLAGS) -I$(INC) -c -o $@ $<

$(OBJ)/scap.skel.h: $(OBJ)/scap.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OBJ)/scap.bpf.o: $(SRC)/scap.bpf.c $(INC)/common.h
	clang $(CLANG_FLAGS) -I$(INC) -c $< -o $@

test: $(BIN) $(OBJ) $(OBJ)/rdma_manager.o $(OBJ)/rdma_utils.o
	$(CC) $(CFLAGS) -I$(INC) -o $(BIN)/client $(TEST_SOCKET)/client.c $(LDLIBS)
	$(CC) $(CFLAGS) -I$(INC) -o $(BIN)/server $(TEST_SOCKET)/server.c $(LDLIBS)
	$(PUSH)

	
clean:
	rm -rf $(BUILD)

```






``` c++

// writer thread
while (true) {
	select(socketToReadFrom[]);

	if(ISSET(socketToReadFrom[i])) {
		// retrrieve the context to reach the destination
		ctx = getContext(socketToReadFrom[i]);
		// read the msg and write it into the buffer
		ctx.writeMsg(socketToReadFrom[i]);
	}
}

```







