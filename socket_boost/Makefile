# Variabili
CC = gcc
CLANG_FLAGS = -g -O2 -target bpf
BPFTOOL = bpftool
LDLIBS = -lbpf -lrdmacm -libverbs
PUSH = rsync -avz --delete /home/lucam/poli/socket-over-rdma/socket_boost/build/bin lucam@192.168.100.6:/home/lucam/poli/socket-over-rdma

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

$(OBJ)/rdma_utils.o: $(SRC)/rdma_utils.c $(INC)/rdma_utils.h
	$(CC) $(CFLAGS) -I$(INC) -c -o $@ $<

$(OBJ)/rdma_manager.o: $(SRC)/rdma_manager.c $(INC)/rdma_manager.h
	$(CC) $(CFLAGS) -I$(INC) -c -o $@ $<

$(OBJ)/scap.skel.h: $(OBJ)/scap.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OBJ)/scap.bpf.o: $(SRC)/scap.bpf.c $(INC)/common.h
	clang $(CLANG_FLAGS) -I$(INC) -c $< -o $@

test: $(BIN) $(OBJ) $(OBJ)/rdma_manager.o $(OBJ)/rdma_utils.o
	$(CC) $(CFLAGS) -I$(INC) -o $(BIN)/rdma_client $(TEST_RDMA)/rdma_client.c $(OBJ)/rdma_manager.o $(OBJ)/rdma_utils.o $(LDLIBS)
	$(CC) $(CFLAGS) -I$(INC) -o $(BIN)/rdma_server $(TEST_RDMA)/rdma_server.c $(OBJ)/rdma_manager.o $(OBJ)/rdma_utils.o $(LDLIBS)
	$(CC) $(CFLAGS) -I$(INC) -o $(BIN)/client $(TEST_SOCKET)/client.c $(LDLIBS)
	$(CC) $(CFLAGS) -I$(INC) -o $(BIN)/server $(TEST_SOCKET)/server.c $(LDLIBS)
	$(PUSH)

	
clean:
	rm -rf $(BUILD)
