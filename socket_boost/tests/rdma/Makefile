CC = g++
CFLAGS = -Wall -O2
LDFLAGS = -libverbs
BUILD_DIR = build
PUSH = rsync -avz --delete $(BUILD_DIR)/ poli-server:/home/${USER}/poli/test/build

TARGETS = $(BUILD_DIR)/rdma_server $(BUILD_DIR)/rdma_client

all: $(TARGETS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/rdma_common.o: rdma_common.cpp rdma_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c rdma_common.cpp -o $(BUILD_DIR)/rdma_common.o

$(BUILD_DIR)/rdma_server: rdma_server.cpp $(BUILD_DIR)/rdma_common.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ rdma_server.cpp $(BUILD_DIR)/rdma_common.o $(LDFLAGS)

$(BUILD_DIR)/rdma_client: rdma_client.cpp $(BUILD_DIR)/rdma_common.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ rdma_client.cpp $(BUILD_DIR)/rdma_common.o $(LDFLAGS)

push: all
	$(PUSH)

clean:
	rm -rf $(BUILD_DIR)
