
CXX = g++
CXXFLAGS = -Wall -O2 -Iinclude -MMD -MP -g
LDFLAGS = -libverbs

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build

RDMATRANSFER_SRC = $(SRC_DIR)/RdmaTransfer.cpp
RDMATRANSFER_OBJ = $(BUILD_DIR)/RdmaTransfer.o

MANAGER_SRC = $(SRC_DIR)/Manager.cpp
MANAGER_OBJ = $(BUILD_DIR)/Manager.o

THREADPOOL_SRC = $(SRC_DIR)/ThreadPool.cpp
THREADPOOL_OBJ = $(BUILD_DIR)/ThreadPool.o

OBJS = $(RDMATRANSFER_OBJ) $(MANAGER_OBJ) $(THREADPOOL_OBJ)

TARGETS = $(BUILD_DIR)/rdma_server $(BUILD_DIR)/rdma_client

PUSH = rsync -avz --delete /home/${USER}/poli/socket-over-rdma/tests/rdma/build poli-server:/home/${USER}/poli/socket-over-rdma/test/rdma/build

all: $(TARGETS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# RdmaTransfer
$(RDMATRANSFER_OBJ): $(RDMATRANSFER_SRC) $(INC_DIR)/RdmaTransfer.h $(INC_DIR)/RdmaTestConf.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(LDFLAGS)

$(THREADPOOL_OBJ): $(THREADPOOL_SRC) $(INC_DIR)/ThreadPool.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(LDFLAGS)

$(MANAGER_OBJ): $(MANAGER_SRC) $(INC_DIR)/Manager.h $(RDMATRANSFER_OBJ) $(THREADPOOL_OBJ) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(LDFLAGS)

$(BUILD_DIR)/rdma_server: $(SRC_DIR)/rdma_server.cpp $(OBJS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/rdma_client: $(SRC_DIR)/rdma_client.cpp $(OBJS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	$(PUSH)

clean:
	rm -rf $(BUILD_DIR)

-include $(OBJS:.o=.d)

.PHONY: all clean
