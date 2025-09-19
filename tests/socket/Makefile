
CXX       := g++
CXXFLAGS  := -Wall -Wextra -O2 -std=c++17 -Iinclude

SRC_DIR   := src
BUILD_DIR := build
BIN_DIR   := $(BUILD_DIR)/bin
OBJ_DIR   := $(BUILD_DIR)/obj

CLIENT_BIN := $(BIN_DIR)/client
SERVER_BIN := $(BIN_DIR)/server

PUSH = rsync -avz --delete /home/${USER}/poli/socket-over-rdma/tests/socket/build poli-server:/home/${USER}/poli/socket-over-rdma/test/build

.PHONY: all
all: $(CLIENT_BIN) $(SERVER_BIN) 

# Ensure build folders exist
$(BIN_DIR) $(OBJ_DIR):
	@mkdir -p $@

# Pattern rule for object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link executables
$(CLIENT_BIN): $(OBJ_DIR)/client.o | $(BIN_DIR)
	$(CXX) $^ $(LDFLAGS) $(LDLIBS) -o $@

$(SERVER_BIN): $(OBJ_DIR)/server.o | $(BIN_DIR)
	$(CXX) $^ $(LDFLAGS) $(LDLIBS) -o $@
	$(PUSH)

clean:
	@rm -rf $(BUILD_DIR)


