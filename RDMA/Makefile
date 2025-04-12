# Compilatore e flag
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./librdma
LDFLAGS = -lrdmacm -libverbs

# Libreria statica
LIB_DIR = librdma
LIB_NAME = librdma
LIB_SRC = $(LIB_DIR)/$(LIB_NAME).c
LIB_OBJ = $(LIB_DIR)/$(LIB_NAME).o
LIB_A = $(LIB_DIR)/lib$(LIB_NAME).a

# Eseguibili
CLIENT = rdma_client
SERVER = rdma_server

# Obiettivo principale
all: $(CLIENT) $(SERVER)

# Compilazione della libreria statica
$(LIB_A): $(LIB_OBJ)
	ar rcs $@ $^

# Compilazione oggetto libreria
$(LIB_OBJ): $(LIB_SRC) $(LIB_DIR)/$(LIB_NAME).h
	$(CC) $(CFLAGS) -c $< -o $@

# Compilazione del client
$(CLIENT): rdma_client.c $(LIB_A)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -l$(LIB_NAME) $(LDFLAGS) -o $@

# Compilazione del server
$(SERVER): rdma_server.c $(LIB_A)
	$(CC) $(CFLAGS) $< -L$(LIB_DIR) -l$(LIB_NAME) $(LDFLAGS) -o $@

# Pulizia
clean:
	rm -f $(CLIENT) $(SERVER) $(LIB_OBJ) $(LIB_A)

.PHONY: all clean
