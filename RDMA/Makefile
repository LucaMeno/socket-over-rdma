# Makefile - Client RDMA

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -libverbs -lrdmacm
TARGET_C = rdma_client
TARGET_S = rdma_server
TARGET = $(TARGET_C) $(TARGET_S)

all: $(TARGET)

$(TARGET_C): rdma_client.c
	$(CC) $(CFLAGS) -o $(TARGET_C) rdma_client.c $(LDFLAGS)

$(TARGET_S): rdma_server.c
	$(CC) $(CFLAGS) -o $(TARGET_S) rdma_server.c $(LDFLAGS)

clean:
	rm -f $(TARGET)
