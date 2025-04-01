CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -libverbs
TARGETS = rdma_server rdma_client

all: $(TARGETS)

rdma_server: rdma_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

rdma_client: rdma_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)
