CC = gcc
CFLAGS = -Wall

OUT = bin
SERVER = $(OUT)/server
CLIENT = $(OUT)/client

all: $(OUT) $(SERVER) $(CLIENT)

$(SERVER): server.c
	$(CC) $(CFLAGS) -o $@ server.c

$(CLIENT): client.c
	$(CC) $(CFLAGS) -o $@ client.c

$(OUT):
	mkdir -p $@

clean:
	rm -rf $(OUT)
