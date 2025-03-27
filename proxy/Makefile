# Compiler and flags
CC = gcc
CFLAGS = -Wall

# Output executables
SERVER = server
CLIENT = client

# Source files
SERVER_SRC = server.c
CLIENT_SRC = client.c

# All targets
all: $(SERVER) $(CLIENT)

# Rule to build the server executable
$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $(SERVER) $(SERVER_SRC)

# Rule to build the client executable
$(CLIENT): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT_SRC)

# Clean up generated files
clean:
	rm -f $(SERVER) $(CLIENT)

# Rule to run the server and client (to be used with `make run`)
run: $(SERVER) $(CLIENT)
	./$(SERVER) & ./$(CLIENT)
