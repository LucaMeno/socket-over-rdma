CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -libverbs
TARGET = test_rdma
SRC = test_rdma.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
