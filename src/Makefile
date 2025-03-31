# Compiler flags
CLANG_FLAGS = -g -O2 -target bpf
BPFTOOL = bpftool
CC = gcc
CFLAGS = -g -Wall -O2 -I/usr/include/bpf
LDLIBS = -lbpf

# Targets
all: scap

scap: main.c common.h scap.skel.h
	$(CC) $(CFLAGS) -o scap main.c $(LDLIBS)

scap.skel.h: scap.bpf.o
	$(BPFTOOL) gen skeleton ./scap.bpf.o > scap.skel.h

scap.bpf.o: scap.bpf.c common.h
	clang $(CLANG_FLAGS) -c scap.bpf.c -o scap.bpf.o

clean:
	rm -f scap scap.skel.h scap.bpf.o
