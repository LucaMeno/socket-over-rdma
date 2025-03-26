# Compiler flags
CLANG_FLAGS = -g -O2 -target bpf
BPFTOOL = bpftool
CC = gcc
CFLAGS = -g -Wall -O2 -I/usr/include/bpf
LDLIBS = -lbpf

# Targets
all: scap

scap: scap.c scap.h scap.skel.h
	$(CC) $(CFLAGS) -o scap scap.c $(LDLIBS)

scap.skel.h: scap.bpf.o
	$(BPFTOOL) gen skeleton ./scap.bpf.o > scap.skel.h

scap.bpf.o: scap.bpf.c scap.h
	clang $(CLANG_FLAGS) -c scap.bpf.c -o scap.bpf.o

clean:
	rm -f scap scap.skel.h scap.bpf.o
