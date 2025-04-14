# Variabili
CC = gcc
CLANG_FLAGS = -g -O2 -target bpf
BPFTOOL = bpftool
LDLIBS = -lbpf

SRC = src
INC = include

BUILD = build
BIN = $(BUILD)/bin
OBJ = $(BUILD)/obj
OUT = $(BIN)/scap


all: $(BUILD) $(BIN) $(OBJ) $(OUT)

$(BUILD) $(BIN) $(OBJ):
	mkdir -p $@

$(BIN)/scap: $(SRC)/main.c $(INC)/common.h $(OBJ)/scap.skel.h $(OBJ)/scap.o
	$(CC) $(CFLAGS) -I$(INC) -o $@ $< $(OBJ)/scap.o $(LDLIBS)

$(OBJ)/scap.o: $(SRC)/scap.c $(INC)/scap.h
	$(CC) $(CFLAGS) -I$(INC) -c -o $@ $< $(LDLIBS)

$(OBJ)/scap.skel.h: $(OBJ)/scap.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OBJ)/scap.bpf.o: $(SRC)/scap.bpf.c $(INC)/common.h
	clang $(CLANG_FLAGS) -I$(INC) -c $< -o $@


clean:
	rm -rf $(BUILD)
