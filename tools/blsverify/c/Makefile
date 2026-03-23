BLST_DIR := blst
BLST_LIB := $(BLST_DIR)/libblst.a
BLST_INC := $(BLST_DIR)/bindings

CJSON_H := cJSON.h
CJSON_C := cJSON.c
CJSON_URL := https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18

CC ?= cc
CFLAGS := -O2 -Wall -Wextra -Wpedantic -I$(BLST_INC) -I.
LDFLAGS := -L$(BLST_DIR) -lblst -lpthread

TARGET := blsverify

.PHONY: all clean test

all: $(TARGET)

$(BLST_DIR)/libblst.a:
	@if [ ! -d $(BLST_DIR) ]; then \
		echo "Cloning blst..."; \
		git clone --depth 1 https://github.com/supranational/blst.git $(BLST_DIR); \
	fi
	cd $(BLST_DIR) && ./build.sh

$(CJSON_H):
	curl -sL -o $@ $(CJSON_URL)/cJSON.h

$(CJSON_C):
	curl -sL -o $@ $(CJSON_URL)/cJSON.c

cJSON.o: $(CJSON_C) $(CJSON_H)
	$(CC) $(CFLAGS) -Wno-unused-parameter -c $(CJSON_C) -o $@

main.o: main.c $(BLST_LIB) $(CJSON_H)
	$(CC) $(CFLAGS) -c main.c -o $@

$(TARGET): main.o cJSON.o $(BLST_LIB)
	$(CC) main.o cJSON.o -o $@ $(LDFLAGS)

test: $(TARGET)
	./$(TARGET) ../../../testvectors_v1

clean:
	rm -f $(TARGET) main.o cJSON.o $(CJSON_H) $(CJSON_C)
	rm -rf $(BLST_DIR)
