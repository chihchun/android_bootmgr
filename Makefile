CC=gcc
CFLAGS=-I. -Wall
LDFLAGS=

all: bootmgr

bootmgr: bootmgr.c bootimg.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(TARGETS) *.o
