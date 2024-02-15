CC := gcc
CFLAGS := -Wall -g -O2 -shared -fPIC

-include Makefile.local

dns-isolate.so: dns-isolate.c
	$(CC) $(CFLAGS) -o$@ $^ -ldl
