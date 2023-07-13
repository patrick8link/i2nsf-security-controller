
CONFD_DIR ?= /usr/local

LIBCONFD = $(CONFD_DIR)/lib/libconfd.a

CFLAGS   += -Wall -g -I$(CONFD_DIR)/include

LDFLAGS    = -lpthread

mmap_schema: mmap_schema.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBCONFD) $(LDFLAGS) -lm
