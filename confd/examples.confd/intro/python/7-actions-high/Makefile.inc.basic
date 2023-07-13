# Make sure makefiles which have a usage target first use it even if
# they include this file at the top...

iusage: usage

# Define common ConfD build tools and flags

OSNAME		 := $(shell uname -s)

CONFD		 = $(CONFD_DIR)/bin/confd
CONFDC		 = $(CONFD_DIR)/bin/confdc
INCLUDE		 = -I$(CONFD_DIR)/include
CONFD_LIB	?= $(CONFD_DIR)/lib/libconfd.a
LIBS		 = $(CONFD_LIB) -lpthread -lm
CFLAGS		 = -Wall -g $(INCLUDE)
CDB_DIR		 = ./confd-cdb

KILLALL		 = killall

ifeq ($(OSNAME),FreeBSD)
CFLAGS		+= -I/usr/local/include
LIBS		+= -L/usr/local/lib
endif

ifeq ($(OSNAME),Darwin)
SHARED_FLAGS	= -dynamiclib
LD_ENV		= DYLD_LIBRARY_PATH
else
SHARED_FLAGS	= -shared
LD_ENV		= LD_LIBRARY_PATH
endif
# Targets to require/reject specific OS

.PHONY: linux not_sunos

linux:
ifneq ($(OSNAME),Linux)
	@echo "This example only works on Linux" ; exit 1
endif

not_sunos:
ifeq ($(OSNAME),SunOS)
	@echo "This example does not work on Solaris" ; exit 1
endif

iclean:
	-rm -rf *.o *.a *.xso *.fxs *.xsd *.log *.db *.ccl \
               host.key host.cert client.key client.cert ca.cert *_proto.h \
               running.invalid global.data aaa_cdb.* $(CDB_DIR) ssh-keydir \
               webui etc
