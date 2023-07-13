######################################################################
# CDB operational data subscriber example
# (C) 2018 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all     Build all example files"
	@echo "make clean   Remove all built and intermediary files"
	@echo "make start   Start CONFD daemon and example agent"
	@echo "make stop    Stop any CONFD daemon and example agent"
	@echo "make query   Run NETCONF query against ConfD"
	@echo "make cli     Start the CONFD Command Line Interface, J-style"
	@echo "make cli-c   Start the CONFD Command Line Interface, C-style"

######################################################################
# Where is ConfD installed? Make sure CONFD_DIR points it out
CONFD_DIR ?= ../../..

# Include standard ConfD build definitions and rules
include $(CONFD_DIR)/src/confd/build/include.mk

# In case CONFD_DIR is not set (correctly), this rule will trigger
$(CONFD_DIR)/src/confd/build/include.mk:
	@echo 'Where is ConfD installed? Set $$CONFD_DIR to point it out!'
	@echo ''

######################################################################
# Example specific definitions and rules

CONFD_FLAGS ?= --addloadpath $(CONFD_DIR)/etc/confd
START_FLAGS ?=

YANG=routes.yang
H_FILE = $(YANG:.yang=.h)

PROG = cdb-oper-subs
SRC	= $(PROG).c
OBJS = $(SRC:.c=.o)
LIBS += -lcrypto


all:	$(YANG:.yang=.fxs) $(PROG) $(CDB_DIR) ssh-keydir
	@echo "Build complete"

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

$(PROG).o: $(H_FILE)


######################################################################
clean:	iclean
	-rm -rf $(PROG) $(H_FILE) cli-history/ 2> /dev/null || true

######################################################################
start:  stop
	$(CONFD) -c confd.conf $(CONFD_FLAGS)
	### * In this window, the daemon now starts:
	###   (hit Ctrl-c to exit)
	./$(PROG) $(START_FLAGS)

######################################################################
stop:
	### Killing any ConfD daemons an example ConfD agent
	$(CONFD) --stop || true
	killall $(PROG) || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
query:
	$(CONFD_DIR)/bin/netconf-console --get -x /system/ip

######################################################################
