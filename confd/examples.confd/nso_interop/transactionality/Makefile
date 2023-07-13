######################################################################
# (C) 2021 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all      Build all example files"
	@echo "make clean    Remove all built and intermediary files"
	@echo "make start    Start CONFD daemon and example agent"
	@echo "make stop     Stop any CONFD daemon and example agent"
	@echo "make cli      Start the CONFD Command Line Interface"
	@echo "make trigger  Trigger all subscriptions"

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

PROGS  = cdb_client

all: build

build: example.fxs $(PROGS) $(CDB_DIR) ssh-keydir \
	$(CDB_DIR)/example_init.xml
	@echo "Build complete"


$(CDB_DIR)/example_init.xml: example_init.xml
	rm -f $@ ; cp $< $@


%: %.c
	$(CC) -o $@ -Wall -g $< $(CFLAGS) $(LIBS)

#
# Cleanup
#
clean: iclean
	rm -rf log/* *.output _tmp*
	rm -rf $(PROGS) *.dSYM example.h

#
# Dependencies
cdb_client: example.h


#
# Convenience targets

start: stop build
	$(CONFD) -c confd.conf --addloadpath $(CONFD_DIR)/etc/confd
	./cdb_client

stop:
	$(CONFD_DIR)/bin/confd --stop || true

status:
	$(CONFD_DIR)/bin/confd --status

cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

trigger:
	$(CONFD_DIR)/bin/confd_cmd -c trigger
