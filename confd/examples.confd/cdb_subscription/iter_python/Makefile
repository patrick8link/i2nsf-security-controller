######################################################################
# Interface Status example - python version
# (C) 2006-2017 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all     Build all example files"
	@echo "make clean   Remove all built and intermediary files"
	@echo "make start   Start CONFD daemon and example agent"
	@echo "make stop    Stop any CONFD daemon and example agent"
	@echo "make cli     Start the CONFD Command Line Interface"

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

all:	root.fxs root_ns.py $(CDB_DIR) ssh-keydir
	@echo "Build complete"


######################################################################
clean:	iclean
	rm -rf _tmp* log/*
	-rm -rf root_ns.py *.pyc __init__.py > /dev/null || true

######################################################################

start_confd:  stop_confd
	### Start the confd daemon with our example specific confd-config
	$(CONFD) -c confd.conf $(CONFD_FLAGS)
	### In another terminal window, start the CLI (make cli)

start:  stop start_confd
	### Starting the cdb subscriber
	$(PYTHON) cdbl.py

######################################################################
stop_confd:
	### Killing any confd daemon
	$(CONFD) --stop    || true

stop: stop_confd
	### Killing confd agents
	$(KILLALL) `pgrep -f "$(PYTHON) cdbl.py"` || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit
