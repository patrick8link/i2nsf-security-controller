######################################################################
# Example maapi - python version
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
	@echo "make query   Run query against CONFD"
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

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd
START_FLAGS ?=

maapi_example_ns.py: maapi-example.fxs
	$(CONFDC) --emit-python $@ $<

all: maapi-example.fxs maapi_example_ns.py commands-c.ccl $(CDB_DIR) ssh-keydir
	@echo "Build complete"

######################################################################
clean:	iclean
	-rm -rf maapi_example_ns.py *.pyc __init__.py 2> /dev/null || true
	-rm -rf cli-history 2> /dev/null || true

start_confd:  stop_confd
	### Start the confd daemon with our example specific confd-config
	$(CONFD) -c confd.conf $(CONFD_FLAGS)

start:  stop start_confd
	### Starting the maapi_example
	$(PYTHON) maapi_example.py

######################################################################
stop_confd:
	### Killing any confd daemon
	$(CONFD) --stop    || true

stop: stop_confd
	### Killing any confd daemon and hooks confd agents
	$(CONFD) --stop || true
	$(KILLALL) `pgrep -f "$(PYTHON) maapi_example.py"` || true

######################################################################
cli: cli-j

cli-j:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit
