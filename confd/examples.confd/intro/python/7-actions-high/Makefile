######################################################################
# Introduction example 7-actions-high
# (C) 2017 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all     Build all example files for Python"
	@echo "make clean   Remove all built and intermediary files"
	@echo "make start   Start CONFD daemon and python example agent"
	@echo "make stop    Stop any CONFD daemon and example agent"
	@echo "make query   Run query against CONFD"
	@echo "make cli     Start the CONFD Command Line Interface"
	@echo "make cli-c   Start the CONFD Command Line Interface, C-style"
	@echo "make cli-j   Start the CONFD Command Line Interface, J-style"

######################################################################
# Where is ConfD installed? Make sure CONFD_DIR points it out
CONFD_DIR ?= ../../..
NETCONF_CONSOLE ?= $(CONFD_DIR)/bin/netconf-console

# Include standard ConfD build definitions and rules
include $(CONFD_DIR)/src/confd/build/include.mk

# In case CONFD_DIR is not set (correctly), this rule will trigger
$(CONFD_DIR)/src/confd/build/include.mk:
	@echo 'Where is ConfD installed? Set $$CONFD_DIR to point it out!'
	@echo ''

######################################################################
# Example specific definitions and rules

PYAPP=action.py

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd
START_FLAGS ?=

all:	config.fxs config_ns.py $(CDB_DIR) ssh-keydir
	@echo "Build complete"

######################################################################
clean:	iclean
	-rm -rf cli-history/ config_ns.py* __init__.py 2> /dev/null || true

start: stop
	$(CONFD) -c confd.conf $(CONFD_FLAGS)
	### * In one terminal window, run: tail -f ./confd.log
	### * In another terminal window, run queries
	###   (try 'make query' for an example)
	### * In this window, the actions confd daemon now starts:
	$(PYTHON) $(PYAPP) $(START_FLAGS)

######################################################################
stop:
	### Killing any confd daemon and confd agents
	$(CONFD) --stop || true
	$(KILLALL) `pgrep -f "$(PYTHON) $(PYAPP)"` || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

cli-j:
	$(CONFD_DIR)/bin/confd_cli -J --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
query:
	$(NETCONF_CONSOLE) cmd-invoke-action.xml

query2:
	$(NETCONF_CONSOLE) cmd-invoke-action2.xml

query-err:
	$(NETCONF_CONSOLE) cmd-invoke-action-err.xml

######################################################################
