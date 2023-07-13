######################################################################
# Server-side filtering using Python API
# (C) 20019 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all     Build all example files for Python"
	@echo "make clean   Remove all built and intermediary files"
	@echo "make start   Start CONFD daemon and python example agent"
	@echo "make stop    Stop any CONFD daemon and example agent"
	@echo "make cli     Start the CONFD Command Line Interface, J-style"
	@echo "make cli-c   Start the CONFD Command Line Interface, C-style"
	@echo "make query   Run few netconf queries using a filter"


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

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd
START_FLAGS ?=

all:	not_sunos arpe.fxs arpe_ns.py $(CDB_DIR) ssh-keydir
	@echo "Build complete"


######################################################################
clean:	iclean
	-rm -rf arpe_ns.py arpe_ns.pyc __init__.py 2> /dev/null || true
	rm -rf __pycache__

######################################################################
start:  stop arpe_ns.py
	$(CONFD) -c confd.conf $(CONFD_FLAGS)
	### * In one terminal window, run: tail -f ./confd.log
	### * In another terminal window, run queries
	###   (try 'make query' for an example)
	### * In this window, the arpstat confd daemon now starts:
	###   (hit Ctrl-c to exit)
	$(PYTHON) ./arpstat.py $(START_FLAGS)

######################################################################
stop:
	### Killing any confd daemon and ARP confd agents
	$(CONFD) --stop || true
	$(KILLALL) `pgrep -f "$(PYTHON) ./arpstat.py"` || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################

query: query-ip query-if

IP_ADDR ?= 10.0.0.1
IFACE ?= eth0

query-ip:
	$(MAKE) FIELD=ip VALUE=$(IP_ADDR) query-field

query-if:
	$(MAKE) FIELD=ifname VALUE=$(IFACE) query-field

query-field:
	$(NETCONF_CONSOLE) --get -x '/arpentries/arpe[$(FIELD)="$(VALUE)"]'

######################################################################
