######################################################################
# Python Transform example
# (C) 2018 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all      Build all example files"
	@echo "make clean    Remove all built and intermediary files"
	@echo "make start    Start ConfD daemon and example agent"
	@echo "make stop     Stop any ConfD daemon and example agent"
	@echo "make query    Run NETCONF query against ConfD"
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
	@exit 1

######################################################################
# Example specific definitions and rules

print-%  : ; @echo $* = $($*)

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd
START_FLAGS ?=

DAEMON_PY = transform.py

YANGS = $(wildcard *.yang)
FXSS = $(patsubst %.yang, %.fxs, $(YANGS))
NSS = $(patsubst %.yang, %_ns.py, $(YANGS))

all:	$(FXSS) $(NSS) $(DAEMON_PY) $(CDB_DIR) ssh-keydir
	@echo "Build complete"

######################################################################
clean:	iclean
	-rm -rf ./*.pyc ./*_ns.py __init__.py ./cli-history/ 2> /dev/null || true

######################################################################
start:  stop $(NSS)
	$(CONFD) -c confd.conf $(CONFD_FLAGS)
	### * In one terminal window, run: tail -f ./confd.log
	### * In another terminal window, run queries
	###   (try 'make query' for an example)
	### * In this window, the daemon now starts:
	###   (hit Ctrl-c to exit)
	$(PYTHON) ./$(DAEMON_PY) $(START_FLAGS)

######################################################################
stop:
	$(CONFD) --stop || true
	$(KILLALL) `pgrep -f "$(PYTHON) ./$(DAEMON_PY)"` || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
query:
	$(CONFD_DIR)/bin/netconf-console -u admin --get-config

######################################################################
