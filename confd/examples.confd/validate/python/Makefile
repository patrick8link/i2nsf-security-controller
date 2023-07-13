######################################################################
# ConfD simple validation example
# (C) 2006-2020 Tail-f Systems
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
	@echo "make cli      Start the ConfD Command Line Interface"

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

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd
START_FLAGS ?=
CS = mtest

######################################################################
$(CS)_ns.py: $(CS).fxs
	$(CONFDC) --emit-python $@ $<

all:	$(CS).fxs $(CS)_ns.py $(PROG) $(CDB_DIR) ssh-keydir
	@echo "Build complete"

mtest.fxs: mtest.yang mtest.annot.yang
	$(CONFDC) -c -a mtest.annot.yang mtest.yang

######################################################################
clean:	iclean
	-rm -rf $(CS)_ns.py __init__.py __pycache__ 2> /dev/null || true

start:  stop
	$(CONFD) -c ./confd.conf --start-phase0 $(CONFD_FLAGS); \
	$(CONFD) --wait-phase0; \
	# Start the valpoint before phase1
	$(PYTHON) ./more_a_than_b.py $(START_FLAGS) & \
	# wait until validation points are registered
	sleep 2; \
	$(CONFD) --start-phase1 $(CONFD_FLAGS); \
	$(CONFD) --start-phase2 $(CONFD_FLAGS);

	### * The more_a_than_b validation daemon now runs in the background
	### * In one terminal window, run: tail -f ./confd.log
	### * In another terminal window, run queries
	###   (try 'make query' for an example)


######################################################################
stop:
	### Stopping any confd daemon
	$(CONFD) --stop || true
	$(KILLALL) `pgrep -f "$(PYTHON) more_a_than_b.py"` || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
query-invalid:
	$(CONFD_DIR)/bin/netconf-console cmd-set-invalid-config.xml

query-valid:
	$(CONFD_DIR)/bin/netconf-console cmd-set-valid-config.xml

######################################################################
