######################################################################
# ConfD external logging example
# (C) 2019 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all      Build all example files"
	@echo "make clean    Remove all built and intermediary files"
	@echo "make start    Start ConfD daemon"
	@echo "make stop     Stop any ConfD daemon"
	@echo "make cli      Start the ConfD Command Line Interface"
	@echo "make demo     Run demo application"


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

######################################################################
# Example specific definitions and rules

all:	build

build:	secret_model.fxs $(CDB_DIR) ssh-keydir
	cp secret_model_init.xml $(CDB_DIR)
	@echo "Build complete"

######################################################################
clean:	iclean clean-logs

clean-logs:
	-rm -rf netconf.trace netconf_filtered.trace 2>/dev/null || true

start:  stop $(CDB_DIR)
	$(CONFD) -c ./confd.conf $(CONFD_FLAGS)

######################################################################
stop:
	$(CONFD) --stop || true


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
	netconf-console --get --rpc-attribute \
		"xmlns:esm='urn:example:secret_model'" -x '/esm:secret_model'

diff:
	diff -u netconf.trace netconf_filtered.trace
