######################################################################
# Handling OpenConfig models - example for ConfD
# (C) 2019 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all     Build all example files"
	@echo "make clean   Remove all built and intermediary files"
	@echo "make start   Start CONFD daemon and example agent"
	@echo "make stop    Stop any CONFD daemon and example agent"
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
YANGER_DIR ?= $(CONFD_DIR)/erlang/yanger
ERLC ?= $(CONFD_DIR)/bin/erlc

all:	yanger_oc.beam oc-test.fxs $(CDB_DIR) ssh-keydir
	@echo "Build complete"

yanger_oc.beam: yanger_oc.erl
	$(ERLC) -pa $(YANGER_DIR) $^

oc-test.fxs: oc-test.yang yanger_oc.beam
	YANGER_PLUGINPATH=$$PWD $(CONFDC) -c -o $@ $<

######################################################################
clean:	iclean
	rm -rf *.beam

start:  stop
	$(CONFD) -c confd.conf $(CONFD_FLAGS)

######################################################################
stop:
	### Killing any confd daemon
	$(CONFD) --stop || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
