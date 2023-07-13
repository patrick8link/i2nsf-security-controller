######################################################################
# Example ext-author
# (C) 2019 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all     Build all example files"
	@echo "make clean   Remove all built and intermediary files"
	@echo "make clean_delete_cli_history  Clean also cli_history"
	@echo "make start   Start CONFD daemon"
	@echo "make stop    Stop any CONFD daemon"
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

all: datamodel.fxs $(CDB_DIR) ssh-keydir xpath.j.ccl xpath.c.ccl
	@echo "Build complete"

######################################################################
clean:	iclean

clean_delete_cli_history:	clean
	-rm -rf cli-history 2> /dev/null || true

start:  stop
	$(CONFD) -c confd.conf $(CONFD_FLAGS)
	@echo "ConfD started"

######################################################################
stop:
	### Killing any confd daemon
	$(CONFD) --stop || true

######################################################################
cli: cli-j

cli-j:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit
