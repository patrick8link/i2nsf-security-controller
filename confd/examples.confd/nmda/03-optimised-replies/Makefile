######################################################################
# Interface example
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

CONFIG_FILE ?= confd.conf

CONFD_FXS_DIR = $(CONFD_DIR)/etc/confd
CONFD_FLAGS += --addloadpath $(CONFD_FXS_DIR)

CDB_DIR := confd-cdb
YANG_MODULES = example-interface.yang
FXS := $(patsubst %.yang,%.fxs,$(YANG_MODULES))

PROG = interface_dp
H = example-interface.h ietf-origin.h
SRC  = $(PROG:%=%.c)
OBJ  = $(PROG:%=%.o)

all: dir $(FXS) $(CDB_DIR) $(INITS) $(H) $(PROG) ssh-keydir
	@echo "build complete"

dir:
	mkdir -p rollback state log

$(INITS):
	cp $(@F) $@

$(CDB_DIR)/aaa_init.xml: $(CONFD_DIR)/var/confd/cdb/aaa_init.xml
	rm -f $@ ; cp $< $@

ietf-origin.h: $(CONFD_DIR)/etc/confd/ietf-origin.fxs
	$(CONFDC) --emit-h $@ $<

%: %.o
	$(CC) -o $@ $< $(LIBS)

# just to get gmake to understand it must go via .o
$(OBJ): $(SRC)

start: stop
	$(CONFD) -c $(CONFIG_FILE) $(CONFD_FLAGS)

dp_get_elem:
	./$(PROG) -d interfaceCP

dp_get_object:
	./$(PROG) -d -o interfaceCP

dp_get_next_object:
	./$(PROG) -d -O 1 interfaceCP

dp_get_next_objects:
	./$(PROG) -d -O 2 interfaceCP

stop:
	$(CONFD) --stop || true
	$(KILLALL) $(PROG) || true

clean:	iclean
	-rm -rf log state rollback confd-cdb 2> /dev/null || true
	-rm  $(H) ietf-origin.h $(PROG) 2> /dev/null || true

clean_cdb:
	-rm -f $(CDB_DIR)/*.cdb 2>/dev/null || true
	-rm -f $(CDB_DIR)/rollback* 2>/dev/null || true
	@echo clean_cdb completed

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit
cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

cli-i:
	$(CONFD_DIR)/bin/confd_cli -I --user=admin --groups=admin \
