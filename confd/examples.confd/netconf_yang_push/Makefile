######################################################################
# YANG-Push example
# # (C) 2020 Tail-f Systems
#
######################################################################
usage:
	@echo "See README file for more instructions"
	@echo "make build            	 	Build all example files."
	@echo "make clean            	 	Remove all built files and \
	artefacts."
	@echo "make start            	 	Start ConfD daemon."
	@echo "make start-dp             	Start data provider."
	@echo "make stop             	 	Stop ConfD daemon and data \
	provider process."
	@echo "make periodic-subscription	Establish a periodic \
	subscription on interactive netconf console."
	@echo "make on-change-subscription	Establish an on-change \
	subscription on interactive netconf console."
	@echo "make edit-data			Execute an edit-data RPC \
	netconf console."
	@echo "make on-change-push		Trigger an on-change push \
	from DP."

TEST_DIR ?= $(CONFD_DIR)/../system/test
include $(CONFD_DIR)/src/confd/build/include.mk

export TEST_DIR
CONFIG_FILE ?= ./confd.conf

CONFD_FLAGS := -c $(CONFIG_FILE) --addloadpath $(CONFD_DIR)/etc/confd

INITS := $(patsubst %_init.xml,$(CDB_DIR)/%_init.xml,$(wildcard *_init.xml))
YANG_MODULES = ietf-interfaces.yang iana-if-type.yang
FXS := $(patsubst %.yang,%.fxs,$(YANG_MODULES))
HDR  = $(FXS:%.fxs=%.h)
PGM  = example-dp
OBJ  = $(PGM:%=%.o)

build: $(FXS) $(PGM) $(CDB_DIR) $(CONFD_CONFS) inits

%: %.o $(CONFD_LIB)
	$(CC) -o $@ $< $(LIBS)

inits: $(INITS) ssh-keydir state log

state:
	mkdir state

log:
	mkdir log

$(CDB_DIR)/if_init.xml: if_init.xml
	rm -f $@ ; cp $< $@

$(CDB_DIR)/aaa_init.xml: $(CONFD_DIR)/var/confd/cdb/aaa_init.xml
	rm -f $@ ; cp $< $@

ietf-interfaces.fxs: ietf-interfaces.yang ietf-interfaces-ann.yang
	$(CONFDC) --fail-on-warnings -c -a ietf-interfaces-ann.yang -o $@ -- $<

start: stop
	$(CONFD) $(CONFD_FLAGS)

start-dp:
	./example-dp -ddY -f example-cp

stop:
	$(CONFD) --stop || true
	$(KILLALL) $(PGM) || true

periodic-subscription: periodic-subscription.xml
	(cat $<; echo) | netconf-console -i -v 1.1

on-change-subscription: on-change-subscription.xml
	(cat $<; echo) | netconf-console -i -v 1.1

edit-data:
	netconf-console --rpc=edit-data.xml

on-change-push:
	echo p | nc 127.0.0.1 9999

# just to get gmake to understand it must go via .o
$(OBJ): $(HDR)

clean:
	rm -f *.fxs *.o $(PGM) $(HDR) $(CONFD_CONFS)
	rm -f local.data global.data *.db ssh-keydir
	rm -rf log state
	rm -rf cli-history lux_logs $(CDB_DIR)

clean_cdb:
	-rm -f $(CDB_DIR)/*.cdb 2>/dev/null || true
	-rm -f $(CDB_DIR)/rollback* 2>/dev/null || true
