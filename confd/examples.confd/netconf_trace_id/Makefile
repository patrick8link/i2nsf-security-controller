######################################################################
# NETCONF Trace-ID example
# # (C) 2021 Cisco Systems
#
######################################################################
usage:
	@echo "See README file for more instructions"
	@echo "make build            	 	Build all example files."
	@echo "make clean            	 	Remove all built files and \
	artifacts."
	@echo "make start            	 	Start ConfD daemon."
	@echo "make start-subs             	Start cdb-subscriber."
	@echo "make start-notifications        Start ConfD NETCONF \
	notifications."
	@echo "make stop             	 	Stop ConfD daemon and data \
	provider process."
	@echo "make edit-config             	Invoke example NETCONF \
	edit-config operation."

TEST_DIR ?= $(CONFD_DIR)/../system/test
include $(CONFD_DIR)/src/confd/build/include.mk

export TEST_DIR
CONFIG_FILE ?= ./confd.conf

CONFD_FLAGS := -c $(CONFIG_FILE) --addloadpath $(CONFD_DIR)/etc/confd

FXS  = smp.fxs
HDR  = $(FXS:%.fxs=%.h)
PGM  = confd_notifications cdb_subscriber
OBJ  = $(PGM:%=%.o)

build: $(FXS) $(PGM) $(CDB_DIR) ssh-keydir

smp.fxs:
	confdc --fail-on-warnings -c -o $@ smp.yang

%: %.o $(CONFD_LIB)
	$(CC) -o $@ $< $(LIBS)

start:
	$(CONFD) $(CONFD_FLAGS)

start-subs:
	./cdb_subscriber -dd

start-notifications:
	./confd_notifications -N

stop:
	$(CONFD) --stop || true
	$(KILLALL) $(PGM) || true

edit-config:
	netconf-console -s raw --edit-config=edit.xml

tail-netconf-trace:
	tail -f netconf.trace

# just to get gmake to understand it must go via .o
$(OBJ): $(HDR)

clean:
	rm -f *.fxs *.o $(PGM) _tmp_* $(HDR)
	rm -f cdb/* *log confderr* global.data local.data *.db netconf.trace
	rm -rf lux_logs $(CDB_DIR) ssh-keydir cli-history

.PHONY: build clean
