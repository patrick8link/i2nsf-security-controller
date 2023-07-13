TEST_DIR ?= $(CONFD_DIR)/../system/test
include $(CONFD_DIR)/../support/include.mk
include $(TEST_DIR)/support/lux_testcases.mk

export TEST_DIR

CONFIG_FILE := ./confd.conf
CONFD_FLAGS := -c $(CONFIG_FILE) --addloadpath $(CONFD_DIR)/etc/confd --addloadpath .

FXS = ENG-19779.fxs ENG-23170.fxs ietf-origin.fxs

ERLC_FLAGS = -I $(CONFD_DIR)/erlang/econfd/include
ERL_PROG = ENG-19779_dp.beam ENG-23170_dp.beam

build: $(FXS) ietf-origin.hrl $(ERL_PROG) confd-cdb/aaa_init.xml ssh-keydir

confd-cdb/aaa_init.xml: $(CONFD_DIR)/var/confd/cdb/aaa_init.xml confd-cdb
	rm -f $@ ; cp $< $@

%.beam: %.erl
	$(ERLC) $(ERLC_FLAGS) $<

ietf-origin.fxs:
	cp $(CONFD_DIR)/etc/confd/$@ .

ietf-origin.hrl: ietf-origin.fxs
	$(CONFDC) --emit-hrl $@ $<

start:
	$(CONFD) $(CONFD_FLAGS)

starti:
	$(CONFD) $(CONFD_FLAGS) -i -v

wait-until-started:
	$(CONFD) --wait-started

stop:
	$(CONFD) --stop || true

clean: iclean
	rm -f *.fxs *.o *.hrl _tmp_* *.beam
	rm -f *log confderr* global.data candidate.db
	rm -fr lux_logs

clean_cdb:
	-rm -f $(CDB_DIR)/*.cdb 2>/dev/null || true
	-rm -f $(CDB_DIR)/rollback* 2>/dev/null || true
	@echo clean_cdb completed

.PHONY: build clean

include $(CONFD_DIR)/src/confd/build/include.mk
