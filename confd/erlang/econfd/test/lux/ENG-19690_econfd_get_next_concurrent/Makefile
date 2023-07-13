TEST_DIR ?= $(CONFD_DIR)/../system/test
include $(TEST_DIR)/support/lux_testcases.mk

export TEST_DIR

CONFIG_FILE := ./confd.conf
CONFD_FLAGS := -c $(CONFIG_FILE) --addloadpath $(CONFD_DIR)/etc/confd --addloadpath .

FXS = ENG-19690.fxs

ERLC = erlc
ERLC_FLAGS = -I $(CONFD_DIR)/erlang/econfd/include
ERL_PROG = ENG-19690_dp.beam

build: $(FXS) $(ERL_PROG) confd-cdb/aaa_init.xml

confd-cdb/aaa_init.xml: $(CONFD_DIR)/var/confd/cdb/aaa_init.xml confd-cdb
	rm -f $@ ; cp $< $@

%.beam: %.erl
	$(ERLC) $(ERLC_FLAGS) $<

start:
	$(CONFD) $(CONFD_FLAGS)

starti:
	$(CONFD) $(CONFD_FLAGS) -i -v

wait-until-started:
	$(CONFD) --wait-started

stop:
	$(CONFD) --stop

clean:
	rm -f *.fxs *.o *.h _tmp_* *.beam
	rm -f confd-cdb/* fxs/* *log confderr* global.data candidate.db
	rm -rf lux_logs

.PHONY: build clean

include $(CONFD_DIR)/src/confd/build/include.mk
