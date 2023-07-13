CONFD_FXS_DIR = $(CONFD_DIR)/etc/confd
CONFD_FLAGS_EXTRA += --addloadpath $(CONFD_FXS_DIR) \
                     --addloadpath $(CONFD_FXS_DIR)/snmp

HEADERS = test.hrl
BEAMFILES = ebin/test_econfd_maapi.beam

ROLLBACK = $(CDB_DIR)/rollback0

BUILD_EXTRA = $(HEADERS)
CLEAN_EXTRA = myclean

include ../_common/common.mk

ERLC = erlc
ERLC_FLAGS = -pa ../../../ebin -I ../../../include


ebin:
	mkdir $@

ebin/%.beam: %.erl
	$(ERLC) $(ERLC_FLAGS) -o ebin $<.erl

test-econfd-maapi-fail:
	erl -pa ebin -pa ../../../ebin -noshell -s test_econfd_maapi fail \
		-s init stop
test-econfd-maapi-pass:
	erl -pa ebin -pa ../../../ebin -noshell -s test_econfd_maapi pass \
		-s init stop
.PHONY: test-econfd-maapi-fail test-econfd-maapi-pass

reset-cdb:
	rm -rf $(CDB_DIR)
	$(MAKE) $(CDB_DIR)
.PHONY: reset-cdb

test.hrl: test.fxs
	$(CONFDC) --emit-hrl $@ $<

myclean:
	rm -rf $(HEADERS)
.PHONY: myclean
