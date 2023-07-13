include $(TEST_DIR)/support/lux_testcases.mk
include $(CONFD_DIR)/src/confd/build/include.mk

# Internal env
CONFD_FXS_DIR = $(CONFD_DIR)/etc/confd
CONFD_FLAGS = --addloadpath $(CONFD_FXS_DIR)
FXS=$(patsubst %.yang,%.fxs,$(wildcard *.yang))

$(CDB_DIR)/%_init.xml: %_init.xml
	cp $< $@

clean_cdb:
	-rm -f $(CDB_DIR)/*.cdb 2>/dev/null || true
	-rm -f $(CDB_DIR)/rollback* 2>/dev/null || true

clean:	clean_cdb
	rm -f *.data *.fxs *.db *.trace *.hrl
	rm -rf ssh-keydir confd-cdb log

all: build
build:	base.fxs \
	$(CDB_DIR) \
	ssh-keydir \
	log

compile_erl:
	erlc -pa $(CONFD_DIR)/erlang/econfd/ebin test.erl

run_erl:
	erl -pa $(CONFD_DIR)/erlang/econfd/ebin -noshell -s test test -s init stop

log:
	mkdir -p log

start:  stop
	$(CONFD) -c ./confd.conf $(CONFD_FLAGS)

starti: stop
	$(CONFD) -c confd.conf $(CONFD_FLAGS) -i

stop:
	$(CONFD) --stop || true
