include ../../../../..//support/include.mk
include $(TEST_DIR)/support/lux_testcases.mk
include $(CONFD_DIR)/src/confd/build/include.mk

CONFIG_FILE ?= ../_common/confd.conf
# Internal env
CONFD_FXS_DIR = $(CONFD_DIR)/etc/confd
CONFD_FLAGS = --addloadpath $(CONFD_FXS_DIR)

# auto-compile all the .cli and yang files
CCL=$(patsubst %.cli,%.ccl,$(wildcard *.cli))
FXS=$(patsubst %.yang,%.fxs,$(shell awk '/submodule/{next} /module.*\{/{print FILENAME}' *.yang))
BEAM=$(patsubst %.erl,%.beam,$(wildcard *.erl))
INITS=$(patsubst %_init.xml,$(CDB_DIR)/%_init.xml,$(wildcard *_init.xml))

# Mandatory targets
build:	$(FXS) \
	$(BEAM) \
	$(CCL) \
	$(CDB_DIR) \
	$(INITS) \
	$(BUILD_EXTRA) \
	log \
	ssh-keydir
	@echo "Build complete"

clean:	iclean $(CLEAN_EXTRA)
	-rm -rf $(FXS) $(BEAM) $(CCL) log xpath.trace cli-history lux_logs

######################################################################
# Internal targets

log:
	mkdir -p log

$(CDB_DIR)/%_init.xml: %_init.xml
	cp $< $@

clean_cdb:
	-rm -f $(CDB_DIR)/*.cdb 2>/dev/null || true
	-rm -f $(CDB_DIR)/rollback* 2>/dev/null || true

start:  stop
	$(CONFD) -c $(CONFIG_FILE) $(CONFD_FLAGS)

starti: stop
	$(CONFD) -c $(CONFIG_FILE) $(CONFD_FLAGS) -i

wait-until-started:
	$(CONFD) --wait-started

stop:
	$(CONFD) --stop || true

%.beam: %.erl
	$(ERLC) $(ERLC_FLAGS) $*.erl

######################################################################

cli:
	$(CONFD_DIR)/bin/confd_cli -J --user=admin --groups=admin \
		--interactive || echo Exit
