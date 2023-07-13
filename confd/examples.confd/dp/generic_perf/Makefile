######################################################################
# ConfD data provider generic performance setup example
# (C) 2006-2020 Tail-f Systems
#
# See the README file for more information
#####################################################################
# Where is ConfD installed? Make sure CONFD_DIR points it out
CONFD_DIR ?= ../..

# Include standard ConfD build definitions and rules
include $(CONFD_DIR)/src/confd/build/include.mk

# In case CONFD_DIR is not set (correctly), this rule will trigger
$(CONFD_DIR)/src/confd/build/include.mk:
	@echo 'Where is ConfD installed? Set $$CONFD_DIR to point it out!'
	@echo ''

######################################################################
# Example specific definitions and rules

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd --addloadpath fxs
START_FLAGS ?=

CONFDC=$(CONFD_DIR)/bin/confdc

YANG_SOURCES        = $(wildcard yang/*.yang)
SUBMODULES          = $(shell grep -l belongs-to yang/*.yang)
ANNOTATION_MODULES  = $(wildcard yang/*-ann*.yang)

YANG_MODULES = $(filter-out $(SUBMODULES) $(ANNOTATION_MODULES),$(YANG_SOURCES))

ALL_FXS_FILES = $(YANG_MODULES:yang/%.yang=fxs/%.fxs)
FXS_DIR = ./fxs

CSRCS = $(wildcard src/*.c)
CAPPS = $(patsubst src/%.c,%,$(CSRCS))
HSS = $(ALL_FXS_FILES:fxs/%.fxs=src/%.h)
CFLAGS += -Isrc

src/%.h:
	$(CONFDC) --emit-h src/$*.h fxs/$*.fxs

%: src/%.c
	$(CC) -c -o $@.o $^ -Wall -g -I$(CONFD_DIR)/include
	$(CC) -o $@ $@.o -Isrc $(CFLAGS) $(LIBS)

fxs/%.fxs: yang/%.yang yang/%-ann.yang
	$(CONFDC) -c --yangpath yang --yangpath $(CONFD_DIR)/src/confd/aaa \
	-o $@  -a yang/$*-ann.yang -- $<

fxs/%.fxs: yang/%.yang
	$(CONFDC) -c --yangpath yang --yangpath $(CONFD_DIR)/src/confd/aaa \
	-o $@ -- $<

$(FXS_DIR):
	-mkdir -p $(FXS_DIR)

######################################################################
all: $(FXS_DIR) \
	$(ALL_FXS_FILES) \
	$(HSS) $(CAPPS) \
	$(CDB_DIR) ssh-keydir
	@echo "Build complete"

######################################################################
clean:	iclean
	-rm -rf *.log *.trace obj fxs cli-history \
	$(CAPPS) src/*.h 2> /dev/null || true

######################################################################
start:  stop
	$(CONFD) --start-phase0 -c confd.conf $(CONFD_FLAGS)
	./cdboper_dp -l libconfd.log -t -c oper-cp &
	$(CONFD) --start-phase1
	./wait_started_dp.sh
	confd_load -O -m -l init-state.xml
	$(CONFD) --start-phase2
	### * ConfD and data provider application daemon started
	### * To run queries try for example 'make ncgeta'

######################################################################
stop:
	@ # Kill the confd daemon
	$(CONFD) --stop || true
	$(KILLALL) $(CAPPS) || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
	--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
	--interactive  || echo Exit

######################################################################
ncgeta:
	netconf-console --rpc=-<<<'<get><filter type="subtree"><sys xmlns="http://tail-f.com/ns/example/router"/></filter></get>'

ncgeto:
	netconf-console --rpc=-<<<'<get-data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"><datastore>ds:'"operational"'</datastore><subtree-filter><sys xmlns="http://tail-f.com/ns/example/router"/></subtree-filter><config-filter>false</config-filter></get-data>'

ncgetd:
	netconf-console --rpc=-<<<'<get-data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"><datastore>ds:'"candidate"'</datastore><subtree-filter><sys xmlns="http://tail-f.com/ns/example/router"/></subtree-filter></get-data>'

# Enable restconf in confd.conf before running this query
#rcgeta:
#	curl -s -u admin:admin http://localhost:8008/restconf/data/router:sys -H "Accept: application/yang-data+json"

msavex:
	./maapi-save -s -O -x -p "/r:sys"

msavej:
	./maapi-save -s -O -j -p "/r:sys"

mgobjs:
	./maapi-get-objects -s -O -e 100 -p "/r:sys"

mitera:
	./maapi-iterate -s -O -p "/r:sys"

clish:
	./cli-show-sys.sh

######################################################################
