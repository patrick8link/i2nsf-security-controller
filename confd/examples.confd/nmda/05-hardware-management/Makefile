######################################################################
# IETF Hardware NMDA example
# (C) 2006-2021 Tail-f Systems
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

RED=\033[0;31m
GREEN=\033[0;32m
PURPLE=\033[0;35m
NC=\033[0;m # No Color

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

ietf-origin.h: $(CONFD_DIR)/etc/confd/ietf-origin.fxs
	$(CONFDC) --emit-h src/$*.h $<

src/%.h:
	$(CONFDC) --emit-h src/$*.h fxs/$*.fxs

%: src/%.c
	$(CC) -c -o $@.o $^ -Wall -g -I$(CONFD_DIR)/include
	$(CC) -o $@ $@.o -Isrc $(CFLAGS) $(LIBS)

fxs/%.fxs: yang/%.yang yang/%-ann.yang
	$(CONFDC) -c --no-features --yangpath yang \
	  --yangpath $(CONFD_DIR)/src/confd/aaa -o $@  -a yang/$*-ann.yang -- $<

fxs/%.fxs: yang/%.yang
	$(CONFDC) -c --no-features --yangpath yang \
	  --yangpath $(CONFD_DIR)/src/confd/aaa -o $@ -- $<

$(FXS_DIR):
	-mkdir -p $(FXS_DIR)

######################################################################
all: $(FXS_DIR) \
	$(ALL_FXS_FILES) \
	$(HSS) ietf-origin.h $(CAPPS) \
	$(CDB_DIR) ssh-keydir
	@echo "Build complete"

######################################################################
clean:	iclean
	-rm -rf *.log *.trace hardware_state.* obj fxs cli-history \
	$(CAPPS) src/*.h 2> /dev/null || true

######################################################################
start:  stop
	@printf "\n${GREEN}### Move ConfD to start-phase 0\n${NC}"
	$(CONFD) --start-phase0 -c confd.conf $(CONFD_FLAGS)
	@printf "\n${GREEN}### Load the initial configuration data\n${NC}"
	confd_load -i -dd -m -l chassis_init.xml
	@printf "\n${GREEN}### Start the system-controller module\n${NC}"
	./system_controller $(START_FLAGS) &
	# The system controller will move us to start phase 1
	@printf "\n${GREEN}### Wait for the system-controller to move ConfD to \
start-phase 1\n${NC}"
	confd_cmd -dd -c 'wait-start 1'
	@printf "\n${GREEN}### Load the initial state data\n${NC}"
	confd_load -dd -O -m -l chassis_init.xml
	@printf "\n${GREEN}### Register an example card and have the card open up \
the nortbound interfaces by moving ConfD to start-phase 2\n${NC}"
	./card -c "dummy" -a "82" -n "2391" -m "tail-f" -r 1 -u 4 -l 1 -o 4 -t -i 	\
						$(START_FLAGS) &
	@printf "\n${GREEN}### Wait for the card to move ConfD to \
start-phase 2\n${NC}"
						confd_cmd -dd -c 'wait-start 2'
	@printf "\n${GREEN}### ConfD started\n### In another terminal window, run '\
make start-card' to register another example card\n${NC}"

start-card:
	@printf "\n${GREEN}### Register another example card\n${NC}"
	./card -c "clone" -a "87" -n "9985" -m "tail-f" -r 1 -u 4 -l 2 -o 2 -t \
						$(START_FLAGS) &
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

nc-get:
	netconf-console --rpc=nc-get-rpc.xml

nc-get-datax:
	netconf-console --rpc=nc-get-datax-rpc.xml

nc-get-datas:
	netconf-console --rpc=nc-get-datas-rpc.xml

nc-subscribe-hwstate:
	netconf-console --create-subscription=hardware_state

nc-cfg-card:
	netconf-console --rpc=nc-cfg-card-rpc.xml
	netconf-console --commit

nc-rename-chassis:
	netconf-console --rpc=nc-rename-chassis-rpc.xml
	netconf-console --commit

######################################################################
