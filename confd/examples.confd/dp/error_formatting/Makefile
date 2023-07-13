######################################################################
# ConfD DP API error formatting callback example
# (C) 2018 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all     Build all example files"
	@echo "make clean   Remove all built and intermediary files"
	@echo "make start   Start ConfD daemon and example agent"
	@echo "make stop    Stop any ConfD daemon and example agent"
	@echo "make cli     Start the CONFD Command Line Interface, J-style"
	@echo "make cli-c   Start the CONFD Command Line Interface, C-style"

######################################################################
# Where is ConfD installed? Make sure CONFD_DIR points it out
CONFD_DIR ?= ../../..

# Include standard ConfD build definitions and rules
include $(CONFD_DIR)/src/confd/build/include.mk

# In case CONFD_DIR is not set (correctly), this rule will trigger
$(CONFD_DIR)/src/confd/build/include.mk:
	@echo 'Where is ConfD installed? Set $$CONFD_DIR to point it out!'
	@echo ''
	@exit 1

######################################################################
# Example specific definitions and rules

print-%  : ; @echo $* = $($*)

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd --addloadpath $(BUILD_DIR)/
START_FLAGS ?=

CINCLUDE_DIRS += $(CONFD_DIR)/include
CINCLUDE_DIRS += $(CONFD_DIR)/examples.confd/include
CINCLUDE_DIRS += $(BUILD_DIR)/

BUILD_DIR = ./build

DAEMON_BINARY = error-formatting-app

YANGS = $(wildcard *.yang)
FXSS = $(patsubst %.yang, $(BUILD_DIR)/%.fxs, $(YANGS))
HSS = $(FXSS:.fxs=.h)

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRCS))

CFLAGS += -I$(CONFD_DIR)/examples.confd/include -DT_LOG_TRACE

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.fxs: %.yang
	$(CONFDC) -o $@ -c $<

$(BUILD_DIR)/%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(addprefix -I, $(CINCLUDE_DIRS))

$(DAEMON_BINARY): $(HSS) $(OBJS)
	$(CC) -o $(BUILD_DIR)/$@ $(OBJS) $(LIBS)

all:	$(BUILD_DIR) $(FXSS) $(DAEMON_BINARY) $(CDB_DIR) ssh-keydir
	@echo "Build complete"

######################################################################
ITEMS_TO_CLEAN = $(BUILD_DIR) cli-history/

clean:	iclean
	-rm -rf $(ITEMS_TO_CLEAN) 2> /dev/null || true

start:  stop
	$(CONFD) --ignore-initial-validation -c confd.conf $(CONFD_FLAGS)
	# app daemon starts in this thread running in infinite loop!
	# use another shell session to run e.g. CLI or NETCONF query towards
	# the running ConfD instance.
	$(BUILD_DIR)/$(DAEMON_BINARY) 2>&1 $(START_FLAGS)

######################################################################
stop:
	$(CONFD) --stop    || true
	$(KILLALL) $(DAEMON_BINARY) || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit
