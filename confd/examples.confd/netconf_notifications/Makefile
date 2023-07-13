######################################################################
# NETCONF Notification example
# (C) 2006-2021 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all              	 Build all example files"
	@echo "make clean            	 Remove all built and intermediary files"
	@echo "make start            	 Start ConfD daemon and example notifier app using the builtin"
	@echo "                      	 replay store"
	@echo "make start-py         	 Start ConfD daemon and Python example notifier app using the"
	@echo "                      	 builtin replay store"
	@echo "make start-builtin    	 Start ConfD daemon and example notifier app using the builtin"
	@echo "                      	 replay store"
	@echo "make start-builtin-py 	 Start ConfD daemon and Python example notifier app using the"
	@echo "                      	 builtin replay store"
	@echo "make start-external   	 Start ConfD daemon and example notifier app using an external"
	@echo "                      	 replay store"
	@echo "make stop             	 Stop any ConfD daemon and example notifier app"
	@echo "make nc-query         	 Run NETCONF query against ConfD"
	@echo "make nc-subscribe         Subscribe for the interface stream using NETCONF"
	@echo "make nc-subscribe-rfc8639 Subscribe for the interface stream using NETCONF RFC 8639"
	@echo "                          add-ons"
	@echo "make nc-replay            Replay the interface stream using NETCONF"
	@echo "make nc-replay-rfc8639    Replay the interface stream using NETCONF RFC 8639 add-ons"
	@echo "make nc-filter            Replay the interface stream with a filter using NETCONF"
	@echo "make nc-filter-rfc8639    Replay the interface stream with a filter using NETCONF"
	@echo "                          RFC 8639 filter and add-ons"
	@echo "make nc-subscribe-netconf Subscribe for the NETCONF stream using the NETCONF protocol"
	@echo "make cli     	     	 Start the CONFD Command Line Interface"
	@echo "make cli-c   	     	 Start the CONFD Command Line Interface, C-style"
	@echo "make cli-j   	     	 Start the CONFD Command Line Interface, J-style"

######################################################################
# Where is ConfD installed? Make sure CONFD_DIR points it out
CONFD_DIR ?= ../../..

# Include standard ConfD build definitions and rules
include $(CONFD_DIR)/src/confd/build/include.mk

# In case CONFD_DIR is not set (correctly), this rule will trigger
$(CONFD_DIR)/src/confd/build/include.mk:
	@echo 'Where is ConfD installed? Set $$CONFD_DIR to point it out!'
	@echo ''

######################################################################
# Example specific definitions and rules
CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd

CFLAGS	+= $(EXPAT_INC)
LIBS	+= $(EXPAT_LIB)

all: notifier notifier_builtin_replay_store notif.fxs notif_ns.py $(CDB_DIR) ssh-keydir
	@echo "Build complete"

notifier: notifier.o
	 $(CC) notifier.o $(LIBS) $(CFLAGS) -ansi -pedantic -o $@

notifier.o: notifier.c notif.h

notifier_builtin_replay_store: notifier_builtin_replay_store.o
	 $(CC) notifier_builtin_replay_store.o $(LIBS) $(CFLAGS) -o $@

notifier_builtin_replay_store.o: notifier_builtin_replay_store.c notif.h

%.h: %.fxs
	$(CONFDC) --emit-h $*.h $<

######################################################################
clean:	iclean
	-rm -rf notifier notifier_builtin_replay_store *.h notif_ns.py *.pyc\
		__init__.py __pycache__ interface.* confd_prim.conf netconf.trace 2>\
		/dev/null || true

start:  start-builtin

start-builtin:  stop
	sed 's/[ \t]*<!-- enableBuiltinReplayStore -->/          <enabled>true<\/enabled>/' confd.conf > confd_prim.conf
	$(CONFD) -c ./confd_prim.conf $(CONFD_FLAGS)
	LD_LIBRARY_PATH=$(CONFD_SO) ./notifier_builtin_replay_store -t

startw:  stop
	sed 's/[ \t]*<!-- enableBuiltinReplayStore -->/          <enabled>true<\/enabled>/' confd.conf > confd_prim.conf
	$(CONFD) -c ./confd_prim.conf $(CONFD_FLAGS) -w
	LD_LIBRARY_PATH=$(CONFD_SO) ./notifier_builtin_replay_store -t

starti:  stop
	sed 's/[ \t]*<!-- enableBuiltinReplayStore -->/          <enabled>true<\/enabled>/' confd.conf > confd_prim.conf
	$(CONFD) -c ./confd_prim.conf $(CONFD_FLAGS) -i

start-notif:
	LD_LIBRARY_PATH=$(CONFD_SO) ./notifier_builtin_replay_store -t

start-external:  stop
	sed 's/[ \t]*<!-- enableBuiltinReplayStore -->/          <enabled>false<\/enabled>/' confd.conf > confd_prim.conf
	$(CONFD) -c ./confd_prim.conf $(CONFD_FLAGS)
	LD_LIBRARY_PATH=$(CONFD_SO) ./notifier -t

start-py: start-builtin-py

start-builtin-py:  stop
	sed 's/[ \t]*<!-- enableBuiltinReplayStore -->/          <enabled>true<\/enabled>/' confd.conf > confd_prim.conf
	$(CONFD) -c ./confd_prim.conf $(CONFD_FLAGS)
	$(PYTHON) ./notifier_builtin_replay_store.py --debuglevel t

######################################################################
stop:
	### Stopping any confd daemon
	$(CONFD) --stop || true
ifeq ($(shell uname -s),Darwin)
	$(KILLALL) -m notifier || true
else
	$(KILLALL) -r notifier || true
endif

######################################################################
nc-query:
	$(CONFD_DIR)/bin/netconf-console --get -x netconf

nc-subscribe:
	$(CONFD_DIR)/bin/netconf-console -s all sub_rfc5277.xml

nc-subscribe-rfc8639:
	$(CONFD_DIR)/bin/netconf-console -s all sub_rfc8639.xml

nc-replay:
	$(CONFD_DIR)/bin/netconf-console -s all replay_rfc5277.xml

nc-replay-rfc8639:
	$(CONFD_DIR)/bin/netconf-console -s all replay_rfc8639.xml

nc-subscriptions:
	$(CONFD_DIR)/bin/netconf-console --get -x /subscriptions

nc-filter:
	$(CONFD_DIR)/bin/netconf-console -s all filter_rfc5277.xml

nc-filter-rfc8639:
	$(CONFD_DIR)/bin/netconf-console -s all filter_rfc8639.xml

nc-subscribe-netconf:
	$(CONFD_DIR)/bin/netconf-console --create-subscription=NETCONF

edit-config1:
	$(CONFD_DIR)/bin/netconf-console --edit-config=edit1.xml

edit-config2:
	$(CONFD_DIR)/bin/netconf-console --edit-config=edit2.xml

######################################################################

cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user=admin --groups=admin \
		--interactive || echo Exit

cli-j:
	$(CONFD_DIR)/bin/confd_cli -J --user=admin --groups=admin \
		--interactive || echo Exit
