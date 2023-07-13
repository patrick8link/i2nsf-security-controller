######################################################################
# Example showing use of external application providing encryption
# keys to ConfD.
#
# (C) 2019 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all      Build all example files"
	@echo "make clean    Remove all built and intermediary files"
	@echo "make start    Start ConfD daemon"
	@echo "make test     Run demo sequence"
	@echo "make stop     Stop any ConfD daemon and example agent"
	@echo "make cli      Start the ConfD Command Line Interface"

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

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd

SRC	= external_crypto_keys.c
OBJS	= $(SRC:.c=.o)
LIBS	+= $(LIBDIR) -lcrypto

all:	example.fxs external_crypto_keys confd.encryptedStrings $(CDB_DIR) ssh-keydir
	@echo "Build complete"

external_crypto_keys: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

gen_random=$(shell dd if=/dev/urandom bs=1 count=$(1) 2>/dev/null | xxd -ps)

confd.encryptedStrings:
	@echo "DES3CBC_KEY1=$(call gen_random,8)" > confd.encryptedStrings
	@echo "DES3CBC_KEY2=$(call gen_random,8)" >> confd.encryptedStrings
	@echo "DES3CBC_KEY3=$(call gen_random,8)" >> confd.encryptedStrings
	@echo "AESCFB128_KEY=$(call gen_random,16)" >> confd.encryptedStrings
	@echo "AES256CFB128_KEY=$(call gen_random,16)$(call gen_random,16)" >> confd.encryptedStrings

######################################################################
clean:	iclean
	-rm -rf external_crypto_keys confd.encryptedStrings 2> /dev/null || true
	-rm -rf *log cli-history 2> /dev/null || true

######################################################################
start:  stop
	@echo "### Start the confd daemon with our example specific confd-conf"
	$(CONFD) -c ./confd.conf $(CONFD_FLAGS)

load:
	confd_load -l -F x example_clear.xml

test:
	@$(MAKE) start
	@$(MAKE) load
	@$(MAKE) query
	@$(MAKE) stop

######################################################################
stop:
	@echo "###  Stop the confd daemon"
	$(CONFD) --stop    || true

######################################################################
cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

######################################################################
query:
	@$(CONFD_DIR)/bin/confd_cmd -c "mget /ex:strings/ex:string{1}/secret"
	@$(CONFD_DIR)/bin/confd_cmd -c "mget /ex:strings/ex:string{2}/secret"
	@$(CONFD_DIR)/bin/confd_cmd -c "mget /ex:strings/ex:string{3}/secret"

######################################################################
