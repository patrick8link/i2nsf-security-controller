######################################################################
# Crypto2 example
# (C) 2006 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all      Build all example files"
	@echo "make clean    Remove all built and intermediary files"
	@echo "make start    Start ConfD daemon"
	@echo "make get      Show database contents"
	@echo "make decrypt  Show key and decrypt secrets"
	@echo "make set      Initialize database with secrets"
	@echo "make scramble Decrypt, change key, re-encrypt secrets"
	@echo "make test     Run demo sequence"
	@echo "make stop     Stop any ConfD daemon and example agent"
	@echo "make query    Run query against ConfD"
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

SRC	= crypto_keys.c
OBJS	= $(SRC:.c=.o)
LIBS	+= $(LIBDIR) -lcrypto

# Initial DES3 AES128 and AEAS256 keys
DES3KEY1 = 0123456789abcdef
DES3KEY2 = 0123456789abcdef
DES3KEY3 = 0123456789abcdef
AES128KEY = 0123456789abcdef0123456789abcdef
AES256KEY = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef


NOW  = `date +%s`

all:	not_sunos smp.fxs smp.h crypto_keys confd.conf $(CDB_DIR) ssh-keydir
	@echo "Build complete"

confd.conf: confd.conf.in
	sed -e "s/%%DES3KEY1%%/$(DES3KEY1)/g" \
	-e "s/%%DES3KEY2%%/$(DES3KEY2)/g" \
	-e "s/%%DES3KEY3%%/$(DES3KEY3)/g" \
	-e "s/%%AES128KEY%%/$(AES128KEY)/g" \
	-e "s/%%AES256KEY%%/$(AES256KEY)/g" < $< > $@

crypto_keys: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

crypto_keys.o: smp.h

######################################################################
clean:	iclean
	-rm -rf smp.h crypto_keys confd.conf TOP_SECRET \
		2> /dev/null || true
	-rm -rf *log cli-history 2> /dev/null || true

######################################################################
start:  stop
	@echo "### Start the confd daemon with our example specific confd-conf"
	$(CONFD) -c ./confd.conf $(CONFD_FLAGS)

test:
	@$(MAKE) start
	@$(MAKE) set
	@$(MAKE) get
	@$(MAKE) decrypt
	@$(MAKE) scramble
	@$(MAKE) get
	@$(MAKE) decrypt

set:
	@echo "### Adding some secret information to the database"
	$(CONFD_DIR)/bin/netconf-console cmd-initialize-secret.xml

get:
	@echo "### This is what is stored in the database"
	$(CONFD_DIR)/bin/netconf-console --get -snoaaa

decrypt:
	@echo "### If you have the decryption key, you can decrypt the secrets"
	@echo "### The current key in confd.conf is:"
	@grep "<key>" confd.conf
	@echo "### The decrypted secrets are:"
	./crypto_keys -g

scramble:
	@echo "### Will now decrypt secrets to a temporary file, then generate"
	@echo "    a new crypto key, restart ConfD and inject the secrets"
	@echo "    Finally, the temporary file is deleted"
	@echo ""
	@echo "### Save the clear-text strings in the file TOP_SECRET"
	./crypto_keys -g > TOP_SECRET
	@echo ""
	@$(MAKE) stop
	@echo ""
	@echo "### Generate and install new encryption key into confd.conf"
	@rm -f confd.conf
	@$(MAKE) AESKEY=fedcba9876543210fedcb9$(NOW) DES3KEY1=fedcba$(NOW) \
	DES3KEY2=fedcba$(NOW) DES3KEY3=fedcba$(NOW) \
	AES128KEY=fedcba9876543210fedcba$(NOW) \
	AES256KEY=fedcba9876543210fedcba9876543210fedcba9876543210fedcba$(NOW) \
	confd.conf
	@echo ""
	@echo "### Restart confd daemon"
	$(CONFD) -c ./confd.conf $(CONFD_FLAGS)
	@echo ""
	@echo "### Now install saved strings from the TOP_SECRET file"
	./crypto_keys -s < TOP_SECRET
	rm -f TOP_SECRET
	@echo ""
	@echo "### The original clear-text strings are now stored encrypted"
	@echo "### with the new encryption key"

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
	$(CONFD_DIR)/bin/netconf-console -snoaaa --get

######################################################################
