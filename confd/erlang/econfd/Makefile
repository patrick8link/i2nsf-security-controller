include ./include.mk
include ./confdvsn.mk

DIRS = src
EDIRS = examples/procs examples/simple_notrans examples/test # examples/yaws
all: app examp

TAR ?= tar

app: headers
	set -e ; \
	for d in $(DIRS) ; do	\
		( cd $$d &&  $(MAKE)) || exit 1; \
	done

examp:
	set -e; \
	for d in $(EDIRS) ; do \
		(cd $$d && $(MAKE) all) || exit 1; \
	done

# maapi_proto.hrl is not available on Jenkins when building NSO tests,
# do not include the dependency if it is missing to avoid failing the
# build.
ifeq ($(shell test -e ../confd/src/maapi_proto.hrl && echo true),true)
MAAPI_PROTO=../confd/src/maapi_proto.hrl
endif
HEADERS=./include/econfd_maapi.hrl ./src/econfd_maapi_proto.hrl

./include/econfd_maapi.hrl: $(MAAPI_PROTO)
	@-export PATH=$(ERL_TOP)/installed/bin:$$PATH; \
	./gen-maapi-hrls public  $(MAAPI_PROTO) > $@;

./src/econfd_maapi_proto.hrl: $(MAAPI_PROTO)
	@-export PATH=$(ERL_TOP)/installed/bin:$$PATH; \
	./gen-maapi-hrls private $(MAAPI_PROTO) > $@;

headers: $(HEADERS)

clean:
	@set -e ;						\
	for d in $(DIRS) $(EDIRS) ;  do				\
		( cd $$d &&  $(MAKE) clean) || exit 1;	\
	done

distclean: clean
	rm -f ./include/econfd_maapi.hrl
	rm -f ./src/econfd_maapi_proto.hrl

DIST_FILE = confd-$(CONFDVSN).econfd.tar

dist:
	$(MAKE) clean
	cd .. && $(TAR) c -h \
		--exclude '*.svn' \
		--exclude '*~' \
		--exclude .gitignore \
		--exclude Makefile.release \
		--exclude gen-maapi-hrls \
		-f $(DIST_FILE) econfd && gzip -9 $(DIST_FILE)
