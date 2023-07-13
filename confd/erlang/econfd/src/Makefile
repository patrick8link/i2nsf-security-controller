
all:	generated.hrl headers
	$(MAKE) iall

# maapi_proto.hrl is not available on Jenkins when building NSO tests,
# do not include the dependency if it is missing to avoid failing the
# build.
ifeq ($(shell test -e ../../confd/src/maapi_proto.hrl && echo true),true)
MAAPI_PROTO=../../confd/src/maapi_proto.hrl
endif
HEADERS=../include/econfd_maapi.hrl ./econfd_maapi_proto.hrl

../include/econfd_maapi.hrl: $(MAAPI_PROTO)
	@-export PATH=$(ERL_TOP)/installed/bin:$$PATH; \
	../gen-maapi-hrls public  ${MAAPI_PROTO} > $@;

./econfd_maapi_proto.hrl: $(MAAPI_PROTO)
	@-export PATH=$(ERL_TOP)/installed/bin:$$PATH; \
	../gen-maapi-hrls private ${MAAPI_PROTO} > $@;

include ../confdvsn.mk
include ../include.mk
include ../stderl.mk

headers: $(HEADERS)

generated.hrl: generated.hrl.src ../confd_lib.vsn ../confd_lib_proto.vsn
	v=`cat ../confd_lib.vsn`; \
	pv=`cat ../confd_lib_proto.vsn`; \
	sed -e "s/%lib_vsn%/$${v}/" -e "s/%lib_proto_vsn%/$${pv}/" $@.src > $@

clean:	iclean
	rm -f generated.hrl


