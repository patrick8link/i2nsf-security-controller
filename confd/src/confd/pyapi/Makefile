# Makefile for building ConfD/NCS Python API
#
# This Makefile builds the Python API using the same compiler and
# linker options that was used when building Python itself by
# utilizing distutils through build.py.
#
# Just typing 'make' should build everything correctly for both
# release builds and local builds.
#
# In addition there are targets to build specific parts of the library:
#
# confd-py3: only build the ConfD parts for Python 3
# ncs-py3: only build the NCS parts for Python 3
# doc: build the HTML documentation
#

ifneq ($(CONFD_DIR),)
	TOP_DIR = $(CONFD_DIR)
	PY_SRC=$(CONFD_DIR)/src/confd/pyapi
else
ifneq ($(NCS_DIR),)
	TOP_DIR = $(NCS_DIR)
	PY_SRC = $(NCS_DIR)/src/ncs/pyapi
else
	TOP_DIR = $(PWD)/../../confd_dir
	PY_SRC = $(TOP_DIR)/src/confd/pyapi
endif
endif

# If BUILD_NCS is set to true the NSO part of the API will be built.
# Also a couple of namespace files will be generated.
NCS_DM_DIR = ../ncs/dm
# ConfD release build
ifeq ($(BUILDNCS),false)
	BUILD_NCS = false
else
# ConfD source release builds
ifeq ($(wildcard $(NCS_DM_DIR)/.),)
	BUILD_NCS = false
else
# NSO release build or local build
	BUILD_NCS = true
endif
endif

ifeq ($(V),1)
    Q=
else
    Q=@
endif

# Only used when building the NSO part of the API.
NCSC = ../../bin/ncsc
NCS_SYMBOLS = ncs/ns/ncs_ns.py ncs/ns/netconf_ncs_ns.py
FXS_DIR = tmp_fxs
DIRS = ncs/ns $(FXS_DIR)

OSNAME:=$(shell uname -s)

PYTHON_VERS = python3.10 python3.9 python3.8 python3.7 python3
ifneq ($(BUILDRELEASE),true)
# If pyenv is installed - just take the appointed Python
  ifeq ($(PYTHON),)
    PYENV:=$(shell which pyenv)
    ifneq ($(PYENV),)
      PYTHON = $(shell pyenv which python3)
    endif
  endif

  # For local builds we use the latest Python3 version found on the system,
  # if pyenv does not select a specific version
  ifeq ($(PYTHON),)
    PYTHON=$(shell which $(PYTHON_VERS) 2>/dev/null | sort -t '.' -k 2nr | head -n 1)
  endif
else
# Python 3.7 is used for release builds but since the world has long moved on
# and sometimes engineers need to build releases locally - allow them set it
    ifeq ($(TAILF_ANYPYTHON),)
        PYTHON = $(shell which python3.7 2>/dev/null)
    else
        PYTHON = $(shell which $(TAILF_ANYPYTHON))
    endif
endif

SRC = src/common.c \
      src/_cdb.c \
      src/_dp.c \
      src/_events.c \
      src/_ha.c \
      src/_error.c \
      src/_lib.c \
      src/_maapi.c \
      src/types.c \
      src/types_iter.c

ifneq ($(CONFD_PY_EXT_API_TIMING),)
SRC += src/ext_api_timing.c
endif

PYAPI_NCS_DIR = _ncs
PYAPI_CONFD_DIR = _confd

NCS_SRC = $(SRC) $(PYAPI_NCS_DIR)/_ncs.c
CONFD_SRC = $(SRC) $(PYAPI_CONFD_DIR)/_confd.c

INC = include/_cdb.h \
      include/_dp.h \
      include/_events.h \
      include/_ha.h \
      include/_error.h \
      include/_lib.h \
      include/_maapi.h \
      include/confdpy_config.h \
      include/confdpy_err.h \
      include/types.h \
      include/types_iter.h \
      doc/src/cdb_doc.c \
      doc/src/dp_doc.c \
      doc/src/events_doc.c \
      doc/src/ha_doc.c \
      doc/src/lib_doc.c \
      doc/src/maapi_doc.c \
      doc/src/types_doc.c \
      doc/src/error_doc.c

CONFD_PY2_SO := $(PYAPI_CONFD_DIR)/_confd_py2.so
CONFD_PY3_SO := $(PYAPI_CONFD_DIR)/_confd_py3.abi3.so

NCS_PY2_SO := $(PYAPI_NCS_DIR)/_ncs_py2.so
NCS_PY3_SO := $(PYAPI_NCS_DIR)/_ncs_py3.abi3.so

ifeq ($(TAILF_BUILD),local)
	INC += ../capi/c_src/include/confd_lib.h
	LIBCONFD_SO_DEP = ../capi/c_src/src/libconfd.so
else
	LIBCONFD_SO_DEP =
endif

-include ../../support/include.mk

# Python may be skipped
ifeq ($(SKIP_PYTHON),true)
	TARGETS = skip-python
else					# Ok then, we should proceed with build
ifeq ($(BUILDRELEASE),true)		# We are building a release
ifeq ($(PYTHON),)			# Ouch, no python 3 for release builds
	TARGETS = skip-no-py3 fail-py
else					# python3 OK
	TARGETS += version confd-py3
ifeq ($(BUILD_NCS),true)
	TARGETS += ncs-py3
endif
	ADD_LTH = true
endif
else					# This is a local build
ifeq ($(PYTHON),)			# No python 3 at all
	TARGETS += skip-no-py3
else					# python3 OK
	TARGETS = version
ifneq ($(CONFD_DIR),)
	TARGETS += confd-py3
endif
ifneq ($(NCS_DIR),)
ifeq ($(BUILD_NCS),true)
	TARGETS += ncs-py3
endif
endif
	ADD_LTH = true
endif
endif
ifeq ($(ADD_LTH),true)
# A release install does not have low_to_high.py so ignore it
ifneq ($(wildcard low_to_high.py),)
	TARGETS += low-to-high
endif
endif
endif

CONFD_SO_RPATH_BASE=../../confd_dir/lib
NCS_SO_RPATH_BASE=../../ncs_dir/lib
ifeq ($(BUILDRELEASE),true)
    CONFD_SO_RPATH = ../../../../lib
    NCS_SO_RPATH = ../../../../lib
else
    CONFD_SO_RPATH = ../$(CONFD_SO_RPATH_BASE)
    NCS_SO_RPATH = ../$(NCS_SO_RPATH_BASE)
endif

all: $(TARGETS)

version:
	@echo "BUILD_PYTHON3 $(shell ${PYTHON} --version 2>&1|cut -f2 -d' ' 2>/dev/null)" > VERSION
skip-python:
	@echo "*** Not building Python API (SKIP_PYTHON=true)"

skip-no-py3:
	@echo "*** Not building Python 3 API (no useful Python 3 installation found)"
ifeq ($(BUILDRELEASE),true)
	@echo "    (For release builds Python 3.7 is required)"
else
	@echo "    (For local builds Python 3.7 or higher is required)"
endif

fail-py:
	@echo "    You may set SKIP_PYTHON=true to skip the Python API build."
	@exit 1

# '_confd' top module name

TGT:=$(shell $(CC) -dumpmachine)
# this particular subst is for FreeBSD where "uname -m" is amd64
# we won't discuss support for FreeBSD here
HOST:=$(subst amd64,x86_64,$(shell uname -m))
CROSS=$(if $(findstring $(HOST),$(TGT)),0,1)

# This is specific for distutils, the bug in their sysconfig takes wrong
# LDSHARED (native) if not set explicitly
ifeq ($(LDSHARED),)
# We can't rely on CC != gcc since it can be set to clang/cc,which does not mean
# cross-build
    ifeq ($(CROSS),1)
        ADD_LDSHARED=LDSHARED="$(CC) -pthread -shared"
    endif
else
    ADD_LDSHARED=LDSHARED="$(LDSHARED)"
endif

confd-py3: $(CONFD_PY3_SO)

$(CONFD_PY3_SO): $(CONFD_SRC) $(INC) $(LIBCONFD_SO_DEP)
	PROD=ConfD $(MAKE) src/gen_add_lib_const.c
	# Clean all Python 3 so files, including possible leftovers. Possibly built
	# with a previous Python 3 version, which might make them differ in naming.
	$(Q)rm -f $(PYAPI_CONFD_DIR)/_confd_py3*.so
	@echo "Building ConfD Python 3.x bindings"
ifneq ($(OSNAME),Darwin)
	$(Q)env TOP_DIR=$(TOP_DIR) PY_SRC=$(PY_SRC) SRC="$(CONFD_SRC)" \
	     INC="$(INC)" PROD=ConfD PYVER=py3 RTPATH="$(CONFD_SO_RPATH)" \
	     CBASE_FLAGS="$(CBASE_FLAGS)" $(ADD_LDSHARED) \
	  $(PYTHON) build.py build_ext --build-temp build/$@ --build-lib .
	$(Q)mv $(PYAPI_CONFD_DIR)/_confd_py3*.so $(CONFD_PY3_SO)
else
	$(Q)env TOP_DIR=$(TOP_DIR) PY_SRC=$(PY_SRC) SRC="$(CONFD_SRC)" \
	     INC="$(INC)" PROD=ConfD PYVER=py3 \
	     CBASE_FLAGS="$(CBASE_FLAGS)" \
	  $(PYTHON) build.py build_ext --build-temp build/$@ --build-lib .
	$(Q)mv $(PYAPI_CONFD_DIR)/_confd_py3*.so $(CONFD_PY3_SO)
	install_name_tool -change libconfd.so \
	@loader_path/$(CONFD_SO_RPATH)/libconfd.so \
	$(CONFD_PY3_SO)
endif

# '_ncs' top module name

ncs-py3: $(NCS_PY3_SO) $(NCS_SYMBOLS)

$(NCS_PY3_SO): $(NCS_SRC) $(INC) $(LIBCONFD_SO_DEP)
	PROD=NCS $(MAKE) src/gen_add_lib_const.c
	# Clean all Python 3 so files, including possible leftovers. Possibly built
	# with a previous Python 3 version, which might make them differ in naming.
	$(Q)rm -f $(PYAPI_NCS_DIR)/_ncs_py3*.so
	@echo "Building NCS Python 3.x bindings"
ifneq ($(OSNAME),Darwin)
	$(Q)env TOP_DIR=$(TOP_DIR) PY_SRC=$(PY_SRC) SRC="$(NCS_SRC)" \
	     INC="$(INC)" PROD=NCS PYVER=py3 RTPATH="$(NCS_SO_RPATH)" \
	     CBASE_FLAGS="$(CBASE_FLAGS)" $(ADD_LDSHARED) \
	  $(PYTHON) build.py build_ext --build-temp build/$@ --build-lib .
	$(Q)mv $(PYAPI_NCS_DIR)/_ncs_py3*.so $(NCS_PY3_SO)
else
	$(Q)env TOP_DIR=$(TOP_DIR) PY_SRC=$(PY_SRC) SRC="$(NCS_SRC)" \
	     INC="$(INC)" PROD=NCS PYVER=py3 \
	     CBASE_FLAGS="$(CBASE_FLAGS)" \
	  $(PYTHON) build.py build_ext --build-temp build/$@ --build-lib .
	$(Q)mv $(PYAPI_NCS_DIR)/_ncs_py3*.so $(NCS_PY3_SO)
	install_name_tool -change libconfd.so \
	@loader_path/$(NCS_SO_RPATH)/libconfd.so \
	$(NCS_PY3_SO)
endif

# Generating python symbols for NSO

$(DIRS):
	mkdir $@

ncs/ns/%.py: | ncs/ns
	$(NCSC) --emit-python $@ $<

ncs/ns/netconf_ncs_ns.py: $(FXS_DIR)/tailf-netconf-ncs.fxs
ncs/ns/ncs_ns.py: $(FXS_DIR)/tailf-ncs.fxs

$(FXS_DIR)/%.fxs: | $(FXS_DIR)
	$(NCSC) -c -o $@ -- $<

$(FXS_DIR)/tailf-netconf-ncs.fxs: $(NCS_DM_DIR)/tailf-netconf-ncs.yang
$(FXS_DIR)/tailf-ncs.fxs: $(NCS_DM_DIR)/tailf-ncs.yang \
                       $(wildcard $(NCS_DM_DIR)/tailf-ncs*.yang) # submodules

# Misc

gen-const-clean:
	rm -f   src/gen_add_*_const.c

# $CC can't be used here directly to select gcc vs clang since it can be set to just 'cc'
# So I invented this way to select which we are using. If there is a cleaner/more clever way
# - I'm happy to learn it
COMPILER=$(shell $(CC) -E -dM - < /dev/null | grep -i vers | grep clang)
ifeq ($(COMPILER),)
  COMPILER=gcc
else
  COMPILER=clang
endif
ifneq ($(PYTHON),)
.PHONY: src/gen_add_lib_const.c
src/gen_add_lib_const.c: $(patsubst %, \
                       $(TOP_DIR)/include/%, \
                       $(shell $(PYTHON) ./gen-constants.py -p))
	$(Q)$(PYTHON) ./gen-constants.py $(TOP_DIR)/include $(COMPILER)
endif

# Tests

all-tests-all-versions:
	$(MAKE) all-confd-py3-tests
	$(MAKE) all-ncs-py3-tests

all-confd-py3-tests: clean confd-py3
	$(MAKE) -C test/lux/unittest TEST_NAME="ConfD PY3" all-tests-py3

all-ncs-py3-tests: clean ncs-py3
	$(MAKE) -C test/lux/unittest TEST_NAME="NCS PY3" all-tests-py3


.PHONY: doc
doc: all
	env PYTHONPATH=$(PY_SRC):$(PYTHONPATH) PYTHON=$(PYTHON) $(MAKE) -C doc

low-to-high:
	$(Q)env LD_LIBRARY_PATH=$(CONFD_SO_RPATH_BASE):$(NCS_SO_RPATH_BASE) \
		 DYLD_LIBRARY_PATH=$(CONFD_SO_RPATH_BASE):$(NCS_SO_RPATH_BASE) \
		 $(PYTHON) low_to_high.py $(BUILD_NCS)

.PHONY: clean
clean: gen-const-clean
	rm -rf build MANIFEST _tmp_* $(DIRS) VERSION
	# Do not remove __init__.py if there's no way to rebuild it (release installs)
	test -f low_to_high.py && rm -f ncs/__init__.py confd/__init__.py || true
	-find . -name "__pycache__" -o -name "*.pyc" \
			-o -name "*.so" | xargs rm -rf
	$(MAKE) -k -C test clean || true
	$(MAKE) -k -C doc clean || true
