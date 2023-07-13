###-*-makefile-*-   ; force emacs to enter makefile-mode

ERL       =  erl
ERLC      =  $(CONFD_DIR)/bin/erlc
CONFD     =  $(CONFD_DIR)/bin/confd
CONFDC     = $(CONFD_DIR)/bin/confdc

ERLC_FLAGS=-W

ifeq ($(TYPE), debug)
  ERLC_FLAGS+=+debug_info -Ddebug
endif

ifeq ($(TYPE), dialyzer)
  ERLC_FLAGS+=+debug_info
endif

ERL_SOURCES  := $(wildcard *.erl) $(wildcard deps/*.erl)
ERL_HEADERS += $(wildcard *.hrl) $(wildcard ../include/*.hrl)
ERL_OBJECTS := $(patsubst %.erl, ../ebin/%.beam, $(ERL_SOURCES:deps/%=%))
MODULES     := $(notdir $(ERL_SOURCES:%.erl=%))


APP_SOURCES := $(wildcard *.app.src)
APP_OBJECTS := $(APP_SOURCES:%.app.src=../ebin/%.app)

APPNAME := $(APP_SOURCES:%.app.src=%)


# This Perl script can be replaced by support/app_script.py with same invocation
# Kept the Perl script here as Econfd is compiled outside of ConfD source tree.
APPSCRIPT = '$$vsn=shift; $$mods=""; while(@ARGV){ $$_=shift; s/^([A-Z].*)$$/\'\''$$1\'\''/; $$mods.=", " if $$mods; $$mods .= $$_; } while(<>) { s/%VSN%/$$vsn/; s/%MODULES%/$$mods/; print; }'

EDOC_OPTS=[{dir,"../doc/"},{todo,true},{preprocess,true},no_subpackages]

# Erlang Targets

../ebin/%.app: %.app.src ../confdvsn.mk Makefile
	perl -e $(APPSCRIPT) "$(CONFDVSN)" $(MODULES) < $< > $@

../ebin/%.beam: %.erl
	$(ERLC) $(ERLC_FLAGS) -o ../ebin $<

../ebin/%.beam: deps/%.erl
	$(ERLC) $(ERLC_FLAGS) -o ../ebin $<

../ebin/%.beam: %.yrl
	$(ERLC) $<
	$(ERLC) $(ERLC_FLAGS) -o ../ebin $*.erl
	rm -f $*.erl
