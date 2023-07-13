# This Makefile relies on being called from the parent (via doc target),
# e.g.: cd .. && make doc

ifeq ($(PYTHON),)
  PYTHON = $(shell which python3)
endif
ifeq ($(shell $(PYTHON) -c 'import pdoc' 2>/dev/null || echo false),false)
  USE_VENV = true
  PDOC_PYTHON = build-venv/bin/python
else
  PDOC_PYTHON = $(PYTHON)
endif

all: confd ncs

confd: confd/index.html

ncs: ncs/index.html

.PHONY: all confd ncs clean

# Ignore confd|ncs/__init__.py as it is always rebuilt
%/index.html: custom_pdoc/__init__.py ../_%/*.so ../_%/*.py ../%/[a-z]*.py
	@rm -rf $(dir $@)
	#$(PDOC_PYTHON) generate.py -- $(NCS_MODULES)
	$(PDOC_PYTHON) generate.py -- $* _$*

custom_pdoc/__init__.py: custom_pdoc/init.patch
ifeq ($(USE_VENV),true)
	@echo "Python pdoc3 module not found, installing it in build-venv/"
	$(PYTHON) -m venv build-venv
	build-venv/bin/pip install -r custom_pdoc/requirements.txt
endif
	cp -f `$(PDOC_PYTHON) -c 'import pdoc; print(pdoc.__file__)'` \
		custom_pdoc/
	patch custom_pdoc/__init__.py < custom_pdoc/init.patch

clean:
	@rm -rf confd ncs custom_pdoc/__init__.py build-venv
