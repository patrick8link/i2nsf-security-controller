DIRS = lux

all: test

build: clean
	for d in $(DIRS) ; do \
		(cd $$d && $(MAKE) build) || exit 1; \
	done


test:
	@cd lux && $(MAKE) bitten_lux_html --no-print-directory
	@error="" ; \
	for d in $(DIRS);  do \
		( cd $$d && $(MAKE) test;  \
	         ) || error="$$error $$d"; \
	done ; \
	if [ "$$error" ]; then \
		echo '***********************************' ; \
		echo '*** Failed test(s) (see above): ***' ; \
		echo '     ' $$error ; \
		echo '***********************************' ; \
		exit 1 ; \
	fi;


clean:
	for d in $(DIRS) ; do ( cd $$d &&  $(MAKE) clean) ; done

desc:
	@echo "Overview:"
	@echo "Tests of ECONFD API."
	@echo ""
	@$(MAKE) -C lux  lux_desc --no-print-directory

.PHONY: all build test clean
