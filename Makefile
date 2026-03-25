SCRIPT   = python3 nginx_to_ols.py
QUIET    =
VERBOSE  =

ifdef q
QUIET    = --quiet
endif
ifdef quiet
QUIET    = --quiet
endif
ifdef v
VERBOSE  = --verbose
endif
ifdef verbose
VERBOSE  = --verbose
endif

FLAGS    = $(QUIET) $(VERBOSE)

.PHONY: preview apply apply-public help

## Run a dry-run preview (default)
preview:
	$(SCRIPT) $(FLAGS)

## Apply migration to live OLS config
apply:
	$(SCRIPT) --apply -y $(FLAGS)

## Apply only public sites (ports 80/443), patch OLS user/group
apply-public:
	$(SCRIPT) --use-nginx-user-group --only-public-sites --apply -y $(FLAGS)

## Show script help
help:
	$(SCRIPT) --help
