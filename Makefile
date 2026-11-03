EMACS ?= emacs
ECL ?= ecl
PYTHON ?= python3
SODIUM_PREFIX ?= /usr
SERVICE ?= $(CURDIR)/build/lispm-auth-service
VERSION ?= v0.2.0
LOAD_PATH = -L .
FILES = lispm-auth.el

.PHONY: service test compile crypto-test package packaging-test

service:
	SODIUM_PREFIX="$(SODIUM_PREFIX)" $(ECL) --norc --load common-lisp/build.lisp

crypto-test:
	LISPM_AUTH_SERVICE="$(SERVICE)" $(PYTHON) common-lisp/test.py

# Requiring an executable prevents a green test run with skipped integration tests.
test:
	test -x "$(SERVICE)"
	LISPM_AUTH_SERVICE="$(SERVICE)" $(EMACS) -Q --batch $(LOAD_PATH) \
	  --eval '(setq native-comp-enable-subr-trampolines nil)' \
	  -l test/lispm-auth-test.el -l test/lispm-auth-install-test.el \
	  -f ert-run-tests-batch-and-exit

packaging-test:
	$(PYTHON) -m unittest discover -s test -p 'test_*.py'

package:
	$(PYTHON) scripts/package-service.py --binary "$(SERVICE)" --version "$(VERSION)" --output dist

# Remove compiled files so checkout loads cannot shadow the sources.
compile:
	$(EMACS) -Q --batch -L . --eval '(setq byte-compile-error-on-warn t)' \
	  -f batch-byte-compile $(FILES); \
	  status=$$?; rm -f *.elc; exit $$status
