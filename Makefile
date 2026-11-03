EMACS ?= emacs
LOAD_PATH = -L .

FILES = lispm-auth.el

.PHONY: test compile native native-debug native-test

# Build the bundled crypto module; Cargo is needed only by builders.
native-debug:
	cargo build --locked --manifest-path native/Cargo.toml

native:
	cargo build --locked --release --manifest-path native/Cargo.toml

native-test:
	cargo test --locked --manifest-path native/Cargo.toml

# Each store is tested in a directory of its own.
test: native-debug
	$(EMACS) -Q --batch $(LOAD_PATH) --eval '(setq native-comp-enable-subr-trampolines nil)' \
	  -l test/lispm-auth-test.el -f ert-run-tests-batch-and-exit

# A check: the .elc files are removed again, as they would shadow the
# sources of a checkout Emacs loads from.
compile:
	$(EMACS) -Q --batch -L . --eval '(setq byte-compile-error-on-warn t)' \
	  -f batch-byte-compile $(FILES); \
	status=$$?; rm -f *.elc; exit $$status
