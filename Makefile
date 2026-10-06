# piddigger — build, test and Debian packaging
# THUGS(red) · https://thugs.red

PREFIX  ?= /usr
DESTDIR ?=
TARGET  ?=
CARGO   ?= cargo

TARGET_FLAG = $(if $(TARGET),--target $(TARGET),)
BIN = target/$(if $(TARGET),$(TARGET)/,)release/piddigger

.PHONY: all build run demo test check fmt clippy deb install uninstall clean preview

all: build

build:
	$(CARGO) build --release --locked $(TARGET_FLAG)

run: build
	$(BIN)

demo: build
	$(BIN) --demo

test:
	$(CARGO) test --locked

check:
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings
	$(CARGO) test --locked

fmt:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy --locked --all-targets -- -D warnings

deb: build
	./scripts/package-deb.sh $(BIN)

install: build
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/piddigger
	install -Dm644 README.md $(DESTDIR)$(PREFIX)/share/doc/piddigger/README.md
	install -Dm644 docs/GUIDE.md $(DESTDIR)$(PREFIX)/share/doc/piddigger/GUIDE.md
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/doc/piddigger/copyright

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/piddigger
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/piddigger

preview: build
	python3 scripts/capture-preview.py

clean:
	$(CARGO) clean
	rm -rf dist
