# piddigger — build, test and Debian packaging
# THUGS(red) · https://thugs.red

PREFIX  ?= /usr
DESTDIR ?=
TARGET  ?=
CARGO   ?= cargo

TARGET_FLAG = $(if $(TARGET),--target $(TARGET),)
BIN = target/$(if $(TARGET),$(TARGET)/,)release/piddigger

.PHONY: all build run demo test check fmt clippy deb deb-bookworm apt-status apt-publish apt-verify install uninstall clean preview

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

# Release build in pinned Debian 12 userspace (needs docker), so the package
# installs on Debian 12 and newer. Writes the same dist/ file as `make deb`.
deb-bookworm:
	docker build -t piddigger-bookworm -f packaging/bookworm.Dockerfile packaging
	docker run --rm -u "$$(id -u):$$(id -g)" -v "$(CURDIR)":/workspace \
		-e CARGO_HOME=/workspace/target/bookworm/cargo-home piddigger-bookworm \
		sh -c 'cargo build --release --locked --target-dir target/bookworm && ./scripts/package-deb.sh target/bookworm/release/piddigger'

# Publish to apt.thugs.red (suite zerotrust). Publishes the .deb files already in
# dist/ for the Cargo.toml version, so run `make deb-bookworm` (or `make deb`)
# first. See scripts/apt-repo.py for the credential file; apt-verify needs none.
apt-status:
	python3 scripts/apt-repo.py status

apt-publish:
	python3 scripts/apt-repo.py publish

apt-verify:
	python3 scripts/apt-repo.py verify

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
