# SPDX-License-Identifier: LGPL-2.1-or-later

PREFIX ?= /usr
DESTDIR ?=

BINDIR := $(DESTDIR)$(PREFIX)/bin
LIBEXECDIR := $(DESTDIR)$(PREFIX)/libexec
SYSTEMD_UNITDIR := $(DESTDIR)$(PREFIX)/lib/systemd/system
TMPFILESDIR := $(DESTDIR)$(PREFIX)/lib/tmpfiles.d
DBUS_POLICYDIR := $(DESTDIR)$(PREFIX)/share/dbus-1/system.d
DBUS_SERVICEDIR := $(DESTDIR)$(PREFIX)/share/dbus-1/system-services
POLKIT_DIR := $(DESTDIR)$(PREFIX)/share/polkit-1/actions
BASH_COMPDIR := $(DESTDIR)$(PREFIX)/share/bash-completion/completions
ZSH_COMPDIR := $(DESTDIR)$(PREFIX)/share/zsh/site-functions
FISH_COMPDIR := $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
DOCDIR := $(DESTDIR)$(PREFIX)/share/doc/kestrel
SYSCONFDIR := $(DESTDIR)/etc/kestrel

CARGO ?= cargo
TARGET_DIR := $(or $(CARGO_TARGET_DIR),target)

.PHONY: all build check test test-e2e install uninstall clean

all: build

build:
	$(CARGO) build --release -p kestrel-daemon -p kestrel-cli

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) check -p kestrel-api --no-default-features
	$(CARGO) check -p kestrel-api --no-default-features --features client
	$(CARGO) check -p kestrel-wlan-wpa --no-default-features
	$(CARGO) check -p kestrel-wlan-iwd --no-default-features
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps
	./scripts/check-system-files.sh

test:
	$(CARGO) test --workspace --all-features

test-e2e:
	./crates/kestrel-e2e/run.sh

install: build
	install -Dm755 $(TARGET_DIR)/release/kestrel $(BINDIR)/kestrel
	install -Dm755 $(TARGET_DIR)/release/kestrel-daemon $(LIBEXECDIR)/kestrel-daemon
	install -d $(SYSTEMD_UNITDIR)
	sed -e 's#/usr/libexec/kestrel-daemon#$(PREFIX)/libexec/kestrel-daemon#g' \
	    -e 's#/usr/share/doc/kestrel#$(PREFIX)/share/doc/kestrel#g' \
	    data/kestrel.service > $(SYSTEMD_UNITDIR)/kestrel.service
	chmod 644 $(SYSTEMD_UNITDIR)/kestrel.service
	install -Dm644 data/kestrel.tmpfiles.conf $(TMPFILESDIR)/kestrel.conf
	install -Dm644 data/com.hihusky.Kestrel.conf $(DBUS_POLICYDIR)/com.hihusky.Kestrel.conf
	install -Dm644 data/com.hihusky.Kestrel.service $(DBUS_SERVICEDIR)/com.hihusky.Kestrel.service
	install -Dm644 data/com.hihusky.kestrel.policy $(POLKIT_DIR)/com.hihusky.kestrel.policy
	install -Dm644 config.example.toml $(SYSCONFDIR)/kestrel.toml.example
	install -d $(BASH_COMPDIR) $(ZSH_COMPDIR) $(FISH_COMPDIR)
	$(TARGET_DIR)/release/kestrel completions bash > $(BASH_COMPDIR)/kestrel
	chmod 644 $(BASH_COMPDIR)/kestrel
	$(TARGET_DIR)/release/kestrel completions zsh > $(ZSH_COMPDIR)/_kestrel
	chmod 644 $(ZSH_COMPDIR)/_kestrel
	$(TARGET_DIR)/release/kestrel completions fish > $(FISH_COMPDIR)/kestrel.fish
	chmod 644 $(FISH_COMPDIR)/kestrel.fish
	install -Dm644 LICENSE $(DOCDIR)/LICENSE
	install -Dm644 README.md $(DOCDIR)/README.md
	install -Dm644 ARCHITECTURE.md $(DOCDIR)/ARCHITECTURE.md
	find docs -type f -print0 | while IFS= read -r -d '' f; do \
		install -Dm644 "$$f" "$(DOCDIR)/$$f"; \
	done

uninstall:
	rm -f $(BINDIR)/kestrel
	rm -f $(LIBEXECDIR)/kestrel-daemon
	rm -f $(SYSTEMD_UNITDIR)/kestrel.service
	rm -f $(TMPFILESDIR)/kestrel.conf
	rm -f $(DBUS_POLICYDIR)/com.hihusky.Kestrel.conf
	rm -f $(DBUS_SERVICEDIR)/com.hihusky.Kestrel.service
	rm -f $(POLKIT_DIR)/com.hihusky.kestrel.policy
	rm -f $(BASH_COMPDIR)/kestrel
	rm -f $(ZSH_COMPDIR)/_kestrel
	rm -f $(FISH_COMPDIR)/kestrel.fish
	rm -f $(SYSCONFDIR)/kestrel.toml.example
	rm -rf $(DOCDIR)

clean:
	$(CARGO) clean
