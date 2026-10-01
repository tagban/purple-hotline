# purple-hotline: the libpurple plugin (Pidgin, Finch) and its tests.
# The Adium bundle is built by adium/build.sh.

PKG_CONFIG ?= pkg-config
CC ?= cc
CFLAGS ?= -O2 -g
WARN = -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-deprecated-declarations
PURPLE_CFLAGS := $(shell $(PKG_CONFIG) --cflags purple)
PURPLE_LIBS := $(shell $(PKG_CONFIG) --libs purple)
PLUGIN_DIR := $(shell $(PKG_CONFIG) --variable=plugindir purple)
# Pidgin's protocol icons (16, 22, 48 px and SVG) go under its data folder.
DATA_DIR := $(shell $(PKG_CONFIG) --variable=datadir pidgin 2>/dev/null || $(PKG_CONFIG) --variable=datadir purple)
ICON_DIR := $(DATA_DIR)/pixmaps/pidgin/protocols

UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
  SHARED = -bundle -undefined dynamic_lookup
else
  SHARED = -shared -fPIC
endif

SRC = src/hotline.c src/hl_wire.c src/hl_crypto.c src/hl_json.c src/hl_tracker.c src/hl_room.c
HDR = src/hl_wire.h src/hl_crypto.h src/hl_json.h src/hl_tracker.h src/hl_room.h

all: libhotline.so

libhotline.so: $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(WARN) -fPIC $(PURPLE_CFLAGS) $(SHARED) -o $@ $(SRC) $(PURPLE_LIBS)

build/test_crypto: tests/test_crypto.c src/hl_crypto.c src/hl_crypto.h
	@mkdir -p build
	$(CC) -std=c89 -pedantic -Wall -Wextra -Wno-long-long -O2 -o $@ tests/test_crypto.c src/hl_crypto.c

build/test_tracker: tests/test_tracker.c src/hl_tracker.c src/hl_json.c src/hl_tracker.h src/hl_json.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(WARN) $(PURPLE_CFLAGS) -o $@ tests/test_tracker.c src/hl_tracker.c src/hl_json.c $(PURPLE_LIBS)

build/test_client: tests/test_client.c libhotline.so
	@mkdir -p build
	$(CC) $(CFLAGS) $(WARN) $(PURPLE_CFLAGS) -o $@ tests/test_client.c $(PURPLE_LIBS)

# Crypto vectors, then a full session against HIM's mock server (MOCK=path/to/mock-server).
check: build/test_crypto build/test_tracker build/test_client
	build/test_crypto
	build/test_tracker tests/fixtures/servers.json tests/fixtures/live.json
	tests/run-client.sh

install: libhotline.so
	install -d $(DESTDIR)$(PLUGIN_DIR)
	install -m 644 libhotline.so $(DESTDIR)$(PLUGIN_DIR)/
	for s in 16 22 48 scalable; do \
		install -d $(DESTDIR)$(ICON_DIR)/$$s; \
		install -m 644 pidgin/pixmaps/$$s/hotline.* $(DESTDIR)$(ICON_DIR)/$$s/; \
	done

# Just for you: the plugin in ~/.purple/plugins (icons still need "make install" or a package).
install-user: libhotline.so
	install -d $(HOME)/.purple/plugins
	install -m 644 libhotline.so $(HOME)/.purple/plugins/

clean:
	rm -rf libhotline.so build

.PHONY: all check install install-user clean
