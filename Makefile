# Minimal Makefile for bootstrapping without cmake

PKG_CONFIG ?= pkg-config

SRCS = main.cpp hash.cpp macho.cpp signature.cpp commands.cpp
OBJS := $(SRCS:.cpp=.o)

CPPFLAGS := -I vendor $(shell $(PKG_CONFIG) --cflags openssl)
LDFLAGS := $(shell $(PKG_CONFIG) --libs openssl)

sigtool: $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

.PHONY: install
install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp sigtool $(DESTDIR)$(PREFIX)/bin/
