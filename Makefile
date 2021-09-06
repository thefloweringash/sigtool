# Minimal Makefile for bootstrapping without cmake

PKG_CONFIG ?= pkg-config
CXXFLAGS = -std=c++17

COMMON_SRCS = hash.cpp macho.cpp signature.cpp commands.cpp der.cpp

SIGTOOL_SRCS = main.cpp $(COMMON_SRCS)
SIGTOOL_OBJS := $(SIGTOOL_SRCS:.cpp=.o)

CODESIGN_SRCS = codesign.cpp $(COMMON_SRCS)
CODESIGN_OBJS := $(CODESIGN_SRCS:.cpp=.o)

CPPFLAGS := -I vendor $(shell $(PKG_CONFIG) --cflags openssl)
LDFLAGS := $(shell $(PKG_CONFIG) --libs openssl)

sigtool: $(SIGTOOL_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

codesign: $(CODESIGN_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

.PHONY: install
install: sigtool codesign
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp codesign sigtool $(DESTDIR)$(PREFIX)/bin/
