# Minimal Makefile for bootstrapping without cmake

SRCS = main.cpp hash.cpp macho.cpp signature.cpp
OBJS := $(SRCS:.cpp=.o)

CPPFLAGS := -I vendor $(shell pkg-config --cflags openssl)
LDFLAGS := $(shell pkg-config --libs openssl)

sigtool: $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

.PHONY: install
install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp sigtool $(DESTDIR)$(PREFIX)/bin/
