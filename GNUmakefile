SRC := $(shell pwd)
DEP := $(SRC)/dep_root
BIN := movpatcher
STRIP := strip
CXX ?= c++

SRCS := movpatcher.cpp

CFLAGS += -I$(DEP)/include -Ofast -std=gnu++14
LDFLAGS += -L$(DEP)/lib
LIBS := -Wl,-Bstatic -lLIEF -Wl,-Bdynamic -lcapstone -lm

TARGET_OS := $(shell uname -s)

ifeq ($(TARGET_OS),Darwin)
	ifneq ($(shell sw_vers -productName),macOS)
		TARGET_OS := iOS
	endif
endif

TARGET_CPU := $(shell uname -m)
LIEF_VERSION := 0.16.6

all: $(BIN)

$(BIN): download-deps
	$(CXX) $(SRCS) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@
	$(STRIP) $@

download-deps:
	if [ ! -f $(DEP)/lief.tar.gz ]; then \
		curl -Lfo $(DEP)/lief.tar.gz https://github.com/lief-project/LIEF/releases/download/$(LIEF_VERSION)/LIEF-$(LIEF_VERSION)-$(TARGET_OS)-$(TARGET_CPU).tar.gz; \
		tar -xzf $(DEP)/lief.tar.gz -C $(DEP) --strip-components=1; \
	fi

clean:
	rm -f $(BIN) $(OBJS)
	rm -fr $(DEP)/*

.PHONY: all $(BIN) download-deps clean
