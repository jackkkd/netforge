CC ?= cc
AR ?= ar
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -Iinclude
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -MMD -MP
NCURSES_LIBS ?= -lncurses
CORE = job log util text net_io scanner http_server packet_parser
CORE_OBJS = $(addprefix build/,$(addsuffix .o,$(CORE)))
PROGRAMS = bin/netforge bin/netforge-scan bin/netforge-http bin/netforge-packets
.PHONY: all check clean
all: $(PROGRAMS)
build bin:
	mkdir -p $@
build/%.o: src/%.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/app_%.o: apps/%.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/libnetforge.a: $(CORE_OBJS)
	$(AR) rcs $@ $^
bin/netforge: build/main.o build/ui.o build/art.o build/libnetforge.a | bin
	$(CC) $(LDFLAGS) $^ -o $@ $(NCURSES_LIBS) -pthread $(LDLIBS)
bin/netforge-scan: build/app_scan_main.o build/app_cli_common.o build/libnetforge.a | bin
	$(CC) $(LDFLAGS) $^ -o $@ -pthread $(LDLIBS)
bin/netforge-http: build/app_http_main.o build/app_cli_common.o build/libnetforge.a | bin
	$(CC) $(LDFLAGS) $^ -o $@ -pthread $(LDLIBS)
bin/netforge-packets: build/app_packets_main.o build/app_cli_common.o build/libnetforge.a | bin
	$(CC) $(LDFLAGS) $^ -o $@ -pthread $(LDLIBS)
build/test_core.o: tests/test_core.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
bin/test-core: build/test_core.o build/libnetforge.a | bin
	$(CC) $(LDFLAGS) $^ -o $@ -pthread -lutil $(LDLIBS)
check: all bin/test-core
	./bin/netforge-packets --self-test
	./bin/test-core ./bin
clean:
	rm -rf build bin
-include $(wildcard build/*.d)
