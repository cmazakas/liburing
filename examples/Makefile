CPPFLAGS ?=
override CPPFLAGS += -D_GNU_SOURCE -I../src/include/
CFLAGS ?= -g -O2 -Wall
LDFLAGS ?=
override LDFLAGS += -L../src/ -luring

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

LDFLAGS ?=
override LDFLAGS += -L../src/ -luring -lpthread

ifeq ($(CONFIG_USE_SANITIZER),y)
	override CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls
	override CPPFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls
	override LDFLAGS += -fsanitize=address,undefined
endif

example_srcs := \
	io_uring-close-test.c \
	io_uring-cp.c \
	io_uring-test.c \
	io_uring-udp.c \
	link-cp.c \
	napi-busy-poll-client.c \
	napi-busy-poll-server.c \
	poll-bench.c \
	reg-wait.c \
	send-zerocopy.c \
	rsrc-update-bench.c \
	proxy.c \
	zcrx.c \
	kdigest.c

all_targets :=


ifdef CONFIG_HAVE_UCONTEXT
	example_srcs += ucontext-cp.c
endif
all_targets += ucontext-cp helpers.o

example_targets := $(patsubst %.c,%,$(patsubst %.cc,%,$(example_srcs)))
rust_example_targets := $(patsubst %.c,%-rs,$(patsubst %.cc,%-rs,$(example_srcs)))
rust_example_targets += ucontext-cp-rs
all_targets += $(example_targets)

helpers = helpers.o

all: $(example_targets)

CARGO_TOOLCHAIN ?= x86_64-unknown-linux-gnu
CARGO_FLAGS ?= --profile release-with-debug --target $(CARGO_TOOLCHAIN)
OBJCOPY ?= objcopy

RUSTFLAGS ?=

ifeq ($(CONFIG_USE_SANITIZER),y)
	CARGO_FLAGS += -Zbuild-std --features sanitizers
	RUSTFLAGS += -Zsanitizer=address
endif

liburing_rs: liburing.h.in
	+ CC=$(CC) CXX=$(CXX) RUSTFLAGS="$(RUSTFLAGS)" cargo +nightly clippy $(CARGO_FLAGS)
	+ CC=$(CC) CXX=$(CXX) RUSTFLAGS="$(RUSTFLAGS)" cargo +nightly build $(CARGO_FLAGS) -Z unstable-options --artifact-dir . --manifest-path ../test/Cargo.toml
	$(OBJCOPY) --weaken-symbol io_uring_get_sqe liburing_rs_test.a
	cp liburing.h.in liburing.h

liburing_rs_examples: $(rust_example_targets)
	rm liburing.h

helpers.o: helpers.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

%: %.c $(helpers) ../src/liburing.a
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(helpers) $(LDFLAGS)

%-rs: %.c $(helpers) liburing_rs
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(helpers) liburing_rs_test.a $(LDFLAGS)

clean:
	@rm -f $(all_targets) $(rust_example_targets) liburing_rs_test.a

.PHONY: all clean liburing_rs_examples
