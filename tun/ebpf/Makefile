# apt install libbpf-dev

CLANG   ?= clang
ARCH    := $(shell uname -m \
             | sed -e 's/x86_64/x86/' \
                   -e 's/aarch64/arm64/' \
                   -e 's/riscv64/riscv/' \
                   -e 's/mips.*/mips/' \
                   -e 's/ppc64le/powerpc/' \
                   -e 's/s390x/s390/')

CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
           -I /usr/include/$(shell uname -m)-linux-gnu

SRCS    := nat66.c
OBJS    := $(SRCS:.c=.o)

all: $(OBJS)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

.PHONY: all clean
