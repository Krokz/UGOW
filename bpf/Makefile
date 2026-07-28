CLANG   ?= clang
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# vmlinux.h is generated from the running kernel's BTF data.
# The WSL2 kernel ships with CONFIG_DEBUG_INFO_BTF=y so this works
# out of the box.
VMLINUX_H := vmlinux.h

CFLAGS := -O2 -g -Wall \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I.

.PHONY: all clean vmlinux

# The vmlinux.h rule redirects into its target, so a bpftool failure would
# otherwise leave a truncated header behind that later builds treat as valid.
.DELETE_ON_ERROR:

all: $(VMLINUX_H) ugow.bpf.o

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

ugow.bpf.o: ugow.bpf.c ugow.h $(VMLINUX_H)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f ugow.bpf.o $(VMLINUX_H)
