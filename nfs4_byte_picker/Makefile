APP=nfs4_byte_picker

# this is for using distribution provided bpftool
BPFTOOL=bpftool
#ARCH=x86_64
# Change these to wherever you keep
# your mainline and stable kernel
LINUX_KERNEL_DIR_MAINLINE=/usr/src/kernel/$(shell uname -r)
LINUX_KERNEL_DIR_STABLE=/code/linux-stable
LINUX_KERNEL_DIR_BPF_NEXT=/code/bpf-next

# change this to set whether you want to use
# mainline or stable
LINUX_KERNEL_DIR=$(LINUX_KERNEL_DIR_MAINLINE)
#LINUX_KERNEL_DIR=$(LINUX_KERNEL_DIR_STABLE)
#LINUX_KERNEL_DIR=$(LINUX_KERNEL_DIR_BPF_NEXT)
#BPFTOOL=$(LINUX_KERNEL_DIR)/tools/bpf/bpftool/bpftool

.PHONY: $(APP)
$(APP): skel
		clang -lbpf nfs4_byte_picker.c -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
		clang -g -O2 -target bpf -D__TARGET_ARCH_$(shell uname -m | cut -c -3) -c nfs4_byte_picker.bpf.c -o nfs4_byte_picker.bpf.o

.PHONY: skel
skel: bpf
		$(BPFTOOL) gen skeleton nfs4_byte_picker.bpf.o name nfs4_byte_picker > nfs4_byte_picker.skel.h

.PHONY: run
run: $(APP)
		sudo ./$(APP)

.PHONY: clean
clean:
		-rm -rf *.o *.skel.h vmlinux.h $(APP)

