APP=nfs4_path_finderV2

# this is for using distribution provided bpftool
BPFTOOL=bpftool


.PHONY: $(APP)
$(APP): skel
		clang -lbpf nfs4_path_finderV2.c -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
		clang -g -O2 -target bpf -D__TARGET_ARCH_$(shell uname -m | cut -c -3) -c nfs4_path_finderV2.bpf.c -o nfs4_path_finderV2.bpf.o

.PHONY: skel
skel: bpf
		$(BPFTOOL) gen skeleton nfs4_path_finderV2.bpf.o name nfs4_path_finderV2 > nfs4_path_finderV2.skel.h

.PHONY: clean
clean:
		-rm -rf *.o *.skel.h vmlinux.h $(APP)

