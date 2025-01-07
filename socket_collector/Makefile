APP=socket_collector

# this is for using distribution provided bpftool
BPFTOOL=bpftool


.PHONY: $(APP)
$(APP): skel
		clang -lbpf socket_collector.c -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
		clang -g -O2 -target bpf -D__TARGET_ARCH_$(shell uname -m | cut -c -3) -c socket_collector.bpf.c -o socket_collector.bpf.o

.PHONY: skel
skel: bpf
		$(BPFTOOL) gen skeleton socket_collector.bpf.o name socket_collector > socket_collector.skel.h

.PHONY: clean
clean:
		-rm -rf *.o *.skel.h vmlinux.h $(APP)

