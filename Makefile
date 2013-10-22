obj-m += xt_wildstring.o

all: module lib

module:
	cp include/linux/netfilter/xt_wildstring.h /root/rpmbuild/BUILD/kernel-2.6.32-358.el6/linux-2.6.32-358.el6.x86_64/include/linux/netfilter/xt_wildstring.h
	make -C /lib/modules/2.6.32/build M=$(PWD) modules
lib:
	cp libxt_wildstring.c /root/rpmbuild/BUILD/iptables-1.4.7/extensions
	cp include/linux/netfilter/xt_wildstring.h /root/rpmbuild/BUILD/iptables-1.4.7/include/linux/netfilter/xt_wildstring.h
	make -C /root/rpmbuild/BUILD/iptables-1.4.7/extensions
	cp /root/rpmbuild/BUILD/iptables-1.4.7/extensions/libxt_wildstring.so libxt_wildstring.so
install:
	iptables -F 
	cp libxt_wildstring.so /usr/local/libexec/xtables/libxt_wildstring.so
	rmmod xt_wildstring
	insmod xt_wildstring.ko
userspace:
	gcc userspace_wildstring.c -o userspace
	./userspace
	rm -f userspace
clean:
	rm -f *~ *.ko *.so *.mod.c *.ko.unsigned *.o modules.order Module.symvers
