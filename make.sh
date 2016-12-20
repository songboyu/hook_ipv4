cd kernel_mode
make
rmmod hook_ipv4
insmod hook_ipv4.ko
