cd kernel_mode
cp hook_ipv4_fix_seq.c hook_ipv4.c
make
rmmod hook_ipv4
insmod hook_ipv4.ko
