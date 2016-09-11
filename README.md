### 基于netfilter修改HTTP数据包（插入、修改、删除）

> 测试内核：```3.13.0-32-generic```

> hook点
  ```c
  { 
  		.hook 			= hook_func,
  		.pf 		    = NFPROTO_IPV4,
  		.hooknum 		= NF_INET_FORWARD, 
  		.priority 		= NF_IP_PRI_MANGLE,
  		.owner			= THIS_MODULE
  },
```

### 内核NAT修正数据接口：

  ```C
  static inline int nf_nat_mangle_tcp_packet(
                struct sk_buff *skb,
                struct nf_conn *ct,
                enum ip_conntrack_info ctinfo,
                // IP头偏移量
                unsigned int protoff,
                // 插入点偏移量（距离payload首部）
                unsigned int match_offset,
                // 插入点覆盖长度
                unsigned int match_len,
                // 待插入数据
                const char *rep_buffer,
                // 带插入数据长度
                unsigned int rep_len)
  ```
### 注意事项：

* 在调用```nf_nat_mangle_tcp_packet```前需要调用```nfct_seqadj_ext_add```将当前连接跟踪信息加入seq修正。

* 修改数据包长度后3.13内核可自动修改seq和ack

  > 原理：

  > ```nf_nat_mangle_tcp_packet```时会做以下处理```set_bit(IPS_SEQ_ADJUST_BIT, &ct->status)```
  
  >  后续内核跟踪钩子会修正```test_bit(IPS_SEQ_ADJUST_BIT, &ct->status)```的tcp数据包的seq和ack）

* 3.2以及2.68以下内核只是在ct->status中高几位做了标记（```IPS_SEQ_ADJUST_BIT```），还需要后续手动hook修改
  ```c
  unsigned int fix_seq(unsigned int hooknum, struct sk_buff *skb,
     const struct net_device *in, const struct net_device *out, int(*okfn)(struct sk_buff *))
  {
      enum ip_conntrack_info ctinfo;
      struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
      if (ct && test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) 
      && (ctinfo != IP_CT_RELATED + IP_CT_IS_REPLY)  ) {
          nf_nat_seq_adjust(skb, ct, ctinfo);
      }
      return NF_ACCEPT;
  }
  ```
  
  ```c
  // 3.2以及2.68以下内核适用
	{
		.hook		   	= fix_seq,
		.pf			 	= PF_INET,
		.hooknum		= NF_INET_PRE_ROUTING,
		.priority	   	= NF_IP_PRI_CONNTRACK_CONFIRM,
		.owner			= THIS_MODULE
	},
	{
		.hook		   	= fix_seq,
		.pf			 	= PF_INET,
		.hooknum		= NF_INET_POST_ROUTING,
		.priority	  	= NF_IP_PRI_CONNTRACK_CONFIRM,
		.owner			= THIS_MODULE
	},
  ```
* 处理gzip压缩：发送请求时删除请求头中```Accept-Encoding```字段，防止收到gzip压缩包

* 处理chunked分段传输：发送请求时将```HTTP/1.1```修改为```HTTP/1.0```防止收到chunked数据包（Transfer-Encoding： chunked是HTTP 1.1中特有的）

* 对数据包进行修改需要重新计算checksum

* 处理完整数据包需要合并ip分片
  ```c
  // IP数据包frag合并
  if (0 != skb_linearize(skb)) {
    return NF_ACCEPT;
  }
  ```
