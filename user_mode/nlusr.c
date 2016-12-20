#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>

#include "zlibTool.h"

#define MAX_PAYLOAD 1024 /*消息最大负载为1024字节*/

int main(int argc, char* argv[])
{
    struct sockaddr_nl dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd=-1;
    struct msghdr msg;
        

    if(-1 == (sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_NETFILTER))){ //创建套接字
            perror("can't create netlink socket!");
            return 1;
    }
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /*我们的消息是发给内核的*/
    dest_addr.nl_groups = 0; /*在本示例中不存在使用该值的情况*/
        
    //将套接字和Netlink地址结构体进行绑定
    if(-1 == bind(sock_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr))){
          perror("can't bind sockfd with sockaddr_nl!");
          return 1;
    }

    if(NULL == (nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD)))){
          perror("alloc mem failed!");
          return 1;
    }

    memset(nlh,0,MAX_PAYLOAD);
    /* 填充Netlink消息头部 */
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_type = NLMSG_NOOP; //指明我们的Netlink是消息负载是一条空消息
    nlh->nlmsg_flags = 0;

    char content[] = "hello";
    /*设置Netlink的消息内容，来自我们命令行输入的第一个参数*/
    strcpy(NLMSG_DATA(nlh), content);

    /*这个是模板，暂时不用纠结为什么要这样用。有时间详细讲解socket时再说*/
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(sock_fd, &msg, 0); //通过Netlink socket向内核发送消息

    /* 关闭netlink套接字 */
    close(sock_fd);
    free(nlh);
    return 0;
}