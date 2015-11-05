#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/vmalloc.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jody");
MODULE_DESCRIPTION("Netfilter Firewall Module");


static char BLOCKED_IP[16] = "192.168.1.1"; 

static struct nf_hook_ops nfho;
static inline unsigned char *skb_network_header(const struct sk_buff *skb);

static char ip_holder[16];


char *data;



static void ip_conv(int ip)
{
  static char res[16];
  sprintf(res, "%d.%d.%d.%d",
    ip & 0xFF,
    (ip >> 8)  & 0xFF,
    (ip >> 16) & 0xFF,
    (ip >> 24) & 0xFF);

  strcpy(ip_holder, res);

}



char *replace_str(char *str, char *orig, char *rep, int start)
{
  static char temp[40096];
  static char buffer[40096];
  char *p;

  strcpy(temp, str + start);

  if(!(p = strstr(temp, orig)))
    return temp;

  strncpy(buffer, temp, p-temp);
  buffer[p-temp] = '\0';

  sprintf(buffer + (p - temp), "%s%s", rep, p + strlen(orig));
  sprintf(str + start, "%s", buffer);    

  return str;
}



unsigned int hook_v(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))  {

    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    

if(ip_header->protocol == IPPROTO_TCP){
    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int src_p, dest_p;


     struct tcphdr *tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
    
    ip_conv(src_ip);

    src_p = htons((unsigned short int) tcp_header->source);
    dest_p = htons((unsigned short int) tcp_header->dest);

    data = (char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));

    printk("Packet entered! Src IP:%s SrcPort:%hu DestPort:%hu \n", ip_holder, src_p, dest_p);

if(src_p == 80){
    
    while(strstr(data, "the") != NULL){
    data = replace_str(data, "the", "REDACTED", 0);
    //censors the word "the" and replaces with "REDACTED"
    }
    printk("Port 80 Web Data:\n %s \n",data); 
    



}



    

    

    if(strcmp(ip_holder, BLOCKED_IP) == 0)
    {
	printk("Dropping Packet from a blocked IP\n");
	return NF_DROP;

    }
    
} else {
printk("Packet other than TCP came in.\n");
}


    return NF_ACCEPT;
}

static int filter_init(void)
{
  nfho.hook = hook_v;
  nfho.hooknum = 0;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nfho);
  return 0;
}


static int __init hook_init(void)
{
    printk("Loading a generic Firewall...\n");
    filter_init();
    return 0;
}

static void __exit hook_cleanup(void)
{
  printk("Unloading a generic Firewall...\n");
  nf_unregister_hook(&nfho);
}


module_init(hook_init);
module_exit(hook_cleanup);






