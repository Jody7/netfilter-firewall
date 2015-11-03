#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/vmalloc.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jody");
MODULE_DESCRIPTION("Netfilter Firewall Module");

static char BLOCKED_IP[16] = "192.168.1.1"; 

static struct nf_hook_ops nfho;
static inline unsigned char *skb_network_header(const struct sk_buff *skb);

static char ip_holder[16];

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


unsigned int hook_v(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))  {

    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    unsigned int src_ip = (unsigned int)ip_header->saddr;
      
    ip_conv(src_ip);
    printk("Packet entered! Src IP:%s\n", ip_holder);

    

    if(strcmp(ip_holder, BLOCKED_IP) == 0)
    {
	printk("Dropping Packet from a blocked IP\n");
	return NF_DROP;

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






