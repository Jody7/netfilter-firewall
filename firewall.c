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

static struct nf_hook_ops nfho;
static inline unsigned char *skb_network_header(const struct sk_buff *skb);



unsigned int hook_v(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))  {
    //A lot of params

    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    //unsigned int src_ip = (unsigned int)ip_header->saddr;
    printk("Packet entered! Source:%pI4\n", &(ip_header->saddr));
    
    
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






