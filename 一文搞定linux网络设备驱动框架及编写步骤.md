>本文阐述了网络架构模型，特别是Linux系统中网络子设备框架4层结构，反别阐述了各层的作用。重点讲解了sk_buff及net_device数据结构及其常用操作接口，最后以实际代码讲述了特定网卡的驱动编写步骤、流程和移植方法。

有点像宋宝华的 linux设备驱动开发详解

# 1、网卡设备驱动原理

## 1.1 网络模型 与 网络子系统

### 网络模型

> OSI网络7层模型：物理层—>数据链路层—>网络层—>传输层—>会话层—>表示层—>应用层。
![图片](计算机网络全部知识点.assets/640.png)

OSI(Open System Interconnection，开放式通信互联)是由ISO(International Organization for Standardization，国际标准化组织)制定的标准模型。旨在将世界各地的各种计算机互联。然而，OSI模型过于庞大、复杂。参照此模型，技术人员开发了TCP/IP协议栈，简化OSI七层模型为TCP/IP四层模型。获得了更广泛的使用。

TCP/IP网络4层模型：应用层—>传输层—>网际层—>网络接口层
	![](assets/Pasted%20image%2020230412204322.png)

### Linux网络子系统

- Linux使用TCP/IP4层概念模型来设计其网络子系统。作为Linux网络设备驱动开发者，需要关心的是最底层（即网络接口层），其余各层Linux内核已经为你设计好了。
- 作为网络接口层的任务，它对上要提供数据收发（数据传输单元sk_buff），对下要填充网络设备硬件信息（构建net_device结构体）。
- Linux系统对网络设备驱动定义了4个层次， 这4个层次有到下分为:

1. `网络协议接口层`：实现统一的数据包收发的协议。该层主要负责调用​​`dev_queue_xmit()​​`函数发送数据， ​​`netif_rx()​​`函数接收数据。  
	当上层 ARP 或 IP 协议需要发送数据包时，它将调用网络协议接口层的`​​dev_queue_xmit()`​函数发送该数据包，同时需传递给该函数一个指向 `​​struct sk_buff` ​​数据 结构的指针。​​`dev_queue_xmit()​​`函数的原型为：
```c
int dev_queue_xmit (struct sk_buff * skb );
```

同样地，上层对数据包的接收也通过向 ​​netif_rx()​​​函数传递一个 ​​struct sk_buff ​​数据 结构的指针来完成。netif_rx()函数的原型为：
```c
/*通知内核一个报文已经收到并且封装到一个 socket 缓存中的函数
 * 返回值：大部分驱动忽略从 netif_rx 的返回值
 *    NET_RX_SUCCESS表示报文成功接收
 *    NET_RX_DROP    表示报文被丢弃
 *      (NET_RX_CN_LOW, NET_RX_CN_MOD, NET_RX_CN_HIGH )指出网络子系统的递增的拥塞级别
 */
int netif_rx(struct sk_buff *skb);  

/*告诉内核报文可用并且应当启动查询接口; 它只是被 NAPI 兼容的驱动使用*/
void netif_rx_schedule(dev);  

/* 以下两个函数应当只被 NAPI 兼容的驱动使用. netif_receive_skb 是对于 netif_rx
 * 的 NAPI 对等函数; 它递交一个报文给内核. 当一个 NAPI 兼容的驱动已处理完接收的报文，
 * 它应当重开中断, 并且调用netif_rx_complete 来停止查询
 */
int netif_receive_skb(struct sk_buff *skb);
void netif_rx_complete(struct net_device *dev);
```

2. `网络设备接口层`：通过`​​net_device​​`结构体来描述一个具体的网络设备的信息,实现不同的硬件的统一。它将协议与具有很多各种不同功能的硬件设备连接在一起。这一层提供了一组通用函数供底层网络设备驱动程序使用，让它们可以对高层协议栈进行操作。

- 首先，设备驱动程序可能会通过调用​​`register_netdevice​​​` 或​​`unregister_netdevice​​​ `在内核中进行注册或注销。调用者首先填写​​net_device ​​结构，然后传递这个结构进行注册。内核调用它的 init 函数（如果定义了这种函数），然后执行一组健全性检查，并创建一个 sysfs 条目，然后将新设备添加到设备列表中（内核中的活动设备链表）。
- 要从协议层向设备中发送 sk_buff ，就需要使用​​`dev_queue_xmit ​​​`函数。这个函数可以对 sk_buff 进行排队，从而由底层设备驱动程序进行最终传输（使用 sk_buff 中引用的 net_device 或 sk_buff->dev 所定义的网络设备）。dev 结构中包含了一个名为​​`hard_start_xmit​​`的方法，其中保存有发起 sk_buff 传输所使用的驱动程序函数。
- 报文的接收通常是使用​​`netif_rx`​​ 执行的。当底层设备驱动程序接收一个报文（包含在所分配的 sk_buff 中）时，就会通过调用 netif_rx 将 sk_buff 上传至网络层。然后，这个函数通过 netif_rx_schedule 将 sk_buff 在上层协议队列中进行排队，供以后进行处理。

3. `设备驱动功能层`：用来负责驱动网络设备硬件来完成各个功能，它通过​​hard_start_xmit()​​ 函数启动发送操作， 并通过网络设备上的中断触发接收操作。

- 在进行初始化时，设备驱动程序会分配一个 net_device 结构，然后使用必须的程序对其进行初始化。这些程序中有一个是 dev->hard_start_xmit ，它定义了上层应该如何对 sk_buff 排队进行传输。这个程序的参数为 sk_buff 。这个函数的操作取决于底层硬件，但是通常 sk_buff 所描述的报文都会被移动到硬件环或队列中。
- 就像是设备无关层中所描述的一样，对于 NAPI 兼容的网络驱动程序来说，帧的接收使用了 netif_rx 和 netif_receive_skb 接口。NAPI 驱动程序会对底层硬件的能力进行一些限制。
- net_device结构体的成员（属性和net_device_ops结构体中的函数指针）需要被设备驱动功能层赋予具体的数值和函数。对于具体的设备xxx，工程师应该编写相应的设备驱动功能层的函数，这些函数形如xxx_open()、xxx_stop()、xxx_tx()、xxx_hard_header()、xxx_get_stats()和xxx_tx_timeout()等。
	由于网络数据包的接收可由中断引发，设备驱动功能层的另一个主体部分将是中断处理函数，它负责读取硬件上接收到的数据包并传送给上层协议，因此可能包含xxx_interrupt()和xxx_rx()函数，前者完成中断类型判断等基本工作，后者则需完成数据包的生成及将其递交给上层等复杂工作。
	对于特定的设备，我们还可以定义相关的私有数据和操作，并封装为一个私有信息结构体xxx_private，让其指针赋值给net_device的私有成员。在xxx_private结构体中可包含设备的特殊属性和操作、自旋锁与信号量、定时器以及统计信息等，这都由工程师自定义。在驱动中，要用到私有数据的时候，则使用在netdevice.h中定义的接口：
```c
static inline void *netdev_priv(const struct net_device *dev);
```

比如在驱动drivers/net/ethernet/davicom/dm9000.c的dm9000_probe()函数中，使用alloc_etherdev(sizeof(struct board_info))分配网络设备，board_info结构体就成了这个网络设备的私有数据，在其他函数中可以简单地提取这个私有数据。例如：
```c
static int dm9000_start_xmit(struct sk_buff *skb, struct net_device *dev) 
{
    unsigned long flags;
    board_info_t *db = netdev_priv(dev);
    ...
}
```

4. `网络设备与媒介层`：网络设备与媒介层直接对应于实际的硬件设备。用来负责完成数据包发送和接收的物理实体, 设备驱动功能层的函数都在这物理上驱动的。

- 网络设备的注册
	网络设备注册方式与字符驱动不同之处在于它没有主次设备号，并使用下面的函数注册
```c
int register_netdev(struct net_deivce*dev);
```

- 网络设备的注销
```c
void unregister_netdev(struct net_device*dev);
```

## 1.2 网卡驱动的初始化

### 1.2.1 初始化网卡步骤

1) 使用​​`alloc_netdev()`​​来分配一个net_device结构体
2) 设置网卡硬件相关的寄存器
3) 设置​​`net_device`​​结构体的成员
4) 使用`​​register_netdev()`​​来注册net_device结构体

### 1.2.2 net_device结构体

网络设备接口层的主要功能是为千变万化的网络设备定义了统一、抽象的数据结构 net_device 结构体，以不变应万变，实现多种硬件在软件层次上的统一。 net_device 结构体在内核中指代一个网络设备，网络设备驱动程序只需通过填充 net_device 的具体成员并注册 net_device 即可实现硬件操作函数与内核的挂接。

net_device结构是Linux内核中所有网络设备的基础数据结构。包含网络适配器的硬件信息（中断、端口、驱动程序函数等）和高层网络协议的网络配置信息（IP地址、子网掩码等）。
每个net_device结构表示一个网络设备，如eth0、eth1…。这些网络设备通过dev_base线性表链接起来。内核变量dev_base表示已注册网络设备列表的入口点，它指向列表的第一个元素（eth0）。然后各元素用next字段指向下一个元素(eth1)。

使用ifconfig -a命令可以查看系统中所有已注册的网络设备。
net_device结构通过alloc_netdev函数分配，该函数需要三个参数：
- 私有数据结构的大小
- 设备名，如eth0，eth1等。
- 配置例程，这些例程会初始化部分net_device字段。
- 分配成功则返回指向net_device结构的指针，分配失败则返回NULL。

net_device 本身是一个巨型结构体，包含网络设备的属性描述和操作接口。当我们编写网络设备驱动程序时，只需要了解其中的一部分。

net_device 本身是一个巨型结构体，包含网络设备的属性描述和操作接口。当我们编写网络设备驱动程序时，只需要了解其中的一部分。
```c
struct net_device
{
    char               name[IFNAMSIZ];      //网卡设备名称
    unsigned long      mem_end;             //该设备的内存结束地址
    unsigned long      mem_start;            //该设备的内存起始地址
    unsigned long      base_addr;            //该设备的内存I/O基地址
    unsigned int       irq;                  //该设备的中断号

    atomic_t             carrier_changes; 
    unsigned long        state; 
  
     struct list_head      dev_list;    /*全局网络设备列表*/
     struct list_head      napi_list;    /*napi机制==napi设备的列表入口*/ 
     struct list_head      unreg_list;    /*注销网络设备的列表入口*/ 
     struct list_head      close_list;    /*关闭的网络设备列表入口*/
   ... 
     const struct net_device_ops *netdev_ops; /*网络设备的操作集函数*/
     const struct ethtool_ops   *ethtool_ops; /*网络管理工具相关函数集*/
    
    unsigned char      if_port;              //该字段仅针对多端口设备，用于指定使用的端口类型
    unsigned char      dma;                  //该设备的DMA通道
    unsigned long      state;                //网络设备和网络适配器的状态信息
    const struct header_ops   *header_ops; /*头部的相关操作函数集，比如创建、解析、缓冲等*/

    struct net_device_stats* (*get_stats)(struct net_device *dev); //获取流量的统计信息,运行ifconfig便会调用该成员函数,并返回一个net_device_stats结构体获取信息

    struct net_device_stats  stats;      //用来保存统计信息的net_device_stats结构体


    unsigned long         features;        //接口特征,     
    unsigned int          flags; //flags指网络接口标志,以IFF_开头，包括：IFF_UP（ 当设备被激活并可以开始发送数据包时， 内核设置该标志）、 IFF_AUTOMEDIA（设置设备可在多种媒介间切换）、IFF_BROADCAST（ 允许广播）、IFF_DEBUG（ 调试模式， 可用于控制printk调用的详细程度） 、 IFF_LOOPBACK（ 回环）、IFF_MULTICAST（ 允许组播） 、 IFF_NOARP（ 接口不能执行ARP,点对点接口就不需要运行 ARP） 和IFF_POINTOPOINT（ 接口连接到点到点链路） 等。


    unsigned        mtu;        //最大传输单元,也叫最大数据包
    unsigned short  type;   　　//接口的硬件类型
    unsigned short   hard_header_len;     //硬件帧头长度,在以太网设备的初始化函数中一般被赋为ETH_HLEN,即14

    unsigned char    *dev_addr;   //存放设备的MAC地址,需由驱动程序从硬件上读出
    unsigned char    broadcast[MAX_ADDR_LEN];    //存放设备的广播地址,对于以太网而言，地址长度为6个0XFF
  ...
    /* Interface address info. */ 
     unsigned char         perm_addr[MAX_ADDR_LEN]; /*永久的硬件地址*/
     unsigned char         addr_assign_type; 
     unsigned char         addr_len;        /*硬件地址长度。*/
   ... 
         
    unsigned long    last_rx;    //接收数据包的时间戳,调用netif_rx()后赋上jiffies即可
  unsigned char    *dev_addr;  /*用于存放设备的硬件地址，驱动可能提供了设置MAC地址的接口，使用户设置的MAC地址等存入该成员(接口信息)*/
    
    #ifdef CONFIG_SYSFS 
     struct netdev_rx_queue  *_rx;        /*接收队列*/
  
     unsigned int          num_rx_queues;    /*接收队列数量*/
     unsigned int          real_num_rx_queues;  /*当前活动的队列数量*/
  
 #endif
  ... 
   /* 
  * Cache lines mostly used on transmit path 
  */ 
     struct netdev_queue  *_tx  /*发送队列*/ ____cacheline_aligned_in_smp; 
     unsigned int          num_tx_queues;    /*发送队列数量*/
     unsigned int          real_num_tx_queues;  /*当前有效的发送队列数量。*/
     struct Qdisc          *qdisc; 
     unsigned long         tx_queue_len; 
     spinlock_t            tx_global_lock; 
     int                   watchdog_timeo; 
  ... 
     /* These may be needed for future network-power-down code. *
  
     /* 
      * trans_start here is expensive for high speed devices on S
      * please use netdev_queue->trans_start instead. 
      */ 
    unsigned long    trans_start;   //发送数据包的时间戳,当要发送的时候赋上jiffies即可

    int (*hard_start_xmit) (struct sk_buff *skb, struct net_device *dev);//数据包发送函数, 以使得驱动程序能获取从上层传递下来的数据包。

    void  (*tx_timeout) (struct net_device *dev); //发包超时处理函数，需采取重新启动数据包发送过程或重新启动硬件等策略来恢复网络设备到正常状态
    ... 
    struct phy_device    *phydev;      /*对应的PHY 设备*/
    struct lock_class_key  *qdisc_tx_busylock; 
}
```

- net_device结构可分为全局成员、硬件相关成员、接口相关成员、设备方法成员和公用成员等五个部分：
-------------------------------
- 全局成员
```c
char name[INFAMSIZ]    设备名，如：eh%d
unsigned long state  设备状态
unsigned long base_addr  I/O基地址
unsigned int
```
------------------------------------
- 硬件相关成员
```c
/*硬件相关字段*/
rmem_end 接受内存尾地址
 rmem_start 接受内存首地址
mem_end 发送内存尾地址
 mem_start 发送内存首地址
base_addr 网络设备的基地址（见后图）
irq 中断号
if_port 端口号
 /*物理层上的数据*/
hard_header_length 第二层包报头长度
 mtu 最大传输单元
tx_queue_len 网络设备输出队列最大长度
type 网络适配器硬件类型
addr_len 第二层地址长度
dev_addr[MAX_ADDR_LEN] 第二层地址
broadcast[MAX_ADDR_LEN] 广播地址
*mc_list 指向具有多播第二层地址的线性表
mc_count dev_mc_list中的地址数量（多播地址数）
watchdpg_timeo 超时时间（从trans_start开始，经过watchdog_timeo时间后超时）
```
---------------------------------
- 接口相关成员
`net_device_stats`​​ 结构体定义在内核的 include/linux/netdevice.h 文件中，其中重要成员如下所示:
```c
struct net_device_stats
{
    unsigned long   rx_packets;     /*收到的数据包数*/
    unsigned long   tx_packets;     /*发送的数据包数    */
    unsigned long   rx_bytes;       /*收到的字节数,可以通过sk_buff结构体的成员len来获取*/       unsigned long   tx_bytes;       /*发送的字节数,可以通过sk_buff结构体的成员len来获取*/
    unsigned long   rx_errors;      /*收到的错误数据包数*/
    unsigned long   tx_errors;      /*发送的错误数据包数*/
    ... ...
}
```

net_device_stats 结构体适宜包含在设备的私有信息结构体中，而其中统计信息的 修改则应该在设备驱动的与发送和接收相关的具体函数中完成，这些函数包括中断处 理程序、数据包发送函数、数据包发送超时函数和数据包接收相关函数等。我们应该 在这些函数中添加相应的代码：
```c
/* 发送超时函数 */ 
void xxx_tx_timeout(struct net_device *dev) 
{ 
  struct xxx_priv *priv = netdev_priv(dev); 
  ... 
  priv->stats.tx_errors++; /* 发送错误包数加 1 */ 
  ... 
} 

/* 中断处理函数 */ 
static void xxx_interrupt(int irq, void *dev_id, struct pt_regs *regs) 
{ 
  switch (status &ISQ_EVENT_MASK) 
  { 
    ... 
    case ISQ_TRANSMITTER_EVENT: / 
      priv->stats.tx_packets++; /* 数据包发送成功，tx_packets 信息加1 */ 
      netif_wake_queue(dev); /* 通知上层协议 */ 
      if ((status &(TX_OK | TX_LOST_CRS | TX_SQE_ERROR | 
        TX_LATE_COL | TX_16_COL)) != TX_OK) /*读取硬件上的出错标志*/ 
      { 
        /* 根据错误的不同情况，对 net_device_stats 的不同成员加 1 */ 
        if ((status &TX_OK) == 0) 
          priv->stats.tx_errors++; 
        if (status &TX_LOST_CRS) 
          priv->stats.tx_carrier_errors++; 
        if (status &TX_SQE_ERROR)
          priv->stats.tx_heartbeat_errors++; 
        if (status &TX_LATE_COL) 
          priv->stats.tx_window_errors++; 
        if (status &TX_16_COL) 
          priv->stats.tx_aborted_errors++; 
      } 
      break; 
    case ISQ_RX_MISS_EVENT: 
      priv->stats.rx_missed_errors += (status >> 6); 
      break; 
    case ISQ_TX_COL_EVENT: 
      priv->stats.collisions += (status >> 6); 
      break; 
  } 
}
```
--------------------------------
- 主要设备方法
	- 需要在驱动代码中实现的接口
```c
	/*
 * 停止接口，ifconfig eth% down时调用
 * 要注意的是ifconfig是interface config的缩写，
 * 通常我们在用户空间输入:ifconfig eth0 up  会调用这里的open函数。
 * 在用户空间输入:ifconfig eth0 down  会调用这里的stop函数。
 * 在使用ifconfig向接口赋予地址时，要执行两个任务。
 * 首先，它通过ioctl(SIOCSIFADDR)(Socket I/O Control Set Interface Address)赋予地址，
 * 然后通过ioctl(SIOCSIFFLAGS)(Socket I/O Control Set Interface Flags)
 * 设置dev->flag中的IFF_UP标志以打开接口。这个调用会使得设备的open方法得到调用。
 * 类似的，在接口关闭时，ifconfig使用ioctl(SIOCSIFFLAGS)来清理IFF_UP标志，然后调用stop函数。
 */
int (*open)(struct net_device *dev); //打开接口。ifconfig激活时，接口将被打开
int (*stop)(struct net_device *dev);  

 
int  (*init)(struct  net_device *dev)
//初始化函数，该函数在register_netdev时被调用来完成对net_device结构的初始化
    
void uninit();  //注销网络设备

void destructor();  // 当网络设备的最后一个引用refcnt被删除时调用此函数
 
int (*hard_start_xmit)(struct sk_buf*skb，struct net_device *dev)
//数据发送函数
 
void (*tx_timeout)(struct net_device *dev);  
//如果数据包发送在超时时间内失败，这时该方法被调用，这个方法应该解决失败的问题，并重新开始发送数据。
  
struct net_device_stats *(*get_stats)(struct net_device *dev);  
//当应用程序需要获得接口的统计信息时，这个方法被调用。
 
int (*set_config)(struct net_device *dev, struct ifmap *map);  
//改变接口的配置，比如改变I/O端口和中断号等，现在的驱动程序通常无需该方法。
 
int (*do_ioctl)(struct net_device *dev, struct ifmap *map);  
//用来实现自定义的ioctl命令，如果不需要可以为NULL。
 
get_stats();  //获取网络设备状态信息，这些信息以net_device_stats 结构的形式返回
get_wireless_stats(); //获取无限网络设备的状态信息，这些信息以iw_statistics 结构的形式返回

void (*set_multicast_list)(struct net_device *dev)；  
//当设备的组播列表改变或设备标志改变时，该方法被调用。
 
watchdog_timeo(); //超时处理函数
```

- dev_addr使用范例：
```c
static int moxart_set_mac_address(struct net_device *ndev, void *addr) 
{
    struct sockaddr *address = addr;
    if (!is_valid_ether_addr(address->sa_data)) {
        return -EADDRNOTAVAIL;
    }
    memcpy(ndev->dev_addr, address->sa_data, ndev->addr_len);
    moxart_update_mac_address(ndev);
    return 0;
}
```

- 网络接口标志以IFF_开头，部分标志由内核来管理，其他的在接口初始化时被设置以说明设备接口的能力和特性。flages接口标志包括：
```c
IFF_UP      （当设备被激活并可以开始发送数据包时，内核设置该标志）
IFF_AUTOMEDIA  （设备可在多种媒介间切换）
IFF_BROADCAST  （允许广播）
IFF_DEBUG    （调试模式，可用于控制prink调用的详细程度）
IFF_LOOPBACK  （回环）
IFF_MULTICAST  （允许组播）
IFF_NOARP    （接口不能执行ARP）
IFF_POINTOPOINT  （接口连接到点到点链路）
```

- 辅助成员：trans_start、last_rx，这两个时间戳记录的都是jiffies，驱动程序应维护这两个成员。
trans_start记录最后的数据包开始发送时的时间戳，
last_rx记录最后一次接收到数据包时的时间戳，

- 不需要接口实现的接口
```c
int (*hard_header)(struct sk_buff *skb, struct net_device *dev, unsigned short type, void *daddr, void *saddr, unsigned len); 

//以太网的mac地址是固定的，为了高效，第一个包去询问mac地址，得到对应的mac地址后就会作为cache把mac地址保存起来。以后每次发包不用询问了，直接把包的地址拷贝出来。
int (*rebuild_header)(struct sk_buff *skb);

//如果接口支持mac地址改变，则可以实现该函数。
int (*set_mac_address)(struct net_device *dev, void *addr);  

hard_header_cache();  //用硬报头缓存中保存的数据填充第二层报头
header_cache_update();  //更改硬报头缓存中保存的第二层报头数据
hard_header_parse();  //从套接字缓冲区的包数据空间读取第二层报头的发送地址
change_mtu();      //改变mtu长度
```
-------------------------
- net_device相关操作函数

1. 分配
`#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \`
`alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, 1, 1)`
```c
- 参数

  - @ sizeof_priv：私有数据块大小。 
- @ name：设备名字
  - @ setup：回调函数，初始化设备的设备后调用此函数
  - @ txqs：分配的发送队列数量
  - @ rxqs：分配的接收队列数量

- 返回值

  - 如果申请成功的话就返回申请到的 net_device指针，失败的话就返回NULL。

- 可以看出alloc_netdev的本质是`alloc_netdev_mqs`函数

struct net_device  * alloc_netdev_mqs ( int sizeof_priv, const char *name,\   
                    void (*setup) (struct net_device *)),
                    unsigned int  txqs, unsigned int rxqs); 


- 网络设备有多种，比如光纤分布式数据接口(FDDI)、以太网设备(Ethernet)、红外数据接口(InDA)、高性能并行接口(HPPI)、CAN 网络等。本文所讲的以太网只是其中一种，且有专门的分配函数:

#define alloc_etherdev(sizeof_priv)  alloc_etherdev_mq(sizeof_priv, 1) 
   
  #define alloc_etherdev_mq(sizeof_priv, count) alloc_etherdev_mqs(sizeof_priv, count, count)

  - alloc_etherdev 最终依靠的是 alloc_etherdev_mqs 函数:

  struct net_device *alloc_etherdev_mqs(int sizeof_priv, unsigned int txqs, unsigned int rxqs) 
     { 
      return alloc_netdev_mqs(sizeof_priv, "eth%d",\
                                NET_NAME_UNKNOWN,ether_setup, txqs, rxqs);
     } 

2. **初始化**

- 对于以太网设备，内核提供了`ether_setup`函数，对 net_device做初步的初始化

void ether_setup(struct net_device *dev) 
   { 
      dev->header_ops       = ð_header_ops; 
      dev->type           = ARPHRD_ETHER; 
      dev->hard_header_len = ETH_HLEN; 
      dev->mtu              = ETH_DATA_LEN; 
      dev->addr_len         = ETH_ALEN; 
      dev->tx_queue_len     = 1000; /* Ethernet wants good queues */
      dev->flags          = IFF_BROADCAST|IFF_MULTICAST; 
      dev->priv_flags       |= IFF_TX_SKB_SHARING; 
    
      eth_broadcast_addr(dev->broadcast); 
   } 

3. **释放**

- 注销网络驱动的时候需要释放掉前面已经申请到的 net_device

void free_netdev(struct net_device *dev);


4. **注册/注销**

- net_device申请并初始化完成以后就需要向内核注册net_device，当设备拔出或模块卸载时要注销net_device，用到以下函数

int register_netdev(struct net_device *dev);
void unregister_netdev(struct net_device *dev);


5. **net_device_ops**

/*
@ 定义在 include/linux/netdevice.h 文件中
@ net_device_ops结构体里面都是一些以“ndo_”开头的函数，这些函数就需要网络驱动编写人员去实现
@ net_device_ops 结构体 
*/
struct net_device_ops { 
      int (*ndo_init)(struct net_device *dev); /*当第一次注册网络设备的时候此函数会执行*/
      void (*ndo_uninit)(struct net_device *dev); /*卸载网络设备的时候此函数会执行*/
      int (*ndo_open)(struct net_device *dev); /*打开网络设备的时候此函数会执行，网络驱动程序需要实现此函数，非常重要*/
      int (*ndo_stop)(struct net_device *dev); 
      netdev_tx_t (*ndo_start_xmit) (struct sk_buff *skb, 
                             struct net_device *dev); /*当需要发送数据的时候此函数就会执行，此函数有一个参数为 sk_buff结构体指针，sk_buff结构体在Linux的网络驱动中非常重要，sk_buff保存了上层传递给网络驱动层的数据。也就是说，要发送出去的数据都存在了sk_buff中*/
      u16 (*ndo_select_queue)(struct net_device *dev, struct sk_buff *skb, void *accel_priv,select_queue_fallback_t fallback); /*设备支持多传输队列的时候选择使用哪个队列*/
      void (*ndo_change_rx_flags)(struct net_device *dev, 
                                 int flags); 
      void (*ndo_set_rx_mode)(struct net_device *dev);/*此函数用于改变地址过滤列表*/ 
      int  (*ndo_set_mac_address)(struct net_device *dev,  void *addr); /*此函数用于修改网卡的 MAC 地址*/
      int  (*ndo_validate_addr)(struct net_device *dev); /*验证 MAC 地址是否合法，*/
      int  (*ndo_do_ioctl)(struct net_device *dev, struct ifreq *ifr, int cmd); /*用户程序调用 ioctl 的时候此函数就会执行，*/
      int  (*ndo_set_config)(struct net_device *dev, struct ifmap *map); 
      int  (*ndo_change_mtu)(struct net_device *dev, int new_mtu); /*更改MTU大小。*/
      int  (*ndo_neigh_setup)(struct net_device *dev, struct neigh_parms *); 
     void  (*ndo_tx_timeout) (struct net_device *dev); /*当发送超时的时候产生会执行，一般都是网络出问题了导致发送超 */
    
 #ifdef CONFIG_NET_POLL_CONTROLLER 
     void (*ndo_poll_controller)(struct net_device *dev); /*使用查询方式来处理网卡数据的收发*/
     int (*ndo_netpoll_setup)(struct net_device *dev, struct netpoll_info *info); 
     void (*ndo_netpoll_cleanup)(struct net_device *dev); 
 #endif 
   
     int (*ndo_set_features)(struct net_device *dev, etdev_features_t features); /*修改net_device的 features属性，设置相应的硬件属性*/
   
 }; 
```

​​函数`ndo_open()`函数的作用是打开网络接口设备, 获得设备需要的I/O地址, IRQ, DMA通道等. 一般驱动函数会在此函数中做如下工作：

使能网络外设时钟、申请网络所使用的环形缓冲区、初始化MAC 外设、绑定接口对应的 PHY、如果使用NAPI 的话要使能NAPI模块，通过 napi_enable函数来使能、开启PHY、调用netif_tx_start_all_queues来使能传输队列，也可能调用netif_start_queue函数。

​​ndo_stop()​​函数的作用是停止网络接口设备，与open()函数的作用相反。关闭网络设备的时候此函数会执行，网络驱动程序也需要实现此函数。一般驱动函数会在此函数中做如下工作：
- 停止PHY、停止NAPI功能、停止发送功能、关闭MAC、断开PHY 连接、关闭网络时钟、释放数据缓冲区。

​​`int (*ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev);​​`
- ndo_start_xmit()函数会启动数据包的发送，当系统调用驱动程序的xmit函数时，需要向其传入一个sk_buff结构体指针，以使得驱动程序能获取从上层传递下来的数据包。

​​`void (*ndo_tx_timeout) (struct net_device *dev);​​`
- 当数据包的发送超时时，ndo_tx_timeout()函数会被调用，该函数需采取重新启动数据包发送过程或重新启动硬件等措施来恢复网络设备到正常状态。

​​`struct net_device_status* (*ndo_get_stats)(struct net_device *dev);​​`

​​ndo_get_status()​​函数用于获得网络设备的状态信息，它返回一个net_device_stats结构体指针。
- net_device_stats结构体保存了详细的网络设备流量统计信息，如发送和接收的数据包数、字节数等。

​​`int (*ndo_do_ioctl) (struct net_device *dev, struct ifreq *ifr, int cmd);​​`
- 函数用于进行设备特定的I/O控制。

​​`int (*ndo_set_config) (struct net_device *dev, struct ifmap *map);​​`
- 用于配置接口，也可用于改变设备的I/O地址和中断号。

​​`int (*ndo_set_mac_address) (struct net_device *dev, void *adddr);​​`
- 用于设置设备的MAC地址。
	ethool_ops

`const struct ethtool_ops *ethool_ops;`
```c
- ethool\_ops成员函数与用户空间ethool工具的各个命令选项对应，ethool提供了网卡及网卡驱动管理能力，能够为Linux网络开发人员和管理人员提供对网卡硬件、驱动程序和网络协议栈的设置、查看以及调试等功能。

7. **header_ops**

const struct header_ops *header_ops;
```
- header_ops对应于硬件头部操作，主要是完成创建硬件头部和从给定的sk_buff分析出硬件头部等操作。

### 1.2.3 sk_buff结构体

sk_buff 结构体非常重要，它的含义为“套接字缓冲区”，用于在 Linux 网络子系 统中的各层之间传递数据，是 Linux 网络子系统数据传递的“中枢神经”。

当发送数据包时，Linux 内核的网络处理模块必须建立一个包含要传输的数据包 的 sk_buff，然后将 sk_buff 递交给下层，各层在 sk_buff 中添加不同的协议头直至交 给网络设备发送。

同样地，当网络设备从网络媒介上接收到数据包后，它必须将接收到的数据转换为 sk_buff 数据结构并传递给上层，各层剥去相应的协议头直至交给用户。

一个套接字缓存由两部份组成：
1. 报文数据：存储实际需要通过网络发送和接收的数据。
2. 管理数据（struct sk_buff）：管理报文所需的数据，在sk_buff结构中有一个head指针指向内存中报文数据开始的位置，有一个data指针指向报文数据在内存中的具体地址。head和data之间申请有足够多的空间用来存放报文头信息。

参看 linux/skbuff.h 中的源代码，sk_buff 结构体包含的主要成员如下：
- 定义
```c
/* <linux/skbuff.h> */
struct sk_buff {
    union 
    {
        struct 
        {
             /* These two members must be first. */
             struct sk_buff *next; //指向下一个 sk_buff 结构体
             struct sk_buff *prev; //指向前一个 sk_buff 结构体
             union { 
                  ktime_t         tstamp; /*数据包接收时或准备发送时的时间戳*/
                  struct skb_mstamp skb_mstamp; 
             };
        };
        struct rb_node  rbnode; /* used in netem & tcp stack */           
    };
    struct sock         *sk; /*当前 sk_buff所属的Socket*/
    struct net_device     *dev; /*当前 sk_buff从哪个设备接收到或者发出的*/
   
    char cb[48] __aligned(8); /*cb 为控制缓冲区，不管哪个层都可以自由使用此缓冲区，用于放置私有数据。 */
   
    unsigned long   _skb_refdst; 
    void  (*destructor)(struct sk_buff *skb); /*当释放缓冲区的时候可以在此函数里面完成某些动作*/
    .... 
        
    unsigned int    len;        //数据包的总长度，数据区的长度（tail-data）与分片结构体数据区的长度之和。 
    unsigned int    data_len;   //表示分片结构体数据区的长度(len=(tail - data) + data_len) 
    __u16           mac_len;    // mac报头的长度 
    __u16           hdr_len;    // 用于clone时，表示clone的skb的头长度 
    ...
    __u32           priority;    // 当前 sk_buff 结构体的优先级，主要用于QOS
    ...
    __be16          protocol;    // 包的协议类型，标识是IP包还是ARP包还是其他数据包，可以通过 eth_type_trans()来获取
    ...
    __be16          inner_protocol;
    __u16           inner_transport_header;    
    __u16           inner_network_header;    
    __u16           inner_mac_header;    
    __u16           transport_header;   // 指向传输层包头
    __u16           network_header;     // 指向传输层包头
    __u16           mac_header;            // 指向链路层包头
    
    /* private: */ 
     __u32               headers_end[0]; /*缓冲区的尾部*/
    
    /* public: 
     * These elements must be at the end, see alloc_skb() for details. 
     */
    sk_buff_data_t      tail;            // 缓冲区的数据包末尾位置
    sk_buff_data_t      end;            // 缓冲区的结束地址
    unsigned char       *head,            // 缓冲区的开始地址
    unsigned char        *data;            // 缓冲区的数据包开始位置
    unsigned int        truesize; 
    atomic_t            users; 
};
```
1. 数据缓冲区指针 head、data、tail 和 end。

>head 指针指向内存中已分配的用于承载网络数据的缓冲区的起始地址;
>data 指针则指向对应当前协议层有效数据的起始地址。各层的有效数据信息包含的内容都不一样：对于传输层而言，用户数据和传输层协议头属于有效数据。 l 对于网络层而言，用户数据、传输层协议头和网络层协议头是其有效数据。 l 对于数据链路层而言，用户数据、传输层协议头、网络层协议头和链路层头 部都属于有效数据。 因此，data 指针的值需随着当前拥有 sk_buff 的协议层的变化进行相应的移动。
>tail 指针则指向对应当前协议层有效数据负载的结尾地址，与 data 指针对应。
>end 指针指向内存中分配的数据缓冲区的结尾，与 head 指针对应。

其实，end 指针所指地 址 数 据 缓 冲 区 的 末 尾 还 包 括 一 个 `​​skb_shared_info` ​​结构体的空间，这个结构体 存放分隔存储的数据片段，意味着可以将数 据包的有效数据分成几片存储在不同的内存空间中。 每一个分片frags的长度上限是一页。

- sk_buff结构体的空间
![](assets/Pasted%20image%2020230414164025.png)

2. 长度信息 len、data_len、truesize

>len是指数据包有 效数据的长度，包括协议头和负载；
>data_len 这个成员，它记录分片的 数据长度；
>truesize 表示缓存区的整体长度: sizeof(struct sk_buff) + “传入 alloc_skb()或dev_alloc_skb()的长度“（但不包括结构体 skb_shared_info 的长度）。

- sk_buff-> data数据包格式
![](assets/Pasted%20image%2020230414164110.png)

3. 套接字缓冲区操作
	- 分配:
		- 函数原型
```c
struct sk_buff *alloc_skb(unsigned int len, gfp_t priority);

struct sk_buff *dev_alloc_skb(unsigned len);
```
- 参数：
len：缓冲区大小，通常以L1_CACHE_BYTES字节(对于ARM为32)对齐
priority：内存分配优先级，为GFP MASK宏，比如GFP_KERNEL、GFP_ATOMIC 等
返回值：成功则返回分配好的sk_buff指针；失败则返回NULL。

区别：
- alloc_skb 函数分配一个缓存并且将 skb->data 和skb->tail 都初始化成 skb->head。
- dev_alloc_skb函数表示以GFP_ATOMIC 优先级（代表分配过程不能被中断）调用 alloc_skb 的快捷方法, 并且在 skb->head 和skb->data 之间保留了一些空间用于网络层之间的优化(16 个字节)，驱动不要管它。
- 分配成功之后，因为还没有存放具体的网络数据包，所以 sk_buff 的 data、tail 指 针都指向存储空间的起始地址 head，而 len 的大小则为 0。

	- 释放
		- 函数原型
```c
void kfree_skb(struct sk_buff *skb);  //在内核内部使用，而网络设备 驱动程序中则必须使用下面3个其一
void dev_kfree_skb(struct sk_buff *skb); //用于非中断上下文
void dev_kfree_skb_irq(struct sk_buff *skb); //用于中断上下文
void dev_kfree_skb_any(struct sk_buff *skb); //在中断和非中断上下文中皆可采用
```
- 参数：
skb：待释放的套接字缓冲区
返回值：无

区别：
- kfree_skb 由内核在内部使用，驱动应当使用其中一种变体:
- 在非中断上下文中使用 dev_kfree_skb；
- 在中断上下文中使用 dev_kfree_skb_irq；
- dev_kfree_skb_any 在任何2 种情况下。

4. 空间调整
套接字缓冲区中的数据缓冲区指针移动操作包括 put（放置）、push（推）、 pull（拉）、reserve（保留）等。无前导`​​__​​​`的函数会检查数据大小是否适合缓存, 而有前导​​`__​​`的函数会省略这个检查。

- put 操作（用于在缓冲区尾部添加数据）：
```c
unsigned char *skb_put(struct sk_buff *skb, unsigned int len); //会检测放入缓冲区的数据
unsigned char *__skb_put(struct sk_buff *skb, unsigned int len); //不会检测放入缓冲区的数据
```

上述函数将 tail 指针下移，增加 sk_buff 的 len 值，并返回 skb->tail 的当前值。
![](assets/Pasted%20image%2020230414164758.png)

- push 操作（用于在数据包发送时添加头部）
```c
unsigned char *skb_push(struct sk_buff *skb, unsigned int len); //会检测放入缓冲区的数据
unsigned char *_ _skb_push(struct sk_buff *skb, unsigned int len); //不会检测放入缓冲区的数据
```

在缓冲区尾部增加数据，会导致skb->tail后移len(skb->tail += len)，而skb->len会增加len的大小(skb->len += len)。通常，在设备驱动的接收数据处理中会调用此类函数。
![](assets/Pasted%20image%2020230414164838.png)

- pull 操作（用于下层协议向上层协议移交数据包，使 data 指针指向上一层协议的协议头）
```c
unsigned char * skb_pull(struct sk_buff *skb, unsigned int len);

```

从数据区头部删除数据，它会将skb->data后移len，同时保持skb->tail不变。执行skb->data -= len、skb->len -= len。
![](assets/Pasted%20image%2020230414164906.png)

- reserve 操作（用于在存储空间 的头部预留 len 长度的空隙）
```c
void skb_reserve(struct sk_buff *skb, unsigned int len);
```

它会将skb->data和skb->tail同时后移len，执行skb->data += len、skb->tail += len。
使用举例:
分配一个全新的sk_buff，接着调用skb_reserve()腾出头部空间，之后调用skb_put()腾出数据空间，然后把数据复制进来，最后把sk_buff传给协议栈。
```c
skb = alloc_skb(len + headspace, GFP_KERNEL);
skb_reserve(skb, headspace);
memcpy(skb_put(skb, len), data, len);
pass_to_m_protocol(skb);
```

## 1.3 网卡驱动发包过程

在内核中,当上层要发送一个数据包时, 就会调用网络设备层里net_device数据结构的成员hard_start_xmit()将数据包发送出去。

hard_start_xmit()发包函数需要我们自己构建,该函数原型如下所示:
```c
int (*hard_start_xmit) (struct sk_buff *skb, struct net_device *dev);
```

发包函数处理步骤：

- 1、把数据包发出去之前,需要使用 `netif_stop_queue()`来停止上层传下来的数据包；
- 2.1、设置寄存器，通过网络设备硬件来发送数据
- 2.2、当数据包发出去后, 再调用dev_kfree_skb()函数来释放sk_buff,该函数原型如下: `​​void dev_kfree_skb(struct sk_buff *skb);`​​
- 3、当数据包发出成功,就会进入TX接收中断函数，然后更新统计信息，调用`netif_wake_queue()`来唤醒，启动上层继续发包下来；
- 4、若数据包发出去超时，一直进不到TX中断函数,就会调用net_device结构体的`*tx_timeout`超时成员函数，在该函数中更新统计信息，并调用`netif_wake_queue()`来唤醒。

## 1.4 网卡驱动收包过程
接收数据包主要是通过中断函数处理,来判断中断类型，如果等于ISQ_RECEIVER_EVENT表示为接收中断,然后进入接收数据函数,通过​​netif_rx()​​​将数据上交给上层。例如，下图内核中自带的网卡驱动:`​​/drivers/net/cs89x0.c​​`
```c
static irqreturn_t net_interupt(int irq, void *dev_id)
{
    struct net_device *dev = dev_id;
    struct net_local *lp;
    int ioaddr,status;
    int handler = 0;
    
    ioaddr = dev->base_addr;
    ip = netdev_priv(dev);
    
    while((status = readword(dev->base_addr,ISO_PORT))){
        if(net_debug > 4)
            printk("%s:event=%04x\n",dev->name,status);
        handled = 1;
        switch(status&ISO_EVENT_MASK){
            case ISO_RECEIVER_EVENT:    //判断是否为接收中断
                net_rx(dev);            //进入net_rx()函数，将接收的数据上交给上层
                break;
            case ISO_TRANSMITTER_EVENT:    //判断是否为发送中断
                ip->stats.tx_packets++;
                netif_wake_queue(dev);
                ...
        }
    }
}
```

通过获取的status标志来判断是什么中断,如果是接收中断,就进入net_rx()。
- 收包函数处理步骤：

1、使用​​dev_alloc_skb()​​来构造一个新的sk_buff；
2、使用​​skb_reserve(rx_skb, 2)​​ 将sk_buff缓冲区里的数据包先向后位移2字节，腾出sk_buff缓冲区里的头部空间；
3、读取网络设备硬件上接收到的数据；
4、使用​​memcpy()​​将数据复制到新的sk_buff里的data成员指向的地址处,可以使用skb_put()来动态扩大sk_buff结构体里中的数据区；
5、使用​​eth_type_trans()​​来获取上层协议,将返回值赋给sk_buff的protocol成员里；
6、然后更新统计信息，最后使用netif_rx( )来将sk_fuffer传递给上层协议中。

- skb_put()函数
- 
原型：​​`static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len);​​`
作用：将数据区向下扩大len字节
sk_buff缓冲区变化图：

![](assets/Pasted%20image%2020230414165356.png)

## 1.5 网卡驱动的注册与注销

网络设备驱动的注册与注销使用成对出现的​​register_netdev()​​​和​​unregister_netdev() ​​函数完成，这两个函数的原型为：
```c
int register_netdev(struct net_device *dev); 
void unregister_netdev(struct net_device *dev);

```
这两个函数都接收一个 net_device 结构体指针为参数， net_device 的生成和成员的赋值并非一定要由工程师逐个亲自动手完成，可以利 用下面的函数帮助我们填充：
```c
struct net_device *alloc_netdev(int sizeof_priv, const char *name,  
                                void(*setup)(struct net_device*));  

struct net_device *alloc_etherdev(int sizeof_priv)
{ 
    /* 以 ether_setup 为 alloc_netdev 的 setup 参数 */ 
    return alloc_netdev(sizeof_priv, "eth%d", ether_setup); 
}
```
​​
`alloc_netdev()`​​函数生成一个 net_device 结构体，对其成员赋值并返回该结构体的指针。第一个参数为设备私有成员的大小，第二个参数为设备名，第三个参数为 net_device 的 setup()函数指针。setup()函数接收的参数也为 net_device 指针，用 于预置 net_device 成员的值。

alloc_etherdev()是 alloc_netdev()针对以太网的“快捷”函数，其中的ether_setup()是由 Linux 内核提供的一个对以太网设备 net_device 结构体中公有成员 快速赋值的函数

释放 net_device 结构体 的函数为：
```c
void free_netdev(struct net_device *dev);
```

## 1.6 NAPI

- Linux 里面的网络数据接收也轮询和中断两种：
	- 通常情况下，网络设备驱动以中断方式接收数据包。中断的好处就是响应快，数据量小的时候处理及时，速度、快，但是一旦当数据量大，而且都是短帧的时候会导致中断频繁发生，消耗大量的CPU处理时间在中断自身处理上。
	- 而poll_controller()则采用纯轮询方式。轮询恰好相反，响应没有中断及时，但是在处理大量数据的时候不需要消耗过多的CPU 处理时间。

- linux在这两个处理方式的基础上，提出了另外一种高效的网络数据接收的处理方法：NAPI(New API)：
	- 核心思想：中断（用来唤醒数据接收服务程序）+ 轮询（在接受服务程序中采用POLL的方法来轮询处理数据）
	- 其数据接收流程为：“接收中断来临->关闭接收中断->以轮询方式接收所有数据包直到收空->开启接收中断->接收中断来临……”

- NAPI相关的操作接口

1. 添加/移除NAPI调度
```c
/*初始化NAPI
@ 定义在 net/core/dev.c中
@ 初始化一个 napi_struct实例
@ dev：每个NAPI 必须关联一个网络设备，此参数指定NAPI要关联的网络设备。
@ napi：要初始化的 NAPI实例
@ poll： NAPI所使用的轮询函数，非常重要，一般在此轮询函数中完成网络数据接收的工作。
@ weight：NAPI默认权重(weight)，一般为NAPI_POLL_WEIGHT。 
@ 返回值：无。
*/
void netif_napi_add(struct net_device *dev, struct napi_struct *napi, 
                    int (*poll)(struct napi_struct *, int), 
                    int weight);

void netif_napi_del(struct napi_struct *napi);

```
poll参数是NAPI要调度执行的轮询函数。

2. 使能和禁止NAPI调度
```c
/*  使能/失能NAPI 
 @ n：要使能/失能的NAPI
 @ 返回值：无。 
 */
static inline void napi_enable(struct napi_struct *n);
static inline void napi_disable(struct napi_struct *n);

```

3. 调度轮询实例的运行
```c
/*NAPI调度 
@ n：要调度的NAPI。 
@ 返回值：无。 
*/
void __napi_schedule(struct napi_struct *n) 

/*是否可以调度+调度 
@ n：要调度的NAPI。 
*/
 static inline void napi_schedule(struct napi_struct *n) 
 { 
     if (napi_schedule_prep(n)) 
         __napi_schedule(n); 
 }

```

4. NAPI处理完成的时候应该调用
```c
/*
@ n：处理完成的NAPI。
@ 返回值：无。 
*/
void napi_complete(struct napi_struct *n);
```

# 2、编写虚拟网卡驱动

虚拟网卡驱动,也就是说不需要硬件相关操作,所以就没有中断函数,我们通过linux的ping命令来实现发包,然后在发包函数中伪造一个收的ping包函数,实现能ping通任何ip地址。编写步骤：

## 1. 初始化（init）
设备探测工作在init方法中进行，一般调用一个称之为probe方法的函数

初始化的主要工作时检测设备，配置和初始化硬件，最后向系统申请这些资源。此外填充该设备的dev结构，我们调用内核提供的ether_setup方法来设置一些以太网默认的设置。

流程：

（1）定义一个net_device结构体变量
（2）使用函数 alloc_netdev()分配一个 net_device 结构体变量
（3）初始化化硬件寄存器
（4）设置net_device结构体变量成员变量
（5）使用register_netdev()注册 net_device结构体变量

## 2. 打开(open)

open这个方法在网络设备驱动程序里是网络设备被激活时被调用（即设备状态由down变成up）

实际上很多在初始化的工作可以放到这里来做。比如说资源的申请，硬件的激活。如果dev->open返回非0，则硬件状态还是down，
注册中断、DMA等；设置寄存器，启动设备；启动发送队列

一般注册中断都在init中做，但在网卡驱动程序中，注册中断大部分都是放在open中注册，因为要经常关闭和重启网卡

## 3. 关闭(stop)

stop方法做和open相反的工作

可以释放某些资源以减少系统负担

stop是在设备状态由up转为down时被调用

## 4. 发送（hard_start_xmit）

在系统调用的驱动程序的hard_start_xmit时，发送的数据放在一个sk_buff结构中。一般的驱动程序传给硬件发出去。也有一些特殊的设备比如说loopback把数据组成一个接收数据在传送给系统或者dummy设备直接丢弃数据。如果发送成功,hard_start_xmit方法释放sk_buff。如果设备暂时无法处理，比如硬件忙，则返回1。

发包函数ndo_start_xmit 中具体要做
（1）调用函数 netif_stop_queue()停止上层下传数据。
（2）通过硬件发送数据。
（3）调用函数 dev_kfree_skb()释放 sk_buff。
（4）发送成功进入中断时，更新统计信息，调用netif_wake_queue()，使上层继续下发数据
（5）发送超时则在net_device_ops 中的ndo_tx_timeout 函数中调用 netif_wake_queue()函数， 使上层继续下发数据。
```c
#define dev_kfree_skb(a)  consume_skb(a)
void consume_skb(struct sk_buff *skb)
    
static inline void netif_wake_queue(struct net_device *dev);

static inline void netif_stop_queue(struct net_device *dev);

```

## 5. 接收

驱动程序并存在一个接受方法。当有数据收到时驱动程序调用netif_rx函数将skb交交给设备无关层。

一般设备收到数据后都会产生一个中断，在中断处理程序中驱动程序申请一块sk_buff(skb)从硬件中读取数据位置到申请号的缓冲区里。

接下来填充sk_buff中的一些信息。

中断有可能是收到数据产生也可能是发送完成产生，中断处理程序要对中断类型进行判断，如果是收到数据中断则开始接收数据，如果是发送完成中断，则处理发送完成后的一些操作，比如说重启发送队列。
接收流程：
（1）使用 alloc_skb()函数极造一个 sk_buff。

（2）使用skb_reserve(sk_buff,2)把sk_buff 里数据包先后位移2 字节以腾出sk_buff里头部空间。

（3）读取网络设备硬件上接收到的数据，把数据复制到 sk_buff 的成员 data 挃针。

（4）使用eth_type_trans()函数来获取上层协议，将返回值赋给sk_buff的成员protocol。

（5）更新统计信息，最后使用netif_rx()将sk_buff上传到上层协议。

## 6. 中断处理

网络接口通常支持3种类型的中断：新报文到达中断、报文发送完成中断和出错中断。中断处理程序可通过查看网卡的中断状态寄存器，来分辨出中断类型。

具体代码:
```c
/*
 * 参考 drivers\net\cs89x0.c
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/ip.h>

#include <asm/system.h>
#include <asm/io.h>
#include <asm/irq.h>

static struct net_device *vnet_dev;

static void emulator_rx_packet(struct sk_buff *skb, struct net_device *dev)
{
    /* 参考LDD3 */
    unsigned char *type;
    struct iphdr *ih;
    __be32 *saddr, *daddr, tmp;
    unsigned char    tmp_dev_addr[ETH_ALEN];
    struct ethhdr *ethhdr;
    
    struct sk_buff *rx_skb;
        
    /* 1.对调ethhdr结构体的"源/目的"的mac地址 */
    ethhdr = (struct ethhdr *)skb->data;
    memcpy(tmp_dev_addr, ethhdr->h_dest, ETH_ALEN);
    memcpy(ethhdr->h_dest, ethhdr->h_source, ETH_ALEN);
    memcpy(ethhdr->h_source, tmp_dev_addr, ETH_ALEN);

    /* 2.对调iphdr结构体的"源/目的"的ip地址 */    
    ih = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    saddr = &ih->saddr;
    daddr = &ih->daddr;

    tmp = *saddr;
    *saddr = *daddr;
    *daddr = tmp;
    
    /* 3.使用ip_fast_csum()来重新获取iphdr结构体的校验码*/
    ih->check = 0;           /* and rebuild the checksum (ip needs it) */
    ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);
    
    /* 4.设置数据类型*/
    type = skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    *type = 0; /*原来0x8表示发送ping包，现在0表示接收ping包 */
    
    /* 5.构造一个新的sk_buff */
    rx_skb = dev_alloc_skb(skb->len + 2);
    
    /* 6.使用skb_reserve腾出2字节头部空间*/
    skb_reserve(rx_skb, 2); /* align IP on 16B boundary */    
    
    /* 7.将之前修改好的sk_buff->data复制到新的sk_buff里 */
    memcpy(skb_put(rx_skb, skb->len), skb->data, skb->len);    //用skb_put()扩大sk_buff的数据区，避免溢出

    /* 8.设置新sk_buff的其它成员*/
    rx_skb->dev = dev;
    rx_skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
    
    /* 9.使用eth_type_trans()来获取上层协议 */
    rx_skb->protocol = eth_type_trans(rx_skb, dev);
    
    /* 10.更新接收统计信息,并向上层传递sk_fuffer收包 */
    dev->stats.rx_packets++;
    dev->stats.rx_bytes += skb->len;
    dev->last_rx = jiffies;        //收包时间戳

    // 提交sk_buff
    netif_rx(rx_skb);
}

static int virt_net_send_packet(struct sk_buff *skb, struct net_device *dev)
{
    static int cnt = 0;
    printk("virt_net_send_packet cnt = %d\n", ++cnt);

    /* 1.停止该网卡的队列，阻止上层向驱动层继续发送数据包 */
    netif_stop_queue(dev); 
    
    /* 2.真实驱动要把skb的数据写入网卡 ，但在此先通过emulator_rx_packet模拟 */
    emulator_rx_packet(skb, dev);    /* 构造一个假的sk_buff,上报 */

    /* 3.释放发送的sk_buff缓存区*/
    dev_kfree_skb (skb);
    
    /* 4.更新统计信息 */
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;
    dev->trans_start = jiffies;    //发送时间戳
    
    /* 5.数据全部发送出去后,唤醒网卡的队列 （真实网卡应在中断函数里唤醒）*/
    netif_wake_queue(dev); 
    
    return 0;
}


static const struct net_device_ops vnetdev_ops = {
    .ndo_start_xmit        = virt_net_send_packet,
};

static int virt_net_init(void)
{
    /* 1. 分配一个net_device结构体 */
    vnet_dev = alloc_netdev(0, "vnet%d", ether_setup);;  /* alloc_ether_dev */

    /* 2. 设置 */
    //vnet_dev->hard_start_xmit = virt_net_send_packet;
    vnet_dev->netdev_ops    = &vnetdev_ops;

    /* 设置MAC地址 */
    vnet_dev->dev_addr[0] = 0x08;
    vnet_dev->dev_addr[1] = 0x89;
    vnet_dev->dev_addr[2] = 0x66;
    vnet_dev->dev_addr[3] = 0x77;
    vnet_dev->dev_addr[4] = 0x88;
    vnet_dev->dev_addr[5] = 0x99;

    /* 设置下面两项才能ping通 */
    vnet_dev->flags           |= IFF_NOARP;
    vnet_dev->features        |= NETIF_F_IP_CSUM;

    /* 3. 注册 */
    //register_netdevice(vnet_dev);     //编译会出错！
    register_netdev(vnet_dev);
    
    return 0;
}

static void virt_net_exit(void)
{
    unregister_netdev(vnet_dev);
    free_netdev(vnet_dev);
}

module_init(virt_net_init);
module_exit(virt_net_exit);

MODULE_AUTHOR("liangzc1124@163.com");
MODULE_LICENSE("GPL");
```

测试如下：
挂载驱动,可以看到net类下就有了这个网卡设备，并尝试ping自己
![](assets/Pasted%20image%2020230414170006.png)

上图的ping之所以成功，并是因为我们在发包函数中伪造了一个来收包，而是因为linux中，ping自己的时候并不调用（不需要）发送函数向网络设备发送sk_buff数据包。

ping同网段其它地址
![](assets/Pasted%20image%2020230414170032.png)

![](assets/Pasted%20image%2020230414170113.png)

ping其它ip地址之所以成功，是因为我们在发包函数中利用emulator_rx_packet函数伪造了一个接收数据包，并通过netif_rx()来将收包上传给上层。

# 3、移植内核自带的网卡驱动程序
在移植之前，首先我们来看一下mini2440（对应的机器ID为：set machid 7CF）中，是如何支持dm9000网卡的。
进入到入口函数，找到结构体：
```c
static struct platform_driver dm9000_driver = {
  .driver  = {
    .name    = "dm9000",
    .owner   = THIS_MODULE,
    .pm   = &dm9000_drv_pm_ops,
  },
  .probe   = dm9000_probe,
  .remove  = __devexit_p(dm9000_drv_remove),
};

```
一般是通过.name这个成员进行匹配的，搜索字符串“dm9000”，找到如下结构体（在平台文件中：`arch\arm\mach-s3c24xx\Mach-mini2440.c`）：

```c
static struct platform_device mini2440_device_eth = {
  .name    = "dm9000",
  .id    = -1,
  .num_resources  = ARRAY_SIZE(mini2440_dm9k_resource),
  .resource  = mini2440_dm9k_resource,
  .dev    = {
    .platform_data  = &mini2440_dm9k_pdata,
  },
};
```

然后搜索结构体mini2440_device_eth，找到：
```c
static struct platform_device *mini2440_devices[] __initdata = {
  &s3c_device_ohci,
  &s3c_device_wdt,
  &s3c_device_i2c0,
  &s3c_device_rtc,
  &s3c_device_usbgadget,
  &mini2440_device_eth,  //在这里
  &mini2440_led1,
  &mini2440_led2,
  &mini2440_led3,
  &mini2440_led4,
  &mini2440_button_device,
  &s3c_device_nand,
  &s3c_device_sdi,
  &s3c_device_iis,
  &uda1340_codec,
  &mini2440_audio,
  &samsung_asoc_dma,
};
```
然后再搜索：mini2440_devices，找到：
```c
platform_add_devices(mini2440_devices, ARRAY_SIZE(mini2440_devices));
```
这就是把结构体mini2440_devices添加到内核，里面的关于网卡的结构在里面，最终匹配驱动程序，就可以使用驱动程序了。
（这就是所谓的平台设备平台驱动的东西了，把可变的东西抽象出来放到平台相关的文件中定义，而我们的驱动程序，基本上是不需要改变的，它是稳定的内容，我们移植的时候，只需要把平台层可变的相关结构体加上，需要修改的资源，进行修改就可以了）。

而我们用的是smdk2440（对应的机器ID为：set machid 16a），然后我在Mach-smdk2440.c中添加以下函数：

```c
/* 以下为liangzc1124@163.com 添加
 * The DM9000 has no eeprom, and it's MAC address is set by
 * the bootloader before starting the kernel.
 */


/* DM9000AEP 10/100 ethernet controller */

#define MACH_SMDK2440_DM9K_BASE (S3C2410_CS4 + 0x300)


static struct resource smdk2440_dm9k_resource[] = {
  [0] = {
    .start = MACH_SMDK2440_DM9K_BASE,
    .end   = MACH_SMDK2440_DM9K_BASE + 3,
    .flags = IORESOURCE_MEM
  },
  [1] = {
    .start = MACH_SMDK2440_DM9K_BASE + 4,
    .end   = MACH_SMDK2440_DM9K_BASE + 7,
    .flags = IORESOURCE_MEM
  },
  [2] = {
    .start = IRQ_EINT7,
    .end   = IRQ_EINT7,
    .flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHEDGE,
  }
};


static struct dm9000_plat_data smdk2440_dm9k_pdata = {
  .flags    = (DM9000_PLATF_16BITONLY | DM9000_PLATF_NO_EEPROM),
};

static struct platform_device smdk2440_device_eth = {
  .name    = "dm9000",
  .id    = -1,
  .num_resources  = ARRAY_SIZE(smdk2440_dm9k_resource),
  .resource  = smdk2440_dm9k_resource,
  .dev    = {
    .platform_data  = &smdk2440_dm9k_pdata,
  },
};

```

在结构体smdk2440_devices中添加网卡成员：
```c
static struct platform_device *smdk2440_devices[] __initdata = {
  &s3c_device_ohci,
  &s3c_device_lcd,
  &s3c_device_wdt,
  &s3c_device_i2c0,
  &s3c_device_iis,
  &smdk2440_device_eth, /* lyy:添加 */
};
```

添加头文件：
```c
#include <linux/dm9000.h>  /* 以下为liangzc1124@163.com 添加*/
```

然后重新编译内核。成功。烧写新内核：
```shell
S3C2440A # nfs 30000000 192.168.1.101:/home/leon/nfs_root/first_fs/uImage;

S3C2440A # bootm 30000000

```

然后挂载网络文件系统：
`​​​mount -t nfs -o nolock 192.168.1.101:/home/leon/nfs_root/first_fs /mnt​​`
成功挂载网络文件系统。

# 4、自己编写网卡驱动程序

有时候，内核自带的网卡驱动程序比较老，而我们的硬件有可能比较新，那么我们就不能使用内核的网卡驱动程序了，就需要去移植最新的网卡驱动程序，那么这种类型的，又该如何移植呢？

## 4.1 网络设备驱动程序的模块加载和卸载函数

```c
int xxx_init_module(void) 
{ 
  ... 
  /* 分配 net_device 结构体并对其成员赋值 */ 
  xxx_dev = alloc_netdev(sizeof(struct xxx_priv), "sn%d", xxx_init); 
  if (xxx_dev == NULL) 
  ... /* 分配 net_device 失败 */ 

  /* 注册 net_device 结构体 */ 
  if ((result = register_netdev(xxx_dev))) 
  ... 
} 

void xxx_cleanup(void) 
{ 
  ... 
  /* 注销 net_device 结构体 */ 
  unregister_netdev(xxx_dev); 
  /* 释放 net_device 结构体 */ 
  free_netdev(xxx_dev); 
}

```

## 4.2 网络设备的初始化

网络设备的初始化主要需要完成如下几个方面的工作：
1. 进行硬件上的准备工作，检查网络设备是否存在，如果存在，则检测设备使用的硬件资源；
2. 进行软件接口上的准备工作，分配 net_device 结构体并对其数据和函数指针 成员赋值；
3. 获得设备的私有信息指针并初始化其各成员的值。如果私有信息中包括自旋 锁或信号量等并发或同步机制，则需对其进行初始化。

个网络设备驱动初始化函数的模板如下所示：

```c
void xxx_init(struct net_device *dev) 
{ 
  /*设备的私有信息结构体*/ 
  struct xxx_priv *priv; 
 
  /* 检查设备是否存在、具体硬件配置和设置设备所使用的硬件资源 */ 
  xxx_hw_init(); 
 
  /* 初始化以太网设备的公用成员 */ 
  ether_setup(dev); 
 
  /*设置设备的成员函数指针*/ 
  dev->open = xxx_open; 
  dev->stop = xxx_release; 
  dev->set_config = xxx_config; 
  dev->hard_start_xmit = xxx_tx; 
  dev->do_ioctl = xxx_ioctl; 
  dev->get_stats = xxx_stats; 
  dev->change_mtu = xxx_change_mtu; 
  dev->rebuild_header = xxx_rebuild_header; 
  dev->hard_header = xxx_header; 
  dev->tx_timeout = xxx_tx_timeout; 
  dev->watchdog_timeo = timeout; 
 
  /*如果使用 NAPI，设置 pool 函数*/ 
  if (use_napi) 
  { 
    dev->poll = xxx_poll; 
  } 

  /* 取得私有信息，并初始化它*/ 
  priv = netdev_priv(dev);
    ... /* 初始化设备私有数据区 */ 
}
```

## 4.3 网络设备的打开与释放

网络设备的打开函数需要完成如下工作。

1. 使能设备使用的硬件资源，申请 I/O 区域、中断和 DMA 通道等。
2. 调用 Linux 内核提供的 netif_start_queue()函数，激活设备发送队列。 网络设备的关闭函数需要完成如下工作。
3. 调用 Linux 内核提供的 netif_stop_queue()函数，停止设备传输包。
4. 释放设备所使用的 I/O 区域、中断和 DMA 资源。

Linux 内核提供的 netif_start_queue()和 netif_stop_queue()两个函数的原型为：
```c
void netif_start_queue(struct net_device *dev);  
void netif_stop_queue (struct net_device *dev);
```

根据以上分析，可得出网络设备打开和释放函数的模板:
```c
int xxx_open(struct net_device *dev) 
{ 
  /* 申请端口、IRQ 等，类似于 fops->open */ 
  ret = request_irq(dev->irq, &xxx_interrupt, 0, dev->name, dev); 
  ... 
  netif_start_queue(dev); 
  ... 
} 
 
int xxx_release(struct net_device *dev) 
{ 
  /* 释放端口、IRQ 等，类似于 fops->close */ 
  free_irq(dev->irq, dev); 
  ... 
  netif_stop_queue(dev); /* can't transmit any more */ 
  ... 
}

```

## 4.4 数据发送流程

（1）网络设备驱动程序从上层协议传递过来的 sk_buff 参数获得数据包的有效数 据和长度，将有效数据放入临时缓冲区。

（2）对于以太网，如果有效数据的长度小于以太网冲突检测所要求数据帧的最小 长度 ETH_ZLEN，则给临时缓冲区的末尾填充 0。

（3）设置硬件的寄存器，驱使网络设备进行数据发送操作。

```c
int xxx_tx(struct sk_buff *skb, struct net_device *dev) 
{ 
  int len; 
  char *data, shortpkt[ETH_ZLEN]; 
  /* 获得有效数据指针和长度 */ 
  data = skb->data; 
  len = skb->len; 
  if (len < ETH_ZLEN) 
  { 
    /* 如果帧长小于以太网帧最小长度，补 0 */ 
  memset(shortpkt, 0, ETH_ZLEN); 
  memcpy(shortpkt, skb->data, skb->len); 
  len = ETH_ZLEN; 
  data = shortpkt; 
  } 
 
  dev->trans_start = jiffies; /* 记录发送时间戳 */ 
 
  /* 设置硬件寄存器让硬件把数据包发送出去 */ 
  xxx_hw_tx(data, len, dev); 
  ... 
}

```

当数据传输超时时，意味着当前的发送操作失败，此时，数据包发送超时处理函 数 xxx_tx_ timeout()将被调用。这个函数需要调用 Linux 内核提供的 netif_wake_queue()函数重新启动设备发送队列：
```c
void xxx_tx_timeout(struct net_device *dev) 
{ 
  ... 
  netif_wake_queue(dev); /* 重新启动设备发送队列 */ 
}
```

## 4.5 数据接收流程

网络设备接收数据的主要方法是由中断引发设备的中断处理函数，中断处理函数 判断中断类型，如果为接收中断，则读取接收到的数据，分配 sk_buffer 数据结构和数 据缓冲区，将接收到的数据复制到数据缓冲区，并调用 netif_rx()函数将 sk_buffer 传 递给上层协议。完成这一过程的函数模板：
```c
static void xxx_interrupt(int irq, void *dev_id, struct pt_regs *regs) 
{ 
    ... 
    switch (status &ISQ_EVENT_MASK) 
    { 
        case ISQ_RECEIVER_EVENT: /* 获取数据包 */
            xxx_rx(dev); 
            break; 
            /* 其他类型的中断 */ 
    } 
} 

static void xxx_rx(struct xxx_device *dev) 
{ 
    ... 
    length = get_rev_len (...); 
    /* 分配新的套接字缓冲区 */ 
    skb = dev_alloc_skb(length + 2); 
    skb_reserve(skb, 2); /* 对齐 */ 
    skb->dev = dev; 

    /* 读取硬件上接收到的数据 */ 
    insw(ioaddr + RX_FRAME_PORT, skb_put(skb, length), length >> 1); 
    if (length &1) 
        skb->data[length - 1] = inw(ioaddr + RX_FRAME_PORT); 
 
    /* 获取上层协议类型 */ 
    skb->protocol = eth_type_trans(skb, dev); 
 
    /* 把数据包交给上层 */ 
    netif_rx(skb); 
 
    /* 记录接收时间戳 */ 
    dev->last_rx = jiffies; 
    ... 
}

```

如果是 NAPI 兼容的设备驱动，则可以通过 poll 方式接收数据包。这种情况下， 我们需要为该设备驱动提供 xxx_poll()函数:
```c
static int xxx_poll(struct net_device *dev, int *budget) 
{ 
    //dev->quota 是当前 CPU 能够从所有接口中接收数据包的最大数目，budget 是在初始化阶段分配给接口的 weight 值
    int npackets = 0, quota = min(dev->quota, *budget); 
    struct sk_buff *skb; 
    struct xxx_priv *priv = netdev_priv(dev); 
    struct xxx_packet *pkt; 

    while (npackets < quota && priv->rx_queue) 
    { 
        /*从队列中取出数据包*/ 
        pkt = xxx_dequeue_buf(dev); 
 
        /*接下来的处理，和中断触发的数据包接收一致*/ 
        skb = dev_alloc_skb(pkt->datalen + 2); 
        if (!skb) 
        { 
            ... 
            continue; 
        } 
        skb_reserve(skb, 2); 
        memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen); 
        skb->dev = dev; 
        skb->protocol = eth_type_trans(skb, dev); 
        /*调用 netif_receive_skb 而不是 net_rx 将数据包交给上层协议
          这里体现出了中断处理机制和轮询机制之间的差别。
         */ 
        netif_receive_skb(skb); 

        /*更改统计数据 */ 
        priv->stats.rx_packets++; 
        priv->stats.rx_bytes += pkt->datalen; 
        xxx_release_buffer(pkt); 
    } 
    /* 网络设备接收缓冲区中的数据包都被读取完了*/ 
    *budget -= npackets; 
    dev->quota -= npackets; 

    if (!priv->rx_queue) 
    { 
        netif_rx_complete(dev); //把当前指定的设备从 poll 队列中清除
        xxx_enable_rx_int (…); /* 再次使能网络设备的接收中断 */ 
        return 0; 
    } 

    return 1; 
}
```
虽然 NAPI 兼容的设备驱动以 poll 方式接收数据包，但是仍然需要首次数据包接 收中断来触发 poll 过程。与数据包的中断接收方式不同的是，以轮询方式接收数据包 时，当第一次中断发生后，中断处理程序要禁止设备的数据包接收中断。poll 中断处理函数如下：

```c
static void xxx_poll_interrupt(int irq, void *dev_id, struct pt_regs *regs) 
{ 
    switch (status &ISQ_EVENT_MASK) 
    { 
    case ISQ_RECEIVER_EVENT:
        .../* 获取数据包 */ 
        xxx_disable_rx_int(...); /* 禁止接收中断 */ 
        netif_rx_schedule(dev); 
        break;
    .../* 其他类型的中断 */ 
    } 
}

```

上述代码的 ​​netif_rx_schedule()​​函数被轮询方式驱动的中断程序调用，将设 备的 poll 方法添加到网络层的 poll 处理队列中，排队并且准备接收数据包，最终触发 一个 NET_RX_SOFTIRQ 软中断，通知网络层接收数据包。下图为 NAPI 驱动 程序各部分的调用关系：
![](assets/Pasted%20image%2020230414171500.png)

## 4.6 网络连接状态

网络设备驱动程序中往往设置一个定时器来对链路状态进行周期性地检查。当定 时器到期之后，在定时器处理函数中读取物理设备的相关寄存器获得载波状态，从而 更新设备的连接状态。

网络设备驱动可以通过 ​​netif_carrier_on()​​​和​​ netif_carrier_off()​​​函数改变或通知内核网络设备的连接状态。此外，函数 ​​netif_carrier_ok()​​ 可用于向调用者返回链路上的载波信号是否存在。

```c
void netif_carrier_on(struct net_device *dev); 
void netif_carrier_off(struct net_device *dev); 
int netif_carrier_ok(struct net_device *dev);
```

以下代码显示了网络设备驱动用定时器周期检查链路状态：
```c
static void xxx_timer(unsigned long data) 
{ 
    struct net_device *dev = (struct net_device*)data; 
    u16 link; 
    ...
    if (!(dev->flags &IFF_UP)) 
    { 
        goto set_timer; 
    }
    /* 获得物理上的连接状态 */ 
    if (link = xxx_chk_link(dev)) //读取网络适配器硬件的相关寄存器以获得链路连接状态
    { 
        if (!(dev->flags &IFF_RUNNING)) 
        { 
            netif_carrier_on(dev); 
            dev->flags |= IFF_RUNNING; 
            printk(KERN_DEBUG "%s: link up\n", dev->name); 
        } 
    } 
    else    
    { 
        if (dev->flags &IFF_RUNNING) 
        { 
            netif_carrier_off(dev); 
            dev->flags &= ~IFF_RUNNING; 
            printk(KERN_DEBUG "%s: link down\n", dev->name); 
        } 
    } 
 
    set_timer: 
    priv->timer.expires = jiffies + 1 * HZ; 
    priv->timer.data = (unsigned long)dev; 
    priv->timer.function = &xxx_timer; /* timer handler */ 
    add_timer(&priv->timer); 
}
```

从上述源代码还可以看出，定时器处理函数会不停地利用第 31～35 行代 码启动新的定时器以实现周期检测的目的。那么最初启动定时器的地方在哪里呢？很 显然，它最适合在设备的打开函数中完成：

```c
static int xxx_open(struct net_device *dev) 
{ 
  struct xxx_priv *priv = (struct xxx_priv*)dev->priv; 
 
  ... 
  priv->timer.expires = jiffies + 3 * HZ; 
  priv->timer.data = (unsigned long)dev; 
  priv->timer.function = &xxx_timer; /* timer handler */ 
  add_timer(&priv->timer); 
  ...
}
```

# 5. CS8900 网卡设备驱动实例分析

当 CS8900 处于 I/O 模式下时（这里所说的 CS8900 处于 I/O 模式并非意味着它一定位于 CPU 的 I/O 空间，实 际上，CS8900 I/O 模式下的寄存器仍然映射 ARM 处理器的内存空间。因此， 我们直接通过读/写寄存器地址ioremap()之后的虚拟地址即可），可以通过以 下几个 PacketPage 空间内的寄存器来控制 CS8900 的行为（括号内给出的是寄存器地 址相对于 PacketPage 基地址的偏移）:
| 寄存器| 作用 |
|:---:|:---:|
|LINECTL(0112H) | 决定 CS8900 的基本配置和物理接口，可选择使用 10BASE-T 接口、AUI 接口或者自动选择。|
| RXCTL(0104H)| 控制 CS8900 接收特定数据包，控制是否接收多播、广播和单播包。|
|RXCFG(0102H) | RXCFG 控制 CS8900 接收到特定数据包后引发接收中断，并控制是否使用接收 DMA 和 CRC 校验。|
|BUSCT(0116H) |BUSCT 可控制芯片的工作模式、DMA 方式、是否使能外部中断引脚。 |
|BUSST(0138H) |标志网络设备的发送状态，如设备是否准备好发送。 |
|ISQ(0120H) |网卡芯片的中断状态寄存器 |

在 I/O 模式下，CS8900 发送数据包的步骤如下：

（1）向控制寄存器 TXCMD 寄存器写入发送命令​​write_reg(TXCMD, send_cmd);​​。
（2）将发送数据长度写入 TXLENG 寄存器​​write_reg(TXLENG, send_len)​​。
（3）读取 PacketPage 空间内的 BUSST 寄存器，确定其第 8 位被设置为 Rdy4TxNOW，即设备处于准备发送状态​​reg(BusST)&0x100​​。
（4）将要发送的数据循环写入 PORT0 寄存器​​write_reg(PORT0, data)​​。
（5）将数据组织为以太网帧并添加填充位和 CRC 校验信息，然后将数据转化为比特流传送到网络媒介。

在 I/O 模式下，CS8900 接收数据包的方法如下：

（1）接收到网络适配器产生的中断，查询相对于 I/O 基地址偏移 0008H 中断状态 队列端口，判断中断类型为接收中断。
（2）读 PORT0 寄存器依次获得接收状态 rxStatus、接收数据长度 rxLength。
（3）循环继续对 PORT0 寄存器读取 rxLength 次，获得整个数据包。
（4）驱动程序进行数据包处理并传递给上层。

对于一种网络设备的驱动而言，工程师主要需完成设备驱动功能层的设计。在 16.2～ 16.8节已经给出了设备驱动功能层主要数据结构和函数的设计模板，因此，在编写CS8900 的这些数据结构和函数时，实际要完成的工作就是用具体的针对 CS8900 的操作来填充模 板，具体包括以下工作：

1. 填充 CS8900 的私有信息结构体，把 CS8900 特定的数据放入这个私有结构体中。在 CS8900 驱动程序中，这个数据结构为​​struct net_local​​​。
	在 CS8900 的设备驱动程序中，核心数据结构 net_device 以全局变量的方式定义， 其数个成员的初始值都被置为空，私有信息结构体为 net_local：
```c
static struct net_device dev_cs89x0 = 
{ 
    "", 
    0, 0, 0, 0, 
    0, 0, 
    0, 0, 0, NULL, NULL 
};

struct net_local 
{ 
    struct net_device_stats stats; /* 网络设备状态结构体 */ 
    int chip_type; /* 区分芯片类型：CS89x0 */ 
    char chip_revision; /* 芯片版本字母，如"A" */ 
    int send_cmd; /* 发送命令: TX_NOW, TX_AFTER_381 或 TX_AFTER_ALL */ 
    ... 
    spinlock_t lock; /* 并发控制自旋锁 */ 
};
```

当芯片的版本字母不同时，net_local 结构体中记录的 send_cmd 命令将不同。例如， 同样是 CS8900 网卡，若芯片版本字母为大于等于“F”，则发送命令为 TX_NOW，而 对于 CS8900A，发送命令为 TX_AFTER_ALL。

1. 填充设备初始化模板，初始化 net_device 结构体，将其注册入内核。net_device 的注册与注销在模块加载与注销函数中完成。在 CS8900 驱动程序中，与此相关的函数有：
```c
struct net_device * _ _init cs89x0_probe(int unit);
int cs89x0_probe1(struct net_device *dev, int ioaddr, int modular); 
int init_module(void);  
void cleanup_module(void);
```

设备的初始化由 net_device 结构体中的 init()函数完成，这个函数将在 net_device 被注册时自动被调用。init()函数在 CS8900 网卡的驱动程序中对应 于 cs89x0_probe()函数：
```c
int __init cs89x0_probe(struct net_device *dev) 
{ 
    int i; 
 
    SET_MODULE_OWNER(dev); 
    DPRINTK(1, "cs89x0:cs89x0_probe(0x%x)\n", base_addr); 

    BWSCON = (BWSCON & ~(BWSCON_ST3 | BWSCON_WS3 | BWSCON_DW3)) | 
                (BWSCON_ST3 | BWSCON_WS3 | BWSCON_DW(3, BWSCON_DW_16)); 
    BANKCON3= BANKCON_Tacs0 | BANKCON_Tcos4 | BANKCON_Tacc14 | 
                BANKCON_Toch1 | BANKCON_Tcah4 | BANKCON_Tacp6 | BANKCON_PMC1; 
 
    set_external_irq(IRQ_CS8900, EXT_RISING_EDGE, GPIO_PULLUP_DIS); 

    for (i = 0; netcard_portlist[i]; i++) 
    { 
        if (cs89x0_probe1(dev, netcard_portlist[i]) == 0) //验证网卡的存在，并获取 CS8900所使用的硬件资源
            return 0; 
    } 
    printk(KERN_WARNING "cs89x0: no cs8900 or cs8920 detected." 
       "Be sure to disable PnP with SETUP\n"); 
    return -ENODEV; 
}


static unsigned int netcard_portlist[] __initdata = 
{ 
    vCS8900_BASE + 0x300,    //假设硬件平台中网卡的基地址为 vCS8900_BASE + 0x300
    0
}; 

/*
 *上述 cs89x0_probe1()函数的流程如下。
 *（1）第 8～20 行分配设备的私有信息结构体内存并初始化，若分配失败，则直接跳入第 78 行的代码返回。
 *（2）第 24～26 行从寄存器中读取芯片的具体类型。
 *（3）第 27～32 行判断芯片类型，若不是 CS8900 则直接跳入第 77 行的代码，释放私有信息结构体并返回。
 *（4）当芯片类型为 CS8900 时，第 34～69 行完成 net_device 设备结构体的初始化，赋值其属性和函数指针。
 */

static int __init cs89x0_probe1(struct net_device *dev, int ioaddr)
{ 
    struct net_local *lp; 
    unsigned rev_type = 0; 
    int ret; 
 
    /* 初始化设备结构体私有信息 */ 
    if (dev->priv == NULL) 
    { 
        dev->priv = kmalloc(sizeof(struct net_local), GFP_KERNEL); 
        if (dev->priv == 0) 
        { 
            ret = - ENOMEM; 
            goto before_kmalloc; 
        } 
    lp = (struct net_local*)dev->priv; 
    memset(lp, 0, sizeof(*lp)); 
    spin_lock_init(&lp->lock); 
    } 
    lp = (struct net_local*)dev->priv; 

    dev->base_addr = ioaddr; 
    /* 读取芯片类型 */ 
    rev_type = readreg(dev, PRODUCT_ID_ADD); 
    lp->chip_type = rev_type &~REVISON_BITS;
    lp->chip_revision = ((rev_type &REVISON_BITS) >> 8) + 'A';30 
    if (lp->chip_type != CS8900) 
    { 
        printk(_ _FILE_ _ ": wrong device driver!\n"); 
        ret = - ENODEV; 
        goto after_kmalloc;
    } 
    /* 根据芯片类型和版本确定正确的发送命令 */ 
    lp->send_cmd = TX_AFTER_ALL; 
    if (lp->chip_type == CS8900 && lp->chip_revision >= 'F') 
        lp->send_cmd = TX_NOW; 

    reset_chip(dev); 

    lp->adapter_cnf = A_CNF_10B_T | A_CNF_MEDIA_10B_T; 
    lp->auto_neg_cnf = EE_AUTO_NEG_ENABLE;
    printk(KERN_INFO "cs89x0 media %s%s", (lp->adapter_cnf &A_CNF_10B_T) ? "RJ-45": "", (lp->adapter_cnf &A_CNF_AUI) ? "AUI" : ""); 

    /* 设置 CS8900 的 MAC 地址 */ 
    dev->dev_addr[0] = 0x00; 
    dev->dev_addr[1] = 0x00; 
    dev->dev_addr[2] = 0xc0; 
    dev->dev_addr[3] = 0xff; 
    dev->dev_addr[4] = 0xee; 
    dev->dev_addr[5] = 0x08; 
    set_mac_address(dev, dev->dev_addr); 
 
    /* 设置设备中断号 */ 
    dev->irq = IRQ_LAN; 
    printk(", IRQ %d", dev->irq); 
 
    /* 填充设备结构体的成员函数指针 */ 
    dev->open = net_open; 
    dev->stop = net_close; 
    dev->tx_timeout = net_timeout; 
    dev->watchdog_timeo = 3 * HZ; 
    dev->hard_start_xmit = net_send_packet; 
    dev->get_stats = net_get_stats; 
    dev->set_multicast_list = set_multicast_list; 
    dev->set_mac_address = set_mac_address; 
 
    /* 填充以太网公用数据和函数指针 */ 
    ether_setup(dev); 

    printk("\n"); 
    DPRINTK(1, "cs89x0_probe1() successful\n"); 
    return 0;
    after_kmalloc: kfree(dev->priv); 
    before_kmalloc: return ret; 
} 


static int __init init_cs8900a_s3c2410(void) 
{ 
    struct net_local *lp; 
    int ret = 0; 
 
    dev_cs89x0.irq = irq; 
    dev_cs89x0.base_addr = io; 
    dev_cs89x0.init = cs89x0_probe; //在使用 register_netdev()函数注net_device 设备结构体时，cs89x0_probe()函数会被自动调用以完成 net_device 结构体的初始化。
    dev_cs89x0.priv = kmalloc(sizeof(struct net_local), GFP_KERNEL); 
    if (dev_cs89x0.priv == 0) 
    { 
        printk(KERN_ERR "cs89x0.c: Out of memory.\n"); 
        return - ENOMEM; 
    } 
    memset(dev_cs89x0.priv, 0, sizeof(struct net_local)); 
    lp = (struct net_local*)dev_cs89x0.priv; 
    
    //为 CS8900 网卡申请了 NETCARD_IO_EXTENT大小的I/O 地址区域
    request_region(dev_cs89x0.base_addr, NETCARD_IO_EXTENT, "cs8900a");
    spin_lock_init(&lp->lock); 
 
    /* 设置物理接口的正确类型*/ 
    if (!strcmp(media, "rj45")) 
    lp->adapter_cnf = A_CNF_MEDIA_10B_T | A_CNF_10B_T; 
    else if (!strcmp(media, "aui")) 
        lp->adapter_cnf = A_CNF_MEDIA_AUI | A_CNF_AUI; 
    else if (!strcmp(media, "bnc")) 
        lp->adapter_cnf = A_CNF_MEDIA_10B_2 | A_CNF_10B_2; 
    else 
        lp->adapter_cnf = A_CNF_MEDIA_10B_T | A_CNF_10B_T; 
 
    if (duplex == - 1) 
        lp->auto_neg_cnf = AUTO_NEG_ENABLE; 
 
    if (io == 0) 
    { 
        printk(KERN_ERR "cs89x0.c: Module autoprobing not allowed.\n"); 
        printk(KERN_ERR "cs89x0.c: Append io=0xNNN\n"); 
        ret = - EPERM; 
        goto out; 
    } 
    //net_device 设备结构体的注册
    if (register_netdev(&dev_cs89x0) != 0) 
    { 
        printk(KERN_ERR "cs89x0.c: No card found at 0x%x\n", io); 
        ret = - ENXIO; 
        goto out; 
    } 
out: if (ret) 
        kfree(dev_cs89x0.priv); 
    return ret; 
} 


static void _ _exit cleanup_cs8900a_s3c2410(void) 
{ 
    if (dev_cs89x0.priv != NULL) 
    { 
        /* 释放私有信息结构体 */ 
        unregister_netdev(&dev_cs89x0); 
        outw(PP_ChipID, dev_cs89x0.base_addr + ADD_PORT); 
        kfree(dev_cs89x0.priv); 
        dev_cs89x0.priv = NULL; 
        /* 释放 CS8900 申请的 I/O 地址区域 */ 
        release_region(dev_cs89x0.base_addr, NETCARD_IO_EXTENT); 
    } 
}
```

上述函数第 8～11 行设置 S3C2410A ARM 处理器的片选，第 13行设置 ARM 与 CS8900 网卡对应的中断，第 15～18 行循环检索 netcard_portlist[ ]数组中定义的基地址处 是否存在 CS8900 网卡

1. 填充设备发送数据包函数模板，把真实的数据包发送硬件操作填充入​​xxx_tx()​​​ 函数，并填充发送超时函数​​xxx_tx_timeout()​​​。当发送数据包超时时，CS8900 驱动程序的数据包发送超时函数将被调用，它重 新启动设备发送队列。在初始化函数中，CS8900 的数据包发送函数指针​​hard_ start_xmit ​​​被赋值为 CS8900 驱动程序中的​​net_send_packet()​​，这个函数完成硬件发送序列。具体代码如下：
```c
static int net_send_packet(struct sk_buff *skb, struct net_device  *dev)
{
    struct net_local *lp = (struct net_local*)dev->priv; 
 
    writereg(dev, PP_BusCTL, 0x0); 
    writereg(dev, PP_BusCTL, readreg(dev, PP_BusCTL) | ENABLE_IRQ); 
 
    spin_lock_irq(&lp->lock);/* 使用自旋锁阻止多个数据包被同时写入硬件*/ 
    netif_stop_queue(dev); 
 
    /* 初始化硬件发送序列 */ 
    writeword(dev, TX_CMD_PORT, lp->send_cmd); 
    writeword(dev, TX_LEN_PORT, skb->len); 
 
    /* 检测硬件是否处于发送 READY 状态 */ 
    if ((readreg(dev, PP_BusST) &READY_FOR_TX_NOW) == 0) 
    { 
        spin_unlock_irq(&lp->lock); 
        DPRINTK(1, "cs89x0: Tx buffer not free!\n"); 
        return 1; 
    } 
 
    writeblock(dev, skb->data, skb->len);    /* 将数据写入硬件 */ 
 
    spin_unlock_irq(&lp->lock);    /* 解锁自旋锁 */ 
    dev->trans_start = jiffies;    /* 记录发送开始的时间戳 */ 
    dev_kfree_skb(skb);            /* 释放 sk_buff 和数据缓冲区 */ 
 
    return 0; 
}

static void net_timeout(struct net_device *dev)
{ 
    DPRINTK(1, "%s: transmit timed out, %s?\n", dev->name,
        tx_done(dev) ? "IRQ conflict ?" : "network cable problem"); 
 
    net_close(dev); //停止网卡
    writereg(dev, PP_SelfCTL, readreg(dev, PP_SelfCTL) | POWER_ON_RESET); //网卡硬复位
    net_open(dev); //再次启动网卡
}

```

填充设备驱动程序的中断处理程序 xxx_interrupt()和具体的数据包接收函数 xxx_rx()，填入真实的硬件操作。在 CS8900 驱动程序中，与此相关的函数有：
```c
irqreturn_t net_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{ 
    struct net_device *dev = dev_id; 
    struct net_local *lp; 
    int ioaddr, status; 
 
    ioaddr = dev->base_addr; 
    lp = (struct net_local*)dev->priv; 
 
    /* 读取中断事件类型 */ 
    while ((status = readword(dev, ISQ_PORT))) 
    { 
        DPRINTK(4, "%s: event=%04x\n", dev->name, status); 
        switch (status &ISQ_EVENT_MASK) 
        { 
            case ISQ_RECEIVER_EVENT: 
                /* 获得数据包 */ 
                net_rx(dev); 
                break; 
            ... /* 其他类型中断 */ 
        } 
    } 
} 


static void net_rx(struct net_device *dev)
{
    struct net_local *lp = (struct net_local*)dev->priv; 
    struct sk_buff *skb; 
    int status, length; 
 
    int ioaddr = dev->base_addr; 
 
    status = inw(ioaddr + RX_FRAME_PORT); 
    if ((status &RX_OK) == 0) 
    { 
        count_rx_errors(status, lp); 
        return ; 
    } 
 
    length = inw(ioaddr + RX_FRAME_PORT);/* 读取接收数据包的长度 */ 
 
    /* 分配新的套接字缓冲区和数据缓冲区 */ 
    skb = dev_alloc_skb(length + 2); 
    if (skb == NULL) 
    { 
        lp->stats.rx_dropped++; /* 分配失败，统计被丢弃的包数 */ 
        return ; 
    } 
    skb_reserve(skb, 2); 
    skb->len = length; 
    skb->dev = dev;
    readblock(dev, skb->data, skb->len); /* 从硬件中读取数据包放入数据缓冲区 */
    skb->protocol = eth_type_trans(skb, dev);/* 解析收到数据包的网络层协议类型 */ 
 
    netif_rx(skb); /* 传递给上层协议 */ 
 
    dev->last_rx = jiffies; /* 记录最后收到数据包的时间戳 */ 
    /* 统计接收数据包数和接收字节数 */ 
    lp->stats.rx_packets++; 
    lp->stats.rx_bytes += length; 
}
```

填充设备打开 xxx_open()与释放 xxx_release()函数代码。在 CS8900 驱动程序 中，与此相关的函数有：
```c
int net_open(struct net_device *dev);  
int net_close(struct net_device *dev);
```

填充设备配置与数据统计的具体代码，填充返回设备冲突的​​xxx_stats()​​函数。

# 6. 网卡驱动移植一般步骤

拿到一块新的网卡，一般厂家会有自带的驱动程序给你，你所要做的就是以下几个事情：

根据网卡与开发板的连接方式确定网卡的内存映射地址iobase，也即确定网卡的片选信号所连接的CPU内存的哪一个bank（nGCS？），然后根据网卡内存的大小，在网卡驱动的初始化函数中调用ioremap()进行地址重映射；
根据网卡与开发板的硬件连接图确定中断号，并在初始化函数中利于request_irq()函数，向内核申请中断（确定中断触发方式、中断处理函数等）；
根据网卡datasheet查看网卡的读写时序和位宽参数，设置开发板相应的内存控制寄存器BWSCON和BANKCON*。
将它拷贝到内核源代码的相关目录并修改该目录下的Makefile文件以添加修改后的网卡驱动目标文件。假设我们已经改好的网卡驱动程序为：dm9dev9000c.c，编译也没有错误。

```shell
cp dm9dev9000c.c /home/leon/linux-3.4.2/drivers/net/ethernet/davicom/
```

修改该目录Makefile文件：
```c
#
# Makefile for the Davicom device drivers.
#

#obj-$(CONFIG_DM9000) += dm9000.o
obj-$(CONFIG_DM9000) += dm9dev9000c.o
```

重新编译内核，烧写新的uImage文件到开发板中，看看是否可以挂载网络根文件系统或者可以设置IP地址及ping通网络。如果可以成功挂载网络根文件系统，所以网卡移植是成功的。
```shell
nfs 30000000 192.168.1.101:/work/nfs_root/uImage_net_new; 
bootm 30000000
mount -t nfs -o nolock,vers=2 192.168.1.101:/work/nfs_root/fs_mini_mdev_new /mnt
```

我们也可以设置开机直接挂载网络根文件系统，这样就可以直接开机启动网络根文件系统了。
uboot中设置：
```shell
set bootargs console=ttySAC0,115200 root=/dev/nfs nfsroot=192.168.1.101:/home/leon/nfs_root/first_fs ip=192.168.1.50:192.168.1.101:192.168.1.1:255.255.255.0::eth0:off
    
save

tftp 30000000 uImage

bootm 30000000

```
>ip=192.168.1.50：为单板ip，
>192.168.1.101：为服务器ip，
>192.168.1.1为网关，
>255.255.255.0为子网掩码

```c
if (skb == NULL) 
{ 
   lp->stats.rx_dropped++; /* 分配失败，统计被丢弃的包数 */ 
   return ; 
} 
skb_reserve(skb, 2); 
skb->len = length; 
skb->dev = dev;
readblock(dev, skb->data, skb->len); /* 从硬件中读取数据包放入数据缓冲区 */
   skb->protocol = eth_type_trans(skb, dev);/* 解析收到数据包的网络层协议类型 */ 

netif_rx(skb); /* 传递给上层协议 */ 

dev->last_rx = jiffies; /* 记录最后收到数据包的时间戳 */ 
/* 统计接收数据包数和接收字节数 */ 
lp->stats.rx_packets++; 
lp->stats.rx_bytes += length; 


```

```c
5.  **填充设备打开 xxx_open()与释放 xxx_release()函数代码**。在 CS8900 驱动程序 中，与此相关的函数有：
int net_open(struct net_device *dev);  

int net_close(struct net_device *dev);
```

填充设备配置与数据统计的具体代码，填充返回设备冲突的​​xxx_stats()​​函数。
