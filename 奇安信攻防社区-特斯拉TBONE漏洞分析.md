0x00 背景
-------

近日，德国的两名安全研究员Ralf-Philipp Weinmann和Benedikt Schmotzle在CanSecWest会议上公布了Tbone漏洞，该漏洞可实现0-click无接触对Tesla的近距离攻击，通过操控一辆无人机实现了开启Tesla后备箱，解锁等操作。

值得一提的是Tbone作者在没有汽车硬件的情况下，通过Tesla使用的第三方组件ConnMan完成了漏洞挖掘。

通过作者公布的资料，本文对Tbone漏洞进行简略分析与记录。

![1](https://shs3.b.qianxin.com/butian_public/f597453db7f9aa3f2d86aa2f99f82f72a3aa5bb88bf63.jpg)

(PPT、PDF资源在文末参考链接)

0x01 **漏洞简介**
-------------

- 漏洞效果: 近场(WIFI信号范围内)获取Tesla信息娱乐系统root权限，操控Tesla车门、后备箱等
- 影响范围: 2018.42.3 and 2020.4.1版本之间的Tesla(S, 3, X, Y)
- 漏洞利用流程:

![2](https://shs3.b.qianxin.com/butian_public/f812044886d717c3ae0a16663d9f2103b054162379ae5.jpg)

0x02 **通过WIFI介入实现0-click效果**
----------------------------

2015年，Mahaffey和Rogers两位研究员指出Tesla Model S会主动连接名为Tesla Service的wifi热点，并且密码为硬编码:

![3](https://shs3.b.qianxin.com/butian_public/f862448418f4af91bd055d383f14f869cc1a5786ae09d.jpg)

该硬编码甚至出现在某人推特的个人信息中:

![4](https://shs3.b.qianxin.com/butian_public/f93490274e257c0a3209e51a9ef978aa908fc9ec14821.jpg)

推特个人信息资料中包含Tesla Service热点密码硬编码

在TBone作者进行漏洞挖掘时，此漏洞依然存在。

攻击者通过hostapd伪造名为`Tesla Service`的热点，并配置密码为发现的硬编码，Tesla扫描到此wifi热点后会主动进行连接。

通过这个漏洞，攻击者便可与Tesla网络连接管理组件ConnMan进行交互，扩展攻击面，实现0-click的攻击效果。

0x03 **漏洞挖掘与分析**
----------------

Tbone作者通过ConnMan组件中DNS与DHCP模块的两个漏洞，最终实现了RCE。

### **ConnMan是什么？**

ConnMan是一款由C语言编写的开源网络连接管理器，包含诸多网络协议: DHCP, DNS, IPv4, IPv6, NTP, WPAD等

ConnMan源码下载: <https://git.kernel.org/pub/scm/network/connman/connman.git/>

Tbone漏洞使用的ConnMan版本为1.37, 文章中涉及到的代码片段均截取自`connman-1.37.tar.gz`

### **DNS栈溢出漏洞(CVE-2021-26675)**

### 1. **AFL fuzz发现crash**

使用AFL fuzz ConnMan，配置ASAN做监控，成功发现一处crash：

```bash
Reading symbols from src/connmand...done.
Starting program: ./src/connmand < out/crashes/id:000003,sig:06,src:006692,op:havoc,rep:8
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
=================================================================
==28665==ERROR: AddressSanitizer: negative-size-param: (size=-1)
    #0 0xf720f9b3 (/usr/lib32/libasan.so.4+0x779b3)
    #1 0x56936544 in uncompress src/dnsproxy.c:1841
    #2 0x5694ba34 in forward_dns_reply src/dnsproxy.c:2086
    #3 0x5694ba34 in fuzz src/dnsproxy.c:2200
    #4 0x5662b475 in main src/dnsproxy.c:2205
    #5 0xf6c88e80 in __libc_start_main (/lib/i386-linux-gnu/libc.so.6+0x18e80)
    #6 0x5662b76f (/home/user/connman/src/connmand+0x3e76f)
Address 0xffe197e4 is located in stack of thread T0 at offset 1220 in f rame
    #0 0x5694b01f in fuzz src/dnsproxy.c:2189
  This f rame has 3 o bject(s):
    [32, 36) 'uptr'
    [96, 1121) 'uncompressed'
    [1184, 5280) 'buf' <== Memory access at offset 1220 is inside this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism
or swapcontext (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: negative-size-param (/usr/lib32/libasan.so.4+0x779b3)
==28665==ABORTING
[Inferior 1 (process 28665) exited with code 01]
```

定位到源码文件`src/dnsproxy.c`

```c
1    static char *uncompress(int16_t field_count, char *start, char *end,
2               char *ptr, char *uncompressed, int uncomp_len,
3               char **uncompressed_ptr)
4    {
5       char *uptr = *uncompressed_ptr; /* position in result buffer */
6
7       debug("count %d ptr %p end %p uptr %p", field_count, ptr, end, uptr);
8
9       while (field_count-- > 0 && ptr < end) {
10          int dlen;       /* data field length */
11          int ulen;       /* uncompress length */
12          int pos;        /* position in compressed string */
13          char name[NS_MAXLABEL]; /* tmp label */
14          uint16_t dns_type, dns_class;
15          int comp_pos;
16
17          if (!convert_label(start, end, ptr, name, NS_MAXLABEL,
18                      &pos, &comp_pos))
19              goto out;
20
21          /*
22           * Copy the uncompressed resource record, type, class and \\0 to
23           * tmp buffer.
24           */
25
26          ulen = strlen(name);
27          **strncpy(uptr, name, uncomp_len - (uptr - uncompressed));**
28
29          debug("pos %d ulen %d left %d name %s", pos, ulen,
30              (int)(uncomp_len - (uptr - uncompressed)), uptr);
31
32          uptr += ulen;
33          *uptr++ = '\\0';
34
35          ptr += pos;
36
37          /*
38           * We copy also the fixed portion of the result (type, class,
39           * ttl, address length and the address)
40           */
41          **memcpy(uptr, ptr, NS_RRFIXEDSZ);**
42
43          dns_type = uptr[0] << 8 | uptr[1];
44          dns_class = uptr[2] << 8 | uptr[3];
45
46          if (dns_class != ns_c_in)
47              goto out;
48
49          ptr += NS_RRFIXEDSZ;
50          uptr += NS_RRFIXEDSZ;
```

代码第41行，`memcpy`函数向`uptr`地址空间拷贝固定10bytes(NS\_RRFIXEDSZ)长度数据，但没有检测拷贝操作是不是向目标`buffer`之外写入数据，导致栈溢出漏洞。

### 2. **绕过栈保护`canary`**

在PWN2OWN提供的固件中查看ConnMan的二进制发现目标使用了`canary`栈保护机制。

![5](https://shs3.b.qianxin.com/butian_public/f481860048ae2021b8bd36a09387bbdb501422c3381ac.jpg)

栈溢出的利用一般通过溢出存在于栈上的局部变量，让多出来的数据覆盖 ebp、eip等，从而达到劫持控制流的目的。但如果溢出的数据覆盖掉了canary，程序检测到canary发生了变化，则判断发生了栈溢出，导致无法正常攻击利用。

目标ConnMan的`canary`为64bit，无法进行爆破，所以必须想办法绕过`canary`机制。

在上文`uncompress`函数的27行，`strncpy`函数将`name`复制到`uptr`中，并且允许复制的最大长度每次循环会减少，同时，指针`uptr`根据`name`的实际字符长度会一直增加。

这表示我们可以找到一个方法，先填充字节到`canary`，然后向前跳8个或更多字节，之后在41行继续向`uptr`继续写入。这里Tbone作者并未详细展开如何绕过`canary`，说法较为模糊，以下是笔者自己猜测见解:

`name`每次循环可控，`uncomp_len`,`uncompressed`可能可控。

当数据覆盖到`canary`时，构造`name`长度为8bytes，构造`uncomp_len - (uptr - uncompressed))`为0。

此时27行`strncpy(uptr, name, uncomp_len - (uptr - uncompressed));`拷贝0字节。

32行`uptr += ulen;` uptr指针移动8字节，绕过`canary`。

41行`memcpy(uptr, ptr, NS_RRFIXEDSZ);`栈溢出覆盖`canary`之后的内容。

### 3. **触发栈溢出**

此栈溢出只有在转发代理添加域名到非法主机名时才会触发(下方代码第9行，`req->append_domain`必须为True)，Tbone作者在fuzz过程注释掉了`req->append_domain`检测。

但是，在CID(中控)和AutoPilot(自动驾驶系统)中，所有的进程都使用合法的主机名。

作者注意到ConnMan使用了Web代理自动发现协议(WPAD)，该服务在获取DHCP lease后会立即查询`wpad.<domain>`，此`<domain>`由`DHCP Server`提供给ConnMan。

```c
1    static intforward_dns_reply(unsigned char *reply, int reply_len, int protocol,
2                   struct server_data *data)
3    {
4    ...
5       if (hdr->rcode == ns_r_noerror || !req->resp) {
6           unsigned char *new_reply = NULL;
7
8            /* req->append_domain为True才可进入漏洞流程*/
9          if (req->append_domain && ntohs(hdr->qdcount) == 1) { 
```

当多个DNS server通过DHCP提供给ConnMan时，ConnMan会发送DNS请求`wpad.<domain>` 。

攻击者通过在DHCP reply中将DNS Server设置为127.0.0.1，来使WPAD发送的DNS请求通过ConnMan DNS转发代理发送。

此外，在DHCP option中将域名设置为0字节组成的字符串，当DNS转发代理添加0字节组成的域名时，`req->append_domain`被设置为True，进而成功进入栈溢出漏洞流程。

### **DHCP信息泄露(CVE-2021-26676)**

1. DHCP协议前置知识

在了解这个漏洞之前，先看一下DHCP基本的交互逻辑。

wiki上对DHCP offer &lt;-&gt; request流程的描述:

![6](https://shs3.b.qianxin.com/butian_public/f741270ca7d5df3ee8172976520f443f31fee856682d9.jpg)

这个场景下，攻击者为server，Tesla为client。

攻击者发送DHCP OFFER(攻击包), Tesla返回DHCP REQUEST(包含泄露的信息)

1. 漏洞分析

由于目标设置了DEP(数据执行保护，无法执行攻击者在栈中构造的恶意代码)与ALSR(地址随机化)，所以必须要搞清楚栈在内存中的地址，ConnMan或其他动态链接库在内存中的分布。即需要找到一个泄露地址的漏洞来配合栈溢出利用。

通过DNS转发功能来触发信息泄露不太现实，因为通过WiFi接口，攻击者只能被动的发送响应，不能主动发送请求。

于是作者转向DHCP代码分析，并且幸运地发现一个监听函数`listener_event()`会为接收到的DHCP包申请栈空间。

gdhcp/client.c:

```c
static gbooleanlistener_event(GIOChannel *channel, GIOCondition condition,
                            gpointer user_data)
{
    GDHCPClient *dhcp_client = user_data;
    structsockaddr_indst_addr = { 0 };
    structdhcp_packetpacket;
    structdhcpv6_packet *packet6 =NULL;
    uint8_t *message_type = NULL, *client_id = NULL, *option,
        *server_id = NULL;
    uint16_t option_len = 0, status = 0;
    uint32_t xid = 0;
    gpointer pkt;
    unsigned char buf[MAX_DHCPV6_PKT_SIZE];
    uint16_t pkt_len = 0;
    int count;
    int re;

    ...

    if (dhcp_client->listen_mode == L2) {
        **re = dhcp_recv_l2_packet(&packet,**  //接收DHCP数据包
                    dhcp_client->listener_sockfd,
                    &dst_addr);
        xid = packet.xid;
```

接着向下看这个函数，在一个`switch`结构体里可以看到处理DHCP服务端响应的代码逻辑:

```c
...
    switch (dhcp_client->state) {
    case INIT_SELECTING:
...
        // 从packet中解析出DHCP_SERVER_ID
        **option = dhcp_get_option(&packet, DHCP_SERVER_ID);**   
        dhcp_client->server_ip = get_be32(option);           
...
```

`dhcp_client->server_ip`字段随后会被编码到DHCP数据包中，在`send_request`函数中发送给DHCP Server。

gdhcp/client.c ：

```c
static int send_request(GDHCPClient *dhcp_client)
{
    struct dhcp_packet packet;
...

    if (dhcp_client->state == REQUESTING)
　　// 将dhcp_client->server_ip构造到DHCP Request包的DHCP_SERVER_ID字段中
        **dhcp_add_option_uint32(&packet, DHCP_SERVER_ID,
                dhcp_client->server_ip);**       
```

回过头看一下解析出DHCP\_SERVER\_ID的函数`dhcp_get_option`(**漏洞点**):

```c
uint8_t *dhcp_get_option(struct dhcp_packet *packet, int code)
{
    int len, rem;
    uint8_t *optionptr;
    uint8_t overload = 0;

    /* option bytes: [code][len][data1][data2]..[dataLEN] */
    optionptr = packet->options;
    **rem = sizeof(packet->options);** // 使用packet->options结构体的长度作为需要解析的长度，
                                               // 而不是数据包字段真实字节长度

    ...
}
```

注意到`rem = sizeof(packet->options);` 使用`packet->options`结构体的长度作为需要解析的长度，而不是数据包真实字节长度。

我们可以发送一个DHCP Offer，携带DHCP\_SERVER\_ID option，并且只设置option的code，不设置data段。

client端在收到DHCP offer时会将offer包中DHCP\_SERVER\_ID字段取出来放入将要发送的DHCP Request包的DHCP\_SERVER\_ID字段中。

但由于取DHCP\_SERVER\_ID字段的函数 `dhcp_get_option` 取字段时使用的是结构体的长度，所以即使我们在offer中设置DHCP\_SERVER\_ID字段为0字节，client端还是会从内存中取4字节内容放入DHCP Request包的DHCP\_SERVER\_ID字段里(此结构体默认4字节)。

这样client端在构造DHCP Request数据包时就会在DHCP\_SERVER\_ID字段中携带内存中的数据，一次泄露4字节。

通过修改domain name(别的option)的长度，在exp里称之为padding，来使option指针偏移，进而读取栈中其余的数据。

DHCP信息泄露流程为:

![7](https://shs3.b.qianxin.com/butian_public/f571550b4ad449ac1f58bcfc586e7785c39e9760dec43.jpg)

### 完整的漏洞利用链

1）远程代码执行

通过以上两个漏洞，攻击者获取动态链接库基址与`forward_dns_reply()`函数栈指针，构造ROP链放在栈中，并使用`mprotect`函数使栈中代码可执行，最终达到RCE的效果。

2）提权

但此时权限非root，且存在以下问题:

1. ConnMan进程运行在自己的用户下
2. 所有的进程被`Kafel`(拦截syscall)与`Apparmor`(资源访问限制)限制
3. ConnMan进程不能开启`/bin/sh`

但通过分析发现ConnMan可以执行受限制的`modprobe`操作，一是只可以加载Tesla签名后的模块；二是可以加载一些模块的固件，比如`BCMDHD`。

Tbone作者通过加载包含已知漏洞的`BCMDHD`博通芯片固件，从WIFI芯片层进行攻击，最终获取到Tesla信息娱乐系统的Root权限。

`BCMDHD`漏洞，参考Google Project Zero文章：[Over The Air: Exploiting Broadcom’s Wi-Fi Stack](https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_4.html)

3）控制车辆

CAN总线操作车辆开关门动作，可参考Keen团队的工作：[FREE-FALL: HACKING TESLA FROM WIRELESS TO CAN BUS](https://www.blackhat.com/docs/us-17/thursday/us-17-Nie-Free-Fall-Hacking-Tesla-From-Wireless-To-CAN-Bus-wp.pdf)

Tesla已修复此漏洞，并改用`dnsmasq`组件。

0x04 **参考资料**
-------------

1. <https://kunnamon.io/tbone/>
2. <https://kunnamon.io/tbone/tbone-v1.0-redacted.pdf>
3. <https://docs.google.com/presentation/d/1T9NAJTBWkqBGsQlQwM1anbFXRhxJcTiq0O4VfQCtVEk/edit#slide=id.p>
4. <https://blog.lookout.com/hacking-a-tesla>
5. <https://ctf-wiki.org/pwn/linux/mitigation/canary/>
6. [https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi\_4.html](https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_4.html)
7. <https://git.kernel.org/pub/scm/network/connman/connman.git/>

0x05 关于我们
---------

**天工实验室**隶属于奇安信技术研究院，专注于**物联网、车联网**领域的安全研究，包括物联网协议安全、固件安全、无线安全、智能网联汽车及自动驾驶安全等，服务于国家和社会对网络空间安全的战略需求。团队成员秉承“天工开物、匠心独运”的创新使命和工匠精神，在物联网漏洞挖掘与攻防领域有丰富的经验积累，漏洞研究成果连续在GeekPwn、天府杯等漏洞破解赛事中斩获多个奖项，漏洞挖掘创新型方法发表于Usenix等国际顶级会议。