**0x00 简介**
-----------

近日，国外安全研究员Mathy Vanhoef公布了FragAttack系列WiFi漏洞，其中802.11协议设计漏洞影响几乎所有WiFi设备。

针对WiFi的漏洞大致可以分为三类:

1. 802.11协议设计漏洞 : 协议标准层面的设计漏洞，通常为逻辑漏洞，由于是协议标准层面的漏洞，所以影响极为广泛。
2. 802.11协议栈实现漏洞 : 即WiFi芯片、WiFi驱动在实现WiFi功能时出现在代码层面的漏洞。
3. WiFi应用层漏洞 : 针对于WiFi应用层的漏洞点并不广泛，多是一些SSID或Vendor字段在上层应用发生漏洞，或者是在一些特殊的机制如smartconfig配网中出现问题。

FragAttacks主要涉及3个802.11协议设计漏洞：

1. **A-MSDU帧注入攻击(CVE-2020-24588)**
2. **混合密钥攻击(CVE-2020-24587)**
3. **分片缓存攻击(CVE-2020-24586)**

与多个协议栈代码实现漏洞:

1. 接受纯文本广播片段作为完整帧(CVE-2020-26145)
2. 在加密网络中接收RFC1042标准开头的纯文本A-MSDU帧(CVE-2020-26144)
3. 在受保护的网络中接收纯文本数据帧(CVE-2020-26140)
4. 在受保护的网络中接收分片帧的纯文本数据帧(CVE-2020-26143)
5. 尚未完成对发送发身份验证的情况下转发 EAPOL帧(CVE-2020-26139)
6. 重新组装具有非连续数据包编号的加密片段(CVE-2020-26146)
7. 重新组装混合的加密/明文片段(CVE-2020-26147)
8. 将碎片帧作为完整帧处理(CVE-2020-26142)
9. 未验证分段帧的 TKIP MIC(CVE-2020-26141)

其中协议栈代码实现漏洞大多是与3个协议设计漏洞相关联的漏洞，本文主要对3个协议设计漏洞进行分析。

**0x01 802.11协议基础知识**
---------------------

此章节简单介绍802.11协议一些基础知识。

我们以手机通过WiFi连接路由器这一通信流程为例，来对802.11协议有一个快速的了解。

通常我们将提供WiFi信号的设备定义为接入点(AP)，连接到接入点的设备称之为工作站(STA)，在当前例子中路由器为AP，手机为STA。

802.11协议中存在**信道**这一概念，WiFi信号依照802.11协议运行在不同频段上，信道便是区分频段的一个定义，国内使用1至13信道(2.4GHz)。

路由器在某一信道广播Beacon帧，Beacon帧中包含AP的一些基本信息如SSID、速率。

手机在扫描时会不断切换无线网卡信道来接收不同信道的AP信号。

以WPA2认证方式为例，STA与AP建立链接流程为:

![1](https://shs3.b.qianxin.com/butian_public/f00a5cc2e7a8b27c93f0dbe72d34c8894.jpg)

1. AP广播Beacon帧。
2. STA发送Probe Request帧请求连接。
3. 经过Authentication、Association交互流程后，双方进入4步握手流程。
4. 通过4步握手，双方协商通信密钥。
5. STA与AP使用密钥加密通信流量，但802.11帧头部不做加密。

以上交互的帧均可通过无线网卡进行嗅探，但攻击者在不知道通信密钥的情况下，无法解密加密数据。

### 1. **硬件设备**

经笔者测试，可以使用3070芯片系列网卡复现攻击。

![1](https://shs3.b.qianxin.com/butian_public/f1a4b052f68f85db1ea00cd4687174b2a.jpg)

### 2. **Multi-Channel MitM （多信道中间人攻击）**

多信道中间人攻击是Fragattack中提到的一种攻击场景。

攻击者在不同信道上克隆目标AP，搭建一个伪AP。

可以使用Deauth攻击迫使目标STA连接到伪AP，进而转发目标STA和目标AP之间的通信流量。由于只是单纯转发802.11协议帧，此攻击不需要知晓目标AP的wifi密码。

802.11协议有提及对抗这种中间人攻击的方案，但实际上并没有实行。所以在实际中，这种攻击可以稳定实现，不过需要以下条件:

1. 2个无线网卡，一个用于搭建伪AP，一个用于连接目标AP实现流量转发，其中伪AP与目标Station同一信道，流量转发网卡与目标AP同一信道。
2. 攻击者需要在目标AP与目标STA无线信号工作范围内。

Multi-Channel MitM示意图:

![1](https://shs3.b.qianxin.com/butian_public/fe518a93e2a8530c71acda4d01598aebc.jpg)

### 3. **聚合帧（A-MSDU）**

每个802.11帧在传输时都必须带上头部，当多个802.11帧的数据段很小时，可以将多个帧聚合到一个帧中，复用一个头部以提高传输效率。

正常的IP/TCP协议帧封装在802.11数据帧中的格式为:

![1](https://shs3.b.qianxin.com/butian_public/f9b9a04b80837f230c78a0622e37e4e47.jpg)

在Wireshark中可以看到更直观的结构:

![1](https://shs3.b.qianxin.com/butian_public/f81e1e24489e1c241a92534dca779f7d0.jpg)

判断当前WiFi数据帧是不是A-MSDU帧的依据是802.11头部的Qos Control字段中的flag标志位:

![1](https://shs3.b.qianxin.com/butian_public/f186d37990471b27b77d83b6b392ea9ee.jpg)

A-MSDU帧中可以包含多个子帧，A-MSDU子帧包含TCP/IP层数据，并在头部添加Destination、Source与Length字段。

A-MSDU帧在wireshark中的结构如下:

![1](https://shs3.b.qianxin.com/butian_public/f9f1c11a9072be4f83844fd7d2475d6c4.jpg)

### 4. **分片帧(Fragment)**

当单个802.11帧长度过大时，通过分片机制可将单个帧分为多个分片帧进行传输，单个分片帧与正常802.11帧格式相同。分片帧通过802.11帧头部FC字段中的标志位表示当前分片是否为最后一分片:

![1](https://shs3.b.qianxin.com/butian_public/f256a5654f5fd2a0e77e75a48bdf59d2b.jpg)

同一序列的分片必须拥有相同的序列号(`Sequence number`)与递增的分片号(`Fragment number`)

`Sequence number`与`Fragment number`同样在802.11帧头部定义:

![1](https://shs3.b.qianxin.com/butian_public/fdedda4c087ba0b32e3db441de3ea1bbd.jpg)

**0x02 A-MSDU帧注入攻击(CVE-2020-24588)**
------------------------------------

- 攻击条件
    
    
    1. 近场
    2. 客户端需请求攻击者服务器
- 利用效果
    
    在不接入AP网络的情况下向网络中任意设备注入TCP/IP协议数据帧，如向某个设备端口发送tcp/udp探测报文。
- 原理
    
    此攻击需要使用`Multi-Channel MitM`攻击场景，攻击者作为中间人转发STA与AP的无线通信流量，**并且攻击者不知晓目标AP WiFi密码**。
    
    当STA与AP建立链接并开始进行TCP/IP数据通信时，攻击者拦截通信的数据帧，数据帧的数据段虽然被加密，但802.11头部是明文传输，所以A-MSDU flag不受保护(802.11协议定义了SPP机制，可对A-MSDU flag进行认证，但实际中并没有实施此措施)，攻击者可将此标志位设置为1。
    
    那么数据段被解密后就会按照A-MSDU格式进行解析。
    
    但攻击者无法加解密数据段，所以需要一个场景来使攻击者可修改数据段明文信息。通过社工使STA访问攻击者的服务器，通过修改服务器返回的Response来控制部分802.11数据帧的数据端内容。
    
    ![1](https://shs3.b.qianxin.com/butian_public/fa1d63365aba1470dccebc142db963c3e.jpg)
    
    上图红色部分不可控，绿色部分可控，黄色部分可控一部分。
    
    `LLC/SNAP`字段会被解析为A-MSDU子帧的Destination等字段，导致第一个A-MSDU子帧的各个字段被填入不合法数据，目标解析第一个子帧时会将其丢弃。所以攻击者需要构造第二个A-MSDU子帧完成注入攻击。
- 攻击流程:

![1](https://shs3.b.qianxin.com/butian_public/fac1c76c32805383482e0294a65739572.jpg)

1. 攻击者使用`Multi-Channel MitM`攻击转发STA与AP 802.11通信流量，并社工STA访问攻击者服务器上的资源，比如图片。
2. 服务器收到request之后，将Response的TCP/IP层的数据按照A-MSDU子帧格式进行构造。由于LLC/SNAP字段不可控，所以第一个A-MSDU子帧的头部会被LLC/SNAP填充，我们需要构造IP层的数据，将第一个子帧格式修复。并构造合法的第二个A-MSDU子帧。
3. AP将response封装为802.11数据帧，攻击者截取此数据帧，并将其头部A-MSDU flag标志位修改为1(数据帧的数据段会被加密，但头部是明文)。
4. STA解密此数据帧后会使用A-MSDU格式解析数据，第一个子帧由于头部字段不合法而被丢弃，第二个子帧为合法子帧，会被正常解析为TCP/IP层数据帧。最终，攻击者达到注入任意TCP/IP帧的攻击效果。

攻击者修改后的数据帧(**解密视图**):

![1](https://shs3.b.qianxin.com/butian_public/fe58ccd7853032e52b4af7704b8b400f3.jpg)

这里攻击者注入了一个icmp request包，通信方向为: 192.168.100.1 ==&gt; 192.168.100.2

在192.168.100.1机器上抓包，观察到192.168.100.2返回的icmp response，攻击成功:

![1](https://shs3.b.qianxin.com/butian_public/f9b011e392cb0cb26c66ad6206b3fc886.jpg)

**0x03 混合密钥攻击(CVE-2020-24587)**
-------------------------------

- 攻击条件
    
    
    1. 近场
    2. 客户端需请求攻击者服务器
- 利用效果
    
    在不接入AP网络的情况下，泄露网络中某个分片帧的明文内容。
- 原理
    
    当单个数据帧长度过大时，可以使用帧分片机制，将一个帧分为多个帧进行传输。
    
    AP收到单个分片帧后会将其解密并存放在内存中，但并不会判断这些分片是否使用同一密钥加解密，而是单纯的使用序列号将解密后的分片帧组合起来，这就导致了混合密钥攻击。
    
    **此攻击无需知晓目标AP WiFi密码**。
- 攻击流程

![1](https://shs3.b.qianxin.com/butian_public/f1751c36b54c917759e4b241a06ad22a3.jpg)

1. 攻击者使用`Multi-Channel MitM`攻击转发STA与AP 802.11通信流量
2. 攻击者社工诱使STA访问攻击者服务器较大资源(图片、Js文件)。STA发送分片帧，并使用密钥k加密分片帧，其中分片的序列号(`Sequence number`)为s1，分片号(`Fragment number`)分别为n，n+1
3. 攻击者转发分片号为n的分片(Frag0)，并丢弃分片号为n+1的分片。分片n中携带IP头部等信息，AP使用密钥k解密Frag0并存放在内存中。
4. STA与AP重新握手(AP在配置rekey机制时，STA与AP会定时重新握手更新密钥)，协商密钥为m。
5. 当攻击者嗅探到STA发送分片时，捕获分片号为n+1的分片(Frag1)，将其序列号(`Sequence number`)修改为s1，并设置为最后一个分片，该分片可能携带敏感信息(HTTP协议)。AP使用密钥m解密Frag1并存放在内存中。
6. AP将Frag0与Farg1组合为完整数据包，由于分片Frag0中的地址指向攻击者的服务器(3.5.1.1)，该数据包则会发送至攻击者的服务器，导致分片Frag1中的内容泄露。

**0x04 分片缓存攻击(CVE-2020-24586)**
-------------------------------

- 攻击条件
    
    
    1. 近场
    2. 已知AP WiFi密码
- 利用效果
    
    泄露网络中某个分片帧的明文内容
- 原理
    
    分片缓存攻击基于混合密钥攻击，区别在于第一组分片由攻击者发送而不是STA，所以攻击者需要知道AP的WiFi密码。此攻击能够实现在于即使STA断开连接，AP依然会将解密的分片缓存在内存中。
- 攻击流程

![1](https://shs3.b.qianxin.com/butian_public/fe7ba861cf63ba848cc69c375da9ad087.jpg)

1. 攻击者伪装成STA与AP建立链接，并请求攻击者服务器较大资源，之后只发送第一个分片。
2. AP使用密钥k将Frag0解密后存在内存中。之后攻击者与AP断开链接。
3. STA与AP建立链接，攻击者使用`Multi-Channel MitM`攻击转发STA与AP 802.11通信流量
4. 当攻击者嗅探到STA发送分片时，捕获分片号为n+1的分片(Frag1)，将其序列号(`Sequence number`)修改为s1，并设置为最后一个分片，该分片可能携带敏感信息。AP使用密钥m解密Frag1并存放在内存中。
5. AP将Frag0与Farg1组合为完整数据包，由于分片Frag0中的地址指向攻击者的服务器(3.5.1.1)，该数据包则会发送至攻击者的服务器，导致分片Frag1中的内容泄露。

**0x05 参考资料**
-------------

1. <https://papers.mathyvanhoef.com/usenix2021.pdf>
2. <https://www.youtube.com/embed/88YZ4061tYw>
3. <https://www.fragattacks.com/#notpatched>
4. <https://github.com/vanhoefm/fragattacks>
5. <https://inet.omnetpp.org/docs/showcases/wireless/aggregation/doc/index.html>

0x06 关于我们
---------

**天工实验室**隶属于奇安信技术研究院，专注于**物联网、车联网**领域的安全研究，包括物联网协议安全、固件安全、无线安全、智能网联汽车及自动驾驶安全等，服务于国家和社会对网络空间安全的战略需求。团队成员秉承“天工开物、匠心独运”的创新使命和工匠精神，在物联网漏洞挖掘与攻防领域有丰富的经验积累，漏洞研究成果连续在GeekPwn、天府杯等漏洞破解赛事中斩获多个奖项，漏洞挖掘创新型方法发表于Usenix等国际顶级会议。