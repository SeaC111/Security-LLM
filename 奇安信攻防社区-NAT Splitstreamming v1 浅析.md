NAT Splitstreamming是啥
---------------------

2020年10月，一名叫Samy Kamkar的研究员公开了一种针对NAT网关的攻击技术：NAT Splitstreamming，通过这种技术，可以实现从外网突破NAT网关，直接访问NAT内网的IP。简而言之，部分基于NAT的路由器、防火墙可能被攻击者从外网突破，直接进入内网，这里贴一张原作者的攻击示意图：

![nat_0](https://shs3.b.qianxin.com/butian_public/f7b6bcb1a7ced76f28b8e4b1ea93905b4.jpg)

本文将会把NAT Splitstreamming的大致原理做一个科普性质的介绍，原作者的详细技术文章可以看这个链接：<https://samy.pl/slipstream/>

### NAT介绍

这里提到的NAT就是Network Address Translation的意思，我们一般使用的家用路由器，以及部分防火墙本质上都是NAT网关。NAT的作用是让多个设备共享同一个IP地址来接入互联网，因为IPv4的地址数量有限，但大家手里的电脑、手机、平板等等设备却越来越多，如果给每个设备分配一个公网IP地址上网那么肯定是不现实的。所以当我们通过家里的Wifi或者公司的局域网来接入互联网时我们的设备实际上只有一个内网地址，就像`10.0.0.0/8`或`192.168.0.0/16`。当我们使用这样的内网地址上网时，外发的IP数据包会先经过你的路由器或者防火墙，而路由器或者防火墙会把外发数据包的源地址和源端口修改，变成真正的公网IP。当数据包从外网传入的时候，路由器或者防火墙又会把包的目的地址和目的端口修改成内网的某台设备的IP，再将其发送给这个设备。

这样NAT设备就需要维护一个地址映射表：

![nat_1](https://shs3.b.qianxin.com/butian_public/f680ec7d775b91c2aa54cf158a1d8e955.jpg)

当内网设备向外部发起连接时NAT网关会把这个内网设备的地址和源端口记录下来，再把它换成一个公网地址和端口，当公网回包时NAT网关又能通过这个记录下来的映射关系把内网地址给改回来。一般来说，大多数NAT网关只做一个方向上的NAT，也就是刚刚上面描述的这种地址转换方式。这种方式有一个特点，就是只能由内网的设备主动连接外网的IP，而外网的设备是不能主动访问内网的IP的，这天然就是一种防火墙。所以一般从外网发起针对内网的攻击大多需要先拿下一台内网设备，再以内网设备为跳板才能访问到内网的其他IP。

### ALG介绍

刚刚简单介绍了NAT的原理，不过如果对网络协议比较熟悉的朋友可能就会发现上述的这地址转换方式并不能支持某些特殊的协议，例如主动模式的FTP：

![nat_3](https://shs3.b.qianxin.com/butian_public/f57a2f3f6da8cbcecff63c01e38db1558.jpg)

其中客户端会主动连接服务端的21端口，并且开放一个本地的随机端口，然后通过PORT命令告诉服务端自己的随机端口具体是哪个，服务端再用自己的20端口主动连接客户端。这里就存在一个问题：如果服务端在外网，那么这里就需要让外网的设备主动连接内网的一个IP，这在上面描述的NAT方式里面是行不通的。

为了解决这个问题，便有了另一个技术：ALG，全称是Application Layer Gateway。ALG也是运行在NAT网关上的，专门处理像FTP这类的“奇葩”协议。它会识别应用层的协议类型，如果一个主动模式的FTP连接建立了，ALG是能识别出来的，然后在客户端发送PORT命令时修改PORT命令指定的IP和端口，把他们换成外网的IP和端口。当服务端向客户端主动发起连接时再把它改成内网客户端的IP和端口，如此就可以让主动模式FTP正常工作了：

![nat_2](https://shs3.b.qianxin.com/butian_public/f0be72556415e2d0ed4c1dfe332884119.jpg)

从上面这张图可以看出来，ALG本质上就是在FTP发送PORT命令时篡改命令内容，并且给NAT增加一条地址映射。后续FTP服务器发起的主动连接就能通过这条新的地址映射来访问内网的IP了。

如何突破NAT
-------

### 基本原理

刚才上面提到NAT天然就是一个防火墙，而NAT Splitstreamming的作用就是突破这个防火墙，直接从外网访问内网IP。刚刚提到的ALG就可以为NAT网关添加地址映射，那么如果能利用ALG的这个特性实现内网任意地址+端口的映射，那么不就可以实现外网主动访问任意内网地址了么～

NAT Splitstreamming的核心方法也就是这个。为了说明清楚这个逻辑，我们可以看看一般的ALG是如何实现的。这里可以简单的看看Linux的ALG实现，也就是Netfilter的Conntrack，这里用的代码版本是Linux 5.9.3。

要对FTP协议做ALG，首先需要识别主动模式的FTP数据包，我们可以在`nf_conntrack_ftp.c`中看到识别FTP的代码：

![image-20210209165202802](https://shs3.b.qianxin.com/butian_public/fa811959288f79188393e645192104a17.jpg)

最关键的部分就在于这个`find_pattern`函数，它的作用是在当前的数据包内容中匹配特征，如果特征命中则认为当前的数据包就是主动模式的FTP包：

![image-20210209165514051](https://shs3.b.qianxin.com/butian_public/f53aef3e771a5bf806f90eb6b3f475e4f.jpg)

而这个`pattern`定义在一个`ftp_search`结构中：

![image-20210209165654203](https://shs3.b.qianxin.com/butian_public/fb1aa3f411ee5617ff4c104127f77a188.jpg)

可以看到Linux除了会对主动模式（`NF_CT_FTP_PORT`）的FTP做ALG处理外，还会对其他几种不同状态下的FTP协议做ALG处理，不过这里我们不需要关心它们。上面用做`pattern`的值就是一个字符串:`"PORT"`，那么就是说数据包的内容匹配上这个pattern就会被识别成FTP协议？当然不是，在`nf_conntrack_ftp.h`中限定了端口：

![image-20210209170121193](https://shs3.b.qianxin.com/butian_public/ffe9e1618af39b2c13babedda7fb8d688.jpg)

也就是说（目的）端口是21，且payload内容匹配`"PORT"`这个pattern的TCP包就会被Linux认为是主动（PORT）模式的FTP。也就是说，如果能从内网向外发一个目的地址端口是21，且包含`"PORT"`的TCP包即可欺骗Linux，让它以为来了个FTP包，从而触发ALG往NAT映射表中添加映射记录的行为。

但是这样需要攻击者从内网发包，既然都能在内网发包了，那哪还需要突破防火墙呢？办法也不是没有，NAT Splitstreamming就使用了一系列的技巧实现了这个目标。

### SIP协议

其实在2010年Samy Kamkar就在BlackHat上公开了这种攻击思路，只不过使用的不是FTP，而是IRC协议。细节可以看这个链接：[https://samy.pl/natpin/，以及这个链接：https://samy.pl/talks/2010-talk.ppt](https://samy.pl/natpin/%EF%BC%8C%E4%BB%A5%E5%8F%8A%E8%BF%99%E4%B8%AA%E9%93%BE%E6%8E%A5%EF%BC%9Ahttps://samy.pl/talks/2010-talk.ppt)。

回到正题，NAT Splitstreamming和NAT Pinning的思路略有不同，且更复杂，这次使用的是SIP协议。SIP的工作机制和主动模式的FTP类似，也存在一个可以触发ALG的包，即SIP的`REGISTER`包。和HTTP类似，SIP也是基于文本的协议，它的REGISTER包通常长这个样子：

```php
REGISTER sip:192.168.2.89 SIP/2.0

Via: SIP/2.0/UDP 192.168.2.161:10586
Max-Forwards: 70
From: <sip:01062237496@192.168.2.89>;tag=ca04c1391af3429491f2c4dfbe5e1b2e;epid=4f2e395931
To: <sip:01062237496@192.168.2.89>
Call-ID: da56b0fab5c54398b16c0d9f9c0ffcf2@192.168.2.161
CSeq: 1 REGISTER
Contact: <sip:192.168.2.161:10586>;methods="INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER"
User-Agent: RTC/1.2.4949 (BOL SIP Phone 1005)
Event: registration
Allow-Events: presence
Content-Length: 0
```

其中的`Contact`字段就是会被ALG修改，并添加NAT映射的地址。那么只要能让内网的某个设备对外发送这么一个SIP包，即可欺骗ALG。那么如何让一个内网的设备发这么一个包出来呢？这里就涉及到NAT Splitstreamming的核心技巧了：TCP分段。

### TCP分段

要搞清楚TCP分段是怎么回事，首先需要搞清楚一个概念：MTU。MTU全称是Maximum Transmission Unit，是指数据链路层上一个frame最大能传输的数据长度。在我们通常的网络里，数据链路层的协议是以太网，以太网的MTU长度是1500字节。那么在以太网上，一个IP包的长度就不能超过1500字节，同理，在IP上一个TCP包的长度就不能超过1500-20（IPv4头长度）字节。

那么明白MTU这个概念后，还需要明白另一个概念：MSS，全称是Maximum Segment Size。TCP协议传输数据时是以段（Segment）为单位的。当一次要传输的数据非常大时，就会被拆分成多个段来传输。那这个单个段的最大长度就是MSS。MSS一定小于MTU，但由于其他的一些因素（例如PMTU等），MSS可能还会更小，且值并不是始终不变的。所以TCP需要在建立连接时协商MSS的具体值。

这里NAT Splitstreamming就巧妙的利用了TCP分段的特性，伪造了一个SIP包。具体伪造的方法如下：

- 给内网的受害者发送一个钓鱼链接，内网的用户打开了这个链接；
- 这个链接所在的网页会在受害者的浏览器里发起一个HTTP POST请求，这个POST包非常大，至少大于受害者设备当前的MSS；
- 受害者发出的POST包被TCP分段发送，这个POST包的第二或则第三段外观看起来和一个SIP REGISTER包一摸一样（这里贴上原作者的图）：

![nat_4](https://shs3.b.qianxin.com/butian_public/f7dbe201ea7a846b2bbd2f78c0c6d7297.jpg)

这里的第三段就有可能被ALG网关识别成一个SIP包，从而触发NAT映射的添加。最后攻击者就可以通过添加的NAT映射访问“SIP包”中指定的内网IP+端口！

剩下的一些小问题
--------

上文简单介绍了NAT Splitstreamming的核心技巧，但要完成整个攻击还需要处理一些细节问题：

- 获取内网设备的准确IP地址
- 控制当前受害者设备的MSS值

### WebRTC 探测内网地址

这个其实已经不是什么新鲜技术了，大家可以看这个链接：<https://github.com/diafygi/webrtc-ips>

### MSS控制

因为最后需要让HTTP POST包发生分段，让后续的某个分段的位置刚好放在伪造的SIP包头部，于是就需要精确的控制MSS的值，然后在第二分段里面填充足够的垃圾数据，把第三段刚好“顶”到“SIP包”的起始位置。这个可以在TCP握手时通过TCP的MSS Option来告诉对端自己能接收的MSS是多少。

完整攻击流程
------

- 攻击者给内网的受害者发送一个恶意链接，受害者打开这个链接；
- 恶意页面通过发起STUN连接来探测当前设备的内网IP；
- 同时恶意连接请求到攻击者的服务器时攻击者可以通过TCP握手的MSS协商来控制MSS值；
- 恶意页面发起一个HTTP POST请求，其中的POST数据经过填充，大小超过MSS，触发分段，且让第三段起始位置精确的落在伪造的SIP包的头部。由此产生一个伪造的“SIP包”；
- SIP包触发ALG添加NAT地址映射，攻击者从这个映射的地址访问内网IP+端口；

总结
--

NAT Splitstreamming涉及两个关键的技术点：

1. TCP分段，并且控制分段的大小（MSS）；
2. 通过分段伪造出来的特定“协议“的”包“来欺骗NAT网关的ALG，使其为这个伪造的包添加NAT地址映射。

本质上是ALG实际实现上的一些不足之处导致被欺骗，从而被利用，而如果路由器或则防火墙本身没有ALG功能那自然不受此问题影响。

本文略掉了一些其他的细节，包括Samy Kamkar最近才更新的NAT Splitstreamming v2，有兴趣的读者建议可以去看看Samy Kamkar的Github：<https://github.com/samyk/slipstream/>。

参考链接
----

<https://samy.pl/slipstream/>

<https://github.com/samyk/slipstream/>

<https://samy.pl/natpin/>

<https://samy.pl/talks/2010-talk.ppt>

<https://github.com/diafygi/webrtc-ips>

[https://en.wikipedia.org/wiki/Maximum\_segment\_size](https://en.wikipedia.org/wiki/Maximum_segment_size)

<https://www.cnblogs.com/xiaxveliang/p/12434170.html>