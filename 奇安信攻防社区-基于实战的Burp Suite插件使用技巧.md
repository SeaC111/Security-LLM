0×00前言
------

​ Burp Suite是一个集成化的渗透测试工具，它集合了多种渗透测试组件，使我们自动化地或手工地能更好的完成对web应用的渗透测试和攻击。在渗透测试中，我们使用Burp Suite将使得测试工作变得更加容易和方便，即使在不需要娴熟的技巧的情况下，只有我们熟悉Burp Suite的使用，也使得渗透测试工作变得轻松和高效。

Burp Suite可执行程序是java文件类型的jar文件，免费版的可以从[免费版下载地址](https://portswigger.net/burp/releases)进行下载。免费版的Burp Suite会有许多限制，很多的高级工具无法使用，如果您想使用更多的高级功能，需要付费购买专业版。

0×01专业版激活
---------

当然了，身为一个合格的安全人士，肯定会白嫖的啦。具体安装大家自行百度吧。

0×02插件的环境安装
-----------

安装完成是不是已经迫不及待想要安装插件了，但是不行的，因为Burp Suite的一些插件需要依赖python或者ruby来实施，所以我们需要安装`jython`和`jruby`

[点我下载jruby](https://cloud.189.cn/t/JRBrAzRnQRji)

[点我下载jython](https://cloud.189.cn/t/YraMRnJjq6by)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0dc2f383139535e09789a1c2e2b35a03e79ed39d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0dc2f383139535e09789a1c2e2b35a03e79ed39d.png)  
下载完成之后我们依次点击Extender →Options 按照提示把对应的文件路径导入进去就可以了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-62b9df62761f382787d82c3cb4cfc4db81f3e41c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-62b9df62761f382787d82c3cb4cfc4db81f3e41c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1312d1a08cffe1262772c1c8ef09915e9121f87f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1312d1a08cffe1262772c1c8ef09915e9121f87f.png)

0×03插件使用
--------

首先打开Extender →BApp Store 可以看到插件市场有大量的插件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d82baea718b34f7b00328042f075603fae22f0c7.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d82baea718b34f7b00328042f075603fae22f0c7.png)  
这里面插件实在是太多了，实战中几乎用不到几个，接下来我们讲一下实战中实用的插件

### Shiro漏洞被动检测

描述：  
`Apache Shiro是美国阿帕奇（Apache）软件基金会的一套用于执行认证、授权、加密和会话管理的Java安全框架。 Apache Shiro默认使用了CookieRememberMeManager，其处理cookie的流程是：得到rememberMe的cookie值 > Base64解码–>AES解密–>反序列化。然而AES的密钥是硬编码的，就导致了攻击者可以构造恶意数据造成反序列化的RCE漏洞。`  
喵呜师傅写的插件，非常好用，推荐！

[下载地址](https://github.com/pmiaowu/BurpShiroPassiveScan)

下载完成之后打开burp主页面点击Extender，可以看到这里有个ADD点一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-fca49bd9409271f1ca44b5a8be56630aba4cb358.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-fca49bd9409271f1ca44b5a8be56630aba4cb358.png)  
我们的这个插件是java写的的所以选择java脚本把插件导入然后下一步  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7a3ed376fe7ecf50886c0c199beb8c22caebeb16.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7a3ed376fe7ecf50886c0c199beb8c22caebeb16.png)  
出现如下界面代表安装成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-10ba35240bfc0bfa1debab9c4b7faf1bc50d38c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-10ba35240bfc0bfa1debab9c4b7faf1bc50d38c4.png)  
接下来我们就可以愉快的挖洞了，由于这个插件是被动式检测，所以我们不用对它进行配置，直接开着BURP就行了，如果遇到漏洞会在Target页面显示出来，我们打开一个靶场测试一下，如下图。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4fdf1d766fc57e23424464ef7ca1d67175e6545f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4fdf1d766fc57e23424464ef7ca1d67175e6545f.png)  
tag界面查看漏洞情况

```php
waiting for test results = 扫描shiro key 中
shiro key scan out of memory error = 扫描shiro key时,发生内存错误
shiro key scan diff page too many errors = 扫描shiro key时,页面之间的相似度比对失败太多
shiro key scan task timeout = 扫描shiro key时,任务执行超时
shiro key scan unknown error = 扫描shiro key时,发生未知错误
[-] not found shiro key = 没有扫描出 shiro key
[+] found shiro key: xxxxxx = 扫描出了 shiro key
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-248cb410ad21e1b90b25e6bac189342c00116c76.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-248cb410ad21e1b90b25e6bac189342c00116c76.png)

### fastjson漏洞被动检测

描述：  
`Fastjson 是阿里巴巴的开源JSON解析库，它可以解析 JSON 格式的字符串，支持将 Java Bean 序列化为 JSON 字符串，也可以从 JSON 字符串反序列化到 JavaBean。 Fastjson 存在反序列化远程代码执行漏洞，当应用或系统使用 Fastjson 对由用户可控的 JSON 字符串数据进行解析时，将可能导致远程代码执行的危害。`  
依旧是喵呜师傅的作品。[点我下载](https://github.com/pmiaowu/BurpFastJsonScan)

插件的安装步骤对照上面的来就行，这个插件也是被动式检测，所以我们不用对它进行配置，如果遇到漏洞会在Target页面显示出来，我们打开一个网站测试一下，如下图。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-093e143649be293d3bf2dab418df0fa460b7d893.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-093e143649be293d3bf2dab418df0fa460b7d893.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-abeedeb5b7f90aab50bea5316f19195f1015d698.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-abeedeb5b7f90aab50bea5316f19195f1015d698.png)

### Struts2漏洞被动检测

描述：  
`Apache Struts是美国阿帕奇（Apache）软件基金会的一个开源项目，是一套用于创建企业级Java Web应用的开源MVC框架，存在多个远程命令执行漏洞。 攻击者可以发起远程攻击,不但可以窃取网站数据信息,甚至还可取得网站服务器控制权。而且,目前针对此漏洞的自动化工具开始出现,攻击者无需具备与漏洞相关的专业知识即可侵入服务器,直接执行命令操作,盗取数据甚至进行毁灭性操作。`  
插件下载地址：[点我下载](https://github.com/x1a0t/Struts2Burp)

插件的安装步骤对照上面的来就行，成功安装如下图。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7e7fe7a75a04e137e235a34a57cfa53ab5df6a15.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7e7fe7a75a04e137e235a34a57cfa53ab5df6a15.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ad29d6fe903ef9d99a7998031eb37dae79370946.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ad29d6fe903ef9d99a7998031eb37dae79370946.png)  
我们用它测试一下Struts2漏洞，本地起一个漏洞环境

[环境下载地址](https://github.com/xhycccc/Struts2-Vuln-Demo)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7892ad318b606e2cfefe6c916823a76bda244549.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7892ad318b606e2cfefe6c916823a76bda244549.png)  
使用这个插件也是被动式检测

所以我们不用对它进行配置直接打开BURP访问网站即可，如果扫描到漏洞会在Target页面显示出来，或者在我们点击它自己的界面展示漏洞情况，如下图。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2a2f8cea2dd33d5ec85e6dda6b8f7a29c327c814.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2a2f8cea2dd33d5ec85e6dda6b8f7a29c327c814.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f86de18a757055d778de464d7c8fdfd40bacf45e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f86de18a757055d778de464d7c8fdfd40bacf45e.png)

### 敏感信息收集工具

描述：  
`HaE是基于 BurpSuite 插件 JavaAPI 开发的请求高亮标记与信息提取的辅助型插件。该插件可以通过自定义正则的方式匹配响应报文或请求报文，可以自行决定符合该自定义正则匹配的相应请求是否需要高亮标记、信息提取。`  
HaE插件是由gh0stkey师傅写的 特别棒的一个插件，使用简单还功能强大。

[下载地址](https://github.com/gh0stkey/HaE)

gh0stkey在Github介绍的使用方法如下：

插件装载: `Extender - Extensions - Add - Select File - Next`

初次装载`HaE`会初始化配置文件，默认配置文件内置一个正则: `Email`，初始化的配置文件会放在与`BurpSuite Jar`包同级目录下。

除了初始化的配置文件外，还有`Setting.yml`，该文件用于存储配置文件路径；`HaE`支持自定义配置文件路径，你可以通过点击`Select File`按钮进行选择自定义配置文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ce3005004d0093254c98c84d11212c4456ecdc31.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ce3005004d0093254c98c84d11212c4456ecdc31.png)  
出现如下界面表示安装成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1150044f9e9de8aed422bbdc8444dfa610c6e4c9.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1150044f9e9de8aed422bbdc8444dfa610c6e4c9.png)  
默认的Email规则  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1355f7946fcee9cea05c0dc3709aff3c0facecbc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1355f7946fcee9cea05c0dc3709aff3c0facecbc.png)  
生成的规则文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-153f815f71c84a7b5193d40408bf76da90ac9fa0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-153f815f71c84a7b5193d40408bf76da90ac9fa0.png)  
`HaE`支持自定义配置文件路径，你可以通过点击`Select File`按钮进行选择自定义配置文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4ce71a24392a6448d23434cf7cabd85c2aed9514.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4ce71a24392a6448d23434cf7cabd85c2aed9514.png)  
到了这一步安装已经成功，接下来会有朋友问，我不会写规则怎么办，这些东西对我来说太难用了，不要担心，作者gh0stkey师傅贴心的准备了一个公共规则网站，里面提供了大部分常用规则，以供大家使用。

地址：<https://gh0st.cn/HaE/>  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-dcb4455d42bcafbc7a49614b3a19f0674d1d3d24.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-dcb4455d42bcafbc7a49614b3a19f0674d1d3d24.png)  
使用方法就是复制这些规则打开Config.yml文件复制进去然后就OK了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-250896adb75e9459b2a8c2f3456ee7b9a5b38f2e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-250896adb75e9459b2a8c2f3456ee7b9a5b38f2e.png)  
默认的规则  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3b03b8d7fc33f0bf43bdbf04bcd8540152b52d68.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3b03b8d7fc33f0bf43bdbf04bcd8540152b52d68.png)  
复制规则网站里面的规则然后粘贴保存（替换规则的时候记得退出burp）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-db0ab1cac5d3af27050f883a495cccb01825e915.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-db0ab1cac5d3af27050f883a495cccb01825e915.png)  
打开我们的插件`HaE`可以发现我们的规则已经替换成功了，可以使用了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d49fda24274974fb7bedcdb8a86f43bacb7f457f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d49fda24274974fb7bedcdb8a86f43bacb7f457f.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d56d8860944cd225368bec2d922587ac706baea8.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d56d8860944cd225368bec2d922587ac706baea8.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-51792dc04093e5f1d6006ddcd12084670b904c66.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-51792dc04093e5f1d6006ddcd12084670b904c66.png)  
我们使用Swagger的规则来演示一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b8f26bf19f03765f759efca37a86a04cf215cd03.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b8f26bf19f03765f759efca37a86a04cf215cd03.png)  
在Proxy - HTTP History中可以看见高亮请求，响应标签页中含有Swagger UI的标签，其中将匹配到的信息提取了出来。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7683d706da9ba845157f3ce6388cfa4829de06de.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7683d706da9ba845157f3ce6388cfa4829de06de.png)  
还有更多用法等待大家去使用。

### 403Bypasser

`绕过 403 受限目录的 burpsuite 扩展。通过使用 PassiveScan（默认启用），这个扩展会自动扫描每个 403 请求，所以只需添加到 burpsuite 并享受。`  
安装

BurpSuite -&gt; Extender -&gt; Extensions -&gt; Add -&gt; Extension Type: Python -&gt; Select file: 403bypasser.py -&gt; Next till Finish

这个插件就是使用python编写的，这个就使用到了我们之前讲的安装`jython`这个插件，我们可以让burp使用python格式的插件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7dd197ccf24ab57cf9d76610389040f3619320d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7dd197ccf24ab57cf9d76610389040f3619320d1.png)  
看到如下界面表示安装成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-95b6690334876909000fadbdaea08dcb565d65a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-95b6690334876909000fadbdaea08dcb565d65a5.png)  
好了，这样我们就可以愉快的使用了。（这个插件也是被动扫描）

我们可以看下这个插件的payload，可以发现这个插件主要功能是用来bypass403页面的，举个例子，比如我们有时候看到很多网站限制外部访问，访问的话直接显示403，我们可能改一个IP头为本地127.0.0.1我们就能绕过这个限制，这个插件可以全自动的来帮我们验证，是不是很方便。

```php
$1/$2
$1/%2e/$2
$1/$2/.
$1//$2//
$1/./$2/./
$1/$2anything -H "X-Original-URL: /$2" 
$1/$2 -H "X-Custom-IP-Authorization: 127.0.0.1" 
$1 -H "X-Rewrite-URL: /$2"
$1/$2 -H "Referer: /$2"
$1/$2 -H "X-Originating-IP: 127.0.0.1"
$1/$2 -H "X-Forwarded-For: 127.0.0.1"
$1/$2 -H "X-Remote-IP: 127.0.0.1"
$1/$2 -H "X-Client-IP: 127.0.0.1"
$1/$2 -H "X-Host: 127.0.0.1"
$1/$2 -H "X-Forwarded-Host: 127.0.0.1"
$1/$2%20/
$1/%20$2%20/
$1/$2?
$1/$2???
$1/$2//
$1/$2/
$1/$2/.randomstring
$1/$2..;/
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4d72a7b52fca0c088a9dcc60f59fd53a3d537737.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4d72a7b52fca0c088a9dcc60f59fd53a3d537737.png)  
好了，目前我使用频率较高的插件已经分享完毕，还有很多好用的插件是我没有讲到的，希望大家也可以留言分享出来，接下来讲一下BURP的一些小技巧，burp是非常一个强大的渗透测试工具，我们平时做渗透使用频率最高的工具，它其实还有很多好用的功能给大家分享一下。

dnslog功能
--------

Burp Collaborator是从Burp suite v1.6.15版本添加的新功能，也就是DNSlog，监控DNS解析记录和HTTP访问记录，在检测盲注类漏洞很好用。

### 首先打开Collaborator

主界面菜单项 burp - burp collaborator client 即可启用  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7b464d8bf29c548fc0694c93b52e5a512df929e2.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7b464d8bf29c548fc0694c93b52e5a512df929e2.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-359ecc38db6ef02ac5505cad4512968fac785793.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-359ecc38db6ef02ac5505cad4512968fac785793.png)  
点击copy to clipborad来复制其提供的 payload url，number to generate 是生成的数量,

我们来ping一下刚才复制的URL  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ef41bd854168bbd3375e1816dad77363eb149da2.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ef41bd854168bbd3375e1816dad77363eb149da2.png)  
可以看到BURP成功接收到我们的请求  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a864010ab1a2b07b269c7e5a5fd26a3cf0804d2b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a864010ab1a2b07b269c7e5a5fd26a3cf0804d2b.png)

条件竞争漏洞测试
--------

“竞争条件”发生在多个线程同时访问同一个共享代码、变量、文件等没有进行锁操作或者同步操作的场景中。

开发者在进行代码开发时常常倾向于认为代码会以线性的方式执行，而且他们忽视了并行服务器会并发执行多个线程，这就会导致意想不到的结果。

简单的说：本来你有100块钱，买一个商品要花100，你可以多开启多个线程去跑，有可能不止一个用户买成功

“竞争条件”漏洞有时很难通过黑盒/灰盒的方法来进行挖掘，因为这个漏洞很受环境因素的影响，比如网络延迟、服务器的处理能力等。一般都会通过对代码进行审计来发现此类问题

可以使用Burp的intruder功能来实现发送多个并发请求

将请求包发送至Intruder

Intruder – Payloads – Payload Stes

Payload type设置为NUll payloads

Payload Options 次数设置100次  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-852a1af261c4bd4cbc0b33b8c3bf1bd8f90cdde0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-852a1af261c4bd4cbc0b33b8c3bf1bd8f90cdde0.png)  
Intruder – Options – Request Engine

线程数设置最大999 ，点击Start attack  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9cf47b32cabb84ef78ea5db0a1423a5d389a6cb0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9cf47b32cabb84ef78ea5db0a1423a5d389a6cb0.png)  
这样就可以来尝试并发漏洞啦。

Intruder模块匹配返回包内的字符和中文
----------------------

在一些渗透测试的教程中，用Intruder模块爆破或fuzz的时候，一般只讲到了通过返回包的长度或者状态码来识别是否爆破成功/是否fuzz出我们想要的内容。

其实在Intruder-&gt;Option-&gt;Grep-Match中提供了返回包匹配内容的功能，可以通过简单的字符串或正则表达式进行内容匹配。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ca4e659d36480723cab071d0a864e5ff7731ec63.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ca4e659d36480723cab071d0a864e5ff7731ec63.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2a65d00f5f9b8c46a177a71282a07ed2b39b84c9.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2a65d00f5f9b8c46a177a71282a07ed2b39b84c9.png)  
可以看到匹配成功的话后面会打勾  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f9c63ce4ec7f62e71a20b5f2084f178306fa0330.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f9c63ce4ec7f62e71a20b5f2084f178306fa0330.png)  
有朋友可能会问了，我要是匹配中文字符怎么办呢，演示一下匹配中文字符怎么操作。

如果要匹配中文，需要将中文转换成十六进制，使用正则匹配的方式，操作如下： 先用python把中文转成十六进制（不局限于此方法）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e182d3ac63391bbaae918db180f2c92d63892f3c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e182d3ac63391bbaae918db180f2c92d63892f3c.png)  
然后设置正则匹配模式，把十六进制添加进去  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1454a0b534ff450add6d33c19e08a88c326370cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1454a0b534ff450add6d33c19e08a88c326370cc.png)  
成功匹配到，大家可以动手操作一下。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-533b107bffd32ed36d24721d1f3cea8c11420f79.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-533b107bffd32ed36d24721d1f3cea8c11420f79.png)  
结束语：BURP的功能也不止这些，大家可以多发掘一下其他功能，让自己在挖洞的时候可以更加方便，如果有其他更好的插件和技巧也希望大家留言分享。