0x01 OAuth授权框架
==============

OAuth是一种常用的授权框架，它使网站和应用程序能够请求对另一个应用程序上的用户帐户进行有限访问。OAuth允许用户授予此访问权限，而无需将其登录凭据暴露给请求的应用程序。这意味着用户可以选择他们想要共享的数据，而不必将其帐户的账号密码交给第三方。

0x02 OAuth2.0是如何运行的？
====================

可以看下阮一峰老师对于OAuth2.0基础知识的讲解，非常的详细这里就不多赘述了。  
[https://www.ruanyifeng.com/blog/2014/05/oauth\_2\_0.html](https://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)

0x03 OAuth 2.0：Bearer Token
===========================

Bearer Token用于 OAuth 2.0授权对资源的访问，任何 Bearer Token 的携带者都可以使用它随意访问相关资源。

一般都采用`Authorization Header`的方式，携带`Authorization: Bearer XXXXXXXXXXXXXXXXXXXXXXXXXX`

```php

GET /resource HTTP/1.1
Host: server.example.com
Authorization: Bearer XXXXXXXXXXXXXXXXXXXXXXXXXX

```

0x04 Bearer Token生成接口未授权访问
==========================

漏洞简介：
-----

一次对经过授权的小程序进行渗透测试，由于开发错误的将获取 Bearer Token的接口设置成了未授权访问，导致上万条超敏感信息泄露。

漏洞流程：
-----

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ce42991384e220b92e0f7184c65a403b536701f5.png)

漏洞利用：
-----

1、访问目标小程序接口，发现返回了spring security oauth2的报错信息。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-863bd2fae5bdaa4dfd408dcb6ac2dad56af5e025.png)

2、我们将小程序进行解包，然后搜索：Bearer，看下能否找到硬编码的Bearer Token，定位到下图位置发现是个文件上传的功能，但是loadToken()方法会帮文件上传功能生成一个Bearer Token，这里我们就可以进一步利用loadToken()帮我们生成一个Bearer Token。(推测此处研发在写代码的时候⽂件上传为未授权接口，但oatth2此处强制校验相关认证字段，故系统需要写一个方法为上传功能⽣成⼀个Bearer Token)

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ba37ee24dddbc2acfc6bb91722a9312fbc98acca.png)

3、我们定位到loadToken()方法，发现是post请求接口

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7a210b3c05cf96837b5c75ee36574fab2e9a487b.png)

4、我们尝试post请求访问该接口，成功返回Bearer Token

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-94682ab9443d731af9c6146dd718cec7de7688c6.png)

5、我们登陆到小程序首页，查看js可看到相关的路由

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-67eee7cae6bc2ff97aaa966ebfd7242c84cb94dd.png)

访问其中一个接口，然后使用burp拦截，修改数据包，添加Authorization: Bearer Bearer Token（上一步获取到的），放包后就来到了相应的路由界面，后续的流量包要直接丢掉，不然就会因为认证问题直接跳转到登陆页面

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c3ae62f55ada60a1d87f0acf124b88be2140851a.png)

6、我们发现该页面是一个数据导出的页面，点击导出抓包，然后添加Authorization: Bearer Bearer Token（上一步获取到的），发送数据包，获取到了上千条超敏感数据

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-44c67ce7d29103ab622574b7ede3e5e92a32e9ce.png)

7、同理访问其它路由接口，本次测试一共获取到了上万条超敏感数据。

0x05 URL重定向漏洞
=============

漏洞简介：
-----

一些授权服务对于回调的URL做设置或者限制，导致攻击者可以利用这点做一些URL重定向攻击，一般有两种情况

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-73d35a95836e019c0b9eb98fbc4a081f54d5fcae.png)

1、对于URL无任何限制，可以为任意

2、对于URL有限制，只能为本网站的地址，该漏洞利用条件较为苛刻，需要目标网站存在任意文件上传漏洞或者存在可以上传图片的功能，伪造URL重定向后的恶意页面，获取目标用户的Token值等敏感信息。

漏洞流程：
-----

1、url无限制

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a86eb3bfafab0d7c79fbec7b98428ff1426be9e8.png)

2、url有限制

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-42747799f7f92e4ad38d5b12fa62c988eb0bdca9.png)
========================================================================================================

漏洞利用：
-----

直接讲解url有限制的漏洞

1、利用网站的任意文件上传漏洞上传一个恶意html页面,如hacker.html，其中设置document.referrer用以获取referrer中的Token值。

2、构造恶意URL链接如：  
` www.hacker.com?reponse\_type=code&client\_id=1234555&redirect\_url=www.hacker.com/hacker.html`

3、诱导用户访问URL，我们就能获取到用户的token值了

0x06 ID、Secret泄漏
================

漏洞简介：
-----

部分开发安全意识不强，将id和secret硬编码进apk中，或者在JS、heapdump、github上泄露出去，导致攻击者利用id和secret获取到token。

漏洞利用：
-----

1、对目标app进行反编译，发现id和secret

2、发现是钉钉的id和secret,利用官方开发文档的代码获取到token，也可以直接利用官方的api获取token[https://open-dev.dingtalk.com/apiExplorer#/?devType=org&amp;api=oauth2\_1.0%23GetAccessToken](https://open-dev.dingtalk.com/apiExplorer#/?devType=org&api=oauth2_1.0%23GetAccessToken)

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b478cc3739e2d02bd7c6fb551ef7cffa61bf3928.png)

0x07 postMessage XSS漏洞
======================

漏洞简介：
-----

Facebook OAuth2.0绕过漏洞，价值38wrmb的漏洞

漏洞流程：
-----

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ebb8102948e7d1ae4b8146f2d37d38e6afb26175.png)

漏洞利用：
-----

Facebook官方网站`staticxx.facebook.com`中的`7SWBAvHenEn.js`为开发人员提供了JavaScript SDK接口接入，开发人员可以创建能够跨域通信的iframe，再使用`window.postMessage()`收发令牌。这就能够使一些跨站点脚本等攻击能够直接生效，不用在花精力去绕过CSP。

facebook利用/connect/ping接口获取access令牌，然后返回redirect\_uri到/connect/xd\_arbiter.php

`https://www.facebook.com/connect/ping?client\_id=APP\_ID&redirect\_uri=https://staticxx.facebook.com/connect/xd\_arbiter.php?version=24&origin=`

攻击者发现`xd\_arbiter.php?version=42`是可以被修改为白名单中的路径，比如修改为`xd\_arbiter/?v=42`，这样就可以在后面添加更多参数或者目录。通过这样的这种方式，我们可以获取到access令牌的hash值。然后借助JavaScript SDK创建`iframe`，再使用`window.postMessage`()将access令牌的hash值传送出来。于是可以构造出redirect\_uri：

`https://staticxx.facebook.com/connect/xd\_arbiter/r/?version=42`

最终可以构造出如下链接，获取用户的token

`https://www.facebook.com/connect/ping?client_id=123&redirect_uri=https://staticxx.facebook.com/ connect/xd_arbiter/r/7SWBAvHenEn.js?version=44#origin=https://domain.com`

0x08 参考链接：
==========

[https://www.ruanyifeng.com/blog/2014/05/oauth\_2\_0.html](https://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)

<https://developer.mozilla.org/zh-CN/docs/Web/API/Window/postMessage>

<https://javascript.info/cross-window-communication>

<https://labs.detectify.com/2016/12/08/the-pitfalls-of-postmessage/>

<https://ngailong.wordpress.com/2018/02/13/the-mystery-of-postmessage/>

<https://yxw21.github.io/2020/06/05/Account-Takeover-Via-PostMessage/>