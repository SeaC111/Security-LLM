0x01 前言
=======

为了写这篇文章，我查了好多外文资料，作为一个系统学过WEB前后端的人，还是花了点时间理解，其实和之前利用特殊字体来伪造钓鱼邮件的正常网址类似。woff字体在国内其实不太普及，虽然一些大型网站会用到，但是主要是用来反爬虫的，今天我们就来介绍下woff字体对于钓鱼技术的利用。

0x02 解读
=======

攻击始于一封伪装成DHL的（全球物流）邮件，里面附上了一个虚假的DHL钓鱼网站地址，目的是盗取信用卡凭证，打开后如下所示。

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-225a7a612c1651f769b71ba98d07d53d5fd5bbdb.640%3Fwx_fmt%3Dpng)

和大家说一下，它是怎么绕过安全检测的，我特地写了一个DEMO。

简单来说，这个技术并不新鲜，但是在2021年还是很流行。

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bf7f209d3bf67a744b77933c312b43d9a214b7b0.640%3Fwx_fmt%3Dpng)

渲染出来的文字和源码的文字是不一样的，因为文字被WOFF字体给替代了，我的理解是它们是一组映射关系，例如p对应u。

&lt;title&gt;部分，我加了点私货，将中文转换为了HTML编码的形式，这个在黑帽SEO中很常见，主要是对网站keywords关键词加密。

这种技术主要应对基于静态和正则表达式，进行检测的安全厂商。

DEMO源码如下：

```php
<html>
<head>
  <title>&#20013;&#22269;&#24314;&#35774;&#38134;&#34892;</title>
  <style type="text/css" media="screen, print">
@font-face {
  font-family: 'Slabo 27px';
  font-style: normal;
  font-weight: 400;
  src: url(1.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
body {
  font-family: 'Slabo 27px', serif;
}
</style>
</head>
<body>
   <span>umzzqvid:</span><input type="text">
</body>
</html>
```

woff2下载地址：

```php
https://s.threatbook.cn/report/file/5dd216ad75ced5dd6acfb48d1ae11ba66fb373c26da7fc5efbdad9fd1c14f6e3
#下载后记得把压缩包里的文件改为1.woff2，和上面的html网页放同一个目录。
```

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-682c267081f5addf9f72842c77fb17e76cb40489.640%3Fwx_fmt%3Dpng)

攻击者的手段更复杂一点，在CSS中把我们的woff2文件直接转换为了base64的形式加载。

攻击者其实是用了广撒网的模式，为了能让不同国家的用户看得懂网页，该钓鱼网站甚至支持根据来访者IP自动切换语言。

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6bf8f8ae6d95a58e12f3b0a18c748f1f3816d215.640%3Fwx_fmt%3Dpng)

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0934449c7233c910a76b9241ec68c4cb529b09ab.640%3Fwx_fmt%3Dpng)

除了利用WOFF2字体外，该钓鱼网站还根据不同来访者返回不同的页面。

- 如果你是电子邮件安全网关的IP或搜索引擎爬虫，就直接返回403。
    
    该钓鱼网站会针对google、Altavista、Israel、M247、barracuda、niw.com.au等。
- 普通访客可正常访问，但是若post三次数据或者get访问五次，就ban掉IP，并且返回403。

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2ced0f7ac048479c86ed39b5142eca7a0b27364f.640%3Fwx_fmt%3Dpng)

用户提交的所有敏感信息会被发到攻击者的邮箱或者Telegram频道，该频道由攻击者掌握，以下是使用 Telegram Bot API 发送数据的 Telegram 通道。

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cc46b6a825a25a772569d7fceea1515a7e882548.640%3Fwx_fmt%3Dpng)

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c3b8acce57db0ff0dbc6f4e94d341ae9e63cad45.640%3Fwx_fmt%3Dpng)

我们能够访问攻击者控制的 Telegram 通道之一，聊天中发送的敏感信息包括 IP 地址和信用卡数据。

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2d025a655e6778bee98d85fcec1e8037824d7401.640%3Fwx_fmt%3Dpng)

```php
https://core.telegram.org/api/obtaining_api_id
```

该API是免费创建的，有兴趣的兄弟可以了解下，利用API发送凭证到频道的PHP源码在上面，可以直接复现了。

值得一提的是，该攻击者采用的是以下邮箱进行接收：

- yandex\[.\]com
- gmail\[.\]com

0x03 总结
=======

- 用WOFF2来混淆源码
- 利用Telegram API来发送被盗凭证
- 反邮箱安全网关和爬虫IP和特征，根据来访者返回不同页面
- HTML中keyword关键词等部分考虑用HTML编码，CSS中url访问敏感文件考虑用base64编码

**XDM，你们的点赞和关注**

**是我更新的最大动力！！！**

![](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-54482612c109f2337bdbbfc5a0ee33d95a3f42c2.640%3Fwx_fmt%3Dgif)