前言
--

在某次渗透过程中，客户的内网里遇见了一个日志设备，于是便有了后续的RCE漏洞挖掘（在很久之前挖出来的，文章只是提供一个小思路，目前已经通知厂商进行了完全修复）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-772a86b55e60f605f90e42121cbd1eb580477961.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-772a86b55e60f605f90e42121cbd1eb580477961.png)

信息收集
----

对于设备我们首先要找到它的使用手册，注意几个功能关键点 (网络连通性，日志查看，系统备份，默认口令)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-85cc6624ae1ba394e6f1bc424fc0c11223fcc672.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-85cc6624ae1ba394e6f1bc424fc0c11223fcc672.png)

非常幸运，发现目标是存在系统源码下载的，我们下载后本地审计  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0238a26ec9a5f8fbf375a2b5e031ed0618b03e5a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0238a26ec9a5f8fbf375a2b5e031ed0618b03e5a.png)

找到了Web目录，有了源码我们就可以进行PHP代码审计来挖掘更多漏洞，首先先看一下有没有默认密码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7bce12c5de31d2e93ce44c6502425a1e492fdbc7.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7bce12c5de31d2e93ce44c6502425a1e492fdbc7.png)

这里发现了一个官方教学帖子里有默认的账号密码，我们去登录试试，毕竟后台漏洞挖掘更加轻松  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-45dc8184c46b2aa7b55caf6c8ae79c8a7408c728.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-45dc8184c46b2aa7b55caf6c8ae79c8a7408c728.png)

漏洞挖掘
----

没有更改默认密码，成功登陆到了后台，我们继续从功能点入手挖掘后台漏洞, 看代码后发现 command-html.php 文件比较可疑，传入 cmd 参数到 cmdhandle.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c02b476b5a1947a6b864b1a8350a105ee3f6b8a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c02b476b5a1947a6b864b1a8350a105ee3f6b8a5.png)

我们查看 cmdhandle.php 文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7360554b154d4881d36ed62e8d8b3890352e05bc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7360554b154d4881d36ed62e8d8b3890352e05bc.png)

这里没有什么过滤就执行了命令，可能是设备的调试页面，我们直接访问测试  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b7abc42e67b45ed9b001412fe3939a2024e75992.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b7abc42e67b45ed9b001412fe3939a2024e75992.png)

权限也挺高的，我们写入 Webshell文件, 成功拿下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-87a3d9ad05ed973f7cbfa49d6f71e8152595e6da.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-87a3d9ad05ed973f7cbfa49d6f71e8152595e6da.png)

结果过了一段时间再看的时候，连接Webshell  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b8230ca81407f74b6f02608eb3a1840468968cb9.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b8230ca81407f74b6f02608eb3a1840468968cb9.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-66e77717369260a31bc7392da0aa175a928e4db8.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-66e77717369260a31bc7392da0aa175a928e4db8.png)

权限就这样没了，不甘心这样，于是继续代码审计尝试挖掘一个前台RCE出来  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-75b576de364efd6e0908e189c050ccea2ece7628.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-75b576de364efd6e0908e189c050ccea2ece7628.png)

首先打开代码，先查看配置文件里有什么  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9eb5cb163f69c5ab99c8692af1c69746b13bdf61.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9eb5cb163f69c5ab99c8692af1c69746b13bdf61.png)

这里没有什么关键信息，只能发现一些配置路径和默认的Mysql账号密码，我们再去查看登录认证的方式是什么  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8a807b7871a211cf23653de2d9f3cbc6bf241fae.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8a807b7871a211cf23653de2d9f3cbc6bf241fae.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-29a0082586b5eb8d3ea7a3790d67ca77eda5d1ec.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-29a0082586b5eb8d3ea7a3790d67ca77eda5d1ec.png)

可以发现后台功能文件均使用 chksession来认证身份，那我们的目标就需要明确为不存在身份验证的文件  
利用命令删除所有包含身份验证的文件

```php
rm -rf $(grep -ril 'chksession()' ./)
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7f215a91ed067d0d6938ddba0af0b8db8b03d849.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7f215a91ed067d0d6938ddba0af0b8db8b03d849.png)

删除后文件大幅度减少，就减小了代码审计的时间，通过关键字搜寻命令执行的地方，发现一处完全没有过滤的命令拼接漏洞，username参数为用户可控的参数，并直接拼接到了命令执行部分，导致RCE  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f0e11de268316b4459ffceece81950134e34a548.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f0e11de268316b4459ffceece81950134e34a548.png)

传入POST请求

```php
POST /account/sy_addmount.php

username=|id
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a39136d429f06c8a21ba5fa69f6a8c322a3de2f0.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a39136d429f06c8a21ba5fa69f6a8c322a3de2f0.png)

成功再次拿下设备，同样的无验证命令拼接还有很多处，在后续也全部都提交给了厂商进行修复  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-38e19d544d3d8f29516bedf44522199512dc7959.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-38e19d544d3d8f29516bedf44522199512dc7959.png)