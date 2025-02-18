Apache
======

Apache的简介
---------

Apache是世界使用排名第一的Web服务器软件。它可以运行在几乎所有广泛使用的计算机平台上，由于其跨平台和安全性被广泛使用，是最流行的Web服务器端软件之一。它快速、可靠并且可通过简单的API扩充，将 Perl/Python等解释器编译到服务器中

这边我用phpstudy进行安装

Apache的原理
---------

一次完整的WEB请求流程

![1619658355135](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-59dd84fc3949ab7227f5ede2f2913633acab0652.png)

从request开始，到response结束

是一次Apache和PHP配合的一次WEB请求，Apache在前，PHP在后

Apache本身是不支持PHP解析的，是通过SAPI进行通信，那 Apache如何和SAP通信呢？Apache怎么知道什么类型的文件要解析为PHP？

```php
#加载php5_module模块
LoadModule php5_module php5apache2_2.dll的路径

#添加可以执行php的文件类型，让.php文件类型解析为PHP 
AddType application/x-httpd-php.php

#或者将 AddType变为下面的(在 Apache2.4.0~2.4.29中默认使用了该方式)
&lt;FiLesMatch \.php$&gt;
    SetHandler application/x-httpd-php
&lt;/FiLesMatch&gt;
以及
&lt;IfModule dir_module
DirectoryIndex index.html index.html index.php index.phtml
&lt;/IfModule&gt;
```

Apache通过 LoadModule来加载php5\_module模块( php5apache2\_2.dll)

这样做的目的是让Apache加载php5\_module模块来解析PHP文件。

意思其实就是用 LoadModule来加载php5\_module。也就是把php作为 Apache的一个子模块来运行。当通过Web访问php文件时，Apache就会调用php5\_module来解析php代码

调用过程概况

```php
HTTP-&gt;Apahce-&gt;php5_module-&gt;sapi-&gt;php
```

Apache的目录结构
-----------

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3a4cefe34f3edf78f6779610628bee4adf2189e9.png)

```php
bin------------存放常用的命令工具，例如httpd 
cgi-bin--------存放 Linux下常用的命令，例如xxx.sh 
conf-----------Linux的配置相关文件，例如httpd．．conf 
error----------错误记录
htdocs---------放网站源码
icons----------网站图标
logs-----------日志
manual---------手册
modules--------扩展模块
```

Apche对文件名扩展名的定义
---------------

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-324f6099acca68958e62514b16d0142b652acd6c.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-384a9d4131141dac5a1566bbb2b0fa799c9999e2.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-acfba6dea81f7e2bbe2dbaf6ceae338be8130cc4.png)

它是不可以解析php的！！！

Apache的解析漏洞(CVE-2017-15715)
---------------------------

搞一张图片 搞一个未知的扩展名

![1619672095365](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dea5d8a8b721ef56407288f303d1c057f847b445.png)

然后我们访问一下

![1619672108239](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-948befe1a8b0776de65e7c98163e4cfb1646d8ae.png)

![1619672124599](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2b91f48defafeeb435fc2ce886da57e55e424e3a.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5dbe20500805bcb291c312aeaf258cd9d0a5a4c5.watermark%2Ctype_zmfuz3pozw5nagvpdgk%2Cshadow_10%2Ctext_ahr0chm6ly9ibg9nlmnzzg4ubmv0l3dvndfnzq%3D%3D%2Csize_16%2Ccolor_ffffff%2Ct_70)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eaffd9cebe9ebfce1459eaf81eb832d5723b5e48.watermark%2Ctype_zmfuz3pozw5nagvpdgk%2Cshadow_10%2Ctext_ahr0chm6ly9ibg9nlmnzzg4ubmv0l3dvndfnzq%3D%3D%2Csize_16%2Ccolor_ffffff%2Ct_70)

这里它不是apache解析的php文件

是php解析的

继续提升版本

![1619672990629](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3ce0273c389aac8533bb3bbe858b3c9a38a6e7da.png)

要安装一个这个vc11-86

![1619672532589](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fa5dd5be86283d5d207e2e0a6b89096b7bad8b2e.png)

php常见运行方式有 apache的模块模式(分为mod\_php和mod\_cgi)cgi模式fast-cgi模式

```php
1.使用 module模式与php结合的所有版本 apache存在未知扩展名解析漏洞
2.使用 fastcgi模式与php结合的所有版本 apache不存在此漏洞。
3.并且，想利用此漏洞必须保证文件扩展名中至少带有一个`.php`，否则将默认被作为`txt/html`文档处理
```

然后访问一下 可以看到是fast-cgi模式

![1619672975811](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0373c905e6028787f9e24ecb06061c9686d04d5c.png)

我们访问`phpinfo.php.xxx` 会报500的错误

![1619673074233](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4888da7f230bbe8d2c234a98b198fa023c9434e3.png)

### kali操作

kali是自带apache的

![1619673403380](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ad394b922631ffaba41f269fd92b7b0735a2be4a.png)

进行配置一下就可以了

开启apache服务

```php
/etc/init.d/apache2 start
```

访问一下 成功开启

![1619673442975](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9c33f3432bcb9834cc4ab015c2dfb8dd248bc9d4.png)

php的版本

![1619673481010](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d2cb1b9ed3ed87ce97e3784ab40dc86f17b925e6.png)

kali下apache默认的网站根目录：

```php
/var/www/html
```

写一个phpinfo的2.php文件

![1619673943395](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d353791c5dbd03c23797579a7a318107d0454025.png)

访问一下

![1619673974508](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a236688f38fc699f018578d29bc02e92ec8ff29f.png)

### 深入解析一下

去这个目录下

```php
/etc/apache2/mods-enabled
```

![1619674158602](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ed2a8acb8979a4d81fefd9320998d952515dc7c.png)

我们打开分析一下

![1619674267163](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-490a784041de68a8c3e8a8fc7b84e91bf38b83b0.png)

```php
&lt;FilesMatch &quot;.+\.ph(ar|p|tml)$&quot;&gt;
```

以 `phar`，`php`， `phtml` 结尾的文件会被 apache当做php解析

apache解析漏洞的根本原因就是这个`$`

![1619674389982](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d00bd640bffb1d2262ab138a7657d9f174fc8411.png)

当我们把`$` 换成`\.`时

![1619674469735](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-788e72cb9341707ecb4af85cbae90ce7f4dae06b.png)

搞一个2.php.xxx

![1619674542411](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3bfbb500c922c2699e9885609d019b269875b539.png)

重启一下apache服务

```php
service apache2 restart
```

访问一下 成功解析了

![1619674629300](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ab912596a1a47bf9301702ffc6eb71e27cdf3f5.png)

### 总结利用条件

```php
1.使用 module模式，且正则符合条件2.文件扩展名中至少带有一个.php
```

Apache HTTPD换行解析漏洞
------------------

### 漏洞原理

上传一个后缀末尾包含换行符的文件，来绕过 FilesMatch。

绕过 FilesMatch不一定能被PHP解析这个漏洞可以用来绕过文件上传黑名单限制

举例：

```php
a001.php\x0a--&gt;a001.php
```

该漏洞属于用户配置不当

### 影响版本

apache ：2.4.0~2.4.29版本

### 漏洞复现

Kail的Apache的版本不符合

我这边上Ubuntu进行复现

![1619159698311](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a92323157567fa018f2e3baf748b64b3aa6e1292.png)

Ubuntu安装docker命令

```php
 sudo apt-get update  sudo apt install curl  curl -s https://get.docker.com/ | sh    sudo apt install python   curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py  sudo python get-pip.py  pip install docker-compose   sudo apt install docker-compose  docker-compose -v  docker -v  sudo service docker start 启动docker
```

![1619160628787](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b13c0633502a06f9a89f5c38a819501bf59629af.png)

安装完成 那么 开始安装vulhub

```php
sudo apt install gitgit clone https://github.com/vulhub/vulhub.git
```

开启环境

```php
cd vulhub/httpd/CVE-2017-15715/ sudo docker-compose build sudo docker-compose up -d docker ps 
```

访问

```php
http://192.168.175.179:8080/
```

![1619161996927](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5c3e7c93017cdd30ce4c65ffec2917bea82817a2.png)

部署成功了

开始上传

直接上传phpinfo.php 是失败的

![1619162125671](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c9f64a130fead197d3d0f66d8ba0a4b4486404fd.png)

![1619162134440](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dbd67059f97a98c21fbd2a74b6906a88c068a605.png)

抓包进行修改

![1619162223821](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e63c9448cb0d6f19a85365fc4fcc61de74eb21c.png)

![1619162269859](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2c854c5896a6c7f00cd4b26205c2aeaa59d52b88.png)

加入一个点

![1619162289190](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7a0ca4f30fcd9a4a5403be367fb9224610065a92.png)

修改后发送到重放器

去看看Hex

![1619162863417](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5c11185ee02627488088481ab458e272d3930905.png)

![1619163076557](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b974e9da5d8ca41849d99dc1254bfe2a0e0cbea8.png)

`.`的Hex--&gt;2e

![1619163098345](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2be416a39b9f39e57a9945f900746f08edd80ea3.png)

改成0a 成功上传

然后我们进行访问

```php
http://192.168.175.179:8080/phpinfo.php%0a
```

![1619163257210](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2063aee0eb5d9af9d33d6d4c616b8ad8b0af1da7.png)

成功上传并解析

分析原因

![1619163418256](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d741bed1171081f6e368844bdf63d8a031c693f2.png)

后台是通过黑名单方式过滤了php后缀的文件，根据最开始的知识，什么样的文件算是php文件呢？在有定义，这句话的意思是以php结尾的文件都算php文件，在正则中表示匹配输入字符串的结尾位置。如果设置了 RegExp对象的 Multiline属性，则也匹配`\n`或`\r`  
恰好，我们在文件末尾加了0x0a（n），所以被匹配成功了。

### 0x0a和0x0d

```php
1.0x0d \r CR这三者代表是回车，是同一个东西，回车的作用只是移动光标至该行的起始位置2.0x0a \n CL这三者代表换行，是同一个东西，换行至下一行行首起始位置；
```

### 修复建议

1.升级到最新版本  
2.或将上传的文件重命名为为`时间戳+随机数+.jpg`的格式并禁用上传文件目录执行脚本权限

4、Apache SsI远程命令执行漏洞
--------------------

### 影响版本

Apache全版本（支持SS与cG）

### 漏洞危害

绕过服务器策略，上传 webshell

### 漏洞原理

ssi：是放置在HTML页面中的指令，它可以将动态生成的内容添加到现有的HTML页面，而不必通过CGI程序或其他动态技术来提供整个页面。以上是定义采用在 Apache官网对SS的定义

简单来讲，就是ssi可以在HTML中加入特定的指令，也可以引入其他的页面。

开启ssi需要单独配置 Apache，可以参考ssi配置

```php
https://httpd.apache.org/docs/2.4/howto/ssi.html
```

总结呢，就是：ssi.html也可以执行命令

创建a001.shtml 写入如下命令 进行上传

### 包含ssi指令的文件

```php
&lt;pre&gt;&lt;!--#exec cmd=&quot;whoami&quot; --&gt;&lt;/pre&gt;
```

### 漏洞复现

同样是用vulhub进行启动

```php
sudo docker-compose up -d
```

访问一下

![1619164572259](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ed898d0fb03f7845d14f5c90e8599cd7150fbf1d.png)

写入ssi指令的文件

```php
&lt;pre&gt;&lt;!--#exec cmd=&quot;whoami&quot; --&gt;&lt;/pre&gt;
```

文件名保存为`a001.shtml`，这个后缀取决于 Apache的配置，默认是此后缀

![1619164582678](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4c61207e1d2cd151f657545a6508f51fd878650f.png)

访问一下

![1619164655934](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5ce2b840871d0904eed81cc4c5b4d86012a96f97.png)

这里的思路 比如上传webshell 或者拿反弹shell都是可以的

文章转载于：<https://www.freebuf.com/articles/web/271745.html>