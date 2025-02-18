简介
==

Apache是世界使用排名第一的Web服务器软件。它可以运行在几乎所有广泛使用的计算机平台上，由于其跨平台和安全性被广泛使用，是最流行的Web服务器端软件之一。它快速、可靠并且可通过简单的API扩充，将Perl/Python等解释器编译到服务器中。

简单来说就是一个好用的，并且能支持基础的HTML、PHP、Perl、Python等语言。很牛逼！

调用过程可以概括为  
HTTP-&gt;Apahce-&gt;php5\_module-&gt;sapi-&gt;php

（原理介绍可以百度下，解释的挺好的）

特性
==

```php
支持最新的HTTP/1.1通信协议
配置文件简单，易操作，用户可以通过直接修改apache的配置文件信息来修改apache
支持实时监控服务器状态和定制服务器日志
支持基于IP和基于域名的虚拟主机
支持多种方式的HTTP认证
支持服务端包含指令（SSI）
支持安全Socket层（SSL）
支持用户会话过程的跟踪
支持FastCGI
通过第三方模块可以支持JavaServlets
支持多进程
```

apache的目录结构
===========

bin-------存放常用的命令工具，例如httpd  
cgi-bin---存放Linux下常用的命令，例如xxx.sh  
conf------Linux的配置相关文件，例如httpd.conf  
error-----错误记录  
htdocs----放网站源码  
icons-----网站图标  
logs------日志  
manual----手册  
modules---扩展模块

环境搭建
====

本次使用phpstudy进行复现

上传安装phpstudy文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e1a88a8e03dafd9cbdfa14ccd8acf373a640041a.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e1a88a8e03dafd9cbdfa14ccd8acf373a640041a.jpg)

选择是

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9c9de23e78c42773ce129b01480f507a78c8e510.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9c9de23e78c42773ce129b01480f507a78c8e510.jpg)

此时会报错

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3fec84060e1752b33714110080df7ff59871869d.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3fec84060e1752b33714110080df7ff59871869d.jpg)

上传vc9文库

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-134cf387050deec6bfc9a0fa0771626e33886c61.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-134cf387050deec6bfc9a0fa0771626e33886c61.jpg)

切换版本

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3989f10b35b22daadb22be887b83bd5b96a1f3a9.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3989f10b35b22daadb22be887b83bd5b96a1f3a9.jpg)

查看（看切换成功没有）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-edf62721a3fddbc03374e53f935fd4a4f4816ac9.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-edf62721a3fddbc03374e53f935fd4a4f4816ac9.jpg)

因为一部分原因，没有在windows下找到文件，后面会提到，如果有大佬知道，可以多多指点，所以更换系统比较多

一、解析漏洞（CVE-2017-15715）
======================

又叫未知扩展名漏洞
---------

影响范围：Apache 1.x、2.x
-------------------

漏洞介绍及成因
-------

Apache 文件解析漏洞与用户的配置有密切关系，严格来说属于用户配置问题。

Apache 文件解析漏洞涉及到一个解析文件的特性：

Apache 默认一个文件可以有多个以点分隔的后缀，当右边的后缀无法识别（不在 mime.tyoes 内），则继续向左识别，当我们请求这样一个文件：

shell.php.xxx.yyy

yyy -&gt;无法识别，向左

xxx -&gt;无法识别，向左

php -&gt;发现后缀是 php，可以解析，交给 php 处理这个文件

复现
--

为了更好理解apache解析文件的特性，使用下面图片来解释

在php文件里上传图片

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6cce87aed05dc371595d61d857986d4ff2413c01.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6cce87aed05dc371595d61d857986d4ff2413c01.jpg)

访问创建的图片

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0e15becaa049614e90cc0b3ab895d9e94717e220.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0e15becaa049614e90cc0b3ab895d9e94717e220.jpg)

成功访问

接下里改文件名后缀（后缀名随意）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0f034ee4126d2a5bb2f09d584ffc91f4f50c4223.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0f034ee4126d2a5bb2f09d584ffc91f4f50c4223.jpg)

再次访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4febe89bc67bbf806495c689a1616cb131cf41bc.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4febe89bc67bbf806495c689a1616cb131cf41bc.jpg)

依然是可以成功访问的，原理就是，

先去解析了.baixi格式，——无法解析

再去解析jpg格式——可以解析，就会以jpg形式解析文件

这就是apache解析文件的特性

既然可以正常解析，我们可以尝试利用它来绕过一些规则，会有不同效果

比如网站一般具有上传功能，通常会对用户上传的文件后缀进行校验，防止用户上传的内容危害网站安全。假设禁止用户上传php类型的文件，此时如果用户上传的文件为test.php.xxxxx，而程序猿如果不了解apache这一特性，编写的校验只检查后缀xxxxx，不认为这是程序文件，允许上传，则攻击者成功绕过了上传时的安全检查，上传了实际为php的文件。当程序解析时，apache则将该文件解析为php文件。

把phpinfo.php文件随便改个名字（或者你复制内容，再创建新的文本也可以）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cdb17b9a2f562a4eeebf4c792ffd38170bd7af4b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cdb17b9a2f562a4eeebf4c792ffd38170bd7af4b.jpg)

访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8ba9404680f889aed07e3e221137f4393510991b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8ba9404680f889aed07e3e221137f4393510991b.jpg)

正常调用php文件

给文件添加新的后缀名

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-172fe3d340b0826d0d34de720e2cbd401b7224d9.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-172fe3d340b0826d0d34de720e2cbd401b7224d9.jpg)

再次访问  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bf16d249403c6a1e517cde1572de687b01452cc0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bf16d249403c6a1e517cde1572de687b01452cc0.jpg)

为什么会出现会是文本内容，是因为对文件进行正则匹配；如果文件后缀以.php结尾，才会认为是php文件，再进行解析。但是依然可以绕过

使用module模式与php结合的所有版本，apache都存在未知名扩展名解析漏洞，

使用fastcgi模式与php结合的版本，不存在此漏洞

想要利用此漏洞必须要保证扩展名中，至少带一个php后缀名，否则会被当作txt/html文档处理

（只要php5.3以下和apache联动才会有module模式，会出现这种漏洞）

扩展
--

apache的文件名扩展名的定义写在conf/mime.types文件中，可以自己查看支持哪些格式的扩展名

既然了解了底层的原理，才能深入测试

（但在Windows环境下我找不到它的底层代码，只能去kali上面测试，有大佬知道，希望告知）

不然会出现抱错

kali深入复现
--------

kali是自带有apache的，可以在/etc目录下找到查看

```php
cd /etc/apache2
ls
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-059c07ee4fb91d5461efc47ad8be49b9ea5e6396.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-059c07ee4fb91d5461efc47ad8be49b9ea5e6396.jpg)

查看php版本

```php
php -v
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7eb9b7a00ffe418a274d047bf09c7f58fd2c15e5.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7eb9b7a00ffe418a274d047bf09c7f58fd2c15e5.jpg)

环境搭建
----

开启apache服务

```php
 /etc/init.d/apache2 start
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-62a13075958d4aff15322957b006bfb623546271.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-62a13075958d4aff15322957b006bfb623546271.jpg)

查看

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-757325a62e87214646182e6182a6916810071e54.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-757325a62e87214646182e6182a6916810071e54.jpg)

显示，apache开启成功

测试apache+php

在/var/www/html/目录下创建文件

```php
cd /var/www/html
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fb6fa0521c554b977df5269a8ceea00d4d660dc0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fb6fa0521c554b977df5269a8ceea00d4d660dc0.jpg)

并写入以下内容

```php
vi baxi.php
```

```php
<?php
      phpinfo();
?>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4ad08cb6850378153346ce4f05e82ddbb85bc73f.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4ad08cb6850378153346ce4f05e82ddbb85bc73f.jpg)

访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-145ceee4cb202036346c91a20b2ed60c17a6cb26.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-145ceee4cb202036346c91a20b2ed60c17a6cb26.jpg)

成功搭建

再创建一个多后缀的文件

```php
vi baxi.php.abc
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c137abe4c07373fd021b32e23efc5c6100489df4.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c137abe4c07373fd021b32e23efc5c6100489df4.jpg)

访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d49c3d0d040e932ff796fa6abfaecd6351ac9ef0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d49c3d0d040e932ff796fa6abfaecd6351ac9ef0.jpg)

分析apache解析漏洞
------------

只有明白原理，才能绕过

kali中apache配置文件在/etc/apache2/下。由于自己的php作为apache的mod方式运行，所以需要在mods—enabled目录下找到相关文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-484ed0feb96d924a2ba2fe3892c8a95ff0843189.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-484ed0feb96d924a2ba2fe3892c8a95ff0843189.jpg)

配置如下（有大佬知道Windows下该文件在哪，请指点下）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6f4c9b91f01e01245ac0926f33ce8856f93c3276.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6f4c9b91f01e01245ac0926f33ce8856f93c3276.jpg)

第一行就知道apache会有哪些后缀名文件当做php解析

以下都是被当作php文件解析

```php
phar
php
phtml 
```

造成解析漏洞的原因，就是因为底层的$,

字符意思可以去看菜鸟教程的解释

<https://www.runoob.com/regexp/regexp-syntax.html>

所以

把$换成 .

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b71317f650c12f59b2d2f27dc0af75d6e56b0eca.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b71317f650c12f59b2d2f27dc0af75d6e56b0eca.jpg)

重启服务

```php
systemctl restart apache2
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9399d4e36ff4160ed42c7cd15103ed9721b62f73.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9399d4e36ff4160ed42c7cd15103ed9721b62f73.jpg)

可以看出，PHP.abc文件已经被当作php程序执行

总结利用条件

使用module模式  
文件名至少带一个php

二、addhandler导致的解析漏洞
===================

漏洞简介
----

这个漏洞是由于不安全的配置导致的，部分运维人员在配置服务器时，为了使apache能解析php，自己添加了一个handler。在apache配置文件中，增加了AddHandler application/x-httpd-php .php配置。这个配置的意思是：只要文件名中包含.php后缀，就会把该文件当作php文件来执行。

复现
--

先把底层的$,恢复下

创建一个如下的文件

```php
vi baxi.php.jpg 
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9e626b6641eb8cd72bb3900b9da9d2548342b9fb.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9e626b6641eb8cd72bb3900b9da9d2548342b9fb.jpg)

访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d28475705d3d67cf9986732ae8e17533aa67c208.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d28475705d3d67cf9986732ae8e17533aa67c208.jpg)

访问错误，无法解析php文件

来到该文件下，随意创建一个文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9baab4038702f0e4de45625553d3f59891522241.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9baab4038702f0e4de45625553d3f59891522241.jpg)

配置文件

下面这句的意思是，只要文件中有。php不管后缀名都解析为php文件，跟位置无关

```php
 AddHandler application/x-httpd-php .php
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-67a0173e39b5b43acf94dcf24009ef98e5494318.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-67a0173e39b5b43acf94dcf24009ef98e5494318.jpg)

重启服务

```php
ystemctl restart apache2
```

访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f261ccc2d8fa41c3f2e3d507f9d7a6fd17a8ca0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f261ccc2d8fa41c3f2e3d507f9d7a6fd17a8ca0.jpg)

访问正常

注意：发现文件名中仅包含php不行，必须是`.php

三、罕见后缀总结
========

在mime。types文件中查看支持那些类型

```php
cat /etc/mime.types | grep php
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5decd79652d960dc743fe60dcf79e488b9bad2fe.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5decd79652d960dc743fe60dcf79e488b9bad2fe.jpg)

可以知道支持php3、php4、php5、pht和html

在php7.4conf中

演示：

把之前那个文件改命或者新建一个都行

```php
mv baxi.php.abc baxi.phtml
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5700d974bc0ec8ffbbcfd6d02242f03bd2222e2b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5700d974bc0ec8ffbbcfd6d02242f03bd2222e2b.jpg)

成功访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-441594d551e3be2dbd016eefc3cfd7ca77950afc.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-441594d551e3be2dbd016eefc3cfd7ca77950afc.jpg)

配置问题导致总结

1.如果在apache的/etc/apache2/apache2.conf有下面的配置

```php
<FilesMatch "baixi.jpg">
SetHandler application/x-httpd-php
</FilesMatch>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1cd6e74e5d40cd3742c0c3c15220ebeed55c6150.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1cd6e74e5d40cd3742c0c3c15220ebeed55c6150.jpg)

只要文件名是baixi，jpg都会以php格式执行

重启

```php
systemctl restart apache2  
```

访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-544b4e7142bf03c225894f90d00f84fc3958f5f9.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-544b4e7142bf03c225894f90d00f84fc3958f5f9.jpg)

2）如果在Apache的conf里有这样一行配置AddHandler php5-script .php 这时只要文件名里包含.php  
即使文件名是dayu.php.jpg也会以php来执行！

3）如果在Apache的conf里有这样一行配置AddType application/x-httpd-php .jpg，即使扩展名是.jpg，也会以php来执行！

四、目录遍历
======

当 Web 服务器配置不当的时候，如果当前目录不存在默认文件（比如 index.html），Apache 会列出当前目录下所有文件，造成敏感信息泄露

（这个没有啥可复现的，主要是信息泄露）

可以在谷歌中通过 intitle ：index of来寻找目录遍历漏洞

五、Apache HTTPD 换行解析漏洞（CVE-2017-15715）
=====================================

简介
--

影响版本 ：Apache 2.4.0~2.4.29
-------------------------

影响说明 ：绕过服务器策略，上传webshell
------------------------

正则匹配，以.php后缀结尾的才认为是php文件。这个漏洞出现的原因就是.php$中的$，主要是因为$匹配输入字符串的结尾位置。$还会匹配到字符串结尾的换行符，所以\*.php%0A也会被认为是以.php结尾。同时，如果上传过程中加入0A，则可以绕过部分黑名单文件上传后缀的限制

复现
--

kali上的apache版本不对，所以使用乌班图来演示

安装环境我跳过了，大家可以去找下靶机里有没有（安装比较费时间）

开启后，默认端口是8080

访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5eaaf2a88df72d7a9fe92c2cae8d3131b553a64b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5eaaf2a88df72d7a9fe92c2cae8d3131b553a64b.jpg)

尝试直接上传php文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-952c22f172f18142cd0b68778edf9f17666c391e.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-952c22f172f18142cd0b68778edf9f17666c391e.jpg)

显示失败，是因为对文件后缀名进行了过滤，使用了黑名单的方式

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-738b33db17d96eaa52e94702f3f128c4f93567e3.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-738b33db17d96eaa52e94702f3f128c4f93567e3.jpg)

使用bp抓包分析

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-49f86c714f717d13de6d3e51658260209c06533e.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-49f86c714f717d13de6d3e51658260209c06533e.jpg)

修改（注意1.php。后边还有一个点，很重要）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1291fe6343c80059a5465c23acb95fdac158a36e.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1291fe6343c80059a5465c23acb95fdac158a36e.jpg)

来到重发器的hex

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f42559cc2a9d82bee8dc66310f68a9b89ff13a9a.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f42559cc2a9d82bee8dc66310f68a9b89ff13a9a.jpg)

点的hex是2e，将2e改为0a就行

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-54ef1c574e4b33bacaa9ef93424432a867115145.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-54ef1c574e4b33bacaa9ef93424432a867115145.jpg)

发送

成功上传

访问（注意后边要有%0a）

[http://192.168.253.2:8080/1.php%0a](http://192.168.253.2:8080/1.php%0A)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9be4a1b793fcc8376de3d5cb812363e104872b7f.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9be4a1b793fcc8376de3d5cb812363e104872b7f.jpg)

成功解析

注意：同样的操作步骤在Windows环境中无法复现成功，因为windows操作系统不允许后缀以换行符结尾的文件命名方式（在其他博客上看到的）

六、Apache SSI远程命令执行漏洞
====================

简介
--

在测试任意文件上传漏洞的时候，目标服务端可能不允许上传php后缀的文件。如果目标服务器开启了SSI与CGI支持，我们可以上传一个shtml文件，并利用语法执行任意命令

影响版本——Apache 全版本（支持SS与cG）
-------------------------

漏洞危害——绕过服务器策略，上传webshell
------------------------

原理
--

ssi：是放置在HTML页面中的指令，它可以将动态生成的内容添加到现有的HTML页面，而不必通过CGI程序或其他动态技术来提供整个页面。以上是定义采用在 Apache官网对SSI的定义

简单来讲，就是ssi可以在HTML中加入特定的指令，也可以引入其他的页面。开启ssi需要单独配置 Apache，可以参考ssi配置

复现一
---

开启后，访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3d96d57b8332c4a126e8cd268eca7e0d4e65330f.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3d96d57b8332c4a126e8cd268eca7e0d4e65330f.jpg)

创建一个文件里面写入

```php


<!--#exec cmd="whoami" -->

```

上传

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a1d4d3e249ee9453a57c03b3411df275fb38f8fe.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a1d4d3e249ee9453a57c03b3411df275fb38f8fe.jpg)

显示上传成功

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-52e6cf64c8990e4567ee049eb12b7b8cb6aebffe.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-52e6cf64c8990e4567ee049eb12b7b8cb6aebffe.jpg)

访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a94354ca1b97d50466b9609ba4a30ae940869dfa.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a94354ca1b97d50466b9609ba4a30ae940869dfa.jpg)

复现二
---

（以下是我看到其他博客发现另一种比较好的方法）

这个文件内容啥都行

上传的时候利用bp抓包将内容发送到中继器

修改

```php

<!--#exec cmd="ls" -->

```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3a539bd9a5b27b3f8f29c0025c1a45ea19961946.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3a539bd9a5b27b3f8f29c0025c1a45ea19961946.jpg)

上传成功

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d60345af6d8ead1ad18bf63a923bc09fc6f92fa5.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d60345af6d8ead1ad18bf63a923bc09fc6f92fa5.jpg)