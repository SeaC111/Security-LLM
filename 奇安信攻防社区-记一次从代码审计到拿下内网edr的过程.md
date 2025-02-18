0x01、前言
-------

在某次授权红队行动中，客户给定目标外网资产很少，

经过各种挖掘，各种尝试，久久没有结果，注意到某系统为**通用系统**。

![image.png](https://shs3.b.qianxin.com/butian_public/f32051736fe82948325e48a9fc655a8b7.jpg)

于是开始了下面的故事。

0x02、寻找源码到getshell
------------------

### 查找源码

1、**网盘泄露**：这套系统并不开源，各种网盘泄露网站一顿查找，无果

2、**Github、gitlab泄露**：尝试了多个关键词，均无果

3、**Fofa找同类型的站**：用favicon.ico，或是用title来搜，并且将这些资产采集起来，最终在某个站发现`web.rar`，成功获得源码

### 代码审计

查看代码目录结构如下

![image.png](https://shs3.b.qianxin.com/butian_public/ff813ae306c737749d32b7b7157089b2a.jpg)

首先看web.xml，注意到这个过滤器`filter.PurFilter`

![](https://shs3.b.qianxin.com/butian_public/f7cd6338d8f609606d11bbf8152477586.jpg)

跟进去看下

![](https://shs3.b.qianxin.com/butian_public/f977756eabe08ffc2d156118430d52f8d.jpg)

此处定义几个数组  
![image.png](https://shs3.b.qianxin.com/butian_public/f44085de63c2406e666b8aea66fb9a14d.jpg)

使用getRequestURI()获取url，查找url中最后一个点的位置，然后获取后缀转小写

![image.png](https://shs3.b.qianxin.com/butian_public/f0d5b9c6e93c6c436c8d52a2ded3187b3.jpg)

这个过滤器实际上是一个权限校验的工作，如果用户没登录的话是只能访问数组里的路径，或者后缀数组的特定后缀的文件。但是此处使用  
getRequestURI()获取url，我们注意到

![image.png](https://shs3.b.qianxin.com/butian_public/fc0163da281c3d9e4e4f1332d351580b5.jpg)

只要我们的`strSuffix为`后缀数组中的就能过了这个验证。

我们首先了解一下**`getRequestURI()`**这个方法  
当我们请求`/test/1.jsp;aaa`时`getRequestURI()`取到的结果也是`/test/1.jsp;aaa`  
那么此时想到构造请求**`/test/1.jsp;1.jpg`**就能绕过这个权限校验

绕过权限校验以后开始寻找可getshell的漏洞点，直接全局搜索multipart，寻找上传功能

![image.png](https://shs3.b.qianxin.com/butian_public/f8db7b7e77d1bddb149603c5eaf440b58.jpg)

看到第二个的时候成功发现一处任意文件上传

### 获得权限

按照代码分析，直接构造包上传shell，成功getshell

![image.png](https://shs3.b.qianxin.com/butian_public/f02e47479409800b4da9f62095989e850.jpg)

0x03、拿下内网edr
------------

### 获取edr系统权限

通过shell执行tasklist发现此机器装了某edr

扫描c段443端口发现https://172.x.x.x为某edr web管理界面

用frp开个代理

用已经公开的漏洞测了一遍发现，存在一处命令执行漏洞没修

利用公开的脚本直接弹了一个shell回来

![](https://shs3.b.qianxin.com/butian_public/f1b7059d33c6d299c5d38f2456a7c1ac7.jpg)

此次的目的不是获取这个edr的服务器权限，而是可以进到web管理界面可以做到给终端下发后门。所以目标为的登录web管理界面

首先的想法是找数据库账号密码然后登录进后台。

之前也没搞过，先看下进程  
![image.png](https://shs3.b.qianxin.com/butian_public/f89623eb93f2e4628d724c1bbd39b6a34.jpg)  
好像是mongodb，使用以下命令查数据库密码

```powershell
find /ac -type f -name "*.php" | xargs grep "password"
```

太多了发现密码名字好像叫mongodb\_password，再次查找.

```powershell
find /ac -type f -name "*.php" | xargs grep "mongodb_password"
```

![image.png](https://shs3.b.qianxin.com/butian_public/f0b5bd34a72cb6494d2aab5481ee41ab1.jpg)

查的过程中感觉就算找到数据库连上了密码也很难解密

于是想到之前的未授权任意用户登录，漏洞文件在`/ui/login.php`

![image.png](https://shs3.b.qianxin.com/butian_public/ff84ebea832ad9f99ee78935549ddea93.jpg)

于是先备份文件，然后将此处的if改为`if(1==1)`

![image.png](https://shs3.b.qianxin.com/butian_public/f264a0ad7471daf2c645c268b7f1aba18.jpg)

使用`/ui/login.php?user=admin`登录成功

![image.png](https://shs3.b.qianxin.com/butian_public/fadc5b22c7f298e4e389fc0e33dd796de.jpg)

然后就可以加白名单批量下发马执行上线了。

0x04技术总计
--------

1、想办法获取外网系统源码

2、代码审计获取外网shell

3、历史漏洞获取edr系统权限

4、修改文件进而任意登录到web管理端