基本信息收集
======

打开入口后是一个`phpinfo`页面, 进行一波信息收集. `Windows 10 X64` 系统 2017 年 创建的站点。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8984eb390388f8f5001fd0453cc8f9a206060ddd.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8984eb390388f8f5001fd0453cc8f9a206060ddd.png)

对其进行了目录爆破. 爆破得到了 `carts` 目录。再次对此目录进行一次目录爆破. 经过长时间的数据爆破. 没有什么可利用的信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cf63f0e61c15229522e1178e043952d7c6f70e29.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cf63f0e61c15229522e1178e043952d7c6f70e29.png)

爆破结果中的`master`. 打开连接后下载了一个文件. 是`SQL Server Dumper`的数据库文件. 数据库版本 2.0.0 数据库是 master. 又是很长一段时间的翻阅. 没有发现可以利用的东西.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-953524d77ca5b7bd6c680c6a23e3c990dd7a6bb0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-953524d77ca5b7bd6c680c6a23e3c990dd7a6bb0.png)

进入下一个目录`librarys`. 经过爆破后发现一个有趣的`tree.txt`, 把文件目录给列出来了. 同时这个 `librarys` 项目存在目录遍历漏洞.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0e9f0be03896114e84c3c5e956ac3fab0364f9a7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0e9f0be03896114e84c3c5e956ac3fab0364f9a7.png)

根目录下有个 `server.php` 是入口文件, 但静态文件悉数丢失.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2e20ca3bd7dcc48f2e3f0e49e3de047013ba908d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2e20ca3bd7dcc48f2e3f0e49e3de047013ba908d.png)

SQL注入漏洞
=======

又是一次长时间的翻阅文件. 一无所获. 所以我在 `carts` 下手. 随便点开一个目录之后. 参数`CATID`引起了我的注意, 用`布尔注入`简单的测试确认了其存在SQL注入  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9ba8936cda5ba45268a28536adf70e22f2c8f603.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9ba8936cda5ba45268a28536adf70e22f2c8f603.png)  
确认了一下当前用户, `root` ! 数据库最高权限  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5846099e0bbcf69412c64eb32cee4f75926f837d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5846099e0bbcf69412c64eb32cee4f75926f837d.png)

试着通过当前注入点写入文件通过`phpinfo`知道站点根目录在: `E:/wamp64/www/`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c46a3c1d4d3f340b0227d2806fd08cd7ab57d5dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c46a3c1d4d3f340b0227d2806fd08cd7ab57d5dc.png)

写入失败  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0ce5841acf78f5b910780c9dc6ac740e059f7542.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0ce5841acf78f5b910780c9dc6ac740e059f7542.png)

口令爆破
====

上`sqlmap`. 收集一下用户信息用来登录 `librarys` 项目， 得到一个用户表, `password`是加盐的.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b3ed8fee767cae9af4e851c8e0d2842629ca73bb.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b3ed8fee767cae9af4e851c8e0d2842629ca73bb.png)

经过很长时间的爆破, 爆破出了一个账号！当我以为可以登录的时候  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3ed7249aa2e678a1ab1e6049a29baea36c8714ba.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3ed7249aa2e678a1ab1e6049a29baea36c8714ba.png)

挂羊头卖狗肉的`label username or Email`。登录后却提示邮件(用户名)字段必须是邮件地址....  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0230c5775d702869ed1555f923c70d8c5a99fd02.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0230c5775d702869ed1555f923c70d8c5a99fd02.png)

为了更好的找到相应用户的数据表. 我注册了一个用户, 又是长时间的翻翻找找. 终于找到了相应记录  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8ac814ada79fafb9f03832a761d3a2f2fcbab7a7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8ac814ada79fafb9f03832a761d3a2f2fcbab7a7.png)

再次使用`john`爆破`admin@admin.com`的密码, 爆破成功，密码`admin`（如果我试一下弱密码就不用这么麻烦了, 测试弱密码真的很重要）.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6ff0d326402a80e65828d15a7ad35de4f73232e0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6ff0d326402a80e65828d15a7ad35de4f73232e0.png)

成功登录后台
======

成功登录！舒服的找文件上传点  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e2d18cc8bec7d0263f6000a506d04e7d8a321d93.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e2d18cc8bec7d0263f6000a506d04e7d8a321d93.png)

但是用了一会发现, 虽然登录成功了, 但`cookie`只能用一下. 过期时间是两三个小时前....  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-199d250bbd4b57832cfdbbf78cc91f4936956168.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-199d250bbd4b57832cfdbbf78cc91f4936956168.png)

拼手速!! 在用户个人信息编辑页面中找到了 文件上传点。尝试上传了一张图片  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9669927b7776dbbe91e5d52784151e966b6a3984.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9669927b7776dbbe91e5d52784151e966b6a3984.png)

上传一句话木马
=======

`.php`一句话木马 上传成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b266c276a9861b3794269eda56bce2b04e707597.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b266c276a9861b3794269eda56bce2b04e707597.png)

删掉多余的 `server.php`, 直接从`uploads`访问. `whoami -> system` 权限. 提权的时间都省了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6bc69b93f9a0d5f93cf247e12d4b54365f69156f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6bc69b93f9a0d5f93cf247e12d4b54365f69156f.png)

上线蚁剑
====

上线蚁剑后, 转移webshell的位置.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2ec7c84d3caa0c883ae35d47c94f9eac733a193f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2ec7c84d3caa0c883ae35d47c94f9eac733a193f.png)

内网信息收集
======

内网这块我非常烂，看看就行  
`ipconfig` 一看居然是外部网卡, netstat -ano 查看端口情况3389远程桌面服务没有开启  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-105da83bb60078ef8b438cb1fbcb74ec09224c6c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-105da83bb60078ef8b438cb1fbcb74ec09224c6c.png)

`tasklist` 检查线程. 对方有小红伞.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-732f8a4d07edd2ab8526a8af715be6aa9603f983.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-732f8a4d07edd2ab8526a8af715be6aa9603f983.png)

为了模拟一下环境. 我装了个免费版的. 尝试了添加用户. 没有拦截. 本地尝试利用`REG ADD`修改注册表开启远程桌面也没有拦截.

所以直接开启远程桌面

```shell
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-11a3940f6ea83778ac17e3751f06a6b34751a30a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-11a3940f6ea83778ac17e3751f06a6b34751a30a.png)

加了个用户名类似的用户, 把用户加到`administrators`组中.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9692b1748830c5e86113acda1d76706520f03a3b.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9692b1748830c5e86113acda1d76706520f03a3b.png)  
成功连接远程桌面.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-100401283424607bdafc150686d8ac28f08a0380.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-100401283424607bdafc150686d8ac28f08a0380.png)

`arp -a` 后只有主机一台机器  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5b05eb47d58b4e2b1f664c382eb90a1c4e092b53.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5b05eb47d58b4e2b1f664c382eb90a1c4e092b53.png)

该主机也没有在域中. 渗透结束

扩展训练
====

在项目的配置文件中找不到数据库root用户名密码时, 在`mysql`静态文件中会存放`root`密码的`hash`. 以`wampserver`为例子路径就是: `/bin/mysql/mysql-x.x.x/data/mysql`, 这个`user.MYD`就是密码`hash`的文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-02655042d6e6bc30a3fc6dbe5ef945470ea96917.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-02655042d6e6bc30a3fc6dbe5ef945470ea96917.png)

用`winhex`打开, 百度一下就有了 Mysql 密文是40位,  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d12ea49f559426db011bae97721118899901dd7a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d12ea49f559426db011bae97721118899901dd7a.png)

不足40位的就拼接密文  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f2ac523816f8009b81b118294a75022aa37267fa.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f2ac523816f8009b81b118294a75022aa37267fa.png)  
找到一条付费记录, 由于家境贫寒就不买了.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bca26c4841842c58fbb64420edf1c38fe55cb619.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bca26c4841842c58fbb64420edf1c38fe55cb619.png)