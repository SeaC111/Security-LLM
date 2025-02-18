0x00 前言
=======

起因：单位给了一个客户端系统的项目还给了账号，让我帮忙看看。

![image-20220907173254723.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-51199a623f651c115fb0d80b442ae870995c8734.png)

结果：客户端-&gt;Web-&gt;内网-&gt;域控-&gt;办公网。  
注：由于目标单位所用的web系统以及服务器都是比较老的机子，所以可能没有很高的技术含量，不足之处还望批评指正。

0x01 餐前小菜
=========

(1)DLL劫持
--------

由于是客户端的渗透，正好之前一直想研究一下DLL劫持，于是尝试了一下。

(2)分析启动时调用的dll
--------------

首先利用**火绒剑**监控分析一下客户端启动时调用的dll。

![image-20220907173659440.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6de668ca4cd07f13692fe2a9eeec97bdff7aa514.png)

这里可以**动作过滤**一下，更快找到dll。

![image-20220907173841663.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-076b96b7f5ffde81bfbfd89c704850bc767b3137.png)

可以看到启动时调用了很多dll，我们选一个wldp.dll看看是不是存在dll劫持。

![image-20220907174243549.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-704dbb2c931f399331e8e0450558448096b89f84.png)

(3)验证是否存在本地调用dll的可能
-------------------

我们验证是否存在dll劫持的方式就是找到wldp.dll，拷贝一份放到该客户端启动的文件夹下，在监控一下系统的启动，是不是直接读了客户端启动文件夹下的wldp.dll。

![image-20220907174718885.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8352944ad2569736c4647bed932aa05200595787.png)

可以看到调用的是启动文件夹下的wldp.dll。  
那么我们就可以在启动文件夹下方一个恶意的wldp.dll文件，在客户端启动时进行无意识的恶意操作。

(4)生成恶意dll
----------

利用github上的工具：  
[strivexjun/AheadLib-x86-x64: hijack dll Source Code Generator. support x86/x64 (github.com)](https://github.com/strivexjun/AheadLib-x86-x64)  
将dll转换成cpp  
再编辑ThreadProc函数执行我们想要实现的恶意操作（我这里弹个窗）

![image-20220908222231441.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1d40879c1ea8b9bc31a92b2859f6a58d26e98d8a.png)

之后再重新将cpp编译成dll放入客户端启动文件夹。  
成功。

![image-20220908224906687.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a25b450bb15eaa5b0d99fa25bb94475a7c567a0d.png)

0x02 回归正题
=========

(1)配置文件泄露
---------

上面的DLL劫持只是蛮研究一下，现在回归文章正题。  
首先先看看这个XX信息管理系统文件夹中有什么配置文件  
注意到**config.ini**文件

![image-20220913084108120.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e64487d5cc09512770d16c2ad78af7be5526ddba.png)

文件内容中出现userName及加密过的userpwd，userpwd无法直接解密，只能先记下来，看看后面能不能用到。  
再往下翻，注意到一个**log4net.config**文件  
文件中泄露了远程数据库连接的信息，远程数据库IP、端口、用户名、密码。

![image-20220908232101743.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1cb1cb0cecb7e026dd4791350c2f9eae3ce4c048.png)

看到用户名，目测不是dba权限，先连接一下看看。

![image-20220908232444915.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a20a33e99a2c3d021c99c5ce608621e30ecf9e91.png)

可以看到真不是dba权限。。  
MSSQL不是dba权限，不会打。。先放着翻下数据库。  
翻了下数据库，数据库中存放着是登录此客户端的用户信息，包括用户名、md5加密过后的密码啥的。猜测客户端登陆时是与此数据库进行验证的。

![image-20220908233131268.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f8922d76e938507772d5d0e006599365e53adcdf.png)

(2)C/S架构渗透
----------

接下来开始对客户端渗透  
对于C/S架构而言，客户端不仅仅是https协议，还可能存在tcp、udp协议。  
C/S架构渗透测试我们需要准备的工具如下：

> **burp**  
> **proxifier**  
> **wireshark或者火绒剑（强烈推荐这个）**

proxifier是用来做代理抓客户端的https包  
wireshark或者火绒剑是用来抓tcp或者udp的包  
我这里用proxifier代理进行了抓包，登录包括登陆后的功能都没有抓到任何https请求包，所以这部分我就略过了。

### ①火绒剑监控进程

启动火绒剑监控客户端进程  
登陆后的客户端出现了几个查询还有业务相关的文件导入导出的功能，我们点击一下查询。  
返回来看看火绒剑中监控到客户端进程对外发起的网络请求有哪些。

![image-20220908233845031.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9fbd0e8696015b0db86d20fd6d7e9680e5e641c5.png)

发现一共对外两个IP发起了网络请求，**其中一个是刚刚数据库的连接地址，验证了我对登陆客户端验证的猜想，另一个地址请求的端口为1433也是个MSSQL数据库，**尝试一下拿刚刚那个数据库的用户名和密码能否连接。  
连接成功且为**DBA**权限。

![image-20220908234334185.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-04239c975563f4e814264a149cefa8ea7260d7fe.png)

但是无法利用**xp\_cmdshell**

![image-20220908234655518.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ebe83365a35ce406244ca5bf27020308337e08a3.png)

**xp\_dirtree**还是能执行的，可以翻翻有没有东西

![image-20220908234823679.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-96bb87dee576221e6326fa146cec93e60217fd3c.png)

查了一下这个数据库的ip，发现是云上的，顺道翻了一下数据库中的内容，发现和上一台数据库机子的表是一样的，但是这台云上的数据库数据量比之前那台大很多，这里猜测客户端请求逻辑应该是这样的。

![image-20220908235520287.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b23187680a2914fc4f24818a987c0f66d07c191d.png)

### ②转变思路

两个数据库ip连上了没有啥作用，那就看看这两个ip下是否还有**开放其他的端口。**  
我对**数据库1**和**数据库2**的ip进行了全端口扫描，数据库1扫出来了10余个端口，不少端口下有着web系统。数据库2没有扫出其他的端口。

![image-20220909100646473.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-50cf3c67143272111ec78769ad7721aaafdf471c.png)

接下来的渗透就和正常的Web系统渗透一致了，指纹识别，历史漏洞，弱口令、注入等等。。。  
在其中一个端口下，我发现了**IIS-PUT上传漏洞**并拿到了Webshell（这个这么久远的漏洞竟然还会存在，我也是没想到的。）

![image-20220909101531716.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-35aa81a3f39b7d019082f969b5b6205359c885da.png)

IIS-PUT漏洞的详情可以看这篇文章  
\[\[WEB安全\]IIS-PUT漏洞 - 肖洋肖恩、 - 博客园 (cnblogs.com)\](<https://www.cnblogs.com/-mo-/p/11295400.html#0x04-iis-put%E6%BC%8F%E6%B4%9E%E6%BC%94%E7%A4%BA%E5%AE%9E%E6%88%98>)  
我蛮提下，如果使用MOVE无法将PUT创建的**shell.txt**文件改名成**shell.asp**的话，可以利用下IIS解析漏洞，将**shell.txt**改名为**shell.asp;.jpg**试试。

#### **踩坑：**

不知道是不是我ASP马的问题，webshell可以连接且可以下载查看系统文件但是无法执行命令，会显示拒绝访问。

![image-20220909101859696.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2e05887fb014047882b5722377a096fac992317b.png)

#### 解决方式：

替换上冰蝎马，在冰蝎中可以执行命令。

```php
whoami
```

![image-20220909102348776.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-57c1d77329355c65ba457f8bc2a3f72469708eef.png)

```php
ipconfig
```

![image-20220909112356408.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6cfa3a6b7d953827b753c46b33d54f47819eac09.png)

```php
systeminfo
```

![image-20220909102721232.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-410ceebb7e0d1e627cb6046bcfcf2e3fc2869c11.png)

系统为Win2003竟然是域控机子，我很诧异为什么域控机子会拿来开web系统  
既然是域控机子那就想办法提权了，想着CS上线脏土豆无脑梭了。

#### 踩坑：

发现打了454个补丁，脏土豆无法梭哈

![image-20220909103010386.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a43aed44052c6e63ad8787c93af944483ef3eae2.png)

CS用脏土豆能够弹回来一个SYSTEM的Beacon，但是whoami执行完，仍然是**nt authority\\network service**权限。  
MSF也尝试过仍没有提权成功。

![image-20220909103550228.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-596b419ea9bfe78a5dc1224715b67c704b2c9288.png)

#### 解决方式：

既然是Win2003肯定是能提权的，如果不能一键梭哈，直接去找历史提权漏洞，只要补丁没打，就能成功提权。  
这里我找到一个**Microsoft Windows RPCSS服务隔离本地权限提升漏洞**  
具体文章如下：  
[(68条消息) 【内网提权】windows2003本地PR提权详解*剑客 getshell的博客-CSDN博客*win2003提权](https://blog.csdn.net/weixin_45588247/article/details/107603186)  
利用以下cmd命令可以查询系统打了这个提权漏洞的补丁没有，如果没打就可以利用此漏洞提权。

```php
systeminfo > C:\\Windows\\Temp\\temp.txt&amp;(for %i in (KB3057191 KB2840221 KB3000061 KB2850851 KB2711167 KB2360937 KB2478960 KB2507938 KB2566454 KB2646524 KB2645640 KB2641653 KB944653 KB952004 KB971657 KB2620712 KB2393802 KB942831 KB2503665 KB2592799 KB956572 KB977165 KB2621440) do @type C:\\Windows\\Temp\\temp.txt|@find /i "%i"|| @echo %i Not Installed!)&amp;del /f /q /a C:\\Windows\\Temp\\temp.txt
```

![image-20220909104338298.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8a29b432072acc935776fd9203952f7efe9fcff9.png)

KB952004 Not Installed!未进行补丁，可以利用MS09-012漏洞其进行提权  
上传pr.exe到目录下执行命令

```php
pr.exe "whoami"
```

![image-20220909105212457.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-550d9d780913aa43ac90f7692d22966f19678674.png)

成功。  
接下来用pr.exe执行下我的CS马就行。

```php
pr.exe "shell.exe"
```

![image-20220909105344518.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-49eaae7dc732acaf5cec7707be46e77101a5de69.png)

可以看到SYSTEM的beacon弹回来了。  
可以看到域用户还是有蛮多的。  
![image-20220909111534051.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d9888f414da528921d35431243e1ab6a4ef267c7.png)

后面直接猕猴桃抓密码做代理登陆域控了。

![image-20220909110945445.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5a1d326ae81cae1ece4c91d98f30edb855d6f826.png)

### ③继续深入

刚刚拿下域控的过程有点索然无味，看看还有没有其他有价值的东西，翻了一下web目录，看到了数据库的配置文件。

![image-20220909111312961.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7f2eb899af87137fef37fbb9934df19f5fcc4a1e.png)

翻到内网的一台MSSQL机子，蚁剑连接。

![image-20220909112037594.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a569e83c298e3cc533c605aaa1f256cb2591f6d5.png)

![image-20220909112046057.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3968f68e3f7050ed32e69614a3d43f264d2877fd.png)

system权限，出网，CS上线。

![image-20220909112156205.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4234983cf7d88f147a72d2cf0e1e245d8dc755f5.png)

```php
ipconfig
```

![image-20220909112509660.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1fbef6927796fbbeb6e43f6c3f8ac3825ae5f695.png)

```php
systeminfo
```

![image-20220909114159048.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5a68fd0842271751de722439c034b85fd16018e2.png)

2012机子抓不到明文密码，看到机子上开了3389，于是用frp做下代理尝试下用刚刚**域控Win2008机子上抓到的明文密码**进行远程3389登陆。  
**administrator成功登陆**

![image-20220909114519266.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e48884f1f455a6b54152204315a44a50e9e72cb7.png)

现在我们梳理一下我们手中有的资产

![image-20220909113626719.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8b1180950cce1553f17d97d3fa16a92b4b6b2fca.png)

### ④永恒之蓝扫描

对3段和11段分别进行了永恒之蓝的扫描  
发现3段和11段扫出来的结果是一样的  
比如 192.168.3.55存在永恒之蓝 则 192.168.11.55也存在永恒之蓝  
可以看出这两个段上的机子都是同一台机子。

![image-20220910151904056.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4dfb68bbea1560fb16e79ddc988c7bc9060d3501.png)

于是对3段下存在永恒之蓝的机子进行了攻击  
将CS的beacon转到公网MSF中，利用MSF的MS17\_010Exploit进行攻击，但无一例外，不管正向反向payload全都失败。。。。  
只能想着利用Fscan看看内网有没有其他有价值的东西了。

### ⑤Fscan扫描

在3段和11段分别用fscan进行扫描。  
没扫出什么东西，只有两个比较值得关注的点  
一个phpstudy后门RCE  
一个防火墙 可以看看没有弱口令

#### phpstudy backdoor RCE

参考这篇文章写入webshell  
[https://blog.csdn.net/weixin\_43268670/article/details/107098135](https://blog.csdn.net/weixin_43268670/article/details/107098135)

![image-20220910133203939.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-69f64b3e0cd11a6720bd3cfc4575d6cc03211212.png)

#### 防火墙

![image-20220910133500659.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-810fc1e90364e140522d8c0c2d3e753406f61b4a.png)

系统默认的管理员用户默认密码改了  
但是尝试了下刚刚从域控机上抓的**管理员明文密码**，成功登陆防火墙。

![image-20220910134637067.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-aeb3879a0e7be887d8c74d44c5f3c0f7c2e60a36.png)

在防火墙的SSL VPN配置中看到了内网存在192.168.1.1/24的C段

![image-20220910153642738.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7102a1e8919c3160b87da6240a57747fed820ff0.png)

### ⑥对1段进行横向

在刚刚内网数据库服务器3上对1段进行扫描。  
发现有好几个打印机系统，确定1段是**办公网段**。

![image-20220910142639497.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0b97016b0809da1337ad4bdde37bafc51d1c755e.png)

两个MSSQL弱口令

![image-20220910142905274.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7cc8e36f999349bce9216d686ccab7adc9071d39.png)

打印机系统弱口令

![image-20220910143219596.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0e4d2366c71619fff8dfe9c599d49f0fe0ee066e.png)

海康威视未授权RCE

![image-20220910143648087.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d1467b826c7ddc8fda211945aefa1c1e2ec37993.png)

接着利用fscan扫出的可能存在永恒之蓝的主机进行攻击尝试。  
打了5台，只有一台打成功了。

![image-20220910142501369.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-739d0eedd7175721eadf9d5361f73019dde2c271.png)

后续开了3389连上去了（图找不到了，就不放了）

0x03 总结
=======

本次内网打的还算顺利，只是对对面的网络架构感到疑惑，没想到打的Web系统就是域控，此外从防火墙上翻到了办公网段也是意外惊喜。  
由于远程登陆到域控机器和内网数据库服务器3上时发现上面运行着业务，所以本次渗透算是比较谨慎。  
还有在获得这些机子的过程中也通过抓取谷歌浏览器的密码，获得了不少内网其他系统的密码，但篇幅受限没写出来。  
**另外一点感想就是，在内网渗透过程中，一定要收集所获得的密码，利用手中的密码去尝试登陆内网中其他的业务系统，有时候会有意外惊喜的。**  
最后做下拿下的资产梳理（部分不重要的就不写了）：

![image-20220910151239208.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fc45212db51be054ffa6f6de94aac63c63f4f0eb.png)

### 不足之处：

本次内网渗透没有用到哈希传递。。。很重要的一点是我一传递我CS的beacon就会直接down掉，摸不着头脑。  
还有不管是1段还是3段扫描永恒之蓝时，扫出来了很多台，但是利用MSF进行攻击时，不管正向反向，只打出来了一台，有点离谱。  
此外，本次打的域环境和我心目中的域环境渗透还是有所差距的，看其他大佬的文章都是各种姿势技巧。。希望下次能打一个真正的域环境。