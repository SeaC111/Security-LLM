windows
-------

### 开启审核策略

运行 **secpol.msc** 可以打开本地安全策略，依次点开本地策略-审核策略。可以看到windows默认情况是没有开启审核策略的，不开启策略的话，windows就不会记录某些事件，比如登录事件，进程创建事件等等。

我们可以挨个手动修改审核策略的属性，将审核操作选上成功和失败。

![image-20210422105516759](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-105759f73665c75473a1e5124213586e205ce9d1.png)

当然有简单方法：将下面脚本另存为bat，然后管理员运行就可以打开全部策略了。

```php
echo [version] >1.inf 
echo signature="$CHICAGO$" >>1.inf 
echo [Event Audit] >>1.inf 
echo AuditSystemEvents=3 >>1.inf 
echo AuditObjectAccess=3 >>1.inf 
echo AuditPrivilegeUse=3 >>1.inf 
echo AuditPolicyChange=3 >>1.inf 
echo AuditAccountManage=3 >>1.inf 
echo AuditProcessTracking=3 >>1.inf 
echo AuditDSAccess=3 >>1.inf 
echo AuditAccountLogon=3 >>1.inf 
echo AuditLogonEvents=3 >>1.inf 
secedit /configure /db 1.sdb /cfg 1.inf /log 1.log /quiet 
del 1.*
pause
```

![image-20210422110029884](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fb8e3f25766a431b17cb8f859d20fe23ac2897df.png)

### Windows系统日志

#### Windows系统日志简介

Windows操作系统在其运行的生命周期中会记录其大量的日志信息，这些日志信息包括：Windows事件日志（Event Log），Windows服务器系统的IIS日志，FTP日志，Exchange Server邮件服务，MS SQL Server数据库日志等。处理应急事件时，客户提出需要为其提供溯源，这些日志信息在取证和溯源中扮演着重要的角色。

Windows事件日志文件实际上是以特定的数据结构的方式存储内容，其中包括有关系统，安全，应用程序的记录。每个记录事件的数据结构中包含了9个元素（可以理解成数据库中的字段）：日期/时间、事件类型、用户、计算机、事件ID、来源、类别、描述、数据等信息。应急响应工程师可以根据日志取证，了解计算机上上发生的具体行为。

Windows系统中自带了一个叫做事件查看器的工具，它可以用来查看分析所有的Windows系统日志。运行 **eventvwr** 可以快速打开事件查看器。使用该工具可以看到系统日志被分为了两大类：Windows日志和应用程序和服务日志。

系统内置的三个核心日志文件（System，Security和Application）默认大小均为20480KB（20MB），记录事件数据超过20MB时，默认系统将优先覆盖过期的日志记录。其它应用程序及服务日志默认最大为1024KB，超过最大限制也优先覆盖过期的日志记录。

#### windows日志类型

**系统日志**

系统日志包含 Windows 系统组件记录的事件。例如，在启动过程中加载驱动程序或其他系统组件失败将记录在系统日志中。系统组件所记录的事件类型由 Windows 预先确定。

默认位置：%SystemRoot%\\System32\\Winevt\\Logs\\System.evtx

**应用程序日志**

应用程序日志包含由应用程序或程序记录的事件。例如，数据库程序可在应用程序日志中记录文件错误。程序开发人员决定记录哪些事件。

默认位置：%SystemRoot%\\System32\\Winevt\\Logs\\Application.evtx

**安全日志**

安全日志包含诸如有效和无效的登录尝试等事件，以及与资源使用相关的事件，如创建、打开或删除文件或其他对象。管理员可以指定在安全日志中记录什么事件。例如，如果已启用登录审核，则对系统的登录尝试将记录在安全日志中。

默认位置：%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx

#### 应用程序及服务日志

**Microsoft**

Microsoft文件夹下包含了200多个微软内置的事件日志分类，只有部分类型默认启用记录功能，如远程桌面客户端连接、无线网络、有线网路、设备安装等相关日志。

默认位置：%SystemRoot%\\System32\\Winevt\\Logs目录下Microsoft-Windows开头的文件名

![image-20210422111852969](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-94617b252a8862e6e91aaf96b9eab0c9c7e1ed50.png)

**Microsoft Office Alerts**

微软Office应用程序（包括Word/Excel/PowerPoint等）的各种警告信息，其中包含用户对文档操作过程中出现的各种行为，记录有文件名、路径等信息。

默认位置：%SystemRoot%\\System32\\Winevt\\Logs\\OAerts.evtx

**Windows PowerShell**

Windows自带的PowerShell应用的日志信息。

默认位置：%SystemRoot%\\System32\\Winevt\\Logs\\Windows PowerShell.evtx

**Internet Explorer**

IE浏览器应用程序的日志信息，默认未启用，需要通过组策略进行配置。

默认位置：%SystemRoot%\\System32\\Winevt\\Logs\\Internet Explorer.evtx

#### windows事件类型/级别

Windows事件日志中共有五种事件类型，所有的事件必须拥有五种事件类型中的一种，且只可以有一种。五种事件类型分为：

1. 信息（Information）：信息事件指应用程序、驱动程序或服务的成功操作的事件。
2. 警告（Warning）：警告事件指不是直接的、主要的，但是会导致将来问题发生的问题。例如，当磁盘空间不足或未找到打印机时，都会记录一个“警告”事件。
3. 错误（Error）：错误事件指用户应该知道的重要的问题。错误事件通常指功能和数据的丢失。例如,如果一个服务不能作为系统引导被加载，那么它会产生一个错误事件。
4. 成功审核（Success audit）：成功的审核安全访问尝试，主要是指安全性日志，这里记录着用户登录/注销、对象访问、特权使用、账户管理、策略更改、详细跟踪、目录服务访问、账户登录等事件，例如所有的成功登录系统都会被记录为“ 成功审核”事件。
5. 失败审核（Failure audit）：失败的审核安全登录尝试，例如用户试图访问网络驱动器失败，则该尝试会被作为失败审核事件记录下来。

#### Windows事件属性

Windows事件日志属性如下：

| 属性名 | 描述 |
|---|---|
| 事件ID | 标识特定事件类型的编号。描述的第一行通常包含事件类型的名称。例如，6005 是在启动事件日志服务时所发生事件的 ID。此类事件的描述的第一行是“事件日志服务已启动”。产品支持代表可以使用事件 ID 和来源来解决系统问题。 |
| 来源 | 记录事件的软件，可以是程序名（如“SQL Server”），也可以是系统或大型程序的组件（如驱动程序名）。例如，“Elnkii”表示 EtherLink II 驱动程序。 |
| 级别 | 事件严重性的分类，以下事件严重性级别可能出现在系统和应用程序日志中： **信息：**指明应用程序或组件发生了更改，如操作成功完成、已创建了资源，或已启动了服务。 **警告：**指明出现的问题可能会影响服务器或导致更严重的问题（如果未采取措施）。 **错误：**指明出现了问题，这可能会影响触发事件的应用程序或组件外部的功能。 **关键：**指明出现了故障，导致触发事件的应用程序或组件可能无法自动恢复。以下事件严重性级别可能出现在安全日志中： **审核成功 ：**指明用户权限练习成功。 **审核失败：**指明用户权限练习失败。在事件查看器的正常列表视图中，这些分类都由符号表示。 |
| 用户 | 事件发生所代表的用户的名称。如果事件实际上是由服务器进程所引起的，则此名称为客户端 ID；如果没有发生模仿的情况，则为主 ID。如果适用，安全日志项同时包含主 ID 和模仿 ID。当服务器允许一个进程采用另一个进程的安全属性时就会发生模拟的情况 |
| 操作代码 | 包含标识活动或应用程序引起事件时正在执行的活动中的点的数字值。例如，初始化或关闭 |
| 日志 | 已记录事件的日志的名称 |
| 任务类别 | 用于表示事件发行者的子组件或活动。 |
| 关键字 | 可用于筛选或搜索事件的一组类别或标记。示例包括“网络”、“安全”或“未找到资源” |
| 计算机 | 发生事件的计算机的名称。该计算机名称通常为本地计算机的名称，但是它可能是已转发事件的计算机的名称，或者可能是名称更改之前的本地计算机的名称 |
| 日期和时间 | 记录事件的日期和时间 |

重点讲述**事件ID**值，Windows 的日志以事件 id 来标识具体发生的动作行为，可通过下列网站查询具体 id 对应的操作：

<https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor>

<https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j>

#### 常用的事件id

| 事件ID | 说明 |
|---|---|
| 1102 | 清理审计日志 |
| 4624 | 账号登录成功 |
| 4625 | 账号登录失败 |
| 4634 | 账号注销成功 |
| 4647 | 用户启动的注销 |
| 4672 | 使用超级用户（如管理员）进行登录 |
| 4720 | 创建用户 |
| 4726 | 删除用户 |
| 4732 | 将成员添加到启用安全的本地组中 |
| 4733 | 将成员从启用安全的本地组中移除 |
| 4688 | 创建新进程 |
| 4689 | 结束进程 |

每个**成功登录**的事件都会标记一个登录类型，不同登录类型代表不同的方式：

| 登录类型 | 描述 | 说明 |
|---|---|---|
| 2 | 交互式登录（Interactive） | 用户在本地进行登录。 |
| 3 | 网络（Network） | 最常见的情况就是连接到共享文件夹或共享打印机时。 |
| 4 | 批处理（Batch） | 通常表明某计划任务启动。 |
| 5 | 服务（Service） | 每种服务都被配置在某个特定的用户账号下运行。 |
| 7 | 解锁（Unlock） | 屏保解锁。 |
| 8 | 网络明文（NetworkCleartext） | 登录的密码在网络上是通过明文传输的，如FTP。 |
| 9 | 新凭证（NewCredentials） | 使用带/Netonly参数的RUNAS命令运行一个程序。 |
| 10 | 远程交互，（RemoteInteractive） | 通过终端服务、远程桌面或远程协助访问计算机。 |
| 11 | 缓存交互（CachedInteractive） | 以一个域用户登录而又没有域控制器可用 |

#### 事件分析工具和命令

##### Get-WinEvent

```php
powershell管理员执行
列出安全日志 Get-WinEvent -FilterHashtable @{logname="Security";}
列出系统日志 Get-WinEvent -FilterHashtable @{logname="System";}
列出应用程序日志 Get-WinEvent -FilterHashtable @{logname="Application";}
```

![image-20210422133932604](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cf92128638f5be42b63be5d3da466c4e5e6836c2.png)

![image-20210422134141961](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-04d465d44d55b131ac19a7c0b23490d072109d26.png)

![image-20210422134242368](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ad5f9c68ce72d03d4b1fcaa6b708a5b95a2546fd.png)

##### **wevtutil**

wevtutil 命令参数如下

| 命令 | 意义 | 注释 |
|---|---|---|
| el | enum-logs | 列出日志名称 |
| gl | get-log | 获取日志配置信息 |
| sl | set-log | 修改日志配置 |
| ep | enum-publishers | 列出事件发布者 |
| gp | get-publisher | 获取发布者配置信息 |
| im | install-manifest | 从清单中安装事件发布者和日志 |
| um | uninstall-manifest | 从清单中卸载事件发布者和日志 |
| qe | query-events | 从日志或日志文件中查询事件 |
| gli | get-log-info | 获取日志状态信息 |
| epl | export-log | 导出日志 |
| al | archive-log | 存档导出的日志 |
| cl | clear-log | 清除日志 |

导出 安全 日志的命令为：

```php
wevtutil epl security d:\security.evtx
该命令将安全日志信息导出到d盘下的security.evtx文件
```

查询 安全 日志的命令为：

```php
wevtutil qe Security /f:text /rd:true > c:\1.txt    导出为文本
wevtutil qe Security /f:xml /rd:true > c:\1.xml     导出为xml格式
wevtutil qe Application /c:3 /rd:true /f:text       以文本格式显示应用程序日志中三个最近的事件

/f:<Format> 指定输出应为 XML 格式或文本格式。 如果 <Format> 为 xml，则输出以 xml 格式显示。 如果 <Format> 是文本，则显示不带 XML 标记的输出。 默认值为 Text。
/rd:<Direction> 指定读取事件的方向。 <Direction> 可以为 true 或 false。 如果为 true，则首先返回最新的事件。
/c<Count>   设置要读取的最大事件数。
```

![image-20210422135321389](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4f479ec1a061e86b4f106e48b9aefb59b29ffccd.png)

![image-20210422135550212](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-658c2284a454e15d35c11e88163da0dcc1b3e373.png)

更多可以参考wevtutil微软官方文档说明：<https://docs.microsoft.com/zh-cn/windows-server/administration/windows-commands/wevtutil>

##### logparser(需下载安装)

logparser工具下载地址 <https://www.microsoft.com/en-us/download/confirmation.aspx?id=24659>

```php
查询 系统日志 事件id为4688的事件 按事件倒序：
LogParser.exe  -i:EVT "SELECT TimeGenerated,EventID,EXTRACT_TOKEN(Strings,1,'|')  as UserName,EXTRACT_TOKEN(Strings,5,'|')  as ProcessName FROM Security where EventID=4688 ORDER BY TimeGenerated desc"
其中FROM Security 中的Security可以换成System和Application或 导出的日志、备份日志，例c:\11.evtx；事件id可以替换成其他id；当然也可以select *来查询所有列。
EXTRACT_TOKEN(Strings,5,'|')表示将String列按'|'隔开取第5个。类似编程语言中的split函数。

查询系统日志，所有列，事件倒序
LogParser.exe  -i:EVT "SELECT * FROM System  ORDER BY TimeGenerated desc"

-o:csv 将日志另存为csv格式，其他常用格式tsv(文本格式)、xml

LogParser.exe  -i:EVT "SELECT TimeGenerated,EventID,EXTRACT_TOKEN(Strings,1,'|')  as UserName,EXTRACT_TOKEN(Strings,5,'|')  as ProcessName FROM Security ORDER BY TimeGenerated desc" -o:tsv > c:\1.txt
```

![image-20210422142206393](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b984b15c82d80f98b23cf2823413eb06400cc5fc.png)

![image-20210422143018616](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68b3212b06b0733f46d9765643fec969b089c199.png)

![image-20210422144555022](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f29d985d526f16126d954883efdf70340210ebbe.png)

### 日志清除（管理员权限）

清除日志之后会留下清除日志的审核事件。

**手动删除：**

开始-程序-管理工具-计算机管理-系统工具-事件查看器-清除日志

**meterperter自带清除日志功能：**

```php
清除windows中的应用程序日志、系统日志、安全日志 clearev     
查看事件日志:  run event_manager -i
清理事件日志: run event_manager -c
```

**wevtutil：**

```php
wevtutil el             列出系统中所有日志名称
wevtutil cl system      清理系统日志
wevtutil cl application 清理应用程序日志
wevtutil cl security    清理安全日志
```

![image-20210422145807123](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-61ff674e0453042caf2f9f2a8924070dcf7393db.png)

**Clear-Eventlog（powershell）**

```php
Clear-Eventlog -Log Application, System,Security
```

![image-20210422150000978](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dd2ee050c1da2713bfbd6718128ebcbfc1c02a76.png)

**清除应用程序和服务日志**

```php
FOR /F "delims=" %I IN ('WEVTUTIL EL') DO (WEVTUTIL CL "%I")
```

前面所有命令都只是清除了windows日志，没有清除应用程序和服务日志，这个命令可以清除。

![image-20210422150041680](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-07d299b2d810b9ee8f95247b24e1b3142e54f90b.png)

清除应用程序和服务日志：

![image-20210422150131242](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-15e84df2753be19b75289eb42bc2ccdf3864f5ca.png)

![image-20210422150547760](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-87cc8503df329880736e4152b714ea4415631edd.png)

**清除recent：**

recent是windows下用户打开的文档历史文件记录 。

```php
在文件资源管理器中点击“查看”->“选项”->在常规->隐私中点击”清除”按钮
或直接打开C:\Users\用户名\Recent并删除所有内容
或在命令行中输入del /f /s /q %userprofile%\Recent*.*
```

清除之前：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1b5cb8d9f83543be074b3bed251849873f782cae.png)

清除之后：

![image-20210422154539113](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1b8c4ab4f152ed9969e2a2645843d628c25487ad.png)

参考连接（站在巨人的肩膀上登高望远）：

<https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor>

<https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j>

<https://docs.microsoft.com/zh-cn/windows-server/administration/windows-commands/wevtutil>

<https://www.freebuf.com/vuls/175560.html>

<https://mp.weixin.qq.com/s/sah3GAVlOALP4hx7vk8eJA>

<https://mp.weixin.qq.com/s/pzQxkl3Ngbapuso75LgnLQ>

[https://blog.csdn.net/Z\_Z\_W\_/article/details/104406072](https://blog.csdn.net/Z_Z_W_/article/details/104406072)

[https://blog.csdn.net/Captain\_RB/article/details/109573106](https://blog.csdn.net/Captain_RB/article/details/109573106)