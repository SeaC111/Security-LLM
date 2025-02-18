0x00 前言
=======

在介绍PrintSpoofer之前，笔者会先详细介绍Windows下的权限控制以及Windows RPC远程过程调用。

0x01 Windows权限控制
================

Windows的访问控制模型有两个主要的组成部分，访问令牌 (Access Token) 和安全描述符 (Security Descriptor)，它们分别是访问者和被访问者拥有的东西。通过访问令牌和安全描述符的内容，Windows可以确定持有令牌的访问者能否访问持有安全描述符的对象。

笔者在写 [Windows认证协议](http://a3bz.top/2022-7-26-windows-%E8%AE%A4%E8%AF%81%E5%8D%8F%E8%AE%AE/) 这篇文章的时候提到了 `Windows Access Token (访问令牌)`，这个`Access Token` 会在用户创建进程或线程的时候被拷贝使用，`Access Token`用来指明当前进程或线程的权限。所以，Windows下的安全对象需要一个用来判断来访问对象权限的数据结构，这个就是安全描述符。

Windows的安全对象包括：

- 进程
- 线程
- 文件
- 服务
- 计划任务
- 互斥体
- 管道
- 文件共享
- 访问令牌
- 注册表
- 打印机
- 作业
- 等等

安全描述符(Security Descriptors, SD)
-------------------------------

安全描述符的数据结构如下：

typedef struct \_SECURITY\_DESCRIPTOR {  
BYTE Revision;  
BYTE Sbz1;  
SECURITY\_DESCRIPTOR\_CONTROL Control;  
PSID Owner;  
PSID Group;  
PACL Sacl;  
PACL Dacl;  
} SECURITY\_DESCRIPTOR, \*PISECURITY\_DESCRIPTOR;

安全描述符主要包括以下重要安全信息：

- Security identidiers (SID)，用来标识安全对象的用户和组
- Discretionary access control list (DACL)，通过一系列的acess control entry (ACE)定义了所有被允许或禁止的安全对象的访问者
- System access control list (SACL)，指明系统应该审核的内容，系统会根据审核项产生对应的系统日志

[![vsIc90.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-36e6ddff13f52deb2dabe7269defc95027aa0efb.png)](https://imgse.com/i/vsIc90)

下图当中的安全选项就指明了哪些用户或组能够访问，以及对应用户或组的权限

[![vsIfuF.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-00ad9e755a887e4f6c4d11c01ade09c390d4a80a.png)](https://imgse.com/i/vsIfuF)

### 安全标识符(Security Identifier, SID)

安全标识符是标识用户、组和计算机账户的唯一的号码。每个账户都有一个由权威机构 (例如，Windows域控制器) 颁发的唯一SID，并存储在安全数据库中。每次用户登陆时，系统都会从数据中检索该用户的SID，并将其放入访问令牌中。在于Windows安全性相关的所有后续交互中，系统使用访问令牌中的SID识别用户。当SID用作用户或组的唯一标识符时，就不能再使用它来标识另一个用户或组。

SID的组成：

S-\[修订级别\]-\[权值\]-\[标识符\]

SID分为两种，1. 内置SID；2. 自动分配SID。内置SID有：

- S-1-5-18 (LocalSystem)
- S-1-5-19 (LocalService)
- S-1-5-20 (NetworkService)
- S-1-5-32-544 (Administrators)
- S-1-5-32-545 (Users)
- S-1-5-32-550 (PrintOperators)
- ...

### 相对标识符(Relative Identifier, RID)

RID的组成：

S-\[修订级别\]-\[权值\]-\[标识符\]-\[相对标识符\]

例如：

- S-1-5-21-xxxx-xxx-500 (Administrator) 本地管理员
- S-1-5-21-xxxx-xxx-501 (Guest) 本地来宾用户
- S-1-5-21-xxxx-xxx-1004 (Workstaion) 本地工作站

[![vsoaP1.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0a182547c58c27158d23208ad6a7b1d412327b53.png)](https://imgse.com/i/vsoaP1)

### 自主访问控制列表(Discretionary access control list, DACL)

每个Windows进程都拥有一个线程，当程序想要访问某个安全对象时，系统会提取当前线程的访问令牌，然后将访问令牌的权限和被访问的安全对象DACL进行比较。

[![v6wxbT.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-100ef601317691d4247316affc37a8a70c5da3d9.png)](https://imgse.com/i/v6wxbT)

- 对于线程A，系统会先读取 ACE 1然后立马禁止访问，因为ACE 1的禁止访问用户中包含了Andrew，而线程A的Access Token里正是Andrew，所以返回错误代码5。
- 对于线程B，ACE 1通过，所以系统会检查ACE 2，而ACE 2要求属于Group A，线程B通过从而获得Write权限，而系统检查ACE 3时，所有人都能通过，所以线程B获得读取和执行权限。

当一个线程访问安全对象时，操作系统会将访问令牌的属性与被访问对象安全描述符中的DACL进行检查，检查的条目就是访问控制条目 (Access control entries，ACE)，最先检查的ACE优先级越高。

**NOTE**

- 如果安全对象的DACL被设置为NULL时，任何用户都要用对该安全对象的完全访问权限；
- 如果安全对象的DACL被设置为空时，任何对象都不允许访问。

### 系统访问控制列表(System access control list, SACL)

系统访问控制列表主要涉及的是关于ACE的日志，当审核对象的ACE被允许或拒绝的时候，系统就会产生相应的日志。

访问令牌(Access Token)
------------------

访问令牌包括两种：

1. Primary Token (主令牌)
2. Impersonation Token (模拟令牌)

默认情况下，系统会在线程中使用主令牌与安全对象交互。

一个令牌主要包括会话ID，用户和组列表，特权列表，令牌类型，模拟令牌等级和默认DACL等。

**特权列表**

SeAssignPrimaryTokenPrivilege  
SeAuditPrivilege  
SeBackupPrivilege  
SeChangeNotifyPrivilege  
SeCreateGlobalPrivilege  
SeCreatePagefilePrivilege  
SeCreatePermanentPrivilege  
SeCreateSymbolicLinkPrivilege  
SeCreateTokenPrivilege  
SeDebugPrivilege  
SeEnableDelegationPrivilege  
SeImpersonatePrivilege  
SeIncreaseBasePriorityPrivilege  
SeIncreaseQuotaPrivilege  
SeIncreaseWorkingSetPrivilege  
SeLoadDriverPrivilege  
SeLockMemoryPrivilege  
SeMachineAccountPrivilege  
SeManageVolumePrivilege  
SeProfileSingleProcessPrivilege  
SeRelabelPrivilege  
SeRemoteShutdownPrivilege  
SeRestorePrivilege  
SeSecurityPrivilege  
SeShutdownPrivilege  
SeSyncAgentPrivilege  
SeSystemEnvironmentPrivilege  
SeSystemProfilePrivilege  
SeSystemtimePrivilege  
SeTakeOwnershipPrivilege  
SeTcbPrivilege  
SeTimeZonePrivilege  
SeTrustedCredManAccessPrivilege  
SeUndockPrivilege  
SeUnsolicitedInputPrivilege

这些特权并不会都出现在令牌中。不在令牌出现的特权，是没有办法再次添加到令牌当中。

**令牌模拟级别**

| 模拟级别 | 说明 |
|---|---|
| SecurityAnonymous | 无法获取有关客户端的表示信息且无法模拟客户端 |
| SecurityIdentification | 可以获取有关客户端的信息（比如安全标识符和特权）但是无法模拟客户端 |
| SecurityImpersonation | 可以在本地模拟客户端但无法在远程系统上模拟客户端 |
| SecurityDelegation | 可以在本地和远程系统上模拟客户端 |

三个通过用户身份创建进程的函数：

| 函数 | 需要特权 | 输入 |
|---|---|---|
| CreateProcessWithLogon | NULL | 域/用户名/密码 |
| CreateProcessWithToken | SeImpersonatePrivilege | Primary令牌 |
| CreateProcessAsUser | SeAssignPrimaryTokenPrivilege和SeIncreaseQuotaPrivilege | Primary令牌 |

0x02 Windows RPC远程过程调用
======================

RPC (Remote Procedure Call)，远程过程调用其实本质上来说也是一种进程间通信，但是相比于传统的进程间通信，RPC机制提供了一种开发者不必显示的区分本地调用和远程调用，从而实现允许本地程序调用另一个地址空间的过程或函数。

**RPC框架**

- 客户端 (client)：服务的调用方
- 客户端存根 (client stub)：存放服务端的地址信息，再将客户端的请求参数打包成网络数据，然后通过网络远程发送给服务方
- 服务端存根 (server stub)：接受客户端发送过来的信息，将信息解包并调用本地方法
- 服务端 (server)：真正的服务提供者

**RPC调用过程**

1. client 以本地调用方式（接口）调用服务
2. client stub 接受到调用后，负责将方法，参数等组装成能够进行网络传输的消息体（将消息对象序列化为二进制）
3. client 通过socket通信将网络消息发送到服务端
4. server stub 收到消息后进行解码（将消息对象反序列化）
5. server stub 根据解码结果调用本地的服务
6. server 执行本地过程并将执行结构返回给 server stub
7. server stub 将返回结果打包成网络消息（将结果消息进行序列化）
8. server 通过socket通信将网络消息发送到客户端
9. client stub 接受到结果消息，并进行转码（将结果消息反序列化）
10. client 接收到返回结果

所以RPC机制对开发者来说，隐藏了2，3，4，7，8，9步骤，使得调用远程函数和本地函数一样。

如何在windows实现RPC，笔者这里不会去写，有想了解的师傅可以参考以下链接：

<https://www.cnblogs.com/wanghaiyang1930/p/4469222.html>

0x03 PrintSpoofer
=================

上面提到Windows上的访问令牌有两种，一种是主令牌，另一种是模拟令牌。模拟令牌可以使得当前用户以另一个用户的身份创建进程，那么如果可以窃取高权限用户（比如 NT AUTHORITY\\SYSTEM）的访问令牌，低权限用户就可以模拟高权限用户从而完成提权。

但是通过模拟令牌创建进程需要当前用户有`SeImpersonatePrivilege`或`SeAssignPrimaryTokenPrivilege`，而拥有这两个权限的账户是服务账户，比如 IIS、SQL Server。

进程令牌模拟流程：

1. 调用OpenProcess获取进程句柄
2. 调用OpenProcessToken，传入进程句柄获取访问令牌
3. 调用DuplicateTokenEx，设置令牌模拟级别并复制一个令牌句柄
4. 调用CreateProcessWithToken，传入模拟令牌， 创建一个新的进程达到命令执行的目标

而窃取令牌的方式一般是利用命名管道。因为命名管道服务端提供模拟客户端的功能，使得服务端可以调用ImpersonateNamedPipeClient获取客户端的访问令牌，并且Windows RPC中也提供了相同的功能`RpcImpersonateClient`。所以，可以通过创建一个命名管道服务端，然后系统中高权限账户来连接命名管道从而使得服务端可以模拟高权限账户的模拟令牌。

关键问题是，如何让高权限用户连接攻击者创建的命名管道。

### Printer Bug

Windows的MS-RPRN协议用于打印客户机和打印服务器之间的通信，默认情况下是启用的。Printer Spooler服务暴露RPC接口`RpcRemoteFindFirstPrinterChangeNotificationEx()`，这样客户端可以调用创建一个远程更改通知对象，该对象监视对打印机对象的更改，并将更改通知发送到打印机。

DWORD RpcRemoteFindFirstPrinterChangeNotificationEx(  
 /\* \[in\] \*/ PRINTER\_HANDLE hPrinter,  
 /\* \[in\] \*/ DWORD fdwFlags,  
 /\* \[in\] \*/ DWORD fdwOptions,  
 /\* \[unique\]\[string\]\[in\] \*/ wchar\_t \*pszLocalMachine,  
 /\* \[in\] \*/ DWORD dwPrinterLocal,  
 /\* \[unique\]\[in\] \*/ RPC\_V2\_NOTIFY\_OPTIONS \*pOptions)

并且，这个通知是通过命名管道发送的，而这个命名管道是`\\.\pipe\spooless`。所以，如果能够控制连接的命名管道是攻击者创建的，那就可以窃取该服务的访问令牌了。但是，又存在一个问题，这个命名管道是`NT AUTHORITY\SYSTEM`账户控制的，攻击者不能创建同名的命名管道。

接下来，就需要想办法创建另一个命名管道且符合路径检查。当尝试将传入的`\\server_name`改为`\\server_name\hack`时，会因为路径验证检查而失败。

后来PrintSpoofer作者了解到，如果路径里包含`/`，将会通过路径检查，并且在连接命名管道的时候会将`/`转换为`\`。这意味着，传入的`pszLocalMachine`为`\\server_name/hack`时，命名管道的路径就会拼接为`\\server_name\hack\pipe\spoolss`从而通过验证并且与规定的命名管道不同。

利用代码写的非常清晰，调用该RPC接口后窃取访问令牌的操作都是相同的。

[![vyrOUS.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d83b4e0617eee34101848e76cc70ae2f2888b630.png)](https://imgse.com/i/vyrOUS)

### 执行效果

[![vysdqP.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1d61751cc2548c4f65db214d447efb343f70ee4a.png)](https://imgse.com/i/vysdqP)

切换成服务账户可以使用PsExec，指定对应的服务账户名称即可。

0x04 参考链接
=========

1. <https://www.anquanke.com/post/id/270774>
2. <https://blog.csdn.net/hjxyshell/article/details/38502933>
3. <https://payloads.online/archivers/2021-01-31/1/>
4. <https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens>
5. <https://docs.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object>
6. [https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security\_descriptor](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor)
7. <https://bbs.pediy.com/thread-262291.htm>
8. <https://www.anquanke.com/post/id/254904#h2-3>
9. <https://github.com/itm4n/PrintSpoofer>
10. <https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/#getting-a-system-token>