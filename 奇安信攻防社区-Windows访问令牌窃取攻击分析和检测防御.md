Windows访问令牌窃取攻击分析和检测防御
======================

前言
--

​ 令牌窃取（Token Theft）是一种Windows上常用的提权攻击技术，攻击者可以通过获取系统中一个高权限进程的安全令牌，然后将其注入到一个低权限进程中，使得低权限进程可以获得高权限进程的访问权限，如域管理员在域内某台普通主机上留下未清除的令牌，攻击者可窃取域管理员的令牌以提升权限，从而执行各种恶意操作。

一、Windows中的令牌
-------------

1. 令牌概述

​ 令牌是系统的临时密钥，相当于账户名和密码，用来决定是否允许这次请求以及判断这次请求是属于哪一个用户的，它允许你在不提供密码或其他凭证的前提下，访问网络和系统资源；令牌由LSA分配，包含用户安全标识SID、权限列表等，这些令牌持续存在系统中，除非系统重新启动。

2. 令牌分类

- 访问令牌(Access Token)：表示访问控制操作主体的系统对象；
- 会话令牌(Session Token)：是交互会话中唯一的身份标识符；
- 密保令牌(Security Token)：又叫做认证令牌或硬件令牌，是一种计算机身份校验的物理设备，例如U盾等。

如：访问令牌（access token）

​ 是用来描述进程或线程安全上下文的对象，令牌所包含的信息是与该user账户相关的进程或线程的身份和权限信息。当user登录时，系统通过将user输入的密码与储存在安全数据库中的密码进行对比。若密码正确，系统此时会为user生成一个访问令牌。之后，该user执行的每个进程都会拥有一个该访问令牌的拷贝。

![1](https://shs3.b.qianxin.com/butian_public/f8996922523819ba87e009048006c2cfab3c31ad65c82.jpg)

3. Windows的访问令牌（AccessToken）有两种类型：

- Delegation token(授权令牌)：用于交互会话登录(例如本地用户直接登录、远程桌面登录)
- Impersonation token(模拟令牌)：用于非交互登录(利用net use访问共享文件夹)

​ 想列举令牌只能列出当前用户和比当前用户权限更低用户的令牌，例如当前权限是system或者是administrator，那么我们就可以看到系统中所有的令牌，如使用其他用户登录后注销再用administrator用户登录，通过incognito.exe工具能够获取到已注销用户的token：

![2](https://shs3.b.qianxin.com/butian_public/f707396746b243ddfed71b72250c8c63f39f1a251e331.jpg)

二、攻击复现
------

1. 利用incognito工具窃取用户令牌

- 指定用户token，执行任意命令
    
    > incognito.exe execute -c "用户名" calc.exe

![3](https://shs3.b.qianxin.com/butian_public/f978635e3a6a6f528bd2a35758c5accd5f07d5b1a57b3.jpg)

![4](https://shs3.b.qianxin.com/butian_public/f217410aadde06447829cf7de570dbbb18c4a4726d3e7.jpg)

- 窃取SYSTEM用户token提升权限

> incognito.exe execute -c "NT AUTHORITY\\SYSTEM" cmd.exe

![5](https://shs3.b.qianxin.com/butian_public/f3513259138fbe2f3d398f75d850053e38a971f63acd8.jpg)

2. 使用Invoke-TokenManipulation.ps1窃取用户令牌

- 列举token
    
    > Invoke-TokenManipulation -Enumerate
    
    ![6](https://shs3.b.qianxin.com/butian_public/f4963381a213886dbeac5e7ab672a4eb33a71accef0a3.jpg)
- 提升system权限
    
    > Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "nt authority\\system"

![7](https://shs3.b.qianxin.com/butian_public/f868186a92fbdc7508e5ff2d60df11e8a6c6ccfa6eff6.jpg)

- 通过指定进程id窃取用户token启动进程
    
    > Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 436

![8](https://shs3.b.qianxin.com/butian_public/f136968818e4a48b3065265a5df3430833d1d471f445a.jpg)

3. Msf下的利用
    
    ![9](https://shs3.b.qianxin.com/butian_public/f3461445583c429817da8f5aa3cd4bd38fe3a74646aaa.jpg)

三、原理分析
------

这里打断点对Invoke-TokenManipulation.ps1进行分析：

1. 命令参数

![10](https://shs3.b.qianxin.com/butian_public/f40482391bb2246a64f181bcbe2fac18853055eedcae5.jpg)

2. 跳转至调用win API函数，这里分析几个窃取过程必要的函数
    
    ![11](https://shs3.b.qianxin.com/butian_public/f532049ab1b4991c5f29a7ac32e2a741ef253aa72da4d.jpg)

1)给OpenProcess()传入指定的进程PID，返回一个可操作的进程句柄(HANDLE)；且必须指定进程的权限标志：PROCESS\_QUERY\_LIMITED\_INFORMATION、PROCESS\_QUERY\_INFORMATION或PROCESS\_ALL\_ACCESS（三者权限按从低到高排序），我们可以使用拥有SeDebugPrivilege权限（忽视安全描述符允许调试进程）的用户，如用户为Administrator或是被给予了相应的权限；

函数原型如下：

```c++
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```

2)将OpenProcess()获取的进程句柄传入OpenProcessToken()用于打开与进程关联的访问令牌的句柄，且必须传入一个访问权限标志才能使用OpenProcessToken()：TOKEN\_QUERY和TOKEN\_DUPLICATE访问权限

函数原型如下：

```c++
 BOOL OpenProcessToken(
   [in]  HANDLE  ProcessHandle,
   [in]  DWORD   DesiredAccess,
   [out] PHANDLE TokenHandle
 );
```

3)使用 DuplicateTokenEx()来复制一个新的访问令牌。必须使用 TOKEN\_ADJUST\_DEFAULT TOKEN\_ADJUST\_SESSIONID, TOKEN\_QUERY, TOKEN\_DUPLICATE 和TOKEN\_ASSIGN\_PRIMARY 访问权限来调用 DuplicateTokenEx() 。

![12](https://shs3.b.qianxin.com/butian_public/f51313850048c1c309cff18d360100e03f0aa4e037e10.jpg)

4)使用 CreateProcessWithTokenW()，通过DuplicateTokenEx()创建的访问令牌可以传递给CreateProcessWithTokenW()，从而使用复制的令牌生成一个新的进程。

![13](https://shs3.b.qianxin.com/butian_public/f7270547d3751fa189199d54de761f93b9e4b867b2bcb.jpg)

新发现：不是所有的SYSTEM权限运行的进程都被窃取，主要有两个结构标识：TOKEN\_USER和 TOKEN\_OWNER，OWNER结构标识用户是使用访问令牌创建的任何进程的所有者，当该标识符是SYSTEM的时候但我们当前的权限并不是SYSTEM是无法窃取的，如winlogon.exe可利用而spoolsv.exe不可利用：

![14](https://shs3.b.qianxin.com/butian_public/f363601dc266aaa594a440f8d7b8e7bed0e31934245c7.jpg)

![14](https://shs3.b.qianxin.com/butian_public/f2247262029656ca411a8ed75746febf2603a30bacd50.jpg)

枚举可窃取的进程：

> Where-Object {$*.UserName -eq 'NT AUTHORITY\\SYSTEM' -and $*.OwnerName -ne 'NT AUTHORITY\\SYSTEM'} | Select-Object ProcessName,ProcessID | Format-Table

貌似这些进程均可以窃取SYSTEM的令牌：![15](https://shs3.b.qianxin.com/butian_public/f828057c77c05e0acd2d8416a861dfcd3f129547a4bd9.jpg)

结果还是有一些SYSTEM进程不可被窃取，通过Process Explorer可以发现了一个导致此行为的常见属性：PsProtectedSignerWinTcb-Light（PPL），此时需要使用PROCESS\_QUERY\_LIMITED\_INFORMATION权限标记才能进行窃取令牌操作：

![16](https://shs3.b.qianxin.com/butian_public/f302521985c7b22aa89ed21fb3d6b8f96681de796a65c.jpg)

总结：

从 SYSTEM 进程窃取访问令牌：

1） 必须调用TokenOwner为BUILTIN\\Administrator进程执行的OpenProcessToken()；

2） OpenProcess()与受 PPL 保护的 SYSTEM 进程的访问权限一起使用PROCESS\_QUERY\_LIMITED\_INFORMATION。

四、检测方法
------

1. 通过分析Windows主机安全日志进程创建事件（4688）和请求对象句柄事件（4656）

4688事件：一般通过窃取SYSTEM令牌调用cmd窗口会有以下特征，令牌提升类型为%%1936(不同的版本win日志类型字段值不一样)。

对令牌提升类型说明如下 :

- %% 1936（TokenElevationTypeDefault (1)） - 类型 1 是一个完整的令牌，表示进程在常规用户模式下运行，没有管理员权限。与TokenElevationTypeLimited相似，不过没有弹出输入凭据的提示框，除非当前用户本身具有管理员权限（令牌窃取）。
- %% 1937（TokenElevationTypeFull (2)） - 类型 2 是一个提升的令牌，没有删除权限或禁用组。当启用用户帐户控制并且用户选择使用以管理员身份运行来启动程序时，将使用提升的令牌。当应用程序配置为始终需要管理权限或始终需要最大权限，并且用户是管理员组的成员时，也会使用提升的令牌。表示进程拥有完全的管理员权限，可以访问任意系统资源。此时操作系统会提示用户是否允许该进程进行管理员权限请求。需要注意的是，如果当前用户不是管理员，会被要求提供管理员密码。
- %% 1938（TokenElevationTypeLimited (3)） - 类型 3 是启用 UAC 且用户只需从“开始”菜单启动程序时的正常值。这是一个有限的令牌，表示进程没有管理员权限，但是用户需要输入管理员凭据才能启动该进程并提升其权限。这可以通过右键单击应用程序并选择“以管理员身份运行”来实现。

4656事件：常见的SYSTEM进程dllhost.exe、lsass.exe、OfficeClickToRun.exe、svchost.exe、Sysmon64.exe、unsecapp.exe、VGAuthService.exe、vmacthlp.exe、vmtoolsd.exe、winlogon.exe等被可疑进程赋予权限标记:0x400(PROCESS\_QUERY\_INFORMATION)

受PPL保护的进程：csrss.exe、Memory Compression.exe、services.exe、smss.exe、wininit.exe等被可疑进程赋予权限标记:0x1000(PROCESS\_QUERY\_LIMITED\_INFORMATION)

2. 通过监测Windows API的使用，例如DuplicateToken(Ex)、ImpersonateLoggedOnUser、SetThreadToken等。

五、防御措施
------

1. 限制权限。

删除不必要的用户或组，只保留需要具备这些权限的用户或组

1） 创建令牌对象的权限设置，通过GPO策略：计算机配置 &gt; Windows 设置 &gt; 安全设置 &gt; 本地策略 &gt; 用户权限分配：创建令牌对象。

![17](https://shs3.b.qianxin.com/butian_public/f4029731c883089c639218954c64bea774ebcf57ec7dc.jpg)

2） 限制谁可以通过 GPO 创建仅本地和网络服务的进程级令牌：计算机配置 &gt; \[策略\] &gt; Windows 设置 &gt; 安全设置 &gt; 本地策略 &gt; 用户权限分配：替换进程级令牌。

![18](https://shs3.b.qianxin.com/butian_public/f646191ab98c4a798173cd1c95879ea00bc2d5e256782.jpg)

攻击者必须已经在本地系统上拥有管理员级别的访问权限才能充分利用此技术；确保将用户和帐户限制为所需的最低权限；

2. 及时安装微软推送的补丁，不要使用来路不明的软件；
3. 对令牌的时效性进行限制，越短越好；
4. 采用加密存储和多重验证保护；
5. 加密链路防止中间人窃听；
6. 为了防止域管理员的令牌被窃取，应该禁止域管理员登录其它主机。如果登录了，使用完后应该及时重启电脑，清除令牌。

六、参考文章
------

\[1\] <https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Token%E7%AA%83%E5%8F%96%E4%B8%8E%E5%88%A9%E7%94%A8>

\[2\]<https://www.secpulse.com/archives/131423.html>

\[3\]<https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688>

\[4\]<https://gist.github.com/vector-sec/a049bf12da619d9af8f9c7dbd28d3b56#file-get-token-ps1>

\[5\]<https://attack.mitre.org/techniques/T1134/001/>