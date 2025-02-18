### 禁止任何公众号/营销号转发

在过去几年中，Windows 内核利用变得越来越复杂，尤其是随着 Windows 10 的发布及其连续的核心更新。除了内核利用之外，还可以通过其他方式滥用令牌特权。在服务帐户遭到破坏且启用了非标准权限的情况下，通常可以利用它们来获得本地特权提升。

Token Overview
==============

我们滥用令牌特权的基础源于 Windows 中对象访问控制模型的核心。Windows 使用令牌对象来描述特定线程或进程的安全上下文。这些由 `nt!_TOKEN` 结构表示的令牌对象包含大量安全和参考信息，包括完整性级别、特权、组等。我们的重点在于这些令牌中包含的特权部分。

Windows Privilege Model
-----------------------

系统上的每个进程都在其 [`EPROCESS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess) 结构中持有一个令牌对象引用，以便在对象访问协商或特权系统任务期间使用，如下所示。此令牌在登录过程中通过 LSASS 授予，因此会话中的所有进程最初都在同一令牌下运行。

```ruby
kd> dt _eprocess ffffa88e400d0080
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   // ...
   +0x358 ExceptionPortState : 0y000
   +0x360 Token            : _EX_FAST_REF
   +0x368 MmReserved       : 0
   +0x370 AddressCreationLock : _EX_PUSH_LOCK
   +0x378 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x380 RotateInProgress : (null) 
   +0x388 ForkInProgress   : (null) 
   // ...
```

一个进程持有一个主令牌，在进程中执行的线程继承这个相同的令牌。当线程需要使用一组不同的凭据访问对象时，它可以使用模拟令牌。使用模拟令牌不会影响主令牌或其他线程，只会在模拟线程的上下文中执行。这些模拟令牌可以通过内核提供的许多不同的 API 获得。

令牌用作进程访问票证，必须提交给 Windows 中的各种看门人，并在访问对象时通过 `SeAccessCheck()` 函数进行评估，在特权操作期间通过 `SeSinglePrivilegeCheck()` 函数进行评估。例如，当进程请求对文件的写访问权时，`SeAccessCheck()` 函数将评估令牌完整性级别，然后评估其自主访问控制列表（DACL）。 当进程试图通过 `NtShutdownSystem()` 关闭系统时，内核将评估请求进程令牌是否启用了 `SeShutdownPrivilege` 特权。

Token Structure and Privileges
------------------------------

如前所述，`_TOKEN` 结构主要包含有关进程或线程的安全上下文信息，如下所示：

```ruby
kd> dt _TOKEN ffff838b73a1a6b0
nt!_TOKEN
   +0x000 TokenSource      : _TOKEN_SOURCE
   +0x010 TokenId          : _LUID
   +0x018 AuthenticationId : _LUID
   +0x020 ParentTokenId    : _LUID
   +0x028 ExpirationTime   : _LARGE_INTEGER 0x7fffffff`ffffffff
   +0x030 TokenLock        : 0xffffa88e`3fccb590 _ERESOURCE
   +0x038 ModifiedId       : _LUID
   +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
   +0x058 AuditPolicy      : _SEP_AUDIT_POLICY
   +0x078 SessionId        : 1
   +0x07c UserAndGroupCount : 0x13
   +0x080 RestrictedSidCount : 0
   +0x084 VariableLength   : 0x2a4
   +0x088 DynamicCharged   : 0x1000
   +0x08c DynamicAvailable : 0
   +0x090 DefaultOwnerIndex : 4
   +0x098 UserAndGroups    : 0xffff838b`73a1ab40 _SID_AND_ATTRIBUTES
   +0x0a0 RestrictedSids   : (null) 
   +0x0a8 PrimaryGroup     : 0xffff838b`740c1b10 Void
   +0x0b0 DynamicPart      : 0xffff838b`740c1b10  -> 0x501
   +0x0b8 DefaultDacl      : 0xffff838b`740c1b2c _ACL
   +0x0c0 TokenType        : 1 ( TokenPrimary )
   +0x0c4 ImpersonationLevel : 0 ( SecurityAnonymous )
   +0x0c8 TokenFlags       : 0x2000
   +0x0cc TokenInUse       : 0x1 ''
   +0x0d0 IntegrityLevelIndex : 0x12
   +0x0d4 MandatoryPolicy  : 3
   +0x0d8 LogonSession     : 0xffff838b`720fc840 _SEP_LOGON_SESSION_REFERENCES
   +0x0e0 OriginatingLogonSession : _LUID
   +0x0e8 SidHash          : _SID_AND_ATTRIBUTES_HASH
   +0x1f8 RestrictedSidHash : _SID_AND_ATTRIBUTES_HASH
   +0x308 pSecurityAttributes : 0xffff838b`7163e6d0 _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
   +0x310 Package          : (null) 
   +0x318 Capabilities     : (null) 
   +0x320 CapabilityCount  : 0
   +0x328 CapabilitiesHash : _SID_AND_ATTRIBUTES_HASH
   +0x438 LowboxNumberEntry : (null) 
   +0x440 LowboxHandlesEntry : (null) 
   +0x448 pClaimAttributes : (null) 
   +0x450 TrustLevelSid    : (null) 
   +0x458 TrustLinkedToken : (null) 
   +0x460 IntegrityLevelSidValue : (null) 
   +0x468 TokenSidValues   : (null) 
   +0x470 IndexEntry       : 0xffff838b`7281a370 _SEP_LUID_TO_INDEX_MAP_ENTRY
   +0x478 DiagnosticInfo   : (null) 
   +0x480 BnoIsolationHandlesEntry : (null) 
   +0x488 SessionObject    : 0xffffa88e`3a33e180 Void
   +0x490 VariablePart     : 0xffff838b`73a1ac70
```

我们关注的重点是该结构中的 `_SEP_TOKEN_PRIVILEGES` 条目，位于 0x40 偏移量处，包含令牌特权信息：

```ruby
kd> dt nt!_SEP_TOKEN_PRIVILEGES ffff838b73a1a6b0+0x40
   +0x000 Present          : 0x0000001e`73deff20
   +0x008 Enabled          : 0x60800000
   +0x010 EnabledByDefault : 0x60800000
```

`Present` 条目是一个 unsigned long long 型，其中包含令牌的当前特权。这并不意味着它们被启用或禁用，而只是它们存在于令牌上。创建令牌后，您无法为其添加特权，而只能启用或禁用在此字段中找到的现有项。第二个字段 `Enabled` 也是一个 unsigned long long 型，其中包含令牌上所有已启用的特权。特权必须在此位掩码中启用才能通过 `SeSinglePrivilegeCheck()` 的评估。最后一个字段 `EnabledByDefault` 表示令牌在构造时的默认状态。可以通过调整这些字段中的特定位来启用或禁用特权。

尽管从表面上看，为各种任务定义特定特权的令牌安全模型似乎允许实施特定于服务的细粒度访问控制，但仔细观察会发现更复杂的情况。许多权限在启用时允许用户执行可导致权限提升的特权操作。

Enable Privileges for Process
-----------------------------

通过 Windows 的 `AdjustTokenPrivileges()` 函数，能够启用或禁用指定访问令牌中的特权。在访问令牌中启用或禁用特权需要 `TOKEN_ADJUST_PRIVILEGES` 访问权限。如下给出示例代码。

```c++
#include <Windows.h>
#include <stdio.h>

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
    BOOL status = FALSE;
    LUID luidValue = { 0 };
    TOKEN_PRIVILEGES tokenPrivileges;

    // Get the LUID value of the privilege for the local system
    if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
    {
        wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
        return status;
    }

    // Set escalation information
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luidValue;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Elevate Process Token Access
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
    {
        wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
        return status;
    }
    else
    {
        status = TRUE;
    }
    return status;
}

int wmain(int argc, wchar_t* argv[])
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
        return 0;
    }

    // Enable SeDebugPrivilege for the current process token.
    if (!EnableTokenPrivilege(hToken, SeDebugPrivilege))
    {
        wprintf(L"[-] Failed to enable privilege.\n", GetLastError());
        return 0;
    }
}
```

Token Impersonation
-------------------

在深入研究特权之前，我们先介绍一下 “令牌模拟级别” 得概念描述，这是用于确定特定线程是否可以使用给定令牌的 Windows 机制。任何用户都可以获得特权令牌的句柄，但能否实际使用它是另一回事。

在 Windows 中，“令牌模拟” 是指将新令牌分配给不同于父进程令牌的线程。尽管 “模拟” 一词暗示一个用户正在使用属于另一个用户的令牌，但情况并非总是如此。用户可以模拟属于他们的令牌，但只是具有一组不同的特权或一些其他修改。

每个令牌中的 ImpersonationLevel 字段是令牌模拟级别，该字段控制该令牌是否可用于模拟目的以及在何种程度上进行模拟。有以下四种模拟级别：

| 模拟级别 | 说明 |
|---|---|
| SecurityAnonymous | 服务器进程无法获取客户端的身份信息，也无法模拟客户端。 |
| SecurityIdentification | 服务器可以获得客户端的身份和权限，但不能模拟客户端。 |
| SecurityImpersonation | 服务器进程可以在其本地系统上模拟客户端的安全上下文。服务器无法模拟远程系统上的客户端。 |
| SecurityDelegation | 服务器进程可以在远程系统上模拟客户端的安全上下文。 |

SecurityImpersonation 和 SecurityDelegation 是我们最感兴趣的模拟级别，而 SecurityIdentification 级别及更低级别的令牌不能用于运行代码。

对于是否允许给定用户模拟特定令牌，可以确定如下规则：

> - IF the token level &lt; Impersonate THEN allow (such tokens are called “Identification” level and can not be used for privileged actions).
> - IF the process has “Impersonate” privilege THEN allow.
> - IF the process integrity level &gt;= the token integrity level AND the process user == token user THEN allow ELSE restrict the token to “Identification” level (no privileged actions possible).

Use WinDbg to modify the token of the process to elevate privileges
-------------------------------------------------------------------

我们以 cmd.exe 进程为例，将普通用户启动的 cmd.exe 进程的 Token，替换为 SYSTEM 权限进程的 Token，以提升 cmd.exe 进程的权限。

首先以普通用户 Marcus 启动一个 cmd.exe 进程，如下图所示。

![image-20230619202940652](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1319f2226abd541bb54cfb5d2580209fea4d13d9.png)

在 WinDbg 中找到该进程的地址并列出相关信息：

```cmd
!process 0 1 cmd.exe
```

![image-20230619203338052](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b5c2452bcf8bc927d30205ee4f4ecbc304935977.png)

可以看到该进程的 `EPROCESS` 结构地址为 `ffffb1863f6b2080`，查看该进程的 `EPROCESS` 结构：

```cmd
dt _eprocess ffffb1863f6b2080
```

![image-20230619203727523](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8e352ed028907795cb34546c8d18d7216708fe59.png)

可知该进程的 Token 在 `EPROCESS` 结构的 `0x360` 偏移处，查看该进程的 Token:

```cmd
dd ffffb1863f6b2080+0x360
```

![image-20230619203909416](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a83d15f2c7aaf434ea961a5fc50906e961b810e7.png)

同理，我们可以得到 lsass.exe 进程的 Token，地址为 `ffffb1863bda8080+0x360`：

```php
dd ffffb1863bda8080+0x360
```

![image-20230619204152580](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9be89eafb6f41fa6e660e30d73c6421e6004133f.png)

最后，用 lsass.exe 进程的 Token 替换 cmd.exe 进程的 Token：

```cmd
ed ffffb1863f6b2080+0x360 0e1d30a4
```

![image-20230619204425805](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-986f259eff8338f269e7557221ef27111c581d3b.png)

如下图所示，cmd.exe 进程的权限成功提升至 SYSTEM。

![image-20230619204522895](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3158504de3f2ab7111b4749af30267d8587f0011.png)