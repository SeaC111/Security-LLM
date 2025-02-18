0x00 前言:
========

YARA 通常是帮助恶意软件研究人员识别和分类恶意软件样本的工具，它基于文本或二进制模式创建恶意样本的描述规则，每个规则由一组字符串和一个布尔表达式组成，这些表达式决定了它的逻辑。

但是这次我们尝试使用 YARA 作为一种扫描工具，我们根据要扫描的红队工具提取出它们特有的二进制或文本特征，希望能整理成能唯一标识该类（不同版本）的红队工具的 YARA 规则，用于对特定主机扫描时可以快速识别该主机上是否存在对应的红队工具，以加强对目标主机的了解。

0x01 发生背景：
==========

有一天师兄给了我一个红队工具网站 <https://github.com/Threekiii/Awesome-Redteam> ，说让我对里面的红队工具做一下Yara 规则？？？

一开始我也是很懵的，我也不解为什么要对工具做 Yara 规则，因为 Yara 的确是用于提取分析恶意样本的啊。我一开始猜想是有可能是这些工具被装了后门，毕竟这种情况网上太多了，然后我就打开上面的 github 网站，仔细浏览了一下。

真的，不得不说这个网站太全了，太赞了！真的不得不佩服作者的良苦用心，所以这样一个 1.4k stats 的如此优秀的项目会有后门？？？

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b2f40c4406bf8ce8bddfb317f14eedc672eb3579.png)

谁知道呢，下个 BP 插件目录下的 RouteVulScan——检测脆弱路径插件 扔进 VT 上看一下先：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-09fcdd1c184ab78d77585de0be8388e08ba718e3.png)

。。。有点绿啊~ 陆陆续续又试了几个，除了几个有点误报外基本都是没问题的，不得不说项目的作者还是很好的，所以这咋提取后门啊！

然后我和师兄吐槽说这些都是普通的工具啊，这怎么做 Yara 规则啊，做来干什么啊？师兄耐心的和我解释说："一台目标主机上如果出现这些红队工具的话那是很可疑的事情，如果我们在目标内网的一台主机上扫描到这种工具的存在那我们就可以更加掌握这台主机的了解，可以判断使用者用它干了什么之类的……"

一语惊醒梦中人！我觉得非常有道理！就用 Yara 对这些红队工具打标嘛，类似一种本地软件识别工具。至于怎么打进内网？那不是我该考虑的问题。

0x02 明确要求——初步制定方案：
==================

要做的是扫描器，平常对恶意样本做 yara 规则是通过仔细逆向来分析获取该类样本特有的混淆、固定的功能代码、特有的字符串等等能标识这一类样本的信息。

那现在正常的软件怎么分析呢，一个个逆向是不可能的，我甚至都不想扔入 IDA 里，因为这是一批工具，量大。然后就是不适合，因为很多工具我没用过，不知道功能，反汇编看了耗时耗力。最后就是没必要，我们只是用 yara 对它们打标，工具和工具相差性还是很大的，无论是字符串还是字节码，而且文件体积上很多也不是一个量级的，随便提取一点能够标识的就够了。

所以综合以上考虑我决定用字节码查看工具 010 Editor ，我使用文件比较功能把不同版本的大块的可标识该类软件的字节码提取出来，右侧的 ASCII/UNICODE 字符串栏中也可以提取自己仍未足够独特的字符串来写成 Yara 规则。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-64b9b3b71ca782d8f3156208839a3a850dca8d80.png)

尝试对 BP 插件写 Yara 规则：
-------------------

先从 "RouteVulScan——检测脆弱路径插件" 下手，拿最新的前 3 个打包好的 jar 版本开始比较，这里先拿其中两个版本进行比较，从众多相同的字节码中挑选大块的，并且自己感觉能标识该插件唯一性的作为 Yara 规则。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b129f36488280cf8391dbc1d711c1511a32dbd62.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6931ddb858c3d762493d6a74f4ce18e0cdba498b.png)

把字节码作为字符串，然后条件那里再加点限制，比如 jar 插件本质是压缩包，所以我们限制文件头为 "PK"，对应 Yara 规则就是 int16(0)=0x4B50 ，然后在文件体积上也精确一点，这里三个版本的 jar 插件都在 30MB 以上，写成 Yara 规则就是 filesize &gt; 30MB，最终 Yara 规则如下：

```c
rule routevulscan {
   meta:
    description = "Choose commonalities from multiple versions"
   strings:
    $s1 = {00 00 00 62 75 72 70 2F 56 69 65 77 24 54 61 62 6C 65 2E 63 6C 61 73 73 85 52 4D 6F D3 40 10 7D EB 38 71 9D 98 34 2D 0D 50 D2 96 06 92 92 A4 A1 2E DF 12 45 BD 44 80 82 0C 1C 8A 72 C8 CD 71 57 CE 56 C6 46 8E 43}
   condition:
        ( uint16(0) == 0x4B50 and filesize > 30MB) and $s1
```

对自己整个 D 盘文件全范围测试一下，避免误报：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-435a294b8584097a81a73072612ab4267e2b5de9.png)

可以看到在较大环境中测试也是可以的，没有匹配到杂七杂八的其它 jar 包（也可能是我的本地环境比较简单），那么同理我们把剩下两个 Log4j2Scan、HaE 的 Yara 规则也写出来，并在本地环境中测试一下命中及误报情况：

```c
rule Log4j2Scan {
   meta:
    description = "Choose commonalities from multiple versions"
   strings:
    $s1 = {32 00 63 6F 6D 2F 61 6C 69 62 61 62 61 2F 66 61 73 74 6A 73 6F 6E 2F 4A 53 4F 4E 50 61 74 68 24 46 6C 6F 6F 72 53 65 67 6D 65 6E 74 2E 63 6C 61 73 73 50 4B 01 02 14 00 14 00 08 08 08 00 72 07 B7 54 00 00 00 00 02 00 00 00 00 00 00 00 1B 00 00 00 00 00 00 00 00 00 00 00 00 00}
   condition:
        ( uint16(0) == 0x4B50 and filesize > 3MB) and $s1
}

rule HaE {
   meta:
    description = "Choose commonalities from multiple versions"
   strings:
    $s1 = {03 00 00 AA 06 00 00 33 00 00 00 62 75 72 70 2F 75 69 2F 4A 54 61 62 62 65 64 50 61 6E 65 43 6C 6F 73 65 42 75 74 74 6F 6E 24 43 6C 6F 73 65 42 75 74 74 6F 6E 54 61 62 2E 63 6C 61 73 73 9D 55}
   condition:
        ( uint16(0) == 0x4B50 and filesize < 2MB) and $s1
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-99afff8ed937c3e9d447a6caa975b530cedc7896.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-488de57b6331f6459bf85da73baf88a6ca57a46b.png)

0x03 二次制定方案——寻找"检测面"：
=====================

前面初步制定的方案很快就发现不够用了，因为受制于寻找文件之间的相同性，所以面向的对象都是单一的或少数不多的整合型的 releases 版本，但其实有很多不是单独的文件形式，比如说 Yakit 这种大型工具，Py2exe 和 PyInstaller 这些 python 打包工具，那这其实就得换个思路了。

一开始我想和别的扫描工具一样去检查这些工具文件夹内某个特殊文件是否存在来判定该工具，但是想了想还是统一用 Yara 规则吧，毕竟我们要统一可用性，就不用切来切去了。

所以我要找有几个有代表性的文件来检测，即 "检测面"。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d72f13dfc8389de59d780b5695532ae89606933c.png)

yarGen 工具利用：
------------

由于这些大型工具我基本没用过，哪怕是用过的 Py2exe 和 PyInstaller 也只是会用而已，所以哪里会知道哪些文件是有代表性的关键文件？从几十个几百个文件中逐个挑选来尝试可不是明智的选择，所以我在网络上看到了一个自动 Yara 生成工具 [yarGen](https://github.com/Neo23x0/yarGen)。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e3b8ed5cba0cfd0de7fc886406cb180eac49b72a.png)

yarGen 原理是从样本中提取所有 ASCII 和 UNICODE 字符串，并删除同时出现在 goodware 字符串数据库中的所有字符串。然后，它使用模糊正则表达式和 “乱码检测器” 对每个字符串进行评估和评分，该检测器允许 yarGen 检测和偏向真实语言而不是没有意义的字符链，前 20 个字符串将集成到生成的规则中。它能尝试识别要分析的文件之间的相似性，然后将字符串组合成所谓的 "超级规则"。

但是自动生成的 Yara 规则总是不如手工准确，yarGen 项目的作者也注意到了这一点，所以我们在其自动生成的规则上还需要进行手工调整，调整总归比自己从0到1做一个强，所以还是决定用上这个工具。

如何编写合理有效的 Yara 规则：
------------------

从 [Nextron](https://www.nextron-systems.com/) 公司博客站上[如何构建最佳 Yara 规则](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/)的文章中我们知道一个有效的 Yara 规则不应该太简单，不然它会产生许多误报的规则，也不应该太复杂，否则它仅能匹配特定样本而且不比散列值好多少。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d280183c85969bce914b95fac847d954faee85e6.png)

**yarGen 检查所有字符串并将它们分为以下类别：**

- 非常具体的字符串（检测的硬指标,例如 IP 地址、有效负载 URL、PDB 路径、用户配置文件目录，错别字语意字符串）
- 稀有字符串（有几率在正常软件中出现,例如 “wwwlib.dll”）
- 看起来很常见的字符串（并不具体但不会在好软件中出现，比如乱码字符串等）。

yarGen 推崇 Unicode 字符串优先级大于 ASCII 字符串，自动生成规则的字符串区中以 $s 开头的为硬指标字符串，以 $x 开头的为稀有字符串，以 $z 开头的为看起来很常见的字符串，以 $a 开头的字符串是不确定它们是否不会出现在合法软件中。那么对于这种权重不同的字符串我们可以在限制条件上也体现出来：( 1 of $s *) and ( 2 of $x* ) and ( 5 of $z *) and (all of $a* ) 。

**举个例子如下**：

```C
rule an_example {

meta:

description = “This is just an example”

strings:

$s1 = “Micorsoft Corportation” fullword wide

$s2 = “IM Monnitor Service” fullword wide

$x1 = “imemonsvc.dll” fullword wide

$x2 = “iphlpsvc.tmp” fullword

$x3 = “{53A4988C-F91F-4054-9076-220AC5EC03F3}” fullword

$z1 = “urlmon” fullword

$z2 = “Registered trademarks and service marks are the property of their” wide

$z3 = “XpsUnregisterServer” fullword

$z4 = “XpsRegisterServer” fullword

condition:

int16(0) == 0x4D5A and (( 1 of ($s*) ) or ( 2 of ($x*) and all of ($z*) )) and filesize < 40000

}
```

但有时候并不能提取出足够的规则，特别是对于我做规则的对象有些完全就是合法的，比如 py2exe 和 pyinstall 或 HFish 蜜罐等，他们甚至没法自动生成出规则！  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-11a74a41c6bc38d20abb3bc4d8360df1457e2467.png)

这种情况在[如何构建最佳 Yara 规则 - 第 2 部分 ](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)中其实也提及了，我们可以多思考一下限制条件，比如魔术头、文件大小、字符串位置等（前面两个我一直在用，字符串位置我们做像 metasploit 、Cobaltstrike 等渗透测试，木马生成工具时再详细讲）。

对于我现在的情况其实我们可以简单一点，比如不断换个 "检测面"（反正也是自动生成），或者照第一个方案那样手动挑两个文件组成的 "检测面"来进行字节码比对挑共性即可（主要挑的应该是 exe、dll 等 PE 格式的文件，因为这些文件通常比较关键）

实践尝试——pyinstall：
----------------

以 pyinstall 为例，前面说过最好选择 PE 格式文件，所以我在文件夹目录中定位到了 Pyinstall\\PyInstaller\\bootloader\\Windows-64bit ：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2f04fd1cd87b78388a67b32c72f8098fcc56a14e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9291d793f2284a79141ca47041483a6a5c0437ba.png)

yarGen 生成的规则，这其中把有交集的文件都写出了超级规则：

```c
/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2022-09-18
   Identifier: Windows-64bit
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

/* Super Rules ------------------------------------------------------------- */

rule _run_runw_runw_d_run_d_0 {
   meta:
      description = "Windows-64bit - from files run.exe, runw.exe, runw_d.exe, run_d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-09-18"
      hash1 = "1b184fb48ed8394eea4e3f181156653ebc4a7bd457ccca45736c5140ae191e8c"
      hash2 = "2de57a934dacbf12e1ce942d58f9a34c5ac611da4759400fca3f2ab6a2090e6e"
      hash3 = "948a6e2cb814b1120bec89678d6370b72341a7dba8a6aa68b3e237caf1f53521"
      hash4 = "d5c25b8c43e0f88bab93a0f47192e4ccc2be481ef32dcefe185eb46b3952d5a0"
   strings:
      $s1 = "Failed to get address for Tcl_FindExecutable" fullword ascii
      $s2 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii
      $s3 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii
      $s4 = "Failed to get address for Tcl_MutexUnlock" fullword ascii
      $s5 = "Failed to get address for Tcl_MutexLock" fullword ascii
      $s6 = "Failed to extract %s: failed to open target file!" fullword ascii
      $s7 = "LOADER: Failed to convert runtime-tmpdir to a wide string." fullword ascii
      $s8 = "LOADER: Failed to expand environment variables in the runtime-tmpdir." fullword ascii
      $s9 = "LOADER: Failed to obtain the absolute path of the runtime-tmpdir." fullword ascii
      $s10 = "Failed to get executable path." fullword ascii
      $s11 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s12 = "LOADER: Failed to set the TMP environment variable." fullword ascii
      $s13 = "Path of ucrtbase.dll (%s) length exceeds buffer[%d] space" fullword ascii
      $s14 = "Failed to get address for Tcl_FinalizeThread" fullword ascii
      $s15 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii
      $s16 = "Failed to get address for Tcl_CreateObjCommand" fullword ascii
      $s17 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii
      $s18 = "Failed to get address for Tcl_ThreadAlert" fullword ascii
      $s19 = "Failed to get address for Tcl_GetCurrentThread" fullword ascii
      $s20 = "Failed to get address for Tcl_ThreadQueueEvent" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _runw_d_run_d_1 {
   meta:
      description = "Windows-64bit - from files runw_d.exe, run_d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-09-18"
      hash1 = "948a6e2cb814b1120bec89678d6370b72341a7dba8a6aa68b3e237caf1f53521"
      hash2 = "d5c25b8c43e0f88bab93a0f47192e4ccc2be481ef32dcefe185eb46b3952d5a0"
   strings:
      $s1 = "LOADER: ucrtbase.dll found: %s" fullword ascii
      $s2 = "LOADER: Creating child process" fullword ascii
      $s3 = "LOADER: Already in the child - running user's code." fullword ascii
      $s4 = "LOADER: SetDllDirectory(%S)" fullword ascii
      $s5 = "LOADER: Coping file %s to %s" fullword ascii
      $s6 = "LOADER: temppath exceeds PATH_MAX" fullword ascii
      $s7 = "LOADER: Executing self as child" fullword ascii
      $s8 = "LOADER: temppath is %s" fullword ascii
      $s9 = "LOADER: Running %s.py" fullword ascii
      $s10 = "LOADER: Error extracting binaries" fullword ascii
      $s11 = "LOADER: failed to unmarshal code object for %s!" fullword ascii
      $s12 = "LOADER: Successfully resolved the specified runtime-tmpdir" fullword ascii
      $s13 = "LOADER: failed to read chunk (%zd bytes)!" fullword ascii
      $s14 = "LOADER: absolute runtime tmpdir is %ls" fullword ascii
      $s15 = "LOADER: Found runtime-tmpdir %s" fullword ascii
      $s16 = "LOADER: Waiting for child process to finish..." fullword ascii
      $s17 = "LOADER: failed to allocate read buffer (%d bytes)!" fullword ascii
      $s18 = "LOADER: Getting file from archive." fullword ascii
      $s19 = "LOADER: Cookie found at offset 0x%llX" fullword ascii
      $s20 = "LOADER: Post-init sys.path is %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _runw_runw_d_2 {
   meta:
      description = "Windows-64bit - from files runw.exe, runw_d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-09-18"
      hash1 = "2de57a934dacbf12e1ce942d58f9a34c5ac611da4759400fca3f2ab6a2090e6e"
      hash2 = "948a6e2cb814b1120bec89678d6370b72341a7dba8a6aa68b3e237caf1f53521"
   strings:
      $s1 = "Failed to execute script '%ls' due to unhandled exception: %ls" fullword wide
      $s2 = "Traceback is disabled via bootloader option." fullword ascii
      $s3 = "Unhandled exception in script" fullword wide
      $s4 = "Fatal error detected" fullword ascii
      $s5 = "Error detected" fullword ascii
      $s6 = "Failed to obtain/convert traceback!" fullword wide
      $s7 = "pyi-disable-windowed-traceback" fullword ascii
      $s8 = "format_exception" fullword ascii
      $s9 = "T$hfD+D$df+T$`" fullword ascii
      $s10 = "T$<f+T$4" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( all of them )
      ) or ( all of them )
}

rule _run_run_d_3 {
   meta:
      description = "Windows-64bit - from files run.exe, run_d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-09-18"
      hash1 = "1b184fb48ed8394eea4e3f181156653ebc4a7bd457ccca45736c5140ae191e8c"
      hash2 = "d5c25b8c43e0f88bab93a0f47192e4ccc2be481ef32dcefe185eb46b3952d5a0"
   strings:
      $s1 = "Failed to execute script '%s' due to unhandled exception!" fullword ascii
      $s2 = "Failed to get ANSI buffer size." fullword ascii
      $s3 = "Failed to encode filename as ANSI." fullword ascii
      $s4 = "lambda: None))()" fullword ascii
      $s5 = "import sys; sys.stderr.flush();                 (sys.__stderr__.flush if sys.__stderr__                 is not sys.stderr else (" ascii
      $s6 = "import sys; sys.stdout.flush();                 (sys.__stdout__.flush if sys.__stdout__                 is not sys.stdout else (" ascii
      $s7 = "import sys; sys.stderr.flush();                 (sys.__stderr__.flush if sys.__stderr__                 is not sys.stderr else (" ascii
      $s8 = "import sys; sys.stdout.flush();                 (sys.__stdout__.flush if sys.__stdout__                 is not sys.stdout else (" ascii
      $s9 = "win32_wcs_to_mbs" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( all of them )
      ) or ( all of them )
}

```

根据描述我们知道第一个是包含 4 个文件的真正超级规则，所以我们单独提取出来进行修改：

```C
rule _run_runw_runw_d_run_d_0 {
   meta:
      description = "Windows-64bit - from files run.exe, runw.exe, runw_d.exe, run_d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-09-18"
      hash1 = "1b184fb48ed8394eea4e3f181156653ebc4a7bd457ccca45736c5140ae191e8c"
      hash2 = "2de57a934dacbf12e1ce942d58f9a34c5ac611da4759400fca3f2ab6a2090e6e"
      hash3 = "948a6e2cb814b1120bec89678d6370b72341a7dba8a6aa68b3e237caf1f53521"
      hash4 = "d5c25b8c43e0f88bab93a0f47192e4ccc2be481ef32dcefe185eb46b3952d5a0"
   strings:
      $s1 = "Failed to get address for Tcl_FindExecutable" fullword ascii
      $s2 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii
      $s3 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii
      $s4 = "Failed to get address for Tcl_MutexUnlock" fullword ascii
      $s5 = "Failed to get address for Tcl_MutexLock" fullword ascii
      $s6 = "Failed to extract %s: failed to open target file!" fullword ascii
      $s7 = "LOADER: Failed to convert runtime-tmpdir to a wide string." fullword ascii
      $s8 = "LOADER: Failed to expand environment variables in the runtime-tmpdir." fullword ascii
      $s9 = "LOADER: Failed to obtain the absolute path of the runtime-tmpdir." fullword ascii
      $s10 = "Failed to get executable path." fullword ascii
      $s11 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s12 = "LOADER: Failed to set the TMP environment variable." fullword ascii
      $s13 = "Path of ucrtbase.dll (%s) length exceeds buffer[%d] space" fullword ascii
      $s14 = "Failed to get address for Tcl_FinalizeThread" fullword ascii
      $s15 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii
      $s16 = "Failed to get address for Tcl_CreateObjCommand" fullword ascii
      $s17 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii
      $s18 = "Failed to get address for Tcl_ThreadAlert" fullword ascii
      $s19 = "Failed to get address for Tcl_GetCurrentThread" fullword ascii
      $s20 = "Failed to get address for Tcl_ThreadQueueEvent" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}
```

因为都是 $s 开头的，也就是说 yarGen 认为这 20 个字符串都是具体特殊且不包含在原生 goodware 字符串数据库中的，但是这对我来说还是太多太具体了，所以我们也不用修改，删减一点就好啦：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-61b52c2c188fb0d2f0d3c49de1f82622ad5eddd0.png)

```c
rule pyinstall {
   meta:
      description = "the_part_for_extracting_the_yara - from files run.exe, runw.exe, runw_d.exe, run_d.exe"
      hash1 = "1b184fb48ed8394eea4e3f181156653ebc4a7bd457ccca45736c5140ae191e8c"
      hash2 = "2de57a934dacbf12e1ce942d58f9a34c5ac611da4759400fca3f2ab6a2090e6e"
      hash3 = "948a6e2cb814b1120bec89678d6370b72341a7dba8a6aa68b3e237caf1f53521"
      hash4 = "d5c25b8c43e0f88bab93a0f47192e4ccc2be481ef32dcefe185eb46b3952d5a0"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "LOADER: Failed to set the TMP environment variable." fullword ascii
      $s5 = "Path of ucrtbase.dll (%s) length exceeds buffer[%d] space" fullword ascii
      $s6 = "Failed to get address for Tcl_CreateObjCommand" fullword ascii
      $s7 = "Failed to get address for PyRun_SimpleStringFlags" fullword ascii
      $s8 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 5 of them )
      ) or ( all of them )
}

```

在整个D盘上测试一下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9d21804fe483e7e30bb34cfe764657fe88570ff9.png)

实践尝试——HFish：
------------

HFish 有点特殊，我从 yarGen 中无法获取到如下检测面的规则，他们本来就是合法的软件，可能本身所有的字符串都是其它合法软件通用的。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2c3a55f5240da4f9f797f2ff8dfc9a4d53590f70.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4163c438da23c3172595caa89bf1b401cc430bbd.png)

所以和前面我们说的一样，我们换个思路，照第一个方案那样手动挑两个文件组成的 "检测面"来进行字节码比对挑共性即可，这里我梦两个项目名的可执行文件来比较，因为我觉得它们足够唯一！  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0628e9242669dff2e7312ad834cef817e68973e4.png)

```C
rule HFish
{
    meta:
        descript = "The main executables for windows and linux are selected here"
        hash1 = "b4187ab0a33c0fe32be635f08d39baf2"
        hash2 = "5c4a5bfeaf29085567d34fb0bc135e5a"
    strings:
        $s1 = {FF 48 8B 6C 24 20 48 83 C4 28 C3 48 89 44 24 08 48 89 5C 24 10 48 89 4C 24 18 48 89 7C 24 20 E8} 
        $s2 = {A7 FF 48 8B 44 24 08 48 8B 5C 24 10 EB AF 4C 8D 6C 24 20 4D 39 2C 24 75 C1 49 89 24 24 EB BB CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 49 3B 66
10 76}
    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x457F ) and filesize < 15MB and all of them
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ff4f2a715dc2f69b9a62ee0eb9a4480e0b0818f7.png)

0x04 小插曲——UPX脱壳加壳的规则匹配：
=======================

在我对 PEID 做 Yara 规则时没有意识滴地查了一下壳，然后又没有意识地用工具脱了壳，然后我愣了，我脱壳干嘛？

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-dbc2c017ad295392155c8c63b7d5c12701231864.png)

然后我想了一下，Yara 是静态扫描工具，对于那些加了混淆或加了壳的我们怎么办，正常情况下是提取样本的混淆特征或加壳后的 "二重特征"，那我这里可不可以从加壳和脱壳后的样本中提取出能识别两个的规则呢?

还真有，这次是只局限于 UPX 壳的，UPX 是压缩壳，体积前后本来就不一样，我尝试用 ResourceHacker 查看资源，看看加壳后有没有什么资源还是可看的，结果发现 ICON 区真的有没改动的地方！

ICON 是程序图标，本来就非常具有唯一性，UPX 压缩原理我没研究过，但可以猜想对资源区和调用资源区的代码没有进行处理，不然一个压缩前后的程序图标怎么还是一样的呢！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e540fd35c27f9f100006c59850030d2907630ea5.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-cf16780a8e2d4675a5566d958e7a2e6f142c44c2.png)

拿着这段资源区的代码就开始写规则，果不其然效果很好：

```c
rule PEID
{
    meta:
        decription = "I think I extracted the only part of the same data that upx compresses the program and it's still there after decompression"
        md5 = "ef2327b387b8e22b186cf935913b05d5"
        rev = 3
    strings:
        $s0 = {28 00 00 00 20 00 00 00 40 00 00 00 01 00 04 00 00 00 00 00 80 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 35 17 00 AF 99 3F 00 77 61 3E 00 E2 DB DB 00 AA 69 1D 00 88 51 12 00 
D2 B9 53 00 BC 86 35 00 5D 4D 3A 00 89 83 7E 00 CB A3 4A 00 FA F7 FA 00 9D 91 90 00 C3 BD B7 00 A9 A1 96 00 77 6D 62 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 47 77 AA 66 66 66 66 A6 AA A7 74 44 44 55 55 44 47 7A 7A 66 66 66 66 6A AA A7 74 44 55 52 20 44 44 77 77 7A 66 66 6A AA AA A7 44 45 55 5C 98 55 44 45 44 77 11 1A A1 17 77 47 44 55 55 59 CF F8 88 88 2F 88 52 88 12 28 28 85 44 45 55 02 3C FE E8 2E EC DD 89 D9 2E DE CD E5 45 55 50 58 3C 8E E8 8D C8 9F 2F DC 59 3E 23 E8 45 50 00 00 ED 0F DF 8D C2 88 08 3E 82 3D 8E D2 55 5C 99 FF FD 88 D9 0E D9 CD C8 ED 88 DD 8F 39 55 5C EE C9 0D 90 DE 8F DF 8D E0 9D 20 ED F2 3C 04 5F DE C9 8E E8 ED 82 DE 2D E8 8D 90 9D E8 DE 05 52 DE C9 08 88 88 00 22 88 80 02 80 0F 2F DE 85 55 EC C9 F8 80 88 80 88 08 88 88 80 88 00 FD F5 55 EC 99 F9 CC 99 F8 00 99 99 99 E9 FF F0 8E F5 55 CE CC DE CD CF FF 00 C9 CE ED D3 D9 F8 05 55 55 9D EE D8 0C DC 99 00 CE DD 38 0B B3 D9 00 55 55 83 EE EF 08 3D DE 00 F3 33 38 0E 3B 33 05 55 55 53 3E DE 00 B3 3D 90 8B BB 39 00 00 00 00 55 55 5E BD DD 00 3B B3 D0 0B BB 3C 88 88 08 00 55 55 59 B3 33 80 FB BB 30 0D BB BB 33 3D C9 F0 55 55 55 B3 33 C0 03 BB BF 09 BB BB 3E BB BB D0 55 55 55 3D D3 30 8D BB BD 02 BB BB D0 9B BB B2 55 55 55 D3 D3 30 8E 3B B3 88 3B B3 30 8B BB BC 05 45 55 93 DD 3F 5F 33 33 25 DB 33 38 83 BB BD 55 55 54 23 D3 3C 2C 33 33 C5 CB BB BE 93 BB 3D 85 45 45 4B BB BB BB BB BB E2 2B BB BB BB B3 B3 55 45 44 4C EE EE EE DE DE F4 44 CD EE EE EE E9 54 44 44 44 44 47 77 71 71 71 77 77 77 77 77 44 44 44 44 44 74 74 77 AA AA AA AA A7 A7 77 77 77 44 44 44 74 74 74 77 7A A6 AA 6A 6A A7 A7 7A 77 74 44 44 44 44 44 45 44 44 44 44 44 44 44 44 44 44 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 1MB and $s0
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3409f825c6001ba3838e4e10895203c94574d54a.png)

0x05 三次制定方案——从资源入手：
===================

对于 PE 文件，PEID 的处理给了我一个很好的思维灵感，对于 PE 格式文件我们可以挑选资源来做规则啊！像图标，对话框这种都是很唯一的标识规则，当然这些程序得有资源，像那些只有最后 Mainfest 的版权资源就算了，这些都是通用的。

对 Exeinfope 写 Yara 规则：
----------------------

对于有图标的程序我们应用方案三，这次拿 exeinfope 试一下看看：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c485a30188a9a420c57fc985efac0ea96ae083f3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3228805762b794e89cab0387f6051ca8908e269b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4a4d9d28f77c1c64e50ca97ee5ce8e47c39332ce.png)

抽取小部分图标资源字节码写成 Yara 规则：

```c
rule ExeinfoPe {
   meta:

      hash1 = "7ffcbdedd2fef54b22840be62e0658d2bf203096f33dd9a95bcbb1698d324f42"
   strings:
      $s1 = {3D 32 3D 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 45 3D 2F 36 32 32 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2MB and $s1
}

```

扫描整个磁盘查看命中结果和误报：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fc6e3e2977b0bdcb7638281dcf31d5210348e711.png)

可以发现该方法生成的规则简单可靠的！

0x06 附上我目前整理的一些 Yara 规则：
========================

```c
rule RouteVulScan {
   meta:
    description = "Choose commonalities from multiple versions"
   strings:
    $s1 = {00 00 00 62 75 72 70 2F 56 69 65 77 24 54 61 62 6C 65 2E 63 6C 61 73 73 85 52 4D 6F D3 40 10 7D EB 38 71 9D 98 34 2D 0D 50 D2 96 06 92 92 A4 A1 2E DF 12 45 BD 44 80 82 0C 1C 8A 72 C8 CD 71 57 CE 56 C6 46 8E 43}
   condition:
        ( uint16(0) == 0x4B50 and filesize > 30MB) and $s1
}

rule pyinstall {
   meta:
      description = "the_part_for_extracting_the_yara - from files run.exe, runw.exe, runw_d.exe, run_d.exe"
      hash1 = "1b184fb48ed8394eea4e3f181156653ebc4a7bd457ccca45736c5140ae191e8c"
      hash2 = "2de57a934dacbf12e1ce942d58f9a34c5ac611da4759400fca3f2ab6a2090e6e"
      hash3 = "948a6e2cb814b1120bec89678d6370b72341a7dba8a6aa68b3e237caf1f53521"
      hash4 = "d5c25b8c43e0f88bab93a0f47192e4ccc2be481ef32dcefe185eb46b3952d5a0"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "LOADER: Failed to set the TMP environment variable." fullword ascii
      $s5 = "Path of ucrtbase.dll (%s) length exceeds buffer[%d] space" fullword ascii
      $s6 = "Failed to get address for Tcl_CreateObjCommand" fullword ascii
      $s7 = "Failed to get address for PyRun_SimpleStringFlags" fullword ascii
      $s8 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 5 of them )
      ) or ( all of them )
}

rule py2exe {
   meta:
      description = "I chose 3 py2exe. I think the important files are used for YARA rules matching. They are in the folder of the_part_for_extracting_the_yara"
      hash1 = "1dba26c9ffb5df77c7841baffb80426d7d62dd52772f75fc9d5c23cb8913a48a"
      hash2 = "34ef42ecbabaa459011ef88399b61a7a2c903a50e96430dc0fb40aafdeae29a6"
      hash3 = "901b650d43c2647d5fca39e878f72cf162e9754c49aba40302326b108db6c55f"
   strings:
      $s1 = "py2exe failed to activate the activation context before loading a DLL" fullword ascii
      $s2 = "Could not lock script resource:" fullword ascii
      $s3 = "Could not load script resource:" fullword ascii
      $s4 = "PyModule_GetState" fullword ascii
      $s5 = "_SHGetSpecialFolderPath" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( 3 of them )
      ) or ( all of them )
}

rule PEID
{
    meta:
        decription = "I think I extracted the only part of the same data that upx compresses the program and it's still there after decompression"
        md5 = "ef2327b387b8e22b186cf935913b05d5"
        rev = 3
    strings:
        $s0 = {28 00 00 00 20 00 00 00 40 00 00 00 01 00 04 00 00 00 00 00 80 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 35 17 00 AF 99 3F 00 77 61 3E 00 E2 DB DB 00 AA 69 1D 00 88 51 12 00 
D2 B9 53 00 BC 86 35 00 5D 4D 3A 00 89 83 7E 00 CB A3 4A 00 FA F7 FA 00 9D 91 90 00 C3 BD B7 00 A9 A1 96 00 77 6D 62 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 47 77 AA 66 66 66 66 A6 AA A7 74 44 44 55 55 44 47 7A 7A 66 66 66 66 6A AA A7 74 44 55 52 20 44 44 77 77 7A 66 66 6A AA AA A7 44 45 55 5C 98 55 44 45 44 77 11 1A A1 17 77 47 44 55 55 59 CF F8 88 88 2F 88 52 88 12 28 28 85 44 45 55 02 3C FE E8 2E EC DD 89 D9 2E DE CD E5 45 55 50 58 3C 8E E8 8D C8 9F 2F DC 59 3E 23 E8 45 50 00 00 ED 0F DF 8D C2 88 08 3E 82 3D 8E D2 55 5C 99 FF FD 88 D9 0E D9 CD C8 ED 88 DD 8F 39 55 5C EE C9 0D 90 DE 8F DF 8D E0 9D 20 ED F2 3C 04 5F DE C9 8E E8 ED 82 DE 2D E8 8D 90 9D E8 DE 05 52 DE C9 08 88 88 00 22 88 80 02 80 0F 2F DE 85 55 EC C9 F8 80 88 80 88 08 88 88 80 88 00 FD F5 55 EC 99 F9 CC 99 F8 00 99 99 99 E9 FF F0 8E F5 55 CE CC DE CD CF FF 00 C9 CE ED D3 D9 F8 05 55 55 9D EE D8 0C DC 99 00 CE DD 38 0B B3 D9 00 55 55 83 EE EF 08 3D DE 00 F3 33 38 0E 3B 33 05 55 55 53 3E DE 00 B3 3D 90 8B BB 39 00 00 00 00 55 55 5E BD DD 00 3B B3 D0 0B BB 3C 88 88 08 00 55 55 59 B3 33 80 FB BB 30 0D BB BB 33 3D C9 F0 55 55 55 B3 33 C0 03 BB BF 09 BB BB 3E BB BB D0 55 55 55 3D D3 30 8D BB BD 02 BB BB D0 9B BB B2 55 55 55 D3 D3 30 8E 3B B3 88 3B B3 30 8B BB BC 05 45 55 93 DD 3F 5F 33 33 25 DB 33 38 83 BB BD 55 55 54 23 D3 3C 2C 33 33 C5 CB BB BE 93 BB 3D 85 45 45 4B BB BB BB BB BB E2 2B BB BB BB B3 B3 55 45 44 4C EE EE EE DE DE F4 44 CD EE EE EE E9 54 44 44 44 44 47 77 71 71 71 77 77 77 77 77 44 44 44 44 44 74 74 77 AA AA AA AA A7 A7 77 77 77 44 44 44 74 74 74 77 7A A6 AA 6A 6A A7 A7 7A 77 74 44 44 44 44 44 45 44 44 44 44 44 44 44 44 44 44 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 1MB and $s0
}

rule Log4j2Scan {
   meta:
    description = "Choose commonalities from multiple versions"
   strings:
    $s1 = {32 00 63 6F 6D 2F 61 6C 69 62 61 62 61 2F 66 61 73 74 6A 73 6F 6E 2F 4A 53 4F 4E 50 61 74 68 24 46 6C 6F 6F 72 53 65 67 6D 65 6E 74 2E 63 6C 61 73 73 50 4B 01 02 14 00 14 00 08 08 08 00 72 07 B7 54 00 00 00 00 02 00 00 00 00 00 00 00 1B 00 00 00 00 00 00 00 00 00 00 00 00 00}
   condition:
        ( uint16(0) == 0x4B50 and filesize > 3MB) and $s1
}

rule identYwaf {
   meta:
      hash1 = "cf37c9d7ed9129679fc125d2ab5d2d5953aa333c0a9a894f6b33eab6543320d6"
   strings:
      $s1 = "https://github.com/sqlmapproject/sqlmap/blob/master/lib/core/settings.py" fullword ascii
      $s2 = "https://github.com/sqlmapproject/sqlmap/blob/master/lib/request/basic.py" fullword ascii
      $s3 = "https://myexternalip.com/raw" fullword ascii
      $s4 = "https://stackoverflow.com/a/28052583" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 80KB and 3 of them
}

rule HFish
{
    meta:
        descript = "The main executables for windows and linux are selected here"
        hash1 = "b4187ab0a33c0fe32be635f08d39baf2"
        hash2 = "5c4a5bfeaf29085567d34fb0bc135e5a"
    strings:
        $s1 = {FF 48 8B 6C 24 20 48 83 C4 28 C3 48 89 44 24 08 48 89 5C 24 10 48 89 4C 24 18 48 89 7C 24 20 E8} 
        $s2 = {A7 FF 48 8B 44 24 08 48 8B 5C 24 10 EB AF 4C 8D 6C 24 20 4D 39 2C 24 75 C1 49 89 24 24 EB BB CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 49 3B 66
10 76}
    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x457F ) and filesize < 15MB and all of them
}

rule HaE {
   meta:
    description = "Choose commonalities from multiple versions"
   strings:
    $s1 = {03 00 00 AA 06 00 00 33 00 00 00 62 75 72 70 2F 75 69 2F 4A 54 61 62 62 65 64 50 61 6E 65 43 6C 6F 73 65 42 75 74 74 6F 6E 24 43 6C 6F 73 65 42 75 74 74 6F 6E 54 61 62 2E 63 6C 61 73 73 9D 55}
   condition:
        ( uint16(0) == 0x4B50 and filesize < 2MB) and $s1
}

rule dirsearch {
   meta:
      hash1 = "076ea463a7dca58dd90673b1a4c1128a1fc22ad1a487cf5108fd89885ca7250c"
   strings:
      $s1 = "#  it under the terms of the GNU General Public License as published by" fullword ascii
      $s2 = "#  the Free Software Foundation; either version 2 of the License, or" fullword ascii
      $s3 = "#  You should have received a copy of the GNU General Public License" fullword ascii
      $s4 = "#  GNU General Public License for more details." fullword ascii
      $s5 = "        self.controller = Controller(self.script_path, self.arguments, self.output)" fullword ascii
      $s6 = "#  (at your option) any later version." fullword ascii
      $s7 = "#  Author: Mauro Soria" fullword ascii
      $s8 = "from lib.controller.controller import Controller" fullword ascii
      $s9 = "        self.arguments = ArgumentParser(self.script_path)" fullword ascii
      $s10 = "        self.script_path = os.path.dirname(os.path.realpath(__file__))" fullword ascii
      $s11 = "#  This program is distributed in the hope that it will be useful," fullword ascii
      $s12 = "#  but WITHOUT ANY WARRANTY; without even the implied warranty of" fullword ascii
      $s13 = "#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" fullword ascii
      $s14 = "#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston," fullword ascii
      $s15 = "#  along with this program; if not, write to the Free Software" fullword ascii
      $s16 = "if sys.version_info < (3, 7):" fullword ascii
      $s17 = "#!/usr/bin/env python3" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 4KB and 8 of them
}

rule DruidCrack {
   meta:
      hash1 = "8a1dc161533e12b2ee830cae0dce6b76b63e286df05b4e2637d69ca1b02136da"
   strings:
      $s1 = "com/alibaba/druid/proxy/jdbc/StatementExecuteType.class" fullword ascii
      $s2 = "com/alibaba/druid/proxy/jdbc/StatementExecuteType.classPK" fullword ascii
      $s3 = "com/alibaba/druid/support/spring/stat/annotation/StatAnnotationBeanPostProcessor.class" fullword ascii
      $s4 = "com/alibaba/druid/support/spring/stat/annotation/StatAnnotationBeanPostProcessor.classPK" fullword ascii
      $s5 = "com/alibaba/druid/support/ibatis/SqlMapExecutorWrapper.classPK" fullword ascii
      $s6 = "com/alibaba/druid/support/ibatis/SqlMapExecutorWrapper.class" fullword ascii
      $s7 = "com/alibaba/druid/sql/dialect/mysql/ast/statement/MySqlExecuteStatement.classPK" fullword ascii
      $s8 = "com/alibaba/druid/sql/dialect/mysql/ast/statement/MySqlExecuteStatement.class" fullword ascii
      $s9 = "com/alibaba/druid/sql/dialect/mysql/ast/statement/MySqlExecuteForAdsStatement.class" fullword ascii
      $s10 = "com/alibaba/druid/mock/handler/MockExecuteHandler.classPK" fullword ascii
      $s11 = "com/alibaba/druid/sql/dialect/mysql/ast/statement/MySqlExecuteForAdsStatement.classPK" fullword ascii
      $s12 = "com/alibaba/druid/sql/dialect/oracle/ast/stmt/OracleExecuteImmediateStatement.classPK" fullword ascii
      $s13 = "com/alibaba/druid/sql/dialect/oracle/ast/stmt/OracleExecuteImmediateStatement.class" fullword ascii
      $s14 = "com/alibaba/druid/mock/handler/MySqlMockExecuteHandlerImpl.classPK" fullword ascii
      $s15 = "com/alibaba/druid/mock/handler/MySqlMockExecuteHandlerImpl.class" fullword ascii
      $s16 = "com/alibaba/druid/mock/handler/MockExecuteHandler.classu" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 4MB and 8 of them
}

rule ExeinfoPe {
   meta:
      hash1 = "7ffcbdedd2fef54b22840be62e0658d2bf203096f33dd9a95bcbb1698d324f42"
   strings:
      $s1 = {3D 32 3D 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 46 45 3D 2F 36 32 32 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2MB and $s1
}

```

0x07 想说的话：
==========

授人以鱼不如授人以渔嘛，我把我刚接触到这个任务的思路和方案都写在上面了，我是怎么思考的，怎么一步步改进的都写了下来。虽然现在做的规则不是很多，但是凭借着上面的思路相信看的人自己也能做出合适的 Yara 规则。当然每个人的思考高度和深度不同，思考面也不同，所以肯定有人有更好的方法，上面仅代表我自己的见解。

对于剩下的工具规则特别是那些大头戏——混淆工具和 metasploit 、Cobaltstrike 等渗透测试，木马生成工具的落地样本匹配，我在后面慢慢学习尝试，并分享出来~

0x08 参考链接：
==========

[Neo23x0/yarGen: yarGen is a generator for YARA rules (github.com)](https://github.com/Neo23x0/yarGen)

[How to Write Simple but Sound Yara Rules - Nextron Systems (nextron-systems.com)](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/)

[How to Write Simple but Sound Yara Rules - Part 2 - Nextron Systems (nextron-systems.com)](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)

[How to Write Simple but Sound Yara Rules – Part 3 - Nextron Systems (nextron-systems.com)](https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)

[Writing YARA rules — yara 4.2.0 documentation](https://yara.readthedocs.io/en/v4.2.3/writingrules.html#file-size)

[Threekiii/Awesome-Redteam: 一个红队知识仓库 (github.com)](https://github.com/Threekiii/Awesome-Redteam#%E5%AE%9E%E7%94%A8%E5%B7%A5%E5%85%B7)