用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（四）
=========================================

前言：
---

该系列文章是对 [红队知识仓库 ](https://github.com/Threekiii/Awesome-Redteam)这个高赞项目中所提到的红队工具进行 "打标"的知识分享。前面已经整理了 [用Yara 对红队工具 "打标"](https://forum.butian.net/share/1913) 、 [用 Yara 对红队工具 "打标"（二） ](https://forum.butian.net/share/1954)、[用 Yara 对红队工具 "打标"（三）——免杀类规则提取](https://forum.butian.net/share/2008)，[用 Yara 对红队工具 "打标"（三）——免杀类规则提取（二）](https://forum.butian.net/share/2016)，[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析](https://forum.butian.net/share/2070)、[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（二） ](https://forum.butian.net/share/2073)、[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（三）](https://forum.butian.net/share/2075)

这里继续跟随 [Google 云情报威胁团队开源的 YARA 规则集](https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse)，尝试分析最后两个 Windows Stager Payload 和 Windows Stageless Payload：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b31f7cde5d0abf44efaa9c8a523dfdaf6049b0d2.png)

环境准备：
-----

工具：Cobalt Strike 4.7

Google 开源的 YARA 规则集：[GCTI/YARA/CobaltStrike](https://github.com/chronicle/GCTI/tree/main/YARA/CobaltStrike)

Windows Stager Payload 和 Windows Stageless Payload：
---------------------------------------------------

前面我们分析了 Payload Generator 的 stager 和 stageless 版，这次生成的木马应该是属于 windows 可执行文件类型，也就是 PE 结构文件，exe、dll 这些。

**先来看 Windows Stager Payload 的介绍：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bc2705bb386ee783f34497996396d97919dd4bfc.png)

从介绍中可以看到，该类型生成包含 stager 的落地木马，主要有三种类型。EXE 是直接点击执行的；Windows Service EXE 得加载成服务来运行，可以使用 sc 命令或 MSF 框架中的 PsExec 模块来加载；最后的 DLL 提供了名为的 StarW 的导出函数，并且可以使用 rundll32 来加载运行。

**再来看 Windows Stageless Payload 的介绍：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-97b2280a63673aa9dbe20b93c59a48a9678df31f.png)

stageless 就是无分段的 stager，即 stager 与它所请求的数据的集合体。从介绍中可以看到生成的是完整的 beacon，并且多了 PowerShell 和 Raw 类型。

——————————————————————————分割线————————————————————————————

现在我们把它们全部生成出来用 Google 的规则匹配看看：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ed0a207a8f4b2cb062104b003b00dfc976d68799.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-dec0cd997e46a0a698b294b94fde7b89bfacc574.png)

总共有 6 个匹配结果，但是只有三种规则集，更特别的是只匹配了 stageless 类的 beacon，而 stager 类的 artifact 是一个都没匹配到。

匹配的 Yara 规则分析：
--------------

匹配的 3 个规则集中发现有两个都是以前分析过的，比如 CobaltStrike\_\_Sleeve\_BeaconLoader\_all.yara 规则集中的CobaltStrike\_Sleeve\_BeaconLoader\_VA\_x64\_o\_v4\_3\_v4\_4\_v4\_5\_and\_v4\_6 ，在 “[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（三）](https://forum.butian.net/share/2075)” 中 payload64\_process.bin 中详细讲过，有需要的回头去看看即可。

```c
rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
        author = "gssincla@google.com"
        reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
        date = "2022-11-18"

  strings:
    /*
      C6 44 24 48 56 mov     [rsp+88h+var_40], 56h ; 'V'
      C6 44 24 49 69 mov     [rsp+88h+var_40+1], 69h ; 'i'
      C6 44 24 4A 72 mov     [rsp+88h+var_40+2], 72h ; 'r'
      C6 44 24 4B 74 mov     [rsp+88h+var_40+3], 74h ; 't'
      C6 44 24 4C 75 mov     [rsp+88h+var_40+4], 75h ; 'u'
      C6 44 24 4D 61 mov     [rsp+88h+var_40+5], 61h ; 'a'
      C6 44 24 4E 6C mov     [rsp+88h+var_40+6], 6Ch ; 'l'
      C6 44 24 4F 41 mov     [rsp+88h+var_40+7], 41h ; 'A'
      C6 44 24 50 6C mov     [rsp+88h+var_40+8], 6Ch ; 'l'
      C6 44 24 51 6C mov     [rsp+88h+var_40+9], 6Ch ; 'l'
      C6 44 24 52 6F mov     [rsp+88h+var_40+0Ah], 6Fh ; 'o'
      C6 44 24 53 63 mov     [rsp+88h+var_40+0Bh], 63h ; 'c'
      C6 44 24 54 00 mov     [rsp+88h+var_40+0Ch], 0
    */

    $core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }

    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

  condition:
    all of them
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-03634a00750562e4a0e7762c87ff48fc49597abb.png)

第二个是 CobaltStrike\_\_Resources\_Template\_x64\_Ps1\_v3\_0\_to\_v4\_x\_excluding\_3\_12\_3\_13.yara 中的CobaltStrike\_Resources\_Template\_x64\_Ps1\_v3\_0\_to\_v4\_x\_excluding\_3\_12\_3\_13 ，这是匹配 stageless 中 beacon\_powershell 类型的，在 “[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析](https://forum.butian.net/share/2070)” 中也是讲过：

```c
rule CobaltStrike_Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13
{
    meta:
        description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"
        hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
        author = "gssincla@google.com"
        reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
        date = "2022-11-18"

    strings:
    $dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase
    $imm = "InMemoryModule" nocase
    $mdt = "MyDelegateType" nocase
    $rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase
    $data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase
    $64bitSpecific = "[IntPtr]::size -eq 8"
    $mandatory = "Mandatory = $True"

  condition:
    all of them
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-384d5fe18e9c10b01ad7ba4c4b63bca15adccc99.png)

那么就只剩下最后匹配 beacon\_raw32.bin 的 CobaltStrike\_\_Resources\_Beacon\_Dll\_All\_Versions\_MemEnabled.yara 规则集中的 CobaltStrike\_Sleeve\_Beacon\_Dll\_v4\_7\_suspected 规则了，然而单独从该规则中并不能看出挑选的什么，那就后面细细分析。

```c
rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
    hash =  "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
        author = "gssincla@google.com"
        reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
        date = "2022-11-18"

  strings:

    /*
      53                push    ebx
      56                push    esi
      48                dec     eax; switch 104 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 67          cmp     eax, 67h
      0F 87 5E 03 00 00 ja      def_10008997; jumptable 10008997 default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
    */
    $version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }

    /*
      80 B0 [5]      xor     byte_10033020[eax], 2Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_1000ADA1
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}
```

同样的我们前面用过的免杀框架和字节码提取脚本编译生成 32 位的 exe 木马：（在前面的文章中有个笔误就是我说这个免杀框架是64位的，但其实不是，我们可以把他编译成32位来用的，这波我的，大脑抽了~）

```python
import os
f = open("D:\Cobaltstrike_payload\payload64_process.txt","w")
file_bytes = list()
for a in open("D:\Cobaltstrike_payload\payload64_process.bin","rb").read():
    file_bytes.append(hex(a).replace("0x","\\x"))
f.write(''.join(i for i in file_bytes))
f.close()
```

```c
#include<stdio.h>
#include<windows.h>

#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
unsigned char shellcode[]= 这里填shellcode;
int main(){
     LPVOID Memory = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
     memcpy(Memory, shellcode, sizeof(shellcode));
    ((void(*)())Memory)();
    return 0;
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-80e00ac04ae2824664cacc176dd9a98b54a5e5e9.png)

### beacon\_raw32.exe （stageless）分析：

同样的，由于程序体积太大，短时间内无法完全分析，所以我们的思路是先看 Google 规则中给出的部分，并在定位代码之后根据局部上下文和经验判断是否较为特殊。

#### version\_sig 规则分析：

先来看第一个规则：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a136fc910d5227a7d9c8810d462989dc956b2999.png)

在 IDA 中通过 Search——&gt;Sequencebytes 搜寻字节串定位到 sub\_7F8988 函数中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-05fb6b23ae6dddb951e65cbc3a4ef70883b930e0.png)

然后神奇的事情发生了，这个函数没有引用的地方！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-70a3b9c96fb809bb06a7bf3b652f22ca1769b8c5.png)

由于是动态调用该 beacon 函数，所有代码一开始都是以字节码形式展示。一开始我以为是没有手动转换代码，但是想想并不是这样的，哪怕是字节码，只要被调用都会有一个引用点被断下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2c6c7290ef23601ddfc0da0a8b68b722368daca9.png)

但是这里就是没有，我一下呆住了，没有前后文那我咋整。然后一直彷徨，看着那个 switch 104 cases ，突然灵机一动，这里有 104 个跳转，会不会是 beacon 的命令？

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0db245f240c1147616b5855ef42783f6656880b5.png)

然后我便在 switch 处下断点，并在输入一个 pwd 命令后果然断在开头！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f727cf8772ed6cfa43723287752fb72e8bb408b1.png)

pwd 的跳转指令值是 0x26，来到该处后是一个 sub\_7F3219 函数。跟进后发现确实有调用获取目录的 kernel32\_GetCurrentDirectoryA 函数，那么这里的跳转确实是根据命令类型来跳转的了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-28491ecf0a333b793b49dcf813d3a4a6eebc3118.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ecb25518061f95e109565159abaa5b08454212ca.png)

##### 规则评估：

说真的 Google 研究人员能定位到这里实在是太牛逼了，这里应该属于消息监听的处理函数部分，我记得是定义在 widnows 类中的，所以没有相关引用。而这里的特征度不言而喻，那个恶意样本能恰好有 103 个命令处理的跳转呢？所以Google直接把开头 switch 跳转那段抽出来作为检测规则的做法实在是太棒了！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6795ff9c7e1adbe393747766617abd888be753cd.png)

#### decoder 规则分析：

嗯嗯嗯，，，看起来像是一个比较跳转？

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-edda23787f7c391a600e8b3e01016509cf7944bc.png)

在 IDA 中定位到 sub\_7FAD62 函数中，该函数同样没有被引用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1a072d4edf67761764bec80122fc38c5bef94cea.png)  
因为上次是 103 个 beacon 命令，除了命令之外这里我就只想到右键菜单这些插件，我自己是真的刚开始用 Cobalt Strike ，可能有很多其它的东西我没想到。但是把这些右键项试了个遍，都没能触发断点一下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-5354bf963a4d936d952193ccedde7d02b8173cc4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-54996f89cf84d69dd40a7b849f64aee67fbb11e3.png)

尝试关键偏移和内容入手找点蛛丝马迹，结果都是未赋值状态：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8818080592cc889c40fba276dd7a0b0239c30a2b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bbb9ca67dd66ea62b935947dbc03d5d0d8120327.png)

。。。。。卡在这里了，有师傅知道怎么触发该函数的话还请在评论区告知，不胜感激！

##### 规则评估：

没有前后数值，也没有逻辑分析，我也不知道怎么说，Google 研究人员挑的就是这样一个循环加密/解密函数，4096 是缓冲区的大小 4 kb，加密的密钥 0x2E 自我感觉也是比较常见。

Google 选择这里可能是逻辑上与周围不和吧，比如 "[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（二）](https://forum.butian.net/share/2073)" 中挑选的就是自定义 hash 算法，在 PE 结构操作中突然出现一个 hash 计算确实是很大的特征点。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-9005f413ff980c875683068989be09da435dfaa2.png)

然后看一下规则提取的字节码，这里涉及一个会变的数组位置，当加载不同位置不同大小的免杀框架时 byte\_1E3020 就不会在它原来的位置上了，所以得用通配符来替换掉。至于最后的 0X2E ，我感觉是不用换的，除非其它版本的 CS 中会更换这个密值。上面这些我都在 "[用 Yara 对红队工具 "打标"（三）——免杀类规则提取 ](https://forum.butian.net/share/2008)" 有提到，具体细节请自行对照。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d663889a34380a020428d17482acd22d6e23753a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-24d456c6ddf7b8bd1f01bcc9996cd7097b67d1d1.png)

总结：
---

由于是顺着 Google 的 YARA 规则集来分析，所以没匹配到的 Windows Stager Payload 也不继续深究。Windows Stageless Payload 分析中，最后的 decoder 规则没能弄清个所以然有点遗憾，如有师傅有见解还请评论区告知。

这篇是 Cobalt Strike 的类型的最后一篇，分析的是 4.7 版本的 Payload 类型，如果以后有进一步分析的话会继续分享在攻防社区。

一路分析过来发现很多木马都是相通的，框架大同小异，透过 Google 的规则确实能学到很多思路上的启发和他们对 CS 马的理解程度。

上面的分析中如有错误还请指正！

参考链接：
-----

[Profile Language (helpsystems.com)](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile-language.htm?Highlight=xor)

[MSF木马的免杀(三)\_谢公子的博客-CSDN博客\_msf安卓木马免杀](https://xie1997.blog.csdn.net/article/details/106348527)

[msys2/msys2-installer: The one-click installer for MSYS2 (github.com)](https://github.com/msys2/msys2-installer)

[奇安信攻防社区-用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（二） (butian.net)](https://forum.butian.net/share/2073)

[奇安信攻防社区-用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析 (butian.net)](https://forum.butian.net/share/2070)

<https://blog.csdn.net/qq512028505/article/details/78239656>