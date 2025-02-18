用 Yara 对红队工具 "打标"（三）——免杀类规则提取（二）
================================

前言:
---

该系列文章是对 [红队知识仓库 ](https://github.com/Threekiii/Awesome-Redteam) 这个高赞项目中所提到的红队工具进行 "打标"的知识分享。前面已经整理了 [用Yara 对红队工具 "打标"](https://forum.butian.net/share/1913) 、 [用 Yara 对红队工具 "打标"（二） ](https://forum.butian.net/share/1954)、[用 Yara 对红队工具 "打标"（三）——免杀类规则提取](https://forum.butian.net/share/2008)。这里继续分享免杀工具中剩余的 GolangBypassAV、shellcodeloader 和 “掩日” 的 "打标" 思路和细节。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d089fa1f91c7c01cb41ccf7c8d713e47110d8de2.png)

免杀类工具特征提取：
----------

在前面 [用 Yara 对红队工具 "打标"（三）——免杀类规则提取](https://forum.butian.net/share/2008) 的文章中讲解了 "静态的 YARA 和 PE文件结构"、"用代码还是数据做规则？"、"机器码也是字节码"、"汇编中的变与不变" 这些知识点，这里不重复累赘直接上手了，如果需要建议回顾上篇。

### GolangBypassAV：

项目介绍：研究利用golang来bypassAV

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b70dee88cb7074d9f18ce4c21872ac04ab14e5fa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2853945ad77ceb028673717cc0011845fe84a685.png)

根据 README.md 文档可只，只有 gen 目录是可用的，其它都是一些知识分享，我们直接看 gen 目录下的内容：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-110b3bb60bba35633ccf1f011d9e107c10eac392.png)

代码文件不多，一个主代码 main.go，template 目录下是两个免杀模板，使用说明表明可以自己配置或快速免杀。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-defd0156b1bb8fede87a05050c94f29f034831b2.png)

#### 源码分析：

##### mian.go：

从头到尾来吧，因为函数调用穿插得挺多的，我也不知道用什么顺序讲了。

**首先来看变量区，如下所述：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d9769c68d9f030bb6124d2ece0a2575abd36f65d.png)

**解密代码：**

解密区由 decodeMethod 和 decodeMethod1 变量组成，把相关解密代码赋值在变量当中，其中用了运行时赋值的方法把一个标准函数拆分成两部分，应该是避免静态查杀。

给函数中 $encode$ 替换的代码在 main 函数中，分别是decodeMethod = strings.ReplaceAll(decodeMethod, "$encode$", "hex") 和 decodeMethod = strings.ReplaceAll(decodeMethod, "$encode$", "base64.StdEncoding")。

从上到下分别替换成 hex.DecodeString 和 base64.StdEncoding.DecodeString，对应了该项目可选的 hex 加密和 base64 加密。

函数名 $getDeCode 和密钥 $keyName 也是等待被替换的变量值，这个后面会讲。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f8a131b1c01f2e46142e0ba92914992d2bfff5cd.png)

**初始化函数区：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-30b4a6880d263da38ef345b39f9aa09b467f854f.png)

**加密区：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a8be3348550d9924e343d009c5305913b7346099.png)

**用户 shellcode 和免杀模板整合区：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-756643dae305694ca1fdea4a948313ba91ca12cc.png)

**主逻辑代码：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6e772a2bcf921ab41ce446695b8792dff6e4491f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2d190ec12b34be4200b360a70efe7381d5d47471.png)

##### 模板文件——**createThread**：

createThread 模板文件免杀的原理是动态加载函数，内存开辟空间并写入shellcode，然后更改对应页面为可执行后以创建线程的方式启动代码。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-dd5472c5fef04f64ac086485315b3561a1d8ac71.png)

##### 模板文件——**syscall**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e3fabb1a7a1bc884981559587667022fed71f94b.png)

##### 整体逻辑：

该项目从 main.go 出发，其接受用户的 payload.bin ，打开并读取里面的内容。然后以可选的 hex 或 base64 变形加密方式加密 shellcode 内容后传入 template 目录下可选的免杀模板 createThread 或 syscall 中 ，最终的落地文件就是整合了 shellcode 和免杀模板文件中的一个。

免杀方法是变量名随机生成 + 自定义的加密方式。

#### 免杀特征提取：

##### 寻找检测点：

因为要查杀的是最终落地文件，所以看 template 目录下的 createThread 和 syscall 即可。本来想提取替换进去的解密函数的，但是 hex 解密就一个标准库函数调用，base64 的异或特征也不够明显。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4a17a8e0dffbe8395a8d1784f1213d4d2d2971c1.png)

然后又看到时间反调试函数处，这在两个免杀模板文件中是通用的，但是还是感觉不太明显，而且函数本身是没危害性的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6125912ac803ba3e94c66d9dd4e115c07fb93e3b.png)

最后还是挑选了主体函数，反正也没不可能一次性把这种类型的免杀一次杀完，等作者改了源码再更新对应的规则咯。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6179824b07cb598065d7a266458b78006f185052.png)

##### 提取字节码：

这里以 createThread 为例，生成一个对应的文件扔入 IDA 中定位到该函数处：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9b60c5620f07f4cee0b29e3b1fa5c764dde57c65.png)

再定位到对应的汇编语言和机器码列表中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d32f80426acd773749dcafc92a2f22d804705aba.png)

同样的提取机器码（字节码）：

&gt; 49 3B 66 10 0F 86 FC 01 00 00 48 83 EC 60 48 89 6C 24 58 48 8D 6C 24 58 48 89 5C 24 70 48 89 44 24 68 B9 00 30 00 00 BF 04 00 00 00 31 C0 E8 ED 28 FF FF 48 89 44 24 28 90 48 8D 05 E0 1E 01 00 E8 FB CA F7 FF 48 89 44 24 48 48 C7 40 08 09 00 00 00 48 8D 15 77 97 01 00 48 89 10 C6 40 10 01 90 48 8D 05 78 1F 01 00 E8 D3 CA F7 FF 83 3D EC AB 10 00 00 75 0C 48 8B 4C 24 48 48 89 48 18 90 EB 0E 48 8D 78 18 48 8B 4C 24 48 E8 D0 CF FC FF 48 89 44 24 40 48 C7 40 08 0D 00 00 00 48 8D 0D A5 A5 01 00 48 89 08 E8 94 01 00 00 48 8B 44 24 70 48 85 C0 0F 86 40 01 00 00 48 8B 4C 24 68 48 89 4C 24 50 48 8D 05 95 8E 00 00 E8 70 CA F7 FF 48 8B 4C 24 28 48 89 08 48 8B 54 24 50 48 89 50 08 48 8B 54 24 70 48 89 50 10 48 89 C3 BF 03 00 00 00 48 8B 44 24 40 48 89 F9 E8 A1 1C FF FF C7 44 24 24 00 00 00 00 48 8B 44 24 28 48 8B 5C 24 70 B9 20 00 00 00 48 8D 7C 24 24 0F 1F 44 00 00 E8 3B 29 FF FF E8 16 01 00 00 90 48 8D 05 EE 1D 01 00 E8 09 CA F7 FF 48 89 44 24 38 48 C7 40 08 0C 00 00 00 48 8D 0D EE A1 01 00 48 89 08 C6 40 10 01 E8 E9 00 00 00 90 48 8D 05 81 1E 01 00 90 E8 DB C9 F7 FF 83 3D F4 AA 10 00 00 75 0B 48 8B 4C 24 38 48 89 48 18 EB 0E 48 8D 78 18 48 8B 4C 24 38 E8 D9 CE FC FF 48 89 44 24 30 48 C7 40 08 0C 00 00 00 48 8D 0D 2E 9F 01 00 48 89 08 66 90 E8 9B 00 00 00 B8 88 13 00 00 E8 11 9A FC FF 48 8D 05 8A 8F 00 00 E8 85 C9 F7 FF 48 8B 4C 24 28 48 89 48 10 44 0F 11 78 18 48 C7 40 28 00 00 00 00 48 89 C3 B9 06 00 00 00 48 89 CF 48 8B 44 24 30 E8 BA 1B FF FF BB FF FF FF FF E8 B0 29 FF FF 48 8B 6C 24 58 48 83 C4 60 C3

根据 "汇编中的变与不变" 寻找所有内存操作数等地址引用部分，用通配符替换:

&gt; 49 3B 66 10 0F 86 FC 01 00 00 48 83 EC 60 48 89 6C 24 58 48 8D 6C 24 58 48 89 5C 24 70 48 89 44 24 68 B9 00 30 00 00 BF 04 00 00 00 31 C0 E8 ?? ?? ?? ?? 48 89 44 24 28 90 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 89 44 24 48 48 C7 40 08 09 00 00 00 48 8D 15 ?? ?? ?? 00 48 89 10 C6 40 10 01 90 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? 00 00 75 0C 48 8B 4C 24 48 48 89 48 18 90 EB 0E 48 8D 78 18 48 8B 4C 24 48 E8 ?? ?? ?? ?? 48 89 44 24 40 48 C7 40 08 0D 00 00 00 48 8D 0D ?? ?? ?? 00 48 89 08 E8 ?? ?? ?? ?? 48 8B 44 24 70 48 85 C0 0F 86 40 01 00 00 48 8B 4C 24 68 48 89 4C 24 50 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 8B 4C 24 28 48 89 08 48 8B 54 24 50 48 89 50 08 48 8B 54 24 70 48 89 50 10 48 89 C3 BF 03 00 00 00 48 8B 44 24 40 48 89 F9 E8 ?? ?? ?? ?? C7 44 24 24 00 00 00 00 48 8B 44 24 28 48 8B 5C 24 70 B9 20 00 00 00 48 8D 7C 24 24 0F 1F 44 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 89 44 24 38 48 C7 40 08 0C 00 00 00 48 8D 0D ?? ?? ?? 00 48 89 08 C6 40 10 01 E8 ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? 00 90 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? 00 00 75 0B 48 8B 4C 24 38 48 89 48 18 EB 0E 48 8D 78 18 48 8B 4C 24 38 E8 ?? ?? ?? ?? 48 89 44 24 30 48 C7 40 08 0C 00 00 00 48 8D 0D ?? ?? ?? 00 48 89 08 66 90 E8 ?? ?? ?? ?? B8 88 13 00 00 E8 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 8B 4C 24 28 48 89 48 10 44 0F 11 78 18 48 C7 40 28 00 00 00 00 48 89 C3 B9 06 00 00 00 48 89 CF 48 8B 44 24 30 E8 ?? ?? ?? ?? BB FF FF FF FF E8 ?? ?? ?? ?? 48 8B 6C 24 58 48 83 C4 60 C3

##### 最终 yara 规则与测试：

syscall 也是一样的操作，最终写成的 yara 规则如下：

```php
rule GolangBypassAV{
    meta:
    reference = "https://github.com/Threekiii/Awesome-Redteam"

    strings:
/*
ÿ Go build ID:

——————————————————————————————createThread————————————————————————————————————
func trIhQz(code []byte) {
    addr, _ := windows.VirtualAlloc(uintptr(0), uintptr(len(code)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
    qCtgzA()
    RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&amp;code[0])), uintptr(len(code)))
    var oldProtect uint32
    windows.VirtualProtect(addr, uintptr(len(code)), windows.PAGE_EXECUTE_READ, &amp;oldProtect)
    qCtgzA()
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    qCtgzA()
    CreateThread := kernel32.NewProc("CreateThread")
    qCtgzA()
    time.Sleep(5000)
    thread, _, _ := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)
    windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
}

——————————————————————————————syscall——————————————————————————————————————————
func bKIoHY(charcode []byte) {

    addr, _, err := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if err != nil &amp;&amp; err.Error() != "The operation completed successfully." {
        syscall.Exit(0)
    }
    _YqhvZ()
    _, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&amp;charcode[0])), uintptr(len(charcode)))
    if err != nil &amp;&amp; err.Error() != "The operation completed successfully." {
        syscall.Exit(0)
    }
    _YqhvZ()
    syscall.Syscall(addr, 0, 0, 0, 0)
}

*/

    $s1 = {FF 20 47 6F 20 62 75 69 6C 64 20 49 44 3A}

    $x1 = {49 3B 66 10 0F 86 FC 01 00 00 48 83 EC 60 48 89 6C 24 58 48 8D 6C 24 58 48 89 5C 24 70 48 89 44 24 68 B9 00 30 00 00 BF 04 00 00 00 31 C0 E8 ?? ?? ?? ?? 48 89 44 24 28 90 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 89 44 24 48 48 C7 40 08 09 00 00 00 48 8D 15 ?? ?? ?? 00 48 89 10 C6 40 10 01 90 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? 00 00 75 0C 48 8B 4C 24 48 48 89 48 18 90 EB 0E 48 8D 78 18 48 8B 4C 24 48 E8 ?? ?? ?? ?? 48 89 44 24 40 48 C7 40 08 0D 00 00 00 48 8D 0D ?? ?? ?? 00 48 89 08 E8 ?? ?? ?? ?? 48 8B 44 24 70 48 85 C0 0F 86 40 01 00 00 48 8B 4C 24 68 48 89 4C 24 50 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 8B 4C 24 28 48 89 08 48 8B 54 24 50 48 89 50 08 48 8B 54 24 70 48 89 50 10 48 89 C3 BF 03 00 00 00 48 8B 44 24 40 48 89 F9 E8 ?? ?? ?? ?? C7 44 24 24 00 00 00 00 48 8B 44 24 28 48 8B 5C 24 70 B9 20 00 00 00 48 8D 7C 24 24 0F 1F 44 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 89 44 24 38 48 C7 40 08 0C 00 00 00 48 8D 0D ?? ?? ?? 00 48 89 08 C6 40 10 01 E8 ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? 00 90 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? 00 00 75 0B 48 8B 4C 24 38 48 89 48 18 EB 0E 48 8D 78 18 48 8B 4C 24 38 E8 ?? ?? ?? ?? 48 89 44 24 30 48 C7 40 08 0C 00 00 00 48 8D 0D ?? ?? ?? 00 48 89 08 66 90 E8 ?? ?? ?? ?? B8 88 13 00 00 E8 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 8B 4C 24 28 48 89 48 10 44 0F 11 78 18 48 C7 40 28 00 00 00 00 48 89 C3 B9 06 00 00 00 48 89 CF 48 8B 44 24 30 E8 ?? ?? ?? ?? BB FF FF FF FF E8 ?? ?? ?? ?? 48 8B 6C 24 58 48 83 C4 60 C3}

    $x2 = {49 3B 66 10 0F 86 6A 01 00 00 48 83 EC 40 48 89 6C 24 38 48 8D 6C 24 38 48 89 5C 24 50 48 89 44 24 48 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 8B 4C 24 50 48 89 48 08 48 C7 40 10 00 30 00 00 48 C7 40 18 40 00 00 00 48 8B 15 ?? ?? ?? 00 48 89 C3 BF 04 00 00 00 48 89 D0 48 89 F9 0F 1F 40 00 E8 ?? ?? ?? ?? 48 89 44 24 28 48 85 C9 74 3C 48 8B 49 18 48 89 F8 FF D1 48 83 FB 25 74 07 B8 01 00 00 00 EB 14 48 8D 1D ?? ?? ?? 00 B9 25 00 00 00 E8 ?? ?? ?? ?? 83 F0 01 84 C0 75 07 48 8B 44 24 28 EB 07 31 C0 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 50 48 85 C0 0F 86 AB 00 00 00 48 8B 4C 24 48 48 89 4C 24 30 48 8D 05 ?? ?? ?? 00 E8 ?? ?? ?? ?? 48 8B 4C 24 28 48 89 08 48 8B 54 24 30 48 89 50 08 48 8B 54 24 50 48 89 50 10 48 8B 15 ?? ?? ?? 00 48 89 C3 BF 03 00 00 00 48 89 D0 48 89 F9 E8 ?? ?? ?? ?? 48 85 C9 74 38 48 8B 49 18 48 89 F8 FF D1 48 83 FB 25 74 07 B8 01 00 00 00 EB 14 48 8D 1D ?? ?? ?? 00 B9 25 00 00 00 E8 ?? ?? ?? ?? 83 F0 01 84 C0 74 0A 31 C0 0F 1F 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 28 31 DB 48 89 D9 48 89 CF 48 89 CE E8 ?? ?? ?? ?? 48 8B 6C 24 38 48 83 C4 40 C3}

    condition:
    uint16be(0) == 0x4D5A and $s1 and 1 of ($x*)
}
```

**本地测试：（全部命中并且没有误报）**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d5b3c01ae03796558c46d4437565cef212f81636.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-99a405b8422dd69e69aba7e1a804fc90100b1dbe.png)

### shellcodeloader：

项目介绍：Windows平台的shellcode免杀加载器。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cd9c90d69df116a265e99797b3ed483afcaba845.png)

#### 项目分析：

shellcodeloader 是用 MFC 实现 UI 界面和其接口的，免杀模板是用 C++ 编写的，并且分 32 位和 64 位。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-098f3db94458718506e3850716238fdb2d460b23.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c414ce4d1a29a38bdf24f83576f3ab7ac7b1f348.png)

使用方法和最终落地文件：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-87bd9b72a32948ae6686898df3612eacd502e7d5.png)

#### 简单源码分析：

MFC 没学过，windows 图形编程也没学过，代码也比较长，全部看完是不太现实的。那根据前面规则提取的经验，我们把范围缩小一下，我们找最终写入落地文件的代码即可。而根据上面的项目分析，最终落地文件是一个文件名写死的 loader.exe 文件，至于文件内容，猜测是和前面几个免杀项目一样把加密 shellcode 整合到可选的免杀模板之中。

##### shellcodeLoaderDlg.cpp：

从 shellcodeLoaderDlg.cpp 的源码中可以看到确实是把 shellcode 整合到免杀模板中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e9bd0606a65e0b6bdbceff09fe422a06befd3820.png)

##### 免杀模板源码分析：

###### 通用的 public.hpp：

每一个免杀模板中都包含一个 public.hpp ，项目介绍中说要想扩展免杀方法，需要在新的模板源文件中包含public.hpp，下面是该文件的一些介绍。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ec578b29454d71d0080ad3dfa5a5419a8ff839e2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-83f0abfc097ac47c1f1f387caf7318b061d8c268.png)

public.hpp 从源码中看发现都是一些比较通用的方法，分别是 RC4 算法——对称的加密解密算法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-040c1ab4b69d7a535482a90b2af1af11c3eb71e6.png)

遍历进程，根据其数量的反沙箱函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5e497e17b1733d3377d3b091762ea37c1a34fae3.png)

把免杀文件路径写入开机启动注册表的自启动函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5d31c099537c08e30ccc96e2ea712d60984ac1a3.png)

分开选择调用反沙箱和自启动的条件函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9142b7acc81480f72aabc6ee4725328cfb09245c.png)

主要的 GetShellcodeFromRes 方法，从函数名可以知道前面操作中程序会把用户的 shellcode 加密并嵌入免杀文件 loader.exe 资源中，然后通过调用该函数把其提取出来并解密。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8ad674fc8dbbb620a95e304bedcbe725b0918fcc.png)

###### 单独的 public.hpp：

本来就着上面那个放置在外部的 public.hpp 的函数来做规则的，结果发现很多免杀文件匹配不上，进一步查看源码才发现原来还有单独的 public.hpp。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3fd366ad788029cc719f1091cbec42f5899d48ce.png)

每个单独的 public.hpp 的代码都不尽相同，主要集中在最后 GetShellcodeFromRes 函数上，它们会根据所选的免杀的类型，进行特定的函数调用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ad67f792396c0665ad0b4b579e933a9a70677637.png)

#### 免杀特征提取：

##### 共有代码及其机器码摘录：

本着寻找最通用代码以写出最少行规则的原则，决定挑选所有 public.hpp 都存在的下面三个函数，分别是反沙箱，自启动，和它们的条件函数。

```C
void AntiSimulation()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return;
    }
    PROCESSENTRY32 pe = { sizeof(pe) };
    int procnum = 0;
    for (BOOL ret = Process32First(hSnapshot, &amp;pe); ret; ret = Process32Next(hSnapshot, &amp;pe))
    {
        procnum++;
    }
    if (procnum &lt;= 40)  //判断当前进程是否低于40个，目前见过能模拟最多进程的是WD能模拟39个
    {
        exit(1);
    }
}

void AutoStart()
{
    HKEY hKey;
    char currentpath[256] = { 0 };
    GetModuleFileNameA(NULL, currentpath, 256);
    if (!RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &amp;hKey))
    {
        RegSetValueExA(hKey, "Windows Security", 0, REG_SZ, (PUCHAR)currentpath, strlen(currentpath));
        RegCloseKey(hKey);
    }
}

void init(BOOL anti_sandbox, BOOL autostart)
{
    if (anti_sandbox)  //反仿真
    {
        AntiSimulation();
    }
    if (autostart)  //注册表添加自启动
    {
        AutoStart();
    }
}
```

这里先从 32 位目录下的免杀模板文件开始，这些 .DAT 结尾的模板文件都是 exe 可执行文件来的，所以也不用特地生成不同类型的 loader.exe 了。至于为什么模板文件都是 .exe 文件？那是因为加密后的 shellcode 是嵌入到其资源中的，而不是整合到其源码中的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-eb59ba6148a17c39dee566ff998b7cc8cbe89514.png)

抓第一个 "APC注入加载.DAT" 扔入 IDA 中反编译定位到上述公共代码部分，发现编译时两个函数编译到一起去了，如下所示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-39cc0ccaf1bd8a9aca4f18085b76a1ee01e939b8.png)

这不影响其机器码摘录，我们转到反汇编并提取出其机器码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-dbc5fe4627fb177b77a33ac2bed8e0016e92d2f1.png)

&gt; 55 8B EC 81 EC 34 03 00 00 A1 04 30 41 00 33 C5 89 45 FC 8B C2 89 85 CC FC FF FF 57 85 C9 74 75 6A 00 6A 02 FF 15 18 D0 40 00 8B F8 83 FF FF 0F 84 ED 00 00 00 53 56 68 28 02 00 00 8D 85 D4 FC FF FF C7 85 D0 FC FF FF 2C 02 00 00 6A 00 50 E8 6C 1C 00 00 83 C4 0C 8D 85 D0 FC FF FF 33 F6 50 57 FF 15 48 D0 40 00 85 C0 0F 84 C2 00 00 00 8B 1D 20 D0 40 00 8D 85 D0 FC FF FF 46 50 57 FF D3 85 C0 75 F1 83 FE 28 5E 5B 0F 8E A2 00 00 00 8B 85 CC FC FF FF 85 C0 0F 84 85 00 00 00 68 00 01 00 00 8D 85 FC FE FF FF 6A 00 50 E8 10 1C 00 00 83 C4 0C 8D 85 FC FE FF FF 68 00 01 00 00 50 6A 00 FF 15 4C D0 40 00 8D 85 CC FC FF FF 50 68 88 1C 41 00 68 01 00 00 80 FF 15 08 D0 40 00 85 C0 75 40 8D 8D FC FE FF FF 8D 51 01 0F 1F 44 00 00 8A 01 41 84 C0 75 F9 2B CA 8D 85 FC FE FF FF 51 50 6A 01 6A 00 68 B8 1C 41 00 FF B5 CC FC FF FF FF 15 04 D0 40 00 FF B5 CC FC FF FF FF 15 00 D0 40 00 8B 4D FC 33 CD 5F E8 9D 06 00 00 8B E5 5D C3

根据前面提到的 "汇编中的变与不变" ，把内存操作数和地址引用部分用通配符代替后如下所示：

&gt; 55 8B EC 81 EC 0C 02 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 53 56 57 68 00 01 00 00 33 FF 89 95 F8 FD FF FF 8D 85 FC FD FF FF 89 8D F4 FD FF FF 57 50 E8 ?? ?? ?? 00 68 00 01 00 00 8D 85 FC FE FF FF 57 50 E8 ?? ?? ?? 00 8B 55 08 83 C4 18 33 C0 8B C8 88 84 05 FC FE FF FF 83 E1 7F 8A 0C 11 88 8C 05 FC FD FF FF 40 3D 00 01 00 00 7C E2 33 F6 8A 94 35 FC FE FF FF 0F B6 84 35 FC FD FF FF 03 F8 0F B6 CA 03 F9 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 8A 84 3D FC FE FF FF 88 84 35 FC FE FF FF 46 88 94 3D FC FE FF FF 81 FE 00 01 00 00 7C BC 33 DB 33 F6 33 FF 39 9D F8 FD FF FF 76 6D 46 81 E6 FF 00 00 80 79 08 4E 81 CE 00 FF FF FF 46 8A 94 35 FC FE FF FF 0F B6 C2 03 F8 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 0F B6 84 3D FC FE FF FF 88 84 35 FC FE FF FF 88 94 3D FC FE FF FF 0F B6 8C 35 FC FE FF FF 0F B6 C2 03 C8 0F B6 C1 8B 8D F4 FD FF FF 0F B6 84 05 FC FE FF FF 30 04 19 43 3B 9D F8 FD FF FF 72 93 8B 4D FC 5F 5E 33 CD 5B E8 ?? ?? ?? 00 8B E5 5D C3

##### TLS 模板中代码编译的差别：

本来像上面提取完之后就收工了，结果本地测试后发现只命中了这些免杀模板中的一小部分，排查后先是发现是 TLS 模板没命中到。

把 TLS 模板扔入 IDA 中发现在 TLS 里 init 函数又被编译出来了，两个函数分开存放了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-acd867461aec2e67076082943a6fb22cfb7fc6e8.png)

那通样的把这两个函数的机器码分开提取出来咯：

&gt; 55 8B EC 81 EC 30 02 00 00 A1 04 20 41 00 33 C5 89 45 FC 57 6A 00 6A 02 FF 15 18 C0 40 00 8B F8 83 FF FF 74 52 53 56 68 28 02 00 00 8D 85 D4 FD FF FF C7 85 D0 FD FF FF 2C 02 00 00 6A 00 50 E8 2C 0F 00 00 83 C4 0C 8D 85 D0 FD FF FF 33 F6 50 57 FF 15 2C C0 40 00 85 C0 74 2B 8B 1D 10 C0 40 00 8D 85 D0 FD FF FF 46 50 57 FF D3 85 C0 75 F1 83 FE 28 5E 5B 7E 0F 8B 4D FC 33 CD 5F E8 C3 01 00 00 8B E5 5D C3

&gt; 55 8B EC 81 EC 08 01 00 00 A1 04 20 41 00 33 C5 89 45 FC 68 00 01 00 00 8D 85 FC FE FF FF 6A 00 50 E8 BA 0E 00 00 83 C4 0C 8D 85 FC FE FF FF 68 00 01 00 00 50 6A 00 FF 15 30 C0 40 00 8D 85 F8 FE FF FF 50 68 C8 09 41 00 68 01 00 00 80 FF 15 08 C0 40 00 85 C0 75 3B 8D 8D FC FE FF FF 8D 51 01 8A 01 41 84 C0 75 F9 2B CA 8D 85 FC FE FF FF 51 50 6A 01 6A 00 68 F8 09 41 00 FF B5 F8 FE FF FF FF 15 04 C0 40 00 FF B5 F8 FE FF FF FF 15 00 C0 40 00 8B 4D FC 33 CD E8 18 01 00 00 8B E5 5D C3

处理并整合后的机器码如下：

```c
    $a = {55 8B EC 81 EC 0C 02 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 53 56 57 68 00 01 00 00 33 FF 89 95 F8 FD FF FF 8D 85 FC FD FF FF 89 8D F4 FD FF FF 57 50 E8 ?? ?? ?? 00 68 00 01 00 00 8D 85 FC FE FF FF 57 50 E8 ?? ?? ?? 00 8B 55 08 83 C4 18 33 C0 8B C8 88 84 05 FC FE FF FF 83 E1 7F 8A 0C 11 88 8C 05 FC FD FF FF 40 3D 00 01 00 00 7C E2 33 F6 8A 94 35 FC FE FF FF 0F B6 84 35 FC FD FF FF 03 F8 0F B6 CA 03 F9 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 8A 84 3D FC FE FF FF 88 84 35 FC FE FF FF 46 88 94 3D FC FE FF FF 81 FE 00 01 00 00 7C BC 33 DB 33 F6 33 FF 39 9D F8 FD FF FF 76 6D 46 81 E6 FF 00 00 80 79 08 4E 81 CE 00 FF FF FF 46 8A 94 35 FC FE FF FF 0F B6 C2 03 F8 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 0F B6 84 3D FC FE FF FF 88 84 35 FC FE FF FF 88 94 3D FC FE FF FF 0F B6 8C 35 FC FE FF FF 0F B6 C2 03 C8 0F B6 C1 8B 8D F4 FD FF FF 0F B6 84 05 FC FE FF FF 30 04 19 43 3B 9D F8 FD FF FF 72 93 8B 4D FC 5F 5E 33 CD 5B E8 ?? ?? ?? 00 8B E5 5D C3}

    $b = {55 8B EC 81 EC 08 01 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 68 00 01 00 00 8D 85 FC FE FF FF 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 FC FE FF FF 68 00 01 00 00 50 6A 00 FF 15 ?? ?? ?? 00 8D 85 F8 FE FF FF 50 68 ?? ?? ?? 00 68 01 00 00 80 FF 15 ?? ?? ?? 00 85 C0 75 3B 8D 8D FC FE FF FF 8D 51 01 8A 01 41 84 C0 75 F9 2B CA 8D 85 FC FE FF FF 51 50 6A 01 6A 00 68 ?? ?? ?? 00 FF B5 F8 FE FF FF FF 15 ?? ?? ?? 00 FF B5 F8 FE FF FF FF 15 ?? ?? ?? 00 8B 4D FC 33 CD E8 ?? ?? ?? 00 8B E5 5D C3}

    $c = {55 8B EC 81 EC 30 02 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 57 6A 00 6A 02 FF 15 ?? ?? ?? 00 8B F8 83 FF FF 74 52 53 56 68 28 02 00 00 8D 85 D4 FD FF FF C7 85 D0 FD FF FF 2C 02 00 00 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 D0 FD FF FF 33 F6 50 57 FF 15 ?? ?? ?? 00 85 C0 74 2B 8B 1D ?? ?? ?? 00 8D 85 D0 FD FF FF 46 50 57 FF D3 85 C0 75 F1 83 FE 28 5E 5B 7E 0F 8B 4D FC 33 CD 5F E8 ?? ?? ?? 00 8B E5 5D C3}
```

##### 中英文之间的编译差别：

本来以后可以收工了，结果本地测试一下发现中文版的 TLS 模板没匹配到？！！然后屁颠屁颠地把 cn 版的 TLS 模板扔进 IDA 中看个究竟，结果发现中文版的 TLS 免杀模板是整合到一个函数中的，并且还和上面的不一样。。。。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8af201f8c0e7db094f55cba5fc3be7df00ffc1e3.png)

那好吧，继续提取机器码并用通配符修正，连着前面的规则整合如下：

```c
    $a = {55 8B EC 81 EC 0C 02 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 53 56 57 68 00 01 00 00 33 FF 89 95 F8 FD FF FF 8D 85 FC FD FF FF 89 8D F4 FD FF FF 57 50 E8 ?? ?? ?? 00 68 00 01 00 00 8D 85 FC FE FF FF 57 50 E8 ?? ?? ?? 00 8B 55 08 83 C4 18 33 C0 8B C8 88 84 05 FC FE FF FF 83 E1 7F 8A 0C 11 88 8C 05 FC FD FF FF 40 3D 00 01 00 00 7C E2 33 F6 8A 94 35 FC FE FF FF 0F B6 84 35 FC FD FF FF 03 F8 0F B6 CA 03 F9 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 8A 84 3D FC FE FF FF 88 84 35 FC FE FF FF 46 88 94 3D FC FE FF FF 81 FE 00 01 00 00 7C BC 33 DB 33 F6 33 FF 39 9D F8 FD FF FF 76 6D 46 81 E6 FF 00 00 80 79 08 4E 81 CE 00 FF FF FF 46 8A 94 35 FC FE FF FF 0F B6 C2 03 F8 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 0F B6 84 3D FC FE FF FF 88 84 35 FC FE FF FF 88 94 3D FC FE FF FF 0F B6 8C 35 FC FE FF FF 0F B6 C2 03 C8 0F B6 C1 8B 8D F4 FD FF FF 0F B6 84 05 FC FE FF FF 30 04 19 43 3B 9D F8 FD FF FF 72 93 8B 4D FC 5F 5E 33 CD 5B E8 ?? ?? ?? 00 8B E5 5D C3}

//$x2、$x3 是拆分部分，两个函数在TLS回调中被拆开了，这是en版的
    $b = {55 8B EC 81 EC 08 01 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 68 00 01 00 00 8D 85 FC FE FF FF 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 FC FE FF FF 68 00 01 00 00 50 6A 00 FF 15 ?? ?? ?? 00 8D 85 F8 FE FF FF 50 68 ?? ?? ?? 00 68 01 00 00 80 FF 15 ?? ?? ?? 00 85 C0 75 3B 8D 8D FC FE FF FF 8D 51 01 8A 01 41 84 C0 75 F9 2B CA 8D 85 FC FE FF FF 51 50 6A 01 6A 00 68 ?? ?? ?? 00 FF B5 F8 FE FF FF FF 15 ?? ?? ?? 00 FF B5 F8 FE FF FF FF 15 ?? ?? ?? 00 8B 4D FC 33 CD E8 ?? ?? ?? 00 8B E5 5D C3}

    $c = {55 8B EC 81 EC 30 02 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 57 6A 00 6A 02 FF 15 ?? ?? ?? 00 8B F8 83 FF FF 74 52 53 56 68 28 02 00 00 8D 85 D4 FD FF FF C7 85 D0 FD FF FF 2C 02 00 00 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 D0 FD FF FF 33 F6 50 57 FF 15 ?? ?? ?? 00 85 C0 74 2B 8B 1D ?? ?? ?? 00 8D 85 D0 FD FF FF 46 50 57 FF D3 85 C0 75 F1 83 FE 28 5E 5B 7E 0F 8B 4D FC 33 CD 5F E8 ?? ?? ?? 00 8B E5 5D C3}

//$x4 也是TLS回调函数的部分，但是它是整合在一个函数中的，可能是中英文导致的编译有些变化，这是cn版的
    $d = {55 8B EC 81 EC 34 03 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 8B C2 89 85 CC FC FF FF 57 85 C9 74 75 6A 00 6A 02 FF 15 ?? ?? ?? 00 8B F8 83 FF FF 0F 84 ED 00 00 00 53 56 68 28 02 00 00 8D 85 D4 FC FF FF C7 85 D0 FC FF FF 2C 02 00 00 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 D0 FC FF FF 33 F6 50 57 FF 15 ?? ?? ?? 00 85 C0 0F 84 C2 00 00 00 8B 1D ?? ?? ?? 00 8D 85 D0 FC FF FF 46 50 57 FF D3 85 C0 75 F1 83 FE 28 5E 5B 0F 8E A2 00 00 00 8B 85 CC FC FF FF 85 C0 0F 84 85 00 00 00 68 00 01 00 00 8D 85 FC FE FF FF 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 FC FE FF FF 68 00 01 00 00 50 6A 00 FF 15 ?? ?? ?? 00 8D 85 CC FC FF FF 50 68 ?? ?? ?? 00 68 01 00 00 80 FF 15 ?? ?? ?? 00 85 C0 75 40 8D 8D FC FE FF FF 8D 51 01 0F 1F 44 00 00 8A 01 41 84 C0 75 F9 2B CA 8D 85 FC FE FF FF 51 50 6A 01 6A 00 68 ?? ?? ?? 00 FF B5 CC FC FF FF FF 15 ?? ?? ?? 00 FF B5 CC FC FF FF FF 15 ?? ?? ?? 00 8B 4D FC 33 CD 5F E8 ?? ?? ?? 00 8B E5 5D C3}
```

##### 32 位和 64 位的编译差别：

当我本地测试发现差不多后，突然灵光一闪，好像匹配结果都是 32 位目录下的，64 位下的呢？突然想起来 64 位和 32 位的汇编代码不一样，寄存器也不相同，这意味着又要加规则了！

好在 64 位目录下没有 TLS 模板，一下子少了交叉的好几个规则：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5234ac74719b4bbfcb0851f30b2128d43e57f596.png)

但是 64 位 cn 版和 en 版在编译方面还是有区别的，en 版的共有代码是拆分成两个函数的，cn 版的共有代码是整合到一个函数中的，这大概率是因为 ascii 字符和 unicode 字符占位不同导致的编译结果不同。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0d70f14e5e7ab9ba6b04f793fb7d034414f3f299.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4dac0359354f49a719f928f082dbfbff9dbf19c7.png)

我们直接提取规则如下：

```c
//这是en版的
    $a = {40 57 48 81 EC 70 02 00 00 48 8B 05 ?? ?? ?? 00 48 33 C4 48 89 84 24 60 02 00 00 33 D2 8D 4A 02 FF 15 ?? ?? 00 00 48 8B F8 48 83 F8 FF 74 62 33 D2 48 89 9C 24 80 02 00 00 41 B8 34 02 00 00 C7 44 24 20 38 02 00 00 48 8D 4C 24 24 E8 ?? ?? ?? 00 48 8D 54 24 20 48 8B CF 33 DB FF 15 ?? ?? ?? 00 85 C0 74 45 66 66 66 0F 1F 84 00 00 00 00 00 48 8D 54 24 20 48 8B CF FF C3 FF 15 ?? ?? ?? 00 85 C0 75 EC 83 FB 28 7E 21 48 8B 9C 24 80 02 00 00 48 8B 8C 24 60 02 00 00 48 33 CC E8 ?? ?? ?? 00 48 81 C4 70 02 00 00 5F C3}

    $b = {48 81 EC 58 01 00 00 48 8B 05 ?? ?? ?? 00 48 33 C4 48 89 84 24 40 01 00 00 33 D2 48 8D 4C 24 40 41 B8 00 01 00 00 E8 ?? ?? ?? 00 41 B8 00 01 00 00 48 8D 54 24 40 33 C9 FF 15 ?? ?? ?? 00 4C 8D 44 24 30 48 C7 C1 01 00 00 80 48 8D 15 ?? ?? ?? 00 FF 15 ?? ?? ?? 00 85 C0 75 46 48 8D 4C 24 40 48 83 C8 FF 48 FF C0 80 3C 01 00 75 F7 48 8B 4C 24 30 48 8D 15 ?? ?? ?? 00 89 44 24 28 41 B9 01 00 00 00 48 8D 44 24 40 45 33 C0 48 89 44 24 20 FF 15 ?? ?? ?? 00 48 8B 4C 24 30 FF 15 ?? ?? ?? 00 48 8B 8C 24 40 01 00 00 48 33 CC E8 ?? ?? ?? 00 48 81 C4 58 01 00 00 C3}

//这是cn版的
    $c = {48 89 5C 24 08 48 89 74 24 10 57 48 81 EC 90 03 00 00 48 8B 05 ?? ?? ?? 00 48 33 C4 48 89 84 24 80 03 00 00 8B F2 85 C9 74 73 33 D2 8D 4A 02 FF 15 ?? ?? ?? 00 48 8B F8 48 83 F8 FF 0F 84 FE 00 00 00 33 D2 C7 44 24 40 38 02 00 00 41 B8 34 02 00 00 48 8D 4C 24 44 E8 ?? ?? ?? 00 48 8D 54 24 40 48 8B CF 33 DB FF 15 ?? ?? ?? 00 85 C0 0F 84 F1 00 00 00 0F 1F 40 00 0F 1F 84 00 00 00 00 00 48 8D 54 24 40 48 8B CF FF C3 FF 15 ?? ?? ?? 00 85 C0 75 EC 83 FB 28 0F 8E C8 00 00 00 85 F6 0F 84 9B 00 00 00 33 D2 48 8D 8C 24 80 02 00 00 41 B8 00 01 00 00 E8 ?? ?? ?? 00 41 B8 00 01 00 00 48 8D 94 24 80 02 00 00 33 C9 FF 15 ?? ?? ?? 00 4C 8D 44 24 30 48 C7 C1 01 00 00 80 48 8D 15 ?? ?? ?? 00 FF 15 ?? ?? ?? 00 85 C0 75 53 48 8D 8C 24 80 02 00 00 48 83 C8 FF 0F 1F 80 00 00 00 00 48 FF C0 80 3C 01 00 75 F7 48 8B 4C 24 30 48 8D 15 ?? ?? ?? 00 89 44 24 28 41 B9 01 00 00 00 48 8D 84 24 80 02 00 00 45 33 C0 48 89 44 24 20 FF 15 ?? ?? ?? 00 48 8B 4C 24 30 FF 15 ?? ?? ?? 00 48 8B 8C 24 80 03 00 00 48 33 CC E8 ?? ?? ?? 00 4C 8D 9C 24 90 03 00 00 49 8B 5B 10 49 8B 73 18 49 8B E3 5F C3}
```

#### 最终 yara 规则：

```c
rule Shellcodeloader{
    meta:
    reference = "https://github.com/Threekiii/Awesome-Redteam"

    strings:
/*

void AntiSimulation()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return;
    }
    PROCESSENTRY32 pe = { sizeof(pe) };
    int procnum = 0;
    for (BOOL ret = Process32First(hSnapshot, &amp;pe); ret; ret = Process32Next(hSnapshot, &amp;pe))
    {
        procnum++;
    }
    if (procnum &lt;= 40)  //判断当前进程是否低于40个，目前见过能模拟最多进程的是WD能模拟39个
    {
        exit(1);
    }
}

void AutoStart()
{
    HKEY hKey;
    char currentpath[256] = { 0 };
    GetModuleFileNameA(NULL, currentpath, 256);
    if (!RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &amp;hKey))
    {
        RegSetValueExA(hKey, "Windows Security", 0, REG_SZ, (PUCHAR)currentpath, strlen(currentpath));
        RegCloseKey(hKey);
    }
}

void init(BOOL anti_sandbox, BOOL autostart)
{
    if (anti_sandbox)  //反仿真
    {
        AntiSimulation();
    }
    if (autostart)  //注册表添加自启动
    {
        AutoStart();
    }
}
*/

//————————————————————————————————————————————这些都是32位下的————————————————————————————————————————————————————
//$x1 是整合部分，两个函数被编译在一个函数内了

    $a32 = {55 8B EC 81 EC 0C 02 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 53 56 57 68 00 01 00 00 33 FF 89 95 F8 FD FF FF 8D 85 FC FD FF FF 89 8D F4 FD FF FF 57 50 E8 ?? ?? ?? 00 68 00 01 00 00 8D 85 FC FE FF FF 57 50 E8 ?? ?? ?? 00 8B 55 08 83 C4 18 33 C0 8B C8 88 84 05 FC FE FF FF 83 E1 7F 8A 0C 11 88 8C 05 FC FD FF FF 40 3D 00 01 00 00 7C E2 33 F6 8A 94 35 FC FE FF FF 0F B6 84 35 FC FD FF FF 03 F8 0F B6 CA 03 F9 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 8A 84 3D FC FE FF FF 88 84 35 FC FE FF FF 46 88 94 3D FC FE FF FF 81 FE 00 01 00 00 7C BC 33 DB 33 F6 33 FF 39 9D F8 FD FF FF 76 6D 46 81 E6 FF 00 00 80 79 08 4E 81 CE 00 FF FF FF 46 8A 94 35 FC FE FF FF 0F B6 C2 03 F8 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 0F B6 84 3D FC FE FF FF 88 84 35 FC FE FF FF 88 94 3D FC FE FF FF 0F B6 8C 35 FC FE FF FF 0F B6 C2 03 C8 0F B6 C1 8B 8D F4 FD FF FF 0F B6 84 05 FC FE FF FF 30 04 19 43 3B 9D F8 FD FF FF 72 93 8B 4D FC 5F 5E 33 CD 5B E8 ?? ?? ?? 00 8B E5 5D C3}

//$x2、$x3 是拆分部分，两个函数在TLS回调中被拆开了，这是en版的
    $b32 = {55 8B EC 81 EC 08 01 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 68 00 01 00 00 8D 85 FC FE FF FF 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 FC FE FF FF 68 00 01 00 00 50 6A 00 FF 15 ?? ?? ?? 00 8D 85 F8 FE FF FF 50 68 ?? ?? ?? 00 68 01 00 00 80 FF 15 ?? ?? ?? 00 85 C0 75 3B 8D 8D FC FE FF FF 8D 51 01 8A 01 41 84 C0 75 F9 2B CA 8D 85 FC FE FF FF 51 50 6A 01 6A 00 68 ?? ?? ?? 00 FF B5 F8 FE FF FF FF 15 ?? ?? ?? 00 FF B5 F8 FE FF FF FF 15 ?? ?? ?? 00 8B 4D FC 33 CD E8 ?? ?? ?? 00 8B E5 5D C3}

    $c32 = {55 8B EC 81 EC 30 02 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 57 6A 00 6A 02 FF 15 ?? ?? ?? 00 8B F8 83 FF FF 74 52 53 56 68 28 02 00 00 8D 85 D4 FD FF FF C7 85 D0 FD FF FF 2C 02 00 00 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 D0 FD FF FF 33 F6 50 57 FF 15 ?? ?? ?? 00 85 C0 74 2B 8B 1D ?? ?? ?? 00 8D 85 D0 FD FF FF 46 50 57 FF D3 85 C0 75 F1 83 FE 28 5E 5B 7E 0F 8B 4D FC 33 CD 5F E8 ?? ?? ?? 00 8B E5 5D C3}

//$x4 也是TLS回调函数的部分，但是它是整合在一个函数中的，可能是中英文导致的编译有些变化，这是cn版的
    $d32 = {55 8B EC 81 EC 34 03 00 00 A1 ?? ?? ?? 00 33 C5 89 45 FC 8B C2 89 85 CC FC FF FF 57 85 C9 74 75 6A 00 6A 02 FF 15 ?? ?? ?? 00 8B F8 83 FF FF 0F 84 ED 00 00 00 53 56 68 28 02 00 00 8D 85 D4 FC FF FF C7 85 D0 FC FF FF 2C 02 00 00 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 D0 FC FF FF 33 F6 50 57 FF 15 ?? ?? ?? 00 85 C0 0F 84 C2 00 00 00 8B 1D ?? ?? ?? 00 8D 85 D0 FC FF FF 46 50 57 FF D3 85 C0 75 F1 83 FE 28 5E 5B 0F 8E A2 00 00 00 8B 85 CC FC FF FF 85 C0 0F 84 85 00 00 00 68 00 01 00 00 8D 85 FC FE FF FF 6A 00 50 E8 ?? ?? ?? 00 83 C4 0C 8D 85 FC FE FF FF 68 00 01 00 00 50 6A 00 FF 15 ?? ?? ?? 00 8D 85 CC FC FF FF 50 68 ?? ?? ?? 00 68 01 00 00 80 FF 15 ?? ?? ?? 00 85 C0 75 40 8D 8D FC FE FF FF 8D 51 01 0F 1F 44 00 00 8A 01 41 84 C0 75 F9 2B CA 8D 85 FC FE FF FF 51 50 6A 01 6A 00 68 ?? ?? ?? 00 FF B5 CC FC FF FF FF 15 ?? ?? ?? 00 FF B5 CC FC FF FF FF 15 ?? ?? ?? 00 8B 4D FC 33 CD 5F E8 ?? ?? ?? 00 8B E5 5D C3}

//————————————————————————————————————————————————这些都是64位下的——————————————————————————————————————————————————
//这是en版的
    $a64 = {40 57 48 81 EC 70 02 00 00 48 8B 05 ?? ?? ?? 00 48 33 C4 48 89 84 24 60 02 00 00 33 D2 8D 4A 02 FF 15 ?? ?? 00 00 48 8B F8 48 83 F8 FF 74 62 33 D2 48 89 9C 24 80 02 00 00 41 B8 34 02 00 00 C7 44 24 20 38 02 00 00 48 8D 4C 24 24 E8 ?? ?? ?? 00 48 8D 54 24 20 48 8B CF 33 DB FF 15 ?? ?? ?? 00 85 C0 74 45 66 66 66 0F 1F 84 00 00 00 00 00 48 8D 54 24 20 48 8B CF FF C3 FF 15 ?? ?? ?? 00 85 C0 75 EC 83 FB 28 7E 21 48 8B 9C 24 80 02 00 00 48 8B 8C 24 60 02 00 00 48 33 CC E8 ?? ?? ?? 00 48 81 C4 70 02 00 00 5F C3}

    $b64 = {48 81 EC 58 01 00 00 48 8B 05 ?? ?? ?? 00 48 33 C4 48 89 84 24 40 01 00 00 33 D2 48 8D 4C 24 40 41 B8 00 01 00 00 E8 ?? ?? ?? 00 41 B8 00 01 00 00 48 8D 54 24 40 33 C9 FF 15 ?? ?? ?? 00 4C 8D 44 24 30 48 C7 C1 01 00 00 80 48 8D 15 ?? ?? ?? 00 FF 15 ?? ?? ?? 00 85 C0 75 46 48 8D 4C 24 40 48 83 C8 FF 48 FF C0 80 3C 01 00 75 F7 48 8B 4C 24 30 48 8D 15 ?? ?? ?? 00 89 44 24 28 41 B9 01 00 00 00 48 8D 44 24 40 45 33 C0 48 89 44 24 20 FF 15 ?? ?? ?? 00 48 8B 4C 24 30 FF 15 ?? ?? ?? 00 48 8B 8C 24 40 01 00 00 48 33 CC E8 ?? ?? ?? 00 48 81 C4 58 01 00 00 C3}

//这是cn版的
    $c64 = {48 89 5C 24 08 48 89 74 24 10 57 48 81 EC 90 03 00 00 48 8B 05 ?? ?? ?? 00 48 33 C4 48 89 84 24 80 03 00 00 8B F2 85 C9 74 73 33 D2 8D 4A 02 FF 15 ?? ?? ?? 00 48 8B F8 48 83 F8 FF 0F 84 FE 00 00 00 33 D2 C7 44 24 40 38 02 00 00 41 B8 34 02 00 00 48 8D 4C 24 44 E8 ?? ?? ?? 00 48 8D 54 24 40 48 8B CF 33 DB FF 15 ?? ?? ?? 00 85 C0 0F 84 F1 00 00 00 0F 1F 40 00 0F 1F 84 00 00 00 00 00 48 8D 54 24 40 48 8B CF FF C3 FF 15 ?? ?? ?? 00 85 C0 75 EC 83 FB 28 0F 8E C8 00 00 00 85 F6 0F 84 9B 00 00 00 33 D2 48 8D 8C 24 80 02 00 00 41 B8 00 01 00 00 E8 ?? ?? ?? 00 41 B8 00 01 00 00 48 8D 94 24 80 02 00 00 33 C9 FF 15 ?? ?? ?? 00 4C 8D 44 24 30 48 C7 C1 01 00 00 80 48 8D 15 ?? ?? ?? 00 FF 15 ?? ?? ?? 00 85 C0 75 53 48 8D 8C 24 80 02 00 00 48 83 C8 FF 0F 1F 80 00 00 00 00 48 FF C0 80 3C 01 00 75 F7 48 8B 4C 24 30 48 8D 15 ?? ?? ?? 00 89 44 24 28 41 B9 01 00 00 00 48 8D 84 24 80 02 00 00 45 33 C0 48 89 44 24 20 FF 15 ?? ?? ?? 00 48 8B 4C 24 30 FF 15 ?? ?? ?? 00 48 8B 8C 24 80 03 00 00 48 33 CC E8 ?? ?? ?? 00 4C 8D 9C 24 90 03 00 00 49 8B 5B 10 49 8B 73 18 49 8B E3 5F C3}

    condition:
    uint16be(0) == 0x4D5A and ((($a32 or ($b32 and $c32) or $d32) or ($a64 and $b64)) or (($a64 and $b64) or $c64))
}
```

匹配结果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d4450c0974afa5ca7448c076cad27c4b68ec06d1.png)

### 掩日：

在 用 Yara 对红队工具 "打标"（三）——免杀类规则提取 中说过 “掩日” 这个工具它的源码和发布版本对应不上，我看了半天源码，代码和功能间怎么都对不上，结果一编译才发现是不一样的，醉了~

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d7f9b00590d0b35cf4955f5aaac4218492192177.png)

想说的话：
-----

提取规则的方法有很多，免杀类的有源码就跟着源码分析。目标是找出写入最终落地免杀文件的部分，而这通常都是那些可选的模板文件。不同情况下对同一代码有着不同的编译方式，也就有着不同的机器码，如果是以代码作为特征则要注意好这一点。

攻防是一体的，懂防才更懂攻，上面的检测规则绕过也很简单，在 [用 Yara 对红队工具 "打标"（三）——免杀类规则提取](https://forum.butian.net/share/2008) 已有提及，有添加无关代码，拆分函数等等，具体细节请参照上篇。