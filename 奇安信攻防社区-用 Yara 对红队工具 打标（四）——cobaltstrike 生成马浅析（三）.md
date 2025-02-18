用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（三）
=========================================

前言：
---

该系列文章是对 [红队知识仓库 ](https://github.com/Threekiii/Awesome-Redteam)这个高赞项目中所提到的红队工具进行 "打标"的知识分享。前面已经整理了 [用Yara 对红队工具 "打标"](https://forum.butian.net/share/1913) 、 [用 Yara 对红队工具 "打标"（二） ](https://forum.butian.net/share/1954)、[用 Yara 对红队工具 "打标"（三）——免杀类规则提取](https://forum.butian.net/share/2008)，[用 Yara 对红队工具 "打标"（三）——免杀类规则提取（二）](https://forum.butian.net/share/2016)，[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析](https://forum.butian.net/share/2070)、[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（二）](https://forum.butian.net/share/2073)

这里继续跟随 [Google 云情报威胁团队开源的 YARA 规则集](https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse)，分析 Stagerless Payload Generator 生成的部分。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bf2ec6599cef3dfa4917c2161244fd082c5b45ec.png)

环境准备：
-----

工具：Cobalt Strike 4.7

Google 开源的 YARA 规则集：[GCTI/YARA/CobaltStrike](https://github.com/chronicle/GCTI/tree/main/YARA/CobaltStrike)

Payload Generator (stageless)
-----------------------------

在上一篇中我们分析了 Payload Generator ，现在来看看 stageless 版。前面说过 stageless 就是无阶段的stager，即 stager 与它所请求的数据的集合体，所以体积会大很多，常用于内网穿透。

首先看官网介绍怎么用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-105be77e2ded9e991b97cda176a6b9a846e6e679.png)

和上一次的介绍一样，都是只给了核心源码，不过这次没有了 stager 了，是完完全全的监听-通信-执行的 shellcode 代码了，同样需要我们把其加载到 msf 等工具生成的免杀框架中加载。

从参数列表中可以看到这次只有 Raw 不是纯字节码数组，相比于上次 stager 少了 COM Scriptlet、PowerShell、PowerShell Command、Veil 类型，因为这些都是纯纯的 stager 框架。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-08df1083729cc46a1e17908ce6e52cc6e2f8f5a6.png)

Google Yara 规则匹配：
-----------------

对于纯 code 数组的类型，在 "[用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（二）](https://forum.butian.net/share/2073)" 中说过 Google 的研究人员不会和这种隐晦的类型硬碰硬。这里生成了 Process 类的 64 位和 32 位来做实验，可以看到一个都没匹配，所以 thread 类型也不用尝试了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1d1c325a445e746bd4549fa401a9871fb2ab20ab.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f99c5b641730798a248c4d951c06b475af854d96.png)

现在我们把 Raw 类型 32 位、64 位、Process、Thread 共 4 种类型生成出来看一下匹配了谷歌那些规则：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8995d9e6a151401bf369d0631b1528c44f1d25ee.png)

由于匹配的规则集中不止一个规则，所以我修改了一下匹配代码，加多了打印规则部分：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7837d7b6cd236017466060d044fe3173106afb9c.png)

匹配结果如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0f13310c4b650fca1e93e9354158cbb9daabc6e7.png)

从结果集中可以发现虽然匹配了 6 行，但实际上只匹配了 2 个规则集，并且 process 和 thread 类型在规则集中没有差别。32 位匹配了 2 个规则集，64 位匹配了 1 个规则集。

Raw 类型分析：
---------

### payload64\_process.bin

同样的我们只以 64 位为例，exit 类型不影响规则匹配，所以我随便挑了 process。首先是字节码转 C 风格 16 进制数组，由于内容太多了，原先的脚本无法在控制台上全部输出，所以改成如下的写入到文件的形式：

```python
import os
f = open("D:\Cobaltstrike_payload\payload64_process.txt","w")
file_bytes = list()
for a in open("D:\Cobaltstrike_payload\payload64_process.bin","rb").read():
    file_bytes.append(hex(a).replace("0x","\\x"))
f.write(''.join(i for i in file_bytes))
f.close()
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f1281483855a07eb9574f1ba71168c22b0f52200.png)

同样的把其插入到 64 位免杀框架中生成 exe 文件，运行后成功上线：

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

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-74a7b917ee7e71187cc6fdc3bdb02dd342141fef.png)

#### 转换思路——局部分析：

由于程序体积太大，短时间内无法完全分析，所以我们先来看 Google 规则中给出的部分，并在定位代码之后根据局部上下文和经验判断是否较为特殊：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-683ad3b917125d0066baf1e3f3e2b028eb229b06.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c46ac9a070d954b08d294ce080663fe3b65ab114.png)

#### core\_sig 规则分析：

规则中有两个要匹配的字节码，第一个看起来像是动态加载中的使用的，而第二个不是很懂，那就先定位到第一个字节码$core\_sig。

首先把前面搭配免杀框架生成的 exe 扔入 IDA 中，由于是字节码输入嵌入的动态调用，所有代码都是未反编译形式，所以我们要先用热键 P 初始化所有相关的函数引用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-cf8d163437629c3044d915e5cbcd713f896bc10c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-915f792cc6b8909e1cc7caa39414b36efef45f6d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8fa85f938cf2dc1c3efd11e271115dfced9c7e46.png)

通过 search 将第一块匹配的字节码定位到函数 sub\_1A1E6ED75BC 中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-5ecc82fdf3f6c2dc9cff03f02fc3fb328d54e9fb.png)

该函数的反编译如下， 从逻辑上看是动态加载操作，a1 数组存的应该是函数地址，无非是 GetProcAddress 这些：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7a6e2923e5f4e2503c4115f3fadb5f4065e36270.png)

在附近函数中定位到 sub\_1D1E53071CC 函数，该函数执行的便是动态获取函数操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d39fc8ac69feab393f59957ade02099b723e712f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-65ffe0e8c1afd159729af643cf74aa4361c2ce1d.png)

获取的 dll 是 kernel32，而最后 a1 中函数地址的顺序分别是 GetModuleHandleA、GetProcAddress、LoadLibraryA、LoadLibraryExA、VirtualAlloc、VirtualProtect

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-effb311484ae9ca7fe7e3e7257808a7aad0889db.png)

那么这一轮操作下来就是反复动态获取。。。。不过在恶意软件中也确实经常有这种操作，虽然以我的水平暂时理解不了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e20929d1a2cceee070a34544020b50db913af27e.png)

##### 规则评估

那么这个规则提取得怎么样呢？我觉得还是很好的，因为要满足这个规则首先他的相对位置要对的上，它得恰好是 var\_40 开始赋值。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-eb49f36019f59c7ab7db5d212508c9742e469720.png)

第二个就是它相对 rsp 这个位置，要刚好在 rsp+88h 处就得有一样的局部变量的数量，也就是 sub rsp,80h 这个操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-318b25b577a94408367d04dfd3cb019b8667fdca.png)

所以总得来说该规则还是很独特的。

#### deobfuscator 规则分析：

现在来看第二个 deobfuscator 规则，这代码我也不知道啥意思，先定位看看：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e5343e063a52f5061a61d99c47b305714d8853c8.png)

结果定位到 sub\_1F0636A70CC 函数中，如下所示，看上去像是一个异或加密或解密函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-9fe8bcab166fa15ebf5477041c65df827554fd13.png)

查看一下调用位置，发现回到了最外层那部分，现在我们分析前面部分来获取传入参数的含义：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d8c4729f4a0834acb02ddbdc3b34b89753cbdc0f.png)

第一个参数值 v10 = sub\_1F0636A713C() 中函数内容如下所示，0x5A4D 和 0X4550 分别是 MZ 和 PE，所以这是要定位到给定范围内的 PE 结构文件。

而 sub\_1F0636A70BC() 返回的 \[rsp+0\] 得关联到免杀框架层中 call Memory 那里，只有那里才是最近的 rsp 的赋值，所以这里 \[rsp+0\] 得到的是自己 shellcode 的起始位置。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3e171211ac78e5f431b26157091936e291cd461d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-de29951566d2a040b2eec2a472e358177dbd0b73.png)

所以 v5 的值是 NT 头，v8 的值不明觉厉，因为 0x8000属性是被废弃的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e2a7f898c00dcf80167ceb339a300b5f3cc99510.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-9a58e01c4a463f84297875ef4c97f3d1a08fbaeb.png)

接下来是 v6 = sub\_1F0636A780C(v14, v5, v10, v8) 传入的分别是前面获取的函数地址数组，NT 头，DOS 头，和不明觉厉的 v8，函数内容如下所示。

可以看到其想加载DOS的0x44位置处的模块，但是那里没有东西，所以最后调用的是 VirtualAlloc 分配了一个和该 bin 文件同样大小的镜像区域作为后续填充。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0921652c4303e5231994938c50766ff34ed125a7.png)

然后来到v7 = sub\_1F0636A79DC(v6, v5, v10, v4) 中，传入的参数分别是前面开辟的同样大小的内存块，NT 头，DOS 头，和调试符号数量（为0）。

函数的内容是把自己的 PE 头复制填充过去，而且由于充定位值为 0 ，里面的 IF 语句并不执行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-80a27268296db2b15e8a792ffd1c095cdc23993b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3c6b6d278d8f34a83092a1d1b1e726089d945098.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-83fc8758091df90c290978a0b8c220f99eddb36c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-4b8c5d95fecd4108f1729d7958f5baff7a06c89d.png)

继续定位到 sub\_1F0636A7B9C(v14, v7, v5, v10, v3)中，传入的参数分别是函数地址数组，开辟的内存，NT 头，DOS头，v3 也是调试符号数量（为0），该函数是要分析的 sub\_1F0636A70CC 引用之一。

函数先定位到自己 bin 文件中导入表的 name 字段处复制 40 字节过去，然后调用 sub\_1F0636A70CC 函数进行异或处理，可是 a5=v3=调试符号数量（为0），所以并没有进行异或计算。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-960490c0a5e24ca9786bd841404e2cf33f108a85.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-cb78fcba07c871f4c8a03ae3dedf15551a75d961.png)

后面就交叉着走了，导入表——&gt;DLL——&gt;导出表——&gt;函数地址：

1：对于前面获取的导入 dll 名，通过 LoadLibraryA 加载其基址

2：对于自身则进一步定位到桥1指向的 IAT 获取 dll 内相关导入函数名字，符号等信息。

3：对于每个获取到的导入函数名，如果是符号导入的（有函数名），则以偏移量定位的方式定位到 dll 的导出表中来获取导入函数地址。反之如果是序号导入的（无导入名），则用 GetProcAddress 函数搭配 dll 基址来获取导入函数的地址。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1cdad3b92ecba709d2f0e4095c8c6ab0cce0103b.png)

##### 规则评估：

到这里基本局部分析完了，sub\_1F0636A70CC 由于第三个参数是 IMAGE\_NT\_HEADERS64-&gt;FileHeader.NumberOfSymbols 调试符号表中的符号数，而该值为 0 所以一直没有执行异或处理。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-75da294783937dbb893f944af572e610ab98c17b.png)

更关键的是在整个流程中这个异或函数一直很突兀，因为全部都是依据 PE 文件结构特性的操作，都是导入表、导出表、数据目录表，DOS头、NT头这些。这个异或如果根据 NumberOfSymbols 调试符号数进行异或操作的话则应该是作者有意为值，比如特定的解密什么的，因为CS生成的bin文件确实和普通文件很不一样。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-baa47d338c4972cdae2c973c36d890533578a339.png)

所以这个规则也很不错，提取出了 PE 操作之外的特殊部分.

总结：
---

一开始的计划是先分析再看规则的，结果由于体积太大直接被绕晕了，来来回回断了好几次。最后想先放弃的时候突然想到先从规则的局部范围入手，结果还真的把第一个函数块给梳理出来了。再透过局部逻辑反观 Google 规则，便是这篇文章的由来。

上面的分析中，如有错误还请指正！

参考链接：
-----

[Memory Protection Constants (WinNT.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)

[IMAGE\_FILE\_HEADER (winnt.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header)

\[Vergilius Project | 2104 21H1 (May 2021 Update)\](<https://www.vergiliusproject.com/kernels/x64/Windows> 10 | 2016/2104 21H1 (May 2021 Update))

[User-driven Attack Packages (helpsystems.com)](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/init-access_user-driven-attack-packages.htm#_Toc65482753)

<https://www.cnblogs.com/YenKoc/p/14532409.html>

[IDA Help: The Interactive Disassembler Help Index (hex-rays.com)](https://hex-rays.com/products/ida/support/idadoc/index.shtml)

[奇安信攻防社区-用 Yara 对红队工具 打标（四）——cobaltstrike 生成马浅析（二） (butian.net)](https://forum.butian.net/share/2073)