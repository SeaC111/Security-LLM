0x00 前言：
========

在前面写过了 [APT 恶意 DLL 分析及 C2 配置提取（子 DLL 篇）](https://forum.butian.net/share/1804)，那是用于恶意样本 C2 配置提取学习的，这里分析的是其母 DLL 篇，主要是想知道子 DLL 和母 DLL 是怎么关联起来的，所以一并分析了。因为子 DLL 和 母 DLL的手法和操作重点不一样，所以拆成两篇来写，避免混乱。建议先看子 DLL 篇的分析过程，因为样本的发展阶段在那里提及，能有一个总览的效果。

0x01 外层 DLL 分析：
===============

样本 IOC：
-------

| HASH | 值 |
|---|---|
| MD5 | e5fcf505c25e66116f288a8ae28d2c8a |
| SHA1 | e597f6439a01aad82e153e0de647f54ad82b58d3 |
| SHA256 | 63996a39755e84ee8b5d3f47296991362a17afaaccf2ac43207a424a366f4cc9 |

**关键行为预览：**
-----------

### **动态获取手法分析：**

#### **动态获取 dll 基址：**

母体 DLL 的动态获取手法都经过反复多次的数学运算混淆，但是底层手法还是一样的，获取 PEB 结构----&gt; LDR 结构----&gt;InLoadOrderModuleList链遍历----&gt;比较 BaseDllName----&gt;最终获取 DllBase。

关键的偏移我们提取出来就是 0xC----&gt;0xC----&gt;0x30遍历----&gt;0x18，在下面的混淆中我们用这种方法来识别出其目的是遍历 PEB 结构获取 DLL 基址。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-94339dfa17cc137a4da5abb3dfc6ec150a63c2c7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3a1d08f2813d3644898b7c67dc9fe7e8b0ed37b4.png)

应用到题目中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-90b808ff90ebd5ec4b190112ea3d70c0fce4a908.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-542dfb919db91a9580d510ce8f73aa8b20f52308.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c050da2c39614d1c7ccb884eb4fb07059bfdfd95.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b276eb4aa82ef967a1b1aa25adbfe47a0752acc4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bcb904b60684200c96ed173d6e92387d91d25085.png)

#### **动态获取导出函数基址：**

同理的，在 DLL 基址上获取导出函数，用的是 PE 结构特性，具体结构体就不截图了，常规的步骤还是如《Windows PE 权威指南》中所说：

步骤1 定位到 PE 头。

步骤2 从 PE 文件头中找到数据目录表，表项的第一个双字值是导出表的起始 RVA。

步骤3 从导出表中获取 NumberOfNames 字段的值，以便构造一个循环，根据此值确定循环的次数。

步骤4 从 AddressOfNames 字段指向的函数名称数组的第一项开始，与给定的函数名字进行匹配; 如果匹配成功，则记录从 AddressOfNames 开始的索引号。

步骤5 通过索引号再去检索 AddressOfNameOrdinals 数组，从同样索引的位置映射找到函数的地址(AddressOfFunctions)索引。

步骤6 通过查询 AddressOfFunctions 指定函数地址索引位置的值，找到虚拟地址。

步骤7 将虚拟地址加上该动态链接库在被导入到地址空间的基地址，即为函数的真实入口地址。

关键的偏移提取出来就是：

DOS头（DLL 基址）----&gt;0x3c（指向 PE 头）----&gt;0x  
78（数据目录表）----&gt;0x0（数据目录表第一项就是导出函数表，IMAGE\_EXPORT\_DIRECTORY 结构）----&gt;0x18 （定位 NumberOfNames 字段构成循环）----&gt;0x20（定位 AddressOfNames 字段，函数名称地址表RVA）----&gt;0x24（定位 AddressOfNameOrdinals 字段，函数序号地址表）----&gt;0x1c（定位 AddressOfFunctions 字段，导出函数地址表 RVA）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c8e33b3697caf496c1fc11296ea3d4960554c46c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fde47e88788c110ab4a374dd4b3367223e521e15.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2e6a4db4bde931ceaaba06292ec46f61c67210d3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0c52c86501ff8e4b6cb491277419f4b6e42160cc.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2a264a987f9d12a8e97aca339ddb118b40d535af.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9f67f6dad364f6da4ee3570fde569da4950b59ee.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2efae482130de822b787d08e8b9d4e18e7e8ff42.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3b3411443e99f81a33ff4fcb85990a4c661b042f.png)

### PE 文件内存映像操作：

这次的分析过程中发现样本把解密后文件格式的 DLL 通过 PE 结构特征进行 PE 文件内存的映像操作，本着学习的目的，所以手法还是跟踪探讨下。

#### **涉及知识：**

分析中需要一些对 PE 文件结构的前置知识，以下是我的一些笔记积累：

**节的属性：**

1：为了保证程序执行的安全，保障内核的稳定，Windows 操作系统通常对不同用途的数据设置不同的访问权限。比如，代码段中的字节码在程序运行的时候，一般不允许用户进行修改，数据段则允许在程序运行过程中读和写，常量只能读等。

2：内存中的节和文件中的节会出现很大的不同。例如 “.data?” 的数据在磁盘中不存在，但在内存中存在。而 “.reloc” 重定位表数据却恰怡相反，在磁盘数据中存在但在内存中被抛弃。

**节的对齐：**

1： 文件对齐：（200h）

为了提高磁盘利用率，通常情况下，定义的节在文件中的对齐单位要远小于内存对齐的单位 ，通常会以一个物理扇区的大小作为对齐粒度的值，即 512 字节，十六进制表示为 200h。

2： 内存对齐：（1000h、2000h）

由于 Windows 操作系统对内存属性的设置以页为单位，所以通常情况下，节在内存中的对齐单位必须至少是一个页的大小。对 32 位的 Windows XP 系统来说，这个值是 4KB(1000h)，而对于 64 位操作系统来说，这个值就是 8KB (2000h)。

**PE 内存映像：（为运行，就是 OD 中解析的 exe 文件，在进程内）**

是指将 PE 文件按照一定的规则装载到内存中，装入后的整个文件头内容不会发生变化，但 PE 文件的某一部分如节的内容会按照字段中的对齐方式在内存中对齐，从而使得内存中的 PE 映像与装载前的 PE 文件不同。

其目的是为了运行。为了配合操作系统的运行，方便调度，提高运行效率。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-07edc6177e74c020a109726008c2d09546a59f93.png)

**要用上的 PE 结构体：（32 位，文件头和节表）**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd141c6dd64a2d1df1fdf6e768afe722515ee743.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5aefc2be3b7d35b4360164a4896250c54d1c0acd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1f7063af7b784c514df5ac034084317044979b6a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-93ea466e3af75b96831cd4a6467686ade84e2db6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-73041bf9018b540ea2e0c1a4d3e3078204027bc3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-39645b0330cb3890771c848fed3bde13fbb68ade.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f1246e8658cd79c18ec91e980023060dd4441690.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7c8613fa6728c67b9e55dc224d521cf776b2c4e1.png)

**定位并提取节表字段信息：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1f754071f1b387849d2c5570af26e2a79f1846b1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c9a9d91869bc66f3a4d3d70b4c60df617a19570c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e0a1a0a2ad6731e5b8b4c220c1a3c7ef84e3bca3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-88f3c647484f8937ada3d5840ec70a3ccbe779cf.png)

**申请、划分并填充内存映像空间：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-23b45a7c405b77491bd8538e82382c421be4a433.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b510d3df433781202fd0d1510beb1f3b00733f19.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1f2b3c91b229043b640a1c94f223c4d0a78504df.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6563bab07726a16f0f1ea3ac7e091a6d73cda627.png)

**节属性分配：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bb68472871b27090dfd4549ad08f434a79133b3f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-df692c9bf6a148e584ccb6daec43e15b8411fd70.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-eb88c4d958f429a2452a9953575991e4db8407a8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-49407323ff298ed23fcf40189539549dda4d9854.png)

#### **手法总结：**

解密出内层核心 DLL（文件结构）----&gt;0x3c 处 e\_lfanew 字段定位 PE 头----&gt;ASCII 4555 确认 PE 标识

定位到 PE 头后：（从这里开始以 PE 头为起始偏移）

0x4 定位 IMAGE\_FILE\_HEADER.Machine 字段确定值为14c 的Inter 386 架构----&gt;0x38 定位IMAGE\_OPTIONAL\_HEADER32.SectionAlignment字段获取内存中节的对齐粒度（后面映射时使用）----&gt;0x14定位IMAGE\_FILE\_HEADER.SizeOfOptionalHeader字段获取扩展头大小----&gt;扩展头大小加上 IMAGE\_FILE\_HEADER 的 0x18 大小就定位到节表项了。

定位到节表项后：（从这里开始以节表头为起始偏移）

0xc 定位 IMAGE\_SECTION\_HEADER.VirtualAddress 字段获取节区的 RVA 地址（在内存映像中用到）----&gt;0x10 定位到 IMAGE\_SECTION\_HEADER.SizeOfRawData 字段获取节在文件中对齐后的尺寸（在内存映像中用到）----&gt; 加 0x28 遍历下一个节表继续获取相应字段（节表项40字节大小）

最后就是空间申请，划分，填充，段属性分配了。

**行为分析：**
---------

### **开辟空间，填充数据并解密成内层核心 DLL（文件格式）：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2c8f15c71f501a1a9425113063e5cfd6adef46e6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-19378f6147a94850d5c154b5794a035e10a6eebe.png)

### **检索系统信息：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e24f65b712060679d190b387fb29039a2dd64e55.png)

### **进入内核 DLL 中，检查参数，开启线程：（这里我重新调的，所以地址和前面对不上）**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3943476fc65cf4ecbea804558222fee5765e5993.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7d4006c8848744b3a680cbd36477437b7a72ecda.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-90b3f6d523f8a1428c5ce8aaaa82d73c5fcd0ee4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4656e1310f679aa0dfe5fee9c42fe4a9ca9ec0fb.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-90a90d1f5c1d13d971706d038360fb3cc40c9f7c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8e877c477cdfdf5b66fd4fecae990f3b30d5faab.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-14eb5204de53d74851a5ebefa0aa9ec33c4fe6f7.png)

### **设定参数重新执行，直接来到母体的 DllRegisterServer 函数：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6d2b9d1dc290fdd2d830f70d1b85187d0c21ad1a.png)

0x02 母 DLL 与子 DLL 关联梳理：
=======================

母 DLL 与子 DLL 的联系现在理清了，母 DLL 在解密子 DLL 并进行 PE 内存映像操作后进入子 DLL 的入口点中获取并凭借路径和参数，开启新的进程来运行母 DLL 的 DllRegisterServer 导出函数。但其实际上是一个过渡，过渡到子 DLL 同样的导出函数中进行操作。

0x03 函数链顺序划分：
=============

分配空间：（混淆操作）

malloc----&gt;free

PE 内存映像操作：

VirtualAllocExNuma----&gt;memcpy----&gt;malloc----&gt;“data\_operation”——"PE 文件"----&gt;VirtualAlloc（文件头和每个节表各一次）----&gt;VirtualProtect（除 .reloc 节表外各一次）----&gt;VirtualFree（内存映射中释放 .reloc 段）

检索系统信息：

GetNativeSystemInfo

比较参数：

GetCommandLineW----&gt;“截取逗号后字符”----&gt;lstrcmpiw（对比 L"DllRegisterServer"）

拼接参数，开启线程运行：

SHGetFolderPathA----&gt;GetModuleFileName----&gt;L"%s\\rundll32.exe \\"%s\\",DllRegisterServer"----&gt;sprintfw（L"C:\\Windows\\SysWOW64\\rundll32.exe \\"C:\\Users\\xxx\\Desktop\\1.dll\\",DllRegisterServer"）----&gt;CreateProcessW