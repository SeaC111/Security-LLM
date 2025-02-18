0x00 前言
-------

本文主要是通过IDA对一个恶意dll样本进行分析，来熟悉IDA的基本操作，也可以了解到一些恶意样本的底层逻辑。

### 0x01 Dllmain 的地址是什么？

BInary file: 二进制文件

选Binary file这个选项 是因为恶意代码有时候会带有shellcode、其他数据、加密参数，甚至在正常的PE文件中带有其他exe可执行文件，并且当包含这些附加数据的恶意代码在Windows上运行或者被加载到IDA 时，它不会被加载到内存中。因此，当加载一个包含shellcode的原始二进制文件时，应当将这个文件作为二进制文件加载并且反汇编。

但是这里切记刚开始就选portable 模式，不要选Binary FIle，我刚开始就选的Binary File，怎么也找不到入口点，具体原因还未知……  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f846175ae1fd303c5b2bf5bf0f43e6778d7a0cf7.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f846175ae1fd303c5b2bf5bf0f43e6778d7a0cf7.png)

就像下面一样

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0a4e978f0014079fcd2bba9c18d1a77a7ee30b19.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0a4e978f0014079fcd2bba9c18d1a77a7ee30b19.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-db0aed0d10728fedf76cb1cf283f9087e87c1e85.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-db0aed0d10728fedf76cb1cf283f9087e87c1e85.png)

跳转到 `1000D02E`处，这里 开始执行汇编指令的地方才是 dllmain 函数的入口点，虽然前面这个地址也有很多行，但都是注释，并没有实际含义。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e98158ca02b79fb32c6a87cbdee476990f7000ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e98158ca02b79fb32c6a87cbdee476990f7000ed.png)

切忌分析前面的那一段，因为所有从 `DllEntryPoint` 到 `Dllmain` 之间执行的代码一般是由编译器生成的。

### 0x02 使用imports窗口并浏览到 gethostbyname，导入函数定位到什么地址？

首先定位下这个函数，

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5eae513900fa4118ea2450101bcbfc7ad4bb721d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5eae513900fa4118ea2450101bcbfc7ad4bb721d.png)

最终定位的地址就是 `idata` 区段的 `100163CC` 处

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f9f8bd6e84cdd1461c43ba7405476d157167d4bf.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f9f8bd6e84cdd1461c43ba7405476d157167d4bf.png)

### 0x03 有多少函数调用了gethostbyname？

右键该函数名， `Jump to xref to operated`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-895efe6061bc85359e02fe4737fc0b8219ae6bdf.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-895efe6061bc85359e02fe4737fc0b8219ae6bdf.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-03ca308fc0a268819104980299c30c9361670f3b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-03ca308fc0a268819104980299c30c9361670f3b.png)

`Type` 中的 `r` 是 read，读取的意思，函数首先要被cpu读取，才能够被调用， `Type`中的`p`是被调用的引用

这里就是5个函数一共调用了9次`gethostbyname`函数

### 0x04 0x10001757 处,哪个DNS请求将被触发？

首先 g 跳转到 `0x10001757` 这个地址

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a7d3f70d4aa06fa01bf1efcb9870c839d1db6c49.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a7d3f70d4aa06fa01bf1efcb9870c839d1db6c49.png)

简单分析下这段汇编

首先， 将 `off_10019040` 赋值给 `eax` 寄存器，接着 地址位 + 0Dh(转换为10进制就是13)，就是将地址往后偏移 13 位，然后`push` 入栈，接着 `call` 调用 `gethostbyname` 参数。

大概流程是这样，要找 被触发的dns请求，就一个个分析地址吧。先拿`10019040` 开刀，

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c8924d52ef1fe3bbdf11ccd7a08c87d2f7d3a799.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c8924d52ef1fe3bbdf11ccd7a08c87d2f7d3a799.png)

找到了一串字符串，跳转到这里看一看，找到完整的字符串 `pics.praticalmalwareanalysis.com`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d4fe3f0699bfc0a217c6932b76c0ded51a1de616.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d4fe3f0699bfc0a217c6932b76c0ded51a1de616.png)

所以，`off_10019040` 是一个字符串指针，指向字符串的 `[This is RDO]pics.praticalmalwareanalysis.com` 的第一个字符，然后`add 0Dh` 后，偏移13位，指向字符p，最后 `push`入栈的值是 `pics.praticalmalwareanalysis.com`

### 0x05 IDA 识别了在 `0x10001656` 处的子过程中的多少个局部变量？

还是先跳转到这里，

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-afbd08ef637a88bb1e54417929aeda09f2260109.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-afbd08ef637a88bb1e54417929aeda09f2260109.png)

数一数，一共24个局部变量。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6dd6725d659fa90c1a4c95076e14e0330ec18748.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6dd6725d659fa90c1a4c95076e14e0330ec18748.png)

### 0x06 IDA Pro 识别了在 `0x10001656` 处的子过程中的多少参数？

首先搞清楚参数的定义： 参数是调用这个函数的函数传递给被调用函数的值

很明显，这里只传入了一个 `LPVOID`类型的参数 `lpThreadParameter`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7ca9a6813d75eee83f975ce332ab695acc4b5462.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7ca9a6813d75eee83f975ce332ab695acc4b5462.png)

### 0x07 使用string窗口，在反汇编中定位字符串\\cmd.exe /c。它位于哪？

string 窗口： `shift+f12`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5e7fdf0ab4b22905bff33a142af25f69268b522b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5e7fdf0ab4b22905bff33a142af25f69268b522b.png)

定位 cmd.exe 的地址

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-faf64b944ae2d803e3b474b0afc636e99989d462.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-faf64b944ae2d803e3b474b0afc636e99989d462.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0c513ee495708f83c0be6b1f82902b51fd0bc084.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0c513ee495708f83c0be6b1f82902b51fd0bc084.png)

定位到地址： `xdoors_d:10095834`处

### 0x08 在引用 `\cmd.exe /c` 的代码所在的区域发生了什么？

首先查找 `cmd.exe` 的引用源，

右键

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-05e3eea1c0bf5c8f57731ecdbf2b5fbfe062f03f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-05e3eea1c0bf5c8f57731ecdbf2b5fbfe062f03f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0bc4b4a1b61dc09287cc90eb69fed821133aa4e5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0bc4b4a1b61dc09287cc90eb69fed821133aa4e5.png)

下面就分析下这段汇编

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-627475a4b8c2449469efe1690f6b7799c80f5fee.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-627475a4b8c2449469efe1690f6b7799c80f5fee.png)

首先第一眼看到的是将 `\\cmd.exe /c` 字符串 `push` 入栈，

点击字符串，跳转  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cdc4341c971dfd8b75d40f74802023cf5cdc5380.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cdc4341c971dfd8b75d40f74802023cf5cdc5380.png)

看到这些字符串， `Hi… Welcome… Machine Uptime… Machine IdleTime…Encrype Magic… Remote Shell Session…`

大概也能猜到这是一个获取机器信息的远程shell会话

定位一下字符串的地址，看到还有 `language /robotwork /mbase /mhost`等等，获取的都是一些系统信息

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cd03301261d02e83c71ea0a5f51980b1ca9e83bd.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cd03301261d02e83c71ea0a5f51980b1ca9e83bd.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-602259fc4eca68bcbaa39715f1a63e3c23fabffd.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-602259fc4eca68bcbaa39715f1a63e3c23fabffd.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bc0d470be30893002be8fb48f8d2b29f27d079dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bc0d470be30893002be8fb48f8d2b29f27d079dc.png)

### 0x09 恶意代码是如何设置dword\_1008E5C4的呢？

老惯例，先跳，  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6b44ff02ed3c7ee419ac5759008a0181128d9511.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6b44ff02ed3c7ee419ac5759008a0181128d9511.png)

接着右键查看下交叉引用,或者 `ctrl + x`

3个指令，两个 `cmp`, 只有第一个 `mov` 指令改变了该地址值

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a424c388553edf773ea0425f3dfdd8ec04026081.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a424c388553edf773ea0425f3dfdd8ec04026081.png)

跳：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1e053dfa57ddace3e2312f5c11cd6dbad4698d25.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1e053dfa57ddace3e2312f5c11cd6dbad4698d25.png)

来看一下这条指令的前后都做了些什么。

在`mov`之前 `call sub_10003695` ,那就先看这个函数地址到底返回了什么东西。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bf44771a934d71b3bfddaf3bb50139053930149b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bf44771a934d71b3bfddaf3bb50139053930149b.png)

先根据几个字符串猜测一下吧，`VersionInformation/ dwOsVersionInfoSize/ Getversion/ dwPlatformId` 首先猜测跟操作系统的版本信息有关。

比较关键的几步操作就是：

```php
xor eax eax:    将eax清零，此前eax中存放的是 GetVersionExA 的返回值    

cmp:            将 ebp+VersionInformation.dwPlatformId 的值与2进行比较（VER_PLATFORM_WIN32_NT等于2的话，代表的系统为Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003, Windows XP, or Windows 2000）

setz  al:       当ZF标志被设定时，AL寄存器设为1
```

刚刚我们 `cmp`了两个数，所以如果两个数相同，ZF=1，然后setz，AL被设置为1，反之不相同的话，AL被设置为0(AL是 `eax`的低8位，对应的AH是`eax`的高8位)，一般来说执行上面命令的都是这几种机器，所以一般情况下 AL 会被设置为1，接着`ret`返回`eax`的值。

所以`ret eax`最后的结果通常会被设置为1,即 `sub_10003694`的返回值是1，接着`mov dword_1008E5C4, eax`,最后`dword_1008E5C4`全局变量的值也是1。

### 0x0A 在0x1000FF58处的子过程中，分析下 robotword 字段

`0x1000FF58`处的远程shell函数从`0x1000FF58`开始包含一系列`memcmp`函数

跳：

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3e65773d5f3948271606e873ca5e2c5a0d2178b3.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3e65773d5f3948271606e873ca5e2c5a0d2178b3.png)

往下找 `memcpy` 函数，看到前面 `aQuit 和 eax` 被 `push`入栈，所以这里`memcpy`这两个值

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2e9fb9f4ebbdabe72dd8a4bf7e00b08ac43c5672.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2e9fb9f4ebbdabe72dd8a4bf7e00b08ac43c5672.png)

接下来找`robotwork`,

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a0a8e5feca0d104bf9f04a9db292af49abc11bf5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a0a8e5feca0d104bf9f04a9db292af49abc11bf5.png)

如果`eax`和 `robotwork`相同，返回0，`0Ch`是`12d`，也是`4(字节)*3(个)`，因为`push`后面跟的是立即数，所以一个数占`4`字节，然后`offset`也是`4`个字节，所以，一开始的`push 9`，和后面的两次`push`，加起来一共是3次，所以这里回收了这3个一共12字节的空间

`test eax,eax` 按位与操作，接着如果 `eax`为0，则`ZF`置为`1`，`JnZ`跳转，`eax`为`0`说明前面的`memcmp`比较的结果是相同，也就是如果前面两个数相同，则`JZ`跳转，`JNZ`不跳转

`push [ebp+s]`: 栈中，`esp`是栈顶指针，`ebp`是栈基址，`esp`地址减小，栈空间增大；`ebp`增加，`ebp`将向栈底偏移 。所以这里是将`ebp`向下s的指针地址压栈.

然后`call sub_100052A2`， 来看下这个地址。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5117acd9c868a1c9696a439f90ef6510dd7f18bf.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5117acd9c868a1c9696a439f90ef6510dd7f18bf.png)

看样子是进行socket通信的函数，

仔细看下这个函数的代码，可以看到它获取了注册表的一些信息。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1a87b45884b331cdc70e35622ac7322e7bbdf2a3.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1a87b45884b331cdc70e35622ac7322e7bbdf2a3.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-77574ff71c638fa11b12f487f2219fbc08ff38aa.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-77574ff71c638fa11b12f487f2219fbc08ff38aa.png)

书上说应该是这两个键值：

`SOFTWARE\Microsoft\Windows\CurrentVersion\WorkTime`

`SOFTWARE\Microsoft\Windows\CurrentVersion\WorkTimes`

我在我的计算机上去对应的注册表目录找，并没有找到这两个键值，猜测可能是以前的Windows版本

### 0x0B PSLIST导出函数做了什么？

打开导出表

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-564c7436d70da3cad618f70fad5a52325c3f597e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-564c7436d70da3cad618f70fad5a52325c3f597e.png)

可以看到这个函数有两条执行路径，判断的条件是由`sub_100036C3`决定的

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b8e8b7d7f2550d1f66f533795292a45a8574786d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b8e8b7d7f2550d1f66f533795292a45a8574786d.png)

来看下 `sub_100036C3`函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-de0c494d172905e0d3b5e580eccb6981390653e1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-de0c494d172905e0d3b5e580eccb6981390653e1.png)

```php
call    ds:GetVersionExA ; 调用函数查看系统版本
cmp     [ebp+VersionInformation.dwPlatformId], 2 ; 这个我们上面说过，如果等于2，是那些windows版本
                                                 ; 包括`Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003, Windows XP, or Windows 2000`
jnz     short loc_100036FA ; 如果不想等，则跳转结束
cmp     [ebp+VersionInformation.dwMajorVersion], 5 ; 5代表特殊版本的windows
jb      short loc_100036FA ; 无符号比较，如果[ebp+VersionInformation.dwMajorVersion]小于5跳转
push    1
pop     eax
leave                   ; High Level Procedure Exit
retn
```

其中，`cmp   [ebp+VersionInformation.dwMajorVersion], 5` 中的5是下面的5

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9534adbef40d0aa29d46db856bf19e11c63594c3.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9534adbef40d0aa29d46db856bf19e11c63594c3.png)

如果是过低的版本，就直接跳转结束，如果是符合要求的版本，则返回 1

然后就是比较跳转，如果`eax`为`0`，`test`之后，`ZF`为`1`，然后`JZ`跳转

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-069266e6923bc41529b2249872410fae7f95f0a9.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-069266e6923bc41529b2249872410fae7f95f0a9.png)

如果`eax`不为`0`，`ZF`不为`0`，然后`JZ`不跳转，也就是如果版本符合要求，就不跳转（跳转之后是直接结束），`ZF` 置为0

如果是不跳转的话，push了一个字符串进去，然后调用`strlen`返回字符串的长度在`eax`中，然后`test eax, eax`

如果`eax`为0`ZF`置为1，`JNZ`不跳转  
反之如果不为`0`，`JNZ`跳转

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b2c92b7b4fb4d593344d3daf1f40b793a7020395.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b2c92b7b4fb4d593344d3daf1f40b793a7020395.png)

假设`eax`为0，`JNZ`不跳转，我们走一下这条线

`call sub_10006518`

可以看到这个地址调用的一个函数 `CreateToolhelp32Snapshot`

`CreateToolhelp32Snapshot函数为指定的进程、进程使用的堆[HEAP]、模块[MODULE]、线程[THREAD]）建立一个快照[snapshot]。`

简单来说这个函数用来获取进程列表。通过`send` 将进程列表通过 `socket` 发送。但是我没有找到 `send` 函数………..

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1a00ed7a5bc22f371c56d0af569c2cae237274ae.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1a00ed7a5bc22f371c56d0af569c2cae237274ae.png)

### 0x0C 使用图模式来绘制出对sub\_10004E79的交叉引用图

首先跳： `sub_10004E79`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-67865d63df40279ed05846d925938801165868a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-67865d63df40279ed05846d925938801165868a4.png)

使用图模式绘制交叉引用图

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b79eec4fb1c7cdf5588cba556fe5c9c850f7938f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b79eec4fb1c7cdf5588cba556fe5c9c850f7938f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ddb2c0323cd051592e75d07829718aebf7efb131.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ddb2c0323cd051592e75d07829718aebf7efb131.png)

默认选项，可以看到交叉引用图  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b624fb84f012ff357a54d70cdbab81456b756076.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b624fb84f012ff357a54d70cdbab81456b756076.png)

可以看出`sub_10004E79`函数调用的有`GetSystemDefaultLangID`、`sprintf`、`sub_100038EE`、`strlen`，而`sub_100038EE`调用了`send`、`malloc`、`free`、`__imp_strlen`，然后`GetSystemDefaultLangID`是获取系统的默认语言的函数，`send`是通过`socket`发送信息的函数。因此可以右键函数名，重命名为 `send_languageId`

```php
ps: 这种快速分析是一种获得对二进制文件高层次视图的好方法，在分析二进制文件时非常有用
```

### 0x0D DllMain直接调用了多少个Windows API？多少个在深度为2的时候被调用?

有两种思路：

```php
1.逐一查看Dllmain函数的代码，在代码中看api调用
2.利用交叉引用图
```

先定位到 `Dllmain`的位置

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8033f0015cb6dd956f559b711decb0dc9e85d276.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8033f0015cb6dd956f559b711decb0dc9e85d276.png)

像前文一样，打开交叉引用图

默认配置后会…一言难尽……

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dfe32df2dc87f4c169f9004b34715332c84b52ad.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dfe32df2dc87f4c169f9004b34715332c84b52ad.png)

这里修改下`Recursion depth(递归深度)`，改为1

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dd02db0f58419182e5a1813b83ececa5ea582f5f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dd02db0f58419182e5a1813b83ececa5ea582f5f.png)

如下就是`Dllamin`所调用的api函数

`strncpy`、`_strnicmp`、`CreateThread`、`strlen`

但是很明显没有显示完全，省略了很多，可以把`Recursion depth`设置为2

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e63faaa042dd9d69c992f4e43a2f82d93b90554e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e63faaa042dd9d69c992f4e43a2f82d93b90554e.png)

也是一个很大的图啊…放大看吧，太多了，这里就不一一列举了

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-beeda2fb60cad24ada642bee46d6126aa63ed823.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-beeda2fb60cad24ada642bee46d6126aa63ed823.png)

### 0x0E 在0x10001358处，对Sleep函数的调用，参数是多少？

先跳后看

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4a8df6f40909446c48d50a5a47f2dd251490af8e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4a8df6f40909446c48d50a5a47f2dd251490af8e.png)

```assembly
.text:10001341                 mov     eax, off_10019020 ; "[This is CTI]30"
.text:10001346                 add     eax, 0Dh
.text:10001349                 push    eax             ; String
.text:1000134A                 call    ds:atoi
.text:10001350                 imul    eax, 3E8h
.text:10001356                 pop     ecx
.text:10001357                 push    eax             ; dwMilliseconds
.text:10001358                 call    ds:Sleep
.text:1000135E                 xor     ebp, ebp
.text:10001360                 jmp     loc_100010B4
.text:10001360 sub_10001074    endp
```

从注释`[This is CTI]30`中可以猜测，睡眠30s

分析下这段汇编代码

```php
将 off_10019020 放入寄存器中，向后偏移 0Dh(13d),push eax 入栈，调用 ds:atoi 函数，接着 eax 的值乘 3E8h，  pop ecx 出栈， 再将eax push 入栈， 调用 sleep ，然后 清零 ebp， jmp到loc_100010B4。
很明显，sleep 函数的参数是 eax，跟踪下eax，首先是从off_10019020这里传进来，接着做atoi函数的参数，然后atoi函数的返回值再乘3E8h，push入栈，作为sleep的参数
```

跳 `off_10019020`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d3ce606631dd7cab3fb11177008e454ae2cab43d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d3ce606631dd7cab3fb11177008e454ae2cab43d.png)

偏移 `0Dh`后恰好是3，所以入栈的指针指向 3，传进去的值是30，`atoi`函数是将char函数转化为int型，接着乘 `3E8h（1000）`，所以`push`入栈的值是3w，而 `slepp`函数在Windows里的单位是毫秒，在Linux里的单位是s，所以这里`sleep`了30s，与最初的猜测也是一致的。

### 0x0F 在0x10001701处是一个对socket的调用。它的3个参数是什么？

跳：

看到在 `call ds:socket`之前，`push` 了 6/1/2 3个参数  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1f9ab18288ba764aced595d560afe75a911980f4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1f9ab18288ba764aced595d560afe75a911980f4.png)

右键单击每个数，选择符号变量

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ec4f209f8a5aa508444679356ac9f14747f87daa.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ec4f209f8a5aa508444679356ac9f14747f87daa.png)

这里列举了ida为这个特定值找到所有的对应常量。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-be50f34f1108e650a1151af077ef5a38d981a127.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-be50f34f1108e650a1151af077ef5a38d981a127.png)

socket函数的原型:

```php
SOCKET socket(int af, int type, int protocol);
```

而常见的创建套接字的参数

```php
SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);  //创建TCP套接字
```

根据入栈规则，先进后出，先找2. 根据注释可以猜测，找对应的`AF`，所以 `2`处传递的参数就是 `AF_INET`

接着看1处的参数，在`socket`中对应的是`type`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9698b777af3eaa2238c1f2032bad1d7c783a077e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9698b777af3eaa2238c1f2032bad1d7c783a077e.png)

最后找6，对应的是`protocol`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ddbd85c0775e7b8c3a9dfdbf97e0b1538f1ee928.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ddbd85c0775e7b8c3a9dfdbf97e0b1538f1ee928.png)

所以整个socket函数的传参是这个顺序

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-798753c7f8aca45a29f6157f7a3c89d8f2ebdaa8.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-798753c7f8aca45a29f6157f7a3c89d8f2ebdaa8.png)

这三个参数大致含义:

```php
AF_INET 用于连接连接对象是IPv4时（对应的IPv6用的是 AF_INET6)
SOCK_STREAM 用于连接方式使用TCP时候（对应的UDP对应的是SOCK_DGRAM）
IPPROTO_TCP 用于继续指明传输的方式是TCP（对应的UDP是IPPROTO_UDP）
```

因此这个 `socket`会被配置为基于IPV4 的TCP连接（常被用于HTTP）

关于`socket`函数的更多资料可以去 `MSDN` 上查

### 0x10 使用socket和IDA中命名符号常量，参数会有更多意义吗？

在你应用修改之后，参数是什么？

这里修改的过程就是上文分析的过程……不再多述...

这里附上链接：[socket function (winsock2.h) - Win32 apps | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5acfd677967cd4a3cb7f48e65ced1f5146572d3d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5acfd677967cd4a3cb7f48e65ced1f5146572d3d.png)

### 0x11 in指令可以用来检测VMware吗？

搜索 `in` 指令的话，通过选择菜单的 `Search->Text`，然后输入`in` （或者`Search -> Sequence of Bytes`，然后搜索 `in` 指令的 opcode,也就是ED）。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5e056bce7822d7dc4919875a23c839ccb0fe15e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5e056bce7822d7dc4919875a23c839ccb0fe15e4.png)

这里的选项建议全部勾选上，不然会产生一堆无用信息。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-828bf17a3510a35379c1f65cd6a19c73cf717a8a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-828bf17a3510a35379c1f65cd6a19c73cf717a8a.png)

如果无法快速定位到有用的信息的话，就一个个点开试。直接找`in`指令，

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-69b4f87abd80d20b735df89a965321b51cf67fd1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-69b4f87abd80d20b735df89a965321b51cf67fd1.png)

定位到这里，`in`指令在的位置是 `0x100061c7`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-56afa38250049cfdde69f69babc28fbcec9d031c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-56afa38250049cfdde69f69babc28fbcec9d031c.png)

在 `0x100061c7`处的`mov`指令将 `0x564D5868`赋值给 `eax`。右键可以看到它相当于 ASCII 字符串 `VMXh`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d7f25d845f847d85e3e1f425583ea55c8379a983.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d7f25d845f847d85e3e1f425583ea55c8379a983.png)

书上说在`交叉引用`中可以看到 `Found VIrtual MAchine` 字符串，但是我没找到……

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-10a558bcd44a86420f49f0aa0d293c7624486274.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-10a558bcd44a86420f49f0aa0d293c7624486274.png)

### 0x12 将你的光标跳转到0x1001D988处，你发现了什么？

先跳：

看到是一些巴拉巴拉字符，不具有可读性。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f267879082f8db64565c5d3562b131f33c0c2be5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f267879082f8db64565c5d3562b131f33c0c2be5.png)

### 0x13 在你运行某个脚本后发生了什么？

大概可以看到这个脚本实现的是解密的操作，通过异或。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6ca7a2ab544e77fdeed0bf45df5e15a656fd724c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6ca7a2ab544e77fdeed0bf45df5e15a656fd724c.png)  
加载脚本后，字符串被解密 `xdoor is this backdoor`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-152ecbb707575daa0d635eeb30283f201b76a30b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-152ecbb707575daa0d635eeb30283f201b76a30b.png)

### 总结

分析恶意样本的过程是比较枯燥的，地址需要来回跳转，逻辑性要求比较高，还需要对底层汇编很熟悉，笔者是第一次使用ida分析恶意样本，学到了很多，也了解到很多不足，长路慢慢~  
个人博客：0range-x.github.io  
欢迎师傅们一起交流~