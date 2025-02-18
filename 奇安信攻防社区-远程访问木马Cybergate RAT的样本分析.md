前言
==

CyberGate 是一种远程访问木马 (RAT)，允许攻击者未经授权访问受害者的系统。攻击者可以从世界任何地方远程连接到受感染的系统。恶意软件作者通常使用此程序窃取密码、文件等私人信息。它还可能用于在受感染的系统上安装恶意软件。

IOC
===

| Hash | Value |
|---|---|
| SHA1 | 83ebbf632e25dbe69b060d190a42a5125ffe3902 |
| MD5 | 0ee2f7d6a851faf44bf235186be91a19 |
| SHA256 | b64c40843b011d715c431b761680e8565383ac702f5ed80492fb30bd6aa33929 |

unpame链接（dump文件下载地址）：<https://www.unpac.me/results/7ec3268f-b1ed-49af-a8ff-218513c127db/>

DIE静态分析
=======

分析第一步，借助PE查询工具，这里用的是DIE：

![image-20240809140658291](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b09f51a3d6607e2375465ae0cfcd8e12e59591dc.png)

32位程序，可以看到加了UPX壳（这一类壳最简单，直接脱就可以）。语言用的Delphi。

![image-20240807103512894](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a320c34a7d89b402c792b6441d68b76b0e676b54.png)

查看节表也可以发现，没有被魔改过，那就直接UPX -d

![image-20240809140749979](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-75ca9127ff9a526454475ad97373697e1eb24ab6.png)

脱完壳的文件会直接覆盖掉原文件，DIE继续深入分析

查看信息熵，信息熵可以判断该恶意程序是否有被加壳混淆，或者是在内存中载入了一些有效负荷。

![image-20240807103822341](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e3f698f58177aee1b1d6ad27a2a485fd927a3a7b.png)

加了壳的，准确来说是.rsrc节被加壳混淆了；图表上具有高而平坦的熵值区域，说明很有可能该恶意软件具有注入的行为，即注入了代码到内存中。

可以查看导入表，再次肯定这一推测：

![image-20240807104102308](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e1d8cf1df8a893089a25996f69a1cf711caf6296.png)

发现函数 `VirtualAlloc` ，该函数是合法的用于分配内存的函数，但是恶意软件经常用它来进行一些注入行为。在地址空间中分配一块内存，将恶意代码注入其中并执行。

字符串方面查看了，但是没有什么可疑信息。

沙箱大致行为
======

用沙箱查看一下大致的流程，仅作为参考。（高级分析要收费，普通用户的随便看看）

![image-20240807104631360](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f2b5e9e2afae80fdcfcace84ec0fc01680c0816e.png)

主进程释放了俩个文件，推测其一就是进程注入的恶意代码。

![image-20240807104739664](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-32f1a6857a327573029d711a6d7ce0a1e463d7d1.png)

可以看到特别多的网络连接，充分说明了CyberGate作为一个远程访问木马的作用。

![image-20240807104851590](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b27e040d60cfd467218a8ccb4728a1d799942507.png)

其它没有什么了，还是得手动分析。

IDA初步分析
=======

IDA配置
-----

语言用的是Delphi，IDA可以做些修改

禁用分析：

![image-20240809140822420](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-03e45bc19bc0b536ee76120ed13291bb563aa56c.png)

Option -&gt; Compiler options

![image-20240807105927181](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-de95c90435fa0172b7b5c1d19ca7eff222e7b439.png)

Options -&gt; general -&gt; Analysis

![image-20240807110006849](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a530ecf2fd4f0ee822fc603bf3cd868a846dd4fe.png)

点击OK，可以开始分析了

创建互斥锁
-----

start函数开始先用`CreateMutexA`创建了俩个互斥锁：

![image-20240807110531259](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b262af5633cae4d0db3e4fa12862508ff1630836.png)

![image-20240807110621781](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1f67e8b4dd20e77a6efd682d78e9b1a482f358a8.png)

分别是 `"_x_X_UPDATE_X_x_"` 和 `"_x_X_PASSWORDLIST_X_x_"` , 用`GetLastError`获取错误码，与0xB7比较。

第一处互斥锁如果存在，它会关闭互斥句柄并会休眠12秒，不存在的话就直接关闭互斥句柄。

一般情况下，互斥锁都不会存在，也就是这里不会进入if判断，往下走：

![image-20240808161803440](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ac77f878ceec26e3e4cb8f978078295fc9c067e6.png)

else中又是互斥锁，不用理会，继续向下

![image-20240808162136771](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-78ae52cfe6d9817ab614a1be333a743c0b4fe049.png)

创建文件
----

在 `sub_40B93C`中的`sub_405D70` 发现了`CreateFileA`函数：

![image-20240808162252815](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a71fbe0a812603e3873b43cf637f14b0b564951f.png)

在这里创建了一个文件并写入数据，字符串str\_XX**XX**XX\_txt，实际上就是XX--XX--XX.txt。这个正是我们在沙箱中观察到的释放文件。

注入技术
----

继续往下，在函数`sub_40B7FC`中发现了关键操作

![image-20240808162456008](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7a3ed70837f3c2bdcaf715a81e337566ef85f578.png)

先是通过`FindWindowA`函数尝试查找**Shell\_TrayWnd**窗口，后检索其进程ID，如果没有找到的话就会创建一个名为 explorer.exe的新进程，然后使用 **ProcessInformation**、**hProcess** 作为参数调用`sub_4040F4`。

进入函数`sub_4040F4`：

![image-20240808162905286](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9f2f8a26f163ee6521b459b416cd19c1b07d14d3.png)

无疑，发现了`VirtualAlloc`函数，恶意软件惯用的伎俩，通过该函数分配内存，之后`WriteProcessMemory`写入恶意代码并执行，依次排查下面的函数，最终在`sub_4038AC`中找到了执行代码的函数。

![image-20240808163057401](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-10064ff8d396d4604b9340457377a70b53c9505b.png)

通过函数`CreateRemoteThread`创建一个在另一个进程中的新线程来执行恶意代码。

提取二阶段
=====

![image-20240808163630971](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-10d26ca624f4f7b6b4f4fcb8b3d27527789229ed.png)

要想提取出有效负荷，就需要先过掉前面的互斥锁。我先是尝试了在`GetLastError`上设置了断点，但是，实际上发现，互斥锁根本就不会触发。那么直接`bp VirtualAlloc`

之后程序会陷入异常。仔细检查后发现问题出现在中间的一个call函数上，

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1080efc3d20c6760bbd77da81c140af5f837af0a.png)

IDA反编译后会报错：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-446ae39531d10fc57f43f2e37779f121683e280d.png)

从汇编上看是这样的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8caa0e29873c05bb5f71de8be9c98bcbb93a2115.png)

会一直call一个函数，然后cmp比较不符合就exit了。符合也是一直向下。不太想深入去调它，做了一个比较暴力的决定，直接nop掉了该函数，（不清楚后面会不会有影响）

在xdbg中nop掉之后，就可以F9运行了，断点会命中`VirtualAlloc`

在这里用硬件断点可以提取出内存中的恶意代码，具体如何操作，可以查看我近几篇文章。

断点命中后，Ctrl+F9得到函数的返回值，即分配内存区域的基地址，跳转到内存中，对第一个字节下硬件断点。

~接着F9 Ctrl+F9继续跑，慢慢跑，好像会再断俩次在`VirtualAlloc`上，最终，可以得到如下内存区：~

上面说错了，这样dump出去的文件只有几kb大小，在IDA分析的时候忽略了。这次的分配内存和之前的不同，之前是只执行一个`VirtualAlloc`，该恶意软件是循环多次分配内存，直到满了才结束

![image-20240808170701485](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-805223c5aa043e3f79f8e5cfe540502630a7dc46.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1cc404cf48971cfa424de7759a09675490f71d95.png)  
这里折腾了一会，还是有点残缺，因为dump出来的文件也是带壳的，upx没有魔改但是还是会报错。应该PE结构也被损坏了。

有个思路是通过写条件断点来自动化执行的，但是能力有待提高，最后还是选择使用沙箱dump出的文件。

第二阶段分析
======

使用unpacme可以dump出三个文件

![image-20240809140127783](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5549a843bf195c803fcf45d7a3b6960d0e818702.png)

第一个样本
-----

![image-20240809141207854](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-10affde3ceb2b1a2855489288b133ef3706f21d2.png)

是一个Delphi编写的dll文件。

### IDA分析

入口点：

![image-20240809141349310](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fcc289bf434feafb63241d629aff5135c8e9a93a.png)

没有什么值得留意的。查看导入表

有一个`StartHttpProxy`值得注意，前言说过这是一个远程访问木马。

### StartHttpProxy

#### 逃避防火墙

![image-20240809141559644](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f73e0c11f34265d958d4732f38b3bc2464c4fde2.png)

函数`sub_4302E4`接收的参数1字符串代表的是 **'Windows Firewall Update'**，说明这里可能进行了和防火墙相关的操作。

![image-20240809141925033](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-19ec5e831b6ff3c8620045c545a26574b956a1ec.png)

进入到该函数中：

![image-20240809141958246](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0a08e4ba5328bb6bc66b8ca15e599204bc11c709.png)

该恶意软件使用`Registry::TRegistry`类来操作注册表，完整的路径下来是：**SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List**，恶意软件会尝试打开该路径，如果不存在就创建它。

之后`LStrCat`可知将字符串拼接起来：将v2和`':*:Enabled:'`和`'Windows Firewall Update'`拼接起来给v7

![image-20240809142718490](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1804c9612a4bc58de8cf2fa8e406eb7b03d778bc.png)

之后将拼接起来的v7写入上面的注册表中，并以**System\_\_AnsiString**作为值名称。

“Windows Firewall Update”应用程序已添加到授权应用程序列表中。“\*:Enabled:”部分通常表示已为该应用程序启用所有端口和协议，可能允许其通过防火墙自由通信。

这意味着恶意软件可能以“Windows Firewall Update”的名称运行，以逃避防火墙。

#### 启动HTTP代理

![image-20240809143217873](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6eca469d9ec586ed307cc833645b28639d07c9a2.png)

在设置完防火墙之后，`sub_430214` 初始化了一个`TIdTCPServer`对象，表明了这是一个TCP服务器。

#### 创建互斥锁

![image-20240809143418928](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-83d137e76ead77125b63825e9ab86f19891c6dec.png)

![image-20240809143428559](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1dbb0186575746073507f90a961b496bff289d4d.png)

### GetChromePass

这个导出函数看名字就和Chrome有关：

![image-20240809143814220](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ca7415a835f00c32d15413e2b52d6432ef7ae573.png)

定位到函数 `sub_420C04`

![image-20240809145720432](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-005521d5f8a8af6e21259976d4b9db0a8df900b3.png)

**'Local AppData'**作为参数，分析`sub_41E4F8`

![image-20240809145842478](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7f575931a3aa28c8de0ef59ffe81db55ea2c231b.png)

恶意软件将字符串**“SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders”**分配给v8，并将字符串 **Local AppData** 分配给v7。

![image-20240809145957094](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6b17346bb8d70084fe9d09e114fe758a37badf82.png)

在这里，从给定项 (Local AppData) 注册表 (SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders) 下的 Windows 注册表中检索特定值。

将文件从**“\\Local AppData\\Google\\Chrome\\User Data\\Default\\Web Data”**复制到`.tmp`文件夹

打开名为**“\\x0FTSQLiteDatabase”**的 SQLite 数据库

循环遍历数据库查询结果，然后检索并处理password\_value、username\_value、origin\_url。

使用`CryptUnprotectData`解密数据 (pDataIn)并将其存储在 pDataOut 中

### Mozilla3\_5Password

获取获取 Mozilla 的个人凭证。

![image-20240809150418714](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8aa53bf472e25f5ff9a4a6154bb6131ee58012e6.png)

对user和passwd解密：

![image-20240809150616673](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7e697f11edf1f8bd0df9caef88fb5e285bad8710.png)

第二个样本
-----

该样本同初始文件一样。

第三个样本
-----

![image-20240809150858346](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-36395edea435a9805d105179e339a53584ff6cd1.png)

![image-20240809151145075](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fc93193be4f45c0cded00cf5e7aac13f19372453.png)

该dll没有导出函数，只有一个入口点：

### 实现持久性

![image-20240809151339006](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2ae578ddc254ad80b5d4605f7327430e331042d7.png)

查看字符串发现很多关于注册表的操作。

**Software\\Microsoft\\Windows\\CurrentVersion\\Run**用于在用户登录时自启动的操作，**\\Policies\\Explorer\\Run**也是用于配置系统启动时的程序，不过它由系统策略控制，用于在特定情况下强制启动。

### 进程注入

![image-20240809151929652](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-bb0e99b53edeccf849c9dc94020129024f30420d.png)

创建进程和获取进程ID

![image-20240809152058057](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3de5f7327e772004daec6d26ffbfe783cf87b62d.png)

然后它使用`LookupPrivilegeValueA`，**“SeDebugPrivilege”**

恶意软件使用 **SeDebugPrivilege** 获取访问权限，以调试和调整系统上任何用户拥有的进程的内存

### 检查Windows版本

在`sub_14043A04`函数中：

![11](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6f757558b848d79834e0c9ae1f0f1c586e1165c3.png)

恶意软件通过检查`dwMinorVersion` 来检查 Windows 版本

如果它等于 1，则表示 Windows 版本是：

**Windows NT 3.1**或**Windows XP**或**Windows 7**或**Windows Server 2008 R2**