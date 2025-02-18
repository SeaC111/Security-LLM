0x01 前言
=======

本文主要内容：

> 1、windows uac机制的流程及原理
> 
> 2、windows uac逻辑代码逆向调试分析
> 
> 3、windows bypassuac 构造原理以及实践
> 
> 4、常见uacme里面bypass方法及检测方式

之前分析一个黑产样本里面内置了一堆Bypasss UAC提权的操作，分析完之后测试发现一些杀软这个行为检测不到，于是准备从windows uac机制底层详细分析下Bypass UAC提权的原理和产生的行为有哪些，以及如何针对这种Bypass UAC 提权行为产生的特征进行关联从而落下来一个检测思路；

0x02 UAC流程
==========

一、判断流程
------

UAC的流程，微软有说明文档，用文字和图大致说了UAC的提权过程中的一些影响因素，我们可以先简单了解下：

参考：`https://learn.microsoft.com/zh-cn/windows/security/application-security/application-control/user-account-control/how-it-works`

运行一个可执行文件之前，调用CreatePrcess之前的相关判断流程图如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fa65c8a484bb5251939ec57210ff1fa6d4b4dd58.png)

这里面有几个判断点：

### 1、第一个判断点：ActiveX是否安装

简单查了下ActiveX这个东西是一个windows下的用户交互组件，之前基本都是和IE联动是实现一些功能，但是这个东西现在的电脑上基本都没有了，具体分界可以大致参考，微软弃用ie，转Microsoft Edge的时候；引入Microsoft Edge之后windows在默认情况下不再内置ActiveX；所以这里我们默认都是no就行；

### 2、第二个判断点：检查UAC滑块设置

cmd运行msconfig，工具里面有个更改AC设置，这里就是这个UAC滑块，如下图，我们可以看到其分为四个档次；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8f4d2bbd51141f30783ffeb9199e269bd247284d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c8ef53bf83c88425ac921ac1c65d6a486acd1d2e.png)

对于四个级别的定义：

```php
始终通知 将：  
当程序尝试安装软件或对计算机进行更改时，通知你。  
更改 Windows 设置时通知你。  
冻结其他任务，直到你做出响应。  
如果你经常安装新软件或访问不熟悉的网站，建议这样做。  
​  
​  
仅当程序尝试对我的计算机进行更改时，才会通知我 ：  
当程序尝试安装软件或对计算机进行更改时，通知你。  
对 Windows 设置进行更改时，不会通知你。  
冻结其他任务，直到你做出响应。  
如果你不经常安装应用或访问不熟悉的网站，建议这样做。  
​  
​  
仅当程序尝试对我的计算机进行更改时通知我 (不调暗我的桌面) 会：  
当程序尝试安装软件或对计算机进行更改时，通知你。  
对 Windows 设置进行更改时，不会通知你。  
在响应之前，不会冻结其他任务。  
不建议这样做。 仅当需要很长时间来调暗计算机上的桌面时，才选择此选项。  
​  
​  
从不通知 (禁用 UAC 提示) 将：  
当程序尝试安装软件或更改计算机时，不会通知你。  
对 Windows 设置进行更改时，不会通知你。  
在响应之前，不会冻结其他任务。  
出于安全考虑，不建议这样做。  
​
```

我理解其实就是分了三个档，对应图上就是高中低，中等级占了两个，有点区别，选择中高的时候，系统会打开安全桌面，选择中低的时候不会；

如下图是选择中里面的第一个偏高模式的时候，系统打开安全桌面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-225f5654693c3c59362a55621f0dc1f1a9bc24ed.png)

如下是选择中里面的第二个偏低模式的时候，系统关闭安全桌面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-593fe90e5e24e10d96ad858f55d2eeda47e61704.png)

从流程中可以看到，低就会直接创建；中的话会去校验一些东西，比如可执行文件的签名、过文件清单、注册表等，就是类似白名单的东西，只不过这个表现形式不一样，如果符合白名单就要可以直接创建，不符合就去下一个判断节点；高就是不会直接创建，都会来到下一个节点判断安全桌面开没；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-00364d20a2606e3f8dea70d658914b48a6d1ce3e.png)

### 3、第三个判断点：安全桌面

这个安全桌面本身就会受UAC滑片影响，除非是特定的修改；直观的用户体验就是，uac弹窗时背景是否时灰色的，灰色就是开始，白色就是没开；

如下图，左边时开了，右边时没开：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ca70a47c4906e013407afce50714b5c51acd0911.png)

到这我们就了解这个uac的工作机制了，但是不清楚具体过程是怎么个调用实现的，接着我们来看下这个调用过程；

二、UAC进程逆向分析
-----------

调试环境：windows10 19045

笔者之前学习fakePPID技术的时候，接触过一点uac提权的知识，通过fakePPID技术我们可以实现父进程伪造；并且uac就是利用的这一过程，手动设置被提权运行的进程的父进程；

我们不妨想想，平常我们右击已管理员运行某个程序的时候，最后运行完他的父进程都是explorer.exe，他的父进程真的是explorer.exe吗；

如下图，通过process explorer，我们可以看到explorer.exe进程使隶属于g0用户，并且没什么特殊权限，显然不是system权限；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-093b287bbb7b30234546f2a8194bf808dbd75553.png)

然后我们再看下通过右击运行的进程的权限，如下图，我们可以看到相关其相关特权权限已经变成system的了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c358cb1a6bdfee9a8ad4d95545f737d70e733753.png)

一个不是system权限，没有对应权限令牌token的进程，凭什么可以创建一个system权限的进程呢，这显然和windows安全权限管控相悖；**所以，当我们以管理员权限运行的时候，这里真正创建对应的应用程序的进程不是explorer.exe，当时学习的时候了解到的是consent.exe这个进程做的**；

**真的是这个进程做的吗，所以这次我们深入的来剖析下；**

这里我们可以先看下现象，sysmon全开，手动右击以管理员身份运行任意可执行文件，查看日志；

如下图（去除模块加载、注册表操作后）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b61cf1f2a9a8b473b78539054470e4d069e7f23d.png)

按时间顺序我们简单看下；

第一条如下图，就是我们熟悉的consent.exe进程的创建，这里我们注意看其父进程；可以看到父进程是一个通过svchost启动，在netsvcs组的，一个叫Appinfo的服务；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-eb422231f9e46ef83f672f52c6cbc2dcee914b3e.png)

然后就是consent.exe结束：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-115a0428e9c6796a4f8dceb446255153759c95c9.png)

最后应用程序被创建，可以看到父进程换成成explorer.exe；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4504f627a94810c26482b0e83a39905079d6c517.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8b2f02b468f034469a4aa9e4dfb141187bd1bd42.png)

接着往下，

### 搞清楚两个问题：

第一个问题，谁去创建要提权的进程；

第二个问题，如何去创建要提权的进程；

其实就是流程图中这两部分在哪完成的，如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-52e8986422f38bd7e611a9e2665a279bcc98f78b.png)

#### 1、谁去创建要提权的进程

这里我们直接使用windbg调试explorer.exe，不管怎么说，右击管理员运行这个过程，肯定是先走的replorer.exe 的逻辑，所以在 explorer.exe！`kernelbase!CreateProcessW/A`下个断，以管理员权限运行应用程序（当前uac等级是中等偏上）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-70bf9e9bdd52b7a3829d624ae1a320958bafe579.png)

直接运行成功，没有断点，说明不是explorer.exe 里面调用CreateProcess来创建被提权的进程；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ca5c22e935fb8b7ca47fd87b2818f62e46010e60.png)

普通双击运行，断下来了，此时堆栈如下图，这里我们需要往回找，根据栈回溯，肯定有相关判断逻辑，类似判断这个操作是正常运行，还是要提权运行的，也就是createprocess之前是从哪来的；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1face83013da6d3b5fa656f5e44227c7bcfdc29c.png)

可以看到，最近的是来自一个`windows_storeage!CinvokeCreateProcessVerb::CallCreateProcess`;

使用ida简单看下windows.storage.dll这个函数：

应该是从这来的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b5800cc75886cffbd800cb4b6bc0562f5c833f54.png)

看下伪代码逻辑，可以看到调用这个createprocessw之前，是有个判断的，通过SHTestTokenMembership判断之前检查进程的令牌是否是域中管理员组里成员的(这个是uac的一个判断条件，用户在管理员组，提升权限的时候，会起uac)，所以这里我们回到windbg，在这个函数下断点；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-064504e70e59ec6f4593805084df2e11469bc442.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fd0815d44d6f092c954c4ca1b272fd03715cc6c0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-181f729b54199ec936a850d1756d9b672bf3f7c0.png)

explorer.exe里面下断点：`windows_storage!cinvokecreateprocessverb::callcreateprocess`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-23934aeba64e7c6a52b2e02dd19af4795bb03ef7.png)

再以管理员权限运行，这次果然断下来了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4409a42a01fcaa347f5139e869f86180b3defac0.png)

堆栈和上面一致，

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-86b350dd76adf623f1a61ea7dbbc4bd92698b3ce.png)

进入调试跟踪分析，我们来看下，这个在要uac提权的情况下，这个函数如何走向：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e13424fb5cd65ec5726bb57971e744612cc38d1b.png)

调试发现，提权运行最后都会来到如下函数AicLaunchAdminProcess，顾名思义启动管理进程；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8f579addb849c01903bc4880776ef5dce3b62c89.png)

这个函数里面，调用了rpc函数`AicpCreateBindingHandle`，这里有一个uuid，我们可以大致判断，这里可能是尝试通过这个uuid和com组件进行通信,`201ef99a-7fa0-444c-9399-19ba84f12a1a`;

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e1c8fcc3970d6306aaca7936ce0592df2529e260.png)

通过rpcview，我们看到这个请求的uuid对应的接口是来自svchost的Appinfo服务，就是上面我们找到的那个服务

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b7180a8ba75e7016f40962de38f0c2005ee27ba1.png)

#### 2、如何去创建要提权的进程；

Appinfo这个服务，通过查注册表服务项路径，找到对应的dll文件

`计算机\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f769dbb40bcdefd3f84242b99515d5d2462e1934.png)

接着我们跟进appinfo.dll分析，先找到LaunchAdminProcess相关接口，如下图，应该就是我们上面提到的AicLaunchAdminProcess对应，处理使用

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b0101075ec3f3806e0334a449b7dc1acaeab2e9b.png)

我们详细来分析这个函数，如下第一个判断点，传入的参数r8，对应的文件名是否传入：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5bc7aa72b07df472cecccea594acaff26ffae3ba.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a49d6a285ee411d376d595a3e818222ffd5d4d65.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-effda1df9ae2470f94dc8008438c59bb82ce943f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e7b1053ce3d2c728a6adfabc7096924ff4cf3867.png)

这里我们动态跟（windbg attach svchost 启的appinfo服务，然后右键以管理员权限运行位于桌面上的010Editor），可以看到r8传入的参数就是要打开的可执行文件名称,(`c:\Users\g0\Desktop\010Editor\010Editor.exe`)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ebb24d643f1a190fb1df1b7ebe97cf9304850919.png)

然后在如下位置调用CheckElevationEnabled 判断是否启用了uac，这个CheckElevationEnabled并非微软公开记录的导出函数，当返回0表示uac是开启的；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-54bac032eb052c2492a23f34f56e1d02db08a934.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4a70b9c237cb37760a891c07b7bf9ab99be17c15.png)

然后拿到父进程explorer.exe的句柄：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5c2530628d9efcdcb7af2e883c89aac606c2ee21.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2c1e8cf3ee2aba9ab2f9996d57fbedf25f4bea91.png)

这里拿到后没有做其他操作，其实就是判断下父进程还活着，别rpc过来了，父进程g了，那这边就没必要继续处理了；

然后调用了一个有意思的函数`**RpcImpersonateClient**`，msdn对其的描述如下，意思是模拟rpc的客户段操作，这里其实就是模拟explorer.exe 操作；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2310e2805649ed890ccf0c281adfc5ee892b5592.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0461b07acedb9b13711fceece6f10fa92c7621e1.png)

然后通过尝试NtOpenThreadToken、NtDuplicateToken 复制线程令牌；（\[handle\]-2|0x0xFFFFFFFFFFFFFFFE 指当前线程句柄）当前线程就是模拟的rpc客户端即explorer.exe ，所以这里的令牌token是低权限的令牌；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-83130afa4af1acce2e793388960216bfee729620.png)

并通过NtQueryInformationToken检查是否具备管理员权限：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c6ce9c8bedc7b056be5273b916aa8bd79ef6e5fc.png)

接着，打开要执行的文件句柄；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-40b6ab7aa259405b74c40e1abe591eb553f662b8.png)

成功打开，就会传入文件名，调用CheckElevation函数检查对应的路径执行文件，是否需要提升权限来运行；这里的CheckElevation是从kernel32里面导出来的，但是微软公开资料并没有对这个函数及参数进行解释；我从如下微软的求助链接，拿到了一个参考，链接里面提到可以通过这个函数来检查一个路径文件是否需要管理员权限执行，返回0，则说明需要提权，反之不需要（详细的检查原理可以逆向分析kernel32的checkElevation看，这里我们暂时先不看了）；

`https://learn.microsoft.com/en-us/answers/questions/1184440/is-there-a-way-to-determine-if-a-program-needs-to`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4586d307c30b26ddceceffdaa55781a6e336a66f.png)

判断逻辑的位置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d607e80b5e77da51c957003e487e7fa16c45a4d3.png)

我们这里调试的时候就是右键通过管理员权限运行的pe，所以这里返回了0，流程来到需要提权；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d29469ee4ebbd3407f9153978d12456123c0c868.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e1bec884f947723d5f6ee20b719ab398a5af5968.png)

然后对该路径进行转换，转化成长路径，这里主要是兼容一些版本中的短路径（比如路径中存在 `~`这种）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-09a6a5c0637b3535f3f9fa937cade23b29ab940c.png)  
接着使用kernelbase里面导出的`RtlDosPathNameToRelativeNtPathName_U_WithStatus`、`RtlReleaseRelativeName`尝试转化为nt文件系统形式名称,转化后的文件名如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-70ae32b8883d3b0cff41499b4c6ff929fb72791e.png)

然后来到如下位置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9e36a4e639dff7d38ce167867bba408d98665132.png)

获取到`g_Dirs`，将要打开文件路径同g\_Dirs里面的路径循环对比，开头是否相同：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a53045f33737b3f97fa93b204ab26c6bee7eebcd.png)

可以看到循环次数ebx 是和3比较，所以这个g\_Dirs里面因该是有三个路径,通过动态调试，我们拿到这三个路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-801fb2c83861cf480c69023d94baa5d153f0086e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d196d982eb8f1538e73939138f0a3167275cd563.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d2327608a3c6a047b9dc17fe453fe66b63d6854c.png)

这里三个都没匹配上；

判断逻辑如下，如果ebx为1，也就是第二个路径（`\??\c:\\windows\`）匹配上了才往左走，不然都是往右走：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-18f6f09686a3d4d814069428a08befcc1a5bd420.png)

这里我们的路径显然不在上述路径，所有接下来的逻辑是往右走，但是往下分析之前我们简单看下左边的逻辑，

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-33dd893381586123a566d22a0a63eec5b6b3252e.png)

如下图，可以看到左边的逻辑是：又出现一个`g_ExcludeWinDir`的路径list，循环匹配，

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c6c5f4aedbcc734cd0c86225cde5c1ae4f3f89a9.png)

然后更具结果不同，又去其他路径list匹配（`g_IncludedWinDir`、`g_IncludedXmtExe`等），根据匹配的不同，会给r15d这个寄存器置入一些值，比如，如果匹配 `g_IncludedWinDir`列表里面的路径，那么就把0x6000置入r15d，（这里其实是在做一些标记，r15d后续是会用来做判断的）;

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-40ad28f2682631a64ea60e338ca260608268d2f1.png)

然后我们会到右边逻辑，如下图，如果`g_Dirs`里面的路径都没匹配上，就会渠道`3aba`appinfo的偏移位置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6e6be6ac981dbe7224ee57e3673989493a1af80e.png)

appinfo 的`3ad2`偏移位置，释放路径存储的空间；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f271f39b93954eab5ba0ed2e50b6576cddd84814.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-709938aec6e3349a8efe63ae4ebd0c110a341b1c.png)

appinfo 的`3ad2`偏移逻辑，拿到原路径名传入`appinfo!AiIsEXESafeToAutoApprove`函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-156954bf876aabdb80ce2ad071eab7f1e30a4bd1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-70edf4bb787103c5dd2c6854e28f1298f04716da.png)

AilsEXESafeToAutoApprove，首先通过注册表`Software\Microsoft\Windows\CurrentVersion\Policies\`判断当前是否开启了受限的自动审批`EnableRestrictedAutoApprove`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a3484eb9cfe84fc9716e7e7de6e23ee4b6f71d73.png)

然后对r15存在一个判断，判断第21位是否为1，为1就运行下面逻辑（这个标志不出意外因该是路径判断那里给的，后续我们会使用符能够匹配对应路径的pe文件，然后详细看下路径匹配那边的规则）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ca20edcae79ebf845a446d7601ebc19a3a6710c1.png)

通过文件路径获取文件内容，通过读取映射后的文件内容里面是否配置了，autoElevate = T（这个是可执行程序 manifest里面的一个标记，带这个标记说明需要自动提权，运行就需要提权；）；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c72a56bd92e2ab02efb57221c1bbc63a174518d9.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ff05bb25fe2fc014f54caebb1f012a2d934e41f7.png)

如果没有这个标记，就进入下面的白名单匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f1c768d58d05445a205013a2cddb9fbed1449864.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c843798c4260a86903cec9f8d748d48571ab7f7c.png)

`g_lpAutoApproveEXEList` 白名单列表：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6030fd3cf66964e39f2eb614ee101ca2e07726d2.png)

AipIsValidAutoApprovalEXE校验，获取签名信息，以及匹配

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fa6655d377545f2d5fcd7811854c6c721df6255a.png)

WTGetSignatureInfo是校验签名的；下面的AipMathchesOriginalFileName是通过文件信息里面的OriginalFilename和当前名称对比，判断名称是否更改过，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b5480626dafa9547e5fa432f1fdd0e205137bfac.png)

取的字段如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a2e76543101c1248e0cc9bdc301fe3c248db887c.png)

所以在AilsEXESafeToAutoApprove 这个检查exe是否能够被允许自动提升权限的的函数中，只要上面提到的两个条件只要满足一个即可：

1、要么是manifest文件里面带自动提权标记提权

2、要么是校验通过的白名单

接着AilsEXESafeToAutoApprove 下来就是一些特殊判断，比如mmc.exe运行有一些特殊的操作；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4ea06a26e53553cfc2f122889bf710d3ee92167b.png)

显然，本次我们运行的可执行文件是不满足上面要求的，调试函数返回如下,r15没有改变；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8e9c31cd967039dd58f57c0426530f5a981751b8.png)

回到`RAiLaunchAdminPorcess`函数之后，对r15d进行判断逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ee7666885d4e92d1eccd9c32909da6e81d7d73e4.png)

这里我们的r15各个位置都是0，所以最后是走没匹配上的逻辑，就是左边的逻辑，左边逻辑好像是在做一个缓存校验，看看缓存列表里面是否有，具体我们就不看了，这里是没有匹配上：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3870f48a3d52ea100a0c4193b82fd5a575fa7410.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c9913ea048676f93b50c89ffc82b1054884e945b.png)

接着读取注册表`\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`获取`ValidateAdminCodeSignatures`值，判断本地是否开启管理员权限运行的代码必须做签名校验

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3ea20a6a7d99ab09ff7349492dae6b304289409f.png)

这里默认时没有开启的，即键值为0；

然后来到如下函数AiLaunchConsentUI，即启动consent 的ui处：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1612184f5f412fc0dec173cfd105ac8e2068362d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0457fd87c5cdf30f88bead62489ecb9e17c4b756.png)

跟进AiLaunchConsentUI，关于consent起来的过程

这个函数先获取了一个一份svchost自己的高权限token：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3c63ef3792f77d68b26305a7b874d0bec827f83a.png)

然后通过AilaunchProcess起consent.exe ，并传入刚刚高权限token

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-01be89c6ea07e73d88a1177690f16ef910006bc0.png)

跟进AilaunchProcess函数：

通过调用CreateProcessAsUserW函数，起的consent.exe进程

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-53024b90d46fbc28a4eafdda3a390bfb384f4550.png)

这里有一个细节，我们看这个lpCommandLine参数，也就是consent.exe进程的参数；

如下图这个参数是从a6来的，也就是形参的第六个参数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1b65b6dedcf485ac93ae401029bbe105d68cd26a.png)

回到AilaunchProcess调用的时候的第六个参数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-083273f73aff5414973359d664370b9c33c06f4d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-13d00439f410abbff11fea03daed228004343c7b.png)

可以看到，带了三个参数，第一个参数是appinfo服务的进程PID，第二个第三个参数是一个类似结构体的地址，

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-996f6dcf989d01d0f90acba06f5996a26b464814.png)

这也是为什么我们当时看sysmon 日志的时候，看到consent.exe是带参数的，如下，8248是appinfo服务的进程pid，第二、三个参数是appinfo进程里面的一个结构体地址相关内容；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b8c7f52e85499c8b6c4567287bc50ea94b263fa8.png)

这里为什么要这么做呢？

1、那个结构体里面都是些什么，至少说appinfo想要给consent传递这个内容

2、对consent.exe对参数处理逻辑分析

我们先看下结构体里面是什么：通过ida代码往回找，笔者找了下没找到明显直观的答案

这里调试下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fd37a6fd7e151a317d1fd5217f6306ab4330b473.png)

如下图是结构体的内容，最直观的就是 0x28偏移是我们要打开的进程的绝对路径，

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-715960e4ccc279b61459139bd2eb62b585109532.png)

对应的comsent.exe界面上面也有这个信息，所以相关信息应该都是从这个结构体里面获取的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-46b06c8ec3ad586e8dd5b64b1c1f98d714ef5790.png)

这里我们就不在多次一举分析consend.exe 了；

这里还有一个细节，通过调用AiLaunchConsentUI—&gt;AilaunchProcess —&gt;CreateProcessAsUserW函数，起consent.exe进程的时候，createflag参数是带0004的，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-605115c62287016bcca4430f1558a34ba5ad1d55.png)

也就是这里创建的时候，是以挂起状态创建的consent.exe，然后如下图，AiLaunchProcess里面接着调用AipVerifyConsent 函数，对挂起的consent.exe操作，看名字这个函数应该是校验consent的，防止被篡改劫持；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-23f2528ee5b6f5f8d389833fd9f9f0e0f3979651.png)

获取挂起的consent相关位置内容（AipVerifyConsent ），比较校验；（这里的校验好像不怎么严格，发行信息是微软）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6ce71f0bec5e6574833560286006dd46d6f81066.png)

校验通过，后续调用ResumeThread激活挂起的进程，等待consent返回，用户给的结果，一个ExitCode

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f0cc671061c0289ebee63aecb2b2978da64523a7.png)

用户选是，返回的值是exitcode就是：0，（注意这里下面图标错了，对应的是edi，也是0）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d59605990c9fd5c77decc102329ce68116bec73c.png)

这里笔者也测试了下，用户选否，返回的exitcode是：`0x4c7` （1223）；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-931d51460444fca00e9ed8e3522fa748e343352f.png)

然后结束consent：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3adbbe31d4a52526a3fa163449ce3d91edde5212.png)

回到RAiLaunchAdminProcess，判断AiLaunchConsentUI返回结果，同意提权就借助AiLaunchProcess使用带特殊权限令牌起待提权进程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-337a9ad5b12a8e38af8190f3bb4ae3fa6cd2b760.png)

到这整个流程差不多就结束了；；

#### 简单判断逻辑总结

通过分析出来的逻辑，这里大致能够推断其实 对pe是否可以不弹窗提权，主要取决于三方面：

1、和pe文件本身路径相关

上面分析的过程中，提到的内置的几个路径列表，当前可执行文件是否匹配，以及具体匹配哪个会影响最后的判断逻辑；

2、和`appinfo!AiIsEXESafeToAutoApprove`函数相关；

这个函数里面判断当前可执行文件是否符合两个条件之一：

- 条件一：g\_lpAutoApproveEXEList 成员里面的可执行文件，并且签名校验通过
- 条件二：manifest里面是否存在autoelavate 为true的pe文件

3、和注册表的设置的一些键值相关

`\\HKEY\_LOCAL\_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\`的`EnableRestrictedAutoApprove`  
判断当前是否开启了受限的自动审批  
​  
`\\HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`的`ValidateAdminCodeSignatures`  
判断本地是否开启管理员权限运行的代码必须做签名校验  
​

这里里面我们对路径的判断其实没了解具体的匹配逻辑，所以这里我们需要找一个合适的测试pe文件；

**在指定路径（system32 、systemWOW64）下面的两种程序，一是经过校验的白名单程序，二是manifest里面存在autoElevate为true的程序；**

不着急这里我们先测试下已有的逻辑；

### 测试下分析出来的已有逻辑是否正确：

#### 找一个白名单程序看下

找到到一个位于`g_lpAutoApproveEXEList`中的白名单pe文件，如：pkgmgr.exe 是在上面我们提到的白名单里面的;

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-bb00a6c65d37f4406d0b5647cd2250aaded1b20c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9e1d4cb4a0b8a8d40e26f2e03b4cd55e87e4c1a8.png)

可以看到右下角是有一个小标，说明这个可执行文件要高权限运行，这里我们直接双击，并没有产生弹窗直接运行成功了；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e4f5023bf94a5f5bea98ed24329367a326a59cd4.png)

控制变量法，我们尝试将其路径做膝盖，看看结果

如下，将其移出system32文件夹，再次双击运行测试，此时uac验证弹窗了，说明这里是上面那个我们还没弄清楚的路径匹配生效了，所以这里我们分析具体的路径匹配规则的时候，可以尝试调试分析下，位于`c:\\windows\\system32\\PkgMgr.exe`的文件，看下这里的路径匹配逻辑，正好也能看看，windows本身自带uac自动审批的逻辑是什么（内置的uac绕过方式），

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-94b643b34dc5bb9575d5af24f338357b708e0dc4.png)

#### 分析路径匹配逻辑

这次调试`c:\\windows\\system32\\PkgMgr.exe`我们的断点直接打到如下图路径匹配的位置(appinfo!0x3987的位置)：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-47f710131d3edfb2534f04bdcaad33c5ced36b7d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9c043c25f79775bd89ad06613d7d5d289a087e78.png)

此时路径是匹配上了 `g_Dirs`里面的第二个路径（`c:\windows\`），此时ebx为1；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e7ee13c44f9b54feb499f17a845fc8a2dc90da6e.png)

ebx为1，进入左边逻辑，开始匹配`g_ExcludeWinDir`里面的路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6d2c117bc264c6d813ac127cb529db430e97542c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e4c362c15c35d65bf185bb1d8d158bfa6c53a266.png)

根据判断条件，这里我们大致知道，是要匹配前0x20个路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c63324d211a2d6dad1d13fc010fc1b29da155fb3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b1ac4252f077d7334897707871928e6e7c2eff9f.png)

这些路径大致如下：

```php
\\??\\C:\\Windows\\Debug  
\\??\\C:\\Windows\\PCHealth  
\\??\\C:\\Windows\\Registration  
\\??\\C:\\Windows\\System32\\com  
\\??\\C:\\Windows\\System32\\FxsTmp  
\\??\\C:\\Windows\\System32\\Microsoft  
\\??\\C:\\Windows\\System32\\Spool  
\\??\\C:\\Windows\\System32\\Tasks  
\\??\\C:\\Windows\\SysWow64\\com  
\\??\\C:\\Windows\\SysWow64\\FxsTmp  
\\??\\C:\\Windows\\SysWow64\\Microsoft  
.  
.  
```

此时我们运行的pe文件路径没有能够匹配的，然后来到下面的匹配点，匹配`g_IncludeWindDir`列表，这里注意，进入下面匹配之前，将r15d置值0x2000h；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-72e4fefd979dfee7e4f979e1a3efba7d98a11361.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-af23694ef9ac5c8b0db152b9686cdde8332ba462.png)

匹配5个路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c57cb77b46f5bf52fa45036af760e875a73f0208.png)

5个路径如下：

```php
\\??\\C:\\Windows\\System32  
\\??\\C:\\Windows\\ehome  
\\??\\C:\\Windows\\ImmersiveContriolPanel  
\\??\\C:\\Windows\\Adam  
\\??\\C:\\Windows\\SyswOW64
```

这次第一个路径就匹配上了，将0x6000置入r15d;

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a620e0a027b0abbf7bef5e49a462cda5ba9bd056.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1db141be11ad8a39e4911d42046335c929b8226e.png)

然后，再匹配`g_IncludedXmtExe`这个列表，匹配两个路径，这个两个路径是两个exe文件，一个是windows操作系统中涉及系统部署的sysprep.exe 一个IIS管理器 InetMgr.exe;

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1e3b40982cb891384eb1977925e18fc9da133f37.png)

```php
\\??\\C:\\Windows\\System32\\Sysprep\\sysprep.exe  
\\??\\C:\\Windows\\System32\\inetsrv\\InetMgr.exe  
```

没匹配上之后，开始在`g_IncludedSysDir`匹配

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-11db92e151d401cde8dcf2b2fabc8812d686a5e0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-596867077fd67b4ab3fc67ac585254d60269398a.png)

对应的匹配的两个路径是：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2b7de28cb2994142dd1fba89c6a9225b4d6c5acc.png)

```php
\\??\\C:\\Windows\\System32  
\\??\\C:\\Windows\\SyswOW64
```

匹配上第一个路径之后，获取匹配路径之后的内容，这里我们测试使用的是`\??\c:\Windows\System32\pkgMgr.exe`,所以去除前面的路径，就只剩一个PE文件名，然后尝试找`\(0x5c)`， 其实就是找到是system32下pe文件，还是其下还有目录；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e33ffdcb3a7f26ec35011569725bf574370283ff.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-805b9c2f10033cfebc938fd285276a936a7f5a94.png)

如果是直接system32下的路径，就把r15d里面第21位置值1（这个标记非常重要，上文我们分析下面的校验函数AilsEXESafeToAutoApprove的时候，会校验r15的第21位，校验的就是这个值）；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e2b8e72aaf812984ccb551999f38194494fd2157.png)

此时我们看下r15，如下图，值位`0x20600`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7b0968e57a59a9b5081a2a3bcc65a988564daca1.png)

接着下面就是AiIsEXESafeToAutoApprove了,这里我们可以看到是把r15d作为第四个参数传入了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3420df4f556eadd4a44bf2aa68626cbf189dfb23.png)

和上面我们分析AiIsEXESafeToAutoApprove就对上了，里面会判断第21位是否为1，为1，才会进行manifest内容以及后续的白名单匹配；

那么什么时候第21位才为1呢？在匹配到`system32 和 sysWow64`路径下的pe文件的时候才置1；

所以这里我们对路径的检查和把控也分析出来了；这也是把Pkgmgr.exe 丢到桌面，运行的时候uac就弹窗了；

另外不妨也总结回顾下这里的路径匹配：

其实就是搞了个黑名单+白名单的匹配方式，黑名单是:`g_ExcludeWinDir`,白名单是：`g_IncludedXmtExe`+`g_IncludedSysDir`，先过黑名单，然后过白名单；

为了验证我们这一想法，我们再测试几个案例：

#### system32下找一个带自动提权标记的进程：

找一个manifest的里面的存在autoElevate为true的

如：msconfig.exe

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-101e1513c55f3c39660d9b128acaf44f3dd9e8ba.png)

使用微软的签名校验工具sigcheck查看manifest内容，存在自动提权的标志；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-65001f206cdfe942a4beae8ea1550bc81eade735.png)

因为这个程序图标下面也有一个小盾（这个盾是否存在其实就是上图中的manifest里面的requestedExecutionLevel决定的），说明需要高权限执行，这里直接运行运行测试就行，或者你右击管理员权限运行也行，一回事，测试结果是没有uac弹窗：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3dd518fb82b4c83a81f7b189da3655da708bf8aa.png)

同样这里我们也把文件放到随意路径双击运行测试，结果是还是会弹出uac校验：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9df8f6fd7c8c9692e986440edfd005631f717062.png)

#### 最后我们找一个system32下，但是既不是白名单，也没有自动提权标记的可执行程序测下

这里我们找到一个netsh.exe可执行程序：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5b9179935c8424dbd8a67f9111ed334dac91251b.png)

查看manifest不存在自动提权标记：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ca4a171b1268c6c9d177a295544de419b37052f8.png)

并且该程序也不在白名单里面；此时我们右键以管理员运行（注意这里不能双击，因为这个可执行文件对权限没有要求）；

测试效果：需要uac验证；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-057442872b95d7ada82f010f9d2ce767d11d3c2b.png)

通过这几个测试，说明我们逆向分析出来的uac逻辑基本没有问题；sysWow64路径和system32测试下来一样的效果；

0x03 UAC提权
==========

说起UAC提权，那必不可少的搬出UACME这个项目：`https://github.com/hfiref0x/UACME`

这个项目几乎是记录了目前所有公开的bypass UAC技术的方法；

目前来看，能够绕过uac弹窗验证的可执行文件，需要满足的特点是（注册表相关自动审批打开，admincode要前面关校验，）：

- **在指定路径（system32 、systemWOW64）下面的两种程序，一是经过校验的白名单程序，二是manifest里面存在autoElevate为true的程序；**

学习完该项目之后会发现bypass的思路大致就那么几条：

一、Bypass思路
----------

项目中的主要的思路大致可以分为以下的几大类：

### 1、dll劫持UAC白名单进程

通过利用IFileOperation往高权限目录（system32\\syswow）写dll文件，dllHijack劫持windows内置的能够不弹窗自提权的exe，从而实现提权；

如：uacme23，利用pkgmgr.exe 白名单bypassuac

实现原理细节、落地代码、测试效果以及检测方式可以参考：

[ga0weI'blog-BypassUAC-白名单\_PkgMgr\_DLL劫持](https://minhangxiaohui.github.io/2024/07/19/BypassUAC-%E7%99%BD%E5%90%8D%E5%8D%95_PkgMgr_DLL%E5%8A%AB%E6%8C%81/)

### 2、篡改pe执行逻辑通过注册表

通过修改低权限注册表，使某些windows内置的能够不弹窗自提权的exe的逻辑被篡改，从而实现提权；

如：uacme33，利用fodhelper.exe 会获取HKCU注册表内容，修改特定路径`shell\open\command`执行pe文件来bypassuac；

实现原理细节、落地代码、测试效果以及检测方式可以参考：

[ga0weI'blog-BypassUAC\_fodhelper进程Registry-Shell\_Open\_Command提权](https://minhangxiaohui.github.io/2024/07/26/BypassUAC_fodhelper%E8%BF%9B%E7%A8%8BRegistry-Shell_Open_Command%E6%8F%90%E6%9D%83/)

### 3、通过高权限com组件任意代码、命令执行的接口提权

通过利用某些com组件的某些接口方法存在类似任意命令执行的接口实现提权，然后利用com组件的校验缺陷（和IFileOpearion提权操作一样，IFileOperation本身也是一个com组件），从而实现提权；

如：uacme41，利用一个叫`CMSTPLUA`的com组件，其存在一个名为ICMLuaUtil的接口，这个接口提供了一个名为ShellExec的方法可以实现任意进程执行；

实现原理细节、落地代码、测试效果以及检测方式可以参考：

[BypssUAC\_com组件CMSTPLUA\_ICMLuaUtil接口提权](https://minhangxiaohui.github.io/2024/07/29/BypssUAC_com%E7%BB%84%E4%BB%B6CMSTPLUA_ICMLuaUtil%E6%8E%A5%E5%8F%A3%E6%8F%90%E6%9D%83/)

二、调用com组件本身也需要权限
----------------

如果我们使用自己的进程直接调用com组件，IFileOperation、CMSTPLUA这种，那么其实调用com组件的时候，就会弹窗uac了，windows这里rpc调用com接口是存在校验的，微软自己的可信程序调用的时候，就不需要弹窗提权;

当一个com组件调用发生的时候，微软是如何辨认对应的调用者是否是其受信的调用者的呢，有人分析发现，这个对调用进程判断的逻辑存在几个点：

- PEB下面的\_RTL\_USER\_PROCESS\_PARAMETERS 里面的ImagePathName;
- PEB下面的\_LDR\_DATA\_TABLE\_ENTRY里面的FullDllName 和 BaseDllName；

所以这里只需要修改下自己进程的peb里以上三个变量就行；

0x04 一个待解决的疑问
=============

uac流程分析下来，其实笔者在没有具体去看uacme这个项目的时候，就在想，直接可信目录下，写个样本，然后修改manifest，满足自动提权，这样uac岂不是直接就被绕过了，于是这里笔者做了一个测试：

使用visualstudio随便生成一个exe，配置的时候，生成清单打开，把运行权限调高，并且可避uac：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d4205dfbea979fba4b5d4976a2af0bfd94f5ef3f.png)

通过mt.exe 修改exe的manifest文件

获取当前的manifest文件

```php
mt.exe -inputresource:Create\_thing.exe;#1 -out:current.manifest   
```

修改current.manifest文件，加上自动提权的标记

```php
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>  
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">  
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">  
    <security>  
      <requestedPrivileges>  
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"></requestedExecutionLevel>  
      </requestedPrivileges>  
    </security>  
  </trustInfo>  
<asmv3:application>  
    <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">  
        <dpiAware>true</dpiAware>  
        <autoElevate>true</autoElevate>  
    </asmv3:windowsSettings>  
</asmv3:application>  
</assembly>
```

修改完，再写回exe：

mt.exe -manifest current.manifest -outputresource:Create\_thing.exe;#1

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fbc3a4451262a1e1040b3435b152df511a6ae442.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e3d962715719a4d0464b3883810757b37a0b540d.png)

使用sigcheck检查下修改是否成功，如下图可以看到修改成功了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-557d39ce600c21d02c1d3a180951440bcd831150.png)

我们把这个exe丢到指定目录：system32下（这里只是测试效果，实际情况可以结合IFileOperation来做文件移动），看下能否提权，如下图，失败了；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ab4cc516c82489c23b291be4738d480bc43166ef.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-069dc934409823fcfeeee5e6ba8afcb1eca6de9f.png)

奇怪，这里并没有直接提权成功，出现了弹窗；

难道我们分析的uac流程有问题？于是这里我回溯回去，调试了下，发现上面的校验都过了，应该是没问题的才对；

嗯，反复分析，笔者推断是consent.exe里面出问题了，后续待分析调试，暂时没找到问题在哪；

0x05 检测及思考
==========

检测思路，拿sysmon日志举例，这几篇blog中对几个常见场景给出了一些检测建议：[检测方法](https://minhangxiaohui.github.io/archive/?tag=BypassUAC)

攻击者一般在渗透过程中什么阶段会需要使用到uacbypass呢？

1、边界突破钓鱼的时候，如果我们肯定希望自己的样本是高权限执行的，那么对于一般样本用户双击运行样本，样本本身如果要高权限，就会触发uac弹窗，从而被钓鱼的用户就会产生警觉；所以此时需要bypassuac提权弹窗；

2、权限维持的时候，如果我们现在一个样本已经以一个低权限在受害机器上运行了，那么我们如何做到权限维持呢，一般来说都是写计划任务和服务等方法实现权限维持，这些实现的时候都是需要管理员权限的；

3、对抗av的时候，比如有些黑灰产上来就是关防火墙和干掉av，这里写操作至少也要管理员权限；

0x06 总结
=======

笔者分析学习windows的uac机制，前前后后加上bypass也学习了一个半月，这一套学习下来感觉还是收获颇丰的，虽然这个东西以及很多技术四五年前就有了，但是其实你会发现只有你自己亲自去调试分析这里面的细节逻辑的时候，你才能体会到后面的绕过技术为什么要那么做，而且还有一个意外的收获就是通过对uac机制的逆向分析，感觉也锻炼了逆向分析能力，笔者之前逆向分析大多数都是一些攻击者写的样本和一些破解类的东西，怎么说呢，攻击者技术参差不齐使用的百编程语言也各部相同，分析的时候就是大杂烩（这里面一堆干扰因素，什么编译器、编程语言、优化结构等等东西，如果你去过分关注细节你会发现你就会被绕进去）；但是这次分析windows uac的时候发现，每个动作和步骤都是有他的原因，也反向的学习到了一些安全编程；

还有就是你会发现，虽然技术四五年前就有，但是很多现在还是可以使用的，甚至在win11里面也可以使用；那么你觉得使微软不想修吗？这个问题智者见智，仁者见仁；了解细节，然后去推敲问什么他不修，这也是个非常有意思的事情；当然有些因素绕回来了，就是业务和安全之间对一个问题的不同看法了；

笔者才疏学浅，文笔轻浮，如有笔误，请各位师傅不吝赐教；

参考：

<https://3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6IFileOperation%E8%B6%8A%E6%9D%83%E5%A4%8D%E5%88%B6%E6%96%87%E4%BB%B6>

<https://www.youtube.com/watch?v=TkC19ukBBxk>

<https://www.youtube.com/watch?v=6LUo-Crd9pc>