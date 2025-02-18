0x01 介绍
=======

强制完整性控制（Mandatory Integrity Control，MIC），它是对 discretionary access control list 的补充，并且是在 DACL 之前检查的

这是从 Windows Vista 新增的安全机制，在 Windows XP 中几乎所有的进程都是运行在管理员权限下的。

在官方文档中描述为 Windows 为其划分了四个完整性级别：低、中、高、系统；但从实际上看到的对应表中，有五个等级，多了一个不受信任等级

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2b1de3fd0d72677393775ecb2b81e5d3999c3cca.png)

在查资料的时候发现，还会有一个等级，高于 System 完整性，被叫做 Protected integrity level，但是它默认情况下是没有使用的，它只能由内核层来设置

具有低完整性级别的主体无法写入具有中等完整性级别的对象，这就相当于提供了一种在同一用户下，根据可信程度来限制不同进程之间的交互，低完整性等级的进程都无法对高完整性进程进行注入

虽然是限制了进程间的交互，但是高低完整性的进程还是可以通过其他的进程间通信的方式来进行交互：共享内存、Sockets、RPC、Windows 消息机制、命名管道，这些是不受限制的。

0x02 完整性等级
==========

Windows 直接使用了 SID 来定义完整性等级，这样就非常容易的将此机制集成到现有的结构当中，还不用修改代码

完整性等级所使用的 SID 格式是：S-1-16-xxxx

16 就是强制完整性的标识，后面的 xxxx，就是所对应的 RID，用来表示完整性等级的，这个值就是上面所提到的那几个十六进制值，它们以 0x1000 为间隔，也是为了将来能够再定义其他的等级

所以组合到一起以后完整性等级所对应的 SID 就变成了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-10bfe2b076be876b35441e18a7bdca0e0c58792e.png)

**System**

这是最高的完整性级别，由在本地服务、网络服务和系统账户下运行的进程和服务使用。此级别的目的是在管理员和系统之间提供一个安全层，即使以完全管理员身份运行的进程也无法与系统完整性级别进程交互

唯一的例外情况是，如果管理员账户被授予 SE\_DEBUG\_NAME 权限，那么他就可以在 token 中启用这个权限，来进行交互

**High**

分配给在管理员账户下运行的进程的默认完整性级别，如果启用了 UAC，则此级别将仅提供给提升过 UAC 权限的用户

**Medium**

授予在非管理员用户账户下运行的进程或启用 UAC 的管理员账户上的进程。

此完整性级别的进程只能修改 HKEY\_CURRENT\_USER、非受保护文件夹中的文件以及具有相同或更低完整性的进程。

**Low**

最低完整性级别默认不分配给进程，它要么通过继承，要么由父进程设置。

以低完整性级别运行的进程只能在 HKEY\_CURRENT\_USER\\Software\\AppDataLow 下操作，或者将文件写入 %USERPROFILE%\\AppData\\LocalLow 目录下

低完整性进程实际上不可能对系统进行任何更改，但仍然可以读取大部分的数据。

在 Process Explorer 中可以查看到进程的完整性等级

可以看到 Chrome 默认启动的是 Medium 等级的，其中还有 Low 等级的，这个可能就是沙盒用到的，给它们足够低的等级，能够最大限度的减少在出现问题时所带来的影响；而大量的不被信任的进程，有可能就是各个标签页所在的处理进程

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8f81abd4daf3cc52e48cb0021289bd99eb996faf.png)

还有几点需要注意：

1.进程是无法更改自己的完整性等级的

2.进程一旦运行，完整性等级是无法再修改了，即使是更高完整性等级的进程

3.进程只能够创建具有相同或者更低完整性等级的进程

4.进程不能修改或者写入具有更高完整性等级的进程或者文件

完整性等级的限制还有几个例外的情况

1.被授予 SE\_DEBUG\_NAME 权限的高完整性等级的进程可以修改更高完整性等级的进程

2.中等完整性的进程可以通过一些操作提升到高完整性等级，这就是平时的 Bypass UAC 的操作

3.进程可以请求从中等完整性提升到高完整性等级，这个只能在执行的时候发生，会弹出 UAC 的提示让用户来选择

0x03 文件读取测试
===========

微软提供了一个可以来修改默认完整性等级的命令行工具——icacls

具体的命令参数可以查看帮助信息

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d3c3757c5354ad893d33e5826d29a883e189de22.png)

除此之外，还有一个更强大的替代方案——Chml，可以在 <http://www.minasi.com/apps/> 中获得

从中可以很清楚的看到完整性等级以及详细的权限等等

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6f9314514f452b874b709d8e85dfb700bde7c0c9.png)

因为当前是中等完整性等级，我们运行的 cmd 也是中等完整性等级，所以是可以直接看到的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-be075160928a8bd8ff3413deeaaa73d0816543d5.png)

为了验证，我们拷贝一个 cmd 应用出来，并将它处理为低完整性等级

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4790c7758ee9386d7f20f59da561f01fd974f3b7.png)

但是，发现它还是可以读取的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4711dbc9632d8f8072d44c0430daebe9d03f5f36.png)

这是因为这个权限并没有被禁止，我们在上面查询的时候，发现只有不可写是开启的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-894a3d0671ed7ef9447b67df754497d7a2ff8596.png)

可以用写操作来验证一下，可以发现确实是不可写的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-805e5c76150e9d825823bae18d79228e132d1896.png)

如果想要让其也不可读，就需要将不可读的权限开起来

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1c369e6b1a13e44061e1670562e6fa3709d619d3.png)

然后再来验证一下，确实跟我们所设想的是一样的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-923b52b07d37e1d36242e0bc78c2f6f4b039489a.png)

这样我们就有了一个保护文件的方案，将敏感文件的完整性等级修改为高完整性，这样完整性等级低一些的将无法对文件进行读取等操作

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9697f5e81e6d5f48107eece96d6e2c7b0d62b2ac.png)

正常启动的 cmd 与低完整性的 cmd 都是无法查看的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0714ac720a044dced17cfa5d18b3e0b8ff5ae7fa.png)

只有管理员权限的才能够对其进行查看

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6401b0dd24a6fa4ec7d4bf7ad17a9d92b2a57751.png)

0x04 进程注入测试
===========

至于注入，就直接偷懒了，用 RDI 来进行测试

首先我们起一个 notepad，现在两个都是中等完整性级别

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b22e22e6d3a1faa3632a816ab2ac3dfe94c067a7.png)

然后进行注入的测试，是没有问题的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-da431b880d576c087c917153e78b629d064d7f62.png)

然后再使用我们之前所用到的低完整性等级的 cmd，再来测试注入

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-dad24882196960c5c615c3aa3a96f3f6bcd46f83.png)

发现访问被拒绝，无法打开句柄

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-917ee9948b7d59c75b79ed0be5eee0aac6d8f6f2.png)

0x05 原理分析 Win10\_x64\_20H2
==========================

在内核里，强制完整性等级是存储在 Token 当中的，我们可以在 \_TOKEN 结构体当中找到，以这个 msedge 为例

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-53f857f6ad69b697880660cdb4d98d3c473fa72a.png)

6200 换成十六进制也就是 0x1838，先找到这个进程

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8fcf949586c53d137806599716b6e8ccba165dde.png)

查看当前的 EPROCESS 结构，需要从中找到 Token，可以发现 Token 在 0x4b8 的位置

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3965c172b21f24b49fd030f45102bb8989775da4.png)

然后看一下这个结构体的内容，Token 的地址就应该是 0xffffb681`c89d20a0

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-670f856426b42ddf47b3e31a24c4bc99495b086b.png)

从中可以发现 0xd0 的位置与完整性等级有关，但是根据这个名字可以看出来，这只是一个索引

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-87cf7edd4347a1b6daef99fa1862fec3902f55f3.png)

那么如何根据索引来找其对应的内容呢，我们可以来找一找相关的函数，看 Windows 是怎么处理的，可以发现有一个跟查询相关的函数

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0d1d12652db4b1efbf4907151634f8e221b0184f.png)

跟过以后发现，它直接调用了 SepCopyTokenIntegrity，同时传了两个参数

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-530e540c32c0bad85686a0792be09d50ec36541a.png)

跟进去以后发现，没有做任何处理直接调用了 SepLocateTokenIntegrity

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ecd3cdc366183b88480ef6e7b0956e8af5d734e2.png)

因为之前传来了两个参数，所以 rcx 就是 TOKEN，根据这里可以看出来，先从 TOKEN 中获取到 IntegrityLevelIndex，如果索引是 -1 的话，就直接返回 0，否则就将索引乘以 16，然后在 UserAndGroups 当中寻找，并将值返回

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3bba1087a0b0b56ca0e138aff6146712906e1fc1.png)

如果返回值不为 0，就从返回值中取值，将其返回到第二个参数中，然后再将返回值中的地址 +8 的位置存储到第二个参数偏移 8 的位置，最后返回

如果返回值为 0，也就意味着 IntegrityLevelIndex 为 -1，就从 SeUntrustedMandatorySid 中取值，并将其返回到第二个参数当中，然后将 0x60 存入，返回

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d08df8b10776524953163a0efc5c7385a4745471.png)

而第二个参数是 SID\_AND\_ATTRIBUTES 类型的，可以看到，第一个位置存储的就是 Sid，而偏移 8 的位置就是 Attributes

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a820b5566594811338759a95293e58e07787126a.png)

所以，我们也要按照这样的方式来进行查找

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3b3a61749ee102cba94fdd524e7c0b3422a2d0fb.png)

通过官方文档可以看到第一个参数是一个指向 SID 结构的指针

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-941332a798f5049ebb9bd8d5218ef86f78db41e7.png)

所以我们继续来查结构

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0b066458cc767534809c12c23fda97ad89e73b73.png)

到这里已经发现跟刚开始所提到的知识对上了，16 代表是强制完整性，0x2000 代表了是中等完整性等级

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-feb42b0b701d37dc8a9ad8d200d05dd780995a92.png)

我们让 WinDBG 自己来解析一下，也是得到了一样的结果

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-596dfcd98e9794a3d83863306236a39c4f367025.png)

0x06 参考文章
=========

1.<https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control>

2.<https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625957(v=msdn.10>)

3.<https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625963(v=msdn.10>)

4.<https://www.malwaretech.com/2014/10/usermode-sandboxing.html>

5.<https://zeltser.com/windows-integrity-levels-for-spyware-protection-processe/>

6.<https://zeltser.com/windows-integrity-levels-malware-protection-files/>

7.<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753525(v=ws.10>)

8.<http://www.minasi.com/apps/>

9.<https://blog.didierstevens.com/2010/09/07/integrity-levels-and-dll-injection/>

10.[https://en.wikipedia.org/wiki/Mandatory\\\_Integrity\\\_Control](https://en.wikipedia.org/wiki/Mandatory%5C_Integrity%5C_Control)

11.<https://helgeklein.com/blog/internet-explorer-in-protected-mode-how-the-low-integrity-environment-gets-created/>

12.[https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token\_groups](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups)

13.[https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid\\\_and\\\_attributes](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid%5C_and%5C_attributes)