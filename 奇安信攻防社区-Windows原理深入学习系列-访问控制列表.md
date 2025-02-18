这是\[**信安成长计划**\]的第 19 篇文章

0x00 目录
=======

0x01 介绍

0x02 DACL

0x03 创建DACL

0x04 文件读取测试

0x05 进程注入测试

0x06 原理分析 Win10\_x64\_20H2

0x07 参考文章

在最后分析的时候纠正一下网上大批分析文章中的一个错误，东西只有自己实践了才知道

0x01 介绍
=======

在上一篇讲强制完整性控制的时候提到过，在权限检查的时候，会先进行强制完整性检查，然后再进行 DACL 检查，DACL 就是包含在这次要提到的 ACL 当中的。

访问控制列表（Access Control List，ACL），其中的每一项叫做访问控制条目（Access Control Entries，ACE）。

访问控制列表是属于安全对象的安全描述符的，根据文档可以看出来，安全描述符中包含了两个跟 ACL 相关的信息，DACL（discretionary access control list）和 SACL（system access control list）

DACL 可以对发起请求的用户或者组进行权限控制，允许或者拒绝它们的访问

SACL 使监视对受保护对象的访问成为可能，其信息会在安全日志中被记录

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b92e8816ae7d40dbdb8ff2490413dd9cf7e50ca4.png)

那所谓的安全对象又是什么，根据微软提供的文档可以发现，文件、目录、进程、线程、注册表、服务、管道、打印机、网络共享等等都属于安全对象，也就意味着它们都拥有 DACL 和 SACL，也就说明了所有这些内容都是可以进行权限控制和日志记录的。

说了这么多，那到底 DACL 和 SACL 都是什么东西，这其实就是我们平时最常见的安全属性界面

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bfeb5bb0f6a15ab7169655ea4c25ca4cf5d7bea5.png)

DACL、SACL、ACE 分别对应的就是下面这些

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-33b542b703c1b5df8edd9a60a61dd928f704a32f.png)

接下来我们重点来说一下 DACL

0x02 DACL
=========

对于 DACL 的不同情况，Windows 也会有不同的处理方式

如果安全描述符中没有 DACL，即 DACL 为 NULL，Windows 会允许任何用户的完全访问权限。

如果有 DACL，但是 DACL 为空，即没有 ACE，Windows 将不允许任何用户的任何访问

如果有 DACL，也有 ACE，Windows 将会依次检查 ACE，直到找到一个或多个 ACE 允许所有请求的访问权限，或者直到任何请求的访问权限被拒绝

对于前两种就不必多说了，主要来说一下第三种情况，这里就借用微软的图来说一下

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0256f660c97a4c58c7efb4349abc2c9f4994ccc8.png)

Thread A 拥有 Andrew 的访问令牌，当 Thread A 访问 Object 对象的时候，会从 DACL 中的第一个 ACE 开始检查，第一个权限是 Access denied，用户名是 Andrew，刚好与 Thread A 相同，就发生了拒绝访问。

Thread B 拥有 Jane 的访问令牌，当 Thread B 访问 Object 对象的时候，也会从第一个 ACE 开始检查，第一个并不满足；然后检查第二个，Group A 的允许写，而 Jane 是属于 Group A 的，所以获得了写的权限；然后检查第三个，Everyone 有读和执行权限，所以 Thread B 就有了读、写、执行权限。

根据上面这个例子也能够看出来，ACE 顺序的重要性，如果第一个不是对 Andrew 的禁止的话，Thread A 就已经获取到权限了。

同时 ACE 也是可以被继承的，在每个 ACE 中都有一个专门标记与继承相关信息的标志位，一般最常见的就是全继承，父对象与子对象具有相同的权限控制和审计设置。

需要注意的是，继承而来的 ACE，在子对象中是不能进行修改的，找两个例子就可以看出来了

这一项是没有被继承的，权限位是可以进行修改的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7e7861caa7e4ba9a3e579488d8b60e5329187255.png)

如果是继承的话，所有的权限位直接为灰色，不可修改

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-33e2a89c1c2cce745a8dacc203d19cc0f29ca8e5.png)

0x03 创建DACL
===========

先说一个小插曲，刚开始的时候，我还想着 ProcessHacker 会有相关的代码，是不是可以直接拿来用了，然后在源码里翻了半天，并没有发现有相关的代码，最后在 ProcessHacker 官方论坛上发现了如下的对话

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-00e743b9e05871ef4c31431c6ad6193dd8c17987.png)

EditSecurity 函数上面写的很清楚，这个展示页是专门让用户编辑 ACE 的，它属于一个专门的 DLL，名字是 Aclui.dll

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4fbb9402dfcee9c5eba84ce00792f2bbd3d897c3.png)

除了使用上面那样在图形化界面中修改之外，还可以通过 API 来进行处理

整个的流程微软也已经列出来了 <https://docs.microsoft.com/en-us/windows/win32/secbp/creating-a-dacl>

唯一感觉不甚友好的就是设置其权限时候所使用的 SDDL，这个可读性确实是有点差了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8ab594eeffbdef81ffc757ee98316f63d46dfb58.png)

这里就不实践了，相关的文档，还有一份大佬的博客，我一起放到最后的参考链接当中

还可以通过我们上一篇文章中所提到的命令行工具 icacls 来完成，它在示例当中也描述的很清楚了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d7d225872d8882d744c76b5d60abe330f86dbbe5.png)

除此之外，PowerShell 真是个好东西，有一个 Get-Acl 命令也可以查询

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c6d57cfc08cabb26bc016dd166006431ee8190ad.png)

它也能获取注册表的访问权限

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-397392e72254bb0ce6196ca41eab8302c806533d.png)

就查看的信息而言，也更加的清晰了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-182b92ef38347a3aafc215866bf37e1a341e0ab9.png)

当然，也能使用 Set-Acl 命令对其进行修改，大佬的文章链接我直接贴到最后的参考文献里

0x04 文件读取测试
===========

首先我们先看一下文件当前的 ACL

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1b6a7b5d1eea77a25f63e1c394ce679ddfa545ba.png)

由于当前用户属于 Administrator 组，所以读取是没有问题的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a81947bf75b102f031df9df329c3175de808b7a7.png)

然后手动删除掉权限，由于当前的权限都是继承过来的，所以无法直接删除

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-541663c82b4bfa5cdbca68f68722e2ae37949f79.png)

但是在编辑框中可以很方便的禁用继承关系，我们可以直接禁用掉，最好还是选择第一个，因为当前所有的 ACE 都是继承过来的，如果删除掉所有的继承权限的话，当前的 DACL 就会变成一个空的 DACL，那将无法进行访问了!

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-89fe021da0c1bae88b2cb94677b3d0740176c1e2.png)

然后对权限进行删除，这里我只保留了 SYSTEM 权限

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5819aa7f14e070d97cd140cda2138a0981025f91.png)

访问直接就被拒绝了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-74b26b4aa6f0d9abf821f6540f6a32ef54f34adc.png)

0x05 进程注入测试
===========

与上次一样，我们还是使用 RDI 来进行测试

先起一个 notepad 进程，可以发现我们的当前账户 admin 是拥有完全控制权限的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-090837b709386aad781d5941d79bfb63705ad545.png)

然后使用 RDI 来进行注入，一切正常

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5773a984957b61ddc450193f45323759635f1ce6.png)

接下来再找一个当前没有权限的来尝试一下注入，为了排除完整性带来的干扰，我们直接修改这个 notepad 的 ACE，直接删除当前用户

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-27082bb83fbf64d9b5cf629193b4a29525cb3c4a.png)

然后再来进行测试，可以发现，直接无法打开目标进程了，返回的错误码是拒绝访问

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bf77988cd3fadeccaa736c0422f29a383be04c79.png)

0x06 原理分析 Win10\_x64\_20H2
==========================

我们以这个 winlogon 为例

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-72d465e05625b6f2b69126b28d8f922f68cbe929.png)

先取到 EPROCESS 结构

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b38a533052e2ec32642926a0dd44c2a22dc45ae2.png)

看一下对象头的结构，SecurityDescriptor 存在里面，这一点我们在刚开始的时候也说过了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a6fb2d7890a98fe69d1125ee26d5d620d541d81b.png)

要取到当前进程的结构头，这里需要注意的是，SecurityDescriptor 与 Token 一样，最后四位都是一个快速引用的东西（虽然现在还不太明白是干什么用的）

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3370439a8785310cae4822b91e08a023dd7c96cc.png)

接着就来看一下 \_SECURITY\_DESCRIPTOR 结构当中到底存储了哪些内容

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c2dfda43a47f7086ef0e2cbeed3c358df20cd918.png)

虽然能够看到 SACL、DACL 等信息，但是有点问题，这些地址很明显是不正确的，它们明显不是地址，也是读不出来的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b45243f2004f975c6dc9d752ae23682a1150c6c4.png)

经过查找，发现网上在碰到这里的时候，都没有看这个结构的数据，直接从首地址加上 0x30 的偏移找到 DACL，为了能更好的明白 Windows 在这个时候在做什么，可以一个与获取 DACL 有关的函数

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4101f26189169d57384e10c80734ae71d0cf9048.png)

通过微软文档可以看到这个函数所用到的参数

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-741dc29406019f6c3183ecb79bed872bea07b374.png)

这里的 r8 寄存器就是用来存储返回的 Dacl 的指针，如果按照 \_SECURITY\_DESCRIPTOR 结构来验证的话，这里先取到了 Group 中的值，然后加上 \_SECURITY\_DESCRIPTOR 的地址，最后直接返回给了 r8，这在逻辑上是完全讲不通的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-389876a842415954827c3574c1b923d72adfa7ca.png)

但是就在分析的时候，无意中发现了另外的一个结构 \_SECURITY\_DESCRIPTOR\_RELATIVE，看名字当前的位置应该都是相对偏移了，感觉有可能是正确的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0f95dcb7ec190e20c4f144560b7c9b169b416658.png)

再拿刚刚的逻辑来分析一下，很明显是对的上了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9b219a64493656fb2ae1fb9b27197c4a137243a7.png)

那就回到前面，继续用这个结构进行分析，可以看到 Dacl 处的 0x30 偏移，这也就是网上都在说结构错了，需要 +0x30 才能找到 Dacl 的真正原因

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0bf023261545f3e2f8d33f1b2b72d9d60bfa335d.png)

按照刚刚分析函数的逻辑，可以直接取到 DACL 的地址

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6f428e7c4beb025e9638ad4ce9a32d5098a4ff8f.png)

因为它们还是 ACL 结构的，所以继续查看结构体，可以看到当前 ACL 的大小是 0x3c，当前 ACL 当中有 2 个 ACE

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4ee1665d9d2b91bb5b2faec654dfb0a463362360.png)

接下来应该查找 ACE 了，但是并没有发现与 ACE 有关的结构，经过搜索，发现在 Win32 的 API 里有一个与 ACE 有关的结构 \_ACE\_HEADER，可以看到里面有 ACE 的类型、大小等信息

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bf2ae55a89ab5ee86d26019f66bf4650af33e5e9.png)

根据类型可以找到更多的与 ACE 相关的结构，比如 ACCESS\_ALLOWED\_ACE

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8078705afc91e43a312a16b17157c28568cb9a13.png)

这样就都串起来了，每一项 ACE 都有一个 ACE\_HEADER，然后根据类型的不同，后面跟着的是不同的数据结构

但是还有个问题，ACE 到底该怎么取，从哪里开始取，接下来就来分析一下 RtlGetAce 函数，根据参数可以很明显的发现，他会先传入 ACL，然后根据要获取的 ACE 的索引进行查找，最后再进行返回

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3f08ca7fe3c55e5f90347713e6c1c5c702f7d524.png)

上面这些判断并不是关键，下面的循环取值才是关键要看到的内容

先取到 ACL 的大小，然后偏移到 ACL 的后面

r9 是 rcx+8 的地址，目前也就是 ACL 的头的结尾位置，加二并将值赋给 eax，因为紧接着是 \_ACE\_HEADER 结构，所以 eax 就是当前 ACE 的大小

r8 用来循环计数，判断 AceIndex 的，我们暂且不用关心，只看它是怎么获取的

将 r9 加上大小，然后赋值回去，就返回 ace 了

这里看着是跳过了第一个 ACE，实际上是因为当 AceIndex 为 0 时，在上面 rcx+8 的时候就已经是其地址了，所以就不会进入当前的这个循环

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-caba4ac44bd7ba1a901b0561386857ac20b328ff.png)

在分析完结构以后，继续在 WinDBG 当中看一下

第一位是 Type，第二位是 Flags，第三位是 Size，紧接着四位是 Mask，接着后面是 Sid

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4a637ad6f5ee2d91a0a0f0c6b0df74886bcde10d.png)

Type 为 0，就是 ACCESS\_ALLOWED\_ACE，虽然最后的 Sid 只是一个 DWORD 类型，但是根据名字就可以看出来了，这只是记录一下地址的，总大小在前面已经有记录了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d6f1b519397c9034c020ae44b0cd893027f69943.png)

对于 ACCESS\_MASK，就是用来描述当前权限的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-33444a55dc961fc647470b00eb262274d9e90077.png)

它主要分为了几个部分，对于一般和标准的都有详细标记，至于特殊权限位，没有查到详细的内容，感兴趣可以挨个试一试，链接我全部放到最后的参考文章当中

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a38b1f8aa1c6eb50c03636fa6f7e69d189577871.png)

接下来就是 SID 了，它是有结构的，可以直接进行查看

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-730a12ce97099230d834ef74095f01dac9ed9675.png)

这样 ACE 也就解析出来了

第一个是 S-1-5-18 即 SYSTEM 账户允许 STANDARD\_RIGHTS\_ALL 和 SPECIFIC\_RIGHTS\_ALL 权限

第二个 SID 就是 S-1-5-32-544，可以查到他对应的是账户是 Administrators

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f8bb6a555f43cb65a4346531f66c271c7f2c9600.png)

这也就刚开始看到的 ACE 项所对应了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-15cd1af23eb453b8e83a010958a9671f20304dae.png)

这样也就完成了整个 DACL 的查找

0x07 参考文章
=========

1.<https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists>

2.[https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security\_descriptor](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor)

3.<https://docs.microsoft.com/en-us/windows/win32/secauthz/securable-objects>

4.<https://docs.microsoft.com/en-us/windows/win32/secauthz/securable-objects>

5.<https://docs.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces>

6.<https://docs.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object>

7.<https://www.cnblogs.com/cdaniu/p/15630284.html>

8.<https://helgeklein.com/blog/permissions-a-primer-or-dacl-sacl-owner-sid-and-ace-explained/>

9.<https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/acls-dacls-sacls-aces>

10.<https://secureidentity.se/acl-dacl-sacl-and-the-ace/>

11.<https://wj32.org/processhacker/forums/viewtopic.php?t=2568>

12.<https://docs.microsoft.com/en-us/windows/win32/api/aclui/nf-aclui-editsecurity>

13.<https://docs.microsoft.com/en-us/windows/win32/secbp/creating-a-dacl>

14.<https://www.cnblogs.com/iBinary/p/11399114.html#tid-HABck4>

15.<https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings>

16.<https://myzxcg.com/2021/08/Windows-%E8%AE%BF%E9%97%AE%E6%8E%A7%E5%88%B6%E6%A8%A1%E5%9E%8B%E4%BA%8C/>

17.<https://www.redteaming.top/2020/02/03/Windows%E2%80%94%E2%80%94Access-Control-List/>

18.<https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B8%8B%E7%9A%84Access-Control-List>

19.<https://blog.csdn.net/sunyikuyu/article/details/9041067>

20.<https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgetdaclsecuritydescriptor>

21.<https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2>

22.[https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace\_header](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header)

23.[https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access\\\_allowed\\\_ace](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access%5C_allowed%5C_ace)

24.<https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask>

25.<https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/access-mask>