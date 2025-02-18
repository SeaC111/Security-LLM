基础设施加固确实能增强应用程序抵御攻击的能力。这些安全措施提高了攻击者的门槛,使漏洞利用变得更加困难。但是,我们不能把它当作解决一切问题的银弹,因为执着的攻击者仍然可以利用源代码中的漏洞实现突破。

在这篇博文中,我们将强调代码安全基础的重要性。我们会展示一个技术案例:攻击者如何能够把 Node.js 应用中的文件写入漏洞转化为远程代码执行,即便目标系统的文件系统是以只读方式挂载的。这个技术通过利用暴露的管道文件描述符来获得代码执行能力,从而绕过了这类加固环境中的限制。

文件写入漏洞
======

在我们主要针对Web的漏洞研究过程中，经常会遇到各种不同类型的漏洞，比如跨站脚本(XSS)、SQL注入、不安全的反序列化、服务器端请求伪造(SSRF)等等。这些漏洞的影响程度和利用难度各不相同，但有一些类型的漏洞一旦被发现，几乎可以确定整个应用都会被攻陷。

**任意文件写入**就是这样一种严重的漏洞类型。虽然攻击者还需要想办法确定写入什么内容以及写入到哪里，但通常有很多方式可以把它转化为代码执行，从而完全控制应用服务器：

- 在网站根目录写入PHP、JSP、ASPX等类型的文件
- 覆盖会被服务端模板引擎处理的模板文件
- 写入配置文件(比如uWSG的.ini文件或Jetty的.xml文件)
- 添加Python的站点特定配置钩子
- 使用通用手法,如写入SSH密钥、添加定时任务或覆盖用户的.bashrc文件

这些例子说明，攻击者通常能找到简单的方法把任意文件写入漏洞转化为代码执行。为了减少此类漏洞的危害，应用的底层基础设施往往会进行加固。这确实增加了攻击者利用的难度，但并非完全无法利用。

加固环境中的文件写入
==========

我们最近发现了一个Node.js应用中的任意文件写入漏洞，这个漏洞的利用并不那么容易。虽然漏洞本身比较复杂，但可以简化为以下的代码片段：

```php
app.post('/upload', (req, res) => {   const { filename, content } = req.body;   fs.writeFile(filename, content, () => {       res.json({ message: 'File uploaded!' });   });});
```

这段代码中的`fs.writeFile`函数用于写入文件，其中`filename`和`content`这两个参数都可以被用户完全控制。因此，这里存在一个任意文件写入漏洞。

在评估这个漏洞的影响时，我们注意到运行该应用的用户只对特定的上传文件夹有写入权限。**文件系统的其他部分都是只读的**。虽然这看起来像是漏洞利用的死胡同，但它引发了我们一个有趣的研究问题：

**在目标系统的文件系统以只读方式挂载的情况下，是否可能将任意文件写入漏洞转化为代码执行？**

只读环境下的文件写入
==========

在Linux这样的Unix系统中，一切皆文件。不同于ext4这样存储数据在物理硬盘上的传统文件系统，还有一些文件系统服务于不同的目的。procfs虚拟文件系统就是其中之一，它通常挂载在`/proc`目录下，充当了探察内核内部运作的窗口。procfs并不存储实际的文件，而是提供了对运行中进程、系统内存、硬件配置等实时信息的访问。

procfs提供的一个特别有趣的信息是运行中进程的打开文件描述符，可以通过`/proc/<pid>/fd/`来查看。进程打开的文件不仅包括传统文件，还包括设备文件、套接字和管道。例如，可以用下面的命令列出Node.js进程打开的文件描述符：

```php
user@host:~$ {% mark yellow %}ls -al /proc/`pidof node`/fd{% mark %}total 0dr-x------ 2 user user 22 Oct 8 13:37 .dr-xr-xr-x 9 user user  0 Oct 8 13:37 ..lrwx------ 1 user user 64 Oct 8 13:37 0 -> /dev/pts/1lrwx------ 1 user user 64 Oct 8 13:37 1 -> /dev/pts/1lrwx------ 1 user user 64 Oct 8 13:37 2 -> /dev/pts/1lrwx------ 1 user user 64 Oct 8 13:37 3 -> 'anon_inode:[eventpoll]'lr-x------ 1 user user 64 Oct 8 13:37 4 -> 'pipe:[9173261]'l-wx------ 1 user user 64 Oct 8 13:37 5 -> 'pipe:[9173261]'lr-x------ 1 user user 64 Oct 8 13:37 6 -> 'pipe:[9173262]'l-wx------ 1 user user 64 Oct 8 13:37 7 -> 'pipe:[9173262]'lrwx------ 1 user user 64 Oct 8 13:37 8 -> 'anon_inode:[eventfd]'lrwx------ 1 user user 64 Oct 8 13:37 9 -> 'anon_inode:[eventpoll]'...
```

从上面的输出可以看到，这里包含了匿名管道(比如`pipe:[9173261]`)。与在文件系统上有具体文件名的命名管道不同，由于缺少引用，通常无法直接写入匿名管道。但是，procfs文件系统允许我们通过`/proc/<pid>/fd/`中的条目来引用管道。与procfs下的其他文件相比，这种文件写入不需要root权限，运行Node.js应用的低权限用户就可以执行：

```php
user@host:~$ echo hello > /proc/`pidof node`/fd/5
```

即使procfs以只读方式挂载(比如在Docker容器中)，写入管道仍然是可能的，因为管道由内核内部使用的一个单独的文件系统`pipefs`处理。

这为能够写入任意文件的攻击者打开了新的攻击面，因为他们可以向从匿名管道读取数据的事件处理器输送数据。

Node.js与管道
==========

Node.js构建在V8 JavaScript引擎之上，是单线程的。但Node.js提供了异步非阻塞的事件循环。为此，它使用了一个叫libuv的库。这个库使用匿名管道来发送和处理事件，正如我们在上面的输出中看到的，这些管道通过procfs暴露出来。

当一个Node.js应用存在文件写入漏洞时，攻击者可以自由地写入这些管道，因为这些管道对运行应用的用户来说是可写的。那么，写入管道的数据会发生什么呢？

在审计相关的libuv源码时，一个名为`uv__signal_event`的处理器引起了我们的注意。它假定从管道读取的数据是`uv__signal_msg_t`类型的消息：

```php
static void {% mark yellow %}uv__signal_event{% mark %}(uv_loop_t* loop,                             uv__io_t* w,                             unsigned int events) {  {% mark yellow %}uv__signal_msg_t*{% mark %} msg;  // [...]  do {    r = {% mark yellow %}read{% mark %}(loop->{% mark yellow %}signal_pipefd[0]{% mark %}, {% mark yellow %}buf{% mark %} + bytes, sizeof(buf) - bytes);    // [...]    for (i = 0; i < end; i += sizeof(uv__signal_msg_t)) {      {% mark yellow %}msg = (uv__signal_msg_t*) (buf + i);{% mark %}      // [...]
```

这个`uv__signal_msg_t`数据结构只包含两个成员：一个`handle`指针和一个名为`signum`的整数：

```php
typedef struct {  {% mark yellow %}uv_signal_t* handle;{% mark %}  int signum;} uv__signal_msg_t;
```

`handle`指针的`uv_signal_t`类型是`uv_signal_s`数据结构的别名，其中包含了一个特别有趣的成员`signal_cb`：

```php
struct uv_signal_s {  UV_HANDLE_FIELDS  uv_signal_cb signal_cb;  int signum;  // [...]
```

`signal_cb`成员是一个函数指针，它指向了一个回调函数的地址。当事件处理器中两个数据结构的`signum`值匹配时，这个回调函数会被调用：

```php
      // [...]      handle = msg->handle;      if (msg->signum == handle->signum) {        assert(!(handle->flags & UV_HANDLE_CLOSING));        handle->signal_cb(handle, handle->signum);      }
```

也就是说，如果我们能够精心构造写入管道的数据，让它包含合适的`handle`指针和`signum`值，就有机会让事件处理器执行我们指定的代码。这为漏洞利用打开了一个新的思路。

下图显示了事件处理程序所需的数据结构：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-86c4e408edf182e4bf306945a8b72a7f0ec616b2.png)

这对攻击者来说是一个非常有希望的情况：他们可以向管道写入任意数据，而且有一条直接通往函数指针调用的路径。事实上，我们并不是第一个注意到这一点的研究者。在8月8日，HackerOne公开了来自Lee Seunghyun的一份精彩报告，他描述了一个不同的场景，在这个场景中他能够利用Node.js程序内的开放文件描述符绕过任何模块和进程级别的权限限制 - 基本上就是一种沙箱逃逸。

即便在他描述的场景中（这不是我们最初考虑的情况），这也不被认为是一个安全漏洞，该报告被标记为信息性报告并关闭。这意味着我们接下来要描述的技术仍然适用于最新版本的Node.js，而且在近期可能也不会改变。

构建数据结构
======

攻击者利用文件写入漏洞来利用这个事件处理器的一般策略可能是这样的：

- 向管道写入一个伪造的`uv_signal_s`数据结构
- 将`signal_cb`函数指针设置为想要调用的任意地址
- 向管道写入一个伪造的`uv__signal_msg_t`数据结构
- 将`handle`指针指向之前写入的`uv_signal_s`数据结构
- 为两个数据结构设置相同的`signum`值
- 获得任意代码执行能力

假设攻击者只能写入文件，这一切都需要在一次写入中完成，而且无法预先读取任何内存。

事件处理器的缓冲区相当大，这让攻击者可以轻松地将两个数据结构写入管道。但是这里有一个障碍：由于写入管道的所有数据都存储在栈上，数据结构的地址是未知的：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-620b4da046258fcf4953dace9ac149bd6c5a3963.png)

因此，攻击者无法让`handle`指针引用伪造的`uv_signal_s`数据结构。这就引出了一个问题：是否还有任何数据是攻击者可以引用的？

通过ASLR(地址空间布局随机化)，栈、堆和所有库的地址都是随机化的。但是，让人意外的是，Node.js二进制文件本身的段并没有启用PIE(位置无关可执行文件)。我们可以看到官方Linux版本的Node.js的安全特性：

```php
user@host:~$ checksec /opt/node-v22.9.0-linux-x64/bin/node [*] '/opt/node-v22.9.0-linux-x64/bin/node'    Arch:     amd64-64-little    RELRO:    Full RELRO    Stack:    No canary found    NX:       NX enabled    PIE:      No PIE (0x400000)
```

这样做的原因显然是出于性能考虑，因为PIE的间接寻址会带来一些额外开销。对攻击者来说，这意味着他们可以引用Node.js段中的数据，因为这个地址是已知的。

这一发现为构建利用链提供了重要的基础，因为攻击者可以利用这个固定的地址空间来定位和引用所需的数据结构。

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-582374b0bbbc22067393a59ee87bd6ac8be6bc71.png) 接下来的问题是：攻击者如何能在Node.js的段中存储一个伪造的`uv_signal_s`数据结构？一种思路是寻找让Node.js在静态位置存储攻击者控制的数据的方法（比如从HTTP请求读取的数据），但这看起来相当具有挑战性。

一个更简单的方法是直接利用已有的数据。通过检查Node.js的内存段，攻击者可以在现有数据中找到适合用作`uv_signal_s`伪结构的数据。

攻击者理想中的数据结构应该是这样的：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-143749893ab6daec9c652b1008487a1af78f8426.png)

攻击者需要在Node.js的二进制段中找到一个满足这些条件的数据片段，这样就可以复用这些已存在的数据，而不是试图注入新的数据。

这个数据结构以一个命令字符串(`"touch /tmp/pwned"`)开始，后面紧跟着`system`函数的地址，这个地址正好与`signal_cb`函数指针重叠。攻击者只需要让`signum`值与伪造的`uv_signal_s`数据结构匹配，回调函数就会被调用，从而实际执行了`system("touch /tmp/pwned")`。

这种方法需要在Node.js的段中存在`system`函数的地址。全局偏移表(GOT)通常是一个候选位置。但是，Node.js并不使用`system`函数，所以它的地址并不在GOT中。即使地址存在，生成的伪造`uv_signal_s`数据结构的开头可能也只是GOT中的另一个条目，而不是一个有用的命令字符串。

因此，另一个方法似乎更可行：经典的ROP链(Return-Oriented Programming，返回导向编程)。

搜索数据结构片段
========

每个ROP链的开始都是搜索有用的ROP片段(gadget)。用于搜索ROP片段的工具通常会解析磁盘上的ELF文件，然后确定所有可执行段。`.text`段通常是最大的可执行段，因为它存储了程序本身的指令：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-34a80fab1e87fdf26a38ec52b7971534729221b8.png)

这个工具会遍历这个段中的字节，寻找比如`ret`指令这样适合作为ROP片段末尾的指令。然后工具会从表示`ret`指令的字节开始，逐字节向前搜索，以找出所有可能有用的ROP片段：

```php
位置A:  pop rdi          ; 设置第一个函数参数  ret             ; 返回到下一个片段位置B:  mov rax, [rsp]   ; 从栈上读取数据  ret             ; 返回到下一个片段位置C:  push rax         ; 保存数据到栈上  jmp [rdi]       ; 跳转到目标地址  ret             ; 返回到下一个片段
```

我们的思路和寻找ROP片段类似，但目标不是寻找指令序列，而是要在Node.js二进制中搜索可以用作我们所需数据结构的字节序列。这种数据结构的搜索方法和传统ROP片段搜索有异曲同工之妙。

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-5c2a9f84ee3d6b592f8f538ea32cde189ca6f7c3.png)

但在本例中，这并不是攻击者所需要的。他们不需要 ROP 小工具，而需要一个引用虚假`uv_signal_s`数据结构的地址，该地址通过其`signal_cb`函数指针引用 ROP 小工具。因此，存在一种间接方式：ROP 小工具（指令序列的地址）需要存储在引用的数据本身中：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-21c195f005079725155d9cce4b8b7455b8b759db.png) 为了识别此类合适的数据结构，攻击者需要搜索 Node.js 镜像，类似于经典的 ROP 小工具查找工具。但不同之处在于，攻击者不仅对可执行部分（如.text部分）感兴趣。伪造数据结构所在的内存不必是可执行的。攻击者需要指向小工具的指针。因此，他们可以考虑所有至少可读的段。此外，此搜索可以在内存中完成，而不仅仅是解析磁盘上的 ELF 文件。这样，攻击者还可以找到仅在运行时在.bss部分中创建的数据结构。这可能会导致误报或特定于环境的结构，但增加了他们获得有用发现的机会，这些发现可以手动验证。

这种内存中搜索虚假数据结构的基本实现实际上非常简单：

```php
for addr, len in nodejs_segments:   for offset in range(len - 7):       ptr = read_mem(addr + offset, 8)       if is_mapped(ptr) and is_executable(ptr):           instr = read_mem(ptr, n)           if is_useful_gadet(instr):               print('gadget at %08x' % addr + offset)               print('-> ' + disassemble(instr))
```

Python 脚本遍历所有 Node.js 内存区域，每次将 8 个字节解释为一个指针，并尝试引用该指针。如果地址被映射并引用可执行段中的内存，它会确定存储在此地址的字节序列是否是有用的 ROP 小工具：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-583da48e5a21445dbd4a3cc4d895fbdbad14eff3.png)

Python 脚本的实际运行情况如下：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-de4ebe6a9952b9553401ec18e6ade00d55b8b8bf.png)

所有可能有用的 ROP 小工具都会输出，现在可以用作调用回调函数时执行的第一个初始 ROP 小工具。由于写入管道的所有数据都存储在堆栈中，因此只需为第一个小工具找到合适的旋转小工具即可。一旦攻击者将堆栈指针旋转到受控数据，就可以使用经典的 ROP 链：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-696f7163eb4ffe0c2bec729ac40846a671838a40.png) 使用此技术利用任意文件漏洞时仍需注意一点。通常，用于写入文件的函数（`fs.writeFile`在本例中）仅限于有效的 UTF-8 数据。因此，写入管道的所有数据都必须是有效的 UTF-8。

克服 UTF-8 限制
===========

由于 Node.js 二进制文件非常庞大（最新的 x64 版本约为 110M），因此为经典 ROP 链找到有用的 UTF-8 兼容小工具并不困难。但是，这种限制进一步限制了`uv_signal_s`现有数据中可能适合伪造的数据结构。基于此，需要在脚本中添加额外的检查，以验证伪造数据结构的基地址是否为有效的 UTF-8：

```php
for addr, len in nodejs_segments:   for offset in range(len - 7):       {% mark yellow %}if not is_valid_utf8(addr + offset - 0x60): continue{% mark %}       ptr = read_mem(addr + offset, 8)       # [...]
```

即使添加了这个额外的检查，脚本仍然可能产生一些适合伪造的数据结构，它们可能指向一个利用pivot gadget的结构，如下所示。

`... 0x4354ca1 -> 0x12d0000: pop rsi; pop r15; pop rbp; ret ...`

这就是相关数据结构在内存中的样子：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-8a6da188973a29d46f6ae78d833183d2122eb570.png) 这个伪造数据结构的基地址（`0x4354c41`）是有效的UTF-8，因此`uv__signal_msg_t`数据结构中的handle指针可以正确地被填充。然而，仍然存在另一个与UTF-8相关的问题。这次与signum值有关。

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-e899a5f3322340275362e573bca5ea66f16b10f8.png) signum 值的最后一个字节是 0xf0，它不是有效的 UTF-8 编码。如果攻击者试图通过文件写入漏洞写入这个字节，它会被替换为替换字符，而 signum 值的检查会失败。如果我们在 UTF-8 可视化工具中输入 0xf0，我们可以看到这个字节引入了一个 4 个字节的 UTF-8 序列：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-5ce3ec814e1140979ff00b29116e98dc4980069b.png)

因此，UTF-8 解析器期望在这个字节后面跟随 3 个继续字节。由于 `uv__signal_msg_t` 数据结构包含一个 8 字节的指针和一个 4 字节的整数，编译器添加 4 个补齐字节以使结构体对齐到 16 字节。这些字节可以用来添加 3 个继续字节，如此便可构造出一个有效的 UTF-8 序列：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-f1362cb4b77f3ed94f3a75f9c2cfa7e6063ff23f.png)

例如，上面的软盘图标是一个以 0xf0 开头的有效的 4 字节 UTF-8 序列。通过添加这些继续字节，攻击者可以满足整个有效负载都是有效 UTF-8 的要求，并使两个.signum值相匹配：

![](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-efaa6c2d139b94965158c27538f646c34a6dc726.png) 解决了最后一个障碍后，攻击者便能够获得远程代码执行权限。

以下视频展示了如何在脆弱的示例应用上实施此漏洞利用。该应用运行在一个具有只读根文件系统和只读 procfs 的系统上，且用户权限较低。

学习与结论
=====

Unix 系统中的 “一切皆文件” 哲学，在利用文件写入漏洞时，打开了不常见的攻击面。在本文中，我们展示了一种技术，可以将 Node.js 应用中的文件写入漏洞转化为远程代码执行。由于事件处理器代码来自 libuv，该技术也可以应用于使用 libuv 的其他软件，如 Julia。

这种通用方法甚至可以在没有 Node.js 和 libuv 的情况下使用。只要应用程序使用管道作为通信机制，攻击者就可能利用文件写入漏洞，通过 procfs 暴露的管道文件描述符进行攻击。正如这个例子所展示的，这种攻击方式可能在常见的威胁模型中未被考虑到，但却能让远程攻击者执行任意代码。

从防御角度看，这个例子凸显了基础设施加固只能作为额外的防御层，不能替代根本的代码安全。即使采取了加固措施，决心强烈的攻击者仍可以利用源代码中的漏洞。这再次证明了代码安全的重要性，正如《整洁代码》所强调的那样，漏洞应当从根源——源代码中被修复。