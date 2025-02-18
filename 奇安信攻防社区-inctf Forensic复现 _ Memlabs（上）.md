自己到现在还没认真用过Vol，打算刷刷题然后系统学习一下。  
（毕竟不能总是指望着用取证大师之类的吧?）

0x01 MemLabs Lab\_0 | Never Too Late Mister
===========================================

下载链接：[Lab0](https://drive.google.com/file/d/1MjMGRiPzweCOdikO3DTaVfbdBK5kyynT/view)

Challenge Description
---------------------

My friend John is an "environmental" activist and a humanitarian. He hated the ideology of Thanos from the Avengers: Infinity War. He sucks at programming. He used too many variables while writing any program. One day, John gave me a memory dump and asked me to find out what he was doing while he took the dump. Can you figure it out for me?

> 我的朋友约翰是一位“环保”活动家和人道主义者。他讨厌复仇者联盟中灭霸的观点：无限战争。他编程很烂。他在编写任何程序时使用了太多变量。有一天，约翰给了我一个内存转储，并让我找出他在转储时在做什么。你能帮我弄清楚吗？

Progress
--------

整体下来就是一个常规取证思路，先`imageinfo`看一下：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-32c9f79a2d22e84421a687a4b294ea1c8c8b4862.png)​

Vol3给出的建议是`Win7SP1X86_23418`，查看一下进程信息：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-02f03cf1f56acd48ee9686c8a1950ce5859e399e.png)​

看到有运行过`cmd.exe`，查看一下历史命令行信息：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2a6cdbfed81fb579f4c8917a1f77f5da51c47371.png)​

有一个可疑文件，用`cmd`调用`python.exe`，这个地方可以用`consoles`插件，来查看执行的命令行历史记录（扫描\_`CONSOLE_INFORMATION`信息）

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-71d5b878917c025906bb5a5a0e5968914bbae264.png)​

得到一串字符串`335d366f5d6031767631707f`

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0391cbfc4458dd39918b7f820857888a3280269b.png)​

看上去是一段乱码：3\]6o\]`1vv1p.

如果不解密字符串的话，下一步也不知道干什么。

此时结合上面题目描述`"environmental" activist`环保主义者提示，应该是要查看环境变量

`envars`查看一下发现太多了。。。果然是个很差的技术员，在编写程序时使用了太多环境变量

不过后面有提到`Thanos`，尝试在环境变量里面搜一下

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-48c3bed30be39fbb80ce26105e589bf6cf7e25bc.png)​

发现真的有，环境变量指向`xor and password`

先提取`password`

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-fcc2032a4b6d50b5d63f3b83d7de9dbff7d69dc9.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7d8f6d170433454ff18529378b71c37217c1a4fa.png)​

后面这串查不到啊艹，看了WP人家是查到了。。。。。。

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-87b9de0b320e204402e908b37d02381b007c41d7.png)​

这是第一部分：`flag{you_are_good_but`

剩下一部分，来处理提示中的`xor`，目标字符串应该是前面hex解密出的乱码

不过不清楚异或字符是啥，只能爆破了

```python
a = "335d366f5d6031767631707f".decode("hex")
for i in range(0,255):
    b = ""
    for j in a:
        b = b + chr(ord(j) ^ i)
    print b
```

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-67b21e3307a00f8b1f4bd599b93387703f1eabbe.png)​

**flag{you\_are\_good\_but1\_4m\_b3tt3r}**

0x02 MemLabs Lab\_1 | Beginner's Luck
=====================================

下载链接：[Lab1](https://mega.nz/#!6l4BhKIb!l8ATZoliB_ULlvlkESwkPiXAETJEF7p91Gf9CWuQI70)

Challenge description
---------------------

My sister's computer crashed. We were very fortunate to recover this memory dump. Your job is get all her important files from the system. From what we remember, we suddenly saw a black window pop up with some thing being executed. When the crash happened, she was trying to draw something. Thats all we remember from the time of crash.

**Note** : This challenge is composed of 3 flags.

> 我姐姐的电脑坏了。我们非常幸运地恢复了这个内存转储。你的工作是从系统中获取她所有的重要文件。根据我们的记忆，我们突然看到一个黑色的窗口弹出，上面有一些正在执行的东西。崩溃发生时，她正试图画一些东西。这就是电脑崩溃时我们所记得的一切。
> 
> **注意** ：此挑战由 3 个flag组成。

Progress
--------

### Flag 1

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-b9e404158cfdfab908a86a3dafb1141ce226f2e8.png)​

既然有提到`突然看到黑色窗口弹出，在执行一些东西`，（看描述像是cmd命令行）那么我们用`pslist`查看一下：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c89119df62ec26ec8b41f1f62ce512b4144ffe26.png)​

确实是有`cmd.exe`这个进程，`consoles`查看命令行输出结果：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-76facdf3526b8acb8984790a110540584adc9327.png)​

很熟悉的base64，

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9cb8a4e32bbf13a6e90ae939384cf46d8015a872.png)​

**flag{th1s\_1s\_th3\_1st\_st4g3!!}**

### Flag 2

When the crash happened, she was trying to draw something.

在画画，看一下进程列表：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-53cef9787b1d2356105fe9c0849c9a2fd7cfa02b.png)​

看名称，这个进程和画画有关，PID是2424

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-22ab5d8b6ca36c920ca44a8505a14e1b153b8d0e.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0544050f05a325a838389466044cfb2d91d5214c.png)​

修改文件名后缀为`data`，导入GIMP

调整一下偏移量和宽高，

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d4e14d36ba146cf29a92367431c69b7b70d0ab75.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d6cb8ddc1f8029ee2ccd4b2fd0476dc6af4a0b8c.png)​

翻转一下就是`flag`

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-be1ebf53e7ee5c7bbd4069fb97f31634dfbaf323.png)​

**flag{Good\_Boy\_good\_girl}**

### Flag 3

后来才知道，这个地方看的是`WinRAR.exe`进程，

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5181bb0fcbbdba2be09b29498ed4ccd7a7a97130.png)​

看一下`WinRAR.exe`进程历史

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0f77c015362e55a731d4e41e8a8aae47355dcc16.png)​

看到了一个RAR压缩包：`Important.rar`

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-88a9a06d50d308ebf0731cdc5cdcefcbb59bf3af.png)​

根据地址提取出来：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-89e07a86e760a85f8ff21c20f333a6e8737517e7.png)​

检测是rar文件类型。修改文件名解压发现需要密码：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9edfd5edf7114e032cb3b5f66dc1ccfe04ec9c50.png)​

`hashdump`提取

```bash
┌──(root㉿SanDieg0)-[/mnt/d/volatility_2.6_win64_standalone]
└─# ./volatility.exe -f "F:\Memlabs\lab1\Lab1.raw" --profile=Win7SP1x64 hashdump
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SmartNet:1001:aad3b435b51404eeaad3b435b51404ee:4943abb39473a6f32c11301f4987e7e0:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:f0fc3d257814e08fea06e63c5762ebd5:::
Alissa Simpson:1003:aad3b435b51404eeaad3b435b51404ee:f4ff64c8baac57d22f22edc681055ba6:::
```

> hashdump提取有两个HASH，第一个是使用`LANMAN`算法，这种散列值非常不安全，在`Vista`以来的`Windows`系统已经不再采用`LANMAN HASH`。因此这个hash前会提供一个`aad`开头的虚拟值。
> 
> 第二个HASH是我们常说的`NTLM HASH`，也好不到哪去。

这个地方要解密NTLM，看用户名我盲猜是最后一个`f4ff64c8baac57d22f22edc681055ba6`：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-cca608dfa3b063a7c4f8c4b45657484b046e22c6.png)​

拿解密到的字符串怎么试都不对，结果发现，不用解密，换成大写。。。（无语住了）

![flag3](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e17c3e193cf8d2e098cc7e6cf4a6721f9b345158.png)​

**flag{w3ll\_3rd\_stage\_was\_easy}**

0x03 MemLabs Lab\_2 | A New World
=================================

下载链接：[MemLabs Lab\_2](https://mega.nz/#!ChoDHaja!1XvuQd49c7-7kgJvPXIEAst-NXi8L3ggwienE1uoZTk)

Challenge description
---------------------

One of the clients of our company, lost the access to his system due to an unknown error. He is supposedly a very popular "environmental" activist. As a part of the investigation, he told us that his go to applications are browsers, his password managers etc. We hope that you can dig into this memory dump and find his important stuff and give it back to us.

**Note** : This challenge is composed of 3 flags.

> 我们公司的一位客户由于未知错误而失去了对其系统的访问权限。据推测，他是一位非常受欢迎的“环保”主义者。作为调查的一部分，他告诉我们他的应用程序是浏览器、他的密码管理器等。我们希望你能深入这个内存转储并找到他的重要资料并将其还给我们。
> 
> **注意：**这个挑战由3个flag组成

Progress
--------

### Flag 1

老规矩：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-b93d753582105d7858705d9f414be56d82e4c066.png)​

根据题目描述，查看进程，重点查看浏览器和密码管理相关进程：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-1ed119e88eaf665a879498cdbdb9f46739fad7da.png)​

此外，上面还提到了环境变量，`envars`查看一下：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9ebd7f2ea133f65060b61faeb7ccf2fc2366c658.png)​

啊！这串熟悉的base64开头

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-1ed4600f2bde0aa2b95b703ec98293b3a15408c7.png)​

**flag{w3lc0m3*T0*$T4g3\_!\_Of\_L4B\_2}**

### Flag 2

回到浏览器，提取浏览器历史记录，`volatility`是不自带这个插件的

<https://github.com/superponible/volatility-plugins>

[(255条消息) volatility2各类外部插件使用简介\_Blus.King的博客-CSDN博客\_volatility插件](https://blog.csdn.net/q851579181q/article/details/110956485)

**注意：** `--plugins`后写清插件位置，比如这样：

```bash
┌──(root㉿SanDieg0)-[/mnt/d/volatility-master]
└─# python2 vol.py  --plugins=./volatility/plugins/ -f "/mnt/f/Memlabs/lab2/Lab2.raw" --profile=Win7SP1x64 chromehistory
```

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-79d3222ffa5acea95047f66b837a715f93cb5cfc.png)​

发现了一个下载链接，

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8fe35de530444f5ac8784bdefdbbf4804bbb0d3f.png)​

&lt;br /&gt;![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-344253e32b6aabe4d218e02d5b0123dfbd159a84.png)​

上个实验第三部分flag：**flag{w3ll\_3rd\_stage\_was\_easy}**

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c4ca3d33b747807d0116a18b2ac9b3437cb04dc0.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-88da219b3eeb384e3893b978646ff5a0780598b1.png)​

**flag{oK\_So\_Now\_St4g3\_3\_is\_DoNE!!}**

### Flag 3

还有一个密码管理器进程`KeePass.exe`没有用到

`KeePass`会存储密码在以`.kdbx`为后缀的数据库中，并用主密码（master password）进行管理

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9c73d8766852e8f4ae779cd0c048d67999796851.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5f6270592536c06fb7702ec0741cacb9925626b3.png)​

`filescan`并进行筛选：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-401cf1bbca80b2f18f694753292989ec69bb4710.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-48f58d11d997ec4db00e95bbad57a22a42c99619.png)​

将`Hidden.kdbx`转储出来后，找密码，文件里面有一张叫`Password.png`的图片

![Password](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-b557cd06d449c7bdf5395c0c0ebadf08c6eda87d.png)​

密码右下角：**P4SSw0rd\_123**

有了密码后，在`KeePass`里面打开这个数据库：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d03e4ed4bd9801f28cd478a3efc169d935f5db21.png)​

右键直接复制出来密码：**flag{w0w\_th1s\_1s\_Th3\_SeC0nD*ST4g3*!!}**

（咦？这个才是第二个flag吗？没事，我懒得改了：）

0x04 MemLabs Lab 3 | The Evil's Den
===================================

下载链接：[MemLabs Lab 3](https://mega.nz/#!2ohlTAzL!1T5iGzhUWdn88zS1yrDJA06yUouZxC-VstzXFSRuzVg)

Challenge Descryption
---------------------

A malicious script encrypted a very secret piece of information I had on my system. Can you recover the information for me please?

**Note-1** : This challenge is composed of only 1 flag. The flag split into 2 parts.

**Note-2** : You'll need the first half of the flag to get the second.

You will need this additional tool to solve the challenge,

```bash
sudo apt install steghide
```

The flag format for this lab is: **inctf{s0me\_l33t\_Str1ng}**

> 恶意脚本加密了我系统上的一条非常机密的信息。你能为我恢复信息吗？
> 
> **注意-1：**本次挑战只有一个flag，但被分为两个部分。
> 
> **注意-2：**你需要得到第一部分的flag才能得到第二部分flag。

Progress
--------

### The first part of the flag：

懂得都懂：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-1bfb17c1248aa224ae56b7ed33b886f39da85473.png)​

题目描述说有恶意脚本，看一下`cmd`的记录：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f873fc0bc67d0615a439fa7a6bfa3ec3e2bdf1d9.png)​

确实有一个叫恶意脚本的py脚本?还有一个`vip.txt`

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-add5744b74aa2ca224213c9278a1995b2e9492da.png)​

**evilscript.py.py：**

```python
import sys
import string

def xor(s):

    a = ''.join(chr(ord(i)^3) for i in s)
    return a

def encoder(x):

    return x.encode("base64")

if __name__ == "__main__":

    f = open("C:\\Users\\hello\\Desktop\\vip.txt", "w")

    arr = sys.argv[1]

    arr = encoder(xor(arr))

    f.write(arr)

    f.close()

```

**vip.txt：**

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d0d89f689cd8ce2ab0e9818234c84ba29e32cbdf.png)​

呃。。。

看一下脚本过程比较简单，先用一个字符将`vip.txt`的内容进行异或，然后base64加密一遍，解密也很简单，把过程逆过来就好：

```python
s = 'am1gd2V4M20wXGs3b2U='
d = s.decode('base64')
a = ''.join(chr(ord(i)^3) for i in d)

print a
```

执行结果：**inctf{0n3\_h4lf**，这是第一部分

### The second part of the flag

按照题目描述，还会用到`steghide`，扫一下图片文件：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-097dfed328fa63d7cf27e4eb1a3e23502ffc2aa5.png)​

`.jpg`都是些临时文件，`.jpeg`这个可能性最大，而且名字就很可疑?导出来看看：

![suspision1](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0bba642e9b4c9f64d3ac50f6fc46434a5072b52c.jpeg)![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-da032c3b25f64811a4390c8ecac2a030d54711e0.png)上面说，**有了第一部分的flag才能获取到第二部分**，那提示很明显了，密码应该就是第一部分flag

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-21a45d620d1dcd35ae5ebb8001992e9bd9c91601.png)​

**\_1s\_n0t\_3n0ugh}**

综上，flag为：**inctf{0n3\_h4lf\_1s\_n0t\_3n0ugh}**