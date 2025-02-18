前言
==

Amadey是一种常见的恶意软件，通常被归类为信息窃取程序（Stealer）或僵尸网络（Botnet）木马。因为它的主要功能就是从被感染的系统中窃取各种敏感信息发送给C2服务器。同时，系统被感染后，Amadey会将受害者系统连接到一个僵尸网络中，攻击者可以远程控制受感染的机器，执行进一步的恶意操作，例如安装其它恶意软件，发送垃圾邮件、发送DDoS攻击等。

样本分析
====

IOC
---

| Hash | Value |
|---|---|
| SHA256 | 449d9e29d49dea9697c9a84bb7cc68b50343014d9e14667875a83cade9adbc60 |
| MD5 | 26b31e11da1e9fb60b64b91414884eb9 |
| SHA1 | 0358b52196af9125be76f335a57f2905f400999d |

ANY.RUN沙箱链接：<https://app.any.run/tasks/5c44716d-e2f8-4cbd-a86e-031147a3a02b/>

DIE查看
-----

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-039b2ba5bd06d1c989801241c713203b32b74531.png)

本质上是一个zip文件，解压。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-80dd156cf8a2004cd87202729e111a638ab907d1.png)

si684017.exe
------------

### DIE查看

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e26d77cb3d04e0091ff9b1269d9081a084e7039e.png)

32位文件，查看一下信息熵：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-18b8e5a0ee91696261e33fa9893b048d9ba9c2d3.png)

高而平坦的曲线，说明该文件是一个加过壳的程序。

### 脱壳

使用x32dbg载入恶意程序。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3eb1ccd12c50dcc26d562ffc2ee9fb5640c504dd.png)

通过命令 `bp VirtualAlloc` 给函数 `VirtualAlloc`打下断点。该函数用于在地址空间中分配内存，其执行完返回值是分配的页面区域的基地址。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-36788bb4446da00280ea942fd1323f112d66ef75.png)

F9运行后 会断在`VirtualAlloc`处

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-cd0e0ac100fbc20c0b1649142534bbccf002fefe.png)

此时通过 Ctrl+F9 可以执行到该函数结束，观察eax，eax的值就是该函数的返回值，即分配的内存的地址。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b977219cea58c0340bb322a273a60fb8854d8295.png)

点击跳转到该内存：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-cc516c4285edc4a33c8f29e723907b796a9575de.png)

创建一个硬件断点

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-32a4a1bf2d9e8970f432db76f3e9922c8f4acbd8.png)

接着F9运行，再Ctrl+F9运行到结束，会发现该内存已经填满了数据。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2c039422ebf383098838a75511ad9dcb46531b36.png)

可是发现，该内存起始 是EB，并不是PE文件标识，推测这里并不是我们要的有效负载。

删除这个硬件断点，接着F9会断到下一个 `VirtualAlloc`处，继续刚刚的步骤

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0b99dfa7aa5b851732949192df9d835641abf4ed.png)

成功将脱壳文件加载到了内存中。

这里需要等待一段时间，确保这块缓冲区被填满。不然dump出来的文件是缺失的，分析了半天没有东西。

### Dump

右键刚刚的内存基地址，查看其内存布局

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7510bbc1ea7e33a6c3b00713790ce8d275d5da4c.png)

找到其对应的模块，右键选择dump到文件中

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-de1bf525d6cae64256b77f5364434ec629f9c5d0.png)

重命名为dump.bin

dump.bin
--------

### DIE查看

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-67c80878f5fa150705f3512b600c20c037797a2a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-eacffefa69cc1779fef0e448ea7210590e596903.png)

32位程序，信息熵表示没有隐藏的有效负载。

#### 导入表

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f39acfcacd6e0484e9309f8aedc88a6082357cd3.png)

发现wininet.dll,说明该恶意程序有关于C2服务器的操作。

#### 字符串

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1ddad9170ee2c9f97212b7d7e7dd519d13e96aa4.png)

发现了很多可能由base64编码的字符串，尝试解密

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3be7c422eb8d493e4a5bde33f1386995418daae0.png)

都是乱码，估计是加了别的混淆

### Ghidra和xdbg分析

#### 同步地址

为了方便调试。先同步一下地址。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2f3cd354dd644fdb77f214d59419e44d4faf8379.png)

先找到该文件在xdbg中的基址，005B0000

在ghirda内存映射中设置

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a37bdd9f357324c25b91de36d2d9da7e10835d47.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9252f151a18289faf0d98ee83347a0acbddbebbe.png)

#### 定位字符串

在Ghirda中搜索字符串：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7da6816b4c0bab660ccc203ad4de9e41eab8a853.png)

双击跳转到该地址处

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-32e496f8d426d746dc27f6c9b2face220ff5ba3a.png)

右键选择 Reference -&gt; Show References to Address

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8e48cc8e26a6c205b8f5fc8bf33505ef5a876dda.png)

可以看到该函数还未定义：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b3f8b2360a2f23ffd8be50cb91e53856c3c3b7cb.png)

鼠标选中左侧该函数首地址，按F可以定义函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1538850dc309d35797b14e9751746af1d19157ec.png)

#### FUN\_005c4550

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-70de2039032d9e9852007fd35dd83e2b1d3fcb69.png)

该函数像是在进行解码操作，对其进行交叉引用可以发现它被大量引用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-242f17f795b6d36a563befbfe7229bcbf7db2b40.png)

因此我们可以对该函数下断点，动态调试的方法得到解码后的数据。

### xdbg解密

刚刚已经进行了同步地址，直接在xdbg上下断点 `bp 005c4550`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-605ab3c1971d93572e438f994b5713d3f3c7942d.png)

F9运行 命中了一个字符串

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5192e5b48414ad85f07327272a7d2ed63dde53a5.png)

之后继续 Ctrl+F9 就可以得到解密的结果

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-832eb7a9322d1a6a26b8385f02febfbac7ed4593.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-025990baa1084b01d0fd4c676465dc1a36bbfaf5.png)

经过多次的尝试后，发现解密的东西并不是我们所需的，这个函数也并不是最终解码的函数，它似乎只是base64混淆的一部分。

### 回到Entry入口

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-96739ddca17549c6320f0ac9cca7e2d53e1aedf6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b517e13e27a9a1bd1dd1009263902347a27ef963.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c76c0cc146ba69ecb20bb7962e587269c4728802.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e6508d379129d8f49d3fd528c244e99cd0fe50f7.png)

一个解码函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-75cb8edf56a7168b1d9db788ad10d4a18295de2d.png)

同样的，在xdbg中对该函数下断点，调试：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-53defb9bd650b2556f0953955169efd4ba6787d6.png)

传入了一个base64编码，解码后：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-141d12d3233b76dd70a6e5f83fbce3f837c4144d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b7ef6042fe73c4f2add637d85a2e104fea0f4058.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a19fd2926f1e35641ef07aedff7ea7fe8e7e10da.png)

可以看到，上一个编码的值被作为路径的一部分。这里像是在检查该路径

继续F9：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-41fd35f5bad2d439f087e2903b2690296d0d4e0e.png)

发现没有命中任何东西了，Ctrl+F9，执行完该函数，你会发现程序结束了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-92eb9934d33e5c0b1ae2842d337a0314f9abdfa9.png)

说明这里存在了某种反调试。

### 绕过反调试

回到刚刚的`FUN_005c4040`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fad81728705b6e936fb91b4b57e9cf39e9d11d74.png)

查看一下`FUN_005b7b70`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5f00bd6a1b585157bf2f4cef5de25d8417784981.png)

`CreateMutexA`函数创建了一个互斥锁，后面检查错误码 `0xb7`，不符合的话退出程序。

回到xdbg，命令 `bp 005b7b70`

重新运行后，发现程序还是退出了，结合刚刚分析出来的路径，推测是检查同一路径下是否有文件 `oneetx.exe`

这里绕过可以 运行下恶意软件，让其再路径下自动生成一个副本。之后分析副本即可，重新同步一下地址（有所变化）再次运行，发现成功断下来了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f3749308b504fa854f0a5b42b96649cbdd1c3d11.png)

该 `00967b70`即刚刚的 `FUN_005b7b70`

F8单步下去，直接patch掉即可

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-da9277d0d0332996e19dc96c5da86de0e1fbd365.png)

这样俩处反调试就绕过了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6da349a9a425488b12ec89f154e0e1b72e0ee254.png)

### 开始解码

之后就是不断运行，F9后Ctrl+F9 查看返回值

疑似对注册表进行查询修改

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3bb1b2562a05cf0c1b7501a9ddd73253695c32fe.png)

该命令用于创建计划任务，持久性操作

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3403bc470abe333452fa2e95b904f4de2d63ea90.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-84381bd52e2f235735bee50aae5754c531bf3417.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-26eb85bd2cffa1590b5b19beb27993c48e45b1e1.png)

可能尝试窃取计算机上的某些数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-56f6a0dd13ca478a3c51a37d24b677c533e04130.png)

检查一些安全厂商

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c96b8966a19fc4a1f9bb5dcabdeee943db84c872.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-bef7a8d897b635d00de659df8d6577eacfe92ad5.png)

#### C2服务器

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f5bed18df59e2c5a3a899d6608e8e28017031288.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-4a4df4ffedf050d524d626212715614309cf31fa.png)

最后找到了该恶意软件的C2域名。

后言
==

分析了该样本的大致流程，如何找到了C2信息。关于该样本恶意行为具体是怎样实现的后续再分析。