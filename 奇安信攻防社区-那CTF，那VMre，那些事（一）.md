0x00前言
------

最近做题刷到了2020网鼎杯一道vm虚拟机保护的re题目，遂决定系统的学习一下vm虚拟机保护逆向的相关知识。毕竟vm逆向在各大比赛中势头正盛。

题目附件在文章末尾。需要的大佬可以下载学习一下。

0x01什么是虚拟机？什么是vm？
-----------------

学习虚拟机逆向，首先要了解什么是虚拟机。按照我之前的粗浅理解，虚拟机是寄生于宿主电脑上的一台虚拟电脑，来满足使用者关于多个操作系统配合、危险软件隔离分析等等需求的技术。当然这是个人理解，仅供参考。而在大佬博客中，我看到了如下精彩的定义：

> 虚拟机：自己定义一套指令，在程序中能有一套函数和结构解释自己定义的指令并执行功能。

上述定义将虚拟机的原理讲的很透彻了。接下来我们说说什么是vm。首先给出官方定义

> vm（虚拟机保护）是一种基于虚拟机的代码保护技术。他将基于x86汇编系统中的可执行代码转换为字节码指令系统的代码。来达到不被轻易篡改和逆向的目的。

简单来说就是出题人通过实现一个小型的虚拟机，把程序的代码转换为程序设计者自定义的操作码（opcode）然后在程序执行时通过解释操作码，执行对应的函数，从而实现程序原有的功能。

下图是一个一般虚拟机结构

![未命名文件.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-62df7fdcb0d174e10d09b59fd6af5df5ce0840e5.png)

对于上图出现的概念的解释:

> **VMRUN**:虚拟机入口函数  
> **dispatcher**：调度器，用于解释opcode，并选择对应的Handler函数执行，当Handler执行完后会跳回这里，形成一个循环。  
> **opcode**：程序可执行代码转换成的操作码  
> **Handler**：各种功能对象模块

当然这里的虚拟机并不是指VMWare\\VirtualBox之类的虚拟机，它更像是一个用于解释系统函数的一个小型模拟器。

0x02出题人如何实现vmre小型虚拟机
--------------------

想要搞清楚虚拟机保护re首先要搞清楚用于保护的虚拟机是如何实现的。

要想实现虚拟机的话需要完成两个目标：  
1.定义一套opcode  
2.实现opcode的解释器

### 初始化虚拟寄存器、opcode存放

```php
typedef struct
{
    unsigned long r1;    //虚拟寄存器r1
    unsigned long r2;    //虚拟寄存器r2
    unsigned long r3;    //虚拟寄存器r3
    unsigned char *eip;    //指向正在解释的opcode地址
    vm_opcode op_list[OPCODE_N];    //opcode列表，存放了所有的opcode及其对应的处理函数
}vm_cpu;
```

r1-r3用来传参或者是存放返回值,eip指向opcode的地址

### 定义opcode

opcode只是一个标识，可以随便定义

```php
typedef struct
{
    unsigned char opcode;
    void (*handle)(void*);
}vm_opcode;
```

### 关联opcode和对应handler函数

```php
void *vm_init()
{
    vm_vpu *cpu;
    cpu->r1 = 0;
    cpu->r2 = 0;
    cpu->r3 = 0;
    cpu->eip = (unsigned char *)vm_code;//将eip指向opcode的地址

    cpu->op_list[0].opcode = 0xf1;
    cpu->op_list[0].handle = (void (*)(void *))mov;//将操作字节码与对应的handle函数关联在一起

    cpu->op_list[1].opcode = 0xf2;
    cpu->op_list[1].handle = (void (*)(void *))xor;

    cpu->op_list[2].opcode = 0xf5;
    cpu->op_list[2].handle = (void (*)(void *))read_;

    vm_stack = malloc(0x512);
    memset(vm_stack,0,0x512);//定义了一个新栈并在malloc上申请了0x512位的空间
```

### 虚拟机入口函数

```php
void vm_start(vm_cpu *cpu)
{
    cpu->eip = (unsigned char*)opcodes;//eip指向要被解释的opcode地址
    while((*cpu->eip) != 0xf4)//如果opcode不为RET，就调用vm_dispatcher来解释执行
    {
        vm_dispatcher(*cpu->eip)
    }
```

### 解释执行器编写

```php
void vm_dispatcher(vm_cpu *cpu)
{
    int j;
    for(j=0;j<OPCODE_N;j++)
    {
        if(*cpu->eip ==cpu->op_list[i].opcode)
        {
            cpu->op_list[i].handle(cpu);
            break;
        }
    }
}
```

### 具体执行函数实现

这里实现 mov xor read 三个简单的指令 其中read指令用于读取数据 在题目中用于读取flag。具体题目中根据题目要求实现不同的函数功能即可。所以说虚拟机类re题目很好的考察了参赛选手的代码能力

```php
void xor(vm_cpu *cpu)
{
    int num;
    num =cpu->r1 ^cpu->r2;
    num ^=0x12;
    cpu->r1= temp;
    cpu->eip=eip+1;//这里一定要注意xor指令本身是占一个字节的。
}
void mov(vm_cpu *cpu)
{
    /*mov指令的参数都隐藏在字节码中，指令表示后的一个字节是寄存器标识，第二到第五是要mov的数据在vm_stack上的偏移。这里只实现了从vm_stack栈上存取数据*/
    unsigned char *res =cpu->eip+1;//寄存器标识
    int *offset = (int *)(cpu->eip+2);
    char *dest=0;
    dest=vm_stack;
    switch(*res){
        case 0xe1:
        cpu->r1=*(dest + *offset);
        break;
        case 0xe2:
        cpu->r2=*(dest + *offset);
        break;
        case 0xe3:
        cpu->r3=*(dest + *offset);
        break;//数据寄存
        case 0xe4:
            {
                int x=cpu->r1;
                *(dest + *offset)=x;
                break;
            }//获取寄存器中数据
    }
    cpu->eip += 6;//mov指令占六个字节，所以eip要向后移6位
}
```

### 定义opcode字符集

定义opcode字符集，每个字符对应一个函数功能模块

```php
unsigned char vm_code[] = {
    0xf5,
    0xf1,0xe1,0x0,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x20,0x00,0x00,0x00,
    0xf1,0xe1,0x1,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x21,0x00,0x00,0x00,
    0xf1,0xe1,0x2,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x22,0x00,0x00,0x00,
    0xf1,0xe1,0x3,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x23,0x00,0x00,0x00,
    0xf1,0xe1,0x4,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x24,0x00,0x00,0x00,
    0xf1,0xe1,0x5,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x25,0x00,0x00,0x00,
    0xf1,0xe1,0x6,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x26,0x00,0x00,0x00,
    0xf1,0xe1,0x7,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x27,0x00,0x00,0x00,
    0xf1,0xe1,0x8,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x28,0x00,0x00,0x00,
    0xf1,0xe1,0x9,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x29,0x00,0x00,0x00,
    0xf1,0xe1,0xa,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x2a,0x00,0x00,0x00,
    0xf1,0xe1,0xb,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x2b,0x00,0x00,0x00,
    0xf1,0xe1,0xc,0x00,0x00,0x00,0xf2,0xf1,0xe4,0x2c,0x00,0x00,0x00,
    0xf4
};
```

至此，一个简化版的小型虚拟机就实现完了。该虚拟机实现了对输入字符串简单的异或加密，并将加密后的值存储到指定位置。

用gcc编译一下就可以在ida上自己逆着玩（没想到意外的学会了vmre怎么出题）

0x03 ctf vm逆向思路
---------------

了解了上述知识，下面我们来梳理一下ctf中vm逆向的思路

这里借用一位大佬的总结

> 解题一般步骤：
> 
> 分析VM结构-&gt;分析opcode-&gt;编写parser-&gt;re算法
> 
> VM结构常见类型：
> 
> 基于栈、基于队列、基于信号量
> 
> opcode：
> 
> 与VM数据结构对应的指令 ：push pop
> 
> 运算指令：add、sub、mul

0x04 ctf实战
----------

纸上得来终觉浅，掌握了vm虚拟机保护的核心科技。做几个ctf题目来实践一下。先来看看南邮CTF经典的两道vm逆向（ WxyVM1 WxyVM2）

### WxyVM1

先查壳，文件为无壳64位文件 反编译main函数

```c++
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4; // [rsp+Bh] [rbp-5h]
  int i; // [rsp+Ch] [rbp-4h]

  puts("[WxyVM 0.0.1]");
  puts("input your flag:");
  scanf("%s", &byte_604B80);
  v4 = 1;
  sub_4005B6();
  if ( strlen(&byte_604B80) != 24 )
    v4 = 0;
  for ( i = 0; i <= 23; ++i )
  {
    if ( *(&byte_604B80 + i) != dword_601060[i] )
      v4 = 0;
  }
  if ( v4 )
    puts("correct");
  else
    puts("wrong");
  return 0LL;
}
```

main函数逻辑非常简单 flag经过sub\_4005B6的处理之后 与dword\_601060\[i\] 进行匹配。

那么我们只需要把sub\_4005B6研究明白就可以了

```php
__int64 sub_4005B6()
{
  __int64 result; // rax
  int i; // [rsp+0h] [rbp-10h]
  char v2; // [rsp+8h] [rbp-8h]
  int v3; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 14999; i += 3 )
  {
    v2 = byte_6010C0[i + 2];
    v3 = byte_6010C0[i + 1];
    result = (unsigned int)byte_6010C0[i];
    switch ( byte_6010C0[i] )
    {
      case 1:
        result = byte_6010C0[i + 1];
        *(&byte_604B80 + v3) += v2;
        break;
      case 2:
        result = byte_6010C0[i + 1];
        *(&byte_604B80 + v3) -= v2;
        break;
      case 3:
        result = byte_6010C0[i + 1];
        *(&byte_604B80 + v3) ^= v2;
        break;
      case 4:
        result = byte_6010C0[i + 1];
        *(&byte_604B80 + v3) *= v2;
        break;
      case 5:
        result = byte_6010C0[i + 1];
        *(&byte_604B80 + v3) ^= *(&byte_604B80 + byte_6010C0[i + 2]);
        break;
      default:
        continue;
    }
  }
  return result;
}
```

sub\_4005B6()函数里也有一个已知数组byte\_6010C0，byte\_6010C0数组三位为一组，第一位指示操作，第二位指示输入的哪一位进行操作，第三位指示操作数。观察发现byte\_6010C0数组第一位只有1, 2, 3，所以只会存在前三种运算，即加减异或，这都是很好逆的算法。由于byte\_6010C0数组过大，我们选择不导出直接利用idapython的方式直接re

```php
from idc_bc695 import * //IDA7.5+需要引入该库不然会报错
arr = [4294967236, 52, 34, 4294967217, 4294967251, 17, 4294967191, 7, 4294967259, 55, 4294967236, 6, 29, 4294967292, 91, 4294967277, 4294967192, 4294967263, 4294967188, 4294967256, 4294967219, 4294967172, 4294967244, 8]
addr = 0x6010c0
for i in range(len(arr)):
    arr[i] &= 0xffffffff 
for i in range(14997,-1,-3):
    v0 = Byte(addr + i)
    v3 = Byte(addr + i + 2)
    result = Byte(addr + i + 1)
    if v0 == 1:
        arr[result] -= v3

    if v0 == 2:
        arr[result] += v3
    if v0 == 3:
        arr[result] ^= v3
for i in range(len(arr)):
    arr[i] &= 0xff
print(''.join(map(chr, arr)))

```

运行得到flag

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d416869e47726660851b7715084efb57fdfbcd8d.png)

### WxyVM2

考察去花指令

同样的无壳64位。这次反编译main函数的时候出问题了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2cfeb8f8c9e60063e9f2188272f8db1263a9d4ef.png)

百度搜索了一波找到了解决方案

```php
修改ida中的cfg文件夹下的hexrays.cfg中的 
MAX_FUNCSIZE= 1024(64改为1024)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8182e8cb487a274144d7cbe87951ea3833a8dc95.png)

耐心等待...让子弹飞一会儿。进去会看到大量的伪代码。千万不要被这两万多行的代码吓住了（确实很吓人）我们仔细观察一下末尾的循环发现，由于的循环长度只有24，dword的地址远远超出了这个范围。所以dword数据的计算，其实影响不到最后的结果。byte的计算才是我们这题真正的算法所在。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9cecbcb89001c2122527e470a348a4f0ffe4f91b.png)

接下来可以使用ida脚本去花。只保留byte的相关计算

```python
import os
file_1 = open('flag.txt', 'r')
s = file_1.read()
s = s.replace('\n', '')
s = s.replace('u','')
s=s.replace(' ','') #去除空格
a = s.split(';')
ss = ''
for i in a[::-1]: #逆向算法
    if i[0] == 'b':
        ss += i + '\n'
file_1.close()
ss = ss.replace('+','$') #逆向加减法
ss = ss.replace('-','+')
ss = ss.replace('$','-')
ss = ss.replace('byte_','arr[')
for i in range(65,71,1): #大写变小写
    ss = ss.replace(chr(i),chr(i+32))
for  i in range(25):
    ss = ss.replace(str(hex(0x694100+i)).replace('0x',''),str(i)+']')
file_2 = open('flag2.txt','w')
file_2.write(ss)
file_2.close()
```

也可以使用文本编辑器，这里推荐emeditor 正则匹配的功能相当完善。处理大批量数据不卡顿。最后将处理过的数据输出即可

```php
arr = [4294967232, 4294967173, 4294967289, 108, 4294967266, 20, 4294967227, 4294967268, 13, 89, 28, 35, 4294967176, 110, 4294967195, 4294967242, 4294967226, 92, 55, 4294967295, 72, 4294967256, 31, 4294967211, 4294967205]
#这里是直接复制过滤后的文件 太长了这里就不放上了
for i in range(25):
    print(chr(arr[i]&0xff),end='')
```

### \[网鼎杯 2020 青龙组\]singal

前两道题目感觉还是缺点vm的味道。应该是题目简单的原因吧。接下来网鼎杯的这道题目才真的开始有内味了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2fe1ad58877a23061374cf2b26c12324db995454.png)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4[117]; // [esp+18h] [ebp-1D4h] BYREF

  __main();
  qmemcpy(v4, &unk_403040, 0x1C8u);
  vm_operad(v4, 114);
  puts("good,The answer format is:flag {}");
  return 0;
}
```

反编译一下main函数。发现本题是一道标准的vm逆向。先根据我们总结过的vm逆向思路，写个脚本提取出operad\_code

```php
from idc_bc695 import *
start_addr=0x403040
alist=[]
for i in range(114):
    t=Dword(start_addr)
    alist.append(t)
    start_addr+=4
print(alist)
print(len(alist))
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a4f459a2fdf67661e4fb4ea7687e3ca3c9ca3ae6.png)

整理一下获取的数据

```php
op_code=[10,4,16,8,
3,5,1,4,32,8,
5,3,1,3,2,8,11,1,12,8,4,
4,1,5,3,8,3,33,1,11,8,11,1,4,
9,8,3,32,1,2,81,8,4,36,1,12,8,11,
1,5,2,8,2,37,1,2,54,8,4,65,1,2,32,
8,5,1,1,5,3,8,2,37,1,4,9,8,3,32,1,2,
65,8,12,1,7,34,7,63,7,52,7,50,7,114,7,51,
7,24,7,4294967207,
7,49,7,4294967281,7,
40,7,4294967172,7,4294967233,
7,30,7,122]
```

接下来分析 vm opread部分。是典型的VM switch结构

```php
int __cdecl vm_operad(int *a1, int a2)
{
  int result; // eax
  char op_code[200]; // [esp+13h] [ebp-E5h] BYREF
  char v4; // [esp+DBh] [ebp-1Dh]
  int v5; // [esp+DCh] [ebp-1Ch]
  int v6; // [esp+E0h] [ebp-18h]
  int v7; // [esp+E4h] [ebp-14h]
  int v8; // [esp+E8h] [ebp-10h]
  int op_index; // [esp+ECh] [ebp-Ch]

  op_index = 0;
  v8 = 0;
  v7 = 0;
  v6 = 0;
  v5 = 0;
  while ( 1 )
  {
    result = op_index;
    if ( op_index >= a2 )
      return result;
    switch ( a1[op_index] )
    {
      case 1:
        op_code[v7] = v4;
        ++op_index;
        ++v6;
        ++v8;
        break;
      case 2:
        v4 = a1[op_index + 1] + op_code[v8];
        op_index += 2;
        break;
      case 3:
        v4 = op_code[v8] - LOBYTE(a1[op_index + 1]);
        op_index += 2;
        break;
      case 4:
        v4 = a1[op_index + 1] ^ op_code[v8];
        op_index += 2;
        break;
      case 5:
        v4 = a1[op_index + 1] * op_code[v8];
        op_index += 2;
        break;
      case 6:
        ++op_index;
        break;
      case 7:
        if ( op_code[v8] != a1[op_index + 1] )
        {
          printf("what a shame...");
          exit(0);
        }
        ++v7;
        op_index += 2;
        break;
      case 8:
        op_code[v5] = v4;

        ++op_index;
        ++v5;
        break;
      case 10:
        read(op_code);
        ++op_index;
        break;
      case 11:
        v4 = op_code[v8] - 1;
        ++op_index;
        break;
      case 12:
        v4 = op_code[v8] + 1;
        ++op_index;
        break;
      default:
        continue;
    }
  }
}//该代码经过阅读理解对变量进行了重命名
//字符数组是用来存储op_code的 在每个case中都出现的变量应该是指针索引
```

分析一下这些case 我们发现可以分为三类

**第一类：验证类**

```php
 case 7:
        if ( op_code[v8] != a1[op_index + 1] )
        {
          printf("what a shame...");
          exit(0);
        }
        ++v7;
        op_index += 2;
        break;
```

其实就是把输入的字符串经过一系列操作之后存到了`opcode`中

**第二类：字符处理**

```php
      case 2:
        v4 = a1[op_index + 1] + op_code[v8];
        op_index += 2;//加法
        break;
      case 3:
        v4 = op_code[v8] - LOBYTE(a1[op_index + 1]);
        op_index += 2;//减法
        break;
      case 4:
        v4 = a1[op_index + 1] ^ op_code[v8];
        op_index += 2;//异或
        break;
      case 5:
        v4 = a1[op_index + 1] * op_code[v8];
        op_index += 2;//乘法
        break;
      case 11:
        v4 = op_code[v8] - 1;
        ++op_index;//自减
        break;
      case 12:
        v4 = op_code[v8] + 1;
        ++op_index;//自增
        break;
```

**第三类：其他操作**

```php
case 1:
        op_code[v7] = v4;
        ++op_index;
        ++v6;
        ++v8;
        break;//赋值操作
case 6:
        ++op_index;
        break;//啥也不干指针++
case 8:
        op_code[v5] = v4;
        ++op_index;
        ++v5;
        break;//变量赋值
```

进一步分析我们发现：v5 v6 v7 v8是数组的索引，v4为操作的返回值.这样switch就分析的很明了了。下面回过头来看一看op\_code。发现在比较操作数7第一次出现的位置之后，都是一些无效指令(大于12)，所以，加密运算应该是在操作数7第一次出现之前完成。因此有效的opcode应该是

```php
a=[10, 4, 16, 8, 3, 5, 1, 4, 32, 8, 5, 3, 
1, 3, 2, 8, 11, 1, 12, 8, 4, 4, 1, 5, 3, 8,
 3, 33, 1, 11, 8, 11, 1, 4, 9, 8, 3, 32, 
1, 2, 81, 8, 4, 36, 1, 12, 8, 11, 1, 5, 2,
 8, 2, 37, 1, 2, 54, 8, 4, 65, 1, 2, 32, 8,
 5, 1, 1, 5, 3, 8, 2, 37, 1, 4, 9, 8, 3, 32, 1, 
2, 65, 8, 12, 1]
```

分析剩余的部分。既然case7是对数据进行验证。那么7后面跟着的就是加密后的字符。

```php
7,34,7,63,7,52,7,50,7,114,7,51,
7,24,7,4294967207,
7,49,7,4294967281,7,
40,7,4294967172,7,4294967233,
7,30,7,122]
```

整理后开始写re脚本。由于本题逆向来写的话实现操作比较复杂所以我们采取正向遍历的思路去试出`flag`

```php
encrypts = [0x22, 0x3F, 0x34, 0x32, 0x72, 0x33, 0x18, 0xA7, 0x31, 0xF1, 0x28, 0x84, 0xC1, 0x1E, 0x7A]

data = [[4, 0x10, 8, 3, 5, 1]
    , [4, 0x20, 8, 5, 3, 1]
    , [3, 2, 8, 0x0B, 1]
    , [0x0C, 8, 4, 4, 1]
    , [5, 3, 8, 3, 0x21, 1]
    , [0x0B, 8, 0x0B, 1]
    , [4, 9, 8, 3, 0x20, 1]
    , [2, 0x51, 8, 4, 0x24, 1]
    , [0x0C, 8, 0x0B, 1]
    , [5, 2, 8, 2, 0x25, 1]
    , [2, 0x36, 8, 4, 0x41, 1]
    , [2, 0x20, 8, 5, 1, 1]
    , [5, 3, 8, 2, 0x25, 1]
    , [4, 9, 8, 3, 0x20, 1]
    , [2, 0x41, 8, 0x0C, 1]]

for_each = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
            'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0']

def encrypted(c, li):
    # print(li)
    x = 0
    while x < len(li):
        if li[x] == 2:
            c = c + li[x + 1]
            x += 2
        elif li[x] == 3:
            c = c - li[x + 1]
            x += 2
        elif li[x] == 4:
            c = c ^ li[x + 1]
            x += 2
        elif li[x] == 5:
            c = c * li[x + 1]
            x += 2
        elif li[x] == 11:
            c = c - 1
            x += 1
        elif li[x] == 12:
            c = c + 1
            x += 1
        elif li[x] == 8:
            x += 1
        elif li[x] == 1:
            break
    res = c
    return res

if __name__ == '__main__':
    flag = ''
    for x in range(len(encrypts)):
        for i in for_each:
            tmp = encrypted(ord(i), data[x])
            if tmp == encrypts[x]:
                flag += i
                break
            else:
                continue
    print('flag{%s}' % flag)
```

0x05后记
------

在我看来，vm虚拟机保护逆向，是一种利用了虚拟机技术的一种特殊加花指令方式。目前比赛中，虚拟机题目特点是核心算法不是很复杂，虚拟机本身没有反调试和代码加密混淆的加入。大部分题目的思路都是考察分析switch语句及其分支。当然，随着整体CTF水平的不断进步，未来虚拟机逆向难度只会越来越高。

这两天应该会写出系列的第二篇文章，围绕vm虚拟机逆向进阶操作。以及网鼎杯题目的更多解法思路讨论（利用angr）敬请期待

0x06参考链接
--------

<https://www.cnblogs.com/nigacat/p/13039289.html>

<https://www.freebuf.com/column/174623.html>

<https://xz.aliyun.com/t/3851>

[https://blog.csdn.net/weixin\_43876357/article/details/108570305](https://blog.csdn.net/weixin_43876357/article/details/108570305)

[https://blog.csdn.net/weixin\_45055269/article/details/105940348](https://blog.csdn.net/weixin_45055269/article/details/105940348)

<https://blog.csdn.net/lhk124/article/details/108946313>

<https://blog.csdn.net/xiangshangbashaonian/article/details/78884187>