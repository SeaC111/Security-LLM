0x00前言
======

vmre的简单知识点研究的差不多了，这篇我们只聊做题，复现分析三道较为复杂的vmre题目，谈谈感受

0x01\[defcon2016quals\]\_baby-re
================================

题目标签：进阶angr利用。

解题过程：

查壳 无壳64位elf文件，ida打开直接反编译main函数。发现函数逻辑非常简单。输入匹配13位的字符串。看到这种和输入，匹配相关的，当然立马就想到angr符号执行一把梭啦。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+0h] [rbp-60h] BYREF
  unsigned int v5; // [rsp+4h] [rbp-5Ch] BYREF
  unsigned int v6; // [rsp+8h] [rbp-58h] BYREF
  unsigned int v7; // [rsp+Ch] [rbp-54h] BYREF
  unsigned int v8; // [rsp+10h] [rbp-50h] BYREF
  unsigned int v9; // [rsp+14h] [rbp-4Ch] BYREF
  unsigned int v10; // [rsp+18h] [rbp-48h] BYREF
  unsigned int v11; // [rsp+1Ch] [rbp-44h] BYREF
  unsigned int v12; // [rsp+20h] [rbp-40h] BYREF
  unsigned int v13; // [rsp+24h] [rbp-3Ch] BYREF
  unsigned int v14; // [rsp+28h] [rbp-38h] BYREF
  unsigned int v15; // [rsp+2Ch] [rbp-34h] BYREF
  unsigned int v16; // [rsp+30h] [rbp-30h] BYREF
  unsigned __int64 v17; // [rsp+38h] [rbp-28h]

  v17 = __readfsqword(0x28u);
  printf("Var[0]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v4);
  printf("Var[1]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v5);
  printf("Var[2]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v6);
  printf("Var[3]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v7);
  printf("Var[4]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v8);
  printf("Var[5]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v9);
  printf("Var[6]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v10);
  printf("Var[7]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v11);
  printf("Var[8]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v12);
  printf("Var[9]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v13);
  printf("Var[10]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v14);
  printf("Var[11]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v15);
  printf("Var[12]: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v16);
  if ( (unsigned __int8)CheckSolution(&v4) )
    printf("The flag is: %c%c%c%c%c%c%c%c%c%c%c%c%c\n", v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16);
  else
    puts("Wrong");
  return 0;
}
```

avoid\_addr和 find\_addr都肥肠好找

![image-20220226101048156](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b4e904bb73a400616ec4a50ffd1c7ab3876512a2.png)

基本的angr脚本不难写，但是我们发现执行起来居然有问题，原因是使用了 `__isoc99_scanf`这一特殊函数。仅凭我们现有的angr的那点可怜知识，怕是解决不了这个问题了。所以我们需要进一步学习angr的奇特操作。

```php
import angr
import claripy
def main():
    proj =angr.Project('./2016baby-re',auto_load_libs=False)
    state= proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
    simgr=proj.factory.simulation_manager(state)
    simgr.explore(find=0x40292c,avoid=0x402941)
```

angr操作进阶：编写自定义函数替代系统函数
----------------------

首先明确一点：编写自定义函数替代系统函数的目的，是为了控制输入，从而方便我们的输出。

可以通过这样的方式，替换函数：

```php
proj.hook_symbol('__isoc99_scanf', my_scanf(), replace=True)
```

这样我们就把`__isoc99_scanf`替换成了我们需要的my\_scanf()函数。我们在保持scanf功能不变的情况下，将我们的符号变量存储进去。下面按照需求编写一下my\_scanf()函数

```php
class my_scanf(angr.sim_procedure):
    def run(self,fmt,ptr):
        self.state.mem[ptr].dword =flag_chars[self.state.globals['scanf_count']]
        self.state.globals['scanf_count']+=1
```

当程序每次调用scanf时，my\_scanf就会将flag\_chars\[i\]存储到self.state.mem\[ptr\]当中，这其中ptr参数，其实是scanf传递进来的rdi。为了控制下标，还设置了一个全局变量scanf\_count.如此一来，只要angr执行到我们想要到达的分支，那么我们就可以通过`solver.eval()`的方式将其打印出来。

好了，万事俱备，只欠东风。

解题代码如下：

```php
import angr
import claripy
def main():
    proj =angr.Project('./2016baby-re',auto_load_libs=False)
    flag_chars =[claripy.BVS('flag_%d' % i,32)for i in range(13)]
    class my_scanf(angr.SimProcedure):
        def run(self, fmt, ptr):
            self.state.mem[ptr].dword = flag_chars[self.state.globals['scanf_count']]
            self.state.globals['scanf_count'] += 1
    proj.hook_symbol('__isoc99_scanf', my_scanf(), replace=True)
    smage=proj.factory.simulation_manager()
    smage.one_active.options.add(angr.options.LAZY_SOLVES)## 取代了什么 可以观察一下
    smage.one_active.globals['scanf_count'] = 0
    smage.explore(find=0x4028E9,avoid=0x402941)
    flag = ''.join(chr(smage.one_found.solver.eval(c)) for c in flag_chars)
    return flag
if __name__ == '__main__':
    print(main())

```

![image-20220226111057250](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-330321bcf3731bf3402cbce4c59c9c94f3975c73.png)

0x02\[2021长安杯\] VP
==================

题目标签：40万规模的op\_code

题目结构并不复杂，就是opcode的体量大了亿点点。当我看到那份40多万字节的opcode的时候，内心是崩溃的。（不得不吐槽一下出题人，真是超大规模数据集的狂热拥簇。长安杯前两个题目让解32元一次方程就算了，这又来一个40万规模的opcode）

定位主要操作函数也是个手艺活，耐心跟进，直到`sub_401840()`。看到了熟悉的while（1）switch结构

![image-20220226130150027](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-79195d5e81f0b7ffa18c5d652e7f9fdb0869700f.png)

做vm题目嘛，最重要的还是分割opcode和分析指令集功能：

指令 作用  
0x01 加法运算

0x02 乘法运算

0x03 除法运算

0x04 异或运算

0x05 与运算

0x06 或运算  
0x09 取值，可看作mov  
0x0a 异或运算  
0x0b 加法运算  
0x0c 乘法运算  
0x0e 异或运算  
0x12 位运算 相当于 &lt;&lt;  
0x13 转移指令  
0x14 转移指令  
0x15 转移指令  
0x16 字符输出，相当于 getchar()  
0x17 字符输入，相当于 putchar()  
0x18 比较指令，相当于 cmp  
0x1b 赋值  
0x1f 条件跳转，不符合直接退出的那种  
0x27 跳转指令，相当于jmp

vm这玩意，显然是没办法静态调试调出来的，一开始进行了大量的赋值和跳转操作，整的跟花指令似的。把前面的赋值和跳转屏蔽掉（有大佬清点了一下大概是八千多个赋值，算上花指令我要点差不多 16000 多次运行。）flag的接受轮次太多了，需要写脚本辅助调试，然而笔者暂时没有这个能力，找到网上一个大佬的unicorn脚本辅助调试。

```php
from ctypes import addressof
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import binascii

vp_base = 0x401000  # 程序加载的地址
vp_opcode_base = 0x405000  # 输入的地址
vp_stack_base = 0x670000

with open("vp_opcode.bin", "rb") as f:
    vp_opcode = f.read()  # 读取 vm 运行所需的 opcode 指令
    f.close()
with open("vp_code.bin", "rb") as f:
    x64_code = f.read()  # 读取 vp.exe 的指令
    f.close()

with open("vp_stack.bin", "rb") as f:
    vp_stack = f.read()  # 从 x64dbg 里面dump出来的现成的栈上的数据
    f.close()

xxx = [b'\x00', b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08', b'\x09', b'\x0a', b'\x0b',
       b'\x0c', b'\x0d', b'\x0e', b'\x0f', b'\x10', b'\x11', b'\x12', b'\x13', b'\x14', b'\x15', b'\x16', b'\x17',
       b'\x18', b'\x19', b'\x1a', b'\x1b', b'\x1c', b'\x1d', b'\x1e', b'\x1f', b'\x20', b'\x21', b'\x22', b'\x23',
       b'\x24', b'\x25', b'\x26', b'\x27', b'\x28', b'\x29', b'\x2a', b'\x2b', b'\x2c', b'\x2d', b'\x2e', b'\x2f',
       b'\x30', b'\x31', b'\x32', b'\x33', b'\x34', b'\x35', b'\x36', b'\x37', b'\x38', b'\x39', b'\x3a', b'\x3b',
       b'\x3c', b'\x3d', b'\x3e', b'\x3f', b'\x40', b'\x41', b'\x42', b'\x43', b'\x44', b'\x45', b'\x46', b'\x47',
       b'\x48', b'\x49', b'\x4a', b'\x4b', b'\x4c', b'\x4d', b'\x4e', b'\x4f', b'\x50', b'\x51', b'\x52', b'\x53',
       b'\x54', b'\x55', b'\x56', b'\x57', b'\x58', b'\x59', b'\x5a', b'\x5b', b'\x5c', b'\x5d', b'\x5e', b'\x5f',
       b'\x60', b'\x61', b'\x62', b'\x63', b'\x64', b'\x65', b'\x66', b'\x67', b'\x68', b'\x69', b'\x6a', b'\x6b',
       b'\x6c', b'\x6d', b'\x6e', b'\x6f', b'\x70', b'\x71', b'\x72', b'\x73', b'\x74', b'\x75', b'\x76', b'\x77',
       b'\x78', b'\x79', b'\x7a', b'\x7b', b'\x7c', b'\x7d']

cmp_list = []
rsi_2_6 = []
rsi_2_5 = []

class Unidbg:

    def __init__(self, flag, except_hit):
        self.except_hit = except_hit
        self.hit = 0
        self.flag = flag
        self.success = False
        self.fff = False
        self.code_hook = True
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        # 程序基址为 0x401000，分配 8 MB内存
        mu.mem_map(0x400000, 0x300000)
        mu.mem_write(vp_base, x64_code)
        # 程序基址为 0x405020，分配 8 MB内存
        # mu.mem_map(vp_opcode_base, 0x63000)
        mu.mem_write(vp_opcode_base, vp_opcode)
        # 程序栈基址为 0x670000，分配 64 KB内存
        # mu.mem_map(vp_stack_base, 0x10000)
        mu.mem_write(vp_stack_base + 0xA000, vp_stack)
        # 设置寄存器的值
        mu.reg_write(UC_X86_REG_RAX, 0x0000C35000000000)
        mu.reg_write(UC_X86_REG_RBX, 0)
        mu.reg_write(UC_X86_REG_RCX, 0x67FDA0)
        mu.reg_write(UC_X86_REG_RDX, 0xB56AE0)
        mu.reg_write(UC_X86_REG_RSI, 0)
        mu.reg_write(UC_X86_REG_RDI, 0)
        mu.reg_write(UC_X86_REG_RBP, 0x67FDF0)
        mu.reg_write(UC_X86_REG_RSP, 0x67FD78)
        mu.reg_write(UC_X86_REG_RIP, 0x401840)

        mu.hook_add(UC_HOOK_CODE, self.hook_function_scanf, begin=0x401C82, end=0x401C9D)
        mu.hook_add(UC_HOOK_CODE, self.hook_function_putchar, begin=0x401C26, end=0x401C1f)
        mu.hook_add(UC_HOOK_CODE, self.hook_code, begin=0x401882, end=0x401884)
        # mu.hook_add(UC_HOOK_CODE, self.trace)
        # mu.hook_add(UC_HOOK_CODE, self.hook_emu_exit, begin=0x401BF9, end=0x401BFC)
        mu.hook_add(UC_HOOK_CODE, self.vp_hook_case18_cmp, begin=0x4019E9, end=0x4019ED)
        # patch putchar()
        mu.mem_write(0x401C2A, b'\x90\x90\x90\x90\x90')
        # patch scanf()

        mu.mem_write(0x401C98, b'\x90\x90\x90\x90\x90')
        self.mu = mu
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)

    def solve(self):
        try:
            self.mu.emu_start(0x401840, 0x402090)
        except:
            pass
        if self.hit > self.except_hit:
            self.success = True
        return self.success

    def trace(self, mu, address, size, data):
        if self.fff == False:
            return
        disasm = self.md.disasm(mu.mem_read(address, size), address)
        for i in disasm:
            print(i)

    def hook_emu_exit(self, mu, address, size, user_data):
        if address == 0x401BF9:
            pass
            # print(self.flag,self.hit)
        pass

    def vp_hook_case18_cmp(self, mu, address, size, user_data):
        if address == 0x4019E9:
            v1 = binascii.b2a_hex(mu.mem_read(0x67FDA0 + 8 + mu.reg_read(UC_X86_REG_RAX) * 4, 4))
            v2 = binascii.b2a_hex(mu.mem_read(0x67FDA0 + 8 + mu.reg_read(UC_X86_REG_RDX) * 4, 4))
            print("cmp ", v1, ",", v2)
            cmp_list.append("cmp " + v1.decode() + "," + v2.decode())
            v3 = binascii.b2a_hex(mu.mem_read(0x67FDC0, 4))
            rsi_2_6.append(v3)
            v4 = binascii.b2a_hex(mu.mem_read(0x67FDC0-4, 4))
            rsi_2_5.append(v4)
        pass

    def hook_function_putchar(self, mu, address, size, user_data):
        if address == 0x401C2A:
            char = mu.reg_read(UC_X86_REG_RCX)
            if char == ord(":"):
                self.code_hook = False
            print(chr(char), end="")
            if char == ord("."):
                pass
                # print("\n",self.flag, self.hit)

    def hook_function_scanf(self, mu, address, size, user_data):
        y = hex(address)
        x = address
        if address == 0x401C98:
            try:
                mu.mem_write(0x67FDA8, xxx[self.flag[self.hit]])
                self.hit += 1
            except UcError as e:
                print(e)
            # print(self.flag, binascii.b2a_hex(self.mu.mem_read(0x67FDA8, 4)))

    def hook_code(self, mu, address, size, user_data):
        code = mu.reg_read(UC_X86_REG_RAX)
        if code != 0x27 and code != 0x15 and self.code_hook != True:
            print("  " + hex(code)[2:])
        #     for s in range(6):
        #         print(hex(0x67FDA0+16*s)[2:].upper(), end=" ")
        #         hex_mem = binascii.b2a_hex(self.mu.mem_read(0x67FDA0+16*s, 16)).decode()
        #         for k in range(0,32,2):
        #             print(hex_mem[k:k+2],end=" ")
        #         print()
        #     print("=================================================================================")
        if code == 0x17:
            print(binascii.b2a_hex(self.mu.mem_read(0x401c98, 32)).decode(), self.hit)
            self.fff = True

flag = b'10' * 64

Unidbg(bytes(flag), 127).solve()

for i in cmp_list:
    print(i)
```

来源：<https://pimouren.blog.csdn.net/article/details/120386650>

作者：pimouren

调试出来的汇编语言翻译成python代码就是

```php
from opcode_s_s_s import num_tab
# num_tab ： 最开始的那一堆数据
right_x7 = 0x18ad2
print(hex(right_x7))
flag = b'11' * 64
x6 = 0
x7 = 0x87
for i in range(128):
    x6 = x6 + i + flag[i] - 48 + 1
    x5 = 0x90
    x5 += x6 * 4
    x4 = num_tab[x5 // 4]
    x7 += x4

print(hex(x7))
if x7 != right_x7:
    exit(0)

```

形象的翻译一下

![image-20220226125844942](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f743fc1d3a2813f0fc20c0e98d250f46ae0c694c.png)

总的来说，就是从最高层0x87开始下山，每一次可以选择向正下方或者向右下方移动，走到最后一层。路径上经过的所有数之和为`0x0x18ad2`

这里尝试使用dfs（深度优先搜索）算法。

先写个小程序预估我们要开多大空间的二维数组

```php
#include<bits/stdc++.h>
using namespace std;
int main()
{
    int sum=0;
    int num=400000;
    int i=1;
    while(num>=sum)
        {
            sum+=i;
            i++;
        }
        printf("%d",i);
        return 0;
}
```

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c032a52a81547e63324cc6e4047faa28ca8ec721.png)

唔，还好，可以接受。

接下来尝试使用dfs算法写出解题脚本  
定义一个搜索函数，设计山高，总和两个参数进行深度优先搜索。

```php
#include<bits/stdc++.h>
using namespace std;
int a[900][900];//代码山 
int flag[900]; 
int high;//代码山的行数 
void dfs(int h,int ans)
{
    if (high>strlen[a])
        return;
    if(high==strlen[a])
        {
            if(ans==0x0x18ad2)
            {
                for(int i=0;i<h;i++)
                    printf("%d",flag[i]);
                    return;
            }
            else return;
        }
        for(int i=0;i<h;i++)
            dfs(h+1,ans+a[h][i]);

}
int main()
{
    dfs(1);
    return 0;
}
```

忙活了半天这个题目还是没有完全复现出来，只搞出来一份c++形式的伪代码。思路wojio的应该没什么问题，就是时间复杂度有点高了。网上也没有更多资料了，可能这种题目对于本菜鸡来讲还是难了一些，有没有哪个老哥会的帮个忙（有大佬提供一个思路，可以用贪心算法降低复杂度）

0x03\[2020网鼎杯玄武组\] \_babyvm
===========================

题目标签:复杂过程的vm逆向

无壳64位，无main函数，start跟进太困难，`shift+f12` 发现 **Tell Me Your Flag** 关键字符串。找到关键函数。

```php
__int64 sub_14007FEF0()
{
  char *v0; // rdi
  __int64 i; // rcx
  char v3[48]; // [rsp+0h] [rbp-20h] BYREF
  char v4[144]; // [rsp+30h] [rbp+10h] BYREF
  char v5[132]; // [rsp+C0h] [rbp+A0h] BYREF
  int v6; // [rsp+144h] [rbp+124h]
  int j; // [rsp+164h] [rbp+144h]
  __int64 v8; // [rsp+188h] [rbp+168h]
  __int64 v9; // [rsp+268h] [rbp+248h]

  v0 = v3;
  for ( i = 162i64; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  sub_140075A41(&unk_1401B5035);
  sub_140076CDE("Tell Me Your Flag:\n");
  sub_14007805C((__int64)&unk_14016D510, (__int64)v4, 50i64);
  dword_1401A3260 = sub_1400804A0(0i64);
  sub_14007584D();
  if ( sub_1400753CF(v4) != 42 )
    goto LABEL_25;
  sub_14007584D();
  if ( v4[0] != 'f'
    || v4[1] != 'l'
    || v4[2] != 'a'
    || v4[3] != 'g'
    || v4[4] != '{'
    || v4[41] != '}'
    || v4[13] != '-'
    || v4[18] != '-'
    || v4[23] != '-'
    || v4[28] != '-' )
  {
    goto LABEL_25;
  }
  sub_14007584D();
  v6 = 0;
  for ( j = 5; j < 41; ++j )
  {
    if ( v4[j] >= 48 && v4[j] <= 57 || v4[j] >= 97 && v4[j] <= 102 )
      v5[v6++] = v4[j];
  }
  sub_14007584D();
  if ( v6 == 32 )
  {
    sub_14007584D();
    v9 = v6;
    if ( (unsigned __int64)v6 >= 0x64 )
      j___report_rangecheckfailure();
    v5[v9] = 0;
    sub_14007584D();
    v8 = sub_1400780D9(v5);
    sub_14007584D();
    if ( (unsigned __int8)sub_140075A78(v8) )
    {
      sub_140076CDE("Right flag!\n");
    }
    else
    {
      sub_14007584D();
      sub_140076CDE("Wrong flag!\n");
      sub_14007584D();
    }
    sub_1400788EF("pause");
  }
  else
  {
LABEL_25:
    sub_140076CDE("No flag for you!\n");
  }
  sub_14007878C(v3, &unk_14016D4E0);
  return 0i64;
}
```

分析关键函数中对v4数组中的处理可以得出flag的格式

flag长度42，uuid格式，并且由0-9，a-f组成，也就是小写16进制数。形如：

```php
flag{12345678-0123-5678-0123-567890123456}
```

接着动调下断点规避检测调试的`ifdebug`函数

查看chkflag函数

![image-20220226134924274](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ba2c785ec60e89baf8c46e46987ca2914d9d7b34.png)

学习了一波大佬的分析，得知该函数的基本逻辑为

```php
1.首先对输入（flag去掉头尾和-之后转换成16进制数之后）进行md5，然后对flag进行某种变换接着对变换结果进行md5。
2.再然后分别取输入（flag去掉头尾和-之后转换成16进制数之后）、输入的md5、输入的变换的md5的依次4个字节转换成整数
3.将上述三个整数进入VM虚拟机进行计算，一共四轮
4.每一轮的计算结果（4字节）和输入的md5的4字节一起存入一个数组，然后和一个全局变量校验
5.返回校验结果，如果相同则通过，输出flag正确
```

接下来就得分析一波vm了。以笔者目前的水平无法完全复现，推荐去看https://blog.csdn.net/Breeze\_CAT/article/details/106373603

使用ida将操作数导出

```php
D0 00 00 00 00 02 01 0D  01 02 04 01 10 00 00 00 
02 01 01 00 00 00 00 02  03 01 01 00 00 00 02 02 
09 01 02 0D 01 02 05 01  08 00 00 00 02 06 14 05 
06 11 04 05 01 B9 79 37  9E 02 05 0C 04 05 0D 04 
03 AD 00 00 00 0C 04 01  02 04 0E 01 03 07 06 19 
00 00 00 D0 01 00 00 00  D0 02 00 00 00 02 02 02 
03 0D 04 02 05 10 05 02  10 05 03 0D 05 0D 04 02 
05 0F 05 02 0F 05 03 0D  05 0D 04 02 05 0F 05 02 
0D 05 0D 04 02 05 0F 05  03 0D 05 0D 02 02 05 0F 
05 03 02 06 0C 05 06 02  06 0C 05 06 02 06 0C 05 
06 02 06 0C 05 06 0D 05  02 01 13 01 FF 00 08 00 
00 00 01 01 03 00 00 00  02 02 08 01 02 E0 08 00 
00 00 01 00 09 00 00 00  02 01 06 00 00 00 02 03 
12 02 03 E0 09 00 00 00  02 04 00 00 00 00 00 00 
90 36 D8 C5 CC 02 79 1F  EA 62 81 97 15 3D AE 2F 
6C A9 32 19 91 FE EB CE  69 26 22 04 42 AF F6 AF 
```

分析的opcode表如下

```php
opcode:
00 xx 00 00 00 0x: 把栈偏移xx mov 给0x寄存器
E0 xx 00 00 00 0x: 把第x个寄存器mov到栈偏移xx处
01 xx xx xx xx：push xxxxxxxx 立即数
0d 0x : push xreg
02 0x : pop reg0x
03 AD 00 00 00 0C 04 01: call AD
04 : 返回
06 19 00 00 00 : jmp 19
07 : falg=~flag
08 0x 0y : 加法运算
09 0x 0y : 减法运算
0c 0x 0y : 异或
0f 0x 0y : 与
10 0x 0y : 或
11 0x 0y : regx 循环右移regy位
12 0x 0y : regx 循环左移regy位
13 0x : 对 0x寄存器中的内容取反
14 0x 0y : 取余数运算
D0 0x 00 00 00 : 缓冲区 第x部分（输入）拿到栈上
ff : 退出
```

整理一下虚拟机的操作翻译成c++就是

```php
#include<bits/stdc++.h>
using namespace std;
int main()
{
int num,num2,num3,input1,input2,input3,newnum;
num=input1;
num2=input2;
num3=input3;
for(i=0;i<=16;i++)
{
    x=(15-i)%8;
    num=((temp>>x)&0xffffffff|(num<<(32-x))&0xffffffff)&0xffffffff;
    num=num^0x9e3779b9;
    num=((num<<6)&0xffffffff|(num>>(32-6))&0xffffffff)&0xffffffff;
}
newnum=(num3&num2)^(num & num2)^(num & num3)^(num & num3& num2)^(num | num3| num2);
newnum=newnum^0xffffffff;
}
```

对代码的理解：input1 input2 input3分别是输入的flag转换成16进制之后的4个字节、flag的md5转换成16进制的4个字节和flag变换后md5后的4个字节。接着对输入的这三个内容进行了一些列的逻辑运算，然后得到的结果（newtemp6）就是要返回去对比的。

但是由于逻辑运算的复杂性，这题的脚本我写不出来，这里只能呈上大佬的脚本，具体解题思路见大佬博客https://blog.csdn.net/Breeze\_CAT/article/details/106373603

```php
import hashlib
import binascii

result=[0xC5D83690, 0x1F7902CC, 0x978162EA, 0x2FAE3D15, 0x1932A96C,0xCEEBFE91, 0x04222669, 0xAFF6AF42] #结果数组
flagmd5='9036d8c5ea6281976ca9321969262204'  #flag的md5
vmRetable={
        "111":"1",
        "100":"1",
        "010":"1",
        "001":"1",
        "110":"0",
        "101":"0",
        "011":"0",
        "000":"0"
}

def transform(input):   #变换函数
    output=""
    for k in range(100):
        a=0
        input^=0xC3
        output+=chr(input&0xff)
        for j in range(8):
            a^=((input&0xff)>>j)&1
        input=(a|2*input)&0xff
    m = hashlib.md5()
    m.update(output)
    output=m.hexdigest()
    return output

def getinputbit(a,b,c):   #查表复原最后胡的逻辑运算
    return vmRetable[a+b+c]

def movere(temp):         #复原逻辑运算前的循环位移
    i=15
    while i>=0:
        x=(15-i)%8
        temp=((temp>>6)&0xffffffff|(temp<<(32-6))&0xffffffff)&0xffffffff
        temp=temp^0x9e3779b9
        temp=((temp<<x)&0xffffffff|(temp>>(32-x))&0xffffffff)&0xffffffff
        i-=1
    return temp    
def big2small(data):   #大小端转换
    return binascii.hexlify(binascii.unhexlify(data)[::-1])

for i in range(0x64):   #循环生成变换内容
    transoutput=transform(i)
    flag=""
    for i in range(4):
        md5bin=bin(int(result[2*i]))[2:].rjust(32,'0')
        transbin=bin(int(big2small(transoutput[8*i:8*i+8]),16))[2:].rjust(32,'0')
        resultbin=bin(result[2*i+1]^0xffffffff)[2:].rjust(32,'0')
        flagbin=""  #先将三个输入转换成二进制
        for j in range(32):  #对二进制内容查表复原flag的位移后二进制形式
            flagbin+=getinputbit(md5bin[j],transbin[j],resultbin[j])
        flagtemp=movere(int(flagbin,2))   #复原flag的一部分
        flagpart=""
        for j in range(4):  #将flag从整型转换成字符串型（好md5）
            flagpart+=chr((flagtemp>>(j*8))&0xff)
        flag+=flagpart

    m = hashlib.md5()
    m.update(flag)
    flagmd5_=m.hexdigest()  #对flag求md5

    flagstr="flag{"
    if(flagmd5_==flagmd5):  #如果和真flag的md5相同则计算正确，输出
        for i in range(len(flag)):
            if(i==4 or i==6 or i==8 or i==10):
                flagstr+='-'
            flagstr+=hex(ord(flag[i]))[2:].rjust(2,'0')
        flagstr+='}'
        print flagstr
```

原文链接：[https://blog.csdn.net/Breeze\_CAT/article/details/106373603](https://blog.csdn.net/Breeze_CAT/article/details/106373603)

作者：[breezeO\_o](https://blog.csdn.net/Breeze_CAT)

0x04后记
======

这是笔者vmre系列学习的第四篇文章，用这篇文章给笔者的vmre学习之路暂时画上一个不完美的句号。这篇文章选择的三个题目，可以说都具有相当的难度，说实在的，以笔者目前的水平能够完整复现的，只有第一道。

通过做这些较难的题目，虽然没有拿到flag，笔者同样获益匪浅，学到了很多新的知识点，同时，也发现了自己re知识体系的许多欠缺，接下来，是该总结经验，补足短板的时间了。

VMRE 江湖路远，我们有缘再见。

0x05参考文章
========

<https://xz.aliyun.com/t/4137#toc-1>

<https://pimouren.blog.csdn.net/article/details/120386650>

[https://blog.csdn.net/Breeze\_CAT/article/details/106373603](https://blog.csdn.net/Breeze_CAT/article/details/106373603)

[http://www.yxfzedu.com/rs\_show/243](http://www.yxfzedu.com/rs_show/243)