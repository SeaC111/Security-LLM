> Everyone want to debug me，why not debug myself?

0x00 技术原理
=========

父进程创建并调试子进程，父子进程大多为同一可执行程序，并且通过 IsDebuggerPresent等检测调试的技术来使父子进程执行不同代码。这一特征类似fork，但因为父子进程是调试和被调试的关系，所以子进程无法直接attach调试，然而真正的逻辑往往都在修改后的子进程，故拿到真正的逻辑有一定的难度，DebugBlocker技术是比较硬核的一种反调试技术。

该类技术和SMC技术以及异常处理机制形影不离，其中父进程负责恢复控制流和程序代码，子进程则执行真正的程序代码。

0x01 常用API和结构体
==============

1、CreateProcessA

创建新进程及其主线程

```c
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);

typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;  //新进程的句柄
  HANDLE hThread;   //新建进程的主线程的句柄
  DWORD  dwProcessId; //PID
  DWORD  dwThreadId;  //TID
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
```

其中最重要的是`dwCreationFlags`标志位，其值表示着进程创建标志，各个值可通过或随机组合。

| 常量 | **值** | 意义 |
|---|---|---|
| DEBUG\_PROCESS | 0x00000001 | 启动并调试新进程，可使用 WaitForDebugEvent接受相关调试事件 |
| DEBUG\_ONLY\_THIS\_PROCESS | 0x00000002 | 如果和DEBUG\_PROCESS同时选择，则调用方只能调试该新进程 |

更多详见[进程创建标志 （WinBase.h） - Win32 应用|微软文档 (microsoft.com)](https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)，上述两个标志值为最基础的设置调试关系，即`dwCreationFlags`的值为1或3时。

2、WaitForDebugEvent

等待调试进程中的调试事件

```c
BOOL WaitForDebugEvent(
  [out] LPDEBUG_EVENT lpDebugEvent,
  [in]  DWORD         dwMilliseconds
);
```

其中要了解`DEBUG_EVENT`结构体

```c
typedef struct _DEBUG_EVENT {
  DWORD dwDebugEventCode;
  DWORD dwProcessId;
  DWORD dwThreadId;
  union {
    EXCEPTION_DEBUG_INFO      Exception;
    ...
  } u;
} DEBUG_EVENT, *LPDEBUG_EVENT;
```

`dwDebugEventCode`标识调试事件的类型，主要关注其中的异常事件和进程退出事件。

![image-20220708231704101](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e07ebdb6015c03fe8e2ea8791c226350d2012afa.png)

对于异常则关注 u.Exception.ExceptionRecord结构体

```c
typedef struct _EXCEPTION_RECORD {
  DWORD                    ExceptionCode;
  DWORD                    ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID                    ExceptionAddress;
  DWORD                    NumberParameters;
  ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD;
```

需要了解一些常见的异常类型及其值

![image-20220708232909026](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1469b1357842b01d57d7863ea867fbfad1a7db58.png)

一般题目中常以**int3断点**触发**0x80000003**异常，或**访问未分配(不合理)的地址**触发**0xc0000005**异常。

3、Get/Set Context

获取或设置指定线程的上下文

```c
BOOL GetThreadContext(
  [in]      HANDLE    hThread, //线程句柄
  [in, out] LPCONTEXT lpContext //上下文结构指针
);

BOOL SetThreadContext( 
HANDLE hThread, 
CONST CONTEXT * lpContext );
```

**而上下文主要是指寄存器上下文，往往会修改ip的值来修改控制流走向。**

4、Read/Write ProcessMemory

向指定的进程中写入内存，要写入的区域必须有写权限。

> 这里并不是多个进程实现了共享内存，而是对指定进程的某地址进行了读和写。

```c
BOOL WriteProcessMemory( 
HANDLE hProcess,      //进程句柄
LPVOID lpBaseAddress, //基址的指针
LPVOID lpBuffer,      //要写入数据的指针
DWORD nSize,          //写入的字节数
LPDWORD lpNumberOfBytesWritten );

BOOL ReadProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPCVOID lpBaseAddress,//读取内存的基址
  [out] LPVOID  lpBuffer,     //存放读出数据的缓冲区
  [in]  SIZE_T  nSize,        //读取字节数
  [out] SIZE_T  *lpNumberOfBytesRead
);
```

5、ContinueDebugEvent

调试器继续调试新进程

```c
BOOL ContinueDebugEvent(
  [in] DWORD dwProcessId, //继续调试的PID
  [in] DWORD dwThreadId,  //继续调试的TID
  [in] DWORD dwContinueStatus //继续调试事件的选项
);
```

`dwContinueStatus`一般为`DBG_CONTINUE`常量(0x10002),表示异常已经得到处理，继续执行。

0x02 例题解析
=========

接下来通过分析2022鹏城杯的BUG之眼来进一步了解该技术，此题由父-&gt;子-&gt;孙子，修改完的逻辑在孙子进程中，并且是将主体代码分成了多块，边执行边修改，很好的隐藏了逻辑代码和控制流。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  if ( IsDebuggerPresent() )
    sub_1400024B0();
  else
    sub_140002D50();
  return 0;
}
```

main函数中通过`IsDebuggerPresent`函数来区分执行代码，当为被调试身份时执行if块语句，不处于调试器状态即最开始的进程执行else语句块。

else块函数
-------

![image-20220709234217738](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-26d383017765af5dae4092e9d10a5d6c74756855.png)

首先是获取当前文件路径，并且调用`CreateProcessA`创建新进程，并且`dwCreationFlags`的值为1，即启动并调试新进程。

![image-20220709234637069](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-efb8bbea92719927b7673c408ab48dafc32b8c15.png)

随后启动`WaitForDebugEvent`来等待调试事件，主要关注`dwDebugEventCode`为1时，即收到了调试进程的异常事件。

0x80000003是遇到的int3断点(0xcc)，并通过异常相关结构体获取异常地址，`GetThreadContext`获取主线程的rip回退到异常触发的哪一个字节，并用WriteProcessMemory将0xcc替换为0xc3即ret指令。

![image-20220709235713044](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ebe78648a1a88f191c2c410082375eecab32c85c.png)

之后是将主线程的enc\_data处的数据读入v9，v15是enc\_data的地址转为10进制字符，5368733776(0x140006050)。之后按照其长度为一组进行逐字节异或，解密出的数据再写回新建进程，通过`ContinueDebugEvent`通知调试器继续调试。

> 可见父进程的工作即捕获异常点，处理异常并解密子进程相关的数据(SMC)。

if块函数
-----

if块则主要是由被调试进程即子进程执行的代码。

![image-20220710000904319](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-d8d3b881ec922372b2819f91b5f9d91bb74f2766.png)

该块首部的代码类似else块，但是通过像内存中写入0xcc，之后以函数方式调用来触发异常，使父进程捕获并修改其相关数据，即enc\_data。同时0xcc的值修改为0xc3(ret)，并继续执行，会继续启动并调试一个新进程(孙子)。

> 对于孙子进程，父进程已经对enc\_data进行了修改，所以孙子进程的enc\_data是与子进程修改后的相同。

![image-20220710001214110](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3b99509671c250b849bae1a699b37c8f31d6b337.png)

这里针对异常事件也有了两种处理，第一种是`0x141000000`地址触发的0xcc，另一种则是低地址触发的处理。当孙子进程第一次在`0x141000000`触发异常后，子进程会将其的eip改为`0x140001330`并继续执行。

![image-20220710001952167](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-15b56227d90007857b4a99c1dbf37573c6efa222.png)

即在`0x140001330`执行中再出现异常则会执行该步处理，这里需要先获得修改后的enc\_data，可以通过调试或idapy获取。

![image-20220710002057845](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-72b65f4559f3a7b3f0886fedaf59411a3bc0de2c.png)

而修改后的`0x140001330`处的数据中有着许多0xcc会引发异常进而调用子进程进行处理。

![image-20220710002253452](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7ec1dfebbd8925c1bc3d6b8b3807f42a730a1e37.png)

再结合解密后的enc，可知enc\_data\[0\]表示发生异常处距离`0x140001330`的偏移，enc*data\[1\]表示这一个块的大小，而enc*\[2\]用于修复0xcc。

> 例如enc\_data\[3\] = 0x5f 可以计算 0x140001330 + 0x5f = 0x0x14000138f ，查看改地址处的字节为0xcc。这样通过enc\_data来记录每次修改的代码块，边运行边中断，这样更能阻止逆向分析人员的动态调试。

![image-20220710003220139](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f4f424c40b3943ab712d025599729e9fc1716ed4.png)

好在每段的解密逻辑一致且与父进程解密enc\_data相同，由上述分析知采用动态调试的手段很难拿到修改后的代码，所以这里采取手动修复，使用ipy脚本。

```python
import idautils
enc_data=[0x0000000000000000, 0x000000000000005F, 0x000000000000008C, 0x000000000000005F, 0x000000000000001E, 0x0000000000000084 ...]
start=0x140001330
for p in range(0,len(enc_data),3):
    offset=enc_data[p] #异常地址偏移
    size=enc_data[p+1] #代码块大小
    tmp=enc_data[p+2]  #首字节恢复 
    adr=start+offset
    k=list(str(adr+1))
    PatchByte(adr,Byte(adr)^tmp)

    for i in range(1,size): #修复代码块大小
        t=Byte(adr+i)
        PatchByte(adr+i,t^ord(k[(i-1)%len(k)]))
        if i%len(k)==0:
            k = list(str(adr+i))
print('ok')  
```

> enc\_data可以通过调试获取，或者采取ipy来进行patch。

修复后的`0x140001330`函数如下

![image-20220710003817249](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-b0ad813e7a9d650324917c30c8eb0301548ecf3f.png)

这与实际运行时程序的输出一致，故经过父-&gt;子-&gt;孙的修复，程序已经恢复原有的逻辑。

![image-20220710003909002](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9c29d63fb2b90399db9c3b98b94716054c85e6a1.png)

可以通过process explore来查看调用链。

![image-20220710004049299](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c4381e7b9536df1ad64bf81b9a8e0accb227bbed.png)

0x03 总结
=======

本文主要是对DebugBlocker反调试技术的研究，更多的解密细节不再展开。另外，我们是否能找到合适的patch点，让孙子进程再CreateProcess，并且不设置调试的运行关系，通过调试器attch来拿到解密后的代码。或者是通过API来使子进程退出调试状态或许也能达到预期的效果。