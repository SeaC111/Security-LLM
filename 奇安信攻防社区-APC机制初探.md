0x01 本质
=======

`APC`（Asynchronous Procedure Call 异步过程调用）是一种可以在 Windows 中使用的机制，用于将要在特定线程上下文中完成的作业排队。

线程是不能被“杀掉”、“挂起”、“恢复”的，线程在执行的时候自己占据着CPU,别人怎么可能控制它呢？

举个极端的例子：如果不调用API,屏蔽中断,并保证代码不出现异常，线程将永久占用CPU，何谈控制呢?所以说线程如果想“死”，一定是自己执行代码把自己杀死，不存在“他杀”这种情况！

那如果想改变一个线程的行为该怎么办呢?

可以给他提供一个函数，让它自己去调用，这个函数就是APC(Asyncroneus Procedure Call)，即异步过程调用。

APC队列
-----

```c++
kd> dt _KTHREAD

nt!_KTHREAD

 ...

   +0x034 ApcState     : _KAPC_STATE

 ...

kd> dt _KAPC_STATE

nt!_KAPC_STATE

  +0x000 ApcListHead //2个APC队列 用户APC和内核APC

  +0x010 Process //线程所属或者所挂靠的进程

  +0x014 KernelApcInProgress //内核APC是否正在执行

  +0x015 KernelApcPending //是否有正在等待执行的内核APC

  +0x016 UserApcPending //是否有正在等待执行的用户APC

用户APC：APC函数地址位于用户空间，在用户空间执行

内核APC：APC函数地址位于内核空间，在内核空间执行
```

`NormalRoutine`会找到你提供的APC函数，并不完全等于APC函数的地址。

![image-20220322151711667.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0789bee8642468cadbf7a6941f09598544d0d7a1.png)

APC函数何时被执行?

KiServiceExit函数：

这个函数是系统调用、异常或中断返回用户空间的必经之路。

KiDeliverApc函数：

负责执行APC函数

逆向TerminateThread/ResumeThread
------------------------------

![image-20220324185923118.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2850e00bb6995f607f65f981f248905fbc87a472.png)

![image-20220324190034227.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-dba803a7c845e4ac3b36b3a89d88281b68e7b6a8.png)

![image-20220324190229563.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1018069dc2fd0e2d2700886c3c4d89e4cce2c705.png)

自己实现APC队列的插入，在3环调用`QueueUserAPC`

```c++
// APC1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

DWORD WINAPI MyThread(LPVOID)
{
    int i = 0;

    while (true)
    {
        SleepEx(300, TRUE);
        printf("%d\n", i++);
    }
}

void __stdcall MyApcFunction(LPVOID)
{
    printf("Run APCFuntion\n");

    printf("APCFunction done\n");
}

int main(int argc, char* argv[])
{
    HANDLE hThread = CreateThread(0, 0, MyThread, 0, 0, 0);

    Sleep(1000);
    if (!QueueUserAPC((PAPCFUNC)MyApcFunction, hThread, NULL))
    {
        printf("QueueUserAPC error : %d\n", GetLastError());
    }
    getchar();
    return 0;
}
```

![image-20220324193323947.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e65f94ea63246bed7fc746b752b046bc5562afa7.png)

![image-20220325201254684.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-371fae1fe3b469dac432b9451a7714b82615a784.png)

QueueUserApc
------------

通过**3环的QueueUserApc函数可以完成将APC插入到队列的操作**，首先调用了`ntdll.dll`的`NtQueueApcThread`

![image-20220324195957194.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-132589b67e1cfb8a7665da3101e40170f0f04728.png)

![image-20220324200008288.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-364c3ac9081c861637ed490a5e7f91b0318f8841.png)

然后通过`0xB4`的调用号进入ring0

![image-20220324200046930.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a515ad693fb13a33588572d3c479cc0c4b3d5877.png)

在windbg里面对应的内核函数为`NtQueueApcThread`

![image-20220324200253019.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e23e0406947cc6796ae1b02e4bb3f7b8ca3ec5d3.png)

然后在`ntosknl.exe`里面定位到`NtQueueApcThread`

![image-20220324200735122.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-96a28f47e15ad88803b8f2d23082671e78deee8e.png)

最后是调用`KeInitializeApc`和`KeInsertQueueApc`这两个函数来实现APC的效果

![image-20220324200751146.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b73fd6983d6707898dfd5c1d468be8dfdb3afa53.png)

0x02备用APC
=========

备用APC里面有几个重要的成员

```c++
kd> dt _KTHREAD
nt!_KTHREAD
   ...
   +0x034 ApcState         : _KAPC_STATE
   ...
   +0x138 ApcStatePointer  : [2] Ptr32 _KAPC_STATE
  ...
   +0x14c SavedApcState    : _KAPC_STATE
  ...
   +0x165 ApcStateIndex    : UChar
   +0x166 ApcQueueable     : UChar
```

**SavedApcState**
-----------------

线程APC队列中的APC函数都是与进程相关联的，具体点说：A进程的T线程中的所有APC函数，要访问的内存地址都是A进程的。

但线程是可以挂靠到其他的进程：比如A进程的线程T，通过修改Cr3(改为B进程的页目录基址)，就可以访问B进程地址空间，即所谓“进程挂靠”。

当T线程挂靠B进程后，APC队列中存储的却仍然是原来的APC，具体点说，比如某个APC函数要读取一个地址为0x12345678的数据，如果此时进行读取，读到的将是B进程的地址空间，这样逻辑就错误了

为了避免混乱，在T线程挂靠B进程时，会将`ApcState`中的值暂时存储到`SavedApcState`中，等回到原进程A时，再将APC队列恢复。

所以，`SavedApcState`又称为备用APC队列。

**挂靠环境下ApcState的意义**
--------------------

在挂靠的环境下，也是可以向线程APC队列插入APC的，那这种情况下，使用的是哪个APC队列呢？

A进程的T线程挂靠B进程，A是T的所属进程，B是T的挂靠进程

> ApcState B进程相关的APC函数
> 
> SavedApcState A进程相关的APC函数

在正常情况下，当前进程就是所属进程A，如果是挂靠情况下，当前进程就是挂靠进程B。

ApcStatePointer
---------------

为了操作方便，`_KTHREAD`结构体中定义了一个指针数组`ApcStatePointer`，长度为2。

正常情况下：

ApcStatePointer\[0\] 指向 ApcState

ApcStatePointer\[1\] 指向 SavedApcState

挂靠情况下：

ApcStatePointer\[0\] 指向 SavedApcState

ApcStatePointer\[1\] 指向 ApcState

**ApcStateIndex**
-----------------

用来标识当前线程处于什么状态

0 正常状态 1 挂靠状态

**ApcStatePointer 与 ApcStateIndex组合寻址**
---------------------------------------

正常情况下，向ApcState队列中插入APC时：

- ApcStatePointer\[0\] 指向 ApcState 此时 ApcStateIndex 的值为0
- ApcStatePointer\[ApcStateIndex\] 指向 ApcState

挂靠情况下，向ApcState队列中插入APC时：

- ApcStatePointer\[1\] 指向 ApcState 此时 ApcStateIndex 的值为1
- ApcStatePointer\[ApcStateIndex\] 指向 ApcState

总结：

​ 无论什么环境下，ApcStatePointer\[ApcStateIndex\] 指向的都是ApcState，ApcState则总是表示线程当前使用的apc状态

0x03 APC挂入
==========

无论是正常状态还是挂靠状态，都有两个APC队列，一个内核队列，一个用户队列。

每当要挂入一个APC函数时，不管是内核APC还是用户APC，内核都要准备一个KAPC的数据结构，并且将这个KAPC结构挂到相应的APC队列中。

KAPC
----

```c++
kd> dt _KAPC
nt!_KAPC
   +0x000 Type      //类型  APC类型为0x12
   +0x002 Size      //本结构体的大小  0x30
   +0x004 Spare0        //未使用                             
   +0x008 Thread        //目标线程                                  
   +0x00c ApcListEntry  //APC队列挂的位置
   +0x014 KernelRoutine //指向一个函数(调用ExFreePoolWithTag 释放APC)
   +0x018 RundownRoutine//略 
   +0x01c NormalRoutine //用户APC总入口  或者 真正的内核apc函数
   +0x020 NormalContext //内核APC：NULL  用户APC：真正的APC函数
   +0x024 SystemArgument1//APC函数的参数 
   +0x028 SystemArgument2//APC函数的参数
   +0x02c ApcStateIndex //挂哪个队列，有四个值：0 1 2 3
   +0x02d ApcMode   //内核APC 用户APC
   +0x02e Inserted  //表示本apc是否已挂入队列 挂入前：0  挂入后  1
```

挂入流程

![image-20220325160508879.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-236fb912117a5c7fc0bc72e670c56094648bfd5d.png)

KeInitializeApc(APC初始化)
-----------------------

```c++
VOID KeInitializeApc
(
IN PKAPC Apc,//KAPC指针
IN PKTHREAD Thread,//目标线程
IN KAPC_ENVIRONMENT TargetEnvironment,//0 1 2 3四种状态
IN PKKERNEL_ROUTINE KernelRoutine,//销毁KAPC的函数地址
IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
IN PKNORMAL_ROUTINE NormalRoutine,//用户APC总入口或者内核apc函数
IN KPROCESSOR_MODE Mode,//要插入用户apc队列还是内核apc队列
IN PVOID Context//内核APC：NULL  用户APC：真正的APC函数
) 
```

主要看`TargetEnvironment`这个参数，对应的是`ApcStateIndex`，与`KTHREAD(+0x165)`的属性同名，但含义不一样

```c++
ApcStateIndex 有四个值：
0 原始环境 1 挂靠环境 2 当前环境 3 插入APC时的当前环境

正常情况下：
    ApcStatePointer[0]  指向 ApcState    
    ApcStatePointer[1]  指向 SavedApcState
挂靠情况下：
    ApcStatePointer[0]  指向 SavedApcState
    ApcStatePointer[1]  指向 ApcState    

2 初始化的时候，当前进程的ApcState

3 插入的时候，当前进程的ApcState    
```

当传入值为2时，会直接使用当前进程的ApcState

![image-20220325161244201.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cb83b80f3eaedb6c72c6d283005fc12259218bea.png)

![image-20220326105729996.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-21a2777a758bc09bb1edbd1ee4bb893644d2b646.png)

当传入值为3时，使用的是当前进程的APC，那么这里跟2有什么区别呢？

当初始化的时候可能处于原始环境，也可能处于挂靠环境，在即将插入的那个时候可能环境发生了改变，所以传入值设置为3

伪代码分析

![867232_HDZTASGTZ4TRJ7U.jpg](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-539d4a9d37b586b73f9f33365c4a3e892130b8a9.jpg)

KiInsertQueueApc(插入APC队列)
-------------------------

```c++
1) 根据KAPC结构中的ApcStateIndex找到对应的APC队列

2) 再根据KAPC结构中的ApcMode确定是用户队列还是内核队列

3) 将KAPC挂到对应的队列中(挂到KAPC的ApcListEntry处)

4) 再根据KAPC结构中的Inserted置1，标识当前的KAPC为已插入状态

5) 修改KAPC_STATE结构中的KernelApcPending/UserApcPending
```

1、Alertable=0 当前插入的APC函数未必有机会执行：UserApcPending = 0

2、Alertable=1 UserApcPending = 1 将目标线程唤醒(从等待链表中摘出来，并挂到调度链表)

`KeInsertQueueApc`源码

```c++
NTKERNELAPI
BOOLEAN
KeInsertQueueApc (
    __inout PRKAPC Apc,
    __in_opt PVOID SystemArgument1,
    __in_opt PVOID SystemArgument2,
    __in KPRIORITY Increment    //优先级，3环添加用户APC时默认为0.
);
/*++

Routine Description:

    This function inserts an APC object into the APC queue specifed by the
    thread and processor mode fields of the APC object. If the APC object
    is already in an APC queue or APC queuing is disabled, then no operation
    is performed. Otherwise the APC object is inserted in the specified queue
    and appropriate scheduling decisions are made.

Arguments:

    Apc - Supplies a pointer to a control object of type APC.

    SystemArgument1, SystemArgument2 - Supply a set of two arguments that
        contain untyped data provided by the executive.

    Increment - Supplies the priority increment that is to be applied if
        queuing the APC causes a thread wait to be satisfied.

Return Value:

    If the APC object is already in an APC queue or APC queuing is disabled,
    then a value of FALSE is returned. Otherwise a value of TRUE is returned.

--*/
```

![867232_44BYGK47URRVQE5.jpg](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-68f565ffb06e1d3d7ce09c26f0a633942d9eb521.jpg)

首先根据之前传入的Enviroment来判断要取哪个`_KPAC_STATE`成员

![867232_VFR95WB4ZKW6E7W.jpg](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-283c3116dda964c829dc045673ee1ef38f036607.jpg)

选择完`_KPAC_STATE`后，判断`ApcMode`与`NormalRoutine`决定插入到哪个链表中。经分析得知，用户APC回调存在`NormalRoutine`中，但`KernelRoutine`会存一个名为`PsExitSpecialApc`的特殊APC回调（用于释放当前APC内存空间）。

![867232_8KQYZEPCSBR952Z.jpg](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9af20434bc3ba79be5e6b169f473c662120bb26c.jpg)

如果当前`APC`插入到了备用`APC`队列（`SavedApcState`）中就返回。如果插入的是`ApcState`队列中就继续判断这个APC是自身插入还是其他线程插入的

![867232_CRYSHA9MJKHAPVF.jpg](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-151d64333a4d74d665797302a038479e1ebcb4eb.jpg)

如果是插入到其他线程的APC并且是个用户APC

![867232_SCREVH7F6EZE7C9.jpg](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7f548c03ab4a38680e3ec3c3190d964b6bb49841.jpg)

如果这个APC是内核APC并且是插入到其他线程的

![867232_PDRRNYTU7CABV4M.jpg](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-38927226d78f9803afeb1d9697fed77980554a10.jpg)

APC的插入位置与传入的`Enviroment`函数相关。如果是插入到了备用APC队列中则执行返回。若是普通APC队列中则继续进行多个判断。

- 当这个APC是自身线程插入给自身的，并且是个特殊内核APC，则会立马触发软中断执行。
- 如果这个APC是当前线程插入给其他线程的，且是个用户APC。当APC所属线程处于等待时，会尝试唤醒线程来执行APC。如果不是等待状态，则`UserOrNormalKernel`默认为0，插入后不执行APC。
- 如果这个APC是当前线程插入给其他线程的，且是个内核APC。当APC所属线程处于运行时，会直接触发软中断执行APC或通知其他核触发软中断执行。当APC所属线程处于等待时，会尝试唤醒线程来执行APC。其他状态则不会立马执行APC。