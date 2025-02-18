0x00 前言
=======

我们在之前已经了解了VEH和SEH异常，在这里我们来深入探究一下编译器为我们提供的`_try_except`和`_try_finally`的原理实现。

0x01 \_try\_except原理
====================

![image-20220329091038461.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-73cfdfd71d9b1fd2810a643fd04c56069a5cf891.png)

调用`_except_handle3`这个异常处理函数，这里并不是每个编译器的异常处理函数都是相同的，然后存入结构体，将esp的值赋给`fs:[0]`，再就是提升堆栈的操作

![image-20220328203820634.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bb9beb697d58c0904780a04e8f0e39ae9d49ee48.png)

每个使用 `_try _except`的函数，不管其内部嵌套或反复使用多少`_try _except`，都只注册一遍，即只将一个 `_EXCEPTION_REGISTRATION_RECORD`挂入当前线程的异常链表中(对于递归函数，每一次调用都会创建一个 `_EXCEPTION_REGISTRATION_RECORD`，并挂入线程的异常链表中)。

```c++
typedef struct _EXCEPTION_REGISTRATION_RECORD {

    struct _EXCEPTION_REGISTRATION_RECORD *Next;

    PEXCEPTION_ROUTINE Handler;

  } EXCEPTION_REGISTRATION_RECORD;
```

可以看到只有一个异常处理函数

![image-20220328204334138.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-546576b9e217c967b7e969f07d99a5228637dc8a.png)

那么这里编译器是如何做到只用一个异常处理函数的呢？编译器把原来`_EXCEPTION_REGISTRATION_RECORD`结构进行了拓展，添加了三个成员

```c++
struct _EXCEPTION_REGISTRATION{
        struct _EXCEPTION_REGISTRATION *prev;
        void (*handler)(PEXCEPTION_RECORD, PEXCEPTION_REGISTRATION, PCONTEXT, PEXCEPTION_RECORD);
        struct scopetable_entry *scopetable;
        int trylevel;
        int _ebp;
    };       
```

新堆栈结构如下  
![image-20220328205626354.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1ffdaac2d737ead2f57d7f327b121bd7b100f540.png)

scopetable
----------

```c++
struct scopetable_entry
{
       DWORD    previousTryLevel        //上一个try{}结构编号 
       PDWRD        lpfnFilter              //过滤函数的起始地址
       PDWRD        lpfnHandler         //异常处理程序的地址     
}
```

查看地址可以发现有三个结构体

![image-20220328210620793.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a56aa035c6f37e6e1bd2580bd1ab07e66c4ef757.png)

存储着的正式异常函数的开始地址和结束地址

![image-20220328210921516.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ca5dc13285c8367a7c8e08d2f63d9133018590ed.png)

第一个值`previousTryLevel`是上一个`try`结构的编号，这里如果在最外层就是-1，如果在第二层就是0，如果在第三层就是1，以此类推

![image-20220328211441617.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a3760788ab14f48b1574324bd85d5a2c8d6b26c7.png)

![image-20220328211431096.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2d6c3104ae88f5fb2b10169f158eaabdf26a2702.png)

trylevel
--------

该成员表示代码运行到了哪个`try`结构里面，进入一个`try`则加1，`try`结构执行完成之后则减1

![image-20220328212928168.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8aa376ecdd470afb97762ec7657688588ab5df38.png)

![image-20220328213102558.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f48c5c15b22570d078cb3bb493145a68eb66fe62.png)

\_except\_handler3
------------------

1.CPU检测到异常 -&gt; 查中断表执行处理函数 -&gt; `CommonDispatchException` -&gt; `KiDispatchException` -&gt; `KiUserExceptionDispatcher` -&gt; `RtlDispatchException` -&gt;`VEH` -&gt; `SEH`

2.执行`_except_handler3`函数

&lt;1&gt; 根据`trylevel`选择`scopetable`数组

&lt;2&gt; 调用`scopetable`数组中对应的`lpfnFilter`函数

> 1.EXCEPTION\_EXECUTE\_HANDLER(1) 执行except代码
> 
> 2.EXCEPTION\_CONTINUE\_SEARCH(0) 寻找下一个
> 
> 3.EXCEPTION\_CONTINUE\_EXECUTION(-1) 重新执行

&lt;3&gt; 如果`lpfnFilter`函数返回0 向上遍历 直到`previousTryLevel=-1`

假设有两个异常点

![image-20220328214631447.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0334eea907dfa825877b5b1f1149b27f729202c7.png)

首先找到`trylevel`为0

![image-20220328214712048.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ab0d73cfc644b2e719c71b5f359fae87dfb2567f.png)

然后找到异常过滤表达式为1

![image-20220328214828859.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4c807cc4734c6b1590149a0deebb24ce9c45a3b4.png)

然后遍历数组的`lpfnFilter`

![image-20220328214920905.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e963342501c69dc120edc3eb72f3fe19d6e88411.png)

![image-20220328215004575.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bcf203816b74c5f41299641f73cd9f639d08d68e.png)

如果返回值为1则调用异常处理函数，如果为0则该异常函数不处理，如果为-1则继续从原异常点向下执行

![image-20220328215147660.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4a4c72453a52ba587bbcbc0e8ca8c1187634545b.png)

![image-20220328215136933.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1a4ac35a792647aa7ab1da3784ce9cc47defa648.png)

假设在B这个地方出异常，得到`trylevel`为2

![image-20220328215213691.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-73e3ad576bec6f64eaff31ad2c0b92f14e3db860.png)

那么这里就回去遍历`lpfnFilter`为2的地方

![image-20220328215328118.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ac7e5839a58cf285532949107f1e7a0b0ea652fa.png)

假设这里返回值为0，则继续查找，注意这个地方是向上查找，首先判断当前`previousTryLevel`的值是否为-1，如果为-1就停止查找(-1代表已经是最外层)`try`结构，然后再向上找，假设这里返回值仍然为0，判断`previousTryLevel`的值为-1，就停止查找，没有找到响应的异常处理函数

![image-20220328215543352.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4ce08fda2997fc53a3a1a7c8f2753b8b680db0fb.png)

0x02 \_try\_finally原理
=====================

无论`try`结构体中是什么代码，都会执行`finally`里面的代码

```c++
// SEH6.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

VOID ExceptionTest()
{
    __try
    {
        return;

        printf("Other code");
    }
    __finally
    {
        printf("Must run this code");
    }
}

int main(int argc, char* argv[])
{
    ExceptionTest();
    getchar();
    return 0;
}
```

![image-20220329091038461.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f3ed59471ff20ad93a1661289ef0bd745633e5b6.png)

局部展开
----

当`try`里面没有异常，而是`return`、`continue`、`break`等语句时，就不会走`_except_handle3`这个函数，而是调用`_local_unwind2`进行展开

![image-20220329091558879.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c2a4c449a866bcebaf095e5c64886d6f25598e4b.png)

然后调用`[ebx + esi*4 + 8]`

![image-20220329091914211.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-729a0a65cc143eceab38881e2acf6fae795f3017.png)

跟进去就到了`finally`语句块的地方

![image-20220329092006412.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-73169bd9ceda317fbcb0aa5caa5c7a317d08cb06.png)

我们探究一下实现的原理，这里本来应该是`lpfnFilter`参数，指向异常处理过滤的代码的地址，但是这里是0。只要这个地方的地址为0就是`finally`语句块

![image-20220329092429559.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-74f7fb01568d3760e56d7aceb445041621884480.png)

全局展开
----

```c++
// SEH6.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

VOID ExceptionTest()
{
    __try
    {
        __try
        {
            __try
            {
                *(int*)0 = 1;
            }
            __finally
            {
                printf("Must run this code : A");
            }
        }
        __finally
        {
            printf("Must run this code : B");
        }
    }
    __except(1)
    {
        printf("Here is Exception_functions");
    }
}

int main(int argc, char* argv[])
{
    ExceptionTest();
    getchar();
    return 0;
}
```

全局展开就是一层一层的向上找异常处理函数，`finally`模块还是照常执行

![image-20220329094846868.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-32c30bf023d0269850b2179aec77a05060e28df1.png)

![image-20220329102145583.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0921bb6291bc99c0f3133bb51d7fd1481cf5180a.png)

0x03 未处理异常
==========

入口程序的最后一道防线
-----------

![image-20220329104223648.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0e15556043b7b46167fcf3654d18d9344663a43c.png)

这里调用`mainCRTStartup()`，然后调用入口程序

![image-20220329104250459.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-670685195c51fb9eadfdd9d5f0b91b0305aa1160.png)

相当于这里才是一个进程开始执行的地方

![image-20220329104533520.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ff9c8516a5341b09dcfbe358758d79543569fe8b.png)

这里有一个call调用，跟进去看看

![image-20220329104602203.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-29a80768045b035c5437f88e822e298fc204b01a.png)

发现有修改`fs:[0]`的操作，这里就相当于编译器为我们注册了一个异常处理函数

![image-20220329104705199.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e62c4bf0298767e43e62d2bbf3ce74cebc33e583.png)

这里到`kernel32.dll`里面的`BaseProcessStart`里面看一下，这里有一个注册SEH异常处理函数的操作

![image-20220329105057347.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9b144753ec0f51c162b3d442757a7319ae3cc786.png)

线程启动的最后一道防线
-----------

```c++
// SEH7.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

DWORD WINAPI ThreadProc(LPVOID lpParam)
{
    int i = 1;
    return 0;
}

int main(int argc, char* argv[])
{
    CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);

    getchar();

    return 0;

```

可以发现线程也是从`kernel32.dll`开始的

![image-20220329105932341.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a9ff961225455d54dc7591013a8a2b27680abd31.png)

然后跟进调用

![image-20220329110018752.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-71a5be67c567ffc856dc56c3c73e315468da83bc.png)

可以发现还是注册了一个异常处理函数

![image-20220329110034166.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-821ef77710298fac85c7462c6660b5ea754c2b66.png)

还是去IDA里面看`BaseThreadStart`函数，发现也注册了一个`SEH`异常的函数

![image-20220329110402112.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ddd2fccdd1ae51837fc4f943c207694fe1961959.png)

### UnhandledExceptionFilter

相当于编译器为我们生成了一段伪代码

```c++
__try
{

}
__except(UnhandledExceptionFilter(GetExceptionInformation())
{
    //终止线程
    //终止进程
}
```

只有程序被调试时，才会存在未处理异常

UnhandledExceptionFilter的执行流程：

```c++
1) 通过NtQueryInformationProcess查询当前进程是否正在被调试，如果是，返回EXCEPTION_CONTINUE_SEARCH，此时会进入第二轮分发 

2) 如果没有被调试： 

查询是否通过SetUnhandledExceptionFilter注册处理函数 如果有就调用 

如果没有通过SetUnhandledExceptionFilter注册处理函数 弹出窗口 让用户选择终止程序还是启动即时调试器 

如果用户没有启用即时调试器，那么该函数返回EXCEPTION_EXECUTE_HANDLER
```

### SetUnhandledExceptionFilter

如果没有通过`SetUnhandledExceptionFilter`注册异常处理函数，则程序崩溃

![image-20220401142104425.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1d2dd4418bbe4d6bee8620d98be68ca9223dd9ad.png)

![image-20220401142146258.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1cb90d1d0ab2c2aef7d1b30cf1b4a92b9012a55d.png)

测试代码如下，我自己构造一个异常处理函数`callback`并用`SetUnhandledExceptionFilter`注册，构造一个除0异常，当没有被调试的时候就会调用`callback`处理异常，然后继续正常运行，如果被调试则不会修复异常，因为这是最后一道防线，就会直接退出，起到反调试的效果

```c++
// SEH7.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

long _stdcall callback(_EXCEPTION_POINTERS* excp)
{
    excp->ContextRecord->Ecx = 1;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(int argc, char* argv[])
{
    SetUnhandledExceptionFilter(callback);

    _asm
    {
        xor edx,edx
        xor ecx,ecx
        mov eax,0x10
        idiv ecx
    }

    printf("Run again!");
    getchar();
    return 0;
}
```

直接启动可以正常运行

![image-20220329113645787.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6f0fc2f2aaf1d8f53eaaf0beb330386453cff500.png)

使用od打开则直接退出

![image-20220329113851211.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8b2f3440d5c0f7db06fe232dc2067972b388d2fc.png)

![image-20220329113905022.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-cee39b805c2f862539529516f4c0c51b7932c39f.png)

### KiUserExceptionDispatcher

只有当前程序处于调试的时候才可能产生未处理异常

```c++
1) 调用RtlDispatchException  查找并执行异常处理函数

2) 如果RtlDispatchException返回真,调用ZwContinue再次进入0环，但线程再次返回3环时，会从修正后的位置开始执行。

3) 如果RtlDispatchException返回假,调用ZwRaiseException进行第二轮异常分发
(参见KiUserExceptionDispatcher代码)
```

![image-20220329114630657.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c3eebfc74fbbea398b7d87669a361d168936ff95.png)