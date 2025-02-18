0x00 前言
=======

因为`Trap_Frame`结构在3环的原因，会有一个从0环临时返回3环的过程，所以在用户层的异常执行过程相比于内核层更加复杂。

0x01 VEH
========

首先定位到`KiUserExceptionDispatcher`函数，这里首先通过`RtlDispatchException`来找到异常处理的函数

![image-20220328111335748.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0297833efa6daf897d1cbd9f8378c9228b5936ef.png)

经过异常处理之后调用`ZwContinue`重新进入0环，这里是因为`Trap_Frame`结构被修改了，这里需要重新进入0环把新的值传入

![image-20220328111820754.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d6822e4261e9d1eae725479497635f56d71be80d.png)

如果这里异常没有处理成功会再次分发异常

![image-20220328113310567.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f99362069ccacae3f2f0d92eb2aa3ffdc011107c.png)

RtlDispatchException
--------------------

这里`RtlDispatchException`是分发异常的函数，0环跟3环是共用的，但是有一些细节是不同的，我们跟进去看看

![image-20220328113755960.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5c57da288436646b6d0669bcf1d7037f79ca3302.png)

首先看一下3环的`RtlDispatchException`里面有一个`RtlCallVectoredExceptionHandlers`

![image-20220328114206798.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f4f7a24842f37819c50ee538a9b53ab3bce99069.png)

但是在0环的`RtlDispatchException`里面是没有这个函数的

![image-20220328114346379.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6302f01f3ea9f69667798642f0ceb768081252bf.png)

跟进`RtlCallVectoredExceptionHandlers`，首先找全局链表(VEH链表)，存储了很多个异常处理函数，如果在全局链表里面没有找到，就会继续往下找局部链表(SEH链表)

![image-20220328114831441.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e49cf39f62ee63a85fd61ec1caf3c2086c050afa.png)

我们尝试用代码来实现VEH

```c++
// VEH1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

typedef PVOID (NTAPI *FnAddVectoredExceptionHandler)(ULONG, _EXCEPTION_POINTERS *);

FnAddVectoredExceptionHandler MyAddVectoredExceptionHeader;

// UEH异常处理函数只能返回2个值
// EXCEPTION_CONTINUE_EXECUTION 已处理
// EXCEPTION_CONTINUE_SEARCH 未处理

LONG NTAPI VectExceptionHandler( PEXCEPTION_POINTERS pExcepInfo )
{
    ::MessageBoxA(NULL, "VEH Function run", "VEH error", MB_OK);

    if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xC0000094)
    {
        //pExcepInfo->ContextRecord->Eip = pExcepInfo->ContextRecord->Eip + 2;
        pExcepInfo->ContextRecord->Ecx = 1;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;

}

VOID VEH()
{
    // 动态获取AddUectoredExceptionHandler函数地址
    HMODULE hMyModule = GetModuleHandle("kernel32.dll");
    MyAddVectoredExceptionHeader = (FnAddVectoredExceptionHandler)::GetProcAddress(hMyModule, "AddVectoredExceptionHandler");

    // 参数1表示插入VEH链的头部、0表示插入到UEH链的尾部
    MyAddVectoredExceptionHeader( 0, (_EXCEPTION_POINTERS *)&VectExceptionHandler );

    // 构造除0异常
    __asm
    {
        xor edx,edx
        xor ecx,ecx
        mov eax,0x10
        idiv ecx    // EDX:EAX 除以 ECX
    }

    printf("veh_code run here again");
}

int main(int argc, char* argv[])
{
    VEH();
    getchar();

    return 0;
}
```

AddVectoredExceptionHandler
---------------------------

这里有几个注意的点，首先是注册异常处理函数，使用到`AddVectoredExceptionHandler`，这个函数是在`kernel32.dll`里面的，在xp以前的版本里面是没有的，所以需要动态获取

```c++
PVOID AddVectoredExceptionHandler(
  ULONG                       First,
  PVECTORED_EXCEPTION_HANDLER Handler
);
```

第二个要注意的点就是veh是一个链表，第一个参数表示插入异常的位置，1的话就是插入到链表的头部，0的话就是插入到链表的尾部

![image-20220328144105354.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3b8dd4c2621dc7ce723bfb8c3a48c23abdef0324.png)

第三个点就是异常处理的指针指向两个结构，一个是`ContextRecord`，这个结构里面存储的是所有寄存器的值，另外一个就是`ExceptionRecord`，这个结构里面存储的就是异常的具体信息

![image-20220328145137446.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b4fa5c1ea14291fb5b93ce3e5158a35967bf7b24.png)

第四个点就是因为构造的是ecx为0，那么这里异常处理函数就可以修改eip指向的地址或者修改ecx的值为1即可

![image-20220328145326738.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e1ad6337da993f49262629d713aee9e98c851510.png)

看下效果，首先是执行了我们自己注册的异常处理函数里面的`MessageBoxA`，然后程序正常下向下执行

![image-20220328145408530.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-85846c0dcb74e0694297db1720eac3f5d9cea76d.png)

![image-20220328145421162.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-00cc95045b8e94ba4659e3d8e369abfe1f995c72.png)

VEH异常流程
-------

1.CPU捕获异常信息

2.通过`KiDispatchException`进行分发(`EIP=KiUserExceptionDispatcher`)

3.`KiUserExceptionDispatcher`调用`RtlDispatchException`

4.`RtlDispatchException`查找VEH处理函数链表 并调用相关处理函数

5.代码返回到`KiUserExceptionDispatcher`

6.调用`ZwContinue`再次进入0环(`ZwContinue`调用`NtContinue`,主要作用就是恢复`TRAP_FRAME` 然后通过`KiServiceExit`返回到3环)。

7.线程再次返回3环后，从修正后的位置开始执行

0x02 SEH
========

SEH就是一个跟0环异常处理结构类似的链表

![image-20220328161015012.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-21bb51719e9cb9ed278d62aea6669fa0209531c5.png)

首先看一下`RtlpGetStackLimits`

![image-20220328160146709.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6b150bdd362175a4ca9d7177fbb08aa109452996.png)

取出了`fs:[8]`和`fs:[4]`

![image-20220328160159015.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7b032a9a9fe0933c6e90a8aa677f79470f2f75da.png)

我们知道`fs:[0]`指向的是`_NT_TIB`结构，那么`fs:[4]`对应的就是`StackBase`，`fs:[8]`对应的就是`StackLimit`，即基址和界限

然后再拿到`fs:[0]`

![image-20220328160704780.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-012eacb282e5c20ac0652c5f122fb5545b3e73a1.png)

![image-20220328160722882.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-347ecea5e039c883e06649685f331e3fbbb16d25.png)

拿到一系列的参数之后，会首先进行一系列的判断

![image-20220328160901600.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6646cc9867b831955d8b0ae27428d355a146255e.png)

RtlpExecuteHandlerForException
------------------------------

最后调用`RtlpExecuteHandlerForException`处理异常

![image-20220328160907800.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-dfb1821ca0a1b11b1f122d9e2433c20f6e582878.png)

SEH异常的实现

```c++
// SEH1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

// ring0
/*
typedef struct _EXCEPTION_REGISTRATION_RECORD {
        struct _EXCEPTION_REGISTRATION_RECORD *Next;
        PEXCEPTION_ROUTINE Handler;
    } EXCEPTION_REGISTRATION_RECORD;
*/

struct MyException
{
    struct MyException *prev;
    DWORD Handle;
};

EXCEPTION_DISPOSITION __cdecl MyException_Handler(
    struct _EXCEPTION_RECORD *ExceptionRecord,  // ExceptionRecord 存储异常信息 什么类型异常产生位置
    void* EstablisherFrame,     // MyException结构体地址
    struct _CONTEXT *ContextRecord,     // Context结构体 异常发生时的各种寄存器值堆栈位置等
    void* DispatcherContext)
{
    ::MessageBoxA(NULL, "SEH Function", "SEH error", MB_OK);

    if (ExceptionRecord->ExceptionCode == 0xC0000094)
    {
        ContextRecord->Eip = ContextRecord->Eip + 2;
        return ExceptionContinueExecution;
    }

    return ExceptionContinueSearch;
}

void ExceptionTest()
{
    DWORD temp;

    MyException myException;

    __asm
    {
        mov eax,FS:[0]
        mov temp,eax
        lea ecx,myException
        mov FS:[0],ecx
    }
    myException.prev = (MyException*)temp;
    myException.Handle = (DWORD)&MyException_Handler;

    __asm
    {
        xor edx,edx
        xor ecx,ecx
        mov eax,0x10
        idiv ecx
    }

    // 摘除链表
    __asm
    {
        mov eax,temp
        mov FS:[0],eax
    }

    printf("SEH run again");
}

int main(int argc, char* argv[])
{
    ExceptionTest();
    getchar();
    return 0;
}
```

\_EXCEPTION\_REGISTRATION
-------------------------

首先定义一个异常处理`_EXCEPTION_REGISTRATION`结构

![image-20220328163927041.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-96285982c178a20e5c8de74d33b76172ba6f9a2d.png)

然后定义异常处理函数

```c++
EXCEPTION_DISPOSITION __cdecl MyException_Handler(
    struct _EXCEPTION_RECORD *ExceptionRecord,  // ExceptionRecord 存储异常信息 什么类型异常产生位置
    void* EstablisherFrame,     // MyException结构体地址
    struct _CONTEXT *ContextRecord,     // Context结构体 异常发生时的各种寄存器值堆栈位置等
    void* DispatcherContext)
```

![image-20220328164040189.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-18bcc3bb9c021f029466dcd6891836a416655725.png)

然后在当前线程里面声明结构体，把自己的结构体挂到链表里面，并定义`Next`指针指向下一个结构体

![image-20220328164133895.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8b3ccffecf9f7b6a0c903e5f9efad3c952754777.png)

然后构造除0异常，然后将我们自己定义的结构体从链表里面摘除

![image-20220328164256525.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1f38458f835be01e487272d8e642d824706f8a14.png)

运行结果如下

![image-20220328164336804.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-441ef7d4565eb227d8846f1cc41df4e854f010a4.png)

![image-20220328164343143.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0c86075438f0f76b2ddc73cfb017e024cb6fba02.png)

**总结**

1.FS:\[0\]指向SEH链表的第一个成员

2.SEH的异常处理函数必须在当前线程的堆栈中

3.只有当VEH中的异常处理函数不存在或者不处理才会到SEH链表中查找

SEH异常流程
-------

1.`RtlpGetStackLimits`取出`_NT_TIB`结构的`fs:[4]`和`fs:[8]`，那么`fs:[4]`对应的就是`StackBase`，`fs:[8]`对应的就是`StackLimit`，即基址和界限

2.`RtlpGetRegistrationHead`取出`_NT_TIB`结构的`fs:[0]`，取出`ExceptionList`

3.然后调用`RtlpExecuteHandlerForException`处理异常

0x03 SEH编译器扩展
=============

编译器可以直接帮我们进行简化挂入链表、异常过滤、执行异常处理程序的操作

![image-20220328200408099.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-15b3f7b7a898a00115716aeddd6af604604e457e.png)

在过滤表达式处只能有以下三种情况

```c++
1) EXCEPTION_EXECUTE_HANDLER(1) 执行except代码 

2) EXCEPTION_CONTINUE_SEARCH(0) 寻找下一个异常处理函数

3) EXCEPTION_CONTINUE_EXECUTION(-1) 返回出错位置重新执行 
```

而过滤表达式可以有3种写法

```c++
1) 直接写常量值 

2) 表达式

3) 调用函数
```

常量值
---

```c++
// SEH2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

void ExceptionTest()
{
    _try
    {
        _asm
        {
            xor edx,edx
            xor ecx,ecx
            mov eax,0x10
            idiv ecx
        }
    }
    _except(EXCEPTION_EXECUTE_HANDLER)
    {
        printf("SEH function run");
    }
}

int main(int argc, char* argv[])
{
    ExceptionTest();

    getchar();
    return 0;
}
```

![image-20220328201627389.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-38158fbdbb0f4c0401f2514d7be9905280fc21b1.png)

表达式
---

使用`GetExceptionCode`得到异常码

```c++
// SEH3.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

void ExceptionTest()
{
    _try
    {
        _asm
        {
            xor edx,edx
            xor ecx,ecx
            mov eax,0x10
            idiv ecx
        }
    }
    _except(GetExceptionCode() == 0xC0000094?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH)
    {
        printf("SEH function run");
    }
}

int main(int argc, char* argv[])
{
    ExceptionTest();

    getchar();
    return 0;
}
```

![image-20220328201811639.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-294ae17f76101cc2679b8b9d0c300d45ae19f119.png)

调用函数
----

使用`GetExceptionInformation`得到指向异常处理结构的指针

```c++
// SEH4.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

int ExceptFilter(LPEXCEPTION_POINTERS pExceptionInfo)
{
    pExceptionInfo->ContextRecord->Ecx = 1;
    return EXCEPTION_CONTINUE_EXECUTION;    // -1 返回出错位置重新执行
}

void ExceptionTest()
{
    _try
    {
        _asm
        {
            xor edx,edx
            xor ecx,ecx
            mov eax,0x10
            idiv ecx
        }
    }
    _except(ExceptFilter(GetExceptionInformation()))
    {
        printf("SEH function run");
    }
}

int main(int argc, char* argv[])
{
    ExceptionTest();

    getchar();
    return 0;
}
```

这里先修改值之后回到异常发生的地方重新执行，没有异常了，然后就走到`getchar()`的地方

![image-20220328202630875.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5599636fe20ab4af26ea0269c8bafc14084a0b9e.png)