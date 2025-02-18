0x00 前言
=======

windows是一个消息驱动的系统，windows的消息提供了应用程序之间、应用程序与windows 系统之间进行通信的手段。要想深入理解windows，消息机制的知识是必不可少的。

0x01 基础
=======

进程接收来自于鼠标、键盘等其他消息都是通过消息队列进行传输的

![image-20220330142934499.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e55fbbda5698636eae6f6edee5e3f5dfc9949238.png)

常规模式下，有一个专用的进程来接收这些消息，然后再插入某个进程的消息队列，但是这样的话会涉及到频繁的进程间的通信，效率很差

![image-20220330143018662.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-72405e0010ad55957b23d04bd7d315b256f6aa7f.png)

windows为了解决这一问题，因为高2G的内核空间每个进程都是共用的，所以微软想到把消息的接收放到了0环，使用GUI线程

&lt;1&gt; 当线程刚创建的时候，都是普通线程，指向的是SSDT表

Thread.ServiceTable-&gt; KeServiceDescriptorTable

&lt;2&gt; 当线程第一次调用`Win32k.sys`时，会调用一个函数：`PsConvertToGuiThread`，我们知道在3环进0环的过程中会取得一个调用号，当调用号在100以下的时候，在`ntosknl.exe`里面，当调用号大于100则是图形处理函数，调用`Win32k.sys`

如果是一个GUI线程，`win32Thread`指向的就是`THREADINFO`结构，如果是普通线程，这里就是一个空指针

主要做几件事：

a. 扩充内核栈，必须换成64KB的大内核栈，因为普通内核栈只有12KB大小。

b.创建一个包含消息队列的结构体，并挂到`KTHREAD`上。对应的就是`MessageQueue`属性

c.Thread.ServiceTable-&gt; KeServiceDescriptorTableShadow，把`Thread.ServiceTable`指向SSDTShadow表，这个表既包含了SSDT表里面的函数，又包含了`win32k.sys`里面的图形函数

d.把需要的内存数据映射到本进程空间

总结：

&lt;1&gt; 消息队列存储在0环,通过`KTHREAD.Win32Thread`可以找到

&lt;2&gt; 并不是所有线程都要消息队列，只有GUI线程才有消息队列

&lt;3&gt; 一个GUI线程对应1个消息队列

0x02 窗口与线程
==========

![image-20220330151435668.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-68e9da84efb5bbe49478068ee2fac30c50fad8ac.png)

我们知道创建windows窗口使用的是`CreateWindow`，而这个函数底层调用的是`CreateWindowExA`和`CreateWindowExW`，我们逆向分析一下`CreateWindowExW`

![image-20220330152859474.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0f75f3f854f6b50111226b948925321bb72053e0.png)

首先调用`CreateWindowEx`

![image-20220330152911168.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c57d4a6c85e9a66324ee751fed8bbb80d540e55b.png)

然后调用`VerNtUserCreateWindowEx`

![image-20220330152922981.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-afa1bca87412e8be8f8064963bc1643fc8b17325.png)

再调用`NtUserCreateWindowEx`

![image-20220330152935780.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e010e3b4d6190defe6039b97cf7d3d62557b3ac3.png)

通过`NtUserCreateWindowEx`进入0环

![image-20220330152945944.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4f7886ea0622ddfc2846e0e2ceae78ddd7f5466f.png)

windows窗口都在0环有一个结构体，就是`WINDOW_OBJECT`，`pti`即窗口对象指向的线程。一个线程可以对应多个窗口，但是在同一个程序里面多个窗口只能对应一个线程

总结

1、窗口是在0环创建的

2、窗口句柄是全局的

3、一个线程可以用多个窗口，但每个窗口只能属于一个线程

一个GUI线程只有一个消息队列，一个线程可以有很多个窗口，一个线程中所有的窗口共享同一个消息队列

消息的接收
-----

![image-20220330181051283.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b6bdd8678e7d3a571d39d874e2cd25bc53ba1f95.png)

首先在3环创建窗口和窗口类的对象，对应0环的`_WINDOW_OBJECT`结构

![image-20220330182843878.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fb5750972add0be67b6ececd85c75ca6f73d4532.png)

消息队列的结构

```c++
<1> SentMessagesListHead    //接到SendMessage发来的消息

<2> PostedMessagesListHead  //接到PostMessage发来的消息

<3> HardwareMessagesListHead    //接到鼠标、键盘的消息
```

如果要取所有队列的消息，则第二个参数设置为NULL，后两个参数全部设置为0

GetMessage的主要功能：循环判断是否有该窗口的消息，如果有，将消息存储到MSG指定的结构，并将消息从列表中删除。

```c++
GetMessage(     LPMSG lpMsg,        //返回从队列中摘下来的消息
        HWND hWnd,      //过滤条件一：发个这个窗口的消息
        UNIT wMsgFilterMin, //过滤条件
        UNIT wMsgFilterMax  //过滤条件
);
```

使用`GetMessage()`获取信息，另外一个程序利用`SendMessage`发送给窗口，这里`GetMessage`会接收到消息并直接处理

![image-20220330204403037.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-12b2d7eb660496f1f3cc543c929d8fccdf5a3776.png)

![image-20220330204429829.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-aea1fd3c9c386af613f7fab211c851cf5ca6a906.png)

NtUserGetMessage
----------------

`User32!GetMessage` 调用 `w32k!NtUserGetMessage`

```c++
do
{
    //先判断SentMessagesListHead是否有消息 如果有处理掉
    do
    {
        ....
        KeUserModeCallback(USER32_CALLBACK_WINDOWPROC,
                               Arguments,
                               ArgumentLength,
                               &ResultPointer,
                               &ResultLength);
        ....
    }while(SentMessagesListHead != NULL)
    //以此判断其他的6个队列，里面如果有消息 返回  没有继续
}while(其他队列!=NULL)
```

SendMessage/PostMessage
-----------------------

`SendMessage`为同步，`PostMessage`为异步，`GetMessage`只处理第一个链表即`SentMessagesListHead`里面的消息

当一个程序利用`SendMessage`向另外一个程序发送消息时，另外一个程序会用`GetMessage`接收，这个过程`GetMessage`会在0环的`SentMessagesListHead`链表里面搜索是否存在`SendMessage`，如果存在`SendMessage`，`GetMessage`就会在两个程序的共享内存里面向发送消息的程序发送一个结果，在这个过程中，发送消息的程序是一直处于等待状态的，只有接收到返回的消息才会结束，这称为同步

![image-20220330204458740.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-458eb236890282339111f36d4f89c98dafb3c149.png)

![image-20220330204508959.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8fa567e79f813e4aece244cf08660e84dc1b17ee.png)

如果利用`PostMessage`发送消息，处于第二个链表里面，`GetMessage`不会处理，而程序发完消息之后也会立即结束，不会有等待的过程，这成为异步，如果要处理，使用`DispatchMessage()`处理

```c++
MSG msg;
while(GetMessage(&msg, NULL, 0, 0))
{
    TranslateMessage(&msg);
    DispatchMessage(&msg);
}
```

![image-20220330204559571.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6fb27e1437215749a08572c46073a4e8b8be2432.png)

![image-20220330204605162.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a25293c6406daacf64ae65dae758d02af8d5716f.png)

0x03 消息的分发
==========

这里如果只有`GetMessage`的话，关闭窗口是关闭不了的

![image-20220330204948712.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-95c040e9c87a6366b5383be0def5ff68dc74da33.png)

DispatchMessage
---------------

`User32!DispatchMessage` 调用 `w32k!NtUserDispatchMessage`

&lt;1&gt; 根据窗口句柄找到窗口对象

&lt;2&gt; 根据窗口对象得到窗口过程函数，由0环发起调用

如果使用`DispatchMessage`分发消息，根据窗口句柄调用相关的窗口过程，即可关闭

因为很多个消息共用一个消息队列，所以通过`GetMessage`取出消息之后，需要用`DispatchMessage`进行消息的分发

`DispatchMessage`通过`GetMessage`取出的句柄，进入0环找到`Window_Object`对象，再找到对应的窗口过程调用

![image-20220330205024274.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2a6a8470f2a0598181c761c401508fd41e9f990b.png)

`TranslateMessage`是用来处理键盘输出的函数，定义一个函数

```c++
    case WM_CHAR:
        {
            sprintf(szBuffer, "Down : %c", wParam);
            MessageBox(hwnd, szBuffer, "", 0);
            return 0;
        }
```

![image-20220330210532824.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bb4a9c3d7b1a74ea35aaee356c90ac3147eabfa4.png)

这里如果不使用`TranslateMessage`，则没有`WM_CHAR`这个消息，需要自己定义`WM_KEYDOWN`

```c++
    case WM_KEYDOWN:
        {
            sprintf(szBuffer, "Down : %d", wParam);
            MessageBox(hwnd, szBuffer, "", 0);
            return 0;
        }
```

![image-20220330211319530.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9b792e996d4cd32247699832e52f4b7ee6630f10.png)

![image-20220330211224396.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3cef1dc3c90a3b54f6a1f5a5fa58d94d3e3d08f4.png)

消息有很多，但是不是每个消息都需要我们自己去处理，所以与我们无关的消息就使用windows提供的`DefWindowProc`让微软替我们处理即可

![image-20220330211726951.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-536bf2cb6ae46e2583b8736f671fd196f01bcf8e.png)

0x04 内核回调机制
===========

窗口过程函数除了`GetMessage`和`DispatchMessage`能够调用，一些在0环的函数也能够直接进行调用。例如`CreateWindow`不向消息队列里面发送消息，而是直接调用3环提供的函数

这些消息类型可以被直接调用

![image-20220330212919027.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-aa770cca8a691cc2dba5b6ac46468c254ae6e48e.png)

这里对`WM_CREATE`进行修改，当创建成功的时候弹窗

![image-20220330213223172.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a9bc281a452f785a0e61d23766040c1e5aff3c9b.png)

这里并没有执行到`GetMessage`和`TranslateMessage`就弹窗，说明被`CreateWindow`调用0环函数，0环函数通过回调机制(`KeUserModeCallBack`)，再调用窗口过程函数

![image-20220330213206308.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-be373998513b59977a59c5f86b27d04f5f826a0d.png)

所以调用窗口过程只能是以下三种情况

```c++
<1> GetMessage()在处理SentMessagesListHead中消息时

<2> DispatchMessage()在处理其他队列中的消息时

<3> 内核代码
```

1、从0环调用3环函数的几种方式：

APC、异常、内核回调

2、凡是有窗口的程序就有可能0环直接调用3环的程序。回调机制中0环调用3环的的代码是函数：`KeUserModeCallback`

3、回到3环的落脚点：

APC：`ntdll!KiUserApcDispatcher`

异常：`ntdll!KiUserExceptionDispatcher`

KeUserModeCallback
------------------

`KeUserModeCallback`在0环对应`NtUserDispatchMessage`，调用`IntDispatchMessage`。通过`UserGetWindowObject`获得一个`Window_Object`类型，通过对象得到当前窗口的对应的窗口函数，然后调用`co_IntCallWindowProc`

```c++
NTSTATUS KeUserModeCallback (
IN ULONG ApiNumber,
IN PVOID InputBuffer,
IN ULONG InputLength,
OUT PVOID *OutputBuffer,
IN PULONG OutputLength`
);
```

调用`KeUserModeCallback`，第一个值为索引，第二个值为窗口回调过程中所有有用的信息。第一个索引值， `KeUserModeCallback`函数的第一个参数就是索引，其实它是一个宏，有很多个对应的值

内核回调在3环的落脚点，有很多个地方，我们拿着索引去3环里面找回调函数地址表，如果索引为0，则取表里面的第一个函数，如果索引为1，则取表里面的第二个函数

> PEB+0x2C 回调函数地址表，由`user32.dll`提供

`KeUserModeCallback`的调用过程如下

```c++
nt!KeUserModeCallback -> nt!KiCallUserMode -> nt!KiServiceExit -> ntdll!KiUserCallbackDispatcher -> 回调函数 -> int2B -> nt!KiCallbackReturn -> nt!KeUserModeCallback(调用后)
```

在堆栈准备完毕后，调用`KiServiceExit`回到3环，它的着陆点是`KiUserCallbackDispatcher`，然后`KiUserCallbackDispatcher`从`PEB`中取出`KernelCallbackTable`的基址，再以`ApiIndex`作为索引在这个表中查找对应的回调函数并调用，调用完之后再`int2B`触发`nt!KiCallbackReturn`再次进入内核，修正堆栈后跳回`KeUserModeCallback`，完成调用。

这里打开一个exe，通过`fs:[0]`找到TEB

![image-20220330215539012.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e68e8140bad3eefe74bbb2fa4bc35e90ffa8dcc8.png)

TEB的0x30偏移为PEB

![image-20220330215551359.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c00ac9d224eee50d67ffaed59d0c4598fc5b8c24.png)

PEB的0x2C偏移即为回调地址函数表

![image-20220330215604629.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5a53335d473c419379421737d3d02f08580e4986.png)

这里通过`KeUserModeCallback`的第一个值，即索引找到函数之后，这个函数再去调用窗口过程函数，窗口过程函数已经通过`Arguments`放在了堆栈里面

![image-20220330215640190.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8fdd8bf82b299da042ce6b5a0e29d461865764a1.png)