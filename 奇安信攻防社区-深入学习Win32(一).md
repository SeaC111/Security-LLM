0x00 前言
=======

Win32 API 是windows平台下的最基本的API接口，面向Windows编程

以学习底层的角度去学习Windows操作系统

r3是一定要学明白的！

0x01 多字节字符
==========

前言
--

多字节字符，又叫窄字节字符

```php
ASCII码表:0111 1111

拓展ASCII码表:1111 1111
```

一个字节有8位，两个拓展ASCII码(2字节)拼成一个汉字

问题
--

- 有可能和韩文、日文撞了，就出现了乱码
- 当判断`city5`时，正常的返回应该是5，但是实际返回6，因为`ASCII`是按照字节去判断的，一个汉字是2字节，所以返回6

Unicode
-------

针对以上的问题，Unicode表应运而生，进行标准的统一

Unicode表中每一个符号都有2字节

0x02 C语言&amp;宽字符
================

前言
--

`中`字的编码：

```php
ASCII:d6 d0                 
UNICODE:4e 2d 
```

示例1\_一个汉字
---------

当我们用char去存储`中`时，编译和运行都不会报错

![image-20220228163331541](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f5cdde6f10349188a6a5d42807809ba29e35efcd.png)

但是，char只可以存储一个字节，会有字节丢失，断点执行看内存

![image-20220228163413079](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-653f2859b7ec67978c976bc000e2317783e4f20d.png)

当我们用`wchar_t`去存储`中`时，继续断点执行看内存

![image-20220228163817352](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-02ad623c122714ab072933985f94561b0cbdc46c.png)

`wchar_t`确实可以存储两字节，但是我们发现编译器使用的还是Ascii表

![image-20220228163905205](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e7405e27d4ac4e85a84a9497786a9a362be85d9b.png)

告诉编译器我们使用的时宽字符，让它使用Unicode表

```php
wchar_t x2 = L'中';
```

![image-20220228165036864](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-23fc08b29eb8a2af231f309ec48e17551aab2579.png)

继续看内存

![image-20220228165116456](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0b9642b032afbd9d5bf22ae09692ca7c499163e8.png)

示例2\_两个汉字
---------

```php
char x[] = "中国";
//d6 d0 b9 fa 00            使用拓展ASCII编码表  以00(\0)结尾             

wchar_t x1[] = L"中国";
//2d 4e fd 56 00 00         使用UNICODE编码表 以00 00(\0\0)结尾
```

断点看内存

![image-20220228165517394](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6ef2d982022ec637dadf7c2b46ade4263ccfc888.png)

![image-20220228165613591](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-70ce9da68e1325f5a4667c535c380b0a9c6d0359.png)

![image-20220228165639871](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0b19f947b7e6b837c604f11ece0b5ce6e4fdef57.png)

示例3\_控制台打印
----------

```php
char x[] = "中国";                    

wchar_t x1[] = L"中国";                   

printf("%s\n",x);           //使用控制台默认的编码        

wprintf(L"%s\n",x1);            //默认使用英文
```

![image-20220228170002236](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-761672c179a854d592e1346569f548e1f9c91381.png)

我们可以看到编译器不认识我们写的宽字符打印，所以没有显示出来

![image-20220228170058329](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3a2208df1088c51bde596241418be9af758575a0.png)

稍作修改：

```php
1、包含头文件 #include <locale.h>                 

2、setlocale(LC_ALL,""); //告诉编译器我们的地域
```

![image-20220228170314752](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ad483e0309fa516697dcd2e8c45e9e4d573e5e96.png)

![image-20220228170357102](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1101d1d16198d9d17fb78a49e5b5e840e5f370ea.png)

示例4\_字符串长度
----------

包含头文件

```php
#include<string.h>
```

```php
char x[] = "中A国";

wchar_t x1[] = L"中A国";                              

strlen(x); //5 //取得多字节字符串中字符长度，不包含 00               

wcslen(x1); //3 //取得宽字节字符串中字符长度，不包含 00
```

![image-20220228172809949](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-34d79eccc222ab6c81d0660d6f0b1616392510b5.png)

![image-20220228172825044](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-cb9ba56283fd3b5595cd28cd169efa9cebe388f9.png)

示例5\_字符串复制
----------

两者本质都是调用一个函数

```php
strcpy:字符串复制，全复制，上层多了一个容量的判断处理

memcpy:内存复制，按多少字节复制
```

```php
char x[] = "china";     

char x1[] = "123";      

strcpy(x,x1);       

wchar_t y[] = L"中国";        

wchar_t y1[] = L"好";        

wcscpy(y,y1);
```

0x03 C语言&amp;宽字符&lt;--&gt;多字符
=============================

```php
多字节字符类型     宽字符类型                   

char            wchar_t         

printf          wprintf     打印到控制台函数            

strlen          wcslen      获取长度            

strcpy          wcscpy      字符串复制           

strcat          wcscat      字符串拼接           

strcmp          wcscmp      字符串比较           

strstr          wcsstr      字符串查找
```

0x04 Win32 API&amp;宽字符
======================

前言
--

主要是存放在`C:\WINDOWS\system32`下面所有的dll

Windows是使用C语言开发的，Win32 API同时支持宽字符与多字节字符.

重要DLL
-----

```php
Kernel32.dll:最核心的功能模块，比如管理内存、进程和线程相关的函数等.               

User32.dll:是Windows用户界面相关应用程序接口,如创建窗口和发送消息等.                

GDI32.dll:全称是Graphical Device Interface(图形设备接口),包含用于画图和显示文本的函数              
比如要显示一个程序窗口，就调用了其中的函数来画这个窗口
```

注：其实DLL都只是外壳，其中的内核函数才是关键

当我们对DLL特别了解的时候，可以绕过DLL，直接调用内核函数

字符类型
----

```php
char      CHAR

wchar_t   WCHAR

宏        TCHAR
```

注：这里的TCHAR，宏是这么理解的，根据当前项目

编译器使用Ascii表：char

编译器使用Unicode表：wchar\_t

所以，它是一种宏，推荐使用，因为适用性好

字符串指针
-----

```php
PSTR(LPSTR):指向多字节字符串

PWSTR(LPWSTR):指向宽字符串

宏:PTSTR(LPTSTR)
```

字符数组赋值
------

```php
CHAR cha[] = "中国";

WCHAR chw[] = L"中国";

TCHAR cht[] = TEXT("中国");
```

字符串指针赋值
-------

```php
PSTR pszChar = "china";                 //多字节字符

PWSTR pszWChar = L"china";              //宽字符

PTSTR pszTChar = TEXT("china");         //如果项目是ASCII的 相当于"china" UNICODE 相当于L"china"
```

各种版本的MessageBox
---------------

Windows提供的API 凡是需要传递字符串参数的函数，都会提供两个版本和一个宏.

```php
MessageBoxA(0,"内容多字节","标题",MB_OK); //多字节字符

MessageBoxW(0,L"内容宽字节",L"标题",MB_OK); //宽字符

MessageBox(0,TEXT("根据项目字符集决定"),TEXT("标题"),MB_OK); //它也是一个宏
```

0x05 Win32主函数分析
===============

头文件
---

头文件会帮我们添加

```php
#include <windows.h>
```

![image-20220228192013294](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5ba51ecc0bf9fcd1b4b314e9db51be7a5f0294cd.png)

`__stdcall`
-----------

继续看主函数

![image-20220228191536153](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b9e80e5be7e0615ba76a0f0f0f4acf31bf466e36.png)

```php
#define APIENTRY    WINAPI

#define WINAPI      __stdcall
```

Win32程序使用的都是`__stdcall`调用约定

`__stdcall`特点：内平栈、参数的压栈顺序是从右到左

灵格斯翻译

hInstance
---------

```php
#include "stdafx.h"

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    // TODO: Place code here.

    return 0;
}
```

其实hInstance参数就是ImageBase

我们修改一下编译器的ImageBase

```php
十六进制:500000
十进制:5242880
```

![image-20220228192559226](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1ae847d993a47333fc39549251e6f467b61bcd2c.png)

进行修改

![image-20220228192631995](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-cc162ebb44d28273278966cc2531c1915f1af3be.png)

我们可以打印看看

![image-20220228192742611](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a19612d75338c1371a1ecf81b505772ef9e07118.png)

总结
--

```php
#include "stdafx.h"

int APIENTRY WinMain(HINSTANCE hInstance, //ImageBase
                     HINSTANCE hPrevInstance, //永远为0
                     LPSTR     lpCmdLine, //命令行执行内容，允许我们在程序启动时，进行传值
                     int       nCmdShow) //以什么方式显示，最大化，最小化，隐藏等
{
    // TODO: Place code here.

    return 0;
}
```

0x06 Win32&amp;打印信息
===================

前言
--

它只能在输出窗口中打印文本信息

使用
--

```php
OutputDebugString("xxx");
```

打开输出窗口

![image-20220228195405756](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a3a98f84a3780d7e0203cf90c1bfb59b15604764.png)

成功输出信息

![image-20220228195431629](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b4dec60b0ef4dd93e3eabb26dc5292ed2c7df68b.png)

改造&amp;打印参数
-----------

tools.cpp

```php
#include "stdafx.h"
#include "tools.h"

void __cdecl OutputDebugStringF(const char *format, ...)  
{  
    va_list vlArgs;  
    char    *strBuffer = (char*)GlobalAlloc(GPTR, 4096);  

    va_start(vlArgs, format);  
    _vsnprintf(strBuffer, 4096 - 1, format, vlArgs);  
    va_end(vlArgs);  
    strcat(strBuffer, "\n");  
    OutputDebugStringA(strBuffer);  
    GlobalFree(strBuffer);  
    return;  
}
```

tools.h

```php
// tools.h: interface for the tools class.
#if !defined(AFX_TOOLS_H__1C580EE6_D5B3_40B3_9BBD_A164B5C714F9__INCLUDED_)
#define AFX_TOOLS_H__1C580EE6_D5B3_40B3_9BBD_A164B5C714F9__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//
void __cdecl OutputDebugStringF(const char *format, ...); 

#ifdef _DEBUG  
#define DbgPrintf   OutputDebugStringF  
#else  
#define DbgPrintf //当项目改为Release版本时，所有的DbgPrintf都自己消失了
#endif
//

#endif // !defined(AFX_TOOLS_H__1C580EE6_D5B3_40B3_9BBD_A164B5C714F9__INCLUDED_)
```

stdafx.h

```php
#include <windows.h>
#include <stdio.h>
```

使用`DbgPrintf`，即可打印参数

```php
DbgPrintf("%d %d", 10, 20);
```

![image-20220228200119695](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-940180e010794ce06aff506383d0e90a5f10d85e.png)

0x07 Win32&amp;错误返回
===================

前言
--

使用`GetLastError()`函数，放到出问题的那行代码下面，返回值是DWORD类型

使用
--

返回DWORD类型

```php
#include "stdafx.h"
#include "tools.h"

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    // TODO: Place code here.
    //明显的使用有误
    MessageBox((HWND)1, 0, 0, 0);

    DWORD errorCode = GetLastError();
    return 0;
}
```

调试的时候，鼠标放到`errorCode`值上面

报错编号：显示1400

![image-20220302131249299](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f58ee481265207fe58da557e01fe6fe84bc3f1cd.png)

MSDN
----

搜索`GetLastError`

![image-20220302151314403](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1bbcdf59059ef3c0f8cb8a4f68f90daf05f299c0.png)

![image-20220302151354989](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c62da845a305e8829da24228775c1a56a5465261.png)

![image-20220302151505765](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bd72a1876b844861a67793942ed8f2e702e0ad86.png)

```php
1400 Invalid window handle.  ERROR_INVALID_WINDOW_HANDLE 

#无效的窗口句柄
```

![image-20220302151534796](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-08c17839c806d4008b5913583a359d0a17e5f220.png)

![image-20220302133004434](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-be4f9169cb6488d6cd57235ec474e3f19b34dd2c.png)

0x08 事件&amp;消息
==============

前言
--

Windows中的事件是一个`动作`，这个动作可能是用户操作应用程序产生的，也可能是Windows自己产生的.

而消息，就是用来描述这些`动作`的，动作被封装成了消息

Windows为了能够准确的描述这些信息，提供了一个结构体：MSG

MSG
---

这个结构体里面记录的事件的详细信息

```php
typedef struct tagMSG {             
  HWND   hwnd;              
  UINT   message;               
  WPARAM wParam;                
  LPARAM lParam;                
  DWORD  time;              
  POINT  pt;                
} MSG, *PMSG;
```

参数解析
----

```php
1、hwnd:窗口句柄

表示消息所属的窗口               

一个消息一般都是与某个窗口相关联的               

在Windows中 HWND 类型的变量通常用来标识窗口        

2、message:消息类型

在Windows中，消息是由一个数值来表示的              

但是由于数值不便于记忆，所以Windows将消息对应的数值定义为WM_XXX宏（WM == Window Message）               

鼠标左键按下 WM_LBUTTONDOWN               键盘按下 WM_KEYDOWN

3、wParam 和 lParam:message(消息类型)的附加消息，消息的进一步描述   

32位消息的特定附加信息,具体表示什么处决于message               

4、time:消息创建时的时间                 

5、pt:消息创建时的鼠标位置，通过坐标(x, y)

屏幕左上角是(0 ,0)
```

0x09 消息处理
=========

前言
--

系统消息队列与应用程序消息队列

示意图
---

![image-20220302143453720](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2f2cf0098dbb7023d34130c6732be0228b7c7bcd.png)

整体流程解析
------

1、用户输入：用户触发了一个动作，统称为用户输入，这个时候有一个事件触发了

2、保存消息：把事件封装到消息结构(MSG)

3、系统队列：把消息结构放到系统队列，队列里面的消息是一个挨着一个的，先进先出

4、应用消息队列：开始分流，窗口一的消息给窗口一，窗口二的消息给窗口二，每一个窗口都会有自己的窗口队列

5、通过消息循环，从队列里取出消息

5、处理消息：判断消息类型

是我们关注的，就处理

不是我们关注的(拖过来拖过去、点击空白处等等)，就让Windows去处理

![image-20220302143319607](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4fb6dbe1cb8fa8aff5b88983b466eb09910f5658.png)

![image-20220302143355246](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8c011394065dcdb56bc136176114357191bb616e.png)

0x10 图形界面
=========

创建窗口类的对象
--------

```php
//窗口的类名，这是我们自定义的
//Windows本身也有窗口的类名
TCHAR className[] = "My First Window"; 

//创建窗口类的对象
WNDCLASS wndclass = {0}; //一定要先将所有值赋值，进行初始化         
wndclass.hbrBackground = (HBRUSH)COLOR_MENU; //窗口的背景色           
wndclass.lpfnWndProc = WindowProc; //窗口过程函数(指定回调函数) 
wndclass.lpszClassName = className; //窗口类的名字            
wndclass.hInstance = hInstance; //定义窗口类的应用程序的实例句柄
```

```php
typedef struct _WNDCLASS { 
    UINT       style; 
    WNDPROC    lpfnWndProc; //窗口的消息处理函数
    int        cbClsExtra; 
    int        cbWndExtra; 
    HINSTANCE  hInstance; //窗口属于的应用程序
    HICON      hIcon; //窗口的图片标识
    HCURSOR    hCursor; //窗口鼠标形状
    HBRUSH     hbrBackground; //窗口背景色
    LPCTSTR    lpszMenuName;  //菜单名
    LPCTSTR    lpszClassName; //窗口名
} WNDCLASS, *PWNDCLASS;
```

![image-20220302151801398](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bfc8b4d74977b56a919f7f0eaed3ff3d07e6d450.png)

它是一个结构体，包含窗口类的属性

需要使用`RegisterClass`函数进行注册

![image-20220302151828070](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b6d26a9139e531f1eda08bfb384cf969b635374a.png)

注册窗口类
-----

```php
RegisterClass(&wndclass); //注册窗口类
```

![image-20220302155658205](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-fa33f7e03bffc535a55694b07dd26b4f06f362f2.png)

这里注意：

在我们调用`RegisterClass`之前，要先把`WNDCLASS`结构体中的成员全部赋值，不需要的值赋值为0

![image-20220302155719945](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9611acd4d3738d82d651fcd22c7ddc8ef68aeaf3.png)

消息处理函数
------

```php
WNDPROC    lpfnWndProc; //窗口的消息处理函数
```

![image-20220302152815667](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d70bd21f67b5c9bf6fe13c09699ed47c142a000d.png)

```php
LRESULT CALLBACK WindowProc(
  HWND hwnd,      // 窗口句柄
  UINT uMsg,      // 消息类型
  WPARAM wParam,  // first message parameter
  LPARAM lParam   // second message parameter
);
```

多选择的时候，switch的效率是很高的

每一个case中，其实都是一个个的宏

```php
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{                                   
    switch(uMsg)                                
    {                               
    //窗口消息                          
    case WM_CREATE:                                 
        {                           
            DbgPrintf("WM_CREATE %d %d\n",wParam,lParam);                       
            CREATESTRUCT* createst = (CREATESTRUCT*)lParam;                     
            DbgPrintf("CREATESTRUCT %s\n",createst->lpszClass);                     

            //表示这个消息已被处理
            return 0;                       
        }                           
    case WM_MOVE:                               
        {                           
            DbgPrintf("WM_MOVE %d %d\n",wParam,lParam);                     
            POINTS points = MAKEPOINTS(lParam);                     
            DbgPrintf("X Y %d %d\n",points.x,points.y);                     

            return 0;                       
        }                           
    case WM_SIZE:                               
        {                           
            DbgPrintf("WM_SIZE %d %d\n",wParam,lParam);                     
            int newWidth  = (int)(short) LOWORD(lParam);                            
            int newHeight  = (int)(short) HIWORD(lParam);                           
            DbgPrintf("WM_SIZE %d %d\n",newWidth,newHeight);                        

            return 0;                       
        }                           
    case WM_DESTROY:                                
        {                           
            DbgPrintf("WM_DESTROY %d %d\n",wParam,lParam);                      
            PostQuitMessage(0);                     

            return 0;                       
        }                           
        //键盘消息                          
    case WM_KEYUP:                              
        {                           
            DbgPrintf("WM_KEYUP %d %d\n",wParam,lParam);                        

            return 0;                       
        }                           
    case WM_KEYDOWN:                                
        {                           
            DbgPrintf("WM_KEYDOWN %d %d\n",wParam,lParam);                      

            return 0;                       
        }                           
        //鼠标消息                          
    case WM_LBUTTONDOWN:                                
        {                           
            DbgPrintf("WM_LBUTTONDOWN %d %d\n",wParam,lParam);                      
            POINTS points = MAKEPOINTS(lParam);                     
            DbgPrintf("WM_LBUTTONDOWN %d %d\n",points.x,points.y);                      

            return 0;                       
        }                           
    }                               
    return DefWindowProc(hwnd,uMsg,wParam,lParam);                              
}
```

创建窗口
----

```php
HWND hwnd = CreateWindow(                           
    className,                           //窗口的类名        
    TEXT("我的第一个窗口"),                //窗口的标题     
    WS_OVERLAPPEDWINDOW,                //窗口外观样式        
    10,                                 //相对于父窗口的X坐标        
    10,                                 //相对于父窗口的Y坐标        
    600,                                //窗口的宽度         
    300,                                //窗口的高度         
    NULL,                               //父窗口句柄，为NULL       
    NULL,                               //菜单句柄，为NULL        
    hInstance,                          //当前应用程序的句柄,一个应用程序有很多窗口 
    NULL);                              //附加数据一般为NULL       

if(hwnd == NULL)                        //判断是否创建成功，成功不为0        
    return 0;                   
```

```php
WS_OVERLAPPEDWINDOW,                //窗口外观样式
```

![image-20220302153921078](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4a3e0b002f548f39605f6758521dc0ee71c678d1.png)

```php
WS_OVERLAPPEDWINDOW   Creates an overlapped window with the WS_OVERLAPPED, WS_CAPTION, WS_SYSMENU, WS_THICKFRAME, WS_MINIMIZEBOX, and WS_MAXIMIZEBOX styles.
```

![image-20220302154002491](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-eb60d323b3d7d15ea34bd6d952013da7046f34e6.png)

显示窗口
----

```php
ShowWindow(hwnd, SW_SHOW); //显示窗口
```

消息循环
----

```php
MSG msg;            
while(GetMessage(&msg, NULL, 0, 0)) //从消息队列中获取消息，放到我们定义的Msg中，然后开始加工消息       
{           
    TranslateMessage(&msg); ////翻译消息        
    DispatchMessage(&msg); //分发消息，把消息转回操作系统，告诉操作系统它分发完成了        
}
```

回调函数
----

### 前言

`WindowProc`函数我们只管提供好，放到这里，是由操作系统去调用的

`WindowProc`函数会被系统一直调用，一直在发消息，但是我们只处理自己关注的消息

### 注意

```php
1、窗口回调函数处理过的消息，必须传回0.                   

2、窗口回调不处理的消息，由DefWindowProc来处理.
#return DefWindowProc(hwnd,uMsg,wParam,lParam);
```

### 回调函数结构

```php
LRESULT CALLBACK WindowProc(            
    IN  HWND hwnd,          
    IN  UINT uMsg,          
    IN  WPARAM wParam,          
    IN  LPARAM lParam       
    ); 
```

### 回调函数的堆栈

![image-20220303164357295](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-954a8fe83819a9da1082c2eb6abc48bbe1ad4e72.png)

代码示例
----

```php
// test6.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "tools.h"

//声明
LRESULT CALLBACK WindowProc(                                    
    IN  HWND hwnd,
    IN  UINT uMsg,
    IN  WPARAM wParam,
    IN  LPARAM lParam);

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    //窗口的类名，这是我们自定义的
    //Windows本身也有窗口的类名
    TCHAR className[] = "My First Window"; 

    //创建窗口类的对象
    WNDCLASS wndclass = {0}; //一定要先将所有值赋值，进行初始化         
    wndclass.hbrBackground = (HBRUSH)COLOR_MENU; //窗口的背景色           
    wndclass.lpfnWndProc = WindowProc; //指定窗口过程函数           
    wndclass.lpszClassName = className; //窗口类的名字            
    wndclass.hInstance = hInstance; //定义窗口类的应用程序的实例句柄

    RegisterClass(&wndclass); //注册窗口类

    //创建窗口
    HWND hwnd = CreateWindow(                           
        className,                           //窗口的类名        
        TEXT("我的第一个窗口"),                //窗口的标题     
        WS_OVERLAPPEDWINDOW,                //窗口外观样式        
        10,                                 //相对于父窗口的X坐标        
        10,                                 //相对于父窗口的Y坐标        
        600,                                //窗口的宽度         
        300,                                //窗口的高度         
        NULL,                               //父窗口句柄，为NULL       
        NULL,                               //菜单句柄，为NULL        
        hInstance,                          //当前应用程序的句柄         
        NULL);                              //附加数据一般为NULL       

    if(hwnd == NULL)                        //判断是否创建成功，成功不为0        
        return 0;

    ShowWindow(hwnd, SW_SHOW); //显示窗口

    //消息循环
    MSG msg;            
    while(GetMessage(&msg, NULL, 0, 0)) //从消息队列中获取消息，放到我们定义的Msg中，然后开始加工消息       
    {           
        TranslateMessage(&msg); ////翻译消息        
        DispatchMessage(&msg); //分发消息，把消息转回操作系统，告诉操作系统它分发完成了        
    }

    return 0;
}

//消息处理函数
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{                                   
    switch(uMsg)                                
    {                               
        //窗口消息                          
    case WM_CREATE:                                 
        {                           
            DbgPrintf("WM_CREATE %d %d\n",wParam,lParam);                       
            CREATESTRUCT* createst = (CREATESTRUCT*)lParam;                     
            DbgPrintf("CREATESTRUCT %s\n",createst->lpszClass);                     

            return 0;                       
        }                           
    case WM_MOVE:                               
        {                           
            DbgPrintf("WM_MOVE %d %d\n",wParam,lParam);                     
            POINTS points = MAKEPOINTS(lParam);                     
            DbgPrintf("X Y %d %d\n",points.x,points.y);                     

            return 0;                       
        }                           
    case WM_SIZE:                               
        {                           
            DbgPrintf("WM_SIZE %d %d\n",wParam,lParam);                     
            int newWidth  = (int)(short) LOWORD(lParam);                            
            int newHeight  = (int)(short) HIWORD(lParam);                           
            DbgPrintf("WM_SIZE %d %d\n",newWidth,newHeight);                        

            return 0;                       
        }                           
    case WM_DESTROY:                                
        {                           
            DbgPrintf("WM_DESTROY %d %d\n",wParam,lParam);                      
            PostQuitMessage(0);                     

            return 0;                       
        }                           
    //键盘消息                          
    case WM_KEYUP: //键盘抬起来                      
        {                           
            DbgPrintf("WM_KEYUP %d %d\n",wParam,lParam);                        

            return 0;                       
        }                           
    case WM_KEYDOWN: //键盘按下去                            
        {                           
            DbgPrintf("WM_KEYDOWN %d %d\n",wParam,lParam);                      

            return 0;                       
        }                           
    //鼠标消息                      
    case WM_LBUTTONDOWN: //鼠标点击                         
        {                           
            DbgPrintf("WM_LBUTTONDOWN %d %d\n",wParam,lParam);                      
            POINTS points = MAKEPOINTS(lParam);                     
            DbgPrintf("WM_LBUTTONDOWN %d %d\n",points.x,points.y);                      

            return 0;                       
        }                           
    }                               
    return DefWindowProc(hwnd,uMsg,wParam,lParam);                              
}
```

![image-20220302161436235](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c52f16a21ff2ed49c3ed46c83678209c6c890d1a.png)

窗口的最小化，最大化，关闭

我们并没有去写代码，都是操作系统替我们完成的

```php
return DefWindowProc(hwnd,uMsg,wParam,lParam);
```

0x11 事件分析
=========

`WM_CREATE`
-----------

### 前期

窗口创建会触发事件

### 代码示例

```php
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{   
    //输出消息类型
    DbgPrintf("%x\n", uMsg);        
    switch(uMsg)                                
    {                               
    //窗口消息                          
    case WM_CREATE:                                 
        {       
            //输出窗口创建的消息类型
            DbgPrintf("WM_CREATE:%x\n", uMsg); //返回1，它是WM_CREATE的宏              

            //表示这个消息已被处理
            return 0;                       
        }
    }
}
```

### `wParam`&amp;`lParam`

当消息是`WM_CREATE`时，`wParam`和`lParam`两个参数的意义

![image-20220302171829605](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a243771a7f7d63b7a86e678f3dd1582d75b6192a.png)

wParam：并不使用这个参数

lParam：`CREATESTRUCT` 类型指针包含窗口的创建信息

![image-20220302173310367](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-23ef78eea806d9310f817603371ca83122ba5f0c.png)

```php
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{   
    //输出消息类型
    DbgPrintf("%x\n", uMsg);        
    switch(uMsg)                                
    {                               
    //窗口消息                          
    case WM_CREATE:                                 
        {
            CREATESTRUCT* p = (CREATESTRUCT* ) lParam;

            //打印类名
            DbgPrintf("WM_CREATE:%x\n",p->lpszClass);

            //表示这个消息已被处理
            return 0;                       
        }
    }
}
```

`WM_MOVE`
---------

### 前言

窗口移动会触发事件

### 代码示例

```php
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{   
    //输出消息类型
    DbgPrintf("%x\n", uMsg);        
    switch(uMsg)                                
    {                               
    //窗口消息                          
    case WM_MOVE:                               
        {                           
            //输出窗口移动的消息类型
            DbgPrintf("WM_MOVE:%x\n", uMsg); //返回3，它是WM_MOVE的宏                      

            return 0;                       
        }
    }
}
```

### `wParam`&amp;`lParam`

当消息是`WM_MOVE`时，`wParam`和`lParam`两个参数的意义

![image-20220302174155804](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6540c67ead2776cf2e69ac2bfde8204d1dfc654f.png)

wParam：并不使用这个参数

lParam(4字节指针)：包含了x、y坐标

低位word：x坐标，使用宏LOWORD

高位word：y坐标，使用宏HIWORD

![image-20220302174511815](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8827704a3b29c470655b19db0c20d5688d31d8a5.png)

```php
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{   
    //输出消息类型
    DbgPrintf("%x\n", uMsg);        
    switch(uMsg)                                
    {                               
    //窗口消息                          
    case WM_MOVE:                       
        {
            DWORD xPos = (int)(short) LOWORD(lParam);   //x坐标
            DWORD yPos = (int)(short) HIWORD(lParam);   //y坐标

            //输出窗口创建的消息类型
            DbgPrintf("%d,%d\n", xPos, yPos); //返回3，它是WM_MOVE的宏                     

            return 0;                       
        }
    }
}
```

`WM_SIZE`
---------

### 前言

改变窗口大小会触发事件

### 代码示例

```php
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{   
    //输出消息类型
    DbgPrintf("%x\n", uMsg);        
    switch(uMsg)                                
    {                               
    //窗口消息                          
    case WM_SIZE:                               
        {                           
            //输出窗口大小的消息类型
            DbgPrintf("WM_SIZE:%x\n", uMsg); //返回5，它是WM_SIZE的宏                      

            return 0;                       
        }
    }
}
```

### `wParam`&amp;`lParam`

![image-20220302175748184](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-fa280427115ae91649c4cf81e21db217df361cf1.png)

当消息是`WM_SIZE`时，`wParam`和`lParam`两个参数的意义

wParam：可能是下面这5种情况中的一种

```php
SIZE_MAXHIDE -- 0
SIZE_MAXIMIZED -- 2
SIZE_MAXSHOW
SIZE_MINIMIZED -- 1
SIZE_RESTORED
```

lParam(4字节指针)：

低位word：当前调整后的窗口的宽度

高位word：当前调整后的窗口的高度

![image-20220302175809186](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5d4556d5d55eac0c31780132dccd4a681d1aa15b.png)

```php
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{   
    //输出消息类型
    DbgPrintf("%x\n", uMsg);        
    switch(uMsg)                                
    {                               
    //窗口消息                          
    case WM_SIZE:                               
        {                           

            DbgPrintf("%d %d\n", wParam, lParam); 

            DWORD xW = (int)(short) LOWORD(lParam);   //x坐标
            DWORD xH = (int)(short) HIWORD(lParam);   //y坐标

            //输出窗口创建的消息类型
            DbgPrintf("%d,%d\n", xW, xH); //窗口的宽和高

            return 0;                       
        }
    }
}
```

0x12 Win32应用程序入口识别
==================

前言
--

要根据主函数中的第一个参数hInstance，就是ImageBase

实操
--

![image-20220303124750324](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a61e2dd3a5d0d605f063de34aef3fb0b2103db00.png)

GetModuleHandleA：用来获取函数模块的句柄

它是间接Call，地址是`405024`

注意：这个地址已经修正过了

![image-20220303125005848](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c24c83128759e30507e1bf09d28556dbbe4efd87.png)

那么我跳过去

```php
dd 405024
```

这个地址就是GetModuleHandleA的地址

![image-20220303125120388](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ff5c29bed8e62af5dc12838a3928984389a041ea.png)

0x13 ESP寻址特点
============

前言
--

EBP是不变的，但是ESP是一直在变的

实操
--

因为Win32的程序都是`__stdcall`，内平栈，从右往左压栈

所以ImageBase是最后一个参数压栈

继续往下看，E8直接Call

![image-20220303125148468](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-30d12218ad906a9ddeb4780053ff992e0450874c.png)

按回车跟进去看看

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c20313429f55b9cabd87b6b24839f777e4613e4c.png)

注意到：

```php
RETN 10
```

初步判断是4个参数

但是注意：当我们看它传入几个参数的时候，要考虑寄存器传参

![image-20220303125314357](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-14f5bcb1a4f4304b0e190f01151fa315cae7f3c5.png)

我们往上看

寄存器传参：没给寄存器赋值，直接使用，那么就是从外面传进来的

![image-20220303125434135](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-61f6fe2e85410cc2ae1ca75589a98bf8d7b6047f.png)

在提升堆栈的位置

```php
SUB ESP,54
```

F2下断点，然后执行

注：F8是步过，F7是步入

![image-20220303125603163](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5001a36b6addd64b24ef3edae13bf8c03e417e50.png)

调用的下一个地址

```php
0012FF38   0040122E  RETURN to test6.<ModuleEntryPoint>+0CE from test6.00401000
```

继续看这个RETURN 是哪里来的

回车或者Follow in Disassembler

压进去的值就是下一条指令的地址

![image-20220303125908396](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-df57eba92fa7526159b36fcf466878c34b41d123.png)

有4个参数

```php
4 ImageBase  0012FF3C   00400000  test6.00400000
3 0012FF40   00000000
2 0012FF44   00141F18
1 0012FF48   0000000A
```

![image-20220303125717833](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bc2b2230dbfcf98a6d87183a07a18131689e57e7.png)

开栈是54，那么取第一个参数

```php
ESP+58
```

我们开始F8步过

当我们走到这里的时候，找到压栈的ImageBase

```php
MOV ESI,DWORD PTR SS:[ESP+5C]      ;  test6.00400000
```

![image-20220303130546097](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3b8e984fa6d1ccb3f6fb29ef79f7c0fcf206e1c5.png)

注意这里：上面

```php
PUSH ESI
```

push了一个，ESP的值又会-4

![image-20220303130641633](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-df5003564fa0938f2818562f5c7c605705e536a0.png)

在栈中，可以看到ESP的值

双击一下

![image-20220303130740160](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-83bebf183098f6da05954ee8db779f4ef924e933.png)

我们要找的第一个参数`00400000`

就是`+5C`

![image-20220303130811150](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b928c224316b9237d0a07c91bd45cc4d191739af.png)

找到`$ ==>`，双击即可回去

![image-20220303130836150](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-920c0650059af179e4f29be468919d709011319f.png)

继续F8步过，往下走

```php
PUSH EDI

MOV DWORD PTR SS:[ESP+C],ECX
```

同样是push了一下，ESP-4

![image-20220303133439239](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0f8ba4c91b80a195c3d5e473a2d1bae1eab30e62.png)

注意到ESP 在栈中，继续双击一下

![image-20220303133615033](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-61667b7e2a5b212a6c1f8f89da3c5c09772e9c25.png)

找第一个参数`00400000`

可以看到是

```php
$+60     >|00400000  test6.00400000
```

![image-20220303133703531](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-704f91206f98600b9e34f6c132b73a9a56a63777.png)

0x14 窗口回调函数的定位
==============

前言
--

我们的思路是：

```php
RegisterClass-->WNDCLASS-->wndclass.lpfnWndProc
```

实操
--

参数类型是指针，并且只有一个参数

```php
RegisterClass(&wndclass); //注册窗口类
```

E8直接Call

![image-20220303125148468](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-30d12218ad906a9ddeb4780053ff992e0450874c.png)

按回车跟进去看看

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c20313429f55b9cabd87b6b24839f777e4613e4c.png)

往下看，根据`RegisterClass`

那么这个参数`EDX`就是`WNDCLASS`

![image-20220303121045037](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-47d3bfb7529e195d9e93c6af7ab8fe095ff5764a.png)

F2下断点，然后执行

注意：断点，在push上面就行

![image-20220303121142944](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-48be4a8b18fb97f88e59c6981458f95318fddf6e.png)

F8步过

```php
PUSH EDX
```

EDX是结构体的首地址

```php
0012FF10
```

![image-20220303121239206](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d5054c5ccc6f00c78827969c949a7d03503ccfc6.png)

右键EDX，Follow in Stack，放到栈里面

我们现在看到这个结构体里面还没有值

```php
0012FF10---0012FF34
```

![image-20220303121332226](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-10051cd170933d8e076991f1e81e03069f1b6f63.png)

然后：锁住堆栈

右键--&gt;Look stack

![image-20220303121430787](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f0dc3cd5bc77a5925645fe8b6c90ac11a942f677.png)

F8步过，赋值完成

![image-20220303121601451](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6433918f3e6e9bd631f39f98c5d9aa63b4398e5a.png)

第二个参数，就是我们要找的回调函数

![image-20220303001034945](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7f21535c5807e7d0c496b22cb02dbfd1700f03d8.png)

![image-20220303121631316](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-055bb9e25d38fed1f30997dd42f4f9a6b9a1a9a2.png)

选中这一行，回车，看一下它的反汇编

![image-20220303121731341](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-11c60eedac81688c6c9b33f01a2d5791f70222ff.png)

然后下一个断点

![image-20220303121802667](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-33900bd79b817b186dd1ba523278be2ebd9df5e8.png)

按B查看我们下的断点有哪些

空格暂停断点，只留我们找到的回调函数开始的位置

![image-20220303122226083](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b582ce5044321747e6deecd406b84250cf9a4a07.png)

按C回来

![image-20220303122319823](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9d3d6ace3d94e2e14a6611e8cf61f3199264afba.png)

事件\_鼠标左键的处理函数定位
---------------

```php
#define WM_LBUTTONDOWN                  0x0201
```

![image-20220303122455893](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0d3ff45eba17206e3f28672335e8d0721a256e09.png)

在我们回调函数的断点位置，编辑条件

右键--&gt;Edit condition

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d8cfd5a3bf75cae098d55f22d5911bcff8b29b3e.png)

进行编辑

esp+8：存储的就是消息的ID

```php
[esp+8] == WM_LBUTTONDOWN
```

![image-20220303122643645](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-22b3eaab604500f1d3e5be53e63fcf2de9dfab94.png)

![image-20220303122725004](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-81d385cb4884a9357a8a0c4e06bd2035dc986b26.png)

双击进入断点

![image-20220303122805160](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e8c0d7ade85b1687748f247af2fc391a305f09cd.png)

开始运行

现在我们只有点击左键，窗口才会有变化

![image-20220303122959409](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ca2f388fbd81786c3a1e25d087710c00a292526c.png)

抓到，鼠标左键的消息的处理函数

![image-20220303123649772](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0d82a9cf3b666a885d9ce4136be2648906744d3f.png)

0x15 子窗口(按钮)
============

前言
--

Windows中所有的组件，其实都是窗口

函数要放到创建窗口之后，因为它参数有子窗口ID

```php
void CreateButton(HWND hwnd)            
{
    HWND hwndPushButton;
    hwndPushButton = CreateWindow (                             
        TEXT("button"), //类名                        
        TEXT("普通按钮"), //标题                  
        //WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON,                     
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON, //按钮属性                    
        10, 10, //坐标    
        80, 20, //宽度高度              
        hwnd, //父窗口句柄                       
        (HMENU)1001, //子窗口ID，强转为菜单类型            
        hAppInstance, //当前应用程序句柄            
        NULL); //附件程序，一般为NULL
}
```

整体代码
----

```php
// test6.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "tools.h"

HINSTANCE hAppInstance; //应用程序句柄定义为全局变量

//声明
LRESULT CALLBACK WindowProc(                                    
                                IN  HWND hwnd,          
                                IN  UINT uMsg,          
                                IN  WPARAM wParam,          
                                IN  LPARAM lParam);
//按钮函数
void CreateButton(HWND hwnd)            
{
    //定义句柄
    HWND hwndPushButton;
    HWND hwndCheckBox;      
    HWND hwndRadio;     

    hwndPushButton = CreateWindow (                             
        TEXT("button"), //类名                        
        TEXT("普通按钮"), //标题                  
        //WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON,                     
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON, //按钮属性                    
        10, 10, //坐标    
        80, 20, //宽度高度              
        hwnd, //父窗口句柄                       
        (HMENU)1001, //子窗口ID，强转为菜单类型            
        hAppInstance, //当前应用程序句柄            
        NULL); //附件程序，一般为NULL

    hwndCheckBox = CreateWindow (                           
        TEXT("button"),                         
        TEXT("复选框"),                        
        //WS_CHILD | WS_VISIBLE | BS_CHECKBOX | BS_AUTOCHECKBOX,                        
        WS_CHILD | WS_VISIBLE | BS_CHECKBOX |BS_AUTOCHECKBOX ,                      
        10, 40,                     
        80, 20,                     
        hwnd,                       
        (HMENU)1002,        //子窗口ID             
        hAppInstance,                       
        NULL);                      

    hwndRadio = CreateWindow (                          
        TEXT("button"),                         
        TEXT("单选按钮"),                       
        //WS_CHILD | WS_VISIBLE | BS_RADIOBUTTON | BS_AUTORADIOBUTTON,                      
        WS_CHILD | WS_VISIBLE | BS_RADIOBUTTON  ,                       
        10, 70,                     
        80, 20,                     
        hwnd,                       
        (HMENU)1003,        //子窗口ID             
        hAppInstance,                       
        NULL);                      

}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    hAppInstance = hInstance;

    //窗口的类名，这是我们自定义的
    //Windows本身也有窗口的类名
    TCHAR className[] = "My First Window"; 

    //创建窗口类的对象
    WNDCLASS wndclass = {0}; //一定要先将所有值赋值，进行初始化         
    wndclass.hbrBackground = (HBRUSH)COLOR_MENU; //窗口的背景色           
    wndclass.lpfnWndProc = WindowProc; //指定窗口过程函数           
    wndclass.lpszClassName = className; //窗口类的名字            
    wndclass.hInstance = hInstance; //定义窗口类的应用程序的实例句柄

    RegisterClass(&wndclass); //注册窗口类

    //创建窗口
    HWND hwnd = CreateWindow(                           
        className,                           //窗口的类名        
        TEXT("我的第一个窗口"),                //窗口的标题     
        WS_OVERLAPPEDWINDOW,                //窗口外观样式        
        10,                                 //相对于父窗口的X坐标        
        10,                                 //相对于父窗口的Y坐标        
        600,                                //窗口的宽度         
        300,                                //窗口的高度         
        NULL,                               //父窗口句柄，为NULL       
        NULL,                               //菜单句柄，为NULL        
        hInstance,                          //当前应用程序的句柄         
        NULL);                              //附加数据一般为NULL       

    if(hwnd == NULL)                        //判断是否创建成功，成功不为0        
        return 0;

    CreateButton(hwnd);

    ShowWindow(hwnd, SW_SHOW); //显示窗口

    //消息循环
    MSG msg;            
    while(GetMessage(&msg, NULL, 0, 0)) //从消息队列中获取消息，放到我们定义的Msg中，然后开始加工消息       
    {           
        TranslateMessage(&msg); ////翻译消息        
        DispatchMessage(&msg); //分发消息，把消息转回操作系统，告诉操作系统它分发完成了        
    }

    return 0;
}

//消息处理函数
LRESULT CALLBACK WindowProc(                                    
                            IN  HWND hwnd,          
                            IN  UINT uMsg,          
                            IN  WPARAM wParam,          
                            IN  LPARAM lParam       
                            )       
{                                   
    switch(uMsg)                                
    {                               
        //窗口消息                          
    case WM_CREATE:                                 
        {                           
            DbgPrintf("WM_CREATE %d %d\n",wParam,lParam);                       
            CREATESTRUCT* createst = (CREATESTRUCT*)lParam;                     
            DbgPrintf("CREATESTRUCT %s\n",createst->lpszClass);                     

            return 0;                       
        }                           
    case WM_MOVE:                               
        {                           
            DbgPrintf("WM_MOVE %d %d\n",wParam,lParam);                     
            POINTS points = MAKEPOINTS(lParam);                     
            DbgPrintf("X Y %d %d\n",points.x,points.y);                     

            return 0;                       
        }                           
    case WM_SIZE:                               
        {                           
            DbgPrintf("WM_SIZE %d %d\n",wParam,lParam);                     
            int newWidth  = (int)(short) LOWORD(lParam);                            
            int newHeight  = (int)(short) HIWORD(lParam);                           
            DbgPrintf("WM_SIZE %d %d\n",newWidth,newHeight);                        

            return 0;                       
        }                           
    case WM_DESTROY:                                
        {                           
            DbgPrintf("WM_DESTROY %d %d\n",wParam,lParam);                      
            PostQuitMessage(0);                     

            return 0;                       
        }                           
    //键盘消息
    case WM_KEYUP: //键盘抬起来                      
        {                           
            DbgPrintf("WM_KEYUP %d %d\n",wParam,lParam);                        

            return 0;                       
        }                           
    case WM_KEYDOWN: //键盘按下去                            
        {                           
            DbgPrintf("WM_KEYDOWN %d %d\n",wParam,lParam);                      

            return 0;                       
        }                           
    //鼠标消息                      
    case WM_LBUTTONDOWN: //鼠标点击                         
        {                           
            DbgPrintf("WM_LBUTTONDOWN %d %d\n",wParam,lParam);                      
            POINTS points = MAKEPOINTS(lParam);                     
            DbgPrintf("WM_LBUTTONDOWN %d %d\n",points.x,points.y);                      

            return 0;                       
        }                           
    }                               
    return DefWindowProc(hwnd,uMsg,wParam,lParam);                              
}
```

![image-20220303171303370](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b6288c544b55277a646e0f706f9b445af14535e9.png)

子窗口事件的处理
--------

button按钮，是系统给我们预定义好的，我们并没有去创建

那么我们去获取button的属性，使用`GetClassName`函数用来：获取类名

```php
TCHAR szBuffer[0x20];
GetClassName(hwndPushButton,szBuffer,0x20);
```

![image-20220303160251630](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4134e4ae2546659014a521c0869e9bde0111f9a9.png)

参数解析：

```php
int GetClassName(
  HWND hWnd,           // 获取窗口的句柄
  LPTSTR lpClassName,  // 缓冲区的地址，out类型的参数，会获取到类名会保存在这个指针中
  int nMaxCount        // 缓冲区的大小
);
```

![image-20220303160627574](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6c082d9337faa0e2d4f0fb9d387231922c6aaaf2.png)

使用`GetClassInfo`获取函数的其他信息

```php
WNDCLASS wc;
GetClassInfo(hAppInstance,szBuffer,&wc);

//指针打印输出
//打印类名
OutputDebugStringF("-->%s\n",wc.lpszClassName);

//打印消息处理函数的地址
OutputDebugStringF("-->%x\n",wc.lpfnWndProc);
```

![image-20220303160851624](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a9f2728b821b8ba029fc821ae24a52e8777f2a02.png)

参数分析：

```php
BOOL GetClassInfo(
  HINSTANCE hInstance,    // 应用程序的ImageBase
  LPCTSTR lpClassName,    // 类名，in类型参数
  LPWNDCLASS lpWndClass   // out类型参数，保存到指针中
);
```

![image-20220303161245592](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-91c44ceedae6c470e7a5f3b838fc4e85219aa9d2.png)

查看输出：

系统预定义的类名：Button

系统预定义的消息处理函数的地址：77d3b036

![image-20220303171718005](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4675005d3c829cf74fb01deb87bd745fb9f8aec2.png)

子窗口&amp;父窗口消息处理
---------------

前言
--

在消息处理函数中添加子窗口的消息处理函数，即可

### 示意图

![image-20220303162257371](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-350f7c8c1a33b2bf77767be5db674be0a49d05e2.png)

### `WM_COMMAND`

```php
case WM_COMMAND:            
{               
    switch(LOWORD(wParam)) //子窗口的ID     
    {
        case 1001:      
            MessageBox(hwnd,"Hello Button 1","Demo",MB_OK);     
            return 0;       
        case 1002:          
            MessageBox(hwnd,"Hello Button 2","Demo",MB_OK);         
            return 0;       
        case 1003:          
            MessageBox(hwnd,"Hello Button 3","Demo",MB_OK);         
            return 0;       
    }
    return DefWindowProc(hwnd,uMsg,wParam,lParam);                      
}
```

总结
--

1、在父窗口的消息处理函数中添加单击左键的事件，跟子窗口没关系

2、button按钮，是系统给我们预定义好的

3、按钮是一种特殊的窗体，并不需要提供单独的窗口回调函数.

4、当按钮有事件产生时，消息类型会发生改变，会给父窗口消息处理程序发送一个`WM_COMMAND`消息

子窗口回调函数的定位
==========

前言
--

```php
RegisterClass-->WNDCLASS-->wndclass.lpfnWndProc-->[ESP+8] == WM_COMMAND&&[ESP+0xC] == 某个窗口的ID
```

实操
--

回车进来

![image-20220303172007195](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-13f8f3cd5efaba623e94e2130ef46d874dbbe4ff.png)

父窗口的回调函数

```php
004011F0
```

![image-20220303172047465](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c7894ca39e91c271c76a820fb274029d55ea2142.png)

ctrl+g 跳过去

![image-20220303172122693](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2c2b388c6875557673a853f22660f66a75b5dd0c.png)

F2下断点，ESP+8 == uMsg

![image-20220303172224451](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a476cc652eb7f3ca3e580ad381db67aaec5896d5.png)

开始编辑断点

```php
[ESP+8] == WM_COMMAND
```

![image-20220303164634652](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9dcc70f406563521fb673cd6a2f8affc1139146a.png)

开始运行

这个时候，我们只有点击子窗口，才会有反应

![image-20220303172427456](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-073fde85cf48d283eb635e59015aea66e04c9dca.png)

点击后，就断进来了

![image-20220303172353070](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b80263501c9b400875ac36af6c7fd8469ee79bd8.png)

按W，子控件的编号

![image-20220303172824600](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7e0c773431c105c837c186ccec8d22e861a60ab1.png)

这个时候呢，我们要精确控制每一个子窗口

编辑断点处，就要多+一个条件

```php
[ESP+8] == WM_COMMAND&&[ESP+0xC] == 0x3EB
```

![image-20220303173059825](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-15ad003bf703b268f0d40f7f248651ba7b78af38.png)

重新运行，这个时候，我们只有单击单选框，它才会有反应

![image-20220303173309261](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f42bcdd68c78af1d5d3a922b84e0ecb5a9c85c01.png)

0x16 资源文件&amp;对话框
=================

前言
--

消息断点本质是条件断点

通过资源文件创建对话框，会非常的简单

```php
1、创建窗口
2、提供消息处理函数
```

操作系统会为我们做很多的事情

实操
--

创建资源文件

![image-20220303182917914](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6dcfd3cdd96cdd3decc31370f87283075697d946.png)

![image-20220303183026439](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9e23a523e523530b4abbd5adaba05acd8b9fc7f1.png)

![image-20220303183204166](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2943918d23305cdf8e80d0a9ef1bf70597928e73.png)

添加头文件

![image-20220303183238575](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-60040b5e9f524a08a12424b7d75aff3f1eafdae7.png)

![image-20220303183258252](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9cea5372f613c850846f44b1ac882eda1152a695.png)

创建Dialog(对话框)

![image-20220303183413955](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-353fd6848d88dd4dc45204e2464e55991c1870d8.png)

![image-20220303183457846](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3d78f6301f827c41ca092e51b5fcef7735dac88e.png)

默认会带两个按钮

![image-20220303183536633](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-abc9d3dc5773730746389b1856c8e729447add10.png)

右键--&gt;cut删掉

![image-20220303183602000](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-49cf48278b709e6cc5c924a77fb9e929850b0bdc.png)

首先要修改它的属性

![image-20220303183709797](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e17ca8adeae283b197081b6f0a55dc7adba0aa7d.png)

ID：IDD\_DIALOG\_MAIN

文本框标题：My FirstDialog

![image-20220303201332836](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-de3f21c8a0e570e35490ba857b00d507cade28d0.png)

F7编译一下

![image-20220303183857740](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d2cf56e1f62b4734e48bffe0dc54e05117732698.png)

资源的头文件有增加的内容

```php
#define IDD_DIALOG_MAIN                 101
```

这是一个宏，表示刚才的那个对话框编号

![image-20220303201817435](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-27771884dc483a2612950eefbf0ac39283c49eff.png)

创建对话框

使用`DialogBox`函数

```php
INT_PTR DialogBox(                  
  HINSTANCE hInstance,  // ImageBase        
  LPCTSTR lpTemplate,   // dialog对话框        
  HWND hWndParent,      // 父窗口的句柄           
  DLGPROC lpDialogFunc  // dialog对话框的消息处理函数     
);
```

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4bb543f003fa184b7edc43d6a11a47d802a0427f.png)

![image-20220303195717539](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-25f3329b5ff8ddef3c93be150a25147fd920db21.png)

当前的参数指向以空结尾的字符串

当它是一个数字时

1、可以通过`(char* )`把它转换为一个指针

2、可以按照文档中的做法，使用`MAKEINTRESOURCE`宏，也是将数字转换为一个`(char* )`类型的指针

![image-20220303200511764](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6f94bbe20f34ff63566d3d89415ea9832948cb78.png)

```php
DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);
```

继续，进行添加按钮

双击它

![image-20220303202442205](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e783212519cda29a9924b9f6ea58360a0ca6c0f2.png)

可以自己随意去画

![image-20220303202542924](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6ad80f4a07dc15313ab6eb3dabd0802055a7b093.png)

排版

同时选中两个按钮

下面一行都是排版用的按钮

![image-20220303202812710](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-879fa51a8badd3a7604b878d9fba8b447a25a138.png)

设置按钮属性

![image-20220303203601918](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-dfd6f1221242e3beb50a11415c1c039027c66765.png)

![image-20220303203627889](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8186c279e148041d1c1069ab3775701324212db1.png)

F7重新编译，然后重新看资源头文件

替我们生成了编号

![image-20220303203737746](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f1ab084ae2f0541bed3cd8874fd20517cb07c48d.png)

将按钮对接到消息处理函数上

```php
case  WM_COMMAND :                              
    switch (LOWORD (wParam))                            
    {                           
        case   IDC_BUTTON_OK :                          

        MessageBox(NULL,TEXT("IDC_BUTTON_OK"),TEXT("OK"),MB_OK);                        

        return TRUE;                        

        case   IDC_BUTTON_NO:                           

        MessageBox(NULL,TEXT("IDC_BUTTON_NO"),TEXT("NO"),MB_OK);                        

        EndDialog(hwndDlg, 0);                      

        return TRUE;                        
    }
```

![image-20220303204315121](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4aa1b770a558618525679cadc9ac9d178641943f.png)

![image-20220303204358361](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f0e449b400ebf4ef62b0df88c43c799c87c605d1.png)

继续画一些按钮

静态框：

![image-20220303204907920](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-29d4c7b0632bed645b155a8bfa4e0210587d59e2.png)

![image-20220303204931490](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-497993536ecf93dbde217477adff237f90fef05c.png)

文本框：

![image-20220303205158133](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-33781e6f8498f2250ffb6405c2b5a7d8bc187af0.png)

![image-20220303205054370](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-747f82a579cc7986a2f091cbfb10095b6b626aba.png)

![image-20220303205116730](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-902ac7ee1db283801865b0e07246d64df34e7fe1.png)

现在呢，想实现功能：点击按钮，打印文本框的输出

1、获取文本框的句柄(通用)

使用`GetDlgItem`函数

![image-20220303212218381](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a9dc90aee4bb374f1a1782a69af91cb1d21b867a.png)

参数分析：

```php
hDlg:当前文本框的句柄

IDC_EDIT_USER:对话框的编号
```

示例：

```php
HWND hEditUser = GetDlgItem(hDlg, IDC_EDIT_UserName);
```

![image-20220303212235652](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b8215375f48568ea5c5b7b4a1ad86594b000ccc7.png)

2、通过句柄获取文本框内容

使用`GetWindowText`函数

首先要有一个缓冲区

参数分析：

```php
hEditUser:文本框句柄

szUserBuff:输出缓冲区
```

示例：

```php
TCHAR szUserBuff[0x50];
GetWindowText(hEditUser, szUserBuff, 0x50);
```

![image-20220304093858213](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d5c3398437c450553127b04d58ed5f4fd84eb128.png)

代码示例
----

```php
// test6.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

//消息处理函数
BOOL CALLBACK DialogProc(                                   
                         HWND hDlg,  // handle to dialog box            
                         UINT uMsg,     // message          
                         WPARAM wParam, // first message parameter          
                         LPARAM lParam  // second message parameter         
                         )          
{                                   
    HWND hEditUser = NULL;
    HWND hEditPassWord = NULL;

    switch(uMsg)                                
    {                               
    case  WM_INITDIALOG :                               

        MessageBox(NULL,TEXT("WM_INITDIALOG"),TEXT("INIT"),MB_OK);                          

        return TRUE ;                           

    case  WM_COMMAND :                              

        switch (LOWORD (wParam))                            
        {                           
        case   IDC_BUTTON_OK :  

            //1、获取文本框的句柄
            hEditUser = GetDlgItem(hDlg,IDC_EDIT_UserName);
            hEditPassWord = GetDlgItem(hDlg,IDC_EDIT_PassWord);

            //2、通过句柄获取文本框内容
            TCHAR szUserBuff[0x50];
            TCHAR szPassBuff[0x50];

            GetWindowText(hEditUser, szUserBuff, 0x50);
            GetWindowText(hEditPassWord, szPassBuff, 0x50);

            MessageBox(NULL,TEXT("IDC_BUTTON_OK"),TEXT("OK"),MB_OK);                        

            return TRUE;                        

        case   IDC_BUTTON_NO:                           

            MessageBox(NULL,TEXT("IDC_BUTTON_NO"),TEXT("NO"),MB_OK);                        

            EndDialog(hDlg, 0);                     

            return TRUE;                        
        }

        break ;                         
    }                                   

    return FALSE ;                                  
}                                   

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);

    return 0;
}
```

总结
--

对话框的消息处理函数：

```php
1、处理过的消息，返回TRUE
2、不处理的消息，返回FALSE
```

0x17 对话框&amp;定位消息处理函数
=====================

回车跟进去

![image-20220304094618517](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-66cf3a0726adb4a581d4cfba501327a6992b75b0.png)

间接Call，创建Dialog的地址

![image-20220304094702945](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f00f83feea804090c63e432a1209742f512357a6.png)

定位消息处理函数

![image-20220304094808726](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-82c25147d07883687273c0eb29cfe81bae5747a9.png)

Ctrl+g 跟过去

```php
00401000
```

![image-20220304094907032](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ae09ea9994abc9b5c97fe122a8e0272271cb8c32.png)

F2下断点，因为消息在不停的发送，所以我们要添加条件，让它停下来

添加条件

```php
[esp+8] == WM_COMMAND
```

![image-20220304095633805](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b05090d1629d2c9c52404313d13932d97013bb38.png)

![image-20220304095732196](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-aa2509d18ae8d6547f8b957345d2e3e0e07491f8.png)

当我们点击OK，它断进来了

![image-20220304095809116](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-948eddea114d4842e3d642df4819628a3880e65d.png)

0x18 消息断点
=========

前言
--

当程序特别复杂的时候，我们一时间找不见消息处理函数

实操
--

打开DTDebug，拖入exe，开始执行

点击W

![image-20220304100156782](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8163b637d8063dae1d9b6fd7876da5549f6646a2.png)

刷新一下

![image-20220304100235655](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4c6b0b5bcb7346c92b2e7715cdd9236a22aae2e8.png)

当前页面的所有窗口都在这里了

![image-20220304100308058](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-13e1a7788c526215d1e26d30864d9ce576cf2ea0.png)

系统为我们指定的消息处理函数，由某个dll提供的

![image-20220304100458072](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-acef87e4b99be7bf32ba475187848798edb477d5.png)

这中间存在一个关系

系统为我们指定的消息处理函数--&gt;最终仍要调用我们自己写的消息处理函数

现在，我们在系统为我们指定的消息处理函数处，下断点

首先跳过来

![image-20220304101858137](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2910b03ad722d08aa382bbe8153f657e1f20a20a.png)

![image-20220304101935558](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e0acc4db819e53d605748de1d20125931ad7ab00.png)

还有一种更方便的操作，就是我们下一个消息断点

![image-20220304102021479](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3bfbaa5dab0c967923c02b46c728421e947c15d9.png)

选择消息类型，这里注意：我们找的不应该是`WM_COMMAND`

要找的是，系统为我们指定的消息处理函数的消息类型

小技巧，我们要确定是鼠标左键点下去，还是鼠标左键抬起来

鼠标左键点下去的时候，消息没有被触发

鼠标左键抬起来的时候，消息没有被触发

所以，我们这里找消息类型，应该是

```php
WM_LBUTTONUP
```

![image-20220304102557383](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-61586ca0c1128403d73cf69e02244d39af5c6bc0.png)

![image-20220304102610800](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3f183840279ba13517bd2df6302e75f61e7dfddf.png)

两个都变色了，因为对于按钮Button，系统为我们指定的消息处理函数的消息类型都是一样的

我们继续去看断点

![image-20220304111924555](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e7e07b15c4aff43efe7c7a0c0b1ff13baf473c58.png)

开始执行

我们一点击`OK`，它就断下来了

![image-20220304120351893](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0c3665df8f99a4b3ef94c1dd0edb00ea819a6ede.png)

断到系统为我们指定的消息处理函数

![image-20220304112036770](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-49ac5671a76419df930452c7499c5dfd0e9c000a.png)

打开内存窗口

```php
代码段
数据段
资源段
```

![image-20220304112300548](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-805b207328c3dd179696dd51ef62faa3113fc0db.png)

我们可以在代码段，下一个断点，它是访问断点

![image-20220304114031990](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9adde9a35481f46f9de2f9d6b9fef87c165e0af7.png)

然后我按了F9，它要去调用我们的消息处理函数

我在代码段，下了访问断点，它就停下来了

![image-20220304114304449](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-895617ac5e0c301fd3ddbbe576e05f34e20af0e8.png)

我们继续看

我们知道进到消息处理函数中时，是`WM_COMMAND`，消息类型是111

```php
调用地址
句柄
消息类型
w
l
```

我们可以看到消息类型是135，并不是我们要找的鼠标左键事件，消息处理函数

![image-20220304114926801](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-336d92ebfc95401b020b87dae0b2781455f89a9a.png)

那么，怎么定位到我们鼠标左键事件的，消息处理函数

F8，我们一直往下走，往下走

可以看到又回到，`7xxxxx`

![image-20220304120513202](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a95c4c059a7f75ff13c20df63d0b06b57c49324a.png)

然后F9，我们可以看到找到了鼠标左键的，消息处理函数

```php
111
```

![image-20220304120542026](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1fc0416103f0e29d70035b404836c889050703ca.png)

总结
--

系统为我们指定的消息处理函数--&gt;最终仍要调用我们自己写的消息处理函数

0x19 图标
=======

前言
--

注意：VC6.0C++只支持32\*32像素256色

实操
--

首先生成`32*32像素256色`的图标

![image-20220304142922965](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-df79a0ac5ccadf6984d401ba5571013514f57689.png)

![image-20220304142911932](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8f3c3ca30a13cf044a36064e2718a69d4d4b6bca.png)

创建图标

![image-20220304143100463](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-07901017fe75f2f649b4433f18f35586deca8b3b.png)

![image-20220304133511434](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d90837f3e49640a6f9344e3e12633c48add98872.png)

![image-20220304143148712](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-871a31f0e93a1343303f48bdfdcd9b438e420723.png)

修改属性

![image-20220304143221211](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0efa51649aadc2f897b5dbfd1ef7630a4f928d58.png)

![image-20220304143243708](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e5013729ba1e8b2dc80ed378f224ef2597c52212.png)

继续添加一个图标，修改属性

F7编译一下

![image-20220304143356214](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-aefb209a45c5ed2cbc4d1262d8a4f41c18d394c1.png)

查看资源头文件

有两个图标的编号

```php
#define IDI_ICON_BIG                    101
#define IDI_ICON_SMALL                  102
```

![image-20220304143428418](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5bdd446316a9140b5684267dd9fa61b115ab8c52.png)

具体是这样划分的：

Alt+Tab--&gt;大图标

其他地方--&gt;小图标

加载图标

使用`LoadIcon`函数

参数分析：

```php
hAppInstance:应用程序句柄         

IDI_ICON:图标编号           

MAKEINTRESOURCE:用这个宏的主要原因是有的资源是用序号定义的,而不是字符串.所以要把数字转换成字符串指针
```

示例

```php
hBigIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_BIG));

hSmallIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_SMALL));
```

设置图标

```php
SendMessage(hDlg,WM_SETICON,ICON_BIG,(DWORD)hBigIcon);      

SendMessage(hDlg,WM_SETICON,ICON_SMALL,(DWORD)hSmallIcon);  
```

代码示例
----

```php
#include "stdafx.h"
#include "resource.h"

HINSTANCE hAPPhinstance;

BOOL CALLBACK DialogProc(
                         HWND hwndDlg,  // handle to dialog box
                         UINT uMsg,     // message
                         WPARAM wParam, // first message parameter
                         LPARAM lParam  // second message parameter
                         )
{
    HWND hEditUser = NULL;
    HWND hEditPass = NULL;
    HICON hBigIcon;
    HICON hSmallIcon;

    switch(uMsg)
    {
    case  WM_INITDIALOG :

        hBigIcon = LoadIcon(hAPPhinstance, MAKEINTRESOURCE(IDI_ICON_BIG));
        hSmallIcon = LoadIcon(hAPPhinstance, MAKEINTRESOURCE(IDI_ICON_SMALL));

        SendMessage(hwndDlg,WM_SETICON,ICON_BIG,(DWORD)hBigIcon);
        SendMessage(hwndDlg,WM_SETICON,ICON_SMALL,(DWORD)hSmallIcon);

        //MessageBox(NULL,TEXT("WM_INITDIALOG"),TEXT("INIT"),MB_OK);

        return TRUE ;

    case  WM_COMMAND :

        switch (LOWORD (wParam))
        {
        case   IDC_BUTTON_OK :

            // 第一步：先获取文本框的句柄
            hEditUser = GetDlgItem(hwndDlg, IDC_EDIT_USERNAME);
            hEditPass = GetDlgItem(hwndDlg, IDC_EDIT_PASSWORD);

            // 第二步：通过句柄得到里面的内容
            TCHAR szUserBuff[0x50];
            TCHAR szPassBuff[0x50];

            GetWindowText(hEditUser, szUserBuff, 0x50);
            GetWindowText(hEditPass, szPassBuff, 0x50);

            MessageBox(NULL,TEXT("IDC_BUTTON_OK"),TEXT("OK"),MB_OK);

            return TRUE;

        case   IDC_BUTTON_ERROR:

            MessageBox(NULL,TEXT("IDC_BUTTON_ERROR"),TEXT("ERROR"),MB_OK);

            EndDialog(hwndDlg, 0);

            return TRUE;
        }
        break ;
    }

    return FALSE ;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    // TODO: Place code here.
    hAPPhinstance = hInstance;
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);

    return 0;
}
```

0x20 提取图标
=========

实操
--

![image-20220304204342873](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-260c5b62055f4c669c3d2830d9a39eaa0410c5d2.png)

使用`ResHacker.exe`

把exe拖进来，选中图标

![image-20220304204556007](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9b7280ded078f383d8d7642158055562a9552c19.png)

![image-20220304204638300](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6cbeca38f30b68ad5194c32ba33f8f90f86c94ca.png)

成功提取图标

![image-20220304204652616](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ba8f7f9d954e01f2a2fc8f012650f33b3a61412b.png)

图标
--

这里，注意：

当我们拖入一个exe，它展现了很多图标，但是我们并没有添加这么多图标

这是，因为Windows操作系统在处理图标的时候，他必须要考虑到很多情况

考虑，在不同分辨率情况下，展现更好的效果，所以它分了好多份

**它是编译器分的**

![image-20220304211159059](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1d3644db4a1c51c3fb7759cd6ccec40518effe46.png)

图标组
---

它是对图标信息的一种描述

![image-20220304211610750](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-81735d7197a43c6c120063b0804b61326b5ae92f.png)

总结
--

这个工具，它会替我们去解析

![image-20220304223934739](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-773e68831c1d651c6112ce4b5610e5926979411d.png)

![image-20220304224016703](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a5d8bd2d2f6ef3787f6d2516b9484acb62198b4e.png)

0x21 更改标题
=========

使用LordPE

点击PE编辑器，拖入我们的exe

![image-20220304205032924](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d68f5c252f3b85a2ddf9f57389c503295106a43f.png)

![image-20220304205119512](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4142b206098938a5a9070c10cbb1d78d2ca040d9.png)

![image-20220304205148805](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-309a108d4b9e2b2ac672c07be08ebb2529c1a7ed.png)

```php
对话框:"DLG_ABOUT"

RVA:00007004

偏移:00002A04

大小:00000190
```

进行保存

![image-20220304205253482](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e1e223d3a9900eb71e9b000210d6fa34c467bf5e.png)

![image-20220304205418041](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ae5b120344274ebf278210b9a7a022cf01a9ee9a.png)

打开16进制的编辑器，拖入`exe`和保存的`.dmp`文件

找到我们exe的标题

这里注意：在资源文件中，所有的字符串都是Unicode

![image-20220304205818973](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1c1910f2b30fa73f471d2579cce33835d6a18d55.png)

在exe中，Ctrl+f搜索一下

![image-20220304210001293](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9b78e53e08d4eb293c21d5a4de5f867f06d7f26b.png)

简单修改一下，然后保存

![image-20220304210044642](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f99eb6f8906b33eb98f664ddec6aed8f04e2d833.png)

![image-20220304210145918](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-27499c5e96b55e6461eb1378e8e04f4b811bbc51.png)

总结
--

这个工具，对于每一个exe文件，我们都可以找到它的资源文件对于的二进制文件

但是，每一种资源文件它都有自己对应的文件结构，它并没有替我们去解析

0x22 资源表
========

前言
--

在PE文件中，资源表是最复杂的

资源目录在PE结构数据目录的数组下标为2的位置，第三个表

```objectivec
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
```

头文件目录

```php
C:\Program Files\Microsoft Visual Studio\VC98\Include\WINNT.H
```

每一块都是资源节点：

```php
绿的:资源目录

黄的:资源目录项
```

示意图
---

![image-20220314192004870](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-edfb70fcea2cb094331d6c013e34688e0f664988.png)

资源目录&amp;资源目录项
--------------

资源目录它是资源表中每一层都会有的结构

以名称命名的资源数量 + 以ID命名的资源数量 = 一个节点中的数据项(资源节点中黄色的结构体个数)

```php
typedef struct _IMAGE_RESOURCE_DIRECTORY {                              
    DWORD   Characteristics;                            //资源属性  保留 0        
    DWORD   TimeDateStamp;                              //资源创建的时间       
    WORD    MajorVersion;                               //资源版本号 未使用 0       
    WORD    MinorVersion;                               //资源版本号 未使用 0       
    WORD    NumberOfNamedEntries;                       //以名称命名的资源数量        
    WORD    NumberOfIdEntries;                          //以ID命名的资源数量        
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];                              
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
```

资源目录项：

```php
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {                                

    //这个联合体要根据最高位0还是1，做不同的事情
    //通过判断DWORD NameIsString成员是否为1
    //4字节联合体
    union {                 //目录项的名称、或者ID       
        struct {
            //共占4字节，总共32位，目的:是对位的精确控制
            DWORD NameOffset:31;  //位段或者叫位域，从后往前，它代表0-30，第31位               -
            DWORD NameIsString:1; //代表31，第32位(最高位)      
        };                              
        DWORD   Name;                               
        WORD    Id;                             
    };

    //4字节联合体
    union {                             
        DWORD   OffsetToData;                       //目录项指针     
        struct {                                
            DWORD   OffsetToDirectory:31;                               
            DWORD   DataIsDirectory:1;                              
        };                              
    };                              
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;
```

第一层
---

绿色：资源目录

黄色：它是资源目录项结构体，用来判断资源的类型，Windows共16中预定义类型，

像：光标：1，位图：2，图标：3，菜单：4，对话框：5等

我们要去判断它是Windows的预定义类型，还是我们使用了自定义类型

在第一层中，资源目录项结构体中Name代表：资源类型，又有两种情况

它可以通过字符串去指定，也可以是一个数字

```php
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {                                

    //这个联合体要根据最高位0还是1，做不同的事情
    //通过判断DWORD NameIsString成员是否为1
    //4字节联合体
    union {                 //目录项的名称、或者ID       
        struct {
            //共占4字节，总共32位，目的:是对位的精确控制
            DWORD NameOffset:31;  //位段或者叫位域，从后往前，它代表0-30，第31位               -
            DWORD NameIsString:1; //代表31，第32位(最高位)      
        };                              
        DWORD   Name;                               
        WORD    Id;                             
    };

    //4字节联合体
    union {                             
        DWORD   OffsetToData;                       //目录项指针     
        struct {                                
            DWORD   OffsetToDirectory:31;                               
            DWORD   DataIsDirectory:1;                              
        };                              
    };                              
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;
```

看第一个联合体union

当它最高位是1时，当前的资源类型是通过字符串指定的，低31位是一个`UNICODE指针`，指向一个结构：

```php
typedef struct _IMAGE_RESOURCE_DIR_STRING_U {               
    WORD    Length; //长度            
    WCHAR   NameString[ 1 ]; //UNICODE起始地址          
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;
```

当它最高位是0时，`低31位`是一个一个`int类型的数字`，是一个编号，表示字段的值作为 ID 使用

判断第一位的值

```php
1、printf("%x\n",(pResourceEntry[i].Name & 0x80000000) == 0x80000000);

2、printf("%x\n",pResourceEntry[i].NameIsString == 1);
```

继续看第一个联合体union

OffsetToData，它是用来找第二层的地址，它不是一个RVA

公式：资源表地址(RES) + OffsetToData的低31位 = 下一层目录节点的起始位置

```php
最高位如果为1，低31位 + 资源地址 == 下一层目录节点的起始位置

最高位如果为0，指向 IMAGE_RESOURCE_DATA_ENTRY
```

第一层、第二层全为1，第三层为0

![image-20220314204011616](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-30cff05e4972776a7382e96d87dca4a17b116c8e.png)

第二层
---

绿色：资源目录

黄色：它是资源目录项结构体

在第二层中，资源目录项结构体中Name代表：资源编号，又有两种情况

它可以通过字符串去指定，也可以是一个数字，和第一层的判断方法一样

公式：资源表地址(RES) + OffsetToData的低31位 = 下一层目录节点的起始位置

![image-20220314204043135](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4f41843e4a333c64ed65e3d66be8b6dffaa6791d.png)

第三层
---

绿色：资源目录

黄色：它是资源目录项结构体

在第三中，资源目录项结构体中Name代表：代码页，又有两种情况

它可以通过字符串去指定，也可以是一个数字，和第一层的判断方法一样

代码页又会有编号，简体中文：2052

其他编号参考：<http://blog.itpub.net/68137/viewspace-687394/>

节点指针
----

第三层又指向了节点指针

```php
typedef struct _IMAGE_DATA_DIRECTORY {                  
    DWORD   VirtualAddress; //当前资源的RVA是多少           
    DWORD   Size; //当前资源的大小是多少          
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

代码示例
----

```php
#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <malloc.h>

#define FilePath_In         "C:\\notepad.exe"

//函数声明
//ReadPEFile:将文件读取到缓冲区
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);

//RvaToFileOffset:将内存偏移转换为文件偏移
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);

//ReadPEFile:将文件读取到缓冲区
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{

    FILE* pFile = NULL;
    //定义一个FILE结构体指针，在标准的stdio.h文件头里面

    DWORD fileSize = 0;
    LPVOID pTempFileBuffer = NULL;

    //打开文件
    pFile = fopen(lpszFile,"rb"); //lpszFile是当作参数传递进来
    if (!pFile)
    {
        printf("打开文件失败!\r\n");
        return 0;
    }
    /*
    关于在指针类型中进行判断的操作，下面代码出现的情况和此一样，这里解释下：
    1.因为指针判断都要跟NULL比较，相当于0，假值，其余都是真值
    2.if(!pFile)和if(pFile == NULL), ----> 为空，就执行语句；这里是两个等于号不是一个等于号
    3.if(pFile)就是if(pFile != NULL), 不为空，就执行语句；
    */

    //读取文件内容后，获取文件的大小
    fseek(pFile,0,SEEK_END);
    fileSize = ftell(pFile);
    fseek(pFile,0,SEEK_SET);

    //动态申请内存空间，得到的是内存分配的指针
    pTempFileBuffer = malloc(fileSize);

    if (!pTempFileBuffer)
    {
        printf("内存分配失败!\r\n");
        fclose(pFile);
        return 0;
    }

    //根据申请到的内存空间，将文件读取到缓冲区

    size_t n = fread(pTempFileBuffer,fileSize,1,pFile);
    if (!n)
    {
        printf("读取数据失败!\r\n");
        free(pTempFileBuffer);   // 释放内存空间
        fclose(pFile);            // 关闭文件流
        return 0;
    }

    //数据读取成功，关闭文件
    *pFileBuffer = pTempFileBuffer;  // 将读取成功的数据所在的内存空间的首地址放入指针类型pFileBuffer
    pTempFileBuffer = NULL;  // 初始化清空临时申请的内存空间
    fclose(pFile);           // 关闭文件
    return fileSize;         // 返回获取文件的大小
}

//RvaToFileOffset:将内存偏移转换为文件偏移
DWORD RvaToFileOffset(LPVOID pFileBuffer, DWORD dwRva)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pFileBuffer + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER pSectionHeader = \
        (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    // RVA在文件头中或者文件对齐==内存对齐时，RVA==FOA  错！第一句是对的，第二句是错的
    if (dwRva < pOptionHeader->SizeOfHeaders)
    {
        return dwRva;
    }

    // 遍历节表，确定偏移属于哪一个节  
    for (int i = 0; i < pPEHeader->NumberOfSections; i++)
    {
        if (dwRva >= pSectionHeader[i].VirtualAddress && \
            dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
        {
            int offset = dwRva - pSectionHeader[i].VirtualAddress;
            return pSectionHeader[i].PointerToRawData + offset;
        }
    }
    printf("找不到RVA %x 对应的 FOA，转换失败\n", dwRva);
    return 0;
}

//打印资源表
VOID ResourceTable(LPVOID pFileBuffer)
{
    //资源的类型
    PCHAR lpszResType[17] = { "未定义", "光标", "位图", "图标", "菜单",
        "对话框", "字符串","字体目录", "字体",
        "加速键", "非格式化资源", "消息列表", "光标组",
        "未定义", "图标组","未定义", "版本信息" };

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER pSectionHeader = \
        (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    // 定义第一层的指针和长度
    PIMAGE_RESOURCE_DIRECTORY pResDir1 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pFileBuffer + \
        RvaToFileOffset(pFileBuffer, pOptionHeader->DataDirectory[2].VirtualAddress));
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir1 + \
        sizeof(IMAGE_RESOURCE_DIRECTORY));  
    int dwNumberOfResDirEntry1 = pResDir1->NumberOfNamedEntries + pResDir1->NumberOfIdEntries;
    printf("资源类型数量: %d\r\n", dwNumberOfResDirEntry1);
    //上面是将名称和ID相加得出资源类型的数量
    // 总共三层，所以需要3层循环，开始遍历第一层：类型 
    for (int i = 0; i < dwNumberOfResDirEntry1; i++)
    {
        // 如果高位是1，则低31位就是指针，她是指向一个Unicode字符串
        if (pResDirEntry1[i].NameIsString == 1)
        {
            PIMAGE_RESOURCE_DIR_STRING_U uString = 
                (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResDir1 + (pResDirEntry1[i].NameOffset & 0x7FFFFFFF));           
            WCHAR *pName = (WCHAR *)malloc(2 * (uString->Length + 1));
            memset(pName, 0, 2 * (uString->Length + 1));
            memcpy(pName, uString->NameString, 2 * uString->Length);
            wprintf(L"ID:  - 资源类型: \"%s\"\n", pName);
            free(pName);            
        }
        // 如果最高位是0，则其就是一个序号，此时字段的值作为ID使用，她是预定义的16种资源之一
        else
        {
            if (pResDirEntry1[i].Id <= 16)
                printf("ID: %2d 资源类型: %s\n", pResDirEntry1[i].Id, lpszResType[pResDirEntry1[i].Id]);
            else
                printf("ID: %2d 资源类型: 未定义\n", pResDirEntry1[i].Id);
        }
        // 定义第二层的指针和长度      
        PIMAGE_RESOURCE_DIRECTORY pResDir2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResDir1 + \
            (pResDirEntry1[i].OffsetToData & 0x7FFFFFFF));
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir2 + \
            sizeof(IMAGE_RESOURCE_DIRECTORY));      
        int dwNumberOfResDirEntry1 = pResDir2->NumberOfNamedEntries + pResDir2->NumberOfIdEntries;
        // 开始遍历第二层：编号   
        for (int j = 0; j < dwNumberOfResDirEntry1; j++)
        {
            if (pResDirEntry2[j].NameIsString == 1)
            {
                PIMAGE_RESOURCE_DIR_STRING_U uString = 
                    (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResDir1 + (pResDirEntry2[j].NameOffset & 0x7FFFFFFF));           
                WCHAR *pName = (WCHAR *)malloc(2 * (uString->Length + 1));
                memset(pName, 0, 2 * (uString->Length + 1));
                memcpy(pName, uString->NameString, 2 * uString->Length);                
                wprintf(L"\tName: \"%s\"\n", pName);
                free(pName);
            }
            else
            {
                printf("\tID: %d\n", pResDirEntry2[j].Id);
            }
            // 定义第三层的指针和长度
            PIMAGE_RESOURCE_DIRECTORY pResDir3 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResDir1 + \
                (pResDirEntry2[j].OffsetToData & 0x7FFFFFFF));
            PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir3 + \
                sizeof(IMAGE_RESOURCE_DIRECTORY));      
            int dwNumberOfResDirEntry3 = pResDir3->NumberOfNamedEntries + pResDir3->NumberOfIdEntries;
            // 遍历第三层：代码页
            // 大多数情况下一个资源的代码页只定义一种，但不是绝对，因此第三层也要循环遍历            
            //printf("\t\t%d\n", dwNumberOfResDirEntry3); // 真有不是1的
            for (int k = 0; k < dwNumberOfResDirEntry3; k++)
            {
                if (pResDirEntry3[k].Name & 0x80000000)
                {
                    printf("\t非标准代码页\n");
                }
                else
                {
                    printf("\t代码页: %d\n", pResDirEntry3[k].Id & 0x7FFF);
                }
                // 资源数据项，通过这个结构可以找到资源的RVA，以及大小
                PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResDir1 + \
                    pResDirEntry3[k].OffsetToData);
                DWORD FoaResource = RvaToFileOffset(pFileBuffer, pDataEntry->OffsetToData);
                //printf("\tRVA: %#010x\r\n \tFOA: %#010x\r\n \tSIZE: %d ", pDataEntry->OffsetToData,FoaResource,pDataEntry->Size);
                printf("\tFOA: %#010x\r\n \tSIZE: %d ", FoaResource,pDataEntry->Size);
                printf("\r\n");
                //system("pause");
            }
            printf("\r\n");
        }
    }
}

//调用上面函数的调用代码
VOID PrintResourceTable()
{
    PVOID pFileBuffer = NULL;
    DWORD FileBufferSize = 0;

    //File-->FileBuffer
    FileBufferSize = ReadPEFile(FilePath_In,&pFileBuffer);
    if (FileBufferSize == 0 || !pFileBuffer)
    {
        printf("文件-->缓冲区失败\r\n");
        return ;
    }
    printf("FileBufferSize: %#X \r\n",FileBufferSize);

    ResourceTable(pFileBuffer);

    free(pFileBuffer);

}

int main(int argc, char* argv[])
{
    PrintResourceTable();
    return 0;
}
```

![image-20220314210813097](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0e6bdc1f842a272c75922635fdaef3ebb5139323.png)