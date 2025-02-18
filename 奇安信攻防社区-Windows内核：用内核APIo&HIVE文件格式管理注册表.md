前言
==

注册表（Registry）是Windows操作系统中的一个重要数据库，用于存储系统和应用程序的配置和设置信息。注册表包括多个层次结构的键（Key）和值（Value），通过这些键和值，操作系统和应用程序可以管理各种设置，如硬件配置、用户偏好和系统服务等。

病毒木马可以操作注册表实现注入、开机自启动、驱动加载等恶意行为。病毒木马可以通过直接调用导出的内核API函数操作注册表，但由于内核API操作比较容易检测和监控（例如，hook api），所以也可以通过注册表更底层的HIVE文件操作注册表。HIVE文件是注册表中很底层的文件形式，所以更难被检测和监控。

注册表
===

注册表是一个层次结构的数据库，有五个一级分支（也成为根键，root key）。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b1c34d108a0f999230f5ce627974c84a98dcd230.png)

注册表存储的内容对于用户来说都相当重要，这也是为什么越来越多的恶意软件将攻击对象转向了注册表。

病毒和木马常常利用注册表进行下列操作：

- 持久化操作：通过在注册表中添加自启动项，恶意软件可以在系统启动时自动运行。
    
    
    - HKEY\_LOCAL\_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKEY\_CURRENT\_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- 隐藏自身：修改注册表的一些设置，以隐藏自身的文件或进程。例如，通过修改Explorer的设置来隐藏自身。
- 修改系统配置：破坏系统的正常允许。例如禁用任务管理器、Windows安全中心等等。
- 劫持应用程序：通过修改与特定文件类型关联的程序，恶意软件可以劫持系统中的某些应用程序的启动。如修改`.exe`文件的关联，使所有可执行文件都由恶意软件启动。
- 收集信息：一些病毒木马会在注册表中窃取敏感信息，如用户凭据、系统配置或其它机密数据。

内核API
=====

函数介绍
----

用户层和内核层中各有一组注册表API函数，这俩者的函数命名、使用方式和实现功能都类似。这里只讲述基于内核API函数实现的注册表管理。

### 创建注册表项

`ZwCreateKey`函数用于创建一个新的注册表项或打开一个现有的注册表项。`ZwOpenKey`也可以用于打开注册表项。

函数原型：

```c
NTSTATUS ZwCreateKey(
    PHANDLE KeyHandle,             //指向接收注册表项句柄的变量。
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
);
```

主要代码：

```c
HANDLE hKey;
UNICODE_STRING regPath;
RtlInitUnicodeString(&regPath, L"\\Registry\\Machine\\Software\\MyKey");
OBJECT_ATTRIBUTES objAttr;
InitializeObjectAttributes(&objAttr, &regPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

NTSTATUS status = ZwCreateKey(
    &hKey,
    KEY_ALL_ACCESS,
    &objAttr,
    0,
    NULL,
    0,
    NULL
);

if (NT_SUCCESS(status)) {
    // 成功创建或打开注册表项，接下来可以进行其他操作
}
```

### 删除注册表键与键值

使用`ZwDeleteKey`函数删除注册表键，利用`ZwDeleteValueKey`删除键值。

这俩个函数的函数原型类似，前者只接收一个参数`KeyHandle`后者多接收一个`ValueName`。

使用：

```c
NTSTATUS status = ZwDeleteKey(hKey);

if (NT_SUCCESS(status)) {
    // 成功删除注册表项
}

UNICODE_STRING valueName;
RtlInitUnicodeString(&valueName, L"MyValue");

NTSTATUS status = ZwDeleteValueKey(hKey, &valueName);

if (NT_SUCCESS(status)) {
    // 成功删除键值
}

```

### 添加或修改注册表键值

通过`ZwSetValueKey`函数实现注册表键值的添加或者修改功能。

函数原型：

```c
NTSTATUS ZwSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
);

```

`KeyHandle`是注册表句柄，由`ZwCreateKey`或`ZwOpenKey`返回。`ValueName`是要设置的值名称。由`Data`指向要写入的数据，`DataSize`表示数据的字节大小。

```c
UNICODE_STRING valueName;
RtlInitUnicodeString(&valueName, L"MyValue");
DWORD data = 1;

NTSTATUS status = ZwSetValueKey(
    hKey,           // 之前创建或打开的注册表项句柄
    &valueName,
    0,
    REG_DWORD,
    &data,
    sizeof(data)
);

if (NT_SUCCESS(status)) {
    // 成功设置键值
}
```

### 查询注册表键值

`ZwQueryValueKey`函数可以查询注册表键值，获取键值的数据和类型。

函数原型：

```c
NTSTATUS ZwQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

```

`KeyValueInformationClass`指定查询的信息类型，例如KeyValueBasicInformation。

实操
--

### 实现注册表持久化操作

实现这个操作的核心是利用 `ZwSetValueKey` 函数，在`Run`键下添加一个指向应用程序路径的值，实现持久化。

关键步骤：

1. **打开注册表 `Run` 键**：通过 `ZwOpenKey` 打开 `HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` 键。
2. **设置自启动项**：使用 `ZwSetValueKey` 将应用程序的路径写入到 `Run` 键下，这样在系统启动时，指定的应用程序就会自动运行。
3. **关闭句柄**：操作完成后，关闭注册表句柄。

代码如下：

```c
#include <ntddk.h>

VOID ShowError(PUCHAR pszText, NTSTATUS ntStatus)
{
    DbgPrint("%s Error[0x%X]\n", pszText, ntStatus);
}

// 注册表持久化操作：在 Run 键中添加自启动项
BOOLEAN SetRegistryAutoRun(PUNICODE_STRING ustrExecutablePath)
{
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING ustrKeyPath, ustrValueName;
    NTSTATUS status;

    // 定义注册表的 Run 键路径
    RtlInitUnicodeString(&ustrKeyPath, L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");

    // 初始化 OBJECT_ATTRIBUTES 结构体
    InitializeObjectAttributes(&objectAttributes, &ustrKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 打开 Run 键
    status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
    if (!NT_SUCCESS(status)) {
        ShowError("ZwOpenKey", status);
        return FALSE;
    }

    // 定义注册表键值的名称（自定义名称）
    RtlInitUnicodeString(&ustrValueName, L"MyPersistentApp");

    // 设置自启动项，写入可执行文件的路径
    status = ZwSetValueKey(hKey, &ustrValueName, 0, REG_SZ, ustrExecutablePath->Buffer, ustrExecutablePath->Length);
    if (!NT_SUCCESS(status)) {
        ZwClose(hKey);
        ShowError("ZwSetValueKey", status);
        return FALSE;
    }

    // 关闭注册表键句柄
    ZwClose(hKey);
    DbgPrint("Successfully set auto-run entry.\n");

    return TRUE;
}

// DriverEntry：示例驱动入口函数
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNICODE_STRING ustrExecutablePath;

    // 指定要持久化的可执行文件路径
    RtlInitUnicodeString(&ustrExecutablePath, L"C:\\Path\\To\\YourApp.exe");

    // 设置自启动项
    SetRegistryAutoRun(&ustrExecutablePath);

    return STATUS_SUCCESS;
}

```

HIVE文件解析
========

在学习文件管理技术的时候，我们知道计算机上所有的信息都是以文件的形式存储在磁盘上的。注册表当然也算，我们看到的注册表是一个层次结构，它是经过注册表编辑器读取之后呈现给我们的，其磁盘形式是一组称为HIVE的单独文件形式。

HIVE与其它文件形式不同，每个HIVE文件都可以理解为一颗单独的注册表树，就像Windows 的 PE 格式一样，它也有自己的组织形式。

HIVE文件概念
--------

简单理解，HIVE文件格式就是Windows操作系统用来存储注册表数据的一种二进制文件格式。

一个注册表 HIVE 文件是由一个 Header 以及多个 HBIN 记录所组成的。而每一个 HBIN 记录又是由 Cell 记录和 List 记录等所组成的。其中，Cell 记录包含 nk、vk 以及 sk记录;List 记录包括lf、lh、li、ri 以及 db 记录。

HIVE文件一般位于`%SystemRoot%\System32\Config`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2d41d106f583374bf5b46ec808ef274b5d753236.png)

HIVE文件通常不能使用文本编辑器打开，可以通过regedit.exe导出HIVE文件，再使用WinHex进行分析。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-dde3896df38c352ee928c4050d489a78a0f552ea.png)

记得导出的时候要导成注册表配置单元文件，而不是reg后缀的注册文件。

HIVE文件格式结构
----------

HIVE的格式结构较为复杂，下列结构分析以导出的SOFTWARE HIVE文件为例。

### Header

每个HIVE文件都有一个头部，包含文件的基本信息，如签名、版本、序列号等。这个数据结构在整个HIVE文件格式中处于顶层，并且包含了一些关键的字段，用于标识和管理HIVE文件。HIVE的大小通常为4096（0x1000）个字节大小，即4kb。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e39a4c6cefbeada372cd6744ac71bfe08602686c.png)

如上图所示：

- Signature（0x0）：HIVE文件的标识符，通常为字符串`regf`，用于标识它是一个HIVE文件。
- 主序列号（0x4）：用于校验完整性。
- 次序列号（0x8）：同上。
- 最后写入事件（0xC）：这个占8个字节，表示HIVE文件的最后写入事件，通常是Windows文件时间格式。如图是0x1DAEF8B3B87FBA9，转换为十进制表示为133682520239111081个100纳秒，即13368252023--&gt;423年，然后加上Windows文件起始时间1601.1.1，即可得到最后写入时间2024
- 主版本号（0x14）：表示HIVE的主要版本。
- 次版本号（0x18）：表示HIVE的次版本。
- Type文件类型（0x1C）：表示HIVE的文件类型，如0x0为标准类型，0x1为事务日志方式存储的HIVE文件。
- 格式标志（0x20）：表示HIVE文件的格式类型。
- 根键的偏移量（0x24）：它表示RootCell的相对偏移位置，注意在HIVE中所有的偏移量都是相对于第一个HBIN块的。Header大小占4096字节，其后紧跟HBIN，也就是0x1000处为HBIN。这个键表示第一个HBIN块的第一个cell位置在0x1020处。
- 文件长度（0x28）：记录整个HIVE文件的字节数。从图中可知0x86C9000--&gt;141332480--&gt;138020kb，这实际上比我们导出的要小：  
    ![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-92ea3bea1778c0274104499d1a37e7b3f5e4eea5.png)  
    这是因为这一数值并不包含注册表头的大小，也不包含注册表 HIVE结尾处的一些附加数据。
    
    
    - 文件名（0x30）：存储HIVE文件的名称信息，通常是配置单元的路径或名称。以0x00为结尾的Unicode字符串。这里我也不知道为啥我的没显示，换了好几个HIVE文件了也是空白。

### HBIN

第一个HBIN块位于Header后面，即0x1000处：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-aa17d8e911ddb6040885809202a471a895545646.png)  
HBIN的典型大小为4096字节，也可以是多个4096字节的倍数。HBIN块是HIVE文件中的数据存储单元，包含多个“单元”（Cell），每个单元可以是键、值、或子键等信息。每个HBIN块开头有一个头结构，包含块的大小和偏移量。HBIN块中的数据按顺序存储，形成注册表树结构。

重点字段：

- Signature（0x0）：通常为ASCII的hbin。
- 文件偏移（0x4）：表示相对于第一个HBIN块的偏移。
    
    这里用第二个HBIN块查看：  
    ![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f026b4e041b4314b23647ba4a4ddc658c541e2f1.png)
    
    
    - 数据大小（0x8）：表示该HBIN块的大小，该HBIN块大小为0x1000。

### Cell

Cell单元是包含在HBIN块之内的，其中Cell单元又由nk、sk、vk记录组成。

#### nk记录

`nk`记录用于描述一个注册表项，它是注册表结构的核心，定义了每个注册表项的基本信息。这一记录主要用于存储关于一个键的信息，包括该键的名称、子项、值及其相关的元数据。

一条`nk`记录如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-52bcee0a77793af52ad4fa8e0a158024e48a630a.png)

它较为重要的数据字段如下：

- 签名 (0x4)：`nk`是注册表项的标识符，表明这是一个`nk`记录。
- 最后修改时间 (0x8)：8字节大小，表明最后一次修改的时间。
- 父项偏移量 (0x14)：4字节，表明该项的父项地址，这里为0xFFFFFFFF表明没有父项。
- 子项数量 (0x18)：4字节，表明子项数量，这里2D表示该键下面有45个子项。
- 子项列表偏移量 (0x20)：该偏移量指向包含该键所有子项的列表（List）记录。
- vk数量 (0x28)：该字段表示与该注册表项相关的值数量。
- vk列表偏移量 (0x2C)：指向值列表。
- sk索引（0x30）：表示sk记录的偏移值。
- 名称长度 (0x4C)：4字节，表明键名的长度。
- 键名称 (0x50)：以0x00结尾的ASCII字符串表示nk记录名称，即注册表键的名称

#### vk记录

`vk`记录用于描述与某个注册表项关联的值，在注册表中，每个键可以拥有多个值，这些值记录在`vk`记录中。`vk`记录保存了注册表值的名称、类型及实际数据。

**怎么从nk记录找到vk记录**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e7557babd9833becafaf443f1467fd137ff769f0.png)

这里换了一条nk记录，上面那条nk名称是ROOT的，应该是SOFTWARE本身。从图中可知，vk属性有3个，vk列表偏移在3E8处：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b7b8d31f3df34c183b3ea57e316ba75fd22d40fa.png)

这里其实就是list列表，第一个四字节内容为0xF，表明该列表大小，后门第一个四字节为0x300，跟过去：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-03db295d3061d32649c0cff4e1e09bec83332cfb.png)

这样就找到了第一条vk记录。接下来解析一下vk记录，一条vk记录有十个数据字段：

- 大小（0x0）：4字节，表明该记录的大小。
- 签名（0x4）：2字节，ASCII字符串“VK”。
- vk名称长度（0x6）：2字节，表示vk记录名称长度。
- vk数据长度（0x8）：4字节，表示vk记录的数据的长度。
- vk数据（0xC）：4字节，即键值内容。
- vk数据类型（0x10）：4字节，表示数据类型，即键值的数据类型。类型有REG SZ(0x1)、REG EXPAND SZ(0x2)、REG BINARY(0x3)、REG DWORD(0x4)、REG MULTI SZ(0x7)等。
- vk名称（0x18）：以0x00结尾的ASCII字符串表示vk记录名称。

#### sk记录

`sk`记录描述了这些子键的具体信息，例如注册表的安全权限数据，`sk`记录通常是通过`nk`记录中的子项列表指针访问的。

回到刚刚的nk记录：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8d7c039101b6671abe243b21bcefdd79efbac064.png)

sk索引在偏移1E8处，跟过去：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f9baa1991cef03d5ab2c8fa6ca6879ded28b37ab.png)

比较重要的数据字段，有大小、签名，还有：

- Flink（0x8）：4字节，Flink正向链路表示下一条sk记录的偏移。
- Blink（0xC）：4字节，表示上一条sk记录的偏移。

### List

在注册表HIVE文件中，共有5种不同类型的列表结构，分别是lf、lh、li、ri以及db。其中lf列表和lh列表结构相似，li和ri列表结构相似。

前四种记录存储的都是注册表子项：

- `lf`：用于小型子项集合，按字母顺序排列。
- `lh`：用于大型子项集合，采用哈希表组织。
- `li`：用于存储少量子项，结构简单。
- `ri`：用于处理非常大的子项列表，通过分块存储提升查找效率。

上面nk记录中的vk记录列表是一个单独的值列表。

`db`记录是一个特殊的列表类型，用于存储已经被删除的子项或值项的信息。

它的字段结构：

- **签名**：前两个字节为`db`，表示这是一个`db`类型的删除记录。
- **删除项目的偏移量表**：存储已经被删除的注册表项或值的偏移量。

HIVE文件解析实践
----------

要解析HIVE文件并获取注册表键、键值等数据，流程主要包含以下步骤：从HIVE文件头（`header`）开始，依次解析`hbin`记录、`nk`记录、`vk`记录、`sk`记录和各种列表结构（如`list`、`lf`、`lh`、`li`、`ri`等）。

如果我们要编写一个驱动解析HIVE，首先我们要能读取文件，之后先解析HIVE文件的头部，以获取`RootCell`的偏移地址，该偏移地址是相对于第一个HBIN记录的。而header的大小是固定4096字节的，后面紧跟着第一个HBIN记录数据。

得到RootCell数据的地址后，开始解析nk记录。从注册表根键开始解析，先获取签名字段判断当前的记录类型。之后从中获取键名、子健数量、子健索引、键值数量以及键值索引等数据。这里接下去就根据键值索引可以解析出vk记录结构数据。nk记录中还可以解析sk记录。

### 驱动框架

首先，需要一个驱动程序的基本框架。

```c
#include 

// 驱动卸载函数
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("HIVE解析驱动卸载！\n");
}
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // 设置Driver的卸载函数
    DriverObject-&gt;DriverUnload = DriverUnload;

    // 打印驱动加载信息
    DbgPrint("HIVE解析驱动加载成功！\n");

    return STATUS_SUCCESS;
}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-69ac8810521df7e9f8622ab31a7d3bba534da56c.png)

### 处理文件

为了解析HIVE文件，我们需要首先能够打开HIVE文件并从中读取数据。因此，我们要实现基本的文件操作功能，允许驱动从文件中读取二进制数据。

添加文件读取功能：

```c
NTSTATUS ReadFile(
    _In_ PUNICODE_STRING FileName,
    _Out_ PVOID* Buffer,
    _Out_ ULONG* FileSize
) {
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;
    FILE_STANDARD_INFORMATION fileInfo;

    InitializeObjectAttributes(&objectAttributes, FileName, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&fileHandle,
        GENERIC_READ,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    if (!NT_SUCCESS(status)) {
        DbgPrint("打开文件失败，状态码: 0x%08x\n", status);
        return status;
    }

    // 获取文件大小
    status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return status;
    }

    *FileSize = fileInfo.EndOfFile.LowPart;

    // 分配缓冲区
    *Buffer = ExAllocatePoolWithTag(NonPagedPool, *FileSize, 'Hive');
    if (*Buffer == NULL) {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 读取文件数据
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, *Buffer, *FileSize, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(*Buffer, 'Hive');  // 如果读取失败，需要释放已分配的缓冲区
        ZwClose(fileHandle);
        return status;
    }

    ZwClose(fileHandle);
    return status;
}
```

### 解析HIVE文件的头部

解析HIVE文件的头部，以获取`RootCell`的偏移地址，定义HIVE文件头部的结构，以便能够正确读取数据。

```c
typedef struct _HIVE_HEADER {
    CHAR Signature[4];         // 签名，应该为"regf"
    ULONG Sequence1;           // 序列号
    ULONG Sequence2;           // 序列号（应与Sequence1一致）
    ULONG RootCellOffset;      // RootCell的偏移
    ULONG HiveBinsDataSize;    // hbin数据的大小
    ULONG ClusteringFactor;
    // 其他字段...
} HIVE_HEADER, *PHIVE_HEADER;

```

将读取的HIVE文件数据转换为结构体形式，并解析出`RootCell`的偏移量。

```c
NTSTATUS ParseHiveHeader(
    _In_ PVOID Buffer,
    _Out_ ULONG* RootCellOffset
) {
    PHIVE_HEADER hiveHeader = (PHIVE_HEADER)Buffer;

    // 检查HIVE文件签名是否正确
    if (RtlCompareMemory(hiveHeader->Signature, "regf", 4) != 4) {
        DbgPrint("HIVE文件签名错误！\n");
        return STATUS_INVALID_PARAMETER;
    }

    // 获取RootCell偏移量
    *RootCellOffset = hiveHeader->RootCellOffset;
    DbgPrint("RootCell Offset: 0x%08x\n", *RootCellOffset);

    return STATUS_SUCCESS;
}

```

### 解析nk记录

有了`RootCell`的偏移量后，我们可以从该偏移开始解析`nk`记录。同样先定义nk记录结构。

```c
NTSTATUS ParseNkRecord(
    _In_ PVOID Buffer,
    _In_ ULONG Offset
) {
    PNK_RECORD nkRecord = (PNK_RECORD)((PUCHAR)Buffer + Offset);

    // 检查NK记录签名
    if (nkRecord->Signature != 0x6B6E) {  // "nk"的十六进制
        DbgPrint("NK记录签名错误！\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("NK记录解析成功！子键数量: %u, 键值数量: %u\n", nkRecord->SubkeyCount, nkRecord->ValueCount);

    // 可以继续解析子键和键值等信息

    return STATUS_SUCCESS;
}

```

定义完也一样解析，关键在：`PNK_RECORD nkRecord = (PNK_RECORD)((PUCHAR)Buffer + Offset);`通过传入的偏移量定位`nk`记录，并读取其中的字段。

后续再扩展，直到vk和sk记录以及list列表。

### 小结

这里也可以用创建文件映射的方式来读取各个数据字段的偏移。