前言
==

Bootkit恶意软件的目标是将其隐藏在非常低的级别的目标系统上，所以它需要篡改操作系统的引导组件。Windows系统的引导过程是操作系统中一个非常重要的阶段，从安全的角度看，引导进程负责启动系统并将其带到可信任的状态。在此过程中还会创建防御性逻辑的代码用来检查系统转台，因此，攻击者越早设法破坏系统，就越容易在检查中隐藏起来。

从攻击者的角度探讨Windows系统的引导过程。

Windows引导过程概述
=============

WIndows现代引导过程大致如下图所示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8bd6673f7b93c21348d22b68a6aaa01752fdc234.png)

1. 固件初始化（BIOS Initialization）
    
    
    - 第一阶段，即计算机电源打开后，BIOS（基本输入输出系统）或UEFI（统一可扩展固件接口）开始执行，这一阶段会进行硬件自检（POST），检测和初始化硬件，并准备引导环境。
2. 引导加载程序
    
    
    - 固件初始化后，系统会查找并加载引导加载程序。对于使用BIOS的系统，这通常是**主引导记录（MBR）**，而对于使用UEFI的系统，则是EFI系统分区中的`BOOTMGR`文件。
3. Windows启动管理器
    
    
    - 引导加载程序加载**Windows启动管理器（Bootmgr.exe）**，这是一个负责加载操作系统的程序。启动管理器会读取 `BCD`（引导配置数据） 文件，以确定可用的启动选项。
4. Windows内核加载
    
    
    - Windows启动管理器选择操作系统后，它会加载Windows内核（`ntoskrnl.exe`）及其他核心驱动程序。此时，Windows启动画面会出现。
5. 内核初始化
    
    
    - 内核加载后，它会初始化**硬件抽象层（HAL）**、内存管理、文件系统等关键组件，并加载所有必要的设备驱动程序。
6. 会话管理器初始化
    
    
    - Windows内核初始化完成后，会话管理器（`smss.exe`）启动，负责设置系统环境、启动用户模式驱动程序和系统服务，以及加载`winlogon.exe`。
7. 用户登录
    
    
    - 会话管理器启动`winlogon.exe`后，系统会显示登录界面，用户可以输入凭据登录系统。登录成功后，系统会加载用户的配置文件和桌面环境。

整个过程从固件初始化到用户登录，这些步骤共同构成了Windows的现代引导过程。随着引导过程的进行，执行环境变得更加复杂，为防御者提供了更丰富、更熟悉的编程模型。但是，创建和支持这些抽象模型的是较低级的代码，因此，针对这些代码，攻击者可以操纵模型以拦截引导过程的流程并干扰较高级的系统状态。

在该流程中，几乎所有进程的任何部分都可以被Bootkit恶意软件攻击，但是最常见的攻击目标是**基本输入/输出系统（BIOS）初始化**、**主引导记录（MBR）** 和 **操作系统引导加载程序（Bootloader）**。

BIOS启动阶段和预引导环境
==============

BIOS是计算机启动时最先运行的固件。它负责执行一系列硬件初始化任务，包括电源自检（POST）和硬件资源的配置，除此，它还负责查找和加载操作系统的引导加载程序（如主引导记录MBR中的代码）。

BIOS还提供了一个专门的环境，其中就包括与系统设备通信所需的基本服务。例如键盘输入、显示输出、硬盘和光驱访问等；BIOS是通过一组中断向量和中断服务例程来实现这些基本服务的，这些**中断服务例程（Interrupt Service Routines, ISRs）** 是预定义的，允许在系统启动前的任何时刻，操作系统或应用程序调用它们来执行与设备通信的操作。例如，通过调用中断`INT 13h`，系统可以与硬盘进行读写操作。

引导程序通常会通过篡改`INT 13h`来针对磁盘服务。这样做是为了通过修改操作系统启动期间从硬盘驱动器读取的操作系统和引导组件来禁用或规避操作系统保护。

**预引导环境**是指BIOS完成硬件初始化后，但在操作系统启动之前的阶段。在这个时候，BIOS将会查找可引导的磁盘驱动器，该磁盘驱动器承载要加载的操作系统实例。这可能是硬盘驱动器、USB驱动器或CD驱动器。一旦确定了可引导设备，BIOS引导代码将加载**MBR**。

上述是在BIOS系统中，如果在UEFI系统中，预引导环境由EFI系统分区（ESP）管理。ESP是一个特殊的分区，包含引导加载程序、设备驱动程序和其他与启动相关的文件。UEFI在预引导阶段会直接执行ESP中的`BOOTMGR`或其他EFI应用程序。

主引导记录MBR
========

**主引导记录（MBR, Master Boot Record）** 是BIOS引导系统中的一个关键部分，位于存储设备（通常是硬盘或SSD）的第一个扇区。它其实是一个数据结构，包含关于硬盘驱动器分区和引导代码的信息。它的主要任务是确定可引导硬盘驱动器的活动分区，该分区包含要加载的操作系统实例。一旦确定了活动分区，MBR就读取并执行其引导代码。

MBR的组成
------

**引导程序（Boot Loader）**：

- MBR的前446字节通常存放引导程序代码。这段代码的作用是从存储设备的活动分区加载操作系统的引导加载程序（如Windows的`BOOTMGR`或Linux的`GRUB`）。
- 引导程序会执行一些初步的硬件设置，并确定哪个分区是活动的，然后将控制权交给该分区中的引导加载程序，以继续启动过程。

**分区表（Partition Table）**：

- 紧随引导程序之后的是64字节的分区表。
- 每个分区条目占用16字节，记录了分区的起始位置、大小、类型等信息。

**分区标识符（Disk Signature）**：

- 分区表之后是4字节的磁盘签名（Disk Signature），用于标识磁盘设备，尤其是在多磁盘系统中。这一签名在某些情况下会被操作系统用来跟踪和标识特定的磁盘。

**签名字节（Signature Bytes）**：

- MBR的最后两个字节是固定的签名值`0x55AA`，用于标识这一扇区确实是一个有效的MBR。如果这个签名不存在，系统将无法识别该扇区为MBR，进而无法启动操作系统。

要写成C代码的话，如下：

```c
 typedef struct _MASTER_BOOT_RECOED{  
     BYTE bootCode[0x1BE];   //用于存放实际的启动代码的空间  
     MBR_PARTITION_TABLE_ENTRY partitionnTable[4];  
     USHORT mbrSignature;    //设置为0xAA55，表示PC MBR格式  
 }MASTER_BOOT_RECODE, *PMASTER_BOOT_RECODE;
```

`bootCode`即MBR引导程序代码，大小被限制为446字节。只能实现基本功能。`partitionTable`即分区表，包含四个分区条目。`mbrSignature`是MBR签名字节，通常为`0xAA55`，表示MBR的合法性。

MBR会解析分区表，以查找活动分区，读取第一个扇区中的**卷引导记录（VBR）**，并将控制权转移给它。

分区表
---

MBR的分区表是一个包含四个元素的数组，每个元素都由`MBR_PARTITION_TABLE_ENTRY`结构描述，这个结构体通常被用来描述分区在硬盘上的位置和属性。

结构体定义：

```c

 typedef struct _MBR_PARTITION_TABLE_ENTRY{  
     BYTE status;    //活动状态 0 = no, 128 = yes  
     BYTE chsFirst[3];   //起始扇区号  
     BYTE type;  //操作系统类型指示代码  
     BYTE chsLast[3];    //结束扇区号  
     DWORD lbaStart; //相对于硬件起点的第一个扇区  
     DWORD size; //分区中的扇区数  
 }MBR_PARTITION_TABLE_ENTRY, *PMBR_PARTITION_TABLE_ENTRY
```

第一个字段`status`用来表示分区是否处在活动状态，在任何时候，都只有一个分区被标记为活动状态，活动状态用值128（0x80，这个值也表示8位二进制中的最高位被设置为1）

- 为什么只有一个分区被标记为活动状态？  
    这是由于传统的BIOS设计导致的，因为BIOS没有能力处理多个活动分区，并且如果有多个分区被标记为活动分区，系统可能无法确定从哪个分区启动，导致启动失败。而且只有一个活动分区可以简化启动流程，不需要额外的处理逻辑。

字段`type`列出了分区类型，常见的类型有：

- EXTENDED MBR分区类型
- FAT12/16/32 文件系统
- IFS（用于安装过程的可安装文件系统）
- LDM（适用于Microsoft Windows NT的逻辑磁盘管理器）
- NTFS（主要的Windows文件系统）  
    该值的类型设置为0表示未使用。

字段`lbaStart` 和 `size` 定义了分区在磁盘上的位置，以扇区表示。`lbaStart`表示分区从磁盘驱动器开始处的偏移量，而`size`字段表示分区的大小。

卷引导记录VBR
========

上述说了，硬盘驱动器可能包含承载不同操作系统的多个实例的几个分区，但是通常只有一个分区应该被标记为活动的。MBR不包含解析活动分区上使用的特定文件系统的代码，因此它读取并执行分区的第一个扇区VBR。

卷引导记录VBR包含分区布局信息，它指定正在使用的文件系统的类型及其参数，以及从活动分区读取初始程序装入器（IPL）模块的代码。该模块实现了文件系统解析功能，以便能够从分区的文件系统中读取文件。

VBR结构
-----

VBR布局由`BIOS_PARAMETER_BLOCK_NTFS`和`BOOT_STRAPCODE`结构组成。`BIOS_PARAMETER_BLOCK`(BPB)结构的布局对应卷的文件系统。`BIOS_PARAMETER_BLOCK_NTFS`和`VOLUME_BOOT_RECORD`结构对应于NTFS卷。

代码如下所示：

```c
typedef struct BIOS_PARAMETER_BLOCK_NTFS {
    WORD SectorSize:
    BYTE SectorsPerCluster,
    WORD ReservedSectors;
    BYTE Reserved[5];
    BYTE MediaId;
    BYTE Reserved2[2];
    WORDSectorsPerTrack;
    WORD NumberOfHeads ;
    DWORD HiddenSectors;
    BYTE Reserved3[8];
    0WORD NumberOfSectors;
    OWORD MFTStartingCluster;
    OWORD MFTMirrorStartingCluster;
    BYTE ClusterPerFileRecord;
    BYTE Reserved4[3];
    BYTE ClusterPerIndexBuffer;
    BYTE Reserved5[3];
    OWORD NTFSSerial;
    BYTE Reserved6[4];
}BIOS_PARAMETER_BLOCK_NTFS，*PBIOS_PARAMETER_BLOCK_NTFS;

typedef struct _BOOTSTRAP_CODE{
    BYTE bootCode[420];  //引导扇区机器代码
    WORD bootSectorSignature;  // 0x55AA
}BOOTSTRAP_CODE,*PBOOTSTRAP_CODE

typedef struct VOLUME_BOOT_RECORD{ 
    WORD jmp;
    BYTE nop;
    DWORD OEM_Name;
    DWORD OEM_ID;  //NTFS
    BIOS_PARAMETER_BLOCK_NTFS BPB;
    BOOTSTRAP_CODE BootStrap;
}VOLUME_BOOT_RECORD，*PVOLUME_BOOT_RECORD;
```

从`VOLUME_BOOT_RECORD`结构中可以看到，VBR结构体的开始部分是一个jmp指令，将系统的传输控制转换倒VBR代码。VBR代码将从分区中开始读取和执行IPL，只当的位置是 `HiddenSectors`字段。IPL报告硬盘驱动器开始的偏移量。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0002bf0f77ac08f363cfa7fcdcaeb0f372bed84e.png)

以下是一个NTFS文件系统中的VBR布局：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7454181b26405e47bbc8bedaf8bb8d2b3457da6f.png)

所以，VBR基本由以下组件组成：

- 负责加载IPL的VBR代码
- BIOS参数块（存储卷参数的数据结构）
- 出现错误时显示给用户的文本字符串
- 0xAA55，VBR的2字节签名

初始程序加载器IPL
----------

严格意义上，从传统的BIOS来说，IPL是指MBR开始的那446字节大小的引导代码，它负责找到并加载活动分区的VBR，从而继续引导过程。

这里的IPL是VBR中的一部分，通常占用15个连续的512字节的扇区，并且恰好位于VBR之后。它实现了足够解析分区文件系统并继续加载bootmgr模块的代码。IPL和VBR一起使用是因为VBR只能占用一个扇区，并且由于卷的文件系统可用空间太少，因此无法实现足够的功能来解析卷的文件系统。

bootmgr模块和引导配置数据
================

IPL从文件系统中读取并加载操作系统引导管理器的bootmgr模块。也就是说，BIOS-&gt;MBR-&gt;IPL-&gt;VBR-&gt;IPL-&gt;bootmgr。

bootmgr是Windows操作系统的引导管理器模块，它是在 BIOS 或 UEFI 完成初步硬件初始化后启动的，负责加载 Windows 内核并启动操作系统。

启动过程
----

IPL运行后，**bootmgr**接管引导过程。**bootmgr**会读取系统盘上的**引导配置数据（BCD）**，获取有关启动选项和配置信息。如果系统配置了多个启动选项，**bootmgr**会显示启动菜单，用户可以根据需求自己选择要启动的操作系统或进入恢复模式。**bootmgr**会选择对应的操作系统加载器(`winload.exe`)并将控制权交给它,`winload.exe`负责加载内核和其它组件,最终启动Windows。

如果用户选择进入恢复模式或系统检测到启动问题，**bootmgr**会启动恢复工具，例如`winre.exe`，帮助用户修复系统问题。

真实模式和保护模式
---------

**真实模式**（Real Mode）和**保护模式**（Protected Mode）是 x86 架构处理器的两种不同操作模式。

首次打开计算机电源时，CPU在真实模式下运行，该模式使用16位内存模式。在真实模式下，处理器只能访问 1 MB 的内存空间，内存地址是通过 16 位段寄存器和 16 位偏移量结合来计算的，使用的是段：偏移的寻址方式。

实际可访问的内存范围是 0x00000 到 0xFFFFF，总共**1MB**左右，1MB显然是不满住现代操作系统和应用程序的需要的。为了规避这一限制并访问所有可用内存，**bootmgr**和`winload.exe`在bootmgr接管后将处理器切换保护模式(在64位系统中称为长模式)

bootmgr模块由16位真实模式代码和一个压缩的PE镜像组成,该印象在未压缩时以保护模式执行。16位代码从bootmgr映像中提取和解压缩PE,将处理器切换到保护模式,并将控制权传递给未压缩的模块。

保护模式其实就是现代操作系统运行的模式,它允许处理器访问 4 GB 的内存空间（32 位处理器），通过分页机制，可以扩展到更大的内存空间。同时它使用段寄存器和段描述符来管理内存，每个段可以包含高达 4 GB 的内存，而不是像真实模式下的 64 KB 限制。

引导配置数据BCD
---------

BCD数据实际上是一个二进制格式的数据库,通过BCD编辑工具可以查看和修改其中的内容。例如使用`bcedit`命令行工具,它允许用户查看、创建、修改和删除BCD中的引导项,也可以调整启动菜单、设置引导顺序，以及配置启动参数。

当BCD存储在硬盘驱动器上,其布局与注册表配置单元相同(可以通过使用`regedit.exe`,导航到健`HKEY_LOCAL_MACHINE\BCD000000`浏览其内容)。

为了从硬盘驱动器上读取数据,bootmgr运行在保护模式下,而为了使用INT 13h磁盘服务,需要真实模式下运行。为此,bootmgr将处理器执行的运行环境保存到临时变量中,临时切换到真实模式,执行INT 13h处理程序。

bootmgr初始化保护模式后,未压缩的映像将接受并从BCD中加载引导配置信息,BCD存储区包含bootmgr加载操作系统所需的所有信息,包含要加载的操作系统实例分区的路径、可用的引导应用程序、代码完整性选项以及指示操作系统在预安装模式、安全模式加载的参数等。

### BCD引导变量

引导配置数据BCD变量是Windows操作系统中用于配置引导过程的各种参数。这些变量存储在BCD存储中，并控制操作系统如何启动、加载哪些驱动程序、是否启用调试模式等。

| 变量名 | 描述 | 参数类型 | 参数ID |
|---|---|---|---|
| BcdLibraryBoolean\_DisableIntegrityCheck | 禁用内核模式代码完整性检查 | Boolean | 0x16000048 |
| BcdOsLoaderBoolean\_winPEMode | 通知内核以预安装方式加载，同时禁用内核模式代码完整性检查 | Boolean | 0x26000022 |
| BcdLibraryBoolean\_AllowPrereleaseSignatures | 启用测试签名（TESTSIGNING） | Boolean | 0x16000004 |

`BcdLibraryBoolean_DisableIntegrityCheck`变量用于禁用完整性检查并允许加载未签名的内核模式驱动程序。可以使用bcdedit来启动这个变量：

```c
bcdedit /set {current} nointegritychecks on
```

这样就可以将该变量设置为TURE。

`BcdOsLoaderBoolean_winPEMode`变量指示系统应在Windows预安装环境模式下启动，该模式本质上是具有最小有限服务的最小Win32操作系统。

变量`BcdLibraryBoolean_AllowPrereleaseSignatures`使用测试代码签名证书来加载内核模式驱动程序以进行测试。

除了上述三个又臭又长的BCD变量外，还有一些比较常见的变量，例如：

- debug，禁用或启动内核调试模式。
- default,指定默认启动的操作系统或引导项的GUID。
- osdevice,指定操作系统所在的分区。
- systeamroot,指定操作系统的根目录，通常是 `\Windows`。
- path,指定要加载的操作系统或启动项的路径。

在获取引导选项后，bootmgr执行自我完整性验证。如果检查失败，bootmgr将停止引导系统并显示一条错误信息。但是，如果BCD中的`BcdLibraryBoolean_DisableIntegrityCheck`或`BcdOsLoaderBoolean_winPEMode`设置为TRUE，则bootmgr不会执行自我完整性检查。因此，如果任意一个变量为TRUE，那么bootmgr不会注意到它是否被恶意代码篡改了。

### 引导加载程序

在加载了所有的必要的BCD参数并通过自我完整性验证后，bootmgr将要选中引导应用程序进行加载。

- 如果是重新从硬盘加载，bootmgr会选择winload.exe。
- 从休眠状态中恢复，bootmgr会选择winresume.exe。

`winload.exe`是Windows的操作系统加载程序，它负责加载操作系统内核、设备驱动程序和硬件抽象层（HAL），然后将控制权移交给内核。也同bootmgr一样，winload.exe也会检查它负责的所有模块的完整性。

`winresume.exe`负责恢复系统的休眠文件（hiberfil.sys），将系统恢复到休眠前的状态，包括打开的应用程序和文件。

这些应用程序会负责加载和初始化操作系统内核模块。然后bootmgr以同样的方式检查引导应用程序的完整性，同上面的一样，如果这俩个BCD变量任意一个为TRUE，bootmgr会再次跳过验证。

**Bootkit**：`winload.exe`为了从硬盘驱动器读取所有组件，它使用的是bootmgr提供的接口。此接口依赖于BIOS INT 13h磁盘服务。因此，如果INT 13h处理程序被Bootkit恶意软件挂载了，则该恶意软件可以棋牌你winload.exe读取的所有数据。

### 最后一步

到了引导过程的最后一步，一旦用户选择了要加载的特定操作系统实例，bootmgr就会加载winload.exe。正确初始化所有模块后，`winload.exe`将控制权传递给操作系统内核，一般是`ntoskrnl.exe`。

在`winload.exe`到`ntoskrnl.exe`的中间，有一个执行环境的转化，从用户模式切换到内核模式，意味着系统从实模式（16位）或保护模式（32位）切换到64位的内核模式。

`ntoskrnl.exe`首先会调用硬件抽象层（HAL）的初始化函数。HAL负责屏蔽不同硬件平台之间的差异，确保内核代码可以在不同硬件上运行。之后内核会初始化核心子系统，包括内存管理、进程调度、I/O管理、以及安全子系统。这些子系统是操作系统运行的基础。

内核还会启动系统进程，`System`进程。

最后，内核启动Session Manager子系统（`smss.exe`），它负责初始化系统会话、加载用户会话、启动重要服务以及配置系统环境。

而`smss.exe`会启动`winlogon.exe`和`csrss.exe`，分别负责登录界面和控制台子系统。