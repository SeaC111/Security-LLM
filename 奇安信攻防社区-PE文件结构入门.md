一、PE文件结构
--------

#### 1.1 可执行文件

可执行文件（executable file） 指的是可以由操作系统进行加载的=执行的文件。

可执行文件格式：

- windows 平台： PE（Portable Executable） 文件结构。
- Linux 平台：ELF（Executable and Linking Format） 文件结构。

用处：

- 病毒与反病毒
- 外挂与反外挂
- 加壳与脱壳
- 无源码修改功能，汉化

#### 1.2 识别PE文件

识别是否为 PE 文件：

通过 PE 文件的特征，（PE指纹）

前两字节ascii是MZ, 3C位置的十六进制对位位置ascii是 PE。

exe文件

![image-20210215175305531](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d7367aeab5a113f33cb49f78c24e3354bb47c440.png)

dll 文件

![image-20210215175804518](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-46c2935d639266e95045a92c44f486a7a07ee472.png)

这些方框内的即为 PE 指纹。

txt 文件，很明显不是 pe 文件，

![image-20210215193514290](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a1d5dc41a5b3565031abe9e671dbfa5a150203b1.png)

他是借助 `notepad` 记事本软件打开的。

二、PE文件格式
--------

定义PE格式的主要是头文件 `winnt.h` .

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e4cecdbad94fce095bd1fef54ff994a38aacda35.png)

#### 2.1 DOS 部分

```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

**e\_magic：一个WORD类型，值是一个常数0x4D5A，用文本编辑器查看该值位 MZ，可执行文件必须都是 MZ 开头。**

**e\_lfanew：为32位可执行文件扩展的域，用来表示DOS头之后的PE头相对文件起始地址的偏移。**

18个 WORD 类型，一个 LONG 类型

```c
typedef long LONG;
```

18\*2+4 = 64

**DOS MZ头**，64字节

![image-20210215195740462](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f5878b81ecbeebf58b79953c0278c36e199f107.png)

**DOS 块** 不确定大小，DOS MZ头与PE头之间的部分即为 DOS块。可随意修改，不影响。

![image-20210215200422039](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5c98fad39521f3647a0ec9de5f2c38c38d1192e9.png)

#### 2.2 PE 文件头

前四字节为PE文件头标志,可根据 DOS头的 e\_lfanew 得到。

（一个64位，一个32位）

```c
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

- `DWORD Signature;` 4字节，小端存储， 00004550 ，代表PE文件头标志

![image-20210215200617368](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b056f940fc072460bdae3403186a646ce098cadf.png)

- `IMAGE_FILE_HEADER FileHeader;` 20字节，代表PE文件表头
    
    ```c
    typedef struct _IMAGE_FILE_HEADER {
      WORD    Machine;
      WORD    NumberOfSections;
      DWORD   TimeDateStamp;
      DWORD   PointerToSymbolTable;
      DWORD   NumberOfSymbols;
      WORD    SizeOfOptionalHeader;
      WORD    Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    ```
    
    2+2+4+4+4+2+2=20
- `WORD    Machine;` 2字节，该文件的运行平台，是x86、x64还是I64等等，可以是下面值里的某一个。
    
    ```c
    #define IMAGE_FILE_MACHINE_UNKNOWN           0
    #define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
    #define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
    #define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
    #define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
    #define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
    #define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
    #define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
    #define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
    #define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
    #define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
    #define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
    #define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
    #define IMAGE_FILE_MACHINE_THUMB             0x01c2
    #define IMAGE_FILE_MACHINE_AM33              0x01d3
    #define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
    #define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
    #define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
    #define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
    #define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
    #define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
    #define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
    #define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
    #define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
    #define IMAGE_FILE_MACHINE_CEF               0x0CEF
    #define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
    #define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
    #define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
    #define IMAGE_FILE_MACHINE_CEE               0xC0EE
    ```
- `WORD    NumberOfSections;` 2字节，该PE文件中有多少个节，也就是节表中的项数。即有多少区段表。
- `DWORD   TimeDateStamp;` 4字节，PE文件的创建时间，一般有连接器填写。
    
    比如下图 `3FCCF133` 转换成十进制就是`1070395699` ,也就是 `2003-12-03 04:08:19` 。注意此时间不会随着更改程序某些字节的变化而变化。
- `DWORD   PointerToSymbolTable;` 4 字节，COFF文件符号表在文件中的偏移，现在基本没用了。
- `DWORD   NumberOfSymbols;` 4 字节，符号表的数量。如果有COFF 符号表，它代表其中的符号数目，COFF符号是一个大小固定的结构，如果想找到COFF 符号表的结束位置，则需要这个变量。
- `WORD    SizeOfOptionalHeader;` 2字节，紧随其后的**PE可选头**的大小。下图为 00E0 即为32字节。
- `WORD    Characteristics;` 2字节，可执行文件的属性，，有选择的通过几个值可以运算得到。( 这些标志的有效值是定义于 winnt.h 内的 IMAGE*FILE*\*\* 的值，具体含义见下表。普通的EXE文件这个字段的值一般是 0100h，DLL文件这个字段的值一般是 210Eh。)多种属性可以通过 “或运算” 使得同时拥有！
    
    ```c
      #define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
      #define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references).
      #define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
      #define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
      #define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
      #define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
      #define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
      #define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
      #define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
      #define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
      #define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
      #define IMAGE_FILE_SYSTEM                    0x1000  // System File.
      #define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
      #define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
      #define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.
    ```

可以看出，PE文件头定义了PE文件的一些基本信息和属性，这些属性会在PE加载器加载时用到，如果加载器发现PE文件头中定义的一些属性不满足当前的运行环境，将会终止加载该PE。

**PE文件表头，标准 PE 头，20 字节。**

![image-20210215200851504](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-15fa0131586ad863ae43a84bea713c76e3a29b88.png)

**PE文件表头可选部分，PE扩展PE头**

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;      //  标志字, ROM 映像（0107h）,普通可执行文件（010Bh）
    BYTE    MajorLinkerVersion;    // 链接程序的主版本号
    BYTE    MinorLinkerVersion;    // 链接程序的次版本号
    DWORD   SizeOfCode;           // 代码段的长度，如果有多个代码段，则是代码段长度的总和。
    DWORD   SizeOfInitializedData;     // 所有含已初始化数据的节的总大小
    DWORD   SizeOfUninitializedData;   // 所有含未初始化数据的节的大小
    DWORD   AddressOfEntryPoint;       // 程序执行入口 RVA
    DWORD   BaseOfCode;                // 代码的区块的起始RVA
    DWORD   BaseOfData;                // 数据的区块的起始RVA

    //
    // NT additional fields.
    //

    DWORD   ImageBase;                 // 程序的首选装载地址，数据机制
    DWORD   SectionAlignment;          // 内存中的区块的对齐大小，块对齐
    DWORD   FileAlignment;             // 文件中的区块的对齐大小，文件块对齐
    WORD    MajorOperatingSystemVersion;    // 要求操作系统最低版本号的主版本号
    WORD    MinorOperatingSystemVersion;    // 要求操作系统最低版本号的副版本号
    WORD    MajorImageVersion;      // 可运行于操作系统的主版本号
    WORD    MinorImageVersion;      // 可运行于操作系统的次版本号
    WORD    MajorSubsystemVersion;   // 要求最低子系统版本的主版本号
    WORD    MinorSubsystemVersion;    // 要求最低子系统版本的次版本号
    DWORD   Win32VersionValue;         // 莫须有字段，不被病毒利用的话一般为0
    DWORD   SizeOfImage;             // 映像装入内存后的总尺寸
    DWORD   SizeOfHeaders;            // 所有头 + 区块表的尺寸大小
    DWORD   CheckSum;                  // 映像的校检和
    WORD    Subsystem;                 // 可执行文件期望的子系统
    WORD    DllCharacteristics;        // DllMain()函数何时被调用，默认为 0
    DWORD   SizeOfStackReserve;        // 初始化时的栈大小
    DWORD   SizeOfStackCommit;         // 初始化时实际提交的栈大小
    DWORD   SizeOfHeapReserve;          // 初始化时保留的堆大小
    DWORD   SizeOfHeapCommit;          // 初始化时实际提交的堆大小
    DWORD   LoaderFlags;               // 与调试有关，默认为 0
    DWORD   NumberOfRvaAndSizes;    //下边数据目录的项数，这个字段自Windows NT 发布以来一直是16
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;   // 数据目录表
```

- `WORD    Magic;` , 表示可选头的类型。
    
    ```c
      #define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b  // 32位PE可选头
      #define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b  // 64位PE可选头
      #define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107  
    ```
- `IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];`
    
    这个字段可以说是最重要的字段之一，它由16个相同的IMAGE\_DATA\_DIRECTORY结构组成，虽然PE文件中的数据是按照装入内存后的页属性归类而被放在不同的节中的，但是这些处于各个节中的数据按照用途可以被分为导出表、导入表、资源、重定位表等数据块，这16个IMAGE\_DATA\_DIRECTORY结构就是用来定义多种不同用途的数据块的IMAGE\_DATA\_DIRECTORY结构的定义很简单，它仅仅指出了某种数据块的位置和长度。
    
    ```c
    typedef struct _IMAGE_DATA_DIRECTORY {
      DWORD   VirtualAddress;
      DWORD   Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
    ```
    
    VirtualAddress：是一个RVA。  
    Size：是一个大小。
    
    数据目录列表的含义如下：
    
    ```c
      #define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
      #define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
      #define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
      #define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
      #define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
      #define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
      #define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
      //      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
      #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
      #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
      #define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
      #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
      #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
      #define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
      #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
      #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
    ```
    
    在PE文件中寻找特定的数据时就是从这些IMAGE\_DATA\_DIRECTORY结构开始的，比如要存取资源，那么必须从第3个IMAGE\_DATA\_DIRECTORY结构（索引为2）中得到资源数据块的大小和位置；同理，如果要查看PE文件导入了哪些DLL文件的哪些API函数，那就必须首先从第2个IMAGE\_DATA\_DIRECTORY结构得到导入表的位置和大小。

32 为 224 字节，可扩展， 一行 16 字节，14 行

![image-20210215201354062](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dc1d6fe3966eff75a715fcb0e8cf4cef86ba56a5.png)

#### 2.3 节表

参考下边 `三、PE两种状态`

![http://image.bubuko.com/info/201409/20180921125127615796.jpg](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-80ded0f43b4f9acfb800672da2d312a01dc68105.jpg)

PE文件中所有节的属性都被定义在节表中，节表由一系列的IMAGE\_SECTION\_HEADER结构排列而成，

```c
typedef struct _IMAGE_SECTION_HEADER {    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];     // 8个字节的节区名称    union {            DWORD   PhysicalAddress;            DWORD   VirtualSize;      //节区的尺寸    } Misc;    DWORD   VirtualAddress;      // 节区的 RVA 地址    DWORD   SizeOfRawData;        // 在文件中对齐后的尺寸    DWORD   PointerToRawData;      // 在文件中的偏移量    DWORD   PointerToRelocations;  // 在OBJ文件中使用，重定位的偏移    DWORD   PointerToLinenumbers;    // 行号表的偏移（供调试使用地）    WORD    NumberOfRelocations;    // 在OBJ文件中使用，重定位项数目    WORD    NumberOfLinenumbers;    // 行号表中行号的数目    DWORD   Characteristics;        // 节属性如可读，可写，可执行等} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

顺序排列的一系列节表数量和节的数量相应数据。

分别都为 40 字节。

![image-20210215201800217](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-38c967f3d3758a79a12def531a1dddf017b4ea87.png)

![image-20210215201822701](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c892e0de455bb23cc8221ae7aea6145cf2b643f7.png)

![image-20210215201852825](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9dabe01c56abe365bda8da9ded9370bb4f55c8d1.png)

![image-20210215201915024](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-18daf515ef1859b3167667f8371c045481ad335a.png)

![image-20210215201939573](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e40a670cffdb7b953f450fcd54f526f8b55606f5.png)

![image-20210215201958288](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1d23d3b9f23619d79b422cd547f035d06790d262.png)

#### 2.4 节数据

从这往下的就是节数据了。

![image-20210215202824587](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-af282376c917e3adbfb0f02f7ef9f96fc1bca30a.png)

三、PE两种状态
--------

在执行一个PE文件的时候，windows 并不在一开始就将整个文件读入内存的，而是采用与内存映射文件类似的机制。也就是说，windows 装载器在装载的时候仅仅建立好虚拟地址和PE文件之间的映射关系。当且仅当真正执行到某个内存页中的指令或者访问某一页中的数据时，这个页面才会被从磁盘提交到物理内存，这种机制使文件装入的速度和文件大小没有太大的关系。

但是要注意的是，系统装载可执行文件的方法又不完全等同于内存映射文件。当使用内存映射文件的时候，系统对“原著”相当忠实，如果将磁盘文件和内存映像比较的话，可以发现不管是数据本身还是数据之间的相对位置的都是完全相同的。而我们知道，在装载可执行文件的时候，有些数据在装入前会被预处理，如重定位等，正因此，装入以后，数据之间的相对位置可能发生微妙的变化.

Windows 装载器在装载DOS部分、PE文件头部分和节表（区块表）部分是不进行任何特殊处理的，而在装载节（区块）的时候则会自动按节（区块）的属性做不同的处理。

①内存页的属性：

对于磁盘映射文件来说，所有的页都是按照磁盘映射文件函数指定的属性设置的。但是在装载可执行文件时，与节对应的内存页属性要按照节的属性来设置。所以，在同属于一个模块的内存页中，从不同节映射过来的的内存页的属性是不同的。

②节的偏移地址：

节的起始地址在磁盘文件中是按照 IMAGE\_OPTIONAL\_HEADER32 结构的 FileAlignment 字段的值进行对齐的，而当被加载到内存中时是按照同一结构中的 SectionAlignment 字段的值对其的，两者的值可能不同，所以一个节被装入内存后相对于文件头的偏移和在磁盘文件中的偏移可能是不同的。

注意，节事实上就是相同属性数据的组合！当节被装入到内存中的时候，相同一个节所对应的内存页都将被赋予相同的页属性， 事实上，Windows 系统对内存属性的设置是以页为单位进行的，所以节在内存中的对齐单位必须至少是一个页的大小。（对于32位操作系统来说，这个值一般是4KB==1000H; 对于64位操作系统这个值一般是8KB==2000H）。节在磁盘中就没有最小4K的限制，为了减少磁盘文件的大小，文件对齐的单位一般要小于内存对齐的单位(FileAlignment的值一般为200h，一个扇区)，这样，在磁盘中就不必为每个节最后的零头数据补足4KB的大小了。

③节的尺寸：

对节的尺寸的处理主要分为两个方面：

第一个方面，正如刚刚我们所讲的，由于磁盘映像和内存映像中节对齐存储单位的不同而导致了长度扩展不同（填充的0数量不同嘛~）；

第二个方面，是对于包含未初始化数据的节的处理问题。既然是未初始化，那么没有必要为其在磁盘中浪费空间资源，但在内存中不同，因为程序一运行，之前未初始化的数据便有可能要被赋值初始化，那么就必须为他们留下空间。

④不进行映射的节：

有些节并不需要被映射到内存中，例如.reloc节，重定位数据对于文件的执行代码来说是透明的，无作用的，它只是提供Windows 装载器使用，执行代码根本不会去访问到它们，所以没有必要将他们映射到物理内存中。.

在硬盘中文件对齐。

![image-20210215202915854](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-225d48b9b27bad99ff9a591807646e653a151aac.png)

在内存中 内存对齐

![image-20210215203711536](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a069b8ca7e92e772fe29e1b0a2d2a168f9778c64.png)

![image-20210215203734796](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8198dd00cf7f1f15d27154d0370f18340cc84b91.png)

四、DOS头
------

DOS MZ头 64 字节

![image-20210215204321131](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7b90ac8e49a7c3c1049218c0a0add850e3f84676.png)

前两字节（PE文件表示）和后四字节（通过其找到PE文件头位置）可以必须要，其他可以都为0.

![image-20210215204426143](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-90ce9469ee32354729d32ae0c07d1e92342ce14f.png)

其余以0填充后任然可以运行。

![image-20210215204544442](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5a3116bab2f9cea52d5046a48cf22955e5cf44a6.png)

DOS块，MZ头与PE文件头之间部分，是由连接器自动填写的，可随意修改。

![image-20210215204752197](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d6dbfbc16e3e41bdf003047dc4e4d888e2fa777.png)

全部以 0 填充，程序无影响。

![image-20210215204831546](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8395c88cdaf5555c4f0c0f723519f25ccdda0099.png)

五、PE头
-----

![image-20210215205100144](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-40c4ccf73e745986dbc7ed82ccf1ce2f21530d1c.png)

#### 5.1 PE标识

PE标识不能破坏，操作系统在启动一个程序的时候会检测这个标识。

#### 5.2 标准PE头

![image-20210215205904529](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-aa9c8bc470adfb732749d9f9cdd93a1b88188fdd.png)

小端存储，前两字节为 用 32 位 winhex打开 014c

![image-20210215210552746](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ee4e8b9618cd89a030305c531c1c59f98e40c2a.png)

用 64位 winhex 打开为 8664，即为 x64程序。

![image-20210215205921564](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-478c5c778d9b7432cb6ee449abfa9cef9cd16409.png)

第二个属性值为 0070，代表有 7 个节表。

![image-20210215210743935](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-402ff5bc85a42819391a3f297caccd29853733eb.png)

第三个属性值，4个字节为编译程序时产生的时间戳。修改五任何影响，这里的时间并不是我们修改导致程序显示的时间，

![image-20210215210917953](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f778e0ff5f34381e3feb47d3024a6e68297f57cc.png)

第六个属性值，扩展PE头，00f0 ,即为64位程序。

![image-20210215211154179](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd1d956e3c3eec044bfbe9c6f6736238db02e8d5.png)

最后一个属性值，2字节，代表文件属性，

2200，拆分 0000 0000 0010 0010

![image-20210215211336082](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-902d4831acc51c4b6e4a790444cd82c63bd805a9.png)

对照下图，第一位和第五位有值，可执行，应用程序可处理大于 2GB的地址。

![image-20210215211408294](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-08973bb8a12a523b2c93f29078659e7406ed747a.png)

#### 5.3 扩展PE头

32位和64位略有不同。

![image-20210215211656819](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4957346ba323f2a8903f9081bf710716979aa580.png)

六、RVA和FOA的转换
------------

RVA : 相对虚拟地址(Relative Virtual Address)，PE 文件中的各种数据结构中涉及地址的字段大部分都是以 RVA 表示的。

VA 是当PE 文件被装载到内存中后，某个数据位置相对于文件头的偏移量。 即

**RVA = 内存地址 - ImageBase**

FOA : 文件偏移值

**RVA 转换位 FOA：**

1. 判断 RVA 是否位于 PE 头，如果是 FOA=RVA,(在内存中和文件中PE头（DOS头+PE头+节表）是相同的，节数据不同，因为文件对其和内存大小可能不相等)
2. 判断 RVA 位于哪个节
    
    RVA &gt;= 节.VirtualAddress
    
    RVA &lt;= 节.VirtualAddress + 当前内存对齐后的大小
    
    差值 = RVA - 节.VirtualAddress
3. FOA = 节.PointerToRawData + 差值

七、空白区添加代码
---------

1. 构造要写入的代码
2. 在PE的空白区构造一段代码
3. 修改入口地址位新增代码
4. 新增代码执行后，跳回入口地址

这个就是一个很简单的只有弹框的程序

```c
#include <windows.h>

int main() 
{
    MessageBox(0,0,0,0);
    return 0;
}
```

反汇编：

![image-20210216103217975](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f6d5209b09877c05fffab45ba119c5aa7000e5a0.png)

```txt
MessageBox(0,0,0,0);009E1778 8B F4                mov         esi,esp  009E177A 6A 00                push        0  009E177C 6A 00                push        0  009E177E 6A 00                push        0  009E1780 6A 00                push        0  009E1782 FF 15 98 B0 9E 00    call        dword ptr [__imp__MessageBoxW@16 (09EB098h)]  009E1788 3B F4                cmp         esi,esp  009E178A E8 A6 FA FF FF       call        __RTC_CheckEsp (09E1235h)  
```

上边的要依赖导入表，所以改为下边的

机器码

```txt
6A 00 6A 00 6A 00 6A 00  E8 00 00 00 00
```

E8后边的对应的`00 00 00 00`是算出来的

```txt
要跳转的地址 - 当前地址 - 5
```

![image-20210216104803005](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-70ea829e104475a2052cfcf2462634ab55735e6c.png)

在看下 jmp 指令，因为执行完添加的代码之后要调回去执行原来的代码，

E9 后边的跟计算 E8 的一样

机器码：

```txt
6A 00 6A 00 6A 00 6A 00  E8 00 00 00 00 E9 00 00 00 00
```

![image-20210216105643222](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-79a72d46a85b913c7a076faba72b7ce6c4a8ac6f.png)

如果上面那段是保护程序的代码，那就是壳，如果破坏，就是病毒。

可以把上段代码插入到空白区，也就是 0 区域。

找到 messagebox 函数

![image-20210216110537273](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-498ee3f1c2a3c3488a8e0f21c9407f621f3ba7a6.png)

![image-20210216110550539](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9d7a84e44b07bd2a42d4f077ec07450e1db2c8b7.png)

ctrl+n,

![image-20210216110649915](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0f91b8b6cbce69d9ff9fd2afc761a2f798b11b57.png)

记下地址 `75 D2 19 30`

现在构造的代码只能在自己机器上执行，先插入代码

![image-20210216111552955](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f135bf5004cec0e9b32484476b03d537c745c08c.png)

计算

文件偏移地址转换为内存地址

![image-20210216114158284](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b901a2ff06d0a5970d8bd7f58cd8b2af3cba9b0c.png)

```txt
要跳转的地址 - E8指令当前的地址 - 575D21930 - 4AD27D38 -5 = 2AFF9BF36A 00 6A 00 6A 00 6A 00  E8 F3 9B FF 2A E9 00 00 00 00
```

跳到程序入口处 `4AD05046`

```TXT
4AD05046 - 4AD27D3E -5 = FFFDD3036A 00 6A 00 6A 00 6A 00  E8 F3 9B FF 2A E9 03 3D DF FF
```

我们还需要修改程序入口处，是入口处变为咱们添加的代码地址，然后执行完之后在跳回原本的程序入口处，

我们添加代码的地址 `026930`

![image-20210216120056681](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0021bbc5fc400a23dc2cd96a6640ad2bc4988397.png)

找到程序原本入口`00005046`，

![image-20210216120315699](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2d470ae23dd47226604281669c5be5f7fb9cbfd8.png)

修改入口点，之后保存，

![image-20210216120131328](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3415035b5aa1a12b6fdf2ae4c306345364bd6d2a.png)

测试，成功弹窗

![image-20210216120414376](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3beacb3b5e11efa5b2a0ec3c4a1236204a573145.png)

八、扩大节
-----

在空白区加入代码只限少数代码，如果要添加的代码很多，显然这种方法就不显示了。

所以我们可以适当的扩大一个节以便添加更多代码。

扩大最后一个节

步骤：

1. 分配一块新的空间，大小为 S
2. 将最后一个节的 SizeOfRawData 和 VirtualSize 改成 N
    
    N = (SizeOfRawData 或者 VirtualSize 内存对齐后的值) + S
3. 修改 SizeOfImage 的值

先看下本来的节查看

![image-20210216124452300](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e16d6edaf2a4ca4e11dceb32c07e3ef1e1786c15.png)

在文件最后添加 1000H 个字节，转成十进制就是 4096 个

利用 `UltraEdit` ，右键十六进制插入。

![image-20210216124657854](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2eca5663ce915579489010754a130a1ee251bbd3.png)

然后去修改节表属性信息，

![image-20210216125041892](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7d280d2c4488fec91bc6bb273a4460dc31510aae.png)

![image-20210216125358253](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c7225fa29b76f55dd454cca7b765ed622000a5bf.png)

最后修改镜像大小

![image-20210216130410807](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2fe75a8c3abd26c9fc5be2d3dbd471b765a75cc1.png)

![image-20210216130424897](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bad2853b0b4a952e6ae07cd94c0975a1b46a470a.png)

原来是 `00500700` 改为 `00600700`

![image-20210216130813504](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f5e1cd376a4c2003a06e7a4836e7fb6a7c785dc.png)

改完之后程序运行不影响，但扩大了节。

修改后的

![image-20210216130937233](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-22beb993bcbdcd0aafbc57b182fe2cd458007d71.png)

九、新增节
-----

如果添加代码时，空白区不够，我们可以无限的扩大最后一个节，我们还可以新增节，在新增节里放我们的数据。

新增节步骤：

1. 判断是否有足够的空间，可以添加一个节表。
2. 在节表中新增一个成员。
3. 修改 PE 头中节的数量
4. 修改 sizeOfImage 的大小
5. 在原有数据的最后，新增一个节的数据（内存对其的整数倍）
6. 修正新增节表的属性。

还可直接使用 PEtools 添加

![image-20210216162700707](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5773858216ed52e9b75253e22348e516ebdc0896.png)

十、导出表
-----

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;    // 一般为0
    DWORD   TimeDateStamp;      // 导出表生成的时间戳，由连接器生成。
    WORD    MajorVersion;       // 主版本号
    WORD    MinorVersion;       // 副版本号
    DWORD   Name;              // 模块的名字。
    DWORD   Base;              // 序号的基数，按序号导出函数的序号值从Base开始递增。
    DWORD   NumberOfFunctions;   // 所有导出函数的数量。
    DWORD   NumberOfNames;       // 按名字导出函数的数量。
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

一个可执行文件是由多个 PE 文件组成的。

还有其他 DLL pe 文件。

![image-20210216164554067](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f1cf51c516ecafb51d82b6250603a5dae1874dd9.png)

通常 dll 既有导入表，也有导出表。Exe 通常只有 导入表。

> exe程序中通常会使用动态链接库dll中的函数；
> 
> dll相当于一个独立的模块，dll中的代码并不会编译到exe程序中；
> 
> 这就产生了一个问题：exe怎么知道dll中的代码在什么位置；
> 
> 这就需要dll提供一个清单，这个清单中能清晰说明有多少个函数、它们的名字、地址；
> 
> 导出表就是这样的一个清单；

作用:记录了导出符号的地址,名称,与序号  
(提示:exe文件中很少有导出表的,大多数dll都有导出表,某些存放资源文件的dll就没有导出表)

导出表在扩展PE头的最后一个成员数组的第一个结构体， 8个数组，1个数组 8字节

![image-20210216165636632](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b4aabf5dca48af92ef673b9d4099c98851fbfc2d.png)

十一、导入表
------

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

> 在编程中常常用到“导入函数”(Import functions),导入函数就是被程序调用但其执行代码又不在程序中的函数，这些函数的代码位于一个或者多个DLL中，在调用者程序中只保留一些函数信息，包括函数名及其驻留的DLL名等。
> 
> 于磁盘上的PE 文件来说，它无法得知这些输入函数在内存中的地址，只有当PE 文件被装入内存后，Windows 加载器才将相关DLL 装入，并将调用输入函数的指令和函数实际所处的地址联系起来。这就是“动态链接”的概念。动态链接是通过PE 文件中定义的“导入表”来完成的，导入表中保存的正是函数名和其驻留的DLL 名等。

十二、重定位表
-------

> 既然有VA这么简单的表示方式为什么还要有前面的RVA呢？因为虽然PE文件为自己指定加载的基地址，但是windows有茫茫多的DLL，而且每个软件也有自己的DLL，如果指定的地址已经被别的DLL占了怎么办？如果PE文件无法加载到预期的地址，那么系统会帮他重新选择一个合适的基地址将他加载到此处，这时原有的VA就全部失效了，NT头保存了PE文件加载所需的信息，在不知道PE会加载到哪个基地址之前，VA是无效的，所以在PE文件头中大部分是使用RVA来表示地址的，而在代码中是用VA表示全局变量和函数地址的。那又有人要问了，既然加载基址变了以后VA都失效了，那存在于代码中的那些VA怎么办呢？答案是：重定位。系统有自己的办法修正这些值，到后续重定位表的文章中会详细描述。既然有重定位，为什么NT头不能依靠重定位采用VA表示地址呢（十万个为什么）？因为不是所有的PE都有重定位，早期的EXE就是没有重定位的。

步骤：

1.编译的时候由编译器识别出哪些项使用了模块内的直接VA，比如push一个全局变量、函数地址，这些指令的操作数在模块加载的时候就需要被重定位。

2.链接器生成PE文件的时候将编译器识别的重定位的项纪录在一张表里，这张表就是重定位表，保存在DataDirectory中，序号是 IMAGE\_DIRECTORY\_ENTRY\_BASERELOC。

3.PE文件加载时，PE 加载器分析重定位表，将其中每一项按照现在的模块基址进行重定位。

以上三步，前两部涉及到了编译和链接的知识，跟本文的关系不大，我们直接看第三步，这一步符合本系列的特征。

在查看重定位表的定义前，我们先了解一下他的存储方式，有助于后面的理解。按照常规思路，每个重定位项应该是一个DWORD，里面保存需要重定位的RVA，这样只需要简单操作便能找到需要重定位的项。然而，Windows并没有这样设计，原因是这样存放太占用空间了，试想一下，加入一个文件有n个重定位项，那么就需要占用4\*n个字节。所以Windows采用了分组的方式，按照重定位项所在的页面分组，每组保存一个页面其实地址的RVA，页内的每项重定位项使用一个WORD保存重定位项在页内的偏移，这样就大大缩小了重定位表的大小。

有了上面的概念，我们现在可以来看一下基址重定位表的定义了：

```c
typedef struct _IMAGE_BASE_RELOCATION {    DWORD   VirtualAddress;    DWORD   SizeOfBlock;//  WORD    TypeOffset[1];} IMAGE_BASE_RELOCATION;typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```

VirtualAddress：页起始地址RVA。  
SizeOfBlock：表示该分组保存了几项重定位项。

TypeOffset：这个域有两个含义，大家都知道，页内偏移用12位就可以表示，剩下的高4位用来表示重定位的类型。而事实上，Windows只用了一种类型IMAGE\_REL\_BASED\_HIGHLOW 数值是 3。

此内容转载 <http://blog.csdn.net/evileagle/article/details/12886949>

参考文章：

<https://www.bilibili.com/video/BV18r4y1K7sa>

<https://blog.csdn.net/adam001521/article/details/84658708>

<https://blog.csdn.net/evileagle/article/details/12886949>

<https://blog.csdn.net/chenlycly/article/details/53378196>

此文章转载于： <https://www.freebuf.com/articles/network/265889.html>