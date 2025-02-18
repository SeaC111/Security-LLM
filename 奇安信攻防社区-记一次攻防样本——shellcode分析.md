0x01 背景
=======

书接上文，笔者发的一篇对某红队钓鱼样本分析的文章：[记一次（反虚拟+反监测+域名前置）钓鱼样本分析及思考](https://forum.butian.net/share/3701);

本文主要针对上文中样本使用的shellcode展开分析，非常详细的记录了笔者分析该shellcode过程；以及对其使用的相关技术进行分析拆解；

0x02 分析
=======

对于shellcode我们首先可以通过一些模拟器来查看其内部的大致函数调用情况，然后有针对性的开展分析；

一、自动化模拟分析探虚实
------------

笔者一般使用speakeasy这款工具，`https://github.com/mandiant/speakeasy`

模拟运行的结果如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6f3189b2366f92e3cd6fff62988697fa82955b3c.png)

如上，可以看到这个样本前面做的一些动作，拿到几个关键函数的调用地址，其中比较明显特征的有：CreatFileMappingA、MapViewOfFile，后面也调用了这两个函数，结合我们dump下来的shellcode文件大小（3百多kb），不难看出里面应该是藏了一个pe文件，这里的逻辑是把藏于其中的pe文件从文件格式映射成内存格式，并且还调用了VirtualProtect来修改内存权限属性，应该是要修改相关数据；

在大致知道了这个情况之后，我们可以做一些尝试，比如直接去dump下来的shellcode文件里面找，是否存在相关pe文件：

二、妙计上心头直捣黄龙
-----------

我们在dump下来的shellcode文件里面查可执行文件：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d61207fe40f0b2585cc27ada80067bead60f2d86.png)

上图是我们查看shellcode中pe文件dos头的情况，可以发现有一个`4d5a`开头的地方，但是0x3c偏移，以及后面的pe头都没有，所以大概率不是；也有可能是：是，但是其他数据被加密了，需要动态解密还原出来，然后才去拉伸；所以这里我们尝试走捷径失败；

三、老老实实正常分析
----------

那没办法就直接怼dump的文件把：

如下，可以看到，上来第一部分就是调用`sub_188e6`（这个地址是内置的一个相对地址+获取的运行时绝对地址拿到的和call $+5,pop 操作类似），然后下面的第二部分就是传入几个参数，调用第一部分返回的rax函数，r8d传入的像是特征码；（和CobaltStrike有点像，但是前面头不符合，并且没有出现pe文件头的特征）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2223660327b169598ff2b92fa0f94bbd3a6db12e.png)

我们跟进`sub_188e6`,直接ida f5看逻辑（一般来说分析shellcode的时候是没有比较逐字节扣的，能f5直接f5即可，但是有些做了编码壳的shellcode还是需要先简单分析壳逻辑，动态调试脱壳后再f5即可；例如：之前[笔者分析的一个带编码壳的shellcode](https://minhangxiaohui.github.io/2024/07/15/%E6%9F%90%E5%A4%A7%E5%8E%82%E7%BA%A2%E9%98%9F%E9%92%93%E9%B1%BC%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90/) 中的shellcode）

如下图，上来第一部分对一个v13数组变量进行构造赋值操作，然后第二部分调用`sub_18c66`对v9变量进行赋值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b4e7f305bf874a4ad84ee30a981d746a81e3a7b7.png)

### 找PE

跟进`sub_18c66`，其实现如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c3ae7dca4efe2eb4fe07c38c9c366d4d229b1f88.png)

简单转化下出现数据的编码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-207229c904ee24ca05b327893ee943a746466ebe.png)

上图，我们可以直观的看出，做了一个递减的循环，寻找当i对应地址的WORD为`YA`的时候，并且其0x3c偏移处的值在`0x40-0x400`之间，并且i+（0x3c偏移处地址的值）的地址对应值的WORD为`0x4a51`(JQ)的时候，i的值；

i的起始取值来自`sub_18b66`，如下，该函数就是返回函数的返回值；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-17efc61e6dfae32a763dab894cdba9dd961ebcac.png)

所以我们简单总结就知道了v9的赋值函数`sub_18c66`,其实就是从函数的返回地址开始，往前找，找到一个符合上述分析条件的地址；并且我们稍加留意可以看到条件当中出现了0x3c这个敏感偏移；这不就是回溯找PE文件位置吗，只不过这里攻击者做了特征隐藏，DOS头的MZ到这里变成了AY，PE头的PE到这里变成了QJ；（难怪刚刚我们上面查pe文件的时候没找到）

按照这个逻辑我们再次查看shellcode的二进制文件，如下图可以看到就是在刚开始的地方；（结合上面我们直接分析的开头代码，这里有点像反射dll加载，但是又不全是，因为做了一些改良，往前面头部加了一些lj代码）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ec83b923cb66522995f85a07e35e67ec28d2cd46.png)

然后我们回到`sub_188E6`的主逻辑上；

如下：先是对v13数组前两个元素做一个条件判断（这个条件肯定是成立的，上面的赋值就是直接这样赋值的，取低32位，比较也成立，所以这里就是一个恒真式），接着调用`sub_18cf6`传入v13变量地址；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b16d44bb4eddf07b6757b536d62583a7bb9514a2.png)

### peb找函数地址

跟入`sub_18cf6`函数：

其实现如下：

```php
\_\_int64 \_\_fastcall sub\_18CF6(\_QWORD \*a1)  
{  
  int v1; // eax  
  \_\_int64 result; // rax  
  \_\_int16 v3; // \[rsp+0h\] \[rbp-68h\]  
  unsigned \_\_int16 v4; // \[rsp+0h\] \[rbp-68h\]  
  \_\_int64 v5; // \[rsp+8h\] \[rbp-60h\]  
  int v6; // \[rsp+10h\] \[rbp-58h\]  
  unsigned int \*v7; // \[rsp+18h\] \[rbp-50h\]  
  int v8; // \[rsp+20h\] \[rbp-48h\]  
  int v9; // \[rsp+20h\] \[rbp-48h\]  
  \_\_int64 \*i; // \[rsp+28h\] \[rbp-40h\]  
  unsigned int \*v11; // \[rsp+30h\] \[rbp-38h\]  
  unsigned int \*v12; // \[rsp+38h\] \[rbp-30h\]  
  unsigned \_\_int8 \*xx\_address; // \[rsp+40h\] \[rbp-28h\]  
  \_BYTE \*v14; // \[rsp+48h\] \[rbp-20h\]  
  unsigned \_\_int16 \*v15; // \[rsp+50h\] \[rbp-18h\]  
​  
  for ( i \= \*(\_\_int64 \*\*)(\*(\_QWORD \*)(\_\_readgsqword(0x60u) + 0x18) + 0x20i64); i; i \= (\_\_int64 \*)\*i )  
  {  
    xx\_address \= (unsigned \_\_int8 \*)i\[10\];  
    v3 \= \*((\_WORD \*)i + 0x24);  
    v8 \= 0;  
    do  
    {  
      v9 \= \_\_ROR4\_\_(v8, 13);  
      if ( \*xx\_address < 97u )  
        v1 \= \*xx\_address;  
      else  
        v1 \= \*xx\_address \- 0x20;  
      v8 \= v1 + v9;  
      ++xx\_address;  
      \--v3;  
    }  
    while ( v3 );  
    if ( v8 \== 0x6A4ABC5B )  
      break;  
  }  
  v5 \= i\[4\];  
  v11 \= (unsigned int \*)(\*(unsigned int \*)(\*(int \*)(v5 + 0x3C) + v5 + 0x88) + v5);  
  v12 \= (unsigned int \*)(v11\[8\] + v5);  
  v15 \= (unsigned \_\_int16 \*)(v11\[9\] + v5);  
  v4 \= 6;  
  while ( 1 )  
  {  
    result \= v4;  
    if ( !v4 )  
      break;  
    v14 \= (\_BYTE \*)(\*v12 + v5);  
    v6 \= 0;  
    do  
      v6 \= (char)\*v14++ + \_\_ROR4\_\_(v6, 13);  
    while ( \*v14 );  
    if ( v6 \== 3960360590  
      || v6 \== 2081291434  
      || v6 \== \-1850750380  
      || v6 \== 2034681371  
      || v6 \== 122922236  
      || v6 \== \-751679228 )  
    {  
      v7 \= (unsigned int \*)(v11\[7\] + v5 + 4i64 \* \*v15);  
      switch ( v6 )  
      {  
        case \-334606706:  
          a1\[2\] \= \*v7 + v5;  
          break;  
        case 2081291434:  
          a1\[1\] \= \*v7 + v5;  
          break;  
        case \-1850750380:  
          a1\[4\] \= \*v7 + v5;  
          break;  
        case 2034681371:  
          a1\[5\] \= \*v7 + v5;  
          break;  
        case 122922236:  
          a1\[3\] \= \*v7 + v5;  
          break;  
        default:  
          \*a1 \= \*v7 + v5;  
          break;  
      }  
      \--v4;  
    }  
    ++v12;  
    ++v15;  
  }  
  return result;  
}
```

可以明显看出，函数`sub_18cf6`存在两部分，第一部分是一个for循环，第二部分是一个while循环：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d50e521734c29ee7f0a3ef3b45f7888d104d3099.png)

我们先不着急分析详细逻辑，我们先在看下大的方面这个函数大概率是用来干啥的，首先我们从主函数的`sub_188E6`看，其调用这个`sub_18cf6`是没有获取其返回值的，其次传入的是一个指针；

然后我们结合`sub_18cf6`内容，先看下哪里对传入的指针做了处理，如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1d26dd83d209e569f720de92669a13186474771a.png)

上图中可以看到，在`sub_18cf6`的第二部分while循环里面，对指针指向的数组的几个元素做了赋值操作；所以分析到这，我们也不难看出这个函数其实就是在给主逻辑函数里面的v13变量（指向数组首地址的指针）赋值；

然后我们再来看`sub_18cf6` 里面两部分详细逻辑：

第一部分：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6b8f45133edb78d283f0b072272e06b104dda893.png)

上图首先通过fs拿peb拿ldr\_list,遍历list，拿basedllname

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-91af90450731716fd57f3c6ce5ac9af72a92aca4.png)

接着，计算计算dllbasename的特征码（特征码算法：name，逐位小写转大写累加上次结果，结果循环右移13位），找到结果是`0x6a4abc5b`的这个特征码就结束；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-00b0419d7e96cf5bbf2044db1ae4bad816c7f4de.png)

然后获取dllbase地址和以及获取导出表地址，i\[4\]就是0x20的相对偏移（相对InMemoryOrderLinks内存加载顺序列表），对应的就是dllbase；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-eba29bd72dd26ba8f56dcf6554e56d373a8dcbac.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ca722b81aa4e0676a9f0b4570d663bdc9e0d9a63.png)

接着取导出函数名称表、导出函数序号表：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c8ba9b9bbcab411101af048039e66e42f9ef4901.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e00bf7f115b8a135a93c0be2d33bbe6e2d999733.png)

然后就是第二部分的while循环了，非常直观的取导出名称，然后计算特征码（方法和上面一样就是不做大小写转换了）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5e04b38111770b5491f06f4c8b0e1ee698960879.png)

内置了几个要找的特征码，当匹配到的时候，就找到对应函数的地址，通过传入的指针，带出返回

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-26828c7ab30c73881ef2424ae08503714696e818.png)

简单总结，`sub_18cf6`这个函数的其实就是一个类似初始化操作的函数，找到之后几个要使用的函数地址；

然后回到主逻辑：`sub_188E6`:

一个恒真的if(`sub_19086`是直接返回0)，调用`sub_19096`，传入的参数还是v13指针（也就是刚刚做了些函数地址赋值的数组）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-67666d4ee8153ee7b5f065fba9fa96a745c8f280.png)

跟入`sub_19096`，其实现如下，还是一样，我们可以看到主逻辑其实没有获取其返回的值，结合我们观察传入指针的，这里其实和上个函数差不多，也是个传入指针指向的内容做一些初始化赋值，然后通过指针带回；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4161ee80c66f2b99512ba0597a342e32a72d398e.png)

我们来详细看下，直接把a1指针指向的数组第一个值，转函数指针执行，传入的参数是`kernel32`,并且函数的返回值v2被用作下面几个函数执行的参数，这里稍有分析经验的师傅应该一眼就能看出，a1\[0\]就是GetModuleHandle()函数的地址，a1\[1\]就是GetProcAddress()地址；（这里如果看不出来也没关系，我们只要动态调试、或者通过上面分析的特征码算法计算，就知道上面找到的那几个函数地址到底是哪些函数的地址了）；所以下面其实就是通过前面找到的基础函数，动态再找到几个函数给传入指针对应的值做初始化，并带回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-9410ffbfe6df3725eb140804607c253fd226d4b5.png)

```php
a1\[2\] = LoadLibraryA  
a1\[5\] = VirtualPortect  
a1\[8\] = CloseHandle  
a1\[9\] = MapViewOfFile  
a1\[10\] = CreateFileMappingA
```

然后回到主逻辑`sub_188E6`,一个获取我们从shellcode中到的pe文件的pe头的Characteristics`**IMAGE_FILE_BYTES_REVERSED_HI**`值操作（这个值之前是用来判断文件字节是大尾还是小尾的，现在废弃了，也就是说该字段不会对windows对pe的加载又任何影响了）这里估计攻击者做了一些“文章”，利用windows现在不认这个，他有可能会把配置写到的这个地方，我们接着看判断下的逻辑代码；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-eba831af69ae9ad6276543b39e1756985b475ff6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-42d66c0f6d6b8366d2bc9a175e20d34adfd1464b.png)

两个逻辑都是对v6做了赋值，这个v6后面用到了，所以这里留意下；执行`sub_19396`这个函数，参数就一个不同，最后一个参数，如果IMAGE\_FILE\_BYTES\_REVERSED\_HI是1，传入的参数是64，如果是0，传入的就是4；

### 开辟内存空间

跟入`sub_19396`函数，其实现如下,首先很明确，主逻辑是要取其返回值的，所以分析的时候我们要重点关注v8；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5d1fc07bc4892f394c9d011b27b4fbc49a6c9cb0.png)

通过分析我们可以发现，第一个参数就是指针，指向上面获取到的函数地址；这个`sub_19396`主要就是调用里面函数进行了一些操作，如下：

先是调用CreatFileMapping+MapViewOfFile创建一个和内置pe文件内存大小的内存映射(CreatFileMapping的时候申请的权限是0x40（64）, 可读可写可执行)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c4f5019e7c8f21a3d09f7e81af520db7ea5d07bc.png)

然后判断a4是否等于4，等于就调用VirtualProtect把内存属性调成可读可写

最后return的是创建的内存映射地址；

然后回到主逻辑里面，获取PE内存大小，并且把刚刚返回的内存映射地址做了一个初始化清0操作（从这里我们就能get到，攻击者上面`sub_19396`做的组合操作，其实就是用来申请内存空间，然后有一个控制位来控制要申请的内存空间权限，控制位是pe头里面的Characteristics`**IMAGE_FILE_BYTES_REVERSED_HI**`值，应该是一个配置项，生成payload的时候是可控的；简单说：攻击者利用CreatFileMapping+MapViewOfFile申请内存空间，来绕过杀软对VirtualAlloc的监控，并且存在一个配置影响申请空间的权限，因为有的杀软对带执行权限的内存是会做非常严格的扫描或者多的处理的，所以这里攻击者将其做成可以调整的配置，这个配置项非常微妙的嵌入在pe头中微软弃用的一个地址），

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-889134c11d5fdd06e60af15685a3beee62ea590d.png)

然后又获取了一个弃用地址的值，pe头中的NumberOfSymbols的值（符号表中的项数。 此数据可用于查找紧跟在符号表后面的字符串表。 映像的此值应为零，因为 COFF 调试信息已被弃用。）；

接着调用sub\_194b6函数，并传入四个参数，分别是：内存开辟并做了初始化空间的地址、shellcode藏着的peheader的地址、pe的基址、pe头的NumberOfSymbols的值；

跟入`sub_194b6`函数，其实现如下，首先我们知道其存在一个return，并且我们可以看处，return的是一个地址（下面）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2e582ede5c9351ccd4bc899bbd4c77a0177e45c6.png)

`sub_194b6`逻辑做了几个操作：

1、如果pe头的numberofsymbols字段不为0，那么这里直接return 申请空间-区块对齐大小（pehead+0x38）

2、将pe头的内容复制到申请的空间

3、判断pe头`IMAGE_FILE_RELOCS_STRIPPED` 的值，如果为1，就开始对复制到申请的内存空间的PE文件头部内容去特征；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ce07ce4e193fe6a26ade57303500d95fbd6dc08d.png)

简单总结`sub_194b6`就是把pe头复制到的映射的空间，并做了去特征化；

回到主逻辑`sub_188E6`，调用`sub_19576`，如下图，传入参数分别是：内存映射的空间地址、shellcode中影藏的pe头地址、pe基址、以及两个引用（大概率是用来回传东西的）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-3e197f46eed3cf054fcdebbe80c8ab777ed6ad6b.png)

### PE文件拉伸到内存

跟进`sub_19576`，稍作解析，其实现如下，不难看出，这里其实就是对区节遍历，循环复制，将pe文件区节内容复制到的内存映射空间里面去；除此之外，就是对a4、a5的赋值，赋值逻辑是：找到带执行权限的区节，a4赋值对应区节的开始地址，a5赋值对应区节的大小

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d8912af3f0a70caac9869bdbfe964ab2fd328bb1.png)

然后回到主逻辑，调用`sub_19676`，传入参数分别是：v13、内存映射地址、shellcode影藏的pe头地址、pe基址、pe头中的numberofsymbols的值

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-280ed8d02e9d026f568069751c1d440a391b040b.png)

跟入`sub_19676`函数，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b969501cfe8b2446ee8e42f7814e6c9f938eb719.png)

### 解密还原导入表

我们来详细看下其逻辑：

首先，对v6赋值，通过a2（申请内存映射地址）+a3（0x50）（加载后pe文件的内存总大小）-0x40，拿到的是加载到内存之后的最后40个字节的地址；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-331a912fd7a3832f057f900d3b2be0556147901d.png)

然后遍历，这个影藏pe的导入表，获取导入模块的名称赋值到刚刚的v6处；随后作为参数调用`sub_18b76`,随之传入的参数还有，0x40和a5（pe头中被弃用的numberofsymbols的值）

这个`sub_18b76`实现如下：其实就是一个解密函数，我们可以把传入的numberofsymbols的值看作密钥，对刚刚获取的导入模块名称进行解密（这里不难看出攻击者做了静态分析对抗，隐藏导入模块的名称，所以这里需要恢复）；解密方法也非常简单，就是一个异或解密，numberofsymbols一共四个字节，循环使用；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e1c3cd4904a2d92d87097cf526f6dae8a24e46d1.png)

然后回到`sub_19676`，在拿到解密后的名称后，调用LoadLibrary函数加载对应模块：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-09c662599f163ce570fabeef961e601379b8604a.png)

然后就是用相同的思想，遍历对应模块的导入函数，还原导入函数的名称：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7a407718f5b42177523c3cdba66f4644a22b539a.png)

最后return之前，把刚刚暂用的pe最后0x40个地址恢复0x0;

简单总结`sub_19676`函数做的事情，解密还原导入模块名称和对应的导入函数名称；

### 解密可执行区节

然后我们回到主逻辑`sub_188E6`，出来之后直接调用`sub_18b76`，解密刚刚获取到的可执行段的内容（v11是pe可执行段起始地址，v8是长度），解密方法和上面解密导出函数名称一样，密钥放到了pe头中微软遗弃的字段:numberofsymbols;(这里也可以看出，攻击者为了免杀选择了将pe中的可执行段加密，因为一般带执行权限的段会被杀软重点“照顾”)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-df550e38e23aa52514c508867d389d82cf07a1c0.png)

### 修复重定位表

接着调用`sub_19366`,传入两个参数，一个是pe内存映射的地址，一个是shellcode中的隐藏的pe的peheader的地址，没有获取其返回值，其实实现如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-167897126ce292f813fff2e1eaf8f81fab25b9ab.png)

上图简单分析，不难看出，其利用之前文件格式的pe，来修复映射到内存后的pe的重定位表：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f1395131dd3d01a01d71bf3e75650456ae5bdd71.png)

然后回到`sub_188E6`，其接着调用`sub_19456`,传入参数分别：v13（指向一堆函数调用地址数组的指针）、加载到内存的恶意PE可执行段地址起始位置、可执行段的长度、最后一个参数a4（取值4或者64，上面分析，我们知道其取决于pe头的Characteristics`**IMAGE_FILE_BYTES_REVERSED_HI**`值是否为1，为1就是64，反之则为4，大概率是攻击者的一个配置项）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5b3f8b008d26c21b860397c45e1b41e0332c331d.png)

`sub19456`其逻辑实现如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f78f51d4f78293fbfe964bfda8c30867d686a728.png)

如果a4为4，也就是之前隐藏在shellcode中的文件格式pe的pe头其Characteristics`**IMAGE_FILE_BYTES_REVERSED_HI**`值为0，那么这里就会调用VirtualProtect函数将，现在加载到内存的pe的可执行段权限修改为可读可执行，这里攻击者这么做的目的也非常明显，因为上面我们分析`sub_19396`的时候，如何a4==4，其将申请的空间的权限，利用VirtualProtect将其修改成可读可写了，没有执行权限，那么这里攻击者经过上面一堆操作，差不多就是手动的把文件格式pe以内存格式（也就是我们常说的拉升）加载到了内存的一个地址，并且做了一些还原，对可执行段代码进行解密，对导入函数表解密还原，对重定向表进行修复等相关操作；做完这些操作自然就是要开始运行了，所以给可执行节区的内存空间要加个可执行权限；如下图：a1+0x28，其实就是v13里面的第六个数组，v13\[5\]，也就是VirtualPortect；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-754973f92fed5933f36f5cdbfb5afc545749d742.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-3fc869c8cea1ef891b74f8d1ff45acad045cb64f.png)

然后回到主逻辑`sub_188E6`,对v13里面的进行清空，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a691b00a2d9a541aa9f19d2d138c0bbc47a7ad29.png)

一个条件判断，获取PE\_head\_Characteristic的值，判断第13位是否为1，这个位一般是用来标志映像是系统文件的；如果该标志位为1，v2等于pehead的文件可选头里面的SizeOfInitializedData的值，反之，v2等于pehead的文件头里面的TimeDateStamp和PointerToSymbolTable的组合部分值，前者的后两个字节+后者的前两个字节，不难看出这v2的值应该也是受攻击者的配置项影响的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6d5db6e90b4b750b97a18e2a51beae6674442af3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-bc0e7029585abd61b1e91ba61766ac507c4a332d.png)

### 调用DLL主函数初始化

然后继续看，拿到这个v2用来做什么了，v10=v5+v2，v5是映射到内存pe的基址，那么这里应该是基址加相对偏移拿到的拿到一个绝对地址；

最后直接把v10强行转化成指针函数执行了，传入了三个函数，v5，1，a1分别的实际含义是：映射到内存的恶意pe的基址、1、最先传入的参数（没有：0）；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-63d42e3c9cc575f94b42e4e6bdeca2598d4b5148.png)

最后返回的rax，就是v10的值（这个大概率就是一个内置好的函数地址，攻击者通过是可以通过配置更改，调用的函数的，这里应该是有两个选择，因为v2的取值有两种可能，是看攻击者怎么配置的）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ea70e1f59ac33dfd703651a54c6860dae40ea978.png)

简单总结`sub_188e6`这部分逻辑，就是找到隐藏在shellcode中的恶意pe文件，该pe文件被做了很多手脚，于是做了很多操作还原，并申请空间，将其拉伸到内存中，中间做了一些免杀手段，最后调用拉伸pe中的某个函数的地址； 返回的地址就是调用的地址；

到这，我们就需要动态调试了，可以直接把开辟的用来加载恶意pe的空间，直接dump下来，我们再分析对应调用的函数实现；

如下图是最后调用代码段中v10对应的函数的时候，开辟空间里面的相关内容，

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-71ff787b865e3cd25e17e0b74bf89687c5029a09.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a07398b17b1c034ff47ad8e3bcf873dbaccc851a.png)

拿到这个v10 call调用的地址：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5e338921335e70b6de52ab20017a614455829dac.png)

ida里面直接找到对应偏移的函数：`sub_20b48`(v10 对应的函数)：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6e4f9c8b03bd5098f62995cc379ad715c6893cf7.png)

分析逻辑，上来一个条件判断第二个参数是否为1，是则调用`sub_282d0`，（上面我们分析引导加载的函数最后调用v10传入的第二个参数就是1）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6c61d8bacad0cfcf151a7e4cc9026bcab824312e.png)

里面越界内存分别调用的函数是GetSystemTimeAsFileTime、GetCurrentThreadId 、GetCurrentProcessId 、QueryPerformanceCounter

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a7de22bd8f8de5aea6ce952746c37d10f71d8188.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-934d2fe3769e23560edcbc1782ea28ea284ff7db.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d6bf2f8fd5e60183508269429d5172e672ecbdb8.png)

这里逻辑大致就是通过GetSystemTimeAsFileTime获取当前时间戳，异或线程ID和进程ID得到一个值v2；然后QueryPerformanceCounter获取另一个时间戳v4，通过位移运算以及和v2进行一些异或运算得到v0，对v0做了一个判断是否等于指定值：0x2B992DDFA232，等于就赋值0x2B992DDFA233，最后使用v0给`qw_47ef0`赋值，并返回；（乍一看感觉是攻击者在做什么校验，其实不然，这里是在计算64位的security\_cookie，就是我们编译的时候开GS生成的代码）

分析到这，我们不难发现其实这个v10call，也就是`sub_20B48`其实就是恶意加载的pe文件（dll）的dllmain或dllentrypoint，我们看其逻辑和参数和dllmain都是一样的，这里的第二个参数就是fdwReason，为1一般是首次加载dll触发，再加上上面的security\_cookies计算；参考cobaltstrike，反射调用引导函数修复加载dll之后也是直接跳去dll主逻辑；

所以我们基本可以把重点定位到如下函数`sub_209e8`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-038ba65029d3740162d00d420ddc2409df225bae.png)

`sub_209e8`实现逻辑如下，接收两个参数，这里我们可以看到a2为1的时候，先调用的是上面那次，此时传入的v6是被加载恶意pe的基址，a2是1

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-cde2afd452439e4e8d72e8570921c9b27831a0c0.png)

case1情况下，先是两个条件判断，`sub_20d88`和`sub_249B0`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1e817c20ba73c6f1fa1d0ed6813d4f765ed51710.png)

第一个if，sub\_20d88实现如下，可以看到调用了一个函数，然后根据函数是否调用成功返回eax，函数如果返回是0，`sub_20d88`也返回0，反之返回1；此外还把函数的返回值存到`qw_4c930`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-581d10cb48b0425a680327ff8ff4fa16938a1c54.png)

调用的函数是：GetProcessHeap，这里是获取进程的堆句柄；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e178db4b14630b4bca96f19c83b6727713c65089.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d06452fa4003408e8c4c8be0d7152fa653a14301.png)

然后`sub_249B0`这个判断，其实现如下，没有接收参数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-180cd5158336fad333885232775d0a50aa87fe29.png)

先调用`sub_1f1a8`函数，该函数实现如下：先调用函数RtlEncodePointer获取返回值，然后作为参数调入下面几个函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0c4ce90fb1e4dc522e70586ecb0e8c87618aca09.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6c4e3ae0252e31b87b10e9972c327d3c18450e52.png)

RtlEncodePointer不是windows公开的api，看名称像是获取一个“被编码/被加密”指针；

在如下的几个函数里面，传入刚刚RtlEncodePointer的返回，这些函数都是赋值函数，把返回值赋值给一些指定处；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5f1a90f40fd25bc6b37ec758ec073bc48aa1b4b8.png)

如：`sub_20de8`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-36d992c34afca311f7b9c4782cd718bf6210e055.png)

最后调用`sub_2312c`并返回，其实现如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5a1ab7b63e5c659d32432bd58947b887d754c2d3.png)

如上图，`sub_2312c`也是一个赋值函数，这个函数先调用GetModuleHandle()拿到kernel32.dll的基址，然后调用GetPorcAddress，获取上述的函数的地址并保存到指定处（`qw_525a0`）,存的时候还做了一个异或加密，key是：`2b992ddfa232`;最后返回GetCurrentPackageId的地址；

简单总结：`sub_1F1A8`,就是做了很多初始化的赋值操作，获取函数地址值等；

然后我们回到`sub_249B0`，一个判断，判断条件`sub_22f14`，做赋值操作,将`sub_23070`函数结果返回`dw_479c8`，然后调用另一个函数`sub_24a30`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f544cc7524e5a36f57dec330f8905c2e48621d78.png)

这些函数的逻辑有些晦涩难懂，不太好分析；

四、恍然大悟跳出来
---------

到这其实我们可以看出，shellcode中的引导加载后调用v10（dllmain），这里就是在做初始化；关键call相关逻辑大概率是初始化做完之后：

跳回shellcode开始处，我们可以看到`sub_188e6`返回的rax，接下来被调用了，所以`sub_188e6`里面自己调用一次是在做初始化；（这和cs一模一样）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c8618d0eb1734efcaf084c7cd9b676923e9a25ae.png)

此时传入的三个参数：shellcode中隐藏pe开始位置、4、一个类似特征码的`56a2b5f0`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4d5dabe3170d0edcea382139524fa8ba0ccbf400.png)

此时再调用dllmian ，我们来到`sub_183e0`函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1f8e4d53c3d3f00d22e5c9786ff139b010468320.png)

其实现如下，三个参数和dllmian传入的一样；a2等于4；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-931e0549d033cb3fd6bca83baaff7d9caaaf1d02.png)

带入a2=4，来到如下逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ed8ae5a34909fe8ad75cbda54974bef8cf4cfde8.png)

五、终是CobaltStrike没跑了
-------------------

到这差不多我们就可以定性了，就是cobaltstrike，如下是之前之前笔者22年一文章里面分析的 ；[Cobaltstrike4.0——记一次上头的powershell上线分析](https://forum.butian.net/share/1934)，可以看到上图逻辑和之前笔者分析的一样的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6b1ea1e5140b7461a20c26a82a0b1f6fda046528.png)

按照cs逻辑,这里后续主要的逻辑在：`sub_BA74()`里面；

回连c2、接收指令

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d41c8598345fb15bb1e2dc3c0fdb78d26438d435.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a573e767b93f0cfac6788e6b1cca1edf2f5e8527.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-49bc273d8ed5e437f2214c39057ec54465234926.png)

指令解析执行流：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-52281355605a4a3cdf0acb5149c2b274eefc66aa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d73ea9213a7ac80b068003f94e231440dbe1058e.png)

到这shellcode基本内容差不多就这些了，其实主要就是过了一遍反射加载函数和相关逻辑实现；

0x03 该shellcode利用的技术点
=====================

抛开上面的shellcode不谈，其是cobaltstrike的“shellcode”（严格意义说就是stage，只不过我们切入的时候是把他当shellcode切入），那么我们简单总结下分析出来的cs的反射加载函数里面兼容使用一些技术：

> 1、shellcode头部插入垃圾代码；  
> 2、shellcode去call pop特征；  
> 3、shellcode中隐藏pe文件（dll），去dos头特征、去pe头特征；  
> 4、利用反射加载的dll里面的微软弃用字段来存储一些配置项（如密钥、是否开启内存权限管控等）；  
> 5、利用CreateFileMapping+MapViewOfFile来替换Virtual相关的内存空间申请；  
> 6、反射加载函数里面找到要加载的pe之后，完全抹除pe文件的dos头、pe头特征；  
> 7、反射加载的pe文件的导入表中的导入模块名称、导入函数名单以及可执行节区代码都是被加密的，反射加载函数加载的时候动态解密加载

通过分析我们也间接的学习了cobaltstrike对一些配置项落地实现的原理；  
通过对比对应的关键profile配置项如下（这里我们根据分析出来的逻辑回去对比cs的配置profile里面的配置项，注意不是说上面的shellcode都做了）

```php
stage{  
    set userwx “true”  # 避免申请rwx权限内存  
    set allocator "MapViewOFFile" #利用MapViewOfFile来申请匿名映射内存空间，用于加载dll  
    set cleanup “true”   

    set magic\_mz\_x64 "YA" # 修改反射加载dll的头部特征，dos头和pe头  
    set magic\_pe "JQ"  

    set obuscate "true" # 混淆导入表  

    set stomppe "true" # 消除加载内存后的pe头中的dos头和pe头特征  

    transform-x64{  
    \`   prepend "xxxxxx"   #上述shellcode头部的多余字段内容  
    }  
}
```

最后我们回过头来，直接使用脚本提取下这个beacon的配置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f8ec26f0f7331e1554ea8b62aac2942a73391436.png)

这个样本的上线方式和之前的文章核对下，没有问题，可以看到如下图两个标记的地方，可以明显看到回连的c2，以及其使用了域名前置的手段；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c94cda4ee30e582936019e523f8dbc2f23856d57.png)

0x04 总结
=======

其实攻防中，红队使用的主流c2框架基本还都是CobaltStrike，因为cs 可以生成跨平台payload、可选远控形式的隧道多、强大的后渗透能力、互联网上有丰富的现成功能插件、和其他远控工具的兼容及其优秀的团队协作设计；所以很多红队都是使用cs；

但是享受其优点的同时也要接纳其缺点，比如会被检测设备重点照顾，你可能会说那cs不是可以修改profile来修改流量侧和端侧的特征吗，但是防守方法做检测的同学会想不到吗，所以在一定程度上你修改了profile的样本还是会被检测到（这个需要大量测试，因为不同厂商的检测点可能不尽相同，甚至对相同特征不同厂商的检测点也可能不同，你煞费苦心调制的profile可能因为没有做一个点，直接被秒了，如上文，拿几年前Didier Stevens师傅写的配置提取样本都可以直接把这个beacon秒了，那厂商端侧检测就更容易了，当然肯定是有一堆能绕过检测的配置能满足实际的攻防需求，因为实际攻防场景里我们不是要过所有安全设备，而是知道了目标环境之后，把目标环境里面的杀软以及相关安全设备过了就行）； 那么在这种场景下，我们不妨思考下，红队如何破圈呢；这是一个值得思考的问题！

笔者才疏学浅，文章如有错误欢迎指出；

一方面是通过修改profiles