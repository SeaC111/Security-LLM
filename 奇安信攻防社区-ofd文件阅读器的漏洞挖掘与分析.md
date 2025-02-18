近期研究了下国内特有的ofd版式阅读器，这款阅读器针对国内ofd文件阅读开发而来，而ofd文件是由工业和信息化部软件司牵头中国电子技术标准化研究院成立的版式编写组制定的版式文档国家标准，在国家标准全文公开系统上也可以查到，如下：

![image-20210629172055123.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-e84be37e9120710796f14ae0c1b3caa16b486ccf.png)  
但是ofd文件在民用领域推广力度相对不足，安全研究这块也相对较少，因此大概率还是存在不少问题的，因此针对ofd版式阅读器windows平台的软件进行了研究，下面说下针对这款软件的漏洞挖掘与分析过程。

### 动态漏洞挖掘

动态漏洞挖掘主要是通过fuzzing工具对程序进行漏洞挖掘，当然也会配合ida等工具进行静态分析。针对文档类型的程序，在windows平台上主要通过winafl这款工具进行fuzz，其它工具如honggfuzz、peach等和winafl相比双方各有优劣，也尝试过在linux平台利用模拟器对windows应用进行黑盒漏洞挖掘，但是有大量的问题需要解决，目前该方案并不成熟。如果对文档格式了解不深的话，使用winafl可能是漏洞挖掘产出最快的方式之一，下面说下利用winafl进行漏洞挖掘的基本流程。

#### 准备

- winafl、dynamorio、procmon、ida、study-pe、x64dbg
- SuwellReader.exe（1.6.6.29）
- 测试环境：win10 1909 64位
    
    #### pdf文件漏洞挖掘过程

1. 寻找fuzzing所需的函数偏移
    
    具体参考[winafl官方说明](https://github.com/googleprojectzero/winafl#how-to-select-a-target-function)。这里说明下，前段时间ofd阅读器对进行了大规模更新，整体框架发生了较大变化，这里分析的是之前的版本，新版本后边会介绍。
    
    在使用过程中发现该程序可以打开pdf、ofd、sfd等文件，由于pdf的样本比较容易获取，因此先针对pdf格式进行漏洞挖掘。
    
    先看下程序的目录，大概可以确定SuwellReader.exe是主程序，由于没有发现其它处理文件相关的开源库，配合一些分析基本可以确定它将库代码和主程序一起打包为一个程序，因此这里没办法针对特定的组件编写harness来进行针对性的fuzzing，直接分析这个程序即可，windows上使用procmon或者火绒剑可以很方便的观测程序的宏观行为如读写文件，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-51cba55fefa4eba7ed5a38511da4910eb4cb4c02.png)  
由于程序会多次创建、读取文件，因此需要额外的进行分析来进一步确定fuzz所需的函数偏移。由于程序中的大量函数内部并没有将ebp作为函数栈帧，同时函数调用时采用虚表调用的方式，因此静态与动态分析函数调用栈时都比较麻烦，难以形成一个完整的函数调用栈，需要一步步去调试分析。同时这里建议选择的函数尽量接近调用栈底部，这样能最大可能保证输入文件被程序解析完全，尽可能多的覆盖程序的解析文件逻辑，提高fuzzing所需的程序覆盖率。当然如果发现fuzzing速度非常低的话，就需要更改下函数偏移了，不然的话很难产生有效的变异，如何取舍就看后面fuzzing的效果了。

2. 寻找关闭文件句柄的函数偏移  
    因为程序在打开一个文件后并不会主动关闭文件句柄，因此需要手动去在特定的位置关闭文件句柄。这里需要两个函数偏移，一个位于程序创建后面读文件所需的文件句柄的函数尾部，在这个函数中可以拿到需要关闭的文件句柄，另一个位于程序完全读取文件后的某个函数尾部，这个函数偏移相对宽泛，可以直接选择上一步的fuzzing所需的函数偏移，在那个函数尾部调用对应的api关闭文件句柄即可，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-eda2949e311b3203e8cd2a9c8e3c49324835ad1e.png)

3. 利用winafl的debug模式进行测试
    
    命令如下：
    
    ```C++
    drrun.exe -c winafl.dll -debug -target_module SuwellReader.exe -target_offset 0x195b30 -call_convention fastcall -nargs 2 -fuzz_iterations 10 -- C:\target\shuke\Suwell\Reader_Pro\SuwellReader.exe C:\fuzztools\manul\input\PDFBOX-1074-1.pdf
    ```
    
    这里使用了最新版的dynamorio并重新编译了winafl，但是这里存在一个性能方面的问题，新版的dynamorio在windows上的性能表现似乎和旧版的存在一定差距，这个性能方面的问题也是后期才发现的，后面会进行说明。
    
    运行看起来没有什么问题，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-d462b235841981d40899c03ea13cfae6dff74d63.png)  
这里为了确认fuzzing一个循环所需的时间，特地修改了winafl.dll，添加了计时函数，可以看出fuzzing一个循环的时间还是很长的，因此后面fuzzing的整体速度会非常慢。

4. pdf样本获取
    
    可以采用网络上公开的[fuzzing样本集](https://github.com/strongcourage/fuzzing-corpus)或者用爬虫从百度、google等搜索引擎批量爬取，当然还可以使用libfuzzer、honggfuzz等工具对开源的pdf程序进行fuzzing，将触发新覆盖率的文件保存作为种子在windows平台上进行测试。
5. 样本裁剪
    
    利用winafl自带的python脚本winafl-cmin.py对样本进行裁剪，筛选出能够尽可能多的触发更多程序代码路径的样本,将无法触发新路径的样本进行过滤。
6. 正式fuzzing
    
    使用如下命令：
    
    ```C++
    afl-fuzz.exe -i in -o out -t 20000 -m none -D C:\fuzz\fuzz_tools\dyn\dyn\bin32\ -M fuzz1 -- -covtype bb -call_convention fastcall -target_module SuwellReader.exe -target_offset 0x195b30 -coverage_module SuwellReader.exe -fuzz_iterations 50000 -nargs 2 -- C:\fuzz\fuzz_tools\Reader_Pro\SuwellReader.exe @@
    ```
    
    效果如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-ca22f8f89d9d452d7e46976a0207cc7441504497.png)  
虽说有crash，但是后面分析了下是由于提前关闭文件句柄导致，因此需要重新patch程序。可以看出速度确实非常慢，和之前利用debug模式测试的速度基本一致，需要两到3秒钟才能完成一次循环。而且由于变异过程中可能产生程序无法识别的样例，导致程序弹出打开文件失败的对话框，这样就必须找到弹出对话框的大概位置，将相关的代码进行patch。还有一种情况是生成了带密码的pdf文件，这样打开文件的时候还会弹窗需要用户输入密码，针对这类需要用户交互的行为都必须修改程序的逻辑，这样才能保证fuzzing的正常运行。但是这同样也会带来其它风险，比如由于patch代码导致的程序出现crash，因此在分析crash时最好使用原版程序进行分析，如果发现了严重的问题，可能还需要再次patch程序。  
经过接近半个月的fuzzing，发现了5个不同的漏洞，包括空指针解引用、除零异常、栈溢出(栈上溢)等类型，经过分析发现没有可以完全利用的，因此将这部分漏洞都提交给了cnvd。接下来说下针对ofd文件格式的漏洞挖掘过程中所遇到的一些情况。

#### ofd文件漏洞挖掘过程

大致流程和pdf文件漏洞挖掘一致，但针对ofd文件的漏洞挖掘有一个问题就是样本获取较难，目前尚未在互联网上发现可以公开使用的样本集，甚至利用google关键字也无法搜索到对应样本，因此考虑将pdf或者其它文档转换为ofd。试用了网上的一些在线转换工具，可以说效率很低，而且转换后的成功率也比较低，并且没有提供api，无法进行批量转换。而阅读器本身也提供将pdf转换为ofd的功能，但是只能手动转换，这样的话获取大量样本的效率就非常低了。因此尝试使用按键精灵、autohotkey等自动化工具对阅读器图形界面进行自动化测试，发现由于采用了QT模块导致没法识别到windows窗口的组件，如编辑框等，这是因为qt自己对windows的窗口消息机制做了一层封装，通过spyxx等工具就无法获取对应组件的句柄，就无法通过发送消息的方式进行自动化测试。这样就只能基于特定的图形界面位置进行自动化了，最终编写了脚本实现批量的pdf转ofd文件，脚本如下：

```C++
   Function SaveToOfd
    mm = lib.API.查找窗口句柄(0, "ofd阅读器")
    Call Lib.API.激活窗口并置前(mm)
    MoveTo 46, 50
    LeftClick 1
    Delay 500
    LeftUp 1
    MoveTo 115, 282
    LeftClick 1
    Delay 500
    MoveTo 1011, 708
    LeftClick 1
    Delay 500
    MoveTo 1372, 719
    Delay 500
    LeftClick 1
    KeyDown "Ctrl", 1
    Delay 490
    Delay 31
    KeyDown "Ctrl", 1
    Delay 22
    KeyDown "W", 1
    Delay 180
    KeyUp "W", 1
    Delay 16
    KeyUp "Ctrl", 1
    Delay 6
   End Function
   dirname = "C:\myout\temp\"
   files = Lib.文件.遍历指定目录下所有文件名("C:\myout\temp\")
   For i = 0 To UBound(files)-1
    filename = files(i)
    finalfile = dirname & filename
    RunApp ("C:\target\shuke\Suwell\Reader_Pro\SuwellReader.exe " & finalfile)
    SaveToOfd 
    Delay 1000
   Next
```

这样基本可以将之前所用到的pdf样本转换为ofd文件，便于使用winafl进行fuzzing。在fuzzing过程中出现了打开文件失败的弹窗，分析后patch程序可以正常运行，运行一段时间后发现程序出现大量的hang，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-4d26f2f701274e3f5aff8b4b47a86215f6c06713.png)  
经过深入分析发现程序陷入了死循环导致fuzzing超时，原来是winafl变异导致ofd的文件格式被破坏，ofd文件本质是一个zip压缩格式文件，通过xml文件组织内部元素，因此如果破坏了zip压缩格式，导致在解压过程中循环解析同一部分的文件，使应用陷入了死循环，这种情况等同于拒绝服务。

这里通过dynamorio的插件drcov将程序解析ofd文件过程的代码覆盖率输出到xml中，但运行过程中发现消耗时间过久，查看procexp发现程序陷入了死锁，因此考虑利用旧版的dynamorio进行分析。前面提到过新版dynamorio的插桩速度非常慢，由于在win10 1909上测试，只能用新版测试，旧版的api支持存在问题，因此这里选择在win7上利用旧版dynamorio进行测试，结果显示旧版的插桩速度是新版的7-10倍左右，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-cbb1aa3d4c4bfcf53193ddeba1a8710301aa4a0c.png)

还需要注意的一点是新版的dynamorio的drcov组件生成的xml文件的version是5，需要最新版的lighthouse插件才可以在ida中解析，旧版的插件是无法正常解析的。

但就算使用旧版的dynamorio依旧无法改变前面遇到的zip压缩格式被破坏导致的应用hang超时问题，因此这里转变思路，尝试做针对性的fuzzing研究，由于pdf是可以嵌入各种图片格式的，这里将嵌有jpg格式的pdf进行转换，转换后的ofd格式如下：

```php
   |-- Doc_0
   |   |-- Document.xml
   |   |-- DocumentRes.xml
   |   |-- Pages
   |   |   `-- Page_0
   |   |       `-- Content.xml
   |   |-- PublicRes.xml
   |   |-- Res
   |   |   `-- image_108.jpg
   |   `-- Tags
   |       |-- CustomTag.xml
   |       `-- CustomTags.xml
   `-- OFD.xml
```

因此这里可以手动构造zip压缩包，由winafl对jpg文件进行变异，由第三方组件负责将变异后的流重新组装成一个可以被正常解析的压缩文件流，参考afl文档中针对post library的描述，需要开发独立的post\_library模块来进行压缩包的构造。在分析程序过程中发现阅读器使用了zlib1.2.11进行压缩、解压缩，因此这里同样采用这个版本的zlib库对输入流进行压缩，代码大致如下：

```C++
   extern "C" __declspec(dllexport)const unsigned char* afl_postprocess(const unsigned char* in_buf,
       unsigned int* len,unsigned char* id)
   {
       zipFile zf;
       int errclose;
       zlib_filefunc64_def ffunc;
       char filename_try[MAX_PATH];
       fill_win32_filefunc64A(&ffunc);
       char filenameinzip[MAX_PATH];
       char savefilenameinzip[MAX_PATH];
       zip_fileinfo zi;
       sprintf(filename_try, "%s_new.zip", id);
       auto res = CopyFileA("ori.zip", filename_try, 0);
       strcpy(savefilenameinzip, "Doc_0/Res/image_108.jpg");    
       int err = 0;
       int zip64 = 0;
       char* password = NULL;
       zi.tmz_date.tm_sec = zi.tmz_date.tm_min = zi.tmz_date.tm_hour =
           zi.tmz_date.tm_mday = zi.tmz_date.tm_mon = zi.tmz_date.tm_year = 0;
       zi.dosDate = 0;
       zi.internal_fa = 0;
       zi.external_fa = 0;
       int size_read = 0;
       int size_buf;
       FILE* fin;
       unsigned long crcFile = 0;

       zf = zipOpen2_64(filename_try, 2, NULL, &ffunc);
       if (zf == NULL)
       {
           printf("error opening %s ,copy file res:%d\n", filename_try,res);
           return in_buf;
           err = ZIP_ERRNO;
       }
       zipOpenNewFileInZip3_64(zf, savefilenameinzip, &zi,
           NULL, 0, NULL, 0, NULL /* comment*/,
            Z_DEFLATED,
           2, 0,
           /* -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY, */
           -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY,
           password, crcFile, zip64);
       if (err != ZIP_OK)
           printf("error in opening %s in zipfile\n", filenameinzip);
       else
       {
           if (err == ZIP_OK)
           {

               err = zipWriteInFileInZip(zf, in_buf, *len);
               if (err < 0)
               {
                   printf("error in writing %s in the zipfile\n",
                       filenameinzip);
               }
           }
           if (err < 0)
               err = ZIP_ERRNO;
           else
           {
               err = zipCloseFileInZip(zf);
               if (err != ZIP_OK)
                   printf("error in closing %s in the zipfile\n",
                       filenameinzip);
           }
           try {
               err = zipClose(zf, NULL);
           }
           catch (...){
               printf("find exception\n");
           }
           if (err != ZIP_OK)
               printf("error in closing %s,err is %d\n", filename_try,err);
       }
       FILE* zipfin = fopen(filename_try, "rb");
       if (!zipfin)
           printf("open zip file failed\n");
       res = fseek(zipfin, 0, SEEK_END);
       unsigned int zipfilesize = ftell(zipfin);
       unsigned char* zipbuf = (unsigned char*)malloc(zipfilesize + 1);
       fseek(zipfin, 0,SEEK_SET);
       fread(zipbuf, 1, zipfilesize, zipfin);
       fclose(zipfin);
    DeleteFileA(filename_try);
       *len = zipfilesize;
       return zipbuf;
   }
```

这里修改了函数原型，添加了id这个参数，原因是需要进行并行fuzzing，这样可以根据每个不同的fuzzing进程生成对应的文件，避免由于多进程竞争出现一些问题。同样，afl-fuzz.c中的代码也需要进行针对性修改，而且特别注意的是fuzzing的dry-run阶段，是不会主动调用post\_library函数的，同样需要手动修改，不然会出现程序打开文件错误，相当于dry-run阶段的代码路径覆盖率检测其实是无效的。修改后fuzzing过程中一切表现正常，接下来说下静态漏洞挖掘。

### 静态漏洞挖掘

#### 程序静态分析

对程序解析ofd文件的过程进行了分析，在分析过程中发现该程序使用了`zlib 1.2.11`以及`libxml2 20901`两个版本的开源库，而`libxml2 20901`版本相对较老，存在较多的问题，但目前难以直接对该库进行fuzzing，原因是ofd阅读器并没有采用动态库dll的方式而是采用了静态编译的方式将`libxml2`库打包到应用中，并且采用自实现的C++类实现了一系列调用接口从而隐藏了对`libxml2`库函数的调用，而且相关的符号全部都已经strip掉，这样给程序分析带来较大难度，很难直观的判断该应用调用了`libxml2`库的哪些接口，也就没有办法直接写`hardness`来fuzzing libxml2。这里推荐一款工具[karta](https://github.com/CheckPointSW/Karta)，这款工具采用简单而有效的方式对闭源程序中的开源库进行识别，效果如下：

```php
   [26/05/2021 14:15:32] - Karta - INFO: libpng: 1.6.37
   [26/05/2021 14:15:37] - Karta - INFO: zlib: 1.2.11
   [26/05/2021 14:15:48] - Karta - INFO: libxml2: 20901
   [26/05/2021 14:15:52] - Karta - INFO: libtiff: unknown
   [26/05/2021 14:16:01] - Karta - INFO: libjpeg: 9a
```

这里需要注意的有两点，默认的匹配libjpeg的脚本文件存在问题，需要修改后才能正常运行，而且libjpeg的匹配方式是错误的，同样需要修改，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-aac3ead29c25133d8ae57eaacbcbd87fd4d23e94.png)  
阅读器本身添加了对开源软件使用的声明，只是没有具体版本，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-667c509e4a875b5ee888697d74ba1c7d42c86bca.png)  
同时karta还有一个非常强大的功能就是函数匹配，效果好的话可以大大减轻逆向分析工作，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-73e0f586420e9969bb27ecf8c67bbb4904ddd0c8.png)  
结束匹配后默认是没有直接应用的，需要右键import才能将匹配的函数名称替换为库函数名称。但是在使用过程中也发现了一些弊端，karta的函数匹配比较依赖于字符串、特定的整数等特殊值，如果开源软件中没有这部分内容，那么它的匹配效果会大打折扣，但相比于ida自带的FLAIR技术在特定场景来说已经非常强大了，libxml2的匹配度高达60%多。

接下来就是针对这些开源库尝试使用已经发现的漏洞在阅读器上进行复现，最初测试了libjpeg的多个poc，但是都无法成功，通过分析发现解析ofd文件过程中仅仅用到了libjpeg库的解码功能，jpeg图片实际上是一种高效的压缩格式，libjpeg开源库中包含两个主要应用即cjpeg、djpeg，djpeg主要负责解压缩，而针对djpeg目前还没有发现合适的漏洞，同时经过测试也发现个人版的阅读器是没法触发jpeg图片的编码功能。

随后测试了libxml2的历史漏洞，发现一共有两个可以触发，分别是堆越界读以及释放后重引用，触发的函数对应的名称和漏洞描述中的一致，静态分析就暂时到这里。后面发现ofd阅读器更新了原程序，在对新版ofd阅读器做漏洞挖掘过程中发现一个线程竞争漏洞，下面针对这个漏洞做下分析。

### 线程竞争漏洞分析

新版ofd阅读器发生了较大变化，整体框架变化较大，同时抛弃了qt4采用qt5作为图形框架，之前的版本是高耦合的，基本上大部分程序逻辑代码都在主程序内实现，而新版的则将代码模块化，实现了低耦合，各个模块负责具体的功能，这样的话在分析过程中需要同时打开多个文件进行静态分析，当然由于采用模块化机制，可以获取导出函数名称，对分析程序功能也有帮助。大致漏洞挖掘过程同上，只是这次这对xml文件进行fuzzing。利用honggfuzz对libxml2进行源码fuzzing，将生成的xml文件作为阅读器fuzzing所需的种子文件，经过一天的测试，表现如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-7ac2a4e9882a984dd153fbb5fb67b165ecb8b765.png)  
但这个结果看起来似乎不太可信，对crash文件进行分析，发现并没有一个文件触发crash，最初以为是由于patch文件所致，但是用patch后的程序也无法触发崩溃，这种情况很难遇到，这就需要从头来看此次的fuzzing过程到底哪里出了问题。

利用processhacker观测整个fuzzing过程，发现存在内存泄漏，极有可能是由于我们对程序进行了patch所致，32位进程最高仅有2GB内存可用，超过这个上限，申请内存地址总是返回null，因此对fuzzing所需的函数偏移进行了修改，同时更改命令行参数，让fuzz\_iterations这个参数为100，这样就不会触发oom了。但是后续发现问题依旧存在，因此换了全新的环境重新开始测试，此时在winafl的debug模式下发现问题，预期的winafl的debug模式是不会出现crash的，而在测试过中发现会偶尔出现crash，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-65bcef60eac3d75517d00c2dc73dfc8f91b1782c.png)  
此时需要对winafl的debug模式进行调试分析。这里不推荐dynamorio官方的调试模式，因为在添加-msgbox\_mask参数后，利用windbg调试器对suwellofdapp.exe进行附加调试，发现dynamorio不会在对原程序进行插桩，导致调试模式下应用会正常打开文件而不会触发winafl中的pre\_fuzz\_handler、post\_fuzz\_handler函数，原因未知。因此这里需要通过其它方式对debug模式进行调试，我这里直接改了pre\_fuzz\_handler的代码，当第一次进入该函数时会弹框，这样方便调试器进行附加调试，

附加后直接运行，此刻可以在调试器中观测到如下异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-38280e56176311b5542ec9c86ce56e1c0f010c62.png)  
此时中断代码如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-26d989bebdc6a165f9f2ea73aa7b3dd1917c0c98.png)  
此时edi所指内存空间是没有写权限的，因此导致写操作失败，观察此时的调用栈，发现代码此时并不在主线程中，线程状况如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-8543ac1635bdd44a8ea988fed28f3fd9858b7c4a.png)  
从调用链可以看出大概是在receipt.dll中出现了问题，调用链如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-5fe4f8703e12bedce4e98382b5e1ed9322a1c329.png)  
手动分析了该调用链，大致如下(这部分调用链应该是qt创建线程并使用信号、槽机制来在新线程调用槽函数)：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-36e67adff7f5194ff339ca614a94b4d38b19ca72.png)  
顶部的函数是dynamorio动态申请的地址用来保存插桩后的函数代码，由于发生问题时并不在主线程内，因此怀疑可能时由于多线程竞争出现了crash，因此先看下receipt中的函数，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-3f931941d3091b71a457e0ef4fb35de50017eb6c.png)  
看起来是调用`sub_100013d0`函数时触发了crash，这里分析了该函数的代码后，发现内部有访问全局变量，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-7408ef95250f58ab8e188e5aeb158b2f9ca2e57c.png)  
仅有一处赋值的地方，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-10e3c54f19a62cf075584486a3db2f81fc648b2a.png)  
但这个地方的赋值是不会发生变化的，因此理论上来说不会影响线程安全性，直接看下该全局变量的交叉引用，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-24fb95061665ce350a3d2bc2cd7ed96987c1b7dd.png)  
关键在地址0x100015f0的代码，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-2012573e2f5eae1f4d0d94de2333f90926755be4.png)  
此时全局变量的地址作为参数传入了`sub_10001A30`函数中，而f5查看伪代码发现由于ida没有将该函数识别为thiscall调用，导致没有将全局变量作为参数，因此通过手动设置函数类型，可以让ida重新识别该函数的参数，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-9006ade48cbaa7037330a7d52af822ae3c270e4b.png)  
因此之前分析时并没有主动关注这个函数，现在看下该函数的具体实现，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-41fa91de2448a3ea2896d44d43aeaec2605c37f6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-ded0a87e70a7120dc19c1be755dd188ded77a5a8.png)  
可以看出将新申请的地址赋值给全局变量，由于每个新的线程均会修改全局变量值，如果存在多个这样的线程同时访问、修改这个全局变量，就存在线程竞争安全问题了。继续分析，发现如下代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-e9ec5c9408956c099807007425c4e32a3c17f35e.png)  
可以看出，代码在某个分支会将全局变量的内容进行释放，这就极有可能造成释放后重引用漏洞。接下来测试下这个问题发生的频率，

利用gflags.exe对suwellofdapp.exe添加页堆监控，接着利用windbg打开suwellofdapp.exe，参数是多个不同的ofd路径，直接运行后触发如下异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-ba5239b96915455ca0ada6d580ae52565e839f0f.png)  
查看ecx地址状态如下：

```php
0:013> !heap -p -a ecx
    address 6223cff4 found in
    _DPH_HEAP_ROOT @ 94c1000
    in free-ed allocation (  DPH_HEAP_BLOCK:         VirtAddr         VirtSize)
                                   620d3a90:         6223c000             2000
    6aa2adc2 verifier!VerifierDisableFaultInjectionExclusionRange+0x000036a2
    771b9823 ntdll!RtlDebugFreeHeap+0x0000003e
    7710dd3e ntdll!RtlpFreeHeap+0x000000ce
    77156cdb ntdll!RtlpFreeHeapInternal+0x00000783
    7710dc16 ntdll!RtlFreeHeap+0x00000046
    755fe58b ucrtbase!_free_base+0x0000001b
    755fe558 ucrtbase!free+0x00000018
    67245755 Qt5Core!QMapDataBase::freeTree+0x00000045
    65439eb8 receipt+0x00009eb8
    677f3f1d Qt5Widgets!QApplicationPrivate::notify_helper+0x000000cd
```

可以看出此刻堆已经被释放了，由于设置了page heap，因此再次访问时会触发异常，函数调用链如下：

```php
00 6ee2ddbc 65439eb8 receipt+0x19d6
01 6ee2de24 677f3f1d receipt+0x9eb8
02 6ee2de3c 677f2f2e Qt5Widgets!QApplicationPrivate::notify_helper+0xcd
03 6ee2df1c 67206edc Qt5Widgets!QApplication::notify+0x165e
04 6ee2df94 67355ab0 Qt5Core!QThreadData::current+0x3c
05 6ee2dfb0 748e46a7 Qt5Core!QCoreApplicationPrivate::sendPostedEvents+0x200
06 6ee2dff0 67394f5f USER32!GetWindowLongW+0x127
07 6ee2e094 7490474b Qt5Core!QEventDispatcherWin32::sendPostedEvents+0xf
08 6ee2e0c0 748e60bc USER32!_InternalCallWinProc+0x2b
09 6ee2e1a4 748e520e USER32!UserCallWinProcCheckWow+0x3ac
0a 6ee2e218 748e4fd0 USER32!DispatchMessageWorker+0x20e
0b 6ee2e224 67393cbf USER32!DispatchMessageW+0x10
0c 6ee2fec8 67350b39 Qt5Core!QEventDispatcherWin32::processEvents+0x5af
0d 6ee2ff14 672058fd Qt5Core!QEventLoop::exec+0x1b9
0e 6ee2ff4c 67207f1e Qt5Core!QThread::exec+0x9d
0f 6ee2ff70 75d86359 Qt5Core!QThread::start+0x2ee
10 6ee2ff80 77137b74 KERNEL32!BaseThreadInitThunk+0x19
11 6ee2ffdc 77137b44 ntdll!__RtlUserThreadStart+0x2f
12 6ee2ffec 00000000 ntdll!_RtlUserThreadStart+0x1b
```

和之前在winafl的debug模式下触发的路径基本一致，到这里基本可以确定漏洞是由于多线程竞争导致的uaf。然而事情并没有结束，仔细查看函数sub\_100013D0代码，发现在函数头部存在如下代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-08735300cf5d7099569787921a8a954e02c3aaa4.png)  
熟悉QT的应该了解这部分代码的作用是为线程加锁的，根据QT官方文档中的说明，QMutex类是为了保证一个对象、数据结构、代码在同一时间仅有一个线程可以访问，那么为什么这里还会出现多个线程同时访问全局变量的情况，看下`QMutex::lock`的实现，如下：

```assembly
push    ebx
push    esi
mov     ebx, 1
xor     eax, eax
push    edi
mov     edi, ecx
mov     edx, ebx
lock cmpxchg [edi], edx
mov     esi, eax
test    esi, esi
jz      short loc_67028549
loc_67028549:
pop     edi
pop     esi
pop     ebx
retn
```

也就是说如果`[edi]`同1相比，如果不同则将`eax`置0，同时将`[edi]`置1，那么如果每次传入的`[edi]`为0，函数是不会等待而是直接返回的，也就意味着每次传入的QMutex对象都是不同的，这里通过windbg调试并通过命令`bp receipt+0x1400 ".printf \"QMutex:%N-->%N\\n\",ecx,poi(ecx);g"`输出每次进入该线程时的QMutex对象值，可以发现确实每次都不同，如下：

```php
QMutex:5E9C2FF8-->00000000
QMutex:68214FF8-->00000000
QMutex:63246FF8-->00000000
QMutex:646EEFF8-->00000000
QMutex:60DD8FF8-->00000000
```

也就说明每次的线程里传入的QMutex对象都是不一样的，而QMutex::lock针对同一个对象多次进入才会等待，不同对象是没有线程锁的效果的，因此本质上是由于开发者误用QMutex::lock导致线程锁并没有产生应有的效果，当函数中包含对全局变量的访问时就可能触发对应的漏洞。

### 结束语

目前发现的这部分漏洞均上报给CNVD，并且官方也已经修复了这些问题。