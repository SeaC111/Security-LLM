formbook恶意软件剖析
==============

formbook恶意软件剖析样本信息样本执行流程图样本分析核心模块分析1、准备工作2、分析对抗3、ntdll重构4、进程注入4.1、木马进程注入Explorer4.2、Explorer启动系统进程4.3、主进程迁移5、二次注入Explorer进程6、核心功能代码7、信息窃取8、32位进程注入64位进程溯源总结参考文章

0x00 简介
=======

**formbook**是一款臭名昭著的商业木马，其主要由基于.Net制作的加载器和核心PE程序组成，加载器使用C#编写，一般会有两三层外壳加载核心的PE程序。而核心的PE程序完全由C和x86汇编语言编写，无任何直接的windows API调用，且包含各种反调试、反沙箱操作，对抗分析的强度极大。这款畅销的商业木马经常通过钓鱼邮件进行传播扩散，扩展功能也极为丰富，一旦被植入木马，无论是个人用户还是企业都将承受极大的信息泄露风险。

0x01 样本信息
=========

| 样本名 | New order #11042100.exe |
|---|---|
| **大小** | **399872 字节** |
| **MD5** | **65823E4CF39C6384599F9C7DE542238F** |
| **SHA1** | **2A15CB6BB5E0DACA960C7D13C7907E183D710AD4** |

0x02 样本执行流程图
============

![picture](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0d9db78bfe56df7af11d92d364c20d7d8677d9ad.jpg)

0x03 样本分析
=========

- 使用Die对其进行查壳，可以确定该样本基于.Net开发，并使用Eazfuscator保护  
    ![image-20211115154522503.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f146ed4f67edb8d616314b01029f6dcb312b8c64.png)
- 使用dnSpy分析该样本，识别出该样本的原始名称为**LUIDANDATTRIBUT.exe**，以及样本的架构和开发平台版本

![image-20211115155610807.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7a91fb3a8c403878fb6dd0cb5a22f74dfc2d95d7.png)

- 进入主函数，其通过初始化一个FormMain类执行其核心功能

![image-20211115155137659.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-596169c117d77e75c635a8441d754abc63247503.png)

- 在核心函数中，对母体资源数据进行读取解密复制，然后使用Assembly类加载该程序集，并调用其SelectorX函数，这里是第一层加载器。

![image-20211115160257763.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7cfe837749715112da5dc50c6feb0674e395f9ca.png)  
![image-20211115160315936.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-82f879c303f09c8531c518e4f0bfe4da8a374ea3.png)

- 分析加载的内存程序集，识别其原始名称为**TaskNode.dll**，定位调用的**SelectorX**函数，读取母体的资源数据并解密，最后使用Assembly进行加载，最终调用其函数，这其实是第二层加载器。

![image-20211115163216163.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ebdb52aae2a4ca1b048a53b09d42a10c9bad861d.png)

- 再次将加载的PE程序dump并分析，识别出原始名称为UI.dll，初步分析函数，发现函数名被混淆了，并且函数中使用了大量的switch进行流程控制，无法直接分析其执行代码。

![image-20211115161841406.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6ec9d8bfbd0fb2f6bddae4bf84d922a6ad181e2c.png)

- 去除代码混淆后分析，该模块的主要操作在对象初始化和另外一个函数中。在函数调用前，该类对象将先进行初始化，初始化过程中从资源数据中解密出一个PE文件，然后初始化变量，最后获取一些windows API函数

![image-20211115165556967.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-562c9909cb7d2013adabd1d4763064594e855402.png)

- 初始化完毕后，执行调用的函数，根据其执行流程，将先进行互斥体创建，放置重复运行，然后创建傀儡进程，将核心的PE程序通过进程注入的方式运行起来，这便是第三层加载器。

![image-20211115161825339.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fb84c93df167d904344bb3e259f92c9828c219f0.png)  
![image-20211115161817677.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b111b8335d4af2bb0582e8c5e280c71af155750c.png)  
![image-20211115161811387.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ffbfb6c05df2e707aa8bb20c6b8ffd9119d9314b.png)

0x04 核心模块分析
===========

1、准备工作
------

- 将注入的PE程序dump出来，进行PE结构解析。该核心程序由汇编编写，无导入导出表，该特征与formbook商业木马完全契合。

![image-20211115161804308.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d3c45d02cb8dc9046a0e3aec9c3ad9b1bbf8826a.png)

- 对该样本进行简单分析，从main函数进入，发现该样本内部共有446个自定义函数，主分支简单，但子分支含有大量函数，无法直接理清执行流程，只能结合其他的调试工具进行逐步分析
- 通过对程序进行简单分析，初步确定执行流程以及函数调用方法，该木马所使用的所有数据及函数以及一些核心的代码，均被加密保存，程序在进行数据解密之后再执行其核心代码。主要的解密程序通过硬编码的数据起始地址，进行一系列数据的复制，最后进行SHA1校验。

![image-20211117211600764.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-dbb2b7dc9ef3d7eea690c5c1e8ebf91739fbaca7.png)

2、分析对抗
------

![image-20220129170302314.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4bf01ec00b36aeb73372eccd75f84e459a47de9e.png)

- 数据准备完善之后，开始执行其恶意代码。在执行过程中，通过动态获取函数进行hash计算比对来获取所需的函数并调用。在执行其核心恶意代码之前，会进行一系列反调试的校验。
    
    
    - 通过fs寄存器获取其InLoadModuleList，对该List中的模块名进行hash比对查找ntdll基址，由于该程序无导入导出表，正常执行过程中将不会加载ntdll，所以可以通过该方式反调试。
    
    ![image-20220209180249556.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8431d8ce15d220274167ed175f36e5f9309a0ae7.png)
    
    
    - 动态调用NtQueryInformationProcess函数检测调试端口
    
    ![image-20220209180345015.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-39883b0d1d00f6d75efca3ee010e9278bdb75470.png)
    
    
    - 初始化过程中，获取进程列表，通过对比敏感进程的hash来检查是否具有敏感进程
    
    ![image-20220209205720500.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-86ae047d66685b0a7d24471a674135d0437f27e4.png)
    
    
    - 判断进程路径中是否有敏感路径名称，解析路径中每个目录的名称通过hash对比来确定是否有敏感路径
    
    ![image-20220210171605131.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-359f9f27f6a7ec8b10d88b8cece318c9287e2817.png)
    
    
    - 获取系统用户名，然后进行hash运算比较
    
    ![image-20220210174421541.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5b1b83d0e472a81ac0e37d02ed7a5545466cd479.png)
    
    
    - 调用NtQuerySystemInformation传入SystemKernelDebuggerInformation来确认是否处于调试状态
    
    ![image-20220216180006697.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4c6fbdc332f5eda6e2f474015cc36a8369435f10.png)
    
    
    - 上述几项检测都会对初始化内存空间中的标志位进行赋值，以在最后的函数中进行校验，
    
    ![image-20220210202607882.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9d07f9b8ea71f3a7dcd1b38a7343f3e527eecc8b.png)
    
    
    - 通过在线解密出的数据，其检测的主要内容如下
    
    ![image-20220314103858409.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-cdafaa186193175863dddc33e56f81bad846b977.png)
- 由于每一次检查后都会对初始化栈空间的部分数据进行异或加密，所以需要对这里面的关键点进行patch，以保证后续代码的正常运行。

3、ntdll重构
---------

- 在其进行反分析过程中，会将ntdll文件数据展开到申请好的内存空间，而后续的部分API调用则是直接通过动态获取该内存中的ntdll数据来获取对应的函数地址，这里调用的函数主要是一些可通过syscall来执行系统调用的API，而使用该内存中的汇编代码来进行直接调用可以逃避edr和其他杀毒软件对这些敏感函数的监控。
    
    
    - 从PEB中获取ntdll基址及文件路径，申请内存空间将文件读取到内存空间，然后通过解析PE结构将文件进行内存展开
    
    ![image-20220216180309105.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5cfca8fa5f47555e2c699c1cc706bbfecce7c46b.png)
    
    
    - 然后将已经展开好的ntdll数据复制两份到内存中，根据两份数据的重定位表修复数据重定位，并对第一份导出表中的函数地址表进行修改，将函数地址表中的偏移修改为申请内存空间的地址，在申请好的内存空间中构造`push funcAddr ret`的语句，来解决函数的调用
    
    ![image-20220216180454741.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8657953f3bf9481e576de60d7198fe7454b78d5d.png)
    
    
    - 然后对其重点使用的函数再次恢复函数地址，以便后续调用
    
    ![image-20220216180642648.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a64b002fe7b2ec20a65ad0e1ff6a850b22a92106.png)
- 至此，木马的初始化以及数据准备工作完成，从这部分来看，木马后续所有的函数调用都将通过解密出hash，动态获取函数地址，最后直接调用的方式来完成其核心功能。在执行其核心代码前，其首先加载了一些动态链接库，通过对PEB中的InOrderModuleList中的模块进行对比，加载未加载的advapi.dll，然后利用该模块获取提权函数，进行进程提权，无论提权成功还是失败，都会继续执行下去。

![image-20220228100818457.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0a7525bf88dafacad1279547d4c866f600c0d40b.png)

![image-20220228100829896.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-786cd39b18a5e4b74929966da29c37a92988872a.png)

4、进程注入
------

### 4.1、木马进程注入Explorer

- 进入其核心核心函数，其先通过查询环境变量来获取系统用户名，并将用户名使用RC4加密，然后通过RtlSetEnvironmentVariable保存加密后的用户名和当前进程路径

![image-20220303164048598.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ba28b646e1ddd76a7fc818f4623562cd42fdac3b.png)

- 在进行初始化数据之后，将通过映射的方式创建一块内存，并将当前进程的PE数据拷贝进该内存中，并对数据进行二次解密，这部分数据将用于后续进行注入

![image-20220303165527327.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c9dc67a2fcda656d7178862524b23e94556ea72a.png)

- 数据准备完毕后，将会进行进程注入，其首先使用**NtQuerySystemInformation**函数通过传入**SystemProcessInformation**参数来获取系统的进程信息，通过hash对比来寻找Explorer进程获取其进程PID，然后打开该进程。

![image-20220303170828070.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0c8e67d9cc797a8ef4d26560610adf09a2c8c997.png)

- 当系统为32位时，将直接对Explorer进行**APC**注入，将Explorer主线程挂起，获取其线程上下文，使用映射的方式对Explorer进程注入，然后修改其线程上下文的EIP，并恢复线程完成注入

![image-20220303194753636.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-58c9112928e17cba97476573539adfa60f931a69.png)

### 4.2、Explorer启动系统进程

- 通过调试跟进注入的代码，在木马主模块中定位到相应的代码，在这块shellcode中，其将在自身内存中解密出一个在system32目录下的程序名，加载一些系统的模块，由于其通过hash比对获取的程序名，所以无法确定其所有可能调用的进程名，但通过调试可以确定有一下程序：lsm.exe、reserver.exe、ipconfig .exe、control.exe等

![image-20220304113624704.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6430b9d1304ab8a0e683b832f4a152beadb26bec.png)

- 该段shellcode的核心是通过CreateProcessInternalW函数创建系统进程，并读取所创建的进程的PEB信息，为后续的进程迁移做准备

![image-20220304105732785.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-95125bd68aa313f045e2c83b786c4d81d7a8e66c.png)  
![image-20220304150521192.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1056db5efeb4fb8643fb7c3b24fa25c90bbbc3c9.png)

### 4.3、主进程迁移

- 恢复Explorer的线程后，主体进程对映射到Explorer进程空间的内存进行持续读取，以获取其所需的新进程的信息，并对进程信息校验，检验成功后将开始新一轮进程迁移

![image-20220304154258303.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d95a96bc53c6be43efe4347fcf9480081a1dba1e.png)

- 通过读取共享内存信息，获取到进程的Pid，然后打开进程并获取其主线程，获取到Explorer创建的新进程名，然后将该PE文件在内存中复制展开

![image-20220304172630326.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3e9b2f48d0a00e96ebeca19f241f6422f4322bd1.png)

- 对新创建的**lsm**进程进行注入，仍然通过映射的方式进行**shellcode**，并对通过修改lsm进程代码入口进行劫持lsm进程，修改lsm入口点进入其第二部分代码

![image-20220304174931827.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5b5933e3381c57d8c97a777357ef05aaddd9865a.png)

- 通过分析，其二次注入的代码也可以在原始病毒模块中定位，通过对比，发现该代码与原始入口代码十分相似，除主要攻击函数不一致外，其他函数均相同，也就是说，如果shellcode执行同样会对系统进行调试检测和进程检查，所以同样需要手动patch它的检测点避免进程退出

![image-20220307095129009.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bc179b30fbf923027eeea3ae31c051bd3fd1193e.png)

- 进入核心函数，其先进行一些数据准备，然后将木马本体文件读取到内存空间，最后将删除本体文件，并在系统Program File目录下生成一个新的文件用以保存本体

![image-20220307145613425.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b3815af1750ee1c558764ef3a10760f1a4d948e8.png)

![image-20220301155009604.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-57cabdba9665afc096a82e3ede83583410a51703.png)

![image-20220307145314385.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-30dff370cc77ef8d218ee8cc13d12bed46e8198a.png)

5、二次注入Explorer进程
----------------

- 在将自身文件清除后，程序将进行一个持续的注入，初始化数据完毕后，仍然是通过hash匹配来定位Explorer进程，然后进行注入，这里循环的退出条件主要是PEB中的调试状态位和进程信息，当处于调试状态或者遍历完进程后，都将退出该循环

![image-20220307150238827.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b018a4b91049370ab0e052047b073cd2b26a6a7d.png)

- 先分析进行注入的主要函数**sub\_40C7A0**，该函数主要功能为两个，其一是线程创建进行网络通信，其二便是对Explorer进行二次APC注入。

![image-20220307155842280.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3ce7062dd792d2ede0201b59e2156991c83804be.png)

- 通过查询系统令牌获取系统用户SID，从注册表中读取到系统版本，并将这些信息通过格式转换拼接到以FBNG为头的一串数据后面。然后木马将调用NtCreateThread创建线程，而该线程的主要功能是发送和接收数据，但在该线程中需要等待到相应的数据才能触发该该事件

![image-20220307170451111.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ff3a3690375ff13333322397ef590d448ec71f58.png)

- 通过动态调试及代码定位，shellcode将打开Explorer进程，并劫持其主进程入口代码，然后进行APC注入，所注入Explorer进程的shellcode也可以在木马本体文件中定位

![image-20220307175608158.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-df8e590807b121d2136eaf26a89f42bd917c0a42.png)

6、核心功能代码
--------

- 进入其核心代码，发现其在首次运行时会将ntdll以映射的方式释放到内存中，然后修改其节区的内存属性并将shellcode拷贝到节区，然后直接跳转到ntdll内存空间中执行代码，这一步应该也是为了规避杀软的监控

![image-20220308160804408.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-92302f39ca1b78eeedd1abfa6cf999bc4679d75b.png)

- 经过分析，在ntdll空间执行的代码与Explorer的线程代码完全一致，但由于其内存数据的操作，所以原始代码可以正常执行，其先进行一些API的初始化和数据准备，其中包含一些网络和剪切板操作的API，并用base64编码用户名

![image-20220311195510761.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b456fa64a5680d11937f8c8b8755f8b9681f18d9.png)

- 然后其通过注册表获取SID信息，并将该SID和进程PID连接形成字符串作为参数创建互斥体名

![image-20220311200120445.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-dac7b71099603706ded46f9966c60347219be6dd.png)

- 互斥体创建完毕后，木马将创建一个线程来进行网络交互，并将一些返回信息保存到系统AppData目录下的ini文件，通过动态调试，可以看到解密出的其他域名

![image-20220314101108658.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-deeea38dea189d7898976fb90dd602fbddf05b7d.png)

![image-20220314101210869.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c84481670ae3a9276d3c06b7ee1fd23173628d1b.png)

- 在解密出所有的C2域名后，木马将获取到的系统敏感信息用Base64进行编码，然后将数据发往C2，别将返回信息保存到AppData目录的ini文件中

![image-20220310113529036.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a0764b872437641416c590ea1ec04f3c45bb8838.png)

7、信息窃取
------

- 由于该样本的C2全部失效，也无法通过沙箱来获取该样本的历史流量，所以无法确定返回信息，对分析样本的每个执行分支造成困难，但通过IDA可以大致了解其执行流程，如下是二次注入到Explorer进程的代码，在通过判断栈空间a1的0xCAC偏移处的值来确定攻击的主要代码，如下是一些系统关键API的HOOK和系统敏感进程的监控
    
    ![image-20220314102239157.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-187ce4fe13cb5197fc27b8f8d962bb21f429ae11.png)
    
    
    - 按键信息监控  
        ![image-20220314102553228.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-511f45fa9ee2740204ed89fb3f514df1dc555aa1.png)
    - 劫持火狐浏览器关键nspr4.dll的导出函数
    
    ![image-20220314102629171.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-263549c7f1cef672220a073f7c6d92dbc2ad3352.png)
    
    
    - 劫持基于chrome更改的浏览器核心chrome\_child.dll
    
    ![image-20220314102833947.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-dce7220450c3148f7a74f3076971930c2e7501fe.png)
    
    
    - Hook网络通信关键API
    
    ![image-20220314104145720.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e2a07c315a6d46e3067adc47f396aff23bfa9443.png)
    
    
    - 备份木马主体程序，通过注册表设置自启动
    
    ![image-20220314104453780.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-03bcda2c399a7f11d8a7d135470f47e226bd4790.png)
    
    
    - 通过注册表对Outlook信息进行检索窃取
    
    ![image-20220314104714871.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b2ddb928300c8c3ad7b9b28eebcfc949a6588743.png)
    
    
    - 针对用户IE浏览器隐私信息窃取  
        ![image-20220314104744844.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-54a022e31d152f102e88271e8ec54618ad5bbd74.png)
    - 窃取用户在Chrome浏览器的隐私信息
    
    ![image-20220411171235520.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e24c8913b2f79c854ae06b90fffb2a82ac865517.png)
    
    
    - 窃取系统凭证信息
    
    ![image-20220314105217548.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6464671a11b3988e047cf0b3a2a5a4fb0888e544.png)
    
    
    - 获取屏幕截图
    
    ![image-20220314105246692.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2886419032b630c7322dc7879abb2e2ac23b34dd.png)
- 运行过程中，木马会在系统AppData目下生成一个随机名称文件夹，并将获取的敏感信息保存到该目录

![image-20220314113443347.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1d44550a60e02ed406b369f7832d92fd88742f88.png)

8、32位进程注入64位进程
--------------

- 当系统为64位时，其先将一部分shellcode通过映射的方式注入到Explorer进程，然后解密出注入64位进程的代码，这里使用一个指令`jmp far 33:480000`，将CS寄存器设置为0x33然后跳转到0x480000去执行，这里由于CS寄存器设置为0x33时将切换为64位模式，所以跳转到0x480000内存中执行64位shellcode

![image-20220303195805170.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-92891e7eb21f555476dc7dbfb1aaa0f8dc1a57fb.png)

- 此时无法使用32位调试器跟进调试，但使用windbg可以进行代码空间执行跳转

![image-20220304102712387.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e998eab7537807c2ba72bf45b0c9316590155dc4.png)

- 经过分析，其后续功能代码与32代码一致，均会启动一个system32目录下进程再次进行注入

0x05 溯源
=======

- 涉及到的C2域名  
    www.rkprops.com  
    www.transcriptionservicesindia.com  
    www.drayeshaafzal.com  
    www.streetlogic.biz  
    www.protokolavukatlik.com  
    www.aokmanagerbox.com  
    www.subconsciousgod.com  
    www.bitracks56.com  
    www.thelenditudenews.com  
    www.quinube.online  
    www.ottowagnergruende.wien  
    www.magstyletravelingllc.com  
    www.520kouzi.com  
    www.atomicpropertiescarrboro.com  
    www.niasara.com  
    www.tllyou.com  
    www.zerogamesober.com

0x06 总结
=======

该样本主要由外层加载器和内层formbook商业木马组成，木马完全由汇编语言编写，并且所有的敏感数据都被加密，函数调用都通过动态获取进行调用，在分析调试过程有很大的难度。木马通过注入的方式运行其核心代码，使用Map映射方式创建共享内存来进行数据交互，执行过程中在两个进程间不断切换，同时存在多个线程共同协作进行系统敏感信息窃取以及数据接收发送，对用户隐私和企业网络安全构成严重威胁。

0x07 参考文章
=========

- <https://www.stormshield.com/news/in-depth-formbook-malware-analysis-obfuscation-and-process-injection/>
- <https://blog.wuhao13.xin/2793.html>