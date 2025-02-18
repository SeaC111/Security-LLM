0x00 前言
=======

黑月是一个把易语言程序小型化，脱离支持库运行的工具。

文件的基本信息如下：

|  |  |
|---|---|
| 文件名称 | bca11af3fb5437be2c8ce4fae6230836+0aa6f9f75c8e329ae23b3118bcfbf71018fe3a1a\_bca11af3fb5437be2c8ce4fae6230836.vir |
| MD5 | bca11af3fb5437be2c8ce4fae6230836 |
| SHA-128 | 0aa6f9f75c8e329ae23b3118bcfbf71018fe3a1a |
| SHA-256 | d44e73f421132ef7a39c219988821cb4e44fe8dbde5e8d0acbf8cd6a9a156d3d |

0x01 初步观察和信息的收集
===============

1.1人为执行分析
---------

该样本伪装成日历的样子诱导用户点击，图形如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-be0eaaa4f91585645d3834bea0be96a044077411.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-416b3c190e3c33e968a6ef3853c1175993f6e22d.png)

直接在虚拟机运行发现，无明显的操作行为，通过ProcessMonito发现文件在C:\\Users\\admin\\AppData\\Roaming\\Micorsoft\\Winows\\Start Menu\\Programs\\Startup(程序开机启动路)创建了一个文件后退出。

1.2沙箱检测
-------

VT查询：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-13eed8788a2efc673878fccf92af096447ce7549.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bfc91891aaeffb007e4d16d2651f61f0661a41e9.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-426b7b96462b62f503d92c2d5308b5d394f372a2.png)

初步信息总结:

反检测，有网络连接，有键盘钩子，包含洋葱地址：

[http://m3r7ifpzkdix4rf5.onion/kpanel/connect.php，和窃取密码信息的行为](http://m3r7ifpzkdix4rf5.onion/kpanel/connect.php%EF%BC%8C%E5%92%8C%E7%AA%83%E5%8F%96%E5%AF%86%E7%A0%81%E4%BF%A1%E6%81%AF%E7%9A%84%E8%A1%8C%E4%B8%BA)。

洋葱网络：洋葱网络是一种在计算机网络上进行匿名通信的技术。通信数据先进行多层加密然后在由若干个被称为[洋葱路由器](https://baike.baidu.com/item/%E6%B4%8B%E8%91%B1%E8%B7%AF%E7%94%B1%E5%99%A8/1611422)组成的通信线路上被传送。每个洋葱路由器去掉一个加密层，以此得到下一条路由信息，然后将数据继续发往下一个洋葱路由器，不断重复，直到数据到达目的地。这就防止了那些知道数据发送端以及接收端的中间人窃得数据内容

0x02 正式分析
=========

2.1查询壳信息
--------

通过exeinfo查看样本信息发现是一个带upx壳的32位样本。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-73c6a6ff21abc1ab03bd30a32ee5ddddad1a6004.png)

通过oep法，脱壳后用插件修复导入表。

脱壳前数据：609KB

脱壳后数据大小：1.33MB

**样本的整体行为流程图如下：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f1aefc6bb150a0e4fc1feb2a21709fd0f0f0aa3d.png)

2.2第一层脱壳后的样本
------------

先静态分析，先观察字符串和导入函数窗口看看是否有特别有用的信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d84e3b722ca7e0f141105f90ce274de34370077d.png)

字符串没有看到特别有用的信息

数据的前面是一些混淆的数据，动静结合去分析，找到关键的解密数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-97dc29d8ff76006ffc22ec7f506767d0613be31f.png)

2.3第二层shellcode1
----------------

把数据dump分析，大小如图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bdc90a0b53f341bacd744e89f12282101cf3c4ee.png)

第一层shellcode1执行流程：

1）先获取函数或dll的地址：

kernel32.dll、GlobalAlloc、GetLastError、Sleep、VirtualAlloc、CreateToolhelp32Snapshot、Module32First、CloseHandle

2）通过获取到的函数进行系统遍历

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-fabcc0e2fe2130d87ba99f22f3d89cbcec5d90cf.png)

3） 对申请内存后对shellcode进行解密

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d8aad648cf59bd49ca41a8a1a2a52531baec4cc7.png)

2.4第三层shellcode2
----------------

第一层shellcode1传入第二层shellcode2的数据

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8e983d131f5f1bb537c18414eb41b985e02acd61.png)

第二层shellcode2对数据，进行解密后，跳转到第三层

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c1a81f95f30483f2c3897ab31461bd4ab0fddd59.png)

2.5第四层shellcode3
----------------

继续进行解密后，跳转到全新的exe中

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-90288e9a7337ccd994cf1c907c98c8b8a8027b2c.png)

2.6第五层last.exe
--------------

通过winbdg，把数据dump下来，主函数功能如下图所示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-902856395f20e382a34164188812139a907df00f.png)

### 2.6.1隐秘解析ntdll.dll

为了防止被一些软件检测到，程序从自己的代码中直接调用底层函数，不使用代理ntdll.dll，通过从ntdll.dll中获取到系统调用编号，并通过名称哈希值来识别这些函数。

函数名称哈希表如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7fe30ba3289a84f3ceb8f83ca959f7c04831767c.png)

Ntdll.dll文件操作执行流程如下：

1.获取ntdll.dll导出表到内存中

2.创建堆空间,获取ntdll.dll模块基地址

3.ExpandEnvironmentStringsW转换环境变量为路径：

L"C:\\Windows\\system32\\ntdll.dll"

4.打开ntdll模块，获取大小，读取到申请的堆空间

5.通过哈希值识别，并导入函数

6.校验是否正确读取文件

7.拷贝PE头部信息，节区体等信息到VirtualAllocEx申请的内存中，并修复重定位表。

8.判断ntdll.dll是否存在导出表不存在释放空间

获取ntdll路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-71899e3222f16c262524a5e146c2433da5acd2c5.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4a74e4f1f907e282657c3c010979c0d605c5f9f7.png)  
收集当前程序及环境信息

1.加载ntdll.dll模块，调用RtlGetVersion获取OS版本信息

2.判断当前程序是否以管理员权限启动

3.DeviceIoControl获取当前磁盘信息

4.将环境变量%APPDATA% 和%WINDIR%\\System32 转换为路径字符串

a)L"C:\\Windows\\System32"

b)L"C:\\Users\\XXX\\AppData\\Roamin"

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f653e2281608af9a8890112757be5385dbe8e2c3.png)

### 2.6.2从C&amp;C服务器中获取配置文件

last.exe可以从C&amp;C服务中下周带有data\_injectd的配置文件，配置文件与last.exe路径相同。机器人向C&amp;C服务器发送信标，其中包括：

1.配置文件的哈希

2.CoCreateGuid()生成GUID，代表唯一标识符

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-83811bd14976aa611c1a117b86d946da15362268.png)

### 2.6.3提权、遍历进程和尝试进程注入

提权函数IDA查看无调用，猜测通过相对偏移调用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-15c227958a295671ab1552c9886aaf6c778f80a0.png)

检查权限：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c13cd12b8b15f73f62d68ae7ad1e10de42236aba.png)

遍历进程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a39a539dd12c01758f5172c868fbc63e6842d3ab.png)

### 2.6.4防守检测

last.exe1通过前面获取到NtQuerySystemInformation获取系统信息，它却为我们提供了丰富的系统信息，同时还包括对通过PEB 遍历模块链表，检测是否存志指定的模块信息。以下是这个函数的原型：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6f3f7c2bcf34f2d4c203de4a886caefe0347a5d5.png)  
然后遍历系统进程，扫描到vm的相关进程后退出，设置标志defensive\_checks=1.

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-acd80ba376355a0af7134a8b9e57c3229a3d6d44.png)  
判断防守标志后退出程序

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-edf37151015636e1aa95dbd7960bf6974c7e40ba.png)

### 2.6.5初始化和创建远控程序VNC

在Github上发现初始化VNC远程软件的源码与我所分析的样本大体相同

VNC远控软件的初始化，直接连接网络，创建服务

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a29f92a53868d681165e50543e76ab1b64d3d3cb.png)

GitHub上的源码： 样本源码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bb02607c289d3aa6aefc71aa76a2cd727a35b21c.png)

VNC通过RFB协议建立链接

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0314a9e4a8509ef252561c80b25edcb048b7d1eb.png)

github源码地址：

<https://github.com/frankzhangv5/fastdroid-vnc-server/blob/e5d0221030881b1330c09e3fdcd2c7539cfbcddf/LibVNCServer-0.9.7/libvncserver/stats.c>

### 2.6.7窃取键盘消息

last.exe可以在自身进程中运行一个键盘记录器的线程，键盘记录器安装键盘钩子

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7c05ee0c439f1f9c4bc64973b613bafa4763da5e.png)

回调函数收集进程名称、窗口标题的文件以及挂钩窗口中键盘输入的内容，最后通过主线程C&amp;C服务器传输回去

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-215d7ab638508e86c5b6f7dd88940351b9303c35.png)

### 2.6.8复制自身到开机启动项和持久化

把自身复制到开机启动项中，并重新命名为bac58a5f.exe  
静态查看：

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-20d99a5e6c049c7c34dfdda2fb888d888dae5542.png)  
动态调试：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-861f5410ff53554101da116b0226b36da59d6cab.png)  
**持久化：调用函数instal\_bot\_in\_registry\_and\_AppData**

**执行流程如下：**

1.%APPDATA%\\Microsoft\\{GUID 字符串}\\bac58a5f.exe

2.\\REGISTRY\\USER\\SID 字符串\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion

3.Software\\Microsoft\\Windows\\CurrentVersion\\Run

4\. Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5fbd855632fd06cf2a63ea47d4dde25d12a16c61.png)

### 2.6.9窃取浏览器和outlook用户数据

last.exe通过VNC远程发包，在本地解析包数据，通过一个大的switch——case执行不同吗的命令，执行命令如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-cc21bf077a934b20c70f5f22ab5bbce1c60dac77.png)

**使用以下流程抓取filefox的数据：**

1\. last.exe通过访问%s\\\\Mozilla\\\\Firefox\\\\profiles.ini中的路径来获取profile文件的路径，该路径包含包含了用户信息

2\. 然后它从注册表中获取了filefox安装路径加载了nss3.dll

3\. 通过nss3.dll，解析用户数据

获取firefox配置文件路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-13849908afefb3af44cdc0f3b9b619ee9d00c794.png)

获取注册表中的库路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f37802079591de5dbcb9a7b34f4a27abf588fb5c.png)

加载nss3.dll库，解密数据：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c66f17d8698b453a1fc3cbb36d0dda7b0f928767.png)

**多路径查找outlook的配置文件数据：**

|  |
|---|
| 注册表路径 |
| HKEY\_CURRENT\_USER\\Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676 |
| HKEY\_CURRENT\_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676 |
| HKEY\_CURRENT\_USER\\Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676 |
| HKEY\_CURRENT\_USER\\Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676 |

**收集以下注册表的值：**

SMTP Server 、IMAP Server、POP3 Server、email、IMAP Passwords、SMTP Passwords、POP3 Passwords等收集到的数据然后由CryptUnprotectData()解密。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a87c457e1dba5e6fefc1d999c54a5622df9ce34a.png)

**调用另外的远控软件或hellworld.exe**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b388cbe37a0d374bfa8599c167c82f46c36b11ba.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-59847ee7d69598bd4286afc6a08388e0b6524995.png)

3.IOC
=====

**MD5**

|  |  |
|---|---|
| MD5 | 文件大小 |
| 6F8B0451B7DEA07B423650E0B8C7094C | 444938 bytes |
| B4CD27F2B37665F51EB9FE685EC1D373 | 3584 bytes |

**URL**

|  |  |
|---|---|
| **获取方式** | URL |
| **字符串解析** | <https://api.ipify.org/> |
| **字符串解析** | <http://ylnfkeznzg7o4xjf.onion/kpanel/connect.php> |
| **内存中解析** | 194.109.206.212 |
| **内存中解析** | 154.35.175.225 |
| **内存中解析** | 199.58.81.140 |
| **内存中解析** | 193.23.244.244 |
| **内存中解析** | 128.31.0.34 |
| **内存中解析** | 131.188.40.189 |
| **内存中解析** | 171.25.193.9 |
| **内存中解析** | 204.79.197.219 |
| **内存中解析** | 192.23.244.244 |

0x03 结论
=======

具提供的信息表明这是一个远控木马，跟某商业木马Kronos具有相同的起源，功能并不新颖，但精巧的方式（ntdll的调用）还是值得学习的，该代码被很好地混淆了，并且还使用了各种技巧，这些技巧需要了解操作系统的一些低级工作原理。

0x04 附录
=======

**dump\*\***一些问题的说明：\*\*

在第四层shllcode3进入第五层last.exe1,这时候从内存中dump数据的PE会出现一些问题，需要换一个时间去dump，直接跑起来，进程退出之前，在任务管理器中去完整的dump，最后通过windbg去修复导入表、入口点。经过多工具反复dump具体出现的问题如下：数据数据缺失会造成IDA分析的数据不准确，以下图为例：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2094df950e42cec14ffe638c369de0c0f9877ad2.png)

正确的dump流程可以通过视频连接查看视频：

<https://www.aliyundrive.com/s/1EmXJRadWBJ>

windbg工具：

<https://www.aliyundrive.com/s/f4nkB9MQwri>

**关于last.exe调式入口点和PE入口点不同的问题：**

调试入口开始运行**last.exe**，您将在下面找到一些提示。

函数的第一个块负责填充注入模块的导入表。如果我们想从那个点开始运行样本，而不是在注入时跟随它，有一些重要的事情需要注意。首先，加载器应该在注入的可执行文件中填充一些变量，即变量*module\_base*。其他函数会引用这个，因此，如果它不包含有效值，则示例将崩溃。此外，填充导入的函数需要\*.rdata\**部分*（包含要填充的块），设置为可写。在注入样本的情况下，它将被设置为可写，因为那时，完整的 PE 被映射到具有 RWX（读-写-执行）访问权限的内存区域中。然而，在正常情况下——当样本从磁盘运行时——它不是。这就是为什么，为了通过这个阶段，我们需要手动更改对该部分的访问权限。

另一种选择是从主函数的下一个块开始运行**last.exe**示例。这也导致成功执行，因为如果样本是从磁盘运行而不是注入，则导入由 windows 加载程序填充，手动执行只是多余的。

调试入口：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a203a417efdf8b23ff18dd916b2be6d4600c8017.png)

PE入口点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d5cb3656ec13e392f7609677b723d48dbb918d23.png)