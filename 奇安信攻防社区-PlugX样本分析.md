0x01 样本信息
=========

样本基本信息如下。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d351ec5980238c2b0be349eb9b1daad6f6e39180.png)

该样本为WinRAR的自解压文件（即SFX, SelF-eXtracting），由于自解压文件不需要依赖解压缩文件便能运行，所以在Windows系统上经常会用exe文件后缀。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d2c17a7b3b3ca0682c874c9e47a51ad1a1f262b0.png)

将文件名称用rar文件后缀替换，右键打开文件，可以看到自解压脚本。压缩包中包含3个文件，自解压脚本会启动其中的mcs.exe文件。

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0f278c95eb69fd9231cca80e40441df1f11fe825.png)

0x02 样本特点
=========

该样本具有如下特点：

- 木马文件本身隐蔽性较强，样本中的mcs.exe和mcutil.dll文件只起到加载最终木马文件mcutil.dllsys的作用，而mcutil.dllsys包含木马程序的shellcode还添加了花指令混淆和加密处理。木马程序使用的API通过GetProcAddress动态加载，使用的重要数据也进行了额外的加密。
- 木马以创建服务的方式实现持久化，复制样本涉及的三个文件到指定目录中，并将目录和文件属性设置为系统隐藏，同时在执行时将自身注入正常进程从而隐藏踪迹。
- 木马与C&amp;C服务器的通信数据用流密码进行加密。

0x03 样本执行过程
===========

木马加载过程
------

mcs.exe文件执行时会加载同一目录下的mcutil.dll文件

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-36b459e94ebf7ffc130a968e644134cc1e0d484e.png)

进入mcutil.dll后，DllMain函数会调用偏移在0x10B0处的函数

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cb129836231534b153e5f99528a1b261ff19b341.png)

该函数首先检查当前日期是否不小于2014年1月2日，然后获取与mcs.exe加载基址偏移0x2F0C的地址，该地址就是mcs.exe调用LoadLibraryW函数加载mcutil.dll的返回地址，接着将该地址所在内存页权限修改为PAGE\_EXECUTE\_READWRITE(可读可写可执行)，并计算计算mcutil.dll中0x1000函数与返回地址的偏移值，根据该偏移值将返回地址处的指令修改为一条jmp指令（指令码0xE9）。

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8a6371e9b4a7f5ed68b817d8a4893ce705880e6c.png)

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-71ec4265a932f49652f19a2cb5b65321e92eb296.png)

返回地址处的指令修改后如下图所示。样本通过这种方式实现间接跳转，增加自身的隐蔽性。

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fe0bbbb734336bc411ef61f8dbc6d0a1ec800ef1.png)

mcutil.dll偏移0x1000处的函数将同一目录下的mcutil.dllsys文件内容读入内存并执行。

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fe9c09b22f9158d7bf407bfc430b24fa34132d02.png)

mcutil.dllsys中的shellcode首先通过一系列jmp花指令进行混淆，在花指令中包含着一段解密逻辑，将shellcode偏移0x203处，长度为0x1AB5D的二进制数据进行原址解密处理。

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ab0088740366972770d154356c1dd2fd73685039.png)

解密之后0x203处开始的指令如下。

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5a185ad985bfb04badd44d3aa64045516855c93b.png)

0x203处指令为sub\_241构建的参数数组包含7项，前两项为解密后的shellcode起始地址以及到shellcode末尾的长度，第三四项为后续要释放的一个DLL文件的压缩数据起始地址以及长度，第五六项为木马使用的重要数据密文的起始地址以及长度。

| 参数数组序号 | 数组元素值 |
|---|---|
| 1 | Shellcode偏移0x203处地址 |
| 2 | 0x1d09d |
| 3 | Shellcode偏移0x722处地址 |
| 4 | 0x1a63e |
| 5 | Shellcode偏移0x1ad60处地址 |
| 6 | 0x2540 |
| 7 | 0 |

Shellcode中的sub\_241函数将偏移0x722处的数据用RtlDecompressBuffer以LZ格式解压缩，解压出的数据为一个稍作变形的PE文件。将解压数据导出后，修改偏移0x00处和0xD8处的数据分别为”MZ”和”PE”，修改之后的导出数据被识别为DLL文件。

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b7f71c666859ca68c31bb7b8519e8802beec3049.png)  
![10.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2fce0e68a5b95828f104394bfc71432d091e099a.png)

然后sub\_241为解压到内存中的DLL数据各个段建立映射，并根据基址重定位表和导入表对DLL进行重定位，然后转入释放的DLL入口点。

内存中释放的该DLL为木马的主程序，木马首先将shellcode中的加密数据释放出来，复制到木马DLL偏移0x26470的位置。

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f9e18dc6d1a360b9c223c53dfe559309a8956a0c.png)

数据使用流加密，初始key为加密数据的前4字节，解密过程如下。

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ad7e2d9376ea3e02a414d6a10d4d9d0b93470f79.png)

这部分数据包含木马基本的配置内容，包括备选C&amp;C服务器域名端口，用于持久化过程所需创建的服务名称等。

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-faa6448b0cf73eee31ad0c6f88fccf622df24e77.png)

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ce9e34065fe1344d6a181a55ac7367a401cbf192.png)

除了这部分数据，木马执行过程中使用的一些字符串只在使用时解密，用完马上清除明文，这些字符串也用与上文所述类似的流密码方式加密。

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f76f0b7433de6cdf60488261e145de0aed16b4da.png)

![16.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d403dd749819568c53dcaae92f2dd68384acc696.png)

持久化与隐蔽执行
--------

木马完成配置数据初始化后先尝试获取SeDebugPrivilege和SeTcbPrivilege权限。

![17.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3ab6553f7b0636ce926fa37964fdac9b496418c2.png)

木马比较当前程序执行命令的文件路径与一个目标路径是否一致，如果不一致则进行持久化操作。

![18.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-dcfc3d8501b5afe8e84b7550d533eb8cb4c77656.png)

![19.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-127c4f51ee6b188d692a4d64f9fac4d57bb3e4cc.png)

在该分支中木马首先根据自身进程的pid和父进程的pid分别创建一个互斥量，用于后续防止程序多开。

![20.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-448b60b740d772dd552c0451a967e658b70d48e6.png)

木马在注册服务前会先检查系统是否开启了UAC保护，在系统开启UAC保护的情况下，木马会通过远程线程注入的方式绕开UAC的限制。

![21.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e655bea5292b99d86f5933383e1f53771f921d0d.png)

注入前木马首先会释放一个DLL到磁盘中，该DLL的作用是启动所属进程命令行参数1对应的可执行文件。木马选择注入的进程为Windows Installer使用的msiexec.exe。

![22.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bb2e01573a5ce4f8b6d95e8c515c47c0a2ae74e8.png)

注入msiexec.exe进程的函数会利用Windows上的migwiz工具进行提权，该工具用于Windows XP和Vista升级Windows 7之后用户配置文件等数据的迁移。

注入函数首先将之前释放的DLL替换为migwiz所在目录下的dwmapi.dll文件，然后以提权的方式启动migwiz，样本中mcs.exe的文件路径作为migwiz的命令行参数，这使得Migwiz在加载被替换的dwmapi.dll后，木马再次启动，并且具有更高的权限。

![23.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e581125ab6055e8cfd9e6acc24022ab73a669f6e.png)

在Windows 7上用ProcMon监测到的进程创建顺序如下：

![24.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6d504d8d5c831b5ac8c70c357971537bc6c06e36.png)

木马根据Windows系统版本获取一个复制样本文件的目录，目录路径为“系统版本相关目录”+“服务名”。在Windows 7中系统版本相关目录为”C:\\ProgramData”,木马使用的服务名为”IcdSysSvc”，所以创建的目录名为”C:\\ProgramData\\IcdSysSvc”

![25.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d0024fd8b5fbb614518c2701555f9860a39fbeda.png)

![26.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9af9057dd646f8a0aae4c7847d88e8cb16afa6f2.png)

然后将样本涉及的3个文件复制到创建的目录中。

![27.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e6253192cb25e0009fd93bb1b6e9d7738b231c55.png)

木马将上述目录与复制的文件都设置为系统隐藏属性以隐藏自身踪迹。

![28.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3689df327c0862179e3e29aa94dd03527767624d.png)

![29.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c85816a1b5e16dbe43d119a984e25ce84d8502be.png)

木马通过SCManager创建一个名为IcsSysSvc的自启动服务实现持久化。

![30.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e5d989b52731c5e2342bf98f866a948ba066c293.png)

如果通过创建服务实现持久化失败，木马会尝试在注册表中设置自启动项，在“HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run”键下新建名为IcdSysSvc的值项，其数据为文件路径“C:\\ProgramData\\IcdSysSvc\\mcs.exe”。

完成持久化操作后，木马会将mcutil.dllsys解密之后的shellcode部分注入正常进程，实现隐蔽执行。木马选择注入的目标为wmplayer.exe或者svchost.exe。

![31.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cd98c6e01a6acba1243fe339acae2edcbf7d7526.png)

![32.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ba4aa3e4c0887f92157fa93a6a718882a606ccfe.png)

注入完成后，木马会结束其他运行的木马进程。通过检查由进程pid生成的互斥量是否已存在判断其他进程是否与木马相关，如果相关则调用TerminateProcess结束该进程，ExitCode设为1223。

![33.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bb5c7676e053df52233cf90e9645127fed7f72b6.png)

![34.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-aac82b1c3dea4a050206a4ad1767179ecec64abd.png)

C&amp;C通信
---------

配置数据中给出的C&amp;C服务器的域名与端口号分别如下。木马会依次尝试与配置数据中的4个C&amp;C域名建立TCP连接，如果前一个域名无法建立连接则会尝试下一个。

| 序号 | 域名 | 端口 |
|---|---|---|
| 1 | facebook\[.\]controlliamo\[.\]com | 80 |
| 2 | hpservice\[.\]homepc\[.\]it | 443 |
| 3 | dsf14sdf23edfewfewfe\[.\]com | 80 |
| 4 | sdfsewd3fw3dsad\[.\]com | 443 |

木马与C&amp;C服务器通信的报文格式如下，包括16字节首部以及最大长度为0xF000的数据区。

![35.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9089e2d00fea40a39e56bd9004bd72bb918b8e59.png)

![36.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a6b602325eb1a475f10b1043afa91b7a8127122b.png)

报文发送前先进行处理，具体处理方式与首部的code\_num字段的第28和29位有关，处理完之后size字段的低16位保存处理后数据长度，高16位保存原始数据长度。 报文数据部分处理完成之后，会对报文首部用流加密的方式进行处理，加密之后会将流加密使用的初始key写回报文首部。

![37.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-90f0dd4cb12387047a3dea3df8360e9f6b5378a3.png)

整理后的报文数据处理方式如下：

| 报文首部code\_num第28位和第29位 | 处理方式 |
|---|---|
| 0 | 先进行LZ压缩，再进行流加密 |
| 1 | 只进行流加密 |
| 2 | 只进行LZ压缩 |
| 3 | 不处理 |

木马从C&amp;C服务器获取的报文也会以相应的方式进行解密，如下所示。

![38.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d868e45dc4e319a08b2ef19b4f68c493c5c44a1c.png)

建立连接后木马等待接收C&amp;C服务器的指令，如下所示。

![39.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b7480df1fc432dcf895f4b42a5a43efadb4c8a97.png)

如果code\_num为3，则从C&amp;C服务器接收进一步的远控指令并执行，木马提供的部分远控指令如下。

![40.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1630a9f072de7ce423efbc0ab17ddf6b04c25c1f.png)

根据通信报文首部code\_num整理的木马功能如下

| 报文首部code\_num字段 | 功能 |
|---|---|
| 0 | 与C&amp;C服务器建立连接后通知C&amp;C服务器 |
| 1 | 获取感染主机各种软硬件信息 |
| 3 | 开始执行木马指令 |
| 5 | 卸载木马，包括删除服务、清除注册表相应键值以及删除相应文件 |
| 6 | 发送木马当前使用的配置数据 |
| 7 | 保存C&amp;C服务器发送的配置数据，并重新加载配置数据 |
| 0x2000 | 锁屏 |
| 0x2001 | 注销 |
| 0x2002 | 重启 |
| 0x2005 | 消息弹框 |
| 0x3000 | 获取磁盘信息 |
| 0x3001 | 获取指定目录下的所有文件和子目录信息 |
| 0x3002 | 递归获取指定目录下的所有文件和子目录信息 |
| 0x3004 | 读取文件 |
| 0x3007 | 将数据写入指定文件 |
| 0x300A | 创建目录 |
| 0x300C | 创建进程 |
| 0x300D | 调用SHFileOperationW进行文件复制、移动、重命名以及删除操作 |
| 0x300E | 设置环境变量 |
| 0x4000, 0x4100, 0x4200 | 屏幕截图相关功能 |
| 0x5000 | 获取所有进程信息 |
| 0x5001 | 获取指定进程的所有模块信息 |
| 0x5002 | 终止指定进程 |
| 0x6000 | 枚举服务信息 |
| 0x6001 | 更改服务设置 |
| 0x6002 | 开启指定服务 |
| 0x6003 | 向服务发送控制指令 |
| 0x6004 | 删除服务 |
| 0x7002, 0x7100 | 创建远程shell |
| 0x9000 | 枚举指定注册表键下的子键 |
| 0x9001 | 创建注册表键 |
| 0x9002 | 删除注册表键 |
| 0x9003 | 复制注册表键下的子键和值项，并删除原键 |
| 0x9004 | 枚举指定注册表键下的值项 |
| 0x9005 | 查询值项数据 |
| 0x9006 | 删除值项 |
| 0x9007 | 设置值项数据 |
| 0xA000 | 枚举现有的所有网络连接 |
| 0xA001 | 关闭和新增网络连接 |
| 0xB000 | 端口映射 |
| 0xC000, 0xC001, 0xC002 | SQL管理 |
| 0xD000 | 获取TCP连接信息 |
| 0xD001 | 获取UDP端口信息 |
| 0xD002 | 设置TCP连接状态 |
| 0xE | 发送键盘记录数据 |

0x04 IOC
========

31d0e421894004393c48de1769744687

facebook\[.\]controlliamo\[.\]com  
hpservice\[.\]homepc\[.\]it  
dsf14sdf23edfewfewfe\[.\]com  
sdfsewd3fw3dsad\[.\]com