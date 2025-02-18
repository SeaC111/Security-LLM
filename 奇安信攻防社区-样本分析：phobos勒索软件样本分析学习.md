样本基本信息
======

![image-20240914172625919](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0f544bb597c5f8b00c6ee5d3beab91491d28374f.png)

基本信息：

- 文件大小：61kb
- MD5：ca52ef8f80a99a01e97dc8cf7d3f5487
- 文件类型：exe
- 病毒家族：Phobos

基础分析-持久化
========

![image-20240914173428122](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e1e2a0ffdfaaf726109804e11202477fed200095.png)

该勒索软件带有加密配置，可以使用硬编码的AES密钥解密，加密逻辑在`sub_4062A6`中。

`sub_40646A`：

![image-20240914173648086](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2825f1b28ab18f74170c3f5c32f7e5d47442d0f7.png)

该勒索软件自定义实现的AES加密算法，不需要依赖WIndows API。

![image-20240914173748589](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-00f308a050542dbf4de11fe8c5411cc25d31b60f.png)

回到入口，该勒索软件使用`GetTickCount()`检索自系统启动以来经过的毫秒数：

![image-20240914173838232](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-de41aa2e273d0261b01af32dde0ee53de8b6e239.png)

GetLocaleInfoW 函数用于获取操作系统的默认语言环境 (0x800 = **LOCALE\_SYSTEM\_DEFAULT** , 0x58 = **LOCALE\_FONTSIGNATURE** )。

![image-20240914174510006](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b7dbd093fca906cd7fbd4c7053c26693b18360c4.png)

二进制文件通过调用 GetModuleFileNameW 函数检索当前进程的可执行文件的路径，如下图：

![image-20240919064647684](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2568e1574c6a190fb375e7f32720eed1393c770a.png)

调用`CreateFIleW`寻找一个文件（0x80000000 = **GENERIC\_READ**，0x3 = **OPEN\_EXISTING**）

![image-20240919064816040](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a5b5da3350667722db03366a0afb2a1fae9f2435.png)

接着它使用`GetVersion`方法提取系统的主版本号和此版本号： ![image-20240919065108447](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ae1a9221742f6647e984213e6ad028c1d3906862.png)

![image-20240919065142597](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a23288f3418eccaa0a395e6883ff0ae12a6e8cb6.png)

如上图，还调用`OpenProcessToken` API打开与当前进程关联的访问令牌，之后用 `GetTokenInformation`验证令牌是否被提升。

环境变量“％systemdrive％”被展开，显示了包含Windows目录的驱动器：

![image-20240919065430250](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d771210ccb85381fc86ce240b173270e193b4137.png)

该勒索软件还创建了俩个互斥锁：

![image-20240919070509754](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-158d1883e3d961557b2987e2d78da8665c3b2625.png)

分别是`Global\\<<BID>><Volume serial number>00000001`和`Global\\<<BID>><Volume serial number>00000000`。

通过`GetouduuleHandle`获取了Kernel.dll的模块句柄。

![image-20240919070732563](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f10644cf8e33d3fb6bf5233c14978143f49582d5.png)

勒索软件还会使用到`GetShellWindow`函数获取Shell桌面窗口的句柄，通过`GetWindowThreadProcessId`函数来检索创建窗口的进程，例如explorer.exe。如果检索到窗口，会使用`OpenProcess`方法来打开文件句柄。

![image-20240919071154441](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a1474536a1c80cb8c952c5b038497e6d73c563d5.png)

在上图中，`DuplicateTokenEx` API 用于创建一个新的访问令牌，该令牌复制上面提到的令牌。勒索软件在新创建的令牌的安全上下文中运行，它创建一个新线程，该线程将在`sub_264B85`函数中运行以下命令：

- vssadmin delete shadows /all /quiet – 删除所有卷影副本
- wmic shadowcopy delete – 删除所有卷影副本
- bcdedit /set {default} bootstatuspolicy ignoreallfailures – 如果启动、关机或检查点失败，则忽略错误
- bcdedit /set {default} recoveryenabled no – 禁用自动修复
- wbadmin delete catalog -quiet – 删除计算机上的备份目录
- netsh advfirewall set currentprofile state off – 禁用当前网络配置文件的防火墙
- netsh Firewall set opmode mode=disable – 禁用防火墙

![image-20240919071545264](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-337fdec156114f116fac1d814193a133c871230b.png)

![image-20240919073058897](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b96f4baf4574dc80b7b59bc866ef866c3bd1d162.png)

接着往下走：

![image-20240919073300939](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c789c521aba7badb2cfc4a1bfe92c5d666c8ec0b.png)

该进程将其可执行文件复制到“%AppData%\\Local”目录。

`RegOpenKeyExW` 用于打开 Run 注册表项。该勒索软件通过创建一个基于可执行文件名称命名的条目来建立持久性，该条目指向新创建的可执行文件：

![image-20240919073500354](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8426a8c3cd003f8f8250a0e63b741113e84889a0.png)

![image-20240919080027966](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-09e35d7edfac0af52f155b83df3f9c03e8728df2.png)

以下是该勒索软件的加密目标：

 fdb sql 4dd 4dl abs abx accdb accdc accde adb adf ckp db db-journal db-shm db-wal db2 db3 dbc dbf dbs dbt dbv dcb dp1 eco edb epim fcd gdb mdb mdf ldf myd ndf nwdb nyf sqlitedb sqlite3 sqlite

线程活动
====

sub\_XX22EE 函数
--------------

![image-20240919080216345](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-556d66a6b58ffaf0ad0dee66ddc71c45aaa59e9d.png)

![image-20240919080310087](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0458adfc9ae37bff87d548b5702e8da438b41e0c.png)

恶意软件打开与当前进程关联的访问令牌（0x20 = **TOKEN\_ADJUST\_PRIVILEGES**），LookupPrivilegeValueW 方法用于提取代表“SeDebugPrivilege”权限的本地唯一标识符（LUID），之后通过调用 AdjustTokenPrivileges 来启用上述权限。

以下进程将被终止，因为它们可能会锁定要加密的文件：

 msftesql.exe sqlagent.exe sqlbrowser.exe sqlservr.exe sqlwriter.exe oracle.exe ocssd.exe dbsnmp.exe synctime.exe agntsvc.exe mydesktopqos.exe isqlplussvc.exe xfssvccon.exe mydesktopservice.exe ocautoupds.exe agntsvc.exe agntsvc.exe agntsvc.exe encsvc.exe firefoxconfig.exe tbirdconfig.exe ocomm.exe mysqld.exe mysqld-nt.exe mysqld-opt.exe dbeng50.exe sqbcoreservice.exe excel.exe infopath.exe msaccess.exe mspub.exe onenote.exe outlook.exe powerpnt.exe steam.exe thebat.exe thebat64.exe thunderbird.exe visio.exe winword.exe wordpad.exe

该恶意软件会对系统中所有进程进行快照，如下图所示。

![image-20240919080444820](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-3c054ed35901df7736bc067a545eac2b0a5ca8cd.png)

使用 `Process32FirstW` 和 `Process32NextW` API 枚举进程，再使用`TerminateProcess`方法停止任何目标进程：

![image-20240919080527614](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ac85719a6018b3d4e29dcede1b1494eded4df7d8.png)

sub\_XX239A函数
-------------

![image-20240919080647541](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7790fd4f810a5a8d12bc4f834eb46f1c4fc5c557.png)

`OpenProcessToken` 用于打开与进程关联的访问令牌（0x8 = **TOKEN\_QUERY**），二进制文件通过调用 `GetTokenInformation` API（0x14 = TokenElevation ）再次验证令牌是否被提升。

勒索软件它再次使用“Global\\&lt;&lt;BID&gt;&gt;&lt;Volume serial number&gt;00000000”互斥名称调用 OpenMutexW 和 CreateMutexW 方法：

![image-20240919080821091](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-79bd49704335ba2e7aa308461b23b57c77ef3d1c.png)

sub\_XX2161函数（加密网络共享）
---------------------

![image-20240919080851278](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ef1a91825ddfab2c0309135b8e532d292aee0ec0.png)

![image-20240919080920548](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0f66227cdb5b0a3641827f9a16cd71300e288646.png)

勒索软件使用事件来同步线程。它使用 `CreateEventW` 创建两个未命名的事件对象：

创建完事件对象后提取本地机器的 NetBIOS 名称：

![image-20240919080958980](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2bb08a5177af1bb7d7033897a98323fd16d2cfcd.png)

`WNetOpenEnumW` 用于启动所有当前连接的资源的枚举（0x1 = **RESOURCE\_CONNECTED**），再通过调用 `WNetEnumResourceW` 函数继续枚举：

![image-20240919081027255](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-020c79991bca804aa8f8674fec8e8508f7318f72.png)

该过程通过调用`GetIpAddrTable`函数获取接口到IPv4地址映射表，如下所示：

![image-20240919081105198](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-68e2cc52548ab44dbbaef3b09c029e99e4067d96.png)

这里使用 ntohl 将上面提取的每个 IP 地址从网络顺序转换为主机字节顺序

![image-20240919081154510](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-3cd79ddfe3b9dcb94facc1c76dab936882d055ba.png)

它还会创建一个 TCP 套接字（0x2 = **AF\_INET**、0x1 = **SOCK\_STREAM**、0x6 = **IPPROTO\_TCP**），尝试通过端口 445 连接到网络上的每个主机，以加密每个可用的网络共享：

![image-20240919081245944](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-9cc706333a6c904d51072c2f19a8def322662c3e.png)

sub\_XX4B85函数
-------------

![image-20240919081531784](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b940412c57f2596ef011bf09216c7729df9fec81.png)

该进程通过调用 CreatePipe 方法创建两个匿名管道，接着使用 `SetHandleInformation` （0x1 = HANDLE\_FLAG\_INHERIT ）可以使读取句柄可继承。

勒索软件会创建一个“cmd.exe”进程，该进程将执行多个命令，例如负责禁用防火墙、删除所有卷影副本等的命令通过管道传输到新创建的进程：

![image-20240919081645985](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-12b36b5e25a95d7440ca50117e0013ed3c761823.png)

sub\_XX1CC5函数
-------------

![image-20240919081753268](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6d04f0fae4e2f7be2bf143f13ec7f65db478079c.png)

此线程不断使用 `GetLogicalDrives` API 提取代表当前可用磁盘驱动器的位掩码

AES加密
-----

### sub\_XX1A76函数

![image-20240919082132152](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-97899c8b76ef51ca3a89e7ca3d927c1803a5160a.png)

这里会解密用于加密文件所用的 AES256 密钥的 RSA 公钥。

它使用多个函数提取当前本地日期和时间、当前进程和线程 ID 以及其他信息：

![image-20240919082242318](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ac332e77405c55f406165bc161e8e792c8e5fbf0.png)

二进制文件会创建一个新线程，该线程将遍历网络共享和驱动器，以提取要加密的文件：

![image-20240919082326047](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b07b496d3aa992de05918decff5098cf1f8e7b90.png)

### sub\_XX54BF函数

![image-20240919090411399](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-36689635f213ae6b1eff6b637f561eea361f7040.png)

之中的sub\_XX8EBE：

勒索软件以读取模式打开要加密的文件（0x80000000 = **GENERIC\_READ**、0x7 = **FILE\_SHARE\_DELETE** | **FILE\_SHARE\_WRITE** | **FILE\_SHARE\_READ**、0x3 = **OPEN\_EXISTING**），如下

![image-20240919090444698](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4e4781823d2be9050975326cf82c48917459653a.png)

它使用 GetFileSizeEx API 检索文件的大小，将大小与 0x180000 字节（1.5MB）进行比较，字节数较大的文件被部分加密，其余文件则被全部加密：

![image-20240919090556323](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-bcb6696d38ba6baaf9b21cbf6899931a9ab1a817.png)

使用一个`ReadFile`读取文件内容

![image-20240919090650652](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4637ef8eba5e096aeba736a0cbc89849c5e9ee56.png)

自定义的AES加密算法：

![image-20240919090726403](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a14444eda8e3ac330c6105ec6b933a0b904dc92e.png)

内容经过AES加密后使用`WriteFile`写入文件中。

未加密的文件将被0覆盖，然后被删除：

![image-20240919091326219](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-21bea68fd233dcd46d4f49e95da58b7295cea76b.png)