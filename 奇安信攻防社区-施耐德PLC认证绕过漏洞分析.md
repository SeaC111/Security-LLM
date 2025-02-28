近期Amris研究员发现CVE-2021-22779施耐德PLC一个身份验证绕过漏洞，可以与 UMAS 协议中的CVE-2020-7537漏洞联系在一起，会影响 Modicon M340 和 M580 PLC 的最新固件版本。要完全理解上述发现的技术细节，需要了解 Modbus 和 UMAS 协议的一些背景知识。

Modbus
------

Modbus 是在 SCADA 系统中控制 PLC 的事实标准。 它于 1979 年由 Modicon（现为施耐德电气）首次发布。 Modbus 是很久以前设计的，缺少现代系统所需的功能，例如二进制对象与 PLC 之间的传输。  
Modbus 可以通过串行通信或 IP 通信运行。 广泛使用的 Modbus IP 版本是 Modbus/TCP 标准。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eed17c2dd355019b30c3c571e077ad94c8ec8b71.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eed17c2dd355019b30c3c571e077ad94c8ec8b71.png)  
Modicon 选择在保留的 Modbus 功能代码下扩展 Modbus 实施。 扩展协议称为 UMAS，它在基本 Modbus 协议的基础上增加了身份验证、二进制数据传输、固件更新和其他功能。

UMAS
----

Modicon PLC（M340、M580 和其他）实施 UMAS。 UMAS 重新实现了标准 Modbus 命令和一些缺少的必要 Modbus 功能。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0d22bac9297a0e1adf0d0fc8389ca731fdc52ea4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0d22bac9297a0e1adf0d0fc8389ca731fdc52ea4.png)  
例如，专有 UMAS 命令之一是 MemoryBlockWrite 命令（功能代码 0x21），它不需要身份验证。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-414f07414c3245a32aece5764db52744b0f7f32e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-414f07414c3245a32aece5764db52744b0f7f32e.png)  
该命令将一组二进制数据写入特定块 ID 内的偏移量。 这些块位于固定的内存地址中，并被标记为可写或只读块。 尝试写入只读块时，MemoryBlockWrite 命令返回错误响应。

UMAS 预订机制
---------

对 PLC 的某些更改需要多个相互依赖的命令。为允许此类情况，Modicon 实施了预留机制。创建预留机制是为了同步 PLC 程序的修改——一种针对某些关键更改的全局锁定机制。一旦工程工作站通过 UMAS 成功保留 PLC，它就会收到一个一字节的令牌，用于对 PLC 进行修改。此令牌允许工作站更改在 PLC 上运行的应用程序的任何方面。不修改 PLC 的 UMAS 命令不需要此令牌，无需工作站进行任何身份验证即可执行。由于一次只有一个工作站可以保留 PLC，因此该机制可以保护 PLC 免受重叠修改，以免损坏 PLC、其控制的设备和工厂的正常运行。  
预留机制的初始版本通过使用功能代码为 0x10 的 UMAS 命令来工作。此命令不需要身份验证或质询-响应握手，并且依赖于 PLC 和工程师工作站上施耐德管理软件之间的硬编码共享秘密：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0b9d7af600810dc81fc2603b67b8b13c0c16072d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0b9d7af600810dc81fc2603b67b8b13c0c16072d.png)  
这种机制使用的硬编码秘密可以在未加密的 UMAS 流量中观察到，或者通过对 Modicon PLC 固件进行逆向工程来定位。

增强预订
----

随着时间的推移，安全问题被提出，各种未记录的 UMAS 命令被证明允许远程代码执行或其他恶意意图。 施耐德决定增强预留机制，因此它不仅可以充当锁定机制，还可以充当身份验证机制。  
增强保留机制基于质询-响应握手，其中对共享密码进行身份验证。 当项目文件上传到 PLC 时，共享密码，称为应用程序密码，是动态设置的。 Enhanced Reservation 机制使用功能代码为 0x6E 的 UMAS 命令：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d6d044909e6780d0dcc58db7b3eaf43311bc0fd7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d6d044909e6780d0dcc58db7b3eaf43311bc0fd7.png)  
在此命令中，工作站和 PLC 交换随机生成的 0x20 字节缓冲区：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-893943dcdb0c4a3ea0111f229817a21c9e5bac71.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-893943dcdb0c4a3ea0111f229817a21c9e5bac71.png)  
这些缓冲区的哈希值与应用程序密码的哈希值相结合，用于完成预留。（来自 Modicon 固件的 umas\_EnahcnedResvMngt 命令处理程序的反编译代码片段）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6a7a1924578aefeed7433bf7c21501d0b36a133f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6a7a1924578aefeed7433bf7c21501d0b36a133f.png)  
如上所述，该机制中使用的秘密共享密钥是在工程工作站上运行的 EcoStruxure 软件中配置的密码的哈希值。 EcoStruxure 软件鼓励用户在创建新项目时配置密码。 将项目文件传输到 PLC 时，还会在 PLC 上配置新的应用程序密码。  
在预留机制中，成功预留后会发送一个 1 字节令牌作为响应，然后该令牌将被添加到需要身份验证的 UMAS 命令之前。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5776848594b6220738d950ff902a1a27a0ccaed3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5776848594b6220738d950ff902a1a27a0ccaed3.png)  
绕过身份验证 – (CVE-2020-7537)  
在对增强保留机制的算法进行逆向工程后，我们想看看是否可以通过未公开的 UMAS 命令泄露应用程序密码（或其哈希值）。 对 M340 PLC 最新固件（当时）的静态分析，揭示了一个可疑的 UMAS 命令：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-094f213da518052d6440fdfd4de937864e5b6925.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-094f213da518052d6440fdfd4de937864e5b6925.png)  
pu\_ReadPhysicalAddress 将内存块从输入命令中选择的地址复制到响应缓冲区。 除了缓冲区大小的简单验证之外，该函数对从内存中读取的地址没有限制。 本质上，这个未记录的命令允许泄漏 PLC 地址空间中的所有内存。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f8c597b74785a5a2dc0b66799d4156e25eec73d2.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f8c597b74785a5a2dc0b66799d4156e25eec73d2.png)  
该命令可用于泄露应用程序密码的哈希值，该密码存储在 PLC 的内存中，用于未经身份验证的攻击者保留和管理 PLC。

此外，诸如此类的内存读取命令可用于从 PLC 泄漏可能与其操作相关的敏感信息，甚至用作拒绝服务。 由于此命令读取的地址没有限制，攻击者可以滥用此命令通过读取某些特定于硬件的地址来使设备崩溃，这将导致 PLC 上的驱动程序与硬件不同步。 这可能会导致各种边缘情况，从而导致拒绝服务。 当 PLC 以这种方式崩溃时，它不会很快恢复正常运行——操作员需要按下一个物理按钮来重新启动设备。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-93f3092fa86cf247247cac927cd3ed40e5163771.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-93f3092fa86cf247247cac927cd3ed40e5163771.png)  
Wireshark 捕获通过 ReadPhysicalAddress UMAS 命令泄露的应用程序密码哈希  
此漏洞于 2020 年 11 月报告给施耐德，并在 2020 年 12 月的安全公告中披露。 施耐德为解决此问题而引入的补丁将 ReadPhysicalAddress 命令定义为需要保留的命令 - 利用该机制来抵御这种攻击。 虽然这确实减轻了这种身份验证绕过，但它并没有完全解决这个命令中的下划线风险——因为如果使用的项目文件是无密码的，它仍然可能被触发。

绕过身份验证 - (CVE-2021-22779)  
为了更好地了解增强预留机制的 UMAS 消息流，我们使用 EcoStruxure 软件连接到 PLC 并分析了它创建的流量。我们注意到：当在 EcoStruxure 软件中输入正确的密码时，会按预期生成一些 UMAS 命令，但是当输入的密码不正确时，软件拒绝了密码，而不会与 PLC 产生任何流量。

EcoStruxure 软件如何在不与 PLC 通信的情况下知道密码不正确？我们分析了在输入密码之前工作站发送的 UMAS 命令。工作站使用的命令之一是 MemoryBlockRead 命令——它允许从内存中读取预配置的块，无需身份验证（类似于 MemoryBlockWrite 命令）。与 ReadPhysicalAddress 命令不同，块 ID 将内存访问限制为某些固定内存地址。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ff12f469c2240459481892510936bd578f893c80.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ff12f469c2240459481892510936bd578f893c80.png)  
（用于从 PLC 读取预定义内存块的 UMAS 命令的结构）  
然而，软件似乎使用这个命令pre-reservation，从PLC读取密码的哈希值，并验证用户输入的密码是否正确。 这种机制从根本上是有缺陷的——密码哈希既通过未加密的协议传递，也可以被任何未经身份验证的攻击者读取，只需执行内存块读取命令。

虽然 EcoStruxure 软件使用内存读取命令来验证密码哈希，但未经身份验证的攻击者可以简单地使用读取密码哈希完全绕过增强预留的身份验证机制。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8ce232454a83c80355ff0033c639b5709d600b5d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8ce232454a83c80355ff0033c639b5709d600b5d.png)  
实现此身份验证绕过技术的简单脚本  
通过利用身份验证绕过漏洞（CVE-2021-22779和CVE-2020-7537），攻击者可以通过上传未配置密码的新项目文件来降低 PLC 的安全性。一旦这种降级攻击完成，攻击者可以使用CVE-2019-6829和CVE-2018-7852漏洞来获得本机代码执行。