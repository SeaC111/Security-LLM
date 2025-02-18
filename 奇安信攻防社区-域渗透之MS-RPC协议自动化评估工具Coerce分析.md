概述
--

Coercer是一个用于自动强制Windows服务器在任意机器上进行身份验证的Python脚本。它具有多种功能和选项，使得安全研究人员和渗透测试人员可以更容易地评估和利用目标系统中的漏洞。以下是Coercer工具的主要特点和功能：

核心功能

- 列出远程机器上的开放SMB管道。
- 尝试连接远程机器上已知的SMB管道列表。
- 逐个调用易受攻击的RPC函数。
- 生成随机UNC路径，以避免缓存失败的尝试。
- 可配置尝试之间的延迟。

选项

- 按方法名称、协议名称或管道名称进行筛选。
- 指定单个目标机器或从文件中指定多个目标。
- 指定IP地址或接口以侦听传入的身份验证。

结果导出

- 支持以SQLite、JSON和XSLX格式导出结果。

相关协议
----

### MS-RPC（Microsoft Remote Procedure Call）协议

MS-RPC（Microsoft Remote Procedure Call）协议是一种远程过程调用（RPC）协议，由Microsoft开发。它允许客户端与服务器之间进行通信，以便在远程计算机上执行某些过程或操作。MS-RPC协议被广泛应用于Microsoft Windows环境中，用于实现各种系统服务、应用程序和组件之间的通信。

MS-RPC协议的主要组成部分包括：

1. 命名管道（Named Pipes）：这是一种基于SMB（Server Message Block）协议的通信机制，用于在网络上的计算机之间传输数据。命名管道允许客户端和服务器之间建立一个双向的、可靠的通信通道。
2. 接口UUID（Interface UUID）：这是一个全局唯一的标识符，用于在MS-RPC协议中标识特定的接口。每个接口提供一组远程过程，客户端可以调用这些过程来执行特定任务。
3. 版本号（Version）：这表示一个接口的特定实现版本。随着软件的更新和升级，接口可能会有多个版本。客户端和服务器需要使用相同版本的接口来确保正确的通信。

MS-RPC协议在提供强大功能的同时，也可能存在安全风险。恶意攻击者可能利用MS-RPC协议中的漏洞来实施攻击，例如远程代码执行、拒绝服务或未授权访问。因此，对MS-RPC协议进行安全评估和测试至关重要。

### SMB（Server Message Block）协议

SMB（Server Message Block）是一种应用层网络协议，主要用于在局域网（LAN）上共享文件、打印机和其他资源。SMB协议最初由IBM开发，后来被Microsoft采用并扩展。在Windows操作系统中，SMB协议被称为CIFS（Common Internet File System）。

SMB协议允许客户端和服务器之间进行通信，以便在远程计算机上访问和操作资源。客户端可以通过SMB协议访问服务器上的文件、目录和其他资源，并对这些资源进行读取、写入和删除等操作。此外，SMB协议还支持共享打印机和串行端口，以及进行分布式处理和进程间通信（IPC）。

SMB协议具有以下特点：

1. 可靠性：SMB协议在传输层使用TCP/IP协议，保证了数据的可靠传输。
2. 安全性：SMB协议支持用户级别和共享级别的访问控制，可确保只有授权用户才能访问共享资源。此外，SMB协议还支持加密和签名，以保护数据的完整性和机密性。
3. 易用性：SMB协议在操作系统中高度集成，用户无需安装额外的软件即可访问共享资源。
4. 可扩展性：SMB协议支持许多扩展功能，例如压缩、大文件支持和并行传输。

尽管SMB协议提供了许多功能和优点，但它也可能存在安全风险。恶意攻击者可能利用SMB协议中的漏洞或配置错误来实施攻击，例如中间人攻击、拒绝服务或未授权访问。因此，对SMB协议进行安全评估和测试非常重要。

### MS-RPC协议和SMB协议的关系

MS-RPC（Microsoft Remote Procedure Call）协议和SMB（Server Message Block）协议是两种不同的网络协议，但它们之间存在关联。在某些场景下，这两个协议可以一起工作，以实现跨网络的远程访问和操作功能。

MS-RPC协议是一种允许客户端应用程序调用远程服务器上的函数的通信协议。它主要用于跨网络的分布式应用程序开发。MS-RPC允许客户端与远程服务器建立连接，然后向服务器发送请求，执行特定的功能或服务。服务器处理客户端的请求并返回结果，使得客户端可以像调用本地函数一样调用远程函数。

SMB协议则是一种应用层网络协议，主要用于在局域网上共享文件、打印机和其他资源。它允许客户端与远程服务器建立连接，访问和操作服务器上的资源。

在某些情况下，MS-RPC和SMB协议可以一起工作，以提供更高级的功能。例如，MS-RPC可以通过SMB协议进行传输，使得客户端可以在访问远程服务器的共享资源的同时，也可以调用服务器上的远程函数。这种情况下，SMB协议充当了底层的传输协议，为MS-RPC提供了可靠的数据传输服务。

总之，MS-RPC协议和SMB协议是两种不同的网络协议，它们在某些场景下可以相互协作，以实现跨网络的远程访问和操作功能。然而，它们分别具有自己的功能和用途，可以独立地工作。

代码分析
----

程序根据选项（options.mode）执行相应的操作：强制（coerce）、扫描（scan）或模糊测试（fuzz）。后边就分三个方向来深入分析。

### 强制（coerce）

try\_login 函数尝试使用给定的凭据（credentials）登录到目标（target）系统。默认端口是 445。此函数还接受一个可选的参数 verbose，用于控制是否输出详细信息。

首先，函数检查是否提供了匿名凭据。如果没有提供匿名凭据，则尝试使用给定的用户名、密码、域、LM哈希和NT哈希登录到目标系统。为此，创建一个 SMBConnection 对象并尝试登录。

![image-20230409130037353.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6cd2eab1e3f520c8a9cf7e0844e57f8f11687d31.png)

如果登录成功，函数返回 True。如果登录失败，它将打印一条错误消息，显示无法使用给定的凭据登录，并返回 False。如果提供了匿名凭据，函数直接返回 True，表示不需要尝试登录。

如果返回True，会把目标信息传递给`action_coerce`，进一步进行身份验证。

action\_coerce函数主要用于执行操控操作，使目标系统尝试进行身份验证。这是一种安全测试手段，用于检查目标系统是否存在潜在的漏洞和安全风险。

具体来说，函数会根据指定的可用方法、选项、凭证和报告器对目标进行操控。它会遍历各种组合，包括命名管道、UUID和版本。

![image-20230409131702633.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-328ac9b91d835d968e0cf3aa14101c55483180d4.png)

尝试连接到管道并绑定到接口。

![image-20230409132050996.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9091b43373fabcfedd10cec475f7d923a912e830.png)

成功绑定到接口后，函数将尝试使用提供的方法触发身份验证过程。

尝试使用不同的exploit\_paths（利用路径，也就是参数制定的认证类型，比如：smb、http等）对目标进行安全测试。它首先遍历ncan\_np\_tasks字典中的msprotocol\_class实例，并根据函数名称对其进行排序。

然后，针对每个msprotocol\_class实例，它会生成相应的exploit\_paths。接下来，对于每个exploit\_path，代码会检查是否收到了nca\_s\_unk\_if响应。如果收到此响应，将停止对该函数的进一步利用尝试。

![image-20230409132626217.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e16807f3fddd9bb3130941a9f1f42ea3d2544c15.png)

如果没有收到nca\_s\_unk\_if响应，代码将使用generate\_exploit\_path\_from\_template函数生成实际的exploit\_path。然后，它会创建一个msprotocol\_rpc\_instance实例并建立一个DCERPC会话。如果会话建立成功，代码将尝试将会话绑定到UUID和版本，然后执行身份验证测试。

![image-20230409132743844.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0635ae2d2d0f1bc0c6ef588782fc2a4d11ded1bc.png)

这有助于分析目标系统的安全性，以及识别可能的身份验证漏洞。根据测试结果，报告器会报告每个尝试的结果。

### 扫描（scan）

action\_scan函数的主要目的是扫描目标系统，检查它是否存在某些安全漏洞。它首先使用Filter类来过滤可用的方法，然后按照类别和方法名称对其进行排序。接着，针对每个方法，该函数会组织一个包含任务的字典。

![image-20230409134057623.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f1f6111e1c102df1fd796827c9d618ef229fbbb6.png)

在执行任务时，函数会遍历tasks字典中的ncan\_np（SMB命名管道访问）任务。对于每个任务，它会检查是否能连接到目标系统的相应命名管道，并尝试将会话绑定到不同的UUID和版本。

主要用于遍历给定命名管道（namedpipe）、UUID和版本的所有协议类（msprotocol\_class）。这些协议类表示可能的漏洞和可利用的方法。

![image-20230409134434693.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2de23dcf5a754bffb7ddc252e53a0a3faf01db35.png)

- 对于每个协议类，函数会生成相应的exploit\_paths（利用路径），这些路径取决于所需的身份验证类型（options.auth\_type）。

![image-20230409134700120.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c5783780262b327f095b869aac3919d798318d5b.png)

- 对于每个exploit\_path，函数会检查监听类型。如果监听类型为 "http"，函数将调用get\_next\_http\_listener\_port来获取下一个可用的HTTP监听端口。

![image-20230409134642116.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7d2190479c3ab3ef9357b58333691ff5d56b3b8e.png)

- 接下来，函数使用generate\_exploit\_path\_from\_template根据exploitpath模板、监听IP、HTTP监听端口和SMB监听端口生成实际的exploit\_path。

![image-20230409134736982.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c433fe0c8ddc36b2a58124da354e55b6f2100e50.png)

- 然后，函数为每个msprotocol\_class创建一个实例，并使用给定的exploit\_path初始化它。同时，创建一个DCERPCSession（用于与目标进行DCE/RPC通信）并连接到目标系统的命名管道。

![image-20230409134823959.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-57e3be49d1a4a678d08506339665e6de68c9b7a7.png)

- 如果DCERPCSession成功连接到目标，函数将尝试绑定到给定的UUID和版本。成功绑定后，函数会调用reporter.print\_testing以记录正在测试的msprotocol\_class实例。
- 最后，调用trigger\_and\_catch\_authentication函数尝试触发目标系统的身份验证并捕获验证结果。这个函数使用DCE/RPC会话、目标系统、触发方法、监听类型、监听IP和HTTP端口作为参数。

![image-20230409135008151.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ed995835a331eb26f2caf0afd1fcc3b53e67d2de.png)

### 模糊测试（fuzz）

action\_fuzz函数的主要目的是对目标系统进行模糊测试，以寻找和利用潜在的MS-RPC漏洞。这个函数执行以下步骤：

1. 初始化并应用过滤器：根据所提供的选项过滤方法、协议和命名管道。

![image-20230409135907733.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-56a3f3d52e85dc1a63af05873139daa11274e4b1.png)

2. 准备远程命名管道列表：如果使用匿名登录，则使用已知的命名管道列表；否则，从远程机器获取命名管道列表。

![image-20230409135941389.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-99af1d909e657d78341b0b43605e4a4cdf43f957.png)

后边基本跟scan模块一样了。

模糊测试的目的是找到可能引发错误或异常行为的输入，并根据这些信息发现潜在的漏洞。action\_fuzz函数通过尝试多个不同的接口、功能和命名管道，试图找到目标系统中的薄弱点。在测试过程中，会捕获和处理各种结果，以确保输出结果准确。

总结
--

这个工具是一个针对MS-RPC（Microsoft Remote Procedure Call）协议的安全评估和模糊测试工具。通过分析和利用MS-RPC中的漏洞，它可以帮助安全研究人员识别和评估目标系统的潜在安全风险。主要功能包括：

扫描（action\_scan）：扫描目标系统上的MS-RPC接口，检查可用的命名管道、UUID和版本。此功能可用于了解目标系统的MS-RPC配置，并找到可能的攻击面。

强制（action\_coerce）：尝试强制目标系统进行身份验证，以获取更多信息。这个功能可以用于检测目标系统是否存在未授权访问的漏洞。

模糊测试（action\_fuzz）：对目标系统执行模糊测试，以寻找和利用潜在的MS-RPC漏洞。该功能通过测试多种输入和配置，尝试触发错误或异常行为，从而发现目标系统中的潜在漏洞。