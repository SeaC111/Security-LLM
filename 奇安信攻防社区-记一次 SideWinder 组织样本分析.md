记一次 SideWinder 样本分析
===================

前言：
---

这是我在10月份时分析的样本，当时拿到该样本时后门 WarHawk 的网址还是可以访问的，结果在分析的过程中网站被关掉，所以这篇就搁置了好久。现在年尾了，就把当时分析的整理了一下，放上来供大家探讨。

样本概括和 IOC：
----------

分析的样本首次发现于巴基斯坦国家电力监管局 <https://nepra.org.pk/> 的官方网站上，攻击者将一个 PDF 图样的 LNK 文件以及由其执行的 WarHawk 后门，和一个由巴基斯坦内阁部门发布的网络安全建议副本的诱饵 PDF 捆绑成 ISO 文件来引诱受害者打开。

提取的样本信息如下：

| 文件名 | MD5 | 创建时间 |
|---|---|---|
| 33-Advisory-No-33-2022.pdf.iso | 63d6d8213d9cc070b2a3dfd3c5866564 | 2022/9/26 11:28 |
| 33-ADVISORY-NO-33-2022.LNK | 1dd72390f35a9a5e207b61e397bc338e | 2021/10/6 13:51 |
| 33-ADVISORY-NO-33-2022.PDF | 26dd72a5dad80756823d6bf1f95350df | 2022/9/6 12:09 |
| MSBUILD.EXE | 5cff6896e0505e8d6d98bff35d10c43a | 2022/9/26 06:27 |

样本分析
----

解压相关 ISO 后分别得到如下三个文件，其中 PDF文件是巴基斯坦的内阁部门官网上发布的对外咨询文件。而 LNK 文件是恶意的，它以 PDF 图标来诱惑受害者分散注意，其在打开 PDF 的同时也会用CMD 执行剩下的恶意二进制文件 MSBuild.exe

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3039f755580ac841f0d3ae25ea39b27d92cdd9b2.png)

MSBuild.exe 是一个连接 C2 服务器的下载和执行工具，其 C2 服务器首页面板是一个标题为 WarHawk 的登陆框，因此此次事件工具也被视为 SideWinder 的 WarHawk 新后门。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-28eb2047712a6846279aae4746268097f06dbaef.png)

### 动态加载和解密操作：

和其它恶意软件一样，WarHawk 通过运行时链接的方式加载需要的函数，程序一开始就先通过遍历 PEB 中的 InMemoryOrderModuleList 链来获取 Kernel32.dll 的基地址，如下图所示。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-69110c87937cd3c4cc1e18f160152c7a4e51d3c7.png)

紧接着 WarHawk 从预留字符串中解密出需要加载的 API 和 DLL 名称，解密的方式是从每个字节中减去 0x42。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ce5fce5841fef3f6922f205c457511b635f43a9c.png)

在获取 kernel32.dll 的基础上搭配先解密出的两个 LoadLibraryA 和 GetProcAddress函数名称，遍历其导出表所有函数来对比并获取函数基址：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-afcee31433c85d95ec2b315c5975cd2a3330fee3.png)

然后就是用这两个函数动态加载其它需要的 dll 库和函数，由于程序中解密的方式是相同的，因此我们可以编写一个简易的解密器来获取到其解密的所有名称，它们分别是 LoadLibraryA、GetProcAddress、Advapi32、GetCurrentHwProfileA、GetComputerNameA、GetUserNameA

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-037d9e563dc1e748a289389f0ea2b6f283261942.png)

### 信息填充和JSON格式回传：

WarHawk 调用动态获取到的 GetCurrentHwProfileA 函数获取本地硬件配置文件的 GUID 值，然后用 wprintf 填充到预留的 JSON 格式中 {"\_hwid":"{GUID}"}

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-141b8c01c1eb0cd4d3e7abe5f23e4c5652e07323.png)

接着利用自定义 web 信息发送函数将获取到的信息发送到远程的 C2 服务器中并接受特定响应进行下一步操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-16d0f23d21794a7d02076496b4053c4e03cf3960.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1c35896b94f4e0f3f876d85b231613f5f74c6dce.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-54b12b9e9d20f4159f68c93a500d18381e6feccb.png)

如果返回的响应为 0 则动态获取并调用调用 GetComputerNameA 和 GetUserNameA 检索计算机/NetBios 名称以及当前用户名。并调用 RegQueryValueExA() API 检索注册表路径 "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" 下 ProductName 所对应的 Windows 产品名称。反之如果响应不是 0 则不执行这段操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7f14a5385070b11c8eb761a82db27b7a15ab8dee.png)

随后将获取到的信息填充到预留 JSON 格式 { "\_hwid": {GUID}, "\_computer": computer\_name, "\_username": "user\_name", "\_os": "windows\_products" } 中,并利用同样的消息发送函数回传.

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d1535f4cc414a91d608d6a9c6b7591ed2363e717.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b61b96b92c48316db3d2a778cf50b9231e39a946.png)  
接着 WarHawk 直接发送 JSON 格式 { "\_hwid":{GUID}, "\_ping": "true" } 来获取 C2 服务器的指示，如果响应是 del 则不执行后续主要的恶意控制行为，其会退出程序并发送{"\_hwid": {GUID}, "\_del": "true"}进行行为报告。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-079690daed5fb78919125adeca02251a843975be.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-989404f8a8bffe2376f741a5e56d4b6971da8228.png)

### WarHawk后续行为划分：

#### 第一部分——下载 EXE 或加载 DLL：

第一部分是从C2服务器下载文件执行exe或加载DLL，其会先发送 {"\_hwid": {GUID}, "\_task": "true"} 到 C2 服务器中获取响应。如果响应不是 1 的话则应为带有 \_id、\_type、\_url 字段的JSON 格式，WarHawk会用轻量级的 JSON 格式解析并获取其中的值。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-eb8111aab7a9d94994d95719410f84daaa97bcf9.png)

接着根据解析到的 \_type 字段值为 1、2、3 分别执行不同的操作：

l \_type 值为 1 和3时会调用 URLDownloadToFileA 下载 \_url 字段值所指向的文件名到本地文件中并调用 ShellExecuteA 函数来执行，其中本地文件名是随机生成的并拼接从 \_url 字段中解析的扩展名。此外其会填充并发送任务完成标志和 ID 的 JSON 格式 {"\_hwid": {GUID}, "\_task\_done": "true", "\_id": "id" } 进行回传，以上报执行了该操作。

l \_type 值为 2 时进行同样的下载操作，但最后用的是 LoadLibraryA 加载文件，所以下载的应该是一个 DLL  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-154c8877bea6f2653fbb00d8a813ae841d17e8e5.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3173b91b685987f64ecf89f481f69fdcbddec973.png)

#### 第二部分——接受命令并执行：

第二部分是从 C2 服务器接受命令执行，并传输加密结果。其会先发送 {"\_hwid": {GUID}, "\_cmd": "true"} 到 C2 服务器中获取响应。如果响应不是 0 或 1 的话则应为带有要执行的 cmd 命令。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e394e6cecf998d80c83b1676299731d3afccd775.png)

程序在获取到 cmd 命令时会和随机生成的 .bin 后缀的文件名拼接成 /c cmd\_command &gt; file.bin 格式，然后调用 ShellExecuteExA 启动 cmd 执行该命令，旨在把执行结果暂存到程序当中。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8cc11923d561485c2575e751261180f989e7cced.png)

最后程序打开文件读取结果到内存中后删除文件，调用自定义的 base64 加密函数加密内容并填充到 JSON 格式 { "\_hwid": {GUID}, "\_cmd\_done": "true", "\_response": "base64\_encry\_infomation" } 回传。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1b8fb2c74c06ad53b9905a23d25863ec7dfba4cc.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-333dea4913da2c1c15659138fc6cfe078f55cfa8.png)

#### 第三部分——检索本地文件：

第三部分是检查本地驱动或检索指定目录下文件信息。其会先发送 {"\_hwid": {GUID}, "\_filemgr": "true"} 到 C2 服务器中获取响应。如果响应不是 0 或 "drive" 的话则应为指定的要检索的路径信息。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-68f5a7d9a52d67a4f319ac2773ed0636ccd4f829.png)

对于指定的路径，程序会遍历其下除当前目录和上级目录外的所有文件和文件夹，对于文件夹则会获取名称和时间信息。对于文件名则会获取其名称，日期，类型，和大小分别填充到不同的 JSON 格式中。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-77426e4ce7fdd820552464e554644b8209db500a.png)

最后把所有信息填充到回传 JSON 格式的 \_response 字段中进行发送：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d88d5daa99ce872334c90e600b19126dedf2bc51.png)

如果响应是 "drive" 的话，程序会在循环中遍历A—Z 的驱动器号并调用 PathFileExistsA() 函数来确定磁盘是否存在。如果存在则进一步调用 GetDriveTypeA() 获取驱动器类型。然后将对应信息填充到带有 name 和 type 字段的 JSON 格式中，并和前面一样填充到 \_reponse 字段中进行信息回传。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a00e81091ca4a149ad5671f1b48d4f7eab1852a6.png)

#### 第四部分——下载远程文件：

第四部分从C2服务器中下载指定文件到当前目录中。其会先发送 {"\_hwid": {GUID}, "\_fileupload": "true"} 到 C2 服务器中获取响应。如果响应不是 1 的话则应为 C2 服务器上的指定文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b9405ee4d607acc219add3b8c41aebb78c9aaed8.png)

这和第一部分有点类似，不一样的是此次下载到本地的文件名不是随机生成的，而是响应的 JSON 格式中 \_path 字段的值 base64 加密而来的。根据下载是否成功其会填充响应的 JSON 状态 {"\_hwid": {GUID}, "\_uploadstatus": "true/false" } 并回传。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a32c9b51b2138b0762b360d48cfdd357f97c9b19.png)

### 样本归属判定：

跟随本次发现的 WarHawk 后门一同出现的还有 Snitch.exe 和 OneDrive.exe 程序，它们都是从前面提到的四个主要行为中第一部分从 C2 服务器下载到的文件，文件信息如下。

| filename | hash | create |
|---|---|---|
| Snitch.exe | ec33c5e1773b510e323bea8f70dcddb0 | 2022/9/19 5:18 |
| OneDrive.exe | d0acccab52778b77c96346194e38b244 | 2022/9/19 11:46 |

其中第一个 snitch.exe 是一个 Cobalt Strike 的加载器，在其中有特定于 “巴基斯坦” 标准时间而设置的时间反调试，以及前面 iso 样本出现在巴基斯坦国家电力监管局网站上可以确定这批样本主要针对巴基斯坦国家。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1bc53da040ccf0c993a05fdea99f3d9f21768c10.png)

而第二个 OneDrive.exe 也同样由 Cobalt Strike 生成，通过 tria.ge 沙箱提取其配置可以发现其使用的回连地址 fia-gov.org 是模仿了巴基斯坦联邦调查局 fia.gov.pk 的域名。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-911b2d19f1ebff68f8fda877d9c26fb64b76df20.png)

在以前的关于 SideWinder 的分析文章中，该组织曾被报告使用过相同的域名，基于网络基础设施的重用可以将此该样本归因于 SideWinder 组织。

总结：
---

分析这个样本时感觉C2服务器对我的电脑信息有判定，导致我在构造 JSON 数据和接受 JSON 数据时并不是很顺利，很多时候直接给我返回一个空包，这使下阶段的payload分析难以继续。

而在分析这些组织的样本时真的得手快，很多时候样本被发现时 C2 服务器就关闭了，只能去各大样本池中去看看有没有其它人获取到样本的后续 payload。

上面的分析当中如有错误还请指正！

参考链接：
-----

[南亚地区隐藏的獠牙—响尾蛇组织近期攻击活动简报 (qq.com)](https://mp.weixin.qq.com/s/NOpFJx4LnMOWhTm0iluFfw)

[WarHawk: New APT backdoor from SideWinder | Zscaler](https://www.zscaler.com/blogs/security-research/warhawk-new-backdoor-arsenal-sidewinder-apt-group-0)

[飓风再现，响尾蛇（SideWinder）攻击预警 (qq.com)](https://mp.weixin.qq.com/s/heWhL6ev_pigAF_HMR4oLQ)

[响尾蛇（APT-Q-39）利用Google Play传播的恶意Android软件分析 (qq.com)](https://mp.weixin.qq.com/s/LaWE4R24D7og-d7sWvsGyg)

[SideWinder.AntiBot.Script (group-ib.com)](https://blog.group-ib.com/sidewinder-antibot)

[filesyncshell.dll劫持？APT-C-24响尾蛇最新攻击活动简报 (qq.com)](https://mp.weixin.qq.com/s/qsGxZIiTsuI7o-_XmiHLHg)