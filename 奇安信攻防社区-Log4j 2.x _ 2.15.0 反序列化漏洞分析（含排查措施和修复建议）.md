漏洞简述
====

Log4j 2系列 &lt; 2.15.0版本中存在反序列化漏洞。

奇安信代码安全实验室分析发现该组件存在Java JNDI注入漏洞。程序将用户输入的数据进行日志，即可触发此漏洞；成功利用此漏洞的攻击者可在目标服务器上执行任意代码。

奇安信代码安全实验室经验证，Apache Struts2、Apache Solr、Apache Druid、Apache Flink等众多组件与大型应用均受影响。

漏洞复现
====

为便于验证，复现使用的是环境 java 1.8.0\_161 的较老版本。  
利用工具如下：  
<https://github.com/tangxiaofeng7/apache-log4j-poc>

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e27609448d1bb75649cf4b06aa06dc3845eb2be6.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e27609448d1bb75649cf4b06aa06dc3845eb2be6.png)

结果成功执行指定命令（打开macdown）。

代码分析
====

在org.apache.logging.log4j.core.lookup Interpolator.calss lookup() 处理时，从第 190 行可以看到，它支持多种格式，其中包含jndi，故而使用jndi尝试进行攻击。

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f0386d0a4af690aa10157059265c67c960920408.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f0386d0a4af690aa10157059265c67c960920408.png)

触发点在org.apache.logging.log4j.core.net JndiManager.class lookup()。  
传入可能的用户输入值，即可触发攻击。

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd6cb6cfd0499342483d1f4fe78509299bc25cdc.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd6cb6cfd0499342483d1f4fe78509299bc25cdc.png)

修复分析
====

在 org.apache.logging.log4j.core.appender AbstractOutputStreamAppender.class directEncodeEvent() 调用getLayout()进行处理时，如下所示代码中添加了对于jndi调用的白名单检查。

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9156dfaf4e223ffaa51c96bf3abf6cbda89cecb.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9156dfaf4e223ffaa51c96bf3abf6cbda89cecb.png)

并且，后续对 org.apache.logging.log4j.core.net JndiManager.class lookup() 基本重写，也添加了jndi检查。

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-562b59d204bd400caadb3263a9f18066cd1454a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-562b59d204bd400caadb3263a9f18066cd1454a5.png)

缓解分析
====

jvm 启动参数

```html
-Dlog4j2.formatMsgNoLookups=true`
```

在传入上述逻辑之前，org.apache.logging.log4j.core.pattern MessagePatternConverter.class format() 中

第114 行会执行检查：如果按照缓解建议添加jvm启动参数，那么此处this.noLookups即为true，则不会进入后续处理，不会触发后续反序列化流程。

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6befa36ccaf36ce2b5e209b4bc4d9344c3b9db61.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6befa36ccaf36ce2b5e209b4bc4d9344c3b9db61.png)

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

1. 攻击者在利用前通常采用 dnslog 方式进行扫描、探测，对于常见  
    利用方式可通过应用系统报错日志中的  
    "javax.naming.CommunicationException"、  
    "javax.naming.NamingException: problem generating object using object factory"、"Error looking up JNDI resource"关键字进行排查。
2. 流量排查：攻击者的数据包中可能存在：“${jndi:rmi”、  
    “${jndi:ldap” 字样，推荐使用奇安信网神网站应用安全云防护系  
    统全流量或 WAF 设备进行检索排查。

**3、修复建议**  
**（1）升级到最新版本：**  
请联系厂商获取修复后的官方版本：<https://github.com/apache/logginglog4j2> ；  
请尽快升级 Apache Log4j2 所有相关应用到最新的 log4j-2.15.0-rc2 版本，地址：<https://github.com/apache/logginglog4j2/releases/tag/log4j-2.15.0-rc2> 或采用奇安信产品解决方案来防护此漏洞。

**（2）缓解措施：**

1. 添加 jvm 启动参数 -Dlog4j2.formatMsgNoLookups=true。
2. 在应用程序的 classpath 下添加 log4j2.component.properties 配置文件文件，文件内容：log4j2.formatMsgNoLookups=True。
3. 设置系统环境变量 FORMAT\_MESSAGES\_PATTERN\_DISABLE\_LOOKUPS 设置为 true。
4. 建议 JDK 使用 11.0.1、8u191、7u201、6u211 及以上的高版本。
5. 限制受影响应用对外访问互联网。

事件启发
====

Apache Log4j 是Apache 的一个开源项目。Log4j 是一个强大的日志操作包，是可重用组件，广泛应用于Java、 C、C++、.Net、PL/SQL 等程序中。通过各种第三方扩展，可将 Log4j 集成到 J2EE、JINI以及SNMP应用中。

近年来，攻击者越来越多地开始利用开源组件漏洞发动供应链攻击。据安全机构调查显示，开源供应链攻击事件比2020年增长了650%。虽然企业第三方风险管理的意识和预算已经增长，但这并不一定意味着所采取的措施是有效的。

奇安信代码安全事业部技术总监章磊认为，Apache Log4j RCE 漏洞之所以能够引起安全圈的极大关注，不仅在于其易于利用，更在于它巨大的潜在危害性。当前几乎所有的技术巨头都在使用该开源组件，它所带来的危害就像多米诺骨牌一样，影响深远。我们首先需要做的是梳理自身产品中所使用的软件资产，检测其中是否使用了开源组件、影响哪些资产、影响程度如何，判断受影响资产应修复到哪个版本，其它关联组件是否受影响等，最后着手修复和防御后续类似攻击。用户可通过奇安信开源卫士等工具系统化地应对此类漏洞。

章磊还表示，开源软件安全治理是一项任重道远的工作，需要国家、行业、用户、软件厂商都重视起来并投入才能达到良好效果。

奇安信开源卫士20211209.907版本已支持对Log4j 任意代码执行漏洞的检测。用户可登录https://oss.qianxin.com 进行检测。