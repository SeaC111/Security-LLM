0x00 关于Spring WebFlux
=====================

 Spring WebFlux是Spring Framework提供的用于构建响应式Web应用的模块，基于Reactive编程模型实现。它使用了Reactive Streams规范，并提供了一套响应式的Web编程模型，以便于处理高并发、高吞吐量的Web请求。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d6c09aefad6ef0327cd4301926bea2983700fe3a.png)

 除了本身支持类似SpringMVC注解方式进行路由注册以外，还可以使用函数式编程的方式定义路由规则。通过创建一个 `RouterFunction` 对象，可以将不同的请求路径和请求方法映射到相应的处理函数。例如下面的例子：

 通过 `RouterFunctions.route()` 创建一个路由构建器，并使用不同的 HTTP 方法和路径定义了多个路由规则。每个路由规则都与相应的处理函数进行绑定。

```Java
@Configuration
public class RouterConfig {

    @Bean
    public RouterFunction<ServerResponse> routerFunction(Handler handler) {
        return RouterFunctions.route()
            .GET("/users", handler::listUsers)
            .POST("/users", handler::createUser)
            .GET("/users/{id}", handler::getUser)
            .PUT("/users/{id}", handler::updateUser)
            .DELETE("/users/{id}", handler::deleteUser)
            .build();
    }
}
```

0x01 Spring WebFlux解析过程
=======================

1.1 解析过程
--------

 在SpringMvc中，DispatcherServlet是前端控制器设计模式的实现,提供Spring Web MVC的集中访问点,而且负责职责的分派。而**WebFlux的前端控制器是DispatcherHandler**。以spring-webflux-5.2.8.RELEASE.jar为例，查看具体的解析过程。

 org.springframework.web.reactive.DispatcherHandler#handler，其主要流程是遍历HandlerMapping数据结构，并封装成数据流类Flux。它会触发对应的handler方法，执行相应的业务代码逻辑，而HandlerMapping在配置阶段 会 根 据 @Controller 、 @RequestMapping 、 @GetMapping 、@PostMapping注解注册对应的业务方法到HandlerMapping接口，这也是 WebFlux兼容注解方式的原因 。 这些配置路由最终都会通过getHandler方法找到对应的处理类:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c2bd0dd4384677ae940b82f14f24c7b8ebd5dde1.png)

 跟进getHandler方法，首先会调用getHandlerInternal()方法获取适当的处理器，并根据跨域配置信息对请求进行处理，最终返回要用于处理请求的处理器对象或标识对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b9f2d6a0cdc99aee14bca8853b5fe8f6afc441a9.png)

 在getHandlerInternal()方法中会调用父类的 getHandlerInternal() 来获取请求的处理方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b1fc1eda46f1073fe7ca1b84882509133ad11a04.png)

 而父类的getHandlerInternal方法会根据exchange找到handlerMethod：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-51f04f2599798c170b1205bece8f5c377097f0c8.png)

 在lookupHandlerMethod中，主要是调用 `addMatchingMappings()` 方法，将与当前请求匹配的映射添加到 `matches` 列表中。该方法会遍历所有注册的映射，并将与请求路径匹配的映射添加到 `matches` 列表中。如果 `matches` 列表为空，说明没有找到匹配的处理方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ca4168b9826590c034fdfaf226d100feeaa05841.png)

 继续跟进`addMatchingMappings()` 方法，这里会遍历识别到的ReuqestMappingInfo对象并进行匹配:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-df2d4db550f1714d98787dafed8b286b6f45acb8.png)

 核心方法getMatchingMapping实际上调用的是org.springframework.web.reactive.result.method.RequestMappingInfoHandlerMapping#getMatchingCondition方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-79a4accae2fa19ce10db48ac64f5bfdba77b48a2.png)

 跟Spring MVC类似，在getMatchingCondition中会检查各种条件是否匹配，例如请求方法methods、参数params、请求头headers还有出入参类型等等，其中patternsCondition.getMatchingCondition(request)是核心的路径匹配方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-45f853346156551f02fb67f295aa95e0757474e9.png)

 然后会调用org.springframework.web.reactive.result.condition.PatternsRequestCondition#getMatchingPatterns方法进行相关的匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0ffacc429f214e98911acb9c34bbf86948e80ae3.png)

 这里首先会从exchange对象中获取请求的路径信息并赋值给lookupPath，然后通过PathPattern的方式进行路径匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5e53f5ace5d89dadce50c5cb2c832acc1aef2120.png)

 这里就跟SpringMVC的处理类似了，都是通过org.springframework.web.util.pattern.PathPattern#matches进行处理，同样的会根据/将URL拆分成多个PathElement对象，然后根据PathPattern的链式节点中对应的PathElement的matches方法逐个进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2a5e9d50f86695ee0ac95c5f7d2e659aa7a15d20.png)

 在获取到url 和 Handler 映射关系后，就可以根据请求的uri来找到对应的Controller和method，处理和响应请求。

1.2 与Spring MVC的差异
------------------

 根据上面的分析，对比下Spring WebFlux与Spring MVC在解析过程中的一些差异。

 首先，在SpringMVC中，同样的会在getHandler方法中通过getHandlerInternal获取handler构建HandlerExecutionChain并返回，但是这里会有区别（下图是Spring MVC的处理）：

- 在 Spring MVC 中，请求是基于 Servlet 的，因此 `getHandler()` 方法通过 `HttpServletRequest` 对象获取处理器，并使用该对象构建 `HandlerExecutionChain`。
- 在 Spring WebFlux 中，请求是基于 Reactor 的，因此 `getHandler()` 方法通过 `ServerWebExchange` 对象获取处理器，并使用该对象构建 `HandlerExecutionChain`。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2b1b269dd16357bb8d8ee3d76cd1cd7ddb09248e.png)

 patternsCondition.getMatchingCondition(request)是核心的路径匹配方法，两者匹配的对象是有区别的（下图是Spring MVC的处理）：

- 在SpringMVC中主要是通过lookupPath进行匹配的，而lookupPath会根据SpringMVC版本的不同，调用UrlPathHelper进行处理，例如URI解码、移除分号内容并清理斜线等进一步的处理。高版本的话则没有那么复杂，会根据removeSemicolonContent的值（默认为true）确定是移除请求URI中的所有分号内容还是只移除jsessionid部分：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8a7ea627adba3c089392484279baa6b0894002b6.png)

- 在Spring WebFlux中会直接对exchange进行处理。实际上会获取`exchange.getRequest().getPath().pathWithinApplication();`进行匹配。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-6ed8d52685ce5747bc761006c6c8eab5f3b936db.png)

 也就是说，相比SpringMVC，**Spring WebFlux在调用PathPattern进行匹配时，并没有经过太多的路径规范化处理**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2dfa93b51728be235a4d91909c75b4c10db2a404.png)

 最后是匹配模式的差异， 2.6 及之后版本的 Spring Boot 将 Spring MVC 处理请求的路径匹配模式从AntPathMatcher更改为了PathPatternParser。而Spring WebFlux一直都是通过PathPatternParser进行路径匹配的。

1.3 路径规范化处理
-----------

 根据前面的分析，Spring WebFlux并没有类似Spring MVC调用initLookupPath方法进行一定的规范化处理，但是实际上，在PathPattern解析时，会对URL编码以及类似`;`的操作进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5b6abd526f25541a852bcef58dd740098c58bddf.png)

 所以类似如下的请求也是可以成功匹配对应的资源进行访问的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ccbfb58ea5dddc57561665aa01b5bbbb6c36a33c.png)

0x02 潜在的安全风险
============

 通过上面对Spring WebFlux请求解析过程的分析，结合现有的一些漏洞场景，列举下可能存在的安全风险。

2.1 权限绕过
--------

### 2.1.1 获取请求Path未规范化处理

 过滤器（Filter）和拦截器（Interceptor）经常会用于实现权限验证和访问控制的功能。在**Webflux中没有拦截器这个概念**，要做类似的工作需要在过滤器中完成。而相比Spring MVC通过实现 `javax.servlet.Filter` 接口来创建过滤器，Spring WebFlux主要是通过实现 `org.springframework.web.server.WebFilter` 接口来创建过滤器的：

```Java
import org.springframework.web.server.WebFilter;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AuthWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.debug("before controller...");
        return chain.filter(exchange)
                .then(Mono.fromRunnable(() -> {
                    log.debug("after controller...");
                }));
    }

}
```

 某些时候可能会有基于URI白名单的方式对特定的请求进行放行。跟Servlet中的request.getRequestURI()方法一样，当获取请求Path的方法不规范时，可能会存在绕过权限Filter的风险。

 在 Spring WebFlux 中，可以通过 `ServerWebExchange` 对象获取当前请求的路径。下面是常见的方法：

1. 使用 `getRequest()` 方法获取 `ServerHttpRequest` 对象，再通过 `getPath()` 方法获取请求路径：

```Java
public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String path = exchange.getRequest().getPath().toString();
    ......
}
```

2. 使用 `getRequest().getURI().getPath()` 方法直接获取请求的路径：

```Java
public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String path = exchange.getRequest().getURI().getPath();
    ......
}
```

 以请求http://127.0.0.1:8080/admin/manage;bypass/ 为例，查看各个方法的返回值：

| 方法名 | 返回值 |
|---|---|
| exchange.getRequest().getPath() | /admin/days;bypass/ |
| exchange.getRequest().getURI().getPath() | /admin/days;bypass/ |

 此外，`exchange.getRequest().getURI().getPath()`是会进行URL Decode的。

 可以看到返回值均未进行标准化处理。如果只是简单的使用startwith或者contiain方法进行白名单/黑名单的鉴权处理的话，在某种情况下是存在绕过的可能的。

### 2.1.2 以`/`结尾的Bypass

 例如下面的例子，正常来说访问`/manage`会匹配到manage方法然后进行相应的处理：

```Java
@GetMapping("/manage")
public String manage() {
    return "admin page";
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9522f2a8579ca73f3d9f211d6efb5ae67d281936.png)

 因为实际上Spring WebFlux是使用PathPattern进行匹配的，所以在解析时如果请求路径有尾部斜杠也能成功匹配（类似Spring里TrailingSlashMatch的作用）:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7bfeea211a1e8232af53afa100ef0cd1f865110d.png)

 那么在使用filter或者某些权限控制框架进行鉴权处理的的时候需要额外注意，避免绕过的风险。

### 2.1.3 解析差异绕过

 根据前面的分析可以知道，Spring WebFlux是使用PathPattern进行请求路径解析的。那么很自然会想到Apache Shiro之前披露的CVE-2023-22602，因为Shiro使用的是AntPathParser进行路径解析而高版本Spring是使用PathPattern进行处理的，两者间存在解析差异。

 但是shrio框架需要对HttpServletRequest进行配置相关参数，是基于Servlet的Filter进行处理的，而Spring WebFlux并不是基于servlet的，所以直接没法使用shrio。

 但是SpringSecurity对WebFlux还是支持的，主要依赖于 `WebFilter`。具体可以参考https://springdoc.cn/spring-security/reactive/configuration/webflux.html 。

 看一个具体的例子，首先创建 SecurityConfig 类，并添加 @EnableWebFluxSecurity 注解。然后配置权限规则，通过在 SecurityConfig 类中 securityWebFilterChain方法中调用http.authorizeExchange() 方法配置不同路径的访问权限。

```Java
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange()
                .pathMatchers("/public/**").permitAll()
                .pathMatchers("/private/**").authenticated()
                .and()
            .build();
    }

}
```

 查看pathMatchers的实现，可以看到这里跟PathPatternParserServerWebExchangeMatcher有关：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0fc52246ef0a45a513fc9445e5e4061daca84141.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8a984a9fb9f40851b24deac59e379b7d825de7cb.png)

 查看PathPatternParserServerWebExchangeMatcher的matches方法，这里实际上也是使用的PathPattern进行解析，也就是说SpringSecurity在解析时跟Spring WebFlux的路径解析模式是一致的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-6f53ecd2c54524af643fd7377d86d10dbfe741b5.png)

 但是在使用其他权限控制框架进行鉴权处理的的时候需要额外注意解析模式的差异，避免绕过的风险。

2.2 任意文件下载
----------

 根据前面的分析可知，Spring WebFlux是基于PathPattern进行路径解析的，那么同样的也会支持`{*path}`的语法。

 例如下面的例子：

```Java
@RequestMapping("/download/{*path}")
public Mono<ResponseEntity<byte[]>> fileDownload(@PathVariable("path") String fileName) throws IOException {
    File file = new File("/tmp/"+fileName);
    FileInputStream fileInputStream = new FileInputStream(file);
    InputStream fis = new BufferedInputStream(fileInputStream);
    byte[] buffer = new byte[fis.available()];
    fis.read(buffer);
    fis.close();
    return Mono.just(ResponseEntity.ok().body(buffer));
}
```

 在PathPattern解析时，{\*path}是可以获取到`/`的，所以直接以`../`的形式进行访问即可：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-567c5b86413cabb84128d768cb05d7151cb65fc7.png)

 对于`{pathVariable:正则表达式(可选)}`的情况，在PathPattern解析时，主要的值是从pathContainer中获取的，而pathContainer会根据/进行分隔，创建对应的Element，所以没办法获取到`/`:

```Java
@RequestMapping("/download/{path:.*}")
public Mono<ResponseEntity<byte[]>> fileDownload(@PathVariable("path") String fileName) throws IOException {
    File file = new File(resource+fileName);
    FileInputStream fileInputStream = new FileInputStream(file);
    InputStream fis = new BufferedInputStream(fileInputStream);
    byte[] buffer = new byte[fis.available()];
    fis.read(buffer);
    fis.close();
    return Mono.just(ResponseEntity.ok().body(buffer));
}
```

 但是可以通过对`/`进行URL编码的方式进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-137dd6024f73410f75351132e2eb617d6b29fe98.png)

 Spring WebFlux底层默认使用Netty作为容器进行解析，在处理请求时不会类似tomcat一样，默认会对%2f以及%2F进行处理抛出异常，但是同样的Spring WebFlux也支持异步Servlet 3.1容器（Tomcat、Jetty等），所以在实际利用时需要考虑不同容器在解析请求时的限制。

2.3 线程安全问题
----------

 在 Spring WebFlux 中，跟Spring MVC的Controller类似，默认情况下，Controller也是单例的。如果在控制器类中引入了非线程安全的状态（如实例变量），就需要小心处理。确保控制器类的实例变量是无状态的或线程安全的，以避免潜在的线程问题。

 下面证明Controller是单例的：

1. 首先创建一个简单的Controller：

```Java
@RestController
@RequestMapping("/api")
public class ApiController {

    private int count = 0;

    @GetMapping("/count")
    public int count() {
        count++;
        return count;
    }
}
```

2. 启动应用程序，并使用浏览器或其他客户端工具访问该接口`http://127.0.0.1:8080/api/count`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4ded25e9fa10afef7a602cebeb29c5f0cb2844c8.png)

3. 多次访问该接口，并观察返回结果：

```Plain
count=1
count=2
count=3
...
```

 从输出结果可以看出，在多次访问同一个接口时，每次都会增加 count 的值，说明不同的请求实际上都在使用同一个 Controller 实例。

 那么如果需要为每个请求创建一个新的控制器实例，可以在控制器类上使用 `@Scope` 注解，并将作用域设置为 `prototype`。这样每次请求时，Spring 将为控制器创建一个新的实例。

 同样是上面的例子，可以看到此时每个请求的Controller实例是独立的：

```Java
@RestController
@Scope("prototype")
@RequestMapping("/api")
public class ApiController {

    private int count = 0;

    @GetMapping("/count")
    public int count() {
        count++;
        return count;
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-428ea5b8f760fdb628cc9dbdda8b9368d08fa17a.png)