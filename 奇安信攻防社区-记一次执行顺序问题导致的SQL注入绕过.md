0x00 背景
=======

 在Java Web开发中，SQL注入是一种常见的安全漏洞，它允许攻击者通过构造恶意的SQL查询语句来操纵数据库。在实际业务中发现一处SQL注入的绕过case，当前**漏洞已经修复完毕** 。提取关键的的漏洞代码做下复盘。

 目标应用使用mybatis进行SQL交互，部分业务接口通过orderby实现了排序的功能。因为动态SQL没办法进行预编译处理，若缺少对应的安全措施，会因为存在SQL直接拼接而引入SQL注入风险的：

```XML
 order by ${_parameter} desc
```

 应用是通过过滤器Filter的方式对用户传递的参数进行检查，来防御SQL注入风险的。关键代码如下，大致思路是首先获取当前请求的参数以及对应的值，然后调用checkSqlInject方法进行对应的安全检查：

```Java
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;

        MyRequestWrapper requestWrapper = new MyRequestWrapper(req);

        // 获取请求参数
        Map<String, Object> paramsMaps = new TreeMap<>();
        if ("POST".equals(req.getMethod().toUpperCase())) {
            String body = requestWrapper.getBody();
            paramsMaps = JSONObject.parseObject(body, TreeMap.class);
        } else {
            Map<String, String[]> parameterMap = requestWrapper.getParameterMap();
            Set<Map.Entry<String, String[]>> entries = parameterMap.entrySet();
            for (Map.Entry<String, String[]> next : entries) {
                paramsMaps.put(next.getKey(), next.getValue()[0]);
            }
        }

        // 校验SQL注入
        for (Object o : paramsMaps.entrySet()) {
            Map.Entry entry = (Map.Entry) o;
            Object value = entry.getValue();
            if (value != null) {
                boolean isValid = checkSqlInject(value.toString(), servletResponse);
                if (!isValid) {
                    return;
                }
            }
        }

        chain.doFilter(requestWrapper, servletResponse);
    }
```

 checkSqlInject方法具体实现如下，通过正则匹配的方式如果检查到当前参数内容存在非法字符，会进行拦截：

```Java
private static final String SQL_REGX = ".*(\\b(select|update|and|or|delete|insert|trancate|char|into|substr|ascii|declare|exec|count|master|drop|execute)\\b).*";

/**
     * 检查SQL注入
     *
     * @param value           参数值
     * @param servletResponse 相应实例
     * @throws IOException      IO异常
     */
    private boolean checkSqlInject(String value, ServletResponse servletResponse) throws IOException {
        if (null != value && value.matches(SQL_REGX)) {
            log.error("您输入的参数有非法字符，请输入正确的参数");
            HttpServletResponse response = (HttpServletResponse) servletResponse;

            Map<String, String> rsp = new HashMap<>();
            rsp.put("code", HttpStatus.BAD_REQUEST.value() + "");
            rsp.put("message", "您输入的参数有非法字符，请输入正确的参数！");

            response.setStatus(HttpStatus.OK.value());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(rsp));
            response.getWriter().flush();
            response.getWriter().close();
            return false;
        }
        return true;
    }
```

 这里过滤的规则比较粗糙，倒是也限制了类似select等关键字，防止进一步的数据获取，从某种意义上也防止了SQL注入的进一步利用。那么有没有办法可以绕过当前的关键字检测呢？从代码上看，这里没有考虑当JSON请求时，过滤器跟Controller JSON请求方式不一致可能导致潜在的参数走私问题。也没有考虑GET请求在特定注解的情况下可以转换成POST进行请求的情况。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-66950a634e300215c4dd63f902a7b35eba48d3fa.png)

 抛开前面提到的思路，还有没有更多的缺陷需要进一步修复呢？下面是具体的分析过程。

0x01 绕过分析
=========

 在代码审计时筛选和整理当前应用使用的安全措施是一个非常好的习惯。能更直观的感知整个参数的调用过程。除了SQL注入过滤器以外，应用还存在另外一个拦截器Interceptor。在其`preHandle`方法中，会使用Jsoup对所有用户输入进行HTML净化，移除潜在的恶意脚本。

```Java
@Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 对请求参数进行HTML净化
        for (String key : request.getParameterMap().keySet()) {
            String value = request.getParameter(key);
            value = sanitizeInput(value); 
            request.getParameterMap().replace(key, value);
        }
        return true;
    }
```

 在sanitizeInput中，主要是通过Jsoup的clean方法对用户输入进行处理，`clean()` 方法可以接收一个HTML字符串，并对其进行清理，移除任何潜在的恶意脚本，只保留安全的HTML标签和属性：

```Java
public static String sanitizeInput(String strHtml) {
        String cleaned = "";
        if (StringUtil.isNotBlank(strHtml)){
            cleaned = Jsoup.clean(strHtml, whitelist);
            return cleaned;
        }
        return cleaned;
    }
```

 这里针对SQL和XSS分别使用了Filter和interceptor进行处理。那么有没有可能因为两者的解析顺序不同，可能导致了潜在的绕过风险呢？下面对具体的执行顺序进行简单的分析：

- **过滤器Filter**

 过滤器位于请求处理链的最外层，可以拦截请求并进行对应的处理。如果某资源已经配置对应filter进行处理的话，那么每次访问这个资源都会执行doFilter()方法，该方法也是过滤器的核心方法。例如上面SQL注入的风险识别就是基于该方法实现的。

 Spring Boot默认内嵌Tomcat作为Web服务器。简单查看Filter的具体调用过程。

 Filter调用时会在org.apache.catalina.cor.StandardWrapperValve#invoke()方法中被创建。会通过ApplicationFilterFactory.createFilterChain创建FilterChain：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-28e02e6514d1a8ffcd845fb60894e181ec19bdbe.png)

 查看createFilterChain方法的具体实现，首先检查 `servlet` 是否为 `null`，若为 `null`，表示没有指定Servlet，就没有需要创建的过滤器链。否则根据实际的情况创建一个 `ApplicationFilterChain` 对象，或者获取已存在的过滤器链对象。而过滤器链对象会负责对一系列的过滤器进行管理:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-53f2ef7d4e8fb892b8667e9f3d605cd954f15d46.png)

 接着获取所有的filter的映射对象，在filterMaps中保存的是各个filter的元数据信息，若filterMaps不为null且length不为0，则对前面创建的filterChain进一步的封装，这里首先会获取与当前请求相关的标识信息，例如请求的调度类型（dispatcher）和请求的路径（requestPath）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-07f36c679c96a660b746642138a553d6d1edc369.png)

 然后遍历所有过滤器映射，根据一定的条件判断将匹配的过滤器添加到过滤器链中。条件包括与调度类型的匹配和与请求路径或Servlet名称的匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-f5c306f73943fe4e0901052ed7a02897259eb7be.png)

 最后，返回创建的过滤器链，该过滤器链包含了所有匹配的过滤器。如果没有找到匹配的过滤器，则返回一个空的过滤器链。创建了filterChain之后，就开始执行ApplicationFilterChain的doFilter进行请求的链式处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-152c63768756d01857d7aea7fb882b4584a27397.png)

 具体的逻辑在org.apache.catalina.core.ApplicationFilterChain#internalDoFilter方法，这里会通过pos索引判断是否执行完了所有的filter，如果没有，取出当前待执行的索引filter，调用其doFilter方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-55647db244322258309ea3125577ee0f7e2d6bc1.png)

 当所有的filter执行完后，会释放掉过滤器链及其相关资源。然后执行servlet具体的业务模块`servlet.service(request, response);`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-1f98df628120388118ea0c8caffa152757fc0ca1.png)

 以上是tomcat中整个Filter的调用过程。

 也就是说，**过滤器主要在Servlet容器级别处理请求的，会在Spring的其他组件之前执行**。在Spring中，**DispatcherServlet**是前端控制器设计模式的实现,提供Spring Web MVC的集中访问点,而且负责职责的分派。其也是在这个环节中进行解析处理的。业务场景中Controller 中收到的请求，都是经过 Tomcat 容器解析后交给 `DispatcherServlet`，再由其转交给对应 Controller 的。

- **拦截器Interceptor（preHandle）**

 拦截器（Interceptor）是一个设计用于在请求处理流程之前或之后执行的组件。它们可以用于多种目的，包括日志记录、安全控制、事务管理、错误处理等。其可以拦截进入Controller之前的请求，也可以拦截Controller处理完请求之后的响应。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-91b24f2c10c37279e2167f594a04c34235c615ee.png)  
 这里只讨论**preHandle**方法，其在请求进入Controller之前执行，可以返回一个布尔值，决定是否继续执行后续的Interceptor或Controller。看看具体的调用过程。在`DispatcherServlet`的解析过程中，找到了拦截器的解析逻辑。

 Spring MVC在接收到请求时，会调用DispatcherServlet的service方法进行处理。主要是调用doDispatch方法来获取对应的mappedHandler：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-621c18b3e214a0c40c191f12b2e15eee19f78e32.png)

 在getHandler方法中，顺序循环调用HandlerMapping的getHandler方法进行解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-41bbcb357b820bd84afca15d7445d01b68e1b864.png)

 这里首先会通过RequestMappingHandlerMapping，在其getHandler方法中通过getHandlerInternal获取handler构建HandlerExecutionChain并返回，这里会添加当前请求相关的所有Interceptor：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-206cc97e14d841f62973fa99d26ef92439a7f143.png)

 在getHandlerExecutionChain方法中，一开始会创建一个`HandlerExecutionChain`对象，用于存储处理器和拦截器。然后遍历 `adaptedInterceptors` 的拦截器集合，如果拦截器是 `MappedInterceptor` 的实例，并且它的 `matches(request)` 方法返回 `true`（表示请求的URL路径匹配该拦截器），则将该拦截器中的实际拦截器添加到 `chain` 中。否则直接将它添加到 `chain` 中，无需进行路径匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-182a27dd5040a560a6c618723c3ac1cc1f8f5c9c.png)

 最后返回构建好的 `HandlerExecutionChain` 对象 `chain`，其中包含了处理程序和相应的拦截器，以便在处理HTTP请求时按照一定的顺序执行这些拦截器操作。处理完后会获取处理器适配器，然后调用applyPreHandle方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-c38969f05760ebd539aa7709f2fca806368fb138.png)

 实际就到了执行拦截器前置处理preHandle方法的时候了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-9c4b69317bad40ec278a2a357f9d7aa289b57cdd.png)

 以上是拦截器Interceptor的大致执行流程。

 拦截器的preHandle方法是在`DispatcherServlet`中进行处理，并且在调用Controller方法之前进行拦截。

 也就是说，**过滤器Filter的执行顺序要在拦截器Interceptor之前**。

 结合前面的分析，SQL注入主要是对内容进行检查，而XSS则是对恶意的内容进行移除处理。若Filter的解析顺序在Interceptor之前，精简下对应的代码逻辑大致如下：

```Java
private static final String SQL_REGX = ".*(\\b(select|update|and|or|delete|insert|trancate|char|into|substr|ascii|declare|exec|count|master|drop|execute)\\b).*";

public static void main(String[] args) throws Exception {
    String value = "用户输入的内容";
    System.out.println("用户输入:"+value);
    if (null != value && value.matches(SQL_REGX)) {
        throw new Exception("您输入的参数有非法字符，请输入正确的参数");
    }

    String cleaned = Jsoup.clean(value, whitelist);

    System.out.println("最终处理后的内容并交给Controler进行处理："+cleaned);

}
```

通过类似`selec</script>t`的输入即可绕过当前的注入防护，可以看到成功绕过了对应的SQL检测逻辑，并且最终经过处理后成功获取到了理想状态的字符串select：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-5d97b238b3b327767c2a0f98750ec37828a5ff44.png)

0x02 其他
=======

 除此之外，很多安全措施还可以通过切面或者直接在Service 层进行实现。相比Filter和Interceptor，**切面在方法级别执行**。而Service的调用一般都是通过在Controller调用的。

 结合上面的分析，可以大概知道，当一个请求到达时，执行顺序是大致如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-eed55e90b14a0377a333be74727bf995aa65538c.png)

 在实际代码审计过程中，可以结合实际的业务场景，关注对应措施的解析顺序问题（也包括interceptor和filter自身的解析顺序）。可能会有意想不到的惊喜。