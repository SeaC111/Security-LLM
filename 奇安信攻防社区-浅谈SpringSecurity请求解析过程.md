0x00 关于Spring Security 
=======================

Spring Security内部其实是通过一个过滤器链来实现认证/鉴权等流程的。

 常见的例如AuthenticationProcessingFilter处理用户登陆相关的操作，ExceptionTranslationFilter用于处理异常并返回对应的页面或者状态码，SessionFixationProtectionFilter用于防止csrf攻击，还有主要用户权限控制的FilterSecurityInterceptor等。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b233dda9cbb0158598f9e2eded94dbfd45434216.png)

 简单的过滤器链如下：  
以认证授权流程为例，UsernamePasswordAuthenticationFilter用于拦截我们通过表单提交接口提交的用户名和密码，然后在AuthenticationProcessingFilter处理用户登陆认证相关的操作，最后的FilterSecurityInterceptor是首先判断我们当前请求的url是否需要认证，如果需要认证，那么就看当前请求是否已经认证，是的话就放行到我们要访问的接口，否则重定向到认证页面。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a811287104b16686f4f97c5aeb6e858c4d343cec.png)

0x01 SpringSecurity解析过程
=======================

 当发起HTTP请求时，Spring Security 的多个过滤器形成了一条链，所有请求都必须通过这些过滤器后才能成功访问到资源。

 当接收请求时，首先由org.springframework.web.filter.DelegatingFilterProxy负责处理，DelegatingFilterProxy的doFilter()的方法打上断点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cbbcac1eefb6383383a5fbca1598ba2c60470619.png)

 其会将请求委派给org.springframework.security.web.FilterChainProxy进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-678eec41500eae4d5046f98d554a36ffef03e979.png)

 在FilterChainProxy中，会继续调用doFilterInternal方法进行处理，首先在进入Spring Security过滤器链之前，对请求对象&amp;响应对象进行处理，这里主要**通过Spring Security设计的HttpFirewall处理，会把一些恶意的字符拦截掉**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fb3f67bd536f4008ef93068798de9cfb1fa6af58.png)

 在doFilterInternal()方法中会生成一个内部类VirtualFilterChain的实例，通过其来调用 Spring Security 的整条filterChain:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ce8f5891f141e760458a17b0ee6ff673015135fc.png)

 在VirtualFilterChain的doFilter方法中可以看到，其会通过currentPosition依次调用相应的过滤器：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-43bc474b66a0763d4548489c94c6a24c3b65f5b9.png)

 以FilterSecurityInterceptor为例(一般基于URL的权限处理都会经过这里处理),在doFilter中会调用invoke方法进行进一步的处理:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-038625b9f87c6450571765743ebd6c5e52fc05cc.png)

 在invoke方法中，首先会调用beforeInvocation方法进行权限认证的过程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8b08b67782ee2065d2f5fd1031a69c2d794b77e3.png)

 在beforeInvocation中，验证Context中的Authentication和目标url所需权限是否匹配，不通过则会抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3dead463aab6498aa316b4eadd322035197e7d16.png)

 在这个过程中会通过SpringSecurity中的**请求匹配器RequestMatcher**，用于匹配请求 `HttpServletRequest` 是否符合定义的匹配规则。

 最后会根据权限控制的结果决定是否访问目标Controller，获取真正的请求内容。接下来详细看看SpringSecurity的两个关键接口HttpFirewall和RequestMatcher。

0x02 HttpFirewall接口
-------------------

 在Spring Security中提供了一个HttpFirewall接口，用于处理掉一些非法请求。目前一共有两个实现类：

- StrictHttpFirewall（严格模式）
- DefaultHttpFirewall

 Spring Security缺省使用的是StrictHttpFirewall，在FilterChainProxy的实例化方法中可以看到，创建的是StrictHttpFirewall对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2b8412bb374bf50cbaeb7bf86568b91c0b97b959.png)

 然后在doFilterInternal方法中触发请求校验的逻辑，请求的校验主要是在getFirewalledRequest方法中处理，会在进入Spring Security过滤器链之前，对请求对象&amp;响应对象进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bcbef8c4bad995014d6a2390895efc4b6e486d52.png)

 从调试信息中也可以知道默认使用的是StrictHttpFirewall：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-31327764a08a0514f8810d0a34f174f67e183998.png)

 分别看下两个Firewall的具体实现：

### 2.1 StrictHttpFirewall

 在StrictHttpFirewall中，主要通过如下函数进行了相关的安全检查：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-318391cfde06bc5b9b362bad4cba4e64422d09a3.png)

- rejectForbiddenHttpMethod

 该方法主要用于判断请求的方法是否合法，allowedHttpMethods变量中主要包含了get、post、head、options、patch、put、delete这几个常见的请求方式,默认情况下如果不是这几个请求方式的话会被拦截：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d4e7d47a6b9bf3f1eb705a828a3926fce3736810.png)

 具体效果：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-838544d74962cebbd3854c16f644ab30f17432c7.png)

 从返回的信息可以看到由于TEST请求方法不在whiteList中导致请求被拦截：

```text
org.springframework.security.web.firewall.RequestRejectedException: The request was rejected because the HTTP method "TEST" was not included within the whitelist [HEAD, DELETE, POST, GET, OPTIONS, PATCH, PUT]
```

- rejectedBlacklistedUrls

 校验请求URL是否规范，对于不规范的请求直接拒绝：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8e1278fbeba05f511d9b0e36749e38210ebeb35b.png)

 这里主要有两层校验，分别校验编码前后的内容进行校验（decodedUrlBlacklist/encodedUrlBlacklist两个Set集合），从StrictHttpFirewall的构造方法可以看到这两个Set初始化的内容：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fe25e5420be309c2cf43e00bdba3406d8c2b21d1.png)

 首先调用urlBlacklistsAddAll方法，向两个Set集合添加对应的属性：

```Java
private static final List<String> FORBIDDEN_SEMICOLON = Collections.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));
private static final List<String> FORBIDDEN_FORWARDSLASH = Collections.unmodifiableList(Arrays.asList("%2f", "%2F"));
private static final List<String> FORBIDDEN_BACKSLASH = Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0fe6740e7a80370e0c23732f708874bbf7a3ad6a.png)

 大概可以知道当请求中如果包含如下字符的话会被拒绝：

| 拦截字符 |
|---|
| 分号(;或者%3b或者%3B) |
| 斜杠(%2f或者%2F) |
| 反斜杠(\\或者%5c或者%5B) |
| %25(URL编码了的百分号%) |
| 英文句号.(%2e或者%2E) |

 然后就是循环遍历这两个Set集合，调用encodedUrlContains和decodedUrlContains方法进行处理，如果命中黑名单字符的话就抛出RequestRejectedException异常，在encodedUrlContains方法中检验contextPath和requestURI两个属性，这两个是直接传递的字符串，未做任何更改。在decodedUrlContains方法中校验servletPath，pathInfo两个属性，这两个属性是经过归一化处理后的请求地址：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-331f9cf4bd7a4b4ae594754ff32c98fdc5d9a40c.png)

 具体效果，以`;`为例：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bbe36bc53feb739ea145b3f95e13336d69cf6b37.png)

 从返回的信息可以看到由于URL中包含黑名单字符`;`导致请求被拦截：

```text
org.springframework.security.web.firewall.RequestRejectedException: The request was rejected because the URL contained a potentially malicious String ";"
```

- isNormalized

 主要是对requestURI、ContextPath、ServletPath还有PathInfo四个属性进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6b8651bd28a0100b1163c9caedf6643aa728faeb.png)

 实际处理的方法实现，首先判断是否包含`//`，是的话返回false，抛出RequestRejectedException异常，再往下就是检查是否包含`./`、`/../` 以及`/.`三种字符:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7504d2e8e04093ed648fcd5ca51943ee1df5e698.png)

 具体效果，以`//`为例：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6552becb36beeda8e995e7aeedeffa1cf8463869.png)

 从返回的信息可以看到由于URL中不符合相应的格式请求被拦截：

```text
org.springframework.security.web.firewall.RequestRejectedException: The request was rejected because the URL was not normalized.
```

- containsOnlyPrintableAsciiCharacters

 主要检查请求地址中是否包含非ASCII字符：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f073ac3a73500d2a7bf9ed0a38053e68d44adbf5.png)

 此外，不同版本的StrictHttpFirewall方法是有差异的，以spring-security-web-5.6.8为例，增加了黑名单的规则：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c2a5d866d1ff5a6f1ecb348e235d15de33a9530d.png)

 主要是增加了一些类似换行符的黑名单：

```Java
private static final List<String> FORBIDDEN_DOUBLE_FORWARDSLASH = Collections.unmodifiableList(Arrays.asList("//", "%2f%2f", "%2f%2F", "%2F%2f", "%2F%2F"));
private static final List<String> FORBIDDEN_BACKSLASH = Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));
private static final List<String> FORBIDDEN_NULL = Collections.unmodifiableList(Arrays.asList("\u0000", "%00"));
private static final List<String> FORBIDDEN_LF = Collections.unmodifiableList(Arrays.asList("\n", "%0a", "%0A"));
private static final List<String> FORBIDDEN_CR = Collections.unmodifiableList(Arrays.asList("\r", "%0d", "%0D"));
private static final List<String> FORBIDDEN_LINE_SEPARATOR = Collections.unmodifiableList(Arrays.asList("\u2028"));
private static final List<String> FORBIDDEN_PARAGRAPH_SEPARATOR = Collections.unmodifiableList(Arrays.asList("\u2029"));
```

 除此之外，还有一些功能上的拓展，例如在5.3.11.RELEASE及之后版本，增加了rejectedUntrustedHosts方法，用于校验HOST是否可信：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4f6dfcc92f23f0253aa6eb50958c856ad639457a.png)

 主要是通过request.getServerName()方法获取host然后跟配置的白名单进行比对：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-20df851913875743869e63417da23e8e6e7fcef7.png)

### 2.2 DefaultHttpFirewall

 相比严格模式，DefaultHttpFirewall的处理逻辑会相对简单，主要是做了以下的处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0d5970d6ffc683e42af9ec5385d22404a200cd64.png)

- **isNormalized**

 这里跟StrictHttpFirewall是类似的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8fa8a4713491ae49df6c9f44218364ac10bee8d5.png)

- **containsInvalidUrlEncodedSlash**

 主要用于判断requestURI是否包含编码后的斜杠(%2f或%2F):

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a0eefa0ce90ee1b5cea05bf62e606ebc56f25a81.png)

0x03 RequestMatcher
-------------------

 作为SpringSecurity中的请求匹配器，用于匹配请求 `HttpServletRequest` 是否符合定义的匹配规则，其定义了matches方法，如果返回是true表示提供的请求与提供的匹配规则匹配，如果返回的是false则不匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8391edb10eb8814d14a3abfe8289b301deb79a63.png)

 下面看看RequestMatcher常用的实现类具体的作用：

### 3.1 AntPathRequestMatcher

 AntPathRequestMatcher是基于Ant风格模式进行匹配。例如如下的例子，所有/admin/下的接口都需要经过认证，否则无法访问：

```Java
protected void configure(HttpSecurity http) throws Exception {
   http.authorizeRequests().antMatchers("/admin/**").authenticated();
}
```

 查看AntPathRequestMatcher的具体实现,主要的匹配在org.springframework.security.web.util.matcher.AntPathRequestMatcher#matches方法中进行。

 首先判断请求方法是否一致，一致的话如果pattern是`/**`的话，说明是全路径匹配，直接返回true。否则获取当前请求的url，然后调用当前matcher的matches方法进行进一步的匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cc97c65d797dc470d792b7b0c0ac654be9631e06.png)

 首先看看当前请求url的获取方法，实际上是调用了Spring中的一个帮助类**UrlPathHelper**(封装了有很多与URL路径处理有关的方法)的getPathWithinApplication方法进行获取，如果没有配置urlPathHelper的话，则通过请求的ServletPath和PathInfo进行拼接，获取归一化处理后的url：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d7ab29e1660d1820f6162c1d753c88c236f3fc11.png)

 获取完url后，会调用当前matcher的matches方法进行进一步的匹配，mathcer的实例化如下，根据pattern的不同，会分别使用SubpathMatcher和SpringAntMatcher：

- SubpathMatcher

 如果pattern以`**`结尾并且不包含`?`和`{`和`}`并且pattern的倒数第二个字符是`*`的话，会使用SubpathMatcher，例如/admin/\*\*就会使用SubpathMatcher，查看具体的matches方法实现，首先是大小写敏感的处理，如果开关打开的话会将path统一转换成小写，然后将path跟subpath（pattern.substring(0, pattern.length() - 3)）进行比对：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b52f389b058abe66bd0cfca19b3a12e9357ef6fc.png)

- SpringAntMatcher

 如果是/admin/index的话就会使用SpringAntMatcher，实际上是调用的org.springframework.util.AntPathMatcher进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3a8c5c8ff189a0a584f27aca786736e8928dfbe9.png)

### 3.1.1 相关风险

- **PathPatternParser解析差异**

 通过SpringSecurity处理后，下一步就是通过Spring处理获取到对应的Controller。

 在2.6 及之后版本的 Spring Boot 将 Spring MVC 处理请求的路径匹配模式从AntPathMatcher更改为了PathPatternParser。那么这里会有一种情况，SpringSecurity某种条件下使用的是AntPathMatcher进行匹配，而高版本的Spring使用的是PathPatternParser。

 利用解析的差异在某些条件下可以达到绕过鉴权的效果。例如如下例子:

```Java
@GetMapping("/admin/*")
public String Manage(){
    return "manage";
}
```

 `/admin/index`是需要认证后才可以访问的：

```Java
@Override
protected void configure(HttpSecurity httpSecurity) throws Exception{
    httpSecurity.authorizeRequests().antMatchers("/admin/*").authenticated();
}
```

 而在高版本的Spring，在进行路由解析时使用的是PathPatternParser，此时使用\\r或者\\n（\\r的URl编码为%0d，\\n的URL编码为%0a）即可绕过当前的鉴权规则：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-58e4840f69b3961f00f38a5e53c30354e3daa579.png)

PS：低版本的Spring仍使用的是AntPathMatcher，即使绕过了SpringSecurity也会因为解析差异找不到对应的Controller返回404。同时高版本的SpringSecurity的StrictHttpFirewall已经对\\r或者\\n（\\r的URl编码为%0d，\\n的URL编码为%0a）进行了拦截处理。

- **结合TrailingSlashMatch属性绕过**

 当**TrailingSlashMatch**为true时(默认为true)，会应用尾部的/匹配，例如/hello和/hello/的匹配结果是一样的。

 例如Spring Security配置如下：

```Java
@Override
protected void configure(HttpSecurity httpSecurity) throws Exception{
    httpSecurity.authorizeRequests().antMatchers("/admin/index").authenticated();
}
```

 此时结合**TrailingSlashMatch**的特性，在结尾加上`/`即可绕过鉴权：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4bd9b4fcbdecc04ff37bb73c3cd8b962cae7c512.png)

- **结合SuffixPatternMatch属性绕过**

 **SuffixPatternMatch**是后缀匹配模式，用于能以 .xxx 结尾的方式进行匹配。当启用后缀匹配模式时，例如/hello和/hello.do的匹配结果是一样的。

 当Spring Security配置如下时，可以尝试添加后缀进行绕过：

```Java
@Override
protected void configure(HttpSecurity httpSecurity) throws Exception{
    httpSecurity.authorizeRequests().antMatchers("/admin/index").authenticated();
}
```

**PS：spring-webmvc 5.3后相关useSuffixPatternMatch的默认值会由true变为false。**

### 3.2 RegexRequestMatcher

 RegexRequestMatcher会根据正则模式进行匹配。例如如下例子，所有/admin/下的接口都需要经过认证，否则无法访问：

```Java
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests().regexMatchers("/admin/.*").authenticated();
}
```

 查看RegexRequestMatcher的具体实现,主要的匹配在org.springframework.security.web.util.matcher.RegexRequestMatcher#matches方法中进行，首先判断请求方法是否一致，一致的话首先进行url的获取，获取以后调用的是java.util.regex.Pattern#matcher方法进行正则表达式的匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f6ca7168ac279436d9069c40e663af1bbb406afb.png)

### 3.2.1 相关风险

- **?认证绕过**

 例如当前配置如下：

```Java
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests().regexMatchers("/admin/index").authenticated();
}
```

 正常情况下直接访问/admin/index请求未经过认证，会被拦截：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e3bb0679911270adc96f17dea6a2dba9019b3750.png)

 查看org.springframework.security.web.util.matcher.RegexRequestMatcher#matches具体实现,在获得 url 路径后，如果query不为空，还会把?和后面的参数拼接上去，作为 url继续进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-95f8f8ed00dcab8390f4058e0f15004e037b6c8f.png)

 也就是说在请求的path后加上?即可绕过鉴权:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1c54f1044838166d1db531644ebf8f37dda2bfbd.png)

- **CVE-2022-22978**

 查阅官方文档：<https://docs.oracle.com/javase/8/docs/api/constant-values.html>

 漏洞版本（Spring Security 5.5.x &lt; 5.5.7&amp;Spring Security 5.6.x &lt; 5.6.4）是默认的Pattern模式，对于默认的Pattern模式，不开启DOTALL时候，在默认匹配的时候不会匹配\\r \\n 字符：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-53fc71403e273161c7ebd36be12b8ff2414af2c4.png)

 同样是上面的例子，正常情况下/admin/index被拦截：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-979352ee2ecdb5e08b33a06ffcfac298b9a96df0.png)

 由于设计缺陷使用\\r或者\\n（\\r的URl编码为%0d，\\n的URL编码为%0a）即可绕过：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fac7d6ac64bc99cdd58bf7c94f1c56f3cfb77e90.png)

PS:这里在Spring路由匹配时候，低版本Spring还会受到AntPathMatcher的影响，导致无法成功利用（返回404）。

 在修复版本，配置成了DOTALL模式，在dotall模式中，表达式`.`匹配任何字符，包括行结束符：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e9e636e98e1cfd82d54db426314bf280419da160.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9fe5cd8c8f747942d490ef801b960a74dae4a3d4.png)

### 3.3 MvcRequestMatcher

 参考https://docs.spring.io/spring-security/reference/servlet/integrations/mvc.html#mvc-requestmatcher

 其使用Spring MVC的HandlerMappingIntrospector来匹配路径并提取变量。相比AntPathRequestMatcher会更严谨。例如mvcMatchers("/index") ，除了匹配/index,对于/index/, /index.html, /index.do也会匹配。避免了前面AntPathRequestMatcher的绕过一些问题。

 同样是前面的例子，使用MvcRequestMatcher 后无法绕过鉴权逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6ea9fd2c3877d181672bfd9ad4cd1af07d4eab7d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-87fc68d958ab715a2a8bda223451fd38e94997d2.png)

 具体的实现原理以及风险可以参考<https://forum.butian.net/share/2199>

### 3.4 AnyRequestMatcher

 这个表示匹配所有的请求。

### 3.5 其他

 参考https://docs.spring.io/spring-security/reference/5.8/migration/servlet/config.html

```Java
In Spring Security 5.8, the antMatchers, mvcMatchers, and regexMatchers methods were deprecated in favor of new requestMatchers methods.

These new methods have more secure defaults since they choose the most appropriate RequestMatcher implementation for your application. In summary, the new methods choose the MvcRequestMatcher implementation if your application has Spring MVC in the classpath, falling back to the AntPathRequestMatcher implementation if Spring MVC is not present (aligning the behavior with the Kotlin equivalent methods).
```

 高版本Spring security会使用如下写法在URL层面上进行权限管控：

```Java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authz) -&gt; authz
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/user/**").hasRole("USER")
                .anyRequest().authenticated()
            );
        return http.build();
    }

}
```

 根据官方文档的描述，跟如下写法是一致的,因为在SpringMVC应用中会自动使用MvcRequestMatcher进行解析，规范了使用避免了大多数的安全问题：

```Java
@Configuration
@EnableWebSecurity
@EnableWebMvc
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authz) -&gt; authz
                .mvcMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );
        return http.build();
    }

}
```