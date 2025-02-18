0x00前言
======

 在SpringMvc中，**DispatcherServlet**是前端控制器设计模式的实现,提供Spring Web MVC的集中访问点,而且负责职责的分派。主要职责如下：

- 文件上传解析，如果请求类型是multipart将通过MultipartResolve进行文件上传解析；
- 通过HandlerMapping，将请求映射到处理器（返回一个HandlerExecutionChain，它包括一个处理器，多个HandlerIntercept拦截器）
- 通过HandlerAdapter支持多种类型的处理器（HandlerExecutionChain中的处理器）；
- 通过ViewReslver解析逻辑视图名到具体视图实现；
- 本地化解析；
- 渲染具体的视图等；
- 执行过程中遇到异常将交给HandlerExecutionResolver来解析；

0x01 Spring Web解析过程
===================

 以spring-webmvc 5.3.9为例。当向Spring MVC发送一个请求时，看看具体的处理过程是怎么样的。

 当Spring MVC接收到请求时，Servlet容器会调用DispatcherServlet的service方法（方法的实现在其父类FrameworkServlet中定义）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4092fc0767ff80630ca336728f028a02f5d43d50.png)

 这里首先获取request请求的类型，除了PATCH方法以外都会通过HttpServlet的service方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-085d8c7b4412cba769e533a2603b56ef8bef3803.png)

 这里实际上是根据不同的请求方法，调用processRequest方法，例如GET请求会调用doGet方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bf6f055dee7079a82f29be912aa7e7d5b50a2470.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d9fb45aed11d0dec76e9a3c3bece39ca5f9ba990.png)

 在执行doService方法后，继而调用doDispatch方法处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f06d2aaa76b5cef7f3f02741c71da8d056b0b159.png)

 在doDispatch方法中，首先会对multipart请求进行处理，然后获取对应的mappedHandler：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0bb23b96e29152bfe38fac3de48a77a9b34548a1.png)

 在getHandler方法中，按顺序循环调用HandlerMapping的getHandler方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-af328e2858169436fa3ae8153e9e3d3223508ea2.png)

 常见的HandlerMapping有如下几个，查阅JavaDoc文档可知注解中配置的路由是通过RequestMappingHandlerMapping处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f0e1a98e1b7a17b75fbdfcb85c00b00b82c0ac46.png)

 在getHandler方法中通过getHandlerInternal获取handler构建HandlerExecutionChain并返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8da6a235a65c2b45d3046c9284865020527387b5.png)

 getHandlerInternal方法从request对象中获取请求的path并根据path找到handlerMethod：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-37efd7ac4da992b1eeb0ede34a5a1520c4a5afeb.png)

 在initLookupPath方法中，主要用于初始化请求映射的路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-be1683cd5f0b353f743b2c8c03c0cbf977be8e0c.png)

 这里通过**UrlPathHelper**类进行路径的处理，UrlPathHelper是Spring中的一个帮助类，有很多与URL路径处理有关的方法。后续单独分析。

 获取到路径后，调用lookupHandlerMethod方法，首先直接根据路径获取对应的Mapping，获取不到的话调用addMatchingMappings遍历所有的ReuqestMappingInfo对象并进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-877e5aab1cfc16dccdbe4905fd4d8edf0323511f.png)

 在addMatchingMappings方法中，遍历识别到的ReuqestMappingInfo对象并进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f825990f335d607e146c4bffd03817fd5e7c3ee6.png)

 核心方法getMatchingMapping实际上调用的是org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping#getMatchingCondition方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7309d1ad927710c0d9428d20dce36e8f704a476f.png)

 getMatchingCondition不同版本的实现也是不一样的，高版本会使用PathPattern来进行URL匹配（**不同版本会有差异，在 2.6之前，默认使用的是AntPathMatcher**进行的字符串模式匹配）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f2605b2a13b2adba8b7e8b96d216cfdcd5ac468d.png)

 在getMatchingCondition中会检查各种条件是否匹配，例如请求方法methods、参数params、请求头headers还有出入参类型等等，其中patternsCondition.getMatchingCondition(request)是核心的路径匹配方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8bb65773a1d0e5f6315d177d4287b8df91a6c4d3.png)

 然后会调用PatternsRequestCondition#getMatchingPattern方法进行相关的匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ebede8a7d98661dab455329ab8194510ade21902.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-402b2ee52bea52956de042d5d9e38ee573e8fc9d.png)

 查看PatternRequestCondition#getMatchingPattern方法的具体实现，如果模式与路径相等，直接返回模式，否则进行后缀模式匹配，这里涉及到两个属性**SuffixPatternMatch&amp;TrailingSlashMatch**，根据这两个属性的boolean值会调用pathMatcher#match方法进行进一步的匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-31168a42e6d4593d515c4b336ce6c02f13e2be65.png)

 查后续获取到url 和 Handler 映射关系后，springMVC就可以根据请求的uri来找到对应的Controller和method，处理和响应请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7d6518741267e6b9be6560ff223af74fe90656fd.png)

0x02 工具类
========

2.1 路径处理帮助类UrlPathHelper
------------------------

 UrlPathHelper类是Spring的一个帮助类，主要根据相应的配置解析请求中的路径，里面实现了很多与URL路径处理有关的方法。

 以spring-web-5.3.9为例，接前面SpringMvc请求解析过程的分析，当进入到UrlPathHelper时，首先调用resolveAndCacheLookupPath方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c84fe4c07e7af5e3498b41e24df3e6424c9f7056.png)

 继续跟进，这里调用了getPathWithinApplication方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-80e2cf630a1762291eaec004fc69984ac3aa6754.png)

 查看getPathWithinApplication的具体实现，这里分别获取了ContextPath和requestUri然后进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1d4aad66e8ea70c633b7d46b0f54e8ab5faf817e.png)

 首先是ContextPath，这里会进行对应的解码操作，相关方法(decodeRequestString-&gt;decodeInternal,若设置了解码属性便进行对应的解码操作)：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-354fbebc202d8d0e2851341a4c62536facb1ea25.png)

 然后是requestUri，这里通过request.getRequestURI()方法获取当前request中的URI/URL，并不会对获取到的内容进行规范化处理，所以UrlPathHelper进行了URI解码、移除分号内容并清理斜线等进一步的处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-208d911ceb06c17426260e7526f10d17d49f7771.png)

 查看decodeAndCleanUriString方法的具体实现，主要有三个方法，看看具体的作用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b02eebccab8556deeca28f9320e4f440d2503c56.png)

 首先是removeSemicolonContent，对于当前处理的URI，如果设置了setRemoveSemicolonContent属性为true，则删除分号，否则删除Jsessionid：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5526704d1b2900c536c3c13cd59210a3a027e75b.png)

 然后是decodeRequestString，这里前面说过，如果设置了解码属性便进行对应的解码操作。

 最后是getSanitizedPath方法，这个方法主要是将`//`替换为`/`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f9593cd07b46594e2aaf7f381bb41294f4fbefbb.png)

 此时ContextPath和requestUri已经处理完成，继续调用getRemainingPath方法进行处理，这里主要是将mapping字符(实际上传入的是ContextPath)与requestUri字符串相匹配，把requestUri中的分号部分忽略掉：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ee2db0652f380813ea0e4f86d71b4023d95044d2.png)

 到这里整个getPathWithinApplication方法处理完成，这时候涉及到一个属性`alwaysUseFullPath`,不同的值将会决定是否经过getPathWithinServletMapping方法处理（当Spring Boot版本在小于等于2.3.0.RELEASE的情况下，alwaysUseFullPath为默认值false，当前版本会直接返回处理后的pathWithinApp）:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a1d7c7c905567c9f757fa1e11234fb8808404bd2.png)

 到此整个`String lookupPath = this.initLookupPath(request);`解析完成。

### 2.1.1 其他

 前面提到在initLookupPath方法中，主要用于初始化请求映射的路径，主要会通过**UrlPathHelper**类进行路径的处理，这里还有一段逻辑，当this.usesPathPatterns()为true时会执行另外一段逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e3e6d61fe3207c26f20b91ae509d8d385be93252.png)

 当使用PathPattern进行解析时，this.usesPathPatterns()为true，以spring-webmvc-5.3.25为例，查看具体的解析过程：

 首先从request域中获取PATH\_ATTRIBUTE属性的内容，然后使用defaultInstance对象进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-54f184a5421050adf2f8c7428c3d046fea40d0cd.png)

 这里会根据removeSemicolonContent的值（默认为true）确定是移除请求URI中的所有分号内容还是只移除jsessionid部分：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a103b626eb990a2800a85d5214084d16cf94db1e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cf00b774c336b5671095e8789eb7ebbcd14ad92b.png)

 到此整个`String lookupPath = this.initLookupPath(request);`解析完成。

 这里并没有前面调用resolveAndCacheLookupPath的逻辑复杂，例如并不会将`//`处理成`/`，结合PathPattern的解析逻辑，如果此时Controller配置如下：

```Java
@RequestMapping("/admin/page")
@ResponseBody
public String hello() {
  return "admin page";
}
```

 那么访问/admin//page是无法匹配的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0bb4c5347f8e7c2c9bd2fd797555728472d7e4d8.png)

0x03 关键属性
=========

3.1 SuffixPatternMatch/TrailingSlashMatch（后缀/结尾匹配模式）
----------------------------------------------------

 前面提到的模式匹配的两个属性**SuffixPatternMatch&amp;TrailingSlashMatch**。看看具体的代码实现：

 **SuffixPatternMatch**是后缀匹配模式，用于能以 .xxx 结尾的方式进行匹配。这里46对应的Ascii码是`.`，根据具体代码可以知道，当启用后缀匹配模式时，例如/hello和/hello.do的匹配结果是一样的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5171bc4489c6bbfb19aa6fa43a0fccf75e850176.png)

 当**TrailingSlashMatch**为true时，会应用尾部的/匹配，例如/hello和/hello/的匹配结果是一样的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f3da00f4fa22bf65449e684f6648074de2732c4d.png)

### 3.1.1 各版本差异

 5.3后相关useSuffixPatternMatch的默认值会由true变为false,参考<https://github.com/spring-projects/spring-framework/issues/23915>

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a1c2f98b352c703532954e9d71d249c35b06734a.png)

 从`org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping`中可以看到对应属性的改变：

- spring-webmvc:5.3.9

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7b32a216700ae88a61a19408a52c5da51ccbba98.png)

- spring-webmvc-5.2.22.RELEASE

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c580bfaf1d98eaf6ad8e4d446ab83c8df0b1fd2e.png)

3.2 alwaysUseFullPath
---------------------

 alwaysUseFullPath主要用于判断是否使用servlet context中的全路径匹配处理器。

### 3.2.1 各版本差异

 WebMvcAutoConfiguration是Spring Boot中关于Spring MVC自动配置类。在org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration#configurePathMatch方法中可以配置URL路径的匹配规则。

 主要是这两个分界点：

- spring-boot-autoconfigure-2.3.0.RELEASE

 在2.3.0以及之前版本，在configurePathMatch中，没有对UrlPathHelper的alwaysUseFullPath属性进行设置，默认为False：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b680bf3897fc31544545a555a43b3d8d7f23863c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9d87fa1c9b9840b3c04002e8f8c5545d5b0dd3d9.png)

- spring-boot-autoconfigure-2.3.1.RELEAS

 在2.3.1及之后版本，在configurePathMatch方法中，通过实例化UrlPathHelper对象并调用对应的setAlwaysUseFullPath方法将alwaysUseFullPath属性设置为true：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e5370d5305ed24773af2fb3df6da6e743eec145e.png)

### 3.2.2 getPathWithinServletMapping方法

 接之前Spring MVC发接收到请求时的分析，`alwaysUseFullPath`属性不同的值将会决定是否经过getPathWithinServletMapping方法处理。这里以2.3.0.RELEASE版本为例，其值默认为false,会经过getPathWithinServletMapping方法进行处理,跟进查看具体的过程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-dbc29f3feade3769217fd7e31e253be39eb8402f.png)

 首先会调用getPathWithinApplication方法进行处理，前面已经分析过具体的行为了，主要是进行了URI解码、移除分号内容并清理斜线等一系列操作，不再赘述：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b894ae364e549820f4874718ccecbc4db2bd3e8b.png)

 跟getPathWithinApplication不同的是，getPathWithinServletMapping会获取ServletPath并进行对应的处理，这里主要是调用request.getServletPath(主要是对uri标准化处理，例如解码然后处理跨目录等一系列操作)方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4636cc85a26652da316d3c4d2925d178db9056df.png)

 再往后就是一系列熟悉的操作了，例如调用getSanitizedPath方法将`//`替换为`/`。调用getRemainingPath进行处理。还有request.getPathInfo()等一系列的组合后，返回对应的值给lookupPath，然后就是熟悉的操作了，调用lookupHandlerMethod方法，遍历所有的ReuqestMappingInfo对象并进行匹配，进行对应的解析。

### 3.2.3 与getPathWithinApplication的区别

 根据前面的分析，getPathWithinServletMapping会对uri进行标准化处理（也就是说**当SpringBoot 版本在小于等于2.3.0.RELEASE时，会对路径进行规范化处理**），而getPathWithinApplication是通过request.getRequestURI()方法获取当前request中的URI/URL，并不会对获取到的内容进行规范化处理。

 当请求路径中包括类似`..`的关键词时，调用getPathWithinApplication方法解析后，会因为没有处理跨目录的字符，导致找不到对应的Handler而返回404。

 看一个具体的实例,注册的路由如下，尝试访问`/file/../hello`路径，看看不同版本的解析情况：

```Java
@GetMapping({"/hello"})
public String index() {
    return "hello";
}
```

 当alwaysUseFullPath为false时，调用了getPathWithinServletMapping进行处理，跨目录字符解码并规范化后，成功匹配对应的handler并访问成功：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-412dd97794472ad6669b98d187d3e9ed10bb9140.png)

 当alwaysUseFullPath为true时，调用的是getPathWithinApplication，没有对跨目录进行标准化处理，最终找不到对应的handler，返回404状态码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-620a863bd75bb29e9c127d184c8764b5504bf908.png)

 这里也解释了类似平时审计中遇到的一些鉴权措施缺陷，为什么没办法结合`../`进行绕过的原因。例如如下的例子：

 在Filter中以/system/login开头的接口是白名单，不需要进行访问控制（登陆页面所有人都可以访问），其他接口都需要进行登陆检查，防止未授权访问：

```Java
    String uri = request.getRequestURI();
    if(uri.startsWith("/system/login")) {
        //登陆接口设置白名单
        filterChain.doFilter(request, response);
    }
    .....
    .....
```

 从代码上看确实可以通过构造类似`/system/login/../admin/userInfo`的方式进行访问，绕过鉴权Filter的处理，但是在后续解析时，若当前alwaysUseFullPath为true时，此时解析调用的是getPathWithinApplication，不会对跨目录进行标准化处理，最终找不到对应的handler，返回404状态码，即使绕过了Filter也没办法进行漏洞利用。

0x04 解析器
========

4.1 AntPathMatcher&amp;PathPattern
----------------------------------

### 4.1.1 各版本差异

 org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration是Spring Boot中关于Spring MVC自动配置类，对比下2.6之前之后的两个版本，可以发现2.6及之后版本多了个PathPatternParser的实现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-510ee932ba1bbb7f598f2cf95f68103902ef1914.png)

 此外，WebMvcAutoConfiguration自动配置类中包含了一个静态类WebMvcAutoConfigurationAdapter，通过这里加载的WebMvcProperties内容也可以看出来具体的差异：

- 在 2.6之前，默认使用的是AntPathMatcher（具体配置在org.springframework.boot.autoconfigure.web.servlet.WebMvcProperties.Pathmatch），查看具体的代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-92ffe9511f78e8dee46b02240fbc94b73390d183.png)

- 2.6.0及之后就变成了PathPattern了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ab6c3ea6da2ebb7a91a46cad834b38348c22a521.png)

### 4.1.2 AntPathMatcher

 AntPathMatcher所属模块为`spring-core`,对应class`org.springframework.util.AntPathMatcher`。一般用于类路径、文件系统和其它资源的解析。

 查看官方文档，可以知道AntPathMatcher支持的Path匹配规则如下：

| 规则 | 作用 |
|---|---|
| ？ | 匹配任意单字符 |
| \* | 匹配0或者任意数量的字符 |
| \*\* | 匹配0或者任意层级的目录 |
| {spring:正则表达式} | 匹配到的path内容赋值给spring变量 |

 简单分析下具体的解析过程：

 2.6之前的Spring会使用PatternsRequestCondition通过AntPathMatcher来进行URL匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a048ea7d96549e478013218a16a3e3c833a1d7f1.png)

 具体的匹配在org.springframework.util.AntPathMatcher#doMatch方法，首先调用tokenizePattern()方法将pattern分割成了String数组，如果是全路径并且区分大小写,那么就通过简单的字符串检查，看看path是否有潜在匹配的可能，没有的话返回false:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2a7755fb71eae4541159ee3a093c00c1d466b72e.png)

 然后调用tokenizePath()方法将需要匹配的path分割成string数组,主要是通过java.util 里面的StringTokenizer来处理字符串：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6842bf648c0f826dd85a95c758600970709c2c37.png)

 这里有个属性trimTokens(**从Spring Framework 4.3.0+开始， AntPathMatcher将 trimTokens 设置为false**):

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b3ca6d6f847679622c6b5d2149e92b395cbf3996.png)

 可以看到这个属性主要是用于消除path中的空格（之前由于与SpringSecurity的解析差异导致了CVE-2016-5007、CVE-2020-17523)：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a8b3d9c5d70be870cd1ee60c916ada8daca67672.png)

 后面就是pathDirs和pattDirs两个数组从左到右开始匹配，主要是一些正则的转换还有通配符的匹配。例如/admin/\*的`*`实际上是正则表达式`.*`通过java.util.regex.compile#matcher进行匹配:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-340247774ab3642fa1d54c6b8b7ccf4d8f7358e9.png)

### 4.1.3 PathPattern

 PathPattern是Spring5新增的API，所属模块为`spring-web`，对应class `org.springframework.web.util.pattern.PathPattern`。

 查看官方文档：

Representation of a parsed path pattern. Includes a chain of path elements for fast matching and accumulates computed state for quick comparison of patterns.

`PathPattern` matches URL paths using the following rules:

- `?` matches one character
- `*` matches zero or more characters within a path segment
- `**` matches zero or more *path segments* until the end of the path
- `{spring}` matches a *path segment* and captures it as a variable named "spring"
- `{spring:[a-z]+}` matches the regexp `[a-z]+` as a path variable named "spring"
- `{*spring}` matches zero or more *path segments* until the end of the path and captures it as a variable named "spring"

**Note:** In contrast to `[AntPathMatcher](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/util/AntPathMatcher.html)`, `**` is supported only at the end of a pattern. For example `/pages/{}` is valid but `/pages/{}/details` is not. The same applies also to the capturing variant `{*spring}`. The aim is to eliminate ambiguity when comparing patterns for specificity.

 根据官方文档的描述，其实\**跟AntPathMatcher匹配规则区别不大，PathPattern在保持其匹配规则的基础上，新增了`{*spring}`的语法支持。\*\*

 `{*spring}`表示匹配余下的path路径部分并将其赋值给名为spring的变量（变量名可以根据实际情况随意命名，与`@PathVariable`名称对应即可）。同时，\**`{*spring}`是可以匹配剩余所有path的，类似`/**`，只是功能更强，可以获取到这部分动态匹配到的内容。**

 简单分析下具体的解析过程：

 2.6以及之后的Spring会使用PathPatternsRequestCondition通过PathPattern来进行URL匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c592632afcbd009afbe425d4e5878ac6c55cebc0.png)

 可以看到跟之前版本使用的PatternsRequestCondition不同的是，此时的路径解析已经不受到类似SuffixPatternMatch属性的影响了:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e0860f91a177f2712cf146a49b71d4d6f118e0f9.png)

 主要在org.springframework.web.util.pattern.PathPattern#matches方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b7f907dce64f03b374a5c4bb6348f177b7a3e58f.png)

 首先会根据/将URL拆分成多个**PathElement**对象，以/admin/index/为例，这里会分割成多个对象，然后根据PathPattern的链式节点中对应的PathElement的matches方法逐个进行匹配：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8b9bd2a41c4b23f1d8007d92346e9d910d23cc60.png)

 以Pattern为/admin/\*为例，首先第一个元素是分隔符`/`，会调用SeparatorPathElement的matches方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1092d77a2f9686bff05e462fe1ddcc513df44f8b.png)

 处理完后pathIndex++，继续遍历下一个元素进行处理，下一个是admin，会通过LiteralPathElement#matches进行处理，同样的最后会对pathindex进行+1，然后继续遍历PathElement元素直到遍历结束为止：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c309a92ba6d6ff01c5583b5914ec94a36b9af3fa.png)

 在最后会根据matchOptionalTrailingSeparator（此参数为true时，默认为true）进行一定的处理，如果Pattern尾部没有斜杠，请求路径有尾部斜杠也能成功匹配（类似TrailingSlashMatch的作用）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0331842a2738f1237d3cbe36e141e6498d2ebdbf.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-aa90624464abcca5f60b8ae0a6c8b0545a77ad15.png)

 所以这里/admin/index和/admin/index/都是可以访问到对应的路由的。

 除此之外，根据不同Pattern的写法，还有很多PathElement。

### 4.1.4 两者的区别

 首先，PathPattern新增{\*spring}语法支持，功能更加的强大。除此以外，相比AntPathMatcher，还有以下区别：

- PathPattern通配符只能定义在尾部，而AntPathMatcher可以在中间：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-eb10e2029758307fd0d99d593f849369e232a7c5.png)

- AntPathMatcher默认使用`/`作为分隔符。也可以根据实际情况自行指定分隔符（例如windows是`\`，Linux是`/`，包名是`.`），这点从其构造器可以看出：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-48553e861d3b4acaebd625aac1938e74a9bba2c2.png)

 因为PathPattern的构造器不是public的，只能通过`PathPatternParser`创建其实例，这里构造方法初始化了pathOptions变量：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-df0e8081b39310a70f2d94aa881cabe53f36d2f9.png)

 查看Options.HTTP\_PATH，可以看到跟AntPathMatcher一样，默认使用`/`作为分隔符：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-87b5c254304c1f3a0a318e917fc0bf2018f59acf.png)

 但是**PathPattern只支持两种分隔符（/和.）**。