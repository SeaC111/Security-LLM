0x00 关于Apache Shiro
===================

 Apache Shiro是Java的一个安全框架，主要用于处理身份认证、授权、企业会话管理和加密等。与Spring Security一样都是一个权限安全框架，但是与Spring Security相比，在于其比较简洁易懂的认证和授权方式。

 与Spring security类似，其一系列的认证以及权限校验操作主要是通过filter实现的。  
shiro-web 提供了一些filter，每种filter都对应了不同的权限拦截规则：

| FilterName | class |
|---|---|
| anon | org.apache.shiro.web.filter.authc.AnonymousFilter |
| authc | org.apache.shiro.web.filter.authc.FormAuthenticationFilter |
| authcBasic | org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter |
| logout | org.apache.shiro.web.filter.authc.LogoutFilter |
| noSessionCreation | org.apache.shiro.web.filter.session.NoSessionCreationFilter |
| perms | org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter |
| port | org.apache.shiro.web.filter.authz.PortFilter |
| rest | org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter |
| roles | org.apache.shiro.web.filter.authz.RolesAuthorizationFilter |
| ssl | org.apache.shiro.web.filter.authz.SslFilter |
| user | org.apache.shiro.web.filter.authc.UserFilter |

0x01 Shiro的请求解析过程
=================

 使用 Shiro 时，一般需要配置返回值为ShiroFilterFactoryBean的Bean，用于创建Shiro Filter。

 例如如下的例子，这里通过setFilterChainDefinitionMap设置对应的url和过滤器匹配规则：

```Java
@Bean
ShiroFilterFactoryBean shiroFilterFactoryBean(){
    ShiroFilterConfiguration shiroFilterConfiguration = new ShiroFilterConfiguration();
    shiroFilterConfiguration.setStaticSecurityManagerEnabled(true);
    shiroFilterConfiguration.setFilterOncePerRequest(true);

    ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
    bean.setShiroFilterConfiguration(shiroFilterConfiguration);

    bean.setSecurityManager(securityManager());
    bean.setLoginUrl("/login");
    bean.setSuccessUrl("/index");
    bean.setUnauthorizedUrl("/unauthorizedurl");
    Map<String, String> map = new LinkedHashMap<>();
    map.put("/doLogin", "anon");
    map.put("/admin/*", "authc");
    bean.setFilterChainDefinitionMap(map);
    return  bean;
}
```

 当发起HTTP请求时，Shiro 的多个过滤器形成了一条链，所有请求都必须通过这些过滤器后才能成功访问到资源。以1.10.0版本为例，简单看下Shiro拦截请求处理的过程。

 查阅相关资料，shiro 发挥作用的入口是在`org.apache.shiro.spring.web.ShiroFilterFactoryBean.SpringShiroFilter`中，其中它继承自 OncePerRequestFilter，从字面上看是每个请求执行一次。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7bddf5c78f812b664123e87fa165a4328905c304.png)

 在接收到请求时会先进入 OncePerRequestFilter.doFilter() ，在这里写一个断点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7b28c5a9574509a647ad0f469753b8607346a010.png)

 这里首先会做一些简单的判断，然后org.apache.shiro.web.servlet.AbstractShiroFilter#doFilterInternal方法，首先会对request 和 response 对象进行包装，然后调用createSubject方法，这里会处理认证授权信息并进行封装:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-eb09ba7b93ed5a229e47f767de2264139acf9617.png)

 然后在Callable修改了最近一次的访问时间，然后调用 FilterChain：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-551214c16899dc40250bd03971ca6bb6d53e74dd.png)

 这里主要调用`org.apache.shiro.web.servlet.AbstractShiroFilter#getExecutionChain`创建FilterChain,**实际上调用的是org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver#getChain来获取**（会根据URL路径匹配，解析出ServletRequest请求过程中要执行的过滤器链）:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-56434d16755d9d071b59ba2cda9206e9bb56bd4a.png)

 查看debug info，chain主要有两个Filter，一个authc（对应前面的配置map.put("/admin/\*", "authc");），一个invalidRequest（主要用于拦截存在安全问题的uri并返回400状态码）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-954697b5ddb9aa624bd96a2c6714a88ce15c2af3.png)

 获取到filterchain后，会继续调用chain.doFilter(request, response)逐个调用对应的filter，这里实际上调用的是org.apache.shiro.web.servlet.ProxiedFilterChain#doFilter来调用对应filter的doFilter方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f40b4ef6981bf95a0341e1020bbc9f7a3135f69b.png)

 按照前面的分析，首先会调用InvalidRequestFilter进行拦截，然后再调用authc规则对应的过滤器org.apache.shiro.web.filter.authc.FormAuthenticationFilter。

 首先会调用org.apache.shiro.web.servlet.OncePerRequestFilter#doFilter，此时调用的是org.apache.shiro.web.servlet.AdviceFilter#doFilterInternal（AdviceFilter 主要负责处理anon、authc 等请求的）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cf437c950a7f16f259ed49231c091cc62ef60204.png)

 这里通过调用preHandle方法会进入PathMatchingFilter的调用逻辑，主要是验证filterChain是否需要继续（对请求的URI验证是否匹配，然后获取到路径上对应的配置调用isFilterChainContinued 方法验证是否满足配置）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-45111833f2922d0e6fc3c47cf0324f43e565e602.png)

 当匹配到路径时会执行isFilterChainContinued方法,这里执行onPreHandle,根据返回值来决定是否继续允许执行后续的filter：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-710508ad5a6e1cf3484505eb5bf39e98f801bdb9.png)

 实际调用了org.apache.shiro.web.filter.AccessControlFilter#onPreHandle:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d0ca0dda39d8721d89990ad9da3db127544d4e8d.png)

 继续跟进这里开始调用FilterChain中InvalidRequestFilter的处理逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-db08101b4d07a0e5888e0f0ef8789ee6e93be8d5.png)

 处理完后，返回到AdviceFilter处理逻辑，当continueChain为true时，会继续调用org.apache.shiro.web.servlet.AdviceFilter#executeChain方法（例如权限控制不通过时会返回false逻辑，此时会结束调用）,此时轮到FormAuthenticationFilter调用，同样的会进入类似的调用逻辑。

 同样的，当匹配成功后，会访问org.apache.shiro.web.filter.authc.FormAuthenticationFilter#onAccessDenied方法（也就是之前authc的配置）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f3eef6c9038dcb32373f08638c4b881436359b06.png)

 重复执行对应的filterChain后，最后会进入业务代码。

0x02 关键类
========

 前面简单描述了Apache Shiro接收到请求后的一个解析过程，其中还有一些关键类，这里简单的进行分析。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c6a1cd84f51abac53f82024ef6bb5e974d2bbf5d.png)

2.1 PathMatchingFilterChainResolver
-----------------------------------

 Shiro中对于URL的获取及匹配在`org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver#getChain`方法，

 其会根据URL路径匹配，解析出ServletRequest请求过程中要执行的过滤器链。以1.10.0版本为例，查看具体的解析过程：

 如果没有配置的话，返回null，使用原始默认的过滤器链逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3190a5a5e64fca16e1a832c9556c248c0f812257.png)

 否则会进入路由解析的逻辑。

 首先调用getPathWithinApplication方法获取应用程序内的URI的相对路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bdaf617ece487d334c43e0982fbf7d8da96a82c0.png)

 具体的实现如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3f98e725de59ebf36da38ca633fd5ee0ddea1e0d.png)

 首先通过request.getServletPath()+request.getPathInfo()方法获取URI，然后再调用removeSemicolon和normalize方法处理：

- removeSemicolon方法

 ASCII码59对应的是`;`，这个方法主要是判断url 中是否有分号，有的话会截取分号前的url并返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2c03b3a950537c4667edd4523310496ee6655a3c.png)

- normalize方法

 首先根据replaceBackSlash的值，判断是否需要将正斜杠`\`处理成反斜杠`/`，如果路径是`/.`直接返回`/`,否则判断路径是否以`/`开头，不是的话则在前面补全一个`/`。

```Java
public static String normalize(String path) {
    return normalize(path, Boolean.getBoolean("org.apache.shiro.web.ALLOW_BACKSLASH"));
}

private static String normalize(String path, boolean replaceBackSlash) {
    if (path == null) {
        return null;
    } else {
        String normalized = path;
        if (replaceBackSlash && path.indexOf(92) >= 0) {
            normalized = path.replace('\\', '/');
        }

        if (normalized.equals("/.")) {
            return "/";
        } else {
            if (!normalized.startsWith("/")) {
                normalized = "/" + normalized;
            }

            while(true) {
                int index = normalized.indexOf("//");
                if (index < 0) {
                    while(true) {
                        index = normalized.indexOf("/./");
                        if (index < 0) {
                            while(true) {
                                index = normalized.indexOf("/../");
                                if (index < 0) {
                                    return normalized;
                                }

                                if (index == 0) {
                                    return null;
                                }

                                int index2 = normalized.lastIndexOf(47, index - 1);
                                normalized = normalized.substring(0, index2) + normalized.substring(index + 3);
                            }
                        }

                        normalized = normalized.substring(0, index) + normalized.substring(index + 2);
                    }
                }

                normalized = normalized.substring(0, index) + normalized.substring(index + 1);
            }
        }
    }
}
```

再往下就是对路径进行格式化处理，主要是以下几个措施：

- 双反斜杠处理成反斜杠(// -&gt; /)
- 归一化处理/./（/./ -&gt; /）
- 处理路径跳跃（/a/../b -&gt; /b）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8ebf9310f2fe7f203c827be111b46c06adfe9b42.png)

 处理完后getPathWithinApplication方法调用结束，此时回到getChain方法，继续调用removeTrailingSlash方法对返回的requestURI进行处理，这里主要是删除路径最后的斜杠：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-20a14c8042d95e67673b60aea143076f0e70316f.png)

 再往下会遍历filterChains，requestURI和pattern匹配的话会代理到 filterChainManager.proxy方法里去，**如果不能匹配，会删除最后的"/" 再匹配一次**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-84c3ad19f0c788a49dd3a491085e7e28d5cf2928.png)

 通过调试可以看到，这里使用的PatternMatcher默认是AntPathMatcher，也就是说shiro默认是使用AntPath模式进行匹配的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8a6bfbe9e8e5a5f8610b95429c6d90e60141dbad.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6124052fddd49d1e99e4c8b66bea8208b1788bc2.png)

 这部分处理uri的逻辑在整个Apache Shiro的漏洞维护历史中，变动是最大的，包括上面提到的归一化，匹配最后一个`/`很多措施都是为了漏洞修复新增的。

### 2.1.1 其他

 在执行完Shiro对应的Filterchain后，会调用业务逻辑，也就是spring web路由解析的部分。

 在Spring Framework中,在Controller里以下两个路由访问是等价的：

```Java
@GetMapping("/admin/page")
@GetMapping("admin/page")
```

 主要原因是因为不论是AntPathMatcher还是高版本的PathPattern都会对当前的Pattern进行补全（如果不是以`/`开头的话会在前面补全这个`/`）：

- AntPathMatcher

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a56ae2f8b9a452d0a515d6c409ddcb6e438d511c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-318e0792b34a53b0b32fe283c97c5fea3fbc3386.png)

- PathPattern

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5587e954bcd2a2e9329f93da7d0e42d53a80fcaa.png)

 假设设置对应的url和过滤器匹配规则如下：

```Java
map.put("admin/page", "authc");
```

 按照前面的理解，按道理是能对以下Controller进行防护的：

```Java
@GetMapping("admin/page")
public String admin() {
    return "admin page";
}
```

 实际上这个配置并不会生效，还是可以访问到对应的Controller：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2e8462293029e4a48905c5e953a5b38464d56b85.png)

 同样以1.10.0版本的shiro为例，查看具体的原因：  
根据前面的分析，在解析时会调用org.apache.shiro.web.servlet.AbstractShiroFilter#getExecutionChain创建FilterChain,这里调用的是org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver#getChain来获取其会根据URL路径匹配，解析出ServletRequest请求过程中要执行的过滤器链：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f746a16a4eb0c97c30790c05dbe7a51ad78886e8.png)

 首先调用getPathWithinApplication方法获取应用程序内的URI的相对路径，然后往下遍历filterChains，requestURI和pattern匹配的话会代理到 filterChainManager.proxy方法里去，如果不能匹配，会删除最后的"/" 再匹配一次：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8bc4a2ced5ea3a9e4af6f39c0d322e4ef3c5b888.png)

 shiro使用的是AntPathMatcher进行匹配的，如果请求的path和pattern没有以/，就不再进行匹配了，**与Spring不同的是，shiro在匹配前并不会对pattern进行检查，补全开头的/**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-dd2856caea96510491c00f8282e3ead9697cbf06.png)

 这里会导致前面的对于`admin/page`配置失效，可以看到filterChain仅仅返回了InvalidRequestFilter，并没有返回authc对应的Filter（权限控制失效）:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3638c722bb337784e87ef80a800f12f921e1410b.png)

所以在使用Apache Shiro配置URI层面的权限时，一定要注意对应的规则需要以`/`开头。

2.2 AntPathMatcher
------------------

 以1.10.0版本为例：

 根据前面的分析可以知道，具体的匹配是在org.apache.shiro.util.AntPathMatcher#matches方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cb825e9e5262fe73c822e3d4f7096f32d6ba0520.png)

 实际调用的是doMatch方法，首先调用tokenizeToStringArray()方法分别将pattern和path分割成了String数组:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f8174c7e0f87bb5061d833936e4b46c54cb608ae.png)

 查看tokenizeToStringArray()的具体实现，这里其实**跟spring的实现是类似的**，同样是通过java.util 里面的StringTokenizer来处理字符串，同样的也存在属性trimTokens（判断是否需要消除path中的空格）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fe02c155ccd3765c708c6704648d17dcd81155d1.png)

### 2.2.1 其他

 由于 1.11.0 及之前版本的 Shiro 只兼容 Spring 的ant-style路径匹配模式（pattern matching），且 2.6 及之后版本的 Spring Boot 将 Spring MVC 处理请求的路径匹配模式从AntPathMatcher更改为了PathPatternParser，当 1.11.0 及之前版本的 Apache Shiro 和 2.6 及之后版本的 Spring Boot 使用不同的路径匹配模式时，攻击者访问可绕过 Shiro 的身份验证。

 对比下shiro1.11.0跟1.10.1的改动，可以发现主要是通过Spring动态的读取文件留下的扩展接口来将路径匹配模式修改为 AntPathMatcher ：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0b7832e21591a6f84853d432d03feab2edff6066.png)

 此外，trimTokens属性在不同版本也存在差异。  
 在1.7.1版本之前，该属性被设置为true。从1.7.1版本开始，该属性默认设置为false:  
 <https://github.com/apache/shiro/commit/0842c27fa72d0da5de0c5723a66d402fe20903df>

- shiro-core-1.7.0

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2c73c9d94b16014a3b20a95b62c86c0a7ca0def8.png)

- shiro-core-1.7.1

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-51fb62b7a5b3b493aa1f9f9c403661736cc045cf.png)

2.3 ShiroUrlPathHelper
----------------------

 在Spring web中，org.springframework.web.servlet.handler.AbstractHandlerMapping#initLookupPath方法中，主要用于初始化请求映射的路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-6635a79f76a8a12a8ca9b583b94151cfa2ae4c4d.png)

 这里有两个逻辑，主要跟Spring的匹配模式有关。当使用的是PathPattern时，this.usesPathPatterns()返回true，否则走else的逻辑，在shiro1.11.0以后，shiro会通过Spring动态的读取文件留下的扩展接口强制将路径匹配模式修改为 AntPathMatcher ，会走else的逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-34c145b1a779fbbacd41da9597afb18031ec0e35.png)

 这里正常来说会调用org.springframework.web.util.UrlPathHelper#getPathWithinApplication方法。

 但是**为了保持Spring和Shiro两者逻辑一致，会通过ShiroRequestMappingConfig 类将RequestMappingHandlerMapping#urlPathHelper 设置为 ShiroUrlPathHelper**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-96d0a90a72747d7c9c1fd08eb2d671dc727528ad.png)

 此时调用的是org.apache.shiro.spring.web.ShiroUrlPathHelper重写的getPathWithinApplication方法，此时Spring 匹配 handler 时获取路径的逻辑就会使用 Shiro 提供的逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-23566ef0003002716699179401deab026dd3c589.png)

 具体调用的是org.apache.shiro.web.util.WebUtils#getPathWithinApplication，主要是获取ServletPath和PathInfo后再调用removeSemicolon和normalize方法处理（这里跟PathMatchingFilterChainResolver的逻辑是一样的）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-aa81b2ece8a757c7aad813dfb7e156b19627b7a0.png)

 PS:这里有一点要注意的是，**在1.11.0版本之前，Apache Shiro并没有强制Spring将路径匹配模式修改为 AntPathMatcher。当高版本Spring使用PathPattern进行解析时，并不会调用ShiroUrlPathHelper的逻辑。而是会调用Spring自身的UrlPathHelper的defaultInstance对象进行处理**。

2.4 InvalidRequestFilter过滤器
---------------------------

 **从shiro1.6开始，新增了一个InvalidRequestFilter的过滤器，用于拦截存在安全问题的uri并返回400状态码。**

 在org.apache.shiro.spring.web.ShiroFilterFactoryBean#createFilterChainManager中，设置了一个GlobalFilters，这个Filter就是InvalidRequestFilter：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cf46a505ed88921a548aba60949e94bf6941f02e.png)

 同时配置`/**`，说明每一个URL请求都会经过这个过滤器：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b31e44af85f8ba9fc8e9519cf86ff4463fddf7b6.png)

 查看过滤器具体实现的功能,核心方法是isAccessAllowed，这里对一些特殊的内容进行了拦截：

```Java
protected boolean isAccessAllowed(ServletRequest req, ServletResponse response, Object mappedValue) throws Exception {
    HttpServletRequest request = WebUtils.toHttp(req);
    return this.isValid(request.getRequestURI()) && this.isValid(request.getServletPath()) && this.isValid(request.getPathInfo());
}
```

 主要是在isValid方法判断的：

```Java
private boolean isValid(String uri) {
    return !StringUtils.hasText(uri) || !this.containsSemicolon(uri) && !this.containsBackslash(uri) && !this.containsNonAsciiCharacters(uri);
}
```

- hasText

 判断uri是否非null或者是空白字符：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-660ea38f64ece19977401e80040da9e8302c24c6.png)

- containsSemicolon

 判断是否包含引号：

```Java
private static final List<String> SEMICOLON = Collections.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1aadeeda67d8fdd9f5d3cce6a009682956cf724f.png)

- containsBackslash

 判断是否包含反斜杠：

```Java
private static final List<String> BACKSLASH = Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b5b89d1c1e2913e916319a84d36dbfc15eb7210d.png)

- containsNonAsciiCharacters

 判断是否包含非Ascii 字符：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c4a5c99aca1e5b8a7d845d1890f9e4eacb036b19.png)

 可以看到，相比SpringSecurity，Apache Shiro的拦截会更"宽容"一些。