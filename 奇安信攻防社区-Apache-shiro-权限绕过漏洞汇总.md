0x01 简述
-------

前段时间太忙了，忙到很多东西，只是记录了笔记，没有成文，刚好最近阶段又出来了shiro权限绕过漏洞，因此本文将这三个权限绕过的洞进行对比，他们的编号分别是 **CVE-2020-1957、CVE-2020-11989、CVE-2020-13933** 。

0x02 漏洞细节
---------

### 1、CVE-2020-1957

#### 原理

![image-20200820101437933](https://shs3.b.qianxin.com/butian_public/fb2b609d0126bb187ca6a31333857465f.jpg)

首先在 **admin** 位置下断点，可以看到，我们网络请求，是先经过 **shiro** 处理之后，再转发到 **springboot** 进行路由分发工作。

![image-20200820101934974](https://shs3.b.qianxin.com/butian_public/ff02996418c79d00ae226b53cbf18d247.jpg)

这里直接定位到 **shiro** 处理 **url** 的方法位置：**WebUtils#getPathWithinApplication**

```java
    public static String getPathWithinApplication(HttpServletRequest request) {
        String contextPath = getContextPath(request);
        String requestUri = getRequestUri(request);
        if (StringUtils.startsWithIgnoreCase(requestUri, contextPath)) {
            // Normal case: URI contains context path.
            String path = requestUri.substring(contextPath.length());
            return (StringUtils.hasText(path) ? path : "/");
        } else {
            // Special case: rather unusual.
            return requestUri;
        }
    }
```

实际上继续跟进 **getRequestUri(request);** 这个方法，可以清楚的看到，实际上调用的是 **getRequestURI** 方法来获取路由中的 **URI** 请求。

![image-20200820102636599](https://shs3.b.qianxin.com/butian_public/fb8416a6a58779ad9724ec2156accf0d4.jpg)

这里的 **URI** 就是我们传入的`/xxx/..;/hello/aaaa`，也就是说回到 **getRequestUri(request);** 当中，会带着这个传入的 **URI** 进入 **decodeAndCleanUriString** 进行处理。

```java
    public static String getRequestUri(HttpServletRequest request) {
        String uri = (String) request.getAttribute(INCLUDE_REQUEST_URI_ATTRIBUTE);
        if (uri == null) {
            uri = request.getRequestURI();
        }
        return normalize(decodeAndCleanUriString(request, uri));
    }
```

在 **decodeAndCleanUriString** 方法中会根据我们的传入的URI中`;`进行截断处理，也就是说经过处理之后，返回的结果变成了`/xxx/..`

![image-20200820103100527](https://shs3.b.qianxin.com/butian_public/fdf4645dc67c561b24daa787ced4c67aa.jpg)

而 **normalize** 方法就会对我们传入的path进行一些处理，从注释上，也能知道这部分代码处理了什么东西:

- 替换`\\`为`/`
- 替换`/./`为`/`
- 替换`/../`为`/`
- ...

```java
    private static String normalize(String path, boolean replaceBackSlash) {

        if (path == null)
            return null;

        // Create a place for the normalized path
        String normalized = path;

        if (replaceBackSlash && normalized.indexOf('\\') >= 0)
            normalized = normalized.replace('\\', '/');

        if (normalized.equals("/."))
            return "/";

        // Add a leading "/" if necessary
        if (!normalized.startsWith("/"))
            normalized = "/" + normalized;

        // Resolve occurrences of "//" in the normalized path
        while (true) {
            int index = normalized.indexOf("//");
            if (index < 0)
                break;
            normalized = normalized.substring(0, index) +
                    normalized.substring(index + 1);
        }

        // Resolve occurrences of "/./" in the normalized path
        while (true) {
            int index = normalized.indexOf("/./");
            if (index < 0)
                break;
            normalized = normalized.substring(0, index) +
                    normalized.substring(index + 2);
        }

        // Resolve occurrences of "/../" in the normalized path
        while (true) {
            int index = normalized.indexOf("/../");
            if (index < 0)
                break;
            if (index == 0)
                return (null);  // Trying to go outside our context
            int index2 = normalized.lastIndexOf('/', index - 1);
            normalized = normalized.substring(0, index2) +
                    normalized.substring(index + 3);
        }

        // Return the normalized path that we have completed
        return (normalized);

    }
```

而这里经过处理，我们的 **URI** 依然是`/xxx/..`，接着就会回到 **PathMatchingFilterChainResolver#getChain** 方法，进行权限匹配，我们的路径是`/hello/**`下需要进行权限认证，由于路径不匹配，所以权限校验自然过了。

![image-20200820103933492](https://shs3.b.qianxin.com/butian_public/fad59af2285d214e07ce05f6a5c9d34e8.jpg)

这里在提一嘴，可以看看 **PathMatchingFilterChainResolver#getChain** 方法这一小段代码，这一段代码修复的是 [**Shiro-682**](https://issues.apache.org/jira/browse/SHIRO-682) ，具体描述可以点入链接查看。简单翻译一下就是在 **spring web** 下，通过请求 **/resource/menus** 和 **/resource/menus/** 都是能够访问到资源的，但是shiro的路径正则只会匹配到 **/resource/menus** ，忽略了 **/resource/menus/** ，所以这就绕过了。

![image-20200820104119806](https://shs3.b.qianxin.com/butian_public/f4698648da0141d22a743e2a3bab911ea.jpg)

![image-20200820104751691](https://shs3.b.qianxin.com/butian_public/fc87eb08558f70b8e4263c07e320d652c.jpg)

好了，这里提一下这个地方，再回到我们刚刚上面的情况里，由于我们传入的 **URI** `/xxx/..`与权限认证的 **URI** `/hello/**`不匹配，绕过了权限验证之后，进入 **springboot** 当中进行路由分发，而在 **spring** 当中 **UrlPathHelper#getPathWithinServletMapping** 这个方法负责处理我们传入的 **URI** ：`xxx/..;/hello/aaaa`，结果是返回 **servletPath** 。

```java
    public String getPathWithinServletMapping(HttpServletRequest request) {
        String pathWithinApp = getPathWithinApplication(request);
        String servletPath = getServletPath(request);
        String sanitizedPathWithinApp = getSanitizedPath(pathWithinApp);
        String path;

        // If the app container sanitized the servletPath, check against the sanitized version
        if (servletPath.contains(sanitizedPathWithinApp)) {
            path = getRemainingPath(sanitizedPathWithinApp, servletPath, false);
        }
        else {
            path = getRemainingPath(pathWithinApp, servletPath, false);
        }
...
            // Otherwise, use the full servlet path.
            return servletPath;
        }
    }
```

看看 **servletPath** 是怎么来的，这玩意的取值是通过`request.getServletPath();`获取到的，也就是说这里的结果是`/hello/aaaa`。这里通过 **springboot** 进行分发，自然获取到后台接口内容，整个流程：

用户发起请求`/xxx/..;/hello/aaaa`-----&gt;shiro处理之后返回`/xxx/..`通过校验的-----&gt;springboot处理`/xxx/..;/hello/aaaa`返回`/hello/aaaa`，最后访问到需要权限校验的资源。

```java
    public String getServletPath(HttpServletRequest request) {
        String servletPath = (String) request.getAttribute(WebUtils.INCLUDE_SERVLET_PATH_ATTRIBUTE);
        if (servletPath == null) {
            servletPath = request.getServletPath();
        }
        if (servletPath.length() > 1 && servletPath.endsWith("/") && shouldRemoveTrailingServletPathSlash(request)) {
            // On WebSphere, in non-compliant mode, for a "/foo/" case that would be "/foo"
            // on all other servlet containers: removing trailing slash, proceeding with
            // that remaining slash as final lookup path...
            servletPath = servletPath.substring(0, servletPath.length() - 1);
        }
        return servletPath;
    }
```

![image-20200820110012236](https://shs3.b.qianxin.com/butian_public/f3f5dbac0e8eb1b8906da2bb34a2c8176.jpg)

#### 修复

shiro在1.5.2当中把之前的通过 **getRequestURI** 获取URI的方式变成了 **getContextPath()** 、**getServletPath()** 、**getPathInfo()** 的组合。

![image-20200820110753526](https://shs3.b.qianxin.com/butian_public/fa245fd1c8232e5028c78629932b16224.jpg)

这么处理之后自然变成了想要的东西。

![image-20200820111056759](https://shs3.b.qianxin.com/butian_public/ff48dfbc830ae92661c395d220d577090.jpg)

### 2、CVE-2020-11989

#### 原理

这里的 **shiro** 拦截器需要变成`map.put("/hello/*", "authc");`，这里有两种poc，都是可以绕过

```php
/hello/a%25%32%66a
/;/test/hello/aaa
```

我们知道在shiro中的`WebUtils#getPathWithinApplication`这里会处理我们传入的url，在 **getRequestUri** 方法会调用 **decodeAndCleanUriString** 进行处理。

```java
    public static String getRequestUri(HttpServletRequest request) {
        String uri = (String) request.getAttribute(INCLUDE_REQUEST_URI_ATTRIBUTE);
        if (uri == null) {
            uri = valueOrEmpty(request.getContextPath()) + "/" +
                  valueOrEmpty(request.getServletPath()) +
                  valueOrEmpty(request.getPathInfo());
        }
        return normalize(decodeAndCleanUriString(request, uri));
    }
```

在 **decodeAndCleanUriString** 当中会调用 **decodeRequestString** 针对 **URI** 进行一次 **URL** 解码。

```java
    private static String decodeAndCleanUriString(HttpServletRequest request, String uri) {
        uri = decodeRequestString(request, uri);
        int semicolonIndex = uri.indexOf(';');
        return (semicolonIndex != -1 ? uri.substring(0, semicolonIndex) : uri);
    }

    public static String decodeRequestString(HttpServletRequest request, String source) {
        String enc = determineEncoding(request);
        try {
            return URLDecoder.decode(source, enc);
        } catch (UnsupportedEncodingException ex) {
            if (log.isWarnEnabled()) {
              ...
            }
            return URLDecoder.decode(source);
        }
    }
```

所以这里的poc`/hello/a%25%32%66a`------&gt;传入到shiro自动解码一次变成`//hello/a%2fa`------&gt;经过 **decodeRequestString** 变成`//hello/a/a`

由于这里我们的拦截器是`map.put("/hello/*", "authc");`，这里需要了解一下shiro的URL是ant格式，路径是支持通配符表示的

```php
?：匹配一个字符
*：匹配零个或多个字符串
**：匹配路径中的零个或多个路径
```

`/*`只能命中`/hello/aaa`这种格式，无法命中`/hello/a/a`，所以经过 **shiro** 进行权限判断的时候自然无法命中。

![image-20200820141527676](https://shs3.b.qianxin.com/butian_public/f9fd7424f672a0569cf0ce49973ac2bba.jpg)

而在spring当中，理解的 **servletPath** 是`/hello/a%2fa`，所以自然命中`@GetMapping("/hello/{name}")`这个mapping，又springboot转发到响应的路由当中。

![image-20200820142018660](https://shs3.b.qianxin.com/butian_public/f5a7378ba0393c1ff37ee0b95f7126b57.jpg)

另一种利用方式来自这里[《Apache Shiro权限绕过漏洞分析(CVE-2020-11989)》](https://xz.aliyun.com/t/7964)，这里提到了

> 1. 应用不能部署在根目录，也就是需要context-path，server.servlet.context-path=/test，如果为根目录则context-path为空，就会被CVE-2020-1957的patch将URL格式化，值得注意的是若Shiro版本小于1.5.2的话那么该条件就不需要。

![image-20200820142409270](https://shs3.b.qianxin.com/butian_public/fb19ab5b75c3ee98db36a397e0c469f25.jpg)

这里原因在于需要绕过 **getRequestUri** 当中的格式化uri，当 **context-path** 为空的时候，处理结果为`//hello/aaaa`

```java
    public static String getRequestUri(HttpServletRequest request) {
        String uri = (String) request.getAttribute(INCLUDE_REQUEST_URI_ATTRIBUTE);
        if (uri == null) {
            uri = valueOrEmpty(request.getContextPath()) + "/" +
                  valueOrEmpty(request.getServletPath()) +
                  valueOrEmpty(request.getPathInfo());
        }
        return normalize(decodeAndCleanUriString(request, uri));
    }
```

![image-20200820143100885](https://shs3.b.qianxin.com/butian_public/f9df82e3a76b6e52d3c187ee567f742f7.jpg)

当 **context-path** 不为空的时候，处理结果为`/;/test/hello/aaaa`，然后我们知道 **decodeAndCleanUriString** 会根据`;`进行截断，截断之后的结果是`/`自然无法命中拦截器`map.put("/hello/*", "authc");`，所以自然就绕过了。

![image-20200820143233049](https://shs3.b.qianxin.com/butian_public/ffd1734bea479f4da6c81286a64ec9966.jpg)

![image-20200820143405442](https://shs3.b.qianxin.com/butian_public/fc93ee63cd1391a8eaa33bba2ae8d5700.jpg)

#### 修复

在1.5.3版本，采用标准的 **getServletPath** 和 **getPathInfo** 进行uri处理，同时取消了url解码。

```php
    public static String getPathWithinApplication(HttpServletRequest request) {
        return normalize(removeSemicolon(getServletPath(request) + getPathInfo(request)));
    }
```

![image-20200820144001692](https://shs3.b.qianxin.com/butian_public/fd018ce02481fed8d2ae36556a5be813e.jpg)

### 3、CVE-2020-13933

#### 原理

```php
/hello/%3baaaa
```

上面的代码进来之后，通过 **getPathWithinApplication** 处理之后变成了`/hello/;aaaa`

![image-20200820144306530](https://shs3.b.qianxin.com/butian_public/f91e4e860d8f2fb57a66feb831c4566a5.jpg)

而 **removeSemicolon** 会根据`;`进行截断，返回的 **uri** 自然是`/hello/`

```java
    private static String removeSemicolon(String uri) {
        int semicolonIndex = uri.indexOf(';');
        return (semicolonIndex != -1 ? uri.substring(0, semicolonIndex) : uri);
    }
```

这个 **uri** 自然无法命中拦截器`map.put("/hello/*", "authc");`自然就过了

![image-20200820144624875](https://shs3.b.qianxin.com/butian_public/f29dea7592f5b3cccfce0b131659258b4.jpg)

#### 修复

加了一个 **filter** 类 **InvalidRequestFilter** 来针对一些东西进行处理。

```java
    private static final List<String> SEMICOLON = Collections.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));

    private static final List<String> BACKSLASH = Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));
```

![image-20200820145810599](https://shs3.b.qianxin.com/butian_public/fd89a66028d199c018fba4f3b573ff197.jpg)

0x03 小结
-------

总结来看，就是利用 **shiro** 解析 **uri** 和 **spring** 解析 **uri** 之间的差异来挖这个洞。