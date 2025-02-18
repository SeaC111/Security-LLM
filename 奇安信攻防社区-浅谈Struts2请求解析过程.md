0x00前言
======

 在使用Struts2的时候需要在web.xml中配置一个过滤器，来拦截用户发起的请求，并进行一些预处理，根据配置文件把请求分配给对应的action并将请求中的参数与action中的字段进行对应赋值。例如下面的例子，通过配置StrutsPrepareAndExecuteFilter过滤器对 Struts2所有的请求进行处理：

```XML
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>struts2</filter-name>
        <filter-class>org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>struts2</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>
```

 StrutsPrepareAndExecuteFilter是一个Servlet过滤器，它是Struts 2框架的核心组件之一。它起到了连接Servlet容器和Struts 2框架的桥梁作用。它负责拦截请求，将请求交给框架处理，并将处理结果返回给Servlet容器，从而完成整个请求-响应周期。

0x01 Struts2请求解析过程
==================

 从StrutsPrepareAndExecuteFilter出发，查看具体的解析过程。

1.1 关键解析类
---------

### 1.1.1 StrutsPrepareAndExecuteFilter

 以struts2-core-2.5.25为例，查看StrutsPrepareAndExecuteFilter具体的工作流程：

 可以看到其实现了Filter接口，而在过滤器中，doFilter方法是实际处理请求的核心方法。它被用于处理进入过滤器的请求，并在需要的情况下对请求进行修改或拦截，查看具体的实现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-cfd12cfd84c0f693ebd1e872adefffc846b20cbc.png)

 在doFilter中，首先获取到了HttpServletRequest和HttpServletResponse对象，以便后续对请求和响应进行处理，这里通过调用org.apache.struts2.RequestUtils#getUri获取当前请求的uri，主要是用于日志输出的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-653429a752cf0729bed4dad024332d11fa1bb77d.png)

 然后会检查是否有排除的URL模式，并且请求是否被排除在Struts的处理范围之外。如果是排除的URL，日志记录一条消息，并将请求传递给Filter链中的下一个Filter进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c59a3b0c1cb08b9fa80fe1d920af077713187c71.png)

 如果请求不是排除的URL，代码检查请求的URI是否是一个静态资源。如果是静态资源，将执行相应的处理，并将handled标记设置为true：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-9c1c74ca972ecd1fc17120efab3b500ca1930300.png)

 判断逻辑主要如下，首先通过HttpServletRequest对象获取到资源路径（resourcePath）。如果资源路径为空字符串，并且request.getPathInfo()不为空，则将resourcePath设置为request.getPathInfo()，然后获取StaticContentLoader实例（它是Struts2容器的一个组件，用于加载和处理静态资源）。检查StaticContentLoader是否能够处理给定的资源路径（resourcePath）。如果能够处理，调用staticResourceLoader的findStaticResource方法查找并响应静态资源，并返回true。如果StaticContentLoader无法处理资源路径，返回false：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-e38a3eac60df4b9b3b7867a899c0f4fbcc164b4c.png)

 如果请求不是静态资源，代码将进行更进一步的处理。首先，设置请求的编码和区域设置，并创建ActionContext。然后，为当前线程分配一个Dispatcher。接着，对请求进行包装和准备操作。之后，查找请求的ActionMapping，如果找不到Mapping，则将请求传递给Filter链中的下一个Filter。如果找到了Mapping，则执行对应的Action：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-16ab9de82d114ee509c97068d29179bd3ea5cb4c.png)

最后，无论是否找到Mapping，都会执行请求的清理操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-6692bfb498e1691dc813ebb5d83cd4c087ce148a.png)

 以上是StrutsPrepareAndExecuteFilter的处理流程，主要时根据请求的URI和Struts的配置，判断请求是静态资源还是需要执行相应的Action，并对请求进行处理。也是Struts框架中请求处理的核心部分。

### 1.1.2 RequestUtils

 在查找请求对应的ActionMapping进行处理时，主要是获取该URI匹配的ActionMapping配置，而请求的URI主要是在用org.apache.struts2.RequestUtils#getUri获取的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-1a958b3d68942c235ed619f6d78bfbbbf466266d.png)

 查看org.apache.struts2.RequestUtils#getUri的具体实现：

 首先，尝试从request对象的属性中获取`javax.servlet.include.servlet_path`属性值作为URI路径，如果uri不为null，则直接返回该uri：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-bfb345fc849436b43379fe339880de8531650398.png)

 如果uri为null，则调用getServletPath方法获取请求的servlet路径（uri）。非空字符串则直接返回，否则调用request.getRequestURI()方法获取完整的请求URI路径，然后通过截取字符串的方式，去除请求的上下文路径（request.getContextPath().length()），得到相对于上下文路径的URI路径并返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-0046a6cdf657ecff31f5f29ef9f949f7f4934a98.png)

 查看org.apache.struts2.RequestUtils#getServletPath的具体实现：

 首先，通过request.getServletPath()和request.getRequestURI()方法获取对应的路径信息。然后进行一系列判断和处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-7b3f1c93e93a2730592d66c7bbec497c2c91c6a4.png)

 若requestUri不以servletPath结尾，说明servlet路径与请求URI路径不完全匹配。此时，通过查找servletPath在requestUri中的起始位置，截取出匹配的部分作为新的servlet路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-a3acedadc01c9c5ae100449636e22d2d77ee1d9e.png)

 经过上述处理后，若servletPath不为空，则直接返回该servletPath，否则进行进一步处理。首先，确定startIndex为请求上下文路径（request.getContextPath()）的长度。然后，根据request.getPathInfo()是否为null，确定endIndex的值。最后，通过截取字符串的方式，从requestUri中获取相对于上下文路径的servlet路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-fd6d408ca2d1f6dd3912742683cce4ae9f7f39f5.png)

1.2 关键流程
--------

### 1.2.1 寻找ActionMapping

 在StrutsPrepareAndExecuteFilter中，如果请求不是静态资源，会对请求进行包装和准备操作。并查找请求对应的ActionMapping进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-8c3c92872cf61d7ac2ea8eb95062abdba1656f1c.png)

 核心解析是在org.apache.struts2.dispatcher.PrepareOperations#findActionMapping中进行的，首先尝试在请求中查找对应的ActionMapping对象，如果找到了缓存的对象则直接返回，否则通过ActionMapper来获取，并将获取到的对象进行缓存。这样可以避免多次查找ActionMapping对象，提高性能：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-2af3a90ccdff296391b35b05eb08ba42c795a0de.png)

 通过ActionMapper来获取时，主要是调用org.apache.struts2.dispatcher.mapper.DefaultActionMapper#getMapping方法进行处理。查看具体的处理过程。

 首先，会创建一个ActionMapping对象，用于保存请求对应的Action的相关信息，然后通过RequestUtils.getUri(request)方法获取请求的URI路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-0aeae1b7fbdfccd78e8a71aeeb7272e549e71d5e.png)

 然后会对获取到的URI路径进行一定的处理，若URI路径中包含分号的索引，说明URI路径中包含附加信息，需要将其截取掉，只保留分号之前的部分。然后调用dropExtension方法，将URI路径中的扩展名部分去除，得到最终的URI路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-153a0d410ed3faa7bc01b3137a5d8c6289175369.png)

 经过上述处理后，若最终的URI路径为null，表示未找到对应的Action并返回null。

 如果最终的URI路径不为null，继续执行以下操作：

- 调用parseNameAndNamespace方法，解析URI路径中的名称和命名空间，并将解析结果保存到ActionMapping对象中
- 调用handleSpecialParameters方法，处理特殊的请求参数，如路径参数等，并更新ActionMapping对象
- 调用parseActionName方法，解析Action名称，并更新ActionMapping对象

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-15911ab2de8fccf2a2159cbea971e20604caff25.png)

 最终返回封装后的ActionMapping对象。

### 1.2.2 缺省后缀

 默认情况下，如用户请求路径不带后缀或者后缀以.action结尾都是可以解析的。

 主要是在org/apache/struts2/default.properties配置文件定义的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-fd9ade8f26117f77507ef1c28e4f930e4f44f73b.png)

 在dropExtension方法处下断点进行映证，可以看到默认的后缀跟default.properties定义是一致的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-4dd3d122f29331eb06d43fd87c0159684104aada.png)

 也可以在struts.xml中添加常量`struts.action.extension`修改默认处理后缀：

```XML

```

### 1.2.3 parseNameAndNamespace解析

 **Struts2站点的URL路径主要由这三部分组成：namespace+Action+extension扩展**。如下图所示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-6c66d81738283f76901b7e53d500b89035f38167.png)

 在寻找ActionMapping时，会调用parseNameAndNamespace方法，解析URI路径中的名称和命名空间，找到对应的执行类。分析具体的解析过程。

 首先找到URI中最后一个斜杠的位置并赋值给lastSlash变量，如果没有斜杠，将namespace设为默认值（空字符串），name设为请求的URI：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-e7182b408fc19769559d5142386d2498f1d042e2.png)

 如果斜杠在第一个位置，将namespace设为根命名空间（"/"），name为斜杠之后的部分：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-86a7ab2040dece942531519eb41bf90c52f0f0e6.png)

 如果`alwaysSelectFullNamespace`为true，则该代码块将URI中的整个部分作为namespace，将斜杠后面的部分作为名称。这意味着无论URI中是否存在其他命名空间，都会将整个URI作为当前Action的命名空间：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-499c74371ef5302f9e1548b9f022325e7853322a.png)

 如果上述情况均不满足，则根据配置管理器的信息来确定命名空间，首先获取 configManager 中的配置对象 config。 然后通过 uri.substring(0, lastSlash) 将 uri 中的从开头到最后一个斜杠之前的部分提取为 prefix，通过迭代 config 中的所有package配置对象，获取每个package配置对象的namespace：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-ac283391b4a16d4e4f463d2be6c55cb3f201db76.png)

 在迭代过程中，通过判断 prefix 是否以 ns 开头，并且判断 prefix 的长度是否与 ns 的长度相等，或者判断 prefix 的 ns 长度后的下一个字符是否为斜杠，来确定是否将当前的 ns 设为当前的命名空间，同时，如果 ns 是根路径 `/`，则将 `rootAvailable` 设为true：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-a76d1929edc791c20a2d0f71e9e519c89edb7dd7.png)

 最后通过将uri的namespace部分去除获取name，如果rootAvailable为true且 namespace 为空字符串，则将 namespace 的值设置为根路径 /：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-f9927694ce2769461b3c567fc74ed02aa72cdc03.png)

 处理完后，根据配置的规则，会根据allowSlashesInActionNames属性对namespace和name的格式进行处理，以便能正确匹配Action配置。

 若allowSlashesInActionNames为false，会处理name中的斜杠。如果Action名称中存在斜杠，且斜杠不是名称的最后一个字符，则代码会将斜杠后面的部分作为新的name:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-b48f5cce617f745ee03af55d41b819c2895be52b.png)

 最后，将解析得到的命名空间和名称设置到ActionMapping对象中，整个匹配过程完成：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-ede052fcdf3104db7763818cb2b2d106d164f299.png)

1.3 其他
------

### 1.3.1 FilterDispatcher

 FilterDispatcher是struts2.0.x到2.1.2版本的核心过滤器，从2.1.3开始StrutsPrepareAndExecuteFilter就替代了FilterDispatcher：

```XML
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <filter>
        <filter-name>struts2</filter-name>
        <filter-class>org.apache.struts2.dispatcher.FilterDispatcher</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>struts2</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
</web-app>
```

 以struts2-core-2.2.3为例，查看FilterDispatcher具体的工作流程：

 同样实现了Filter接口，在doFilter中，同样的首先获取到了HttpServletRequest和HttpServletResponse对象，以便后续对请求和响应进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-2460db9b7c3dbc9692ddc434496f6b6948eea1d5.png)

 然后创建一个ValueStack对象，用于管理action和视图中使用的值并设置ActionContext并关联上述创建的ValueStack。将计时器键值推入UtilTimerStack中，方便测量执行时间。然后调用repareDispatcherAndWrapRequest方法对request请求进行必要的包装处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-10de14d7dfbdb18e3a1eaada42d4b2214c9ba17e.png)

 然后尝试获取请求对应的ActionMapping，这里逻辑是类似的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-6e497536da4489bfa5ea48bd5db3c9c4a6e2f733.png)

 如果找到了ActionMapping，则通过Dispatcher调用相应的方法来处理Action，如果没有找到ActionMapping，它会检查请求的资源是否是静态资源，并由staticResourceLoader处理。如果是静态资源，将找到并返回该资源，否则会将请求传递给过滤器链中的下一个过滤器进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-7792c77673286568ed84fa35b7e780f555443447.png)

 最后跟StrutsPrepareAndExecuteFilter一样，会执行请求的清理操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-b452279ae66e2e2af5c46c46e6cf14a645e41c26.png)

0x02 区分Spring与Struts2
=====================

 根据前面的分析，可以简单的通过下面的方法对Struts2和Spring进行区分，SpringWeb的解析过程可以参考https://forum.butian.net/share/2214 。

2.1 缺省后缀
--------

 Struts2在默认情况下，如用户请求路径不带后缀或者后缀以.action结尾都是可以解析的，而Spring没有类似的特性。

 可以看到默认情况下不带后缀或者后缀以.action结尾均可正常访问：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-d84a4f9f64e3be544d15461b33bcdb97b0b0cc88.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-1dd7adfc045b0432c65405c0e83197ad100042e2.png)

 但是Spring中的**SuffixPatternMatch**模式启用时能以 .xxx 结尾的方式进行匹配。例如/hello和/hello.do的匹配结果是一样的。

2.2 路径匹配容错机制
------------

 根据前面的分析，Struts2在获取namespace时逻辑如下：

 通过判断 prefix 是否以 ns 开头，并且判断 prefix 的长度是否与 ns 的长度相等，或者判断 prefix 的 ns 长度后的下一个字符是否为斜杠，来确定是否将当前的 ns 设为当前的命名空间，同时，如果 ns 是根路径 `/`，则将 `rootAvailable` 设为true：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-5b5b086e9f496210a8961f363d1392553496ec97.png)

 也就是说可以在对应的namespace后加入任意的目录，均可以找到对应的Action：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-7ce6733de76088a079ac407e0b6a9ef778ddd1bd.png)

 而Spring明显是没有对应的特性的。

2.3 路径规范化的区别
------------

 Struts2在解析时对类似`../`是进行了处理的,如果requestUri中不包含servletPath且request.getServletPath返回不为null的话会直接返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-5a46329d0ebe4189a760081b62bec58f8238a441.png)

 所以如下请求可以成功访问到对应的action:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-2d28f3699eeb88409fd37a5d1f3d164b001aa77e.png)

 当Spring Boot版本在小于等于2.3.0.RELEASE时，会对路径进行规范化处理，但是高版本的getPathWithinApplication是通过request.getRequestURI()方法获取当前request中的URI/URL，并不会对获取到的内容进行规范化处理。当请求路径中包括类似..的关键词时，调用getPathWithinApplication方法解析后，会因为没有处理跨目录的字符，导致找不到对应的Handler而返回404。

2.4 尾部/的区别
----------

 在Spring中，当启用后缀匹配模式时，例如/hello和/hello.do的匹配结果是一样的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-c468fca64c0ce693729c5be2ea2792a35b6c27f3.png)

 同样的，当使用PathPattern进行解析时，在最后会根据matchOptionalTrailingSeparator（此参数为true时，默认为true）进行一定的处理，如果Pattern尾部没有斜杠，请求路径有尾部斜杠也能成功匹配（类似TrailingSlashMatch的作用）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-d730f96071eb30893288258dbbf44a55daf62f9c.png)

 而相比Struts2，在获取ActionName的时候，并没有考虑尾部额外/的问题，所以当尝试追加/时，Struts2可能会因为找不到对应的Action返回404:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-2d260cbc926c46e563e2dfdcc70cec2d035a1bde.png)

2.5 Struts2特有的静态资源
------------------

 除此以外，在Struts2的jar包中包含很多特有静态文件，可以利用这一点进行判断，例如struts2-core-2.5.25:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-7ad8158c76e969322b0ff620b07f8cb2762a1f0d.png)

 那么可以尝试在URL的Web应用根目录下添加/struts/domTT.css，如果返回css代码，大概率是Struts2：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-174bfba7d9fbcfd9496da1717ef4a3d0a98b36a8.png)

 同样的，类似低版本的同样会有特定的文件，例如struts2-core-2.0.1:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-a1faa43d54744321f48b3e7d6de6ae27f5645400.png)