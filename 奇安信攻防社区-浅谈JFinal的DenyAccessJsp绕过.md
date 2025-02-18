0x00 前言
=======

任意文件上传产生的主要原因就是在服务器端没有对用户上传的文件类型做校验或者校验不充分，导致用户可以上传恶意脚本到服务器。最常见的就是上传恶意的jsp到web目录下，从而拿到系统权限。

JFinal 是基于Java 语言的极速 web 开发框架，在一些应用系统中也常常能看到它的身影。为了提升应用的安全性，**JFinal 较新的版本默认不能对** **`.jsp`** **文件直接进行访问，也就是在浏览器地址栏中无法输入** **`.jsp`** **文件名去访问 jsp 文件，但是可以通过 renderJsp(xxx.jsp) 来访问 jsp 文件**。

如果确实需要直接访问 jsp 文件，需要添加如下配置：

```Java
public void configConstant(Constants me) {
    me.setDenyAccessJsp(false);
}
```

 看看JFinal的具体实现，是怎么限制jsp文件的直接访问的。

0x01 DenyAccessJsp的具体实现
=======================

 以5.0.2版本为例:

```XML
<dependency>
    <groupId>com.jfinal</groupId>
    <artifactId>jfinal</artifactId>
    <version>5.0.2</version>
</dependency>
```

 首先启动JFinal后，会先调用对应的过滤器`com.jfinal.core.JFinalFilter`。首先是初始化方法init():

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1478e87d554eb54bf6bd1758bd7ca02b599227c5.png)

 首先是`createJFinalConfig()`,主要是通过反射处理web.xml中的配置信息。然后调用`jfinal.init(jfinalConfig, filterConfig.getServletContext());`，这里通过jfinal.init()初始化配置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2cec3e8cda951941da399db30af1a88fdda5e432.png)

 `Config.configJFinal(jfinalConfig)`会加载对应的配置信息，例如Constants主要是框架的一些常量，Routes是路由信息，Plugins应该是JFinal的插件等。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8c5381f96db30165faa6dda1181b980cf5d6fe89.png)

 查看Constants的具体信息可以看到，denyAccessJsp默认为true，默认是拒绝直接访问jsp文件的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5895e7a72e123497cca6e10f0bbbed7de0d7f7cb.png)

 当然也可以修改，可以创建一个继承自JFinalConfig类的子类，用于对整个web项目进行配置：

```Java
public class DemoConfig extends JFinalConfig {
    public void configConstant(Constants me) {}
    public void configRoute(Routes me) {}
    public void configEngine(Engine me) {}
    public void configPlugin(Plugins me) {}
    public void configInterceptor(Interceptors me) {}
    public void configHandler(Handlers me) {}
}
```

 例如想允许JSP直接访问的话，只需做如下配置即可：

```Java
public void configConstant(Constants me) {    
    // 配置是否拒绝访问 JSP，是指直接访问 .jsp 文件，与 renderJsp(xxx.jsp) 无关
    me.setDenyAccessJsp(false); 
}
```

 在JFinal.init()执行完后，获取项目上下文的路径以及编码方法，然后开始接受请求。然后就是过滤器的核心方法doFilter():

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-891a041e20dbc720a1c9a59295e215641a1b19a6.png)

 在doFilter()可以看到，这里结合上面constants的配置（默认是true），结合isJsp()方法对访问JSP文件的请求进行处理，自动跳转到Error404页面，例如下图的效果：

```Java
// 默认拒绝直接访问 jsp 文件，加固 tomcat、jetty 安全性
if (constants.getDenyAccessJsp() && isJsp(target)) {
   com.jfinal.kit.HandlerKit.renderError404(request, response, isHandled);
   return ;
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1ef223155bb41c9b6735a835b498f3b134431f42.png)

 前面已经分析过了，`constants.getDenyAccessJsp()`默认为true，查看isJsp()的具体实现：

 该方法主要是判断访问的是否是jsp文件，通过切割字符串，首先判断是否为X或P结尾，然后逐次往上寻找是否是S和J，整个过程考虑了大小写以及jsp/jspx的情况。

```Java
boolean isJsp(String t) {
   char c;
   int end = t.length() - 1;

   if ( (end > 3) && ((c = t.charAt(end)) == 'x' || c == 'X') ) {
      end--;
   }

   if ( (end > 2) && ((c = t.charAt(end)) == 'p' || c == 'P') ) {
      end--;
      if ( (end > 1) && ((c = t.charAt(end)) == 's' || c == 'S') ) {
         end--;
         if ( (end > 0) && ((c = t.charAt(end)) == 'j' || c == 'J') ) {
            end--;
            if ( (end > -1) && ((c = t.charAt(end)) == '.') ) {
               return true;
            }
         }
      }
   }

   return false;
}
```

 到这里大概就解释了为什么**JFinal 较新的版本默认不能对`.jsp`文件直接进行访问**了。

0x02 绕过思路
=========

 从上面的分析可以看到，**isJsp()的处理的内容是`String target = request.getRequestURI();`**

- request.getRequestURI()方法会返回除去Host（域名或IP）部分的路径。

 因为request.getRequestURI()方法不会对请求的path做过多的处理，这里做一个猜想，那么当请求路径中包含例如`jsp;`特殊字符时，isJsp()方法便会返回false，`JFinalFilter`会认为该资源不是一个JSP文件，从而绕过访问限制。那么如果类似Tomcat/jetty这类中间件在解析jsp资源时，若能识别类似`jsp;`后缀的资源并成功编译解析的话，就可以绕过DenyAccessJsp的机制了。以常见的中间件Tomcat为例，看看具体解析JSP的过程：

Tomcat解析JSP的过程
--------------

 当请求到达时，如果没有匹配到tomcat web.xml定义的servlet时，会经过DefaultServlet/JspServlet这两个servlet进行处理：  
 其中DefaultServlet主要用于处理静态资源如HTML、图片、CSS以及JS文件等，顾名思义，JspServlet主要用于处理jsp/jspx的请求。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e58b6468a5ec52515489d5b172cb5cedf701adc7.png)

 主要是调用JspServlet的service方法处理，这里会获取当前请求的Jsp路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-622f05929cbb7df8304956ba356ae9684f196656.png)

 再往后preCompile应该是是否有预编译，然后再调用serviceJspFile进行处理，这些暂时不太关心，重点是看看tomcat是怎么识别请求的资源是一个jsp并进行解析的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0a9f801814af37ea8182147bbccf72307114049f.png)

 回到JspServlet#service()方法，首先是两个属性：

- javax.servlet.include.path\_info（当前项目路径）
- javax.servlet.include.servlet\_path（目录路径）

 一般来说，只有Servlet使用RequestDispatcher的include方法调用的时候这两个属性才不会为null。一般是为了实现代码重用，需要将某些代码和数据放在一个或多个Servlet中，以供其他Servlet使用。

 首先是获取RequestDispatcher.INCLUDE\_SERVLET\_PATH属性的值：

```Java
jspUri = (String) request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
```

 一般情况下值为null，此时会走到如下逻辑，可以看到**一般情况下jspUri是通过request.getServletPath()+request.getPathInfo()获取的，然后再进入对应的解析逻辑**：

```Java
jspUri = request.getServletPath();
String pathInfo = request.getPathInfo();
if (pathInfo != null) {
    jspUri += pathInfo;
}
```

 这里跟JFinal的逻辑是有区别的，JFinal是通过request.getRequestURI()获取的。利用这个点看看是否能绕过对应的安全机制。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6a2f2c436081b05a1eeaf72e11ad754c7ccea68c.png)

绕过过程
----

 结合前面对Tomcat解析流程的分析，主要是通过request.getServletPath()以及request.getPathInfo()来获取JSP资源路径的。

 相比request.getRequestURI(),request.getServletPath()和request.getPathInfo()在一定程度上会对相关的path进行标准化处理，剔除不相关的元素，例如../,分隔符(;)后的内容等。可以利用这个差异达到绕过DenyAccessJsp的效果。

 验证猜想：

 需要执行的jsp内容如下，把对应的jsp放在应用的upload目录下：

```Java
<%
    out.println("Hello World！");
%>
```

 启动应用，可以看到正常情况下访问1.jsp，会返回`com.jfinal.kit.HandlerKit.renderError404(request, response, isHandled);`对应的页面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ed2bbeda5a44f324de30f859f2ebec6682f6f6c9.png)

 结合前面的思路，对于request.getRequestURI()来说，使用&amp;连接的参数键值对，其是获取不到的，但是参数分隔符（;）及内容是可以获取到的，所以可以通过`1.jsp;`的访问方式结合解析差异进行绕过，可以看到成功访问到1.jsp的内容：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8c00305668c1695ce77f37292c3937bb51ce0473.png)

 同样的，使用request.getRequestURI()这两个方法进行访问path的获取时，是不会进行URL解码操作的，利用这一点同样可以进行Bypass，可以看到成功绕过DenyAccessJsp机制访问到了1.jsp:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b0b78161154d20d5128b4f6bf6ac52f78c7811ff.png)

0x03 其他
=======

 在实际的业务开发中，不能过于依赖框架自身的安全机制。还是要遵循安全编码规范，例如文件上传场景，应该采用白名单方式检查文件扩展名，禁止白名单以外的扩展名上传。避免上传恶意webshell。同样的，除了DenyAccessJsp以后，JFinal还有很多其他的安全机制，是否存在Bypass的缺陷也是值得探索的。