0x00 前言
=======

 JFinal 是基于 Java 语言的极速 WEB + ORM 框架。

 JFinal在使用时会通过web.xml进行相应的配置，例如下面的例子：

```XML
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://java.sun.com/xml/ns/javaee" xmlns:web="http://java.sun.com/xml/ns/javaee" xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
   <!-- jfinal配置 -->
   <filter>
      <filter-name>jfinal</filter-name>
      <filter-class>com.jfinal.core.JFinalFilter</filter-class>
      <init-param>
         <param-name>configClass</param-name>
         <param-value>com.jfinal.demo.Config</param-value>
      </init-param>
   </filter>
   <filter-mapping>
      <filter-name>jfinal</filter-name>
      <url-pattern>/*</url-pattern>
   </filter-mapping>
</web-app>
```

 其中`configClass`参数的值`com.jfinal.demo.Config`是项目定义的`JFinalConfig`的实现类，其中会进行一些项目初始化的配置：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2c853b1192a71f6f2713da0be7cb5f23cdc3ae21.png)

 这里主要关注configRoute方法，例如如下的例子：

 这里使用`Routes.add()`方法，向`Routes`添加了一个`Controller`。通过这种方式用来配置 JFinal 访问路由，如下代码配置了将”/test”映射到TestController，当访问/test时候将访问到TestController的index()方法，访问/test/info时候将访问到TestController的info()方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-eab4f3739fd21f3018a228c63d1df60fabcfd10e.png)

 这里也可以通过使用JFinal的拓展组件，同样也可以像Spring一样去配置路由，原理也是一样的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1eb41b10a46016b867378dbcc1fc5c4d04388422.png)

0x01 JFinal请求解析过程
=================

 大概知道JFinal的路由配置方法以后，看看其是怎么对请求进行解析的。

 从上面的web.xml配置可以看到，其配置了一个过滤器`com.jfinal.core.JFinalFilter`，对应的作用范围是`/*`。也就是说这个Filter会拦截所有的请求。

 JFinalFilter实现了javax.servlet.Filter接口，从这里也可以看出jFinal是基于Servlet实现的。JFinalFilter在项目初始化时对jFinal项目的配置(com.jfinal.core.Config)、路由表(Route)、映射表(ActionMapping)等进行配置，其中**路由解析是在JFinalFilter的dofilter方法完成的**。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a6a19ca57b19ace6e713f172542afcb2873992bf.png)

1.1 过程分析
--------

 以jfinal3.6版本为例，查看JFinalFilter的dofilter方法的具体实现，首先获取request，response，设置编码,然后通过request.getRequestURI方法获取当前请求路径，如果contextPathLength不等于0的话，通过subString截取除主机名之后的action请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-dfbb275e7d0636fafeba7e01c6281590af70580d.png)

 isHandled作为一个标记位，表示是否需要doFilter这个请求。然后通过handler链进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-92af9afb690fe058b089611908ffa9bbf7b273a5.png)

 handler在初始化的时候被赋值，查看JFinalFilter的init方法，主要是在Jfinal.init进行初始化：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5423425d86e095f1b12faa8570e1ad8c7fa0c585.png)

 在JFinal.init方法调用了initHandler进行初始化：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ad5e246e5daae8bab4085c33b33593fc3a1b5830.png)

 可以看到实际对应的是ActionHandler。也就是说实际调用的是ActionHandler.handle(target, request, response, isHandled)方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e7254eba596f0710c43e9c2a65dd97427a76d5df.png)

 继续跟进ActionHandler.handle(target, request, response, isHandled)方法，首先调用`target.indexOf('.')!=-1`进行判断，这里应该是为了过滤掉一些静态资源的请求，类似1.png、1.html等：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5178954c8485605b1dec19ee2c5e87f1b8fe2748.png)

 然后把isHandled标记改为true，表示要这个请求会被处理掉。然后调用actionMapping#getAction方法，根据用户的请求地址从actionMapping中获取相应的Action。

 查看具体实现，根据用户的请求从map中获取Action（可以理解为是用于处理HTTP请求的）。这里是从mapping中获取的，mapping的初始化是在`com.jfinal.core.ActionMapping`的`buildActionMapping`方法,这里主要处理前面configRoute的配置，遍历`Routes`所有`Controller`、以及对应的`method`，然后进行相应的封装:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e4b6c83f4132accdee16ef7252bd545343025c55.png)

 继续看获取Action处理的逻辑，如果没有获取到Action，那么截取到最后一个`/`之前的路径重新从map集合中获取Action，最后返回对应的Action:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-688a0a009b83a8a0484402f49578698e5b1eb252.png)

 拿到对应的Action后会继续找到对应的Controller以及相应的方法执行相应的逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-676ae0781f8fecac389a5b01a9a2dbae2aca757a.png)

0x02 潜在风险
=========

 以配合shiro进行鉴权为例：

 shiro.ini的配置如下，对于/admin/下的一级路由，需要认证后才能访问：

```Plain
#路径角色权限设置
[urls]
/login = anon
/doLogin = anon
/resources/** = anon
/logout = logout
/admin/* = authc
```

 正常情况下，未授权直接访问/admin/page会返回302跳转到登陆接口：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a0abb410cfcfa687a1b484517ef04d0ebbcd04c6.png)

 根据前面的分析，在没有获取到Action的前提下，JFinal会截取到最后一个`/`之前的路径重新从map集合中获取Action。也就是说/admin/page、/admin/page/、/admin/page/bypass请求到的Action是一致的。

 对于结尾最后一个`/`的问题，shiro在之前已经有修复过了，所以/admin/page/是无法绕过的，但是JFinal在处理的时候比较粗糙，使用/admin/page/bypass即可绕过shiro的鉴权处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-77f60ea3a783f891bbef870ab8b7b75baa7e2e03.png)