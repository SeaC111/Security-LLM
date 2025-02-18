一、前言
====

在接触几次JAVA代码审计项目后，发现JAVA和PHP挺不一样的，在很多看起来没有做任何过滤处理、没有任何权限设置的漏洞链中，却无法完整复现漏洞。经常和团队的小伙伴们扣脑壳的说：“讲道理这里没有任何过滤，直接传入到xxx里面，怎么可能会没有xx漏洞呢？”。在研究学习以后，做了总结，包含：Spring AOP、拦截器和过滤器三个部分内容。

二、Spring AOP
============

2.1 基础知识
--------

引用百度百科的原话：

> 在软件业，AOP为Aspect Oriented Programming的缩写，意为：[面向切面编程](https://baike.baidu.com/item/%E9%9D%A2%E5%90%91%E5%88%87%E9%9D%A2%E7%BC%96%E7%A8%8B/6016335)，通过[预编译](https://baike.baidu.com/item/%E9%A2%84%E7%BC%96%E8%AF%91/3191547)方式和运行期间动态代理实现程序功能的统一维护的一种技术。AOP是[OOP](https://baike.baidu.com/item/OOP)的延续，是软件开发中的一个热点，也是[Spring](https://baike.baidu.com/item/Spring)框架中的一个重要内容，是[函数式编程](https://baike.baidu.com/item/%E5%87%BD%E6%95%B0%E5%BC%8F%E7%BC%96%E7%A8%8B/4035031)的一种衍生范型。利用AOP可以对业务逻辑的各个部分进行隔离，从而使得业务逻辑各部分之间的[耦合度](https://baike.baidu.com/item/%E8%80%A6%E5%90%88%E5%BA%A6/2603938)降低，提高程序的可重用性，同时提高了开发的效率。

**其使用步骤：**  
(1)使用@Aspect注解实现一个切面类。  
(2)在切面类内添加一个切点方法，使用Spring的AOP注解设置Advice通知类型和切入点表达式。  
(3)如果切入点表达式是注解类型，则在Controller中添加一个注解 @xxx，被注解的方法才会调用切点，执行切点中的代码。

**Advice通知类型介绍：**  
(1)Before:在目标方法被调用之前做增强处理,@Before只需要指定切入点表达式即可  
(2)AfterReturning:在目标方法正常完成后做增强,@AfterReturning除了指定切入点表达式后，还可以指定一个返回值形参名returning,代表目标方法的返回值  
(3)AfterThrowing:主要用来处理程序中未处理的异常,@AfterThrowing除了指定切入点表达式后，还可以指定一个throwing的返回值形参名,可以通过该形参名  
来访问目标方法中所抛出的异常对象  
(4)After:在目标方法完成之后做增强，无论目标方法时候成功完成。@After可以指定一个切入点表达式  
(5)Around:环绕通知,在目标方法完成前后做增强处理,环绕通知是最重要的通知类型,像事务,日志等都是环绕通知,注意编程中核心是一个ProceedingJoinPoint

**demo-1：**

```java
/*
 * LogerAscpect.java
 */
@Aspect
@Component
/* 切入点表达式为execution，表示被指定的类，每个public方法执行前，都执行切点方法 */
public class LoggingAspect {
    // 在执行UserService的每个方法前执行:
    @Before("execution(public * com.itranswarp.learnjava.service.UserService.*(..))")
    public void doAccessCheck() {
        System.err.println("[Before] do access check...");
    }
}

// 然后给@Configuration类加上一个@EnableAspectJAutoProxy注解即可。
```

**demo-2：**

```java
/*
 * LogerAscpect.java
 */
@Aspect
@Component
/* 切入点为注解形式，只需要在类上面加上@Loger注解，则进入切面 */
public class LogerAspect {
    @Before("@annotation(controllerLoger)")
    public void doBefore(JoinPoint point, Loger controllerLoger) throws Throwable
    {
        System.out.println("[+] doBefore start .....");
    }
}

```

2.2 代码案例
--------

从若依（RuoYi）的SQL注入修复看切面：（代码来源于RuoYi == 4.7.2版本）

在新版本的若依中，SysDeptMapper.xml仍使用`${`,如下：![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4bed6efb35cb13a2a280b6501f0e45238126acf3.jpg)

依次往上：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-75166ebbd0c903c5b271f63c535e55f80f873223.jpg)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-6a0e2052f52daa6e1d4f18ae183ec437fe276a7b.jpg)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-99c6e8230b404de8e48179369f5da3603a30f5f2.jpg)

仍然没看到任何过滤的代码，但实时是漏洞确实被修复了。那么修复代码究竟是使用什么方法在整个流程中起到作用的呢？

可以看到在selectDeptList方法前打了注解，`@DataScope(deptAlias = "d")`，跟进这个方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-34da6cf249a43377ca8f0e81f1919e5b1736f796.jpg)

其中切面类的实现：在DataScopeAspect.java中

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c5ccc2493ebe4475917501a2401858dbbfdf80bb.jpg)

该类中，打了@Aspect注解，表示是一个切面类，然后使用Before的通知类型，切入点为：打了`@DataScope`注解的地方，切点方法为：doBefore。

所以，在出现`@DataScope`注解的时候，在方法调用前会先调用的切点方法doBefore，然后由clearDataScope方法（代码如下）会将param\['dataScope'\]置空，从而达到修复SQL注入的目的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e153ab7fcd5284d7c18cb41d1fe632270f6c354d.jpg)

注意：controllerDataScope的类型是DataScope，所以注解是DataScope而非controllerDataScope。

三、拦截器(Interceptor)
==================

3.1 基础知识
--------

> 关于Spring MVC的拦截器，主要就是用于拦截用户的请求并作出相应处理的，通常应用在权限验证、记录请求信息的日志、判断用户是否登录等功能。Interceptor的拦截范围其实就是Controller方法，它实际上就相当于基于AOP的方法拦截。

每个拦截器都必须实现`HandlerInterceptor`接口，可以选择实现preHandle、afterCompletion和postHandle三个方法，它们分别代表：

- preHandle：在controller进入前执行拦截器代码。（在`preHandle()`中，可以直接处理响应，如果`return false`，则表示无需controller再进行处理了。）
- postHandle：在controller正常完成后执行拦截器代码，如果controller中抛出异常，则不会执行。
- afterCompletion：在controller完成后执行拦截器代码，不管controller中是否抛出异常。

**使用方法：**

- 定义`AuthInterceptor`类，实现 `HandlerInterceptor` 接口
- 实现`preHandle()`方法
- 在`WebMvcConfigurer`中注册所有的`Interceptor`

3.2 代码案例
--------

从一个未授权访问类型漏洞挖掘过程来看拦截器（Interceptor）  
在controller的实现中，看到了一个接口，访问该接口则会返回管理员的秘密，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-6f88ccde287ee8e9c8f5192731c227ca848b8807.jpg)

没有看到任何过滤，心中一想，此处就是一个大越权啊，然后访问：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e02c2b86b104c6567861f1f9d7768397f45c3d6e.jpg)

然后发现，在AppConfig.java中注册了拦截器,如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-513bb0bda3c6fd39102eacc47d427724adff16a7.jpg)

所以很可能，权限校验的位置在拦截器中，于是发现：AuthInterceptor拦截器，代码如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-940eb19c909450fe5373e77a725d62c786bb7ed0.jpg)

逻辑如下：

- preHandle方法通过`isSecret`方法来判断当前用户请求的是否是一个秘密的URL，
- 如果是，则触发`authenticateByHeader`方法来校验用户是否授权
- 如果通过校验则交给controller处理
- 否则提示授权错误。
- 如果请求不是秘密url，也直接交给controller处理。

接着看下`isSecret`方法的实现

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-84eff5d5be54f606e874c04219117636833d429a.jpg)

将请求的URI与秘密URI列表\[*其实模拟的需要鉴权的URL*\]进行对比，返回比对结果。

然后看下`authenticateByHeader`方法的实现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a2963399a79670c4355aeb6034ee4ad1861ac645.jpg)

从header中取`Authorization`的值进行base64解码，然后调用`userService.sginin`方法进行验证账号密码。

所以，**如果想要访问秘密URL，则需要Authorization头里面的账号密码正确，才能获取到其中的内容。**如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1b025204606e242fb0bf14e9787eb1359d8773d4.jpg)

虽然此处***只看controller的实现***，是没有看到任何权限校验相关的内容的，但其仍**不存在未授权访问**漏洞，原因就在于鉴权逻辑在拦截器中实现的。

四、过滤器(Filter)
=============

4.1 基础知识
--------

> 为了把一些公用逻辑从各个Servlet中抽离出来，JavaEE的Servlet规范还提供了一种Filter组件，即过滤器，它的作用是，在HTTP请求到达Servlet之前，可以被一个或多个Filter预处理，类似打印日志、登录检查等逻辑，完全可以放到Filter中。这样，开发者就只需要关注业务逻辑即可。

编写`Filter`时，必须实现`Filter`接口，在`doFilter()`方法内部，要继续处理请求，必须调用`chain.doFilter()`。最后，用`@WebFilter`注解标注该`Filter`需要过滤的URL。这里的`/*`表示所有路径。

**Filter使用方法：**

- 编写authFilter实现Filter接口
- 实现doFilter方法，编写过滤器逻辑
- 在web.xml中声明Filter及拦截范围

4.2 代码案例
--------

继续使用和3.2中一样逻辑的demo代码，我们拿到代码后，找到Controller，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-6df46f7eca2a676c614e859c3faae0e6c70b240a.jpg)

还是没有任何过滤，然后测试，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3d3370ca57d404be38c4c8f574747a87332bbcda.jpg)

这时候，我们发现并没有未授权访问，那么排查Interceptor：全局搜索Interceptor

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9344dba7421fd7e8b95714b892b676ce1670139b.jpg)

发现并没有拦截器，那么可能的只有过滤器Fliter了，查看web.xml代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8d2d28fe5c722feca1e99c5d7766f69f37582f36.jpg)

发现Filter，且过滤范围只有`/secret`这个URL，然后看下Filter的实现。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-05c58ada0fab4385d6b55d72f9f786722c16c6d2.jpg)

逻辑如下：

- 当匹配到URL，则进入authFilter当中
- 调用`authenticateByHeader`方法进行鉴权处理 
    - 如果鉴权失败，直接返回 Authorization error
    - 否则不做任何处理

`authenticateByHeader`方法的逻辑，依然是从header获取认证字符串，进行校验，如果校验通过则打印log，否则抛出一个异常。当Filter捕获到异常，直接返回Authorization error。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c6aa13024cd142746e2a9189b20b1734f46935d4.jpg)

所以，需要在header头里面有认证字符串才能访问到秘密URL，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-756fcfabebcb830f06ada25264c43f003fc68a90.jpg)

因此，该处不存在未授权访问漏洞，其鉴权代码由Filter实现。

五、总结
====

对AOP、Interceptor和Filter三种通用逻辑处理方法的研究，了解从Controller入手看似整个调用链存在漏洞但黑盒测试又不存在漏洞的幽灵问题的原因。其实，这种通用逻辑不仅可以处理权限类型的问题，也可以实现SQL注入、命令注入、XSS等各种漏洞关键字过滤。

六、参考
====

[https://bbs.huaweicloud.com/blogs/325317?utm\_source=oschina&amp;utm\_medium=bbs-ex&amp;utm\_campaign=other&amp;utm\_content=content](https://bbs.huaweicloud.com/blogs/325317?utm_source=oschina&utm_medium=bbs-ex&utm_campaign=other&utm_content=content)  
<https://www.jianshu.com/p/5b9a0d77f95f>  
<https://www.liaoxuefeng.com/wiki/1252599548343744/1282384114745378>