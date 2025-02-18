没有回显/高并发时才有回显
-------------

残笑师傅给我反馈说：只有高并发的环境下才能看到回显结果，结果中包含了：没HTTP只有命令输出的情况、没回显的情况、有回显的情况、有回显多次的情况。

这里解释个事情：  
这条主要解决的是站点存在其他正常请求的时候，回显可能会串位的问题  
比如：除了命令执行请求以外，还有其它的10个请求同时在访问站点，就可能出现串位。

这个问题是因为搜索到了NIO的队列中，由于Request加了存在cmd头的限定，所以搜索到的Request一定是你的Request，但是Response就不好说了，也就是说如果你在发这个的攻击包的时候，如果还有其它人在访问，那么很有可能，你的命令输出结果就输出到其它访问的结果中了。

之前测试的时候，只测了单一线程发送的情况，所以没发现这个问题，emm，还是得测试充分的。

模拟测试：

模拟正常访问： Burp Intruder使用Null Payloads发送1000次，并发10，固定发送间隔500ms。

访问的其实就是个404页面

![](https://shs3.b.qianxin.com/butian_public/f79852e4ef1d42825f440df686d60a9f8.jpg)  
模拟攻击访问： Burp Repeater发送攻击报文

然后就可以发现,某几次攻击请求中，响应为空，但是一个普通的请求中出现了我们想要的结果：

某几次的攻击请求结果哪里都找不到，应该是找到的Response对象，还没等写入，就被销毁了。。

![](https://shs3.b.qianxin.com/butian_public/f609a0cd44563c9d7dc73eed0f2da55cb.jpg)

![](https://shs3.b.qianxin.com/butian_public/f8ba0ba17410e3e345a7a2267d9589f23.jpg)

解决方法
----

目前翻阅了Tomcat、Weblogic、Jetty、JBOSS的代码，发现Request对象下面都带有对应的Response对象,所以既然可以准确定位到Request对象，那么Response也就有了。

(Jetty的resposne不是直接包含在request对象中，这三者都有无参的getResponse方法，直接反射调用就好了~)

PS： 前几天还在p师傅的小密圈跟Kingkk师傅说觉得Weblogic的Request对象下面带Response好奇怪，结果中间件都这么干，emm，我Out了。。。

目前还是测了Tomcat/Weblogic/Jetty没有问题，JBoss懒得装了，有兴趣的师傅可以试一下。

![](https://shs3.b.qianxin.com/butian_public/f4cedde31a4505c91d66a1c0778fd0594.jpg)

改好的代码：

<https://gist.github.com/fnmsd/5c98b20cef16cf4942de0eba34dc2ad7>

参考：

[http://tomcat.apache.org/tomcat-7.0-doc/api/org/apache/catalina/connector/Request.html#field\_summary](http://tomcat.apache.org/tomcat-7.0-doc/api/org/apache/catalina/connector/Request.html#field_summary)

<https://www.eclipse.org/jetty/javadoc/current/org/eclipse/jetty/server/Request.html>

<https://docs.jboss.org/jbossweb/latest/api/org/apache/catalina/connector/Request.html>

Weblogic的Request类名为：weblogic.servlet.internal.ServletRequestImpl

Tomcat回显不稳定
-----------

ph4nt0mer师傅反馈Tomcat回显不稳定，经过测试发现：

Tomcat除了org.apache.catalina.connector.Request外，还有org.apache.catalina.connector.Request.RequestFacade这个包装类继承了HttpServletRequest接口。

而RequestFacade不包含getReponse方法，无法准确获取到Response对象。

修改如下逻辑：

如果通过反射调用getResponse方法失败，就认为没有搜索到正确的Request对象，重置r字段  
由于改为仅从request中获取response，所以删掉原有的response搜索逻辑。  
改好的代码：  
（其它中间件同样适用）

<https://gist.github.com/fnmsd/4d9ed529ceb6c2a464f75c379dadd3a8>

URLCLassLoader无法回显  
这个是香草师傅发现的，使用URLCLassLoader进行加载（CommonsCollection1之类的链）：

`new URLClassLoader(new URL[]{new File("aaaa.jar").toURI().toURL()}).loadClass("a1").newInstance();`

出现报错：

![](https://shs3.b.qianxin.com/butian_public/f808402cd4a47004f56beab061f1442c1.jpg)

无法找到HTTPServletRequest。

大概原因是URLClassLoader在不加参数的情况，父加载器为SystemClassLoader，而SystemClassLoader里面是没有加载Java Web的类的。（这块不太熟悉，后面还得再学习）

尝试过由URLClassLoader加载的jar包提供HTTPServletRequest、HTTPServletResponse类，可以正常执行，但是无法找到Request和Response。

做了如下实验：

```php
<%
    Class o = new URLClassLoader(new URL[]{new File("aaa.jar").toURI().toURL()}).loadClass("javax.servlet.http.HttpServletRequest");
    System.out.println(o.isAssignableFrom(request.getClass()));
    System.out.println(HttpServletRequest.class.isAssignableFrom(request.getClass()));

%>

```

分别输出了false和true，也就是说通过URLClassLoader加载出的HttpServletRequest和当前request没有继承关系，所以这么做是没法用的。  
查找了资料：

一个类，由不同的类加载器实例加载的话，会在方法区产生**两个不同的类**，彼此不可见，并且在堆中生成不同Class实例。

也就是说无法通过远程加载的jar包中提供相关类来解决这个问题。

那么换一个思路：

**1.**不直接使用HttpServletRequest、HTTPServletResponse，而是通过当前线程的类加载器进行加载：

`Class hsr = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.http.HttpServletRequest");`

**2**由于没法直接加载HttpServletRequest，所以也没法使用强制类型转换，改为使用反射调用getHeader\\getWriter等方法

`hsr.getMethod("getHeader",new Class[]{String.class}).invoke(o,"cmd");`

改好的类：

<https://gist.github.com/fnmsd/2fd47012849f25eb53d703f283679462>

香草师傅还提了一个解决办法：

用URLCLassloader加载的类里面，再创建一个使用当前线程的ClassLoader的URLClassLoader再加载回显类，也是很好的思路。

参考：

<https://blog.csdn.net/csdnlijingran/article/details/89226943>

### BasicDataSource链+BCEL无法回显

这个是Frost Blue师傅发现的，没弄好反序列化环境，写个触发链的代码。

```php
<%@ page import="com.sun.org.apache.bcel.internal.util.ClassLoader" %>
<%@ page import="org.apache.tomcat.dbcp.dbcp2.BasicDataSource" %>
<%    
    ClassLoader  cl = new ClassLoader();
    String BCEL = "$$BCEL$$。。。。。";
    BasicDataSource bds = new BasicDataSource();
    bds.setDriverClassLoader(cl);
    bds.setDriverClassName(BCEL);
    bds.getConnection();
    %>

```

ClassLoader部分的问题跟URLClassLoader的问题相同，但是getConnection会造成异常，并且没有接住的话，会导致请求无响应。

![](https://shs3.b.qianxin.com/butian_public/fc42a4012edbc99095016c0439aea189c.jpg)

所以在PrintWriter的flush后面加了个close，防止由于未catch的异常导致的响应异常。

改好的代码：  
跟上面一条一样。

文章转载于自己博客，原文地址为：<https://blog.csdn.net/fnmsd/article/details/106890242>