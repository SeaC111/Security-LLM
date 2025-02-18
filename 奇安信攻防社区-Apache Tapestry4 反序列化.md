无论是打点能力还是审计能力也好，在红蓝对抗中都有着至关重要的作用，hvv 背景下，我等脚本小子已经末路，不难看出后者已逐渐成为每个安全技术从业者需了解并掌握的必备技能，掌握后者往往也会在每次攻防演练中无往不利，最后希望师傅们轻喷（文笔垃圾，措辞轻浮，内容浅显，操作生疏），unjuanbale。

0x01 简介
=======

本文以 Tapestry4 为例（xz &amp; chen师傅小密圈看到）， 2008年 停止更新的框架，有一个特殊的 servlet 做请求处理分发，现在是 Tapestry 5 , <https://tapestry.apache.org/download.html>，其中 Tapestry 4 会对 "sp" 参数进行反序列化操作，导致未经检验的反序列化数据加载进内存。  
最后，怎么说呢，菜是一回事，动手调是一回事。

0x02 环境搭建
=========

- - - - - -

1、Maven + Servlet（pom.xml &amp; web.xml)
----------------------------------------

创建一个 Java-web 项目，使用 maven 骨架：maven-archetype-webapp，配置 pom.xml 如下  
这里使用 jdk1.7， jdk1.8 部署时出现异常（可直接到4小节）

```xml
<?xml version="1.0" encoding="UTF-8"?>

<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>org.example</groupId>
  <artifactId>Tapestry4De</artifactId>
  <version>1.0-SNAPSHOT</version>
  <packaging>war</packaging>

  <name>Tapestry4 Maven Webapp</name>
  <!-- FIXME change it to the project's website -->
  <url>http://www.example.com</url>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <maven.compiler.source>1.7</maven.compiler.source>
    <maven.compiler.target>1.7</maven.compiler.target>
  </properties>

  <dependencies>

    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>javax.servlet-api</artifactId>
      <version>3.1.0</version>
    </dependency>

    <dependency>
      <groupId>javax.servlet.jsp</groupId>
      <artifactId>javax.servlet.jsp-api</artifactId>
      <version>2.3.3</version>
    </dependency>

    <dependency>
      <groupId>org.apache.tapestry</groupId>
      <artifactId>tapestry-framework</artifactId>
      <version>4.1.6</version>
    </dependency>

....
  </dependencies>

....
</project>

```

web.xml 配置如下

```xml
<?xml version="1.0"?>
<web-app version="2.4" xmlns="http://java.sun.com/xml/ns/j2ee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee
         http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd">

  <servlet>
    <servlet-name>ApplicationServlet</servlet-name>
    <servlet-class>org.apache.tapestry.ApplicationServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>ApplicationServlet</servlet-name>
    <url-pattern>/app</url-pattern>
  </servlet-mapping>

</web-app>
```

2、配置 Tapestry4 应用环境
-------------------

Tapestry4一般配置一个页面，有三个文件

- 模版文件 \[name\].html ： webapp 目录下，必须叫 Home.html，Tapestry 程序入口
- page文件\[name\].page：WEB-INF 目录下，需要与模版文件一致，自动关联
- 处理类 \[name\].class：无其它要求，需与 page 中内容关联

**Home.html**

```html
<span  jwcid ="@Insert"  value ="ognl:Tapestry"  />
```

**Home.page**

```xml
<?xml version="1.0" encoding="GBK" ?>


<page-specification class ="cn.d4rksec.Home"> </page-specification>
```

**Home.class**

```java
package cn.d4rksec;

import org.apache.tapestry.html.BasePage;

public abstract class Home extends BasePage {

    public String getTapestry(){
        return "hello ,Tapestry4..";
    }

}
```

3、访问测试
------

环境部署完后，目录结构如下，调用过程：Home.html -&gt; Home.page -&gt; Home.class

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1650852789845-62bff27f-d0c7-4f33-b63b-697e2c6e15e0.png#clientId=u1d9c65c1-1459-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=291&id=u1ac0cd93&margin=%5Bobject%20Object%5D&name=image.png&originHeight=393&originWidth=1013&originalType=binary&ratio=1&rotation=0&showTitle=false&size=57574&status=done&style=none&taskId=uada27962-b9a9-403e-a316-bffd5a49368&title=&width=750.5)

配置 tomcat 环境进行访问

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1650853209199-31025b2b-47b1-4314-8147-c693a79d1449.png#clientId=u1d9c65c1-1459-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=366&id=u4b55aaf5&margin=%5Bobject%20Object%5D&name=image.png&originHeight=732&originWidth=1760&originalType=binary&ratio=1&rotation=0&showTitle=false&size=273490&status=done&style=none&taskId=uc6cefd22-9886-4c29-a2f3-21566c8a5b2&title=&width=880)

4、漏洞环境部署
--------

因漏洞利用存在条件限制，这里直接以该项目为例：

<https://github.com/codepreplabs/tapestry4Tutorial/tree/main/03userInput>

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1650872753334-a633c67d-dbff-4a2a-a015-bf1aecfc9ef8.png#clientId=u1d9c65c1-1459-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=356&id=u3bf62503&margin=%5Bobject%20Object%5D&name=image.png&originHeight=712&originWidth=1536&originalType=binary&ratio=1&rotation=0&showTitle=false&size=293059&status=done&style=none&taskId=u55666401-5584-4c80-93d6-a7bfeefece1&title=&width=768)

0x03 漏洞分析
=========

1、servlet 路由分析
--------------

审计通常采用正向、反向、混合，在知道漏洞触发点的情况下，采用反向审计方式往往会事半功倍，但是对于分析一个新接触的事物而言，大部分人采用这样的分析思路可能只知其然而不知其所以然（如在哪里下断点，为什么要在这里下断点），所以在分析一个已知的漏洞情况下怎么断点执行到框架内并且定位到反序列化过程才是漏洞分析的意义。

通过 web.xml 配置可以知道，servlet 类在 org.apache.tapestry.ApplicationServlet ，在此处下断意味着所有 servlet-name 对应的 url-pattern 都会执行到该 Servlet ，因此我们可以在该类的 doGet、doPost 方法中下断

```java
public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    this.doService(request, response);
}
```

doService 方法

```java
protected void doService(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    try {
        this._registry.setupThread();
        this._requestServicer.service(request, response);
    } catch (ServletException var8) {
        this.log("ServletException", var8);
        this.show(var8);
        throw var8;
    } catch (IOException var9) {
        this.log("IOException", var9);
        this.show(var9);
        throw var9;
    } finally {
        this._registry.cleanupThread();
    }

}
```

跟进到 org/apache/tapestry/services/impl/InvokeEngineTerminator.class 中，request 请求作为参数传给了给到了 IEngine 中 service 方法

```java
public void service(WebRequest request, WebResponse response) throws IOException {
    IEngine engine = this._engineManager.getEngineInstance();
    request.setAttribute("org.apache.tapestry.Infrastructure", this._infrastructure);

    try {
        engine.service(request, response);
    } finally {
        this._engineManager.storeEngineInstance(engine);
    }

}
```

IEngine 实现类 org/apache/tapestry/engine/AbstractEngine.class 的 service 方法

```java
public void service(WebRequest request, WebResponse response) throws IOException {
        IRequestCycle cycle = null;
        IEngineService service = null;
        if (this._infrastructure == null) {
            this._infrastructure = (Infrastructure)request.getAttribute("org.apache.tapestry.Infrastructure");
        }

        try {
            cycle = this._infrastructure.getRequestCycleFactory().newRequestCycle(this);
        } catch (RuntimeException var21) {
            throw var21;
        } catch (Exception var22) {
            throw new IOException(var22.getMessage());
        }

        try {
            try {
                service = cycle.getService();
                service.service(cycle);
                return;
            } catch (PageRedirectException var23) {
                this.handlePageRedirectException(cycle, var23);
            } catch (RedirectException var24) {
                this.handleRedirectException(cycle, var24);
            } catch (StaleLinkException var25) {
                this.handleStaleLinkException(cycle, var25);
            } catch (StaleSessionException var26) {
                this.handleStaleSessionException(cycle, var26);
            }
        } catch (Exception var27) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Uncaught exception", var27);
            }

            this.activateExceptionPage(cycle, var27);
        } finally {
            try {
                cycle.cleanup();
                this._infrastructure.getApplicationStateManager().flush();
            } catch (Exception var20) {
                this.reportException(EngineMessages.exceptionDuringCleanup(var20), var20);
            }

        }

    }
```

在 this.\_infrastructure.getRequestCycleFactory().newRequestCycle(this) 该方法中，将用户请求参数存储到 QueryParameterMap 对象中（本质上为HashMap），同时使用 newRequestCycle() 封装为 IRequestCycle 对象  
![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651133673605-6b5c3923-00c7-4fe7-885f-3818fd35091c.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=275&id=ucd3e8db8&margin=%5Bobject%20Object%5D&name=image.png&originHeight=430&originWidth=1160&originalType=binary&ratio=1&rotation=0&showTitle=false&size=123526&status=done&style=none&taskId=u029c86b4-03f1-4ce9-ad3b-6a5bcbabb21&title=&width=742)

newRequestCycle() 方法 如下

```java
public IRequestCycle newRequestCycle(IEngine engine) {
    WebRequest request = this._infrastructure.getRequest();
    QueryParameterMap parameters = this.extractParameters(request);
    this.decodeParameters(request.getActivationPath(), request.getPathInfo(), parameters);
    String serviceName = this.findService(parameters);
    IRequestCycle cycle = new RequestCycle(engine, parameters, serviceName, this._environment);
    this._requestGlobals.store(cycle);

    try {
        this._requestGlobals.store(this._responseDelegateFactory.getResponseBuilder(cycle));
        cycle.setResponseBuilder(this._requestGlobals.getResponseBuilder());
        return cycle;
    } catch (IOException var7) {
        throw new ApplicationRuntimeException("Error creating response builder.", var7);
    }
}
```

其中 findService() 决定 请求后面交给哪个 Service 进行处理

```java
private String findService(QueryParameterMap parameters) {
    String serviceName = parameters.getParameterValue("service");
    return serviceName == null ? "home" : serviceName;
}
```

回到 AbstractEngine.class 的 service 方法， cycle.getService() 获取了对应 service 的 IEngineService 对象.

```java
public synchronized IEngineService getService(String name) {
    IEngineService result = (IEngineService)this._proxies.get(name);
    if (result == null) {
        result = this.buildProxy(name);
        this._proxies.put(name, result);
    }

    return result;
}
```

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651136234980-adfde4e5-4b0e-4859-8c59-c95b20fe69f5.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=334&id=u948ff81e&margin=%5Bobject%20Object%5D&name=image.png&originHeight=470&originWidth=1047&originalType=binary&ratio=1&rotation=0&showTitle=false&size=110767&status=done&style=none&taskId=uf88bb047-174b-475a-b59e-8aab76c299b&title=&width=743.5)

service map 取自配置文件 META-INF/tapestry.services.xml

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651137183803-fcb05396-560b-4655-be81-933156c040a0.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=237&id=ud1c3e908&margin=%5Bobject%20Object%5D&name=image.png&originHeight=315&originWidth=1086&originalType=binary&ratio=1&rotation=0&showTitle=false&size=70527&status=done&style=none&taskId=uf8045219-c9e0-4a96-bd9b-858c2a57681&title=&width=817)

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651137254358-8037d821-a710-4110-a648-3080c9e25eba.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=296&id=u47da688d&margin=%5Bobject%20Object%5D&name=image.png&originHeight=421&originWidth=1058&originalType=binary&ratio=1&rotation=0&showTitle=false&size=89177&status=done&style=none&taskId=uc3012304-6d51-434a-b5ee-b0a87489d50&title=&width=745)

其中不同 service name 指明了不同的 construct class 以及对应的 property 属性和属性值，如 direct 和 page

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651137754077-6eb2a004-10fc-4c2e-80a4-008e42edc7a2.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=311&id=u9d71ae7f&margin=%5Bobject%20Object%5D&name=image.png&originHeight=465&originWidth=1110&originalType=binary&ratio=1&rotation=0&showTitle=false&size=103627&status=done&style=none&taskId=u8f576ea7-1a07-40f1-b66f-d709bb21267&title=&width=743)  
回到 org/apache/tapestry/engine/AbstractEngine.class 的 service 方法

```java
public void service(WebRequest request, WebResponse response) throws IOException {
        IRequestCycle cycle = null;
        IEngineService service = null;
.....

        try {
            cycle = this._infrastructure.getRequestCycleFactory().newRequestCycle(this);
.......

        try {
            try {
                service = cycle.getService();
                service.service(cycle);
                return;
......

    }
```

此时 service.service() 即决定调用对应的 construct class ，如 service 为 direct 则会走到 DirectService

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651138581518-f46a9af3-0f84-486b-9667-ad831c83188d.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=312&id=u0d41e2ef&margin=%5Bobject%20Object%5D&name=image.png&originHeight=465&originWidth=1106&originalType=binary&ratio=1&rotation=0&showTitle=false&size=99826&status=done&style=none&taskId=u3e143ec9-f3e2-4c79-8433-024b7cef83d&title=&width=743)

如上，执行到 DirectService 并获取之前被封装为 IRequestCycle 对象中的参数

2、漏洞触发点分析
---------

在 /org/apache/tapestry/engine/DirectService.class 的 service() 方法下断点

```java
public void service(IRequestCycle cycle) throws IOException {
    String componentId = cycle.getParameter("component");
    String componentPageName = cycle.getParameter("container");
    String activePageName = cycle.getParameter("page");
    boolean activeSession = cycle.getParameter("session") != null;
    IPage page = cycle.getPage(activePageName);
    cycle.activate(page);
    IPage componentPage = componentPageName == null ? page : cycle.getPage(componentPageName);
    IComponent component = componentPage.getNestedComponent(componentId);
    IDirect direct = null;

    try {
        direct = (IDirect)component;
    } catch (ClassCastException var11) {
        throw new ApplicationRuntimeException(EngineMessages.wrongComponentType(component, IDirect.class), component, (Location)null, var11);
    }

    if (activeSession && direct.isStateful()) {
        WebSession session = this._request.getSession(false);
        if (session == null || session.isNew()) {
            throw new StaleSessionException(EngineMessages.requestStateSession(direct), componentPage);
        }
    }

    Object[] parameters = this._linkFactory.extractListenerParameters(cycle);
    this.triggerComponent(cycle, direct, parameters);
    this._responseRenderer.renderResponse(cycle);
}
```

加载 Page 并从 IPage 对象中获取 componentId ，在该方法中 getNestedComponent()

```java
public IComponent getNestedComponent(String path) {
    if (path == null) {
        return this;
    } else {
        StringSplitter splitter = new StringSplitter('.');
        IComponent current = this;
        String[] elements = splitter.splitToArray(path);

        for(int i = 0; i < elements.length; ++i) {
            current = ((IComponent)current).getComponent(elements[i]);
        }

        return (IComponent)current;
    }
}
```

其中 getComponen() 如下，在 \_components 中 获取传入的 componentId

```java
public IComponent getComponent(String id) {
    Defense.notNull(id, "id");
    IComponent result = null;
    if (this._components != null) {
        result = (IComponent)this._components.get(id);
    }

    if (result == null) {
        throw new ApplicationRuntimeException(Tapestry.format("no-such-component", this, id), this, (Location)null, (Throwable)null);
    } else {
        return result;
    }
}
```

components 为之前页面加载存入的 jwcid 组件，如传入的请求无对应 jwcid，result 则为null 并抛出 ApplicationRuntimeException 异常

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651161079101-70bef407-dc8b-4abf-a740-049673bd5cfa.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=715&id=ubbc02a6b&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1430&originWidth=1982&originalType=binary&ratio=1&rotation=0&showTitle=false&size=1065395&status=done&style=none&taskId=ucdf39492-ea56-429b-8658-b81809f6a94&title=&width=991)

回到 /org/apache/tapestry/engine/DirectService.class 的 service() 方法

```java
public void service(IRequestCycle cycle) throws IOException {
    String componentId = cycle.getParameter("component");
......
    IPage page = cycle.getPage(activePageName);
    cycle.activate(page);
    IPage componentPage = componentPageName == null ? page : cycle.getPage(componentPageName);
    IComponent component = componentPage.getNestedComponent(componentId);
......

    Object[] parameters = this._linkFactory.extractListenerParameters(cycle);
    this.triggerComponent(cycle, direct, parameters);
    this._responseRenderer.renderResponse(cycle);
}
```

跟进到 this.\_linkFactory.extractListenerParameters()

```java
public Object[] extractListenerParameters(IRequestCycle cycle) {
    String[] squeezed = cycle.getParameters("sp");
    if (Tapestry.size(squeezed) == 0) {
        return this._empty;
    } else {
        try {
            return this._dataSqueezer.unsqueeze(squeezed);
        } catch (Exception var4) {
            throw new ApplicationRuntimeException(var4);
        }
    }
}
```

获取请求的 sp 参数，并交给 this.\_dataSqueezer.unsqueeze() 处理

```java
public Object unsqueeze(String string) {
    SqueezeAdaptor adaptor = null;
    if (string.equals("X")) {
        return null;
    } else if (string.length() <= 0) {
        return null;
    } else {
        int offset = string.charAt(0) - 33;
        if (offset >= 0 && offset < this._adaptorByPrefix.length) {
            adaptor = this._adaptorByPrefix[offset];
        }

        return adaptor == null ? string : adaptor.unsqueeze(this, string);
    }
}
```

此处获取了 sp 参数中的第一位字符并减去33，来决定该字符串交给this.\_adaptorByPrefix 中的谁进行处理

![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651164422177-b70d48c7-dee7-4c78-8457-3e2d6aa61361.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=405&id=u0a5151b0&margin=%5Bobject%20Object%5D&name=image.png&originHeight=898&originWidth=1660&originalType=binary&ratio=1&rotation=0&showTitle=false&size=647862&status=done&style=none&taskId=u0997e02a-6af5-4cfd-9d6b-e8ba5e8f44c&title=&width=748)

其中 46 和 57 对应 org.apache.tapestry.util.io.SerializableAdaptor 类，传入 46+33 / 57+33 对应的 Ascii 会走到该类中 unsqueeze() 方法中，分别为 O / Z

```java
public Object unsqueeze(DataSqueezer squeezer, String encoded) {
    char prefix = encoded.charAt(0);

    try {
        byte[] mimeData = encoded.substring(1).getBytes();
        byte[] decoded = Base64.decodeBase64(mimeData);
        InputStream is = new ByteArrayInputStream(decoded);
        if (prefix == 'Z') {
            is = new GZIPInputStream((InputStream)is);
        }

        InputStream is = new BufferedInputStream((InputStream)is);
        ObjectInputStream ois = new ResolvingObjectInputStream(this._resolver, is);
        Object result = ois.readObject();
        ois.close();
        return result;
    } catch (Exception var9) {
        throw new ApplicationRuntimeException(IoMessages.decodeFailure(var9), var9);
    }
}
```

sp 传入的字符串会采用 base64 进行解码，如果 prefix 为 Z 会进行 GZIP 解压缩，并将相关字节数据存储到 反序列化 ObjectInputStream 对象中，通过 readObject() 方法进行反序列化操作，如下  
![image.png](https://cdn.nlark.com/yuque/0/2022/png/2389403/1651165890193-63edbb0a-4aec-47d3-908c-8bf27eb80dd2.png#clientId=u788c7a0e-c3af-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=584&id=u9744f457&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1168&originWidth=1894&originalType=binary&ratio=1&rotation=0&showTitle=false&size=1234728&status=done&style=none&taskId=uf80592f4-8538-407a-8bb3-a89fba17ce1&title=&width=947)

0x04 参考
=======

[https://xz.aliyun.com/t/11226](https://xz.aliyun.com/t/11226#toc-5)  
<https://github.com/codepreplabs/tapestry4Tutorial>