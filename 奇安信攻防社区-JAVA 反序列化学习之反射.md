0x00前言
======

无论看的是什么文章，只要是学习 JAVA 反序列化的文章，就一定会提到反射机制，这里结合了文档、网上的各种资料、P 牛的 JAVA 安全漫谈，写成了一篇还算过得去的文章。

但这仅仅是 JAVA 安全的开始，甚至只是 JAVA 安全中一个漏洞的一部分的开始。

道阻且艰。

0x01反射机制
========

简介
--

Oracle 官方对反射的解释是：

> Reflection enables Java code to discover information about the fields, methods and constructors of loaded classes, and to use reflected fields, methods, and constructors to operate on their underlying counterparts, within security restrictions.
> 
> The API accommodates applications that need access to either the public members of a target object (based on its runtime class) or the members declared by a given class. It also allows programs to suppress default reflective access control.

Java 反射机制的核心是在程序运行时动态加载类并获取类的详细信息，从而**操作类或对象的属性和方法**。本质是 JVM 得到 class 对象之后，再通过 class 对象进行反编译，从而获取对象的各种信息。

能够实现一些功能，**比如：**

- 在运行时判断任意一个对象所属的类
- 在运行时构造任意一个类的对象
- 在运行时判断任意一个类所具有的成员变量和方法
- 在运行时调用任意一个对象的方法

- - - - - -

开始
--

在 P 牛的 Java 安全漫谈的开篇里是这么描述的：

> 反射是⼤多数语⾔⾥都必不可少的组成部分，对象可以通过反射获取他的类，类可以通过反射拿到所有⽅法（包括私有），拿到的⽅法可以调⽤，总之通过“反射”，我们可以将 Java 这种静态语⾔附加上**动态特性**。

而关于动态特性，我们可以简单地理解为可以被攻击者恶意利用。

⽐如，P 牛举例的这样一个危险的方法：

```java
public void execute(String className, String methodName) throws Exception {
     Class clazz = Class.forName(className);
     clazz.getMethod(methodName).invoke(clazz.newInstance());
}
```

上⾯的例⼦中，存在着⼏个在反射⾥极为重要的⽅法，几乎涵盖了 Java 安全中各种和反射有关的 payload：

- 获取类的⽅法： `forName`
- 实例化类对象的⽅法： `newInstance`
- 获取函数的⽅法： `getMethod`
- 执⾏函数的⽅法： `invoke`

接下来依次分析：

Class.forName
-------------

`Class.forName`：**返回一个给定类或者接口的一个 Class 对象**，如果没有给定 classloader， 那么会使用根类加载器。如果 initalize 这个参数传了 true(`Class.forName(String className)` 默认为 true )，那么给定的类如果之前没有被初始化过，那么会被初始化。

另外还有一个小特点：在正常情况下，除了系统类，如果我们想拿到一个类，需要先 import 才能使用。而使用 forName 就不需要，这样对于我们的攻击者来说就十分有利，我们可以**加载任意类**。这可以对我们的攻击起到很大的便利。

对于大部分人来说，第一次见到 **class.forName(String className)** 这句代码应该是在使用 **JDBC** 方式连接数据库的时候。

```java
import com.mysql.jdbc.Driver;
import java.sql.*;

    public class JdbcDemo {
        public static void main(String[] args) throws SQLException, ClassNotFoundException {
        String url = "jdbc:mysql://127.0.0.1:3306/mydb";
        String username = "root";
        String password = "redhat";
        Class.forName("com.mysql.jdbc.Driver"); //这里
        Connection connection = DriverManager.getConnection(url, username, password);
        String sql = "SELECT * FROM msg";
        PreparedStatement prepareStatement = connection.prepareStatement(sql);
        ResultSet resultSet = prepareStatement.executeQuery();
        resultSet.next();
        String address = resultSet.getString("address");
        System.out.println(address);
    }
}
```

这里通过 **Class.forName** 传入 com.mysql.jdbc.Driver 之后，就判断了连接的数据库为 mysql 数据库

问一个为什么，然后去[文档](https://docs.oracle.com/javase/7/docs/api/java/lang/Class.html#forName(java.lang.String))里查找

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-76f11385e3013c8d5cf090cf4a1d9f54296cfabd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c8e7a2d5c9b96272910e45fe33b0fafdedbda813.png)

存在两个 `forName` 方法

第一种就是上面代码中的用法，`Class.forName(String className)`，参数 name 表示的是类的全名，则相当于后面的 `Class.forName(String name, boolean initialize, ClassLoader loader)` 用法中设置了参数 initialize 的值为 true，loader 的值为当前类的类加载器。

参数 initialize 是一个 bool 值，表示是否初始化，参数 ClassLoader 是一个“加载器”，它告诉 JVM 如何加载这个类。Java 默认的 ClassLoader 就是根据类名来加载类，这个类名是类完整路径，如 java.lang.Runtime，但是之类还有很多有趣的漏洞利用方法，后续会进一步学习。

也就是说上面的代码中，这里传入的类为 `com.mysql.jdbc.Driver` ，我们可以找到这里的这个类

```java
public class Driver extends NonRegisteringDriver implements java.sql.Driver {

static {
    try {
        java.sql.DriverManager.registerDriver(new Driver());
    } catch (SQLException E) {
        throw new RuntimeException("Can't register driver!");
    }
}

    public Driver() throws SQLException {
    // Required for Class.forName().newInstance()
    }
}
```

这个类的代码非常简短。

在这个类被初始化(为什么初始化前面有写)后，静态代码块的内容会被执行。也就是说我们 **Class.forName** 和直接写 **DriverManager.registerDriver(new Driver)** 两者功能是等同的，实际上替换一下之后，代码的功能也是不变的。

### 获取类对象的其他函数

上面只是一个便于理解 forName 的例子。

实际上 `forName` 并不是获取列的唯一途径，一般情况下会有以下三种方式，也就是有三种方式可以得到 Class 的对象 `java.lang.Class` 类的对象。

#### java.lang.Class 类

Java 程序运行时，系统一直对所有的对象进行所谓的运行时类型标识。这项信息纪录了每个对象所属的类。虚拟机通常使用运行时类型信息选准正确方法去执行，用来保存这些类型信息的类是 Class 类。Class 类封装一个对象和接口运行时的状态，当装载类时，Class 类型的对象自动创建。说白了，Class 类对象就是封装了一个类的类型信息，可以通过该对象操作其对应的类，即反射机制。

我们的三个获取对象的方法都来源于 Class 类

- `obj.getClass()` 如果上下⽂中 **存在某个类的实例 obj** ，那么我们可以直接通过 `obj.getClass()` 来获取它的类
    
    ```java
    MyObject x;
    Class c1 = x.getClass();
    ```
- `Test.class` 如果你已经加载了某个类，只是想获取到它的 `java.lang.Class` 对象，那么就直接拿它的 class 属性即可。这个⽅法其实不属于反射。
    
    ```java
    Class cl1 = Manager.class;
    Class cl2 = int.class;
    Class cl3 = Double[].class;
    ```
- `Class.forName` 如果你知道某个类的名字，想获取到这个类，就可以使⽤ forName 来获取
    
    ```java
    Class c2=Class.forName("MyObject");
    ```

#### 初始化

这里是在看完 JAVA 安全漫谈后的进一步认识与学习。

```java
public class TrainPrint {

    {
        System.out.printf("Empty block initial %s\n", this.getClass());
    }

    static {
        System.out.printf("Static initial %s\n", TrainPrint.class);
    }

    public TrainPrint() {
        System.out.printf("Initial %s\n", this.getClass());
    }

}
```

这里是三种不完全一致的初始化的方法。

分别通过两种方法输出来测试一下：

```java
public static void main(String[] args) throws IOException, ClassNotFoundException {
    Class.forName("TrainPrint");  //刚刚说到的初始化
}

public static void main(String[] args) throws IOException, ClassNotFoundException {
   TrainPrint test= new TrainPrint();  //new关键字的实例化
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-43971538dbf242b2d848268f6698c7547bbc947b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3378bb01b432033e4f01555f4571ccbd2300f704.png)

可以发现：

> 类的实例化：`static {}`-&gt;`{}`-&gt;`构造函数`  
> 类的初始化：`static {}`
> 
> 下面是另一个师傅探寻的加上父类的情况：
> 
> 具有父类的类的实例化：`父类静态初始块`-&gt;`子类静态初始块`-&gt;`父类初始块`-&gt;`父类构造函数`-&gt;`子类初始块`-&gt;`子类构造函数`  
> 具有父类的类的初始化：`父类静态初始块`-&gt;`子类静态初始块`

所以说， forName 中的 `initialize=true` 其实就是告诉 Java 虚拟机是否执⾏ 类初始化，而不是 实例化，要注意这两个是不同的。

#### 利用

假设存在这样一个函数，并且其中的参数 name 我们可控

```java
public void ref(String name) throws Exception {
    Class.forName(name);
}
```

那么我们就可以编写一个恶意类，利用初始化来执行我们编写的恶意类中的 `static` 块中的恶意代码

```java
import java.lang.Runtime;
import java.lang.Process;
public class TouchFile {
     static {
         try {
             Runtime rt = Runtime.getRuntime();
             String[] commands = {"touch", "/tmp/success"};
             Process pc = rt.exec(commands);
             pc.waitFor();
         } catch (Exception e) {
             // do nothing
         }
     }
}
```

这个恶意类如何带⼊⽬标机器中，可能就涉及到 ClassLoader 的⼀些利⽤⽅法了，后续再进行学习

#### foeName 调用内部类

另外，我们经常在一些源码里看到，类名的部分包含 `$` 符号，比如 fastjson 在 checkAutoType 时候就会先将 `$` 替换成 `.`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-546800137895a3504d0da550a9d1d434bb3bbf4a.png)

`$` **的作用是查找内部类**

Java 的普通类 C1 中支持编写内部类 C2 ，而在编译的时候，会生成两个文件： `C1.class` 和 `C1$C2.class` ，我们可以把他们看作两个无关的类，通过 `Class.forName("C1$C2")` 即可加载这个内部类。

获得类以后，我们可以继续使用反射来获取这个类中的属性、方法，也可以实例化这个类，并调用方法。

这里只是简单的记下来了 P 牛的经验，自己由于缺少相应的操作与挖掘，只能说是浅显的记了一下，但是后续会尝试分析各种链，到时候像这样的问题多半会迎刃而解的。

### Class.newInstance

这个方法就比较好理解了。

和 PHP 中一样，new 是 JAVA 中的一个非常常用的关键字，可能也是每一门面向对象编程语言中都非常常用的关键字，是用来创建类的实例化的，同时也会起到让对象初始化的效果，当然初始化还是取决于被实例化类中的内容。形式如下：

```java
Object obj=new Object();
```

在 JAVA 语言的环境下，这种语句会先调用 new 指令生成一个对象，然后调用 dup 来复制对象的引用，最后调用 Object 的构造方法。

而 newInstance 并不是关键字。

`newInstance` 是 java 反射框架中类对象创建新的实例化对象的方法。在这个过程中，是先取了这个类的不带参数的构造方法，然后调用构造方法 也就是**无参构造函数** 的 newInstance 来创建对象

```java
Object java.lang.Class.newInstance();
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-af3e75fc3000954edf3c05a1347e22fe452cf477.png)

这个函数在 **Constructor** 类里还有个兄弟，`Class.newInstance()` **只能够调用无参的构造函数**，即**默认的构造函数**；但是 `Constructor.newInstance()` 可以根据传入的参数，**调用任意构造构造函数**。`Class.newInstance()` 要求被调用的构造函数是可见的，也即必须是 public 类型的，但是 `Constructor.newInstance()` 在特定的情况下，可以调用私有的构造函数，需要通过 `setAccessible(true)` 实现

```java
package com.reflect;

import java.lang.reflect.Constructor;

class TestB
{
    public  TestB()
    {
        System.out.println("Test A");
    }
    //设置构造方法私有
    private TestB(int a,String b)
    {
        System.out.println("Test B");
    }
}
public class Test {

    public static void main(String []args) throws Exception
    {
        Test b=new Test();
        Class c=Class.forName("com.reflect.TestB");
        //无参数
        TestB b1=(TestB) c.newInstance();
        //有参数需要使用Constructor类对象
        //这种方式和下面这种方式都行，注意这里的参数类型是 new Class[]
        //Constructor ct=c.getDeclaredConstructor(int.class,String.class);
        Constructor ct=c.getDeclaredConstructor(new Class[]{int.class,String.class});
        ct.setAccessible(true);
        //这种方式和下面这种方式都可以：注意这里的参数类型是 new Object[]
        //TestB b2=(TestB) ct.newInstance(1,"2");
        TestB b2=(TestB) ct.newInstance(new Object[] {1,"2"});
    }
}
/* 运行结果
Test A
Test B
*/
```

#### 关于 newInstance 利用不成功的问题

这里 P 牛提到了可能的两种原因：

1. 你使用的类没有无参构造函数
2. 你使用的类构造函数是私有的

P 牛 用一串代码举例：

```java
Class clazz = Class.forName("java.lang.Runtime");
clazz.getMethod("exec", String.class).invoke(clazz.newInstance(), "id");
```

这里会报错，因为是 Runtime **类的构造方法是私有的**

这里我也会疑惑，为什么会让构造方法写成私有的，感觉有一些不合逻辑，这里涉及到了一些开发中的思想。

P 牛解释，这里是一种叫”单例模式“的设计模式，激励是数据库的链接，数据库只需要链接一次，如果可以多次调用的话可能就会导致错误建立了多个数据库链接，作为开发者，这个时候就可以将类的构造函数设置为私有，然后编写一个静态方法

```java
public class TrainDB { 
    private static TrainDB instance = new TrainDB(); 

    public static TrainDB getInstance() { 
        return instance; 
    }

    private TrainDB() { 
        // 建立连接的代码... 
    } 
}
```

这样，只有类初始化的时候会执行一次构造函数，后面只能通过 getInstance 获取这个对象，避免建立多个数据库连接。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8730fa513ab434d26048334bdd2a5511c464c766.png)

这里的 Runtime 类就是单例模式，我们只能通过 Runtime.getRuntime() 来获取到 Runtime 对象。（不能去实例化类了，就直接调用已经实例化的对象的方法，感觉这里非常的流氓）

```java
Class clazz = Class.forName("java.lang.Runtime");
clazz.getMethod("exec", String.class).invoke(clazz.getMethod("getRuntime").invoke(clazz), "calc.exe");
```

这里就是利用了下面的两个方法实现的对对象中的方法进行调用的一串代码。

### getMethod

`getMethod` 返回一个 Method 对象，它反映此 Class 对象所表示的类或接口的指定 **Public** 方法

getMethod 方法的作用就是通过 Class 实例获取所有 `Method` 信息。

一个 `Method` 对象包含一个方法的所有信息：

- `getName()`：返回方法名称，例如：`"getScore"`；
- `getReturnType()`：返回方法返回值类型，也是一个 Class 实例，例如：`String.class`；
- `getParameterTypes()`：返回方法的参数类型，是一个 Class 数组，例如：`{String.class, int.class}`；
- `getModifiers()`：返回方法的修饰符，它是一个 `int`，不同的 bit 表示不同的含义。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d2db495f090e01116013eece89f5b9e32e566cf8.png)

方法的格式为 `Method getMethod(String name,Class...parameterTypes)` 参数 name 就是方法，或者说函数的名称，`parameterTypes` 是 method 的参数类型的列表，这里要多说两句，在 JAVA 中支持类的重载（在一个类中，方法名相同但参数不用，最常用的就是构造器的重载），所以**我们不能够仅仅通过函数名来确定一个函数**，`parameterTypes` 这个参数是我们能够调用我们想要的方法的参数，并不是之前 PHP 中的调用了方法后方法中的参数，两个条件框定了方法之后 getMethod 就会返回符合 method 名称和参数的 method 对象。例子：

```java
Method execMethod = clazz.getMethod("exec", String.class);
Method getRuntimeMethod = clazz.getMethod("getRuntime");
```

Runtime.exec 方法重载的例子

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-21d715a29382169ec77d3facb9edfdb0f04364a6.png)

### invoke

invoke 属于 Method 类，作用就是对方法进行调用，也比较好理解

`Object invoke(Object obj,Object...args)`，参数 obj 是实例化后的对象，args 为**用于方法调用的参数**

这里要注意 ：

- 如果这个方法是一个普通方法，那么第一个参数是类对象
- 如果这个方法是一个静态方法，那么第一个参数是类
    
    但实际上这里又不是这么死板的，这里可以有一些灵活的操作，invoke 对 obj 的校验实际上是非常不严格的，这里由于 `invoke` 函数 null 抛出报错的机制，存在一些神奇的 tricks，后续会提到。

这里就是我们搞到的要执行的方法的类和执行的方法中的参数了

大概就是 P 牛刻画的这样一个关系：`[1].method([2], [3], [4]...)` ，`method.invoke([1], [2], [3], [4]...)`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-dcddef9eb6d3234480b2bc6c56220425328d6608.png)

### back

理解玩这些个方法之后再回过头来看 P 牛的例子，就可以明白这到底是多么危险的一段代码了

```java
public void execute(String className, String methodName) throws Exception {
 Class clazz = Class.forName(className);
 clazz.getMethod(methodName).invoke(clazz.newInstance());
}
```

我们根据上面一直在使用的 Runtime 中的 exec 方法来代入这里，

```java
Class clazz = Class.forName("java.lang.Runtime");
clazz.getMethod("exec", String.class).invoke(clazz.getMethod("getRuntime").invoke(clazz), "calc.exe");
```

这串代码简直美丽极了。

我们首先用 `forName` 方法获取了 `java.lang.Runtime` 类的实例化对象然后赋给了 clazz ，`java.lang.Runtime` 类中有我们要利用的 `exec` 方法，然后我们可以通过 `getMethod` 来获取我们要的参数为 `String` 的那个可以利用的 `clac` 方法，然后再进一步利用 `.invoke` 来调用能够实现命令执行的方法，这里又由于单例模式下 newInstance 无法调用类的构造方法进行实例化，所以只能通过 Runtime.getRuntime() 来获取到 Runtime 对象，再敲上我们最后的要执行的参数 clac.exe ，这个恶意的 payload 就构造好了。

也算是这里这道题目的一个从 0 开始的讲解了吧 <http://rui0.cn/archives/1015> 在安全研究中，我们使⽤反射的⼀⼤⽬的，就是绕过某些沙盒。⽐如，上下⽂中如果只有Integer类型的数字，我们如何获取到可以执⾏命令的Runtime类呢？也许可以这样（伪代码）： 1.getClass().forName("java.lang.Runtime")

那么这样的话，我们就 Get 了利用反射从任意类中调用任意方法的 trick 了！！当然还存在很多很多的问题，还有待进一步的学习，但是到这里还是先做一个小结好了~