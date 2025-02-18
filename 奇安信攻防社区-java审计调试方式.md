0x00 前言
=======

在审计Java项目时，最理想的情况是我们拿到源码，并且可以直接运行调试；但也有很多时候，我们只能拿到一个Jar包、class文件等。这时候没法直接调试，需要我们用remote attach方式调试；也有一种情况是有源码也有jar包，但直接用源码编译时会报依赖错误很麻烦。为了能直接调试现成的jar包，也可以使用remote attach加依赖库的方式；还有一种情况是为了调试Java的native方法，查看native方法的C/C++实现。下文会一一描述。

0x01 调试无源码Jar包
==============

这种一般是SpringBoot打包的Jar包。调试过程比较简单，分为三步：

1. java命令增加调试参数`-Xdebug -Xrunjdwp:transport=dt_socket,server=y,address=5005,suspend=n`
2. IDEA拉入Jar包作依赖
3. IDEA配置`Remote JVM Debug`

下面以一个简单的SpringBoot Web程序为例。

首先在启动时，手动指定调试参数：

`java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar .web.jar`

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a565e08a9453fd7c125fcbc2b6e403b939f084d3.png)

当输出`Listening for transport dt_socket at address: xxxx`时，表示远程调试端口已经开放

接下来查看要调试的Jar包结构，一般SpringBoot打包出来的Jar包是这样的：

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-22505f2181cac4f584361cc5367e8a47411e90dd.png)

程序的class文件都在`BOOT-INF/classes`下。如果我们给IDEA添加依赖是直接将整个Jar包添加进去的话，会导致下面调试时断点停不下。**我猜测**这是因为IDEA映射类路径不正确：IDEA将整个Jar包当作了一个class path。假设我们有一个类路径为`com.pp.A`，但实际在Jar包的路径为`BOOT-INF/classes/com/pp/A`。IDEA映射Jar包类路径时，就会将当作`BOOT-INF.classes.com.pp.A`，自然就没法和`com.pp.A`对应上，也就没法下断点调试了。

解决方式就是添加依赖时，要添加**Jar包里`BOOT-INF/classes`**作为依赖，即可正常调试。

配置IDEA。先用IDEA新建一个空项目。然后在"File -&gt; Project Structure -&gt; Project Settings -&gt; Libraries"中添加一个Java库依赖，依赖选择程序Jar包中的`BOOT-INF/classes`

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ecdc60211d5d12b79252502c1e80c93412f93320.png)

添加完毕后可以发现，在左侧依赖库侧边栏中显示了这个依赖。

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2e91eee2139435042014cf505f6debb57e9e29bf.png)

jar包中的`BOOT-INF/lib`目录同样也值得我们关注，我们也需要将这些Jar包添加进依赖里。由于这些都是第三方依赖库，Jar包中直接就是类路径：

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f757c82a8317211b0ea22858dba0a6972909e76d.png)

我们直接将这些jar包解压出来，然后全选这些jar包添加进依赖即可。

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4219206a6edbbfc34d3e463e0375ba4a3e20df2e.png)

依赖配置完毕后，接下来就是配置IDEA与程序远程端口的连接。在IDEA右上角的"Add Configuration -&gt; 添加Remote JVM Debug"进行配置

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-13ac32c054dacc18014d63da34f84152b047c4a8.png)

配置完毕后，直接点击调试按钮。会发现控制台处显示`Connected`字样。这里需要注意下，IDEA端使用的JDK版本最好和程序运行的JDK版本一致。

随后就能像普通有源码的程序一样正常调试了。

0x02 调试无源码Web中间件
================

常见的Web中间件有tomcat、weblogic、jetty等。一般通过修改他们的配置文件来开放远程调试，修改配置的方式大同小异，基本都是添加`JAVA_OPTS`调试参数。下面以tomcat为例：

调试过程也很简单，分为三步：

1. `catalina.sh`或`catalina.bat`增加调试参数`-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005`
2. IDEA拉入`/classes`作依赖
3. IDEA配置`Remote JVM Debug`

配置Tomcat，Windows下找到`/bin/catalina.bat`，Linux下找到`/bin/catalina.sh`。然后在第二行添加

```java
#Windows
set JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"

#Linux
export JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
```

随后运行`/bin/startup.bat`或`/bin/startup.sh`启动tomcat

在IDEA中，将webapp的`WEB-INF/classes`的class文件和`WEB-INF/lib`中的jar包作为依赖路径。

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-865548298495f97d1e355177eb11d7870e4f64d8.png)

随后配置remote JVM Debug，调试后断点，就能正常调试了。

其他中间件的调试方式：  
[jboss](http://t.zoukankan.com/duanxz-p-2852961.html)  
[jetty](https://blog.csdn.net/hoho_12/article/details/120831597)  
[weblogic](https://blog.csdn.net/zflovecf/article/details/79136283)

0x03 无源码调试中加入源码依赖
=================

这种情况多见于调试各大组件、中间件。如调试tomcat，若自己手动编译调试会很麻烦，也许会遇到依赖报错、也许会在编译时等待较长时间。为了减少麻烦，直接以上文调试无源码的方式调试是最方便的，但为了能看真正的源码，看到注释等信息。我们还需要提供对应的源码，以供IDEA进行映射。

以上文的tomcat环境为例。我们若想看到tomcat的源码，要如何操作呢？

首先先去[tomcat的镜像站](https://dlcdn.apache.org/tomcat/)下载对应版本的tomcat源码包。一般源码包的文件名为`xxx-src.zip`

下载完毕后，可以看到源码包的结果如下

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-5744cedf83163bd69036a623333d63ae83159f0d.png)

其中`java`目录里面放的就是tomcat java代码。下面要添加的依赖路径就是它。

在IDEA中，首先需要先加入tomcat jar包的依赖。tomcat jar包就在tomcat目录下的`lib`目录中；然后再添加tomcat java源码依赖，这样IDEA才会将源码对应到依赖上

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7b282fe8b97644286c3d8795e48b7f310d159da8.png)

调试时点到tomcat的调用栈中，可以发现源码已经对应上，可以查看代码注释了

0x04 无源码调试中全局搜索问题
=================

如果我们只是单纯的将Jar包拉入依赖，是没法使用全局搜索的，搜不到程序代码片段里的字符串。

应对这种方式，我们需要将Jar包批量反编译，然后再放到IDEA的Project目录下，这样IDEA全局搜索时便能搜索到。

可以使用诸如[jad](https://github.com/skylot/jadx)、[jd-gui](https://github.com/java-decompiler/jd-gui)等工具进行批量反编译，也可以编写脚本批量调用IDEA的`java-decompiler.jar`进行批量反编译。

反编译后得到的"java源码文件"可以放在IDEA的`src`目录下。这样全局搜索的时候，就能搜索到代码片段了。

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-da3136b2977c6b60b5f21cded878076f75ff0ddd.png)

搜索到代码片段后，再根据所在类的全类名和方法名，使用IDEA快捷键`Ctrl+N`即可定位类文件

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-dd9711e06d39bac725d694763d09ede80e59594c.png)

0x05 调试Java Service Wrapper
===========================

有些较大型的程序如[zoho的项目](https://www.manageengine.com/products.html)，是使用wrapper进行打包和运行的。关于wrapper的介绍可以看[这篇文章](https://www.hnbian.cn/posts/3431afe6.html)

调试wrapper打包的程序和调试上文Web中间件步骤差不多，都需要修改配置文件，wrapper的配置文件一般是`/conf/wrapper.conf`。在该文件中可以看到很多这样的配置：

```properties
wrapper.java.additional.37=-XX:+UseG1GC
wrapper.java.additional.38=-XX:+UseStringDeduplication
wrapper.java.additional.39=-XX:+PrintStringDeduplicationStatistics
wrapper.java.additional.40=-XX:StringDeduplicationAgeThreshold=3
.....
```

这是在设置java参数，后面的数字表示这是第几个java参数，也就是参数序号。我们只需要顺着添加远程调试的java参数即可

```properties
#顺着序号添加
wrapper.java.additional.44=-Xdebug
wrapper.java.additional.45=-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=23333
.....
```

配置完毕后再启动wrapper的服务，按照上文的步骤将jar包作为依赖添加到IDEA中，最后启动调试即可。

0x06 调试native方法
===============

为了跟进调试native方法，我们可以尝试使用IDEA和CLion联动的方式进行调试。由于调试native方法就得自行编译jdk。具体的操作我已经在[这篇文章](https://tttang.com/archive/1525/#toc_0x02-jdk)写过，就不赘述了。