0x00 前言
=======

SSTI:Server Side Template Injection，即服务端模板注入。  
在web开发中，为了使用户界面与业务数据分离，提升开发效率，因此会使用模板引擎来生成一个标准的HTML文档用来数据的展示。  
本文主要针对java中Velocity、FreeMarker以及Thymeleaf三个模板的注入漏洞进行分析

0x01 velocity
=============

1.1 Velocity简介
--------------

Apache Velocity是一个基于Java的模板引擎，它提供了一个模板语言去引用由Java代码定义的对象。Velocity旨在确保Web应用程序在表示层和业务逻辑层之间的隔离（即MVC设计模式）。  
**语法概要**  
在 Velocity 中所有的关键字都是以#开头的，而所有的变量则是以$开头  
"#"用来标识Velocity的脚本语句，包括#set、#if 、#else、#end、#foreach、#end、#iinclude、#parse、#macro等；  
"$"用来标识一个对象(或理解为变量)；如$i、$msg、$TagUtil.options(...)等；  
"{}"用来明确标识Velocity变量；  
"!"用来强制把不存在的变量显示为空白；

1.2 漏洞利用
--------

环境：java-sec-code（<https://github.com/JoyChou93/java-sec-code/>）  
服务端代码：

![1.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-fa2c76fb7ead19fb69155f258d1e843e4d114f3f.jpg)

访问/ssti/velocity?template=并提交payload

![2.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8f1d29ce8a8191129ec8dd889274bcb0577d64f3.jpg)

断点进行拦截提交的payload，并跟进Velocity.*evaluate方法进行分析*

![3.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ebc85653c80bc325485ce15d3fe70ef635997c3d.jpg)

继续跟进evaluate方法

![4.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c33ba84194ecd9c1b75a4933faaf167f000f7d22.jpg)

RuntimeInstance类中封装了evaluate方法

![5.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-6039895814b029bf0d5244dc57fd6a45febfd7a5.jpg)

继续跟进分析，可以看到parse方法对reader进行解析

![6.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7c45a1654166c3edf2bff63a4c57cb15a3dfa6a9.jpg)

跟进分析，可以看出进行一次判断，如果nodeTree不为空则进入render方法

![7.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-adef6c44bfe1edd118b78fe2cf0a4dfcb921a361.jpg)

继续跟进分析，多次循环后会进行execute方法下进行for循环，进行payload的遍历

![8.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-2b42e9cca81b19b216bee2df5542542fae82eb88.jpg)

遍历完成后命令成功执行

![9.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-81343845fc3ad82456771345d354ce7f3127af40.jpg)

0x02 FreeMarker
===============

2.1 FreeMarker简介
----------------

FreeMarker 是一款模板引擎：即一种基于模板和要改变的数据， 并用来生成输出文本(HTML网页，电子邮件，配置文件，源代码等)的通用工具。 它不是面向最终用户的，而是一个Java类库，是一款程序员可以嵌入他们所开发产品的组件。

![10.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-55b710aa6d704da57f18300137f308812dd6e63c.jpg)

当需要一个类似Output的页面时，就可以利用FreeMarker模板代码来进行生成。  
FreeMarker模板代码：

```java
<html>
<head>
    <title>Welcome</title>
</head>
<body> 
    <h1>Welcome ${user}!</h1>
</body>
</html>
```

模板文件存放在Web服务器上，就像通常存放静态HTML页面那样。当有人来访问这个页面， FreeMarker将会介入执行，然后动态转换模板，用最新的数据内容替换模板中 ${...} 的部分， 之后将结果发送到访问者的Web浏览器中。  
FreeMarker模板注入主要利用freemarker.template.utility里面的Excute类来执行命令，利用FreeMarker中的内建函数new，new是用来创建一个确定的 TemplateModel 实现变量的内建函数，新建一个Excute类，并将需要执行的命令传入其中。  
具体的payload的构造按照该内建函数的用法进行构造，可以参考[http://freemarker.foofun.cn/ref\_builtins\_expert.html#ref\_builtin\_new](http://freemarker.foofun.cn/ref_builtins_expert.html#ref_builtin_new)，具体用法如下：

```python
<#-- Creates an user-defined directive be calling the parameterless constructor of the class -->
<#assign word_wrapp = "com.acmee.freemarker.WordWrapperDirective"?new()>
<#-- Creates an user-defined directive be calling the constructor with one numerical argument -->
<#assign word_wrapp_narrow = "com.acmee.freemarker.WordWrapperDirective"?new(40)>
```

2.2 漏洞利用
--------

服务端代码：

![11.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-620e778429f53422b390fdfcc8c709ed33c1179a.jpg)

模板代码：

![12.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c136e852faf07464b04ee0ebfee0ac3b9717e500.jpg)

```python
payload：<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("calc") }
```

请求/hello获取模板，可以看出成功实现，对应数据提交到了模板中展示

![13.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-fd026bc40bc608e56de4ec4dbd7410e434bd0b6f.jpg)

构造payload，请求/template

![14.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c2a65028fed7227993cc545535c9bf89872ff7f2.jpg)

post提交payload，注入恶意模板代码，并在for循环中进行断点调试

![15.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-fa776d86164652f104b153d50140fc514a4a6238.jpg)

可以看出stringLoader，也就是StringTemplateLoader函数下的putTemplate通过key:value的形式获取到传入的payload，达到注入hello.ftl的效果

![16.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ebceef7a7db4a4ada57d9c590eaf1969858d400c.jpg)

再访问/hello获取模板，达到恶意代码执行的效果。

![17.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0c6466e3757ee3b7021b2ef93950a15d72798476.jpg)

0x03 Thymeleaf
==============

3.1 Thymeleaf简介
---------------

Thymeleaf是springboot官方推荐使用的java模板引擎,提供spring标准方言和一个与 SpringMVC 完美集成的可选模块，可以快速的实现[表单](https://so.csdn.net/so/search?q=%E8%A1%A8%E5%8D%95&spm=1001.2101.3001.7020)绑定、属性编辑器、国际化等功能。  
**Thymeleaf简单表达式：**

- 变量表达式： ${...}
- 选择变量表达式： \*{...}
- 消息表达式： #{...}
- 链接网址表达式： @{...}
- 片段表达式： ~{...}

简单的Thymeleaf模板代码

```python

<html xmlns:th="http://www.thymeleaf.org">
  <head>
    <title>Good Thymes Virtual Grocery</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <link rel="stylesheet" type="text/css" media="all" 
          href="../../css/gtvg.css" th:href="@{/css/gtvg.css}" />
  </head>
  <body>
    <p th:text="#{home.welcome}">Welcome to our grocery store!</p>  
  </body>
</html>
```

3.2 漏洞利用
--------

环境：spring-view-manipulation（<https://github.com/veracode-research/spring-view-manipulation/>）  
服务端代码：

![18.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-bda975de422b756529b945da0cd0ec045a5fd867.jpg)

模板代码：

![19.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-bb94663f0bc35c4ada0b8afcb0e67a3eb0b665ea.jpg)  
**漏洞利用方法一：**

```python
payload:__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22calc%22).getInputStream()).next()%7d__::.x
uri:/path?lang=__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22calc%22).getInputStream()).next()%7d__::.x
```

![20.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c64bb433b5a3aba802e55b69c8ba8fbeac8405e1.jpg)

进行数据提交，成功获取到提交的payload

![21.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-58fe435422f3c6ae9c0c745f10ee8c6305da05f7.jpg)

进行跟进，在 org.thymeleaf.spring5.view 中的 ThymeleafView类中thymeleaf 在解析包含 :: 的模板名时，会将其作为表达式去进行执行

![22.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-2e314f265becc5ba1665c9240d578b7406ed870c.jpg)

继续跟进，在StandarExpressionPreprocessor类中利用正则对\_\_(.\*?)\_\_进行匹配，也就是payload\_\_中间的内容

![23.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-75fc1f6e10276c3a3c9ed3cf3b2dbba50598580f.jpg)

匹配处理完成后为${new.java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("calc").getInputStream()).next()}

![24.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5aada6175baf005c807753abb97db66246af02d9.jpg)

继续跟进execute

![25.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-2ad3a19f49b2a8c9ade5db98295cca3788c74ea0.jpg)

可以看到是使用的SPEL 引擎，满足**(${SPEL})**::格式达到注入的效果

![26.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f9ff83c59dd2c56e33424616a359249ad7c429f6.jpg)

进入后成功执行代码

![27.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0465f78bc23d2be7db5cd9f44cddb43e3074a186.jpg)  
**漏洞利用方法二：**

```python
payload:__$%7BT(java.lang.Runtime).getRuntime().exec(%22calc%22)%7D__::.x
uri:/doc/__$%7BT(java.lang.Runtime).getRuntime().exec(%22calc%22)%7D__::.x
```

![28.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-16677bb79d9a8ce4d17d809d58c4b0838376582a.jpg)

因为该请求无返回值，因此返回值无法作为模板名，这个时候传入的参数也就是payload便作为了视图名

![29.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-26f07f31407ad25cf185b83dfdf213577c042b92.jpg)

进行跟进，在 org.thymeleaf.spring5.view 中的 ThymeleafView类中thymeleaf 在解析包含 :: 的模板名时，会将其作为表达式去进行执行

![30.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a160fda4974c831c65cf8faa1f70ffdfdf5d572a.jpg)

继续跟进，在StandarExpressionPreprocessor类中利用正则对\_\_(.\*?)\_\_进行匹配，也就是payload\_\_中间的内容，匹配处理完成后为${T(java.lang.Runtime).getRuntime().exec(%22calc%22)}

![31.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-536b0c617a13b09a384cb45ebb3bf70cc8eb6551.jpg)

可以看到是使用的SPEL 引擎，满足**(${SPEL})**::格式达到注入的效果

![32.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7433fb4664c8a44f012f704f0f56eda120ecc118.jpg)