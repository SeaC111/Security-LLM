记详细的Java代码审计
============

过滤器简介
-----

Filter也称之为过滤器，它是Servlet技术中最实用的技术，WEB开发人员通过Filter技术，对web服务器管理的所有web资源：例如Jsp, Servlet, 静态图片文件或静态 html 文件等进行拦截，从而实现一些特殊的功能。例如实现URL级别的权限访问控制、过滤敏感词汇、压缩响应信息等一些高级功能。它主要用于对用户请求进行预处理，也可以对HttpServletResponse 进行后处理。

过滤器运行原理
-------

当客户端向服务器端发送一个请求时，如果有对应的过滤器进行拦截，过滤器可以改变请求的内容、或者重新设置请求协议的相关信息等，然后再将请求发送给服务器端的Servlet进行处理。当Servlet对客户端做出响应时，过滤器同样可以进行拦截，将响应内容进行修改或者重新设置后，再响应给客户端浏览器。在上述过程中，客户端与服务器端并不需要知道过滤器的存在。  
在一个Web应用程序中，可以部署多个过滤器进行拦截，这些过滤器组成了一个过滤器链。过滤器链中的每个过滤器负责特定的操作和任务，客户端的请求在这些过滤器之间传递，直到服务器端的Servlet。具体执行流程如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8eff86b564858386248054f1195e67ad06cb26c7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8eff86b564858386248054f1195e67ad06cb26c7.png)  
简单的来说就是我们请求的数据先通过过滤器，在通过服务器。所以在Java代码审计过程中，对过滤器的分析是相当重要的，当然过滤器的构成分为以下两种：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc17a5e8b87da0323eb4717cdeeefe9fa8bba4ae.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc17a5e8b87da0323eb4717cdeeefe9fa8bba4ae.png)

jeesns1.3无框架类代码审计
-----------------

由于是无框架类，所以查找web.xml文件,寻找到web.xml后，查找xss过滤代码，很明显一下就可以看出下列为xss过滤器代码

```php
<filter>
    <filter-name>XssSqlFilter</filter-name> //过滤器名字
    <filter-class>com.lxinet.jeesns.core.filter.XssFilter</filter-class> //过滤代码存储的地方，分为内部和外部
</filter>
<filter-mapping>
    <filter-name>XssSqlFilter</filter-name>
    <url-pattern>/*</url-pattern>  //过滤器检测的网址，这里为任意网址
    <dispatcher>REQUEST</dispatcher>
</filter-mapping>
```

根据上述的寻找`com.lxinet.jeesns.core.filter.XssFilter`xss过滤器文件，分析代码，主要内容是创建了一个对象XssHttpServletRequestWrapper，调用XssHttpServletRequestWrapper对象中的方法进行过滤

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-763a8cb6de949c50cb0218208b7bb48b64826931.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-763a8cb6de949c50cb0218208b7bb48b64826931.png)

搜索为什么没有发现这个对象了，那是因为在加载项目的时候，很多都还是jar包文件，并没有进行反编译，所以搜索不到，此时需要对jar包进行反编译，并且重新载入到项目中

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1fed034f56f8fdd21b029a5dc43cca10ef6417e7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1fed034f56f8fdd21b029a5dc43cca10ef6417e7.png)

查找到XssHttpServletRequestWrapper.java文件后， 发现在过滤时并不严谨，并未使用正则表达式进行过滤，而只是过滤了关键字，于是想办法绕过，代码如下：

```java
package com.lxinet.jeesns.core.utils;

import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * XSS攻击处理
 * Created by zchuanzhao on 2017/3/23.
 */
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {

    public XssHttpServletRequestWrapper(HttpServletRequest servletRequest) {
        super(servletRequest);
    }

    @Override
    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
        if (values==null)  {
            return null;
        }
        int count = values.length;
        String[] encodedValues = new String[count];
        for (int i = 0; i < count; i++) {
            encodedValues[i] = cleanXSS(values[i]);
        }
        return encodedValues;
    }

    @Override
    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
        if (value == null) {
            return null;
        }
        return cleanXSS(value);
    }
    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        if (value == null) {
            return null;
        }
        return cleanXSS(value);
    }
    private String cleanXSS(String value) {
        value = HtmlUtils.htmlEscape(value);
        // 需要过滤的脚本事件关键字
        String[] eventKeywords = { "onmouseover", "onmouseout", "onmousedown",
                "onmouseup", "onmousemove", "onclick", "ondblclick",
                "onkeypress", "onkeydown", "onkeyup", "ondragstart",
                "onerrorupdate", "onhelp", "onreadystatechange", "onrowenter",
                "onrowexit", "onselectstart", "onload", "onunload",
                "onbeforeunload", "onblur", "onerror", "onfocus", "onresize",
                "onscroll", "oncontextmenu", "alert" };
        // 滤除脚本事件代码
        for (int i = 0; i < eventKeywords.length; i++) {
            // 添加一个"_", 使事件代码无效
            value = value.replaceAll("(?i)" + eventKeywords[i],"_" + eventKeywords[i]);
        }
        return value;
    }
```

### 漏洞复现

通过上面的过滤器内容，可以知道使用`<Script>prompt(/xss/)</Script>`能够绕过过滤器，此时由于是代码审计，在xss漏洞中，关注输入函数去寻找文件，访问页面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2c43c541929cd547af6b7b2ac3e1dad655f0fc62.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2c43c541929cd547af6b7b2ac3e1dad655f0fc62.png)

成功弹框

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7106d79cd4d42d1dfa6d1d285c926b573f567c5d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7106d79cd4d42d1dfa6d1d285c926b573f567c5d.png)

struts2框架类代码审计
--------------

由于此Java代码为框架类，所以先了解框架的执行流程，由搜集的资料得到执行的流程图，可知不仅有过滤器（filter）而且还有拦截器（Interceptor)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d9c55962a2fdf3ebf31899961f9d97d221816b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d9c55962a2fdf3ebf31899961f9d97d221816b2.png)  
**过滤器和拦截器的区别**  
1、Filter是基于函数回调的，而Interceptor则是基于Java反射的。  
2、Filter依赖于Servlet容器，而Interceptor不依赖于Servlet容器。  
3、Filter对几乎所有的请求起作用，而Interceptor只能对action起作用。  
4、Intercept可以访问action的上下文。值桟里的对象，而Filter不能。  
5、执行顺序为先filter后interceptor。  
另外在不同的框架中有过滤器的是自带的，有的是需要自己写的，具体根据情况查看开发资料。  
获取版本信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-59824a87f3f4287f581def6dcb16e2047d0ac8c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-59824a87f3f4287f581def6dcb16e2047d0ac8c0.png)

每个框架的拦截器配置文件不同，可以通过查找开发手册，要使用拦截器，首先要对它进行配置。再该框架类拦截器的配置是在 struts.xml 文件中完成的，它通常以 &lt;interceptor&gt; 标签开头，以 &lt;/interceptor&gt; 标签结束。定义拦截器的语法格式如下所示：

```php
<interceptor name="interceptorName" class="interceptorClass">
<param name="paramName">paramValue</param>
</interceptor>
```

查找到struts.xml文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-29945ef023eadef7b9ae2a29923bf3d17de9889b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-29945ef023eadef7b9ae2a29923bf3d17de9889b.png)

发现里面并没有以上面定义格式的拦截器，有点苦恼，想到可能存在包含文件，此时查找是否有包含文件，发现存在包含文件struts-default.xml

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bb3bd1814e066517d55e29fc1665b3a4fae0fd50.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bb3bd1814e066517d55e29fc1665b3a4fae0fd50.png)

查找到包含文件后，发现存在过滤器的定义，其实跟上述无框架类的命名规则差不多，此时就可以根据过滤器中的内容去一个一个寻找与分析代码进行绕过，操作跟无框架类的差不多

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f534d5991e6ce8c61042bb8a681b3208fd73f7cb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f534d5991e6ce8c61042bb8a681b3208fd73f7cb.png)

继续查找其他过滤器文件web.xml，根据框架查找过滤器，当访问\*.action结尾的的网页时就会触发过滤器。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-127296c6fb9deb60b8c018cc76910658c084fcef.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-127296c6fb9deb60b8c018cc76910658c084fcef.png)

访问.action结尾的网页

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e02f3a27a836676721e14186aa86f0e248c20221.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e02f3a27a836676721e14186aa86f0e248c20221.png)

并且找到该网页的文件夹，来进行断点调试，刷新界面进行分析理解过滤器的使用

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2c3cd2b23717f6e21e6fb4aa417f164cf3cd9c7d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2c3cd2b23717f6e21e6fb4aa417f164cf3cd9c7d.png)

分析执行流程，由断点调试的结果可知，访问\*.action结尾的网页触发了过滤器。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c4408317f90bdbb5b57279b0b9235fe419f91763.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c4408317f90bdbb5b57279b0b9235fe419f91763.png)

帮post数据换成123，查看过滤器执行的语句，post数据被转换为asccii进行过滤，此时分析过滤器的代码发现无法绕过，又该怎么办呢？接下来将从执行流程图入手。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d5e1f559514968b4ea3b259f686ea8073c7295f1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d5e1f559514968b4ea3b259f686ea8073c7295f1.png)

通过大量的代码分析，由下列代码分析得知，在该框架中只要有method、action、redirect、redirectAction关键字，就按执行流程图中自身的方式进行执行，也就是不经过过滤器和拦截器，直接走ActionMapper，此时就可以实现过滤器的绕过。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-29ef4b41a2d734be89e813d3bc667e35bfaa1da9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-29ef4b41a2d734be89e813d3bc667e35bfaa1da9.png)

### 漏洞复现

Ognol表达式存在漏洞，前面的分析主要是为了绕过过滤器和拦截器，不然就算有漏洞也会被过滤器和拦截器拦截，无法利用，所以只要在提交的数据前面添加method、action、redirect、redirectAction关键字就可以绕过过滤器和拦截器，传入符合Ognl表达式语法规则的字符串，使得Struts2将其当做Ognl表达式在ValueStack中执行，从而造成了任意命令的执行。由于网上已经对Ognol表达式漏洞有详细介绍，这里就不再介绍。  
**Ognol表达式漏洞详解：**<https://blog.csdn.net/u011721501/article/details/41735885>

未加关键字时被过滤，命令无法执行。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1a2317b47c2db79d4c23fd66e24a5741a396fd3c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1a2317b47c2db79d4c23fd66e24a5741a396fd3c.png)

添加关键字后就可以绕过过滤器，并且成功执行命令。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c38fd35ffc2df1121fe74c3ada9d1d4f05283533.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c38fd35ffc2df1121fe74c3ada9d1d4f05283533.png)

Java代码审计主要思路
------------

**1.确定有无框架**  
通过以下三种方式确定框架：  
1、web.xml  
2、看导入的jar包或pom.xml  
3、看配置文件  
Spring 配置文件：applicationContext.xml  
Hibernate配置文件：Hibernate.cfg.xml  
Mybaits配置文件：mybatis-config.xml  
Struts2 配置文件：struts.xml  
不同框架的配置文件不同，这里就举这几个  
**2.查看是否存在拦截器**  
通过查看web.xml文件，确定是否配置相关拦截器  
**3.分析过滤器，分析代码，在有框架类的Java代码中要熟悉它的执行流程**

总结
--

通过无框架类和框架类的代码审计对比，可以清楚的知道两者有和不同，并且在代码审计时也更好分类，思路更加清晰，能够快速的寻找过滤器，分析代码。在Java代码框架类代码审计中，需要我们明确执行流程，并且学会进行断点调试，就如上面的代码审计中通过分析执行流程也可以绕过过滤器和拦截器。