某OA 历史RCE分析
===========

payload
-------

```php
/data/sys-common/datajson.js?s_bean=sysFormulaValidate&script=Runtime.getRuntime().exec("whoami");
```

漏洞分析
----

分析payload可以看到漏洞是在`/data/sys-common/datajson`路由下，在源码中找到该路由的位置为lib目录下的`com/xxx/kmss/common/actions/DataController.class`中  
![](https://shs3.b.qianxin.com/butian_public/f44528627138c54bccf2052a505436ebe9ab217514438.jpg)

我们分析一下该方法逻辑，首先提取关键代码

```java
String s_bean = request.getParameter("s_bean");
JSONArray array = new JSONArray();
JSONArray jsonArray = null;

try {
    Assert.notNull(s_bean, "参数s_bean不能为空！");
    RequestContext requestInfo = new RequestContext(request, true);
    String[] beanList = s_bean.split(";");
    List result = null;

    for(int i = 0; i < beanList.length; ++i) {
        IXMLDataBean treeBean = (IXMLDataBean)SpringBeanUtil.getBean(beanList[i]);
        result = treeBean.getDataList(requestInfo);
```

首先是从request请求中获取`s_bean`的值，通过`;`分号对`s_bean`进行分割，循环分割后的数组，通过`SpringBeanUtil`工具类的`getBean`来获取`IXMLDataBean`类型的bean对象，最后调用bean对象的`getDataList`将请求包数据作为参数传入。

我们跟进看看`IXMLDataBean`，发现其实是一个接口

```java
public interface IXMLDataBean {
    List getDataList(RequestContext var1) throws Exception;
}
```

同时看到整个项目其接口实现类其实有四百个之多  
![](https://shs3.b.qianxin.com/butian_public/f7228199ac7936588c80451fe0772ca0cf0f075f88b81.jpg)

根据payload，我们找到s\_bean名为`sysFormulaValidate`,全局搜索找到该类的定义

![](https://shs3.b.qianxin.com/butian_public/f419078c9cbe7cdc195fe8d886f35d924d2bd996f43e4.jpg)

可以看到其是`IXMLDataBean`的实现类，主要处理也是在`getDataList`方法中。  
主要是获取请求参数中`script`的值，并new一个`FormulaParser`对象，调用`parseValueScript`将`script`进行处理得到结果，最后根据value进行返回。

我们继续进入`FormulaParser`类中`parseValueScript`方法的实现

![](https://shs3.b.qianxin.com/butian_public/f8251813d15896765cbd0476ab3a9ae80fc87d41623a8.jpg)

发现其是重载方法，该方法主要是调用`this.parseValueScript(script)`方法，我们继续跟进

![](https://shs3.b.qianxin.com/butian_public/f418679281a23a0e8a4670c977b70267a02861fbc77ce.jpg)

该方法首先是创建一个`Interpreter`对象，其依赖来自`Beanshell`库，它可以执行java代码

> BeanShell是一种脚本语言,一种完全符合java语法的java脚本语言,并且又拥有自己的一些语法和方法,beanShell是一种松散类型的脚本语言(这点和JS类似)

传入的script参数会进行trim()，返回通过提取`$`符号来对index进行赋值，在后面index&gt;-1是进入if语句，而我们poc中并没有`$`符号，所以会跳过这个判断。

往后是对要执行的语句拼接：

```java
final String m_script = importPart.toString() + preparePart.toString() + leftScript + rightScript;
```

因为没有进入if判断所以`preparePart`和`leftScript`变量为空，`importPart`变量是已经经过处理的，`rightScript`变量就是请求参数中`script`的值；所以两者拼接最终得到`m_script`变量。

```java
value = SecurityController.doPrivileged(new PrivilegedAction<Object>() {
    public Object run() {
        try {
            return interpreter.eval(m_script);
        } catch (EvalError var2) {
            FormulaParser.logger.warn("执行公式出错：" + m_script, var2);
            throw new EvalException(var2);
        }
    }
});
```

最后调用`Interpreter`对象的`eval`方法执行`m_script`，从而导致任意代码执行。

另外`SysFormulaValidate`类同级目录下还有一个类`SysFormulaSimulateByJS`，也是实现了`IXMLDataBean`接口。  
![](https://shs3.b.qianxin.com/butian_public/f674235c81f76c74c3b414ce0e7c5bc06847e796fcf40.jpg)  
与之不同的是，在`SysFormulaSimulateByJS`是调用`FormulaParserByJS`的`parseValueScript`方法，而该方法是调用`ScriptEngine`对象的`eval`方法（该方法可执行javascript代码）。  
![](https://shs3.b.qianxin.com/butian_public/f14575640984cde93347f82f6cff5caee2764ac733c39.jpg)  
最终也导致任意代码执行。

权限绕过
----

我们看到poc中该接口`/data/sys-common/datajson.js`最后是加了`.js`，而去掉`.js`是无法未授权访问该接口的，所以此时的`.js`其实是一种绕过方式，而`.js`结尾常常是静态文件，系统是如何成功识别到访问`/data/sys-common/datajson.js`是`/data/sys-common/datajson`接口呢

其实这个问题是springmvc导致的，在springmvc版本`<5.3`之前后缀匹配模式参数`useSuffixPatternMatch`默认值为`true`  
![](https://shs3.b.qianxin.com/butian_public/f952477fd3367a6f16ac07a1528c89183f71015f234c7.jpg)  
当开启后缀匹配模式时，路由匹配中`/users`会被映射到`/users.*`。

![](https://shs3.b.qianxin.com/butian_public/f891693c695861e843e3eec0315f920fe039e156b2302.jpg)

![](https://shs3.b.qianxin.com/butian_public/f417749103f0d15cf82bd6521c53e56e8f2dc30a60579.jpg)

具体调用是在`PatternRequestCondition#getMatchingPattern`中。

例如：controller路由定义为`/admin`，我们访问`/admin.aaa`

![](https://shs3.b.qianxin.com/butian_public/f454633dc65edf3f58781ff0a76a32b8fc9c9607ac7f1.jpg)

在`PatternRequestCondition#getMatchingPattern`方法中，首先是判断模式与路径是否相等，如果相等就直接返回模式。  
此时模式为`/admin`，请求路径为`/admin.aaa`，会进入else逻辑中处理：  
![](https://shs3.b.qianxin.com/butian_public/f302821fce13dd1b8a5cf887e07c931fcdcab2e09dd0a.jpg)

首先是判断`useSuffixPatternMatch`是否为`true`，在`org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping`可以看到该值的初始化

![](https://shs3.b.qianxin.com/butian_public/f677160e231f1f73cd3dd760716469ab25d96bb916b5e.jpg)  
前面也提到了在`version<5.3`的情况下默认为true, 从而进入下一层，由于不满足if判断，进入else语句中

```java
else {
    boolean hasSuffix = pattern.indexOf(46) != -1;
    if (!hasSuffix && this.pathMatcher.match(pattern + ".*", lookupPath)) {
        return pattern + ".*";
    }
}
```

判断`pattern`中是否存在`.`符号（这里46对应的Ascii码是`.`）,如果不存在且`pattern+".*"`可以匹配到lookupPath时，返回`pattern+".*"`的字符串  
![](https://shs3.b.qianxin.com/butian_public/f631816b583c331b2def039b016193d30698966a200da.jpg)  
后续因为`.*`的缘故，成功将`/admin.aaa`匹配到`/admin`。

> 总结：当filter等权限认证对静态文件利用后缀进行放行时，就可能导致绕过。  
> 如访问/api/admin 403,可以替换为/api/admin.html进行绕过

我们来看一下该系统的filter：  
![](https://shs3.b.qianxin.com/butian_public/f48667857bf5b3cba2af2fd6e9510a9b9bc508d7c0a46.jpg)  
在`web.xml`中找到了全局filter，通过注释找到`sys\authentication\spring.xml`配置文件  
![](https://shs3.b.qianxin.com/butian_public/f86592763b577ee7adbf9eb9ba1c1e6b592130a8d7838.jpg)  
可以看到其是通过文件后缀来判断是否是静态资源，同时其springmvc为`3.x.x`版本，导致我们可以访问`xx.js`、`xx.tmpl`等静态资源后缀进行权限绕过，访问漏洞路由。