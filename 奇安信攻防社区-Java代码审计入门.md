Java审计意义
========

```php
随着Java Web应用的普及，安全审计成为了安全测试人员需要直面的工作。 尽管PHP在中小互联网中仍然占有一席之地，但Java仍然是主流大型应用程序的首选开发语言，国内外大部分大型公司都使用Java作为核心开发语言。 因此，对于安全从业者来说，Java代码审计成为了需要掌握的关键技能。
代码审计在攻防两方面都具有重要意义。 在攻击方面，可以从各个平台找到系统泄露的源代码，进行审计，然后利用审计的漏洞获取系统权限。 在防御方面，代码审计可以发现更多更隐蔽的漏洞，在产品上线之前将问题扼杀在摇篮中，做到安全左移。
```

与渗透测试的区别
========

代码审计与渗透测试的主要区别。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4e22401911ec5cb10ab54e7ddfc39bfb1fb839a4.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4e22401911ec5cb10ab54e7ddfc39bfb1fb839a4.jpg)

MVC框架
=====

传统的开发存在结构混乱易用性差耦合度高可维护性差等多种问题，为了解决这些毛病分层思想和MVC框架就出现了，它强制性地使应用程序的输入、处理和输出分开。MVC即模型(Model)、视图(View)、控制器(Controller)， MVC模式的目的就是实现Web系统的职能分工。最典型的MVC就是JSP + servlet + javabean的模式。

```php
M---数据模型层
1、javaBean(数据库表对应的映射类)
2、JDBC工具类JDBCutiljava
3、Dao(针对表的所有操作,点)
4、Service (服务，事)

V----显示层
Html,Jsp

C----控制层
servlet,action,handler
```

下图就是一个典型的MVC框架应用  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cb1242d9dfa7f54854ad6616073021b428116f2b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cb1242d9dfa7f54854ad6616073021b428116f2b.jpg)  
现在绝大多数的新项目都变成了基于Spring Boot的Spring MVC实现，曾经的Struts2框架已经逐渐没落，我们这里也主要以Spring MVC框架展开讲解。  
在Spring3.0版本,引入了Java注解，我们只需要使用Spring MVC注解就可以轻松完成Spring MVC的配置了。下面就是一个基于Spring 注解配置的关于登录的控制器:

```php
import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.system.common.annotation.Log;
import com.system.common.domain.Tree;
import com.system.common.utils.MD5Utils;
import com.system.common.utils.R;
import com.system.common.utils.ShiroUtils;
import com.system.domain.MenuDO;
import com.system.service.MenuService;

@Controller
public class loginCotrller extends BaseController {
private final Logger logger = LoggerFactory.getLogger(this.getClass());

@Autowired
MenuService menuService;

@GetMapping({ "/", "" })
String welcome(Model model) {
    return "redirect:/login";
}

@Log("请求访问主页")
@GetMapping({ "/index" })
String index(Model model) {
    List<Tree<MenuDO>> menus = menuService.listMenuTree(getUserId());
    model.addAttribute("menus", menus);
    model.addAttribute("name", getUser().getName());
    model.addAttribute("username", getUser().getUsername());
    return "index_v1";
}

@GetMapping("/login")
String login() {
    return "login";
}

@Log("登录")
@PostMapping(value="/login")
@ResponseBody
R ajaxLogin(String username, String password) {
    password = MD5Utils.encrypt(username, password);
    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
    Subject subject = SecurityUtils.getSubject();
    try {
        subject.login(token);
        return R.ok();
    } catch (AuthenticationException e) {
        return R.error("用户或密码错误");
    }
}

@GetMapping("/logout")
String logout() {
    ShiroUtils.logout();
    return "redirect:/login";
}

@GetMapping("/main")
String main() {
    return "main";
}

@GetMapping("/403")
String error403() {
    return "403";
}
```

}  
Spring Controller注解:

```php
@Controller
@RestController
@RepositoryRestController
```

Spring MVC请求配置注解:

```php
@RequestMapping
@GetMapping
@PostMapping
@PutMapping
@DeleteMapping
@PatchMapping
```

审计思路
====

以下是一些代码审计时常用思路。

(1)接口排查
-------

先查看项目的开发框架、根据框架特性查找所有的API接口，然后查看从接口接收的参数，并跟踪参数,判断参数数据进入的每一个代码逻辑是否有可利用的点,此处的代码逻辑可以是一个函数，或者是个条件判断语句。  
对于Spring框架，我们可以直接利用Spring注解查找API接口：@(.\*?)Mapping(  
注意打开idea 上的正则表达式  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ae3329fe77ae83aacfad1949f5280b644454cae3.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ae3329fe77ae83aacfad1949f5280b644454cae3.jpg)

(2)危险函数
-------

根据危险函数逆向追踪参数传递，这个方法是最高效，最常用的方法。大多数漏洞的产生是因为函数的使用不当导致的，只要找到这些函数,就能够快速  
挖掘想要的漏洞。

(3)功能点审计
--------

根据经验判断该类应用通常会在哪些功能中出现漏洞，直接审计该类功能的代码。

(4)第三方组件、中间件版本
--------------

在源码中的pom.xml或Libraries中查看应用是否使用了带有已知漏洞的第三方组件或中间件。

(5)“工具”+“人工”
------------

对于某些漏洞，使用代码静态扫描工具代替人工可以显著提高效率。但是工具的误报率高，还需要人工去确认。  
一般常用的工具有：Cobra（<http://cobra.feei.cn/installation>）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dcb0f67d32faace2eee7e36f72a2a9d72d046de9.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dcb0f67d32faace2eee7e36f72a2a9d72d046de9.jpg)

常见漏洞审计
======

1、密码问题
------

**可能存在漏洞：**密码硬编码、密码明文存储、弱口令、密码强度策略问题  
**关键字：**`password、pass、jdbc、密码`  
**操作：**使用代码编辑器的全局搜索功能搜索相应关键字，然后查看代码是否存在漏洞。  
**实战：**成功找到一个数据库的弱口令、一个密码强度策略问题  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f797d002c57ce71abd4c99ef9e51a0181bab604e.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f797d002c57ce71abd4c99ef9e51a0181bab604e.jpg)

2、XSS
-----

XSS分为反射型XSS、存储型XSS、DOM型XSS

### 2.1反射型XSS

**关键字：**`getParameter`  
**操作：**反射型XSS漏洞通过外部输入，然后直接在浏览器触发，简单来说反射型xss的执行过程 前端—&gt;后端—&gt;前端。在白盒审计的过程中，我们需要寻找带有参数的输出方法，然后根据输出方法对输出内容回溯输入参数。  
**实战：**下图就是一个典型的反射型XSS案例，randCode是从HttpServletRequest中直接获取的，然后代码中没有对输入输出进行过滤、干扰或编码，导致了反射型XSS漏洞的产生。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-794bc372dad65fb8647f8305db48b806536f3521.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-794bc372dad65fb8647f8305db48b806536f3521.jpg)

### 2.2存储型XSS

**关键字：**`">${`  
**操作：**在挖掘存储型XSS的时候，要统一寻找“输入点”和“输出点”，可以考虑使用以下方式提高效率，（1）黑白盒结合。（2）通过功能、接口名、表名、字段名等角度做搜索。

### 2.3DOM型XSS

**输入输出点：**

```php
输入点                         输出点         
document.Url                    eval
document. location           document.write
document.referer                document.InnterHTML
document. form                 document.OuterHTML
```

**操作：**DOM型XSS漏洞不需要与服务器交互，它只发生在客户端处理数据阶段。所以只需要查看是否有不可控的数据经过输入点输入，然后未经过滤或者编码就被输出。

3、SQL注入
-------

### 1、JDBC拼接不当造成SQL注入

**关键字：**`Statement`  
**操作：**JDBC有两种方法执行SQL语句,分别为PrepareStatement和Statement。两个方法的区别在于PrepareStatement会对SQL语句进行预编译，Statement方法在每次执行时都需要编译。大家可能都知道SQL注入的一个防御方法就是使用预编译，但并不意味着使用PrepareStatement 就绝对安全,不会产生SQL注入。

### 2、Mybatis框架使用不当造成SQL注入

Mybatis框架下”${xxx}”这样格式的参数会直接参与SQL语句的编译，易产生SQL注入漏洞，出现这种情况主要分为以下三种：

#### 1. 模糊查询like

如以下SQL查询语句：  
`Select * from article where name like ‘%${title}%’`

#### 2. in之后的参数

如以下SQL查询语句：  
`Select * from news where id in (${id})`

#### 3. order by之后

如以下SQL查询语句：  
`Select * from news where title =‘123’ order by ${time} asc`

4、文件操作
------

### 4.1、文件包含

其实不光PHP，Java中也是存在文件包含漏洞的，JSP的文件包含分为静态包含和动态包含两种。  
静态包含：`%@include file="test.jsp"%`  
动态包含：`<jsp:include page="<%=file%>"></jsp:include>、<c:import url="<%=url%></c:import>`  
Java的文件包含只会造成文件读取和文件下载的漏洞。

### 4.2、任意文件下载/读取

**危险函数：**

```php
download
fileName
filePath
write
getFile
getWriter
FileInputStream
```

**操作：**寻找未做严格校验的可控路径，可以通过路径对文件进行下载读取操作

### 4.3、文件上传

**危险函数：**

```php
File
lastIndexOf
indexOf
FileUpload
getRealPath
getServletPath
getPathInfo
getContentType
equalsIgnoreCase
FileUtils
MultipartFile 
MultipartRequestEntity
UploadHandleServlet
FileLoadServlet
FileOutputStream
getInputStream
DiskFileItemFactory
```

**操作：**  
可以从以下几点寻找任意文件上传漏洞  
1、仅前端过滤导致的任意文件上传漏洞  
2、后端过滤不严格导致的任意文件上传漏洞

5、反序列化
------

**危险函数：**

```php
ObjectInputStream.readObject
ObjectInputStream.readUnshared 
XMLDecoder.readObject 
Yaml.load 
XStream.fromXML 
ObjectMapper.readValue 
JSON.parseObject
```

**危险基础库：**

```php
com.mchange:c3p0 0.9.5.2
com.mchange:mchange-commons-java 0.2.11
commons-beanutils 1.9.2
commons-collections 3.1
commons-fileupload 1.3.1
commons-io 2.4
commons-logging 1.2
org.apache.commons:commons-collections 4.0
org.beanshell:bsh 2.0b5
org.codehaus.groovy:groovy 2.3.9
org.slf4j:slf4j-api 1.7.21
org.springframework:spring-aop 4.1.4.RELEASE
```

**操作：**反序列化操作一般应用在导入模板文件、网络通信、数据传输、日志格式化存储、对象数据落磁盘、或DB存储等业务场景。因此审计过程中重点关注这些功能板块。通过寻找危险函数确定反序列化输入点，然后再考察应用的Class Path中是否包含危险基础库。若包含危险库，则使用ysoserial进行攻击复现。若不包含危险库，则查看一些涉及命令、代码执行的代码区域，防止程序员代码不严谨，导致bug。

6、XXE
-----

**危险函数：**

```php
javax.xml.parsers.DocumentBuilderFactory;
javax.xml.parsers.SAXParser
javax.xml.transform.TransformerFactory
javax.xml.validation.Validator
javax.xml.validation.SchemaFactory
javax.xml.transform.sax.SAXTransformerFactory
javax.xml.transform.sax.SAXSource
org.xml.sax.XMLReader
DocumentHelper.parseText
DocumentBuilder
org.w3c.dom
org.xml.sax.helpers.XMLReaderFactory
org.dom4j.io.SAXReader
org.jdom.input.SAXBuilder
org.jdom2.input.SAXBuilder
javax.xml.bind.Unmarshaller
javax.xml.xpath.XpathExpression
javax.xml.stream.XMLStreamReader
org.apache.commons.digester3.Digester
rg.xml.sax.SAXParseExceptionpublicId
```

**实战1:**  
我们可以看到下面的代码使用了危险函数DocumentBuilder()，没有对传参进行过滤限制。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e52b069e8c4d431e2c3023888f085443fcee68d9.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e52b069e8c4d431e2c3023888f085443fcee68d9.jpg)  
并且SAMLResponse可控，攻击者传入构造好的xml代码，造成XXE漏洞。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-02293d6700c0661cf2220b850ceafabb5e2adb21.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-02293d6700c0661cf2220b850ceafabb5e2adb21.jpg)

**实战2：微信支付接口XXE**  
WXPayUtil下的xmlToMap方法存在XXE漏洞，使用了DocumentBuilder危险函数，直接将传入的字符串转换为了map集合，并且未对字符串进行过滤，导致攻击者可以传入任意的攻击代码。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0457c64306b44fa7b815d842b73605d4e1937a5f.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0457c64306b44fa7b815d842b73605d4e1937a5f.jpg)  
我们写一个测试方法，调用xmlToMap方法，发现成功读取文件内容。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-19a12b875ffbae64c5bfcc3999cc04450f2f92a7.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-19a12b875ffbae64c5bfcc3999cc04450f2f92a7.jpg)

```java
package com.github.wxpay.sdk;
import java.util.Map;
public class test {
     public static void main(String[] args) {
        String str = "<?xml version='1.0' encoding='utf-8'?>\r\n"+ 
        "\r\n"+
        " ]>\r\n"+ 
        "<creds><goodies>&goodies;</goodies><pa>susu</pa></creds>";
        Map<String, String> map;
        try {
            map = new WXPayUtil().xmlToMap(str);
            System.out.println(map);   
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

可能有些同学会有疑惑，为什么要嵌套两个元素，如： `"<creds><passwd>&goodies;</passwd></creds>";`  
因为传入的xml语句的元素会被当作map的key，变量会被当成map的value，如果是只嵌套一个元素，如：`"<creds>&goodies;</creds>";`转换为map后就变成了{ }，因为是获取子节点传入nodeList中，上面的写法没有子节点，所以输出null。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2902d0ef947d727e75e050389532ed119534ace1.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2902d0ef947d727e75e050389532ed119534ace1.jpg)  
可以看到子节点都被转换为map输出出来。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-abc537fa286fb838be1531317d75d7c5f6ca02bb.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-abc537fa286fb838be1531317d75d7c5f6ca02bb.jpg)  
**实战3：solrXXE漏洞（CVE-2017-12629）**  
出现问题的代码存在于在/solr/src/lucene/queryparser/src/java/org/apache/lucene/queryparser/xml/CoreParser.java文件中  
我们可以看到下面的代码使用了危险函数DocumentBuilder（），并且没有对传参进行过滤限制，也未禁用DTD和外部实体，造成了XXE漏洞。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-09f4f1d3d5d87440e89368ad9999f8a462bc16bc.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-09f4f1d3d5d87440e89368ad9999f8a462bc16bc.jpg)

7、CSRF
------

挖掘CSRF漏洞，一般需要首先了解程序的框架。  
CSRF漏洞一般会在框架中存在防护方案，所以在审计时，首先要熟悉框架对CSRF的防护方案,若没有防护方案,则存在CSRF漏洞;  
若有防护方案，则可以首先去查看增删改请求中是否有token、formtoken、csrf-token 等关键字,若有则可以进一步去通读该Web程序对CSRF的防护源码，来判断其是否存在`替换token值为自定义值并重复请求漏洞、重复使用token等漏洞`。此外还要关注源程序是否`对请求的Referer进行校验`等。

8、SSRF
------

**危险函数:**

```php
HttpClient.execute()
HttpClient.executeMethod()
HttpURLConnection.connect()
HttpURLConnection.getInputStream()
URL.openStream()
HttpServletRequest()
BasicHttpEntityEnclosingRequest()
DefaultBHttpClientConnection()
BasicHttpRequest()
```

**操作：**程序中发起HTTP请求操作一般在获取远程图片、页面分享收藏等业务场景,在代码审计时可重点关注危险函数。  
**实战：**UeditorSSRF漏洞  
代码中的validHost方法对url进行判断，如果不合法，就提示“被阻止的远程主机”；当满足条件后会使用validContentState方法查看返回的状态是否为200，若不为200，则提示“远程连接出错”，如果url无法访问，则提示“抓取远程图片失败”，这就间接造成了SSRF漏洞。  
我们在代码中找到captureRemoteData中调用了validHost方法，我们可以看到captureRemoteData中使用了HttpURLConnection。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0ca2a1b03e20d5a0051a2024b01bbf015dcccdca.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0ca2a1b03e20d5a0051a2024b01bbf015dcccdca.jpg)  
然后capture方法中调用了captureRemoteData，在invoke中调用了capture方法。  
我们进入到invoke中发现，要想调用capture就需要满足条件为actionCode为ActionMap.CATCH\_IMAGE，当actionType值为catchimage，即action参数对应为catchimage时，才可能触发SSRF漏洞。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a240e83df83cca2631710f79778381084a4f79d6.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a240e83df83cca2631710f79778381084a4f79d6.jpg)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-66601f8a8af26fe2f704bb18e7a21bd731b9acbb.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-66601f8a8af26fe2f704bb18e7a21bd731b9acbb.jpg)

可能有点绕，但简单总结就是  
`ction=catchimage->invoke->capture->captureRemoteData->validHost(SSRF)`。

9、使用含有已知漏洞的组件
-------------

**操作：**可以使用一些搜索平台查看应用程序所选的第三方组件是否存在漏洞。

```php
框架相关：S2、shiro、Spring
中间件相关：JBoss、Weblogic、Jenkins
Java库相关：Fastjson、Jackson
第三方编辑器：UEditor、KindEditor、FCKeditor
```

**实战：**我们可以在项目的pom.xml中查看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1fa2581877fa1a70cc7354fb666f856fc27ffcba.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1fa2581877fa1a70cc7354fb666f856fc27ffcba.jpg)

10、请求轰炸
-------

**关键字：**`短信、用户不存在、验证码、邮箱、发送`  
**操作：**应用程序中可能存在许多接口用来做一些如发送短信验证码、判断用户是否存在，这些接口功能一旦能够进行重复请求就会造成一些问题漏洞。  
**实战：**  
未对短信发送做次数限制导致短信轰炸漏洞  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a0ae1555d38d874e5b72f6ce2966f2f4804ab866.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a0ae1555d38d874e5b72f6ce2966f2f4804ab866.jpg)  
当账号输入错误后，提示“账号不存在”，造成用户名可枚举漏洞  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-52b768867788c4fe8f2d08fbedae8dfc76cee0e0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-52b768867788c4fe8f2d08fbedae8dfc76cee0e0.jpg)

11、越权
-----

**操作：**在对一些数据进行增删改查的时候，如果没有鉴权，就会导致越权漏洞，一般越权漏洞需要根据实际的项目流程来寻找挖掘。  
**实战：**下图就是进行删除操作的时候，没有进行鉴权，直接匹配到id就进行了删除。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-766ea0597a3dcbbb9afb3c11d9534167c827bfba.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-766ea0597a3dcbbb9afb3c11d9534167c827bfba.jpg)

12、URL重定向漏洞
-----------

**危险函数:**

```php
sendRedirect
getHost
redirect
setHeader
forward
```

**操作：**重点寻找危险函数，然后查看是否对重定向地址做有限制。

总结
==

本文只是总结了一下我平时进行Java代码审计的时候常用的思路，属于基础中的基础。