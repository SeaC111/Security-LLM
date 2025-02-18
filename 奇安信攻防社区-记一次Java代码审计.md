前言
==

最近在学习Java代码审计，找了一个Java写的CMS练练手

环境搭建
====

```php
本次审计为MCMS 5.2.4版本：https://gitee.com/mingSoft/MCMS/tree/5.2.4/
目前官方已更新至5.2.5版本：https://gitee.com/mingSoft/MCMS/tree/5.2.5/
```

下载该CMS源码压缩包，解压后使用IDEA打开，修改下配置文件中数据库配置信息

在MySQL中创建一个数据库，然后将`MCMS-5.2.4/doc/mcms-5.2.4.sql`文件导入数据库中

该CMS是基于SpringBoot框架的，SpringBoot内置了Tomcat，我们可以直接启动运行项目，下面来说说如何使用外置Tomcat运行该项目

编辑该CMS的pom.xml文件，修改打包方式为war包

```xml
<packaging>war</packaging>
```

在pom.xml文件中添加如下依赖

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-tomcat</artifactId>
</dependency>

<dependency>
  <groupId>javax.servlet</groupId>
  <artifactId>javax.servlet-api</artifactId>
  <version>3.1.0</version>
  <scope>provided</scope>
</dependency>
```

修改启动类 src\\main\\java\\net\\mingsoft\\MSApplication.java

```java
@SpringBootApplication(scanBasePackages = {"net.mingsoft"})
@MapperScan(basePackages={"**.dao","com.baomidou.**.mapper"})
@ServletComponentScan(basePackages = {"net.mingsoft"})
public class MSApplication extends SpringBootServletInitializer {
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(MSApplication.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(MSApplication.class, args);
    }
}
```

在项目结构中添加构件方式  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-da90056510b85ac15315f75d0193bca75161a2e5.png)

新建一个Tomcat的运行配置  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5738f331dfd8593de8fffa545b74168bd1135d33.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-12e7d7b82cdeea867cef4a4eadfa726adf6404bf.png)

最后点击运行启动项目  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-33661b81c121b7fa410867ae8dc015e041a54ec1.png)

漏洞分析
====

SQL注入
-----

该CMS是使用MyBatis框架来进行数据库操作的，我们知道在MyBatis框架中配置SQL语句使用 `${}` 写法拼接参数是容易产生SQL注入的。

根据CMS目录结构，我们可以知道MyBatis的SQL映射文件都放在dao目录下  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e2e3eec52b1d79900f6985d968056a401082aa75.png)

使用快捷键Ctrl+Shift+F在当前路径下搜索关键字 $，勾选搜索XML后缀的文件  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d988387554bce9a993ba1c2e3e3766f540a1e0c9.png)

在搜索出来的结果中，我们可以看到在 src\\main\\java\\net\\mingsoft\\cms\\dao\\IContentDao.xml 文件中配置的select查询语句使用 `${}` 写法来拼接categoryId参数  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-82749c38f693e5e65738b5c273d624ec73f2d0b3.png)

这里select标签的id属性为query，即对应的调用方法为query方法，接下来我们来看映射接口类的该方法的定义，这里XML映射文件对应的映射接口类为 net.mingsoft.cms.dao.IContentDao  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3efe4380545a6edb22e5f118672833c7f27ca527.png)

注意我们直接在 IContentDao 接口类中是看不到query方法的定义的，IContentDao 接口类是继承自 net.mingsoft.base.dao.IBaseDao 类的，query方法是父类定义的方法  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a47a7eada172a677ab03afa172b5e0bbe4a3170c.png)

根据分层架构设计，我们继续看业务层的代码，这里对应的是 net.mingsoft.cms.biz.IContentBiz 接口类，我们需要去看它的接口实现类 net.mingsoft.cms.biz.impl.ContentBizImpl，同样 ContentBizImpl 类继承了 net.mingsoft.base.biz.impl.BaseBizImpl 类，父类中定义了 query 方法  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b0cb3f451eefe9b8a2b20475bc60f6010e80c207.png)

在代码中可以看到在这个query方法是调用了Dao层的query方法

接下来我们去看控制层的代码，对应的是net.mingsoft.cms.action.web.ContentAction 类，在该类的 list 方法中  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6a4fd34008e85e3667a4e1bc957f9ee81f2c2549.png)

可以接收前端用户输入的categoryId参数，这里前端传递的参数会自动对应到ContentBean对象的属性，所以用户输入的categoryId参数会对应到content对象的categoryId属性，接下来调用了query方法传递了用户输入的参数，这里未对前端用户输入的参数进行过滤，另外该CMS全局也没有针对SQL注入的过滤，所以是存在SQL注入漏洞的。

### 漏洞复现

直接访问接口URL：`http://localhost:8080/ms_mcms_war_exploded/cms/content/list`  
POST提交如下payload：

```shell
categoryId=1' and updatexml(1,concat(0x7e,user(),0x7e),1) and '1
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5c822a7a8798de9e935e09a899993e47cab261ca.png)

可以看到在报错信息中显示了当前数据库用户信息

文件上传
----

### 黑名单校验缺陷绕过

第一处文件上传：上传文件后缀名黑名单校验不严，可上传jspx后缀的文件，该文件类型是可以在Tomcat容器中被正常解析运行的

文件上传接口定义在 net\\mingsoft\\basic\\action\\web\\FileAction.java 文件的 upload 方法中  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-63aa60891c1186b024d423d83e95eb21c695ec8e.png)

在方法中接收用户上传的文件，最后又调用父类BaseFileAction中定义的 upload方法来处理上传文件  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8725af111ff7871fce2fa725633d1649762da379.png)

可以看到在方法的开头定义了一个数组，用来存储要过滤掉的文件类型，这里也就是采用黑名单的方式来进行校验上传文件后缀名。

我们来看看过滤掉了哪些文件类型，uploadFileDenied 其值为配置文件中 ms.upload.denied 项的值  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c4142a93af660533c7838e70ab13667f5aa15896.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-157df3347bc4d95489642882ebbf0822bb64d37a.png)

查看配置文件，可以看到该CMS默认仅配置过滤 .exe .jsp 后缀名，没有考虑 .jspx 这种情况，所以是存在缺陷的

在upload方法接下来获取了上传文件的后缀名，在下面的代码中采用黑名单校验  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fe1180af38071b9830e16a6f8383b76c802809fe.png)

过滤存在缺陷，导致可以上传 jspx 后缀的文件拿shell

#### 漏洞复现

构造上传页面，该上传接口无需登录即可访问

```java
<form method="POST" action="http://localhost:8080/ms_mcms_war_exploded/file/upload" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" name="submit">
</form>
```

上传一个jspx的冰蝎马  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-67b12a7626e8f0e213340e3407edbf44f73007f3.png)

使用冰蝎连接我们的shell  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d4176637a085009888e4dbc98aa21a7642d0d646.png)

### 压缩包上传解压拿Shell

第二处文件上传：程序提供了zip包解压的功能，未对压缩包中的文件进行校验，可上传包含jsp文件zip压缩包拿shell

解压zip模版文件接口定义在 net\\mingsoft\\basic\\action\\TemplateAction.java 文件中  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c14ea59eaedff2b900d9c975fce4fe559aba7617.png)

在方法中使用 request.getParameter() 方法接收前端用户输入的fileUrl参数，接下来调用unzip()方法进行处理，该方法定义在同文件的第529-571行代码处  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-36b41276f5c2452591b2967015bdadb01e6bf912.png)

在unzip方法中是未过滤压缩包中文件后缀名不符合要求的文件

#### 漏洞复现

首先将恶意jsp文件压缩成zip文件，然后通过上传接口上传该zip文件，上传成功后，访问zip包解压功能接口解压我们上传的压缩包，该接口需要登录后访问  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-863b8e5a9d4d655fd67f85fba20642391c11a203.png)

使用冰蝎连接我们的shell  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-95f411fd32cf044ee7481766eba41423d5f50dc2.png)

任意文件删除
------

程序提供了删除模板文件的接口，定义在 net\\mingsoft\\basic\\action\\TemplateAction.java 第232-248 行代码处  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e6180d8f4b5c16dd454084beb3b27c3720241ef.png)

在delete方法中使用 request.getParameter() 方法接收前端用户输入的fileName参数，直接拼接路径，没有过滤 ../，最后调用 org.apache.commons.io.FileUtils类的deleteDirectory()方法，方法用于删除目录及其下面的所有文件。我们可以通过路径跳转符 ../ 来控制删除的路径，达到删除任意目录和文件的目的。

### 漏洞复现

删除upload目录及其下面的所有文件  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-631d9a0fddd3678a77eb136d73896dee7524447f.png)

模板注入
----

该CMS使用的模版引擎是freemarker，该模版引擎是存在模版注入的

登录管理后台，在后台模板管理界面，是可以修改模板文件内容的  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a955fcd6084ba4ce799b2f0eee72a2700d49b03d.png)

插入命令执行的Payload

```java
<#assign ex="freemarker.template.utility.Execute"?new()> 
${ ex("calc") }
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-59401f456a1652b8b869c1c5cfc8b48f6315ef56.png)

点击保存，点击左侧菜单栏中的内容管理 -&gt; 静态化  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ecefba57c85165e6c4c79b50e52bcce66481c79c.png)

点击生成主页  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eaff0e8b4632b1e5a81f9c32ff78e5ff12518f58.png)

可以看到成功触发命令执行的Payload，弹出计算器

修改模板文件的功能代码定义在 net\\mingsoft\\basic\\action\\TemplateAction.java 文件中  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1dd476a4a587c06a634371983738d987e26dd316.png)

可以看到对文件内容是没有进行过滤，可以往模板文件写入任何内容

生成主页功能的代码定义在 src\\main\\java\\net\\mingsoft\\cms\\action\\GeneraterAction.java 文件中  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ec14f305bdd41cf17036fcf931cb5d7194b77257.png)

在方法的最后调用了 CmsParserUtil 类 generate() 方法，跟进该方法  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f0d794fec890b3d9b9f07eb2ceb800b9c81715a.png)

在方法中又调用了 ParserUtil 类的 rendering() 方法，而在这个方法中对模板文件进行解析加载，最后返回生成的内容。  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1ed8ec9b1da2fa040d6acd2a1b8df3a542e4781.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-855af3150344afdc2351769504d18d7cae826340.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-74c72fe2f3df1edccdb25ad6691306d82bacd49b.png)

在对模板渲染的过程中，执行了我们插入的恶意代码，触发命令执行。

总结
==

审计分析了该CMS的SQL注入、文件上传、任意文件删除、模板注入漏洞，在审计分析的过程中对Java代码审计有了更深的理解，提高审计技巧还是要多多练习才行！