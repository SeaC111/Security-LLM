0x0前言
=====

这是我的Java代码审计实战的第二篇文章，下面带来一个新的CMS的审计思路和技巧

0x1环境搭建
=======

```php
本次审计为ofcms 1.1.3版本：https://gitee.com/oufu/ofcms/tree/V1.1.3/
目前官方最新版为1.1.4版本：https://gitee.com/oufu/ofcms
```

首先下载OFCMS 1.1.3版本源码压缩包，解压后，使用IDEA载入项目

自动安装
----

新建一个Tomcat的运行配置

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4890e9a915d942527e02c929ff200d9d15e0efba.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9d6cf8eff2abc70c6aaf4994bcf06bb32a048d70.png)

配置完成后，点击OK按钮使以上配置生效

最后点击运行启动项目，启动后会自动跳转到程序安装界面

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7002bee8adaab349b433cc404aa13d53c540b0e9.png)

点击下一步进行安装

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4d0e883b19a5b624e8f21990a045d173c7b2ec2f.png)

来到配置数据库信息处，输入自己MySQL数据库的配置信息，需要提前在MySQL中创建一个空的数据库

配置好后点击下一步

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-36e1d83daaffe09852793ec199d203b157d432c1.png)

来到设置站点信息处，配置管理员账号密码

配置好后点击下一步

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0ad0b171b86c176002a1085ea50e05bc056a8adc.png)

安装完成，需要重启Web容器

如果自动安装不成功，可以选择手动部署

手动部署
----

首先在MySQL中创建空的ofcms数据库，然后将 `ofcms-V1.1.3/doc/sql/ofcms-v1.1.3.sql`文件导入到自己创建的数据库中

将数据库配置文件`ofcms-V1.1.3/ofcms-admin/src/main/resources/dev/conf/db-config.properties`文件名修改为`db.properties`，然后修改文件中的数据库配置信息

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5cd7bcdf8d8739ed83a6596af63111b8aecd3bbe.png)

启动项目，访问程序后台地址：  
`http://localhost:8080/ofcms_admin_war/admin/index.html`

默认账号和密码：admin/123456

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fdefcda23f3e7b92982f2b2b9f28762602d13f84.png)

0x2漏洞分析
=======

SQL注入
-----

在管理后台 -&gt; 代码生成 -&gt; 新增，这里可以输入SQL语句执行

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8e37bdd8afbabccef4778e46bbd4a6606264c9e2.png)

对应的控制器处理方法为 com.ofsoft.cms.admin.controller.system.SystemGenerateController类的create方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1fb3a6877311190329095822ddc6e83f83c957c3.png)

在create方法中，首先使用`getPara()`方法获取用户的输入，getPara方法定义在com.jfinal.core.Controller类中

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-163d7eac41e3df88ba7b7b93fb4f79103d62d11b.png)

可以看到getPara方法其实就是使用 `request.getParameter(name);` 来获取用户输入的参数值，这里是没有对用户输入的内容进行过滤的

继续看create方法，接下来调用`Db.update(sql)`方法执行输入的SQL语句，跟进该方法，一直跟踪到`com.jfinal.plugin.activerecord.DbPro`类的update方法真正执行SQL语句

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3ff5af6223da7f523d27dec2ea34837279ce34ac.png)

可以看到这里虽然是使用预编译的写法，但是我们可以直接输入整条SQL语句执行，不使用占位符，所以这里预编译处理将不起作用

提交如下Payload执行：

```sql
update of_cms_link set link_name=updatexml(1,concat(0x7e,(user())),0) where link_id = 4
```

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f0e294a01ee946211fbf3b82c38e7ca34c2104e2.png)

在返回的响应包中可以看到SQL语法报错信息，在报错信息中显示了当前数据库用户信息

存储型XSS
------

在前台新闻中心，提供了用户评论的功能

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-382da8fcbaecb83b6dffcd5e30a5c240cbd85353.png)

对应的控制器处理方法为 com.ofsoft.cms.api.v1.CommentApi 类的save方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-721fe3eaac59a145a1452d8ea771f60c10c06b9a.png)

在save方法中调用了getParamsMap方法，这个方法是用来获取用户提交的所有参数的，获取到所有参数后就调用`Db.update()`方法将数据更新到数据库中，这里是没有进行过滤

抓取用户评论的请求数据包，修改comment\_content内容为xss payload：`<script>alert(1)</script>`，提交数据包

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5ed388ebc362e7411fe63d80d40bae3598a3aa18.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0ab8229f8e975f88e8844d14bb68d2e9729f9368.png)

刷新页面可以看到触发弹窗

SSTI模版注入
--------

在查看pom.xml文件的时候发现存在模版引擎freemarker的包依赖信息，该模版引擎是存在模版注入的

在管理后台提供了修改模板文件的功能

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-68fea91a71d4b3dd07087fb3ff8ab7ea93eab324.png)

对应的控制器处理方法为 com.ofsoft.cms.admin.controller.cms.TemplateController类的save方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8d181248654e72bd46447e559175b49f238e3a50.png)

可以看到使用 `String fileContent = getRequest().getParameter("file_content");` 接收我们输入的内容没有经过任何的过滤，最后调用`FileUtils.writeString(file, fileContent)`保存我们修改的模板文件内容

我们可以在模板文件中插入如下payload触发命令执行

```php
<#assign ex="freemarker.template.utility.Execute"?new()> 
  ${ ex("calc") }
```

在管理后台修改 index.html 模板文件的内容，插入我们的payload并保存

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7cad75b63a0467cc39ddba82a8ac4ae67b149fd4.png)

访问首页，触发命令执行，弹出计算器

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-249783cbed37350c61a119b323cc9e8d2c45217e.png)

文件上传
----

在 com.ofsoft.cms.admin.controller.cms.TemplateController类的save方法中还存在任意文件上传漏洞

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-777a841ca197dc5ede405185453d9c43af043f1e.png)

可以看到文件名、文件内容都是可控，且对用户输入的文件名是没有过滤`../`的，我们可以往服务器上写入任意文件

抓取请求数据包往服务器写入webshell，在文件名中插入`../`路径跳转符，控制在static目录下写入恶意JSP文件

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a56d9a6124e95099ad1dd42bb987c1da30f84482.png)

写入成功后，使用冰蝎连接我们的webshell

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-76e1316f1e18e16abdb29e7283868815aa4c0290.png)

XXE
---

在com.ofsoft.cms.admin.controller.ReprotAction类的expReport方法中，接收用户输入的j参数后，拼接生成文件路径，这里没有进行过滤，可以穿越到其它目录，但是限制了文件后缀为jrxml，接下来会调用`JasperCompileManager.compileReport()`方法，跟进该方法看看

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-95cdb688466b96de3274f9dcb8cab238bfa6ec9d.png)

在compileReport方法中又调用了`JRXmlLoader.load()`方法，继续跟踪

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cc6aa5959f816ff166eb05444354dfd0579d4b20.png)

一直跟到调用`JRXmlLoader.loadXML()`方法，在loadXML方法中调用了Digester类的parse解析我们的XML文档内容，默认是没有禁用外部实体解析的，所以这里是存在XXE漏洞的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fe1dcbc24dd705183530a3b066dd3930e5420d9e.png)

这里限制了文件后缀名为jrxml，我们可以利用上面的文件上传写入一个jrxml文件，文件内容为：

```xml
<?xml version="1.0" encoding="UTF-8"?>

    %test;
]>
```

浏览器访问：`http://localhost:8080/ofcms_admin_war/admin/reprot/expReport.html?j=../../static/xxe`触发漏洞

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-286502d1a872b51b6580264fe4d31b837bb05a47.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-212c9b7875ec38e60dc8a65e47049807833212c0.png)

0x3总结
=====

本次审计分析了该CMS的SQL注入、存储型XSS、模板注入、文件上传、XXE漏洞，代码审计要多多进行审计分析，才能更加熟能生巧