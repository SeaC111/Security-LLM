审计环境
----

```js
jdk 7u80 
Tomcat 7 
Maven 3.6.3
```

下载源码后，导入数据库，IDEA导入项目，并修改数据库配置信息

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-9b96fecb81ff6075cbff4852e32f4cf594887326.png)

配置Tomcat运行，即可访问系统

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-b2b94ffc003b3e0f28ad657e3a555cacb372f6a9.png)

结构分析
----

开始审计前，先看看网站文件和结构

- src/main/java：存放java代码的目录
- src/main/resources：存放资源的目录，包括properties、spring、springmvc、mybatis等配置文件
- src/main/webapp：存放网站的JSP、html、xml等web应用源代码  
    可以看出是一个SSM架构（即Spring+Spring MVC+MyBatis）

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-6b6b52bb7a81cb0ad24cec6dd1bd52a162f55686.png)  
然后看一下几个文件：

- pom.xml：Maven的主要配置文件。在这个文件中，可以看到当前项目用了哪些组件以及组件的版本，如果使用了存在漏洞的组件版本，可以快速发现。
- web.xml：Tomcat启动时会自动加载web.xml中的配置，文件中配置了Filter、Listener、Servlet。主要关注Filter过滤器，查看网站的过滤措施。
- applicationContext.xml：Spring的全局配置文件。其中也会包含对其他的配置文件的引用。
- spring-mvc.xml：其中会有静态资源映射、拦截器配置、文件上传限制等配置

### pom.xml

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-f304b6a162e287c87e94ecbc653dd0b290d0cdd2.png)  
搜索发现该版本log4j存在CVE-2019-17571反序列化漏洞，寻找漏洞处触发点，搜索SocketNode类，发现项目中没有调用。  
所以即使项目使用了存在漏洞版本的组件，也不代表就一定存在相应漏洞

### web.xml

只配置了两个filter过滤器，一个是配置了对字符进行编码，另一个是使页面具有统一布局，没有看到对XSS和sql注入的过滤器。  
![5.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-0659135b27d261a1120d0bc0705bc32efefd2dbd.png)

### applicationContext.xml

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-8b275da55869dc5935e05ccb001b1316efbc0b87.png)

### spring-mvc.xml

配置了拦截的路径、上传文件的大小  
![7.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-dfa0ade36c8183ed4f263b2783ef59583f11535d.png)

源码审计
----

### SQL注入审计

已经知道项目使用的是Mybatis，所以SQL语句会有两种定义方式，一个是使用注解的方式，一个是在Mapper.xm文件中编写。

参数拼接也有两种常用的方式，即${}和#{}，#{}是采用预编译的方式，${}是采用简单的拼接。

然后Mybatis框架下易产生SQL注入漏洞的情况主要分为三种，like、 in和 order by 语句。

所以根据以上信息，在xml文件中搜索${（当然也可以去搜索这些语句来寻找审计参数是否可控）

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-9b386e6c3ffa6d93072d7d41af705dc9a625e69f.png)

### 后台SQL注入

在ArticleMapper.xml中，发现存在用 in 语句并使用${}方式传参

![9.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-75e0a7e6972aae65171cd93e8a6e46672765d19c.png)

然后找到该mapper对应的实现类  
![10.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-3a615ca6144b59937612f8f4305e1d0e097d7976.png)

然后找到类调用的地方，确定请求路径和传参方式，请求路径为/admin/article/delete，参数是通过articelId传入  
![11.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-f96e4d5ea27a2cd8cf422f512b411e5db737bb60.png)

![12.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-0f3112220f4efb4e84611cfaca5b1bb43ffb497b.png)

#### 漏洞验证

`/admin/article/delete?articelId=1`  
sqlmap跑一下  
![13.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-973340f544ec7c31a743224200ebe06bd36aacd8.png)

### 前台SQL注入

同样在CourseFavoritesMapper.xml中找到${}传参语句  
![14.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-ac48ff912902768bb99c15aaaca7967c648d350c.png)

然后找到调用该mapper的地方  
![15.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-a817618b20d9d03bb1c9ee8ed8c91a7bf8707a5b.png)

路径为/uc/deleteFaveorite/{ids}，{ids}直接输入参数即可，格式如图  
![16.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-b9ee4cf4e2abed010c5e93da344dc1c7802f068c.png)

#### 漏洞验证：

前台登录后抓包，放到sqlmap跑一下  
![17.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-0c6a84e970f42f8f9110f4bf90d590df8df81923.png)

其他还有几处也存在sql注入，漏洞成因都差不多，这里就不多写了。

### XSS审计

审计XSS要点是定位用户的输入输出，梳理数据交互以及前端展示的过程。找到一个对应的输入输出的地方后，根据现有的安全措施（编码、过滤器）判断是否存在绕过的可能。

在结构分析时，已经知道web.xml中并没有发现对xss的过滤，接下来就需要分析在代码中是否存在过滤。

首先看看插入过程中是否存在过滤

![18.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-42cf530b73afb888ed6ea6469c63f4d0d9d2f0e8.png)

抓包查看路由请求  
![19.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-715ff52fa9877e7e87faf686dbf4d3a5683710ec.png)

全局搜索路由关键字，定位到控制器QuestionsController.java

addQuestions()方法，接收的传参的为Questions类，然后判断用户是否登录，然后调用了sevice层中的addQuestions()方法  
![20.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-a9f40db91a83cb6753b3ae1b99b379293c725a4a.png)

查看Questions类的属性中有哪些是String类型的，可以在这些属性中插入XSS语句  
![21.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-525baaab8fdc57cc77e50fe4a15b2ab1012c1533.png)

查看它的实现类，调用questionsDao的addQuestions()方法  
![22.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-ad4c189233a22fd20d26cca5241cdcd2733c388e.png)

跟进addQuestions()方法，是一个Service  
![23.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-b612dcbcfca2b6e8745f23c626e60278b830e2d5.png)

继续跟进，调用insert插入数据库中  
![24.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-1b29f0504d68dfd80e43bdfc83f37d87d58e008f.png)

根据insert中的信息找到对应的Mapper查看，将数据插入到edu\_question表中  
![25.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-72289d948718ff98def4fabddd031ba07257169b.png)  
在整个插入数据的过程中，都没有对数据进行过滤

接着看输出部分，访问问答页面时触发XSS  
![26.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-147749fbf286b80855ac1c7442ce0114460947e9.png)

根据路由questions/list定位到jsp文件  
![27.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-7e12ddb67db68dbac5a5a887acce199eba5350fd.png)

搜索.title、.content  
![28.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-e7c1429b73b37dedfc47c133a4cf3ca260d1c6de.png)

发现标题处直接拼接数据库中的值输出，而内容处使用了&lt;c:out&gt;标签包裹，&lt;c:out&gt;标签是直接对代码进行输出而不当成js代码执行。所以标题处存在XSS，内容处不存在。

### 文件上传

全局搜索upload、uploadfile等寻找上传功能点  
![29.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-743cb7ff73b65feb17bdf9ada8a80497783da698.png)

fileType从逗号处分割，存入type中，后续与上传文件后缀对比。  
如果fileType中包含了ext则返回true，然后用取反，所以fileType中必须要包含ext，否则直接返回错误。随后获取文件路径，进行文件上传。

这里注意fileType是从请求中传入参数获取的，所以在上传时，只要在fileType传入jsp、jspx，就可以成功上传  
![30.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-196466d3b9183c113944f24e38334010e151de1d.png)

#### 漏洞验证：

构造上传数据包，成功上传  
![31.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-94f54f10a66ccad4f048cf59ee4fdd4fc9b0626e.png)

连接webshell  
![32.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-b591b84c40c8b93ae2d2d8ecc7da7999be86d044.png)

### 越权漏洞

注册账号进入用户中心，点击更改个人信息抓包发现userid，可能存在越权漏洞  
![33.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-e9e844556980f8b9d0d7f119e98d3f1ef79dbf20.png)

在项目中全局搜索/updateUser，找到UserController  
![34.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-674acf1cac426ef3037df32f4c828ec3f3a7ae2e.png)

直接调用了userService的updateUser接口  
![35.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-dfb9977bb2090fd4b72815bef1756ec58e48e898.png)

进入接口实现类  
![36.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-85d92d867552a2dcdc2d651079923d82ad3ce8c7.png)

继续跟进，最终跟到UserDaoImpl的updateUser方法  
![37.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-953dc0ed745305266352c1aaae6b42a61bccc7f6.png)

直接引用UserMapper的updateUser进行更新  
![38.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-01b42d6cb8e54b2a58d056547ac8ad469e228bd2.png)

整个流程没有任何的权限校验，没有判断 userId 与当前用户的关系，所以只要修改为其他用户id，就可以修改其他的用户信息

#### 漏洞验证

注册两个账号

第一个账号test1  
![39.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-c8aff0bd6d7b1c0abe7fcbb2521602c27071bbc8.png)

用户id为70  
![40.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-30933fae9b98cf68d286c9ef9a0820d60d68408c.png)

第二个账号test2  
![41.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-a386210ca0f31d88a0a1d1da55a2764dcee7746a.png)

用户id为71  
![42.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-c106d212c49dedffa63e4db361bc826e8fef3ea0.png)

在登录test2的情况下，抓包修改userId为70，并修改userName  
![43.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-3c68f8bff75aa26cc3e9a6cf1dacdd2a790d37f3.png)

然后登录test1账号，发现个人信息被修改  
![44.png](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-e7fd5dac3ece54ec44141bb550e82af3eddd56ae.png)

总结
--

本文涉及漏洞有限，审计漏洞也不够全面，主要是学习SSM框架的代码审计过程记录，在审计中意识到某些漏洞单纯通过白盒的方式难以发现，所以想要让审计更加全面，还需黑白结合的方式。