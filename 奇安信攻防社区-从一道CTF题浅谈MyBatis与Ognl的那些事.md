0x01引言
======

前段时间看了一道CTF题目ezsql

- 传送门：<http://www.yongsheng.site/2022/03/29/d3ctf/>  
    里面的解题过程大概是Mybatis调用时存在SQL注入，然后还存在OGNL注入。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-750831bf2c1667fe1571d2e3d1ebe662b92bdfcb.png)

看完文章后有一些疑惑：

- 为什么SQL注入能解析ognl表达式达到RCE的效果？
- 题目中是通过Provider注解进行sql配置的，xml配置和类似@Select配置也会存在类似的问题吗？
- 使用#{}预编译后也会存在类似的风险吗？

带着这些疑惑，下面从mybatis的解析流程入手，分析这个case的成因并且看看能不能解决上述提出的疑惑。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-8c93f175e918d9d2d241ad1fa3514574f0ec325d.png)

0x02 mybatis封装SQL流程
===================

提到Mybatis很自然的会想到${}和#{}，看看具体是怎么解析的。

2.1 相关过程
--------

Mybatis的工作流程首先是构建，也就是解析我们写的配置(xml，注解等),将其变成它所需要的对象。然后就是执行，通过前面的配置信息去执行对应的SQL，完成与Jdbc的交互。  
简单的分析下具体的流程，案例代码如下：  
对应的mapper方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6212596978a3ac71e02b08ffc37f478614cd4469.png)

相关的xml配置：

```Java
<select id="getUserByUserName" parameterType="String" resultMap="User">
    select * from users where username like ${username}
</select>
```

以mybatis 3.5.1为例，将断点下在调用的mybatis mapper方法上，简单的梳理对应的执行流程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2c55f30046a81298d7fd36da02949bc0864cec0f.png)

首先是`org.apache.ibatis.binding.MapperProxy#invoke`方法，主要的执行逻辑都在`MapperMethod`的`execute()`方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-bf2f495b001385121d290f41d227b7be395191d6.png)

跟进`org.apache.ibatis.binding.MapperMethod#execute`方法，首先是SQL类型的判断（INSERT/UPDATE/DELETE/SELECT）:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9616c9b3b3c34cc09926bc8e6a66499d2c763eaa.png)

mapper的方法是SELECT的，具体看看SELECT的流程，这里会通过method的返回值的不同调用不同的方法。例如前面的mapper method返回值是List&lt;User&gt;，会返回多行，那么就会调用`executeForMany()`方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-449d8ee840aa993795a25c8ee1d3c405675a5fa6.png)

在`org.apache.ibatis.binding.MapperMethod#executeForMany`中，核心的是`sqlSession.selectList()`，具体的sql执行应该是在这里，rowBounds参数从名称上看应该是跟分页有关的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-37733b1bfddc87829f29fe44a628729143c3bd48.png)

继续跟进，通过`MappedStatement#getBoundSql()`来获取要执行的sql语句，这里应该会对相关的SQL进行组装：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-daed182467ed849960a41b1e0f0ddae1f8a9733f.png)

这里主要是通过SqlSource来组装，继续跟进相关的代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-49ede061bdb0c84fc3c31f4174cf5db8654d9181.png)

sqlSource主要是个接口，有四个实现类：

- StaticSqlSource静态SQL，DynamicSqlSource、RawSqlSource处理过后都会转成StaticSqlSource
- DynamicSqlSource处理包含${}、动态SQL节点的
- RawSqlSource处理不包含${}、动态SQL节点的
- ProviderSqlSource动态SQL，看名称应该是跟类似@SelectProvider注解有关

前面xml里配置的是`${username}`，如果包含`${}`的话一般会调用DynamicSqlSource进行解析，跟进具体的代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-cb8e87afcd50536299416bd2fc2644ce06acb9f4.png)

在`rootSqlNode.apply(context)`会对相关的sql节点进行组装，那么就会对root节点进行遍历，调用对应class的apply方法进行解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-019762102b9395d6e51582d11166eac6b00dcabd.png)

这里会遍历所有的SqlNode,然后根据对应的type再次调用对应的apply方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-cbb24255f963f7f2ddb6eb0102ea9467541cc8ee.png)

例如当前mapper的节点的类型为TextSqlNode，会调用其apply方法进行进一步的解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ee05e01e597e7aea14bdf9350820fd886b5497bd.png)

继续跟进，这里调用了`org.apache.ibatis.parsing.GenericTokenParser#parse`方法进行处理，主要是删除反斜杠并处理相关的参数(${})：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-b16522f0f4ab922686e0f5ca1ffd33f8406bdd59.png)

最后**把${}包裹的内容提取出来**，然后调用`BindingTokenParser#handleToken`方法进行解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c86278707d6355261b9b61b76804376e3aecacd4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-fce0f4516e0454d6b3034269c10649c8638d5a1f.png)

再往下跟进，这里会调用`OgnlCache.getValue`方法，从名称看应该是对sql中ognl表达式进行解析，然后替换SQL中对应的`${xxx}`：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-d26bbf39db0ca223071cd9c809d65ea334fb3515.png)

完成对应sql的封装后，最终会调用selectList方法完成sql执行的操作，从下图中的Exception信息也可以知道该方法与数据库进行了交互：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a7f09148b1080ebe481744ab45bf4c745ae3ffc0.png)

mybatis的整个封装SQL的流程大体上就是这样子了。  
**\#{}的解析流程类似，主要不同的是BindingTokenParser变成了ParameterMappingTokenHandler，然后在handleToken对将#{}替换成占位符？**。

0x03 可能的缺陷
==========

结合前面的CTF题目以及对应的疑惑，这里做一个猜想，mybatis使用不当的话存在sql注入(即输入直接拼接${})的情况，那么根据上面的分析，会调用DynamicSqlSource然后通过OgnlCache进行相应的解析，**如果parseExpression方法中解析的expression是一个恶意的ognl表达式的话，那么有可能存在风险**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-d7ff133a87b73cf5c152f6907433834ccf45f294.png)

那么如何找到一处可以输入${恶意ognl表达式}，同时能调用DynamicSqlSource通过OgnlCache进行相应的解析的利用点呢？题目里的Provider注解有什么关联呢？

3.1 分析过程
--------

MyBatis 默认是支持OGNL 表达式的，尤其是在动态SQL中，通过OGNL 表达式可以灵活的组装 SQL 语句，从而完成更多的功能。从MyBatis的常见使用方式开始梳理，逐个进行分析：

### 3.1.1 XML配置

XML配置是比较常用的一种方式。

假设xml配置如下：

```Java
<select id="test" parameterType="String" resultMap="User">
    select * from users where username like ${@java.lang.Runtime@getRuntime().exec("open /System/Applications/Calculator.app")}
</select>
```

根据前面的分析MyBatis处理${}的时候，会使用OGNL计算这个结果值，然后替换SQL中对应的${xxx}。

很明显在调用这个mapper method时，OGNL会计算`@java.lang.Runtime@getRuntime().exec("open /System/Applications/Calculator.app")`的结果，然后再拼接到原始的SQL中。那么对应的恶意OGNL表达式就会被执行，这里简单写一个controller调用验证猜想。

可以看到提取了${}里的内容，然后OGNL进行了解析，很明显会调用Runtime执行对应的命令：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3899c1cc8d1fb3fde80a5e2a964a79a5081c0644.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7c7d4211ce88bb4d34a9027910ed738dd47b3c9b.png)

以上是一种比较理想的情况，实际上也不会有人在xml里写恶意的ognl表达式，替换跟覆盖已有的XML也不太现实。

更常见的场景一般是如下配置：

```XML
<select id="getUserByUserName" parameterType="String" resultMap="User">
    select * from users where username like ${username}
</select>
```

如果整个解析顺序如下：

- 用户输入username-&gt;拼接到${}中-&gt;调用OGNL解析器解析新的expression

那么确实这里除了SQL注入以外，还可以通过OGNL注入达到上面RCE的效果。显然Mybatis的设计者在设计之初就考虑到了这一个风险，下断点调试，可以看到实际情况在解析时只会解析原有的${username},解析完毕后再把用户输入的值赋予给他。避免了RCE的利用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-08f34f1296146f1f982985facfb427576e34587a.png)

### 3.1.2 普通注解

mybatis3提供了注解的方式，常见的有@Select、@Insert、@Update、@Delete，他们跟xml配置中对应的标签语法是类似的。这里一般sql配置是不可控的，跟xml一样没办法操作。

### 3.1.3 Provider注解

除了上述两种方式以外，MyBatis3提供了使用Provider注解指定某个工具类的方法来动态编写SQL。也就是题目里的注解，常见的注解有：

- @SelectProvider
- @InsertProvider
- @UpdateProvider
- @DeleteProvider

**本质上Provider指定的工具类只需要返回一个SQL字符串，通过在外部定义好 sql直接引用**。

跟进下其封装SQL的过程，前面的过程都是一样的，最后都会通过`MappedStatement#getBoundSql()`来获取要执行的sql语句，进行相应的组装。

然后会调用`org.apache.ibatis.builder.annotation.ProviderSqlSource#getBoundSql`进一步组装：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-55ace55071df136c342da5304e3a0d6f309a5387.png)

相比xml配置，多了一个`org.apache.ibatis.builder.annotation.ProviderSqlSource#createSqlSource`的调用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-cacb9846b4d341718d34e1ae54f9f57b11149402.png)

继续跟进，调用`org.apache.ibatis.builder.annotation.ProviderSqlSource#invokeProviderMethod`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c61e8f65a8c3e7ec121dd773875786238608f49f.png)

因为Provider注解是用户自己编辑的，从对应的参数信息可以看出来这里大致应该是解析相应的外部类，得到对应的SQL，然后返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-dd7e6708d07610840b096c8ad576942c7263beb0.png)

**PS**：在外部类中一般会通过MyBatis 3 提供的工具类org.apache.ibatis.jdbc.SQL或者StringBuilder拼接来生成SQL。

**再往下就跟XML配置的解析过程一样了**，通过SqlSource来组装，如果SQL中包含${}的话则调用DynamicSqlSource进行解析，最后封装完SQL后调用selectList方法完成sql执行的操作。

**相比XML配置方式，其中间会多了一个获取自定义SQL的过程。可以简单的类比为动态生成了一个xml mapper配置**。  
同时因为是直接进行拼接的，假设内容用户可控的话，那么就可以尝试写入类似${content}的内容，因为包含${}，SQL会有变动的可能，拼接成SQL后会调用DynamicSqlSource通过OgnlCache进行相应的解析，达到RCE的效果。也就是题目里的效果。

3.2 缺陷利用过程
----------

根据前面的猜想，这里以@SelectProvider为例进行验证。  
Controller如下：  
通过调用mapper的getUserByUserName方法查询对应的用户名信息：

```Java
@GetMapping("/mybatis/ognl")
public List<User> mybatisOgnl(@RequestParam("name") String name) {
   return userMapper.getUserByUserName(name);
}
```

查看对应的Provider实现，传入的参数name通过SQL拼接进行查询，这里明显是存在SQL注入的，可以任意的拼接内容，写入前面提到的${}：

```Java
@SelectProvider(type = FindUserByName.class, method = "getUser")
List<User> getUserByUserName(String name);

class FindUserByName {
    public String getUser(String name) {
        String s = new SQL() {
            {
                SELECT("*");
                FROM("users");
                WHERE("username='" + name+"'");
            }
        }.toString();
        return s;
    }
}
```

根据前面的分析，这里实现的过程可以类比成xml配置中存在如下的select标签：

```Java
<select id="getUserByUserName" parameterType="String" resultMap="User">
    select * from users where username like 用户传入的name
</select>
```

假设name的值是一个ognl表达式的话，mybatis会进行解析，从而达到RCE的效果。

这里将name设置为如下poc进行请求：

```Java
${@java.lang.Runtime@getRuntime().exec("open /System/Applications/Calculator.app")}
```

可以看到ognl正常解析并且执行了对应的命令：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e73aed5f848f917a6a77aa8610ef2d770938d064.png)

到这里已经把整个CTF题目重新完整的“复现一遍”了。相关的问题也有了答案了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0692d8d8e8d50cca8f9de4cf593f21214dbc471f.png)

0x04 其他
=======

4.1 相关限制
--------

从mybatis从3.5.4开始，在`org.apache.ibatis.ognl.OgnlRuntime#InvokeMethod`方法中，有一个黑名单机制，当\_useStricterInvocation属性为true时，黑名单中的类将不能被使用，例如执行命令要用到的Runtime和ProcessBuilder都在黑名单内：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-289379550393c3f97f70a1a1d0e76252ab1324f6.png)

\_useStricterInvocation属性在static代码块进行了赋值，默认是true：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6642f0743a8da69114b472af876a0ed690cdc92f.png)

同样是上面的案例，此时提交对应的poc会抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f69a3a9d7bd52ed47fd0c2ede055a5e280b7a0ff.png)

但是**这个黑名单应该是存在缺陷的**，可以考虑Bypass。也有师傅提出了相关的poc。这里暂时不讨论了。

4.2 修复建议
--------

在Provider定义sql时，采用#{}预编译的方式进行查询即可，如果一定要直接进行拼接的话，需要对用户的输入进行安全检查。

PS：实际上Provider指定的工具类只需要返回一个SQL字符串，所以不论是通过MyBatis3 提供的工具类org.apache.ibatis.jdbc.SQL来生成SQL，还是简单的String拼接，都是可能存在类似的问题的。

0x05 参考资料
=========

- <http://www.yongsheng.site/2022/03/29/d3ctf/>