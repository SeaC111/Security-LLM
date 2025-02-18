前言
--

因为也是第一次审计java的cms 可能也有很多解释的不对的地方望师傅们指出

### 环境搭建

源码：<https://www.ujcms.com/uploads/jspxcms-9.0.0-release-src.zip>

下载之后解压

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-58648226f86dab76767ca2c0807f7cdf8a6e8bf2.png)

然后用idea导入

先创建数据库导入数据库文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a73140e38c951bed296e09140a1d39acd9f709b3.png)

然后导入源码

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6defb0100ed361e8d2f0260c97e9088eab7a0b17.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ed0295bcbae83bcfe9dc396b030ba22882e3a607.png)  
然后配置好数据库连接

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2a7e5ecf4e2ab6b77b7cb2af6768d71577d6467d.png)

加载maven依赖

根据本地数据库版本情况 记得调整数据库依赖版本

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6656f8bea39fc115f9fddb7d0b6093227abdf4ee.png)

然后启动 因为是springboot 直接启动就行

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-eae2378219957b65ad2a7000de71c296e8a10aad.png)

后台地址：<http://127.0.0.1:8080/cmscp/index.do>

因为刚开始代码也那么多就没有直接看代码 先熟悉熟悉有什么功能点

#### XSS

随便进入了一篇文章 然后评论

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-453dc01a3a975daa0691df32372943ab6f50cfb2.png)

这里发现是没有xss的

但是后面来到“我的空间”

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c83ce750ba6cdb4c37e03dd616343f58a920907e.png)

点击评论的时候

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-252544a067f0316210e8762e83e7c363d32fe7ca.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-598f31df5b3d1966d823870e16a27f45b115d9dd.png)

这里触发了xss

这里相当于是黑盒摸到的 单既然是审计 就要从代码来看 重新回到评论的地方 评论进行抓包 看看请求的路径是什么 先找到入口

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-344d4683c28cb08cf1bee72709e604b7bb78fa4c.png)

然后回到idea搜索comment\_submit

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0e46c30061b9faefa445972f8f468c46c07c7e36.png)

然后在这里打上断点

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8a0ea27e22ea112b0071c6fc082204f1405782c7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bc65103f50bec9057acbf67c5fc7788451ac5e8a.png)

然后一步一步放

跟进submit

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b2aa763155e057456da69ab4f63d1564da42d37f.png)

主要是看传进来的text的走向

到这里text的值都没有变化

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c272454e2ea2fa649621e79e026245cd28aa893f.png)

然后来到最下面这里是save操作

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3b09ed8a711c4b2d716e9fb28b7183a5c6ff774f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-adb38e76878dce1f05e3fae31203f47218e0269a.png)

这里也是直接进行存储 说明存入的时候是没有进行过滤的 那最开始没弹 肯定就是输入的问题了 因为摸到弹的情况

直接根据弹的情况来分析为什么回弹 先找到弹的页面的代码 因为路径有一个space 所以搜索space

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2c173694d8413cd2c9ad7fcb76f2dd44a0964b6c.png)

打上断点 进行调试

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d7e193e75b60f96fed5d858945ca4570c2be815b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-9a260d4c80a8088a0743e76b29fe9d2a12d2aa55.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-9da2c43270d925d729abf3483b7a3425c3551e8c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-15333ba46d8f5ce79c66250db0e63c794ac13858.png)

这里最后返回了一个模板

发现这个是一个html 搜索这个html

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e25a18f4c51819d64a57deb0933f693b7fce53db.png)

通过pom.xml

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-41fd530b484c5a4bc15ecec1e0048ac37260b37e.png)

是freemarker模板

先搜搜这玩意是咋转义的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-aa8a0a7dedcde0978dcb0c5259582093b7b8500d.png)

看到一个熟悉的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-eb0c78f380edb73f1fb86789491d2247a7553854.png)  
这个页面这里有填写这个 但是最终还是弹了 说明有漏网之鱼的页面

通过查找 发现一个没有写这个的页面

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-78cf184daa1c8076540944b8134c8244f318ddb1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-def1859cf3b90418cca1df23cda6b29844a8fba9.png)

搜索 看看哪里用到了这俩

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-850cc43092fc680fbe77cbd75742ceb8dce3f07b.png)

刚还这里的type=comment对应上之前访问时候的type

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bdc02cd6a69def89ecc84340b81fde88873c7f64.png)

所以访问这个页面的时候能触发xss payload没有进行任何过滤 这个页面也没有进行转义

#### SSRF

在审计ssrf的时候 一般都是搜索关键函数

```php
URL.openConnection()
URL.openStream()
HttpClient.execute()
HttpClient.executeMethod()
HttpURLConnection.connect()
HttpURLConnection.getInputStream()
HttpServletRequest()
BasicHttpEntityEnclosingRequest()
DefaultBHttpClientConnection()
BasicHttpRequest()
```

##### 第一处

直接在idea里面搜索

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-51be7618f0939237f6d82a9b83f9a98eadd74fb2.png)

然后一个一个点进去分析

找到这里

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-18c57679331aef2eac09a1f60c7b25e8034ee522.png)

会进行连接 然后我们往上分析这个src的来源

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2ffdd9c99ce09610816ec1daf9dc693d08b64f3a.png)

发现这里是从请求中获取source\[\]参数来的 说明这个是我们所能控制的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-645229782425518963e1de241c8deb5c863cc48d.png)

在往上看 根据函数名能够大概猜出是编辑器图片相关的函数

看看哪里调用了这个函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fa92327019b82ed2f570912e188c938104a59106.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f5d2543b926959d335c247b8894c3b12a0cd7d70.png)

在uploadcontroller下 继续跟进ueditorCatchImage函数 看看那里调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2b06b9bab68ced043e3af5a37e4e0030bc1d33ff.png)

发现在同一页的66行找到 也找到这个路由是在ueditor.do下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-50d242538cb6f5777d9112219792c1383ae2d938.png)

最上面controller 是core

所以路径是/core/ueditor.do?action=catchimage

进行测试

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-16a53cc128bbf89aa809ed46adceb1e18a7996f1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-60a8e96f952b9a352d1d341dd62a85c7d615890a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b4917c286f833181a94ee573878dfae03cc27745.png)

但因为是在back下 所以是一个后台的洞

通过后面的代码可以看到 似乎是对一个图片的操作 直接就进行断点看看这里是到底执行了什么

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-67d47732eef0792d317f09957b88e97594c11507.png)

**测试**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e17583aec876222d1628b242a6e783f145e34310.png)

传入了一个jpg地址 但这个地址是不存在的 来到断点的地方

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e0b5a43759f1e7437263de4dc3f4ce9775ba743d.png)

这里获取到source的值存入数组

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-00185ac71913e5be0991a1b75cf07dafeacc6b21.png)

这里获得后缀

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0cb624bc622691dc49a12ce099bb5543bfa852e3.png)

这里判断请求的是不是图片 因为我们传入的是不存在也就不是 到这里也就直接结束了 在此输入一个存在的链接

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8a758d20aff6986aa03d29b72a25768b1ecfc41c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b877c1a214ce05e962027fbea4a79cdee7281294.png)

跟到这里是重新设置文件名

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-67548cd8187698a3ca9a877fb8b7d6621f54c633.png)

然后读取输入流

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8c4087ebb23f1efef918470b6d78dc0b325f4b27.png)

然后跟进这里创建文件对象

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3fca4ec0f2069dbc57a4a318d48b5cb06f13747f.png)

然后这里直接保存文件 中间也没有任何过滤操作 就判断了是不是图片 然后就保存了文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ec06a7ed4fd7473fc584595a66dcf71a325c4b3b.png)

相当于这里就是一个进行 图片请求然后保存到本地的操作

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-28c7fe6137e23136ca0034ffac6cab7aa0f1f64d.png)

那么这里是不是可以进行svg的xss呢 尝试一些

**测试**：

先创建一个svg xss

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f47b0e4bc8fba68076a3b585aa3431efa8453911.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-4d7cce2e5233d012ec5d0da896944793cecc5a33.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3ef6363c5b968aa468adc4269bd0553a3861b575.png)

##### 第二处

继续搜索ssrf的关键函数HttpClient.execute()

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-949ea3cbf4b2452b52d8a93531913f3112480fcd.png)

然后查看哪里调用了这个函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b1ee04a349cb40c5a2d78094aa65474f7cdf4c65.png)

继续跟进

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ab3be844ebbd3049856c3bc797a4a9f9de537f23.png)

发现在这里进行的调用以及url的传入 而且这个url是 可控的

往上找到控制层

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8a90e68516a0a6c79cfa86e7c4b173cc85c73f28.png)

最后拼接 进行测试

> [http://192.168.1.2:8080/cmscp/ext/collect/fetch\_url.do?url=http://127.0.0.1:8080](http://192.168.1.2:8080/cmscp/ext/collect/fetch_url.do?url=http://127.0.0.1:8080)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-07132efc1daf59c0eadf9eced02820c568910625.png)

直接能访问到服务

最后在页面找到位置

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7bc5ea07f5a6f2fe8e7973df37405d36438804fa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1ad4ed553674793805fd8e3e1c05e64615e8e1be.png)

#### RCE

##### 第一处

在逛后台的时候 发现上传的地方

可以任意上传东西 但是直接jsp这些传上去访问直接下载 无法利用 但是在上传zip的时候会自动解压 这就有意思了 于是乎 先抓包抓到路由 然后全局搜索

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-5b57224f77b284800ebc0ba0880a37e0ba416a2e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-4424eeb25dfcd6ebcb2f6dba0d89cc8d09e04b89.png)

然后跟进来

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fa5fed72f4bbd3e0c4640bbcab7f3a3bb084924e.png)

这里调用了这个zipupload 继续跟进

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ff36e3946db1af847ed01d32b79f99e93af07d31.png)

经过简单代码跟进 发现 这一步才开始对参数进行利用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2b9b78618d93f222fd6627fde48f7c76a0b4e8cf.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c5b50779e667e248507c876c1203a10c5a5592dc.png)

经过初步判断这个函数的作用是将zip里面的文件取出来 然后存入到文件夹里面 具体是不是 利用断点来进行详细的分析

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c8b17dad70a819a24e92d2acef146c30f5815579.png)

这里是将传进来的文件先写入了临时文件 然后将临时文件和一个路径传入到zip函数

继续跟进

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bf210b9d76888ff2e6ddac9af0bb008c135e616a.png)

先判断传入的路径是不是文件夹 不是就直接报错

然后看下面 定义了一些相关变量

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b5cc71e7a70a1a0fe53f07206aea3a80cf36d156.png)

这里创建了一个zipfile文件对象 目标正式传入的zip文件的临时存储文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6150f1d4403be2d42dad1b4ce1b4b59757d7a574.png)

这一步一个就是获取了文件的相关信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-faf4a7e07b5b6b41d9909c2f22c77434aa954448.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f4e10848f4e0b56e0c2e4b06457feb6e8be44357.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f7801af9ee6a8f578f3fc05e2009dc300caa30a0.png)

然后走到这一步就直接将文件写入到文件里面 其中也没有任何的过滤 所以我们哪怕是文件里面放入jsp一句话也可以

先试试

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fbf48a5c4ce1d62878bb99494378896d35d3028d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-007ef704ad9e01da0fd8cbaafa8d0818f856e2b9.png)

jsp文件访问不到 发现在uploads前面竟然多了一个/jsp 其他类型文件直接下载 但是文件又确实存在 那说明肯定是拦截器之类的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2ec1f6b07a9066db3fe8b005cedc6fc5a1792e30.png)

经过搜索 找到这里 在这里打上断点

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6558bb28a7f42ea3de2f18d1ca0585b57e3d14e2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-ce30c28a2c03c0ab6aa2f8693820fa9a4a957a4a.png)

访问之后 确实是走到这里来了 所以直接jsp文件无法利用

那么这里 既然存入文件的过程没有什么过滤 直接利用跨目录的方式写一个war包到 但是这里前提得用tomcat搭建 因为我之前直接用的springboot的 重新切换到tomcat

- jspxcms安装包(部署到Tomcat)：<https://www.ujcms.com/uploads/jspxcms-9.0.0-release.zip>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a090fbb843fdc4f9f9bcc9c4972a395e4590cf0c.png)

也是有安装手册的

根据手册把配置文件改了 然后启动tomcat

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bfc4121b0456f3a266019a2b85dfa5ff22d6d148.png)

然后来到上传的地方

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f3efc340a0c24b1fb9c7d993db42672df8827a7f.png)

先准备恶意的zip包

把一句话打包成war包

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8f67fafdc0c8569143e7be41bc2b1f973a2f9a30.png)

然后把war包压缩 这里得用到脚本来

```php
import zipfile

file = zipfile.ZipFile('shell.zip','w',zipfile.ZIP_DEFLATED)

with open('test.war','rb') as f:
    data = f.read()

file.writestr('../../../test.war',data)
file.close()
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c22774ec9e4f2d4a1536323a332d4f5806bf0014.png)

然后上传

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-380664bc1fd85ad84da9fe1397b81de5acd647a1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-59bb8cc14b969b1fe4e438ee3f9282f8697155a7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c49ee62c73725fbdddcdca37b40cd36f7a228572.png)

冰蝎连接

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-492ab1996e859d1e9197afa48adb7ac1cd62c25b.png)

##### 第二处

在pom.xml中发现该系统用的shiro版本是1.3.2

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-cc0ea2f74563d5625915ae150813ed77c1b6bb65.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-25be1198144da446ee0b2de72e81446a067c7970.png)

符合shiro-721的条件 现在版本符合了 就需要寻找构造链了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c31308f5595708681f045596a000458d1142c124.png)

这是该系统的 和ysoserial的利用链的版本有些差异 但能不能用 先测试一下

要了一个payload

然后利用exp脚本 开始爆破

<https://github.com/inspiringz/Shiro-721>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0f09addef2e5d4bcb707c66cfdef282ce508a924.png)

爆破的时间有点久

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-4c325e27bf0aaf903015d0e26a137c6ab39af9b1.png)

然后把cookie复制 我们来执行

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-75f25e070fc825f3b551811921e9f9329786815e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-eb60db50cb2c129c67dbcba1e7f656da2a545d41.png)

反序列化的细节就不在这篇文章叙述了 请听下回分解

参考：<https://www.freebuf.com/articles/others-articles/229928.html>

JAVA代码审计入门篇