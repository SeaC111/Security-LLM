前段时间看到某系统爆出一个RCE，随后找到了源码对漏洞进行分析，并利用历史漏洞找到了其他突破点，进而找到新的漏洞。

0x01 历史漏洞分析
===========

首先来看一个历史漏洞，Ognl表达式注入导致RCE，具体payload如下

```php
POST /common/common_sort_tree.jsp;.js HTTP/1.1
Host: xx.xx.xx.xx
Accept-Encoding: gzip, deflate
Content-Length: 174
Accept-Language: zh-CN,zh;q=0.8
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Connection: close
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded

rootName={%25Thread.@fe.util.FileUtil@saveFileContext(new%20java.io.File("../web/fe.war/123.jsp"),new%20sun.misc.BASE64Decoder().decodeBuffer("d2hvYW1p"))%25}
```

首先该系统在未登录的状态下默认是无法直接访问一些jsp文件的

在`web.xml`中可以看到对jsp的使用的过滤器

![image-20240104160205503](https://shs3.b.qianxin.com/butian_public/f9361633ca19d02c61b75a98b933a8033f048af53b09c.jpg)

查看ControllerFilter5中的doFilter

![image-20240104160356868](https://shs3.b.qianxin.com/butian_public/f79403784bb904e1bae93b0d5f8af90e425e4f4713bdd.jpg)

发现会判断uri的结尾是否是`.jsp`，判断jsp是否在白名单列表里，如果不在则返回302重定向到登陆页面，可以可以利用tomcat特性使用`;`绕过，因为 在URL中遇到`;`号会将`;xxx/`中的**分号与斜杠之间的字符串以及分号本身**都去掉，当然也可以用url编码绕过，这点在这里不做过多分析。

然后通过payload可以看到漏洞点在common\_sort\_tree.jsp，并且Ognl表达式通过`rootName`参数传递并执行，然后查看具体代码：  
![image-20240103143412286](https://shs3.b.qianxin.com/butian_public/f2603353e43a0edf80e32fc99c8eac8b4ab5bb2c025c2.jpg)

通过查看该jsp文件可以看到`rootName`通过传参得到，然后传入`builder.buildExp`方法

![image-20240103161201521](https://shs3.b.qianxin.com/butian_public/f45996103ebe9c737f470917d84f33567804849df3dfc.jpg)

传入的语句首先会进行`compiler`生成一个列表，这个方法的主要功能是将输入的表达式进行编译，生成子表达式的列表，并在必要时替换原始表达式中的子表达式。该方法使用了一些标签和映射（`startMap` 和 `stopMap`）来辅助解析和替换。

![image-20240104102252861](https://shs3.b.qianxin.com/butian_public/f108100d31fbbc6f38c508fd13d5f0063a250a2e874cb.jpg)

然后在bean.xml中定义了一个`parseMap` 它表示了每个标签所对应的类方法，例如在payload中使用的是`{%%}`就对应使用的是`objectValueParseImpl`bean 的标识符

![image-20240104105559790](https://shs3.b.qianxin.com/butian_public/f50719129122948422ddc8090febd04d56d2c39075db9.jpg)

然后使用该类的实现作为 bean 的实例。.

然后在初始化方法的时候，遍历`parseMap`，并且取前两个字符和后两个字符分别作为start(起始符)和stop(结束符)

![image-20240109111700053](https://shs3.b.qianxin.com/butian_public/f674442452b795ce9cf18112ae39c452d02e910a9970d.jpg)

然后使用`this.analyse.addParse`，生成`mapValue`

![image-20240109111729020](https://shs3.b.qianxin.com/butian_public/f1253516c7acee5e3cfd8734d1b4b7f4a18c76563274e.jpg)

然后使用`tanalyse.analy`进行分析并返回结果

![image-20240103162218299](https://shs3.b.qianxin.com/butian_public/f21457630da726e387c9cf76b05f1fa0d132789b5a910.jpg)

在`analy`中提取开始标签和结束标签和内容content

![image-20240103185239728](https://shs3.b.qianxin.com/butian_public/f39444177095a31c14ae1289f4e5cc0f8557a1782e6e2.jpg)

然后再这个`analy`方法中，首选会确定需要调用的函数，使用`this.mapValue`通过`stop`也就是尾部标识符获取对应的类名，这里的`this.mapValue`是一个hashmap，然后使用最下面的`p.load`调用对应的方法。在该方法中然后调用了`getValue`，这里代码就省略了

![image-20240103162416212](https://shs3.b.qianxin.com/butian_public/f512565408fcef2580c050adab539d901a85f51ad5bf1.jpg)

最终到达`Ognl.getValue`并执行Ognl语句造成RCE。

0x02 其他漏洞发现
===========

了解完了历史漏洞触发的流程，可以发现漏洞的根本原因是最开始的`builder.buildExp`方法对参数过滤不严格造成的，如果按照这个思路去找漏洞，可以看看还有哪里调用了这个方法，并且参数是否可控。

![image-20240103163818411](https://shs3.b.qianxin.com/butian_public/f6729714c9edac77feb310cc0010cde0876449bc62b88.jpg)

![image-20240103163848599](https://shs3.b.qianxin.com/butian_public/f226624435f15ce1ffbedcb664b068a1122fd622e52dc.jpg)

分别在jsp和jar包中搜索相关关键字，发现没有其他的引用。

但是当我们回头看这个类中所定义的其他方法时，发现了其他和`buildExp`相似的方法

例如`build`，他和`buildExp`除了方法名不一样内容都是一样的

![image-20240103164236167](https://shs3.b.qianxin.com/butian_public/f27142847dddaf1694d244212af01dd8cb46213650502.jpg)

包括其他方法，也有简介的调用了`build`方法，例如：

![image-20240103164410533](https://shs3.b.qianxin.com/butian_public/f2350676a493f28e63e6ef25de8bb5f33a37fe195fc8f.jpg)

所以这就大大扩大了我们的寻找范围，通过正则`[\.| ]+builder\.build`，找到了很多调用的地方，接下来就是看看哪些参数可控

![image-20240103165331976](https://shs3.b.qianxin.com/butian_public/f327283994ab643dc9f16fe6ca589acf78eac4ff8828d.jpg)

这里找到其中一个，也就是上图搜索结果中的第一个：

![image-20240103165822965](https://shs3.b.qianxin.com/butian_public/f4440580aa3f87117046c8a44e5deb17cecec08eb1a69.jpg)

但是这里的event会经过`loginInvokeCtrl.formatLogic`的格式化，在这个函数中，会在`logic`前后加上标识符，

![image-20240103170115194](https://shs3.b.qianxin.com/butian_public/f240140dc8539d098ba9a3dac769587bf87afc3235e12.jpg)

但这并不影响，因为在build中的compiler会一层一层剥离语句，首先会执行最内层的标签里的语句。

接着继续追踪`executeLogic`看哪些地方调用了

![image-20240103170651832](https://shs3.b.qianxin.com/butian_public/f581751cd18769dab9d721784e1330f9d3a989892c1d8.jpg)

在`execute`中，这两处均被调用了，并且参数时通过`request.getParameter`获得的，也是可控的。

但是该语句是在一个if判断条件中，需要满足用户登录或者指定的methodName和springId，这两个值也是通过`request.getParameter`直接获取到的

![image-20240103171241635](https://shs3.b.qianxin.com/butian_public/f164540d979d88b1eda1517b983968156b49cb4b6df1f.jpg)

然后继续向上追踪，终于找到了触发的地方`doPost`

![image-20240105145820920](https://shs3.b.qianxin.com/butian_public/f611379abda710b02146392841940cfd59aca915099c3.jpg)

同样找到了它的url映射路径。至此，请求路径，以及所有的请求参数都是可控的，且请求参数可以直接传递到具有漏洞的方法里。