0x01路由信息
========

在审计.net时，首先要看的就是`web.config`，其中包括了网站的一些配置文件，包括数据库的连接信息和网站访问的路由。

其中`<httpHandlers>` 元素是用于配置 HTTP 处理程序的一部分。HTTP 处理程序是处理传入 HTTP 请求的组件，它们可以用于响应特定类型的请求。

![image-20240226101706908](https://shs3.b.qianxin.com/butian_public/f51607664af657257f98beee19b2587c5fcb5f5fac248.jpg)

`verb`表示请求的方式，例如POST，GET。`*`表示任何方式。

`path`表示请求的文件，`*`表示通配符。

`validate`表示指定是否要验证已配置的 HTTP 处理程序。

`type`表示请求该文件时处理类的名称空间完整路径

例如这里如果请求后缀是以`.ajax`就会访问`Carpa.Web.Ajax.AjaxHandlerFactory`，通过查看bin文件下，反编译`Carpa.Web.dll`文件

![image-20240226141419170](https://shs3.b.qianxin.com/butian_public/f3609211f36cf0eb358b7944c1f13fc09333da1d2c817.jpg)

可以看到`AjaxHandlerFactory`类继承了`IHttpHandlerFactory`，他的作用是对IHttpHandler进行管理。`GetHandler`返回实现IHttpHandler接口的类的实例

![image-20240226161716489](https://shs3.b.qianxin.com/butian_public/f70234557c809fdd60b3a124b7540bf73ebe82b3d343e.jpg)

这里首先会判断附加路径信息，长度是否大于2且是否包含/，这要调用的方法名`methodName`即为附加路径信息，`Substring(int startIndex)`指定了要开始提取子字符串的位置，该方法返回从 `startIndex` 位置开始直到原始字符串末尾的子字符串。这里的Substring(1)是为了去除最前面的`/`

举个例子：

例如在登录的时候，会发送这样一个请求包

```php
POST /A8TOP/CarpaServer/CarpaServer.LoginService.ajax/UserLogin HTTP/1.1
Host: 192.168.70.1
Accept: */*
Accept-Language: zh-CN
Cookie: ASP.NET_SessionId=hqynyrsamsa1a5sfvwcqkeer
Content-Type: application/json; charset=utf-8
X-JSONFormat: true
Pragma: no-cache
Referer: http://192.168.70.1/A8TOP/ClientBin/CarpaClient.xap?v=392401900
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E)
X-ClientType: SLJson
Content-Length: 198

{"user":{"name":"admin","password":"123456","isChange":"","verificationCodeId":"","verificationCode":"","database":"002","lockNum":"err","userRank":NaN,"HardDiskNo":"errdisk","MacAddress":"errmac"}}
```

实际就是请求`LoginService`类中的`UserLogin`方法

![image-20240321162225287](https://shs3.b.qianxin.com/butian_public/f328003b18b725cfe62b9965b317cb5794bb3dfcd9374.jpg)

0x02鉴权分析
========

在调用方法之前会首先通过`CheckHasLogin`来进行鉴权，当`CheckHasLogin`返回True就可以跳过throw new Exception

![image-20240227111115534](https://shs3.b.qianxin.com/butian_public/f7564447ec247e501a125e8af814004c170d887bcab2c.jpg)

接下来看看`CheckHasLogin`中是如何判断的

![image-20240227111838921](https://shs3.b.qianxin.com/butian_public/f9854817c846c72264c737768bdb818f7cfbee887eced.jpg)

这里会传入一个`needLogin`，当`!needLogin`符合条件是会直接return true，或者就是从context中获取session进行判断是否登录。

而这里的needLogin时通过调用 `IsDefined` 方法来检查调用的类或方法是否定义了 `NeedLoginAttribute` 特性

![image-20240227141512340](https://shs3.b.qianxin.com/butian_public/f403726994ea9f1d94fa632ac81bbc0f3fc5f416e08c3.jpg)

这里提一下c#特性的解释，熟悉python的读者可以在某种程度上理解与装饰器有相似的目的。

> ## C# 特性（Attribute）
> 
> **特性（Attribute）**是用于在运行时传递程序中各种元素（比如类、方法、结构、枚举、组件等）的行为信息的声明性标签。您可以通过使用特性向程序添加声明性信息。一个声明性标签是通过放置在它所应用的元素前面的方括号（\[ \]）来描述的。
> 
> 特性（Attribute）用于添加元数据，如编译器指令和注释、描述、方法、类等其他信息。.Net 框架提供了两种类型的特性：*预定义*特性和*自定义*特性。

例如下面这里，在类前面使用方括号 `[]` 表示的是类的特性（Attributes）

![image-20240227150627423](https://shs3.b.qianxin.com/butian_public/f36482923d8061927f9bff9144e1371d3063a80eca813.jpg)

至于为什么之前判断的是`NeedLoginAttribute`，是因为C#中定义一个类的特性，你需要创建一个类并继承自 `System.Attribute` 类，它的特性类通常命名为`SomeNameAttribute`的形式，其中`SomeName`是特性的名称，而`Attribute`是固定的后缀，用于表示这是一个特性类。在使用特性时，通常省略`Attribute`后缀，直接使用特性的名称即可。例如在这个系统中定义的就是`NeedLoginAttribute`，实际使用中可以省略`Attribute`后缀

![image-20240227151105694](https://shs3.b.qianxin.com/butian_public/f523587cf97ad321dd84bdf7e1a9ab2b8425dab31aaf1.jpg)

0x03漏洞审计
========

这里审计主要是审计未授权的漏洞，所以首先要筛选出类中不包含`[NeedLogin]`的类，这里可以先把所有文件都反编译成cs文件，然后使用python脚本筛选掉包含`[NeedLogin]`的字符串：

```php
import os
import re
import shutil

# 遍历文件夹
def traverse_directory(source_dir, dest_dir):
    for root, dirs, files in os.walk(source_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if not contains_need_login(file_path):
                copy_file(file_path, dest_dir)

# 检查文件内容是否包含[NeedLogin]
def contains_need_login(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            if '[NeedLogin]' in line:
                return True
    return False

# 复制文件到目标文件夹中，保留目录结构
def copy_file(file_path, dest_dir):
    relative_path = os.path.relpath(file_path, os.getcwd())
    dest_path = os.path.join(dest_dir, relative_path)
    dest_folder = os.path.dirname(dest_path)
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    shutil.copy(file_path, dest_path)

# 源文件夹和目标文件夹路径
source_directory = 'source'
destination_directory = 'source2'

# 遍历文件夹并复制符合条件的文件
traverse_directory(source_directory, destination_directory)
```

除此之外，在 Web Service 程序中，如果要使一个公共方法能够被外部访问和调用，需要为该方法添加`[WebMethod]`属性。只有添加了这个属性的公有方法才可以被外部访问，而没有添加该属性的方法则无法被访问。所以我们只查找添加了`[WebMethod]`属性的方法。

漏洞寻找
----

寻找sql注入漏洞，首先看看原本的sql语句是通过什么方法执行的，可以搜索关键字sql,dbHelper等关键字，发现这套程序里有三种执行sql语句的方法：  
一种是通过`this.dbHelper.SelectFirstRow()`执行，例如下图，这种是使用了预编译进行这种执行的，可以有效阻止sql注入

![image-20240228150927417](https://shs3.b.qianxin.com/butian_public/f888927b470b9bb42a693128177d6fb54fa10dca6c576.jpg)

第二种方法是直接拼接sql语句，然后通过`dbHelper.Select`执行，例如下图，这种情况如果被拼接的参数可以通过传参获取且未进行过滤就可以造成sql注入

![image-20240228151415480](https://shs3.b.qianxin.com/butian_public/f7658831baa8c05c0e52389aa9cba1ac4d2ba9779a082.jpg)

第三种是通过`string.Format`格式化的方式来拼接sql注入，例如：

![image-20240301163909793](https://shs3.b.qianxin.com/butian_public/f783306017c45617fac5be3d9705bd500483dfa67ef63.jpg)

初次之外，该方法必须要被添加了`[WebMethod]`属性的方法直接或间接调用才可以直接通过 HTTP 协议进行调用。

所以使用正则`string sql = ".+?"[\s]*\+`和`string.Format\("SELECT.*?"\)`匹配关键语句

![image-20240228162737666](https://shs3.b.qianxin.com/butian_public/f46445651ded7a3676e062565427fbbe3184161a95083.jpg)

![image-20240314154328713](https://shs3.b.qianxin.com/butian_public/f1880136e7bb31b45101cdcf9d14b860c3bc62887dae4.jpg)

这里我们随便找一处

![image-20240301103134084](https://shs3.b.qianxin.com/butian_public/f5270937a9101b880573593199ce5b0ba0c799817dfc3.jpg)

这里传递过来的参数直接拼接后去执行，但是正当我兴高采烈去发发包时，发现报错了，没有指定连接字符串

![image-20240301103435706](https://shs3.b.qianxin.com/butian_public/f421665ecb5598966f75d8e46ae74e3a81ea38267c1b8.jpg)

失败原因
----

这是怎么回事呢？经过继续研究发现他在通过`AppUtils.CreateDbHelper()`进行实例化对象`dbHelper`的时候，连接字符串是从`UserInfo`中获取的

![image-20240301104220406](https://shs3.b.qianxin.com/butian_public/f574347ba806533070bfd35b01e1e49deb469138d14eb.jpg)

说明这是一个需要登陆以后才可以进行的sql注入

![image-20240301104344817](https://shs3.b.qianxin.com/butian_public/f852831e9ab7cc9ab4e76e43926645c03bad3fb18cdb8.jpg)

然后通过登录添加cookie后可以正常注入

![image-20240301104448237](https://shs3.b.qianxin.com/butian_public/f625697e2687f396ebc7fd505eb31fd2be71f2804dc42.jpg)

绝境逢生
----

正当我决定到此为止时，突然看到`CreateDbHelper`方法下面还有一个重载的方法，他接受了一个`database`的字符串，这样是不是就代表有地方调用了重载的方法，从而不需要从UserInfo中获取连接字符串。或者是直接调用了`DbHepler`传入数据库名字。

![image-20240301104554778](https://shs3.b.qianxin.com/butian_public/f62690754d112faef5604dfdb527f69c5321d87b107fc.jpg)

所以我们将上面的python代码修改一下，将符合两种情况的文件再筛选出来

```php
def contains_need_login(file_path):
    with open(file_path, 'r', encoding="gb18030", errors='ignore') as file:
        for line in file:
            if re.findall('new DbHelper\(.+?\)\)', line):
                return False
            if re.findall('CreateDbHelper\(.+?\)\)', line):
                return False
    return True
```

当然这里可以把`[webmethod]`加入筛选，但考虑到有些方法可能会通过间接调用，这样筛选可能会漏掉一些方法，所以暂时没有加入

继续使用正则查找，找到这样一处，这里接受三个参数，第一个参数是数据库名字，第三个参数是一个json类型的字符串，并且json中的`etypeid` 或`vipcardid`的值拼接到sql语句中进行执行

![image-20240314170707196](https://shs3.b.qianxin.com/butian_public/f124900da9549780c77e51c0860197afefbb67f3c58fd.jpg)

![image-20240314170846189](https://shs3.b.qianxin.com/butian_public/f181765ceea77e2ff9c3f9d140999e3c7f74c5a157a8b.jpg)

最后没有携带任何cookie未授权成功执行。

另外通过`string sql = ".+?"[\s]*\+`这样的查找方式也可以寻找到几处，有感兴趣的小伙伴可以亲自尝试一下。