简介
==

这次是一次网盘搜索找到的代码。原本因为要下载一些资源顺手充了个网盘会员，结果发现意外的发现网盘搜索出来的资源还挺丰富。于是便开始搜索一些源码。。。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a762c5360242fdc6cc2352d028f1821b44e1fa12.png)

然后安装完毕之后进入web目录中，将web目录单独打包出来。  
ps: 由于源码貌似是个备份文件，所以不是很完整，缺少数据库文件源码无法本地安装。（痛点）

找到关键的dll文件，放入dnspy然后导出工程方便之后在vs中打开查看。首先拿到.net源码应该查看webconfig文件。在webconfig文件中可以找到重要的dll，比如web的Controller是哪个dll的。这里不多赘述，详情可看msdn文档，非常之详细。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-4eeeda67821a35b3ff4f88a3774a2da270bbef2a.png)

### 0x01 逻辑缺陷

首先是身份认证逻辑的缺陷，对于用户身份的识别程序没有选择传统的session中判断用户是否登录，而是要求用传递一个token的值，通过判断token值是否等于某字符串来进行一个登录的校验。这个漏洞也将作为基础导致了接下来的一系列未授权漏洞的出现。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-f710e297fb8a98fa042bd03bcdafd79225340f1e.png)  
首先看到代码 **base.IsAuthorityCheck() == null** 判断了登录状态是否为空，这里可以跟进**IsAuthorityCheck**函数看看具体的判断逻辑。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-31f184fb2169d3be545edc771a5d147d6d533d1e.png)

因为条件**base.IsAuthorityCheck() == null** 判断了是否为空，那么我们只需要让**IsAuthorityCheck**返回一个非空的值就可以了。根据逻辑往下走，发现`byValue == “zxh”` 的时候会返回一个UserInfo对象，那么也就是返回一个非空值。

回看到第25行，跟进`getByValue`函数

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-9b9b326fec4b9fe26a7dbd548fbc4e09ded7cea9.png)

getByValue函数如下：  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-5dc3d56829597091b22121b6825fd5a3099992b4.png)

这段代码是Web中用于从请求的参数中获取特定值。解释一下：

1. `base.Request.Properties["MS_HttpContext"]`：这部分代码通过基类的Request对象获取一个名为 "MS\_HttpContext" 的属性，该属性用于存储HttpContextBase对象。
2. `(HttpContextBase)`：这是一个类型转换操作，将上一步获取的属性值转换为HttpContextBase类型的对象。`HttpContextBase`是.net中的http类，简单看成是一个http请求即可，详情：[https://learn.microsoft.com/zh-cn/dotnet/api/system.web.httpcontextbase?redirectedfrom=MSDN&amp;amp;view=netframework-4.8](https://learn.microsoft.com/zh-cn/dotnet/api/system.web.httpcontextbase?redirectedfrom=MSDN&amp;view=netframework-4.8)
3. `.Request[value]`：最后，从上述转换后的 HttpContextBase 对象中获取名为 "value" 的请求参数的值。value是刚刚传递过来的参数，也就是25行的token。

因此，整体来说，这段代码是从 HTTP 请求的参数中获取名为 "token" 的参数。然后判断参数是否是zxh，如果是则返回一个UserInfo对象，然后通过身份认证。也就是说和cookie，session等身份认证不挂钩，登录判断只需要有token字段并且内容是zxh即可。

&gt; 这也是api中常见的安全问题，因为有时候api确实不好做登录验证，常常都会使用一个字段去判断是否登录，但是如果这个字段是静态的，固定不变的则可能引发未授权访问等一系列安全问题。

### 0x02 sql注入

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-9d1e07113e047ce6bfdd7de1e8cca41798099895.png)  
绕过了token验证之后，程序从http中获取了sqlParamenters参数，然后再次判断sqlParamenters是否为空如果不为空就执行ExecuteSqlForSingle函数。其中sql参数则是要执行的sql语句。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-e44ad5f3dd8190cf14ab1fce822c04f641c58d6e.png)  
其实到这里可以选择跟进或者是不跟进，因为如果跟进的话，还需要分析另外的一个dll。一般情况下我都是会直接试一下poc，如果能够运行成功，那么则不跟进，反之则跟进函数看看是否存在一些过滤。像这种看样子是没过滤的，可以尝试直接试一下是否存在注入。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-ea1b96eb46468c043815bb3ff1f373f4464b39cd.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-54e11cc1ce3ee1c915fbfe8d02f713e307b77051.png)

可以看到确实存在sql注入，能够直接执行sql语句。

#### 后话：

如果想跟进看看具体原理就是找到这个Service的dll。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a727c3fabe28b106dbb7aa20ba59d87cf2416083.png)

然后找到systemService的ExecuteSqlForSingle函数

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-d59d8fa914b946677e4343d83324eca8b1e126bd.png)

然后跟进ExecuteScalarSQLToObject可以发现没有任何过滤，直接执行sql语句。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-8670dea7f5cb8c99c6169f6fd7cd780a353b4394.png)

#### 题外话：

还能够看看webconfig文件的sql配置，如果默认用户是sa的话，可以通过sa这个用户直接使用xp\_cmdshell直接执行windows cmd命令。这也是.net中比较有意思的一点，注入有时候就是rce。因为.net大多数都是用sql server作为数据库，而sql server有个xp\_cmdshell可以执行系统命令。

### 0x03 文件上传1

对于.net的文件上传来说可以通过一些controller命名的方式寻找突破口，比如很多开发都习惯性命名为fileController表示文件操作的控制器，比如uploadController，fileController，downloadController等等命名的Controller就是极好的一个突破口，很容易能寻找到各种文件操作的控制器。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-7a0bdc2be74d0234269b0f71210c3da4f09acaaa.png)

这套源码就存在了一个较为常见的文件上传。通常oa系统都会需要上传一些文档比如xls表格或者word，pdf等附件之类的用于办公需求，但是如果没有对后缀名进行过滤，那么就会造成黑客通过文件上传漏洞获取服务器权限。

比如代码如下Upload函数，token已经通过漏洞1的逻辑缺陷进行了绕过。然后程序获取了FileName以及fs两个参数，其中fs就是文件的内容。

fs经过了JsonConvert的反序列化，将字符串内容转换成了Byte数组。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a6e5d42aec1498ac6cc38607b98132c5029bca76.png)

跟进Upload函数，发现FileName就是传递过来的文件名。最后作为一个path给到文件流，文件流最后会写入成真正的文件。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-515f21c8644dd38a936839e68ff224c84d6d57c6.png)

MemoryStream 是一个在内存中创建和操作字节流的类。它继承自 Stream 类，提供了读取和写入字节数组的方法，可以方便地进行内存中的数据操作。也就是说我们传递的http参数fs将会以byte编码的方式传递到fs变量fs变量经过了MemoryStream然后写入到文件。

比如http传入的是\[97,97,97\]这个byte数组那么经过MemoryStream写入文件就是aaa的形式，因为a的ascii码是97

![1711438160800.jpg](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a506ccdf2a7262a8e782ce656f7600f9d63b7e29.jpg)

然后a.txt只是为了省事随便写的，实际上是由http参数传递过去的。现在看看真正的效果。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-c889c51de7ac1ff360853e499e22a20aa513ceaf.png)

访问发现

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-637354f625f25433a369e42f8222b68202da79f8.png)

### 0x04 文件读取

同文件上传类似，基本上一个Controller某个方法如果没有任何防护，基本上整个Controller都没有防护。比如对上传的文件名没有做任何限制，那么对于文件读取的文件名大概率也是没有任何限制的。任意文件读取危害可大可小。任意文件读取在某些情况下危害是同等于文件上传的。比如某些api是对上传没有任何限制但是只限于后台文件上传，这个时候可以用任意文件读取读取数据库的备份文件从而寻找密码进行getshell。还有java的一些文件读取，比如java应用使用了shiro组件的同时还存在任意文件读取漏洞，那么攻击者完全可以通过读取java的shiro的jar包获取shirokey进行getshell。也可以通过读取ssh密钥（需要高权限）等等方式去进行利用。

程序代码如下：

![1711460694276.jpg](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-eba0e264fb7c3dadf50056cbedfd5845285b128b.jpg)

通过requestFileName参数作为文件名然后去读取文件。可以看到虽然限制了文件夹路径，但是并没有过滤掉../的方式，还是可以通过../的方式去对目录进行跨越从而造成任意文件读取。

![1711460729394.jpg](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-b1a4bcda599be9526c97399a66a2c9937b1adc75.jpg)

![1711460674240.jpg](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-f9370fa61faf71e57d2af8363d18058a32ad8767.jpg)

跟进getBinaryFile

![1711460748509.jpg](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-be78bb56d8f30a311cb68a0c7e3b5bffe4012bfc.jpg)

然后读取文件。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-e283e5e24a141aaddfeff7253f57684b000bfdbe.png)