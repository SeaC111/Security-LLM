CORS漏洞
======

CORS（Cross-Origin Resource Sharing）是一种用于Web应用程序的安全机制，用于控制在浏览器中一个网页能够访问来自另一个源（域名、协议或端口）的资源。CORS漏洞指的是在CORS机制实现上存在的安全问题。

1. 简介
-----

CORS漏洞指的是当一个网站未正确配置CORS策略时可能会导致的安全问题。如果服务器未正确配置CORS规则，攻击者可以通过在恶意网站上的JavaScript代码，利用用户在浏览器中登录受害网站的凭据，从而发送跨域请求到受害网站并获取敏感信息。这种漏洞可能会导致信息泄露等安全问题。

下面用AB两个网站举例，A网站表示正常网站，B网站是攻击者的网站。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-8f9d21b933ec30a66445773390bbf58de8c4714d.png)

A网站有个接口，是返回用户个人信息的。先判断用户是否登录，如果登录那么就会返回登录信息，如果没有登录则返回未登录的消息。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-4a8ee5fb645c7dbcb0542e127515b1632360feae.png)

登录代码如下：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-ac23fc2ae566e95e06c5323d00b487ab7e741cfc.png)

如果登录成功，那么访问getinfo会得到一个json数据，登录失败则是提示重新登录。

登录成功如下：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-1036db3e8d3cb09725b6ce4e71792a8d4f5fe28e.png)  
未登录情况如下：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-562bb8dad1475242f24ac0d1cba6b5e906a0c84d.png)  
那么假设我们在a网站登录成功的状态下，这时候访问getinfo接口的时候返回了身份信息。那么这时候又去访问b网站。b网站是一个恶意网站，b网站的js会发送一个请求，请求的是a网站的getinfo接口。b网站的代码如下：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-ddd1900c273f008829508721143162ac0a30d7db.png)

很简单就是一个img标签，通过src属性对getinfo接口发送请求，那么这时候是不是会附带a网站的cookie过去，然后就可以劫持a网站的用户信息。示意图下：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-47505ddf5aa8b9c7c9680211b82f716dfd9fdf3b.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-65da9d656bf8e4e2d3efad6be4fe5858706403ae.png)

步骤1：登录A网站

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a4abe5f93a92ae57c2e7559e586f6746d04475b5.png)

步骤2：打开B网站

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-284d2aaacdee1c71044764720161bc06c77aa0ed.png)

也没有返回信息。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-e04348453d8c53d10546fc2085d94f55f7c86650.png)

可以发现其实是不能劫持a网站用户信息的。这是由于浏览器同源策略做了限制。实际上也就是浏览器不会把cookie携带过去。

同源策略（Same-Origin Policy）是一种浏览器安全机制，用于限制不同源之间的交互，以防止恶意网站通过跨域请求获取用户的敏感信息或进行其他攻击。

同源指的是协议（Protocol）、域名（Domain）和端口（Port）相同。如果两个页面的协议、域名和端口都相同，则它们被认为是同源的，可以自由地进行数据交互。而如果其中任意一项不相同，就被视为跨域请求。

同源策略限制了以下行为：

1. Cookie、LocalStorage 和 IndexDB 等存储的读取：跨域请求无法访问目标网站的存储信息。
2. DOM 的访问限制：跨域请求无法获取目标网站的 DOM 元素。
3. AJAX 请求限制：跨域请求无法直接发送 AJAX 请求。

![](https://shs3.b.qianxin.com/attack_forum/attach-3dea37cad4e202ecad55f.png)

然而，同源策略也允许一些特定的跨域行为：

1. 跨域资源共享（CORS）：服务器可以通过设置响应头来允许特定的跨域请求。
2. JSONP：利用script标签的跨域特性，通过动态插入

在真实场景下比如多了一个子域名pay.a.com，这个子域名需要获取到a.com/getinfo.php这个接口的信息，那么这时候getinfo接口就需要配置一下CORS头。

pay.a.com代码如下：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-dc6aaf064353da630d42a976f8e579d5dc931286.png)

执行效果是失败了的，pay.a.com并没有获取到数据，这个是因为a.com还没有配置CORS头信息。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a5fd39b5f8363940afd38eff75d42a0ca654afa9.png)

在getinfo代码上配置一下CORS头

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-b764d672da4de479f3953b1184948df21c611f30.png)

再次请求发现能够获取到数据了，表示跨域成功。  
解释一下两个请求头  
Access-Control-Allow-Origin 用于指示哪些源站有权限访问特定资源。当一个网页试图通过JavaScript从另一个源站加载数据时，浏览器会执行跨来源HTTP请求。在这种情况下，服务器需要设置Access-Control-Allow-Origin标头来明确指定哪些源站具有权限访问资源。比如Access-Control-Allow-Origin这里设置的是http://pay.a.com:8081 就是表示允许http://pay.a.com:8081进行跨域请求。

Access-Control-Allow-Credentials 可以控制是否允许跨域请求携带凭据信息,跨域时要设置为true。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-bce21d47c5361eca4602115b54127bc1b0ac8d9c.png)

第一种情况
-----

漏洞成因, 往往都是开发或者运维人员为了实现业务需求从而导致了配置不当造成CORS漏洞。  
比如配置如下

| HTTP头 | 配置 |
|---|---|
| Access-Control-Allow-Origin | "Origin" |
| Access-Control-Allow-Credentials | true |

导致如上情况的后端代码可能如下：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-51b4795154c716021afe62e8f4aade45d077fa85.png)

**注意：这种情况下其实也是不能成功利用CORS漏洞的。**

攻击网站b.com代码如下（就是把pay.a.com网站的代码复制过去，但是发现pay.a.com能够成功访问到getinfo接口，但是b.com访问getinfo接口不成功）：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-16afa821ab20a5abfa418a3acb8ba5ff6b0c46ec.png)

b.com攻击结果

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-854407684883c2e726f14d2b3357e97343b1f548.png)

然后查看b.com向getinfo接口发送的http请求。从header来说确实是允许跨域的。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-e5d07ca77992f1f7c7f12b32a0f14d3ee9a00f88.png)

因为除了CORS保护cookie之外浏览器还有一个SameStie的保护策略，控制是否随跨站点请求发送 cookie，从而提供一些针对跨站点请求伪造攻击 (CSRF) 的保护。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-27f99fb64506fcfb77b7e74b605bfa54122163d8.png)

SameStie可能的属性值有三个：

| 属性名 | 含义 |
|---|---|
| Strict | Cookie 只能在第一方环境中发送；也就是说，当获取该 Cookie 的网站与浏览器地址栏中显示的网站匹配时，才会发送 Cookie。 |
| Lax | 默认值，意味着 Cookie 不会在跨站点请求（例如加载img或iframe的请求）上发送，而是在用户从外部站点导航到源站点（例如，点击a标签）时发送。 |
| None | 意味着浏览器会通过跨站点和同站点请求发送 cookie。(必须同时设置Secure属性) Cookie 只能通过 HTTPS 协议发送。 |

可以看见SameStie严格程度： Strict &gt; Lax &gt; None  
那么想使得b.com跨域获取getinfo接口的信息，那么getinfo接口还得配置一下cookie。而且要把a.com换成https协议，否则Secure属性不生效。

a.com添加两行代码

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-bf4539a94860eb1cbe3fa5c3f9d123c7adb0405b.png)

可以看到b.com成功跨域访问了getinfo接口并且携带了cookie。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-de56c532c2686cbcd88b0df80e16df6e45dd9dae.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-cc1ce5fb1beebb34592b641640d74bf73e991287.png)

那么得出的结论就是，想要实现CORS劫持，要满足两个条件。  
**1. Access-Control-Allow-Origin可以是任意值且Access-Control-Allow-Credentials为true。  
2.Cookie设置了samesite为None。**

第二种情况
-----

第二种情况其实是第一种情况下面的一些限制使用。比如在实际业务中会限制跨域请求只允许子域名，但是校验却没有那么严格的情况就会出现问题。比如域名为a.com但是跨域请求校验不严格的情况大致有如下三种：

| 校验方式 | 校验内容 | 绕过方式 |
|---|---|---|
| 前缀校验 | 检测前缀是否是a.com | `Origin`：<http://a.com.b.com> |
| 后缀校验 | 检测后缀是否是a.com | `Origin`：<http://xxxxxxa.com> |
| 包含校验 | 检测是否包含a.com | `Origin`：<http://xxxxxxa.com> |

比如代码如下，判断了origin是否包含了a.com：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-307c5c17273bf7fe70cc722361e9dba7c833d17b.png)

原本的方式已经失效了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-4d822962d4f0250c7c633385afb60883784a1329.png)

那么就可以使用a.com.b.com这个域名去进行绕过过滤

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-7af72e7a2e1ef0e77f3281c28f5ceccf3b5bdfa4.png)

第三种情况
-----

这是对第二种情况的一个扩展，当过滤非常严格，确实只允许子域名访问的情况，但是子域名出现了xss漏洞。这个情况使用就可以使用xss植入javascript代码，让子域名替我们完成CORS劫持，并且把数据返回给到攻击网站。

比如创建一个有xss的子域名bug.a.com。代码如下。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-b0fc9198afd6baa8ce8b91eff079640b8370404c.png)

然后可以使用xss使得bug.a.com发送跨域请求。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-e9c7f7bc4e9511fe66eeb3fb9571673998226904.png)

然后只需要iframe标签的src属性变成xsspayload即可。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-35e188713a9bba12c904c826e97c70e7b447321c.png)

第四种情况
-----

这种情况是当Access-Control-Allow-Origin为null时的情况， 通常是开发者在网站上配置信任null源，用于调试代码。然后调试完成后没正确配置直接上线业务。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-f050097b7d2efe7f793d77c5ab74065e6cd4d3d4.png)

这种情况可以使用`iframe`来完成攻击，攻击者可从通过`iframe`的`sandbox`构造Origin为null的跨域请求。

`sandbox` 属性则是用来定义一个沙盒，它可以限制 `<iframe>` 中加载的内容的行为，从而增加安全性。

使用 `sandbox` 属性时，可以设置不同的值来启用不同的安全策略，例如：

- `sandbox="allow-same-origin"`：允许 `<iframe>` 内容与父页面具有相同的源 (origin)，这意味着 `<iframe>` 内容可以访问与父页面相同的资源。
- `sandbox="allow-scripts"`：允许 `<iframe>` 内容执行脚本。
- `sandbox="allow-forms"`：允许 `<iframe>` 内容提交表单。
- `sandbox="allow-top-navigation"`：允许 `<iframe>` 允许嵌套的页面通过顶级窗口来导航或打开新的顶级浏览器上下文。
- `sandbox="allow-modals"`：允许 `<iframe>` 内容打开模态窗口。

比如可以使用如下Payload发送请求  
`<iframe sandbox="allow-scripts" src='data:text/html,xxxxxxx'>`

这里的base64其实就是，index.html页面的javascript编码。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-2da9c12e1e2b0b432526de906d06fa7bbd161177.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-fefb1f8a965c6692a3b53ca10379a816e4131371.png)

发现确实能够跨域拿到数据，并且origin设置为null。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/04/attach-132767e53ee55d4aebc317220ddf2390a7f28d7d.png)

总结
==

CORS（跨域资源共享）是一种浏览器机制，它允许 Web 应用程序在浏览器中向其他域发送跨域 HTTP 请求，以实现跨域数据访问。但是，如果 CORS 配置不当，可能导致安全漏洞。以下是一些与 CORS 相关的漏洞和安全注意事项的总结：

CORS漏洞类型：

- 允许Origin为任意值：如果服务器配置允许任意来源的请求，则存在风险，因为攻击者可以通过发送恶意请求来获取敏感信息。
- Origin为空值：如果Origin为null，攻击者可以使用ifrmae标签进行绕过。

CORS前提条件：

- Access-Control-Allow-Origin可以控制 （或者说可以被绕过）
- Access-Control-Allow-Credentials 为true
- SameSite为Low

特殊条件：

- Access-Control-Allow-Origin为null
- 子域名存在xss

资源
==

> CORS的详细介绍：  
> <https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CORS#access-control-request-headers>
> 
> SameSite的详细介绍  
> <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value>

所用代码如下：  
getinfo.php

```php
<?php
ini_set('session.cookie_secure', "1");
ini_set('session.cookie_samesite', 'None');

session_start();

//$origin = $_SERVER['HTTP_ORIGIN'];
//$allowed_domain = 'a.com';
//
//if (strpos($origin, $allowed_domain) !== false) {
//    header('Access-Control-Allow-Origin: ' . $origin);
//    header('Access-Control-Allow-Credentials: true');
//}

header('Access-Control-Allow-Origin: null');
header('Access-Control-Allow-Credentials: true');

header('Content-Type: application/json');
if (isset($_SESSION['isLogin'])) {
    $data = array(
        'name' => 'admin',
        'pass' => 'admin'
    );
    $json = json_encode($data);
    echo $json;
} else {
    echo json_encode(array('msg' => '未登录'));
}
```

login.php

```php
<?php
ini_set('session.cookie_secure', "1");
ini_set('session.cookie_samesite', 'None');

session_start();
var_dump($_POST["username"]);
if ($_POST["username"] === "admin" && $_POST["password"] === "admin") {
    $_SESSION['isLogin'] = true;
    header("Location: getinfo.php");
}

?>

<form action="login.php" method="post">
    <input type="text" placeholder="username" name="username">
    <input type="password" placeholder="password" name="password">
    <input type="submit">
</form>
```

b.com的index.html

```html
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://a.com:8081/getinfo.php', true);
    xhr.withCredentials = true;
    xhr.onreadystatechange = function () {
        if (xhr.status === 200) {
            console.log(xhr.responseText);
        }
    };
    xhr.send();
</script>
```

xss.html

```html
<iframe src="https://bug.a.com:8081/index.php?name=%3Cscript%3E%20var%20xhr%20=%20new%20XMLHttpRequest();%20xhr.open(%27GET%27,%20%27https://a.com:8081/getinfo.php%27,%20true);%20xhr.withCredentials%20=%20true;%20xhr.onreadystatechange%20=%20function%20()%20{%20if%20(xhr.status%20===%20200)%20{%20console.log(xhr.responseText);%20}%20};%20xhr.send();%20%3C/script%3E">

</iframe>
```

iframe.html

```html
<iframe sandbox="allow-scripts" src="data:text/html;base64,PHNjcmlwdD4KICAgIHZhciB4aHIgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTsKICAgIHhoci5vcGVuKCdHRVQnLCAnaHR0cHM6Ly9hLmNvbTo4MDgxL2dldGluZm8ucGhwJywgdHJ1ZSk7CiAgICB4aHIud2l0aENyZWRlbnRpYWxzID0gdHJ1ZTsKICAgIHhoci5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbiAoKSB7CiAgICAgICAgaWYgKHhoci5zdGF0dXMgPT09IDIwMCkgewogICAgICAgICAgICBjb25zb2xlLmxvZyh4aHIucmVzcG9uc2VUZXh0KTsKICAgICAgICB9CiAgICB9OwogICAgeGhyLnNlbmQoKTsKPC9zY3JpcHQ+"></iframe>
```