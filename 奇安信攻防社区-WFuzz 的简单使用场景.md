WFuzz 是开源的一款针对 web 应用模糊测试的开源软件，使用 Python 编写，测试的漏洞类型主要包括：未授权访问、注入漏洞（目录遍历、SQL 注入、XSS、XXE）、暴力破解登录口令 等。项目地址：

> <https://github.com/xmendez/wfuzz>

使用文档：

> <http://wfuzz.readthedocs.io/>

所需 Python 环境 Python 3.4+，安装方式：

> pip install wfuzz

或者：

> git clone git://github.com/xmendez/wfuzz.git &amp;&amp; python setup.py install

安装完成之后，查看界面：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9d3af703449d4fa232359f4ff4285d41109f145f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9d3af703449d4fa232359f4ff4285d41109f145f.png)

接下来用 DVWA 靶场作为目标进行工具测试，靶场地址：

> <http://vul.xazlsec.com:8080/login.php>

首先看到的是一个登录框，在我们不知道账号密码的情况下，如何 fuzz 出账号密码呢？

### 绕过 CSRF Token 继续爆破

我们可以使用 BurpSuite 看一下登录的数据包：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3d7fbda8919f9e91b7a032ae386f983f6d8316cb.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3d7fbda8919f9e91b7a032ae386f983f6d8316cb.png)

我们看到除了账号密码之外，还有一个 user\_token 的参数，这个是为了防止暴力破解而设置的 CSRF Token，每次打开页面都会生成一个新的 token，所以每次暴力破解的请求都需要将新的 token 获取到，然后填入参数中，所以需要增加一步操作，对于 wfuzz 而言，貌似没有这个绕过 csrf 爆破的功能，我们可以使用 Burp 的一个插件 `CSRF Token Tracker`，前往 burp 的扩展商店搜索 `csrf` 即可：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-79ef462fff9736780128edff330b4f46d8a1ccb1.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-79ef462fff9736780128edff330b4f46d8a1ccb1.png)

使用也比较简单，安装完成之后，会在菜单栏出现一个 CSRF Token Tracker 的菜单，点进去之后，按下图配置：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cf9e4d171e5316c7cd4f1717759fb2485e26faa8.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cf9e4d171e5316c7cd4f1717759fb2485e26faa8.png)

注意需要填写主机名和要替换的参数名，在 DVWA 登录中使用的参数名为 `user_token`，这样就可以使用 Repeater 或者 Intruder 对其进行登录破解尝试了，检测测试一下，由于登录成功失败返回的信息都一样，所以无法从数据包的角度判断是否破解成功，但是在破解完成之后，刷新页面会有提示：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-41d5a0fcf2949c24b14e674e0f6e706f12a6c0c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-41d5a0fcf2949c24b14e674e0f6e706f12a6c0c1.png)

好像走偏了，由于 dvwa 是个漏洞平台，所以如果有人登录进去，那么服务器就会很危险，所以登录时使用 csrf tokne 来防御暴力破解，虽然可以绕过，但是增加了难度，接下来使用 wfuzz 来测试一下，看看其能力如何。

### 利用 WFuzz 的测试场景

#### 针对登录功能的暴力破解

其实暴力破解的工具有很多，Burp 也能满足要求，本次主题主要目的是测试 WFuzz 的功能，所以使用 WFuzz 来进行暴力破解，DVWA 专门有一个暴力破解的练习模块：

> <http://vul.xazlsec.com:8080/vulnerabilities/brute/>

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-22ca2e228d6aa3654958ad2f8ec08a654384c79f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-22ca2e228d6aa3654958ad2f8ec08a654384c79f.png)

随便输入账号密码 admin/admin 来抓取数据包看看：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1ade54e00f1c3058ca715d697245db595faef831.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1ade54e00f1c3058ca715d697245db595faef831.png)

看请求是通过 GET 请求将用户名和密码作为参数进行验证，由于访问 DVWA 的漏洞页面需要认证，所以需要指定 Cookie，然后尝试使用下面的命令对密码进行 FUZZ：

> wfuzz -c -w pass.txt -u "[http://vul.xazlsec.com:8080/vulnerabilities/brute/?username=admin&amp;password=FUZZ&amp;Login=Login](http://vul.xazlsec.com:8080/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login)" -b "PHPSESSID=isaaiqpa5i849bd933l9jlv3ot; security=low"

Fuzz 的结果如图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a76e582093164d3ca7a124cf94acf1b956d36c2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a76e582093164d3ca7a124cf94acf1b956d36c2a.png)

从图中可以看到第一行，密码为 password 时，Word 和 Chars 与其他不一样，说明，这个密码可能是正确的，然后用这个密码去测试即可。

#### 针对参数进行 SQL 注入检测

在使用之前需要准备一些 SQL 注入检测的 Payload，还是使用 DVWA 来作为目标：

> <http://vul.xazlsec.com:8080/vulnerabilities/sqli/>

在输入框随便填入一个数字，提交之后，获取数据包：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c031c72f2013c3634a741923ac86c4e869a32e2e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c031c72f2013c3634a741923ac86c4e869a32e2e.png)

针对参数中的 id 进行 Fuzz，命令如下：

> wfuzz -z file,SQL.txt -u "[http://vul.xazlsec.com:8080/vulnerabilities/sqli/?id=FUZZ&amp;Submit=Submit](http://vul.xazlsec.com:8080/vulnerabilities/sqli/?id=FUZZ&Submit=Submit)" -b "PHPSESSID=isaaiqpa5i849bd933l9jlv3ot; security=low"

Fuzz 结果如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c5b94f2303fbae699763493e8e57aae53a4b7e64.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c5b94f2303fbae699763493e8e57aae53a4b7e64.png)

结果中有一些 payload 获得的返回包不太一样，可以猜测其存在安全风险，其实 Fuzz 的过程就是触发异常，然后针对异常进行深入测试。

#### 枚举未知参数

这个场景是当我们想发现一些隐藏参数的时候，可以用字典的方式来枚举参数名，比如我们不知道查询用户信息的参数是 `id`，我们可以用下面的命令来枚举参数名，准备一个参数名的字典 `parameter.txt`：

> wfuzz -z file,parameter.txt -u "[http://vul.xazlsec.com:8080/vulnerabilities/sqli/?FUZZ=1&amp;Submit=Submit](http://vul.xazlsec.com:8080/vulnerabilities/sqli/?FUZZ=1&Submit=Submit)" -b "PHPSESSID=j1r5qt89fkjii8dmemc0vdh1td; security=low"

FUZZ 结果如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6e4d8d5c98b6e726b90daa928a2e79a87562c9fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6e4d8d5c98b6e726b90daa928a2e79a87562c9fd.png)

从图中可以看到，只有 `id`的返回结果与其他的不同，所以很大可能这个参数名为 `id`，这个场景经常用于一些伪静态的网站，用这种方式来还原 URL，方便测试。

### 总结

本文总结了一部分 WFuzz 的功能，用到的参数比较简单，主要是 `-d` 指定 POST 数据，`-b`指定 Cookie 值，`-w`指定字典文件路径，相同的功能，使用 `-z file,payload.txt` 的方式指定 payload 文件，其他参数的用法留给大家自行挖掘，如果你有更好的使用 WFuzz 的场景，欢迎留言讨论。