BurpSuite Trick ALL In ONE (第一版)
================================

0x01 Basic
----------

### 1x1 Anti Burp by Web Interface

1. 配置SwitchyOmega代理的时候增加设置如下列表的不走代理
    
    ```php
    burp
    burpsuite
    ```
    
    ![-w624](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d39c94b8338b6646164d7f7cae38440ecb5e2c63.png)
2. 在burpsuite的proxy的opions中禁用掉 web interface <http://burpsuite>

![截屏2021-05-25 上午10.37.08](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3a0b1c5dfe985118c648a5da5b1098ec7ef57145.png)

主要原因是防止被检测到使用burpsuite在抓包，最重要的是防止被检测到使用burp抓包之后返回蜜罐的响应信息给你。  
参考: [《精确判断网站访问者是否是黑客的方法》](https://mp.weixin.qq.com/s/V0WdN9CMrTqo6qInuwyR6g)

3. 最好把burp的favicon.ico也删除

```php
zip -d burpsuite_pro.jar "resources/Media/favicon.ico"
```

参考: [《使用javascript确认对方是否开burpsuite，蜜罐必备策略》](https://mp.weixin.qq.com/s/Dasaal6njCUNU9Dfk-4exA)

### 1x2 Anti Burp by JA3 指纹

cloudflare上的https站点使用burp和python均无法发包，应对的方式就是在burp的上游再加一个代理。

![-w930](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4a69b69ae5210f0bfa8ef4d6a71c9945659426f6.jpg)

cloudflare的anti burp的项目: <https://github.com/cloudflare/mitmengine>

JA3 指纹原理: <https://xz.aliyun.com/t/3889>

0x02 Trick
----------

### 2x1 Turbo Intruder

1/N 使用方法：

1. 首先你需要安装这个插件
2. 选中一个请求，点击右键选择Extensions-Send to turbo intruder

![-w1416](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0df2971c23fdf3d91681584958baf044a40a9518.png)

2/N 一旦你向该插件发送请求，一个python编辑器就会打开，窗口会显示几个现有的python脚本，供你参考和使用。

![-w1196](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc014db62a18602cad4e00ddb256720726202a03.png)

3/N 增加并发量或增加管道，然后点击攻击。示例代码见(或者下面)：[BurpTurboIntruderBasicFileWriteMultiParam.py](https://gist.github.com/r0hi7/47e3d47efaa1ee3df63a6e936dade787)

```python
################### This section will mostly remain as it is ###################

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )
################### ---------------------------------------- ###################

    # This attack will be similar to ClusterBomb technique
    # As they are nested loops
    # You can do almost anything here, with the power of python, 
    # this will be applied to request params where you have set %s %s in the Request section in the top
    for firstParam in open('/usr/share/dict/words'):
        for secondParam in open('/usr/share/dict/web2'):
            engine.queue(target.req, 
                        [
                            firstParam.rstrip(),
                            secondParam.rstrip()
                        ])

# Do anything with response, let write it to a file.
def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    # add response to the table
    table.add(req)
    data = req.response.encode('utf8')
    # Extract header and body
    header, _, body = data.partition('\r\n\r\n')
    # Save body to file /tmp/turbo.dat
    output_file = open("/tmp/turbo.dat","a+")
    output_file.write(body + "\n")
    output_file.close()
```

![-w1200](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cf08e0fb9a0aef2b777ed21a199a20239969482c.png)

4/N 使用这个插件，你几乎可以在Burp里面用Python做任何事情  
例如：

- 处理自定义登录
- 定制化的一些测试
- 过滤你想要的请求
- 添加速率限制、管道等

### 2x2 Match(匹配) and Replace(替换) 功能的有效使用

要点:  
(1) False2True trick  
(2) 在所有的参数处注入通用性payload

1/N False2True trick，当用户访问一个资源是未经授权的。通过在burp响应体匹配和替换中将服务器响应体从F更改为T，有很大的机会可以使隐藏的客户端控件取消隐藏属性。

![-w1080](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b6c78354e7c1563241c67609706c8b37e086ce4e.png)

1. 添加匹配和替换(Match and replace)。  
    ![-w1138](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b54e31c4fb4cef245964869004da4eb73964527c.png)
2. 添加所示的替换。  
    ![-w1131](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-032521069cb1a00521de54f244096eaa15e0869a.png)

这是一个将false返回体更改为true的示例技巧。并且这是一个非常常见的用例。

2/N 今天的主要技巧。 在表格中自动的注入payload，而不是手动打出整个payload。

![-w1133](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b8f3814e507b316927d95fc5653b9921a1e561b.png)

3/N 上述匹配和替换规则将把请求主体中的所有KKK替换为SQLi和XSS这种通用型payload。  
此处的示例载荷

```php
'"><script src="somesrc"></script><h1>test
```

这样的话只要把 `KKK` 放在参数输入处，发送之后就会自动将对应的位置替换为示例中的有效载荷，这样就可以对XSS和SQLi漏洞进行发现。

PS: 其实这个功能也可以用于Hosts碰撞得到host对应的内网域名名之后，设置替换对应的内网域名。相关文章--[利用HOSTS碰撞突破边界](https://xz.aliyun.com/t/9590)

![-w928](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2b22202234ea8b8c0ac68a073a78a6e45b17386c.png)

### 2x3 Find References: Burp中最被低估和未被充分利用的功能

PS: 只有Pro版本的可以在整个Burp中去寻找URIs的references(引用)，这个功能的重点是发现客户端脚本对后端的请求，从而发现更多的测试点。

1/N 从任何地方挑选请求，右击-&gt; Engagement Tools -&gt; Find References

![-w1135](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3527394571766559b5b4b9ff28481917fe019ca8.png)

2/N 一个新的窗口将被打开，它将显示references和这些references的位置。位置可以是repeater, scanner等。reference可以是在请求、响应、头文件中。将会像图片中所示的那样被高亮显示。

![-w1136](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-40994093bbfd6e0c9c5e2919e3940079e36c843c.png)

![-w1136](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-82215c1b8d04606187925872809febf6a60a9bc6.png)

3/N 可以用来发现浏览器的脚本发送的请求，并学习它来制作你对该端点的有效载荷请求。

参考: <https://portswigger.net/burp/documentation/desktop/functions/search#Find-references>

### 2x4 你可以在req模块中修改被压缩的数据

不要忽视BurpSuite中那些看起来的脏数据。可以保持这一设置，并在Burp中玩弄压缩数据

1/N 在Burp Proxy中，解压设置默认是禁用的，像这样启用它。

![-w1062](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-721524aee42b9505557b47f3ad28bb15e4d5ad1c.png)

2/N Before &amp; After.

![-w1137](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3c4426c97b789b25547d17c81bdf4c69d578546b.png)

![-w1137](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b32749d7cd622420674b10199fba74a082531f68.png)

参考: <https://portswigger.net/blog/burp-suite-tips-from-power-user-and-hackfluencer-stok>

### 2x5 一次性检测所有攻击载荷的攻击效果

一次性检查intruder, repeater, sequencer等模块中数据包的响应信息，而不是每次都向浏览器发送反应。

一个一个检查intruder模块中的每一个测试结果是非常无聊的(特别是对XSS漏洞)，所以你可以按照如下过程进行操作:

1. 在启动intruder之前，转到BurpSuite的project options中 -&gt; logging -&gt; tick intruder response -&gt; 将它保存为一个html文件

![-w926](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1f91942d8127d88764d2edca35beb7696d58152.jpg)

2. 然后双击这个html文件，所有的XSS payload就会一起被触发了

### 2x6 禁止Firefox发送与其相关的请求

0/N 首先，为什么使用BurpSuite和Firefox的组合？ 现在的BurpSuite已经内置了Chromium浏览器，为什么还要使用Firefox？

这是因为:

- Burp内置的Chromium在每次不同的运行中都不能保持设置。
- 每次都要重新安装插件
- 不能禁用本地CORS检查
- 不灵活等。

1/N 我个人使用火狐浏览器，如果你和我一样使用过它，你一定看到过很多 `http://detectportal.firefox.com` 的请求。  
它们很吵，你可以右键点击，然后标记 "不要拦截"，但这也不是一个持久的方法。  
在CE中，你没有session。

![-w1138](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a2c20d227513c7efcaa54219ce6981ee93dadbbf.png)

![-w1060](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e6670e3b0345b4103bf6d2cb4ffa73174f2b29c.png)

2/N 最好的办法是在Firefox上禁用这个功能，一劳永逸。  
相信我，这很容易，这将是你的伟大投资。  
进入about:config，完全禁用这个功能。

![-w1137](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2cd2927f8b90a57d0e13e49ad0663d58cadca98b.png)

![-w1137](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-062730c20f1e9c6475740e793e9e09c0aa7f17c0.png)

这个方法只是其中之一，还有两种解决方案

1. 利用 &lt;TLS Pass Through&gt; 功能  
    BurpSuite -&gt; Proxy -&gt; Options -&gt; TLS Pass Through.

```php
.*\.gstatic\.com
.*\.googleapis\.com
.*\.pki\.goog
^.*?apple\..*$
^.*?icloud\..*$
^.*?mzstatic\..*$
^.*mozilla\.(com|net|org)$
^.*\.google\.com$
^.*\.gvt1\.com$
^.*\.ghostery\.(com|net)$
^.*\.aka\.ms$
^.*\.msecnd\.net$
^.*\.skype\.com$
^.*\.microsoft\.com$
^.*\.visualstudio\.com$
^.*\.msn\.com$
^.*\.azureedge\.net$
^sb\.scorecardresearch\.com$
^.*\.msedge\.net$
^.*\.bing\.com$
^.*\.windowsupdate\.com$
.*\.windows\.com
.*\.live\.com
.*\.digicert\.com
```

![-w986](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dce4ff6b47a8431de984006e54d5f789a34ef513.jpg)

如果不想一条一条加，可以直接使用这个师傅的配置文件 [@parsiya](https://github.com/parsiya/Parsia-Clone/blob/main/configs/burp-default-config.json)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5d563352f9a3a53726c44faada8f5f3e6542b80e.png)

PS: 也有师傅提出如果不需要拦截所有网页流量的话，可以用scope，scope的方法可以参考文章 [《Towards a Quieter Burp History》](https://parsiya.net/blog/2020-05-01-towards-a-quieter-burp-history/)

2. 替换掉firefox的user.js文件，从源头上根治

将里面的 [user.js](https://gist.github.com/AetherEternity/5a6bb6e493a3d34988fc7342013f2ea6) 放到对应的profie下，firefox就不会发出一堆烦人的请求了

```php
Windows: C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\xxxxxxxx.default

Mac OS X: Users/<username>/Library/Application Support/Firefox/Profiles/xxxxxxxx.default

Linux: /home/<username>/.mozilla/firefox/xxxxxxxx.default
```

### 2x7 宏(Macro):录制的会话

#### Part 1: What, How &amp; Why?

1/N Burp套件中的宏(Macros)是用来记录一组请求的。

你首先通过代理传递请求，然后选择要添加到宏中的请求集来创建这些记录的请求。

要创建一个宏(Macro)。Project Options -&gt; Sessions -&gt; Macro

![-w978](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6ce619798e5fee06fdc51ad4f64be9c58ab218ca.png)

2/N 点击添加，代理标签将打开。

发送你想记录的请求。  
点击确定。  
宏将被记录下来，给它起个好听的名字。

![-w971](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-569e806fc83c37031ab288f028affcff0e1bda8a.png)

![-w1136](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27cbe51a7a280bb2c42a8474630a8c4672b2deba.png)

3/N 在会话中使用宏。

对于现在所有范围内的URL，在会话下的这个宏将在每个请求之前运行。

![-w979](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e6db8da91cbeb155bbaf18c9481cb6f3eb8926e0.png)

![-w1065](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8c962f46e71121bae6569a1b982d32b1d6cdeeb8.png)

![-w988](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-219bb23e4cbdb092205f3123dc7397de48ca068f.png)

N/N 使用案例

- 拥有自定义登录的网站(常见的例子就是带token的情况)。
- 有助于编写扩展插件。
- IDOR测试。

这里结合一个测试案例来对其功能给一个直观的认识，靶场地址: [https://vuln-demo.com/burp\_macro/macro.php](https://vuln-demo.com/burp_macro/macro.php)

这是典型的使用上一个请求响应中的token作为下一个请求的参数，你发送的请求才能够被后端成功接收的案例。

首先找有token的那个请求记录  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1c84a90d92a7ad7c7e98825cf61c612b0e5ff355.jpg)

点击 configure item -&gt; add -&gt; 双击对应的字符串，burp会自动创建对应的规则  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-039839d58cb5ed440cf05fe510e87baef8073ef3.jpg)

之后设置使我们创建的宏生效(起作用+作用范围)就好了  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f1a7a1b3deaec4e638184200e62d46957816ebb9.jpg)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-595f2f3b006870108c1b1aed9bfaa37d6288e0e8.jpg)

随后在发包的时候只要看到我们的token是发包前更新的就可以验证宏设置成功了  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac7727666e1bd644bac5ce2b8f09658355f8117e.png)

但是这种的局限性就是他只能替换 `token=` 这种形式的，对于json或者其他则无能无力，此时就可以使用插件 [burp-cph](https://portswigger.net/bappstore/a0c0cd68ab7c4928b3bf0a9ad48ec8c7)，关于这个插件的使用可以参考: [《当面对动态参数爆破时，我们该如何处理?》](https://www.anquanke.com/post/id/231145)。但是这个插件还是比较复杂的，更简单一点的插件是 [Burp Extractor](https://github.com/NetSPI/BurpExtractor)，对应的文章介绍是 [《BurpSuite Extender之巧用Marco和Extractor绕过Token限制》](https://xz.aliyun.com/t/2547)

#### Part 2: How to use to automate testing?

通过宏进行自动化，在为API和受保护的资源创建会话时使用宏。

一旦创建，将其作为会话(session)添加，并设置范围(scope)。在演示中，我将所有的URL添加为范围(scope)。

![-w1067](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-898e50609b0ec52e1363445834fe52466630bf59.png)

现在，工具范围中提到的所有请求将被宏处理。

可以使用跟踪器(Tracer)来调试宏

![-w984](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7707c2e4b37b3ab0c7a23f8bb487b906671e5a8c.png)

![-w1128](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e2d935c716db3bd6ecd68e10a44a56c913aab08.png)

可以使用 portswigger 的lab来对 (Macros) 做练习  
link: <https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money>

### 2x8 在BurpSuite中repeater模块的响应中快速追踪你修改的参数

当你在中继器选项卡中修改一个参数，它的值会反映在响应中，当你必须滚动查看变化的内容时，你可以启用这个切换键......真正的省时省力!

操作如下图片所示。

![-w1137](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c79438394fa329bfe07a1b21fb87a977a1c1260e.png)

![-w1139](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0aae7a38127e28a6e26d6cf495673b07c565ff1c.png)

### 2x9 你在使用BurpSuite时也面临着缓存响应的问题吗？

如果受到了缓存的影响，那么关闭它就好了

在这个模块中开启以下两个规则 Proxy -&gt; Options -&gt; Match and Replace.

- If-Modified-Since
- If-None-Match

![-w1071](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-93c8263a6fe06b844b9b19f6e4428263614a00b8.png)

有时我在Burp中看到304的响应，我不得不在Burp历史中挖掘，以检查第一次出现的响应并进行分析。移除这些头文件后，你可能不会再看到这样的响应。

### 2x10 在使用BurpSuite pro进行企业测试的时候，我们不应该捕获和存储企业的证书

使用的步骤以及为什么这点是重要的:

步骤:

1. 临时项目/会话。
2. 登录到应用程序，像正常一样。
3. 识别哪些域的请求包含凭证。
4. 在Burp中启动主项目。
5. 将这些域添加到SSL穿透中。Proxy &gt; Options &gt; TLS Pass-Through

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1adbedca0e859831ad4b64e2a1ffd0bbf92959ea.jpg)

我为什么这样做。我保存了会话，而burp将存储这些凭证和会话。我个人不希望凭证被存储在文件中。  
另一个重要的问题是，我们不是在测试SSO，而是在测试SSO背后的应用程序。

### 2x11 基于burp proxy history生成字典

```python
import xml.etree.ElementTree as ET
import urllib
import base64
import math
import sys
import re

# usage: Open Burp, navigate to proxy history, ctrl-a to select all records, right click and "Save Items" as an .xml file. 
# python burplist.py burprequests.xml
# output is saved to wordlist.txt

def entropy(string):
        #"Calculates the Shannon entropy of a string"
        # get probability of chars in string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

        # calculate the entropy
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

        return entropy

def avgEntropyByChar(en,length):
    # calulate "average" entropy level
    return en / length 

tree = ET.parse(sys.argv[1])
root = tree.getroot()
wordlist = []

for i in root:

    # preserve subdomains, file/dir names with . - _
    wordlist += re.split('\/|\?|&|=',i[1].text)

    # get subdomain names and break up file names
    wordlist += re.split('\/|\?|&|=|_|-|\.|\+',i[1].text)

    # get words from cookies, headers, POST body requests
    wordlist += re.split('\/|\?|&|=|_|-|\.|\+|\:| |\n|\r|"|\'|<|>|{|}|\[|\]|`|~|\!|@|#|\$|;|,|\(|\)|\*|\|', urllib.unquote(base64.b64decode(i[8].text)))

    # response
    if i[12].text is not None:
        wordlist += re.split('\/|\?|&|=|_|-|\.|\+|\:| |\n|\r|\t|"|\'|<|>|{|}|\[|\]|`|~|\!|@|#|\$|;|,|\(|\)|\*|\^|\\\\|\|', urllib.unquote(base64.b64decode(i[12].text)))

auxiliaryList = list(set(wordlist))
final = []
avgEntropyByLength = {}

for word in auxiliaryList:
    if word.isalnum() or '-' in word or '.' in word or '_' in word:
        en = entropy(word)
        # remove "random strings" that are high entropy
        if en < 4.4:
            final.append(word)

final.sort()

with open('wordlist.txt', 'w') as f:
    for item in final:
        f.write("%s\n" % item)

print "wordlist saved to wordlist.txt"
```

### 2x12 使用Burp来对目标进行批量扫描

很多时候我们会在burp上面集成很多萨漏洞扫描或者信息收集插件，所以可以借助设置上层代理的方式来将目标发送到burp，随后使用burp来对目标来做下一步的安全测试。

```php
cat subs.txt | httpx | tee -a livesubs.txt
cat livesubs.txt | gau | tee -a wayback.txt 
ffuf -u FUZZ -w wayback.txt -replay-proxy http://127.0.0.1:8080/
```

基于这个想法扩展一下，准备做一个中间层(数据包去重+重要信息提取)，把爬虫(crawlergo, rad, LSpider)和Burp(xray也可以)联动起来，既然不知道用哪个爬虫那就全都要。 #TODO

### 2x13 IPtables + BurpSuite + Android 应用

- 在设备上添加Burp CA
- 绕过ca pinning
- root设备(iptable需要)

Dport(是设定目的端口的参数) 80 路由 - 运行以下命令 (或许对443端口也需要做这样的事情)

```php
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <BURP_IP>:8080
iptables -t nat -A POSTROUTING -p tcp --dport 80 -j MASQUERADE
```

### 2x14 使用repeater模块测试那些通过反向代理的请求

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5bad5ea5c3914c606c1007c108bca7abdc2aeaf2.png)

例如 blogspot.com 这个网站，网站进行了反向代理的设置，它会检查子域并对其进行相应的路由，现在让我们为它改变host。

图 1 : Target 的值与 Host 的值相同的时候

![16314241507193.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1520dbf1b97c0dc1e97e4c3ee7abfa43a42db4c7.png)

图 2 : Target 的值与 Host 的值不相同的时候, 这个请求就会被路由到不同的站点

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e2b899144cef9aa04656e1cf10e0b81c003ce7a3.jpg)

### 2x15 HTTP-Pipelining

HTTP-Pipelining方式的好处就是会产生跟域前置(domain fronting)相类似的效果，将恶意请求隐藏在正常请求之后，并且目前大多数服务器都是支持这个技术的。此测试技术可以参考文章[《Using HTTP Pipelining to hide requests》](https://digi.ninja/blog/pipelining.php)。在burpsuite中可以使用如下方式来开启HTTP pipelining功能

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4cc22ec3e672c01e0f2d6ed81fc4a6fa4f78a8f9.jpg)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e59106650c7412f17fdc12293f0809e1fc1c8344.jpg)

PS: 其实初看这个概念你可能觉得陌生，但是这个技术点其实就是前一段时间最火的 HTTP-Request-Smuggling (HTTP请求走私漏洞)

### 2x16 在Intruder模块中设置过滤

过滤出那些呈现出特定响应的数据包

1. 为Intruder的响应数据包创建一个过滤器。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-577f2455566def84ea5b71149700031df14bb33f.jpg)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bcf0f6de9aa3d40938363338194018706c7d0f84.jpg)

2. 载入payload开始fuzz
3. 如果响应包含你在 "grep "中输入的字符串，将显示在一个额外的列中。  
    -&gt; 你只能关注你正在寻找的响应。  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fec0714992c9e83c18f1ebdaacfa86b4434463e8.jpg)

### 2x17 Plugin: BurpBounty

在BurpSuite主动/被动扫描器中添加你自己的扫描规则。不需要写一行代码就可以在扫描器中自定义检查策略。

插件名称：BurpBounty扫描检查生成器。  
这是一个相当容易使用的插件。从 BApp Store 安装，用简单的名字创建一个检查。给它一个严重性，检查输入你想执行/检查的req/res，并启用它。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1f0d01356f874bbc4ff0a5e5ef5cec54b199ed20.jpg)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-96d0ab98f8042e8dca1dae771f29563a0af77571.jpg)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-99b556fb16637494eef76dc093c62afbadebd491.jpg)

### 2x19 Burp Collaborator

BurpSuite Collaborator是PortSwigger提供的一个托管网络服务，在手动测试中非常有用。

1/N 当你不清楚手动注入的有效载荷是否触发了与其他网站的交互时，就可以使用Collaborator来验证。Collaborator功能默认使用的是由PortSwigger托管的公共服务器。具体的工作原理如下图所示。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3deb1fce6f6e83abb4e5a68dfdb298f0ea5c7b7.jpg)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0c9c463262b44f54e2fe638c4d4ed893a3627cbc.jpg)

2/N Collaborator客户端的使用如下所示

1. 启动Collaborator客户端  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cdf45f6e5ddc1b8855e2807af2beafd36a01a565.jpg)
2. 点击复制，将创建一个带有&lt;&gt;.burpcollaborator.net域名的自定义URL。之后在payload中使用该URL  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f5fac1d6227aebc072d5b9e87e0479191a1175c9.jpg)
3. 轮询以查看在URL上发出的请求。  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d475848f0daa4abd0a9b3c099c8aeeeabbbd923d.jpg)
4. 用于请求的payload示例（这个案例中会产生DNS和HTTP两种请求）  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ff8930a5611861640c5ab597bbbee1c4bce22fc8.jpg)

3/N 一些有用的场景

- SQLi 盲注
- SSRF
- XSS
- BlindXXE
- 检测你能想到的任何出站的源负载
- 逃避防火墙，如果出站的TCP请求被阻止而HTTP被允许的话

### 2x20 三步创建一个属于你自己的Burp Extender插件(Java类型)

- 从Burp -&gt; Extender -&gt; APIs -&gt; Save Interface files下载API接口。  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a22a888f970b46ffd9e8f9e74f29d2e4e2e654e8.jpg)
- 创建一个名为burp的包，并将文件保存在那里，你可以选择任何你喜欢的IDE。  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-61cb900bd27e90c7dfcdbe16014e8f3c25234bb3.jpg)
- 让IDE准备好构建JAR。
- 创建文件名为BurpExtender并添加以下代码。  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2177ea905dceedf976d45801593748e20126bc73.jpg)

2/n

- 文件名Burp Extender将是你的插件的一个入口点，扩展接口在加载时在Burp中注册。该插件的所有逻辑都在这里。
- 构建Jar
- 在Burp中加载Jar。  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-226aab25e97c279abf10de539122a1061c5df6c4.jpg)  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-98e065e7f873321378417ceb07245c6da8b8794c.jpg)

3/n

- 你也可以用这些命令从命令行建立Jar。 ```php
    代码位置 -> cd usercode
    *.class文件的位置 -> mkdir build
    jar的位置 -> mkdir bin 
    编译代码 -> javac -d build src/burp/*.java
    建立jar -> jar cf bin/burpextender.jar -C build burp
    ```

### 2x21 Autorize 与 IDOR(越权漏洞)

Autorize可以帮助你自动化的查找越权漏洞，基本的使用步骤如下:

1. 首先在 Autorize 扩展中提供低权限/不同用户的 cookie 详细信息。
2. 然后作为高权限用户使用浏览器并连接 burp 漫游并在易受攻击的网站上获取不同的资源。
3. 对于您在站点上向高权限用户发出的每个请求，Autorize 扩展都会使用给定的低权限 cookie 重复相同的请求。
4. 最后，您可以检查 Autorize 扩展是否已使用低特权 cookie 请求访问了任何特权资源。如果是，那就找了一个越权漏洞。

参考链接: [Leveraging Burp Suite extension for finding IDOR(Insecure Direct Object Reference).](https://infosecwriteups.com/leveraging-burp-suite-extension-for-finding-idor-insecure-direct-object-reference-2653f9b89fd4)

### 2x22 burp性能优化之最大限度地减少RAM和处理器的负荷

1. 关闭你不用的 burp 扩展 -- 只要禁用所有不使用的扩展，即使它们被加载，也会影响性能。
2. 确定扫描仪的明确范围 -- 你可以在配置中限制递归的深度
3. 合并用于限定范围的正则表达式 -- 如果你使用正则表达式来过滤流量，可以尝试将多个正则表达式合并为一个，性能上将会有所优化。
4. Burp搜索功能比网站地图过滤器更快

### 2x23 通过代码层面的可视化来更好地理解BurpSuite中不同的intruder攻击类型

![-w611](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc5b2005acc26b65c05efe4fa7a1ae0a5c9d450a.png)

对于上面这个例子来说，如果我们想要去 使用 BurpSuite 的 Intruder 模块去 Fuzz 那么我们就首先会面临四种类型的选择:  
![-w476](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-285e59c756059bbdc2c99719a905b93e43f2bdb6.png)

1. SNIPER
    
    
    - 单一有效载荷集
    - 相同的有效载荷一次适用于所有位置。
    - 适合于每次对单个参数进行模糊处理，在针对所有具有共同漏洞的有效载荷时非常有用。
    - loc1首先用相同的数据进行测试，然后是loc2，以此类推...  
        用代码来表示就是  
        ![-w915](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cd03cd6413823d3490c1fbda1034ae09da6601aa.png)
2. BATTERING RAM
    
    
    - 单一有效载荷
    - 每个有效载荷同时放置在每个位置上
    - 当攻击需要所有参数的相同输入时使用  
        ![-w1254](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fde29865c9ac2b650792ddbe495c54b5fffc8d86.png)
3. CLUSTER BOMB
    
    
    - 每个位置都有不同的有效载荷集。
    - 将此视为嵌套循环。对于locl的每个有效载荷，其他有效载荷的所有条目都被测试。(类似笛卡尔积)  
        ![-w1054](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-84114882e5c7377927264d856998d40d22257734.png)
4. PITCH FORK
    
    
    - 每个位置都有不同的有效载荷集
    - 但每个有效载荷都是同时递增的  
        ![-w1159](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1027460924b26228f31d35bbba64b2acff325ba0.png)

### 2x24 一种简单的在Android设备上安装证书的方式

Burp--&gt;Proxy--&gt;options--&gt;import/export--&gt;certificate in DER format--&gt;cert--&gt;next--&gt;save

![截屏2021-07-22 下午7.35.52](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-60d638d51c81a58ca153d7b669c97f9deef8db35.png)

```php
openssl x509 -inform DER -in cert -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1
mv cacert.pem 9a5ba575.0  #hash from the above command output
adb shell "mount -o rw,remount/system"
adb push 9a5ba575.0 system/etc/security/cacerts/
adb shell "chmod 644 system/etc/security/cacerts/9a5ba575.0"o
mount-o ro,remount /system
adb remount
adb reboot
```