前言
==

上周log4j2的漏洞在中期还不温不火，到了周五，非常简单的POC被爆出，漫天的厂家log4j2告警，朋友圈挤满了漏洞通告。当时还在项目上，Github看到了whwlsfb师傅写的Burpsuite被动扫描log4j2漏洞的插件(链接在文末)。

本着学过菜鸟教程JAVA的基础类型，试着分析下代码是如何实现被动检测的。因为当时的检测方法就是在可能被日志记录的地方胡乱插入POC，然后通过dns平台的回显来判断注入点是否存在。

分析
==

当时正在关注这个插件，想直接拿来测试的，但是在进行最开始的版本测试的时候，发现无法检测到，然后抓包找问题，发现用的是`dnslog.cn`平台来做一个判断，而且POC中漏了`}`，这在新版本中都已经修改

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9b8cc80401ecfe53010b7a2a08c5a3fbf88cd0f0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9b8cc80401ecfe53010b7a2a08c5a3fbf88cd0f0.jpg)

以下为v0.2.1版本的项目树结构

```php
D:.
│  .gitignore
│  pom.xml
│  README.md
│
├─screenshots
│      detected.png
│
└─src
    └─main
        └─java
            └─burp
                │  BurpExtender.java
                │  Log4j2Issue.java
                │
                ├─dnslog
                │  │  IDnslog.java
                │  │
                │  └─platform
                │          Ceye.java
                │          DnslogCN.java
                │
                ├─scanner
                │      Log4j2Scanner.java
                │
                └─utils
                        HttpUtils.java
                        ScanItem.java
                        SslUtils.java
                        Utils.java
```

当时已然更新到v0.2.1版本，Clone下来发现代码量不大，虽然没有接触过burpsuite的插件开发，但是通过函数名以及调用结构可以猜测到大概的意思  
其中主要就三个文件：Ceye.java ，DnslogCN.java ，Log4j2Scanner.java  
`/brup/scanner/Log4j2Scanner.java`  
通过函数名可以知道是被动扫描模块  
主要是定义了exp，并且通过遍历参数，当遍历到是Get参数，Cookie参数，POST参数时，会进行值的替换，替换后进行一个CheckResult的方法调用

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-401cab8d38a9301e9f1438f34db7c355b479d221.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-401cab8d38a9301e9f1438f34db7c355b479d221.jpg)

`/brup/dnslog/platform/DnslogCN.java`  
platform package中就是对具体的dnslog平台的解析，其中内置了ceye和dnslog.cn两个公开站

最主要的就三个函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-055d0dd4d56f84ddcbf181ed15164a7b7ccd42a0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-055d0dd4d56f84ddcbf181ed15164a7b7ccd42a0.jpg)

其中initDomain函数就是请求dnslog.cn然后获取一个子域

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca2ed9a5eb38b68557e94a3aa3fc67c32c2d2e3f.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca2ed9a5eb38b68557e94a3aa3fc67c32c2d2e3f.jpg)

getNewDomain函数就是进行一个拼接，比如获取一个子域ehb52l.dnslog.cn，拼接成xxxcc.ehb52l.dnslog.cn，主要用来递归解析

CheckResult函数则是对应Refresh Recode请求获取解析结果

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3f79d8153b425a532c9db64fddb4f6a9c8ede76.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3f79d8153b425a532c9db64fddb4f6a9c8ede76.jpg)

这样就一目了然了，该插件通过被动扫描遍历每一个参数，提取出Cookie，Get，Post参数，然后有多少个就遍历多少个，每遍历一个参数值就会发送一次子域的获取，获取完后再进行数据的获取，查看是否返回数据，如果有返回数据，就可以确定某个路径下的某个参数存在log4j记录日志的行为并且触发了漏洞(dnslog平台数据和结果的同步性判断通过okhttp3的CookieJar Cookie持久化实现)

实验
==

顺序其实也是先实验遇到问题然后在分析工具改写的，这里倒过来看，稍微清晰点  
由于技术太菜，秉持着脚本小子拿来就用的风格，直接加载了该插件并且被动扫描测试了Tools上有师傅发的漏洞Web Demo，发现了问题=&gt;dnslog.cn炸了

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0e6881ee5841812c467a9bf3f4542e995479286c.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0e6881ee5841812c467a9bf3f4542e995479286c.png)

POC变成了`${jndi:ldap://1639129872920gxXTk./803533}`  
通过之前的getNewDomain函数可以看到.后面应该是rootDomain，也就是我们请求`dnslog.cn/getdomain.php`之后获取到的子域，但是这里无了，测试了好几次还是这个问题，于是去访问了下dnslog.cn平台，发现已经访问不了，直接裂开了，ceye.io也访问不了。两个公开常用的dnslog平台均失效。

```php
    public String getNewDomain() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5) + "." + rootDomain;
    }
```

由于当时气氛火热，很想复现一下，并且将该插件立马用到项目上去检测，但是平台都挂了，等于枪有了，子弹空了。试试看自己能不能再解析一个新平台`https://log.xn--9tr.com/`，于是自己开始面向百度开始修改

修改
==

该平台并不像dnslog一样，Cookie持久化就可以任意取domain，任意获取results，该站点设置了Token  
请求样式如下  
获取子域:

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8a526d000a853c9f4063ca80ba094eea136ef914.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8a526d000a853c9f4063ca80ba094eea136ef914.jpg)

获取数据:

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-41b1a3a9ddddd7292de2631db769325d0047d148.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-41b1a3a9ddddd7292de2631db769325d0047d148.jpg)

可以看到请求获取子域的方式非常的简单，一个Get请求即可，而获取数据的方式需要将获取到的domain和token放入Cookie中，并且请求路径需要改写为`https://log.xn--9tr.com/${token}`的样式。于是照猫画虎，原项目中使用okhttp3，我也面向百度学习使用okhttp3来做请求，并且相应的对`HttpUtils.java`进行基础http请求的改写

最开始真的把原项目代码搬来搬去，并且结合百度学习和自己的思路摘抄改写解析方式。  
最后粗制滥造糅杂了一些Java代码，调来调去，保证了没有报错，形成了如下的代码

```java
package com.K0uaz.demo;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import okhttp3.CacheControl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.Calendar;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class HellWorld {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.SECONDS).
            callTimeout(3000, TimeUnit.SECONDS).build();
    JSONObject paramss = null;
    String platformUrl = "https://log.xn--9tr.com/";
    public static void main(String[] args) {
        HellWorld a = new HellWorld();
        Okktest b = new Okktest();
        System.out.println(b.path);
        //a.Go();
    }
    public  void Go() {
        try {
            // 初始化 OkHttpClient
            //OkHttpClient client = new OkHttpClient();
            // 初始化请求体
            Request request = new Request.Builder()
                    .get()
                    .url("https://log.xn--9tr.com/new_gen?t=0.3113540327207853")
                    //.url("http://121.5.44.178/test.php")
                    .build();
            // 得到返回Response
            Response resp = client.newCall(request).execute();
            String respStr = resp.body().string();
            paramss = sloveJSON(respStr);
            String domain = paramss.getString("domain");
            String token = paramss.getString("token");
            System.out.println(domain.substring(0,domain.length()-1)+"-"+token);
            System.out.println(CheckResult(paramss));
            //parseJsonWithJsonObject(resp);
            //System.out.println(domain);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    private  JSONObject  sloveJSON(String respStr) throws IOException {
        JSONObject object = null;
        try{
            object = JSONObject.parseObject(respStr);
        }catch (JSONException e) {
            e.printStackTrace();
        }
        return object;
    }
    public  boolean CheckResult(JSONObject respStr){
        try {
            String domain = respStr.getString("domain");
            String token  = respStr.getString("token");
            Response resp = client.newCall(GetDefaultRequest(domain,token,platformUrl + token + "?t=0.3113540327207853").build()).execute();
            String  responsedata = resp.body().string();
            System.out.println(responsedata);
            return responsedata.contains("subdomain");
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
    }
    public  Request.Builder GetDefaultRequest(String domain,String token,String url) {
        CacheControl NoCache = new CacheControl.Builder().noCache().noStore().build();
        int fakeFirefoxVersion = GetRandomNumber(45, 94 + Calendar.getInstance().get(Calendar.YEAR) - 2021);
        Request.Builder requestBuilder = new Request.Builder()
                .url(url);
        requestBuilder.header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + fakeFirefoxVersion + ".0) Gecko/20100101 Firefox/" + fakeFirefoxVersion + ".0");
        requestBuilder.header("Cookie", "key=" + domain + "; " + "token=" + token);
        return requestBuilder.cacheControl(NoCache);
    }
    public static int GetRandomNumber(int min, int max) {
        return new Random().nextInt(max - min + 1) + min;
    }
}
```

其中遇到最麻烦的就是Json的解析，百度搜索了okhttp3对于json返回值的解析，发现有很多复制粘贴的，基本都无法使用，都是报错，然后Google搜索到菜鸟教程，看到了两句话就解析完了。

最后就是将上面写的解析的代码柔和到插件项目中，然后由于发包量太大，效率不高，我精简了参数的遍历数量，最后成品也在下文链接中。

感悟
==

该文主要就是简单记录了自己的一次将想法化为行动的经历。

因为我发现很多时候拿来就用的习惯，让自己停止了一些思考，停止了对于知识的探索和运用，总觉得会用=&gt;懂了，收藏了文章=&gt;会了。渐渐的少了很多漏洞复现，少了很多漏洞分析，少了很多新的思考。

以后应该多想着让想法落地，提高自己的效率和行动力，而不是凭空想象。

顺带提一嘴：现在`https://log.咕.com/`限制了频率，且我不太推荐依靠外部Dnslog平台，对公共平台资源利用占用太大，免不了被Ban，更好的方法比如有自己搭建DNSLOG平台，利用JNDI监听器代替dnslog等。

原项目仍在不断的更新，增加了检测类型，忽略静态文件，增加绕过POC等新功能，既然想法适应不了工具，试着动动手，让工具适应你的想法。个人认为这也是造轮子的一种意义。

上文链接：
=====

精品更新原项目：<https://github.com/whwlsfb/Log4j2Scan>  
粗制滥造修改版：[https://github.com/K0uaz/Log4j2Scan\_K](https://github.com/K0uaz/Log4j2Scan_K)