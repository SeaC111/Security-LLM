0x01 Jersey文件上传的实现方式
====================

 在Jersey中解析`multipart`请求，需要使用`jersey-media-multipart`模块，该模块提供了对`multipart`请求的支持。

```XML
<dependency>
    <groupId>org.glassfish.jersey.media</groupId>
    <artifactId>jersey-media-multipart</artifactId>
</dependency>
```

1.1 添加multipart请求解析支持
---------------------

 要想支持multipart请求的解析，首先需要注册`MultiPartFeature`来启用`multipart`支持。主要是下面的配置：

- 在Jersey的`ResourceConfig`类进行应用程序配置：

```Java
javaCopy code
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import javax.ws.rs.ApplicationPath;
import org.glassfish.jersey.server.ResourceConfig;

@ApplicationPath("/api")public class MyApplication extends ResourceConfig {
    public MyApplication() {
        register(MultiPartFeature.class);
    }
}
```

- 在web.xml进行应用程序配置：

```XML
<init-param>
<param-name>
    jersey.config.server.provider.classnames
</param-name>
<param-value>
    org.glassfish.jersey.media.multipart.MultiPartFeature
</param-value>
</init-param>
```

1.2 实现方式
--------

 主要通过以下几种方式实现：

- **使用@FormDataPara注解**

 可以使用`@FormDataParam`注解来获取`multipart`请求中的数据。例如下面的例子：

```Java
@POST
@Path("uploadimage ")
@Consumes(MediaType.MULTIPART_FORM_DATA)
public String uploadimage1(@FormDataParam("file") InputStream fileInputStream,
    @FormDataParam("file") FormDataContentDisposition disposition) {
    String imageName = Calendar.getInstance().getTimeInMillis()
   + disposition.getFileName();

    File file = new File(ARTICLE_IMAGES_PATH + imageName);
    try {
        //使用common io的文件写入操作
        FileUtils.copyInputStreamToFile(fileInputStream, file);
        //原来自己的文件写入操作
        //saveFile(fileInputStream, file);
    } catch (IOException ex) {
        Logger.getLogger(UploadImageResource.class.getName()).log(Level.SEVERE, null, ex);
    }

    return "images/" + imageName;
}
```

- **MultiPart对象**

 首先uploadFile方法接受一个MultiPart对象作为参数，用于处理multipart请求。通过遍历MultiPart中的每个BodyPart，可以获取到上传的文件和其他表单字段。对于文件字段，可以通过将BodyPart转换为FormDataBodyPart对象，并使用getContentDisposition()方法获取文件的相关信息，如文件名。然后，可以使用getEntityAs()方法将文件内容作为流获取，进而进行文件处理操作。当然也可以直接使用MultiPart对象的属性进行操作：

```Java
@POST
@Path("/upload")
@Consumes(MediaType.MULTIPART_FORM_DATA)
public Response uploadFile(MultiPart multiPart) {
    // 遍历MultiPart中的每个BodyPart
    for (BodyPart bodyPart : multiPart.getBodyParts()) {
        // 检查当前BodyPart是否为文件
        if (bodyPart instanceof FormDataBodyPart) {
            FormDataBodyPart filePart = (FormDataBodyPart) bodyPart;
            // 获取文件名和内容
            String fileName = filePart.getContentDisposition().getFileName();
            InputStream fileContent = filePart.getEntityAs(InputStream.class);

            // 处理文件内容，例如保存文件到本地
            // ...

            // 关闭文件流
            fileContent.close();
        } else {
            // 处理其他表单字段
            // ...
        }
    }

    // 文件上传完成，返回响应
    return Response.ok("File uploaded successfully").build();
}
```

- **FormDataMultiPart对象**

 可以使用FormDataMultiPart获取表单数据，实际上@FormDataPara注解也是获取的FormDataMultiPart对应的属性进行处理的：

```Java
@POST
@Path("uploadimage2")
@Consumes(MediaType.MULTIPART_FORM_DATA)
public Viewable uploadimage2(FormDataMultiPart form, @Context HttpServletResponse response) throws UnsupportedEncodingException {
   //获取文件流
   FormDataBodyPart filePart = form.getField("file");
   //获取表单的其他数据
   FormDataBodyPart usernamePart = form.getField("username");

   //ContentDisposition headerOfFilePart = filePart.getContentDisposition();
   //把表单内容转换成流
   InputStream fileInputStream = filePart.getValueAs(InputStream.class);

   FormDataContentDisposition formDataContentDisposition = filePart.getFormDataContentDisposition();

   String source = formDataContentDisposition.getFileName();
   String result = new String(source.getBytes("ISO8859-1"), "UTF-8");

   String filePath = ARTICLE_IMAGES_PATH + result;
   File file = new File(filePath);

   try {
       //保存文件
       FileUtils.copyInputStreamToFile(fileInputStream, file);
// saveFile(fileInputStream, file);
   } catch (IOException ex) {
       Logger.getLogger(UploadImageResource.class.getName()).log(Level.SEVERE, null, ex);
   }

   response.setCharacterEncoding("UTF-8");

   Map map = new HashMap();

   map.put("src", result);

   return new Viewable("/showImg", map);
}
```

 实际上FormDataMultiPart是MultiPart的子类：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-67ab46b4bd51ca2e02f64cde60db247d201d8830.png)

0x02 上传请求解析过程
=============

 `org.glassfish.jersey.media.multipart.internal.MultiPartReaderClientSide#readMultiPart` 方法是 Jersey 中用于解析 multipart 请求的关键方法，其负责将 multipart 请求解析为 `MultiPart` 对象，从而方便后续对请求内容的处理和操作。

2.1 解析请求过程
----------

 在 `readMultiPart` 方法中，会通过解析输入流中的请求数据，创建 `MultiPart` 对象，并将每个请求部分封装为对应的 `BodyPart` 对象。这些 `BodyPart` 对象包含了每个请求部分的内容、类型、文件名等信息。以jersey-media-multipart-2.35.jar为例，查看其具体的解析过程。

 首先根据请求的 mediaType 判断是否为 multipart/form-data，如果是，则创建一个 FormDataMultiPart 对象，否则创建一个 MultiPart 对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f923f1d135adc1bbb7e9c4fa9f85f8fa3b8fd66d.png)

 然后将请求的头信息（headers）复制到 `MultiPart` 对象的头信息（multiPartHeaders）中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-194883dcea66b26e5749339cfecdcde643652ae3.png)

 如果是 `multipart/form-data` 请求，则根据请求的头信息User-Agent判断是否需要进行文件名修复（fileNameFix）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bac75f718265d6dc9cc1e2459c11e6142a647471.png)

 然后遍历解析出的 `MIMEPart`（请求中的各个部分），为每个 `MIMEPart` 创建一个对应的 `BodyPart` 对象，如果是 `multipart/form-data` 请求，则创建 `FormDataBodyPart` 对象，否则创建普通的 `BodyPart` 对象，并将 `MIMEPart` 中的头信息复制到 `BodyPart` 对象的头信息中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3228ddd20a5d4044bd5ecaa7bc1e41dffae8f1ee.png)

 最后尝试从 `BodyPart` 对象的头信息中获取 "Content-Type"，如果存在则设置 `BodyPart` 对象的媒体类型（`MediaType`）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f68e1ed7fcee2307417f61f3d8ca1c3c03c5ba97.png)

 到这里 multipart 请求大致解析完成，包含请求各个部分信息的 MultiPart 也对象构造完成，后续用于进一步处理和操作请求的内容。

2.2 判断是否是Multipart请求
--------------------

 `@Consumes({"multipart/*"})` 注解的作用是告诉 Jersey 框架该类或方法可以处理 `multipart/*` 类型的请求数据：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c1f1179eb6508a16d12046c1c33e864666c3ec94.png)

 也就是说，只要`Content-Type`以`multipart/`开头的请求，都会经过MultiPartReaderClientSide进行处理（只能小写）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-731c7982613b2389c1d0eab6cb97e7a9878736f4.png)

 但是这里封装的是org.glassfish.jersey.media.multipart.MultiPart。根据前面Jersey文件上传的实现，如果想使用FormDataMultiPart进行解析的话，这里会有一个类型强制转换的过程。而在FormDataMultiPart中，限制了Content-Type必须为`multipart/form-data`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-618aba9bd3996eb960f1605f681d9ed831699bb1.png)

 而这里是使用equalsIgnoreCase忽略大小写进行比较的，所以支持对`multipart/form-data`进行大小写的转换：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-62e7f1651bff7ce3aa07fc991258884bd8cf5c97.png)

0x03 获取上传的文件名
=============

3.1 获取方式
--------

 在Jersey中，可以通过以下几种方式获取上传的文件名（案例中FormDataContentDisposition继承了ContentDisposition，实际上调用的是ContentDisposition的对应方法）：

- **org.glassfish.jersey.media.multipart.ContentDisposition#getFileName**：

```Java
@POST
@Consumes(MediaType.MULTIPART_FORM_DATA)
public String upload(@FormDataParam("file") InputStream fis,
                    @FormDataParam("file") FormDataContentDisposition fileDisposition) {

        String fileName = fileDisposition.getFileName();
        ......
}
```

- **org.glassfish.jersey.media.multipart.ContentDisposition#getParameters**：

 直接从ContentDisposition中对应的参数进行获取：

```Java
@POST
@Path("upload")
@Consumes(MediaType.MULTIPART_FORM_DATA)
public String upload(FormDataMultiPart form, @Context HttpServletResponse response)throws UnsupportedEncodingException{
    FormDataBodyPart filePart = form.getField("file");
    FormDataContentDisposition formDataContentDisposition = filePart.getFormDataContentDisposition();
    Map<String, String> parameters = formDataContentDisposition.getParameters();
    String fileName = parameters.get("filename");
    ......
}
```

3.2 文件名解析过程
-----------

 文件名的初始化主要是在org.glassfish.jersey.media.multipart.ContentDisposition#createParameters进行处理的，主要是通过defineFileName方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5eb61523ab8ea056907aa15a5210207b5029927b.png)

 在defineFileName方法中，可以看到主要是根据parameters中的filename和filename\*（跟Spring MVC中使用StandardMultipartHttpServletRequest解析器解析是类似，会对filename\*参数进行处理）进行处理的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8f0f8b274958bba97ca36d5e6c26610275c45559.png)

 首先看看parameters的封装过程，是在实例化ContentDisposition时进行处理的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a64502d5ba105f004b1347330bd911ad0146fa41.png)

 在HttpHeaderReader.readParameters放中，会把对应的parameters进行遍历，并将对应的值封装在LinkedHashMap中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-18e429b379fabc441b0191e00e0667ff26938884.png)

 解析过程主要是根据fileNameFix的值，调用reader.nextTokenOrQuotedString获取对应参数的值进行封装：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d6de0917e2a94f29459095bda04e7ea2a8511a29.png)

 因为在整个遍历过程中会对每一个参数进行解析并保存在LinkedHashMap中，所以当存在多个filename参数的时候，其会获取最后一个的值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1e4ef158699e7347a41ba0e1f6f15731b2680a68.png)

 继续看下defineFileName是怎么处理的，如果filename\*的值为null的话，会直接返回filename的值，否则会对filename\*参数的值进行处理，首先会根据FILENAME\_EXT\_VALUE\_PATTERN对filename\*的值进行正则匹配，如果不匹配则抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-fca71476fca8afba956db7ed627b925de78208bd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8f3195b0b75751dc242f010b2b4b0a2d30c92968.png)

 然后调用isFilenameValueCharsEncoded方法通过正则匹配被编码过的文件名字符，如果成功匹配，会直接返回filename\*的值，否则进行进一步的处理。

 首先会通过正则表达式的匹配来提取出 charset（字符编码）、lang（语言） 和 filename (文件名）的值，如果charset为UTF-8，就将 charset、lang（如果存在）和经过 URI 编码的 filenameValueChars 拼接在一起，作为最终的文件名，否则抛出解析异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-187b3655f9aaf2c1eb402e3653181d081a9f025c.png)

 举个例子，例如下面上传请求的测试.txt经过处理后getFilename获取到的文件名是经过编码处理的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-20eb3afda4b15c6edd3757a059187440f2f322f6.png)

 **相比Spring MVC中使用StandardMultipartHttpServletRequest解析器，在解析filename\*时，Jersey并不会直接返回不包含额外信息的纯粹的文件名**。要获取不包含额外信息的文件名需要自己额外定义逻辑进行处理。

 同样的，Jersey在整个处理过程没有对类似../的路径进行检查&amp;过滤，由于获取的fileName未进行安全处理，在使用File创建文件时，若路径处path写入../../穿越符号，是可以跨目录新建文件的。那么在实际利用时，可以尝试通过linux写入定时任务（etc/cron.d/下的文件可以以任意后缀命名，如果未对filename进行重命名的话还可以绕过上传的后缀限制）、ssh公钥（需要满足root权限）,甚至是替换 JDK HOME 目录下的系统 jar 文件，再主动触发 jar 文件里的类初始化来达到执行任意代码的效果。

3.3 fileNameFix属性
-----------------

 在某些情况下，MS Internet Explorer（特别是较旧的版本）在multipart请求的Content-Disposition头部中的文件名值参数（filename）中会包含额外的反斜杠字符，这会导致解析错误。为了解决这个问题，Jersey提供了一个名为fileNameFix的选项，默认设置为true，以应用修复逻辑来处理这种情况，使解析过程正确处理文件名值参数。

 在解析过程中会在org.glassfish.jersey.media.multipart.internal.MultiPartReaderClientSidereadMultiPart方法中对请求的内容进行一系列的处理，包括fileNameFix属性的设置。

 首先当前请求必须是formData类型的请求，其次会判断当前userAgent是否为null并且是否包含 MSIE 关键字，如果是的话此时fileNameFix为true：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-85ef471c26e266c2a7602656319845c99433816d.png)

 根据前面的分析，**当fileNameFix的值为true时，对应filename的值会进行额外的处理，会根据反斜杠进行截断（目的是去除文件名中的路径部分，只保留文件名部分。）**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4b87fe837cf145f69132337fc24715e4a00c955a.png)

 例如下面的例子，正常情况下反斜杠会直接剔除掉：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-691009a645d983e48a94f55cf1b6f7995dc8a925.png)

 当fileNameFix为true时，会对反斜杠内容进行截断处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8c58726ee45a3eb356710c84f5f80e21545fef1a.png)

0x04 SpringMVC的Multipart请求绕过
============================

 在SpringMVC中，当接收到一个multipart请求后，会调用 MultipartResolver的resolveMultipart()方法对请求的数据进行解析并将解析结果封装到中HttpServletRequest。很多时候一些安全检测的filter在进行类似SQL注入、XSS的过滤时没有考虑到上述情况，那么就可以尝试将普通的GET/POST转换成Multipart请求，绕过对应的安全检查。

 在Jersey中，类似application/x-www-form-urlencoded的请求需要进行额外的处理，才能提取到特定的参数值。例如如下的例子：

```Java
@POST
@Path("/test")
public Response test(@FormParam("msg") String msg) {
    return Response.ok().entity(msg).build();
}
```

 通过`@FormParam`注解可以从表单请求中提取特定的参数值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1842303901b96b48341414ded681555fa1e39298.png)

 而`@FormParam`注解并不能处理multipart请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-83a5190cc2523a90c24a6f12d589883a3376866e.png)

 要解析`multipart/form-data`类型的请求，需要通过`@FormDataParam`注解将特定表单字段的值绑定到方法参数上，并通过参数类型来获取相应的数据。

 也就是说，默认情况下Jersey并不像Spring MVC一样，能在多个请求方式之间灵活解析转换。