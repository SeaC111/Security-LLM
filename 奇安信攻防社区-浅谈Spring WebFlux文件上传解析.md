0x00 前言
=======

 在 Spring MVC 中，可以使用 `org.springframework.web.multipart.MultipartFile` 类来处理文件上传，将multipart中的对象封装到MultipartRequest对象中然后进行相应的处理：

```Java
@RequestMapping(value={"/uploadFile"},method={RequestMethod.POST})
public String uploadFile(MultipartFile file,String type,HttpServletResponse response) throws Exception{
        String UPLOADED_FOLDER="/resource/upload/";
        if(!file.isEmpty()){
                String path = UPLOADED_FOLDER + file.getOriginalFilename();
                File targetFile = new File(path);
                FileUtils.inputStreamToFile(file.getInputStream(),targetFile);
                        ......
                        ......

        }
}
```

 而在 Spring WebFlux 中，不能直接使用 `org.springframework.web.multipart.MultipartFile` 类来处理文件上传，因为它是为 Spring MVC 提供的传统 Servlet 基础的文件上传功能。而Spring WebFlux是基于 Reactor 的。

 在 Spring WebFlux 中，可以使用 `org.springframework.http.codec.multipart.FilePart` 来处理文件上传。`FilePart` 是 Spring WebFlux 提供的用于表示上传文件的类，例如如下的例子：

```Java
@PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
public Mono upload(
        @RequestPart("file") final FilePart filePart,
        final FormData formData
) {
    log.debug("formData =&gt; {}", formData);
    System.out.println(filePart.filename());

    final File directory = new File(UPLOAD_DIRECTORY);
    if(!directory.exists()){
        directory.mkdirs();
    }

    final File file = new File(directory, filePart.filename());

    return filePart
            .transferTo(file)
            .then(Mono.fromCallable(() -&gt; {
                final Map map = new HashMap&lt;&gt;();
                map.put("name", file.getName());
                map.put("lastModified", file.lastModified());
                map.put("size", file.length());
                return map;
            }));
}
```

 `DefaultServerWebExchange` 是 Spring WebFlux 框架中的一个类，它实现了 `ServerWebExchange` 接口，用于表示一个服务器和客户端之间的交互。其封装了底层的 HTTP 请求和响应，提供了访问请求和响应信息的方法，如获取请求方法、路径、请求头、请求体等，以及设置响应状态码、响应头、响应体等。

 其中的`initMultipartData` 方法的用户初始化处理 `multipart` 请求时的相关数据，以spring-web-5.3.27为例，查看其解析过程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0e77b4c33d2ee8e9c50c7681b13e5d989c2c262e.png)

0x01 判断是否是Multipart请求
=====================

1.1 判断方式
--------

 在`initMultipartData` 方法中，首先会判断当前请求是否是Multipart上传请求，首先会从获取当前请求header的ContentType，然后调用org.springframework.http.MediaType#isCompatibleWith方法进行判断：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bd8d8389f8406a626041b10d1be3d974a2583e80.png)

 实际上调用的是其父类MimeType的方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b2392a94808edd6114cc4c8c1691f69bb8de1984.png)

 首先如果传入的 other 参数为 null，则返回 false。如果两个 MIME 类型的类型和子类型都不是通配符类型（即非 `*`），会比较两者是否类型相同且子类型相同，是的话则返回true：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-19de822ffbeb4c506d023e3f67b9cbdc9448a352.png)

 例如在判断文件上传请求时，会判断是否是匹配`multipart/form-data`:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-29740b0d3b5e7562c9ad32b60c21b2c91c18ea84.png)

 如果一个 MIME 类型的子类型是通配符类型 `*`，则返回true:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-28847e9850a52f4d1d1e36cf2a6c8b88e37c8ae2.png)

 也就是说，当Content-Type为`multipart/*`或者`multipart/form-data`都会认为是Multipart请求。（跟Spring MVC一样支持大小写转换）。

 当然了也支持通过配置`consumes = MediaType.MULTIPART_FORM_DATA_VALUE`，限制接受的内容类型为`multipart/form-data`。仅当请求的Content-Type为`multipart/form-data`时，该方法才会被调用：

```Java
@PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
public Mono upload(@RequestPart("file") final FilePart filePart,
        final FormData formData
) {

    ......
}
```

1.2 与其他框架的区别
------------

- Struts2

```Java
if (content_type != null &amp;&amp; content_type.contains("multipart/form-data")){
......
}
```

- Spring MVC

 主要有两个解析器：

1. **StandardServletMultipartResolver解析器:**

 通过判断请求的Content-Type来判断是否是文件请求：

```Java
public boolean isMultipart(HttpServletRequest request) {  
   return StringUtils.startsWithIgnoreCase(request.getContentType(),  
         (this.strictServletCompliance ? "multipart/form-data" : "multipart/"));  
}
```

 其中，strictServletCompliance是StandardServletMultipartResolver的成员变量，默认false，表示是否严格遵守Servlet 3.0规范。简单来说就是对Content-Type校验的严格程度。如果strictServletCompliance为false，请求头以multipart/开头就满足文件请求条件；如果strictServletCompliance为true，则需要请求头以multipart/form-data开头。

2. **CommonsMultipartResolver解析器：**

 CommonsMultipartResolver解析器会根据请求方法和请求头来判断文件请求：

```Java
public boolean isMultipart(HttpServletRequest request) {  
   return (this.supportedMethods != null ?  
         this.supportedMethods.contains(request.getMethod()) &amp;&amp;  
               FileUploadBase.isMultipartContent(new ServletRequestContext(request)) :  
         ServletFileUpload.isMultipartContent(request));  
}
```

 supportedMethods成员变量表示支持的请求方法，默认为null，可以在初始化时指定。主要判断的方法在isMultipartContent(),请求头Content-Type为以multipart/开头即会认为是Multipart请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d659d48f26b59daaf3996596c7dc4026890cec52.png)

0x02 上传解析请求过程
=============

 在Spring WebFlux中，`SynchronossPartHttpMessageReader` 和 `DefaultPartHttpMessageReader` 都是用于处理和解析 HTTP multipart 请求的组件。

 **默认情况下，Spring WebFlux使用`DefaultPartHttpMessageReader`**。

 也可以使用 `SynchronossPartHttpMessageReader`，它是基于 [Synchronoss NIO Multipart](https://github.com/synchronoss/nio-multipart) 库的。两者都可以通过 `ServerCodecConfigurer` Bean进行配置：

```Java
@Configuration
@EnableWebFlux
public class WebConfig implements WebFluxConfigurer {

    @Override
    public void configureHttpMessageCodecs(ServerCodecConfigurer configurer) {
        SynchronossPartHttpMessageReader reader = new SynchronossPartHttpMessageReader();
        reader.setMaxParts(1);
        reader.setMaxDiskUsagePerPart(10L * 1024L);
        reader.setEnableLoggingRequestDetails(true);

        MultipartHttpMessageReader multipartReader = new MultipartHttpMessageReader(reader);
        multipartReader.setEnableLoggingRequestDetails(true);
        configurer.defaultCodecs().multipartReader(multipartReader);
    }

}
```

 下面查看具体的解析方式。

2.1 DefaultPartHttpMessageReader解析
----------------------------------

 在解析每一个part的时候，会根据header调用org.springframework.http.codec.multipart.PartGenerator#newPart进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-53a7f94486d848aeb3dd40aa3cd248faaff699e6.png)

 这里会判断是否是formFiled：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5b598c429f8a96469fefe48071cf0d1afaedd2e2.png)

 这里会判断上传的filename参数是否为空，而filename参数是通过org.springframework.http.ContentDisposition#parse方法解析的，这里对相关的http内容进行了处理跟封装：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7ec2d4770bb80fe34b99d9ba3cb9e08ffb07e04f.png)

 查看具体的处理过程,实际上跟Spring MVC中使用StandardMultipartHttpServletRequest解析器解析是类似的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2cd90f5d408f52929835b5e95e0ccda41ca23cd9.png)

 如果传入的multipart请求无法直接使用filename=解析出文件名，会判断filename是否以=?开头，是的话会进入BASE64\_ENCODED\_PATTERN的正则匹配中，大致的可以知道需要匹配的内容应该是`=?编码方式?B?编码内容?=` ：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8daac28d38e37dcbfde0ae8a55b3ff7858b489c2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9d887703bb36fa43b99ece463af1282938e7805f.png)

 对于filename\*=的内容，例如传入的`UTF-8'1.jpg'1.jsp`会被解析成`UTF-8`编码，最终的文件名为`1.jsp`，而`1.jpg`则会被丢弃（获取到filename\*=后的内容后，首先切割第一个'，通过Charset获取对应的编码方式，然后再切割第二个' 后的内容，并根据前面的编码方式进行解码操作，最后返回对应的filename。可以看到实际上两个`'`之间是可以任意填充内容的（单引号之间的内容在实际解析时会被忽略掉))：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-269249d2a04e105734d5fdfba82431618faadcc8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d6ecd1ba6aa1af08fbc734ca3c2433504326cd88.png)

 如果不满足上述条件的话，则直接将value赋值给filename，实际上就是获取`"`间的内容：

```Java
String value = part.startsWith("\"", eqIndex + 1) &amp;&amp; part.endsWith("\"") ? part.substring(eqIndex + 2, part.length() - 1) : part.substring(eqIndex + 1);
```

 最后会将分析的结果封装成ContentDisposition对象进行返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-38456c0ec1bc2dde3515ac2a7cea6f7a8f3ac8c4.png)

2.2 SynchronossPartHttpMessageReader解析
--------------------------------------

 该解析器在使用时除了需要额外配置以外，还需要引入对应的依赖：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3521391d5f3f476ca0d2626f4336b4d7871acbef.png)

 在解析每一个part的时候，会调用org.springframework.http.codec.multipart.SynchronossPartHttpMessageReader中FluxSinkAdapterListener的createPart方法进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a6ac36889b24f4df15290833475f3bf7bf37d8dc.png)

 实际上调用的是org.synchronoss.cloud.nio.multipart.MultipartUtils#getFileName对请求的headers进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5e52f3753360aedebf599c9a154ade84b9fe6d04.png)

 在getFileName方法中，首先会调用getHeader方法获取contentDisposition：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c7b9c99f6f8dde952c8a546d9bee439c736e1834.png)

 这里会先将headerName转换成小写（multipart请求的话，headerName就是Content-disposition），然后再获取对应的值进行返回：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-962fb08422da388ffec7186f33e8369680d8fbdc.png)

 获取到contentDisposition后，首先将其转换成小写，若其是以form-data或者attachment开头的话，调用org.synchronoss.cloud.nio.multipart.util.ParameterParser解析器进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bdbccecf47d2c8d1996b14ce30a4fc5b7156fb08.png)

 查看org.synchronoss.cloud.nio.multipart.util.ParameterParser解析器的核心方法parse，这里主要是将contentDisposition转换成char数组进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ff8ae632d442d4b62851e5381d8dac95cca26880.png)

 这里会根据`=`划分对应的paramName和paramValue，如果当前字符是等号 (=)，则提取参数值，同时还会对参数值进行解码操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-428703912008fd73c89102311876951b6361ecdb.png)

 查看解码操作org.synchronoss.cloud.nio.multipart.util.MimeUtility#decodeText的具体实现，可以看到这里实际上是对`=?`开头的内容进行解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ba08c35b5f0db1b30bafaa4fefaf20a16a07c4c9.png)

 在ParameterParser解析器解析完成后，如果解析的param中包含fileName，会进行trim操作，删除字符串开头和结尾的空白字符：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7f19227dc087276901c36b5a3f2ac040264d25d7.png)

 最后如果返回fileName不为null，则会创建SynchronossFilePart对象，从而进一步被处理或者传递给其他组件。例如保存文件、处理表单数据等。

2.3 两者的区分
---------

- SynchronossPartHttpMessageReader不支持使用`filename*=`进行文件名解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1809ca7f2be4639eeb209243582467c7fc54d91c.png)

- SynchronossPartHttpMessageReader会对解析的filename进行trim操作，删除字符串开头和结尾的空白字符，而DefaultPartHttpMessageReader不会：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0b58a91085b3703dbb1dfbc9f2707f7f546ccfae.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c4db142e5f46877b8c8758cb84a332e62078d7e7.png)

- 获取filename的位置不一样

 DefaultPartHttpMessageReader在解析时会有这么一个判断条件，当当前解析的参数为filename且值为null的时候才会进行解析，第一次解析时已经获取到对应的值了，所以后续的值不会进行解析，也就是说当存在多个filename参数的时候，其会获取第一个的值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-fe1e23adb42ce266cb132e89df4ba585cafef17d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d9c65349e8eee7d8938d5b4ce67c11ad57f69e48.png)

 SynchronossPartHttpMessageReader在解析时会通过HashMap的形式来存储解析到的param以及对应的值，那么当第二次获取到filename参数时，会覆盖掉原来的值，所以当存在多个filename参数的时候，其会获取最后一个的值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-45f4f359832c66a8f392515d7048b6e92e2d750d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-710e49df9c3af9a0af9c9b979988359164473cd4.png)

- 对`=?`开头的内容解析的差异

 DefaultPartHttpMessageReader在解析时是通过正则进行匹配的，并且需要value以`=?`开头：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-319593f466f255434733767bdeac895775e7fb42.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-daed4e95ce08b80eda1d04b84223496b4695acc6.png)

 SynchronossPartHttpMessageReader在解析时若当前字符为一个空白字符（空格、制表符、回车或换行）时，记录空白数字的起始和结束位置并进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-18d66cd9fff68ec9e5bd1f0f496fc3c27939769a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5dcf2faa00eb5ba085561af3ebbc3f6f8c3fda79.png)

0x03 获取上传的文件名
=============

 Spring WebFlux在处理multipart请求时，如果请求中包含文件上传的部分（Part），可以使用`filePart.filename()`方法来获取该部分对应的文件名。该方法返回一个字符串，表示文件的原始文件名。

 通常，开发人员可以使用该方法来获取上传文件的文件名，并进行相应的处理，例如文件存储、文件名校验等操作。

 当使用DefaultPartHttpMessageReader解析进行解析时，实际上是从ContentDispositio对象中获取的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-499d16a3c1fe5efb59c6cb6b1292a40794ff480d.png)

 使用SynchronossPartHttpMessageReader解析时，是从SynchronossFilePart对象的filename属性进行获取的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f020fa88798e9cb8bc85d940322ffeb565676775.png)

 根据前面的分析，两者在整个过程没有对类似../的路径进行检查&amp;过滤，由于获取的fileName未进行安全处理，在使用File创建文件时，若路径处path写入../../穿越符号，是可以跨目录新建文件的。

 那么在实际利用时，可以尝试通过linux写入定时任务（etc/cron.d/下的文件可以以任意后缀命名，如果未对filename进行重命名的话还可以绕过上传的后缀限制）、ssh公钥（需要满足root权限）,甚至是替换 JDK HOME 目录下的系统 jar 文件，再主动触发 jar 文件里的类初始化来达到执行任意代码的效果。

0x04 SpringMVC的Multipart请求绕过
============================

 众所周知，在SpringMVC中，当接收到一个multipart请求后，会调用 MultipartResolver 的 resolveMultipart() 方法对请求的数据进行解析并将解析结果封装到中HttpServletRequest。很多时候一些安全检测的filter在进行类似SQL注入、XSS的过滤时没有考虑到上述情况，那么就可以尝试将普通的GET/POST转换成Multipart请求，绕过对应的安全检查。

 以如下Controller为例，查看Spring WebFlux是否也存在类似的绕过场景：

```Java
@RequestMapping("/manage")
public String manage(@RequestParam String param) {
    return "param:"+param;
}
```

 正常情况下，通过GET请求访问该资源可以正常获取param参数的内容：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f486b2a206e3cc056f2cb4713da2e0128b8b6af3.png)

 当使用POST方法请求时，会返回400 Status：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0aa7ffa57fdca18a17536ce564316452d94f20dd.png)

 查阅官方文档https://docs.spring.io/spring-framework/reference/web/webflux/controller/ann-methods/requestparam.html 可知:

 在Spring webflux中，@RequestParam注解仅支持url传参方式，无法处理form-data和multipart的方法。如果想处理类似的请求，可以使用ServerWebExchange进行处理。

```Java
The Servlet API “request parameter” concept conflates query parameters, form data, and multiparts into one. However, in WebFlux, each is accessed individually through ServerWebExchange. While @RequestParam binds to query parameters only, you can use data binding to apply query parameters, form data, and multiparts to a command object.
```

 例如需要通过form-data的方式获取param参数：

```Java
@PostMapping("/manage")
public Mono manage(ServerWebExchange exchange) {
    return exchange.getFormData()
            .flatMap(formData -&gt; {
                String paramName1 = formData.getFirst("param"); // 获取 POST 参数 "param"
                // 处理参数并返回结果
                return Mono.just("Param: " + paramName1);
            });
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-838fbca41331b57d27fe626b36342197e2792f4d.png)

 同样的，上述Controller代码并不能处理multipart的请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-79a69dd4aca7752252deb00b495e5ce662aafc51.png)

 如果需要获取multipart的数据，需要额外的调用ServerWebExchange方法进行处理：

```Java
@PostMapping(value = "/handleMultipartRequest", consumes = "multipart/form-data")
public Mono handleMultipartRequest(ServerWebExchange exchange) {
    return exchange.getMultipartData()
            .flatMap(parts -&gt; {
                Part part = parts.getFirst("param");
                if (part instanceof FormFieldPart){
                    return Mono.just("param: " + ((FormFieldPart) part).value());
                }

                // 处理参数并返回结果
                return Mono.just("param: " + null);
            });
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7bb7af50d6c8fcb64c496b755472e683bcfa309e.png)

 也就是说，默认情况下，Spring WebFlux并不像Spring MVC一样，能在多个请求方式之间灵活解析转换。